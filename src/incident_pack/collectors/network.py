from __future__ import annotations

import ipaddress
import multiprocessing
import os
import re
import socket
import stat
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, BinaryIO

from incident_pack.config import HARD_LIMITS

_RESOLVER_PATH = Path("/etc/resolv.conf")
_RESOLVER_ROOTS = (
    Path("/etc"),
    Path("/run/systemd/resolve"),
    Path("/run/NetworkManager"),
    Path("/run/resolvconf"),
)
_HOST_LABEL_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_MAX_RESOLVER_BYTES = 65_536
_MAX_RESOLVER_LINES = 256
_MAX_RESOLVER_LINE_BYTES = 1_024
_MAX_ADDRESSES = 32


@dataclass(frozen=True)
class ResolverCollection:
    status: str
    data: Mapping[str, object]
    diagnostic_code: str | None = None


@dataclass(frozen=True)
class NetworkCheck:
    status: str
    outcome: str
    target: str
    port: int | None
    elapsed_ms: int
    address_families: tuple[str, ...]
    address_scopes: tuple[str, ...]
    diagnostic_code: str | None = None


def parse_resolver_configuration(payload: bytes) -> Mapping[str, object]:
    """Reduce resolv.conf content to counts, address families and scopes."""
    lines = _decode_resolver_lines(payload)
    return _summarise_resolver_lines(lines)


def _decode_resolver_lines(payload: bytes) -> list[str]:
    if not isinstance(payload, bytes) or len(payload) > _MAX_RESOLVER_BYTES:
        raise ValueError("resolver configuration exceeds its input bound")
    if any(byte < 0x20 and byte not in {0x09, 0x0A} or byte == 0x7F for byte in payload):
        raise ValueError("resolver configuration contains a control character")
    try:
        text = payload.decode("ascii")
    except UnicodeError as error:
        raise ValueError("resolver configuration must be ASCII") from error
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    if len(lines) > _MAX_RESOLVER_LINES or any(
        len(line.encode("ascii")) > _MAX_RESOLVER_LINE_BYTES for line in lines
    ):
        raise ValueError("resolver configuration has an invalid line bound")
    return lines


def _summarise_resolver_lines(lines: Sequence[str]) -> Mapping[str, object]:
    families: set[str] = set()
    scopes: set[str] = set()
    nameserver_count = 0
    search_domain_count = 0
    options_count = 0
    for raw_line in lines:
        line = raw_line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if fields[0] == "nameserver":
            address = _parse_nameserver(fields)
            nameserver_count += 1
            families.add(_family_name(address.version))
            scopes.add(_address_scope(address))
        elif fields[0] in {"domain", "search"}:
            if len(fields) < 2:
                raise ValueError("resolver configuration has an invalid search directive")
            search_domain_count += len(fields) - 1
        elif fields[0] == "options":
            options_count += len(fields) - 1

    return MappingProxyType(
        {
            "nameserver_count": nameserver_count,
            "nameserver_families": tuple(sorted(families)),
            "nameserver_scopes": tuple(sorted(scopes)),
            "options_count": options_count,
            "search_domain_count": search_domain_count,
        }
    )


def _parse_nameserver(fields: Sequence[str]) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if len(fields) != 2:
        raise ValueError("resolver configuration has an invalid nameserver")
    try:
        return ipaddress.ip_address(fields[1])
    except ValueError as error:
        raise ValueError("resolver configuration has an invalid nameserver") from error


def collect_resolver_metadata(
    *,
    _path: Path = _RESOLVER_PATH,
    _allowed_roots: Sequence[Path] = _RESOLVER_ROOTS,
) -> ResolverCollection:
    """Read the fixed resolver file without retaining addresses or domain names."""
    _validate_resolver_source(_path, _allowed_roots)
    aliases = tuple(root.absolute() for root in _allowed_roots)
    resolved_roots = _existing_resolved_roots(aliases)
    if not any(_path.is_relative_to(root) for root in aliases):
        return _resolver_result(status="error", diagnostic_code="RESOLVER_PATH_UNSAFE")
    try:
        resolved = _path.resolve(strict=True)
    except FileNotFoundError:
        return _resolver_result(
            status="skipped",
            diagnostic_code="RESOLVER_CONFIGURATION_UNAVAILABLE",
        )
    except OSError:
        return _resolver_result(
            status="skipped",
            diagnostic_code="RESOLVER_CONFIGURATION_UNAVAILABLE",
        )
    if not any(resolved.is_relative_to(root) for root in resolved_roots):
        return _resolver_result(status="error", diagnostic_code="RESOLVER_PATH_UNSAFE")

    try:
        payload = _read_regular_file(resolved, _MAX_RESOLVER_BYTES)
    except OSError:
        return _resolver_result(
            status="skipped",
            diagnostic_code="RESOLVER_CONFIGURATION_UNAVAILABLE",
        )
    except ValueError:
        return _resolver_result(status="error", diagnostic_code="RESOLVER_FILE_UNSAFE")
    try:
        data = parse_resolver_configuration(payload)
    except ValueError:
        return _resolver_result(
            status="error",
            diagnostic_code="RESOLVER_CONFIGURATION_MALFORMED",
        )
    return _resolver_result(status="collected", data=data)


def check_dns(
    target: str,
    *,
    timeout_seconds: int | float,
    _resolver: Callable[..., list[Any]] = socket.getaddrinfo,
) -> NetworkCheck:
    normalised = _validate_host(target, allow_ip=False)
    _validate_timeout(timeout_seconds)
    return _run_network_worker(
        operation="dns",
        target=normalised,
        port=None,
        timeout_seconds=float(timeout_seconds),
        resolver=_resolver,
    )


def check_tcp(
    target: str,
    port: int,
    *,
    timeout_seconds: int | float,
    _resolver: Callable[..., list[Any]] = socket.getaddrinfo,
) -> NetworkCheck:
    normalised = _validate_host(target, allow_ip=True)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
        raise ValueError("TCP port must be between 1 and 65535")
    _validate_timeout(timeout_seconds)
    return _run_network_worker(
        operation="tcp",
        target=normalised,
        port=port,
        timeout_seconds=float(timeout_seconds),
        resolver=_resolver,
    )


def _run_network_worker(
    *,
    operation: str,
    target: str,
    port: int | None,
    timeout_seconds: float,
    resolver: Callable[..., list[Any]],
) -> NetworkCheck:
    started = time.monotonic()
    try:
        context = multiprocessing.get_context("spawn")
        receive, send = context.Pipe(duplex=False)
        process = context.Process(
            target=_network_worker,
            args=(send, operation, target, port, timeout_seconds, resolver),
            daemon=True,
        )
        process.start()
    except (OSError, RuntimeError, ValueError):
        return _network_result(
            status="error",
            outcome="incomplete",
            target=target,
            port=port,
            elapsed_ms=_elapsed_ms(started),
            diagnostic_code="NETWORK_WORKER_FAILED",
        )
    send.close()
    try:
        remaining = timeout_seconds - (time.monotonic() - started)
        if remaining <= 0 or not receive.poll(remaining):
            _terminate_worker(process)
            return _network_result(
                status="error",
                outcome="incomplete",
                target=target,
                port=port,
                elapsed_ms=_elapsed_ms(started),
                diagnostic_code=(
                    "DNS_LOOKUP_TIMEOUT" if operation == "dns" else "TCP_CHECK_TIMEOUT"
                ),
            )
        try:
            payload = receive.recv()
        except (EOFError, OSError):
            return _network_result(
                status="error",
                outcome="incomplete",
                target=target,
                port=port,
                elapsed_ms=_elapsed_ms(started),
                diagnostic_code="NETWORK_WORKER_FAILED",
            )
    finally:
        receive.close()
        process.join(timeout=max(0.0, timeout_seconds - (time.monotonic() - started)))
        if process.is_alive():
            _terminate_worker(process)
    return _normalise_worker_payload(payload, target=target, port=port, started=started)


def _network_worker(
    connection: Any,
    operation: str,
    target: str,
    port: int | None,
    timeout_seconds: float,
    resolver: Callable[..., list[Any]],
) -> None:
    deadline = time.monotonic() + timeout_seconds
    try:
        try:
            records = resolver(
                target,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
            addresses = _normalise_addresses(records)
        except (OSError, ValueError, TypeError):
            diagnostic = "DNS_LOOKUP_FAILED" if operation == "dns" else "TCP_RESOLUTION_FAILED"
            connection.send(("failed", (), (), diagnostic))
            return
        families = tuple(sorted({item[0] for item in addresses}))
        scopes = tuple(sorted({item[1] for item in addresses}))
        if not addresses:
            diagnostic = "DNS_LOOKUP_FAILED" if operation == "dns" else "TCP_RESOLUTION_FAILED"
            connection.send(("failed", families, scopes, diagnostic))
        elif operation == "dns":
            connection.send(("resolved", families, scopes, None))
        elif _connect_without_payload(addresses, deadline):
            connection.send(("connected", families, scopes, None))
        else:
            connection.send(("failed", families, scopes, "TCP_CONNECT_FAILED"))
    except (OSError, RuntimeError, ValueError, TypeError):
        try:
            connection.send(("incomplete", (), (), "NETWORK_WORKER_FAILED"))
        except OSError:
            pass
    finally:
        connection.close()


def _normalise_addresses(records: Sequence[Any]) -> list[tuple[str, str, int, int, int, Any]]:
    addresses: list[tuple[str, str, int, int, int, Any]] = []
    seen: set[tuple[int, Any]] = set()
    for record in records:
        if not isinstance(record, tuple) or len(record) != 5:
            raise ValueError("resolver returned a malformed record")
        family, socktype, protocol, _, sockaddr = record
        if family not in {socket.AF_INET, socket.AF_INET6} or not isinstance(sockaddr, tuple):
            raise ValueError("resolver returned an unsupported address")
        address = ipaddress.ip_address(sockaddr[0])
        if address.version != (4 if family == socket.AF_INET else 6):
            raise ValueError("resolver returned an inconsistent address family")
        identity = (family, sockaddr)
        if identity not in seen:
            addresses.append(
                (
                    _family_name(address.version),
                    _address_scope(address),
                    family,
                    socktype,
                    protocol,
                    sockaddr,
                )
            )
            seen.add(identity)
        if len(addresses) > _MAX_ADDRESSES:
            raise ValueError("resolver returned too many addresses")
    return addresses


def _connect_without_payload(
    addresses: Sequence[tuple[str, str, int, int, int, Any]], deadline: float
) -> bool:
    for _, _, family, socktype, protocol, sockaddr in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        connection = socket.socket(family, socktype, protocol)
        try:
            connection.settimeout(remaining)
            connection.connect(sockaddr)
            return True
        except OSError:
            continue
        finally:
            connection.close()
    return False


def _normalise_worker_payload(
    payload: object, *, target: str, port: int | None, started: float
) -> NetworkCheck:
    if (
        not isinstance(payload, tuple)
        or len(payload) != 4
        or payload[0] not in {"resolved", "connected", "failed", "incomplete"}
        or not isinstance(payload[1], tuple)
        or not set(payload[1]) <= {"IPv4", "IPv6"}
        or not isinstance(payload[2], tuple)
        or not set(payload[2])
        <= {"global", "link-local", "loopback", "multicast", "private", "reserved", "unspecified"}
        or payload[3]
        not in {
            None,
            "DNS_LOOKUP_FAILED",
            "TCP_RESOLUTION_FAILED",
            "TCP_CONNECT_FAILED",
            "NETWORK_WORKER_FAILED",
        }
    ):
        return _network_result(
            status="error",
            outcome="incomplete",
            target=target,
            port=port,
            elapsed_ms=_elapsed_ms(started),
            diagnostic_code="NETWORK_WORKER_FAILED",
        )
    outcome, families, scopes, diagnostic = payload
    return _network_result(
        status="error" if outcome == "incomplete" else "collected",
        outcome=outcome,
        target=target,
        port=port,
        elapsed_ms=_elapsed_ms(started),
        address_families=families,
        address_scopes=scopes,
        diagnostic_code=diagnostic,
    )


def _read_regular_file(path: Path, maximum: int) -> bytes:
    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise ValueError("resolver source must be a bounded regular file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            return _read_bounded(stream, maximum)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_bounded(stream: BinaryIO, maximum: int) -> bytes:
    payload = stream.read(maximum + 1)
    if len(payload) > maximum:
        raise ValueError("resolver source exceeds its byte bound")
    return payload


def _existing_resolved_roots(roots: Sequence[Path]) -> tuple[Path, ...]:
    resolved: list[Path] = []
    for root in roots:
        try:
            resolved.append(root.resolve(strict=True))
        except OSError:
            continue
    return tuple(resolved)


def _resolver_result(
    *,
    status: str,
    data: Mapping[str, object] = MappingProxyType({}),
    diagnostic_code: str | None = None,
) -> ResolverCollection:
    return ResolverCollection(
        status=status,
        data=MappingProxyType(dict(data)),
        diagnostic_code=diagnostic_code,
    )


def _network_result(
    *,
    status: str,
    outcome: str,
    target: str,
    port: int | None,
    elapsed_ms: int,
    address_families: Sequence[str] = (),
    address_scopes: Sequence[str] = (),
    diagnostic_code: str | None = None,
) -> NetworkCheck:
    return NetworkCheck(
        status=status,
        outcome=outcome,
        target=target,
        port=port,
        elapsed_ms=elapsed_ms,
        address_families=tuple(address_families),
        address_scopes=tuple(address_scopes),
        diagnostic_code=diagnostic_code,
    )


def _family_name(version: int) -> str:
    return "IPv4" if version == 4 else "IPv6"


def _address_scope(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    if address.is_multicast:
        return "multicast"
    if address.is_unspecified:
        return "unspecified"
    if address.is_private:
        return "private"
    if address.is_global:
        return "global"
    return "reserved"


def _validate_host(value: str, *, allow_ip: bool) -> str:
    if not isinstance(value, str) or not value or len(value) > 253 or not value.isascii():
        raise ValueError("network target must be a non-empty ASCII host")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None
    if address is not None:
        if not allow_ip:
            raise ValueError("DNS target must be a hostname")
        return str(address)
    candidate = value[:-1] if value.endswith(".") else value
    if not candidate or any(
        _HOST_LABEL_PATTERN.fullmatch(label) is None for label in candidate.split(".")
    ):
        raise ValueError("network target has invalid DNS label syntax")
    return candidate.lower()


def _validate_timeout(value: int | float) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not 0 < value <= HARD_LIMITS["collector_timeout_seconds"]
    ):
        raise ValueError("network timeout must be positive and within the compiled hard maximum")


def _validate_resolver_source(path: Path, roots: Sequence[Path]) -> None:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError("resolver source path must be absolute")
    if not roots or any(not isinstance(root, Path) or not root.is_absolute() for root in roots):
        raise ValueError("resolver roots must be absolute paths")


def _elapsed_ms(started: float) -> int:
    return max(0, round((time.monotonic() - started) * 1_000))


def _terminate_worker(process: Any) -> None:
    if process.is_alive():
        process.terminate()
    process.join(timeout=1)
    if process.is_alive():
        process.kill()
        process.join()
