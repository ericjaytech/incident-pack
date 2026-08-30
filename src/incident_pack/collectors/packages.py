from __future__ import annotations

import re
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from incident_pack.collectors.configuration import SYSTEMD_UNIT_ROOTS
from incident_pack.config import HARD_LIMITS

_DPKG_QUERY = Path("/usr/bin/dpkg-query")
_PACKAGE_FORMAT = "${binary:Package}\\t${Version}\\t${Architecture}\\t${Status}\\n"
_PACKAGE_PATTERN = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}(?::[a-z0-9][a-z0-9-]{0,31})?")
_ARCHITECTURE_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
_MAX_PATHS = 64
_MAX_QUERY_BYTES = 65_536
_MAX_VERSION_BYTES = 256


@dataclass(frozen=True)
class PackageCollection:
    status: str
    packages: tuple[Mapping[str, str], ...]
    diagnostic_code: str | None = None


class _PackageFailure(RuntimeError):
    def __init__(self, code: str, *, status: str = "error") -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def collect_packages(
    *,
    paths: Sequence[Path],
    timeout_seconds: int | float,
    _dpkg_query: Path = _DPKG_QUERY,
    _allowed_roots: Sequence[Path] = SYSTEMD_UNIT_ROOTS,
) -> PackageCollection:
    """Collect installed-package metadata for allowlisted systemd unit paths."""
    _validate_inputs(
        paths=paths,
        timeout_seconds=timeout_seconds,
        dpkg_query=_dpkg_query,
        allowed_roots=_allowed_roots,
    )
    try:
        safe_paths = _validate_paths(paths, _allowed_roots)
    except _PackageFailure as error:
        return _result(status=error.status, diagnostic_code=error.code)
    if not safe_paths:
        return _result(status="skipped", diagnostic_code="PACKAGE_METADATA_UNAVAILABLE")

    deadline = time.monotonic() + float(timeout_seconds)
    try:
        package_names = {
            owner
            for path in safe_paths
            if (owner := _find_owner(path, _dpkg_query, deadline)) is not None
        }
        if not package_names:
            return _result(status="skipped", diagnostic_code="PACKAGE_METADATA_UNAVAILABLE")
        packages = tuple(
            sorted(
                (_read_metadata(name, _dpkg_query, deadline) for name in package_names),
                key=lambda item: item["name"],
            )
        )
    except _PackageFailure as error:
        return _result(status=error.status, diagnostic_code=error.code)
    return _result(status="collected", packages=packages)


def _find_owner(path: Path, executable: Path, deadline: float) -> str | None:
    payload = _run_query(
        executable,
        ["--search", "--", str(path)],
        deadline,
        not_found_is_empty=True,
    )
    if payload is None:
        return None
    lines = _decode_lines(payload, "PACKAGE_OWNER_MALFORMED")
    matches: list[str] = []
    for line in lines:
        owner, separator, owned_path = line.partition(": ")
        if not separator or _PACKAGE_PATTERN.fullmatch(owner) is None:
            raise _PackageFailure("PACKAGE_OWNER_MALFORMED")
        if owned_path == str(path):
            matches.append(owner)
    if len(matches) != 1:
        raise _PackageFailure("PACKAGE_OWNER_MALFORMED")
    return matches[0]


def _read_metadata(name: str, executable: Path, deadline: float) -> Mapping[str, str]:
    payload = _run_query(
        executable,
        ["--show", f"--showformat={_PACKAGE_FORMAT}", "--", name],
        deadline,
        not_found_is_empty=False,
    )
    assert payload is not None
    lines = _decode_lines(payload, "PACKAGE_METADATA_MALFORMED")
    if len(lines) != 1:
        raise _PackageFailure("PACKAGE_METADATA_MALFORMED")
    fields = lines[0].split("\t")
    if len(fields) != 4:
        raise _PackageFailure("PACKAGE_METADATA_MALFORMED")
    returned_name, version, architecture, status = fields
    if (
        _PACKAGE_PATTERN.fullmatch(returned_name) is None
        or returned_name.split(":", 1)[0] != name.split(":", 1)[0]
        or not _safe_printable(version, _MAX_VERSION_BYTES)
        or _ARCHITECTURE_PATTERN.fullmatch(architecture) is None
        or status != "install ok installed"
    ):
        raise _PackageFailure("PACKAGE_METADATA_MALFORMED")
    return MappingProxyType(
        {
            "architecture": architecture,
            "name": returned_name,
            "status": status,
            "version": version,
        }
    )


def _run_query(
    executable: Path,
    arguments: list[str],
    deadline: float,
    *,
    not_found_is_empty: bool,
) -> bytes | None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _PackageFailure("PACKAGE_QUERY_TIMEOUT")
    try:
        completed = subprocess.run(
            [str(executable), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            check=False,
            timeout=remaining,
        )
    except FileNotFoundError as error:
        raise _PackageFailure("DPKG_QUERY_NOT_FOUND", status="skipped") from error
    except subprocess.TimeoutExpired as error:
        raise _PackageFailure("PACKAGE_QUERY_TIMEOUT") from error
    except OSError as error:
        raise _PackageFailure("PACKAGE_QUERY_FAILED") from error
    if completed.returncode == 1 and not_found_is_empty:
        return None
    if completed.returncode != 0:
        raise _PackageFailure("PACKAGE_QUERY_FAILED")
    if len(completed.stdout) > _MAX_QUERY_BYTES:
        raise _PackageFailure("PACKAGE_QUERY_MALFORMED")
    return completed.stdout


def _decode_lines(payload: bytes, error_code: str) -> list[str]:
    if not payload or any(
        byte < 0x20 and byte not in {0x09, 0x0A} or byte == 0x7F for byte in payload
    ):
        raise _PackageFailure(error_code)
    try:
        text = payload.decode("ascii")
    except UnicodeError as error:
        raise _PackageFailure(error_code) from error
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    if not lines or any(not line for line in lines):
        raise _PackageFailure(error_code)
    return lines


def _validate_paths(paths: Sequence[Path], roots: Sequence[Path]) -> tuple[Path, ...]:
    aliases = tuple(root.absolute() for root in roots)
    resolved_roots: list[Path] = []
    for root in aliases:
        try:
            resolved_roots.append(root.resolve(strict=True))
        except OSError:
            continue

    safe: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        raw_path = str(path)
        if (
            not path.is_absolute()
            or len(raw_path.encode("utf-8")) > 4_096
            or any(character.isspace() for character in raw_path)
            or any(character in raw_path for character in "*?[")
            or not any(path.is_relative_to(root) for root in aliases)
        ):
            raise _PackageFailure("PACKAGE_PATH_UNSAFE")
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise _PackageFailure("PACKAGE_PATH_UNSAFE") from error
        if not any(resolved.is_relative_to(root) for root in resolved_roots):
            raise _PackageFailure("PACKAGE_PATH_UNSAFE")
        if path not in seen:
            safe.append(path)
            seen.add(path)
    return tuple(safe)


def _safe_printable(value: str, maximum_bytes: int) -> bool:
    return (
        bool(value)
        and len(value.encode("ascii")) <= maximum_bytes
        and all(0x20 <= ord(character) <= 0x7E for character in value)
    )


def _result(
    *,
    status: str,
    packages: Sequence[Mapping[str, str]] = (),
    diagnostic_code: str | None = None,
) -> PackageCollection:
    return PackageCollection(
        status=status,
        packages=tuple(MappingProxyType(dict(item)) for item in packages),
        diagnostic_code=diagnostic_code,
    )


def _validate_inputs(
    *,
    paths: Sequence[Path],
    timeout_seconds: int | float,
    dpkg_query: Path,
    allowed_roots: Sequence[Path],
) -> None:
    if len(paths) > _MAX_PATHS or any(not isinstance(path, Path) for path in paths):
        raise ValueError("package paths must contain at most 64 Path values")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 < timeout_seconds <= HARD_LIMITS["collector_timeout_seconds"]
    ):
        raise ValueError("timeout_seconds must be positive and within the compiled hard maximum")
    if not isinstance(dpkg_query, Path) or not dpkg_query.is_absolute():
        raise ValueError("dpkg-query executable must be an absolute path")
    if not allowed_roots or any(
        not isinstance(root, Path) or not root.is_absolute() for root in allowed_roots
    ):
        raise ValueError("allowed systemd roots must be absolute paths")
