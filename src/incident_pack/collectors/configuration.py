from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import BinaryIO

from incident_pack.config import HARD_LIMITS

_SYSTEMCTL = Path("/usr/bin/systemctl")
SYSTEMD_UNIT_ROOTS = (
    Path("/etc/systemd/system"),
    Path("/run/systemd/system"),
    Path("/usr/local/lib/systemd/system"),
    Path("/usr/lib/systemd/system"),
    Path("/lib/systemd/system"),
)
_SERVICE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@:-]*\.service")
_MAX_QUERY_BYTES = 65_536
_MAX_PATH_BYTES = 4_096
_MAX_FILES = 64
_MAX_UNIT_FILE_BYTES = 1_048_576
_READ_BYTES = 65_536


@dataclass(frozen=True)
class ConfigurationCollection:
    status: str
    files: tuple[Mapping[str, object], ...]
    diagnostic_code: str | None = None


class _ConfigurationFailure(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def collect_configuration(
    *,
    service: str,
    timeout_seconds: int | float,
    _systemctl: Path = _SYSTEMCTL,
    _allowed_roots: Sequence[Path] = SYSTEMD_UNIT_ROOTS,
    _max_source_bytes: int = _MAX_UNIT_FILE_BYTES,
) -> ConfigurationCollection:
    """Collect metadata and checksums for allowlisted systemd unit files."""
    _validate_inputs(
        service=service,
        timeout_seconds=timeout_seconds,
        systemctl=_systemctl,
        allowed_roots=_allowed_roots,
        max_source_bytes=_max_source_bytes,
    )
    try:
        completed = subprocess.run(
            [
                str(_systemctl),
                "show",
                "--no-pager",
                "--property=FragmentPath",
                "--property=DropInPaths",
                "--",
                service,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            check=False,
            timeout=float(timeout_seconds),
        )
    except FileNotFoundError:
        return _result(status="skipped", diagnostic_code="SYSTEMCTL_NOT_FOUND")
    except subprocess.TimeoutExpired:
        return _result(status="error", diagnostic_code="CONFIGURATION_QUERY_TIMEOUT")
    except OSError:
        return _result(status="error", diagnostic_code="CONFIGURATION_QUERY_FAILED")

    if completed.returncode != 0:
        return _result(status="error", diagnostic_code="CONFIGURATION_QUERY_FAILED")
    try:
        discovered = _parse_paths(completed.stdout)
        if not discovered:
            return _result(
                status="skipped",
                diagnostic_code="CONFIGURATION_NOT_FILE_BACKED",
            )
        roots = _resolve_roots(_allowed_roots)
        files = tuple(
            _inspect_file(
                path,
                source=source,
                roots=roots,
                max_source_bytes=_max_source_bytes,
            )
            for source, path in discovered
        )
    except _ConfigurationFailure as error:
        return _result(status="error", diagnostic_code=error.code)
    return _result(status="collected", files=files)


def _parse_paths(payload: bytes) -> tuple[tuple[str, Path], ...]:
    if not payload or len(payload) > _MAX_QUERY_BYTES:
        raise _ConfigurationFailure("CONFIGURATION_QUERY_MALFORMED")
    if any(byte < 0x20 and byte != 0x0A or byte == 0x7F for byte in payload):
        raise _ConfigurationFailure("CONFIGURATION_QUERY_MALFORMED")
    try:
        text = payload.decode("utf-8")
    except UnicodeError as error:
        raise _ConfigurationFailure("CONFIGURATION_QUERY_MALFORMED") from error
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    if (
        len(lines) != 2
        or not lines[0].startswith("FragmentPath=")
        or not lines[1].startswith("DropInPaths=")
    ):
        raise _ConfigurationFailure("CONFIGURATION_QUERY_MALFORMED")

    fragment = lines[0].removeprefix("FragmentPath=")
    drop_ins = lines[1].removeprefix("DropInPaths=").split()
    raw_paths = ([("fragment", fragment)] if fragment else []) + [
        ("drop-in", value) for value in drop_ins
    ]
    if len(raw_paths) > _MAX_FILES:
        raise _ConfigurationFailure("CONFIGURATION_QUERY_MALFORMED")

    discovered: list[tuple[str, Path]] = []
    seen: set[str] = set()
    for source, raw_path in raw_paths:
        if (
            not raw_path.startswith("/")
            or len(raw_path.encode("utf-8")) > _MAX_PATH_BYTES
            or any(character.isspace() for character in raw_path)
        ):
            raise _ConfigurationFailure("CONFIGURATION_PATH_UNSAFE")
        if raw_path not in seen:
            discovered.append((source, Path(raw_path)))
            seen.add(raw_path)
    return tuple(discovered)


def _resolve_roots(roots: Sequence[Path]) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    aliases: list[Path] = []
    resolved: list[Path] = []
    for root in roots:
        absolute = root.absolute()
        aliases.append(absolute)
        try:
            resolved.append(absolute.resolve(strict=True))
        except OSError:
            continue
    return tuple(aliases), tuple(resolved)


def _inspect_file(
    path: Path,
    *,
    source: str,
    roots: tuple[tuple[Path, ...], tuple[Path, ...]],
    max_source_bytes: int,
) -> Mapping[str, object]:
    resolved = _resolve_safe_path(path, roots)
    metadata, digest = _read_file_metadata(resolved, max_source_bytes)
    try:
        modified_at = datetime.fromtimestamp(metadata.st_mtime, UTC).isoformat(
            timespec="microseconds"
        )
    except (OSError, OverflowError, ValueError) as error:
        raise _ConfigurationFailure("CONFIGURATION_FILE_UNSAFE") from error

    return MappingProxyType(
        {
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "modified_at": modified_at.replace("+00:00", "Z"),
            "path": str(path),
            "resolved_path": str(resolved),
            "sha256": digest,
            "size_bytes": metadata.st_size,
            "source": source,
        }
    )


def _resolve_safe_path(path: Path, roots: tuple[tuple[Path, ...], tuple[Path, ...]]) -> Path:
    aliases, resolved_roots = roots
    if not any(path.is_relative_to(root) for root in aliases):
        raise _ConfigurationFailure("CONFIGURATION_PATH_UNSAFE")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise _ConfigurationFailure("CONFIGURATION_FILE_UNREADABLE") from error
    if not any(resolved.is_relative_to(root) for root in resolved_roots):
        raise _ConfigurationFailure("CONFIGURATION_PATH_UNSAFE")
    return resolved


def _read_file_metadata(resolved: Path, max_source_bytes: int) -> tuple[os.stat_result, str]:
    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(resolved, flags)
    except OSError as error:
        raise _ConfigurationFailure("CONFIGURATION_FILE_UNREADABLE") from error

    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise _ConfigurationFailure("CONFIGURATION_FILE_UNSAFE")
        if before.st_size > max_source_bytes:
            raise _ConfigurationFailure("CONFIGURATION_FILE_TOO_LARGE")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            digest, bytes_read = _hash_bounded(stream, max_source_bytes)
            after = os.fstat(stream.fileno())
    except _ConfigurationFailure:
        raise
    except OSError as error:
        raise _ConfigurationFailure("CONFIGURATION_FILE_UNREADABLE") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or bytes_read != before.st_size:
        raise _ConfigurationFailure("CONFIGURATION_FILE_CHANGED")
    return before, digest


def _hash_bounded(stream: BinaryIO, maximum: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    bytes_read = 0
    while True:
        chunk = stream.read(min(_READ_BYTES, maximum - bytes_read + 1))
        if not chunk:
            break
        bytes_read += len(chunk)
        if bytes_read > maximum:
            raise _ConfigurationFailure("CONFIGURATION_FILE_TOO_LARGE")
        digest.update(chunk)
    return digest.hexdigest(), bytes_read


def _result(
    *,
    status: str,
    files: Sequence[Mapping[str, object]] = (),
    diagnostic_code: str | None = None,
) -> ConfigurationCollection:
    return ConfigurationCollection(
        status=status,
        files=tuple(MappingProxyType(dict(item)) for item in files),
        diagnostic_code=diagnostic_code,
    )


def _validate_inputs(
    *,
    service: str,
    timeout_seconds: int | float,
    systemctl: Path,
    allowed_roots: Sequence[Path],
    max_source_bytes: int,
) -> None:
    if (
        not isinstance(service, str)
        or len(service) > 255
        or _SERVICE_PATTERN.fullmatch(service) is None
    ):
        raise ValueError("service must be a validated systemd .service name")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 < timeout_seconds <= HARD_LIMITS["collector_timeout_seconds"]
    ):
        raise ValueError("timeout_seconds must be positive and within the compiled hard maximum")
    if not isinstance(systemctl, Path) or not systemctl.is_absolute():
        raise ValueError("systemctl executable must be an absolute path")
    if not allowed_roots or any(
        not isinstance(root, Path) or not root.is_absolute() for root in allowed_roots
    ):
        raise ValueError("allowed systemd roots must be absolute paths")
    if (
        isinstance(max_source_bytes, bool)
        or not isinstance(max_source_bytes, int)
        or not 1 <= max_source_bytes <= _MAX_UNIT_FILE_BYTES
    ):
        raise ValueError("max source bytes must be within the compiled bound")
