from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

_MAX_SERVICE_BYTES = 8_192
_MAX_RESOURCE_BYTES = 65_536
_MAX_LINES = 32
_MAX_LINE_BYTES = 1_024
_MAX_INTEGER = 2**63 - 1
_SAFE_STATE = re.compile(r"[A-Za-z0-9_.@:-]{0,128}")
_SAFE_FILESYSTEM_TYPE = re.compile(r"[A-Za-z0-9_.+-]{1,32}")

_SERVICE_FIELDS = {
    "LoadState": ("load_state", "text"),
    "ActiveState": ("active_state", "text"),
    "SubState": ("sub_state", "text"),
    "UnitFileState": ("unit_file_state", "text"),
    "Type": ("service_type", "text"),
    "MainPID": ("main_pid", "integer"),
    "ExecMainStatus": ("exec_main_status", "integer"),
    "Result": ("result", "text"),
    "NRestarts": ("restart_count", "integer"),
    "ActiveEnterTimestampMonotonic": (
        "active_enter_timestamp_monotonic_us",
        "integer",
    ),
}
_SERVICE_DIAGNOSTICS = {
    "SYSTEMCTL_NOT_FOUND": "skipped",
    "SERVICE_QUERY_FAILED": "error",
}
_MEMORY_FIELDS = {
    "MemTotal": "total_bytes",
    "MemAvailable": "available_bytes",
    "SwapTotal": "swap_total_bytes",
    "SwapFree": "swap_free_bytes",
}
_RESOURCE_DIAGNOSTICS = {
    "LOADAVG_NOT_FOUND",
    "MEMINFO_NOT_FOUND",
    "PRESSURE_CPU_NOT_FOUND",
    "PRESSURE_MEMORY_NOT_FOUND",
    "PRESSURE_IO_NOT_FOUND",
    "FINDMNT_NOT_FOUND",
    "FILESYSTEM_QUERY_FAILED",
}


class CollectorParseError(ValueError):
    """Raised when collector output violates its allowlisted line protocol."""


@dataclass(frozen=True)
class CollectorEvidence:
    status: str
    data: Mapping[str, Any]
    diagnostic_code: str | None = None


def parse_service_output(payload: bytes) -> CollectorEvidence:
    lines = _decode_lines(payload, _MAX_SERVICE_BYTES)
    if len(lines) == 1 and "\t" in lines[0]:
        kind, _, code = lines[0].partition("\t")
        expected_status = _SERVICE_DIAGNOSTICS.get(code)
        if (kind == "UNAVAILABLE" and expected_status == "skipped") or (
            kind == "ERROR" and expected_status == "error"
        ):
            return CollectorEvidence(status=expected_status, data={}, diagnostic_code=code)
        raise CollectorParseError("service collector returned an unknown diagnostic")

    parsed: dict[str, Any] = {}
    seen: set[str] = set()
    for line in lines:
        name, separator, value = line.partition("=")
        if not separator or name not in _SERVICE_FIELDS:
            raise CollectorParseError("service collector returned a non-allowlisted property")
        if name in seen:
            raise CollectorParseError("service collector returned a duplicate property")
        seen.add(name)
        output_name, value_type = _SERVICE_FIELDS[name]
        parsed[output_name] = (
            _parse_nonnegative_integer(value) if value_type == "integer" else _parse_state(value)
        )

    if not parsed:
        raise CollectorParseError("service collector returned no evidence")
    if seen != set(_SERVICE_FIELDS):
        raise CollectorParseError("service collector omitted an allowlisted property")
    return CollectorEvidence(status="collected", data=dict(sorted(parsed.items())))


def parse_resource_output(payload: bytes) -> CollectorEvidence:
    lines = _decode_lines(payload, _MAX_RESOURCE_BYTES)
    evidence: dict[str, Any] = {}
    memory: dict[str, int] = {}
    pressure: dict[str, dict[str, dict[str, float | int]]] = {}
    unavailable: list[str] = []
    seen_records: set[tuple[str, ...]] = set()

    for line in lines:
        fields = line.split("\t")
        record_type = fields[0]
        if record_type == "LOAD" and len(fields) == 4:
            _claim_record(seen_records, ("LOAD",))
            evidence["load"] = {
                "1m": _parse_nonnegative_float(fields[1]),
                "5m": _parse_nonnegative_float(fields[2]),
                "15m": _parse_nonnegative_float(fields[3]),
            }
        elif record_type == "MEMORY" and len(fields) == 4:
            key = fields[1]
            if key not in _MEMORY_FIELDS or fields[3] != "kB":
                raise CollectorParseError("resource collector returned an invalid memory field")
            _claim_record(seen_records, ("MEMORY", key))
            kilobytes = _parse_nonnegative_integer(fields[2], maximum=_MAX_INTEGER // 1_024)
            memory[_MEMORY_FIELDS[key]] = kilobytes * 1_024
        elif record_type == "PRESSURE" and len(fields) == 3:
            resource = fields[1]
            if resource not in {"cpu", "memory", "io"}:
                raise CollectorParseError("resource collector returned an unknown pressure source")
            scope, values = _parse_pressure(fields[2])
            _claim_record(seen_records, ("PRESSURE", resource, scope))
            pressure.setdefault(resource, {})[scope] = values
        elif record_type == "FILESYSTEM" and len(fields) == 7:
            _claim_record(seen_records, ("FILESYSTEM",))
            evidence["filesystem"] = _parse_filesystem(fields)
        elif record_type == "UNAVAILABLE" and len(fields) == 2:
            code = fields[1]
            if code not in _RESOURCE_DIAGNOSTICS or code in unavailable:
                raise CollectorParseError("resource collector returned an invalid diagnostic")
            unavailable.append(code)
        else:
            raise CollectorParseError("resource collector returned an unknown record")

    if memory:
        evidence["memory"] = dict(sorted(memory.items()))
    if pressure:
        evidence["pressure"] = {
            resource: dict(sorted(scopes.items())) for resource, scopes in sorted(pressure.items())
        }
    if unavailable:
        evidence["unavailable"] = unavailable
    if not evidence:
        raise CollectorParseError("resource collector returned no evidence")

    _validate_resource_completeness(evidence, memory, pressure, set(unavailable))

    collected_keys = set(evidence) - {"unavailable"}
    if collected_keys:
        return CollectorEvidence(status="collected", data=evidence)
    return CollectorEvidence(
        status="skipped",
        data=evidence,
        diagnostic_code="RESOURCE_EVIDENCE_UNAVAILABLE",
    )


def _decode_lines(payload: bytes, maximum_bytes: int) -> list[str]:
    if not isinstance(payload, bytes) or not payload or len(payload) > maximum_bytes:
        raise CollectorParseError("collector output is empty or exceeds its byte limit")
    try:
        text = payload.decode("ascii")
    except UnicodeError as error:
        raise CollectorParseError("collector output must be ASCII") from error
    lines = text.splitlines()
    if not lines or len(lines) > _MAX_LINES:
        raise CollectorParseError("collector output has an invalid line count")
    if any(not line or len(line.encode("ascii")) > _MAX_LINE_BYTES for line in lines):
        raise CollectorParseError("collector output contains an empty or oversized line")
    if any(ord(character) < 0x20 and character != "\t" for line in lines for character in line):
        raise CollectorParseError("collector output contains a control character")
    return lines


def _parse_state(value: str) -> str:
    if _SAFE_STATE.fullmatch(value) is None:
        raise CollectorParseError("service state contains unsupported characters")
    return value


def _parse_nonnegative_integer(value: str, *, maximum: int = _MAX_INTEGER) -> int:
    if not value.isascii() or not value.isdecimal():
        raise CollectorParseError("collector integer is not a non-negative decimal")
    parsed = int(value)
    if parsed > maximum:
        raise CollectorParseError("collector integer exceeds its bound")
    return parsed


def _parse_nonnegative_float(value: str, *, maximum: float = 1_000_000_000.0) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise CollectorParseError("collector decimal is invalid") from error
    if not math.isfinite(parsed) or not 0 <= parsed <= maximum:
        raise CollectorParseError("collector decimal exceeds its bound")
    return parsed


def _parse_pressure(value: str) -> tuple[str, dict[str, float | int]]:
    fields = value.split()
    if len(fields) != 5 or fields[0] not in {"some", "full"}:
        raise CollectorParseError("pressure record has an invalid shape")
    expected = ("avg10", "avg60", "avg300", "total")
    parsed: dict[str, float | int] = {}
    for token, expected_name in zip(fields[1:], expected, strict=True):
        name, separator, raw_value = token.partition("=")
        if not separator or name != expected_name:
            raise CollectorParseError("pressure record has an unknown field")
        output_name = "total_us" if name == "total" else name
        parsed[output_name] = (
            _parse_nonnegative_integer(raw_value)
            if name == "total"
            else _parse_nonnegative_float(raw_value, maximum=100.0)
        )
    return fields[0], parsed


def _parse_filesystem(fields: list[str]) -> dict[str, int | str]:
    _, target, filesystem_type, size, used, available, used_percent = fields
    if target != "/" or _SAFE_FILESYSTEM_TYPE.fullmatch(filesystem_type) is None:
        raise CollectorParseError("filesystem record has an invalid identity")
    if not used_percent.endswith("%"):
        raise CollectorParseError("filesystem use must be a percentage")
    size_bytes = _parse_nonnegative_integer(size)
    used_bytes = _parse_nonnegative_integer(used)
    available_bytes = _parse_nonnegative_integer(available)
    percentage = _parse_nonnegative_integer(used_percent[:-1], maximum=100)
    if used_bytes > size_bytes or available_bytes > size_bytes:
        raise CollectorParseError("filesystem values are inconsistent")
    return {
        "target": target,
        "filesystem_type": filesystem_type,
        "size_bytes": size_bytes,
        "used_bytes": used_bytes,
        "available_bytes": available_bytes,
        "used_percent": percentage,
    }


def _claim_record(seen: set[tuple[str, ...]], identity: tuple[str, ...]) -> None:
    if identity in seen:
        raise CollectorParseError("resource collector returned a duplicate record")
    seen.add(identity)


def _validate_resource_completeness(
    evidence: Mapping[str, Any],
    memory: Mapping[str, int],
    pressure: Mapping[str, Any],
    unavailable: set[str],
) -> None:
    if ("load" in evidence) == ("LOADAVG_NOT_FOUND" in unavailable):
        raise CollectorParseError("load evidence is missing or contradictory")

    expected_memory = set(_MEMORY_FIELDS.values())
    if memory and set(memory) != expected_memory:
        raise CollectorParseError("memory evidence is incomplete")
    if bool(memory) == ("MEMINFO_NOT_FOUND" in unavailable):
        raise CollectorParseError("memory evidence is missing or contradictory")
    if memory:
        if memory["available_bytes"] > memory["total_bytes"]:
            raise CollectorParseError("memory capacity values are inconsistent")
        if memory["swap_free_bytes"] > memory["swap_total_bytes"]:
            raise CollectorParseError("memory swap values are inconsistent")

    for resource in ("cpu", "memory", "io"):
        diagnostic = f"PRESSURE_{resource.upper()}_NOT_FOUND"
        if (resource in pressure) == (diagnostic in unavailable):
            raise CollectorParseError(f"{resource} pressure evidence is missing or contradictory")

    filesystem_unavailable = bool({"FINDMNT_NOT_FOUND", "FILESYSTEM_QUERY_FAILED"} & unavailable)
    if ("filesystem" in evidence) == filesystem_unavailable:
        raise CollectorParseError("filesystem evidence is missing or contradictory")
