from __future__ import annotations

import json
import os
import re
import selectors
import signal
import subprocess
import time
from collections import Counter
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any

from incident_pack.config import HARD_LIMITS
from incident_pack.redaction import (
    ForbiddenContentError,
    RedactionError,
    RedactionLimitError,
    assert_no_forbidden_content,
    redact_chunks,
)

_DEFAULT_EXECUTABLE = Path("/usr/bin/journalctl")
_SERVICE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@:-]*\.service")
_OUTPUT_FIELDS = "__REALTIME_TIMESTAMP,PRIORITY,_SYSTEMD_UNIT,MESSAGE"
_TRUNCATED_MESSAGE = "[TRUNCATED:MESSAGE_LIMIT]"
_READ_BYTES = 65_536
_JSON_OVERHEAD_BYTES = 8_192
_MAX_TIMESTAMP_MICROSECONDS = 253_402_300_799_999_999


@dataclass(frozen=True)
class JournalCollection:
    status: str
    content: bytes
    record_count: int
    truncated: bool
    truncation_reasons: tuple[str, ...]
    redaction_counts: Mapping[str, int]
    diagnostic_code: str | None = None


class _CollectionFailure(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        truncated: bool = False,
        truncation_reasons: tuple[str, ...] = (),
    ) -> None:
        super().__init__(code)
        self.code = code
        self.truncated = truncated
        self.truncation_reasons = truncation_reasons


@dataclass
class _JournalBuffer:
    service: str
    max_records: int
    max_message_bytes: int
    max_artifact_bytes: int
    content: bytearray = field(default_factory=bytearray)
    record_count: int = 0
    truncation_reasons: list[str] = field(default_factory=list)
    redaction_counts: Counter[str] = field(default_factory=Counter)

    def add(self, raw_line: bytes) -> bool:
        if self.record_count >= self.max_records:
            _append_reason(self.truncation_reasons, "RECORD_LIMIT")
            return False

        record, counts, message_truncated = _parse_record(
            raw_line,
            service=self.service,
            max_message_bytes=self.max_message_bytes,
        )
        if message_truncated:
            _append_reason(self.truncation_reasons, "MESSAGE_LIMIT")
        encoded = _encode_record(record)
        if len(self.content) + len(encoded) > self.max_artifact_bytes:
            _append_reason(self.truncation_reasons, "ARTIFACT_LIMIT")
            return False

        self.content.extend(encoded)
        self.redaction_counts.update(counts)
        self.record_count += 1
        return True

    def finish(self) -> JournalCollection:
        try:
            assert_no_forbidden_content(bytes(self.content))
        except ForbiddenContentError as error:
            raise _CollectionFailure("JOURNAL_REDACTION_FAILED") from error
        return _result(
            status="collected",
            content=bytes(self.content),
            record_count=self.record_count,
            truncated=bool(self.truncation_reasons),
            truncation_reasons=tuple(self.truncation_reasons),
            redaction_counts=self.redaction_counts,
        )


def collect_journal(
    *,
    service: str,
    since_seconds: int,
    max_records: int,
    max_message_bytes: int,
    max_artifact_bytes: int,
    timeout_seconds: int | float,
    _executable: Path = _DEFAULT_EXECUTABLE,
) -> JournalCollection:
    """Collect allowlisted journal records into bounded, redacted NDJSON."""
    _validate_inputs(
        service=service,
        since_seconds=since_seconds,
        max_records=max_records,
        max_message_bytes=max_message_bytes,
        max_artifact_bytes=max_artifact_bytes,
        timeout_seconds=timeout_seconds,
        executable=_executable,
    )
    try:
        process = _start_process(
            executable=_executable,
            service=service,
            since_seconds=since_seconds,
            line_count=max_records + 1,
        )
    except FileNotFoundError:
        return _result(status="skipped", diagnostic_code="JOURNALCTL_NOT_FOUND")
    except OSError:
        return _result(status="error", diagnostic_code="JOURNAL_EXEC_FAILED")

    assert process.stdout is not None
    accumulator = _JournalBuffer(
        service=service,
        max_records=max_records,
        max_message_bytes=max_message_bytes,
        max_artifact_bytes=max_artifact_bytes,
    )
    deadline = time.monotonic() + float(timeout_seconds)
    lines = _bounded_lines(
        process.stdout,
        deadline=deadline,
        max_line_bytes=max_message_bytes * 6 + _JSON_OVERHEAD_BYTES,
    )
    try:
        stopped_early = False
        for raw_line in lines:
            if not accumulator.add(raw_line):
                stopped_early = True
                break
        if stopped_early:
            _terminate(process)
        elif _wait(process, deadline) != 0:
            raise _CollectionFailure("JOURNAL_QUERY_FAILED")
        return accumulator.finish()
    except _CollectionFailure as error:
        _terminate(process)
        return _result(
            status="error",
            diagnostic_code=error.code,
            truncated=error.truncated,
            truncation_reasons=error.truncation_reasons,
        )
    finally:
        lines.close()
        process.stdout.close()
        if process.poll() is None:
            _terminate(process)


def _start_process(
    *, executable: Path, service: str, since_seconds: int, line_count: int
) -> subprocess.Popen[bytes]:
    arguments = [
        str(executable),
        "--no-pager",
        "--quiet",
        "--system",
        "--output=json",
        f"--output-fields={_OUTPUT_FIELDS}",
        f"--unit={service}",
        f"--since=-{since_seconds}s",
        f"--lines={line_count}",
    ]
    return subprocess.Popen(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        start_new_session=True,
    )


def _bounded_lines(stream: Any, *, deadline: float, max_line_bytes: int) -> Iterator[bytes]:
    buffer = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(stream, selectors.EVENT_READ)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise _CollectionFailure("JOURNAL_TIMEOUT")
            chunk = os.read(stream.fileno(), _READ_BYTES)
            if not chunk:
                break
            buffer.extend(chunk)
            while (boundary := buffer.find(b"\n")) >= 0:
                line = bytes(buffer[:boundary])
                del buffer[: boundary + 1]
                _check_line_size(line, max_line_bytes)
                yield line
            _check_line_size(buffer, max_line_bytes)
        if buffer:
            _check_line_size(buffer, max_line_bytes)
            yield bytes(buffer)
    finally:
        selector.close()


def _check_line_size(line: bytes | bytearray, maximum: int) -> None:
    if len(line) > maximum:
        raise _CollectionFailure(
            "JOURNAL_RECORD_TOO_LARGE",
            truncated=True,
            truncation_reasons=("MESSAGE_LIMIT",),
        )


def _wait(process: subprocess.Popen[bytes], deadline: float) -> int:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _CollectionFailure("JOURNAL_TIMEOUT")
    try:
        return process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as error:
        raise _CollectionFailure("JOURNAL_TIMEOUT") from error


def _parse_record(
    raw_line: bytes,
    *,
    service: str,
    max_message_bytes: int,
) -> tuple[dict[str, object], Mapping[str, int], bool]:
    if not raw_line:
        raise _CollectionFailure("JOURNAL_MALFORMED")
    try:
        document = json.loads(
            raw_line,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise _CollectionFailure("JOURNAL_MALFORMED") from error
    if not isinstance(document, dict):
        raise _CollectionFailure("JOURNAL_MALFORMED")

    timestamp = _parse_timestamp(document.get("__REALTIME_TIMESTAMP"))
    priority = _parse_priority(document.get("PRIORITY"))
    unit = document.get("_SYSTEMD_UNIT")
    message = document.get("MESSAGE")
    if timestamp is None or priority is None or unit != service or not isinstance(message, str):
        raise _CollectionFailure("JOURNAL_MALFORMED")

    try:
        encoded_message = message.encode("utf-8")
    except UnicodeEncodeError as error:
        raise _CollectionFailure("JOURNAL_MALFORMED") from error
    if len(encoded_message) > max_message_bytes:
        return _truncated_record(timestamp, priority, service, max_message_bytes)

    try:
        redacted = redact_chunks(
            [encoded_message],
            max_input_bytes=max_message_bytes,
            max_output_bytes=max_message_bytes,
        )
    except RedactionLimitError:
        return _truncated_record(timestamp, priority, service, max_message_bytes)
    except RedactionError as error:
        raise _CollectionFailure("JOURNAL_REDACTION_FAILED") from error
    return (
        _allowlisted_record(timestamp, priority, service, redacted.content.decode("utf-8")),
        redacted.counts,
        False,
    )


def _truncated_record(
    timestamp: str, priority: int, service: str, max_message_bytes: int
) -> tuple[dict[str, object], Mapping[str, int], bool]:
    message = _TRUNCATED_MESSAGE if len(_TRUNCATED_MESSAGE) <= max_message_bytes else ""
    return _allowlisted_record(timestamp, priority, service, message), {}, True


def _allowlisted_record(
    timestamp: str, priority: int, service: str, message: str
) -> dict[str, object]:
    return {
        "message": message,
        "priority": priority,
        "timestamp": timestamp,
        "unit": service,
    }


def _parse_timestamp(value: object) -> str | None:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not value.isdecimal()
        or len(value) > 18
    ):
        return None
    microseconds = int(value)
    if microseconds > _MAX_TIMESTAMP_MICROSECONDS:
        return None
    try:
        timestamp = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=microseconds)
    except OverflowError:
        return None
    return timestamp.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_priority(value: object) -> int | None:
    if not isinstance(value, str) or len(value) != 1 or value not in "01234567":
        return None
    return int(value)


def _encode_record(record: Mapping[str, object]) -> bytes:
    return (
        json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
        + b"\n"
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate JSON key")
        document[key] = value
    return document


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"unsupported JSON constant: {value}")


def _append_reason(reasons: list[str], reason: str) -> None:
    if reason not in reasons:
        reasons.append(reason)


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    finally:
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def _result(
    *,
    status: str,
    content: bytes = b"",
    record_count: int = 0,
    truncated: bool = False,
    truncation_reasons: tuple[str, ...] = (),
    redaction_counts: Mapping[str, int] = MappingProxyType({}),
    diagnostic_code: str | None = None,
) -> JournalCollection:
    return JournalCollection(
        status=status,
        content=content,
        record_count=record_count,
        truncated=truncated,
        truncation_reasons=truncation_reasons,
        redaction_counts=MappingProxyType(dict(sorted(redaction_counts.items()))),
        diagnostic_code=diagnostic_code,
    )


def _validate_inputs(
    *,
    service: str,
    since_seconds: int,
    max_records: int,
    max_message_bytes: int,
    max_artifact_bytes: int,
    timeout_seconds: int | float,
    executable: Path,
) -> None:
    if (
        not isinstance(service, str)
        or len(service) > 255
        or _SERVICE_PATTERN.fullmatch(service) is None
    ):
        raise ValueError("service must be a validated systemd .service name")
    _validate_integer_limit(
        since_seconds,
        "since_seconds",
        minimum=60,
        maximum=HARD_LIMITS["journal_range_seconds"],
    )
    _validate_integer_limit(
        max_records,
        "max_records",
        minimum=1,
        maximum=HARD_LIMITS["max_journal_records"],
    )
    _validate_integer_limit(
        max_message_bytes,
        "max_message_bytes",
        minimum=1,
        maximum=HARD_LIMITS["max_message_bytes"],
    )
    _validate_integer_limit(
        max_artifact_bytes,
        "max_artifact_bytes",
        minimum=1,
        maximum=HARD_LIMITS["max_artifact_bytes"],
    )
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 < timeout_seconds <= HARD_LIMITS["collector_timeout_seconds"]
    ):
        raise ValueError("timeout_seconds must be positive and within the compiled hard maximum")
    if not isinstance(executable, Path) or not executable.is_absolute():
        raise ValueError("journal executable must be an absolute path")


def _validate_integer_limit(value: int, name: str, *, minimum: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer within the compiled bounds")
