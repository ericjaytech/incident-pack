from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from incident_pack.collectors.journal import collect_journal


def _journal_record(message: str, **extra: object) -> dict[str, object]:
    return {
        "__REALTIME_TIMESTAMP": "1788105600123456",
        "PRIORITY": "3",
        "_SYSTEMD_UNIT": "nginx.service",
        "MESSAGE": message,
        **extra,
    }


def _payload(*records: dict[str, object]) -> bytes:
    return b"".join(
        json.dumps(record, ensure_ascii=False).encode("utf-8") + b"\n" for record in records
    )


def _fake_journalctl(
    tmp_path: Path,
    *,
    payload: bytes = b"",
    stderr: bytes = b"",
    exit_code: int = 0,
    delay_seconds: float = 0,
    delay_after_stdout_seconds: float = 0,
    expected_arguments: list[str] | None = None,
    expected_environment: set[str] | None = None,
) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    executable = tmp_path / "journalctl"
    encoded_stdout = base64.b64encode(payload).decode("ascii")
    encoded_stderr = base64.b64encode(stderr).decode("ascii")
    script = f"""#!/usr/bin/python3
import base64
import os
import sys
import time

expected = {expected_arguments!r}
if expected is not None and sys.argv[1:] != expected:
    sys.exit(97)
expected_environment = {expected_environment!r}
if expected_environment is not None and set(os.environ) != expected_environment:
    sys.exit(98)
time.sleep({delay_seconds!r})
sys.stdout.buffer.write(base64.b64decode({encoded_stdout!r}))
sys.stdout.buffer.flush()
time.sleep({delay_after_stdout_seconds!r})
sys.stderr.buffer.write(base64.b64decode({encoded_stderr!r}))
sys.exit({exit_code!r})
"""
    executable.write_text(script, encoding="utf-8")
    executable.chmod(0o755)
    return executable


def _collect(executable: Path, **overrides: object):
    arguments = {
        "service": "nginx.service",
        "since_seconds": 7_200,
        "max_records": 10,
        "max_message_bytes": 8_192,
        "max_artifact_bytes": 65_536,
        "timeout_seconds": 2,
        "_executable": executable,
    }
    arguments.update(overrides)
    return collect_journal(**arguments)


def test_journal_collector_uses_fixed_arguments_and_a_minimal_environment(tmp_path: Path) -> None:
    expected = [
        "--no-pager",
        "--quiet",
        "--system",
        "--output=json",
        "--output-fields=__REALTIME_TIMESTAMP,PRIORITY,_SYSTEMD_UNIT,MESSAGE",
        "--unit=nginx.service",
        "--since=-7200s",
        "--lines=11",
    ]
    executable = _fake_journalctl(
        tmp_path,
        payload=_payload(_journal_record("service started")),
        expected_arguments=expected,
        expected_environment={"LC_ALL", "PATH"},
    )

    result = _collect(executable)

    assert result.status == "collected"
    assert result.diagnostic_code is None
    assert result.record_count == 1


def test_journal_collector_retains_only_allowlisted_fields_and_redacts_messages(
    tmp_path: Path,
) -> None:
    secret = "correct-horse-battery-staple"
    executable = _fake_journalctl(
        tmp_path,
        payload=_payload(
            _journal_record(
                f"login password={secret} from 192.0.2.44",
                _HOSTNAME="private-host",
                _CMDLINE="worker --token raw-command-secret",
                _EXE="/private/bin/worker",
                _ENVIRONMENT="PASSWORD=raw-environment-secret",
            )
        ),
    )

    result = _collect(executable)
    retained = json.loads(result.content)

    assert result.status == "collected"
    assert retained == {
        "message": "login password=[REDACTED:CREDENTIAL] from [REDACTED:IP_ADDRESS]",
        "priority": 3,
        "timestamp": "2026-08-30T16:00:00.123456Z",
        "unit": "nginx.service",
    }
    assert result.redaction_counts == {"CREDENTIAL": 1, "IP_ADDRESS": 1}
    assert secret.encode() not in result.content
    assert b"private-host" not in result.content
    assert b"raw-command-secret" not in result.content
    assert b"raw-environment-secret" not in result.content


def test_journal_collector_rejects_an_invalid_service_before_starting_a_process(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "must-not-run"

    with pytest.raises(ValueError, match="service"):
        _collect(executable, service="nginx.service;id")


def test_journal_collector_enforces_the_record_limit_independently(tmp_path: Path) -> None:
    executable = _fake_journalctl(
        tmp_path,
        payload=_payload(
            _journal_record("first"),
            _journal_record("second"),
            _journal_record("must not be retained"),
        ),
    )

    result = _collect(executable, max_records=2)

    assert result.status == "collected"
    assert result.record_count == 2
    assert result.truncated is True
    assert result.truncation_reasons == ("RECORD_LIMIT",)
    assert b"must not be retained" not in result.content


def test_journal_collector_replaces_an_oversized_message_without_leaking_it(
    tmp_path: Path,
) -> None:
    secret = "password=oversized-secret-" + ("x" * 100)
    executable = _fake_journalctl(tmp_path, payload=_payload(_journal_record(secret)))

    result = _collect(executable, max_message_bytes=32)
    retained = json.loads(result.content)

    assert result.status == "collected"
    assert result.truncated is True
    assert result.truncation_reasons == ("MESSAGE_LIMIT",)
    assert retained["message"] == "[TRUNCATED:MESSAGE_LIMIT]"
    assert b"oversized-secret" not in result.content


def test_journal_collector_enforces_the_artifact_limit_before_appending_a_record(
    tmp_path: Path,
) -> None:
    executable = _fake_journalctl(
        tmp_path,
        payload=_payload(_journal_record("first"), _journal_record("second")),
    )
    first_only = _collect(
        _fake_journalctl(tmp_path / "first", payload=_payload(_journal_record("first")))
    )

    result = _collect(executable, max_artifact_bytes=len(first_only.content))

    assert result.status == "collected"
    assert result.content == first_only.content
    assert result.record_count == 1
    assert result.truncated is True
    assert result.truncation_reasons == ("ARTIFACT_LIMIT",)


def test_journal_collector_times_out_without_retaining_partial_output(tmp_path: Path) -> None:
    executable = _fake_journalctl(
        tmp_path,
        payload=_payload(_journal_record("must not survive timeout")),
        delay_after_stdout_seconds=1,
    )

    result = _collect(executable, timeout_seconds=0.05)

    assert result.status == "error"
    assert result.diagnostic_code == "JOURNAL_TIMEOUT"
    assert result.content == b""
    assert result.record_count == 0


def test_journal_collector_rejects_a_raw_record_before_unbounded_json_parsing(
    tmp_path: Path,
) -> None:
    executable = _fake_journalctl(tmp_path, payload=b"{" + (b"x" * 8_500) + b"}\n")

    result = _collect(executable, max_message_bytes=32)

    assert result.status == "error"
    assert result.diagnostic_code == "JOURNAL_RECORD_TOO_LARGE"
    assert result.truncated is True
    assert result.truncation_reasons == ("MESSAGE_LIMIT",)
    assert result.content == b""


def test_journal_collector_maps_missing_executable_and_failed_query_without_stderr_leakage(
    tmp_path: Path,
) -> None:
    missing = _collect(tmp_path / "missing-journalctl")
    failing = _collect(
        _fake_journalctl(
            tmp_path,
            stderr=b"permission denied for /home/private-user and password=raw-secret",
            exit_code=1,
        )
    )

    assert missing.status == "skipped"
    assert missing.diagnostic_code == "JOURNALCTL_NOT_FOUND"
    assert failing.status == "error"
    assert failing.diagnostic_code == "JOURNAL_QUERY_FAILED"
    assert failing.content == b""
    assert "private-user" not in repr(failing)
    assert "raw-secret" not in repr(failing)


@pytest.mark.parametrize(
    "payload",
    [
        b"not-json\n",
        _payload(_journal_record("message", _SYSTEMD_UNIT="other.service")),
        _payload(_journal_record("message", PRIORITY="8")),
        _payload(_journal_record("message", __REALTIME_TIMESTAMP="not-a-timestamp")),
        _payload({"MESSAGE": "missing required fields"}),
    ],
)
def test_journal_collector_rejects_malformed_records_without_retaining_them(
    tmp_path: Path, payload: bytes
) -> None:
    result = _collect(_fake_journalctl(tmp_path, payload=payload))

    assert result.status == "error"
    assert result.diagnostic_code == "JOURNAL_MALFORMED"
    assert result.content == b""
    assert result.record_count == 0
