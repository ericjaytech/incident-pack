from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from incident_pack.collection.system_parser import CollectorParseError, parse_service_output

SERVICE_SCRIPT = Path(__file__).parents[2] / "src/incident_pack/collectors/service.sh"


def test_parse_service_output_retains_only_allowlisted_typed_properties() -> None:
    payload = b"""\
LoadState=loaded
ActiveState=active
SubState=running
UnitFileState=enabled
Type=notify
MainPID=412
ExecMainStatus=0
Result=success
NRestarts=2
ActiveEnterTimestampMonotonic=987654321
"""

    result = parse_service_output(payload)

    assert result.status == "collected"
    assert result.diagnostic_code is None
    assert result.data == {
        "active_enter_timestamp_monotonic_us": 987654321,
        "active_state": "active",
        "exec_main_status": 0,
        "load_state": "loaded",
        "main_pid": 412,
        "restart_count": 2,
        "result": "success",
        "service_type": "notify",
        "sub_state": "running",
        "unit_file_state": "enabled",
    }


@pytest.mark.parametrize(
    "payload",
    [
        b"Description=must not be retained\n",
        b"Environment=PASSWORD=must-not-be-retained\n",
        b"ActiveState=active\nActiveState=failed\n",
        b"ActiveState=active\n",
        b"MainPID=not-a-number\n",
        b"ActiveState=active\x1b[31m\n",
        b"A" * 8_193,
    ],
)
def test_parse_service_output_rejects_unknown_duplicate_or_malformed_facts(
    payload: bytes,
) -> None:
    with pytest.raises(CollectorParseError):
        parse_service_output(payload)


@pytest.mark.parametrize(
    ("payload", "status", "code"),
    [
        (b"UNAVAILABLE\tSYSTEMCTL_NOT_FOUND\n", "skipped", "SYSTEMCTL_NOT_FOUND"),
        (b"ERROR\tSERVICE_QUERY_FAILED\n", "error", "SERVICE_QUERY_FAILED"),
    ],
)
def test_parse_service_output_preserves_scoped_failure_codes(
    payload: bytes, status: str, code: str
) -> None:
    result = parse_service_output(payload)

    assert result.status == status
    assert result.diagnostic_code == code
    assert result.data == {}


@pytest.mark.skipif(not Path("/usr/bin/bash").exists(), reason="requires Bash")
def test_service_script_never_interprets_service_input_as_shell_syntax(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    hostile_service = f"missing.service;touch {marker}"

    completed = subprocess.run(
        [str(SERVICE_SCRIPT), hostile_service],
        check=False,
        capture_output=True,
        timeout=5,
    )

    assert completed.returncode == 0
    result = parse_service_output(completed.stdout)
    assert result.status in {"collected", "skipped", "error"}
    assert completed.stderr == b""
    assert not marker.exists()
