from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from incident_pack.collection.system_parser import CollectorParseError, parse_resource_output

RESOURCE_SCRIPT = Path(__file__).parents[2] / "src/incident_pack/collectors/resources.sh"


def test_parse_resource_output_returns_numeric_allowlisted_evidence() -> None:
    payload = b"""\
LOAD\t0.10\t0.20\t0.30
MEMORY\tMemTotal\t16384\tkB
MEMORY\tMemAvailable\t8192\tkB
MEMORY\tSwapTotal\t4096\tkB
MEMORY\tSwapFree\t2048\tkB
PRESSURE\tcpu\tsome avg10=0.00 avg60=0.10 avg300=0.20 total=1234
PRESSURE\tmemory\tfull avg10=1.00 avg60=2.00 avg300=3.00 total=5678
UNAVAILABLE\tPRESSURE_IO_NOT_FOUND
FILESYSTEM\t/\text4\t100000\t40000\t60000\t40%
"""

    result = parse_resource_output(payload)

    assert result.status == "collected"
    assert result.diagnostic_code is None
    assert result.data["load"] == {"1m": 0.1, "5m": 0.2, "15m": 0.3}
    assert result.data["memory"] == {
        "available_bytes": 8_388_608,
        "swap_free_bytes": 2_097_152,
        "swap_total_bytes": 4_194_304,
        "total_bytes": 16_777_216,
    }
    assert result.data["pressure"]["cpu"]["some"]["total_us"] == 1234
    assert result.data["filesystem"] == {
        "available_bytes": 60000,
        "filesystem_type": "ext4",
        "size_bytes": 100000,
        "target": "/",
        "used_bytes": 40000,
        "used_percent": 40,
    }


def test_parse_resource_output_keeps_missing_capabilities_explicit() -> None:
    result = parse_resource_output(
        b"UNAVAILABLE\tLOADAVG_NOT_FOUND\n"
        b"UNAVAILABLE\tMEMINFO_NOT_FOUND\n"
        b"UNAVAILABLE\tPRESSURE_CPU_NOT_FOUND\n"
        b"UNAVAILABLE\tPRESSURE_MEMORY_NOT_FOUND\n"
        b"UNAVAILABLE\tPRESSURE_IO_NOT_FOUND\n"
        b"UNAVAILABLE\tFILESYSTEM_QUERY_FAILED\n"
    )

    assert result.status == "skipped"
    assert result.diagnostic_code == "RESOURCE_EVIDENCE_UNAVAILABLE"
    assert result.data == {
        "unavailable": [
            "LOADAVG_NOT_FOUND",
            "MEMINFO_NOT_FOUND",
            "PRESSURE_CPU_NOT_FOUND",
            "PRESSURE_MEMORY_NOT_FOUND",
            "PRESSURE_IO_NOT_FOUND",
            "FILESYSTEM_QUERY_FAILED",
        ]
    }


def test_parse_resource_output_rejects_a_source_that_silently_disappears() -> None:
    payload = b"""\
LOAD\t0.10\t0.20\t0.30
MEMORY\tMemTotal\t16384\tkB
MEMORY\tMemAvailable\t8192\tkB
MEMORY\tSwapTotal\t4096\tkB
MEMORY\tSwapFree\t2048\tkB
PRESSURE\tcpu\tsome avg10=0 avg60=0 avg300=0 total=1
PRESSURE\tmemory\tsome avg10=0 avg60=0 avg300=0 total=1
PRESSURE\tio\tsome avg10=0 avg60=0 avg300=0 total=1
"""

    with pytest.raises(CollectorParseError, match="filesystem"):
        parse_resource_output(payload)


def test_parse_resource_output_rejects_inconsistent_memory_capacity() -> None:
    payload = b"""\
LOAD\t0.10\t0.20\t0.30
MEMORY\tMemTotal\t100\tkB
MEMORY\tMemAvailable\t101\tkB
MEMORY\tSwapTotal\t50\tkB
MEMORY\tSwapFree\t51\tkB
UNAVAILABLE\tPRESSURE_CPU_NOT_FOUND
UNAVAILABLE\tPRESSURE_MEMORY_NOT_FOUND
UNAVAILABLE\tPRESSURE_IO_NOT_FOUND
UNAVAILABLE\tFILESYSTEM_QUERY_FAILED
"""

    with pytest.raises(CollectorParseError, match="memory"):
        parse_resource_output(payload)


@pytest.mark.parametrize(
    "payload",
    [
        b"LOAD\tnan\t0.2\t0.3\n",
        b"MEMORY\tCached\t123\tkB\n",
        b"MEMORY\tMemTotal\t-1\tkB\n",
        b"PRESSURE\tcpu\tsome avg10=0 avg60=0 avg300=0 total=oops\n",
        b"FILESYSTEM\t/\text4\t10\t11\t0\t110%\n",
        b"HOSTNAME\tshould-never-appear\n",
        b"LOAD\t0.1\t0.2\t0.3\n" * 33,
    ],
)
def test_parse_resource_output_rejects_non_numeric_unknown_or_unbounded_facts(
    payload: bytes,
) -> None:
    with pytest.raises(CollectorParseError):
        parse_resource_output(payload)


@pytest.mark.skipif(
    not Path("/usr/bin/bash").exists() or not Path("/proc/loadavg").exists(),
    reason="requires Linux procfs and Bash",
)
def test_resource_script_output_obeys_the_strict_parser_contract() -> None:
    completed = subprocess.run(
        [str(RESOURCE_SCRIPT)],
        check=False,
        capture_output=True,
        timeout=5,
    )

    assert completed.returncode == 0
    assert completed.stderr == b""
    assert len(completed.stdout) <= 65_536
    result = parse_resource_output(completed.stdout)
    assert result.status in {"collected", "skipped"}
    assert set(result.data) <= {"load", "memory", "pressure", "filesystem", "unavailable"}
