from __future__ import annotations

from incident_pack.summary import EvidenceResult, render_summary


def test_summary_prioritises_service_resources_logs_and_connectivity() -> None:
    evidence = (
        EvidenceResult(
            id="service",
            status="collected",
            data={
                "active_state": "active",
                "sub_state": "running",
                "result": "success",
                "restart_count": 2,
            },
        ),
        EvidenceResult(
            id="resources",
            status="collected",
            data={
                "load": {"1m": 0.1, "5m": 0.2, "15m": 0.3},
                "memory": {"available_bytes": 2_000, "total_bytes": 8_000},
                "filesystem": {"used_percent": 40},
                "pressure": {
                    "cpu": {"some": {"avg10": 0.5}},
                    "memory": {"some": {"avg10": 1.0}},
                    "io": {"some": {"avg10": 1.5}},
                },
            },
        ),
        EvidenceResult(
            id="journal",
            status="collected",
            data={"record_count": 12, "error_count": 3},
            redactions={"BEARER_TOKEN": 1},
        ),
        EvidenceResult(
            id="dns",
            status="collected",
            data={"checks": [{"target": "api.example.test", "outcome": "resolved"}]},
        ),
        EvidenceResult(
            id="connectivity",
            status="collected",
            data={"checks": [{"target": "api.example.test", "port": 443, "outcome": "connected"}]},
        ),
    )

    summary = render_summary("nginx.service", 7200, evidence)

    assert summary.startswith("INCIDENT PACK SUMMARY\n")
    assert "Collection status: COMPLETE" in summary
    assert "Service state: active / running; result: success; restarts: 2" in summary
    assert "Journal: 12 records; 3 error-priority records" in summary
    assert "Resources: load 0.10 / 0.20 / 0.30; memory 25.0% available; disk 40% used" in summary
    assert "Pressure (10s): CPU 0.50%; memory 1.00%; I/O 1.50%" in summary
    assert "DNS api.example.test: resolved" in summary
    assert "TCP api.example.test:443: connected" in summary
    assert "Redactions: 1 value across 1 rule" in summary


def test_summary_marks_missing_and_truncated_evidence_as_partial() -> None:
    evidence = (
        EvidenceResult(id="service", status="error", diagnostic_code="SERVICE_QUERY_FAILED"),
        EvidenceResult(
            id="journal",
            status="collected",
            data={"record_count": 1000, "error_count": 0},
            truncated=True,
            truncation_reasons=("RECORD_LIMIT",),
        ),
        EvidenceResult(id="packages", status="excluded", diagnostic_code="EXCLUDED_BY_POLICY"),
    )

    summary = render_summary("nginx.service", 7200, evidence)

    assert "Collection status: PARTIAL" in summary
    assert "Missing evidence:" in summary
    assert "- service: error (SERVICE_QUERY_FAILED)" in summary
    assert "- packages: excluded (EXCLUDED_BY_POLICY)" in summary
    assert "Truncated evidence:" in summary
    assert "- journal: RECORD_LIMIT" in summary
    assert summary.endswith("Inspect the archive before sharing it.\n")
