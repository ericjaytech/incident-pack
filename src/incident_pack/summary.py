from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class EvidenceResult:
    """One bounded evidence result before archive publication."""

    id: str
    status: str
    data: Mapping[str, Any] = field(default_factory=dict)
    path: str | None = None
    content: bytes | None = None
    truncated: bool = False
    truncation_reasons: tuple[str, ...] = ()
    redactions: Mapping[str, int] = field(default_factory=dict)
    diagnostic_code: str | None = None


def render_summary(
    service: str,
    since_seconds: int,
    evidence: Sequence[EvidenceResult],
) -> str:
    """Render a concise deterministic escalation summary."""
    by_id = {result.id: result for result in evidence}
    partial = any(result.status != "collected" or result.truncated for result in evidence)
    lines = [
        "INCIDENT PACK SUMMARY",
        "=====================",
        f"Service: {service}",
        f"Journal range: {since_seconds} seconds",
        f"Collection status: {'PARTIAL' if partial else 'COMPLETE'}",
        "",
        *_service_lines(by_id.get("service")),
        *_journal_lines(by_id.get("journal")),
        *_resource_lines(by_id.get("resources")),
        *_network_lines(by_id.get("dns"), by_id.get("connectivity")),
    ]

    missing = [result for result in evidence if result.status != "collected"]
    if missing:
        lines.extend(["", "Missing evidence:"])
        for result in missing:
            diagnostic = f" ({result.diagnostic_code})" if result.diagnostic_code else ""
            lines.append(f"- {result.id}: {result.status}{diagnostic}")

    truncated = [result for result in evidence if result.truncated]
    if truncated:
        lines.extend(["", "Truncated evidence:"])
        for result in truncated:
            reasons = ", ".join(result.truncation_reasons) or "LIMIT_REACHED"
            lines.append(f"- {result.id}: {reasons}")

    redactions: Counter[str] = Counter()
    for result in evidence:
        redactions.update(result.redactions)
    total_redactions = sum(redactions.values())
    rule_label = "rule" if len(redactions) == 1 else "rules"
    value_label = "value" if total_redactions == 1 else "values"
    lines.extend(
        [
            "",
            f"Redactions: {total_redactions} {value_label} across {len(redactions)} {rule_label}",
            "Inspect the archive before sharing it.",
        ]
    )
    return "\n".join(lines) + "\n"


def _service_lines(result: EvidenceResult | None) -> list[str]:
    if result is None or result.status != "collected":
        return ["Service state: unavailable"]
    data = result.data
    return [
        "Service state: "
        f"{data.get('active_state', 'unknown')} / {data.get('sub_state', 'unknown')}; "
        f"result: {data.get('result', 'unknown')}; restarts: {data.get('restart_count', 'unknown')}"
    ]


def _journal_lines(result: EvidenceResult | None) -> list[str]:
    if result is None or result.status != "collected":
        return ["Journal: unavailable"]
    records = result.data.get("record_count", 0)
    errors = result.data.get("error_count", 0)
    return [f"Journal: {records} records; {errors} error-priority records"]


def _resource_lines(result: EvidenceResult | None) -> list[str]:
    if result is None or result.status != "collected":
        return ["Resources: unavailable"]
    data = result.data
    load = data.get("load", {})
    memory = data.get("memory", {})
    filesystem = data.get("filesystem", {})
    try:
        available_percent = 100 * memory["available_bytes"] / memory["total_bytes"]
        line = (
            f"Resources: load {load['1m']:.2f} / {load['5m']:.2f} / {load['15m']:.2f}; "
            f"memory {available_percent:.1f}% available; disk {filesystem['used_percent']}% used"
        )
    except (KeyError, TypeError, ZeroDivisionError):
        line = "Resources: partial metrics; inspect evidence/resources.json"
    lines = [line]
    pressure = data.get("pressure", {})
    try:
        lines.append(
            "Pressure (10s): "
            f"CPU {pressure['cpu']['some']['avg10']:.2f}%; "
            f"memory {pressure['memory']['some']['avg10']:.2f}%; "
            f"I/O {pressure['io']['some']['avg10']:.2f}%"
        )
    except (KeyError, TypeError):
        pass
    return lines


def _network_lines(
    dns: EvidenceResult | None,
    connectivity: EvidenceResult | None,
) -> list[str]:
    lines: list[str] = []
    if dns is not None and dns.status == "collected":
        for check in dns.data.get("checks", []):
            lines.append(f"DNS {check['target']}: {check['outcome']}")
    if connectivity is not None and connectivity.status == "collected":
        for check in connectivity.data.get("checks", []):
            lines.append(f"TCP {check['target']}:{check['port']}: {check['outcome']}")
    return lines
