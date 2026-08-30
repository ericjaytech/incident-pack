from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any

from incident_pack.archive import Artifact, ArtifactStatus, create_bundle
from incident_pack.collection.system_parser import (
    CollectorEvidence,
    CollectorParseError,
    parse_resource_output,
    parse_service_output,
)
from incident_pack.collectors.configuration import (
    ConfigurationCollection,
    collect_configuration,
)
from incident_pack.collectors.journal import collect_journal
from incident_pack.collectors.network import (
    NetworkCheck,
    check_dns,
    check_tcp,
    collect_resolver_metadata,
)
from incident_pack.collectors.packages import collect_packages
from incident_pack.plan import EvidencePlan
from incident_pack.summary import EvidenceResult, render_summary

_ARTIFACT_PATHS = {
    "service": "evidence/service.json",
    "resources": "evidence/resources.json",
    "journal": "evidence/journal.ndjson",
    "packages": "evidence/packages.json",
    "configuration": "evidence/configuration.json",
    "dns": "evidence/dns.json",
    "connectivity": "evidence/connectivity.json",
}


def collect_bundle(plan: EvidencePlan, output: Path) -> str:
    """Collect the compiled evidence plan and publish one verified archive."""
    started_at = datetime.now(UTC)
    results = _collect_plan(plan)
    summary = render_summary(plan.service, plan.since_seconds, results).encode("utf-8")
    artifacts = [Artifact(id="summary", path="summary.txt", content=summary)]
    statuses: list[ArtifactStatus] = []
    for result in results:
        if result.status == "collected":
            if result.path is None or result.content is None:
                raise RuntimeError("collected evidence omitted its archive content")
            artifacts.append(
                Artifact(
                    id=result.id,
                    path=result.path,
                    content=result.content,
                    truncated=result.truncated,
                    redactions=result.redactions,
                )
            )
        else:
            statuses.append(
                ArtifactStatus(
                    id=result.id,
                    status=result.status,
                    diagnostic_code=result.diagnostic_code or "COLLECTOR_FAILED",
                )
            )

    return create_bundle(
        output,
        service=plan.service,
        since_seconds=plan.since_seconds,
        privilege=plan.privilege,
        started_at=started_at,
        finished_at=datetime.now(UTC),
        artifacts=artifacts,
        artifact_statuses=statuses,
        exclusions=plan.exclusion_patterns,
        known_limitations=(
            *plan.limitations,
            "Redaction reduces disclosure risk but does not make a bundle safe to share "
            "without review.",
        ),
        limits=plan.limits,
    )


def _collect_plan(plan: EvidencePlan) -> tuple[EvidenceResult, ...]:
    configuration = _configuration_dependency(plan)
    results: list[EvidenceResult] = []
    for artifact in plan.artifacts:
        if artifact.state == "not-requested" or artifact.artifact_id == "summary":
            continue
        if artifact.state == "excluded":
            results.append(
                EvidenceResult(
                    id=artifact.artifact_id,
                    status="excluded",
                    diagnostic_code="EXCLUDED_BY_POLICY",
                )
            )
            continue
        results.append(_collect_artifact(artifact.artifact_id, plan, configuration))
    return tuple(results)


def _configuration_dependency(plan: EvidencePlan) -> ConfigurationCollection | None:
    relevant = {
        artifact.artifact_id: artifact.state
        for artifact in plan.artifacts
        if artifact.artifact_id in {"packages", "configuration"}
    }
    if all(state == "excluded" for state in relevant.values()):
        return None
    return collect_configuration(
        service=plan.service,
        timeout_seconds=plan.limits["collector_timeout_seconds"],
    )


def _collect_artifact(
    artifact_id: str,
    plan: EvidencePlan,
    configuration: ConfigurationCollection | None,
) -> EvidenceResult:
    if artifact_id == "service":
        return _structured_result("service", _collect_service(plan))
    if artifact_id == "resources":
        return _structured_result("resources", _collect_resources(plan))
    if artifact_id == "journal":
        return _journal_result(plan)
    if artifact_id == "packages":
        paths = (
            ()
            if configuration is None
            else tuple(Path(item["path"]) for item in configuration.files)
        )
        result = collect_packages(
            paths=paths,
            timeout_seconds=plan.limits["collector_timeout_seconds"],
        )
        return _result(
            "packages",
            status=result.status,
            data={"packages": result.packages},
            diagnostic_code=result.diagnostic_code,
        )
    if artifact_id == "configuration":
        if configuration is None:
            return EvidenceResult(
                id="configuration",
                status="skipped",
                diagnostic_code="CONFIGURATION_NOT_REQUESTED",
            )
        return _result(
            "configuration",
            status=configuration.status,
            data={"files": configuration.files},
            diagnostic_code=configuration.diagnostic_code,
        )
    if artifact_id == "dns":
        return _dns_result(plan)
    if artifact_id == "connectivity":
        return _connectivity_result(plan)
    raise RuntimeError(f"unsupported planned artifact: {artifact_id}")


def _collect_service(plan: EvidencePlan) -> CollectorEvidence:
    return _collect_script(
        "service.sh",
        (plan.service,),
        parser=parse_service_output,
        timeout_seconds=plan.limits["collector_timeout_seconds"],
        maximum_bytes=8_192,
        failure_code="SERVICE_COLLECTOR_FAILED",
        timeout_code="SERVICE_COLLECTOR_TIMEOUT",
    )


def _collect_resources(plan: EvidencePlan) -> CollectorEvidence:
    return _collect_script(
        "resources.sh",
        (),
        parser=parse_resource_output,
        timeout_seconds=plan.limits["collector_timeout_seconds"],
        maximum_bytes=65_536,
        failure_code="RESOURCE_COLLECTOR_FAILED",
        timeout_code="RESOURCE_COLLECTOR_TIMEOUT",
    )


def _collect_script(
    name: str,
    arguments: Sequence[str],
    *,
    parser: Callable[[bytes], CollectorEvidence],
    timeout_seconds: int,
    maximum_bytes: int,
    failure_code: str,
    timeout_code: str,
) -> CollectorEvidence:
    resource = files("incident_pack.collectors").joinpath(name)
    try:
        with as_file(resource) as executable:
            completed = subprocess.run(
                [str(executable), *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                check=False,
                timeout=timeout_seconds,
            )
    except subprocess.TimeoutExpired:
        return CollectorEvidence(status="error", data={}, diagnostic_code=timeout_code)
    except (FileNotFoundError, OSError):
        return CollectorEvidence(status="error", data={}, diagnostic_code=failure_code)
    if completed.returncode != 0 or len(completed.stdout) > maximum_bytes:
        return CollectorEvidence(status="error", data={}, diagnostic_code=failure_code)
    try:
        return parser(completed.stdout)
    except CollectorParseError:
        return CollectorEvidence(status="error", data={}, diagnostic_code=failure_code)


def _journal_result(plan: EvidencePlan) -> EvidenceResult:
    result = collect_journal(
        service=plan.service,
        since_seconds=plan.since_seconds,
        max_records=plan.limits["max_journal_records"],
        max_message_bytes=plan.limits["max_message_bytes"],
        max_artifact_bytes=plan.limits["max_artifact_bytes"],
        timeout_seconds=plan.limits["collector_timeout_seconds"],
    )
    return _result(
        "journal",
        status=result.status,
        data={
            "record_count": result.record_count,
            "error_count": _count_error_records(result.content),
        },
        content=result.content,
        truncated=result.truncated,
        truncation_reasons=result.truncation_reasons,
        redactions=result.redaction_counts,
        diagnostic_code=result.diagnostic_code,
    )


def _dns_result(plan: EvidencePlan) -> EvidenceResult:
    resolver = collect_resolver_metadata()
    if resolver.status != "collected":
        return EvidenceResult(
            id="dns",
            status=resolver.status,
            diagnostic_code=resolver.diagnostic_code or "RESOLVER_CONFIGURATION_UNAVAILABLE",
        )
    checks = tuple(
        check_dns(target, timeout_seconds=plan.limits["collector_timeout_seconds"])
        for target in plan.dns_targets
    )
    failed = next((check for check in checks if check.status == "error"), None)
    if failed is not None:
        return EvidenceResult(
            id="dns",
            status="error",
            diagnostic_code=failed.diagnostic_code or "NETWORK_WORKER_FAILED",
        )
    return _result(
        "dns",
        status="collected",
        data={
            "resolver": {
                "status": resolver.status,
                "data": resolver.data,
                "diagnostic_code": resolver.diagnostic_code,
            },
            "checks": tuple(_network_document(check) for check in checks),
        },
    )


def _connectivity_result(plan: EvidencePlan) -> EvidenceResult:
    checks = tuple(
        check_tcp(
            target,
            port,
            timeout_seconds=plan.limits["collector_timeout_seconds"],
        )
        for target, port in plan.connect_targets
    )
    failed = next((check for check in checks if check.status == "error"), None)
    if failed is not None:
        return EvidenceResult(
            id="connectivity",
            status="error",
            diagnostic_code=failed.diagnostic_code or "NETWORK_WORKER_FAILED",
        )
    return _result(
        "connectivity",
        status="collected",
        data={"checks": tuple(_network_document(check) for check in checks)},
    )


def _structured_result(artifact_id: str, evidence: CollectorEvidence) -> EvidenceResult:
    return _result(
        artifact_id,
        status=evidence.status,
        data=evidence.data,
        diagnostic_code=evidence.diagnostic_code,
    )


def _result(
    artifact_id: str,
    *,
    status: str,
    data: Mapping[str, Any],
    content: bytes | None = None,
    truncated: bool = False,
    truncation_reasons: Sequence[str] = (),
    redactions: Mapping[str, int] | None = None,
    diagnostic_code: str | None = None,
) -> EvidenceResult:
    return EvidenceResult(
        id=artifact_id,
        status=status,
        data=data,
        path=_ARTIFACT_PATHS[artifact_id] if status == "collected" else None,
        content=(content if content is not None else _json_bytes(data))
        if status == "collected"
        else None,
        truncated=truncated,
        truncation_reasons=tuple(truncation_reasons),
        redactions={} if redactions is None else redactions,
        diagnostic_code=diagnostic_code,
    )


def _network_document(check: NetworkCheck) -> Mapping[str, Any]:
    return {
        "address_families": check.address_families,
        "address_scopes": check.address_scopes,
        "diagnostic_code": check.diagnostic_code,
        "elapsed_ms": check.elapsed_ms,
        "outcome": check.outcome,
        "port": check.port,
        "target": check.target,
    }


def _json_bytes(value: object) -> bytes:
    return (json.dumps(_plain(value), indent=2, sort_keys=True) + "\n").encode("utf-8")


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _count_error_records(content: bytes) -> int:
    count = 0
    for line in content.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        priority = record.get("priority")
        if isinstance(priority, int) and not isinstance(priority, bool) and priority <= 3:
            count += 1
    return count
