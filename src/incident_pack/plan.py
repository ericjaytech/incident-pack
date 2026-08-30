from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from types import MappingProxyType

from incident_pack.config import HARD_LIMITS, IncidentConfig


class PlanError(ValueError):
    """Raised when an evidence plan would be ambiguous or unsafe."""


class PrivilegeError(RuntimeError):
    """Raised when collection as root has not been explicitly acknowledged."""


@dataclass(frozen=True)
class ArtifactDefinition:
    logical_id: str
    artifact_id: str
    description: str
    action_template: str
    mandatory: bool = False
    requires_target: str | None = None


@dataclass(frozen=True)
class ExclusionPolicy:
    patterns: tuple[str, ...]
    excluded_ids: tuple[str, ...]


@dataclass(frozen=True)
class PlannedArtifact:
    logical_id: str
    artifact_id: str
    description: str
    action: str
    state: str


@dataclass(frozen=True)
class EvidencePlan:
    service: str
    since_seconds: int
    privilege: str
    root_acknowledged: bool
    collection_allowed: bool
    limits: MappingProxyType[str, int]
    exclusion_patterns: tuple[str, ...]
    excluded_ids: tuple[str, ...]
    artifacts: tuple[PlannedArtifact, ...]
    dns_targets: tuple[str, ...]
    connect_targets: tuple[tuple[str, int], ...]
    limitations: tuple[str, ...]


ARTIFACT_CATALOGUE = (
    ArtifactDefinition(
        "summary",
        "summary",
        "Human-readable escalation summary",
        "internal summary renderer",
        mandatory=True,
    ),
    ArtifactDefinition(
        "service.status",
        "service",
        "Allowlisted systemd service properties",
        "systemctl show --property=<allowlist> -- {service}",
    ),
    ArtifactDefinition(
        "resources.pressure",
        "resources",
        "CPU, memory and disk pressure",
        "allowlisted /proc fields and structured findmnt output",
    ),
    ArtifactDefinition(
        "logs.journal",
        "journal",
        "Bounded recent service journal records",
        "journalctl --unit {service} --since {since_seconds}s --output=json "
        "--lines {max_journal_records}",
    ),
    ArtifactDefinition(
        "packages.metadata",
        "packages",
        "Installed package metadata",
        "dpkg-query package metadata only",
    ),
    ArtifactDefinition(
        "configuration.metadata",
        "configuration",
        "Service-unit metadata and checksums",
        "service-unit file metadata and SHA-256 only",
    ),
    ArtifactDefinition(
        "network.dns",
        "dns",
        "Explicit DNS checks",
        "Python resolver for {dns_target_count} explicit target(s)",
        requires_target="dns",
    ),
    ArtifactDefinition(
        "network.connectivity",
        "connectivity",
        "Explicit bounded TCP checks",
        "Python TCP connect for {connect_target_count} explicit target(s); no payload",
        requires_target="connect",
    ),
)


def compile_exclusions(patterns: Sequence[str]) -> ExclusionPolicy:
    unique_patterns: list[str] = []
    for pattern in patterns:
        _validate_pattern(pattern)
        if pattern not in unique_patterns:
            unique_patterns.append(pattern)
    if len(unique_patterns) > 32:
        raise PlanError("at most 32 exclusion patterns are allowed")

    excluded: set[str] = set()
    for pattern in unique_patterns:
        matches = [item for item in ARTIFACT_CATALOGUE if fnmatchcase(item.logical_id, pattern)]
        if not matches:
            raise PlanError(f"exclusion pattern does not match a known artifact: {pattern!r}")
        if any(item.mandatory for item in matches):
            raise PlanError(f"exclusion pattern matches a mandatory artifact: {pattern!r}")
        excluded.update(item.logical_id for item in matches)

    ordered = tuple(item.logical_id for item in ARTIFACT_CATALOGUE if item.logical_id in excluded)
    return ExclusionPolicy(patterns=tuple(unique_patterns), excluded_ids=ordered)


def compile_plan(
    *,
    service: str,
    since_seconds: int | None,
    config: IncidentConfig,
    cli_exclusions: Sequence[str],
    dns_targets: Sequence[str],
    connect_targets: Sequence[tuple[str, int]],
    allow_root: bool,
    effective_uid: int | None = None,
) -> EvidencePlan:
    if len(dns_targets) > 10 or len(connect_targets) > 10:
        raise PlanError("at most 10 DNS targets and 10 connection targets are allowed")

    limits = dict(config.limits)
    active_since = limits["journal_range_seconds"] if since_seconds is None else since_seconds
    if not 60 <= active_since <= HARD_LIMITS["journal_range_seconds"]:
        raise PlanError("journal range must be between 60 seconds and 24 hours")
    limits["journal_range_seconds"] = active_since

    exclusions = compile_exclusions((*config.exclusions, *cli_exclusions))
    excluded = set(exclusions.excluded_ids)
    artifacts: list[PlannedArtifact] = []
    for definition in ARTIFACT_CATALOGUE:
        if definition.logical_id in excluded:
            state = "excluded"
        elif definition.requires_target == "dns" and not dns_targets:
            state = "not-requested"
        elif definition.requires_target == "connect" and not connect_targets:
            state = "not-requested"
        else:
            state = "planned"
        artifacts.append(
            PlannedArtifact(
                logical_id=definition.logical_id,
                artifact_id=definition.artifact_id,
                description=definition.description,
                action=definition.action_template.format(
                    service=service,
                    since_seconds=active_since,
                    max_journal_records=limits["max_journal_records"],
                    dns_target_count=len(dns_targets),
                    connect_target_count=len(connect_targets),
                ),
                state=state,
            )
        )

    uid = os.geteuid() if effective_uid is None else effective_uid
    privilege = "root" if uid == 0 else "non-root"
    root_acknowledged = privilege == "root" and allow_root
    collection_allowed = privilege == "non-root" or root_acknowledged
    if privilege == "root" and not root_acknowledged:
        limitations = ("Collection requires --allow-root acknowledgement at effective UID 0.",)
    elif privilege == "root":
        limitations = ("Root execution does not widen the evidence allowlist.",)
    else:
        limitations = ("Some evidence may be unavailable without root privileges.",)

    return EvidencePlan(
        service=service,
        since_seconds=active_since,
        privilege=privilege,
        root_acknowledged=root_acknowledged,
        collection_allowed=collection_allowed,
        limits=MappingProxyType(limits),
        exclusion_patterns=exclusions.patterns,
        excluded_ids=exclusions.excluded_ids,
        artifacts=tuple(artifacts),
        dns_targets=tuple(dns_targets),
        connect_targets=tuple(connect_targets),
        limitations=limitations,
    )


def render_preview(plan: EvidencePlan) -> str:
    lines = [
        "INCIDENT PACK PREVIEW",
        "=====================",
        f"Service: {plan.service}",
        f"Journal range: {plan.since_seconds} seconds",
        f"Privilege: {plan.privilege}",
        f"Root acknowledged: {'yes' if plan.root_acknowledged else 'no'}",
        f"Collection allowed: {'yes' if plan.collection_allowed else 'no'}",
        "",
        "Evidence plan:",
    ]
    for artifact in plan.artifacts:
        lines.append(
            f"- [{artifact.state.upper().replace('-', ' ')}] "
            f"{artifact.logical_id}: {artifact.description}"
        )
        lines.append(f"  Source/action: {artifact.action}")

    lines.extend(["", "Active limits:"])
    lines.extend(f"- {name}: {value}" for name, value in plan.limits.items())
    lines.extend(["", "Exclusions:"])
    if plan.exclusion_patterns:
        lines.extend(f"- {pattern}" for pattern in plan.exclusion_patterns)
    else:
        lines.append("- none")
    lines.extend(["", "Privilege notes:"])
    lines.extend(f"- {limitation}" for limitation in plan.limitations)
    lines.extend(
        [
            "",
            "No diagnostic content was read, no network connection was made, "
            "and no files were created.",
        ]
    )
    return "\n".join(lines) + "\n"


def require_collection_privilege(plan: EvidencePlan) -> None:
    if not plan.collection_allowed:
        raise PrivilegeError("collection at effective UID 0 requires --allow-root")


def _validate_pattern(pattern: str) -> None:
    if not isinstance(pattern, str) or not 1 <= len(pattern) <= 128:
        raise PlanError("exclusion patterns must contain 1 to 128 characters")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in pattern):
        raise PlanError("exclusion patterns must not contain control characters")
