from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase


class PlanError(ValueError):
    """Raised when an evidence plan would be ambiguous or unsafe."""


@dataclass(frozen=True)
class ArtifactDefinition:
    logical_id: str
    artifact_id: str
    description: str
    mandatory: bool = False
    requires_target: str | None = None


@dataclass(frozen=True)
class ExclusionPolicy:
    patterns: tuple[str, ...]
    excluded_ids: tuple[str, ...]


ARTIFACT_CATALOGUE = (
    ArtifactDefinition("summary", "summary", "Human-readable escalation summary", mandatory=True),
    ArtifactDefinition("service.status", "service", "Allowlisted systemd service properties"),
    ArtifactDefinition("resources.pressure", "resources", "CPU, memory and disk pressure"),
    ArtifactDefinition("logs.journal", "journal", "Bounded recent service journal records"),
    ArtifactDefinition("packages.metadata", "packages", "Installed package metadata"),
    ArtifactDefinition(
        "configuration.metadata", "configuration", "Service-unit metadata and checksums"
    ),
    ArtifactDefinition("network.dns", "dns", "Explicit DNS checks", requires_target="dns"),
    ArtifactDefinition(
        "network.connectivity",
        "connectivity",
        "Explicit bounded TCP checks",
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


def _validate_pattern(pattern: str) -> None:
    if not isinstance(pattern, str) or not 1 <= len(pattern) <= 128:
        raise PlanError("exclusion patterns must contain 1 to 128 characters")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in pattern):
        raise PlanError("exclusion patterns must not contain control characters")
