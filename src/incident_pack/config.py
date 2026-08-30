from __future__ import annotations

import os
import stat
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

_MAX_CONFIG_BYTES = 65_536

DEFAULT_LIMITS: Mapping[str, int] = MappingProxyType(
    {
        "journal_range_seconds": 7_200,
        "max_journal_records": 1_000,
        "max_message_bytes": 8_192,
        "max_artifact_bytes": 4_194_304,
        "max_total_bytes": 16_777_216,
        "max_archive_bytes": 8_388_608,
        "collector_timeout_seconds": 10,
    }
)
HARD_LIMITS: Mapping[str, int] = MappingProxyType(
    {
        "journal_range_seconds": 86_400,
        "max_journal_records": 5_000,
        "max_message_bytes": 32_768,
        "max_artifact_bytes": 8_388_608,
        "max_total_bytes": 33_554_432,
        "max_archive_bytes": 16_777_216,
        "collector_timeout_seconds": 30,
    }
)


class ConfigError(ValueError):
    """Raised when configuration is unreadable, ambiguous or outside hard limits."""


@dataclass(frozen=True)
class IncidentConfig:
    limits: Mapping[str, int]
    exclusions: tuple[str, ...]


def load_config(path: Path | None) -> IncidentConfig:
    if path is None:
        return IncidentConfig(limits=DEFAULT_LIMITS, exclusions=())

    payload = _read_config(path)
    try:
        document = tomllib.loads(payload.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ConfigError("configuration must be valid UTF-8 TOML") from error

    allowed_sections = {"limits", "exclusions"}
    unknown_sections = set(document) - allowed_sections
    if unknown_sections:
        raise ConfigError("configuration contains an unknown top-level key")

    limits = _parse_limits(document.get("limits", {}))
    exclusions = _parse_exclusions(document.get("exclusions", {}))
    return IncidentConfig(limits=MappingProxyType(limits), exclusions=exclusions)


def _read_config(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ConfigError("configuration path must be a regular file") from error

    try:
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ConfigError("configuration path must be a regular file")
            if metadata.st_size > _MAX_CONFIG_BYTES:
                raise ConfigError("configuration exceeds the 64 KiB input limit")
            payload = source.read(_MAX_CONFIG_BYTES + 1)
    except ConfigError:
        raise
    except OSError as error:
        raise ConfigError("configuration could not be read safely") from error

    if len(payload) > _MAX_CONFIG_BYTES:
        raise ConfigError("configuration exceeds the 64 KiB input limit")
    return payload


def _parse_limits(value: object) -> dict[str, int]:
    section = _require_table(value, "limits")
    unknown = set(section) - set(DEFAULT_LIMITS)
    if unknown:
        raise ConfigError("limits contains an unknown key")

    limits = dict(DEFAULT_LIMITS)
    for name, configured in section.items():
        minimum = 60 if name == "journal_range_seconds" else 1
        if (
            isinstance(configured, bool)
            or not isinstance(configured, int)
            or not minimum <= configured <= HARD_LIMITS[name]
        ):
            raise ConfigError(f"limits.{name} must be an integer within compiled bounds")
        limits[name] = configured
    return limits


def _parse_exclusions(value: object) -> tuple[str, ...]:
    section = _require_table(value, "exclusions")
    if set(section) - {"patterns"}:
        raise ConfigError("exclusions contains an unknown key")
    patterns = section.get("patterns", [])
    if not isinstance(patterns, list) or len(patterns) > 32:
        raise ConfigError("exclusions.patterns must be an array with at most 32 items")
    for pattern in patterns:
        if (
            not isinstance(pattern, str)
            or not 1 <= len(pattern) <= 128
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in pattern)
        ):
            raise ConfigError("each exclusion pattern must contain 1 to 128 printable characters")
    return tuple(patterns)


def _require_table(value: object, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a TOML table")
    return value
