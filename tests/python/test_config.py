from __future__ import annotations

from pathlib import Path

import pytest

from incident_pack.config import DEFAULT_LIMITS, ConfigError, load_config


def test_load_config_returns_compiled_defaults_without_a_path() -> None:
    config = load_config(None)

    assert dict(config.limits) == DEFAULT_LIMITS
    assert config.exclusions == ()


def test_load_config_accepts_only_bounded_limits_and_exclusion_patterns(tmp_path: Path) -> None:
    path = tmp_path / "incident-pack.toml"
    path.write_text(
        """
[limits]
max_journal_records = 2500
max_message_bytes = 16384
collector_timeout_seconds = 20

[exclusions]
patterns = ["network.*", "packages.metadata"]
""".strip(),
        encoding="utf-8",
    )

    config = load_config(path)

    assert config.limits["max_journal_records"] == 2500
    assert config.limits["max_message_bytes"] == 16384
    assert config.limits["max_artifact_bytes"] == DEFAULT_LIMITS["max_artifact_bytes"]
    assert config.exclusions == ("network.*", "packages.metadata")


@pytest.mark.parametrize(
    "document",
    [
        "unexpected = true",
        "[limits]\nunknown = 1",
        "[exclusions]\nunknown = []",
        "[limits]\nmax_journal_records = true",
        "[limits]\nmax_journal_records = 5001",
        "[limits]\nmax_message_bytes = 0",
        "[exclusions]\npatterns = 'network.*'",
    ],
)
def test_load_config_fails_closed_on_unknown_or_invalid_values(
    tmp_path: Path, document: str
) -> None:
    path = tmp_path / "invalid.toml"
    path.write_text(document, encoding="utf-8")

    with pytest.raises(ConfigError):
        load_config(path)


def test_load_config_rejects_symlinks_and_oversized_files(tmp_path: Path) -> None:
    target = tmp_path / "target.toml"
    target.write_text("[limits]\n", encoding="utf-8")
    link = tmp_path / "link.toml"
    link.symlink_to(target)

    with pytest.raises(ConfigError, match="regular file"):
        load_config(link)

    oversized = tmp_path / "oversized.toml"
    oversized.write_bytes(b"#" * 65_537)
    with pytest.raises(ConfigError, match="64 KiB"):
        load_config(oversized)


def test_load_config_reports_malformed_toml_without_echoing_content(tmp_path: Path) -> None:
    path = tmp_path / "invalid.toml"
    path.write_text("password = 'should-not-appear'\ninvalid = [", encoding="utf-8")

    with pytest.raises(ConfigError) as captured:
        load_config(path)

    assert "should-not-appear" not in str(captured.value)
