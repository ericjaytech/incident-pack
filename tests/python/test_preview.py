from __future__ import annotations

import socket
import subprocess
import tempfile
from pathlib import Path

import pytest

from incident_pack.cli import main
from incident_pack.config import DEFAULT_LIMITS, IncidentConfig, load_config
from incident_pack.plan import compile_plan


def test_compile_plan_merges_config_and_cli_exclusions_in_stable_order() -> None:
    config = IncidentConfig(limits=DEFAULT_LIMITS, exclusions=("packages.*",))

    plan = compile_plan(
        service="nginx.service",
        since_seconds=3600,
        config=config,
        cli_exclusions=("network.*", "logs.*", "network.*"),
        dns_targets=(),
        connect_targets=(),
        allow_root=False,
        effective_uid=1000,
    )

    assert plan.service == "nginx.service"
    assert plan.limits["journal_range_seconds"] == 3600
    assert plan.exclusion_patterns == ("packages.*", "network.*", "logs.*")
    assert plan.excluded_ids == (
        "logs.journal",
        "packages.metadata",
        "network.dns",
        "network.connectivity",
    )
    assert plan.privilege == "non-root"
    assert plan.collection_allowed is True
    assert "without root" in " ".join(plan.limitations)


def test_configured_journal_range_applies_when_since_is_not_supplied(tmp_path: Path) -> None:
    config_path = tmp_path / "incident-pack.toml"
    config_path.write_text("[limits]\njournal_range_seconds = 1800\n", encoding="utf-8")

    plan = compile_plan(
        service="nginx.service",
        since_seconds=None,
        config=load_config(config_path),
        cli_exclusions=(),
        dns_targets=(),
        connect_targets=(),
        allow_root=False,
        effective_uid=1000,
    )

    assert plan.since_seconds == 1800
    assert plan.limits["journal_range_seconds"] == 1800


def test_preview_is_side_effect_free_and_describes_the_compiled_plan(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected(*args: object, **kwargs: object) -> None:
        raise AssertionError("preview crossed a collection side-effect boundary")

    monkeypatch.setattr(subprocess, "run", unexpected)
    monkeypatch.setattr(subprocess, "Popen", unexpected)
    monkeypatch.setattr(socket, "create_connection", unexpected)
    monkeypatch.setattr(socket, "getaddrinfo", unexpected)
    monkeypatch.setattr(tempfile, "mkdtemp", unexpected)
    output = tmp_path / "must-not-exist.tar.gz"

    exit_code = main(
        [
            "--service",
            "nginx",
            "--since",
            "2h",
            "--preview",
            "--exclude",
            "packages.*",
            "--dns-target",
            "api.example.test",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert "INCIDENT PACK PREVIEW" in captured.out
    assert "Service: nginx.service" in captured.out
    assert "Privilege: non-root" in captured.out
    assert "[EXCLUDED] packages.metadata" in captured.out
    assert "[PLANNED] network.dns" in captured.out
    assert "[NOT REQUESTED] network.connectivity" in captured.out
    assert "systemctl show" in captured.out
    assert "journalctl --unit nginx.service" in captured.out
    assert "No diagnostic content was read" in captured.out
    assert not output.exists()
    assert list(tmp_path.iterdir()) == []


def test_preview_reports_root_acknowledgement_without_blocking(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("incident_pack.plan.os.geteuid", lambda: 0)

    exit_code = main(["--service", "nginx", "--preview"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Privilege: root" in captured.out
    assert "Collection allowed: no" in captured.out
    assert "--allow-root" in captured.out


def test_preview_reports_non_root_limitations(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("incident_pack.plan.os.geteuid", lambda: 1000)

    exit_code = main(["--service", "nginx", "--preview"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Some evidence may be unavailable without root privileges." in captured.out


def test_invalid_config_or_unmatched_exclusion_returns_exit_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path = tmp_path / "invalid.toml"
    config_path.write_text("unknown = true\n", encoding="utf-8")

    assert main(["--service", "nginx", "--preview", "--config", str(config_path)]) == 2
    assert "configuration" in capsys.readouterr().err

    assert main(["--service", "nginx", "--preview", "--exclude", "typo.*"]) == 2
    assert "does not match" in capsys.readouterr().err
