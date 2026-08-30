from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from incident_pack.archive import Artifact, BundleError, create_bundle
from incident_pack.cli import (
    InputError,
    main,
    normalise_service,
    parse_arguments,
    parse_connect_target,
    parse_duration,
)


@pytest.mark.parametrize(
    ("value", "seconds"),
    [("15m", 900), ("2h", 7200), ("1d", 86400), ("1440m", 86400)],
)
def test_parse_duration_accepts_bounded_positive_durations(value: str, seconds: int) -> None:
    assert parse_duration(value) == seconds


@pytest.mark.parametrize("value", ["", "0m", "2 hours", "1.5h", "25h", "2w", "-1h"])
def test_parse_duration_rejects_invalid_or_overlong_ranges(value: str) -> None:
    with pytest.raises(InputError):
        parse_duration(value)


@pytest.mark.parametrize(
    ("value", "normalised"),
    [
        ("nginx", "nginx.service"),
        ("nginx.service", "nginx.service"),
        ("worker@blue", "worker@blue.service"),
    ],
)
def test_normalise_service_accepts_narrow_systemd_service_names(
    value: str, normalised: str
) -> None:
    assert normalise_service(value) == normalised


@pytest.mark.parametrize(
    "value",
    ["", "--user", "../nginx", "nginx;id", "nginx socket", "nginx.socket", "a" * 256],
)
def test_normalise_service_rejects_names_that_could_change_command_meaning(value: str) -> None:
    with pytest.raises(InputError):
        normalise_service(value)


@pytest.mark.parametrize(
    ("value", "host", "port"),
    [
        ("api.example.test:443", "api.example.test", 443),
        ("localhost:8080", "localhost", 8080),
        ("[2001:db8::1]:443", "2001:db8::1", 443),
    ],
)
def test_parse_connect_target_returns_an_unambiguous_host_and_port(
    value: str, host: str, port: int
) -> None:
    assert parse_connect_target(value) == (host, port)


@pytest.mark.parametrize(
    "value",
    ["", "api.example.test", "api.example.test:0", "api.example.test:65536", "a:b:443"],
)
def test_parse_connect_target_rejects_ambiguous_or_invalid_targets(value: str) -> None:
    with pytest.raises(InputError):
        parse_connect_target(value)


def test_collection_example_parses_without_creating_output(tmp_path: Path) -> None:
    output = tmp_path / "case-1042.tar.gz"

    arguments = parse_arguments(["--service", "nginx", "--since", "2h", "--output", str(output)])

    assert arguments.action == "collect"
    assert arguments.service == "nginx.service"
    assert arguments.since_seconds == 7200
    assert arguments.output == output
    assert not output.exists()


def test_preview_does_not_require_or_create_an_output(tmp_path: Path) -> None:
    arguments = parse_arguments(["--service", "nginx", "--since", "2h", "--preview"])

    assert arguments.action == "preview"
    assert arguments.output is None
    assert list(tmp_path.iterdir()) == []


def test_verify_is_mutually_exclusive_with_collection_inputs(tmp_path: Path) -> None:
    archive = tmp_path / "case.tar.gz"
    archive.write_bytes(b"not yet a bundle")

    with pytest.raises(InputError):
        parse_arguments(["--verify", str(archive), "--service", "nginx"])


def test_collection_refuses_an_existing_output(tmp_path: Path) -> None:
    output = tmp_path / "case.tar.gz"
    output.write_bytes(b"existing")

    with pytest.raises(InputError, match="already exists"):
        parse_arguments(["--service", "nginx", "--output", str(output)])


def test_collection_command_reports_published_digest_and_review_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "case.tar.gz"
    digest = "a" * 64
    monkeypatch.setattr("incident_pack.cli.collect_bundle", lambda _plan, _output: digest)

    exit_code = main(
        ["--service", "nginx", "--since", "2h", "--output", str(output), "--allow-root"]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert f"Archive created: {json.dumps(str(output))}" in captured.out
    assert f"SHA-256: {digest}" in captured.out
    assert "Inspect the archive before sharing it." in captured.err


def test_collection_failure_does_not_claim_an_archive_was_published(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "case.tar.gz"

    def fail_collection(_plan, _output) -> str:
        raise BundleError("synthetic publication failure")

    monkeypatch.setattr("incident_pack.cli.collect_bundle", fail_collection)

    exit_code = main(
        ["--service", "nginx", "--since", "2h", "--output", str(output), "--allow-root"]
    )

    captured = capsys.readouterr()
    assert exit_code == 4
    assert captured.out == ""
    assert "collection failed: synthetic publication failure" in captured.err
    assert not output.exists()


def test_verify_command_reports_a_valid_archive_digest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    archive = tmp_path / "case.tar.gz"
    expected = create_bundle(
        archive,
        service="nginx.service",
        since_seconds=7200,
        privilege="non-root",
        started_at=datetime(2026, 8, 30, 12, 0, 0, tzinfo=UTC),
        finished_at=datetime(2026, 8, 30, 12, 0, 1, tzinfo=UTC),
        artifacts=[Artifact(id="summary", path="summary.txt", content=b"synthetic\n")],
    )

    exit_code = main(["--verify", str(archive)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert expected in captured.out
    assert captured.err == ""


def test_verify_command_returns_exit_four_without_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    archive = tmp_path / "invalid.tar.gz"
    archive.write_bytes(b"not a tar archive")

    exit_code = main(["--verify", str(archive)])

    captured = capsys.readouterr()
    assert exit_code == 4
    assert captured.out == ""
    assert captured.err.startswith("incident-pack: verification failed:")
    assert "Traceback" not in captured.err


def test_verify_command_escapes_control_characters_in_the_archive_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    archive = tmp_path / "case\nname.tar.gz"
    create_bundle(
        archive,
        service="nginx.service",
        since_seconds=7200,
        privilege="non-root",
        started_at=datetime(2026, 8, 30, 12, 0, 0, tzinfo=UTC),
        finished_at=datetime(2026, 8, 30, 12, 0, 1, tzinfo=UTC),
        artifacts=[Artifact(id="summary", path="summary.txt", content=b"synthetic\n")],
    )

    exit_code = main(["--verify", str(archive)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "case\\nname.tar.gz" in captured.out
    assert len(captured.out.splitlines()) == 2
