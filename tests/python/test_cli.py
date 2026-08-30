from __future__ import annotations

from pathlib import Path

import pytest

from incident_pack.cli import (
    InputError,
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
