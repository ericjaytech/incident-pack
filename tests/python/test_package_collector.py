from __future__ import annotations

import base64
from pathlib import Path

import pytest

from incident_pack.collectors.packages import collect_packages

PACKAGE_FORMAT = "${binary:Package}\\t${Version}\\t${Architecture}\\t${Status}\\n"


def _fake_dpkg_query(
    tmp_path: Path,
    responses: dict[tuple[str, ...], tuple[bytes, int]],
    *,
    delay_seconds: float = 0,
    expected_environment: set[str] | None = None,
) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    executable = tmp_path / "dpkg-query"
    encoded_responses = {
        arguments: (base64.b64encode(payload).decode("ascii"), exit_code)
        for arguments, (payload, exit_code) in responses.items()
    }
    script = f"""#!/usr/bin/python3
import base64
import os
import sys
import time

expected_environment = {expected_environment!r}
if expected_environment is not None and set(os.environ) != expected_environment:
    sys.exit(98)
responses = {encoded_responses!r}
response = responses.get(tuple(sys.argv[1:]))
if response is None:
    sys.exit(97)
time.sleep({delay_seconds!r})
payload, exit_code = response
sys.stdout.buffer.write(base64.b64decode(payload))
sys.exit(exit_code)
"""
    executable.write_text(script, encoding="utf-8")
    executable.chmod(0o755)
    return executable


def _collect(executable: Path, root: Path, paths: tuple[Path, ...], **overrides: object):
    arguments = {
        "paths": paths,
        "timeout_seconds": 2,
        "_dpkg_query": executable,
        "_allowed_roots": (root,),
    }
    arguments.update(overrides)
    return collect_packages(**arguments)


def test_package_collector_retains_only_installed_package_metadata_and_deduplicates(
    tmp_path: Path,
) -> None:
    root = tmp_path / "systemd"
    root.mkdir()
    fragment = root / "nginx.service"
    drop_in = root / "nginx.service.d.conf"
    fragment.touch()
    drop_in.touch()
    responses = {
        ("--search", "--", str(fragment)): (f"nginx: {fragment}\n".encode(), 0),
        ("--search", "--", str(drop_in)): (f"nginx: {drop_in}\n".encode(), 0),
        ("--show", f"--showformat={PACKAGE_FORMAT}", "--", "nginx"): (
            b"nginx\t1.24.0-2ubuntu7\tamd64\tinstall ok installed\n",
            0,
        ),
    }
    executable = _fake_dpkg_query(
        tmp_path / "bin",
        responses,
        expected_environment={"LC_ALL", "PATH"},
    )

    result = _collect(executable, root, (fragment, drop_in))

    assert result.status == "collected"
    assert result.diagnostic_code is None
    assert result.packages == (
        {
            "architecture": "amd64",
            "name": "nginx",
            "status": "install ok installed",
            "version": "1.24.0-2ubuntu7",
        },
    )


def test_package_collector_treats_unowned_files_as_unavailable(tmp_path: Path) -> None:
    root = tmp_path / "systemd"
    root.mkdir()
    fragment = root / "local.service"
    fragment.touch()
    executable = _fake_dpkg_query(
        tmp_path / "bin",
        {("--search", "--", str(fragment)): (b"", 1)},
    )

    result = _collect(executable, root, (fragment,))

    assert result.status == "skipped"
    assert result.diagnostic_code == "PACKAGE_METADATA_UNAVAILABLE"
    assert result.packages == ()


def test_package_collector_rejects_unsafe_paths_before_querying(tmp_path: Path) -> None:
    root = tmp_path / "systemd"
    root.mkdir()
    outside = tmp_path / "private.service"
    outside.touch()

    result = _collect(tmp_path / "must-not-run", root, (outside,))

    assert result.status == "error"
    assert result.diagnostic_code == "PACKAGE_PATH_UNSAFE"
    assert "private.service" not in repr(result)


def test_package_collector_rejects_control_characters_in_paths(tmp_path: Path) -> None:
    root = tmp_path / "systemd"
    root.mkdir()

    result = _collect(tmp_path / "must-not-run", root, (root / "bad\nname.service",))

    assert result.status == "error"
    assert result.diagnostic_code == "PACKAGE_PATH_UNSAFE"


@pytest.mark.parametrize(
    ("owner_payload", "metadata_payload", "expected_code"),
    [
        (b"Environment=PASSWORD=must-not-leak\n", b"", "PACKAGE_OWNER_MALFORMED"),
        (
            b"nginx: {path}\n",
            b"nginx\t1.2\tamd64\tdeinstall ok config-files\n",
            "PACKAGE_METADATA_MALFORMED",
        ),
        (
            b"nginx: {path}\n",
            b"nginx\t1.2\tamd64\tinstall ok installed\textra\n",
            "PACKAGE_METADATA_MALFORMED",
        ),
    ],
)
def test_package_collector_rejects_malformed_allowlisted_output(
    tmp_path: Path,
    owner_payload: bytes,
    metadata_payload: bytes,
    expected_code: str,
) -> None:
    root = tmp_path / "systemd"
    root.mkdir()
    fragment = root / "nginx.service"
    fragment.touch()
    owner_payload = owner_payload.replace(b"{path}", str(fragment).encode())
    responses = {("--search", "--", str(fragment)): (owner_payload, 0)}
    if metadata_payload:
        responses[("--show", f"--showformat={PACKAGE_FORMAT}", "--", "nginx")] = (
            metadata_payload,
            0,
        )
    executable = _fake_dpkg_query(tmp_path / "bin", responses)

    result = _collect(executable, root, (fragment,))

    assert result.status == "error"
    assert result.diagnostic_code == expected_code
    assert result.packages == ()
    assert "must-not-leak" not in repr(result)


def test_package_collector_maps_missing_failed_and_timed_out_queries(tmp_path: Path) -> None:
    root = tmp_path / "systemd"
    root.mkdir()
    fragment = root / "nginx.service"
    fragment.touch()
    owner_arguments = ("--search", "--", str(fragment))

    missing = _collect(tmp_path / "missing-dpkg-query", root, (fragment,))
    failed = _collect(
        _fake_dpkg_query(tmp_path / "failed", {owner_arguments: (b"unexpected", 2)}),
        root,
        (fragment,),
    )
    timed_out = _collect(
        _fake_dpkg_query(
            tmp_path / "slow",
            {owner_arguments: (f"nginx: {fragment}\n".encode(), 0)},
            delay_seconds=1,
        ),
        root,
        (fragment,),
        timeout_seconds=0.05,
    )

    assert (missing.status, missing.diagnostic_code) == ("skipped", "DPKG_QUERY_NOT_FOUND")
    assert (failed.status, failed.diagnostic_code) == ("error", "PACKAGE_QUERY_FAILED")
    assert (timed_out.status, timed_out.diagnostic_code) == (
        "error",
        "PACKAGE_QUERY_TIMEOUT",
    )
    assert missing.packages == failed.packages == timed_out.packages == ()
