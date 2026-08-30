from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

from incident_pack.collectors.configuration import collect_configuration


def _fake_systemctl(
    tmp_path: Path,
    *,
    payload: bytes = b"",
    exit_code: int = 0,
    delay_seconds: float = 0,
    expected_arguments: list[str] | None = None,
    expected_environment: set[str] | None = None,
) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    executable = tmp_path / "systemctl"
    encoded = base64.b64encode(payload).decode("ascii")
    script = f"""#!/usr/bin/python3
import base64
import os
import sys
import time

expected = {expected_arguments!r}
if expected is not None and sys.argv[1:] != expected:
    sys.exit(97)
expected_environment = {expected_environment!r}
if expected_environment is not None and set(os.environ) != expected_environment:
    sys.exit(98)
time.sleep({delay_seconds!r})
sys.stdout.buffer.write(base64.b64decode({encoded!r}))
sys.exit({exit_code!r})
"""
    executable.write_text(script, encoding="utf-8")
    executable.chmod(0o755)
    return executable


def _collect(executable: Path, allowed_root: Path, **overrides: object):
    arguments = {
        "service": "nginx.service",
        "timeout_seconds": 2,
        "_systemctl": executable,
        "_allowed_roots": (allowed_root,),
    }
    arguments.update(overrides)
    return collect_configuration(**arguments)


def test_configuration_collector_retains_metadata_and_checksum_without_content(
    tmp_path: Path,
) -> None:
    root = tmp_path / "systemd"
    fragment = root / "nginx.service"
    drop_in = root / "nginx.service.d" / "limits.conf"
    drop_in.parent.mkdir(parents=True)
    fragment.write_text("password=fragment-secret\n", encoding="utf-8")
    drop_in.write_text("token=drop-in-secret\n", encoding="utf-8")
    fragment.chmod(0o644)
    drop_in.chmod(0o640)
    payload = (f"FragmentPath={fragment}\nDropInPaths={drop_in}\n").encode()
    executable = _fake_systemctl(tmp_path / "bin", payload=payload)

    result = _collect(executable, root)

    assert result.status == "collected"
    assert result.diagnostic_code is None
    assert [item["source"] for item in result.files] == ["fragment", "drop-in"]
    assert result.files[0]["path"] == str(fragment)
    assert result.files[0]["resolved_path"] == str(fragment)
    assert result.files[0]["size_bytes"] == fragment.stat().st_size
    assert result.files[0]["mode"] == "0644"
    assert result.files[0]["sha256"] == hashlib.sha256(fragment.read_bytes()).hexdigest()
    assert result.files[1]["mode"] == "0640"
    assert result.files[1]["sha256"] == hashlib.sha256(drop_in.read_bytes()).hexdigest()
    assert "modified_at" in result.files[0]
    assert "fragment-secret" not in repr(result)
    assert "drop-in-secret" not in repr(result)


def test_configuration_collector_uses_fixed_arguments_and_minimal_environment(
    tmp_path: Path,
) -> None:
    root = tmp_path / "systemd"
    root.mkdir()
    expected = [
        "show",
        "--no-pager",
        "--property=FragmentPath",
        "--property=DropInPaths",
        "--",
        "nginx.service",
    ]
    executable = _fake_systemctl(
        tmp_path / "bin",
        payload=b"FragmentPath=\nDropInPaths=\n",
        expected_arguments=expected,
        expected_environment={"LC_ALL", "PATH"},
    )

    result = _collect(executable, root)

    assert result.status == "skipped"
    assert result.diagnostic_code == "CONFIGURATION_NOT_FILE_BACKED"


def test_configuration_collector_records_safe_symlink_resolution(tmp_path: Path) -> None:
    root = tmp_path / "systemd"
    root.mkdir()
    target = root / "real.service"
    link = root / "nginx.service"
    target.write_text("[Service]\n", encoding="utf-8")
    link.symlink_to(target)
    executable = _fake_systemctl(
        tmp_path / "bin",
        payload=f"FragmentPath={link}\nDropInPaths=\n".encode(),
    )

    result = _collect(executable, root)

    assert result.status == "collected"
    assert result.files[0]["path"] == str(link)
    assert result.files[0]["resolved_path"] == str(target)


@pytest.mark.parametrize("use_symlink", [False, True])
def test_configuration_collector_rejects_paths_outside_allowed_roots(
    tmp_path: Path, use_symlink: bool
) -> None:
    root = tmp_path / "systemd"
    root.mkdir()
    outside = tmp_path / "private.conf"
    outside.write_text("password=must-not-leak\n", encoding="utf-8")
    supplied = outside
    if use_symlink:
        supplied = root / "nginx.service"
        supplied.symlink_to(outside)
    executable = _fake_systemctl(
        tmp_path / "bin",
        payload=f"FragmentPath={supplied}\nDropInPaths=\n".encode(),
    )

    result = _collect(executable, root)

    assert result.status == "error"
    assert result.diagnostic_code == "CONFIGURATION_PATH_UNSAFE"
    assert result.files == ()
    assert "private.conf" not in repr(result)
    assert "must-not-leak" not in repr(result)


def test_configuration_collector_rejects_non_regular_and_oversized_files(
    tmp_path: Path,
) -> None:
    root = tmp_path / "systemd"
    directory = root / "nginx.service"
    directory.mkdir(parents=True)
    executable = _fake_systemctl(
        tmp_path / "bin",
        payload=f"FragmentPath={directory}\nDropInPaths=\n".encode(),
    )
    non_regular = _collect(executable, root)

    large = root / "large.service"
    large.write_bytes(b"x" * 65)
    executable = _fake_systemctl(
        tmp_path / "large-bin",
        payload=f"FragmentPath={large}\nDropInPaths=\n".encode(),
    )
    oversized = _collect(executable, root, _max_source_bytes=64)

    assert non_regular.status == "error"
    assert non_regular.diagnostic_code == "CONFIGURATION_FILE_UNSAFE"
    assert oversized.status == "error"
    assert oversized.diagnostic_code == "CONFIGURATION_FILE_TOO_LARGE"


def test_configuration_collector_maps_missing_failed_timed_out_and_malformed_queries(
    tmp_path: Path,
) -> None:
    root = tmp_path / "systemd"
    root.mkdir()

    missing = _collect(tmp_path / "missing-systemctl", root)
    failed = _collect(_fake_systemctl(tmp_path / "failed", exit_code=1), root)
    timed_out = _collect(
        _fake_systemctl(tmp_path / "slow", delay_seconds=1),
        root,
        timeout_seconds=0.05,
    )
    malformed = _collect(
        _fake_systemctl(tmp_path / "malformed", payload=b"Description=must-not-be-retained\n"),
        root,
    )

    assert (missing.status, missing.diagnostic_code) == ("skipped", "SYSTEMCTL_NOT_FOUND")
    assert (failed.status, failed.diagnostic_code) == ("error", "CONFIGURATION_QUERY_FAILED")
    assert (timed_out.status, timed_out.diagnostic_code) == (
        "error",
        "CONFIGURATION_QUERY_TIMEOUT",
    )
    assert (malformed.status, malformed.diagnostic_code) == (
        "error",
        "CONFIGURATION_QUERY_MALFORMED",
    )
    assert missing.files == failed.files == timed_out.files == malformed.files == ()
