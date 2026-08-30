from __future__ import annotations

import hashlib
import io
import json
import tarfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from incident_pack.archive import (
    Artifact,
    BundleError,
    create_bundle,
    verify_bundle,
)

STARTED = datetime(2026, 8, 30, 12, 0, 0, tzinfo=UTC)
FINISHED = datetime(2026, 8, 30, 12, 0, 1, tzinfo=UTC)
SUMMARY = b"Incident Pack synthetic checkpoint bundle\n"


def _create_valid_bundle(path: Path) -> str:
    return create_bundle(
        path,
        service="nginx.service",
        since_seconds=7200,
        privilege="non-root",
        started_at=STARTED,
        finished_at=FINISHED,
        artifacts=[Artifact(id="summary", path="summary.txt", content=SUMMARY)],
        known_limitations=["Synthetic checkpoint bundle; no host evidence was collected."],
    )


def _manifest_for(content: bytes = SUMMARY) -> bytes:
    document = {
        "artifacts": [
            {
                "diagnostic_code": None,
                "id": "summary",
                "path": "summary.txt",
                "redactions": {},
                "sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": len(content),
                "status": "collected",
                "truncated": False,
            }
        ],
        "collection": {
            "finished_at": "2026-08-30T12:00:01Z",
            "privilege": "non-root",
            "service": "nginx.service",
            "since_seconds": 7200,
            "started_at": "2026-08-30T12:00:00Z",
            "status": "complete",
        },
        "exclusions": [],
        "known_limitations": ["Synthetic hostile archive fixture."],
        "limits": {
            "collector_timeout_seconds": 10,
            "journal_range_seconds": 7200,
            "max_archive_bytes": 8388608,
            "max_artifact_bytes": 4194304,
            "max_journal_records": 1000,
            "max_message_bytes": 8192,
            "max_total_bytes": 16777216,
        },
        "schema_version": 1,
        "tool": {"name": "incident-pack", "version": "0.1.0"},
    }
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()


def _add_bytes(archive: tarfile.TarFile, name: str, content: bytes, *, mode: int = 0o600) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(content)
    member.mode = mode
    archive.addfile(member, io.BytesIO(content))


def _write_archive(path: Path, members: list[tuple[str, bytes, int]]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, content, mode in members:
            _add_bytes(archive, name, content, mode=mode)
    path.chmod(0o600)


def test_create_bundle_publishes_a_private_verified_archive(tmp_path: Path) -> None:
    output = tmp_path / "case-1042.tar.gz"

    archive_digest = _create_valid_bundle(output)
    verification = verify_bundle(output)

    assert output.stat().st_mode & 0o777 == 0o600
    assert archive_digest == hashlib.sha256(output.read_bytes()).hexdigest()
    assert verification.archive_sha256 == archive_digest
    assert verification.warnings == ()
    with tarfile.open(output, "r:gz") as archive:
        assert [member.name for member in archive.getmembers()] == ["manifest.json", "summary.txt"]
        assert all(member.isfile() and member.mode == 0o600 for member in archive.getmembers())


def test_manifest_checksum_describes_the_exact_artifact_bytes(tmp_path: Path) -> None:
    output = tmp_path / "case.tar.gz"
    _create_valid_bundle(output)

    with tarfile.open(output, "r:gz") as archive:
        manifest_file = archive.extractfile("manifest.json")
        assert manifest_file is not None
        manifest = json.load(manifest_file)

    artifact = manifest["artifacts"][0]
    assert artifact["size_bytes"] == len(SUMMARY)
    assert artifact["sha256"] == hashlib.sha256(SUMMARY).hexdigest()


def test_create_bundle_never_overwrites_an_existing_output(tmp_path: Path) -> None:
    output = tmp_path / "case.tar.gz"
    output.write_bytes(b"existing evidence")

    with pytest.raises(BundleError, match="already exists"):
        _create_valid_bundle(output)

    assert output.read_bytes() == b"existing evidence"


def test_create_bundle_refuses_a_symlink_output(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_bytes(b"keep me")
    output = tmp_path / "case.tar.gz"
    output.symlink_to(victim)

    with pytest.raises(BundleError, match="already exists"):
        _create_valid_bundle(output)

    assert victim.read_bytes() == b"keep me"


def test_create_bundle_rejects_duplicate_artifact_identifiers(tmp_path: Path) -> None:
    output = tmp_path / "case.tar.gz"

    with pytest.raises(BundleError, match="duplicate artifact id"):
        create_bundle(
            output,
            service="nginx.service",
            since_seconds=7200,
            privilege="non-root",
            started_at=STARTED,
            finished_at=FINISHED,
            artifacts=[
                Artifact(id="summary", path="summary.txt", content=b"one"),
                Artifact(id="summary", path="evidence/summary.txt", content=b"two"),
            ],
        )

    assert not output.exists()


def test_create_bundle_rejects_duplicate_artifact_paths(tmp_path: Path) -> None:
    output = tmp_path / "case.tar.gz"

    with pytest.raises(BundleError, match="duplicate artifact path"):
        create_bundle(
            output,
            service="nginx.service",
            since_seconds=7200,
            privilege="non-root",
            started_at=STARTED,
            finished_at=FINISHED,
            artifacts=[
                Artifact(id="summary", path="evidence/result.json", content=b"one"),
                Artifact(id="service", path="evidence/result.json", content=b"two"),
            ],
        )

    assert not output.exists()


def test_create_bundle_rejects_an_artifact_above_the_default_limit(tmp_path: Path) -> None:
    output = tmp_path / "case.tar.gz"
    oversized = b"x" * (4_194_304 + 1)

    with pytest.raises(BundleError, match="artifact size limit"):
        create_bundle(
            output,
            service="nginx.service",
            since_seconds=7200,
            privilege="non-root",
            started_at=STARTED,
            finished_at=FINISHED,
            artifacts=[Artifact(id="summary", path="summary.txt", content=oversized)],
        )

    assert not output.exists()


def test_create_bundle_cleans_staging_when_verification_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "case.tar.gz"

    def reject_archive(_path: Path) -> object:
        raise BundleError("synthetic verification failure")

    monkeypatch.setattr("incident_pack.archive.verify_bundle", reject_archive)

    with pytest.raises(BundleError, match="synthetic verification failure"):
        _create_valid_bundle(output)

    assert not output.exists()
    assert not list(tmp_path.glob(".incident-pack-*"))


@pytest.mark.parametrize(
    "name", ["/absolute", "../escape", "evidence/../escape", "evidence/line\nbreak"]
)
def test_verify_bundle_rejects_unsafe_member_paths(tmp_path: Path, name: str) -> None:
    path = tmp_path / "hostile.tar.gz"
    _write_archive(path, [(name, b"hostile", 0o600), ("manifest.json", _manifest_for(), 0o600)])

    with pytest.raises(BundleError, match="unsafe member path"):
        verify_bundle(path)


def test_verify_bundle_rejects_duplicate_member_names(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.tar.gz"
    _write_archive(
        path,
        [
            ("manifest.json", _manifest_for(), 0o600),
            ("summary.txt", SUMMARY, 0o600),
            ("summary.txt", SUMMARY, 0o600),
        ],
    )

    with pytest.raises(BundleError, match="duplicate member"):
        verify_bundle(path)


@pytest.mark.parametrize("member_type", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE])
def test_verify_bundle_rejects_non_regular_members(tmp_path: Path, member_type: bytes) -> None:
    path = tmp_path / "special.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        _add_bytes(archive, "manifest.json", _manifest_for())
        special = tarfile.TarInfo("summary.txt")
        special.type = member_type
        special.linkname = "manifest.json"
        archive.addfile(special)
    path.chmod(0o600)

    with pytest.raises(BundleError, match="regular files"):
        verify_bundle(path)


def test_verify_bundle_rejects_permissive_member_modes(tmp_path: Path) -> None:
    path = tmp_path / "permissive.tar.gz"
    _write_archive(
        path,
        [("manifest.json", _manifest_for(), 0o600), ("summary.txt", SUMMARY, 0o644)],
    )

    with pytest.raises(BundleError, match="unsafe mode"):
        verify_bundle(path)


def test_verify_bundle_rejects_unexpected_members(tmp_path: Path) -> None:
    path = tmp_path / "extra.tar.gz"
    _write_archive(
        path,
        [
            ("manifest.json", _manifest_for(), 0o600),
            ("summary.txt", SUMMARY, 0o600),
            ("extra.txt", b"undeclared", 0o600),
        ],
    )

    with pytest.raises(BundleError, match="declared members"):
        verify_bundle(path)


def test_verify_bundle_rejects_checksum_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "tampered.tar.gz"
    _write_archive(
        path,
        [
            ("manifest.json", _manifest_for(), 0o600),
            ("summary.txt", b"x" * len(SUMMARY), 0o600),
        ],
    )

    with pytest.raises(BundleError, match="checksum mismatch"):
        verify_bundle(path)


def test_verify_bundle_warns_when_archive_file_is_not_private(tmp_path: Path) -> None:
    path = tmp_path / "case.tar.gz"
    _create_valid_bundle(path)
    path.chmod(0o644)

    result = verify_bundle(path)

    assert result.warnings == ("archive is readable by group or others",)


def test_verify_bundle_refuses_a_symlink_archive(tmp_path: Path) -> None:
    archive = tmp_path / "case.tar.gz"
    _create_valid_bundle(archive)
    link = tmp_path / "linked.tar.gz"
    link.symlink_to(archive)

    with pytest.raises(BundleError, match="regular file"):
        verify_bundle(link)


def test_verify_bundle_rejects_pathological_json_as_an_invalid_manifest(tmp_path: Path) -> None:
    path = tmp_path / "nested.tar.gz"
    nested_json = ("[" * 2000 + "0" + "]" * 2000).encode()
    _write_archive(path, [("manifest.json", nested_json, 0o600)])

    with pytest.raises(BundleError, match="manifest is invalid"):
        verify_bundle(path)
