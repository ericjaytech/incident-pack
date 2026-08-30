from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import stat
import tarfile
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from incident_pack import __version__
from incident_pack.manifest import (
    ManifestValidationError,
    is_safe_artifact_path,
    validate_manifest,
)

_MANIFEST_NAME = "manifest.json"
_MAX_MANIFEST_BYTES = 1_048_576
_HARD_MAX_ARTIFACT_BYTES = 8_388_608
_HARD_MAX_TOTAL_BYTES = 33_554_432
_HARD_MAX_ARCHIVE_BYTES = 16_777_216
_MAX_ARCHIVE_MEMBERS = 33
_ARTIFACT_IDS = {
    "summary",
    "service",
    "resources",
    "journal",
    "packages",
    "configuration",
    "dns",
    "connectivity",
}
_DEFAULT_LIMITS = {
    "journal_range_seconds": 7200,
    "max_journal_records": 1000,
    "max_message_bytes": 8192,
    "max_artifact_bytes": 4_194_304,
    "max_total_bytes": 16_777_216,
    "max_archive_bytes": 8_388_608,
    "collector_timeout_seconds": 10,
}


class BundleError(ValueError):
    """Raised when a bundle cannot be created or verified safely."""


@dataclass(frozen=True)
class Artifact:
    id: str
    path: str
    content: bytes
    truncated: bool = False
    redactions: Mapping[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class VerificationResult:
    archive_sha256: str
    warnings: tuple[str, ...] = ()


def create_bundle(
    output: Path,
    *,
    service: str,
    since_seconds: int,
    privilege: str,
    started_at: datetime,
    finished_at: datetime,
    artifacts: Sequence[Artifact],
    exclusions: Sequence[str] = (),
    known_limitations: Sequence[str] = (),
    limits: Mapping[str, int] | None = None,
) -> str:
    destination = _resolve_new_output(output)
    active_limits = dict(_DEFAULT_LIMITS if limits is None else limits)
    if limits is None:
        active_limits["journal_range_seconds"] = since_seconds
    _validate_active_limits(active_limits)

    staging_path = Path(tempfile.mkdtemp(prefix=".incident-pack-", dir=destination.parent))
    os.chmod(staging_path, 0o700)
    try:
        artifact_documents = _stage_artifacts(staging_path, artifacts, active_limits)
        manifest = {
            "schema_version": 1,
            "tool": {"name": "incident-pack", "version": __version__},
            "collection": {
                "started_at": _format_timestamp(started_at),
                "finished_at": _format_timestamp(finished_at),
                "service": service,
                "since_seconds": since_seconds,
                "privilege": privilege,
                "status": (
                    "partial"
                    if any(artifact["truncated"] for artifact in artifact_documents)
                    else "complete"
                ),
            },
            "limits": active_limits,
            "exclusions": list(exclusions),
            "artifacts": artifact_documents,
            "known_limitations": list(known_limitations),
        }
        validate_manifest(manifest)
        manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
        total_bytes = len(manifest_bytes) + sum(
            artifact["size_bytes"] for artifact in artifact_documents
        )
        if total_bytes > active_limits["max_total_bytes"]:
            raise BundleError("bundle content exceeds the active total size limit")
        _write_private_file(staging_path / _MANIFEST_NAME, manifest_bytes)

        temporary_archive = staging_path / "bundle.tar.gz"
        _write_archive(temporary_archive, staging_path, artifact_documents)
        if temporary_archive.stat().st_size > active_limits["max_archive_bytes"]:
            raise BundleError("compressed archive exceeds the active archive size limit")
        verification = verify_bundle(temporary_archive)
        try:
            os.link(temporary_archive, destination, follow_symlinks=False)
        except FileExistsError as error:
            raise BundleError(f"output already exists: {_display(str(output))}") from error
        except OSError as error:
            raise BundleError("verified archive could not be published atomically") from error
        return verification.archive_sha256
    except ManifestValidationError as error:
        raise BundleError(f"generated manifest is invalid: {error}") from error
    finally:
        _remove_staging(staging_path)


def verify_bundle(path: Path) -> VerificationResult:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BundleError("archive must be a regular file") from error

    try:
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise BundleError("archive must be a regular file")
            if metadata.st_size > _HARD_MAX_ARCHIVE_BYTES:
                raise BundleError("archive exceeds the hard compressed size limit")
            warnings = (
                ("archive is readable by group or others",) if metadata.st_mode & 0o077 else ()
            )
            try:
                with tarfile.open(fileobj=source, mode="r:gz") as archive:
                    members = archive.getmembers()
                    if len(members) > _MAX_ARCHIVE_MEMBERS:
                        raise BundleError("archive contains too many members")
                    member_by_name = _validate_member_headers(members)
                    manifest_member = member_by_name.get(_MANIFEST_NAME)
                    if manifest_member is None:
                        raise BundleError("archive does not contain manifest.json")
                    manifest_bytes = _read_member(archive, manifest_member, _MAX_MANIFEST_BYTES)
                    try:
                        manifest = json.loads(manifest_bytes.decode("utf-8"))
                        validate_manifest(manifest)
                    except (UnicodeError, ValueError, RecursionError) as error:
                        raise BundleError("archive manifest is invalid") from error
                    _verify_declared_content(archive, member_by_name, manifest, metadata.st_size)
            except BundleError:
                raise
            except (OSError, tarfile.TarError, EOFError) as error:
                raise BundleError("archive is not a readable gzip-compressed tar file") from error
            source.seek(0)
            archive_digest = _sha256_stream(source)
    except BundleError:
        raise
    except OSError as error:
        raise BundleError("archive could not be read safely") from error

    return VerificationResult(archive_sha256=archive_digest, warnings=warnings)


def _stage_artifacts(
    staging_path: Path,
    artifacts: Sequence[Artifact],
    limits: Mapping[str, int],
) -> list[dict[str, Any]]:
    documents: list[dict[str, Any]] = []
    artifact_ids: set[str] = set()
    artifact_paths: set[str] = set()
    total_bytes = 0
    for artifact in sorted(artifacts, key=lambda item: (item.path, item.id)):
        if artifact.id not in _ARTIFACT_IDS:
            raise BundleError(f"unknown artifact id: {_display(artifact.id)}")
        if artifact.id in artifact_ids:
            raise BundleError(f"duplicate artifact id: {_display(artifact.id)}")
        if not is_safe_artifact_path(artifact.path) or artifact.path == _MANIFEST_NAME:
            raise BundleError(f"artifact path is unsafe: {_display(artifact.path)}")
        if artifact.path in artifact_paths:
            raise BundleError(f"duplicate artifact path: {_display(artifact.path)}")
        artifact_ids.add(artifact.id)
        artifact_paths.add(artifact.path)
        if not isinstance(artifact.content, bytes):
            raise BundleError("artifact content must be bytes")
        if len(artifact.content) > limits["max_artifact_bytes"]:
            raise BundleError("artifact size limit exceeded")
        total_bytes += len(artifact.content)
        if total_bytes > limits["max_total_bytes"]:
            raise BundleError("bundle content exceeds the active total size limit")

        destination = staging_path.joinpath(*PurePosixPath(artifact.path).parts)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _write_private_file(destination, artifact.content)
        documents.append(
            {
                "id": artifact.id,
                "status": "collected",
                "path": artifact.path,
                "size_bytes": len(artifact.content),
                "sha256": hashlib.sha256(artifact.content).hexdigest(),
                "truncated": artifact.truncated,
                "redactions": dict(artifact.redactions),
                "diagnostic_code": None,
            }
        )
    return documents


def _write_archive(
    archive_path: Path, staging_path: Path, artifact_documents: Sequence[Mapping[str, Any]]
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(archive_path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as raw_file:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw_file, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as archive:
                    member_paths = [_MANIFEST_NAME] + [
                        str(artifact["path"])
                        for artifact in sorted(
                            artifact_documents, key=lambda document: str(document["path"])
                        )
                    ]
                    for member_path in member_paths:
                        content = staging_path.joinpath(
                            *PurePosixPath(member_path).parts
                        ).read_bytes()
                        member = tarfile.TarInfo(member_path)
                        member.size = len(content)
                        member.mode = 0o600
                        member.mtime = 0
                        member.uid = 0
                        member.gid = 0
                        member.uname = ""
                        member.gname = ""
                        archive.addfile(member, io.BytesIO(content))
            raw_file.flush()
            os.fsync(raw_file.fileno())
    except BaseException:
        archive_path.unlink(missing_ok=True)
        raise


def _validate_member_headers(members: Sequence[tarfile.TarInfo]) -> dict[str, tarfile.TarInfo]:
    member_by_name: dict[str, tarfile.TarInfo] = {}
    declared_total = 0
    for member in members:
        if not is_safe_artifact_path(member.name):
            raise BundleError(f"archive contains unsafe member path: {_display(member.name)}")
        if member.name in member_by_name:
            raise BundleError(f"archive contains duplicate member: {_display(member.name)}")
        if not member.isfile():
            raise BundleError("archive members must be regular files")
        if member.mode != 0o600:
            raise BundleError(f"archive member has unsafe mode: {_display(member.name)}")
        if member.size < 0 or member.size > _HARD_MAX_ARTIFACT_BYTES:
            raise BundleError("archive member exceeds the hard artifact size limit")
        declared_total += member.size
        if declared_total > _HARD_MAX_TOTAL_BYTES:
            raise BundleError("archive exceeds the hard uncompressed size limit")
        member_by_name[member.name] = member
    return member_by_name


def _verify_declared_content(
    archive: tarfile.TarFile,
    member_by_name: Mapping[str, tarfile.TarInfo],
    manifest: Mapping[str, Any],
    archive_size: int,
) -> None:
    limits = manifest["limits"]
    if archive_size > limits["max_archive_bytes"]:
        raise BundleError("archive exceeds its declared compressed size limit")

    collected = {
        artifact["path"]: artifact
        for artifact in manifest["artifacts"]
        if artifact["status"] == "collected"
    }
    expected_names = {_MANIFEST_NAME, *collected}
    if set(member_by_name) != expected_names:
        raise BundleError("archive members do not match declared members")

    total_bytes = member_by_name[_MANIFEST_NAME].size
    for member_path, artifact in collected.items():
        member = member_by_name[member_path]
        if member.size != artifact["size_bytes"]:
            raise BundleError(f"size mismatch for archive member: {_display(member_path)}")
        if member.size > limits["max_artifact_bytes"]:
            raise BundleError("archive member exceeds its declared artifact size limit")
        content = _read_member(archive, member, limits["max_artifact_bytes"])
        if hashlib.sha256(content).hexdigest() != artifact["sha256"]:
            raise BundleError(f"checksum mismatch for archive member: {_display(member_path)}")
        total_bytes += len(content)
    if total_bytes > limits["max_total_bytes"]:
        raise BundleError("archive exceeds its declared uncompressed size limit")


def _read_member(archive: tarfile.TarFile, member: tarfile.TarInfo, limit: int) -> bytes:
    extracted = archive.extractfile(member)
    if extracted is None:
        raise BundleError("archive member could not be read")
    content = extracted.read(limit + 1)
    if len(content) > limit:
        raise BundleError("archive member exceeds its read limit")
    if len(content) != member.size:
        raise BundleError("archive member ended before its declared size")
    return content


def _validate_active_limits(limits: Mapping[str, int]) -> None:
    expected = set(_DEFAULT_LIMITS)
    if set(limits) != expected:
        raise BundleError("active limits do not match the version 1 limit contract")
    maxima = {
        "journal_range_seconds": 86_400,
        "max_journal_records": 5_000,
        "max_message_bytes": 32_768,
        "max_artifact_bytes": _HARD_MAX_ARTIFACT_BYTES,
        "max_total_bytes": _HARD_MAX_TOTAL_BYTES,
        "max_archive_bytes": _HARD_MAX_ARCHIVE_BYTES,
        "collector_timeout_seconds": 30,
    }
    if any(
        isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maxima[key]
        for key, value in limits.items()
    ):
        raise BundleError("active limits must be positive integers within hard maxima")


def _resolve_new_output(path: Path) -> Path:
    if not path.name.endswith(".tar.gz"):
        raise BundleError("output path must end with .tar.gz")
    parent_absolute = path.parent.absolute()
    try:
        parent_resolved = path.parent.resolve(strict=True)
    except OSError as error:
        raise BundleError("output parent could not be resolved safely") from error
    if parent_absolute != parent_resolved or not parent_resolved.is_dir():
        raise BundleError("output parent must be a real directory without symlinks")
    destination = parent_resolved / path.name
    if destination.exists() or destination.is_symlink():
        raise BundleError(f"output already exists: {_display(str(path))}")
    return destination


def _write_private_file(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _remove_staging(path: Path) -> None:
    if not path.exists():
        return
    for entry in sorted(path.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if entry.is_dir() and not entry.is_symlink():
            entry.rmdir()
        else:
            entry.unlink()
    path.rmdir()


def _format_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise BundleError("collection timestamps must include a timezone")
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _sha256_stream(source: io.BufferedReader) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def _display(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)
