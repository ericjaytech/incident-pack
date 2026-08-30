from __future__ import annotations

import json
import stat
from datetime import datetime
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

_MAX_MANIFEST_BYTES = 1_048_576


class ManifestValidationError(ValueError):
    """Raised when a manifest violates its published or semantic contract."""


def load_manifest_schema() -> dict[str, Any]:
    schema_resource = files("incident_pack.schemas").joinpath("manifest-v1.schema.json")
    return json.loads(schema_resource.read_text(encoding="utf-8"))


def validate_manifest(document: object) -> None:
    schema = load_manifest_schema()
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "manifest"
        raise ManifestValidationError(f"{location}: {error.message}")

    if not isinstance(document, dict):
        raise ManifestValidationError("manifest must be a JSON object")
    _validate_semantics(document)


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ManifestValidationError("manifest file could not be inspected") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ManifestValidationError("manifest path must be a regular file")
    if metadata.st_size > _MAX_MANIFEST_BYTES:
        raise ManifestValidationError("manifest exceeds the 1 MiB input limit")

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ManifestValidationError("manifest is not valid UTF-8 JSON") from error
    validate_manifest(document)
    return document


def _validate_semantics(document: dict[str, Any]) -> None:
    collection = document["collection"]
    started = _parse_timestamp(collection["started_at"])
    finished = _parse_timestamp(collection["finished_at"])
    if finished < started:
        raise ManifestValidationError("collection.finished_at precedes started_at")

    artifact_ids: set[str] = set()
    artifact_paths: set[str] = set()
    incomplete = False
    for artifact in document["artifacts"]:
        artifact_id = artifact["id"]
        if artifact_id in artifact_ids:
            raise ManifestValidationError(f"duplicate artifact id: {artifact_id}")
        artifact_ids.add(artifact_id)

        if artifact["status"] != "collected" or artifact["truncated"]:
            incomplete = True
        if artifact["status"] != "collected":
            continue

        artifact_path = artifact["path"]
        if not _is_safe_relative_path(artifact_path):
            raise ManifestValidationError(
                f"artifact {artifact_id} path is not a safe relative path"
            )
        if artifact_path == "manifest.json":
            raise ManifestValidationError("manifest.json cannot be listed as its own artifact")
        if artifact_path in artifact_paths:
            raise ManifestValidationError(f"duplicate artifact path: {artifact_path}")
        artifact_paths.add(artifact_path)

    if collection["status"] == "complete" and incomplete:
        raise ManifestValidationError("complete collection contains incomplete evidence")
    if collection["status"] == "partial" and not incomplete:
        raise ManifestValidationError("partial collection contains no incomplete evidence")


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _is_safe_relative_path(value: str) -> bool:
    if "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.as_posix() == value
        and all(part not in {"", ".", ".."} for part in path.parts)
    )
