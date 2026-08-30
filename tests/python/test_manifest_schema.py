from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from incident_pack.manifest import (
    ManifestValidationError,
    load_manifest,
    load_manifest_schema,
    validate_manifest,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "manifests"


def _fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_packaged_manifest_schema_is_valid_json_schema() -> None:
    schema = load_manifest_schema()

    assert schema["$id"] == "https://ericjaytech.github.io/incident-pack/manifest-v1.schema.json"


@pytest.mark.parametrize("name", ["complete.json", "partial.json"])
def test_synthetic_manifests_validate(name: str) -> None:
    validate_manifest(_fixture(name))


def test_invalid_fixture_is_rejected() -> None:
    with pytest.raises(ManifestValidationError):
        validate_manifest(_fixture("invalid.json"))


def test_unknown_properties_cannot_smuggle_identifiers() -> None:
    document = _fixture("complete.json")
    document["hostname"] = "should-not-be-present"

    with pytest.raises(ManifestValidationError, match="hostname"):
        validate_manifest(document)


def test_unsupported_schema_version_is_rejected() -> None:
    document = _fixture("complete.json")
    document["schema_version"] = 2

    with pytest.raises(ManifestValidationError, match="schema_version"):
        validate_manifest(document)


def test_artifact_identifiers_must_be_unique() -> None:
    document = _fixture("complete.json")
    document["artifacts"].append(copy.deepcopy(document["artifacts"][0]))  # type: ignore[union-attr,index]

    with pytest.raises(ManifestValidationError, match="duplicate artifact id"):
        validate_manifest(document)


def test_complete_manifest_cannot_contain_skipped_evidence() -> None:
    document = _fixture("partial.json")
    document["collection"]["status"] = "complete"  # type: ignore[index]

    with pytest.raises(ManifestValidationError, match="complete collection"):
        validate_manifest(document)


def test_complete_manifest_cannot_contain_truncated_evidence() -> None:
    document = _fixture("complete.json")
    document["artifacts"][0]["truncated"] = True  # type: ignore[index]

    with pytest.raises(ManifestValidationError, match="complete collection"):
        validate_manifest(document)


@pytest.mark.parametrize("path", ["/absolute.json", "../escape.json", "evidence/../escape.json"])
def test_artifact_paths_must_be_safe_relative_posix_paths(path: str) -> None:
    document = _fixture("complete.json")
    document["artifacts"][0]["path"] = path  # type: ignore[index]

    with pytest.raises(ManifestValidationError, match="safe relative path"):
        validate_manifest(document)


def test_collection_finish_cannot_precede_start() -> None:
    document = _fixture("complete.json")
    document["collection"]["finished_at"] = "2026-08-30T11:59:59Z"  # type: ignore[index]

    with pytest.raises(ManifestValidationError, match="finished_at"):
        validate_manifest(document)


def test_load_manifest_rejects_oversized_input(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_bytes(b"{" + b" " * 1_048_576 + b"}")

    with pytest.raises(ManifestValidationError, match="1 MiB"):
        load_manifest(path)
