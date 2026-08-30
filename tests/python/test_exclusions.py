from __future__ import annotations

import pytest

from incident_pack.plan import ARTIFACT_CATALOGUE, PlanError, compile_exclusions


def test_exclusion_globs_match_logical_catalogue_ids_only() -> None:
    policy = compile_exclusions(["network.*", "logs.journal"])

    assert policy.patterns == ("network.*", "logs.journal")
    assert policy.excluded_ids == (
        "logs.journal",
        "network.dns",
        "network.connectivity",
    )


def test_unmatched_exclusion_is_an_error_instead_of_false_assurance() -> None:
    with pytest.raises(PlanError, match="does not match"):
        compile_exclusions(["network.dnsx"])


def test_exclusion_cannot_remove_the_mandatory_summary() -> None:
    with pytest.raises(PlanError, match="mandatory"):
        compile_exclusions(["summary"])


def test_exclusions_cannot_enable_prohibited_or_unknown_sources() -> None:
    with pytest.raises(PlanError, match="does not match"):
        compile_exclusions(["environment.*"])

    assert "environment.variables" not in {item.logical_id for item in ARTIFACT_CATALOGUE}
    assert "configuration.contents" not in {item.logical_id for item in ARTIFACT_CATALOGUE}


def test_duplicate_patterns_are_deduplicated_in_stable_order() -> None:
    policy = compile_exclusions(["network.*", "logs.*", "network.*"])

    assert policy.patterns == ("network.*", "logs.*")


@pytest.mark.parametrize("pattern", ["", "a" * 129, "network.\n*"])
def test_exclusion_patterns_have_a_narrow_text_contract(pattern: str) -> None:
    with pytest.raises(PlanError):
        compile_exclusions([pattern])
