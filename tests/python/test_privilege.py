from __future__ import annotations

import pytest

from incident_pack.cli import main
from incident_pack.config import load_config
from incident_pack.plan import PrivilegeError, compile_plan, require_collection_privilege


def _root_plan(*, allow_root: bool):
    return compile_plan(
        service="nginx.service",
        since_seconds=7200,
        config=load_config(None),
        cli_exclusions=(),
        dns_targets=(),
        connect_targets=(),
        allow_root=allow_root,
        effective_uid=0,
    )


def test_root_plan_requires_explicit_acknowledgement() -> None:
    plan = _root_plan(allow_root=False)

    assert plan.privilege == "root"
    assert plan.root_acknowledged is False
    assert plan.collection_allowed is False
    with pytest.raises(PrivilegeError, match="--allow-root"):
        require_collection_privilege(plan)


def test_allow_root_acknowledges_but_does_not_change_the_catalogue_or_limits() -> None:
    blocked = _root_plan(allow_root=False)
    acknowledged = _root_plan(allow_root=True)

    assert acknowledged.root_acknowledged is True
    assert acknowledged.collection_allowed is True
    assert acknowledged.artifacts == blocked.artifacts
    assert acknowledged.limits == blocked.limits
    require_collection_privilege(acknowledged)


def test_root_collection_without_acknowledgement_fails_before_checkpoint_message(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr("incident_pack.plan.os.geteuid", lambda: 0)

    exit_code = main(["--service", "nginx", "--output", str(tmp_path / "case.tar.gz")])

    captured = capsys.readouterr()
    assert exit_code == 3
    assert "--allow-root" in captured.err
    assert "not implemented" not in captured.err
    assert not (tmp_path / "case.tar.gz").exists()
