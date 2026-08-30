from __future__ import annotations

import json
import tarfile
from pathlib import Path

from incident_pack.archive import verify_bundle
from incident_pack.collection.system_parser import CollectorEvidence
from incident_pack.collectors.configuration import ConfigurationCollection
from incident_pack.collectors.journal import JournalCollection
from incident_pack.collectors.network import NetworkCheck, ResolverCollection
from incident_pack.collectors.packages import PackageCollection
from incident_pack.config import load_config
from incident_pack.plan import compile_plan
from incident_pack.workflow import collect_bundle


def test_integrated_collection_publishes_a_verified_accounted_bundle(
    tmp_path: Path, monkeypatch
) -> None:
    output = tmp_path / "case-1042.tar.gz"
    plan = compile_plan(
        service="nginx.service",
        since_seconds=7200,
        config=load_config(None),
        cli_exclusions=(),
        dns_targets=(),
        connect_targets=(),
        allow_root=False,
        effective_uid=1000,
    )
    monkeypatch.setattr(
        "incident_pack.workflow._collect_service",
        lambda _plan: CollectorEvidence(
            status="collected",
            data={
                "active_state": "active",
                "sub_state": "running",
                "result": "success",
                "restart_count": 0,
            },
        ),
    )
    monkeypatch.setattr(
        "incident_pack.workflow._collect_resources",
        lambda _plan: CollectorEvidence(
            status="collected",
            data={
                "load": {"1m": 0.1, "5m": 0.2, "15m": 0.3},
                "memory": {"available_bytes": 50, "total_bytes": 100},
                "filesystem": {"used_percent": 20},
            },
        ),
    )
    monkeypatch.setattr(
        "incident_pack.workflow.collect_journal",
        lambda **_kwargs: JournalCollection(
            status="collected",
            content=b'{"priority":3,"message":"failed"}\n',
            record_count=1,
            truncated=False,
            truncation_reasons=(),
            redaction_counts={},
        ),
    )
    configuration = ConfigurationCollection(
        status="collected",
        files=(
            {
                "path": "/usr/lib/systemd/system/nginx.service",
                "sha256": "a" * 64,
            },
        ),
    )
    monkeypatch.setattr(
        "incident_pack.workflow.collect_configuration", lambda **_kwargs: configuration
    )
    monkeypatch.setattr(
        "incident_pack.workflow.collect_packages",
        lambda **_kwargs: PackageCollection(
            status="collected",
            packages=(
                {
                    "name": "nginx",
                    "version": "1.0",
                    "architecture": "amd64",
                    "status": "install ok installed",
                },
            ),
        ),
    )

    digest = collect_bundle(plan, output)

    assert verify_bundle(output).archive_sha256 == digest
    with tarfile.open(output, "r:gz") as archive:
        manifest_file = archive.extractfile("manifest.json")
        summary_file = archive.extractfile("summary.txt")
        assert manifest_file is not None
        assert summary_file is not None
        manifest = json.load(manifest_file)
        summary = summary_file.read().decode()
        members = {member.name for member in archive.getmembers()}

    assert manifest["collection"]["status"] == "complete"
    assert [artifact["id"] for artifact in manifest["artifacts"]] == [
        "summary",
        "service",
        "resources",
        "journal",
        "packages",
        "configuration",
    ]
    assert members == {
        "manifest.json",
        "summary.txt",
        "evidence/service.json",
        "evidence/resources.json",
        "evidence/journal.ndjson",
        "evidence/packages.json",
        "evidence/configuration.json",
    }
    assert "Collection status: COMPLETE" in summary
    assert "Journal: 1 records; 1 error-priority records" in summary


def test_integrated_collection_records_exclusions_and_collector_failures(
    tmp_path: Path, monkeypatch
) -> None:
    output = tmp_path / "partial.tar.gz"
    plan = compile_plan(
        service="nginx.service",
        since_seconds=7200,
        config=load_config(None),
        cli_exclusions=("packages.metadata", "configuration.metadata"),
        dns_targets=(),
        connect_targets=(),
        allow_root=False,
        effective_uid=1000,
    )
    monkeypatch.setattr(
        "incident_pack.workflow._collect_service",
        lambda _plan: CollectorEvidence(
            status="error", data={}, diagnostic_code="SERVICE_QUERY_FAILED"
        ),
    )
    monkeypatch.setattr(
        "incident_pack.workflow._collect_resources",
        lambda _plan: CollectorEvidence(
            status="skipped", data={}, diagnostic_code="RESOURCE_EVIDENCE_UNAVAILABLE"
        ),
    )
    monkeypatch.setattr(
        "incident_pack.workflow.collect_journal",
        lambda **_kwargs: JournalCollection(
            status="collected",
            content=b"",
            record_count=0,
            truncated=True,
            truncation_reasons=("RECORD_LIMIT",),
            redaction_counts={},
        ),
    )

    collect_bundle(plan, output)

    with tarfile.open(output, "r:gz") as archive:
        manifest_file = archive.extractfile("manifest.json")
        assert manifest_file is not None
        manifest = json.load(manifest_file)
    statuses = {artifact["id"]: artifact["status"] for artifact in manifest["artifacts"]}
    assert manifest["collection"]["status"] == "partial"
    assert statuses == {
        "summary": "collected",
        "service": "error",
        "resources": "skipped",
        "journal": "collected",
        "packages": "excluded",
        "configuration": "excluded",
    }


def test_integrated_collection_records_only_explicit_network_checks(
    tmp_path: Path, monkeypatch
) -> None:
    output = tmp_path / "network.tar.gz"
    plan = compile_plan(
        service="nginx.service",
        since_seconds=7200,
        config=load_config(None),
        cli_exclusions=(
            "service.status",
            "resources.pressure",
            "logs.journal",
            "packages.metadata",
            "configuration.metadata",
        ),
        dns_targets=("api.example.test",),
        connect_targets=(("api.example.test", 443),),
        allow_root=False,
        effective_uid=1000,
    )
    monkeypatch.setattr(
        "incident_pack.workflow.collect_resolver_metadata",
        lambda: ResolverCollection(
            status="collected",
            data={"nameserver_count": 1, "nameserver_families": ("IPv4",)},
        ),
    )
    monkeypatch.setattr(
        "incident_pack.workflow.check_dns",
        lambda target, **_kwargs: NetworkCheck(
            status="collected",
            outcome="resolved",
            target=target,
            port=None,
            elapsed_ms=2,
            address_families=("IPv4",),
            address_scopes=("global",),
        ),
    )
    monkeypatch.setattr(
        "incident_pack.workflow.check_tcp",
        lambda target, port, **_kwargs: NetworkCheck(
            status="collected",
            outcome="connected",
            target=target,
            port=port,
            elapsed_ms=3,
            address_families=("IPv4",),
            address_scopes=("global",),
        ),
    )

    collect_bundle(plan, output)

    with tarfile.open(output, "r:gz") as archive:
        dns_file = archive.extractfile("evidence/dns.json")
        connectivity_file = archive.extractfile("evidence/connectivity.json")
        assert dns_file is not None
        assert connectivity_file is not None
        dns = json.load(dns_file)
        connectivity = json.load(connectivity_file)

    assert dns["checks"][0]["target"] == "api.example.test"
    assert dns["resolver"]["data"]["nameserver_count"] == 1
    assert connectivity["checks"][0]["port"] == 443
    assert connectivity["checks"][0]["outcome"] == "connected"


def test_missing_resolver_metadata_makes_requested_dns_evidence_partial(
    tmp_path: Path, monkeypatch
) -> None:
    output = tmp_path / "dns-partial.tar.gz"
    plan = compile_plan(
        service="nginx.service",
        since_seconds=7200,
        config=load_config(None),
        cli_exclusions=(
            "service.status",
            "resources.pressure",
            "logs.journal",
            "packages.metadata",
            "configuration.metadata",
        ),
        dns_targets=("api.example.test",),
        connect_targets=(),
        allow_root=False,
        effective_uid=1000,
    )
    monkeypatch.setattr(
        "incident_pack.workflow.collect_resolver_metadata",
        lambda: ResolverCollection(
            status="skipped",
            data={},
            diagnostic_code="RESOLVER_CONFIGURATION_UNAVAILABLE",
        ),
    )

    def unexpected_check(*_args, **_kwargs):
        raise AssertionError("DNS check ran without recordable resolver metadata")

    monkeypatch.setattr("incident_pack.workflow.check_dns", unexpected_check)

    collect_bundle(plan, output)

    with tarfile.open(output, "r:gz") as archive:
        manifest_file = archive.extractfile("manifest.json")
        assert manifest_file is not None
        manifest = json.load(manifest_file)
    dns = next(artifact for artifact in manifest["artifacts"] if artifact["id"] == "dns")
    assert dns["status"] == "skipped"
    assert dns["diagnostic_code"] == "RESOLVER_CONFIGURATION_UNAVAILABLE"
