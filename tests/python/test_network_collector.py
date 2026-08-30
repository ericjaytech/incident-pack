from __future__ import annotations

import socket
import time
from pathlib import Path

import pytest

from incident_pack.collectors.network import (
    check_dns,
    check_tcp,
    collect_resolver_metadata,
    parse_resolver_configuration,
)


def _successful_resolver(
    host: str, port: int | None, *, family: int, type: int
) -> list[tuple[int, int, int, str, tuple[object, ...]]]:
    del host, port, family, type
    return [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 0)),
        (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("2001:4860:4860::8888", 0, 0, 0),
        ),
    ]


def _failing_resolver(
    host: str, port: int | None, *, family: int, type: int
) -> list[tuple[int, int, int, str, tuple[object, ...]]]:
    del host, port, family, type
    raise socket.gaierror("synthetic resolver detail must not leak")


def _slow_resolver(
    host: str, port: int | None, *, family: int, type: int
) -> list[tuple[int, int, int, str, tuple[object, ...]]]:
    del host, port, family, type
    time.sleep(1)
    return []


def _loopback_resolver(
    host: str, port: int | None, *, family: int, type: int
) -> list[tuple[int, int, int, str, tuple[object, ...]]]:
    del host, family, type
    assert port is not None
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", port))]


def test_resolver_parser_reduces_addresses_and_domains_to_metadata() -> None:
    payload = b"""\
# generated configuration
nameserver 127.0.0.53
nameserver 10.20.30.40
nameserver 2001:4860:4860::8888
search internal.example.test example.test
options edns0 trust-ad
"""

    result = parse_resolver_configuration(payload)

    assert result == {
        "nameserver_count": 3,
        "nameserver_families": ("IPv4", "IPv6"),
        "nameserver_scopes": ("global", "loopback", "private"),
        "options_count": 2,
        "search_domain_count": 2,
    }
    assert b"127.0.0.53" not in repr(result).encode()
    assert b"internal.example.test" not in repr(result).encode()


@pytest.mark.parametrize(
    "payload",
    [
        b"nameserver not-an-address\n",
        b"nameserver 8.8.8.8 extra\n",
        b"search bad\x00domain\n",
        b"x" * 65_537,
    ],
)
def test_resolver_parser_rejects_malformed_or_oversized_input(payload: bytes) -> None:
    with pytest.raises(ValueError, match="resolver configuration"):
        parse_resolver_configuration(payload)


def test_resolver_collector_reads_only_the_fixed_bounded_regular_file(tmp_path: Path) -> None:
    root = tmp_path / "run"
    root.mkdir()
    target = root / "resolv.conf"
    target.write_text("nameserver 8.8.8.8\nsearch private.example.test\n", encoding="ascii")
    link = tmp_path / "etc-resolv.conf"
    link.symlink_to(target)

    result = collect_resolver_metadata(_path=link, _allowed_roots=(tmp_path, root))

    assert result.status == "collected"
    assert result.data["nameserver_scopes"] == ("global",)
    assert "8.8.8.8" not in repr(result)
    assert "private.example.test" not in repr(result)


def test_resolver_collector_rejects_symlink_escape_and_missing_file(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside" / "resolv.conf"
    outside.parent.mkdir()
    outside.write_text("nameserver 8.8.8.8\n", encoding="ascii")
    link = allowed / "resolv.conf"
    link.symlink_to(outside)

    escaped = collect_resolver_metadata(_path=link, _allowed_roots=(allowed,))
    missing = collect_resolver_metadata(
        _path=allowed / "missing.conf",
        _allowed_roots=(allowed,),
    )

    assert (escaped.status, escaped.diagnostic_code) == ("error", "RESOLVER_PATH_UNSAFE")
    assert (missing.status, missing.diagnostic_code) == (
        "skipped",
        "RESOLVER_CONFIGURATION_UNAVAILABLE",
    )
    assert escaped.data == missing.data == {}


def test_dns_check_retains_target_family_and_scope_without_raw_addresses() -> None:
    result = check_dns(
        "api.example.test",
        timeout_seconds=1,
        _resolver=_successful_resolver,
    )

    assert result.status == "collected"
    assert result.outcome == "resolved"
    assert result.target == "api.example.test"
    assert result.port is None
    assert result.address_families == ("IPv4", "IPv6")
    assert result.address_scopes == ("global",)
    assert result.diagnostic_code is None
    assert result.elapsed_ms >= 0
    assert "8.8.8.8" not in repr(result)
    assert "2001:4860:4860::8888" not in repr(result)


def test_dns_check_reports_lookup_failure_and_enforces_timeout_without_error_detail() -> None:
    failed = check_dns(
        "api.example.test",
        timeout_seconds=1,
        _resolver=_failing_resolver,
    )
    timed_out = check_dns(
        "api.example.test",
        timeout_seconds=0.2,
        _resolver=_slow_resolver,
    )

    assert (failed.status, failed.outcome, failed.diagnostic_code) == (
        "collected",
        "failed",
        "DNS_LOOKUP_FAILED",
    )
    assert (timed_out.status, timed_out.outcome, timed_out.diagnostic_code) == (
        "error",
        "incomplete",
        "DNS_LOOKUP_TIMEOUT",
    )
    assert "synthetic resolver detail" not in repr(failed)


def test_tcp_check_connects_without_sending_application_payload() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.settimeout(2)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        result = check_tcp(
            "api.example.test",
            port,
            timeout_seconds=1,
            _resolver=_loopback_resolver,
        )
        connection, _ = server.accept()
        with connection:
            connection.settimeout(1)
            received = connection.recv(1)
    finally:
        server.close()

    assert result.status == "collected"
    assert result.outcome == "connected"
    assert result.target == "api.example.test"
    assert result.port == port
    assert result.address_families == ("IPv4",)
    assert result.address_scopes == ("loopback",)
    assert received == b""
    assert "127.0.0.1" not in repr(result)


def test_tcp_check_reports_a_refused_connection_as_collected_evidence() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    server.close()

    result = check_tcp("127.0.0.1", port, timeout_seconds=1)

    assert result.status == "collected"
    assert result.outcome == "failed"
    assert result.diagnostic_code == "TCP_CONNECT_FAILED"
    assert result.address_families == ("IPv4",)
    assert result.address_scopes == ("loopback",)


def test_tcp_check_enforces_one_total_timeout() -> None:
    result = check_tcp(
        "api.example.test",
        443,
        timeout_seconds=0.2,
        _resolver=_slow_resolver,
    )

    assert result.status == "error"
    assert result.outcome == "incomplete"
    assert result.diagnostic_code == "TCP_CHECK_TIMEOUT"


@pytest.mark.parametrize(
    ("operation", "arguments"),
    [
        (check_dns, ("127.0.0.1",)),
        (check_dns, ("-option.example.test",)),
        (check_tcp, ("bad host", 443)),
        (check_tcp, ("api.example.test", 0)),
    ],
)
def test_network_checks_reject_invalid_targets_before_starting_a_worker(
    operation: object, arguments: tuple[object, ...]
) -> None:
    with pytest.raises(ValueError):
        operation(*arguments, timeout_seconds=1)
