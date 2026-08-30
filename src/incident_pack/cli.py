from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from incident_pack import __version__
from incident_pack.archive import BundleError, verify_bundle
from incident_pack.config import ConfigError, load_config
from incident_pack.plan import (
    EvidencePlan,
    PlanError,
    PrivilegeError,
    compile_plan,
    render_preview,
    require_collection_privilege,
)
from incident_pack.workflow import collect_bundle

_DURATION_PATTERN = re.compile(r"([1-9][0-9]*)([mhd])")
_SERVICE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@:-]*")
_HOST_LABEL_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_MAX_DURATION_SECONDS = 24 * 60 * 60


class InputError(ValueError):
    """Raised when command-line input violates the collection contract."""


@dataclass(frozen=True)
class ParsedArguments:
    action: str
    service: str | None = None
    since_seconds: int | None = None
    output: Path | None = None
    archive: Path | None = None
    config: Path | None = None
    exclusions: tuple[str, ...] = ()
    dns_targets: tuple[str, ...] = ()
    connect_targets: tuple[tuple[str, int], ...] = ()
    allow_root: bool = False


def parse_duration(value: str) -> int:
    match = _DURATION_PATTERN.fullmatch(value)
    if match is None:
        raise InputError("duration must be a positive whole number followed by m, h or d")

    quantity = int(match.group(1))
    multiplier = {"m": 60, "h": 3600, "d": 86400}[match.group(2)]
    seconds = quantity * multiplier
    if seconds > _MAX_DURATION_SECONDS:
        raise InputError("duration must not exceed 24 hours")
    return seconds


def normalise_service(value: str) -> str:
    if value.endswith(".service"):
        name = value
    elif "." not in value:
        name = f"{value}.service"
    else:
        raise InputError("service must be a short name or end with .service")

    if len(name) > 255 or _SERVICE_PATTERN.fullmatch(name) is None or name.startswith("-"):
        raise InputError("service contains unsupported characters or is too long")
    return name


def parse_dns_target(value: str) -> str:
    return _validate_host(value, allow_ip=False)


def parse_connect_target(value: str) -> tuple[str, int]:
    if value.startswith("["):
        closing = value.find("]")
        if closing < 0 or closing + 1 >= len(value) or value[closing + 1] != ":":
            raise InputError("IPv6 connection targets must use [address]:port")
        host = value[1:closing]
        port_text = value[closing + 2 :]
        try:
            address = ipaddress.ip_address(host)
        except ValueError as error:
            raise InputError("bracketed connection target is not a valid IP address") from error
        if address.version != 6:
            raise InputError("brackets are only valid for IPv6 connection targets")
    else:
        if value.count(":") != 1:
            raise InputError("connection target must use host:port or [IPv6]:port")
        host, port_text = value.rsplit(":", 1)
        host = _validate_host(host, allow_ip=True)

    if not port_text.isascii() or not port_text.isdecimal():
        raise InputError("connection target port must be an integer")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise InputError("connection target port must be between 1 and 65535")
    return host, port


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="incident-pack",
        description="Create a bounded diagnostic bundle for service desk escalation.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--service", help="Systemd service name.")
    parser.add_argument("--since", help="Journal range such as 15m, 2h or 1d.")
    parser.add_argument("--output", type=Path, help="New .tar.gz bundle path.")
    parser.add_argument("--preview", action="store_true", help="Show the evidence plan only.")
    parser.add_argument("--verify", type=Path, metavar="ARCHIVE", help="Verify an existing bundle.")
    parser.add_argument("--config", type=Path, help="TOML configuration path.")
    parser.add_argument("--exclude", action="append", default=[], help="Artifact exclusion glob.")
    parser.add_argument("--dns-target", action="append", default=[], help="Explicit DNS target.")
    parser.add_argument(
        "--connect-target", action="append", default=[], help="Explicit host:port TCP target."
    )
    parser.add_argument(
        "--allow-root", action="store_true", help="Acknowledge collection as effective UID 0."
    )
    return parser


def parse_arguments(arguments: Sequence[str]) -> ParsedArguments:
    parsed = build_parser().parse_args(arguments)
    collection_values = (
        parsed.service,
        parsed.since,
        parsed.output,
        parsed.preview,
        parsed.config,
        parsed.exclude,
        parsed.dns_target,
        parsed.connect_target,
        parsed.allow_root,
    )

    if parsed.verify is not None:
        if any(collection_values):
            raise InputError("--verify cannot be combined with collection or preview options")
        archive = _validate_archive_input(parsed.verify)
        return ParsedArguments(action="verify", archive=archive)

    if parsed.service is None:
        raise InputError("--service is required for collection and preview")
    if parsed.preview and parsed.output is not None:
        raise InputError("--preview cannot be combined with --output")
    if not parsed.preview and parsed.output is None:
        raise InputError("--output is required for collection")

    output = _validate_output(parsed.output) if parsed.output is not None else None
    return ParsedArguments(
        action="preview" if parsed.preview else "collect",
        service=normalise_service(parsed.service),
        since_seconds=parse_duration(parsed.since) if parsed.since is not None else None,
        output=output,
        config=parsed.config,
        exclusions=tuple(parsed.exclude),
        dns_targets=tuple(parse_dns_target(value) for value in parsed.dns_target),
        connect_targets=tuple(parse_connect_target(value) for value in parsed.connect_target),
        allow_root=parsed.allow_root,
    )


def main(arguments: Sequence[str] | None = None) -> int:
    supplied = list(arguments) if arguments is not None else sys.argv[1:]
    if not supplied:
        build_parser().print_help()
        return 0
    try:
        parsed = parse_arguments(supplied)
    except InputError as error:
        print(f"incident-pack: {error}", file=sys.stderr)
        return 2

    if parsed.action == "verify":
        assert parsed.archive is not None
        try:
            verification = verify_bundle(parsed.archive)
        except BundleError as error:
            print(f"incident-pack: verification failed: {error}", file=sys.stderr)
            return 4
        for warning in verification.warnings:
            print(f"incident-pack: warning: {warning}", file=sys.stderr)
        print(f"Archive verified: {_display_path(parsed.archive)}")
        print(f"SHA-256: {verification.archive_sha256}")
        return 0

    assert parsed.service is not None
    try:
        config = load_config(parsed.config)
        plan = compile_plan(
            service=parsed.service,
            since_seconds=parsed.since_seconds,
            config=config,
            cli_exclusions=parsed.exclusions,
            dns_targets=parsed.dns_targets,
            connect_targets=parsed.connect_targets,
            allow_root=parsed.allow_root,
        )
    except (ConfigError, PlanError) as error:
        print(f"incident-pack: configuration or plan is invalid: {error}", file=sys.stderr)
        return 2

    if parsed.action == "preview":
        print(render_preview(plan), end="")
        return 0

    return _run_collection(parsed, plan)


def _run_collection(parsed: ParsedArguments, plan: EvidencePlan) -> int:
    try:
        require_collection_privilege(plan)
    except PrivilegeError as error:
        print(f"incident-pack: collection blocked: {error}", file=sys.stderr)
        return 3

    assert parsed.output is not None
    try:
        archive_digest = collect_bundle(plan, parsed.output)
    except BundleError as error:
        print(f"incident-pack: collection failed: {error}", file=sys.stderr)
        return 4
    except OSError:
        print(
            "incident-pack: collection failed safely due to an operating-system error",
            file=sys.stderr,
        )
        return 4

    print(f"Archive created: {_display_path(parsed.output)}")
    print(f"SHA-256: {archive_digest}")
    print(
        "incident-pack: warning: Inspect the archive before sharing it. "
        "Redaction reduces risk but is not a guarantee.",
        file=sys.stderr,
    )
    return 0


def _validate_host(value: str, *, allow_ip: bool) -> str:
    if not value or len(value) > 253 or not value.isascii():
        raise InputError("target host must be a non-empty ASCII name of at most 253 characters")

    if allow_ip:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            pass
    else:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            pass
        else:
            raise InputError("DNS target must be a hostname, not an IP address")

    candidate = value[:-1] if value.endswith(".") else value
    if not candidate or any(
        _HOST_LABEL_PATTERN.fullmatch(label) is None for label in candidate.split(".")
    ):
        raise InputError("target host has invalid DNS label syntax")
    return candidate.lower()


def _validate_output(path: Path) -> Path:
    if path.name in {"", ".", ".."} or not path.name.endswith(".tar.gz"):
        raise InputError("output path must end with .tar.gz")
    if path.exists() or path.is_symlink():
        raise InputError(f"output already exists: {_display_path(path)}")
    parent = path.parent
    if not parent.exists() or not parent.is_dir() or parent.is_symlink():
        raise InputError(f"output parent is not a safe existing directory: {_display_path(parent)}")
    return path


def _validate_archive_input(path: Path) -> Path:
    if path.is_symlink() or not path.is_file():
        raise InputError(f"archive is not a regular file: {_display_path(path)}")
    return path


def _display_path(path: Path) -> str:
    return json.dumps(str(path), ensure_ascii=True)
