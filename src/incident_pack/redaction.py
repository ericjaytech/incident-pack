from __future__ import annotations

import ipaddress
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

_HARD_MAX_BYTES = 8_388_608
_DEFAULT_MAX_BYTES = 32_768

_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?P<label>(?:(?:RSA|DSA|EC|OPENSSH|ENCRYPTED) )?PRIVATE KEY)-----"
    r".*?(?:-----END (?P=label)-----|\Z)",
    re.DOTALL,
)
_PRIVATE_KEY_BOUNDARY = re.compile(
    r"-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----"
)
_URI_VALUE_PATTERN = re.compile(
    r"(?P<prefix>[?&](?:password|passwd|passphrase|secret|api[_-]?key|"
    r"access[_-]?token|auth[_-]?token)=)[^&#\s]*",
    re.IGNORECASE,
)
_AUTH_PATTERN = re.compile(
    r"(?P<prefix>\b(?:proxy-)?authorization\s*[:=]\s*)(?:bearer|basic)\s+[^\s,;]+",
    re.IGNORECASE,
)
_COOKIE_PATTERN = re.compile(
    r"(?P<prefix>\b(?:set-cookie|cookie)\s*[:=]\s*)[^\r\n]+",
    re.IGNORECASE,
)
_CREDENTIAL_PATTERN = re.compile(
    r"(?P<prefix>\b(?:password|passwd|passphrase|secret|api[_-]?key|"
    r"access[_-]?token|auth[_-]?token|token)\s*[:=]\s*)"
    r"(?!\[REDACTED:)(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s&,;]+)",
    re.IGNORECASE,
)
_TOKEN_PATTERN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{16,}|"
    r"AKIA[0-9A-Z]{16})\b"
)
_EMAIL_PATTERN = re.compile(
    r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
)
_IPV4_CANDIDATE = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
_IPV6_CANDIDATE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
    r"(?![0-9A-Fa-f:])"
)
_HOME_PATTERN = re.compile(r"(?P<prefix>/home/)[^/\s]+")


class RedactionError(ValueError):
    """Raised when untrusted text cannot be processed safely."""


class RedactionLimitError(RedactionError):
    """Raised when redaction would exceed an explicit byte bound."""


class ForbiddenContentError(RedactionError):
    """Raised when a mandatory forbidden form remains after redaction."""


@dataclass(frozen=True)
class RedactionResult:
    content: bytes
    counts: Mapping[str, int]


def redact_chunks(
    chunks: Iterable[bytes],
    *,
    max_input_bytes: int = _DEFAULT_MAX_BYTES,
    max_output_bytes: int = _DEFAULT_MAX_BYTES,
) -> RedactionResult:
    """Redact a bounded byte stream without writing its raw content to disk."""
    _validate_limit(max_input_bytes, "input")
    _validate_limit(max_output_bytes, "output")

    raw = bytearray()
    for chunk in chunks:
        if not isinstance(chunk, bytes):
            raise RedactionError("redaction chunks must be bytes")
        if len(raw) + len(chunk) > max_input_bytes:
            raise RedactionLimitError("redaction input limit exceeded")
        raw.extend(chunk)

    text = bytes(raw).decode("utf-8", errors="replace")
    counts: dict[str, int] = {}

    text = _replace(text, _PRIVATE_KEY_PATTERN, "PRIVATE_KEY", counts)
    text = _replace_with_prefix(text, _URI_VALUE_PATTERN, "URI_VALUE", counts)
    text = _replace_with_prefix(text, _AUTH_PATTERN, "AUTH", counts)
    text = _replace_with_prefix(text, _COOKIE_PATTERN, "COOKIE", counts)
    text = _replace_with_prefix(text, _CREDENTIAL_PATTERN, "CREDENTIAL", counts)
    text = _replace(text, _TOKEN_PATTERN, "TOKEN", counts)
    text = _replace(text, _EMAIL_PATTERN, "EMAIL", counts)
    text = _replace_valid_addresses(text, _IPV4_CANDIDATE, counts)
    text = _replace_valid_addresses(text, _IPV6_CANDIDATE, counts)
    text = _replace_with_prefix(text, _HOME_PATTERN, "USERNAME", counts)

    text = _escape_terminal_controls(text)
    content = text.encode("utf-8")
    if len(content) > max_output_bytes:
        raise RedactionLimitError("redaction output limit exceeded")
    assert_no_forbidden_content(content)
    return RedactionResult(content=content, counts=MappingProxyType(dict(sorted(counts.items()))))


def assert_no_forbidden_content(content: bytes | str) -> None:
    text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
    if _PRIVATE_KEY_BOUNDARY.search(text):
        raise ForbiddenContentError("forbidden content detected: PRIVATE_KEY_BOUNDARY")


def _validate_limit(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise RedactionLimitError(f"redaction {name} limit must be a positive integer")
    if value > _HARD_MAX_BYTES:
        raise RedactionLimitError(f"redaction {name} limit exceeds the compiled hard maximum")


def _replace(text: str, pattern: re.Pattern[str], rule: str, counts: dict[str, int]) -> str:
    redacted, count = pattern.subn(f"[REDACTED:{rule}]", text)
    if count:
        counts[rule] = counts.get(rule, 0) + count
    return redacted


def _replace_with_prefix(
    text: str, pattern: re.Pattern[str], rule: str, counts: dict[str, int]
) -> str:
    redacted, count = pattern.subn(rf"\g<prefix>[REDACTED:{rule}]", text)
    if count:
        counts[rule] = counts.get(rule, 0) + count
    return redacted


def _replace_valid_addresses(text: str, pattern: re.Pattern[str], counts: dict[str, int]) -> str:
    count = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal count
        try:
            ipaddress.ip_address(match.group(0))
        except ValueError:
            return match.group(0)
        count += 1
        return "[REDACTED:IP_ADDRESS]"

    redacted = pattern.sub(replace, text)
    if count:
        counts["IP_ADDRESS"] = counts.get("IP_ADDRESS", 0) + count
    return redacted


def _escape_terminal_controls(text: str) -> str:
    escaped: list[str] = []
    for character in text:
        if character in {"\n", "\t"} or unicodedata.category(character) != "Cc":
            escaped.append(character)
        elif ord(character) <= 0xFF:
            escaped.append(f"\\x{ord(character):02x}")
        else:
            escaped.append(f"\\u{ord(character):04x}")
    return "".join(escaped)
