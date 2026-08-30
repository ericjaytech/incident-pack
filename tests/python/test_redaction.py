from __future__ import annotations

import pytest

from incident_pack.redaction import (
    ForbiddenContentError,
    RedactionLimitError,
    assert_no_forbidden_content,
    redact_chunks,
)


@pytest.mark.parametrize(
    ("payload", "marker"),
    [
        (b"password=hunter2", "[REDACTED:CREDENTIAL]"),
        (b"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature", "[REDACTED:AUTH]"),
        (b"Cookie: session=deadbeef", "[REDACTED:COOKIE]"),
        (b"token=ghp_abcdefghijklmnopqrstuvwxyz123456", "[REDACTED:CREDENTIAL]"),
        (b"contact=operator@example.test", "[REDACTED:EMAIL]"),
        (b"peer=192.0.2.44", "[REDACTED:IP_ADDRESS]"),
        (b"peer=2001:db8::44", "[REDACTED:IP_ADDRESS]"),
        (b"file=/home/alex/.config/app", "/home/[REDACTED:USERNAME]/.config/app"),
        (b"https://example.test/a?password=hunter2&view=brief", "password=[REDACTED:URI_VALUE]"),
    ],
)
def test_redact_chunks_replaces_supported_sensitive_forms(payload: bytes, marker: str) -> None:
    result = redact_chunks([payload])

    text = result.content.decode("utf-8")
    assert marker in text
    assert "hunter2" not in text
    assert "operator@example.test" not in text
    assert "192.0.2.44" not in text
    assert "2001:db8::44" not in text
    assert "alex" not in text


def test_redact_chunks_handles_a_secret_split_at_every_input_boundary() -> None:
    payload = b"event password=correct-horse-battery-staple complete\n"

    for boundary in range(1, len(payload)):
        result = redact_chunks([payload[:boundary], payload[boundary:]])
        text = result.content.decode("utf-8")
        assert "correct-horse-battery-staple" not in text
        assert "[REDACTED:CREDENTIAL]" in text


def test_redact_chunks_removes_a_complete_or_unterminated_private_key_block() -> None:
    complete = (
        b"before\n-----BEGIN PRIVATE KEY-----\nsecret material\n-----END PRIVATE KEY-----\nafter\n"
    )
    unterminated = b"before\n-----BEGIN OPENSSH PRIVATE KEY-----\nsecret material\n"

    complete_result = redact_chunks([complete[:17], complete[17:]])
    unterminated_result = redact_chunks([unterminated])

    assert complete_result.content == b"before\n[REDACTED:PRIVATE_KEY]\nafter\n"
    assert unterminated_result.content == b"before\n[REDACTED:PRIVATE_KEY]"
    assert complete_result.counts["PRIVATE_KEY"] == 1
    assert unterminated_result.counts["PRIVATE_KEY"] == 1


def test_redact_chunks_normalises_invalid_utf8_and_escapes_terminal_controls() -> None:
    result = redact_chunks([b"safe\xff\x1b[31mtext\x07\nnext\tfield"])

    assert result.content.decode("utf-8") == "safe�\\x1b[31mtext\\x07\nnext\tfield"


def test_redact_chunks_rejects_input_and_output_above_explicit_limits() -> None:
    with pytest.raises(RedactionLimitError, match="input limit"):
        redact_chunks([b"123", b"456"], max_input_bytes=5)

    with pytest.raises(RedactionLimitError, match="output limit"):
        redact_chunks([b"\x1b"], max_input_bytes=1, max_output_bytes=3)


def test_redact_chunks_rejects_limits_above_compiled_hard_maximum() -> None:
    with pytest.raises(RedactionLimitError, match="hard maximum"):
        redact_chunks([], max_input_bytes=8_388_609)


def test_second_pass_rejects_private_key_boundaries_but_accepts_redacted_text() -> None:
    with pytest.raises(ForbiddenContentError, match="PRIVATE_KEY_BOUNDARY"):
        assert_no_forbidden_content("-----BEGIN RSA PRIVATE KEY-----")

    result = redact_chunks([b"-----BEGIN RSA PRIVATE KEY-----\nsecret"])
    assert_no_forbidden_content(result.content)


def test_redaction_counts_never_contain_matched_values() -> None:
    result = redact_chunks([b"password=one password=two"])

    assert result.counts == {"CREDENTIAL": 2}
    assert all(isinstance(count, int) for count in result.counts.values())
