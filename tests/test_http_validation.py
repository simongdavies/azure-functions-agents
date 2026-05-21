"""Tests for the ``x-ms-session-id`` allow-list gate.

The gate enforces that session ids reaching the Copilot SDK / response
header / log fields can only contain ``[A-Za-z0-9_-]`` (max 128 chars).
That rules out path-traversal segments, CRLF for header / log
injection, and control bytes that break downstream parsers.
"""

from __future__ import annotations

import pytest

from .conftest import load_module_in_isolation

_http_validation = load_module_in_isolation(
    "af_agents_http_validation_under_test", "http_validation.py"
)


# ---------------------------------------------------------------------------
# Happy path -- accept legit ids
# ---------------------------------------------------------------------------


def test_accepts_uuid_style() -> None:
    sid = "550e8400-e29b-41d4-a716-446655440000"
    assert _http_validation.validate_session_id(sid) == sid


def test_accepts_alphanumeric_only() -> None:
    sid = "abc123XYZ"
    assert _http_validation.validate_session_id(sid) == sid


def test_accepts_underscores_and_dashes() -> None:
    sid = "a_b-c_d-e"
    assert _http_validation.validate_session_id(sid) == sid


def test_accepts_max_length() -> None:
    sid = "a" * _http_validation.SESSION_ID_MAX_LEN
    assert _http_validation.validate_session_id(sid) == sid


def test_accepts_single_char() -> None:
    assert _http_validation.validate_session_id("x") == "x"


# ---------------------------------------------------------------------------
# Absent / empty -- treated as "no session id"
# ---------------------------------------------------------------------------


def test_none_returns_none() -> None:
    assert _http_validation.validate_session_id(None) is None


def test_empty_string_returns_none() -> None:
    assert _http_validation.validate_session_id("") is None


def test_whitespace_only_returns_none() -> None:
    """A header that was sent as ``"   "`` is treated as not-set, not as
    a 400 -- it carries no semantic content.
    """
    assert _http_validation.validate_session_id("   ") is None


def test_strips_surrounding_whitespace() -> None:
    assert _http_validation.validate_session_id(" abc ") == "abc"


# ---------------------------------------------------------------------------
# Rejection -- the security-relevant cases
# ---------------------------------------------------------------------------


def test_rejects_path_traversal_dotdot() -> None:
    """``..`` is the classic path-escape trick against the SDK's
    session-state directory."""
    with pytest.raises(ValueError):
        _http_validation.validate_session_id("..")


def test_rejects_path_separator_forward_slash() -> None:
    with pytest.raises(ValueError):
        _http_validation.validate_session_id("a/b")


def test_rejects_path_separator_backslash() -> None:
    with pytest.raises(ValueError):
        _http_validation.validate_session_id("a\\b")


def test_rejects_dotdot_with_slash() -> None:
    with pytest.raises(ValueError):
        _http_validation.validate_session_id("../etc/passwd")


def test_rejects_crlf() -> None:
    """CRLF in a header value enables HTTP response splitting and
    log-injection -- the chief reason this gate exists."""
    with pytest.raises(ValueError):
        _http_validation.validate_session_id("abc\r\nX-Evil: 1")


def test_rejects_newline() -> None:
    with pytest.raises(ValueError):
        _http_validation.validate_session_id("abc\nfake-log-line")


def test_rejects_carriage_return() -> None:
    with pytest.raises(ValueError):
        _http_validation.validate_session_id("abc\rmore")


def test_rejects_null_byte() -> None:
    with pytest.raises(ValueError):
        _http_validation.validate_session_id("abc\x00more")


def test_rejects_tab() -> None:
    with pytest.raises(ValueError):
        _http_validation.validate_session_id("abc\tmore")


def test_rejects_space_in_middle() -> None:
    with pytest.raises(ValueError):
        _http_validation.validate_session_id("abc def")


def test_rejects_dot_character() -> None:
    """``.`` is not in the allow-list (it's a path-relevant char)."""
    with pytest.raises(ValueError):
        _http_validation.validate_session_id("abc.def")


def test_rejects_colon() -> None:
    with pytest.raises(ValueError):
        _http_validation.validate_session_id("abc:def")


def test_rejects_unicode() -> None:
    with pytest.raises(ValueError):
        _http_validation.validate_session_id("café")


def test_rejects_just_over_max_length() -> None:
    sid = "a" * (_http_validation.SESSION_ID_MAX_LEN + 1)
    with pytest.raises(ValueError):
        _http_validation.validate_session_id(sid)


def test_error_message_mentions_pattern() -> None:
    """The error message tells the caller what shape is expected."""
    with pytest.raises(ValueError) as excinfo:
        _http_validation.validate_session_id("bad/value")
    msg = str(excinfo.value)
    assert "x-ms-session-id" in msg


# ---------------------------------------------------------------------------
# Constants -- pinned so widening the allow-list is loud
# ---------------------------------------------------------------------------


def test_max_length_pinned() -> None:
    assert _http_validation.SESSION_ID_MAX_LEN == 128


def test_pattern_pinned() -> None:
    """Pin the literal regex source so accidental widening is a test
    failure, not a silent regression."""
    assert _http_validation.SESSION_ID_RE.pattern == r"^[A-Za-z0-9_\-]{1,128}$"
