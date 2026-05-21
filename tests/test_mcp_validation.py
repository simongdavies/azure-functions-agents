"""Tests for the stdio-MCP rejection gate (``mcp_validation.py``).

The gate enforces the invariant: developer-supplied ``mcp.json``
entries may only describe remote MCP servers (``type: http`` /
``type: sse``).  Local / stdio configs are a parse-time error so a
developer cannot have the host process fork an arbitrary binary.

The validation lives in its own stdlib-only module so this test file
runs without ``copilot.session`` installed.
"""

from __future__ import annotations

import pytest

from .conftest import load_module_in_isolation

_validation = load_module_in_isolation(
    "af_agents_mcp_validation_under_test", "mcp_validation.py"
)


# ---------------------------------------------------------------------------
# Local / stdio configs -- hard reject
# ---------------------------------------------------------------------------


def test_rejects_type_local() -> None:
    """``type: local`` (legacy Copilot SDK label) is rejected."""
    with pytest.raises(ValueError, match="not supported"):
        _validation.reject_local_stdio_mcp(
            {"type": "local", "command": "/usr/bin/python"}
        )


def test_rejects_type_stdio() -> None:
    """``type: stdio`` (MCP spec / current Copilot SDK label) is rejected."""
    with pytest.raises(ValueError, match="not supported"):
        _validation.reject_local_stdio_mcp({"type": "stdio", "command": "uvx"})


def test_rejects_type_is_case_insensitive() -> None:
    """``Local`` / ``STDIO`` are normalised before matching."""
    with pytest.raises(ValueError, match="not supported"):
        _validation.reject_local_stdio_mcp({"type": "Local"})
    with pytest.raises(ValueError, match="not supported"):
        _validation.reject_local_stdio_mcp({"type": "STDIO"})


def test_rejects_command_field_even_when_type_missing() -> None:
    """Stdio fields alone trigger the gate (no need for explicit type)."""
    with pytest.raises(ValueError, match=r"command"):
        _validation.reject_local_stdio_mcp({"command": "/usr/bin/python"})


def test_rejects_args_field_even_when_type_missing() -> None:
    with pytest.raises(ValueError, match=r"args"):
        _validation.reject_local_stdio_mcp({"args": ["server.py"]})


def test_rejects_env_field_even_when_type_missing() -> None:
    """``env`` matters: a developer who names AGENT_PATH could chain it."""
    with pytest.raises(ValueError, match=r"env"):
        _validation.reject_local_stdio_mcp({"env": {"PATH": "/etc"}})


def test_rejects_all_fields_listed_in_error() -> None:
    """A combo config lists all offending fields (helps the developer fix it)."""
    with pytest.raises(ValueError) as excinfo:
        _validation.reject_local_stdio_mcp(
            {"command": "x", "args": [], "env": {}}
        )
    msg = str(excinfo.value)
    assert "args" in msg
    assert "command" in msg
    assert "env" in msg


def test_error_message_mentions_remote_alternative() -> None:
    """Error message tells developers what to do instead."""
    with pytest.raises(ValueError) as excinfo:
        _validation.reject_local_stdio_mcp({"type": "stdio"})
    msg = str(excinfo.value)
    # The fix path: run remote, reference via type: http / sse + url.
    assert "http" in msg
    assert "sse" in msg
    assert "url" in msg


# ---------------------------------------------------------------------------
# Remote configs -- pass through silently
# ---------------------------------------------------------------------------


def test_accepts_http_url() -> None:
    """A pure remote-http entry passes through silently."""
    _validation.reject_local_stdio_mcp(
        {"type": "http", "url": "https://learn.microsoft.com/api/mcp"}
    )


def test_accepts_sse_url() -> None:
    _validation.reject_local_stdio_mcp(
        {"type": "sse", "url": "https://example.com/mcp"}
    )


def test_accepts_url_only_without_type() -> None:
    """The current parser defaults ``type`` to http when only url is given."""
    _validation.reject_local_stdio_mcp({"url": "https://example.com/mcp"})


def test_accepts_empty_config() -> None:
    """The gate is silent on shapes it doesn't recognise; the caller
    decides whether to fall through to ``None`` or treat as a noop.
    """
    _validation.reject_local_stdio_mcp({})


# ---------------------------------------------------------------------------
# Constants -- pinned so unintended widening of the allow-list is loud
# ---------------------------------------------------------------------------


def test_local_stdio_types_is_pinned() -> None:
    """Pin the rejected-type set so widening it requires a test edit."""
    assert _validation.LOCAL_STDIO_TYPES == frozenset({"local", "stdio"})


def test_local_stdio_fields_is_pinned() -> None:
    """Pin the rejected-field set."""
    assert _validation.LOCAL_STDIO_FIELDS == frozenset(
        {"command", "args", "env"}
    )


def test_allowed_remote_types_is_pinned() -> None:
    """Pin the allow-listed remote types -- adding to this list expands
    the parser surface and must be a conscious decision.
    """
    assert _validation.ALLOWED_REMOTE_TYPES == frozenset({"http", "sse"})
