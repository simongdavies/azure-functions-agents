"""Stdlib-only validation gates for ``mcp.json`` server entries.

Lives in its own module (rather than inside :mod:`mcp`) because
:mod:`mcp` imports :mod:`copilot.session` at module load -- which
pulls in the rest of the Copilot SDK and a small forest of optional
extras.  Keeping the security gate independent means it can be
unit-tested with nothing more than ``pip install pytest``.
"""

from __future__ import annotations

from typing import Any, Dict

__all__ = [
    "LOCAL_STDIO_FIELDS",
    "LOCAL_STDIO_TYPES",
    "ALLOWED_REMOTE_TYPES",
    "reject_local_stdio_mcp",
]

# Fields that signal a stdio / local MCP server.  Any of these in
# developer-supplied mcp.json is a hard parse-time rejection.
LOCAL_STDIO_FIELDS = frozenset({"command", "args", "env"})

# Type discriminators that name a stdio / local server explicitly.
# Both ``local`` (legacy Copilot SDK) and ``stdio`` (current Copilot
# SDK + the MCP spec) are rejected.
LOCAL_STDIO_TYPES = frozenset({"local", "stdio"})

# Allow-listed remote types.  ``stdio`` / ``local`` are intentionally
# absent: the Copilot SDK supports them but the framework does not.
ALLOWED_REMOTE_TYPES = frozenset({"http", "sse"})


def reject_local_stdio_mcp(server: Dict[str, Any]) -> None:
    """Raise :class:`ValueError` if the entry declares a local stdio server.

    Local / stdio MCP servers would have the Copilot SDK fork a
    developer-named binary in the **host** process tree -- the same
    process that holds the framework's IMDS bearer, ``GITHUB_TOKEN``,
    ``IDENTITY_HEADER``, Storage SAS, and Copilot session token.
    Developer-named commands with developer-supplied env vars are a
    direct escalation primitive inside the trusted boundary and a
    soft target for confused-deputy against the LLM (attacker text
    flows into a tool result whose handler writes ``command:`` into
    mcp.json; the next start exec's that binary).

    The framework therefore only allows the **remote** flavours
    (``http`` / ``sse``).  Remote MCP runs in a separate process
    over a network boundary; bearer-token forwarding is the
    developer's explicit choice via ``headers`` and the framework's
    env-var allow-list (``AGENT_*``) gates which env vars can be
    interpolated into those headers.

    Raises :class:`ValueError` on local / stdio configs (either via
    the discriminator ``type`` field or via any of the
    stdio-specific fields).  Silent on everything else; the caller
    decides whether the remaining shape is a valid remote entry.
    """
    server_type = str(server.get("type", "")).lower()

    if server_type in LOCAL_STDIO_TYPES:
        raise ValueError(
            "mcp.json: local / stdio MCP servers are not supported"
            f" (got type={server_type!r})."
            "  The framework only accepts remote MCP servers (http"
            " or sse) -- a local server would fork a"
            " developer-named binary in the host process tree, which"
            " trivially escalates inside the trusted boundary."
            "  Run your MCP server as a separate HTTP/SSE endpoint"
            " (e.g. a sidecar container) and reference it via"
            " 'type: http' / 'type: sse' + 'url'."
        )

    local_fields_present = sorted(LOCAL_STDIO_FIELDS & server.keys())
    if local_fields_present:
        raise ValueError(
            "mcp.json: local / stdio MCP fields are not supported"
            f" (got {local_fields_present!r})."
            "  The framework only accepts remote MCP servers (http"
            " or sse).  Run your MCP server as a separate"
            " HTTP/SSE endpoint and reference it via 'type: http'"
            " / 'type: sse' + 'url'."
        )
