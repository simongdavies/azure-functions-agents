"""Stdlib-only validators for HTTP request inputs.

Lives in its own module (rather than inside :mod:`app`) because the
app module imports the Azure Functions extensions, the Copilot SDK,
and ``frontmatter`` at module load.  Keeping the input validators
separate means they can be unit-tested with nothing more than
``pip install pytest`` -- which matters for security gates that
must NEVER quietly regress.
"""

from __future__ import annotations

import re
from typing import Optional

__all__ = [
    "SESSION_ID_RE",
    "SESSION_ID_MAX_LEN",
    "validate_session_id",
]

# Session-id allow-list.
#
# Session ids flow from client-controlled HTTP requests into:
#   * the Copilot SDK as a session-resume key (filesystem path under
#     the SDK's session-state directory),
#   * structured log fields ("session_id": ...),
#   * the ``x-ms-session-id`` response header,
#   * the MCP context payload (echoed back to the client).
#
# An unsanitised value can therefore:
#   * escape the SDK's path containment (``..\\..\\..\\evil``);
#   * inject newlines into structured logs (log-injection);
#   * smuggle CRLF into the response header (response splitting);
#   * embed control chars that break downstream JSON / SSE parsers.
#
# Rule: at most :data:`SESSION_ID_MAX_LEN` chars of ``[A-Za-z0-9_-]``.
# The character class covers the SDK's existing GUID-style ids and
# any base64url-safe encoding without leaving room for path or
# control bytes.  128 is generous (UUIDv7 is 36 chars; the SDK
# currently emits 36) but leaves the gate strict enough to refuse
# anything obviously crafted.
SESSION_ID_MAX_LEN = 128
SESSION_ID_RE = re.compile(rf"^[A-Za-z0-9_\-]{{1,{SESSION_ID_MAX_LEN}}}$")


def validate_session_id(value: Optional[str]) -> Optional[str]:
    """Return ``value`` if it passes the allow-list, else raise ``ValueError``.

    ``None`` and the empty string are both treated as "no session id"
    (we have nothing to validate) and return ``None``.  All other
    values are checked against :data:`SESSION_ID_RE`; a mismatch is
    a 400-level client error, not a 500-level framework bug, so we
    raise :class:`ValueError` and let the HTTP wrappers translate it.

    See the threat-model comment near :data:`SESSION_ID_RE` for the
    rationale.  The check is intentionally tight -- any expansion
    should be a conscious code change with security review.
    """
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    if not SESSION_ID_RE.match(stripped):
        raise ValueError(
            "Invalid x-ms-session-id: must match"
            f" {SESSION_ID_RE.pattern} (got len={len(stripped)})"
        )
    return stripped
