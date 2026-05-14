"""Azure IMDS (Instance Metadata Service) token resolver.

Issues a managed-identity token via the IMDS REST endpoint at
``http://169.254.169.254/metadata/identity/oauth2/token``.  Uses
stdlib :mod:`urllib` + the ``Metadata: true`` header so the
resolver tier has zero third-party dependencies -- the secret /
network path is small enough to audit by inspection.

Tokens are cached per ``resource`` and reused until they fall inside
the ``_REFRESH_WINDOW_SECONDS`` window before expiry.  IMDS-issued
tokens last ~24h in practice, so the 5-minute buffer is comfortable
without risking serving an expired token to a downstream call.

This resolver is reached only via
:func:`azure_functions_agents.credentials.resolve`; importing the
module directly is supported but only used by tests and lazy-load
paths.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Dict, Optional

from . import CredentialResolveError

__all__ = ["get_token"]


# ---------------------------------------------------------------------------
# Constants (no magic numbers in the call-sites)
# ---------------------------------------------------------------------------

# IMDS endpoint -- fixed by the Azure platform contract.
_IMDS_URL = "http://169.254.169.254/metadata/identity/oauth2/token"

# IMDS API version -- the OAuth2 token endpoint contract.  Pinned so
# response shape stays stable; bump deliberately if Azure deprecates.
_IMDS_API_VERSION = "2018-02-01"

# IMDS HTTP request timeout (seconds).  Tokens come from a link-local
# address and should answer in <1s; anything slower than 10s implies
# the metadata service is unreachable -- fail loud.
_IMDS_TIMEOUT_SECONDS = 10

# Re-fetch threshold (seconds).  When ``expires_on - now`` drops below
# this value the cached token is treated as stale.  5 minutes balances
# "fresh enough for downstream calls" against "don't hammer IMDS".
_REFRESH_WINDOW_SECONDS = 5 * 60


# ---------------------------------------------------------------------------
# Cache state (module-private)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _CachedToken:
    """A cached IMDS token plus the epoch at which it expires."""

    value: str
    expires_at_epoch: int


# Per-resource cache.  ``threading.Lock`` covers writes; reads happen
# under the same lock to keep cache-line semantics consistent (the
# resolver is called from the sandbox worker thread, but pytest also
# exercises it from the main thread).
_cache: Dict[str, _CachedToken] = {}
_cache_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_token(resource: str) -> str:
    """Return an access token for ``resource`` via Azure IMDS.

    Tokens are cached and reused until they fall inside the refresh
    window.  Raises :class:`CredentialResolveError` on any failure
    (network, malformed response, IMDS error body) -- with the
    *response* body never echoed verbatim so any leaked token bytes
    in an error path stay redacted.
    """
    now = int(time.time())
    with _cache_lock:
        cached = _cache.get(resource)
        if (
            cached is not None
            and cached.expires_at_epoch - now > _REFRESH_WINDOW_SECONDS
        ):
            return cached.value

    fresh = _fetch_token(resource)
    with _cache_lock:
        _cache[resource] = fresh
    return fresh.value


# ---------------------------------------------------------------------------
# Internals -- module-private so tests use ``get_token`` for behaviour
# and the seam below only for cache reset.
# ---------------------------------------------------------------------------


def _fetch_token(resource: str) -> _CachedToken:
    """Issue a single IMDS request and parse the response."""
    query = urllib.parse.urlencode(
        {
            "api-version": _IMDS_API_VERSION,
            "resource": resource,
        }
    )
    req = urllib.request.Request(
        f"{_IMDS_URL}?{query}",
        headers={"Metadata": "true"},
    )
    try:
        with urllib.request.urlopen(
            req, timeout=_IMDS_TIMEOUT_SECONDS
        ) as resp:
            body_bytes: bytes = resp.read()
    except Exception as exc:  # noqa: BLE001 -- normalise to one error type
        # Intentionally broad: urllib raises URLError / HTTPError /
        # OSError / TimeoutError depending on the failure mode, and
        # the caller only cares that *resolution failed*.  The
        # ``from exc`` keeps the original chain visible for debugging.
        raise CredentialResolveError(
            "credentials: IMDS token fetch failed for resource"
            f" {resource!r}: {type(exc).__name__}: {exc}"
        ) from exc

    try:
        payload = json.loads(body_bytes.decode("utf-8"))
        token_value: str = payload["access_token"]
        expires_on: int = int(payload["expires_on"])
    except (KeyError, ValueError, TypeError, UnicodeDecodeError) as exc:
        # Body is a JSON document with access_token (str) +
        # expires_on (str-encoded epoch seconds).  Anything else
        # means IMDS returned an error envelope or a non-token shape;
        # we never echo the body itself to keep accidental token
        # bytes out of logs.
        raise CredentialResolveError(
            "credentials: IMDS response for resource"
            f" {resource!r} is malformed: {type(exc).__name__}"
        ) from exc

    return _CachedToken(value=token_value, expires_at_epoch=expires_on)


def _reset_cache_for_tests() -> None:
    """Clear the per-resource token cache.

    Test-only escape hatch -- production callers MUST NOT rely on
    this.  Exposed under a name that makes the intent obvious in
    coverage reports.
    """
    with _cache_lock:
        _cache.clear()
