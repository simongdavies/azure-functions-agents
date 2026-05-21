"""Azure managed-identity token resolver (IMDS *or* App Service MSI).

Issues a managed-identity token via whichever Azure-platform endpoint
is exposed to the current process:

* **App Service / Azure Functions / Container Apps** -- when both
  ``IDENTITY_ENDPOINT`` and ``IDENTITY_HEADER`` environment variables
  are set, requests go to that per-instance MSI endpoint
  (api-version ``2019-08-01``) with the ``X-IDENTITY-HEADER`` secret.
* **VMs / VMSS / AKS / ACI** -- otherwise the resolver targets the
  link-local IMDS endpoint at
  ``http://169.254.169.254/metadata/identity/oauth2/token``
  (api-version ``2018-02-01``) with the ``Metadata: true`` header.

The source-type identifier is still ``azure_imds`` (frontmatter
contract preserved for existing samples); the name reflects this
file's history, not its current behaviour.  The closed-set semantics
(threat-model policy P1) are unchanged -- the secret never crosses
the host -> guest boundary, and both endpoint flavours speak raw
stdlib :mod:`urllib` so the resolver tier has zero third-party
dependencies.

Tokens are cached per ``resource`` and reused until they fall inside
the ``_REFRESH_WINDOW_SECONDS`` window before expiry.  Managed-identity
tokens last ~60-90 minutes in practice, so the 5-minute buffer is
comfortable without risking serving an expired token to a downstream
call.  Endpoint detection happens per ``get_token`` call so test
monkeypatches and container restarts pick up env-var changes without
a module reload.

This resolver is reached only via
:func:`azure_functions_agents.credentials.resolve`; importing the
module directly is supported but only used by tests and lazy-load
paths.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Dict, Mapping

from . import CredentialResolveError

__all__ = ["get_token"]


# ---------------------------------------------------------------------------
# Constants (no magic numbers in the call-sites)
# ---------------------------------------------------------------------------

# Endpoint discriminator labels.  Surfaced in error messages so
# operators can tell which side of the dispatcher failed.
_KIND_IMDS = "IMDS"
_KIND_APP_SERVICE = "App Service MSI"

# IMDS endpoint -- fixed by the Azure platform contract on
# VMs / VMSS / AKS / ACI.
_IMDS_URL = "http://169.254.169.254/metadata/identity/oauth2/token"

# IMDS API version -- the OAuth2 token endpoint contract.  Pinned so
# response shape stays stable; bump deliberately if Azure deprecates.
_IMDS_API_VERSION = "2018-02-01"

# App Service MSI API version.  The endpoint URL and header secret
# are injected by the host at process start as ``IDENTITY_ENDPOINT``
# and ``IDENTITY_HEADER`` environment variables.
_APP_SERVICE_API_VERSION = "2019-08-01"

# Environment variables that signal the App Service / Functions /
# Container Apps managed-identity endpoint is available.  *Both* must
# be set and non-empty before we dispatch to that flavour -- a
# half-set pair (one env var) is treated as misconfiguration and
# falls through to the IMDS path.
_APP_SERVICE_ENDPOINT_ENV = "IDENTITY_ENDPOINT"
_APP_SERVICE_HEADER_ENV = "IDENTITY_HEADER"

# HTTP headers expected by each endpoint flavour.
_IMDS_AUTH_HEADER = "Metadata"
_IMDS_AUTH_VALUE = "true"
_APP_SERVICE_AUTH_HEADER = "X-IDENTITY-HEADER"

# HTTP request timeout (seconds).  Both endpoints are local /
# link-local and should answer in <1s; anything slower than 10s
# implies the metadata service is unreachable -- fail loud.
_REQUEST_TIMEOUT_SECONDS = 10

# Re-fetch threshold (seconds).  When ``expires_at - now`` drops below
# this value the cached token is treated as stale.  5 minutes balances
# "fresh enough for downstream calls" against "don't hammer the
# metadata endpoint".
_REFRESH_WINDOW_SECONDS = 5 * 60

# Fallback TTL applied when the response omits or mangles its
# ``expires_on`` field.  Some App Service responses return a
# US-locale datetime string (``"5/14/2026 9:35:01 PM +00:00"``) we
# deliberately don't parse here -- locale-parsing is a brittle path
# for marginal benefit.  45 minutes is conservative against the
# real 60-90 minute token lifetime, so a sub-real TTL just triggers
# an extra refresh well before any genuine expiry.
_DEFAULT_TOKEN_TTL_SECONDS = 45 * 60


# ---------------------------------------------------------------------------
# Endpoint detection
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Endpoint:
    """A resolved managed-identity HTTP endpoint."""

    kind: str
    url: str
    api_version: str
    auth_header_name: str
    auth_header_value: str


def _detect_endpoint() -> _Endpoint:
    """Pick the managed-identity endpoint flavour for this process.

    App Service / Functions / Container Apps inject
    ``IDENTITY_ENDPOINT`` + ``IDENTITY_HEADER`` at startup; *both* must
    be present and non-empty for us to prefer that path.  Otherwise
    we fall back to the link-local IMDS endpoint.  Read at call time
    so tests and process restarts pick up env-var changes without a
    module reload.
    """
    endpoint = os.environ.get(_APP_SERVICE_ENDPOINT_ENV) or ""
    header = os.environ.get(_APP_SERVICE_HEADER_ENV) or ""
    if endpoint and header:
        return _Endpoint(
            kind=_KIND_APP_SERVICE,
            url=endpoint,
            api_version=_APP_SERVICE_API_VERSION,
            auth_header_name=_APP_SERVICE_AUTH_HEADER,
            auth_header_value=header,
        )
    return _Endpoint(
        kind=_KIND_IMDS,
        url=_IMDS_URL,
        api_version=_IMDS_API_VERSION,
        auth_header_name=_IMDS_AUTH_HEADER,
        auth_header_value=_IMDS_AUTH_VALUE,
    )


# ---------------------------------------------------------------------------
# Cache state (module-private)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _CachedToken:
    """A cached managed-identity token plus its expiry epoch."""

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
    """Return an access token for ``resource`` via Azure managed identity.

    Dispatches between the IMDS link-local endpoint and the App Service
    MSI endpoint based on the ``IDENTITY_ENDPOINT`` /
    ``IDENTITY_HEADER`` environment variables (see
    :func:`_detect_endpoint`).  Tokens are cached per ``resource`` and
    reused until they fall inside the refresh window.

    Raises :class:`CredentialResolveError` on any failure (network,
    malformed response, error envelope) -- with the response *body*
    never echoed verbatim so any leaked token bytes in an error path
    stay redacted.
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
# and the seams below only for cache reset / focused dispatch checks.
# ---------------------------------------------------------------------------


def _fetch_token(resource: str) -> _CachedToken:
    """Issue a single managed-identity request and parse the response."""
    endpoint = _detect_endpoint()
    query = urllib.parse.urlencode(
        {
            "api-version": endpoint.api_version,
            "resource": resource,
        }
    )
    # Tolerate endpoint URLs that already include a query component
    # (uncommon, but a deployed ``IDENTITY_ENDPOINT`` could in theory
    # carry one -- don't silently produce a malformed URL).
    separator = "&" if "?" in endpoint.url else "?"
    req = urllib.request.Request(
        f"{endpoint.url}{separator}{query}",
        headers={endpoint.auth_header_name: endpoint.auth_header_value},
    )
    try:
        with urllib.request.urlopen(
            req, timeout=_REQUEST_TIMEOUT_SECONDS
        ) as resp:
            body_bytes: bytes = resp.read()
    except Exception as exc:  # noqa: BLE001 -- normalise to one error type
        # Intentionally broad: urllib raises URLError / HTTPError /
        # OSError / TimeoutError depending on the failure mode, and
        # the caller only cares that *resolution failed*.  The kind
        # label tells operators which dispatcher branch dropped; the
        # ``from exc`` keeps the original chain visible for debugging.
        flavour = (
            "IMDS token fetch failed"
            if endpoint.kind == _KIND_IMDS
            else "App Service MSI token fetch failed"
        )
        raise CredentialResolveError(
            f"credentials: {flavour} for resource"
            f" {resource!r}: {type(exc).__name__}: {exc}"
        ) from exc

    try:
        payload = json.loads(body_bytes.decode("utf-8"))
        token_value: str = payload["access_token"]
        expires_at = _expires_at_epoch(payload, now=int(time.time()))
    except (KeyError, ValueError, TypeError, UnicodeDecodeError) as exc:
        # Body is a JSON document with at minimum ``access_token``
        # (str).  Anything else means the endpoint returned an error
        # envelope or a non-token shape; we never echo the body
        # itself to keep accidental token bytes out of logs.
        raise CredentialResolveError(
            f"credentials: {endpoint.kind} response for resource"
            f" {resource!r} is malformed: {type(exc).__name__}"
        ) from exc

    return _CachedToken(value=token_value, expires_at_epoch=expires_at)


def _expires_at_epoch(payload: Mapping[str, object], now: int) -> int:
    """Compute the token expiry epoch from a managed-identity payload.

    Strategy prefer ``expires_on`` parsed as an integer epoch.
    If that fails -- some App Service responses return a US-locale
    datetime string we deliberately don't parse -- fall back to
    ``now + _DEFAULT_TOKEN_TTL_SECONDS``.  Sub-real TTLs are
    harmless because :func:`get_token` re-fetches well before the
    real expiry via the refresh-window check.
    """
    expires_on = payload.get("expires_on")
    if expires_on is not None:
        try:
            return int(expires_on)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            pass
    return now + _DEFAULT_TOKEN_TTL_SECONDS


def _reset_cache_for_tests() -> None:
    """Clear the per-resource token cache.

    Test-only escape hatch -- production callers MUST NOT rely on
    this.  Exposed under a name that makes the intent obvious in
    coverage reports.
    """
    with _cache_lock:
        _cache.clear()
