"""Built-in credential resolvers for ``execution_sandbox`` (closed set).

Auth providers are intentionally a **closed, framework-shipped set**.
Allowing developer Python to run on the host would trivially break
threat-model policy P1 (secret value never crosses host -> guest
boundary), so resolvers live here, in audited framework code, and are
the only producers of the literal token strings that
``Sandbox.register_credential`` ingests.

The frontmatter ``source:`` field is a discriminated union over this
closed set; unknown values are a parse-time error
(:class:`ValueError`).  Adding a new source type requires a code
change and review (PR) -- never a docs recipe.

v1 source types (frozen):

* ``azure_imds`` -- Azure managed-identity token, fetched via whichever
  platform endpoint is exposed to the host process: the link-local
  IMDS endpoint (VMs / VMSS / AKS / ACI) *or* the per-instance App
  Service MSI endpoint (Functions / App Service / Container Apps,
  signalled by the ``IDENTITY_ENDPOINT`` + ``IDENTITY_HEADER`` env
  vars).  Raw urllib at the resolver tier -- no ``azure-identity``
  dependency.  Requires the ``resource`` field on the frontmatter
  entry.  The source-type name reflects the resolver file's history,
  not its current scope; existing samples don't need to change.
* ``env:VAR_NAME`` -- value of the named environment variable.
  ``VAR_NAME`` must be a POSIX-style identifier AND start with the
  framework-baked agent-env-var prefix (see
  :data:`_AGENT_ENV_PREFIX`).  A developer who could name any
  env var here could trivially steal framework / platform secrets
  (``GITHUB_TOKEN``, ``IDENTITY_HEADER``, ``AzureWebJobsStorage``,
  ...), so the parser refuses unprefixed names at frontmatter-load
  time.

The package public surface intentionally lazy-imports the per-source
modules so that ``import credentials`` keeps a minimal dependency
footprint (stdlib only, useful at parse / validation time before any
token is actually fetched).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

__all__ = [
    "CredentialResolveError",
    "ParsedSource",
    "check_imds_audience_target",
    "extract_host",
    "parse_source",
    "resolve",
    "validate_id",
    "KIND_AZURE_IMDS",
    "KIND_ENV",
]

# ---------------------------------------------------------------------------
# Frozen identifiers
# ---------------------------------------------------------------------------

# Frontmatter source-type ids.  Kept as module-level constants so the
# parser and resolvers reference the same string -- a typo in either
# becomes a name-resolution error, not a silent miss.
KIND_AZURE_IMDS = "azure_imds"
KIND_ENV = "env"

# String prefix used in frontmatter for the env-var source type:
# ``source: env:AGENT_GITHUB_TOKEN``.
_ENV_SOURCE_PREFIX = "env:"

# Credential ``id`` rule (mirrors /memories/session/plan.md):
# ASCII alphanumerics, underscore, hyphen.  No leading hyphen
# restriction -- the registry uses ids as opaque strings, and tighter
# rules would only block legitimate names like ``-prod`` markers.
_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")

# POSIX env-var identifier: leading alpha / underscore, then
# alphanumerics / underscore.  Anything else (digits-first, dots,
# dashes) is a parse-time error so we never silently miss a config bug.
_ENV_VAR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Developer env-var allow-list prefix.
#
# A ``source: env:VAR`` reference in developer-supplied frontmatter
# is the most dangerous form of env-var dereference in the framework:
# it pipes the literal value of a host env var into the
# Authorization header of arbitrary outbound calls.  Without an
# allow-list a developer can write ``source: env:GITHUB_TOKEN`` (or
# ``IDENTITY_HEADER``, etc.) and silently steal framework / platform
# secrets.
#
# Mitigation: only env vars whose name starts with this prefix may
# be named in a ``source: env:VAR`` reference.  Anything else is a
# parse-time :class:`ValueError`.  The prefix is duplicated in
# ``azure_functions_agents.config`` (which enforces the same rule
# for ``$VAR`` / ``%VAR%`` substitution in frontmatter values and
# body text) and the two MUST be kept in sync; both sites are
# independently loaded in isolation by the test infrastructure, so
# they cannot share a module without breaking that.
#
# Unlike the silent passthrough used by the text-substitution path,
# parse_source raises a loud error here: the developer is writing
# YAML that *requests* a credential, so a misconfigured request is
# a deployment bug they need to fix (vs an inline ``$X`` reference
# in body text that might legitimately survive as literal text).
_AGENT_ENV_PREFIX = "AGENT_"


# ---------------------------------------------------------------------------
# Error type
# ---------------------------------------------------------------------------


class CredentialResolveError(RuntimeError):
    """Raised when a built-in resolver fails to produce a token.

    Distinct from :class:`ValueError` (which the parser raises for
    frontmatter / config bugs) so callers can tell the difference
    between *misconfiguration* (fix the yaml) and a *runtime
    token-fetch failure* (fix the environment: missing managed
    identity, unset env var, IMDS unreachable, ...).
    """


# ---------------------------------------------------------------------------
# Parsed-source value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParsedSource:
    """A frontmatter ``source:`` value validated against the closed set.

    ``kind`` is one of :data:`KIND_AZURE_IMDS` / :data:`KIND_ENV`.
    ``env_var`` is set iff ``kind == KIND_ENV``.
    """

    kind: str
    env_var: Optional[str]


# ---------------------------------------------------------------------------
# Parse-time helpers
# ---------------------------------------------------------------------------


def parse_source(source: str) -> ParsedSource:
    """Validate ``source`` is in the closed built-in source-type set.

    Returns a :class:`ParsedSource`.  Raises :class:`ValueError` with
    a descriptive message on any unknown / malformed value -- this is
    the parse-time gate that keeps the source field a true
    discriminated union.
    """
    if not isinstance(source, str):
        raise ValueError(
            "credentials: 'source' must be a string,"
            f" got {type(source).__name__}"
        )
    if source == KIND_AZURE_IMDS:
        return ParsedSource(kind=KIND_AZURE_IMDS, env_var=None)
    if source.startswith(_ENV_SOURCE_PREFIX):
        var = source[len(_ENV_SOURCE_PREFIX):]
        if not _ENV_VAR_RE.match(var):
            raise ValueError(
                f"credentials: source 'env:{var}' is not a valid env-var"
                f" name (must match {_ENV_VAR_RE.pattern})"
            )
        if not var.startswith(_AGENT_ENV_PREFIX):
            # Allow-list gate: developer-named env vars must carry the
            # framework's prefix.  Loud parse-time error rather than
            # silent passthrough -- a misconfigured credential request
            # is a deployment bug, not free-form text that might
            # legitimately stay literal.  See the section comment near
            # _AGENT_ENV_PREFIX for the threat-model rationale.
            raise ValueError(
                f"credentials: source 'env:{var}' is not allow-listed:"
                f" developer-named env vars must start with"
                f" {_AGENT_ENV_PREFIX!r}."
                f"  Rename your env var (e.g."
                f" '{_AGENT_ENV_PREFIX}{var}') in your function-app"
                f" settings *and* your agent.md, or use"
                f" 'source: {KIND_AZURE_IMDS}' for managed-identity"
                f" tokens."
            )
        return ParsedSource(kind=KIND_ENV, env_var=var)
    raise ValueError(
        f"credentials: unknown source {source!r}."
        f" Supported source types are {KIND_AZURE_IMDS!r} and"
        f" {_ENV_SOURCE_PREFIX}<VAR_NAME>."
        " New source types require a framework PR (the auth tier is"
        " a closed, audited set)."
    )


def validate_id(cred_id: object) -> str:
    """Validate a credential ``id``; return the stripped value.

    Raises :class:`ValueError` if the value is not a string or fails
    the :data:`_ID_RE` pattern.
    """
    if not isinstance(cred_id, str):
        raise ValueError(
            f"credentials: id must be a string, got {type(cred_id).__name__}"
        )
    stripped = cred_id.strip()
    if not _ID_RE.match(stripped):
        raise ValueError(
            f"credentials: id {cred_id!r} must match {_ID_RE.pattern}"
            " (ASCII alphanumerics, underscore, hyphen)"
        )
    return stripped


# ---------------------------------------------------------------------------
# Host extraction + IMDS audience / target cross-check
# ---------------------------------------------------------------------------


def extract_host(target: str) -> str:
    """Return the bare hostname from a target URL or hostname-only string.

    The host is the key callers cross-check against the allow-domain
    set or against the IMDS ``resource`` audience.  Bare hostnames
    (``management.azure.com``) are accepted as well as full URLs
    (``https://management.azure.com/.default``); both yield the same
    lower-cased hostname.
    """
    if "://" in target:
        parsed = urlparse(target)
        return (parsed.hostname or "").lower()
    return target.split("/", 1)[0].lower()


def check_imds_audience_target(
    cred_id: str,
    resource: str,
    target_host: str,
) -> None:
    """Reject an ``azure_imds`` credential whose audience != target host.

    When ``source: azure_imds``, the host fetches a bearer token whose
    ``aud`` claim is the *resource* URL (e.g.
    ``https://management.azure.com/.default``).  That token is then
    attached to outbound requests routed to ``target``.  If the
    resource hostname and the target hostname disagree there is no
    legitimate use case:

    * Honest typo (resource=vault, target=arm) -- the token gets
      rejected with a confusing 401 / wrong-audience error at runtime;
      surfacing the mismatch at parse time gives the developer an
      actionable message.
    * Confused-deputy attempt (developer declares a high-value audience
      like ARM, target an allow-listed but unrelated endpoint to flow
      the token somewhere it shouldn't) -- defence-in-depth on top of
      the ``allowed_domains`` check.

    Raises :class:`ValueError` with an actionable message if the
    resource URL has no host, or its host (lower-cased) does not match
    ``target_host`` exactly.  ``target_host`` is expected to already
    be normalised by :func:`extract_host`.
    """
    resource_host = extract_host(resource)
    if not resource_host:
        raise ValueError(
            f"credentials[{cred_id}]: resource {resource!r} has no host"
            " (expected a URL like"
            " 'https://management.azure.com/.default')"
        )
    if resource_host != target_host:
        raise ValueError(
            f"credentials[{cred_id}]: resource host"
            f" {resource_host!r} does not match target host"
            f" {target_host!r}."
            "  The token's audience must match the host it is sent"
            " to -- a mismatch is either a typo (the token would be"
            " rejected by the service with a 401) or a"
            " confused-deputy attempt."
            "  Set resource and target to the same hostname (e.g."
            f" resource: 'https://{target_host}/.default',"
            f" target: '{target_host}')."
        )


# ---------------------------------------------------------------------------
# Resolver dispatch (runtime, lazy-imports the per-source modules)
# ---------------------------------------------------------------------------


def resolve(parsed: ParsedSource, *, resource: Optional[str]) -> str:
    """Fetch the literal credential value for ``parsed``.

    The returned string is what the host hands to
    ``Sandbox.register_credential(resolver=...)``; it is the secret
    value.  Callers MUST keep the result out of logs (the framework
    already logs only the credential id, never the token).

    ``resource`` is required for :data:`KIND_AZURE_IMDS` and ignored
    for :data:`KIND_ENV`.  Raises :class:`CredentialResolveError` on
    runtime failure (IMDS unreachable, env var unset, etc.) and
    :class:`ValueError` only if called with an unhandled kind (which
    would indicate a parser / dispatcher mismatch -- caught here
    rather than masquerading as a runtime issue).
    """
    if parsed.kind == KIND_AZURE_IMDS:
        if not resource:
            raise CredentialResolveError(
                "credentials: 'resource' is required for source"
                f" {KIND_AZURE_IMDS!r}"
            )
        from . import azure_imds

        return azure_imds.get_token(resource)
    if parsed.kind == KIND_ENV:
        if parsed.env_var is None:  # defensive: parser sets this
            raise ValueError(
                "credentials: internal error -- parsed.env_var is None"
                " for KIND_ENV (parser invariant violated)"
            )
        from . import env_helper

        return env_helper.read_required(parsed.env_var)
    raise ValueError(
        "credentials: internal error -- unhandled ParsedSource.kind"
        f" {parsed.kind!r}"
    )
