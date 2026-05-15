"""Built-in credential resolvers for ``execution_sandbox`` (closed set).

Auth providers are intentionally a **closed, framework-shipped set**.
Allowing operator Python to run on the host would trivially break
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
  ``VAR_NAME`` must be a POSIX-style identifier.

The package public surface intentionally lazy-imports the per-source
modules so that ``import credentials`` keeps a minimal dependency
footprint (stdlib only, useful at parse / validation time before any
token is actually fetched).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "CredentialResolveError",
    "ParsedSource",
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
# ``source: env:GITHUB_TOKEN``.
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
