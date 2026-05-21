"""Build-time allow-list gates for developer-supplied trigger types.

The host today dispatches to an Azure Functions ``FunctionApp`` decorator
via ``getattr(app, trigger_type)`` and to a connectors-library trigger
via a multi-step ``getattr`` chain.  Both surfaces let a developer who
controls frontmatter navigate to *any* attribute name on those objects.

These gates pin thelegal trigger names so that:

* unknown trigger types are rejected at parse time with a useful error,
* the attribute-chain navigation can't be used to reach methods
  or other unintended attributes,
* a clear audit log shows exactly which trigger surface is in use.

Lives in its own stdlib-only module so it can be unit-tested without
``azure.functions``, ``azure.functions_connectors``, or the Copilot
SDK installed.

Expanding either allow-list is a deliberate, reviewed code change.
"""

from __future__ import annotations

import re
from typing import Literal, Tuple

__all__ = [
    "BUILTIN_TRIGGER_ALLOWLIST",
    "CONNECTOR_TRIGGER_ALLOWLIST",
    "CONNECTION_ID_RE",
    "validate_trigger_type",
    "validate_connection_id",
]


# ---------------------------------------------------------------------------
# Built-in Azure Functions triggers
# ---------------------------------------------------------------------------

# The set of built-in Azure Functions Python decorator names we let
# developer frontmatter reach via ``getattr(app, trigger_type)``.  Every
# entry below corresponds to a documented example in ``docs/triggers.md``.
#
# Adding a new built-in trigger here is fine; the only constraint is
# that the name must correspond to a real decorator on
# ``azure.functions.FunctionApp`` -- otherwise the host will refuse to
# start, which is the failure mode we want.
BUILTIN_TRIGGER_ALLOWLIST: frozenset[str] = frozenset({
    "http_trigger",
    "timer_trigger",
    "queue_trigger",
    "blob_trigger",
    "event_hub_message_trigger",
    "service_bus_queue_trigger",
    "service_bus_topic_trigger",
    "cosmos_db_trigger",
    "event_grid_trigger",
    "kafka_trigger",
    "sql_trigger",
})


# ---------------------------------------------------------------------------
# Connector triggers (azure-functions-connectors)
# ---------------------------------------------------------------------------

# Two shapes are accepted today:
#
#   1. ``"<namespace>.<trigger_method>"`` -- a single-dot path that maps
#      to ``getattr(getattr(connectors_instance, namespace), trigger_method)``.
#
#   2. ``"<trigger_method>"`` -- after the ``"connectors."`` prefix is
#      stripped by the caller, this is a top-level method on the
#      ``FunctionsConnectors`` instance.
#
# Both shapes are pinned: any name not in this set is refused with a
# clear error.  Add new connector triggers explicitly.
CONNECTOR_TRIGGER_ALLOWLIST: frozenset[str] = frozenset({
    "generic_trigger",
    "teams.new_channel_message_trigger",
})


# ---------------------------------------------------------------------------
# Connection IDs (used by tools_from_connections)
# ---------------------------------------------------------------------------

# Connector ``connection_id`` values are Azure resource IDs that flow
# straight into the ARM API.  After env-var resolution the string must
# look like an ARM resource path -- nothing more permissive than the
# documented ARN charset.
#
# Allowed chars: alphanumeric + ``/`` (segment separator) + ``-`` and
# ``_`` (Azure name chars) + ``.`` (used by ``Microsoft.Web``).
#
# Max length is conservative; documented Azure resource IDs are
# typically < 400 chars.
CONNECTION_ID_MAX_LEN = 512
CONNECTION_ID_RE = re.compile(
    rf"^/subscriptions/[A-Za-z0-9\-]{{1,64}}"
    r"/resourceGroups/[A-Za-z0-9_\-\.]{1,90}"
    r"/providers/[A-Za-z0-9_\-\.]+"
    r"/connections/[A-Za-z0-9_\-]{1,80}$"
)


def validate_trigger_type(name: str) -> Tuple[Literal["builtin", "connector"], str]:
    """Validate a developer-supplied trigger type string.

    Returns ``(kind, canonical_name)`` where ``kind`` is ``"builtin"``
    for an Azure Functions built-in trigger and ``"connector"`` for a
    connector-library trigger.  The ``canonical_name`` is what the
    caller should pass to the dispatcher; for connectors this is the
    name with any leading ``"connectors."`` prefix stripped.

    Raises :class:`ValueError` if the name is unknown.
    """
    if not isinstance(name, str):
        raise ValueError(
            f"trigger type must be a string, got {type(name).__name__}"
        )
    cleaned = name.strip()
    if not cleaned:
        raise ValueError("trigger type may not be empty")

    if cleaned in BUILTIN_TRIGGER_ALLOWLIST:
        return ("builtin", cleaned)

    # Connector form: strip the optional "connectors." namespace before
    # matching against the allow-list.  The namespace is special-cased
    # by the caller -- it does NOT correspond to a real attribute on
    # the FunctionsConnectors object.
    candidate = cleaned.removeprefix("connectors.")
    if candidate in CONNECTOR_TRIGGER_ALLOWLIST:
        return ("connector", candidate)

    raise ValueError(
        f"Unknown trigger type '{cleaned}'. Allowed built-in triggers:"
        f" {sorted(BUILTIN_TRIGGER_ALLOWLIST)}. Allowed connector"
        f" triggers: {sorted(CONNECTOR_TRIGGER_ALLOWLIST)}"
        " (with or without the 'connectors.' prefix). Expand the"
        " allow-list in trigger_validation.py if you need a new one."
    )


def validate_connection_id(resolved: str) -> str:
    """Validate a *resolved* (env-vars already substituted) connection id.

    The caller must have run ``resolve_env_var`` first; we want to gate
    the value that actually goes to ARM, not the raw frontmatter form.

    Raises :class:`ValueError` if the value is missing, too long, or
    doesn't match the documented Azure Resource ID shape.
    """
    if not isinstance(resolved, str):
        raise ValueError(
            f"connection_id must be a string, got {type(resolved).__name__}"
        )
    cleaned = resolved.strip()
    if not cleaned:
        raise ValueError("connection_id may not be empty")
    if len(cleaned) > CONNECTION_ID_MAX_LEN:
        raise ValueError(
            f"connection_id too long ({len(cleaned)} >"
            f" {CONNECTION_ID_MAX_LEN})"
        )
    if not CONNECTION_ID_RE.match(cleaned):
        raise ValueError(
            "connection_id must be an Azure Resource ID of the form"
            " '/subscriptions/<sub>/resourceGroups/<rg>/providers/"
            "<provider>/connections/<name>'"
            f" (got: {cleaned!r})"
        )
    return cleaned
