"""Strict Pydantic schemas for agent-file frontmatter.

Every byte of frontmatter in an ``*.agent.md`` file is developer-supplied
and flows into security-relevant decisions: which trigger fires, which
credentials are vended, which domains the sandbox can reach, which
connectors are loaded.

Historically the host parsed frontmatter with ``frontmatter.loads()``
and read keys via ``dict.get(...)`` -- which silently accepted any
extra keys a developer added.  That made it trivially easy to smuggle
a hidden field past a code review (the reviewer doesn't know which
keys the host actually consumes; the developer does).

Solution: every top-level key the host *might* consume is enumerated
in :class:`AgentFrontmatter` with ``model_config = ConfigDict(extra="forbid")``.
Anything else raises at parse time.  The same gate is applied to the
nested security-critical structures (``tools_from_connections``,
``execution_sandbox``, ``credentials``).  ``trigger`` keeps
``extra="allow"`` because trigger-type params are passed through to
the Azure Functions decorator, which has its own per-trigger schema --
adding a forbid-list here would duplicate the Azure schema and
trip on every legitimate new trigger param.

Lives in its own module so the schema can be unit-tested without
``copilot.session`` or other heavy deps.
"""

# NOTE: deliberately *not* using ``from __future__ import annotations``.
# Pydantic v2 needs to resolve forward references in the model's own
# namespace; PEP-563 stringified annotations combined with importlib-loaded
# test modules (see ``conftest.load_module_in_isolation``) trip it up
# with "class is not fully defined".  Keeping annotations evaluated means
# the schema works under both normal import and isolation-loading.

from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "AgentFrontmatter",
    "TriggerSpec",
    "ConnectionSpec",
    "ExecutionSandboxSpec",
    "CredentialSpec",
    "AllowedDomainSpec",
    "FrontmatterError",
    "validate_frontmatter",
]


class FrontmatterError(ValueError):
    """Raised when frontmatter fails strict-schema validation.

    Subclasses ``ValueError`` so callers can ``except ValueError``
    without importing this module.
    """


# ---------------------------------------------------------------------------
# Leaf structures
# ---------------------------------------------------------------------------


class AllowedDomainSpec(BaseModel):
    """One entry in ``execution_sandbox.allowed_domains`` in dict form.

    The shorthand string form (``"host,GET,POST;host,GET"``) is also
    accepted at the higher level -- this model only validates the
    fully-expanded dict shape that the sandbox actually consumes.
    """

    model_config = ConfigDict(extra="forbid")

    url: str
    methods: List[str] = Field(default_factory=list)


class CredentialSpec(BaseModel):
    """An entry in ``execution_sandbox.credentials``.

    Closed schema: ``id``, ``source``, ``target``, ``resource``.  No
    other keys are permitted -- if a future credential kind needs a
    new field, this model must be extended deliberately.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    source: str
    target: str
    resource: Optional[str] = None


class ExecutionSandboxSpec(BaseModel):
    """The ``execution_sandbox`` block.

    Only the keys the host actually reads in :func:`sandbox.create_sandbox_tools`
    are accepted.  Adding a new sandbox-policy knob requires extending
    this model first; a developer can't quietly add a new key and have
    the host pick it up at runtime.
    """

    model_config = ConfigDict(extra="forbid")

    # ``allowed_domains`` accepts either the shorthand string form or
    # an explicit list -- both are normalised inside sandbox.py.
    allowed_domains: Union[str, List[Any], None] = None
    credentials: Optional[List[CredentialSpec]] = None
    filesystem: Optional[str] = None
    heap_size: Optional[int] = None
    stack_size: Optional[int] = None
    # ``tools`` selects which ``<app_root>/tools/*.py`` developer files
    # to load into this agent's sandbox.  Semantics (see
    # :func:`custom_tools.discover_custom_tools`):
    #   - omitted / ``None`` -> auto-discover every ``*.py`` whose name
    #     does not start with ``_``;
    #   - ``[]`` -> opt out entirely, no custom tools;
    #   - ``["foo", "bar"]`` -> only those module names, resolved
    #     against ``<app_root>/tools/<name>.py``.
    # Bare module names only -- path separators or ``..`` are rejected
    # by the discovery code so a developer can't escape the tools dir.
    tools: Optional[List[str]] = None


class ConnectionSpec(BaseModel):
    """An entry in ``tools_from_connections``."""

    model_config = ConfigDict(extra="forbid")

    connection_id: str
    prefix: Optional[str] = None


class TriggerSpec(BaseModel):
    """The ``trigger`` block.

    Unlike the other structures this one is ``extra="allow"``: trigger
    parameters flow through to the Azure Functions Python decorator
    (``app.timer_trigger(...)``, ``app.queue_trigger(...)``, ...) which
    has its own per-trigger schema that we don't want to mirror here.

    The ``type`` field is still strictly validated by
    :func:`.trigger_validation.validate_trigger_type` at registration
    time, so the surface here is intentionally permissive.
    """

    model_config = ConfigDict(extra="allow")

    type: str


# ---------------------------------------------------------------------------
# Top-level model
# ---------------------------------------------------------------------------


class AgentFrontmatter(BaseModel):
    """The complete set of top-level keys the host reads from frontmatter.

    Any key not in this list is rejected at parse time. A developer can't smuggle hidden
    fields past code review because the host literally won't accept
    them.

    To add a new top-level field:
      1. Add it here with the appropriate type.
      2. Add a test in ``tests/test_frontmatter_schema.py``.
      3. Wire it up in the consumer (``app.py`` / ``runner.py``).
    """

    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = None
    description: Optional[str] = None
    trigger: Optional[TriggerSpec] = None
    logger: Optional[bool] = None
    substitute_variables: Optional[bool] = None
    tools_from_connections: Optional[List[ConnectionSpec]] = None
    execution_sandbox: Optional[ExecutionSandboxSpec] = None
    response_example: Union[str, Dict[str, Any], List[Any], None] = None
    response_schema: Optional[Dict[str, Any]] = None


def validate_frontmatter(raw: Any) -> AgentFrontmatter:
    """Validate raw frontmatter (a dict from ``frontmatter.loads``).

    Returns the parsed :class:`AgentFrontmatter` on success.  Raises
    :class:`FrontmatterError` with a clear message on failure --
    callers should ``except ValueError`` so the host can log-and-skip
    the offending agent file rather than crash the whole app.

    ``None`` and empty mappings are accepted (an agent file with no
    frontmatter is valid; everything just defaults to ``None``).
    """
    if raw is None:
        return AgentFrontmatter()
    if not isinstance(raw, dict):
        raise FrontmatterError(
            f"frontmatter must be a YAML mapping at the top level,"
            f" got {type(raw).__name__}"
        )
    try:
        return AgentFrontmatter.model_validate(raw)
    except Exception as exc:  # pydantic ValidationError or others
        # Re-raise as our own subclass of ValueError so callers don't
        # need to depend on pydantic internals.
        raise FrontmatterError(str(exc)) from exc
