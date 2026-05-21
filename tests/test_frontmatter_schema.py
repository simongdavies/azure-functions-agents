"""Tests for the strict Pydantic frontmatter schema.

Every byte of frontmatter in an ``*.agent.md`` file is developer-supplied
and feeds security-relevant host decisions (which trigger fires, which
credentials are vended, which domains the sandbox can reach).  Strict 
Pydantic schema so unknown top-level keys are rejected at
parse time -- a developer can't smuggle a hidden field past code review
because the host literally won't accept it.

These tests pin:

  1. The known-good shape (every key consumed by app.py / runner.py
     parses cleanly).
  2. The strict rejection contract (unknown top-level keys raise).
  3. Nested-structure strictness (``tools_from_connections`` and
     ``execution_sandbox`` / ``credentials`` also reject extras).
  4. Trigger params stay permissive (per-trigger Azure decorator
     schema owns that surface; the host only validates ``type``).
"""

from __future__ import annotations

import pytest

from .conftest import load_module_in_isolation

_fs = load_module_in_isolation(
    "af_agents_frontmatter_schema_under_test", "frontmatter_schema.py"
)

AgentFrontmatter = _fs.AgentFrontmatter
FrontmatterError = _fs.FrontmatterError
validate_frontmatter = _fs.validate_frontmatter


# ---------------------------------------------------------------------------
# Happy-path: every field consumed by the host parses
# ---------------------------------------------------------------------------


def test_accepts_empty_frontmatter():
    """An agent file with no frontmatter is valid -- everything defaults."""
    model = validate_frontmatter({})
    assert model.name is None
    assert model.trigger is None
    assert model.execution_sandbox is None


def test_accepts_none_input():
    """``None`` (no frontmatter at all) is accepted, returns a blank model."""
    model = validate_frontmatter(None)
    assert isinstance(model, AgentFrontmatter)
    assert model.name is None


def test_accepts_all_known_top_level_keys():
    """Every key the host actually reads must validate."""
    model = validate_frontmatter(
        {
            "name": "Test Agent",
            "description": "A test agent.",
            "trigger": {"type": "http_trigger", "route": "x"},
            "logger": True,
            "substitute_variables": False,
            "tools_from_connections": [
                {"connection_id": "conn1", "prefix": "p_"},
            ],
            "execution_sandbox": {
                "allowed_domains": "example.com,GET",
                "filesystem": "read_only",
                "heap_size": 64,
                "stack_size": 16,
            },
            "response_example": "{}",
            "response_schema": {"type": "object"},
        }
    )
    assert model.name == "Test Agent"
    assert model.trigger.type == "http_trigger"
    assert model.tools_from_connections[0].connection_id == "conn1"
    assert model.execution_sandbox.filesystem == "read_only"


def test_accepts_real_basic_chat_main_agent_shape():
    """Mirror the actual shape used by samples/basic-chat/src/main.agent.md."""
    model = validate_frontmatter(
        {
            "name": "Chat Assistant",
            "description": "A helpful assistant ...",
            "execution_sandbox": {
                "allowed_domains": "httpbin.org,GET,POST;api.github.com,GET",
                "filesystem": "read_write",
            },
        }
    )
    assert model.name == "Chat Assistant"
    assert model.execution_sandbox.filesystem == "read_write"


def test_accepts_real_daily_azure_report_shape():
    """Mirror the actual shape used by samples/daily-azure-report agents."""
    model = validate_frontmatter(
        {
            "name": "Daily Azure Report",
            "description": "Lists resources changed in the last 24h.",
            "trigger": {
                "type": "timer_trigger",
                "schedule": "0 0 7 * * *",
            },
            "tools_from_connections": [
                {"connection_id": "$AGENT_O365_CONNECTION_ID"},
            ],
            "execution_sandbox": {
                "allowed_domains": "management.azure.com,GET,POST,PUT,PATCH,DELETE",
                "credentials": [
                    {
                        "id": "azure_mgmt",
                        "source": "azure_imds",
                        "resource": "https://management.azure.com/.default",
                        "target": "management.azure.com",
                    }
                ],
            },
        }
    )
    assert model.trigger.type == "timer_trigger"
    # Trigger extras pass through (Azure decorator owns the schema)
    assert model.trigger.model_extra == {"schedule": "0 0 7 * * *"}
    assert model.execution_sandbox.credentials[0].id == "azure_mgmt"


# ---------------------------------------------------------------------------
# Top-level strict-forbid contract -- unknown keys are rejected at parse time
# ---------------------------------------------------------------------------


def test_rejects_unknown_top_level_key():
    """The whole point of top-level strict-forbid: smuggled keys are rejected at parse time."""
    with pytest.raises(FrontmatterError):
        validate_frontmatter({"evil_smuggled_field": "rm -rf /"})


def test_rejects_typo_in_known_key():
    """A typo (``triger`` instead of ``trigger``) is treated as a smuggle."""
    with pytest.raises(FrontmatterError):
        validate_frontmatter({"triger": {"type": "http_trigger"}})


def test_error_is_value_error_subclass():
    """Callers can ``except ValueError`` without importing this module."""
    with pytest.raises(ValueError):
        validate_frontmatter({"unknown_key": "x"})


def test_rejects_non_dict_top_level():
    """Frontmatter must be a YAML mapping, not a list or string."""
    with pytest.raises(FrontmatterError):
        validate_frontmatter([{"name": "x"}])
    with pytest.raises(FrontmatterError):
        validate_frontmatter("name: x")


# ---------------------------------------------------------------------------
# Nested strictness: tools_from_connections entries
# ---------------------------------------------------------------------------


def test_rejects_unknown_field_in_connection_spec():
    with pytest.raises(FrontmatterError):
        validate_frontmatter(
            {
                "tools_from_connections": [
                    {"connection_id": "x", "evil": "smuggled"}
                ]
            }
        )


def test_connection_spec_requires_connection_id():
    with pytest.raises(FrontmatterError):
        validate_frontmatter({"tools_from_connections": [{"prefix": "p_"}]})


def test_connection_spec_accepts_prefix_only_optional():
    """``prefix`` is optional; ``connection_id`` is the only required field."""
    model = validate_frontmatter(
        {"tools_from_connections": [{"connection_id": "x"}]}
    )
    assert model.tools_from_connections[0].prefix is None


# ---------------------------------------------------------------------------
# Nested strictness: execution_sandbox
# ---------------------------------------------------------------------------


def test_rejects_unknown_field_in_execution_sandbox():
    with pytest.raises(FrontmatterError):
        validate_frontmatter(
            {"execution_sandbox": {"allowed_domains": "x", "evil": "smuggled"}}
        )


def test_rejects_unknown_field_in_credential_spec():
    with pytest.raises(FrontmatterError):
        validate_frontmatter(
            {
                "execution_sandbox": {
                    "credentials": [
                        {
                            "id": "x",
                            "source": "azure_imds",
                            "target": "y",
                            "evil": "smuggled",
                        }
                    ]
                }
            }
        )


def test_credential_spec_requires_id_source_target():
    """Three fields are mandatory on every credential entry."""
    with pytest.raises(FrontmatterError):
        validate_frontmatter(
            {
                "execution_sandbox": {
                    "credentials": [{"id": "x", "source": "azure_imds"}]
                }
            }
        )


# ---------------------------------------------------------------------------
# Trigger spec: ``type`` strict, params permissive
# ---------------------------------------------------------------------------


def test_trigger_requires_type():
    with pytest.raises(FrontmatterError):
        validate_frontmatter({"trigger": {"schedule": "0 0 * * *"}})


def test_trigger_accepts_arbitrary_params():
    """Per-trigger params flow through to the Azure decorator -- permissive."""
    model = validate_frontmatter(
        {
            "trigger": {
                "type": "http_trigger",
                "route": "x",
                "methods": ["GET", "POST"],
                "auth_level": "FUNCTION",
                # Even a wholly-novel param is fine here; the Azure
                # decorator will be the one to reject it, and the
                # build-time allowlist gates `type` separately.
                "some_future_trigger_param": "v",
            }
        }
    )
    assert model.trigger.type == "http_trigger"
    assert "some_future_trigger_param" in model.trigger.model_extra
