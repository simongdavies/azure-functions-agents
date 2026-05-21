"""Tests for the trigger-type / connection-id allow-list gates.

These gates pin the universe of:

* Azure Functions built-in trigger types that developer frontmatter
  can dispatch to via ``getattr(app, trigger_type)``.
* Connector library trigger names that developer frontmatter can
  navigate to via a ``getattr`` chain.
* Resolved Azure resource IDs that flow into the ARM API for
  ``tools_from_connections``.

Lives in a stdlib-only module so this test file runs without
``azure.functions`` or the Copilot SDK installed.
"""

from __future__ import annotations

import pytest

from .conftest import load_module_in_isolation

_tv = load_module_in_isolation(
    "af_agents_trigger_validation_under_test", "trigger_validation.py"
)


# ---------------------------------------------------------------------------
# Built-in trigger types
# ---------------------------------------------------------------------------


def test_accepts_http_trigger() -> None:
    kind, canonical = _tv.validate_trigger_type("http_trigger")
    assert kind == "builtin"
    assert canonical == "http_trigger"


def test_accepts_timer_trigger() -> None:
    kind, canonical = _tv.validate_trigger_type("timer_trigger")
    assert kind == "builtin"
    assert canonical == "timer_trigger"


def test_accepts_every_documented_builtin() -> None:
    """Every name in the allow-list must round-trip successfully."""
    for name in _tv.BUILTIN_TRIGGER_ALLOWLIST:
        kind, canonical = _tv.validate_trigger_type(name)
        assert kind == "builtin"
        assert canonical == name


def test_strips_surrounding_whitespace() -> None:
    kind, canonical = _tv.validate_trigger_type("  timer_trigger  ")
    assert kind == "builtin"
    assert canonical == "timer_trigger"


# ---------------------------------------------------------------------------
# Connector trigger types
# ---------------------------------------------------------------------------


def test_accepts_top_level_connector_trigger() -> None:
    kind, canonical = _tv.validate_trigger_type("generic_trigger")
    # Top-level connector triggers are NOT in the built-in allow-list
    # so the validator must classify them as connector.
    assert kind == "connector"
    assert canonical == "generic_trigger"


def test_accepts_namespaced_connector_trigger() -> None:
    kind, canonical = _tv.validate_trigger_type(
        "teams.new_channel_message_trigger"
    )
    assert kind == "connector"
    assert canonical == "teams.new_channel_message_trigger"


def test_accepts_connectors_dot_prefix_form() -> None:
    """The ``connectors.`` namespace prefix is stripped by the validator."""
    kind, canonical = _tv.validate_trigger_type("connectors.generic_trigger")
    assert kind == "connector"
    assert canonical == "generic_trigger"


# ---------------------------------------------------------------------------
# Rejection -- security relevant cases
# ---------------------------------------------------------------------------


def test_rejects_unknown_builtin() -> None:
    with pytest.raises(ValueError, match="Unknown trigger type"):
        _tv.validate_trigger_type("not_a_real_trigger")


def test_rejects_dunder_attribute_access() -> None:
    """``__class__`` / ``__init__`` etc must NOT slip through into the
    ``getattr(app, ...)`` dispatcher."""
    with pytest.raises(ValueError):
        _tv.validate_trigger_type("__class__")
    with pytest.raises(ValueError):
        _tv.validate_trigger_type("__init__")
    with pytest.raises(ValueError):
        _tv.validate_trigger_type("__getattribute__")


def test_rejects_arbitrary_attribute_chain() -> None:
    """Multi-segment chains beyond ``namespace.method`` are refused."""
    with pytest.raises(ValueError):
        _tv.validate_trigger_type("a.b.c")
    with pytest.raises(ValueError):
        _tv.validate_trigger_type("teams.connection.evil")


def test_rejects_path_traversal_segments() -> None:
    with pytest.raises(ValueError):
        _tv.validate_trigger_type("../timer_trigger")
    with pytest.raises(ValueError):
        _tv.validate_trigger_type("connectors.../generic_trigger")


def test_rejects_empty_string() -> None:
    with pytest.raises(ValueError, match="empty"):
        _tv.validate_trigger_type("")


def test_rejects_whitespace_only() -> None:
    with pytest.raises(ValueError, match="empty"):
        _tv.validate_trigger_type("   ")


def test_rejects_non_string() -> None:
    with pytest.raises(ValueError, match="string"):
        _tv.validate_trigger_type(None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="string"):
        _tv.validate_trigger_type(123)  # type: ignore[arg-type]


def test_error_lists_allowlist_for_developer_remediation() -> None:
    """The error message names the allow-lists so a developer can
    pick a legal trigger without grepping source."""
    with pytest.raises(ValueError) as excinfo:
        _tv.validate_trigger_type("bogus")
    msg = str(excinfo.value)
    assert "http_trigger" in msg
    assert "timer_trigger" in msg
    assert "generic_trigger" in msg


# ---------------------------------------------------------------------------
# Connection IDs
# ---------------------------------------------------------------------------


_VALID_CONN = (
    "/subscriptions/11111111-2222-3333-4444-555555555555"
    "/resourceGroups/my-rg"
    "/providers/Microsoft.Web/connections/my-conn"
)


def test_accepts_valid_connection_id() -> None:
    assert _tv.validate_connection_id(_VALID_CONN) == _VALID_CONN


def test_strips_whitespace_on_connection_id() -> None:
    assert _tv.validate_connection_id(f"  {_VALID_CONN}  ") == _VALID_CONN


def test_rejects_empty_connection_id() -> None:
    with pytest.raises(ValueError, match="empty"):
        _tv.validate_connection_id("")


def test_rejects_non_string_connection_id() -> None:
    with pytest.raises(ValueError, match="string"):
        _tv.validate_connection_id(None)  # type: ignore[arg-type]


def test_rejects_relative_path_connection_id() -> None:
    with pytest.raises(ValueError):
        _tv.validate_connection_id("subscriptions/abc/connections/x")


def test_rejects_path_traversal_connection_id() -> None:
    with pytest.raises(ValueError):
        _tv.validate_connection_id(
            "/subscriptions/../../../etc/passwd"
        )


def test_rejects_url_scheme_connection_id() -> None:
    """A full URL is not an ARM resource ID."""
    with pytest.raises(ValueError):
        _tv.validate_connection_id(
            "https://management.azure.com" + _VALID_CONN
        )


def test_rejects_query_string_in_connection_id() -> None:
    """Trailing query strings could redirect ARM requests."""
    with pytest.raises(ValueError):
        _tv.validate_connection_id(_VALID_CONN + "?api-version=evil")


def test_rejects_overlong_connection_id() -> None:
    sid = "/subscriptions/" + "a" * (_tv.CONNECTION_ID_MAX_LEN + 1)
    with pytest.raises(ValueError, match="too long"):
        _tv.validate_connection_id(sid)


# ---------------------------------------------------------------------------
# Pinned constants -- widening must require a test edit
# ---------------------------------------------------------------------------


def test_builtin_allowlist_pinned() -> None:
    assert _tv.BUILTIN_TRIGGER_ALLOWLIST == frozenset({
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


def test_connector_allowlist_pinned() -> None:
    assert _tv.CONNECTOR_TRIGGER_ALLOWLIST == frozenset({
        "generic_trigger",
        "teams.new_channel_message_trigger",
    })


def test_connection_id_max_len_pinned() -> None:
    assert _tv.CONNECTION_ID_MAX_LEN == 512
