"""Tests for the built-in credential resolvers (``credentials/`` package).

These tests exercise the *closed* credential source-type set: parse-time
validation (the discriminated union over ``azure_imds`` and ``env:VAR``),
the env-var resolver, and the Azure IMDS resolver with its urlopen path
mocked.

We deliberately do NOT import :mod:`azure_functions_agents.sandbox` here
-- the sandbox module pulls in :mod:`hyperlight_sandbox` and
:mod:`copilot.tools`, which are heavy + optional in CI.  The credentials
subpackage is stdlib-only, so it is loaded in isolation via
:func:`load_package_in_isolation` and the parse-time helpers from
``sandbox.py`` are re-exercised in a follow-up test module that lives
behind that import.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from .conftest import load_package_in_isolation

# Load the credentials package without triggering the heavy
# ``azure_functions_agents/__init__.py`` import chain.  Re-using the same
# top-level name (``af_agents_credentials_under_test``) for the package
# and its submodules so internal ``from . import azure_imds`` lookups
# resolve correctly.
credentials = load_package_in_isolation(
    "af_agents_credentials_under_test",
    "credentials",
)


# Pre-import the submodules so the lazy ``from . import azure_imds``
# inside ``credentials.resolve`` finds them under the expected
# parent-package name.  Without this the lazy import would look up
# ``af_agents_credentials_under_test.azure_imds`` and miss.
import importlib  # noqa: E402

azure_imds = importlib.import_module(
    "af_agents_credentials_under_test.azure_imds"
)
env_helper = importlib.import_module(
    "af_agents_credentials_under_test.env_helper"
)


# ---------------------------------------------------------------------------
# parse_source — the closed-source-type gate
# ---------------------------------------------------------------------------


def test_parse_source_azure_imds_returns_imds_kind() -> None:
    parsed = credentials.parse_source("azure_imds")

    assert parsed.kind == credentials.KIND_AZURE_IMDS
    assert parsed.env_var is None


def test_parse_source_env_prefix_extracts_var_name() -> None:
    parsed = credentials.parse_source("env:GITHUB_TOKEN")

    assert parsed.kind == credentials.KIND_ENV
    assert parsed.env_var == "GITHUB_TOKEN"


def test_parse_source_unknown_kind_raises_value_error() -> None:
    """Unknown source types are a parse-time gate -- not silently ignored."""
    with pytest.raises(ValueError, match="unknown source 'azure_kv'"):
        credentials.parse_source("azure_kv")


def test_parse_source_env_invalid_name_raises_value_error() -> None:
    """POSIX env-var rule: identifier must not start with a digit."""
    with pytest.raises(ValueError, match="not a valid env-var name"):
        credentials.parse_source("env:1invalid")


def test_parse_source_non_string_raises_value_error() -> None:
    with pytest.raises(ValueError, match="'source' must be a string"):
        credentials.parse_source(42)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# validate_id — credential identifier rules
# ---------------------------------------------------------------------------


def test_validate_id_accepts_alnum_underscore_hyphen() -> None:
    assert credentials.validate_id("github_prod") == "github_prod"
    assert credentials.validate_id("azure-mgmt") == "azure-mgmt"


def test_validate_id_strips_surrounding_whitespace() -> None:
    assert credentials.validate_id("  azure_mgmt  ") == "azure_mgmt"


def test_validate_id_rejects_empty_after_strip() -> None:
    with pytest.raises(ValueError, match="must match"):
        credentials.validate_id("   ")


def test_validate_id_rejects_dots() -> None:
    with pytest.raises(ValueError, match="must match"):
        credentials.validate_id("github.prod")


def test_validate_id_rejects_non_string() -> None:
    with pytest.raises(ValueError, match="must be a string"):
        credentials.validate_id(123)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# env_helper -- the env:VAR resolver
# ---------------------------------------------------------------------------


def test_env_helper_returns_value_when_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AF_TEST_TOKEN", "ghp_secret_value")

    assert env_helper.read_required("AF_TEST_TOKEN") == "ghp_secret_value"


def test_env_helper_missing_var_raises_credential_resolve_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AF_TEST_TOKEN", raising=False)

    with pytest.raises(
        credentials.CredentialResolveError,
        match="is required for source",
    ):
        env_helper.read_required("AF_TEST_TOKEN")


def test_env_helper_empty_var_raises_credential_resolve_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty string is treated as unset: a credentialed call with no
    Authorization header is a worse failure mode than a loud error."""
    monkeypatch.setenv("AF_TEST_TOKEN", "")

    with pytest.raises(credentials.CredentialResolveError):
        env_helper.read_required("AF_TEST_TOKEN")


# ---------------------------------------------------------------------------
# azure_imds -- raw urllib resolver + cache
# ---------------------------------------------------------------------------


def _build_imds_response(token: str, expires_on: int) -> MagicMock:
    """Construct a urlopen-context-manager mock that returns a JSON body."""
    body = json.dumps(
        {
            "access_token": token,
            "expires_on": str(expires_on),
            "token_type": "Bearer",
        }
    ).encode("utf-8")
    resp = MagicMock()
    resp.read.return_value = body
    cm = MagicMock()
    cm.__enter__.return_value = resp
    cm.__exit__.return_value = False
    return cm


@pytest.fixture(autouse=True)
def _clear_imds_cache() -> None:
    """Each IMDS test starts with an empty token cache."""
    azure_imds._reset_cache_for_tests()
    yield
    azure_imds._reset_cache_for_tests()


def test_azure_imds_fetch_returns_token_and_caches() -> None:
    """Second call within the refresh window hits the cache, not the wire."""
    resource = "https://management.azure.com/.default"
    cm = _build_imds_response("token-v1", expires_on=2_000_000_000)

    with patch.object(
        azure_imds.urllib.request, "urlopen", return_value=cm
    ) as mocked:
        first = azure_imds.get_token(resource)
        second = azure_imds.get_token(resource)

    assert first == "token-v1"
    assert second == "token-v1"
    assert mocked.call_count == 1


def test_azure_imds_fetch_propagates_metadata_header() -> None:
    """The ``Metadata: true`` header is mandatory for IMDS."""
    cm = _build_imds_response("tok", expires_on=2_000_000_000)

    with patch.object(
        azure_imds.urllib.request, "urlopen", return_value=cm
    ) as mocked:
        azure_imds.get_token("https://management.azure.com/.default")

    request_arg = mocked.call_args.args[0]
    assert request_arg.get_header("Metadata") == "true"


def test_azure_imds_network_failure_raises_credential_resolve_error() -> None:
    """URLError / timeout / refused-connection all surface as one error type."""
    with patch.object(
        azure_imds.urllib.request,
        "urlopen",
        side_effect=OSError("connection refused"),
    ):
        with pytest.raises(
            credentials.CredentialResolveError,
            match="IMDS token fetch failed",
        ):
            azure_imds.get_token("https://management.azure.com/.default")


def test_azure_imds_malformed_response_raises_credential_resolve_error() -> None:
    """IMDS returning non-token JSON is treated as a runtime failure."""
    body = json.dumps({"error": "no_identity_assigned"}).encode("utf-8")
    resp = MagicMock()
    resp.read.return_value = body
    cm = MagicMock()
    cm.__enter__.return_value = resp
    cm.__exit__.return_value = False

    with patch.object(
        azure_imds.urllib.request, "urlopen", return_value=cm
    ):
        with pytest.raises(
            credentials.CredentialResolveError,
            match="is malformed",
        ):
            azure_imds.get_token("https://management.azure.com/.default")


# ---------------------------------------------------------------------------
# resolve() dispatch
# ---------------------------------------------------------------------------


def test_resolve_env_kind_reads_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AF_TEST_RESOLVE", "ghp_via_resolve")
    parsed = credentials.parse_source("env:AF_TEST_RESOLVE")

    assert credentials.resolve(parsed, resource=None) == "ghp_via_resolve"


def test_resolve_azure_imds_kind_requires_resource() -> None:
    parsed = credentials.parse_source("azure_imds")

    with pytest.raises(
        credentials.CredentialResolveError,
        match="'resource' is required",
    ):
        credentials.resolve(parsed, resource=None)


def test_resolve_azure_imds_kind_calls_imds_with_resource() -> None:
    parsed = credentials.parse_source("azure_imds")
    cm = _build_imds_response("imds-token", expires_on=2_000_000_000)

    with patch.object(
        azure_imds.urllib.request, "urlopen", return_value=cm
    ):
        token = credentials.resolve(
            parsed, resource="https://management.azure.com/.default"
        )

    assert token == "imds-token"
