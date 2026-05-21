"""Tests for the developer env-var allow-list in ``config.py``.

The framework's threat model treats the developer as adversarial inside
their own process boundary.  Developer-supplied content (agent.md
frontmatter values and body text) may reference env vars via
``$VAR`` / ``%VAR%`` substitution, and without an allow-list a
developer can write ``$IDENTITY_HEADER`` or ``$GITHUB_TOKEN`` and
exfiltrate framework / platform secrets through the rendered prompt
that ships to the LLM.

The mitigation is a build-time-baked name prefix: only env vars whose
name starts with :data:`config._AGENT_ENV_PREFIX` (currently
``AGENT_``) are dereferenceable from developer content.  Everything else
passes through verbatim (silent fail-closed -- a loud error would let
the developer probe the allow-list).

These tests pin that contract for both substitution entry points:

  - :func:`config.resolve_env_var` -- full-string match on a single
    frontmatter value, e.g. ``connection_id: $AGENT_O365_CONNECTION_ID``.
  - :func:`config.substitute_env_vars_in_text` -- inline replacement in
    free-form body text, e.g. ``send mail to $AGENT_TO_EMAIL``.
"""
from __future__ import annotations

import pytest

from .conftest import load_module_in_isolation

config = load_module_in_isolation("af_agents_config_env_under_test", "config.py")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip env vars touched by these tests so each test sees a clean slate."""
    for name in (
        "AGENT_TO_EMAIL",
        "AGENT_API_KEY",
        "AGENT_CONNECTION_ID",
        "GITHUB_TOKEN",
        "IDENTITY_HEADER",
        "AzureWebJobsStorage",
        "TO_EMAIL",
        "agent_lowercase_var",
    ):
        monkeypatch.delenv(name, raising=False)


# ---------------------------------------------------------------------------
# resolve_env_var -- single-value frontmatter substitution
# ---------------------------------------------------------------------------


def test_resolve_env_var_resolves_allow_listed_dollar_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_TO_EMAIL", "ops@example.com")

    assert config.resolve_env_var("$AGENT_TO_EMAIL") == "ops@example.com"


def test_resolve_env_var_resolves_allow_listed_percent_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_TO_EMAIL", "ops@example.com")

    assert config.resolve_env_var("%AGENT_TO_EMAIL%") == "ops@example.com"


def test_resolve_env_var_rejects_non_prefixed_dollar_name_silently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Developer cannot dereference a non-prefixed env var.

    Even if the env var is set (e.g. the host has ``GITHUB_TOKEN``
    legitimately for its own use), the developer's frontmatter must
    not be able to read it.  The literal ``$GITHUB_TOKEN`` is
    returned, indistinguishable from "env var unset".
    """
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_super_secret")

    assert config.resolve_env_var("$GITHUB_TOKEN") == "$GITHUB_TOKEN"


def test_resolve_env_var_rejects_non_prefixed_percent_name_silently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IDENTITY_HEADER", "x-identity-secret")

    assert config.resolve_env_var("%IDENTITY_HEADER%") == "%IDENTITY_HEADER%"


def test_resolve_env_var_prefix_is_case_sensitive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prefix is uppercase ``AGENT_`` -- ``agent_`` does not match.

    Case-insensitive matching would let a developer slip past a grep
    for ``AGENT_`` with a confusingly-named lowercase variant.
    """
    monkeypatch.setenv("agent_lowercase_var", "should-not-leak")

    assert (
        config.resolve_env_var("$agent_lowercase_var")
        == "$agent_lowercase_var"
    )


def test_resolve_env_var_allow_listed_but_unset_returns_original(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unset allow-listed env var -> literal reference preserved.

    This is the fail-open path for the *developer's own* env vars
    when the developer hasn't configured a deployment yet; it is the
    same observable behaviour as a rejected non-prefixed name, so
    the developer cannot use timing / output to enumerate the
    framework's env-var set.
    """
    assert config.resolve_env_var("$AGENT_API_KEY") == "$AGENT_API_KEY"


def test_resolve_env_var_partial_string_not_substituted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``resolve_env_var`` is full-string only -- partial reference passes
    through unchanged.  This is the pre-existing contract; the
    allow-list gate doesn't change it.
    """
    monkeypatch.setenv("AGENT_TO_EMAIL", "ops@example.com")

    assert (
        config.resolve_env_var("prefix-$AGENT_TO_EMAIL-suffix")
        == "prefix-$AGENT_TO_EMAIL-suffix"
    )


# ---------------------------------------------------------------------------
# substitute_env_vars_in_text -- inline body-text substitution
# ---------------------------------------------------------------------------


def test_substitute_env_vars_in_text_replaces_allow_listed_dollar_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_TO_EMAIL", "ops@example.com")

    rendered = config.substitute_env_vars_in_text(
        "Send the report to $AGENT_TO_EMAIL today."
    )

    assert rendered == "Send the report to ops@example.com today."


def test_substitute_env_vars_in_text_replaces_allow_listed_percent_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_TO_EMAIL", "ops@example.com")

    rendered = config.substitute_env_vars_in_text(
        "Mail to %AGENT_TO_EMAIL%."
    )

    assert rendered == "Mail to ops@example.com."


def test_substitute_env_vars_in_text_leaks_no_non_prefixed_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Critical exfil-defence test.

    A developer's body text that names a framework env var must NOT
    have that value rendered into the LLM-bound prompt, even if the
    env var is set.  The literal reference text is preserved verbatim.
    """
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_super_secret")
    monkeypatch.setenv("IDENTITY_HEADER", "x-identity-secret")
    monkeypatch.setenv("AzureWebJobsStorage", "DefaultEndpoints=...")

    text = (
        "Sneaky developer prompt:"
        " token=$GITHUB_TOKEN id=%IDENTITY_HEADER%"
        " storage=$AzureWebJobsStorage"
    )

    rendered = config.substitute_env_vars_in_text(text)

    # All three secret values must be absent.
    assert "ghp_super_secret" not in rendered
    assert "x-identity-secret" not in rendered
    assert "DefaultEndpoints" not in rendered
    # All three literal references must be preserved.
    assert "$GITHUB_TOKEN" in rendered
    assert "%IDENTITY_HEADER%" in rendered
    assert "$AzureWebJobsStorage" in rendered


def test_substitute_env_vars_in_text_mixes_allow_listed_and_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Allow-listed names resolve; rejected names pass through verbatim,
    side-by-side in the same paragraph.
    """
    monkeypatch.setenv("AGENT_TO_EMAIL", "ops@example.com")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_super_secret")

    rendered = config.substitute_env_vars_in_text(
        "Mail $AGENT_TO_EMAIL using $GITHUB_TOKEN."
    )

    assert rendered == "Mail ops@example.com using $GITHUB_TOKEN."


def test_substitute_env_vars_in_text_skips_fenced_code_blocks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pre-existing fenced-code-block contract is preserved by the
    allow-list gate."""
    monkeypatch.setenv("AGENT_TO_EMAIL", "ops@example.com")

    rendered = config.substitute_env_vars_in_text(
        "Outside $AGENT_TO_EMAIL"
        "\n```\nexample: $AGENT_TO_EMAIL\n```\n"
        "After $AGENT_TO_EMAIL"
    )

    assert "Outside ops@example.com" in rendered
    assert "After ops@example.com" in rendered
    # Inside the fenced block the literal reference is preserved.
    assert "example: $AGENT_TO_EMAIL" in rendered


def test_substitute_env_vars_in_text_prefix_is_case_sensitive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("agent_lowercase_var", "should-not-leak")

    rendered = config.substitute_env_vars_in_text(
        "value=$agent_lowercase_var"
    )

    assert "should-not-leak" not in rendered
    assert "$agent_lowercase_var" in rendered


# ---------------------------------------------------------------------------
# Sanity: the prefix constant matches what credentials/ enforces
# ---------------------------------------------------------------------------


def test_agent_env_prefix_constant_value() -> None:
    """The prefix is a build-time-baked security primitive.

    Pinning the literal value here means changing it is a deliberate,
    reviewable act -- the test will fail loudly and force the change
    to be explicit (and propagated to the credentials/ duplicate).
    """
    assert config._AGENT_ENV_PREFIX == "AGENT_"
