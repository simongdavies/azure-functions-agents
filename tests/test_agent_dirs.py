"""Tests for the AGENT_INPUT_DIR / AGENT_OUTPUT_DIR helpers in ``config.py``.

These helpers describe the **host-side** filesystem layout that the
function-app process sees: the bind-mount targets exposed to the
Hyperlight sandbox as ``/input`` and ``/output``, and the temp directory
the Copilot CLI is redirected to so its large tool outputs land where
the sandbox guest can read them via ``/input/tmp/``.

The values they return are consumed by Linux processes (the sandbox
guest, the CLI's Node runtime running inside a Linux container) and
embedded in LLM-facing tool descriptions, so the helpers MUST return
POSIX-style paths regardless of the dev OS the tests run on.  The tests
below pin that contract.
"""
from __future__ import annotations

import logging

import pytest

from .conftest import load_module_in_isolation

config = load_module_in_isolation("af_agents_config_under_test", "config.py")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip the agent-dir env vars so each test sees a clean slate."""
    monkeypatch.delenv("AGENT_INPUT_DIR", raising=False)
    monkeypatch.delenv("AGENT_OUTPUT_DIR", raising=False)
    monkeypatch.delenv("CONTAINER_NAME", raising=False)


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------


def test_defaults_match_basic_chat_container_layout() -> None:
    assert config.get_agent_input_dir() == "/sandbox/in"
    assert config.get_agent_output_dir() == "/sandbox/out"
    assert config.get_agent_input_tmp_dir() == "/sandbox/in/tmp"


# ---------------------------------------------------------------------------
# Env-var overrides
# ---------------------------------------------------------------------------


def test_env_vars_override_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_INPUT_DIR", "/var/agent-input")
    monkeypatch.setenv("AGENT_OUTPUT_DIR", "/var/agent-output")

    assert config.get_agent_input_dir() == "/var/agent-input"
    assert config.get_agent_output_dir() == "/var/agent-output"
    assert config.get_agent_input_tmp_dir() == "/var/agent-input/tmp"


def test_paths_stay_posix_regardless_of_host_os(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Forward-slashes are preserved on every dev OS.

    Regression test: an earlier draft used ``os.path.normpath`` /
    ``os.path.join`` which on Windows produced ``\\sandbox\\in\\tmp``.
    That breaks the Sandbox bindings (Linux paths), the CLI's TMPDIR
    (consumed inside a Linux container), and the LLM-facing tool
    descriptions (which embed the value).  Forcing POSIX semantics in
    the helpers fixes all three at the source.
    """
    monkeypatch.setenv("AGENT_INPUT_DIR", "/foo/bar")

    tmp_dir = config.get_agent_input_tmp_dir()

    assert "\\" not in tmp_dir
    assert tmp_dir == "/foo/bar/tmp"


def test_trailing_slash_in_input_dir_is_handled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_INPUT_DIR", "/foo/bar/")

    assert config.get_agent_input_tmp_dir() == "/foo/bar/tmp"


# ---------------------------------------------------------------------------
# Startup check
# ---------------------------------------------------------------------------


def test_startup_check_silent_without_container_name(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Dev mode (no CONTAINER_NAME) must not log warnings.

    The lazy per-component checks in ``client_manager.py`` and
    ``sandbox.py`` already degrade gracefully when the bind mounts are
    missing.  Logging a startup warning on every dev-machine run would
    just be noise.
    """
    with caplog.at_level(logging.WARNING):
        config.check_agent_dirs_at_startup()

    assert caplog.records == []


def test_startup_check_warns_for_missing_dirs_in_container(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Container deployments expect the bind mounts to be present.

    Surfacing the misconfiguration at startup beats waiting for the
    first sandbox / CLI invocation to mysteriously fail.
    """
    monkeypatch.setenv("CONTAINER_NAME", "test-container")
    monkeypatch.setenv("AGENT_INPUT_DIR", "/definitely/does/not/exist/in")
    monkeypatch.setenv("AGENT_OUTPUT_DIR", "/definitely/does/not/exist/out")

    with caplog.at_level(logging.WARNING):
        config.check_agent_dirs_at_startup()

    messages = [r.getMessage() for r in caplog.records]
    assert any("AGENT_INPUT_DIR=" in m for m in messages), messages
    assert any("AGENT_OUTPUT_DIR=" in m for m in messages), messages


def test_startup_check_warns_for_missing_tmp_dir_only(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Input dir present but ``<input_dir>/tmp`` missing -> targeted warning.

    This is a real, recoverable misconfiguration: the operator
    bind-mounted the input dir but forgot to create the ``tmp``
    subdirectory the Copilot CLI parks its outputs in.
    """
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    input_dir.mkdir()
    output_dir.mkdir()
    # NOTE: deliberately do NOT create input_dir / "tmp"

    monkeypatch.setenv("CONTAINER_NAME", "test-container")
    monkeypatch.setenv("AGENT_INPUT_DIR", str(input_dir))
    monkeypatch.setenv("AGENT_OUTPUT_DIR", str(output_dir))

    with caplog.at_level(logging.WARNING):
        config.check_agent_dirs_at_startup()

    messages = [r.getMessage() for r in caplog.records]
    assert any("/tmp" in m or "\\tmp" in m for m in messages), messages
    # The output dir is fine, so no warning for it.
    assert not any("AGENT_OUTPUT_DIR" in m for m in messages), messages


# ---------------------------------------------------------------------------
# Description-template substitution (consumed by sandbox.py)
# ---------------------------------------------------------------------------


def test_description_template_substitutes_host_tmp_dir(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The {host_tmp} placeholder embeds the runtime-resolved path.

    ``sandbox.py`` formats its filesystem-section description with
    ``host_tmp=get_agent_input_tmp_dir()`` so the LLM is told the real
    on-disk location even when the operator has overridden
    ``AGENT_INPUT_DIR``.
    """
    monkeypatch.setenv("AGENT_INPUT_DIR", "/var/agent-input")

    template = (
        "The CLI reports these on the host as '{host_tmp}/<file>'."
    )
    out = template.format(host_tmp=config.get_agent_input_tmp_dir())

    assert out == (
        "The CLI reports these on the host as '/var/agent-input/tmp/<file>'."
    )
