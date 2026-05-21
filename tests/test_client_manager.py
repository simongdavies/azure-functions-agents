"""Tests for the Copilot CLI auto-recovery in ``client_manager``.

The Copilot CLI runs as a subprocess of the Functions Python worker.
Inside a memory-constrained container the kernel cgroup OOM-killer can
reap it (we measured ~300 MiB anon-RSS under load, comfortably enough
to tip a 512 MiB cap). Before this layer existed, that left the
singleton holding a corpse and the next request crashed with
``BrokenPipeError`` *forever*.

These tests pin the auto-recovery contract:

  1. ``_client_is_alive`` correctly classifies a connected/dead/stopped
     subprocess and **fails open** on introspection errors.
  2. ``report_failure`` only flips the failure marker for the
     dead-subprocess exception types -- it must be a no-op for an
     ordinary ``ValueError`` or ``RuntimeError``.
  3. ``get_client`` proactively tears down + re-spawns the singleton
     when the cached client is dead or the failure marker is set.
  4. Teardown errors are swallowed (the subprocess is *already dead*
     so ``stop()`` raising is expected and must not block recovery).
"""

from __future__ import annotations

import asyncio
import sys
import types
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest


# ---------------------------------------------------------------------------
# Stub the ``copilot`` SDK so ``client_manager`` can be imported without
# the full dependency closure. The real SDK is a 50+ MB install with a
# bundled CLI binary -- not something we want in a unit-test venv.
# ---------------------------------------------------------------------------


class _StubCopilotClient:
    """Stand-in for ``copilot.CopilotClient`` used at import time."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._args = args
        self._kwargs = kwargs


class _StubSubprocessConfig:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._args = args
        self._kwargs = kwargs


class _StubProcessExitedError(Exception):
    """Stand-in for ``copilot._jsonrpc.ProcessExitedError``."""


def _install_copilot_stub() -> None:
    copilot_mod = types.ModuleType("copilot")
    copilot_mod.CopilotClient = _StubCopilotClient  # type: ignore[attr-defined]
    copilot_mod.SubprocessConfig = _StubSubprocessConfig  # type: ignore[attr-defined]
    sys.modules["copilot"] = copilot_mod

    jsonrpc_mod = types.ModuleType("copilot._jsonrpc")
    jsonrpc_mod.ProcessExitedError = _StubProcessExitedError  # type: ignore[attr-defined]
    sys.modules["copilot._jsonrpc"] = jsonrpc_mod


_install_copilot_stub()

from .conftest import load_modules_under_synthetic_package  # noqa: E402

# Load ``config`` first because ``client_manager`` does a relative import
# of it; both go under a synthetic ``af_agents_client_manager_under_test``
# parent so the relative imports resolve cleanly.
_loaded = load_modules_under_synthetic_package(
    "af_agents_client_manager_under_test",
    ["config", "client_manager"],
)
_cm = _loaded["client_manager"]

CopilotClientManager = _cm.CopilotClientManager
_client_is_alive = _cm._client_is_alive
_DEAD_SUBPROCESS_EXCEPTIONS = _cm._DEAD_SUBPROCESS_EXCEPTIONS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_fake_client(
    state: str = "connected", poll_return: Optional[int] = None
) -> MagicMock:
    """Build a mock CopilotClient with controllable state + subprocess poll."""
    client = MagicMock()
    client.get_state.return_value = state
    process = MagicMock()
    process.poll.return_value = poll_return
    client._process = process
    client.stop = AsyncMock()
    return client


def _reset_singleton() -> None:
    """Hard-reset the class-level singleton state between tests.

    The manager is a process-global singleton so each test must scrub
    it to avoid order-dependent flakiness.
    """
    CopilotClientManager._instance = None
    CopilotClientManager._client = None
    CopilotClientManager._lock = None
    CopilotClientManager._started = False
    CopilotClientManager._failure_marker = False


@pytest.fixture(autouse=True)
def _clean_singleton():
    _reset_singleton()
    yield
    _reset_singleton()


# ---------------------------------------------------------------------------
# _client_is_alive
# ---------------------------------------------------------------------------


def test_client_is_alive_when_connected_and_process_running():
    client = _make_fake_client(state="connected", poll_return=None)
    assert _client_is_alive(client) is True


def test_client_is_dead_when_state_not_connected():
    """A ``"connecting"`` or ``"error"`` state means the cached client
    is not usable -- treat it as dead so the next call re-spawns."""
    for bad_state in ("disconnected", "connecting", "error"):
        client = _make_fake_client(state=bad_state, poll_return=None)
        assert _client_is_alive(client) is False, bad_state


def test_client_is_dead_when_subprocess_exited():
    """``_process.poll()`` returning anything other than ``None`` means
    the subprocess has exited -- the typical OOM-kill signature."""
    client = _make_fake_client(state="connected", poll_return=137)  # SIGKILL
    assert _client_is_alive(client) is False


def test_client_is_alive_when_process_attr_missing():
    """External-server mode has no ``_process``; trust the public state."""
    client = MagicMock()
    client.get_state.return_value = "connected"
    # No ``_process`` attribute at all -- attribute access returns the
    # MagicMock auto-attribute, so explicitly delete it.
    del client._process
    assert _client_is_alive(client) is True


def test_client_is_alive_when_state_introspection_fails():
    """If ``get_state`` raises, we fail open: assume alive and let the
    next real SDK call surface any genuine problem."""
    client = MagicMock()
    client.get_state.side_effect = RuntimeError("introspection blew up")
    assert _client_is_alive(client) is True


def test_client_is_alive_when_poll_raises():
    """``poll`` raising must also fail open."""
    client = _make_fake_client(state="connected", poll_return=None)
    client._process.poll.side_effect = OSError("transient")
    assert _client_is_alive(client) is True


# ---------------------------------------------------------------------------
# report_failure
# ---------------------------------------------------------------------------


def test_report_failure_marks_dead_for_broken_pipe():
    """``BrokenPipeError`` is the canonical OOM-killed-CLI signature."""
    assert CopilotClientManager()._failure_marker is False
    CopilotClientManager.report_failure(BrokenPipeError(32, "Broken pipe"))
    assert CopilotClientManager()._failure_marker is True


def test_report_failure_marks_dead_for_process_exited():
    """SDK-emitted ``ProcessExitedError`` is also a dead-subprocess signal."""
    assert CopilotClientManager()._failure_marker is False
    CopilotClientManager.report_failure(_StubProcessExitedError("exit 1"))
    assert CopilotClientManager()._failure_marker is True


def test_report_failure_ignores_unrelated_exceptions():
    """A plain ``ValueError`` is not a subprocess-death signal; the
    marker must stay clear or we will needlessly thrash the CLI."""
    CopilotClientManager.report_failure(ValueError("bad input"))
    assert CopilotClientManager()._failure_marker is False
    CopilotClientManager.report_failure(RuntimeError("model error"))
    assert CopilotClientManager()._failure_marker is False
    CopilotClientManager.report_failure(asyncio.TimeoutError())
    assert CopilotClientManager()._failure_marker is False


def test_report_failure_is_idempotent():
    """Repeated reports must not corrupt state."""
    CopilotClientManager.report_failure(BrokenPipeError())
    CopilotClientManager.report_failure(BrokenPipeError())
    CopilotClientManager.report_failure(BrokenPipeError())
    assert CopilotClientManager()._failure_marker is True


# ---------------------------------------------------------------------------
# get_client recovery flow
# ---------------------------------------------------------------------------


def _patch_spawn(monkeypatch, *, fake_client: MagicMock) -> MagicMock:
    """Stub ``CopilotClient(...)`` so ``get_client`` builds our mock instead
    of trying to launch a real subprocess. Returns the factory mock so
    tests can assert call counts (i.e. "did we re-spawn?")."""
    factory = MagicMock(return_value=fake_client)
    monkeypatch.setattr(_cm, "CopilotClient", factory)
    # Also stub the env/config helpers so ``get_client`` doesn't poke
    # the real filesystem.
    monkeypatch.setattr(_cm, "_build_subprocess_env", lambda: None)
    monkeypatch.setattr(_cm, "get_app_root", lambda: "/tmp")
    monkeypatch.setattr(_cm, "resolve_config_dir", lambda: None)
    fake_client.start = AsyncMock()
    return factory


def test_get_client_spawns_once_when_alive(monkeypatch):
    """A healthy cached client must be returned without re-spawning."""
    alive_client = _make_fake_client(state="connected", poll_return=None)
    factory = _patch_spawn(monkeypatch, fake_client=alive_client)

    async def go() -> None:
        c1 = await CopilotClientManager.get_client()
        c2 = await CopilotClientManager.get_client()
        c3 = await CopilotClientManager.get_client()
        assert c1 is c2 is c3 is alive_client

    asyncio.run(go())
    assert factory.call_count == 1, "alive client should not be re-spawned"


def test_get_client_respawns_when_subprocess_dead(monkeypatch):
    """When the cached client's subprocess has exited, the next
    ``get_client`` must tear down and build a fresh one."""
    dead_client = _make_fake_client(state="connected", poll_return=137)
    fresh_client = _make_fake_client(state="connected", poll_return=None)

    # Alternate which client the factory hands out.
    clients = iter([dead_client, fresh_client])
    factory = MagicMock(side_effect=lambda *a, **k: next(clients))
    monkeypatch.setattr(_cm, "CopilotClient", factory)
    monkeypatch.setattr(_cm, "_build_subprocess_env", lambda: None)
    monkeypatch.setattr(_cm, "get_app_root", lambda: "/tmp")
    monkeypatch.setattr(_cm, "resolve_config_dir", lambda: None)
    dead_client.start = AsyncMock()
    fresh_client.start = AsyncMock()

    async def go() -> None:
        first = await CopilotClientManager.get_client()
        assert first is dead_client
        # Simulate the OOM: the subprocess has been killed by the kernel
        # but the cached client still holds the (now-broken) Popen
        # handle. We model that by leaving ``dead_client`` in place --
        # its ``_process.poll()`` already returns 137.
        second = await CopilotClientManager.get_client()
        assert second is fresh_client, "stale client must be re-spawned"

    asyncio.run(go())
    assert factory.call_count == 2
    dead_client.stop.assert_awaited_once()


def test_get_client_respawns_when_failure_marker_set(monkeypatch):
    """``report_failure`` must force a re-spawn even if the dead client's
    own state probes still claim 'connected' (which can briefly happen
    if the subprocess died after the most recent state read)."""
    stale_client = _make_fake_client(state="connected", poll_return=None)
    fresh_client = _make_fake_client(state="connected", poll_return=None)
    clients = iter([stale_client, fresh_client])
    factory = MagicMock(side_effect=lambda *a, **k: next(clients))
    monkeypatch.setattr(_cm, "CopilotClient", factory)
    monkeypatch.setattr(_cm, "_build_subprocess_env", lambda: None)
    monkeypatch.setattr(_cm, "get_app_root", lambda: "/tmp")
    monkeypatch.setattr(_cm, "resolve_config_dir", lambda: None)
    stale_client.start = AsyncMock()
    fresh_client.start = AsyncMock()

    async def go() -> None:
        first = await CopilotClientManager.get_client()
        assert first is stale_client
        # Caller hits a BrokenPipe mid-request and pushes the marker.
        CopilotClientManager.report_failure(BrokenPipeError())
        second = await CopilotClientManager.get_client()
        assert second is fresh_client

    asyncio.run(go())
    assert factory.call_count == 2
    stale_client.stop.assert_awaited_once()


def test_get_client_teardown_swallows_stop_errors(monkeypatch):
    """If the dead client's ``stop()`` itself raises (the subprocess is
    already gone, so this is realistic), recovery must still complete."""
    dead_client = _make_fake_client(state="connected", poll_return=137)
    dead_client.stop = AsyncMock(side_effect=RuntimeError("already dead"))
    fresh_client = _make_fake_client(state="connected", poll_return=None)
    clients = iter([dead_client, fresh_client])
    factory = MagicMock(side_effect=lambda *a, **k: next(clients))
    monkeypatch.setattr(_cm, "CopilotClient", factory)
    monkeypatch.setattr(_cm, "_build_subprocess_env", lambda: None)
    monkeypatch.setattr(_cm, "get_app_root", lambda: "/tmp")
    monkeypatch.setattr(_cm, "resolve_config_dir", lambda: None)
    dead_client.start = AsyncMock()
    fresh_client.start = AsyncMock()

    async def go() -> None:
        await CopilotClientManager.get_client()
        second = await CopilotClientManager.get_client()
        assert second is fresh_client

    asyncio.run(go())
    assert factory.call_count == 2
