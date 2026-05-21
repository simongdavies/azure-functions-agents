import asyncio
import logging
import os
from typing import Optional

from copilot import CopilotClient, SubprocessConfig

# ``ProcessExitedError`` is the SDK-level signal that the bundled Copilot CLI
# subprocess has died (e.g. OOM-killed inside a constrained container, kernel
# signal, internal crash).  It lives in a private module so we import
# defensively: if the SDK ever reorganises its internals we still recognise
# the OS-level ``BrokenPipeError`` that bubbles up when ``stdin.write()``
# hits a dead pipe.
try:
    from copilot._jsonrpc import ProcessExitedError as _ProcessExitedError
except ImportError:  # pragma: no cover - defensive: private SDK API moved
    _ProcessExitedError = None  # type: ignore[assignment]

# Exceptions that signal "the CLI subprocess is gone; the cached singleton
# is unusable and must be re-spawned before the next request".
_DEAD_SUBPROCESS_EXCEPTIONS: tuple[type[BaseException], ...] = (BrokenPipeError,)
if _ProcessExitedError is not None:
    _DEAD_SUBPROCESS_EXCEPTIONS = (BrokenPipeError, _ProcessExitedError)

from .config import get_agent_input_tmp_dir, get_app_root, resolve_config_dir

# ---------------------------------------------------------------------------
# Sandbox-aware TMPDIR redirect for the Copilot CLI subprocess
#
# The Copilot CLI writes large tool outputs to its system temp dir (Node's
# os.tmpdir(), which honours TMPDIR on Linux) so they stay out of the
# model's context window.  When the configured agent input tmp directory
# (``<AGENT_INPUT_DIR>/tmp``, defaulting to ``/sandbox/in/tmp`` in the
# basic-chat container) is present we redirect TMPDIR for the subprocess
# so those files land on the Hyperlight input bind-mount.  The Hyperlight
# guest then sees the same files at ``/input/tmp/...`` -- one file on
# disk, one reader (the sandbox), zero copies.  This means execute_python
# and the view / head / tail / grep / jq tools all reach the parked
# outputs through the WASI ``/input`` mount instead of the host fs.
#
# Note: SubprocessConfig.env REPLACES the inherited environment rather than
# augmenting it, so we must clone os.environ first.
# ---------------------------------------------------------------------------


def _build_subprocess_env() -> Optional[dict[str, str]]:
    """Return an env mapping for the CLI subprocess, or None to inherit.

    On dev machines (and any environment where the configured agent input
    tmp directory is not present) we return ``None`` so the SDK falls back
    to inheriting the parent process environment unchanged.
    """
    tmp_dir = get_agent_input_tmp_dir()
    if not os.path.isdir(tmp_dir):
        return None
    env = dict(os.environ)
    env["TMPDIR"] = tmp_dir
    logging.info(
        "CopilotClient: redirecting CLI TMPDIR to %s",
        tmp_dir,
    )
    return env


def _is_byok_mode() -> bool:
    """Check if BYO key (Microsoft Foundry) environment variables are configured."""
    return bool(
        os.environ.get("AZURE_AI_FOUNDRY_ENDPOINT")
        and os.environ.get("AZURE_AI_FOUNDRY_API_KEY")
    )


def _client_is_alive(client: CopilotClient) -> bool:
    """Heuristic liveness check for a cached :class:`CopilotClient`.

    Returns ``True`` only when:

    1. The public ``get_state()`` API reports ``"connected"`` *and*
    2. The underlying CLI subprocess (reached via the private
       ``_process`` attribute) has not exited.

    Both probes are wrapped in broad ``except`` blocks that *fail open*
    (return ``True``) so that a transient introspection error never
    bricks the manager -- the worst-case outcome is the caller hits a
    real failure on the next request and ``report_failure`` flips the
    marker for the request after that.

    The ``_process`` attribute is private SDK API; ``getattr`` with a
    default keeps us resilient against future SDK renames.
    """
    try:
        state = client.get_state()
    except Exception:
        # SDK introspection failed for an unknown reason - fail open.
        return True
    if state != "connected":
        return False

    process = getattr(client, "_process", None)
    poll = getattr(process, "poll", None) if process is not None else None
    if poll is None:
        # External-server mode or future SDK rename - we cannot probe;
        # trust the public state.
        return True
    try:
        return poll() is None
    except Exception:
        return True


class CopilotClientManager:
    """
    Singleton manager for the CopilotClient.

    Detects a dead Copilot CLI subprocess on every :meth:`get_client`
    call and transparently tears down + re-spawns the singleton. This
    means an OOM-killed CLI (or any other reason the subprocess dies
    between requests) no longer permanently bricks the function app --
    the next request just gets a fresh client.

    Callers that catch a :class:`BrokenPipeError` (or the SDK's
    ``ProcessExitedError``) mid-call can also push a failure marker
    via :meth:`report_failure` so the *next* :meth:`get_client` call
    re-spawns even if the proactive liveness probe has not caught up.
    """

    _instance: Optional["CopilotClientManager"] = None
    _client: Optional[CopilotClient] = None
    _lock: asyncio.Lock = None
    _started: bool = False
    # Set by ``report_failure`` to force the next ``get_client`` call to
    # treat the cached client as dead even if liveness probing would
    # otherwise pass.  Cleared by ``_teardown_locked``.
    _failure_marker: bool = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._lock = asyncio.Lock()
        return cls._instance

    @classmethod
    async def get_client(cls) -> CopilotClient:
        manager = cls()
        async with manager._lock:
            # Proactively detect a dead CLI subprocess (typical cause:
            # OOM-kill inside the container's memory cgroup).  If the
            # cached client is unusable, tear it down here so the spawn
            # block below builds a fresh one.
            if manager._client is not None and manager._started:
                if manager._failure_marker or not _client_is_alive(manager._client):
                    try:
                        state = manager._client.get_state()
                    except Exception:
                        state = "<introspection failed>"
                    logging.warning(
                        "CopilotClient singleton is dead "
                        "(failure_marker=%s, state=%s) -- re-spawning",
                        manager._failure_marker,
                        state,
                    )
                    await cls._teardown_locked(manager)

            if manager._client is None or not manager._started:
                app_root = str(get_app_root())
                config_dir = resolve_config_dir()

                # Pass --config-dir as a CLI startup flag so the subprocess
                # writes events.jsonl and can load sessions from the shared
                # mount, enabling cross-instance session resume.
                cli_args: list[str] = []
                if config_dir:
                    cli_args = ["--config-dir", config_dir]
                    logging.info(f"CLI config-dir: {config_dir}")

                subprocess_env = _build_subprocess_env()

                if _is_byok_mode():
                    logging.info("BYOK mode: using Microsoft Foundry (no GitHub token)")
                    manager._client = CopilotClient(
                        SubprocessConfig(
                            cwd=app_root,
                            cli_args=cli_args,
                            env=subprocess_env,
                        )
                    )
                else:
                    github_token = os.environ.get("GITHUB_TOKEN")
                    manager._client = CopilotClient(
                        SubprocessConfig(
                            github_token=github_token,
                            cwd=app_root,
                            cli_args=cli_args,
                            env=subprocess_env,
                        )
                    )

                await manager._client.start()
                manager._started = True
                logging.info(f"CopilotClient singleton started (BYOK: {_is_byok_mode()})")
        return manager._client

    @classmethod
    async def _teardown_locked(cls, manager: "CopilotClientManager") -> None:
        """Tear down the cached client. Caller must hold ``manager._lock``.

        Errors during shutdown are swallowed: in the cases that reach
        this path the subprocess is already dead so ``stop()`` is
        best-effort cleanup of Python-side state only.
        """
        try:
            if manager._client is not None:
                await manager._client.stop()
        except Exception as exc:
            logging.debug("CopilotClient shutdown error (ignored): %s", exc)
        finally:
            manager._client = None
            manager._started = False
            manager._failure_marker = False

    @classmethod
    def report_failure(cls, exc: BaseException) -> None:
        """Mark the singleton dead if ``exc`` indicates the CLI is gone.

        Callers should invoke this from their ``except`` branch *before*
        re-raising any exception that came out of an SDK call. The next
        :meth:`get_client` call will then re-spawn, even if the public
        state probe has not yet noticed.

        Idempotent and lock-free; the lock is only required for the
        teardown itself, which happens inside the next ``get_client``.
        Pass-through for exceptions that do not match the dead-subprocess
        set (no-op), so it is safe to wrap any error path.
        """
        if isinstance(exc, _DEAD_SUBPROCESS_EXCEPTIONS):
            manager = cls()
            manager._failure_marker = True
            logging.warning(
                "CopilotClient: marking singleton dead after %s; "
                "next request will re-spawn",
                type(exc).__name__,
            )

    @classmethod
    async def shutdown(cls):
        manager = cls()
        async with manager._lock:
            if manager._client and manager._started:
                await manager._client.stop()
                manager._started = False
                manager._client = None
                logging.info("CopilotClient singleton stopped")

    @classmethod
    def is_running(cls) -> bool:
        manager = cls()
        return manager._started
