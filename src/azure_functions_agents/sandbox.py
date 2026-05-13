"""
Hyperlight Wasm sandbox — execute_python tool.

Provides an ``execute_python`` Copilot SDK tool backed by Hyperlight's
in-process Wasm sandbox.  Configured via the ``execution_sandbox`` block
in agent frontmatter.

Each agent can have its own sandbox configuration (allowed domains, memory
limits).  Within a conversation, sandbox state (variables, imports) persists
across calls — the same ``Sandbox`` instance is reused for a given Copilot
session ID.

Network access is deny-by-default.  Domains must be explicitly allowlisted
in the agent frontmatter via ``allowed_domains``.  Inside the sandbox,
guest code uses ``http_get(url)`` and ``http_post(url, body)`` built-in
globals for outbound HTTP — no import required.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import threading
from typing import Any, Dict, List, Optional

from copilot.tools import Tool, ToolInvocation, ToolResult
from hyperlight_sandbox import Sandbox

from .config import (
    get_agent_input_dir,
    get_agent_input_tmp_dir,
    get_agent_output_dir,
    resolve_env_var,
)

# ---------------------------------------------------------------------------
# Filesystem mounts
#
# The Hyperlight Wasm guest always exposes ``/input`` (read-only) and
# ``/output`` (read-write) at fixed paths.  The corresponding *host-side*
# directories — what the function-app process sees — are configurable via
# the ``AGENT_INPUT_DIR`` / ``AGENT_OUTPUT_DIR`` env vars (see
# :mod:`config`).  Both default to the basic-chat container layout
# (``/sandbox/in`` and ``/sandbox/out``), and both must exist on disk
# before the Sandbox is constructed — the container image creates empty
# placeholders so the unmounted case still works.
# ---------------------------------------------------------------------------

# Read-only access to ``/input`` is the **floor** — there is no "off"
# setting.  The Copilot CLI parks large tool outputs under
# ``<AGENT_INPUT_DIR>/tmp`` to keep them out of the model context (see
# client_manager.py for the TMPDIR override), and the guest sandbox needs
# ``/input`` to read those files.  Agents opt in to writable scratch space
# via ``filesystem: read_write``.
_FILESYSTEM_MODE_READ_ONLY = "read_only"
_FILESYSTEM_MODE_READ_WRITE = "read_write"

_FILESYSTEM_VALID_MODES = {
    _FILESYSTEM_MODE_READ_ONLY,
    _FILESYSTEM_MODE_READ_WRITE,
}

# Legacy frontmatter values silently upgraded to read_only (with a warning).
_FILESYSTEM_LEGACY_DISABLE_VALUES = {"none", "off", "false", "disabled"}

# ---------------------------------------------------------------------------
# Tool description
# ---------------------------------------------------------------------------

_EXECUTE_PYTHON_BASE_DESCRIPTION = (
    "Execute Python code in a persistent sandboxed environment backed by"
    " a Hyperlight Wasm sandbox. Returns JSON with stdout, stderr, and"
    " exit_code.\n"
    "\n"
    "When to use this tool:\n"
    "- Computation, data processing, parsing, or transformation.\n"
    "- Calling HTTP APIs via the built-in http_get / http_post globals.\n"
    "- Reading and processing files the host has made available under"
    " /input (see the filesystem section below), including large tool"
    " outputs the Copilot CLI has parked at /input/tmp/.\n"
    "- Writing artefacts to /output when that path is available.\n"
    "\n"
    "When NOT to use this tool:\n"
    "- To print or format text you already have — respond directly with"
    " text instead.\n"
    "- For quick peeks at a file — the view, head, tail, grep, and jq"
    " tools operate directly on the host filesystem and are cheaper than"
    " spinning up the sandbox.\n"
    "\n"
    "Key behaviours:\n"
    "- State persists across calls within the same conversation:"
    " variables, imports, and files written inside the sandbox are"
    " retained between invocations.\n"
    "- Use print() for ALL output — only stdout, stderr, and exit_code"
    " are captured.\n"
    "- Common modules are available: math, json, re, datetime,"
    " collections, itertools, functools, etc.\n"
    "\n"
    "Network access (HTTP):\n"
    "- Two built-in globals are available — no import needed:\n"
    "    http_get(url)  -> dict with 'status' (int) and 'body' (str)\n"
    "    http_post(url, body='', content_type='application/json')"
    "  -> dict with 'status' (int) and 'body' (str)\n"
    "- Network access is restricted to domains allowlisted by the host.\n"
    "  Requests to non-allowed domains will raise an error.\n"
    "- Example:\n"
    "  resp = http_get('https://httpbin.org/get')\n"
    "  print(resp['status'])  # 200\n"
    "  print(resp['body'])    # JSON response body\n"
    "\n"
    "  resp = http_post('https://httpbin.org/post',"
    " body='{\"key\": \"value\"}')\n"
    "  print(resp['body'])\n"
)

_FILESYSTEM_DESCRIPTION_READ_ONLY = (
    "\n"
    "Filesystem access:\n"
    "- '/input' is a read-only directory containing files provided by the"
    " host. Use it to load datasets, configuration, or any other files"
    " supplied by the operator.\n"
    "- '/input/tmp/' is where the Copilot CLI parks large tool outputs to"
    " keep them out of the model context. The CLI reports these on the"
    " host as '{host_tmp}/<file>'. Inside this sandbox the same files"
    " are visible at '/input/tmp/<file>'.\n"
    "- For quick scans of a large CLI output, prefer the view, head,"
    " tail, grep, or jq tools (they run directly on the host filesystem"
    " against '{host_tmp}/<file>' — no sandbox roundtrip)."
    " Reach for execute_python when you need to compute over the data.\n"
    "- Writes to '/input' will fail; this configuration has no writable"
    " scratch directory.\n"
    "- Example: ``with open('/input/data.csv') as f: rows = f.read()``\n"
)

_FILESYSTEM_DESCRIPTION_READ_WRITE = (
    "\n"
    "Filesystem access:\n"
    "- '/input' is a read-only directory containing files provided by the"
    " host (datasets, configuration, etc.).\n"
    "- '/input/tmp/' is where the Copilot CLI parks large tool outputs to"
    " keep them out of the model context. The CLI reports these on the"
    " host as '{host_tmp}/<file>'. Inside this sandbox the same files"
    " are visible at '/input/tmp/<file>'. For quick scans, prefer view /"
    " head / tail / grep / jq on the host path; reach for execute_python"
    " only when you actually need to compute over the data.\n"
    "- '/output' is a writable directory backed by a real host directory."
    " Files you create there persist across calls, across turns within a"
    " conversation, and (when the operator bind-mounts the directory)"
    " across container restarts.\n"
    "- Example: ``with open('/output/result.json', 'w') as f:"
    " json.dump(data, f)``\n"
)


def _build_tool_description(filesystem_mode: str) -> str:
    """Return the execute_python description tailored to the FS config.

    ``read_only`` is the floor — ``_normalize_filesystem_mode`` guarantees
    every caller lands on one of the two valid modes, so there is no
    bare-base path.

    The filesystem section embeds the *current* host-side path for the
    CLI temp directory so the model is told the real on-disk location
    even when the operator has overridden ``AGENT_INPUT_DIR``.
    """
    host_tmp = get_agent_input_tmp_dir()
    if filesystem_mode == _FILESYSTEM_MODE_READ_WRITE:
        return (
            _EXECUTE_PYTHON_BASE_DESCRIPTION
            + _FILESYSTEM_DESCRIPTION_READ_WRITE.format(host_tmp=host_tmp)
        )
    return (
        _EXECUTE_PYTHON_BASE_DESCRIPTION
        + _FILESYSTEM_DESCRIPTION_READ_ONLY.format(host_tmp=host_tmp)
    )

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sanitize_input(code: str) -> str:
    """Strip backticks, whitespace, and 'python' prefix from LLM output."""
    code = re.sub(r"^(\s|`)*(?i:python)?\s*", "", code)
    code = re.sub(r"(\s|`)*$", "", code)
    return code


def _normalize_filesystem_mode(value: Any) -> str:
    """Normalize the ``filesystem`` frontmatter setting to a known mode.

    Read-only filesystem access is the **floor** — there is no "off"
    setting because the host needs ``/input`` mounted so the guest can
    read large tool outputs parked under ``/input/tmp/``.

    Accepts:

    - ``None`` / missing / ``False``  → ``"read_only"`` (the floor)
    - ``True``                         → ``"read_write"`` (boolean shorthand)
    - The strings ``"read_only"``, ``"read_write"``
      (case-insensitive, hyphens accepted)
    - Legacy ``"none"`` / ``"off"`` / ``"false"`` / ``"disabled"`` →
      ``"read_only"`` with a warning (kept for forward-compat with older
      agent.md files).

    Unknown values fall back to ``"read_only"`` with a warning so a typo
    cannot silently break agents.
    """
    if value is None or value is False:
        return _FILESYSTEM_MODE_READ_ONLY
    if value is True:
        return _FILESYSTEM_MODE_READ_WRITE
    if isinstance(value, str):
        candidate = value.strip().lower().replace("-", "_")
        if candidate in _FILESYSTEM_LEGACY_DISABLE_VALUES:
            logging.warning(
                "execution_sandbox: filesystem=%r is no longer supported;"
                " using 'read_only' (the new floor).",
                value,
            )
            return _FILESYSTEM_MODE_READ_ONLY
        if candidate in _FILESYSTEM_VALID_MODES:
            return candidate
    logging.warning(
        "execution_sandbox: ignoring unknown filesystem=%r (expected one of"
        " %s, true, or false); defaulting to 'read_only'",
        value,
        sorted(_FILESYSTEM_VALID_MODES),
    )
    return _FILESYSTEM_MODE_READ_ONLY


# Default HTTP methods applied when the shorthand form omits them.
_SHORTHAND_DEFAULT_METHODS = ["GET"]


def _parse_shorthand_allowed_domains(raw: str) -> List[Dict[str, Any]]:
    """Parse the compact string form of ``execution_sandbox.allowed_domains``.

    Format::

        "host[,METHOD,...][;host[,METHOD,...]]..."

    Rules:

    - Entries are separated by ``;``.
    - Within each entry, the first token is the host and the remaining
      tokens are HTTP methods.
    - Methods are case-insensitive (stored uppercase).
    - Missing methods default to ``["GET"]``.
    - Bare hostnames are normalized to ``https://<host>``.
    - Hostnames already prefixed with ``http://`` / ``https://`` are kept
      verbatim.
    - Hostnames beginning with ``$`` or ``%`` are env-var references and are
      left unchanged here; :func:`resolve_env_var` resolves them later when
      the sandbox is constructed.
    - Empty entries (e.g. a trailing ``;``) are ignored.

    Example::

        "api.github.com,GET,POST;httpbin.org"
        -> [
            {"url": "https://api.github.com", "methods": ["GET", "POST"]},
            {"url": "https://httpbin.org",    "methods": ["GET"]},
          ]
    """
    result: List[Dict[str, Any]] = []
    for entry in raw.split(";"):
        entry = entry.strip()
        if not entry:
            continue
        tokens = [t.strip() for t in entry.split(",") if t.strip()]
        if not tokens:
            continue
        host = tokens[0]
        if not (
            host.startswith("http://")
            or host.startswith("https://")
            or host.startswith("$")
            or host.startswith("%")
        ):
            host = f"https://{host}"
        methods = [t.upper() for t in tokens[1:]] or list(
            _SHORTHAND_DEFAULT_METHODS
        )
        result.append({"url": host, "methods": methods})
    return result


# ---------------------------------------------------------------------------
# Per-session sandbox management
#
# The Hyperlight WasmSandbox is !Send (not thread-safe and cannot cross
# thread boundaries).  All sandbox instances MUST live on a single
# dedicated worker thread.  The async handler dispatches requests via a
# queue and awaits the result through a concurrent.futures.Future.
# ---------------------------------------------------------------------------

import concurrent.futures
import queue

# Sentinel to shut down the worker thread.
_SHUTDOWN = object()

# Request queue: each item is either _SHUTDOWN or a tuple of
# (session_id, code, allowed_domains, heap_size, stack_size,
#  filesystem_mode, Future).
_request_queue: queue.Queue = queue.Queue()

# Maximum code payload size (10 MiB) — defence-in-depth matching
# hyperlight's own limit.
_MAX_CODE_SIZE = 10 * 1024 * 1024

# Whether the worker thread has been started.
_worker_started = False
_worker_start_lock = threading.Lock()


def _sandbox_worker() -> None:
    """Dedicated thread that owns all Sandbox instances.

    Sandboxes are created lazily on first use and reused for subsequent
    calls with the same session ID.  Because everything runs on this
    single thread, the Rust !Send constraint is satisfied.
    """
    sandboxes: Dict[str, Sandbox] = {}

    while True:
        item = _request_queue.get()
        if item is _SHUTDOWN:
            break

        (
            session_id,
            code,
            allowed_domains,
            heap_size,
            stack_size,
            filesystem_mode,
            fut,
        ) = item
        try:
            # Get-or-create sandbox for this session
            if session_id not in sandboxes:
                kwargs: Dict[str, Any] = {
                    "backend": "wasm",
                    "module": "python_guest.path",
                }
                if heap_size:
                    kwargs["heap_size"] = heap_size
                if stack_size:
                    kwargs["stack_size"] = stack_size

                # Filesystem mounts.  Hyperlight always exposes the guest
                # paths /input and /output; we wire those to host-side
                # paths from AGENT_INPUT_DIR / AGENT_OUTPUT_DIR (defaults
                # /sandbox/in and /sandbox/out — see config.py).
                #
                # The frontmatter expresses INTENT ("I want read_only /
                # read_write filesystem access"); the host environment
                # decides what's actually available.  On hosts that don't
                # provide the mount points (e.g. Azure Functions Linux
                # consumption plan, dev machines without the basic-chat
                # container layout, or operators who set AGENT_INPUT_DIR
                # to a path that doesn't yet exist), we log a warning and
                # silently skip the mount so the sandbox can still be
                # constructed and used for non-FS work.
                host_input_dir = get_agent_input_dir()
                host_output_dir = get_agent_output_dir()
                if os.path.isdir(host_input_dir):
                    kwargs["input_dir"] = host_input_dir
                else:
                    logging.warning(
                        "execution_sandbox: host directory %s is missing;"
                        " /input will not be available inside the sandbox."
                        " If you intended to expose host files to the"
                        " guest, create the directory (and bind-mount real"
                        " content into it) before starting the function"
                        " app, or set AGENT_INPUT_DIR to an existing path.",
                        host_input_dir,
                    )
                if filesystem_mode == _FILESYSTEM_MODE_READ_WRITE:
                    if os.path.isdir(host_output_dir):
                        kwargs["output_dir"] = host_output_dir
                    else:
                        logging.warning(
                            "execution_sandbox: filesystem=read_write was"
                            " requested but host directory %s is missing;"
                            " /output will not be available inside the"
                            " sandbox. Create (and ideally bind-mount)"
                            " the directory to enable persistent writes,"
                            " or set AGENT_OUTPUT_DIR to an existing path.",
                            host_output_dir,
                        )

                sandbox = Sandbox(**kwargs)

                # Apply network allowlist from agent frontmatter
                for entry in allowed_domains:
                    url = entry.get("url", "")
                    if not url:
                        continue
                    url = resolve_env_var(str(url))
                    methods = entry.get("methods")
                    sandbox.allow_domain(url, methods=methods)
                    logging.info(
                        "execution_sandbox: allowed domain %s (methods=%s)",
                        url,
                        methods or "ALL",
                    )

                # Warm up the sandbox runtime (first run triggers init)
                sandbox.run("None")
                sandboxes[session_id] = sandbox
                logging.info(
                    "execution_sandbox: created sandbox for session %s "
                    "(heap=%s, stack=%s, domains=%d, filesystem=%s)",
                    session_id,
                    heap_size or "default",
                    stack_size or "default",
                    len(allowed_domains),
                    filesystem_mode,
                )

            sandbox = sandboxes[session_id]
            result = sandbox.run(code)
            result_json = json.dumps(
                {
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "exit_code": result.exit_code,
                },
                indent=2,
            )
            fut.set_result(result_json)
        except Exception as exc:
            fut.set_exception(exc)


def _ensure_worker_started() -> None:
    """Start the sandbox worker thread if it hasn't been started yet."""
    global _worker_started
    if _worker_started:
        return
    with _worker_start_lock:
        if _worker_started:
            return
        t = threading.Thread(
            target=_sandbox_worker, daemon=True, name="sandbox-worker"
        )
        t.start()
        _worker_started = True
        logging.info("execution_sandbox: worker thread started")


# ---------------------------------------------------------------------------
# Factory: create per-agent execute_python tool
# ---------------------------------------------------------------------------


def create_sandbox_tools(config: Dict[str, Any]) -> List[Tool]:
    """Create an execute_python tool for a specific agent's sandbox config.

    Returns a list with one Tool, or an empty list if the config is invalid.
    The allowed_domains and memory settings are baked into the tool's closure.

    ``allowed_domains`` accepts two forms:

    1. **Compact string** (recommended)::

        execution_sandbox:
          allowed_domains: "api.github.com,GET,POST;httpbin.org"

       See :func:`_parse_shorthand_allowed_domains` for the full grammar.
       Default method when none is listed is ``GET``.

    2. **Explicit list** (also supported, useful for programmatic config)::

        execution_sandbox:
          allowed_domains:
            - url: "https://httpbin.org"
              methods: ["GET"]          # optional — default: all methods
            - url: "https://api.example.com"
          heap_size: "25Mi"             # optional
          stack_size: "35Mi"            # optional
          filesystem: read_write        # optional: read_only | read_write
                                        # default: read_only (the floor)

    Filesystem mounts:

    ``read_only`` is the **floor** — there is no way to fully disable
    filesystem access, because the Copilot CLI writes large tool outputs
    into ``<AGENT_INPUT_DIR>/tmp`` (see ``client_manager.py``) and the
    guest needs ``/input`` to read them.

    - ``read_only`` (default) — guest sees ``/input`` (read-only) mapped
      to the host-side ``AGENT_INPUT_DIR`` (defaults to ``/sandbox/in``).
      The CLI's parked tool outputs are visible at ``/input/tmp/<file>``.
    - ``read_write`` — guest also sees ``/output`` (writable) mapped to
      ``AGENT_OUTPUT_DIR`` (defaults to ``/sandbox/out``).

    Both host paths exist as empty placeholders in the basic-chat
    container image; bind-mount real host directories with
    ``-v <host>:<AGENT_INPUT_DIR>`` and ``-v <host>:<AGENT_OUTPUT_DIR>``
    to persist data across runs.  Override the container-side paths via
    the ``AGENT_INPUT_DIR`` / ``AGENT_OUTPUT_DIR`` env vars when the
    image uses a different layout.
    """
    raw_allowed_domains = config.get("allowed_domains", [])
    if isinstance(raw_allowed_domains, str):
        allowed_domains = _parse_shorthand_allowed_domains(raw_allowed_domains)
    elif isinstance(raw_allowed_domains, list):
        allowed_domains = raw_allowed_domains
    else:
        allowed_domains = []

    heap_size = config.get("heap_size")
    stack_size = config.get("stack_size")
    filesystem_mode = _normalize_filesystem_mode(config.get("filesystem"))

    logging.info(
        "execution_sandbox: creating tool (domains=%d, heap=%s, stack=%s,"
        " filesystem=%s)",
        len(allowed_domains),
        heap_size or "default",
        stack_size or "default",
        filesystem_mode,
    )

    async def _handle_execute_python(invocation: ToolInvocation) -> ToolResult:
        args = invocation.arguments or {}
        code = args.get("code", "")
        if not code.strip():
            return ToolResult(
                text_result_for_llm='{"error": "No code provided"}',
                result_type="failure",
            )

        code = _sanitize_input(code)

        if len(code.encode("utf-8")) > _MAX_CODE_SIZE:
            return ToolResult(
                text_result_for_llm=(
                    '{"error": "Code exceeds maximum size (10 MiB)"}'
                ),
                result_type="failure",
            )

        session_id = invocation.session_id or "default"
        logging.info(
            "execution_sandbox: executing code in session %s "
            "(tool_call=%s, code_len=%d)",
            session_id,
            invocation.tool_call_id,
            len(code),
        )

        try:
            # Ensure the dedicated sandbox worker thread is running
            _ensure_worker_started()

            # Dispatch to the worker thread via queue and await result.
            # All sandbox instances live on the worker thread to satisfy
            # the Rust !Send constraint (WasmSandbox cannot cross threads).
            fut: concurrent.futures.Future[str] = concurrent.futures.Future()
            _request_queue.put(
                (
                    session_id,
                    code,
                    allowed_domains,
                    heap_size,
                    stack_size,
                    filesystem_mode,
                    fut,
                )
            )

            # Await without blocking the event loop
            loop = asyncio.get_running_loop()
            result_json = await asyncio.wrap_future(fut, loop=loop)

            logging.info(
                "execution_sandbox: session %s completed successfully",
                session_id,
            )
            return ToolResult(
                text_result_for_llm=result_json, result_type="success"
            )
        except Exception as exc:
            error_msg = f"{type(exc).__name__}: {exc}"
            logging.error(
                "execution_sandbox: session %s failed: %s",
                session_id,
                error_msg,
            )
            return ToolResult(
                text_result_for_llm=json.dumps({"error": error_msg}),
                result_type="failure",
            )

    tool = Tool(
        name="execute_python",
        description=_build_tool_description(filesystem_mode),
        parameters={
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Python code to execute",
                },
            },
            "required": ["code"],
        },
        handler=_handle_execute_python,
    )

    logging.info("execution_sandbox: execute_python tool created")
    return [tool]
