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
import re
import threading
from typing import Any, Dict, List, Optional

from copilot.tools import Tool, ToolInvocation, ToolResult
from hyperlight_sandbox import Sandbox

from .config import resolve_env_var

# ---------------------------------------------------------------------------
# Tool description
# ---------------------------------------------------------------------------

_EXECUTE_PYTHON_DESCRIPTION = (
    "Execute Python code in a persistent sandboxed environment backed by"
    " a Hyperlight Wasm sandbox. Returns JSON with stdout, stderr, and"
    " exit_code.\n"
    "\n"
    "IMPORTANT: This runs in an ISOLATED SANDBOX with its own file system."
    " DO NOT use it to read or process files from the local system,"
    " such as copilot large tool outputs. Use the view, head, tail, grep,"
    " or jq tools instead.\n"
    "\n"
    "Only use this tool when you need to actually run code,"
    " when no other tool can accomplish the task (there's a small cost to"
    " using it) — computation, data processing, fetching web data, etc."
    " Do NOT call this tool just to print text, format output, or display"
    " results you already have. Respond directly with text instead.\n"
    "\n"
    "Key behaviors:\n"
    "- State persists across calls: variables, imports, and files"
    " are retained between invocations within the same conversation.\n"
    "- Use print() for ALL output — there is no implicit last-expression"
    " return like Jupyter. Output appears in 'stdout'.\n"
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

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sanitize_input(code: str) -> str:
    """Strip backticks, whitespace, and 'python' prefix from LLM output."""
    code = re.sub(r"^(\s|`)*(?i:python)?\s*", "", code)
    code = re.sub(r"(\s|`)*$", "", code)
    return code


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
# (session_id, code, allowed_domains, heap_size, stack_size, Future).
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

        session_id, code, allowed_domains, heap_size, stack_size, fut = item
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
                    "(heap=%s, stack=%s, domains=%d)",
                    session_id,
                    heap_size or "default",
                    stack_size or "default",
                    len(allowed_domains),
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

    Expected frontmatter structure::

        execution_sandbox:
          allowed_domains:
            - url: "https://httpbin.org"
              methods: ["GET"]          # optional — default: all methods
            - url: "https://api.example.com"
          heap_size: "25Mi"             # optional
          stack_size: "35Mi"            # optional
    """
    allowed_domains = config.get("allowed_domains", [])
    if not isinstance(allowed_domains, list):
        allowed_domains = []

    heap_size = config.get("heap_size")
    stack_size = config.get("stack_size")

    logging.info(
        "execution_sandbox: creating tool (domains=%d, heap=%s, stack=%s)",
        len(allowed_domains),
        heap_size or "default",
        stack_size or "default",
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
                (session_id, code, allowed_domains, heap_size, stack_size, fut)
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
        description=_EXECUTE_PYTHON_DESCRIPTION,
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
