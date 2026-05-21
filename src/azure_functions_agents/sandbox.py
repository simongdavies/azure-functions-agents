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
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from copilot import define_tool
from copilot.tools import Tool, ToolInvocation, ToolResult
from hyperlight_sandbox import Sandbox
from pydantic import BaseModel, Field

from .config import (
    get_agent_input_dir,
    get_agent_input_tmp_dir,
    get_agent_output_dir,
    resolve_env_var,
)
from .credentials import (
    CredentialResolveError,
    KIND_AZURE_IMDS,
    ParsedSource,
    check_imds_audience_target,
    extract_host,
    parse_source,
    resolve as resolve_credential,
    validate_id as validate_credential_id,
)
from .file_tools import (
    PathTranslationError,
    build_grep_snippet,
    build_head_snippet,
    build_jq_snippet,
    build_tail_snippet,
    build_view_snippet,
    parse_snippet_result,
    translate_to_guest_path,
)
from .custom_tools import (
    CustomToolSpec,
    CustomToolset,
    build_dispatch_snippet,
)
from .untrusted import wrap_untrusted_tool_result

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


# ---------------------------------------------------------------------------
# Sandbox poison recovery
#
# A Python-level exception from ``Sandbox.run()`` means the guest VM is
# dead -- in-guest Python errors arrive as ``result.exit_code != 0``,
# never as exceptions.  Causes we've actually observed: oversized
# host->guest IPC payload (single response body wider than the shared
# memory window between host and guest), guest OOM, guest panic.
#
# Recovery strategy (transparent to the caller / LLM):
#
#   1. The cached ``Sandbox`` is evicted -- it is unrecoverable.
#   2. A fresh sandbox is built with the same configuration (allowed
#      domains, credentials, custom-tool bootstrap, filesystem mounts).
#   3. The SAME failing payload is retried exactly once on the new
#      sandbox -- bounded by ``_SANDBOX_RECOVERY_RETRIES`` to avoid an
#      infinite crash loop on a deterministically poisoning payload.
#   4. If the retry also crashes (deterministic failure), we surface a
#      generic ``SandboxExecutionError`` -- no "please retry" hint, no
#      mention of the underlying poison.  The LLM sees a flat tool
#      failure, the user sees "I couldn't do that".
#
# Session-scoped guest globals are necessarily lost across the reset.
# Files in the bind-mounted ``/output`` directory persist because that
# directory is owned by the host, not the sandbox (see user memory:
# "hyperlight-sandbox.md / Filesystem persistence").
# ---------------------------------------------------------------------------

# Maximum number of silent reconstruct-and-retry attempts after a guest
# crash, per request.  ``1`` means: try once on the original sandbox; if
# it crashes, rebuild and try ONE more time; if that crashes too, give
# up.  Bounded so a deterministically poisoning payload cannot DoS the
# worker thread by triggering an infinite rebuild loop.
_SANDBOX_RECOVERY_RETRIES = 1


class SandboxExecutionError(RuntimeError):
    """Raised after sandbox auto-recovery has been exhausted.

    The worker evicts the poisoned sandbox, rebuilds a fresh one, and
    retries the failing payload up to ``_SANDBOX_RECOVERY_RETRIES``
    times.  This exception is raised only when every retry has also
    crashed -- i.e. the failure looks deterministic for this payload.

    The message embeds the underlying exception (``type(cause).__name__``
    + ``str(cause)``) so the diagnostic signal survives the wrap-and-
    re-raise -- without that, the tool-result formatter would only see
    a useless "Sandbox execution failed." string and the original cause
    (e.g. a hyperlight guest panic) would be invisible to both the LLM
    and operators reading logs.
    """

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
    " tools dispatch a small snippet into this same sandbox and are"
    " cheaper than writing the full execute_python call yourself.\n"
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
    " supplied by the developer.\n"
    "- '/input/tmp/' is where the Copilot CLI parks large tool outputs to"
    " keep them out of the model context. The CLI reports these on the"
    " host as '{host_tmp}/<file>'. Inside this sandbox the same files"
    " are visible at '/input/tmp/<file>'.\n"
    "- For quick scans of a parked tool output, the view, head, tail,"
    " grep, and jq tools accept either the host path the CLI reported"
    " or the in-sandbox '/input/tmp/<file>' form; they dispatch a small"
    " snippet into this same sandbox.  Use them for navigation and"
    " reach for execute_python when you need to compute over the data.\n"
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
    " are visible at '/input/tmp/<file>'. The view / head / tail / grep"
    " / jq tools accept either form and dispatch into this same sandbox;"
    " use them for navigation and reach for execute_python only when"
    " you need to compute over the data.\n"
    "- '/output' is a writable directory backed by a real host directory."
    " Files you create there persist across calls, across turns within a"
    " conversation, and (when the developer bind-mounts the directory)"
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
    even when the developer has overridden ``AGENT_INPUT_DIR``.
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
# File-tool parameter models
#
# Defined at module scope (not inside ``create_sandbox_tools``) because
# ``@define_tool`` reads the parameter type via ``get_type_hints``, which
# fails for classes defined inside closures when
# ``from __future__ import annotations`` is in effect.
# ---------------------------------------------------------------------------


class _SandboxViewParams(BaseModel):
    path: str = Field(
        description=(
            "Absolute path to the file. Accepts either an in-sandbox path"
            " (e.g. '/input/tmp/foo.json') or the host path the Copilot"
            " CLI reported for parked tool outputs (e.g."
            " '/sandbox/in/tmp/foo.json'); both are translated to the"
            " same in-sandbox location."
        ),
    )
    start_line: Optional[int] = Field(
        default=None,
        description=(
            "1-based start line. If omitted, reads from the beginning."
        ),
    )
    end_line: Optional[int] = Field(
        default=None,
        description=(
            "1-based end line (inclusive). If omitted, reads to the end."
        ),
    )


class _SandboxHeadParams(BaseModel):
    path: str = Field(description="Absolute path to the file.")
    lines: Optional[int] = Field(
        default=10,
        description=(
            "Number of lines to return from the start (default 10)."
        ),
    )


class _SandboxTailParams(BaseModel):
    path: str = Field(description="Absolute path to the file.")
    lines: Optional[int] = Field(
        default=10,
        description=(
            "Number of lines to return from the end (default 10)."
        ),
    )


class _SandboxGrepParams(BaseModel):
    path: str = Field(description="Absolute path to the file to search.")
    pattern: str = Field(description="Search pattern (plain text or regex).")
    is_regex: Optional[bool] = Field(
        default=False,
        description="Treat pattern as a regex (default: plain text).",
    )
    ignore_case: Optional[bool] = Field(
        default=True,
        description="Case-insensitive search (default: true).",
    )
    max_results: Optional[int] = Field(
        default=50,
        description=(
            "Maximum number of matching lines to return (default 50)."
        ),
    )


class _SandboxJqParams(BaseModel):
    path: str = Field(description="Absolute path to a JSON file.")
    query: str = Field(
        description=(
            "Dot-separated path to extract (e.g. '.results',"
            " '.data.items', '.[0].name'). Use '.' for the entire"
            " document."
        ),
    )
    max_items: Optional[int] = Field(
        default=20,
        description=(
            "If the result is an array, return at most this many items"
            " (default 20)."
        ),
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
# Scoped credentials (closed source-type set; see ``credentials/``)
# ---------------------------------------------------------------------------

# Frontmatter defaults for the ``header`` and ``prefix`` fields on each
# ``credentials:`` entry.  Mirrors the upstream Sandbox.register_credential
# defaults so omitting them in agent.md produces the same wire shape.
_CREDENTIAL_DEFAULT_HEADER = "Authorization"
_CREDENTIAL_DEFAULT_PREFIX = "Bearer "


@dataclass(frozen=True)
class _CredentialSpec:
    """A parsed, validated frontmatter ``credentials:`` entry.

    Resolution to a literal token is deferred to the sandbox worker
    thread (see :func:`_sandbox_worker`) so the runtime call to IMDS /
    env-lookup happens at session-boot time, not at app-startup time.
    Storing the :class:`ParsedSource` (rather than the raw string)
    keeps the worker thread's hot path free of re-parsing and shifts
    every config error to the parse step where the message is more
    actionable.
    """

    id: str
    parsed_source: ParsedSource
    target: str
    resource: Optional[str]
    header: str
    prefix: str


def _normalize_credential_target(target: str) -> str:
    """Normalize a credential ``target`` to a URL-prefix string.

    Bare hostnames are promoted to ``https://<host>`` so the guest's
    ``starts_with`` scoping matches the way agents typically write
    requests (``https://management.azure.com/...``).  Targets that
    already include a scheme are passed through verbatim.
    """
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"https://{target}"


def _parse_credentials(
    raw: Any,
    allowed_domain_hosts: Set[str],
) -> List[_CredentialSpec]:
    """Validate the ``credentials:`` frontmatter block.

    Performs *all* parse-time validation up front (closed source-type
    set, id syntax + uniqueness, target-host containment, resource
    required for IMDS, header / prefix types) so a misconfigured
    agent.md fails app startup -- not a later, harder-to-debug
    invocation.

    Returns ``[]`` for missing / ``None`` values; raises
    :class:`ValueError` on any structural problem.

    ``allowed_domain_hosts`` is the set of bare hostnames already
    granted by ``execution_sandbox.allowed_domains``.  Any
    ``credentials[i].target`` whose host is not in that set is a
    parse-time error: an agent that writes a credentialed request to
    an un-allowlisted host would just receive a denied-domain error
    at runtime, so we surface the contradiction now.
    """
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(
            "credentials: must be a list of entries,"
            f" got {type(raw).__name__}"
        )

    seen_ids: Set[str] = set()
    out: List[_CredentialSpec] = []

    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(
                f"credentials[{idx}]: each entry must be a mapping,"
                f" got {type(entry).__name__}"
            )

        cred_id = validate_credential_id(entry.get("id"))
        if cred_id in seen_ids:
            raise ValueError(
                f"credentials: duplicate id {cred_id!r}"
                " (each id must appear at most once)"
            )
        seen_ids.add(cred_id)

        source_raw = entry.get("source")
        if not isinstance(source_raw, str):
            raise ValueError(
                f"credentials[{cred_id}]: missing or non-string 'source'"
            )
        parsed_source = parse_source(source_raw)

        target = entry.get("target")
        if not isinstance(target, str) or not target.strip():
            raise ValueError(
                f"credentials[{cred_id}]: missing or empty 'target'"
            )
        target_stripped = target.strip()
        target_host = extract_host(target_stripped)
        if not target_host:
            raise ValueError(
                f"credentials[{cred_id}]: target {target!r} has no host"
            )
        if target_host not in allowed_domain_hosts:
            raise ValueError(
                f"credentials[{cred_id}]: target host {target_host!r}"
                " is not in allowed_domains"
                f" ({sorted(allowed_domain_hosts) or 'empty'})."
                " Add the host to allowed_domains first;"
                " credentials may only target hosts the sandbox is"
                " already permitted to reach."
            )
        normalized_target = _normalize_credential_target(target_stripped)

        resource = entry.get("resource")
        if resource is not None and not isinstance(resource, str):
            raise ValueError(
                f"credentials[{cred_id}]: 'resource' must be a string"
                f" when present, got {type(resource).__name__}"
            )
        if parsed_source.kind == KIND_AZURE_IMDS and not resource:
            raise ValueError(
                f"credentials[{cred_id}]: 'resource' is required when"
                " source is 'azure_imds'"
            )

        # MSI audience / target cross-check.
        #
        # Delegated to :func:`check_imds_audience_target` (lives in
        # ``credentials/`` so it is unit-testable without loading the
        # heavy ``copilot`` / ``hyperlight_sandbox`` imports the rest
        # of this module pulls in).  See the helper's docstring for
        # the threat-model rationale.
        if parsed_source.kind == KIND_AZURE_IMDS:
            # ``resource`` is non-None here (the check above raises
            # otherwise); the cast is for the type checker.
            assert resource is not None  # noqa: S101 - parse-time invariant
            check_imds_audience_target(
                cred_id=cred_id,
                resource=resource,
                target_host=target_host,
            )

        header = entry.get("header", _CREDENTIAL_DEFAULT_HEADER)
        if not isinstance(header, str) or not header:
            raise ValueError(
                f"credentials[{cred_id}]: 'header' must be a non-empty"
                " string"
            )

        prefix = entry.get("prefix", _CREDENTIAL_DEFAULT_PREFIX)
        if not isinstance(prefix, str):
            raise ValueError(
                f"credentials[{cred_id}]: 'prefix' must be a string"
                f" (got {type(prefix).__name__});"
                ' use "" if you do not want one'
            )

        out.append(
            _CredentialSpec(
                id=cred_id,
                parsed_source=parsed_source,
                target=normalized_target,
                resource=resource,
                header=header,
                prefix=prefix,
            )
        )

    return out


def _allowed_domain_hosts(
    allowed_domains: List[Dict[str, Any]],
) -> Set[str]:
    """Return the lower-cased host set covered by ``allowed_domains``.

    The set is used to cross-check ``credentials[i].target`` -- see
    :func:`_parse_credentials` for the contract.  Entries whose URL
    is an env-var reference (``$VAR`` / ``%VAR%``) are skipped: we
    cannot statically know what host they resolve to, and the
    cross-check would surface a confusing message that names a
    placeholder rather than the actual config bug.
    """
    hosts: Set[str] = set()
    for entry in allowed_domains:
        url = entry.get("url", "")
        if not isinstance(url, str) or not url:
            continue
        if url.startswith("$") or url.startswith("%"):
            # Env-var reference -- resolved later by ``resolve_env_var``.
            continue
        host = extract_host(url)
        if host:
            hosts.add(host)
    return hosts


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

# Request queue: each item is either ``_SHUTDOWN``, a per-session
# session request (9-tuple shape below), or a :class:`_DiscoveryRequest`
# for the one-shot discovery sandbox path.
#
# Session-request tuple:
#   (session_id, code, allowed_domains, heap_size, stack_size,
#    filesystem_mode, credentials, custom_bootstrap, Future)
#
# ``custom_bootstrap`` is the concatenated source of every developer
# tool file accepted for this agent.  The worker runs it exactly once
# per (agent, session) pair -- right after the warmup ``run("None")``
# and before the first user-triggered call -- so the developer's tool
# function names land in the guest's global namespace.  Subsequent
# dispatch snippets (built by :func:`custom_tools.build_dispatch_snippet`)
# call those functions directly.  The empty string disables the
# bootstrap step, which is the common case for agents that ship no
# custom tools.
_request_queue: queue.Queue = queue.Queue()

# Maximum code payload size (10 MiB) — defence-in-depth matching
# hyperlight's own limit.
_MAX_CODE_SIZE = 10 * 1024 * 1024

# Default hard cap for one-shot discovery sandbox runs.  Discovery
# happens at agent registration (startup) so a generous timeout is
# fine -- but a runaway snippet must not hang Functions startup
# forever.  Tuned to cover the slow first-launch path on small SKUs;
# routine runs complete in well under a second.
_DEFAULT_DISCOVERY_TIMEOUT_SECS = 30.0

# Whether the worker thread has been started.
_worker_started = False
_worker_start_lock = threading.Lock()


@dataclass
class _DiscoveryRequest:
    """A one-shot ephemeral-sandbox run for custom-tool discovery.

    Routed through the same worker thread as session requests because
    Hyperlight ``Sandbox`` instances are ``!Send`` and the worker is
    the single thread allowed to own them.  Each discovery request
    spins up its own fresh sandbox (no domains, no credentials, no
    filesystem mounts) and disposes of it before the worker takes
    the next item -- discovery sandboxes are NEVER cached.
    """

    snippet: str
    fut: "concurrent.futures.Future[str]"


def _build_session_sandbox(
    session_id: str,
    allowed_domains: List[Dict[str, Any]],
    heap_size: Optional[str],
    stack_size: Optional[str],
    filesystem_mode: str,
    credentials: List[Any],
    custom_bootstrap: str,
) -> Sandbox:
    """Construct + fully bootstrap a per-session ``Sandbox``.

    Extracted from the worker loop so the cold-cache path and the
    auto-recovery path (post-crash rebuild) share the same construction
    contract.  Must be called from the sandbox worker thread because
    ``Sandbox`` is ``!Send``.

    Builds and returns a sandbox with:

    * the requested heap / stack overrides (omitted when ``None`` so
      the upstream SDK defaults apply);
    * ``/input`` and (when ``filesystem_mode == 'read_write'``)
      ``/output`` mounts wired to the configured host directories,
      silently skipped with a warning when the host directory is
      missing;
    * each ``allowed_domains`` entry applied via ``allow_domain``;
    * each credential applied via ``register_credential`` with a
      per-spec resolver closure that defers token resolution until the
      first credentialed HTTP call (so IMDS rotation is picked up
      within the cache TTL, and the literal token never crosses the
      host -> guest boundary as guest-runnable bytes);
    * a warmup ``run("None")`` to trigger first-call init;
    * the developer-supplied ``custom_bootstrap`` snippet, when
      non-empty -- a non-zero ``exit_code`` here is fatal (raises
      ``RuntimeError``) because subsequent dispatch snippets would
      reference functions the bootstrap failed to define.

    Caller is responsible for caching the returned sandbox under the
    session id; this helper does not touch any shared state.
    """
    kwargs: Dict[str, Any] = {
        "backend": "wasm",
        "module": "python_guest.path",
    }
    if heap_size:
        kwargs["heap_size"] = heap_size
    if stack_size:
        kwargs["stack_size"] = stack_size

    # Filesystem mounts.  Hyperlight always exposes the guest paths
    # /input and /output; we wire those to host-side paths from
    # AGENT_INPUT_DIR / AGENT_OUTPUT_DIR (defaults /sandbox/in and
    # /sandbox/out -- see config.py).  The frontmatter expresses
    # INTENT; the host environment decides what's actually available.
    # On hosts that don't provide the mount points we log a warning
    # and silently skip the mount so the sandbox can still be
    # constructed and used for non-FS work.
    host_input_dir = get_agent_input_dir()
    host_output_dir = get_agent_output_dir()
    if os.path.isdir(host_input_dir):
        kwargs["input_dir"] = host_input_dir
    else:
        logging.warning(
            "execution_sandbox: host directory %s is missing;"
            " /input will not be available inside the sandbox."
            " If you intended to expose host files to the guest,"
            " create the directory (and bind-mount real content into"
            " it) before starting the function app, or set"
            " AGENT_INPUT_DIR to an existing path.",
            host_input_dir,
        )
    if filesystem_mode == _FILESYSTEM_MODE_READ_WRITE:
        if os.path.isdir(host_output_dir):
            kwargs["output_dir"] = host_output_dir
        else:
            logging.warning(
                "execution_sandbox: filesystem=read_write was requested"
                " but host directory %s is missing; /output will not be"
                " available inside the sandbox. Create (and ideally"
                " bind-mount) the directory to enable persistent writes,"
                " or set AGENT_OUTPUT_DIR to an existing path.",
                host_output_dir,
            )

    sandbox = Sandbox(**kwargs)

    # Apply network allowlist from agent frontmatter.
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

    # Scoped credentials.  The upstream API requires
    # ``register_credential`` to be called before the first
    # ``run()``; doing it here -- after ``allow_domain`` and before
    # the warmup ``run("None")`` -- gives the guest both gates active
    # by the time any agent code runs.
    #
    # The resolver is a **callable** (not a literal token): the fork
    # invokes it on every credentialed outgoing request, so IMDS-token
    # rotation, env-var changes, and transient IMDS outages are handled
    # at request time, not session-boot time.  Token caching (5-min
    # refresh window) lives inside :mod:`credentials.azure_imds`, so we
    # are not hammering IMDS per request -- but we ARE picking up
    # rotated tokens within the cache TTL.
    #
    # The literal token never crosses the host -> guest boundary as
    # guest-runnable bytes: it is produced on the host inside this
    # closure and handed to the WIT ``resolver`` -- the guest only ever
    # references the credential by *id* (threat-model P1).
    #
    # Default-argument capture (``ps=...``, ``r=...``) is required to
    # bind each iteration's spec into the closure -- otherwise every
    # closure would close over the loop variable and resolve the last
    # spec only.
    for spec in credentials:
        def _resolver(
            ps: ParsedSource = spec.parsed_source,
            r: Optional[str] = spec.resource,
        ) -> str:
            return resolve_credential(ps, resource=r)

        sandbox.register_credential(
            spec.id,
            target=spec.target,
            header=spec.header,
            prefix=spec.prefix,
            resolver=_resolver,
        )
        logging.info(
            "execution_sandbox: registered credential id=%s"
            " target=%s header=%s (resolver=callable, token redacted)",
            spec.id,
            spec.target,
            spec.header,
        )

    # Warm up the sandbox runtime (first run triggers init).
    sandbox.run("None")

    # Developer-supplied tools (see :mod:`custom_tools`).  The
    # bootstrap defines every accepted custom function in the guest's
    # global namespace so the per-call dispatch snippets can invoke
    # them by name.  Failures here are FATAL for the session: a broken
    # bootstrap means every subsequent custom-tool call would also
    # fail, so we raise rather than caching a half-initialised
    # sandbox.
    if custom_bootstrap:
        bootstrap_result = sandbox.run(custom_bootstrap)
        if bootstrap_result.exit_code != 0:
            raise RuntimeError(
                "custom-tool bootstrap failed in session"
                f" {session_id} (exit_code={bootstrap_result.exit_code});"
                f" stderr: {bootstrap_result.stderr.strip()!r}"
            )
        logging.info(
            "execution_sandbox: custom-tool bootstrap executed in"
            " session %s (%d bytes)",
            session_id,
            len(custom_bootstrap),
        )

    return sandbox


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

        # One-shot ephemeral-sandbox path for custom-tool discovery.
        # Handled before the session-request unpacking so the two
        # request shapes stay cleanly separated.  The fresh sandbox
        # is intentionally NOT cached -- it has no domains, no
        # credentials, no filesystem mounts, and runs only a single
        # host-controlled introspection snippet, so reuse would buy
        # us nothing and cost us blast-radius.
        if isinstance(item, _DiscoveryRequest):
            try:
                discovery_sandbox = Sandbox(
                    backend="wasm",
                    module="python_guest.path",
                )
                # Warm-up run -- triggers first-call guest init so the
                # subsequent snippet's stdout starts cleanly.
                discovery_sandbox.run("None")
                result = discovery_sandbox.run(item.snippet)
                if result.exit_code != 0:
                    item.fut.set_exception(
                        RuntimeError(
                            "discovery snippet exited with code"
                            f" {result.exit_code}; stderr:"
                            f" {result.stderr.strip()!r}"
                        )
                    )
                else:
                    item.fut.set_result(result.stdout)
            except Exception as exc:
                item.fut.set_exception(exc)
            # ``discovery_sandbox`` falls out of scope here; the
            # Rust ``Drop`` impl on the underlying WasmSandbox tears
            # the VM down.
            continue

        (
            session_id,
            code,
            allowed_domains,
            heap_size,
            stack_size,
            filesystem_mode,
            credentials,
            custom_bootstrap,
            fut,
        ) = item
        try:
            # Get-or-create sandbox for this session
            if session_id not in sandboxes:
                sandboxes[session_id] = _build_session_sandbox(
                    session_id=session_id,
                    allowed_domains=allowed_domains,
                    heap_size=heap_size,
                    stack_size=stack_size,
                    filesystem_mode=filesystem_mode,
                    credentials=credentials,
                    custom_bootstrap=custom_bootstrap,
                )
                logging.info(
                    "execution_sandbox: created sandbox for session %s "
                    "(heap=%s, stack=%s, domains=%d, credentials=%d,"
                    " filesystem=%s, custom_bootstrap=%s)",
                    session_id,
                    heap_size or "default",
                    stack_size or "default",
                    len(allowed_domains),
                    len(credentials),
                    filesystem_mode,
                    "yes" if custom_bootstrap else "no",
                )

            # Cached-sandbox run path with bounded auto-recovery.
            #
            # On each iteration we try ``sandbox.run(code)``.  A
            # Python-level exception means the guest VM is dead (see
            # the "Sandbox poison recovery" header at the top of this
            # module).  We evict the dead instance, rebuild a fresh
            # one with identical config, and retry the SAME payload --
            # bounded by ``_SANDBOX_RECOVERY_RETRIES`` so a
            # deterministically poisoning payload cannot trap the
            # worker thread in an infinite rebuild loop.  Once the
            # budget is exhausted we surface a generic
            # ``SandboxExecutionError`` (no retry hint) so the LLM
            # treats it as a flat tool failure.
            result = None
            last_exc: Optional[BaseException] = None
            # +1 because the first iteration is the initial attempt,
            # not a retry; ``_SANDBOX_RECOVERY_RETRIES`` counts the
            # *recovery* attempts that follow it.
            for attempt in range(_SANDBOX_RECOVERY_RETRIES + 1):
                sandbox = sandboxes[session_id]
                try:
                    result = sandbox.run(code)
                    break
                except Exception as exc:
                    last_exc = exc
                    # Always evict: even if we're about to give up,
                    # we never want to hand the next request a known-
                    # dead sandbox.
                    sandboxes.pop(session_id, None)
                    if attempt < _SANDBOX_RECOVERY_RETRIES:
                        logging.warning(
                            "execution_sandbox: session %s sandbox"
                            " crashed (attempt %d/%d); evicted and"
                            " rebuilding for silent retry. Underlying"
                            " error: %s: %s",
                            session_id,
                            attempt + 1,
                            _SANDBOX_RECOVERY_RETRIES + 1,
                            type(exc).__name__,
                            exc,
                        )
                        try:
                            sandboxes[session_id] = _build_session_sandbox(
                                session_id=session_id,
                                allowed_domains=allowed_domains,
                                heap_size=heap_size,
                                stack_size=stack_size,
                                filesystem_mode=filesystem_mode,
                                credentials=credentials,
                                custom_bootstrap=custom_bootstrap,
                            )
                        except Exception as rebuild_exc:
                            # If even the rebuild fails we have no
                            # cached entry and no point retrying --
                            # break out and surface as the final
                            # failure.
                            logging.error(
                                "execution_sandbox: session %s rebuild"
                                " after crash also failed: %s: %s",
                                session_id,
                                type(rebuild_exc).__name__,
                                rebuild_exc,
                            )
                            last_exc = rebuild_exc
                            break
                        continue
                    # Recovery budget exhausted -- fall through.
                    logging.error(
                        "execution_sandbox: session %s sandbox crashed"
                        " on attempt %d/%d; recovery budget exhausted."
                        " Underlying error: %s: %s",
                        session_id,
                        attempt + 1,
                        _SANDBOX_RECOVERY_RETRIES + 1,
                        type(exc).__name__,
                        exc,
                    )

            if result is None:
                # All attempts crashed.  Surface the underlying cause
                # in the exception message so it propagates to the
                # tool-result wrapper (which stringifies the exception
                # type + message for the LLM).  Without this, the
                # original ``last_exc`` lived only on ``__cause__`` and
                # the LLM saw a useless generic "Sandbox execution
                # failed." -- erasing the diagnostic signal we need to
                # tell deterministic poisoning apart from transient
                # crashes.
                if last_exc is None:
                    underlying = "unknown error"
                else:
                    underlying = f"{type(last_exc).__name__}: {last_exc}"
                raise SandboxExecutionError(
                    f"Sandbox execution failed after"
                    f" {_SANDBOX_RECOVERY_RETRIES + 1} attempt(s):"
                    f" {underlying}"
                ) from last_exc

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


def run_discovery_in_sandbox(
    snippet: str,
    timeout: Optional[float] = None,
) -> str:
    """Run a host-controlled introspection snippet in a fresh sandbox.

    Used at agent registration time by
    :func:`custom_tools.discover_custom_tools` to introspect
    developer-supplied tool sources without invoking the host CPython
    parser on developer bytes (see the threat-model addendum in
    :mod:`custom_tools`).

    Synchronous (blocks the calling thread) because discovery runs
    inside Functions worker startup, which is itself a synchronous
    code path.  The actual Hyperlight VM lives on the existing
    sandbox worker thread to honour the ``!Send`` constraint.

    Args:
        snippet: A complete Python program produced by
            :func:`custom_tools.build_discovery_snippet`.  Must
            contain only framework-generated code -- developer
            content is embedded as JSON string literals, not parsed
            on the host.
        timeout: Hard cap in seconds, or ``None`` for the default
            (:data:`_DEFAULT_DISCOVERY_TIMEOUT_SECS`).  On timeout
            the function raises :class:`concurrent.futures.TimeoutError`
            and the caller treats the agent as having no custom
            tools.

    Returns:
        The snippet's stdout (UTF-8 string), ready to feed into
        :func:`custom_tools.parse_discovery_output`.

    Raises:
        RuntimeError: snippet exited non-zero in the guest.
        concurrent.futures.TimeoutError: snippet exceeded the cap.
        Exception: any other failure raised by the worker
            (sandbox construction error, etc.) propagates as-is.
    """
    effective_timeout = (
        timeout if timeout is not None else _DEFAULT_DISCOVERY_TIMEOUT_SECS
    )
    _ensure_worker_started()
    fut: "concurrent.futures.Future[str]" = concurrent.futures.Future()
    _request_queue.put(_DiscoveryRequest(snippet=snippet, fut=fut))
    return fut.result(timeout=effective_timeout)


# ---------------------------------------------------------------------------
# Factory: create per-agent execute_python tool
# ---------------------------------------------------------------------------


def _build_custom_copilot_tool(
    spec: CustomToolSpec,
    dispatch: Any,
) -> Tool:
    """Wrap one :class:`CustomToolSpec` as a Copilot SDK ``Tool``.

    The handler:

    1. Filters ``invocation.arguments`` down to the developer's declared
       parameter names (the schema already forbids
       ``additionalProperties`` so the LLM should not be sending
       extras, but defence-in-depth costs nothing).
    2. Builds a dispatch snippet via
       :func:`custom_tools.build_dispatch_snippet`.
    3. Runs the snippet through the standard per-session sandbox
       dispatcher and decodes the result via
       :func:`file_tools.parse_snippet_result`.

    ``dispatch`` is the closure :func:`create_sandbox_tools` builds
    around the per-agent settings (allowed domains, credentials, ...).
    Passing it in keeps this helper a pure function of its spec and
    avoids leaking the surrounding closure environment.
    """
    tool_name = spec.name
    allowed_keys = set(spec.parameter_names)

    async def _handler(invocation: ToolInvocation) -> ToolResult:
        raw_args = invocation.arguments or {}
        filtered = {k: v for k, v in raw_args.items() if k in allowed_keys}
        snippet = build_dispatch_snippet(spec, filtered)
        session_id = invocation.session_id or "default"
        logging.info(
            "execution_sandbox: custom tool %r invoked in session %s"
            " (args=%s)",
            tool_name,
            session_id,
            sorted(filtered.keys()),
        )
        try:
            envelope = await dispatch(session_id, snippet)
        except Exception as exc:
            err = f"{type(exc).__name__}: {exc}"
            logging.error(
                "execution_sandbox: custom tool %r dispatch failed"
                " in session %s: %s",
                tool_name,
                session_id,
                err,
            )
            return ToolResult(
                text_result_for_llm=wrap_untrusted_tool_result(
                    tool_name, json.dumps({"error": err})
                ),
                result_type="failure",
            )

        ok, payload = parse_snippet_result(envelope)
        return ToolResult(
            text_result_for_llm=wrap_untrusted_tool_result(
                tool_name, json.dumps(payload)
            ),
            result_type="success" if ok else "failure",
        )

    return Tool(
        name=tool_name,
        description=spec.description,
        parameters=spec.parameters_schema,
        handler=_handler,
    )


def create_sandbox_tools(
    config: Dict[str, Any],
    custom_toolset: Optional[CustomToolset] = None,
) -> List[Tool]:
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

    Developer-supplied tools:

    When a :class:`CustomToolset` is passed (typically discovered
    by :func:`custom_tools.discover_custom_tools` at agent
    registration time), each tool spec becomes its own Copilot SDK
    tool whose handler dispatches into this same per-session sandbox.
    The developer's Python source is executed *inside the Hyperlight
    VM* via a one-shot bootstrap snippet (see ``_sandbox_worker``)
    -- never on the host.
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

    # Credentials parsed at app-startup time so misconfigured agent.md
    # files fail loud here rather than at first-invocation.  The
    # per-host cross-check below relies on allowed_domains having
    # already been normalized into the {url, methods} dict shape.
    credentials = _parse_credentials(
        config.get("credentials"),
        _allowed_domain_hosts(allowed_domains),
    )

    # Developer-supplied tools.  The toolset is discovered upstream
    # (see :mod:`app`) so this function does not need to know about
    # filesystem layout; here we only need the bootstrap string and
    # the per-tool specs.  ``None`` means "no custom tools for this
    # agent" -- the default for agents that omit ``tools/`` or set
    # ``execution_sandbox.tools: []``.
    custom_specs: Tuple[CustomToolSpec, ...] = (
        custom_toolset.specs if custom_toolset else ()
    )
    custom_bootstrap: str = (
        custom_toolset.bootstrap_code if custom_toolset else ""
    )

    logging.info(
        "execution_sandbox: creating tool (domains=%d, credentials=%d,"
        " heap=%s, stack=%s, filesystem=%s, custom_tools=%d)",
        len(allowed_domains),
        len(credentials),
        heap_size or "default",
        stack_size or "default",
        filesystem_mode,
        len(custom_specs),
    )

    async def _dispatch_to_sandbox(session_id: str, code: str) -> str:
        """Send ``code`` to this agent's sandbox and return the raw envelope.

        Shared by both ``execute_python`` and the file tools.  Returns
        the JSON-encoded ``{stdout, stderr, exit_code}`` envelope as a
        string; callers decide how to surface it to the LLM.  Raises any
        exception the worker thread set on the Future (network errors,
        sandbox boot failures, etc.).
        """
        _ensure_worker_started()
        fut: concurrent.futures.Future[str] = concurrent.futures.Future()
        _request_queue.put(
            (
                session_id,
                code,
                allowed_domains,
                heap_size,
                stack_size,
                filesystem_mode,
                credentials,
                custom_bootstrap,
                fut,
            )
        )
        loop = asyncio.get_running_loop()
        return await asyncio.wrap_future(fut, loop=loop)

    async def _handle_execute_python(invocation: ToolInvocation) -> ToolResult:
        args = invocation.arguments or {}
        code = args.get("code", "")
        if not code.strip():
            return ToolResult(
                text_result_for_llm=wrap_untrusted_tool_result(
                    "execute_python", '{"error": "No code provided"}'
                ),
                result_type="failure",
            )

        code = _sanitize_input(code)

        if len(code.encode("utf-8")) > _MAX_CODE_SIZE:
            return ToolResult(
                text_result_for_llm=wrap_untrusted_tool_result(
                    "execute_python",
                    '{"error": "Code exceeds maximum size (10 MiB)"}',
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
            result_json = await _dispatch_to_sandbox(session_id, code)
            logging.info(
                "execution_sandbox: session %s completed successfully",
                session_id,
            )
            return ToolResult(
                text_result_for_llm=wrap_untrusted_tool_result(
                    "execute_python", result_json
                ),
                result_type="success",
            )
        except Exception as exc:
            error_msg = f"{type(exc).__name__}: {exc}"
            logging.error(
                "execution_sandbox: session %s failed: %s",
                session_id,
                error_msg,
            )
            return ToolResult(
                text_result_for_llm=wrap_untrusted_tool_result(
                    "execute_python", json.dumps({"error": error_msg})
                ),
                result_type="failure",
            )

    execute_python_tool = Tool(
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

    # -----------------------------------------------------------------
    # File tools (view / head / tail / grep / jq) -- dispatch a small
    # Python snippet into the same per-session sandbox.  The wrapping
    # helper below is intentionally short: it owns path translation,
    # snippet build error handling, and envelope decoding so every tool
    # body stays a one-liner.
    # -----------------------------------------------------------------

    async def _run_file_tool(
        tool_name: str,
        invocation: ToolInvocation,
        snippet_builder,
        snippet_kwargs: Dict[str, Any],
    ) -> ToolResult:
        # Path translation is the security boundary: if it refuses the
        # path, the LLM gets a clean error and the sandbox is never
        # asked to open anything outside the mount roots.
        path = snippet_kwargs.pop("path")
        try:
            guest_path = translate_to_guest_path(path)
        except PathTranslationError as exc:
            return ToolResult(
                text_result_for_llm=wrap_untrusted_tool_result(
                    tool_name, json.dumps({"error": str(exc)})
                ),
                result_type="failure",
            )

        snippet = snippet_builder(path=guest_path, **snippet_kwargs)
        session_id = invocation.session_id or "default"
        logging.info(
            "execution_sandbox: %s on '%s' in session %s",
            tool_name,
            guest_path,
            session_id,
        )

        try:
            envelope = await _dispatch_to_sandbox(session_id, snippet)
        except Exception as exc:
            err = f"{type(exc).__name__}: {exc}"
            logging.error(
                "execution_sandbox: %s failed in session %s: %s",
                tool_name,
                session_id,
                err,
            )
            return ToolResult(
                text_result_for_llm=wrap_untrusted_tool_result(
                    tool_name, json.dumps({"error": err})
                ),
                result_type="failure",
            )

        ok, payload = parse_snippet_result(envelope)
        return ToolResult(
            text_result_for_llm=wrap_untrusted_tool_result(
                tool_name, json.dumps(payload)
            ),
            result_type="success" if ok else "failure",
        )

    async def _view_handler(
        params: _SandboxViewParams, invocation: ToolInvocation
    ) -> ToolResult:
        return await _run_file_tool(
            "view",
            invocation,
            build_view_snippet,
            {
                "path": params.path,
                "start_line": params.start_line,
                "end_line": params.end_line,
            },
        )

    async def _head_handler(
        params: _SandboxHeadParams, invocation: ToolInvocation
    ) -> ToolResult:
        return await _run_file_tool(
            "head",
            invocation,
            build_head_snippet,
            {"path": params.path, "lines": params.lines},
        )

    async def _tail_handler(
        params: _SandboxTailParams, invocation: ToolInvocation
    ) -> ToolResult:
        return await _run_file_tool(
            "tail",
            invocation,
            build_tail_snippet,
            {"path": params.path, "lines": params.lines},
        )

    async def _grep_handler(
        params: _SandboxGrepParams, invocation: ToolInvocation
    ) -> ToolResult:
        return await _run_file_tool(
            "grep",
            invocation,
            build_grep_snippet,
            {
                "path": params.path,
                "pattern": params.pattern,
                "is_regex": bool(params.is_regex),
                "ignore_case": bool(params.ignore_case),
                "max_results": params.max_results,
            },
        )

    async def _jq_handler(
        params: _SandboxJqParams, invocation: ToolInvocation
    ) -> ToolResult:
        return await _run_file_tool(
            "jq",
            invocation,
            build_jq_snippet,
            {
                "path": params.path,
                "query": params.query,
                "max_items": params.max_items,
            },
        )

    view_tool = define_tool(
        "view",
        description=(
            "View a file in the sandbox by path. Use start_line / end_line"
            " to read specific sections. Accepts either an in-sandbox path"
            " (e.g. '/input/tmp/foo.json') or the host-side path the"
            " Copilot CLI reported for parked tool outputs (e.g."
            " '/sandbox/in/tmp/foo.json'); both resolve to the same"
            " file via the sandbox's '/input' or '/output' mount."
        ),
        overrides_built_in_tool=True,
    )(_view_handler)

    head_tool = define_tool(
        "head",
        description=(
            "Show the first N lines of a file in the sandbox (default 10)."
            " Accepts in-sandbox paths or the host paths the CLI reported"
            " for parked tool outputs."
        ),
    )(_head_handler)

    tail_tool = define_tool(
        "tail",
        description=(
            "Show the last N lines of a file in the sandbox (default 10)."
            " Accepts in-sandbox paths or the host paths the CLI reported"
            " for parked tool outputs."
        ),
    )(_tail_handler)

    grep_tool = define_tool(
        "grep",
        description=(
            "Search for a pattern in a file in the sandbox. Returns"
            " matching lines with line numbers. Supports plain text and"
            " regex patterns. Accepts in-sandbox paths or the host paths"
            " the CLI reported for parked tool outputs."
        ),
        overrides_built_in_tool=True,
    )(_grep_handler)

    jq_tool = define_tool(
        "jq",
        description=(
            "Query a JSON file in the sandbox using a dot-path expression."
            " Examples: '.' (entire doc), '.key', '.items.[0].name',"
            " '.data.results'. Accepts in-sandbox paths or the host paths"
            " the CLI reported for parked tool outputs."
        ),
    )(_jq_handler)

    # ---------------------------------------------------------------
    # Developer-supplied tools (per :mod:`custom_tools`).
    #
    # Each :class:`CustomToolSpec` becomes a Copilot SDK tool with
    # the developer's docstring as the description and the
    # ast-extracted JSON schema as the parameter contract.  The
    # handler builds a dispatch snippet via
    # :func:`build_dispatch_snippet` and runs it against the same
    # per-session sandbox -- so the developer's Python body executes
    # *inside the Hyperlight VM* (loaded by the bootstrap step in
    # ``_sandbox_worker``), not on the host.
    #
    # The factory loop captures each ``spec`` via a default-arg
    # closure to prevent the usual "all closures share the last loop
    # variable" trap.
    # ---------------------------------------------------------------
    custom_tools_list: List[Tool] = []
    for spec in custom_specs:
        custom_tools_list.append(
            _build_custom_copilot_tool(spec, _dispatch_to_sandbox)
        )

    logging.info(
        "execution_sandbox: created %d tools (execute_python + view /"
        " head / tail / grep / jq + %d custom tool(s))",
        6 + len(custom_tools_list),
        len(custom_tools_list),
    )
    return [
        execute_python_tool,
        view_tool,
        head_tool,
        tail_tool,
        grep_tool,
        jq_tool,
        *custom_tools_list,
    ]
