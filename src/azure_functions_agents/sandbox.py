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
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

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
    ParsedSource,
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
    " supplied by the operator.\n"
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


def _extract_host(target: str) -> str:
    """Return the bare hostname from a target URL or hostname-only string.

    The host is the key we cross-check against the allow_domain set so a
    ``credentials.target`` can never reach a destination the
    allowed_domains list does not also permit (defence-in-depth on top
    of the guest's own scoping).
    """
    if "://" in target:
        parsed = urlparse(target)
        return (parsed.hostname or "").lower()
    return target.split("/", 1)[0].lower()


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
        target_host = _extract_host(target_stripped)
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
        if parsed_source.kind == "azure_imds" and not resource:
            raise ValueError(
                f"credentials[{cred_id}]: 'resource' is required when"
                " source is 'azure_imds'"
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
        host = _extract_host(url)
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

# Request queue: each item is either _SHUTDOWN or a tuple of
# (session_id, code, allowed_domains, heap_size, stack_size,
#  filesystem_mode, credentials, Future).
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
            credentials,
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

                # Scoped credentials.  The upstream API requires
                # ``register_credential`` to be called before the first
                # ``run()``; doing it here -- after ``allow_domain`` and
                # before the warmup ``run("None")`` -- gives the guest
                # both gates active by the time any agent code runs.
                #
                # The resolver is a **callable** (not a literal token):
                # the fork invokes it on every credentialed outgoing
                # request, so IMDS-token rotation, env-var changes, and
                # transient IMDS outages are handled at request time,
                # not session-boot time.  Token caching (5-min refresh
                # window) lives inside :mod:`credentials.azure_imds`,
                # so we are not hammering IMDS per request -- but we
                # ARE picking up rotated tokens within the cache TTL.
                #
                # The literal token never crosses the host -> guest
                # boundary as guest-runnable bytes: it is produced on
                # the host inside this closure and handed to the WIT
                # ``resolver`` -- the guest only ever references the
                # credential by *id* (threat-model P1).
                #
                # Default-argument capture (``ps=...``, ``r=...``) is
                # required to bind each iteration's spec into the
                # closure -- otherwise every closure would close over
                # the loop variable and resolve the last spec only.
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
                        " target=%s header=%s (resolver=callable,"
                        " token redacted)",
                        spec.id,
                        spec.target,
                        spec.header,
                    )

                # Warm up the sandbox runtime (first run triggers init)
                sandbox.run("None")
                sandboxes[session_id] = sandbox
                logging.info(
                    "execution_sandbox: created sandbox for session %s "
                    "(heap=%s, stack=%s, domains=%d, credentials=%d,"
                    " filesystem=%s)",
                    session_id,
                    heap_size or "default",
                    stack_size or "default",
                    len(allowed_domains),
                    len(credentials),
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

    # Credentials parsed at app-startup time so misconfigured agent.md
    # files fail loud here rather than at first-invocation.  The
    # per-host cross-check below relies on allowed_domains having
    # already been normalized into the {url, methods} dict shape.
    credentials = _parse_credentials(
        config.get("credentials"),
        _allowed_domain_hosts(allowed_domains),
    )

    logging.info(
        "execution_sandbox: creating tool (domains=%d, credentials=%d,"
        " heap=%s, stack=%s, filesystem=%s)",
        len(allowed_domains),
        len(credentials),
        heap_size or "default",
        stack_size or "default",
        filesystem_mode,
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
            result_json = await _dispatch_to_sandbox(session_id, code)
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
                text_result_for_llm=json.dumps({"error": str(exc)}),
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
                text_result_for_llm=json.dumps({"error": err}),
                result_type="failure",
            )

        ok, payload = parse_snippet_result(envelope)
        return ToolResult(
            text_result_for_llm=json.dumps(payload),
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

    logging.info(
        "execution_sandbox: created %d tools (execute_python + view /"
        " head / tail / grep / jq)",
        6,
    )
    return [
        execute_python_tool,
        view_tool,
        head_tool,
        tail_tool,
        grep_tool,
        jq_tool,
    ]
