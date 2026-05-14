"""Sandbox-backed file tools (``view``/``head``/``tail``/``grep``/``jq``).

These tools execute inside the per-session Hyperlight Wasm sandbox -- the
same sandbox ``execute_python`` uses.  All file reads go through the
guest's WASI filesystem against the ``/input`` (and, when configured,
``/output``) mounts, so:

* the agent cannot reach host files outside the mount roots,
* the same security policy that gates ``execute_python`` reads (heap
  caps, deny-by-default network, etc.) covers these tools,
* there is no "host fast path" to bypass.

The host-side wrapper is just a thin shim that:

1. Translates LLM-supplied paths (which may be in *host* coordinates -- the
   Copilot CLI parks files at ``<AGENT_INPUT_DIR>/tmp/...`` and reports
   that path back to the model) into the *guest* coordinates the WASI
   mount exposes (``/input/tmp/...``).
2. Builds a small, self-contained Python snippet that calls the file
   operation with safely-encoded parameters (no f-string injection from
   LLM input -- everything routes through ``repr()`` for guaranteed
   Python-literal output).
3. Dispatches the snippet via the existing sandbox worker thread and
   parses the JSON the snippet ``print``s to stdout.

The snippets define their helper inside a name-mangled wrapper
(``__azfn_file_tool_*``) and ``del`` it on exit so the sandbox's
``execute_python`` namespace stays clean for the LLM.
"""

from __future__ import annotations

import json
import logging
import os
import posixpath
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from .config import get_agent_input_dir, get_agent_output_dir

__all__ = [
    "PathTranslationError",
    "translate_to_guest_path",
    "build_view_snippet",
    "build_head_snippet",
    "build_tail_snippet",
    "build_grep_snippet",
    "build_jq_snippet",
    "parse_snippet_result",
]


# ---------------------------------------------------------------------------
# Path translation
# ---------------------------------------------------------------------------

# The guest sees mounted host directories at these fixed POSIX paths.
# ``sandbox.py`` configures the Hyperlight sandbox to mount
# ``AGENT_INPUT_DIR`` -> ``/input`` and ``AGENT_OUTPUT_DIR`` -> ``/output``,
# so the only filesystem locations reachable from inside the guest are
# subtrees of these two roots.
_GUEST_INPUT_ROOT = "/input"
_GUEST_OUTPUT_ROOT = "/output"


class PathTranslationError(ValueError):
    """Raised when a path cannot be translated to a guest-visible path.

    Surfaces as a JSON ``{"error": ...}`` to the LLM so it can correct
    the path on its next attempt.
    """


def _is_within(prefix: str, candidate: str) -> bool:
    """True if ``candidate`` is ``prefix`` or a descendant of it.

    Both arguments must already be normalized.  Uses an explicit
    separator check to avoid the ``/foo`` / ``/foobar`` false-positive
    that a naive ``startswith`` would have.
    """
    if candidate == prefix:
        return True
    return candidate.startswith(prefix.rstrip("/") + "/")


def translate_to_guest_path(path: str) -> str:
    """Convert a host or guest path into the guest-visible ``/input`` /
    ``/output`` form.

    Accepts:

    * **Host paths** under ``AGENT_INPUT_DIR`` -> rewritten to
      ``/input/...``  (e.g. ``/sandbox/in/tmp/foo.json`` ->
      ``/input/tmp/foo.json``).
    * **Host paths** under ``AGENT_OUTPUT_DIR`` -> rewritten to
      ``/output/...``.
    * **Already-guest paths** under ``/input`` or ``/output`` -> returned
      verbatim after normalization.

    Rejects everything else (including ``..`` escape attempts that
    normalize outside the mount roots, host paths that match neither
    mount, and obvious traversal patterns).

    Raises :class:`PathTranslationError` on any rejection.  Callers
    should surface the error to the LLM via the tool result so it can
    try a different path -- never silently substitute a default.
    """
    if not isinstance(path, str) or not path:
        raise PathTranslationError(
            "path must be a non-empty string"
        )

    # posixpath.normpath collapses ``..`` and ``.`` segments and gives
    # us a consistent forward-slash representation regardless of the
    # OS the host is running on.  We deliberately do NOT use os.path
    # here because the GUEST is always POSIX.
    #
    # We use posixpath against the input as-is; on Windows hosts the
    # backslash separator would otherwise be preserved unchanged and
    # confuse prefix matching.  Normalise to forward slashes first.
    normalized = posixpath.normpath(path.replace("\\", "/"))

    # Already-guest paths: pass through.  We still normalize to defeat
    # ``/input/../etc/passwd`` style escape attempts: after normpath,
    # such a path becomes ``/etc/passwd`` and fails the prefix check.
    if _is_within(_GUEST_INPUT_ROOT, normalized):
        return normalized
    if _is_within(_GUEST_OUTPUT_ROOT, normalized):
        return normalized

    # Host paths: rewrite under the corresponding guest mount.  The
    # host roots come from config.py so the AGENT_INPUT_DIR /
    # AGENT_OUTPUT_DIR env-var overrides are honoured.
    host_input = posixpath.normpath(get_agent_input_dir().replace("\\", "/"))
    host_output = posixpath.normpath(get_agent_output_dir().replace("\\", "/"))

    if _is_within(host_input, normalized):
        suffix = normalized[len(host_input):].lstrip("/")
        return posixpath.join(_GUEST_INPUT_ROOT, suffix) if suffix else _GUEST_INPUT_ROOT
    if _is_within(host_output, normalized):
        suffix = normalized[len(host_output):].lstrip("/")
        return posixpath.join(_GUEST_OUTPUT_ROOT, suffix) if suffix else _GUEST_OUTPUT_ROOT

    raise PathTranslationError(
        f"path {path!r} is not under any sandbox-visible mount."
        f" Expected a path under {host_input!r} ({_GUEST_INPUT_ROOT!r}"
        f" inside the sandbox) or {host_output!r}"
        f" ({_GUEST_OUTPUT_ROOT!r} inside the sandbox)."
    )


# ---------------------------------------------------------------------------
# Snippet builders
#
# Each builder returns a self-contained Python snippet that, when run in
# the sandbox via ``Sandbox.run(code)``, prints a single JSON object to
# stdout containing either the operation result or an ``{"error": ...}``
# envelope.
#
# Parameter values are inserted via ``repr()`` -- which is guaranteed to
# produce a valid Python literal for the builtin types (str/int/None/
# bool) we accept here.  This means LLM-supplied values cannot escape
# their literal context and execute arbitrary code in the sandbox.
# (The sandbox's own isolation would catch any escape anyway, but the
# defence-in-depth costs nothing.)
# ---------------------------------------------------------------------------


_GUEST_NS_PREFIX = "__azfn_file_tool_"


def _py_literal(value: Any) -> str:
    """Render ``value`` as a safe Python literal usable inside the snippet.

    Restricts to a small whitelist of types whose ``repr()`` is reliably
    a Python literal (i.e. ``eval(repr(x)) == x`` for these types).
    Lists / dicts are not supported here because none of the file tools
    need them as arguments.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return repr(value)
    raise TypeError(
        f"file_tools._py_literal: unsupported type {type(value).__name__}"
    )


def _wrap_snippet(body: str) -> str:
    """Wrap an operation body in the standard try/finally guard.

    The body executes inside the per-session sandbox namespace
    (``execute_python`` shares the same namespace) so we name-mangle
    the helper and ``del`` it on exit.  Exceptions inside the body are
    converted to a JSON error envelope so the host wrapper can surface
    a clean tool result instead of a Python traceback.
    """
    return (
        f"def {_GUEST_NS_PREFIX}op():\n"
        f"{body}\n"
        f"try:\n"
        f"    import json as {_GUEST_NS_PREFIX}json\n"
        f"    try:\n"
        f"        {_GUEST_NS_PREFIX}result = {_GUEST_NS_PREFIX}op()\n"
        f"        print({_GUEST_NS_PREFIX}json.dumps({_GUEST_NS_PREFIX}result))\n"
        f"    except Exception as {_GUEST_NS_PREFIX}exc:\n"
        f"        print({_GUEST_NS_PREFIX}json.dumps({{'error': str({_GUEST_NS_PREFIX}exc)}}))\n"
        f"finally:\n"
        f"    for {_GUEST_NS_PREFIX}name in list(globals()):\n"
        f"        if {_GUEST_NS_PREFIX}name.startswith({_py_literal(_GUEST_NS_PREFIX)}):\n"
        f"            globals().pop({_GUEST_NS_PREFIX}name, None)\n"
    )


def build_view_snippet(
    path: str,
    start_line: Optional[int],
    end_line: Optional[int],
) -> str:
    """Snippet for ``view``: return total/start/end and the line range."""
    body = (
        f"    with open({_py_literal(path)}, 'r', encoding='utf-8',"
        f" errors='replace') as f:\n"
        f"        lines = f.readlines()\n"
        f"    total = len(lines)\n"
        f"    start = max(0, ({_py_literal(start_line)} or 1) - 1)\n"
        f"    end_raw = {_py_literal(end_line)}\n"
        f"    end = total if end_raw is None else end_raw\n"
        f"    start = max(0, min(start, total))\n"
        f"    end = max(start, min(end, total))\n"
        f"    return {{\n"
        f"        'total_lines': total,\n"
        f"        'start_line': start + 1,\n"
        f"        'end_line': end,\n"
        f"        'content': ''.join(lines[start:end]),\n"
        f"    }}"
    )
    return _wrap_snippet(body)


def build_head_snippet(path: str, lines: Optional[int]) -> str:
    """Snippet for ``head``: first N lines."""
    body = (
        f"    with open({_py_literal(path)}, 'r', encoding='utf-8',"
        f" errors='replace') as f:\n"
        f"        all_lines = f.readlines()\n"
        f"    n = max(1, {_py_literal(lines)} or 10)\n"
        f"    return {{\n"
        f"        'total_lines': len(all_lines),\n"
        f"        'lines_returned': min(n, len(all_lines)),\n"
        f"        'content': ''.join(all_lines[:n]),\n"
        f"    }}"
    )
    return _wrap_snippet(body)


def build_tail_snippet(path: str, lines: Optional[int]) -> str:
    """Snippet for ``tail``: last N lines."""
    body = (
        f"    with open({_py_literal(path)}, 'r', encoding='utf-8',"
        f" errors='replace') as f:\n"
        f"        all_lines = f.readlines()\n"
        f"    n = max(1, {_py_literal(lines)} or 10)\n"
        f"    selected = all_lines[-n:] if n < len(all_lines) else all_lines\n"
        f"    return {{\n"
        f"        'total_lines': len(all_lines),\n"
        f"        'lines_returned': len(selected),\n"
        f"        'content': ''.join(selected),\n"
        f"    }}"
    )
    return _wrap_snippet(body)


def build_grep_snippet(
    path: str,
    pattern: str,
    is_regex: bool,
    ignore_case: bool,
    max_results: Optional[int],
) -> str:
    """Snippet for ``grep``: matching lines (plain text or regex)."""
    body = (
        f"    import re\n"
        f"    with open({_py_literal(path)}, 'r', encoding='utf-8',"
        f" errors='replace') as f:\n"
        f"        lines = f.readlines()\n"
        f"    pattern = {_py_literal(pattern)}\n"
        f"    is_regex = {_py_literal(is_regex)}\n"
        f"    ignore_case = {_py_literal(ignore_case)}\n"
        f"    limit = max(1, {_py_literal(max_results)} or 50)\n"
        f"    flags = re.IGNORECASE if ignore_case else 0\n"
        f"    matches = []\n"
        f"    for i, line in enumerate(lines, 1):\n"
        f"        if is_regex:\n"
        f"            try:\n"
        f"                found = re.search(pattern, line, flags)\n"
        f"            except re.error as exc:\n"
        f"                return {{'error': 'Invalid regex: ' + str(exc)}}\n"
        f"        else:\n"
        f"            if ignore_case:\n"
        f"                found = pattern.lower() in line.lower()\n"
        f"            else:\n"
        f"                found = pattern in line\n"
        f"        if found:\n"
        f"            matches.append({{'line_number': i,"
        f" 'content': line.rstrip('\\n\\r')}})\n"
        f"            if len(matches) >= limit:\n"
        f"                break\n"
        f"    return {{\n"
        f"        'total_lines': len(lines),\n"
        f"        'matches_found': len(matches),\n"
        f"        'truncated': len(matches) >= limit,\n"
        f"        'matches': matches,\n"
        f"    }}"
    )
    return _wrap_snippet(body)


def build_jq_snippet(
    path: str,
    query: str,
    max_items: Optional[int],
) -> str:
    """Snippet for ``jq``: dot-path navigation over JSON."""
    body = (
        f"    import json as _jq_json, re as _jq_re\n"
        f"    try:\n"
        f"        with open({_py_literal(path)}, 'r', encoding='utf-8') as f:\n"
        f"            data = _jq_json.load(f)\n"
        f"    except _jq_json.JSONDecodeError as exc:\n"
        f"        return {{'error': 'Invalid JSON: ' + str(exc)}}\n"
        f"    query = {_py_literal(query)}.strip().lstrip('.')\n"
        f"    current = data\n"
        f"    if query:\n"
        f"        for part in query.split('.'):\n"
        f"            if not part:\n"
        f"                continue\n"
        f"            idx_match = _jq_re.match(r'^\\[(\\d+)\\]$', part)\n"
        f"            if idx_match:\n"
        f"                idx = int(idx_match.group(1))\n"
        f"                if not isinstance(current, list) or idx >= len(current):\n"
        f"                    length = len(current) if isinstance(current, list) else 'N/A'\n"
        f"                    return {{'error': 'Index ' + str(idx) + ' out of range (length ' + str(length) + ')'}}\n"
        f"                current = current[idx]\n"
        f"            elif isinstance(current, dict) and part in current:\n"
        f"                current = current[part]\n"
        f"            elif isinstance(current, list):\n"
        f"                try:\n"
        f"                    current = current[int(part)]\n"
        f"                except (ValueError, IndexError):\n"
        f"                    return {{'error': 'Key ' + repr(part) + ' not found'}}\n"
        f"            else:\n"
        f"                available = list(current.keys()) if isinstance(current, dict) else type(current).__name__\n"
        f"                return {{'error': 'Key ' + repr(part) + ' not found. Available: ' + str(available)}}\n"
        f"    limit = max(1, {_py_literal(max_items)} or 20)\n"
        f"    truncated = False\n"
        f"    total_items = None\n"
        f"    if isinstance(current, list):\n"
        f"        if len(current) > limit:\n"
        f"            total_items = len(current)\n"
        f"            current = current[:limit]\n"
        f"            truncated = True\n"
        f"        else:\n"
        f"            total_items = len(current)\n"
        f"    result = {{'result': current}}\n"
        f"    if total_items is not None:\n"
        f"        result['total_items'] = total_items\n"
        f"    if truncated:\n"
        f"        result['truncated'] = True\n"
        f"        result['items_returned'] = limit\n"
        f"    return result"
    )
    return _wrap_snippet(body)


# ---------------------------------------------------------------------------
# Result parsing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _SnippetResult:
    """Decoded payload from a snippet's stdout JSON.

    The snippet always prints exactly one JSON object; the caller
    re-encodes it as the tool's text result.
    """

    payload: Dict[str, Any]


def parse_snippet_result(
    sandbox_result_json: str,
) -> Tuple[bool, Dict[str, Any]]:
    """Decode a sandbox ``execute_python`` JSON envelope.

    The envelope (built in :mod:`sandbox`) is shaped as::

        {"stdout": "...", "stderr": "...", "exit_code": 0}

    On success the snippet's stdout is the JSON object we want; on
    snippet failure (non-zero exit code OR captured stderr) we surface
    stderr so the LLM can see what blew up.  Returns ``(ok, payload)``.
    """
    try:
        envelope = json.loads(sandbox_result_json)
    except json.JSONDecodeError as exc:
        return False, {
            "error": (
                f"sandbox returned non-JSON result: {exc};"
                f" raw={sandbox_result_json[:200]!r}"
            )
        }

    exit_code = envelope.get("exit_code", 0)
    stdout = envelope.get("stdout", "") or ""
    stderr = envelope.get("stderr", "") or ""

    if exit_code != 0:
        return False, {
            "error": f"sandbox snippet exited with code {exit_code}",
            "stderr": stderr.strip(),
            "stdout": stdout.strip(),
        }

    # The snippet prints exactly one JSON object on the last non-empty
    # stdout line.  Take the last line to be defensive against
    # accidental extra prints (which a well-behaved snippet shouldn't
    # emit, but defence-in-depth is cheap).
    candidates = [ln for ln in stdout.strip().splitlines() if ln.strip()]
    if not candidates:
        return False, {
            "error": "sandbox snippet produced no stdout",
            "stderr": stderr.strip(),
        }

    try:
        payload = json.loads(candidates[-1])
    except json.JSONDecodeError as exc:
        return False, {
            "error": (
                f"sandbox snippet emitted non-JSON stdout: {exc};"
                f" last_line={candidates[-1][:200]!r}"
            ),
            "stderr": stderr.strip(),
        }

    return True, payload
