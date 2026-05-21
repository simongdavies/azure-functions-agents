"""Developer-supplied Python tools that execute inside the sandbox.

This module is the host-side bridge between developer-authored ``.py``
files in ``<app_root>/tools/`` and the per-session Hyperlight Wasm VM
that ultimately runs them.  It does NOT execute or parse developer
content on the host.

Threat-model alignment
======================

The controlling invariant is:

    "Every byte of developer-supplied input is either (a) immutable
    text passed verbatim to the LLM as untrusted data, or (b) executed
    inside the Hyperlight Wasm VM. Never both. Never elsewhere."

A strict reading of that rule says even ``ast.parse`` on the host --
which never *executes* developer code but does run CPython C parser
code on developer bytes -- counts as "elsewhere".  The previous
revision of this file did do that; an internal review (sdavies,
2026-05-18) called it out and we rebuilt the discovery path to keep
the rule sharp.

The host's only touch points with developer bytes on this path are
now:

  * directory listing of ``<app_root>/tools/`` (file metadata only);
  * reading raw bytes off disk and UTF-8 decoding them;
  * a size cap (DoS guard before we ship bytes to the guest);
  * JSON-encoding the source map for the discovery snippet.

None of those parse Python.  All real introspection (``ast.parse``,
annotation whitelisting, signature checks) happens *inside* an
ephemeral Hyperlight VM whose stdout the host treats as untrusted
JSON.

Lifecycle
=========

1. **Enumerate (host).**  Walk ``<app_root>/tools/*.py``, apply the
   developer's ``execution_sandbox.tools`` filter, enforce the size
   cap, build a ``{module_name: source}`` dict.
2. **Discover (guest, one-shot).**  Build a discovery snippet
   containing the source map and the introspection logic, ship it to
   ``sandbox_runner`` (provided by :mod:`sandbox`).  The runner spins
   up a fresh Hyperlight VM, runs the snippet, captures stdout, and
   disposes the VM.  The host receives JSON describing each module's
   outcome (accepted with a spec, or rejected with an error string).
3. **Bootstrap (guest, per session).**  When the agent's session
   sandbox is later created in the regular per-session worker, the
   accepted files' source is shipped via :func:`Sandbox.run` once, so
   the developer's functions land in the guest's globals.
4. **Dispatch (guest, per tool call).**  Each custom-tool Copilot
   invocation builds a name-mangled dispatch snippet via
   :func:`build_dispatch_snippet` that JSON-decodes its arguments and
   calls the developer's function inside the same per-session VM.

The Copilot ``Tool`` registration (description + JSON schema) is built
on the host from the JSON the guest returned in step 2.  The schema
the LLM sees is therefore derived entirely from guest-side parsing of
developer-supplied bytes -- never from host-side parsing.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .config import get_app_root

__all__ = [
    "CustomToolParam",
    "CustomToolSpec",
    "CustomToolset",
    "SandboxRunner",
    "build_discovery_snippet",
    "build_dispatch_snippet",
    "discover_custom_tools",
    "parse_discovery_output",
]


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Well-known sub-directory under ``<app_root>`` that holds developer-
# supplied Python tool files.  Matches the legacy v0.7 convention so
# existing deployments don't have to relocate files when migrating to
# the Hyperlight host.
_CUSTOM_TOOLS_DIRNAME = "tools"

# Name-mangled namespace prefix used inside the *per-call* dispatch
# snippet (see :func:`build_dispatch_snippet`).  Every transient
# helper defined by the dispatch snippet is removed in its
# ``finally`` block so the developer's ``execute_python`` namespace
# stays clean between calls.
_PER_TOOL_CALL_NS = "__azfa_tool_call_"

# Whitelist of bare annotation names that map to a JSON schema type.
# ``Any`` / ``object`` map to ``None`` meaning "no type constraint"
# -- the parameter still appears in the schema, just without a type.
# Mirrored verbatim into the discovery snippet via JSON; both host
# and guest must see exactly the same map.
_SCHEMA_TYPE_MAP: Dict[str, Optional[str]] = {
    "str": "string",
    "int": "integer",
    "float": "number",
    "bool": "boolean",
    "list": "array",
    "List": "array",
    "tuple": "array",
    "Tuple": "array",
    "dict": "object",
    "Dict": "object",
    "Any": None,
    "object": None,
}

# Module-name validation for the explicit-list form of
# ``execution_sandbox.tools``.  Used purely for diagnostics on
# developer typos -- the real path-traversal gate is the
# file-existence check inside ``_candidate_files``.
_VALID_MODULE_NAME_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
)

# DoS guard.  Refuse to ship custom-tool source files larger than
# this cap to the discovery sandbox.  256 KiB comfortably covers any
# reasonable hand-authored tool; anything beyond is almost certainly
# either accidental (committed binary blob, generated artifact) or a
# parser-bomb.  The guest has its own heap limits but defence in
# depth is cheap.
_MAX_CUSTOM_TOOL_BYTES = 256 * 1024

# The current envelope version of the discovery snippet's output.
# Bump in lockstep with any breaking change to ``_DISCOVERY_BODY``;
# :func:`parse_discovery_output` rejects mismatched versions.
_DISCOVERY_ENVELOPE_VERSION = 1


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CustomToolParam:
    """One parameter of a developer-supplied tool function."""

    name: str
    schema: Dict[str, Any]
    required: bool


@dataclass(frozen=True)
class CustomToolSpec:
    """A single developer-supplied tool ready to be registered.

    ``parameters_schema`` is the JSON schema the Copilot SDK uses to
    advertise the tool to the LLM.  ``parameter_names`` is kept as a
    separate tuple because the dispatch handler needs the canonical
    order to build the call args dict without re-reading the schema.
    """

    name: str
    description: str
    parameters_schema: Dict[str, Any]
    source_module: str
    parameter_names: Tuple[str, ...]


@dataclass(frozen=True)
class CustomToolset:
    """Complete set of custom tools discovered for one agent.

    ``bootstrap_code`` is empty when no tools were discovered.  The
    per-session sandbox worker skips the bootstrap ``run()`` call in
    that case so agents without custom tools pay zero cost.
    """

    specs: Tuple[CustomToolSpec, ...]
    bootstrap_code: str


# Type alias for the callable that runs a discovery snippet in a
# fresh Hyperlight VM and returns the snippet's stdout.  Threading,
# lifetime, and timeout are the runner's responsibility -- this
# module is deliberately ignorant of the worker mechanics.  Tests
# pass an in-process implementation that just :func:`exec`'s the
# snippet under CPython; production passes the real Hyperlight-backed
# implementation in :mod:`sandbox`.
SandboxRunner = Callable[[str], str]


# ---------------------------------------------------------------------------
# Discovery snippet
# ---------------------------------------------------------------------------

# The introspection program that runs INSIDE THE GUEST.
#
# Only stdlib imports allowed (the WASM Python guest has a curated
# stdlib subset and no PyPI packages).  ``ast``, ``json``, and
# ``sys`` are confirmed present.
#
# Identifiers are name-mangled with the ``__azfa_d_`` prefix so the
# developer's source can't shadow this code by sheer bad luck.  We
# also use this snippet in an *ephemeral* sandbox (no developer code
# loaded), so the prefix is belt-and-braces.
#
# The snippet expects two globals to be defined before it executes:
#   __AZFA_SOURCES_JSON  -- JSON string mapping module name -> source
#   __AZFA_TYPE_MAP_JSON -- JSON string mapping annotation name -> JSON type
#
# Both are produced on the host via ``json.dumps(...)`` and embedded
# in the snippet header as Python string literals (see
# :func:`build_discovery_snippet`).
#
# Output: one ``print(json.dumps(envelope))`` line on stdout, where
# envelope is::
#
#     {
#         "version": 1,
#         "results": [
#             {"module": "foo", "accepted": True,  "spec": {...}},
#             {"module": "bar", "accepted": False, "error": "..."},
#             ...
#         ],
#     }
_DISCOVERY_BODY = r"""
import ast as __azfa_d_ast
import json as __azfa_d_json


def __azfa_d_annotation_to_schema(node, type_map):
    if node is None:
        return {}
    if isinstance(node, __azfa_d_ast.Name):
        name = node.id
        if name in type_map:
            jt = type_map[name]
            return {"type": jt} if jt is not None else {}
        return None
    if isinstance(node, __azfa_d_ast.Subscript) and isinstance(
        node.value, __azfa_d_ast.Name
    ):
        if node.value.id in ("Optional", "Union"):
            sl = node.slice
            if isinstance(sl, __azfa_d_ast.Tuple):
                inners = list(sl.elts)
            else:
                inners = [sl]
            non_none = [
                n
                for n in inners
                if not (
                    isinstance(n, __azfa_d_ast.Constant) and n.value is None
                )
            ]
            if len(non_none) == 1:
                return __azfa_d_annotation_to_schema(non_none[0], type_map)
    return None


def __azfa_d_extract_tool(source, type_map):
    try:
        tree = __azfa_d_ast.parse(source)
    except SyntaxError as exc:
        return None, "SyntaxError: " + str(exc)
    except (RecursionError, ValueError, MemoryError) as exc:
        return None, type(exc).__name__ + ": " + str(exc)

    for node in tree.body:
        if not isinstance(node, __azfa_d_ast.FunctionDef):
            continue
        if node.name.startswith("_"):
            continue
        args = node.args
        if args.vararg or args.kwarg or args.posonlyargs or args.kwonlyargs:
            return None, (
                "tool function " + repr(node.name)
                + " uses unsupported parameter kinds"
                " (*args, **kwargs, positional-only '/',"
                " or keyword-only '*')."
            )
        defaults_padded = (
            [None] * (len(args.args) - len(args.defaults))
            + list(args.defaults)
        )
        params = []
        for arg, default in zip(args.args, defaults_padded):
            schema = __azfa_d_annotation_to_schema(arg.annotation, type_map)
            if schema is None:
                try:
                    ann_src = (
                        __azfa_d_ast.unparse(arg.annotation)
                        if arg.annotation else "<missing>"
                    )
                except Exception:
                    ann_src = "<unparse-failed>"
                return None, (
                    "parameter " + repr(arg.arg)
                    + " has unsupported annotation " + repr(ann_src)
                    + ". Allowed: str, int, float, bool, list, dict, tuple,"
                    " Any, object, and Optional[...] thereof."
                )
            params.append(
                {
                    "name": arg.arg,
                    "schema": schema,
                    "required": default is None,
                }
            )
        docstring = __azfa_d_ast.get_docstring(node) or ("Tool: " + node.name)
        properties = {p["name"]: p["schema"] for p in params}
        required = [p["name"] for p in params if p["required"]]
        return (
            {
                "name": node.name,
                "description": docstring,
                "parameters_schema": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                    "additionalProperties": False,
                },
                "parameter_names": [p["name"] for p in params],
            },
            None,
        )
    return None, "no eligible top-level non-underscore function found"


def __azfa_d_discover_all():
    sources = __azfa_d_json.loads(__AZFA_SOURCES_JSON)
    type_map = __azfa_d_json.loads(__AZFA_TYPE_MAP_JSON)
    results = []
    for module_name in sorted(sources.keys()):
        source = sources[module_name]
        spec, err = __azfa_d_extract_tool(source, type_map)
        if spec is None:
            results.append(
                {"module": module_name, "accepted": False, "error": err}
            )
        else:
            results.append(
                {"module": module_name, "accepted": True, "spec": spec}
            )
    print(
        __azfa_d_json.dumps({"version": 1, "results": results})
    )


__azfa_d_discover_all()
"""


def build_discovery_snippet(source_map: Dict[str, str]) -> str:
    """Build the introspection program for one batch of source files.

    The snippet contains:

    1. Two JSON string literals at the top: the developer source map
       and the schema-type map.  Both are host-generated, so embedding
       them as Python string literals is safe (no developer content
       reaches the Python parser as code).
    2. The static :data:`_DISCOVERY_BODY` introspection logic.

    The returned string is ready to feed into :class:`SandboxRunner`.
    """
    sources_json = json.dumps(source_map, ensure_ascii=False)
    type_map_json = json.dumps(_SCHEMA_TYPE_MAP)
    return (
        f"__AZFA_SOURCES_JSON = {sources_json!r}\n"
        f"__AZFA_TYPE_MAP_JSON = {type_map_json!r}\n"
        + _DISCOVERY_BODY
    )


def parse_discovery_output(stdout: str) -> Dict[str, Dict[str, Any]]:
    """Parse the JSON envelope the discovery snippet printed.

    Returns a dict keyed by module name with entries shaped::

        {"accepted": True,  "spec":  {... spec dict ...}}
        {"accepted": False, "error": "human-readable reason"}

    Raises :class:`ValueError` when the envelope is malformed (caller
    treats this as a fatal discovery failure and registers no
    custom tools, rather than half-loading the toolset).
    """
    try:
        envelope = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"discovery output was not valid JSON: {exc}"
        ) from exc
    if not isinstance(envelope, dict):
        raise ValueError("discovery envelope must be a JSON object")
    version = envelope.get("version")
    if version != _DISCOVERY_ENVELOPE_VERSION:
        raise ValueError(
            f"unexpected discovery envelope version: {version!r}"
            f" (expected {_DISCOVERY_ENVELOPE_VERSION})"
        )
    results = envelope.get("results")
    if not isinstance(results, list):
        raise ValueError("discovery envelope missing 'results' list")
    by_module: Dict[str, Dict[str, Any]] = {}
    for entry in results:
        if not isinstance(entry, dict):
            continue
        name = entry.get("module")
        if not isinstance(name, str):
            continue
        by_module[name] = entry
    return by_module


# ---------------------------------------------------------------------------
# File-system enumeration (no parsing)
# ---------------------------------------------------------------------------


def _is_valid_module_name(name: str) -> bool:
    """Return True if ``name`` looks like a bare Python identifier.

    Conservative: ASCII letters/digits/underscore only, first character
    must not be a digit.  This is a diagnostic gate -- the actual
    path-traversal defence is the file-existence check that follows.
    """
    if not name:
        return False
    if name[0].isdigit():
        return False
    return all(ch in _VALID_MODULE_NAME_CHARS for ch in name)


def _candidate_files(
    tools_dir: Path,
    explicit_modules: Optional[List[str]],
) -> List[Path]:
    """Resolve the set of tool files to attempt loading.

    Semantics, matched to the legacy v0.7 host-side loader so existing
    deployments don't have to change behaviour:

    * ``explicit_modules is None`` -- auto-discover every ``*.py``
      whose name doesn't start with ``_``.
    * ``explicit_modules == []`` -- developer opted out; no files.
    * ``explicit_modules`` is a non-empty list -- resolve each entry
      as a bare module name against ``<tools_dir>/<name>.py``.
      Invalid names and missing files are skipped with a warning.
    """
    if explicit_modules is None:
        return sorted(
            path
            for path in tools_dir.glob("*.py")
            if not path.name.startswith("_")
        )

    if not explicit_modules:
        return []

    resolved: List[Path] = []
    for module_name in explicit_modules:
        if not isinstance(module_name, str) or not _is_valid_module_name(
            module_name
        ):
            logging.warning(
                "custom_tools: rejecting tool module %r"
                " (must be a bare Python identifier)",
                module_name,
            )
            continue
        candidate = tools_dir / f"{module_name}.py"
        if not candidate.is_file():
            logging.warning(
                "custom_tools: rejecting tool module %r"
                " (file %s not found)",
                module_name,
                candidate,
            )
            continue
        resolved.append(candidate)
    return resolved


def _read_source_or_skip(path: Path) -> Optional[str]:
    """Read one tool file, returning ``None`` if it should be skipped.

    Skips and logs a warning if the file is unreadable, exceeds the
    size cap, or isn't valid UTF-8.  Returns the decoded source on
    success.
    """
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        logging.warning("custom_tools: cannot read %s: %s", path, exc)
        return None
    if len(raw_bytes) > _MAX_CUSTOM_TOOL_BYTES:
        logging.warning(
            "custom_tools: skipping %s: file is %d bytes which"
            " exceeds the discovery size cap of %d bytes."
            " Split very large tool files or raise"
            " _MAX_CUSTOM_TOOL_BYTES if you can justify the cost.",
            path,
            len(raw_bytes),
            _MAX_CUSTOM_TOOL_BYTES,
        )
        return None
    try:
        return raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        logging.warning(
            "custom_tools: skipping %s: not valid UTF-8 (%s)",
            path,
            exc,
        )
        return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def discover_custom_tools(
    explicit_modules: Optional[List[str]] = None,
    *,
    sandbox_runner: SandboxRunner,
) -> CustomToolset:
    """Discover custom tools by parsing INSIDE the Hyperlight sandbox.

    The host walks the file system and reads bytes; ``sandbox_runner``
    spins up an ephemeral Hyperlight VM, runs the introspection
    snippet, and returns its stdout.  The host then converts the
    JSON envelope into :class:`CustomToolSpec` instances and builds
    the bootstrap string that the per-session sandbox worker will
    later run to load the developer's functions into the guest.

    Args:
        explicit_modules: ``None`` -> auto-discover all ``tools/*.py``;
            ``[]`` -> opt-out; list -> only those bare module names.
        sandbox_runner: Required.  Production callers pass
            :func:`sandbox.run_discovery_in_sandbox`; tests pass an
            in-process fake that ``exec``'s the snippet under CPython.
            Keyword-only to make the dependency injection explicit at
            every call site.

    Returns:
        :class:`CustomToolset` with the accepted specs and the
        concatenated bootstrap source.  Returns an empty toolset
        (``specs=()``, ``bootstrap_code=""``) when:

        * the ``tools/`` directory does not exist,
        * the developer opted out,
        * every candidate file failed validation,
        * the sandbox runner raised, or
        * the discovery snippet's output was malformed.

        The all-or-nothing failure mode is deliberate: a malformed
        discovery should not silently load a partial toolset.
    """
    tools_dir = get_app_root() / _CUSTOM_TOOLS_DIRNAME
    if not tools_dir.is_dir():
        return CustomToolset(specs=(), bootstrap_code="")

    candidates = _candidate_files(tools_dir, explicit_modules)
    if not candidates:
        return CustomToolset(specs=(), bootstrap_code="")

    sources: Dict[str, str] = {}
    sources_by_path: Dict[str, Path] = {}
    for path in candidates:
        source = _read_source_or_skip(path)
        if source is None:
            continue
        # candidate files are unique by filename so collisions can't
        # happen here, but guard anyway in case the resolver ever
        # changes.
        if path.stem in sources:
            continue
        sources[path.stem] = source
        sources_by_path[path.stem] = path

    if not sources:
        return CustomToolset(specs=(), bootstrap_code="")

    snippet = build_discovery_snippet(sources)

    try:
        stdout = sandbox_runner(snippet)
    except Exception as exc:
        logging.error(
            "custom_tools: discovery sandbox failed (%s);"
            " no custom tools will be available for this agent."
            " Underlying error: %s",
            type(exc).__name__,
            exc,
        )
        return CustomToolset(specs=(), bootstrap_code="")

    try:
        results = parse_discovery_output(stdout)
    except ValueError as exc:
        logging.error(
            "custom_tools: discovery output unparseable (%s);"
            " no custom tools will be available for this agent.",
            exc,
        )
        return CustomToolset(specs=(), bootstrap_code="")

    specs: List[CustomToolSpec] = []
    bootstrap_parts: List[str] = []
    seen_names: set[str] = set()
    for module_name in sorted(sources.keys()):
        entry = results.get(module_name)
        if entry is None:
            logging.warning(
                "custom_tools: discovery returned no entry for %s",
                module_name,
            )
            continue
        if not entry.get("accepted"):
            logging.warning(
                "custom_tools: skipping %s: %s",
                module_name,
                entry.get("error"),
            )
            continue

        spec_dict = entry.get("spec")
        if not isinstance(spec_dict, dict):
            logging.warning(
                "custom_tools: skipping %s: invalid spec payload",
                module_name,
            )
            continue
        try:
            spec = CustomToolSpec(
                name=spec_dict["name"],
                description=spec_dict["description"],
                parameters_schema=spec_dict["parameters_schema"],
                source_module=module_name,
                parameter_names=tuple(spec_dict["parameter_names"]),
            )
        except (KeyError, TypeError) as exc:
            logging.warning(
                "custom_tools: skipping %s: malformed spec (%s)",
                module_name,
                exc,
            )
            continue

        if spec.name in seen_names:
            logging.warning(
                "custom_tools: tool name %r from %s collides with a"
                " previously loaded tool; skipping.",
                spec.name,
                sources_by_path[module_name],
            )
            continue
        seen_names.add(spec.name)

        bootstrap_parts.append(f"# --- custom tool: {module_name} ---")
        bootstrap_parts.append(sources[module_name])
        specs.append(spec)
        logging.info(
            "custom_tools: loaded %s from %s (params=%s, required=%s)",
            spec.name,
            sources_by_path[module_name],
            list(spec.parameter_names),
            spec.parameters_schema.get("required", []),
        )

    if not specs:
        return CustomToolset(specs=(), bootstrap_code="")
    bootstrap_code = "\n".join(bootstrap_parts) + "\n"
    return CustomToolset(specs=tuple(specs), bootstrap_code=bootstrap_code)


# ---------------------------------------------------------------------------
# Dispatch snippet (unchanged from v0.8.0 design)
# ---------------------------------------------------------------------------


def build_dispatch_snippet(spec: CustomToolSpec, args: Dict[str, Any]) -> str:
    """Build the snippet that invokes ``spec`` inside the guest.

    The args dict is JSON-encoded on the host and re-parsed inside the
    guest via :func:`json.loads`, so there is no path for an
    LLM-supplied string to escape its literal context and inject
    code.  The function's return value is JSON-encoded with
    ``default=str`` so non-JSON-native return types (``datetime``,
    ``Path``, ``Decimal``, custom classes with a sensible ``__str__``)
    degrade to a string rather than crashing the dispatch.

    The snippet defines a name-mangled wrapper function, runs it, and
    cleans up the wrapper plus its helper names in the ``finally``
    block -- the same hygiene the file-tool snippets in
    :mod:`file_tools` use, so the developer's ``execute_python``
    namespace is never polluted.
    """
    args_json = json.dumps(args)
    loop_var = f"{_PER_TOOL_CALL_NS}name"
    return (
        f"def {_PER_TOOL_CALL_NS}call():\n"
        f"    import json as {_PER_TOOL_CALL_NS}json\n"
        f"    {_PER_TOOL_CALL_NS}args = {_PER_TOOL_CALL_NS}json.loads"
        f"({args_json!r})\n"
        f"    {_PER_TOOL_CALL_NS}result = {spec.name}"
        f"(**{_PER_TOOL_CALL_NS}args)\n"
        f"    print({_PER_TOOL_CALL_NS}json.dumps("
        f"{{'result': {_PER_TOOL_CALL_NS}result}}, default=str))\n"
        f"try:\n"
        f"    {_PER_TOOL_CALL_NS}call()\n"
        f"except Exception as {_PER_TOOL_CALL_NS}exc:\n"
        f"    import json as {_PER_TOOL_CALL_NS}json2\n"
        f"    print({_PER_TOOL_CALL_NS}json2.dumps({{'error':"
        f" type({_PER_TOOL_CALL_NS}exc).__name__ + ': '"
        f" + str({_PER_TOOL_CALL_NS}exc)}}))\n"
        f"finally:\n"
        f"    for {loop_var} in list(globals()):\n"
        f"        if {loop_var}.startswith({_PER_TOOL_CALL_NS!r}):\n"
        f"            globals().pop({loop_var}, None)\n"
        # Python re-binds the loop variable on each iteration after
        # the pop, so it survives the loop body's cleanup attempt.
        # Drop it explicitly here -- otherwise the developer's
        # subsequent ``execute_python`` calls would see a stray
        # ``__azfa_tool_call_name`` in their globals.
        f"    globals().pop({loop_var!r}, None)\n"
    )
