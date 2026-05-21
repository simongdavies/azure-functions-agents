import logging
import os
import posixpath
import re
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Application root resolution
# ---------------------------------------------------------------------------

_app_root: Optional[Path] = None


def set_app_root(path: Path) -> None:
    """Explicitly set the application root directory.

    Call this early (e.g. before ``create_function_app()``) so that all
    agent, tool, skill, and MCP discovery uses the correct base path.
    """
    global _app_root
    _app_root = Path(path).resolve()


def get_app_root() -> Path:
    """Return the root directory of the user's agent project.

    This is the directory containing ``main.agent.md``, ``tools/``,
    ``.vscode/mcp.json``, skills directories, etc.

    Resolution order:

    1. Value set via ``set_app_root()``
    2. ``COPILOT_APP_ROOT`` environment variable
    3. ``AzureWebJobsScriptRoot`` environment variable (set automatically
       by the Azure Functions host, both locally via ``func start`` and
       in Azure — points to the directory containing ``host.json``)
    4. Current working directory (``Path.cwd()``)
    """
    if _app_root is not None:
        return _app_root
    explicit = os.environ.get("COPILOT_APP_ROOT")
    if explicit:
        return Path(explicit).resolve()
    script_root = os.environ.get("AzureWebJobsScriptRoot")
    if script_root:
        return Path(script_root).resolve()
    return Path.cwd().resolve()

# Default session state directory used by the Copilot CLI
_DEFAULT_CONFIG_DIR = os.path.expanduser("~/.copilot")
_REMOTE_CONFIG_DIR = "/code-assistant-session"


def resolve_config_dir() -> Optional[str]:
    """
    Resolve the config directory for session state persistence.

    Priority:
    1. CODE_ASSISTANT_CONFIG_PATH env var (explicit override)
    2. CONTAINER_NAME env var is set → /code-assistant-session (remote/Azure Functions mode)
    3. Neither set → None (SDK default ~/.copilot/ is used)
    """
    explicit_path = os.environ.get("CODE_ASSISTANT_CONFIG_PATH")
    if explicit_path:
        logging.info(f"Using CODE_ASSISTANT_CONFIG_PATH: {explicit_path}")
        return explicit_path

    container_name = os.environ.get("CONTAINER_NAME")
    if container_name:
        logging.info(f"Remote mode detected (CONTAINER_NAME={container_name}), using {_REMOTE_CONFIG_DIR}")
        return _REMOTE_CONFIG_DIR

    return None


def session_exists(config_dir: Optional[str], session_id: str) -> bool:
    """
    Check if a session exists on disk by looking for its directory.

    Session state is stored under {config_dir}/session-state/{sessionId}/.
    Falls back to ~/.copilot/session-state/{sessionId}/ if config_dir is None.
    """
    base = config_dir if config_dir else _DEFAULT_CONFIG_DIR
    session_path = os.path.join(base, "session-state", session_id)
    exists = os.path.isdir(session_path)
    logging.info(f"Session '{session_id}' exists at {session_path}: {exists}")
    return exists


# ---------------------------------------------------------------------------
# Sandbox host-side directory resolution
# ---------------------------------------------------------------------------
#
# The Hyperlight Wasm guest always exposes ``/input`` (read-only) and
# ``/output`` (read-write) at fixed paths.  The corresponding *host-side*
# directories — what the function-app process and the Copilot CLI
# subprocess see — are configurable via env vars so the library is not
# locked to one container layout:
#
#   AGENT_INPUT_DIR  (default: /sandbox/in)  → bind-mount target for /input
#   AGENT_OUTPUT_DIR (default: /sandbox/out) → bind-mount target for /output
#
# The CLI temp directory is always derived as ``<input_dir>/tmp`` so the
# parked tool outputs land on the same bind-mount the sandbox guest sees
# at ``/input/tmp/<file>`` — one file on disk, one reader (the sandbox),
# zero copies.  All file IO from inside an agent (execute_python plus the
# view / head / tail / grep / jq tools) crosses the sandbox boundary via
# WASI; the host directories are bind-mount targets only.
# ---------------------------------------------------------------------------

_DEFAULT_AGENT_INPUT_DIR = "/sandbox/in"
_DEFAULT_AGENT_OUTPUT_DIR = "/sandbox/out"


def get_agent_input_dir() -> str:
    """Return the host-side directory bound into the sandbox as ``/input``.

    Configurable via the ``AGENT_INPUT_DIR`` env var; defaults to
    ``/sandbox/in`` (matches the basic-chat container layout).

    Returned as a POSIX-style path with forward slashes — the value is
    consumed by Linux processes (the Hyperlight sandbox, the Copilot
    CLI's Node.js runtime running inside a Linux container), so we must
    not let ``os.path`` rewrite it with Windows separators on dev boxes.
    """
    return os.environ.get("AGENT_INPUT_DIR", _DEFAULT_AGENT_INPUT_DIR)


def get_agent_output_dir() -> str:
    """Return the host-side directory bound into the sandbox as ``/output``.

    Configurable via the ``AGENT_OUTPUT_DIR`` env var; defaults to
    ``/sandbox/out`` (matches the basic-chat container layout).

    See :func:`get_agent_input_dir` for why this stays POSIX-style.
    """
    return os.environ.get("AGENT_OUTPUT_DIR", _DEFAULT_AGENT_OUTPUT_DIR)


def get_agent_input_tmp_dir() -> str:
    """Return ``<input_dir>/tmp`` -- where the Copilot CLI parks large outputs.

    The Hyperlight guest reads these files via the ``/input`` WASI mount
    at ``/input/tmp/<file>``; the host process only sees them via this
    bind-mount target.  Always derived from :func:`get_agent_input_dir`
    so the two cannot drift out of sync.  Uses :mod:`posixpath` so the
    result stays forward-slash on every dev OS.
    """
    return posixpath.join(get_agent_input_dir(), "tmp")


def check_agent_dirs_at_startup() -> None:
    """Log warnings if the configured host-side dirs are missing at startup.

    Only fires when ``CONTAINER_NAME`` is set — i.e. we know we are
    running in a container deployment where the bind mounts are *expected*
    to exist.  In dev mode the missing dirs are normal and we stay silent
    (the lazy per-component checks in ``client_manager.py`` and
    ``sandbox.py`` will degrade gracefully).
    """
    if not os.environ.get("CONTAINER_NAME"):
        return
    input_dir = get_agent_input_dir()
    output_dir = get_agent_output_dir()
    tmp_dir = get_agent_input_tmp_dir()
    if not os.path.isdir(input_dir):
        logging.warning(
            "AGENT_INPUT_DIR=%s does not exist. The Copilot CLI's"
            " temp-redirect and the sandbox /input mount will both be"
            " unavailable. Create the directory (or bind-mount real"
            " content) before starting the app.",
            input_dir,
        )
    elif not os.path.isdir(tmp_dir):
        logging.warning(
            "AGENT_INPUT_DIR=%s exists but %s does not. The Copilot CLI"
            " will fall back to the system temp dir, and large tool"
            " outputs will not be visible to the sandbox at"
            " /input/tmp/.",
            input_dir,
            tmp_dir,
        )
    if not os.path.isdir(output_dir):
        logging.warning(
            "AGENT_OUTPUT_DIR=%s does not exist. The sandbox /output"
            " mount will be unavailable to agents that request"
            " filesystem: read_write.",
            output_dir,
        )


# ---------------------------------------------------------------------------
# Developer env-var allow-list
# ---------------------------------------------------------------------------
#
# Developer-supplied content (agent.md frontmatter and body text)
# may reference environment variables via ``$VAR`` / ``%VAR%``
# substitution.  Under the framework's threat model the developer is
# adversarial: a developer who can ask the host to dereference
# ``$AZUREWEBJOBSSTORAGE``, ``$IDENTITY_HEADER``, ``$GITHUB_TOKEN``
# etc. can exfiltrate framework / platform secrets via the rendered
# prompt that ships to the LLM.
#
# Mitigation: dereferencing is gated on a **build-time-baked name
# prefix**.  Only env vars whose name starts with the prefix are
# dereferenceable from developer content; every other name passes
# through verbatim (the ``$X`` reference is preserved unchanged).
# Framework code that legitimately needs to read its own env vars
# does so directly via ``os.environ.get(…)`` and is not affected
# by this gate.
#
# Silent fail-closed: we deliberately do NOT raise on a rejected
# name.  A loud failure would let the developer probe the allow-list
# via error messages and timing; literal-passthrough is the same
# observable behaviour as "env var unset", so the developer cannot
# distinguish "forbidden" from "unbound" — exactly the
# information-hiding we want.
#
# This constant is duplicated in
# ``azure_functions_agents.credentials.__init__`` (which enforces the
# same rule for ``source: env:VAR`` credential references) and MUST
# be kept in sync; both sites are independently loaded in isolation
# by the test infrastructure, so they cannot share a module without
# breaking that.
# ---------------------------------------------------------------------------

_AGENT_ENV_PREFIX = "AGENT_"


def _is_agent_env_var(name: str) -> bool:
    """Return ``True`` if ``name`` is dereferenceable from developer content.

    Only names with the :data:`_AGENT_ENV_PREFIX` prefix are
    accessible via :func:`resolve_env_var` and
    :func:`substitute_env_vars_in_text`.  See the section comment
    above for the threat-model rationale.
    """
    return name.startswith(_AGENT_ENV_PREFIX)


# ---------------------------------------------------------------------------
# Environment variable substitution for agent frontmatter values
# ---------------------------------------------------------------------------

_PERCENT_PATTERN = re.compile(r"^%([^%]+)%$")
_DOLLAR_PATTERN = re.compile(r"^\$([A-Za-z_][A-Za-z0-9_]*)$")


def resolve_env_var(value: str) -> str:
    """Resolve a frontmatter value that is a single env-var reference.

    Supported syntaxes (full-string match only — partial substitution
    such as ``prefix$VAR`` is intentionally **not** supported):

      - ``%VAR_NAME%`` — value is entirely ``%…%``
      - ``$VAR_NAME``  — value is entirely ``$IDENT``

    Allow-list gate: only env vars whose name starts with
    :data:`_AGENT_ENV_PREFIX` are dereferenceable.  Non-prefixed
    names are silently rejected (the original ``$X`` / ``%X%`` text
    is returned unchanged) — see the section comment above for the
    threat-model rationale.

    If the value does not match either pattern, or the referenced
    environment variable is not set, the original string is returned
    unchanged.

    The following agent frontmatter fields are resolved through
    this function (all represent external resource identifiers or
    endpoints):

      - ``trigger.*`` (all string values except ``type``)
      - ``tools_from_connections[].connection_id``
      - ``execution_sandbox.allowed_domains[].url``

    Fields that should **not** use substitution (identifiers, literals,
    or user-facing text): ``name``, ``description``, ``trigger.type``,
    ``logger``.
    """
    stripped = value.strip()
    m = _PERCENT_PATTERN.match(stripped) or _DOLLAR_PATTERN.match(stripped)
    if m:
        name = m.group(1)
        if not _is_agent_env_var(name):
            return value
        return os.environ.get(name, value)
    return value


# ---------------------------------------------------------------------------
# Boolean coercion helper
# ---------------------------------------------------------------------------


def _to_bool(value: Any, default: bool = True) -> bool:
    """Coerce a frontmatter value to bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "y"}:
            return True
        if lowered in {"false", "0", "no", "n"}:
            return False
    return default


# ---------------------------------------------------------------------------
# Inline environment variable substitution for agent markdown body text
# ---------------------------------------------------------------------------

_INLINE_DOLLAR_PATTERN = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")
_INLINE_PERCENT_PATTERN = re.compile(r"%([A-Za-z_][A-Za-z0-9_]*)%")


def substitute_env_vars_in_text(text: str) -> str:
    """Perform inline environment variable substitution in free-form text.

    Unlike :func:`resolve_env_var` (which requires the *entire* string to
    be a single variable reference), this function replaces variable
    references **inline** within arbitrary text.

    Supported syntaxes:

      - ``$VAR_NAME``  — e.g. ``send mail to $AGENT_TO_EMAIL``
      - ``%VAR_NAME%`` — e.g. ``post to the %AGENT_TEAM_NAME% team``

    Allow-list gate: only env vars whose name starts with
    :data:`_AGENT_ENV_PREFIX` are dereferenceable.  Non-prefixed
    names are silently rejected (the original ``$X`` / ``%X%`` text
    passes through verbatim) — see the section comment near
    :data:`_AGENT_ENV_PREFIX` for the threat-model rationale.

    If a referenced (and allow-listed) environment variable is not
    set, the original reference is left unchanged.

    Text inside fenced code blocks (``````...``````) is left untouched
    so that documentation examples are not accidentally altered.
    """

    def _dollar_replacer(m: re.Match) -> str:
        name = m.group(1)
        if not _is_agent_env_var(name):
            return m.group(0)
        return os.environ.get(name, m.group(0))

    def _percent_replacer(m: re.Match) -> str:
        name = m.group(1)
        if not _is_agent_env_var(name):
            return m.group(0)
        return os.environ.get(name, m.group(0))

    def _substitute(segment: str) -> str:
        segment = _INLINE_DOLLAR_PATTERN.sub(_dollar_replacer, segment)
        segment = _INLINE_PERCENT_PATTERN.sub(_percent_replacer, segment)
        return segment

    # Split on fenced code blocks (```); odd-indexed parts are code blocks
    parts = text.split("```")
    for i in range(0, len(parts), 2):
        parts[i] = _substitute(parts[i])
    return "```".join(parts)
