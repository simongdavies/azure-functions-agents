import json
import logging
import os
from typing import Any, Dict, Optional

# The Copilot SDK renamed these types between versions:
#   <= 0.2.x: MCPLocalServerConfig, MCPRemoteServerConfig
#   >= 0.3.0: MCPStdioServerConfig,  MCPHTTPServerConfig
# Support both so the package works with either SDK version.
try:
    from copilot.session import MCPLocalServerConfig, MCPRemoteServerConfig, MCPServerConfig
except ImportError:
    from copilot.session import MCPStdioServerConfig as MCPLocalServerConfig  # type: ignore[no-redef]
    from copilot.session import MCPHTTPServerConfig as MCPRemoteServerConfig  # type: ignore[no-redef]
    from copilot.session import MCPServerConfig

from .config import get_app_root
from .mcp_validation import ALLOWED_REMOTE_TYPES, reject_local_stdio_mcp

_MCP_SERVERS_CACHE: Optional[Dict[str, MCPServerConfig]] = None


def _parse_mcp_server_config(server: Dict[str, Any]) -> Optional[MCPServerConfig]:
    """Parse one ``mcp.json`` server entry, rejecting local stdio variants.

    The security gate (which rejects local / stdio configs) lives in
    :mod:`.mcp_validation` so it can be unit-tested without loading
    the Copilot SDK.  See that module's docstring for the threat-model
    rationale.

    Raises :class:`ValueError` on local / stdio configs.  Returns
    ``None`` for entries that are recognisably remote but missing
    the ``url`` field (legacy behaviour preserved so a single
    broken entry doesn't kill startup -- the next entry still
    loads).
    """
    reject_local_stdio_mcp(server)

    server_type = str(server.get("type", "")).lower()
    if "url" in server or server_type in ALLOWED_REMOTE_TYPES:
        remote_type = (
            server_type if server_type in ALLOWED_REMOTE_TYPES else "http"
        )
        remote_config: MCPRemoteServerConfig = {
            "type": remote_type,  # type: ignore
            "url": str(server.get("url", "")),
            "headers": server.get("headers"),
            "tools": server.get("tools", ["*"]),
        }
        if not remote_config["url"]:
            return None
        return remote_config

    return None


def _load_mcp_servers_from_file() -> Dict[str, MCPServerConfig]:
    app_root = str(get_app_root())
    candidates = [
        os.path.join(app_root, ".vscode", "mcp.json"),
        os.path.join(app_root, "mcp.json"),
    ]

    for path in candidates:
        if not os.path.exists(path):
            continue

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logging.warning(f"Failed to read MCP config from {path}: {e}")
            continue

        servers = data.get("servers", {})
        if not isinstance(servers, dict):
            logging.warning(f"Invalid MCP config in {path}: 'servers' must be an object")
            return {}

        parsed_servers: Dict[str, MCPServerConfig] = {}
        for name, config in servers.items():
            if not isinstance(name, str) or not isinstance(config, dict):
                continue
            parsed = _parse_mcp_server_config(config)
            if parsed is not None:
                parsed_servers[name] = parsed

        if parsed_servers:
            logging.info(f"Loaded {len(parsed_servers)} MCP server(s) from {path}")
        else:
            logging.info(f"No valid MCP servers found in {path}")
        return parsed_servers

    return {}


def get_cached_mcp_servers() -> Dict[str, MCPServerConfig]:
    global _MCP_SERVERS_CACHE
    if _MCP_SERVERS_CACHE is None:
        _MCP_SERVERS_CACHE = _load_mcp_servers_from_file()
    return _MCP_SERVERS_CACHE
