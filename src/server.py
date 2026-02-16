"""
Molt-Shield MCP Server
Zero-Trust Engineering Gateway for secure XML processing.

Exposes tools for reading sanitized XML structures, submitting optimizations,
listing policies, and querying vault status via the Model Context Protocol.
"""

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

logger = logging.getLogger("molt-shield")

# ---------------------------------------------------------------------------
# Server instance
# ---------------------------------------------------------------------------

app = Server("molt-shield")

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------

DATA_INPUT_DIR = Path(os.environ.get("MOLT_INPUT_DIR", "./data/input"))
DATA_OUTPUT_DIR = Path(os.environ.get("MOLT_OUTPUT_DIR", "./data/output"))
VAULT_DIR = Path(os.environ.get("MOLT_VAULT_DIR", "./vault"))
POLICY_DIR = Path(os.environ.get("MOLT_POLICY_DIR", "./config"))
HOST = os.environ.get("MOLT_HOST", "127.0.0.1")
PORT = int(os.environ.get("MOLT_PORT", "3000"))
STRICT_MODE = os.environ.get("MOLT_STRICT", "false").lower() == "true"

# ---------------------------------------------------------------------------
# Path security helpers
# ---------------------------------------------------------------------------


def _resolve_input_path(filepath: str) -> Path:
    """Resolve and validate an input file path within the allowed input directory."""
    path = Path(filepath)
    if not path.is_absolute():
        path = DATA_INPUT_DIR / path

    resolved = path.resolve()
    input_resolved = DATA_INPUT_DIR.resolve()

    if not str(resolved).startswith(str(input_resolved)):
        raise ValueError(
            f"Access denied: path '{filepath}' is outside the input directory"
        )
    if not resolved.exists():
        raise ValueError(f"File not found: {filepath}")
    return resolved


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available MCP tools."""
    return [
        Tool(
            name="read_safe_structure",
            description=(
                "Read and sanitize an XML file for AI analysis. "
                "Applies masking, shuffling, and tag shadowing per the active policy. "
                "Returns the sanitized XML content with all proprietary values replaced."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": (
                            "Path to the XML file "
                            "(relative to input directory or absolute)"
                        ),
                    },
                    "policy": {
                        "type": "string",
                        "description": "Path to policy file (default: policy_locked.json)",
                        "default": "policy_locked.json",
                    },
                },
                "required": ["filepath"],
            },
        ),
        Tool(
            name="submit_optimization",
            description=(
                "Submit optimization suggestions from AI analysis. "
                "The suggestions reference masked/anonymized values which will be "
                "rehydrated using the session vault before applying."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Session identifier from the read operation",
                    },
                    "proposed_changes": {
                        "type": "object",
                        "description": "Dictionary of proposed parameter changes (masked keys/values)",
                    },
                },
                "required": ["session_id", "proposed_changes"],
            },
        ),
        Tool(
            name="list_policies",
            description="List all available policy files and their status.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="get_vault_info",
            description=(
                "Show vault status including active sessions, entry counts, "
                "and storage location. Does NOT reveal original values."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Optional session ID to inspect a specific vault",
                    }
                },
            },
        ),
    ]


# ---------------------------------------------------------------------------
# Tool dispatcher
# ---------------------------------------------------------------------------


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Dispatch tool calls to the appropriate handler."""
    handlers = {
        "read_safe_structure": _handle_read_safe_structure,
        "submit_optimization": _handle_submit_optimization,
        "list_policies": _handle_list_policies,
        "get_vault_info": _handle_get_vault_info,
    }
    handler = handlers.get(name)
    if handler is None:
        raise ValueError(f"Unknown tool: {name}")
    return await handler(arguments)


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


async def _handle_read_safe_structure(
    arguments: dict[str, Any],
) -> list[TextContent]:
    """Read an XML file, apply policy-based sanitization, return safe content."""
    filepath = arguments.get("filepath")
    policy_path_str = arguments.get("policy", "policy_locked.json")

    if not filepath:
        raise ValueError("Missing required argument: filepath")

    input_path = _resolve_input_path(filepath)

    policy_file = Path(policy_path_str)
    if not policy_file.is_absolute():
        policy_file = POLICY_DIR / policy_file
    if not policy_file.exists():
        raise RuntimeError(
            f"No active policy found at {policy_file}. "
            "Run the screener first: python -m src.cli scan <input.xml>"
        )

    # Lazy-import to avoid circular imports and allow independent testing
    from .gatekeeper import apply_gatekeeper
    from .policy_engine import load_policy
    from .config import load_config

    policy = load_policy(policy_file)
    config = load_config()

    sanitized_path, vault_path = await asyncio.to_thread(
        apply_gatekeeper, input_path, policy, config
    )

    sanitized_content = sanitized_path.read_text(encoding="utf-8")

    logger.info(
        "Sanitized %s -> %s (vault: %s)",
        input_path.name,
        sanitized_path.name,
        vault_path.name,
    )

    return [TextContent(type="text", text=sanitized_content)]


async def _handle_submit_optimization(
    arguments: dict[str, Any],
) -> list[TextContent]:
    """Receive optimization suggestions and queue them for rehydration."""
    session_id = arguments.get("session_id")
    proposed_changes = arguments.get("proposed_changes")

    if not session_id:
        raise ValueError("Missing required argument: session_id")
    if not proposed_changes:
        raise ValueError("Missing required argument: proposed_changes")

    # Persist the proposed changes to the output directory
    DATA_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path = DATA_OUTPUT_DIR / f"{session_id}_optimization.json"

    payload = {
        "session_id": session_id,
        "proposed_changes": proposed_changes,
    }
    with open(output_path, "w") as f:
        json.dump(payload, f, indent=2)

    result = {
        "status": "pending",
        "session_id": session_id,
        "changes_count": len(proposed_changes),
        "output_path": str(output_path),
        "message": "Optimization submitted for review. Use the CLI to rehydrate.",
    }

    logger.info(
        "Optimization submitted for session %s (%d changes) -> %s",
        session_id,
        len(proposed_changes),
        output_path,
    )

    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def _handle_list_policies(
    arguments: dict[str, Any],
) -> list[TextContent]:
    """List available policy files and their metadata."""
    policy_dir = POLICY_DIR.resolve()
    if not policy_dir.exists():
        return [
            TextContent(
                type="text",
                text="No policy directory found. Run the screener to generate a policy.",
            )
        ]

    policies: list[dict[str, Any]] = []
    for p in sorted(policy_dir.glob("*.json")):
        try:
            with open(p) as f:
                data = json.load(f)
            policies.append({
                "name": p.name,
                "path": str(p),
                "version": data.get("version", "unknown"),
                "rules_count": len(data.get("rules", [])),
                "active": p.name == "policy_locked.json",
            })
        except (json.JSONDecodeError, OSError) as exc:
            policies.append({
                "name": p.name,
                "path": str(p),
                "error": str(exc),
            })

    if not policies:
        return [
            TextContent(
                type="text",
                text="No policies found. Run the screener to generate a policy.",
            )
        ]

    return [TextContent(type="text", text=json.dumps(policies, indent=2))]


async def _handle_get_vault_info(
    arguments: dict[str, Any],
) -> list[TextContent]:
    """Return vault metadata without exposing original values."""
    session_id = arguments.get("session_id")

    vault_dir = VAULT_DIR.resolve()
    if not vault_dir.exists():
        return [TextContent(type="text", text="Vault directory does not exist.")]

    # Single-session query
    if session_id:
        vault_path = vault_dir / f"{session_id}.vault.json"
        if not vault_path.exists():
            return [
                TextContent(
                    type="text",
                    text=f"No vault found for session '{session_id}'.",
                )
            ]
        with open(vault_path) as f:
            data = json.load(f)
        info = {
            "session_id": session_id,
            "entry_count": len(data) if isinstance(data, dict) else 0,
            "vault_path": str(vault_path),
            "size_bytes": vault_path.stat().st_size,
        }
        return [TextContent(type="text", text=json.dumps(info, indent=2))]

    # List all vault sessions
    vaults: list[dict[str, Any]] = []
    for vf in sorted(vault_dir.glob("*.vault.json")):
        try:
            with open(vf) as f:
                data = json.load(f)
            vaults.append({
                "name": vf.stem.replace(".vault", ""),
                "entry_count": len(data) if isinstance(data, dict) else 0,
                "size_bytes": vf.stat().st_size,
            })
        except (json.JSONDecodeError, OSError):
            vaults.append({"name": vf.stem, "error": "unreadable"})

    info = {
        "vault_directory": str(vault_dir),
        "session_count": len(vaults),
        "sessions": vaults,
    }

    return [TextContent(type="text", text=json.dumps(info, indent=2))]


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


async def main() -> None:
    """Run the Molt-Shield MCP server over stdio."""
    from .security import run_security_checks

    logging.basicConfig(
        level=logging.INFO,
        format="[%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    logger.info("Molt-Shield MCP Server starting (strict=%s)", STRICT_MODE)

    # Run security verification in strict mode
    if STRICT_MODE:
        passed, issues = run_security_checks()
        if not passed:
            for issue in issues:
                logger.warning("Security check failed: %s", issue)
            logger.error(
                "Strict mode enabled but %d security check(s) failed. Aborting.",
                len(issues),
            )
            sys.exit(1)
        logger.info("All security checks passed")

    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
