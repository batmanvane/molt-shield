"""Command-line interface for MoltKeeper."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="moltkeeper",
        description="MoltKeeper - Zero-Trust Engineering Gateway for XML anonymization",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- scan command ---
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan an XML file and generate an anonymization policy",
    )
    scan_parser.add_argument("xml_file", type=Path, help="Path to the XML file to scan")
    scan_parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("policy_locked.json"),
        help="Output path for the generated policy (default: policy_locked.json)",
    )
    scan_parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/default.yaml"),
        help="Path to config.yaml (default: config/default.yaml)",
    )

    # --- serve command ---
    serve_parser = subparsers.add_parser(
        "serve",
        help="Start the MCP server",
    )
    serve_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Server bind address (default: 127.0.0.1)",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=3000,
        help="Server port (default: 3000)",
    )
    serve_parser.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help="Enable strict security mode",
    )
    serve_parser.add_argument(
        "--policy",
        type=Path,
        default=Path("policy_locked.json"),
        help="Path to policy file (default: policy_locked.json)",
    )
    serve_parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/default.yaml"),
        help="Path to config.yaml (default: config/default.yaml)",
    )

    # --- rehydrate command ---
    rehydrate_parser = subparsers.add_parser(
        "rehydrate",
        help="Restore original values from a vault file",
    )
    rehydrate_parser.add_argument(
        "input",
        type=Path,
        help="File to rehydrate (JSON, XML, or text with VAL_xxx placeholders)",
    )
    rehydrate_parser.add_argument(
        "--vault",
        "-v",
        type=Path,
        default=Path("vault/session.vault.json"),
        help="Path to vault file (default: vault/session.vault.json)",
    )
    rehydrate_parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Output file (default: print to stdout)",
    )
    rehydrate_parser.add_argument(
        "--in-place",
        "-i",
        action="store_true",
        help="Modify file in-place (backup created with .bak extension)",
    )

    return parser


def cmd_scan(args: argparse.Namespace) -> None:
    """Execute the *scan* sub-command."""
    from src.config import load_config
    from src.policy_engine import generate_policy, save_policy

    if not args.xml_file.exists():
        print(f"Error: XML file not found: {args.xml_file}", file=sys.stderr)
        sys.exit(1)

    _config = load_config(args.config)
    policy = generate_policy(args.xml_file)
    out = save_policy(policy, args.output)
    print(f"Policy generated: {out}")
    print(f"  Rules detected: {len(policy.rules)}")
    for rule in policy.rules:
        print(f"    - {rule.tag_pattern}: {rule.action}")


def cmd_serve(args: argparse.Namespace) -> None:
    """Execute the *serve* sub-command."""
    if not args.policy.exists():
        print(f"Error: Policy file not found: {args.policy}", file=sys.stderr)
        print("Run 'moltkeeper scan <file.xml>' first to generate a policy.", file=sys.stderr)
        sys.exit(1)

    print(f"Starting MCP server on {args.host}:{args.port}")
    print(f"  Policy: {args.policy}")
    print(f"  Strict mode: {args.strict}")

    # Deferred import so the module loads quickly even if mcp is missing.
    import asyncio
    from src.server import main as server_main

    asyncio.run(server_main())


def cmd_rehydrate(args: argparse.Namespace) -> None:
    """Execute the *rehydrate* sub-command."""
    from src.vault import Vault

    input_path = Path(args.input)
    vault_path = Path(args.vault)

    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    if not vault_path.exists():
        print(f"Error: Vault file not found: {vault_path}", file=sys.stderr)
        print("Run 'moltkeeper scan' first to create a vault.", file=sys.stderr)
        sys.exit(1)

    # Load vault
    vault = Vault(vault_path)
    vault.load()
    print(f"Loaded vault with {len(vault)} entries")

    # Read input
    content = input_path.read_text(encoding="utf-8")

    # Determine file type and rehydrate
    if input_path.suffix == ".json":
        data = json.loads(content)
        restored = vault.rehydrate_dict(data)
        output_content = json.dumps(restored, indent=2)
    else:
        # XML or plain text
        output_content = vault.rehydrate_xml(content)

    # Output
    if args.in_place:
        # Create backup
        backup_path = input_path.with_suffix(input_path.suffix + ".bak")
        input_path.rename(backup_path)
        print(f"Backup created: {backup_path}")
        # Write restored content
        input_path.write_text(output_content, encoding="utf-8")
        print(f"Restored: {input_path}")
    elif args.output:
        output_path = Path(args.output)
        output_path.write_text(output_content, encoding="utf-8")
        print(f"Restored output written to: {output_path}")
    else:
        print("\n--- Restored Content ---")
        print(output_content)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "scan": cmd_scan,
        "serve": cmd_serve,
        "rehydrate": cmd_rehydrate,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
