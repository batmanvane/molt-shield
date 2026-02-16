"""
Container Security Utilities
Zero-Trust verification functions for Molt-Shield.

Provides functions to verify that the runtime environment meets
the security requirements defined in the master plan:
- Network isolation (localhost-only binding)
- Filesystem permissions (read-only input, writable output)
- Process security (non-root, no privilege escalation)
"""

import logging
import os
import socket
import subprocess
from pathlib import Path

logger = logging.getLogger("molt-shield.security")


# ---------------------------------------------------------------------------
# Network isolation
# ---------------------------------------------------------------------------


def verify_network_isolation() -> list[str]:
    """Verify that the server environment enforces network isolation.

    Checks:
    - MOLT_HOST is bound to 127.0.0.1, localhost, or ::1
    - No HTTP/HTTPS proxy environment variables are set
    - No unexpected outbound connectivity (best-effort)

    Returns a list of issues found (empty means all checks passed).
    """
    issues: list[str] = []

    host = os.environ.get("MOLT_HOST", "127.0.0.1")
    allowed_hosts = {"127.0.0.1", "localhost", "::1"}
    if host not in allowed_hosts:
        issues.append(
            f"MOLT_HOST is '{host}', expected one of {sorted(allowed_hosts)}. "
            "Server must bind to localhost only."
        )

    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        value = os.environ.get(var)
        if value:
            issues.append(
                f"Proxy variable {var} is set. "
                "Proxies are not allowed in strict mode."
            )

    # Best-effort check: try to detect if we can reach an external host
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(("8.8.8.8", 53))
        sock.close()
        issues.append(
            "Outbound network connectivity detected (could reach 8.8.8.8:53). "
            "Container should have no external network access."
        )
    except (OSError, socket.timeout):
        pass  # Expected — no outbound connectivity

    return issues


# ---------------------------------------------------------------------------
# Filesystem permissions
# ---------------------------------------------------------------------------


def _is_readonly(path: Path) -> bool:
    """Check if a path is read-only by attempting a write test."""
    if not path.exists():
        return False
    try:
        test_file = path / ".molt_write_test"
        test_file.write_text("test")
        test_file.unlink()
        return False  # Writable — not read-only
    except (PermissionError, OSError):
        return True


def _is_writable(path: Path) -> bool:
    """Check if a path is writable."""
    if not path.exists():
        return False
    try:
        test_file = path / ".molt_write_test"
        test_file.write_text("test")
        test_file.unlink()
        return True
    except (PermissionError, OSError):
        return False


def verify_filesystem_permissions() -> list[str]:
    """Verify filesystem mount permissions match security requirements.

    Checks:
    - Input directory exists and is not writable
    - Output directory exists and is writable
    - Vault directory exists and is writable
    - Application source is not writable (in strict mode)

    Returns a list of issues found (empty means all checks passed).
    """
    issues: list[str] = []

    input_dir = Path(os.environ.get("MOLT_INPUT_DIR", "./data/input"))
    output_dir = Path(os.environ.get("MOLT_OUTPUT_DIR", "./data/output"))
    vault_dir = Path(os.environ.get("MOLT_VAULT_DIR", "./vault"))

    # Check input directory is read-only
    if input_dir.exists():
        if not _is_readonly(input_dir):
            issues.append(
                f"Input directory '{input_dir}' is writable. "
                "It should be mounted read-only."
            )
    else:
        issues.append(f"Input directory '{input_dir}' does not exist.")

    # Check output directory is writable
    if output_dir.exists():
        if not _is_writable(output_dir):
            issues.append(
                f"Output directory '{output_dir}' is not writable. "
                "It must be writable for sanitized output."
            )
    else:
        issues.append(f"Output directory '{output_dir}' does not exist.")

    # Check vault directory is writable
    if vault_dir.exists():
        if not _is_writable(vault_dir):
            issues.append(
                f"Vault directory '{vault_dir}' is not writable. "
                "It must be writable for session vaults."
            )
    else:
        issues.append(f"Vault directory '{vault_dir}' does not exist.")

    # Check that src/ is not writable in strict mode
    if os.environ.get("MOLT_STRICT", "false").lower() == "true":
        src_dir = Path(__file__).parent
        if not _is_readonly(src_dir):
            issues.append(
                f"Source directory '{src_dir}' is writable in strict mode. "
                "Application code should be mounted read-only."
            )

    return issues


# ---------------------------------------------------------------------------
# Process security
# ---------------------------------------------------------------------------


def verify_process_security() -> list[str]:
    """Verify process-level security constraints.

    Checks:
    - Process is not running as root (UID != 0)
    - no-new-privileges flag is set (Linux containers)
    - No dangerous capabilities

    Returns a list of issues found (empty means all checks passed).
    """
    issues: list[str] = []

    # Check non-root execution
    uid = os.getuid()
    if uid == 0:
        issues.append(
            f"Process is running as root (UID={uid}). "
            "Container must run as non-root user."
        )

    # Check no-new-privileges (Linux-specific)
    status_path = Path("/proc/self/status")
    if status_path.exists():
        try:
            status_content = status_path.read_text()
            for line in status_content.splitlines():
                if line.startswith("NoNewPrivs:"):
                    value = line.split(":")[1].strip()
                    if value != "1":
                        issues.append(
                            "NoNewPrivs is not set. "
                            "Container should use 'no-new-privileges:true'."
                        )
                    break
            else:
                logger.debug("NoNewPrivs field not found in /proc/self/status")
        except OSError:
            logger.debug("Could not read /proc/self/status")

    # Check for dangerous capabilities (Linux-specific)
    capsh_path = Path("/usr/sbin/capsh")
    if capsh_path.exists():
        try:
            result = subprocess.run(
                [str(capsh_path), "--print"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            dangerous_caps = {
                "cap_sys_admin",
                "cap_net_admin",
                "cap_sys_ptrace",
                "cap_dac_override",
            }
            current_line = ""
            for line in result.stdout.splitlines():
                if line.startswith("Current:"):
                    current_line = line.lower()
                    break
            for cap in dangerous_caps:
                if cap in current_line:
                    issues.append(
                        f"Dangerous capability detected: {cap}. "
                        "Container should drop all unnecessary capabilities."
                    )
        except (subprocess.TimeoutExpired, OSError):
            logger.debug("Could not check capabilities via capsh")

    # Check for proxy env vars (also a process-level concern)
    proxy_vars = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]
    active_proxies = [v for v in proxy_vars if os.environ.get(v)]
    if active_proxies:
        issues.append(
            f"Proxy environment variables set: {', '.join(active_proxies)}. "
            "Not allowed in strict mode."
        )

    return issues


# ---------------------------------------------------------------------------
# Aggregate check
# ---------------------------------------------------------------------------


def run_security_checks() -> tuple[bool, list[str]]:
    """Run all security verification checks.

    Returns:
        Tuple of (passed: bool, issues: list[str]).
        passed is True when no issues are found.
    """
    all_issues: list[str] = []

    logger.info("Running network isolation checks...")
    all_issues.extend(verify_network_isolation())

    logger.info("Running filesystem permission checks...")
    all_issues.extend(verify_filesystem_permissions())

    logger.info("Running process security checks...")
    all_issues.extend(verify_process_security())

    if all_issues:
        logger.warning("Security verification found %d issue(s)", len(all_issues))
    else:
        logger.info("All security checks passed")

    return len(all_issues) == 0, all_issues


# ---------------------------------------------------------------------------
# Status report (non-strict, informational)
# ---------------------------------------------------------------------------


def get_security_status() -> dict:
    """Get comprehensive security status report.

    Returns a dictionary summarizing the current security posture.
    Useful for the get_vault_info tool or diagnostics.
    """
    passed, issues = run_security_checks()
    return {
        "strict_mode": os.environ.get("MOLT_STRICT", "false").lower() == "true",
        "host_binding": os.environ.get("MOLT_HOST", "127.0.0.1"),
        "all_checks_passed": passed,
        "issues": issues,
        "process": {
            "uid": os.getuid(),
            "is_root": os.getuid() == 0,
        },
    }
