"""Security tests for container/process isolation."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


class TestProcessIsolation:
    """Verify that the process runs with restricted privileges."""

    def test_process_as_non_root(self):
        """The process should not run as root (UID 0).

        In a container, this verifies the USER directive works.
        On a dev machine, this passes unless tests are run as root.
        """
        try:
            result = subprocess.run(
                ["id", "-u"],
                capture_output=True,
                text=True,
                timeout=5,
                check=True,
            )
            uid = result.stdout.strip()
            assert uid != "0", (
                f"Process is running as root (UID={uid}). "
                "The application should run as a non-root user."
            )
        except FileNotFoundError:
            pytest.skip("id command not available")

    def test_no_new_privileges(self):
        """In a container with no-new-privileges, NoNewPrivs should be set.

        This test reads /proc/self/status to check the NoNewPrivs flag.
        On non-Linux systems or outside containers, this test is skipped.
        """
        status_path = "/proc/self/status"
        if not os.path.exists(status_path):
            pytest.skip(
                "Not running on Linux or /proc not available - "
                "skipping no-new-privileges check"
            )

        status_content = Path(status_path).read_text()

        for line in status_content.splitlines():
            if line.startswith("NoNewPrivs:"):
                value = line.split(":")[1].strip()
                assert value == "1", (
                    f"NoNewPrivs should be 1 (enabled), got: {value}. "
                    "Ensure 'no-new-privileges:true' is set in Docker security_opt."
                )
                return

        pytest.skip("NoNewPrivs field not found in /proc/self/status")


class TestEnvironmentSecurity:
    """Verify environment-level security settings."""

    def test_strict_mode_env_variable(self):
        """When MOLT_STRICT is set, verify it's a valid value."""
        strict_mode = os.environ.get("MOLT_STRICT", "false")
        assert strict_mode.lower() in ("true", "false", "1", "0"), (
            f"MOLT_STRICT has invalid value: {strict_mode}"
        )

    def test_host_binding_isolation(self):
        """Verify that MOLT_HOST is bound to localhost only."""
        host = os.environ.get("MOLT_HOST", "127.0.0.1")
        assert host in ("127.0.0.1", "localhost"), (
            f"Host binding '{host}' is not isolated to localhost"
        )

    def test_no_proxy_environment(self):
        """Proxy environment variables should not be set in strict mode."""
        proxy_vars = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]
        set_proxies = [v for v in proxy_vars if os.environ.get(v)]

        assert len(set_proxies) == 0, (
            f"Proxy variables should not be set in strict mode: {set_proxies}"
        )
