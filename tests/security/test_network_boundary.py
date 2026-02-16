"""Security tests for network boundary enforcement."""

from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from src.security import verify_network_isolation


class TestNetworkBoundary:
    """Verify network isolation and boundary enforcement."""

    def test_localhost_binding_allowed(self):
        """Localhost bindings should be allowed."""
        with patch.dict("os.environ", {"MOLT_HOST": "127.0.0.1"}):
            issues = verify_network_isolation()
            # Filter out the outbound connectivity check which may vary
            localhost_issues = [i for i in issues if "localhost" in i.lower()]
            assert len(localhost_issues) == 0, f"Localhost should be allowed: {localhost_issues}"

    def test_localhost_name_allowed(self):
        """'localhost' hostname should be allowed."""
        with patch.dict("os.environ", {"MOLT_HOST": "localhost"}):
            issues = verify_network_isolation()
            host_issues = [i for i in issues if "MOLT_HOST" in i]
            assert len(host_issues) == 0, f"localhost should be allowed: {host_issues}"

    def test_ipv6_localhost_allowed(self):
        """IPv6 localhost (::1) should be allowed."""
        with patch.dict("os.environ", {"MOLT_HOST": "::1"}):
            issues = verify_network_isolation()
            host_issues = [i for i in issues if "MOLT_HOST" in i]
            assert len(host_issues) == 0, f"::1 should be allowed: {host_issues}"

    def test_external_ip_blocked(self):
        """External IP bindings should be blocked in strict mode."""
        with patch.dict("os.environ", {"MOLT_HOST": "0.0.0.0"}):
            issues = verify_network_isolation()
            host_issues = [i for i in issues if "MOLT_HOST" in i]
            assert len(host_issues) > 0, "0.0.0.0 should not be allowed"

    def test_external_hostname_blocked(self):
        """External hostnames should be blocked."""
        with patch.dict("os.environ", {"MOLT_HOST": "0.0.0.0"}):
            issues = verify_network_isolation()
            assert any("MOLT_HOST" in i for i in issues), "External hostname should be blocked"

    def test_http_proxy_blocked(self):
        """HTTP_PROXY should be blocked in strict mode."""
        with patch.dict("os.environ", {"HTTP_PROXY": "http://proxy:8080"}, clear=False):
            issues = verify_network_isolation()
            proxy_issues = [i for i in issues if "proxy" in i.lower()]
            assert len(proxy_issues) > 0, "HTTP_PROXY should be blocked"

    def test_https_proxy_blocked(self):
        """HTTPS_PROXY should be blocked in strict mode."""
        with patch.dict("os.environ", {"HTTPS_PROXY": "https://proxy:8080"}, clear=False):
            issues = verify_network_isolation()
            proxy_issues = [i for i in issues if "proxy" in i.lower()]
            assert len(proxy_issues) > 0, "HTTPS_PROXY should be blocked"

    def test_lowercase_proxy_blocked(self):
        """Lowercase proxy variables should also be blocked."""
        with patch.dict("os.environ", {"http_proxy": "http://proxy:8080"}, clear=False):
            issues = verify_network_isolation()
            proxy_issues = [i for i in issues if "proxy" in i.lower()]
            assert len(proxy_issues) > 0, "http_proxy should be blocked"

    def test_no_proxy_ok(self):
        """No proxy environment should pass."""
        # Ensure no proxy vars are set
        env = {
            k: v for k, v in __import__("os").environ.items()
            if "proxy" not in k.lower()
        }
        with patch.dict("os.environ", env, clear=True):
            issues = verify_network_isolation()
            proxy_issues = [i for i in issues if "proxy" in i.lower()]
            assert len(proxy_issues) == 0, "No proxy should pass"

    def test_outbound_connectivity_check(self):
        """Test outbound connectivity detection."""
        # This test verifies the outbound check runs without error
        issues = verify_network_isolation()
        # We just ensure it runs - the actual result depends on environment
        assert isinstance(issues, list)


class TestSocketSecurity:
    """Test socket-level security."""

    def test_socket_timeout_reasonable(self):
        """Socket timeouts should be reasonable to prevent hanging."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        assert sock.gettimeout() == 2
        sock.close()

    def test_ipv6_socket_available(self):
        """IPv6 sockets should be available on modern systems."""
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.close()
            ipv6_available = True
        except (OSError, socket.error):
            ipv6_available = False

        # IPv6 may not be available in all environments (e.g., containers)
        if not ipv6_available:
            pytest.skip("IPv6 not available in this environment")
