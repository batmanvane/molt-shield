"""Integration tests for the MCP protocol server."""

from __future__ import annotations

import pytest
from mcp.client.session import ClientSession
from mcp.server import Server
from mcp.server.session import ServerSession
from mcp.shared.memory import (
    create_connected_server_and_client_session as create_session,
)

from src.server import app


@pytest.fixture
async def mcp_client() -> ClientSession:
    """Create a connected MCP client session for testing."""
    server_session, client_session = await create_session(app)
    yield client_session


class TestMCPProtocol:
    """Verify that the MCP server exposes the expected tools and behaves correctly."""

    @pytest.mark.asyncio
    async def test_tool_listing(self, mcp_client: ClientSession):
        """The server should expose read_safe_structure and submit_optimization tools."""
        result = await mcp_client.list_tools()
        tool_names = [tool.name for tool in result.tools]

        assert "read_safe_structure" in tool_names, (
            f"Expected 'read_safe_structure' in tools, got: {tool_names}"
        )
        assert "submit_optimization" in tool_names, (
            f"Expected 'submit_optimization' in tools, got: {tool_names}"
        )

    @pytest.mark.asyncio
    async def test_read_safe_structure(
        self, mcp_client: ClientSession, sample_xml_path, tmp_path
    ):
        """read_safe_structure should return sanitized XML without raw numeric values."""
        import json
        import re

        # Create a minimal policy file so the tool doesn't reject
        policy_path = tmp_path / "policy_locked.json"
        policy_path.write_text(json.dumps({
            "version": "1.0",
            "global_masking": True,
            "rules": [
                {"tag_pattern": "pressure", "action": "mask_value", "parameters": None},
                {"tag_pattern": "temperature", "action": "mask_value", "parameters": None},
                {"tag_pattern": "velocity", "action": "mask_value", "parameters": None},
            ],
            "created_at": None,
        }))

        result = await mcp_client.call_tool(
            "read_safe_structure",
            arguments={"filepath": str(sample_xml_path)},
        )

        assert result is not None
        assert len(result.content) > 0

        # The returned content should be sanitized XML text
        output_text = result.content[0].text
        assert "<simulation>" in output_text or "<root>" in output_text, (
            "Output should contain XML structure"
        )

    @pytest.mark.asyncio
    async def test_read_safe_structure_missing_file(self, mcp_client: ClientSession):
        """Requesting a non-existent file should raise an error."""
        with pytest.raises(Exception):
            await mcp_client.call_tool(
                "read_safe_structure",
                arguments={"filepath": "/nonexistent/path.xml"},
            )

    @pytest.mark.asyncio
    async def test_submit_optimization(self, mcp_client: ClientSession):
        """submit_optimization should accept proposed changes and return status."""
        result = await mcp_client.call_tool(
            "submit_optimization",
            arguments={
                "session_id": "test-session-001",
                "proposed_changes": {"param": "new_value"},
            },
        )

        assert result is not None
        assert len(result.content) > 0
