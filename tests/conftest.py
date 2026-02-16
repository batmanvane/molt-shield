"""Shared fixtures for the MoltKeeper test suite."""

from __future__ import annotations

from pathlib import Path

import pytest


FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    """Return the path to the test fixtures directory."""
    return FIXTURES_DIR


@pytest.fixture
def sample_xml_path(fixtures_dir: Path) -> Path:
    """Return the path to the sample XML fixture."""
    return fixtures_dir / "sample.xml"


@pytest.fixture
def sample_xml(sample_xml_path: Path) -> str:
    """Return the raw content of the sample XML fixture."""
    return sample_xml_path.read_text()


@pytest.fixture
def policy_test_path(fixtures_dir: Path) -> Path:
    """Return the path to the test policy JSON fixture."""
    return fixtures_dir / "policy_test.json"


@pytest.fixture
def tmp_vault(tmp_path: Path) -> Path:
    """Return a temporary path for vault storage during tests."""
    return tmp_path / "test_vault.json"
