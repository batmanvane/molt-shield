"""Integration tests to verify no proprietary data leaks through the gateway."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from lxml import etree

from src.config import PolicyEngineConfig
from src.gatekeeper import apply_gatekeeper
from src.policy_engine import Policy


# Proprietary tag names that must never appear in sanitized output
PROPRIETARY_TAGS = {"pressure", "temperature", "velocity", "coordinates"}

# The original numeric values from sample.xml
ORIGINAL_NUMERIC_VALUES = [
    "123.45", "500.0", "25.5",    # element e1
    "678.90", "600.0", "30.2",    # element e2
    "10.5", "20.3", "30.7",       # node n1 coordinates
]


class TestNoNumericLeakage:
    """Verify that no original numeric values survive the gatekeeper pipeline."""

    @pytest.fixture
    def config(self) -> PolicyEngineConfig:
        return PolicyEngineConfig()

    def test_no_numeric_values_in_output(
        self, sample_xml_path: Path, policy_test_path: Path, config: PolicyEngineConfig
    ):
        """The sanitized output must not contain any of the original numeric values."""
        policy = Policy.load(policy_test_path)
        sanitized_xml, _vault_path = apply_gatekeeper(
            sample_xml_path, policy, config
        )

        output_text = sanitized_xml.read_text() if isinstance(sanitized_xml, Path) else sanitized_xml

        for value in ORIGINAL_NUMERIC_VALUES:
            assert value not in output_text, (
                f"Original numeric value '{value}' leaked into sanitized output"
            )

    def test_no_floating_point_patterns_in_text_nodes(
        self, sample_xml_path: Path, policy_test_path: Path, config: PolicyEngineConfig
    ):
        """Text content of elements should not contain raw floating-point patterns."""
        policy = Policy.load(policy_test_path)
        sanitized_xml, _vault_path = apply_gatekeeper(
            sample_xml_path, policy, config
        )

        output_text = sanitized_xml.read_text() if isinstance(sanitized_xml, Path) else sanitized_xml
        tree = etree.fromstring(output_text.encode())

        for elem in tree.iter():
            if elem.text and elem.text.strip():
                # Allow VAL_ placeholders and non-numeric content
                text = elem.text.strip()
                if text.startswith("VAL_"):
                    continue
                # Check this isn't a raw number
                if re.fullmatch(r"-?\d+\.?\d*([eE][+-]?\d+)?", text):
                    pytest.fail(
                        f"Tag <{elem.tag}> contains raw numeric text: {text}"
                    )


class TestNoProprietaryTagsExposed:
    """Verify that proprietary/sensitive tag names are shadowed or removed."""

    @pytest.fixture
    def config(self) -> PolicyEngineConfig:
        return PolicyEngineConfig()

    def test_no_proprietary_tags_exposed(
        self, sample_xml_path: Path, policy_test_path: Path, config: PolicyEngineConfig
    ):
        """Proprietary tag names like 'pressure', 'temperature' should be shadowed."""
        policy = Policy.load(policy_test_path)
        sanitized_xml, _vault_path = apply_gatekeeper(
            sample_xml_path, policy, config
        )

        output_text = sanitized_xml.read_text() if isinstance(sanitized_xml, Path) else sanitized_xml
        tree = etree.fromstring(output_text.encode())

        exposed_tags = set()
        for elem in tree.iter():
            if elem.tag in PROPRIETARY_TAGS:
                exposed_tags.add(elem.tag)

        assert len(exposed_tags) == 0, (
            f"Proprietary tags leaked into output: {exposed_tags}"
        )

    def test_shadowed_tags_are_present(
        self, sample_xml_path: Path, policy_test_path: Path, config: PolicyEngineConfig
    ):
        """The output should contain shadowed versions of proprietary tags."""
        policy = Policy.load(policy_test_path)
        sanitized_xml, _vault_path = apply_gatekeeper(
            sample_xml_path, policy, config
        )

        output_text = sanitized_xml.read_text() if isinstance(sanitized_xml, Path) else sanitized_xml
        tree = etree.fromstring(output_text.encode())

        all_tags = {elem.tag for elem in tree.iter()}

        # There should be some tags in output (the shadowed versions)
        assert len(all_tags) > 1, (
            "Output XML should contain structural elements"
        )

        # None of the output tags should be proprietary
        assert all_tags.isdisjoint(PROPRIETARY_TAGS), (
            f"Found proprietary tags in output: {all_tags & PROPRIETARY_TAGS}"
        )
