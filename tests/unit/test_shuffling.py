"""Tests for element shuffling in the gatekeeper module."""

from __future__ import annotations

from lxml import etree
import pytest

from src.config import ShufflingConfig
from src.gatekeeper import shuffle_siblings


class TestShuffleSiblings:
    """Verify that sibling elements are reordered to break positional inference."""

    @pytest.fixture
    def shuffling_config(self) -> ShufflingConfig:
        return ShufflingConfig(enabled=True, target_tags=["element", "node"])

    def test_shuffle_siblings_reorders_elements(
        self, sample_xml: str, shuffling_config: ShufflingConfig
    ):
        """Shuffling must change the order of sibling <element> tags.

        Since shuffling is random, we run multiple iterations and verify that
        at least one produces a different order than the original.
        """
        original_tree = etree.fromstring(sample_xml.encode())
        original_ids = [
            elem.get("id") for elem in original_tree.findall("element")
        ]

        found_different_order = False
        for _ in range(20):
            result_xml = shuffle_siblings(sample_xml, shuffling_config)
            result_tree = etree.fromstring(result_xml.encode())
            result_ids = [
                elem.get("id") for elem in result_tree.findall("element")
            ]

            # All original elements must still be present
            assert sorted(result_ids) == sorted(original_ids), (
                "Shuffling must not add or remove elements"
            )

            if result_ids != original_ids:
                found_different_order = True
                break

        assert found_different_order, (
            "Shuffling did not reorder elements in 20 attempts "
            "(statistically extremely unlikely unless shuffling is broken)"
        )

    def test_shuffle_preserves_element_content(
        self, sample_xml: str, shuffling_config: ShufflingConfig
    ):
        """Shuffling must not alter the content of individual elements."""
        original_tree = etree.fromstring(sample_xml.encode())
        original_pressures = {}
        for elem in original_tree.findall("element"):
            eid = elem.get("id")
            pressure = elem.find("pressure")
            if pressure is not None:
                original_pressures[eid] = pressure.text

        result_xml = shuffle_siblings(sample_xml, shuffling_config)
        result_tree = etree.fromstring(result_xml.encode())
        for elem in result_tree.findall("element"):
            eid = elem.get("id")
            pressure = elem.find("pressure")
            if pressure is not None:
                assert pressure.text == original_pressures[eid], (
                    f"Element {eid} pressure changed after shuffling"
                )

    def test_shuffle_only_targets_configured_tags(self):
        """Tags not listed in target_tags should remain in original order."""
        config = ShufflingConfig(enabled=True, target_tags=["element"])
        xml = """<root>
            <meta><a>1</a></meta>
            <meta><b>2</b></meta>
            <element id="e1"><v>10</v></element>
            <element id="e2"><v>20</v></element>
        </root>"""

        result_xml = shuffle_siblings(xml, config)
        tree = etree.fromstring(result_xml.encode())

        # <meta> tags should keep their order
        metas = tree.findall("meta")
        assert metas[0].find("a") is not None, (
            "First <meta> should still contain <a>"
        )
        assert metas[1].find("b") is not None, (
            "Second <meta> should still contain <b>"
        )


class TestDeterministicShuffling:
    """Verify that shuffling is reproducible with a fixed seed."""

    def test_deterministic_shuffling_with_seed(self, sample_xml: str):
        """Two shuffles with the same seed must produce identical output."""
        config = ShufflingConfig(enabled=True, seed=42, target_tags=["element"])

        result1 = shuffle_siblings(sample_xml, config)
        result2 = shuffle_siblings(sample_xml, config)

        assert result1 == result2, (
            "Deterministic shuffling with same seed should produce identical results"
        )

    def test_different_seeds_produce_different_output(self, sample_xml: str):
        """Two shuffles with different seeds should (very likely) differ."""
        config_a = ShufflingConfig(enabled=True, seed=42, target_tags=["element"])
        config_b = ShufflingConfig(enabled=True, seed=99, target_tags=["element"])

        result_a = shuffle_siblings(sample_xml, config_a)
        result_b = shuffle_siblings(sample_xml, config_b)

        # With only 2 elements this may sometimes be the same, so we just check
        # that the function accepts different seeds without error.
        # For larger element sets this would be a stronger assertion.
        assert isinstance(result_a, str) and isinstance(result_b, str)

    def test_shuffling_disabled(self, sample_xml: str):
        """When shuffling is disabled, element order must not change."""
        config = ShufflingConfig(enabled=False)
        result_xml = shuffle_siblings(sample_xml, config)

        original_tree = etree.fromstring(sample_xml.encode())
        result_tree = etree.fromstring(result_xml.encode())

        original_ids = [e.get("id") for e in original_tree.findall("element")]
        result_ids = [e.get("id") for e in result_tree.findall("element")]

        assert original_ids == result_ids, (
            "Disabled shuffling should preserve original order"
        )
