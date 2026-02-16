"""Tests for value masking in the gatekeeper module."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from lxml import etree

from src.config import MaskingConfig, PolicyEngineConfig, load_config
from src.gatekeeper import mask_values
from src.vault import Vault


class TestNumericMasking:
    """Verify that all numeric values are replaced with UUID placeholders."""

    @pytest.fixture
    def masking_config(self) -> MaskingConfig:
        return MaskingConfig()

    def test_numeric_masking_removes_all_digits(
        self, sample_xml: str, masking_config: MaskingConfig, tmp_vault: Path
    ):
        """After masking, no raw digits should remain in element text content."""
        vault = Vault(tmp_vault)
        result_xml = mask_values(sample_xml, masking_config, vault)

        # Parse the result and check all text nodes that held numeric data
        tree = etree.fromstring(result_xml.encode())
        numeric_tags = {"pressure", "temperature", "velocity"}
        for elem in tree.iter():
            if elem.tag in numeric_tags and elem.text:
                assert not re.search(
                    r"-?\d+\.?\d*", elem.text
                ), f"Tag <{elem.tag}> still contains unmasked numeric value: {elem.text}"

    def test_masking_replaces_with_val_placeholder(
        self, masking_config: MaskingConfig, tmp_vault: Path
    ):
        """Masked values should follow the VAL_{uuid} format."""
        xml = "<root><pressure>123.45</pressure></root>"
        vault = Vault(tmp_vault)
        result_xml = mask_values(xml, masking_config, vault)

        tree = etree.fromstring(result_xml.encode())
        pressure = tree.find("pressure")
        assert pressure is not None
        assert pressure.text.startswith("VAL_"), (
            f"Expected VAL_ placeholder, got: {pressure.text}"
        )

    def test_negative_numbers_masked(
        self, masking_config: MaskingConfig, tmp_vault: Path
    ):
        """Negative numeric values should also be masked."""
        xml = "<root><value>-42.7</value></root>"
        vault = Vault(tmp_vault)
        result_xml = mask_values(xml, masking_config, vault)

        tree = etree.fromstring(result_xml.encode())
        val = tree.find("value")
        assert val is not None
        assert not re.search(r"-?\d", val.text), (
            f"Negative value not masked: {val.text}"
        )


class TestVaultStorage:
    """Verify that original values are stored in the vault for later restoration."""

    @pytest.fixture
    def masking_config(self) -> MaskingConfig:
        return MaskingConfig()

    def test_vault_stores_original_values(
        self, masking_config: MaskingConfig, tmp_vault: Path
    ):
        """The vault must store the original numeric value for each placeholder."""
        xml = "<root><pressure>999.99</pressure></root>"
        vault = Vault(tmp_vault)
        mask_values(xml, masking_config, vault)

        # Vault should have at least one entry
        assert len(vault.entries) > 0, "Vault should contain at least one entry"

        # One of the stored original values must be "999.99"
        originals = [entry.original_value for entry in vault.entries.values()]
        assert "999.99" in originals, (
            f"Original value '999.99' not found in vault. Stored: {originals}"
        )

    def test_vault_entries_are_reversible(
        self, masking_config: MaskingConfig, tmp_vault: Path
    ):
        """Each masked placeholder should map back to its original value."""
        xml = "<root><temperature>500.0</temperature><velocity>25.5</velocity></root>"
        vault = Vault(tmp_vault)
        result_xml = mask_values(xml, masking_config, vault)

        tree = etree.fromstring(result_xml.encode())
        for elem in tree.iter():
            if elem.text and elem.text.startswith("VAL_"):
                restored = vault.restore(elem.text)
                assert restored is not None, (
                    f"Vault cannot restore placeholder: {elem.text}"
                )
                assert re.match(r"-?\d+\.?\d*", restored), (
                    f"Restored value is not numeric: {restored}"
                )


class TestPreserveAttributes:
    """Verify that specified attributes are not modified during masking."""

    @pytest.fixture
    def masking_config(self) -> MaskingConfig:
        return MaskingConfig(preserve_attributes=["id", "type"])

    def test_preserve_attributes(
        self, sample_xml: str, masking_config: MaskingConfig, tmp_vault: Path
    ):
        """Attributes listed in preserve_attributes must remain unchanged."""
        vault = Vault(tmp_vault)
        result_xml = mask_values(sample_xml, masking_config, vault)

        tree = etree.fromstring(result_xml.encode())

        # Check that id attributes on <element> tags are preserved
        elements = tree.findall(".//element")
        element_ids = {elem.get("id") for elem in elements}
        assert "e1" in element_ids, "Element id='e1' should be preserved"
        assert "e2" in element_ids, "Element id='e2' should be preserved"

        # Check that the <type> tag content is preserved
        type_elem = tree.find(".//type")
        if type_elem is not None:
            assert type_elem.text == "thermal_analysis", (
                "Metadata type should be preserved"
            )

    def test_non_preserved_attributes_can_be_masked(self, tmp_vault: Path):
        """Attributes NOT in preserve_attributes may be masked if they hold numerics."""
        config = MaskingConfig(preserve_attributes=["id"])
        xml = '<root><node id="n1"><coordinates x="10.5" y="20.3" z="30.7"/></node></root>'
        vault = Vault(tmp_vault)
        result_xml = mask_values(xml, config, vault)

        tree = etree.fromstring(result_xml.encode())
        coords = tree.find(".//coordinates")
        assert coords is not None
        # The id on <node> should be preserved
        node = tree.find(".//node")
        assert node.get("id") == "n1"
