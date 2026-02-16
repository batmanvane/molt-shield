"""Security tests to verify comprehensive data masking."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from lxml import etree

from src.config import MaskingConfig, PolicyEngineConfig
from src.gatekeeper import apply_gatekeeper, mask_values
from src.policy_engine import Policy
from src.vault import Vault


# All original numeric values from sample.xml
ORIGINAL_NUMERIC_VALUES = [
    "123.45", "500.0", "25.5",    # element e1
    "678.90", "600.0", "30.2",    # element e2
    "10.5", "20.3", "30.7",       # node n1 coordinates
]


class TestDataMaskingSecurity:
    """End-to-end security verification that masking is thorough."""

    @pytest.fixture
    def config(self) -> PolicyEngineConfig:
        return PolicyEngineConfig()

    @pytest.fixture
    def masking_config(self) -> MaskingConfig:
        return MaskingConfig()

    def test_masking_removes_all_sensitive_data(
        self,
        sample_xml: str,
        masking_config: MaskingConfig,
        tmp_vault: Path,
    ):
        """After masking, no original numeric values from the input should remain.

        This test extracts ALL numeric values from the original XML, masks the
        document, and then verifies none of the original values appear in the
        output.
        """
        # Step 1: Extract all original numeric values
        original_tree = etree.fromstring(sample_xml.encode())
        original_values: set[str] = set()

        for elem in original_tree.iter():
            if elem.text and re.match(r"-?\d+\.?\d*$", elem.text.strip()):
                original_values.add(elem.text.strip())
            for attr_val in elem.attrib.values():
                if re.match(r"-?\d+\.?\d*$", attr_val.strip()):
                    original_values.add(attr_val.strip())

        assert len(original_values) > 0, "Test fixture should contain numeric values"

        # Step 2: Mask the document
        vault = Vault(tmp_vault)
        masked_xml = mask_values(sample_xml, masking_config, vault)

        # Step 3: Verify no original values leaked
        leaked = [v for v in original_values if v in masked_xml]
        assert len(leaked) == 0, (
            f"Original numeric values leaked through masking: {leaked}"
        )

    def test_full_pipeline_removes_all_sensitive_data(
        self,
        sample_xml_path: Path,
        policy_test_path: Path,
        config: PolicyEngineConfig,
    ):
        """The full gatekeeper pipeline must remove all numeric values."""
        policy = Policy.load(policy_test_path)
        sanitized_xml, _vault_path = apply_gatekeeper(
            sample_xml_path, policy, config
        )

        output_text = (
            sanitized_xml.read_text()
            if isinstance(sanitized_xml, Path)
            else sanitized_xml
        )

        for value in ORIGINAL_NUMERIC_VALUES:
            assert value not in output_text, (
                f"Original numeric value '{value}' leaked into sanitized output"
            )

    def test_vault_stores_all_originals(
        self,
        sample_xml_path: Path,
        policy_test_path: Path,
        config: PolicyEngineConfig,
    ):
        """The vault must store all original values for restoration."""
        policy = Policy.load(policy_test_path)
        _sanitized_xml, vault_path = apply_gatekeeper(
            sample_xml_path, policy, config
        )

        assert vault_path.exists(), "Vault file should be created"

        vault_data = json.loads(vault_path.read_text())
        assert len(vault_data) > 0, "Vault should contain entries"

    def test_masking_produces_valid_xml(
        self,
        sample_xml: str,
        masking_config: MaskingConfig,
        tmp_vault: Path,
    ):
        """Masked output must still be well-formed XML."""
        vault = Vault(tmp_vault)
        masked_xml = mask_values(sample_xml, masking_config, vault)

        try:
            etree.fromstring(masked_xml.encode())
        except etree.XMLSyntaxError as e:
            pytest.fail(f"Masked output is not valid XML: {e}")

    def test_no_attribute_leakage(
        self,
        sample_xml_path: Path,
        policy_test_path: Path,
        config: PolicyEngineConfig,
    ):
        """Attributes containing sensitive numeric data must be masked."""
        policy = Policy.load(policy_test_path)
        sanitized_xml, _vault_path = apply_gatekeeper(
            sample_xml_path, policy, config
        )

        output_text = (
            sanitized_xml.read_text()
            if isinstance(sanitized_xml, Path)
            else sanitized_xml
        )

        # Original coordinate attribute values should not appear
        assert "10.5" not in output_text
        assert "20.3" not in output_text
        assert "30.7" not in output_text

    def test_masking_handles_nested_numerics(
        self,
        masking_config: MaskingConfig,
        tmp_vault: Path,
    ):
        """Deeply nested numeric values should also be masked."""
        xml = """<root>
            <level1>
                <level2>
                    <level3>
                        <deep_value>3.14159</deep_value>
                    </level3>
                </level2>
            </level1>
        </root>"""
        vault = Vault(tmp_vault)
        masked_xml = mask_values(xml, masking_config, vault)

        assert "3.14159" not in masked_xml, (
            "Deeply nested numeric value should be masked"
        )
