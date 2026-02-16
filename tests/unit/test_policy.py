"""Tests for the policy engine module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.policy_engine import Policy, Rule, auto_detect_rules


class TestAutoDetectRules:
    """Verify that auto-detection generates correct rules from XML content."""

    def test_auto_detect_rules(self, sample_xml: str):
        """Auto-detect should identify numeric tags and structural groups."""
        rules = auto_detect_rules(sample_xml)

        assert isinstance(rules, list), "auto_detect_rules must return a list"
        assert len(rules) > 0, "Should detect at least one rule from sample XML"

        # Collect all rule actions and tag patterns
        actions = {r.action for r in rules}
        tag_patterns = {r.tag_pattern for r in rules}

        # Numeric-bearing tags should get mask_value
        assert "mask_value" in actions, (
            "Should detect mask_value action for numeric tags"
        )

        # At least pressure/temperature/velocity should be detected
        numeric_tags = {"pressure", "temperature", "velocity"}
        mask_value_tags = {
            r.tag_pattern for r in rules if r.action == "mask_value"
        }
        detected_numeric = numeric_tags & mask_value_tags
        assert len(detected_numeric) >= 2, (
            f"Expected at least 2 numeric tags detected, got: {detected_numeric}"
        )

    def test_auto_detect_identifies_shuffle_candidates(self, sample_xml: str):
        """Sibling groups (e.g. multiple <element> tags) should trigger shuffle_siblings."""
        rules = auto_detect_rules(sample_xml)

        shuffle_tags = {
            r.tag_pattern for r in rules if r.action == "shuffle_siblings"
        }
        assert "element" in shuffle_tags, (
            "Repeated <element> siblings should trigger shuffle_siblings rule"
        )

    def test_auto_detect_preserves_metadata(self, sample_xml: str):
        """Metadata tags like <id> and <type> should get preserve action."""
        rules = auto_detect_rules(sample_xml)

        preserve_tags = {r.tag_pattern for r in rules if r.action == "preserve"}
        # At least id or type should be preserved
        assert len(preserve_tags) > 0, (
            "Auto-detect should identify at least one tag to preserve"
        )

    def test_auto_detect_returns_rule_objects(self, sample_xml: str):
        """Each detected rule should be a proper Rule instance."""
        rules = auto_detect_rules(sample_xml)
        for rule in rules:
            assert isinstance(rule, Rule), f"Expected Rule instance, got {type(rule)}"
            assert rule.tag_pattern, "Rule must have a non-empty tag_pattern"
            assert rule.action in (
                "preserve",
                "redact",
                "mask_value",
                "shuffle_siblings",
            ), f"Unknown action: {rule.action}"


class TestPolicySaveAndLoad:
    """Verify that policies can be serialized and deserialized."""

    def test_save_and_load_policy(self, tmp_path: Path):
        """A policy saved to JSON should be loadable and identical."""
        rules = [
            Rule(tag_pattern="pressure", action="mask_value"),
            Rule(tag_pattern="element", action="shuffle_siblings"),
            Rule(tag_pattern="metadata/id", action="preserve"),
        ]
        policy = Policy(version="1.0", global_masking=True, rules=rules)

        policy_path = tmp_path / "test_policy.json"
        policy.save(policy_path)

        assert policy_path.exists(), "Policy file should be created on disk"

        loaded = Policy.load(policy_path)
        assert loaded.version == policy.version
        assert loaded.global_masking == policy.global_masking
        assert len(loaded.rules) == len(policy.rules)

        for original, restored in zip(policy.rules, loaded.rules):
            assert original.tag_pattern == restored.tag_pattern
            assert original.action == restored.action

    def test_load_policy_from_fixture(self, policy_test_path: Path):
        """Loading the test fixture policy should produce a valid Policy."""
        policy = Policy.load(policy_test_path)

        assert policy.version == "1.0"
        assert policy.global_masking is True
        assert len(policy.rules) > 0

        actions = {r.action for r in policy.rules}
        assert "mask_value" in actions
        assert "shuffle_siblings" in actions

    def test_policy_json_roundtrip(self, tmp_path: Path):
        """Policy JSON output should be valid JSON with expected keys."""
        policy = Policy(
            version="1.0",
            global_masking=False,
            rules=[Rule(tag_pattern="value", action="redact")],
        )

        policy_path = tmp_path / "roundtrip.json"
        policy.save(policy_path)

        raw = json.loads(policy_path.read_text())
        assert "version" in raw
        assert "global_masking" in raw
        assert "rules" in raw
        assert isinstance(raw["rules"], list)
        assert raw["rules"][0]["tag_pattern"] == "value"
