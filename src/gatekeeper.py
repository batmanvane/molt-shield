"""Core masking and shuffling logic for XML anonymization."""

from __future__ import annotations

import random
import re
from pathlib import Path

from lxml import etree

from src.config import MaskingConfig, PolicyEngineConfig, ShufflingConfig
from src.policy_engine import Policy, Rule
from src.vault import Vault

# ---------------------------------------------------------------------------
# Tag shadowing: replace sensitive tag names with neutral labels.
# ---------------------------------------------------------------------------

DEFAULT_TAG_MAP: dict[str, str] = {
    "pressure": "metric_alpha",
    "temperature": "thermal_beta",
    "velocity": "kinematic_gamma",
    "coordinates": "spatial_delta",
}


def mask_values(
    tree: etree._ElementTree | etree._Element,
    masking_config: MaskingConfig,
    vault: Vault,
) -> etree._ElementTree:
    """Replace numeric text content with UUID placeholders stored in the vault."""
    # Handle both Element (from fromstring) and ElementTree
    if isinstance(tree, etree._Element):
        tree = etree.ElementTree(tree)

    pattern = re.compile(masking_config.value_pattern)
    root = tree.getroot()

    for elem in root.iter():
        if not isinstance(elem.tag, str):
            continue
        text = (elem.text or "").strip()
        if text and pattern.fullmatch(text):
            placeholder = vault.store(text)
            elem.text = placeholder

    return tree


def shuffle_siblings(
    tree: etree._ElementTree | etree._Element | str,
    shuffling_config: ShufflingConfig,
    rules: list[Rule] | None = None,
) -> str:
    """Shuffle child elements to break positional inference.

    If *rules* are provided, only parent elements matching a shuffle_siblings
    rule are processed.  Otherwise every element whose tag appears in
    ``shuffling_config.target_tags`` has its children shuffled.
    """
    # Handle string input (XML as string)
    if isinstance(tree, str):
        tree = etree.fromstring(tree.encode())

    # Handle Element (from fromstring) vs ElementTree
    if isinstance(tree, etree._Element):
        tree = etree.ElementTree(tree)

    if not shuffling_config.enabled:
        return etree.tostring(tree, encoding='unicode')

    rng = random.Random(shuffling_config.seed)
    root = tree.getroot()

    # Determine which parent tags should have children shuffled.
    shuffle_parents: set[str] | None = None
    if rules:
        shuffle_parents = {
            r.tag_pattern for r in rules if r.action == "shuffle_siblings"
        }

    for elem in root.iter():
        tag = etree.QName(elem).localname if isinstance(elem.tag, str) else None
        if tag is None:
            continue

        should_shuffle = False
        if shuffle_parents is not None:
            should_shuffle = tag in shuffle_parents
        else:
            should_shuffle = tag in shuffling_config.target_tags

        if should_shuffle and len(elem) >= 2:
            children = list(elem)
            rng.shuffle(children)
            for child in list(elem):
                elem.remove(child)
            for child in children:
                elem.append(child)

    return etree.tostring(tree, encoding='unicode')


def _apply_tag_shadowing(tree: etree._ElementTree, tag_map: dict[str, str]) -> etree._ElementTree:
    """Rename tags according to *tag_map*."""
    root = tree.getroot()
    for elem in root.iter():
        if not isinstance(elem.tag, str):
            continue
        local = etree.QName(elem).localname
        if local in tag_map:
            # Preserve namespace if present.
            ns = etree.QName(elem).namespace
            if ns:
                elem.tag = f"{{{ns}}}{tag_map[local]}"
            else:
                elem.tag = tag_map[local]
    return tree


def apply_gatekeeper(
    xml_path: str | Path,
    policy: Policy,
    config: PolicyEngineConfig | None = None,
    output_dir: str | Path | None = None,
    tag_map: dict[str, str] | None = None,
) -> tuple[Path, Path]:
    """Apply a full masking + shuffling pipeline to an XML file.

    Returns ``(sanitized_xml_path, vault_path)``.
    """
    from src.config import load_config

    if config is None:
        config = load_config()

    xml_path = Path(xml_path)
    out_dir = Path(output_dir) if output_dir else xml_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    # Parse XML
    tree = etree.parse(str(xml_path))  # noqa: S320

    # Vault for this session
    vault = Vault(config.vault_path)

    # 1. Mask numeric values
    mask_rules = [r for r in policy.rules if r.action == "mask_value"]
    if policy.global_masking or mask_rules:
        tree = mask_values(tree, config.masking, vault)

    # 2. Shuffle siblings
    shuffle_rules = [r for r in policy.rules if r.action == "shuffle_siblings"]
    if config.shuffling.enabled and shuffle_rules:
        tree = shuffle_siblings(tree, config.shuffling, shuffle_rules)

    # 3. Tag shadowing
    effective_map = tag_map if tag_map is not None else DEFAULT_TAG_MAP
    tree = _apply_tag_shadowing(tree, effective_map)

    # Write outputs
    sanitized_path = out_dir / f"{xml_path.stem}_sanitized.xml"
    tree.write(str(sanitized_path), xml_declaration=True, encoding="UTF-8", pretty_print=True)

    vault.save()
    vault_path = config.vault_path

    return sanitized_path, vault_path
