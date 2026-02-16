"""Policy generation: auto-detect XML structure and produce masking/shuffling rules."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from lxml import etree


@dataclass
class Rule:
    """A single policy rule binding a tag pattern to an action."""

    tag_pattern: str
    action: Literal["preserve", "redact", "mask_value", "shuffle_siblings"]
    parameters: dict | None = None


@dataclass
class Policy:
    """Collection of rules that govern how an XML file is anonymized."""

    version: str = "1.0"
    global_masking: bool = False
    rules: list[Rule] = field(default_factory=list)
    created_at: str | None = None


# Tags whose text content should always be masked.
_SENSITIVE_KEYWORDS = {"pressure", "temperature", "velocity", "coord", "val", "force", "stress"}

# Numeric-only pattern used to detect values worth masking.
_NUMERIC_RE = re.compile(r"^-?\d+\.?\d*$")


def generate_policy(xml_path: str | Path) -> Policy:
    """Scan an XML file and auto-generate masking / shuffling rules.

    Heuristics:
    * Tag names containing a sensitive keyword -> mask_value
    * Leaf elements with purely numeric text     -> mask_value
    * Elements with >=2 children of the same tag -> shuffle_siblings
    """
    xml_path = Path(xml_path)
    tree = etree.parse(str(xml_path))  # noqa: S320
    root = tree.getroot()

    seen_tags: set[str] = set()
    rules: list[Rule] = []

    for elem in root.iter():
        tag = etree.QName(elem).localname if isinstance(elem.tag, str) else None
        if tag is None:
            continue

        # --- mask_value for sensitive keywords ---
        tag_lower = tag.lower()
        if any(kw in tag_lower for kw in _SENSITIVE_KEYWORDS) and tag not in seen_tags:
            rules.append(Rule(tag_pattern=tag, action="mask_value"))
            seen_tags.add(tag)
            continue

        # --- mask_value for numeric leaf text ---
        text = (elem.text or "").strip()
        if text and _NUMERIC_RE.match(text) and tag not in seen_tags:
            rules.append(Rule(tag_pattern=tag, action="mask_value"))
            seen_tags.add(tag)
            continue

        # --- shuffle_siblings for repeated children ---
        child_tags: dict[str, int] = {}
        for child in elem:
            ctag = etree.QName(child).localname if isinstance(child.tag, str) else None
            if ctag:
                child_tags[ctag] = child_tags.get(ctag, 0) + 1
        for ctag, count in child_tags.items():
            shuffle_key = f"{tag}/{ctag}"
            if count >= 2 and shuffle_key not in seen_tags:
                rules.append(
                    Rule(
                        tag_pattern=tag,
                        action="shuffle_siblings",
                        parameters={"child_tag": ctag},
                    )
                )
                seen_tags.add(shuffle_key)

    return Policy(
        version="1.0",
        global_masking=False,
        rules=rules,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _rule_to_dict(rule: Rule) -> dict:
    d: dict = {"tag_pattern": rule.tag_pattern, "action": rule.action}
    if rule.parameters:
        d["parameters"] = rule.parameters
    return d


def _rule_from_dict(d: dict) -> Rule:
    return Rule(
        tag_pattern=d["tag_pattern"],
        action=d["action"],
        parameters=d.get("parameters"),
    )


def save_policy(policy: Policy, path: str | Path) -> Path:
    """Write a Policy to a JSON file."""
    path = Path(path)
    data = {
        "version": policy.version,
        "global_masking": policy.global_masking,
        "rules": [_rule_to_dict(r) for r in policy.rules],
        "created_at": policy.created_at,
    }
    path.write_text(json.dumps(data, indent=2))
    return path


def load_policy(path: str | Path) -> Policy:
    """Read a Policy from a JSON file."""
    path = Path(path)
    data = json.loads(path.read_text())
    return Policy(
        version=data.get("version", "1.0"),
        global_masking=data.get("global_masking", False),
        rules=[_rule_from_dict(r) for r in data.get("rules", [])],
        created_at=data.get("created_at"),
    )
