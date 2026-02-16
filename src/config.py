"""Configuration loader using Pydantic models."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel


class MaskingConfig(BaseModel):
    """Controls how numeric values are replaced with UUID placeholders."""

    value_pattern: str = r"-?\d+\.?\d*"
    uuid_format: str = "VAL_{uuid}"
    preserve_attributes: list[str] = ["id", "type"]


class ShufflingConfig(BaseModel):
    """Controls element reordering to break positional inference."""

    enabled: bool = True
    seed: int | None = None
    target_tags: list[str] = ["element", "node", "component"]


class PolicyEngineConfig(BaseModel):
    """Top-level configuration combining masking, shuffling, and vault settings."""

    masking: MaskingConfig = MaskingConfig()
    shuffling: ShufflingConfig = ShufflingConfig()
    vault_path: Path = Path("./session_vault.json")
    strict_mode: bool = False


def load_config(path: str | Path = "config/default.yaml") -> PolicyEngineConfig:
    """Load configuration from a YAML file.

    Falls back to defaults if the file does not exist.
    """
    config_path = Path(path)
    if not config_path.exists():
        return PolicyEngineConfig()

    with open(config_path) as f:
        raw = yaml.safe_load(f) or {}

    return PolicyEngineConfig(
        masking=MaskingConfig(**raw.get("masking", {})),
        shuffling=ShufflingConfig(**raw.get("shuffling", {})),
        vault_path=Path(raw.get("vault", {}).get("path", "./session_vault.json")),
        strict_mode=raw.get("strict_mode", False),
    )
