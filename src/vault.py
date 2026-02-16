"""Session key management: maps masked placeholders back to original values."""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class VaultEntry:
    """Single mapping between a masked placeholder and the original value."""

    masked_value: str
    original_value: str
    created_at: str


class Vault:
    """In-memory store for masked <-> original value mappings.

    Persists to a JSON file so values can be restored ("rehydrated") later.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.entries: dict[str, VaultEntry] = {}

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def store(self, original: str, format_str: str = "VAL_{uuid}") -> str:
        """Create a masked placeholder for *original* and store the mapping.

        Returns the placeholder string.
        """
        uid = uuid.uuid4().hex[:12]
        masked = format_str.format(uuid=uid)
        self.entries[masked] = VaultEntry(
            masked_value=masked,
            original_value=original,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        return masked

    def restore(self, masked: str) -> str | None:
        """Look up the original value for a masked placeholder.

        Returns ``None`` if the placeholder is unknown.
        """
        entry = self.entries.get(masked)
        return entry.original_value if entry else None

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self) -> Path:
        """Persist current entries to the vault JSON file."""
        data = {key: asdict(entry) for key, entry in self.entries.items()}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2))
        return self.path

    def load(self) -> None:
        """Load entries from an existing vault file on disk."""
        if not self.path.exists():
            return
        raw = json.loads(self.path.read_text())
        self.entries = {
            key: VaultEntry(**vals) for key, vals in raw.items()
        }

    # ------------------------------------------------------------------
    # Rehydration
    # ------------------------------------------------------------------

    def rehydrate_value(self, value: str) -> str:
        """Rehydrate a single value: if it's a masked placeholder, return original.

        Args:
            value: The value to rehydrate (may be a placeholder like VAL_abc123)

        Returns:
            The original value if found, otherwise the original value unchanged.
        """
        # Check if this looks like a masked value
        if self.restore(value) is not None:
            return self.restore(value)
        return value

    def rehydrate_dict(self, data: dict) -> dict:
        """Rehydrate all values in a dictionary.

        Recursively processes nested dicts and lists.

        Args:
            data: Dictionary with potentially masked values

        Returns:
            New dictionary with original values restored
        """
        if isinstance(data, dict):
            return {k: self.rehydrate_dict(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.rehydrate_dict(item) for item in data]
        elif isinstance(data, str):
            return self.rehydrate_value(data)
        return data

    def rehydrate_xml(self, xml_content: str) -> str:
        """Rehydrate masked values in XML content.

        Args:
            xml_content: XML string with masked values (VAL_xxx)

        Returns:
            XML string with original values restored
        """
        # Find all VAL_xxx patterns and replace with originals
        def replace_match(match):
            masked = match.group(0)
            original = self.restore(masked)
            return original if original is not None else masked

        # Match VAL_ followed by alphanumeric characters
        return re.sub(r"VAL_[a-zA-Z0-9]+", replace_match, xml_content)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self.entries)

    def __contains__(self, masked: str) -> bool:
        return masked in self.entries
