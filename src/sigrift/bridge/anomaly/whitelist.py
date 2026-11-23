"""Known signal whitelist for reducing false-positive anomalies.

Pre-seeded with common RF bands and their expected signal classes.
Matching whitelisted detections have their anomaly score reduced
to avoid operator fatigue from expected transmissions.

Supports operator-added custom entries and JSON persistence.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# WhitelistEntry
# ---------------------------------------------------------------------------


class WhitelistEntry(BaseModel):
    """A known signal pattern that reduces anomaly scoring."""

    model_config = {"extra": "forbid"}

    freq_min_hz: float
    freq_max_hz: float
    expected_classes: list[str] = Field(default_factory=list)
    description: str = ""
    time_windows: list[tuple[int, int]] | None = None
    node_ids: list[str] | None = None
    score_reduction: float = Field(default=0.3, ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# SignalWhitelist
# ---------------------------------------------------------------------------

# Pre-seeded known RF bands
_DEFAULT_ENTRIES: list[dict[str, Any]] = [
    {
        "freq_min_hz": 87_500_000,
        "freq_max_hz": 108_000_000,
        "expected_classes": ["fm", "am-dsb"],
        "description": "FM Broadcast",
    },
    {
        "freq_min_hz": 144_000_000,
        "freq_max_hz": 148_000_000,
        "expected_classes": ["bpsk", "qpsk", "2fsk", "4fsk", "fm"],
        "description": "2m Ham",
    },
    {
        "freq_min_hz": 162_400_000,
        "freq_max_hz": 162_550_000,
        "expected_classes": ["fm"],
        "description": "NOAA Weather",
    },
    {
        "freq_min_hz": 433_050_000,
        "freq_max_hz": 434_790_000,
        "expected_classes": ["ook", "2fsk", "4fsk", "lora-css"],
        "description": "ISM 433",
    },
    {
        "freq_min_hz": 462_000_000,
        "freq_max_hz": 467_000_000,
        "expected_classes": ["fm", "4fsk"],
        "description": "FRS/GMRS",
    },
    {
        "freq_min_hz": 868_000_000,
        "freq_max_hz": 868_600_000,
        "expected_classes": ["lora-css", "2gfsk", "ook"],
        "description": "ISM 868",
    },
    {
        "freq_min_hz": 902_000_000,
        "freq_max_hz": 928_000_000,
        "expected_classes": ["lora-css", "2gfsk", "4gfsk", "ook", "ofdm-64"],
        "description": "ISM 915",
    },
    {
        "freq_min_hz": 2_400_000_000,
        "freq_max_hz": 2_500_000_000,
        "expected_classes": ["ofdm-64", "ofdm-256"],
        "description": "WiFi 2.4",
    },
]


class SignalWhitelist:
    """Manages known signal patterns for anomaly score reduction.

    Initialised with pre-seeded entries for common RF bands.
    """

    def __init__(self) -> None:
        self.entries: list[WhitelistEntry] = []
        self._seed_defaults()

    def _seed_defaults(self) -> None:
        """Pre-seed with known RF bands."""
        for entry_data in _DEFAULT_ENTRIES:
            self.entries.append(WhitelistEntry(**entry_data))

    def check(
        self,
        freq_hz: float,
        class_name: str,
        node_id: str | None = None,
        hour: int | None = None,
    ) -> WhitelistEntry | None:
        """Check if a detection matches any whitelist entry.

        Parameters
        ----------
        freq_hz : float
            Detection frequency in Hz.
        class_name : str
            Detected signal class.
        node_id : str or None
            Node identifier.
        hour : int or None
            Hour of day (0-23).

        Returns
        -------
        WhitelistEntry or None
            First matching entry, or None if no match.
        """
        for entry in self.entries:
            if not (entry.freq_min_hz <= freq_hz <= entry.freq_max_hz):
                continue

            if entry.expected_classes and class_name not in entry.expected_classes:
                continue

            if entry.node_ids is not None and node_id not in entry.node_ids:
                continue

            if entry.time_windows is not None and hour is not None:
                in_window = any(
                    start <= hour <= end for start, end in entry.time_windows
                )
                if not in_window:
                    continue

            return entry

        return None

    def apply_reduction(
        self,
        score: float,
        freq_hz: float,
        class_name: str,
        node_id: str | None = None,
        hour: int | None = None,
    ) -> float:
        """Reduce anomaly score if detection matches whitelist.

        Parameters
        ----------
        score : float
            Original anomaly score.
        freq_hz : float
            Detection frequency.
        class_name : str
            Detected signal class.
        node_id : str or None
            Node identifier.
        hour : int or None
            Hour of day.

        Returns
        -------
        float
            Reduced score (clamped to >= 0).
        """
        entry = self.check(freq_hz, class_name, node_id, hour)
        if entry is not None:
            return max(0.0, score - entry.score_reduction)
        return score

    def add_entry(self, entry: WhitelistEntry) -> None:
        """Add a custom whitelist entry.

        Parameters
        ----------
        entry : WhitelistEntry
            Entry to add.
        """
        self.entries.append(entry)

    def remove_entry(self, index: int) -> None:
        """Remove a whitelist entry by index.

        Parameters
        ----------
        index : int
            Index into the entries list.

        Raises
        ------
        IndexError
            If index is out of range.
        """
        del self.entries[index]

    def save(self, path: str) -> None:
        """Save whitelist to JSON file.

        Parameters
        ----------
        path : str
            Output file path.
        """
        data = {
            "entries": [e.model_dump() for e in self.entries],
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        tmp.replace(p)
        logger.info("Whitelist saved: %d entries → %s", len(self.entries), path)

    def load(self, path: str) -> None:
        """Load whitelist from JSON file.

        Replaces current entries entirely.

        Parameters
        ----------
        path : str
            Input file path.
        """
        p = Path(path)
        if not p.exists():
            logger.warning("Whitelist file not found: %s", path)
            return
        try:
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            raw = data.get("entries", [])
            self.entries = [WhitelistEntry(**e) for e in raw]
            logger.info("Whitelist loaded: %d entries from %s", len(self.entries), path)
        except (json.JSONDecodeError, OSError, KeyError) as exc:
            logger.warning("Failed to load whitelist from %s: %s", path, exc)
