"""OUI (Organizationally Unique Identifier) vendor lookup.

Loads a compressed JSON mapping of 6-char hex OUI prefixes to vendor
names from ``data/oui.json.gz``.  Provides O(1) lookup by MAC address.

If the database file is missing, all lookups return empty string.
"""

from __future__ import annotations

import gzip
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_OUI_DB_PATH = Path(__file__).resolve().parent / "data" / "oui.json.gz"
_oui_db: dict[str, str] = {}


def _load_oui_db() -> dict[str, str]:
    """Load gzip JSON OUI database, returning empty dict on failure."""
    if not _OUI_DB_PATH.exists():
        logger.warning("OUI database not found: %s", _OUI_DB_PATH)
        return {}
    try:
        with gzip.open(_OUI_DB_PATH, "rt", encoding="utf-8") as f:
            db = json.load(f)
        logger.info("OUI database loaded: %d entries", len(db))
        return db
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to load OUI database: %s", exc)
        return {}


def oui_prefix(mac: str) -> str:
    """Extract normalized 6-char uppercase hex OUI prefix from a MAC address."""
    if not mac:
        return ""
    clean = mac.replace(":", "").replace("-", "").replace(".", "").upper()
    if len(clean) < 6:
        return ""
    return clean[:6]


def lookup_vendor(mac: str) -> str:
    """Look up the vendor name for a MAC address. Returns '' if unknown."""
    global _oui_db
    if not _oui_db:
        _oui_db = _load_oui_db()
    prefix = oui_prefix(mac)
    if not prefix:
        return ""
    return _oui_db.get(prefix, "")
