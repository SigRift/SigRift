"""Shared constants for The Bridge.

Centralises values that were previously duplicated across multiple
router modules (admin, maintenance, system_config).
"""

from __future__ import annotations

import os

# ---------------------------------------------------------------------------
# Data retention policy (env-configurable, default 90 days)
# ---------------------------------------------------------------------------

BRIDGE_RETENTION_DAYS: int = int(os.environ.get("BRIDGE_RETENTION_DAYS", "90"))


# ---------------------------------------------------------------------------
# Onboarding: canonical key_id for the in-stack scanner (PR-6)
# ---------------------------------------------------------------------------
#
# The bundled docker-compose stack mints a NODE-role API key for the
# in-stack wifi-scan/bt-scan/scan containers and pre-registers it via
# the BRIDGE_LOCAL_NODE_KEY env var. The bridge stores the resulting
# key entry under this fixed key_id so the dashboard onboarding banner
# can probe a single, stable identifier.
#
# Do not change this value without coordinating with quickstart.sh,
# docker-compose.yml, and the scanner images — they all expect it.

LOCAL_SCANNER_KEY_ID: str = "local-edge"
