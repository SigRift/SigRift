"""PRE-68 follow-up: the gateway must know the bridge's newest migration.

The Rust gateway opens the bridge's database and refuses one that holds a
migration newer than ``NEWEST_KNOWN_BRIDGE_MIGRATION`` (``db/schema.rs``),
as the bridge refuses one newer than its ``_MIGRATIONS``. The two must not
drift: a bridge migration added without bumping the gateway would make the
gateway refuse every database the same release's bridge has migrated.

This test runs with the bridge suite, so a change to ``_MIGRATIONS`` fails
here; the gateway's own ``newest_known_bridge_migration_matches_the_bridge``
test catches a change to the constant. No Rust toolchain is needed.
"""

from __future__ import annotations

import re
from pathlib import Path

from sigrift.bridge.storage.base import _MIGRATIONS

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_SCHEMA_RS = (
    _PROJECT_ROOT
    / "src"
    / "gateway"
    / "crates"
    / "sigrift-gateway-core"
    / "src"
    / "db"
    / "schema.rs"
)
_CONSTANT = re.compile(
    r"^pub const NEWEST_KNOWN_BRIDGE_MIGRATION: i64 = (\d+);$", re.MULTILINE
)


def _gateway_newest_known() -> int:
    assert _SCHEMA_RS.exists(), f"Rust source not found: {_SCHEMA_RS}"
    found = _CONSTANT.findall(_SCHEMA_RS.read_text(encoding="utf-8"))
    assert len(found) == 1, (
        f"expected one `pub const NEWEST_KNOWN_BRIDGE_MIGRATION: i64 = N;` "
        f"in {_SCHEMA_RS}, found {len(found)}"
    )
    return int(found[0])


def test_gateway_knows_the_newest_bridge_migration():
    newest = max(version for version, _, _ in _MIGRATIONS)
    assert _gateway_newest_known() == newest, (
        f"The bridge's newest migration is {newest}, but the gateway's "
        f"NEWEST_KNOWN_BRIDGE_MIGRATION ({_SCHEMA_RS.relative_to(_PROJECT_ROOT)}) "
        "is not. Check that the gateway still reads and writes the bridge's "
        "tables correctly with the new migration, then set it to the newest "
        "migration."
    )
