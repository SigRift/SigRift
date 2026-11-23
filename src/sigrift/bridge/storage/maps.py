"""Map / floor plan storage sub-store.

SQLite-backed storage for floor plan images, coordinate calibration,
and map zones.  Uses the SharedContext pattern for thread-safe access.
"""

from __future__ import annotations

import json
import logging
import math
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_MAPS_SCHEMA = """
CREATE TABLE IF NOT EXISTS floor_plans (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    building TEXT DEFAULT '',
    floor TEXT DEFAULT '',
    description TEXT DEFAULT '',
    image_path TEXT NOT NULL,

    -- Coordinate mapping: image pixels to local coordinate system
    origin_x REAL DEFAULT 0,
    origin_y REAL DEFAULT 0,
    scale_x REAL DEFAULT 1.0,
    scale_y REAL DEFAULT 1.0,
    rotation_deg REAL DEFAULT 0,

    -- Geo-reference (optional, for outdoor overlay)
    geo_lat REAL,
    geo_lon REAL,
    geo_bearing REAL,

    width_px INTEGER,
    height_px INTEGER,

    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS map_zones (
    id TEXT PRIMARY KEY,
    floor_plan_id TEXT REFERENCES floor_plans(id),
    name TEXT NOT NULL,
    zone_type TEXT DEFAULT 'area',
    polygon_json TEXT NOT NULL,
    color TEXT DEFAULT '#3388ff',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_map_zones_floor_plan
    ON map_zones (floor_plan_id);
"""


class MapStore:
    """Floor plan and map zone storage operations.

    Parameters
    ----------
    ctx : SharedContext
        Shared infrastructure (connection, write lock, cache).
    """

    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx
        self._ensure_table()

    def _ensure_table(self) -> None:
        with self._ctx.transaction() as conn:
            conn.executescript(_MAPS_SCHEMA)

    # -- Floor plans --------------------------------------------------------

    def add_floor_plan(
        self,
        plan_id: str,
        name: str,
        image_path: str,
        building: str = "",
        floor: str = "",
        description: str = "",
        origin_x: float = 0.0,
        origin_y: float = 0.0,
        scale_x: float = 1.0,
        scale_y: float = 1.0,
        rotation_deg: float = 0.0,
        geo_lat: float | None = None,
        geo_lon: float | None = None,
        geo_bearing: float | None = None,
        width_px: int | None = None,
        height_px: int | None = None,
    ) -> dict[str, Any]:
        """Add a new floor plan."""
        now = datetime.now(timezone.utc).isoformat()
        with self._ctx.write_transaction() as conn:
            conn.execute(
                """
                INSERT INTO floor_plans
                    (id, name, image_path, building, floor, description,
                     origin_x, origin_y, scale_x, scale_y, rotation_deg,
                     geo_lat, geo_lon, geo_bearing, width_px, height_px,
                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    plan_id,
                    name,
                    image_path,
                    building,
                    floor,
                    description,
                    origin_x,
                    origin_y,
                    scale_x,
                    scale_y,
                    rotation_deg,
                    geo_lat,
                    geo_lon,
                    geo_bearing,
                    width_px,
                    height_px,
                    now,
                    now,
                ),
            )
        return {
            "id": plan_id,
            "name": name,
            "image_path": image_path,
            "building": building,
            "floor": floor,
            "description": description,
            "origin_x": origin_x,
            "origin_y": origin_y,
            "scale_x": scale_x,
            "scale_y": scale_y,
            "rotation_deg": rotation_deg,
            "geo_lat": geo_lat,
            "geo_lon": geo_lon,
            "geo_bearing": geo_bearing,
            "width_px": width_px,
            "height_px": height_px,
            "created_at": now,
            "updated_at": now,
        }

    def get_floor_plan(self, plan_id: str) -> dict[str, Any] | None:
        """Get a floor plan by ID, or None."""
        conn = self._ctx.get_conn()
        row = conn.execute(
            "SELECT * FROM floor_plans WHERE id = ?", (plan_id,)
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    def list_floor_plans(self, building: str | None = None) -> list[dict[str, Any]]:
        """List all floor plans, optionally filtered by building."""
        conn = self._ctx.get_conn()
        if building is not None:
            rows = conn.execute(
                "SELECT * FROM floor_plans WHERE building = ? ORDER BY name",
                (building,),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM floor_plans ORDER BY name").fetchall()
        return [dict(r) for r in rows]

    def update_floor_plan(self, plan_id: str, **kwargs: Any) -> dict[str, Any] | None:
        """Update floor plan metadata/calibration.

        Only provided keyword arguments are updated.  Returns the updated
        record, or None if the plan does not exist.
        """
        allowed = {
            "name",
            "building",
            "floor",
            "description",
            "origin_x",
            "origin_y",
            "scale_x",
            "scale_y",
            "rotation_deg",
            "geo_lat",
            "geo_lon",
            "geo_bearing",
            "width_px",
            "height_px",
            "image_path",
        }
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return self.get_floor_plan(plan_id)

        updates["updated_at"] = datetime.now(timezone.utc).isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [plan_id]

        with self._ctx.write_transaction() as conn:
            cur = conn.execute(
                f"UPDATE floor_plans SET {set_clause} WHERE id = ?",
                values,
            )
        if cur.rowcount == 0:
            return None
        return self.get_floor_plan(plan_id)

    def delete_floor_plan(self, plan_id: str) -> bool:
        """Delete a floor plan and its zones.  Returns True if deleted."""
        with self._ctx.write_transaction() as conn:
            conn.execute("DELETE FROM map_zones WHERE floor_plan_id = ?", (plan_id,))
            cur = conn.execute("DELETE FROM floor_plans WHERE id = ?", (plan_id,))
        return cur.rowcount > 0

    # -- Zones --------------------------------------------------------------

    def add_zone(
        self,
        zone_id: str,
        floor_plan_id: str,
        name: str,
        polygon: list[list[float]],
        zone_type: str = "area",
        color: str = "#3388ff",
    ) -> dict[str, Any]:
        """Add a zone to a floor plan."""
        now = datetime.now(timezone.utc).isoformat()
        polygon_json = json.dumps(polygon)
        with self._ctx.write_transaction() as conn:
            conn.execute(
                """
                INSERT INTO map_zones
                    (id, floor_plan_id, name, zone_type, polygon_json, color, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (zone_id, floor_plan_id, name, zone_type, polygon_json, color, now),
            )
        return {
            "id": zone_id,
            "floor_plan_id": floor_plan_id,
            "name": name,
            "zone_type": zone_type,
            "polygon": polygon,
            "color": color,
            "created_at": now,
        }

    def get_zones(self, floor_plan_id: str) -> list[dict[str, Any]]:
        """Get all zones for a floor plan."""
        conn = self._ctx.get_conn()
        rows = conn.execute(
            "SELECT * FROM map_zones WHERE floor_plan_id = ? ORDER BY name",
            (floor_plan_id,),
        ).fetchall()
        results = []
        for row in rows:
            d = dict(row)
            try:
                d["polygon"] = json.loads(d.pop("polygon_json", "[]"))
            except (json.JSONDecodeError, TypeError):
                d["polygon"] = []
            results.append(d)
        return results

    def delete_zone(self, zone_id: str) -> bool:
        """Delete a zone.  Returns True if deleted."""
        with self._ctx.write_transaction() as conn:
            cur = conn.execute("DELETE FROM map_zones WHERE id = ?", (zone_id,))
        return cur.rowcount > 0

    # -- Coordinate conversions ---------------------------------------------

    def local_to_pixel(
        self, plan_id: str, x: float, y: float
    ) -> tuple[float, float] | None:
        """Convert local coordinates to image pixel coordinates.

        Returns (px, py) or None if floor plan not found.
        """
        plan = self.get_floor_plan(plan_id)
        if plan is None:
            return None

        ox = plan["origin_x"] or 0.0
        oy = plan["origin_y"] or 0.0
        sx = plan["scale_x"] or 1.0
        sy = plan["scale_y"] or 1.0
        rot = math.radians(plan["rotation_deg"] or 0.0)

        # Translate to origin
        dx = x - ox
        dy = y - oy

        # Apply inverse rotation
        cos_r = math.cos(-rot)
        sin_r = math.sin(-rot)
        rx = dx * cos_r - dy * sin_r
        ry = dx * sin_r + dy * cos_r

        # Scale to pixels
        px = rx / sx
        py = ry / sy

        return (px, py)

    def pixel_to_local(
        self, plan_id: str, px: float, py: float
    ) -> tuple[float, float] | None:
        """Convert image pixel coordinates to local coordinates.

        Returns (x, y) or None if floor plan not found.
        """
        plan = self.get_floor_plan(plan_id)
        if plan is None:
            return None

        ox = plan["origin_x"] or 0.0
        oy = plan["origin_y"] or 0.0
        sx = plan["scale_x"] or 1.0
        sy = plan["scale_y"] or 1.0
        rot = math.radians(plan["rotation_deg"] or 0.0)

        # Scale from pixels
        lx = px * sx
        ly = py * sy

        # Apply rotation
        cos_r = math.cos(rot)
        sin_r = math.sin(rot)
        rx = lx * cos_r - ly * sin_r
        ry = lx * sin_r + ly * cos_r

        # Translate from origin
        x = rx + ox
        y = ry + oy

        return (x, y)

    # -- Stats --------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        """Return map statistics."""
        conn = self._ctx.get_conn()

        plan_row = conn.execute("SELECT COUNT(*) as cnt FROM floor_plans").fetchone()
        plan_count = plan_row["cnt"] if plan_row else 0

        zone_row = conn.execute("SELECT COUNT(*) as cnt FROM map_zones").fetchone()
        zone_count = zone_row["cnt"] if zone_row else 0

        building_row = conn.execute(
            "SELECT COUNT(DISTINCT building) as cnt FROM floor_plans WHERE building != ''"
        ).fetchone()
        building_count = building_row["cnt"] if building_row else 0

        return {
            "floor_plans": plan_count,
            "zones": zone_count,
            "buildings": building_count,
        }
