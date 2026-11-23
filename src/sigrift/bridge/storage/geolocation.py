"""Geolocation storage sub-store.

SQLite-backed storage for node positions and RSSI-based position
estimates.  Uses the SharedContext pattern for thread-safe access.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_GEOLOCATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS node_positions (
    node_id    TEXT PRIMARY KEY,
    x          REAL NOT NULL,
    y          REAL NOT NULL,
    z          REAL DEFAULT 0.0,
    label      TEXT DEFAULT '',
    floor      TEXT DEFAULT '',
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS position_estimates (
    id                TEXT PRIMARY KEY,
    detection_id      TEXT,
    emitter_id        TEXT,
    x                 REAL NOT NULL,
    y                 REAL NOT NULL,
    z                 REAL DEFAULT 0.0,
    confidence        REAL,
    error_radius_m    REAL,
    method            TEXT NOT NULL,
    n_nodes           INTEGER,
    path_loss_model   TEXT,
    measurements_json TEXT,
    created_at        TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_pe_detection_id
    ON position_estimates (detection_id) WHERE detection_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pe_created_at
    ON position_estimates (created_at);
CREATE INDEX IF NOT EXISTS idx_pe_emitter_id
    ON position_estimates (emitter_id) WHERE emitter_id IS NOT NULL;
"""


class GeolocationStore:
    """Node position and geolocation estimate operations.

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
            conn.executescript(_GEOLOCATION_SCHEMA)

    # -- Node positions -----------------------------------------------------

    def set_node_position(
        self,
        node_id: str,
        x: float,
        y: float,
        z: float = 0.0,
        label: str = "",
        floor: str = "",
    ) -> dict[str, Any]:
        """Set or update a node's position."""
        now = datetime.now(timezone.utc).isoformat()
        with self._ctx.write_transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO node_positions
                    (node_id, x, y, z, label, floor, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (node_id, x, y, z, label, floor, now),
            )
        return {
            "node_id": node_id,
            "x": x,
            "y": y,
            "z": z,
            "label": label,
            "floor": floor,
            "updated_at": now,
        }

    def get_node_position(self, node_id: str) -> dict[str, Any] | None:
        """Get a single node position, or None."""
        conn = self._ctx.get_conn()
        row = conn.execute(
            "SELECT * FROM node_positions WHERE node_id = ?",
            (node_id,),
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    def get_all_positions(self) -> list[dict[str, Any]]:
        """Get all node positions."""
        conn = self._ctx.get_conn()
        rows = conn.execute("SELECT * FROM node_positions ORDER BY node_id").fetchall()
        return [dict(r) for r in rows]

    def delete_node_position(self, node_id: str) -> bool:
        """Remove a node position.  Returns True if deleted."""
        with self._ctx.write_transaction() as conn:
            cur = conn.execute(
                "DELETE FROM node_positions WHERE node_id = ?",
                (node_id,),
            )
        return cur.rowcount > 0

    # -- Position estimates -------------------------------------------------

    def store_estimate(
        self,
        estimate_id: str,
        detection_id: str | None,
        x: float,
        y: float,
        z: float = 0.0,
        confidence: float | None = None,
        error_radius_m: float | None = None,
        method: str = "",
        n_nodes: int = 0,
        path_loss_model: str = "",
        measurements: list[dict[str, Any]] | None = None,
        emitter_id: str | None = None,
    ) -> dict[str, Any]:
        """Store a position estimate."""
        now = datetime.now(timezone.utc).isoformat()
        measurements_json = json.dumps(measurements or [])
        with self._ctx.write_transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO position_estimates
                    (id, detection_id, emitter_id, x, y, z,
                     confidence, error_radius_m, method, n_nodes,
                     path_loss_model, measurements_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    estimate_id,
                    detection_id,
                    emitter_id,
                    x,
                    y,
                    z,
                    confidence,
                    error_radius_m,
                    method,
                    n_nodes,
                    path_loss_model,
                    measurements_json,
                    now,
                ),
            )
        return {
            "id": estimate_id,
            "detection_id": detection_id,
            "emitter_id": emitter_id,
            "x": x,
            "y": y,
            "z": z,
            "confidence": confidence,
            "error_radius_m": error_radius_m,
            "method": method,
            "n_nodes": n_nodes,
            "path_loss_model": path_loss_model,
            "measurements": measurements or [],
            "created_at": now,
        }

    def get_estimate(self, estimate_id: str) -> dict[str, Any] | None:
        """Get a single estimate by ID."""
        conn = self._ctx.get_conn()
        row = conn.execute(
            "SELECT * FROM position_estimates WHERE id = ?",
            (estimate_id,),
        ).fetchone()
        if row is None:
            return None
        d = dict(row)
        try:
            d["measurements"] = json.loads(d.pop("measurements_json", "[]"))
        except (json.JSONDecodeError, TypeError):
            d["measurements"] = []
        return d

    def get_estimates_for_detection(self, detection_id: str) -> list[dict[str, Any]]:
        """Get all estimates associated with a detection."""
        conn = self._ctx.get_conn()
        rows = conn.execute(
            "SELECT * FROM position_estimates WHERE detection_id = ? "
            "ORDER BY created_at DESC",
            (detection_id,),
        ).fetchall()
        results = []
        for row in rows:
            d = dict(row)
            try:
                d["measurements"] = json.loads(d.pop("measurements_json", "[]"))
            except (json.JSONDecodeError, TypeError):
                d["measurements"] = []
            results.append(d)
        return results

    def list_estimates(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        """List position estimates, ordered by created_at DESC."""
        conn = self._ctx.get_conn()
        rows = conn.execute(
            "SELECT * FROM position_estimates "
            "ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        results = []
        for row in rows:
            d = dict(row)
            try:
                d["measurements"] = json.loads(d.pop("measurements_json", "[]"))
            except (json.JSONDecodeError, TypeError):
                d["measurements"] = []
            results.append(d)
        return results

    def get_stats(self) -> dict[str, Any]:
        """Return geolocation statistics."""
        conn = self._ctx.get_conn()

        node_count_row = conn.execute(
            "SELECT COUNT(*) as cnt FROM node_positions"
        ).fetchone()
        node_count = node_count_row["cnt"] if node_count_row else 0

        est_count_row = conn.execute(
            "SELECT COUNT(*) as cnt FROM position_estimates"
        ).fetchone()
        est_count = est_count_row["cnt"] if est_count_row else 0

        avg_conf_row = conn.execute(
            "SELECT AVG(confidence) as avg_conf FROM position_estimates"
        ).fetchone()
        avg_confidence = (
            avg_conf_row["avg_conf"]
            if avg_conf_row and avg_conf_row["avg_conf"] is not None
            else 0.0
        )

        avg_err_row = conn.execute(
            "SELECT AVG(error_radius_m) as avg_err FROM position_estimates"
        ).fetchone()
        avg_error = (
            avg_err_row["avg_err"]
            if avg_err_row and avg_err_row["avg_err"] is not None
            else 0.0
        )

        method_rows = conn.execute(
            "SELECT method, COUNT(*) as cnt FROM position_estimates GROUP BY method"
        ).fetchall()
        by_method = {r["method"]: r["cnt"] for r in method_rows}

        return {
            "node_positions": node_count,
            "total_estimates": est_count,
            "avg_confidence": round(avg_confidence, 4),
            "avg_error_radius_m": round(avg_error, 4),
            "by_method": by_method,
        }
