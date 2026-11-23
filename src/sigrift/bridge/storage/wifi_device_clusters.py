"""WiFi device cluster storage sub-store.

SQLite-backed storage for device clusters, IE fingerprint data,
timing signatures, and preferred network lists (PNL).  Follows
the SharedContext pattern from bitstreams.py / fingerprints.py.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from sigrift.bridge.cache import CacheTag

logger = logging.getLogger(__name__)


_CLUSTER_SCHEMA = """
CREATE TABLE IF NOT EXISTS wifi_device_clusters (
    cluster_id        TEXT PRIMARY KEY,
    ie_fingerprint    TEXT NOT NULL,
    timing_signature  TEXT DEFAULT '',
    device_class      TEXT DEFAULT '',
    confidence        REAL DEFAULT 0.0,
    first_seen        TEXT NOT NULL,
    last_seen         TEXT NOT NULL,
    mac_addresses     TEXT DEFAULT '[]',
    observation_count INTEGER DEFAULT 1,
    node_id           TEXT DEFAULT '',
    tenant_id         TEXT NOT NULL DEFAULT 'default'
);

CREATE INDEX IF NOT EXISTS idx_wifi_cluster_fp
    ON wifi_device_clusters(ie_fingerprint);
CREATE INDEX IF NOT EXISTS idx_wifi_cluster_seen
    ON wifi_device_clusters(last_seen);

CREATE TABLE IF NOT EXISTS wifi_ie_data (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ie_fingerprint  TEXT NOT NULL,
    ie_raw_hex      TEXT NOT NULL,
    htcap_hex       TEXT DEFAULT '',
    extcap_hex      TEXT DEFAULT '',
    vendor_specific TEXT DEFAULT '[]',
    supported_rates TEXT DEFAULT '',
    ie_order_hash   TEXT DEFAULT '',
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    observation_count INTEGER DEFAULT 1,
    node_id         TEXT DEFAULT '',
    tenant_id       TEXT NOT NULL DEFAULT 'default'
);

CREATE INDEX IF NOT EXISTS idx_wifi_ie_fp
    ON wifi_ie_data(ie_fingerprint);

CREATE TABLE IF NOT EXISTS wifi_timing_signatures (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ie_fingerprint  TEXT NOT NULL,
    mean_ifat_us    REAL,
    std_ifat_us     REAL,
    mean_ibt_us     REAL,
    std_ibt_us      REAL,
    burst_size_mean REAL,
    burst_size_std  REAL,
    burst_freq_hz   REAL,
    sample_count    INTEGER DEFAULT 0,
    computed_at     TEXT NOT NULL,
    node_id         TEXT DEFAULT '',
    tenant_id       TEXT NOT NULL DEFAULT 'default'
);

CREATE INDEX IF NOT EXISTS idx_wifi_timing_fp
    ON wifi_timing_signatures(ie_fingerprint);

CREATE TABLE IF NOT EXISTS wifi_device_pnl (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_id   TEXT NOT NULL,
    ssid         TEXT NOT NULL,
    first_probed TEXT NOT NULL,
    last_probed  TEXT NOT NULL,
    probe_count  INTEGER DEFAULT 1,
    node_id      TEXT DEFAULT '',
    tenant_id    TEXT NOT NULL DEFAULT 'default',
    UNIQUE(cluster_id, ssid, node_id)
);

CREATE INDEX IF NOT EXISTS idx_wifi_pnl_cluster
    ON wifi_device_pnl(cluster_id);
"""


class WiFiDeviceClusterStore:
    """WiFi device cluster CRUD operations backed by a SharedContext.

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
            conn.executescript(_CLUSTER_SCHEMA)

    # ------------------------------------------------------------------
    # Cluster CRUD
    # ------------------------------------------------------------------

    def upsert_cluster(
        self,
        cluster_id: str,
        ie_fingerprint: str,
        *,
        timing_signature: dict[str, float] | None = None,
        device_class: str = "",
        confidence: float = 0.0,
        first_seen: str = "",
        last_seen: str = "",
        mac_addresses: list[str] | None = None,
        observation_count: int = 1,
        node_id: str = "",
        tenant_id: str = "default",
    ) -> None:
        """Insert or update a device cluster."""
        now = datetime.now(timezone.utc).isoformat()
        fs = first_seen or now
        ls = last_seen or now
        ts_json = json.dumps(timing_signature) if timing_signature else ""
        macs_json = json.dumps(mac_addresses or [])

        with self._ctx.write_transaction() as conn:
            conn.execute(
                """INSERT INTO wifi_device_clusters
                   (cluster_id, ie_fingerprint, timing_signature, device_class,
                    confidence, first_seen, last_seen, mac_addresses,
                    observation_count, node_id, tenant_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(cluster_id) DO UPDATE SET
                       timing_signature = excluded.timing_signature,
                       device_class = excluded.device_class,
                       confidence = excluded.confidence,
                       last_seen = excluded.last_seen,
                       mac_addresses = excluded.mac_addresses,
                       observation_count = excluded.observation_count
                """,
                (
                    cluster_id,
                    ie_fingerprint,
                    ts_json,
                    device_class,
                    confidence,
                    fs,
                    ls,
                    macs_json,
                    observation_count,
                    node_id,
                    tenant_id,
                ),
            )
        self._ctx.cache.invalidate_prefix(CacheTag.GET_WIFI_CLUSTERS)

    def get_cluster(
        self,
        cluster_id: str,
        tenant_id: str = "default",
    ) -> dict[str, Any] | None:
        """Get a single cluster by ID."""
        conn = self._ctx.get_conn()
        row = conn.execute(
            """SELECT cluster_id, ie_fingerprint, timing_signature,
                      device_class, confidence, first_seen, last_seen,
                      mac_addresses, observation_count, node_id, tenant_id
               FROM wifi_device_clusters WHERE cluster_id = ? AND tenant_id = ?""",
            (cluster_id, tenant_id),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_dict(row)

    def list_clusters(
        self,
        tenant_id: str = "default",
        min_confidence: float = 0.0,
        min_observations: int = 0,
        since: str = "",
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """List clusters with optional filters."""
        cache_key = self._ctx.cache.make_key(
            CacheTag.GET_WIFI_CLUSTERS.value,
            tenant_id=tenant_id,
            min_confidence=min_confidence,
            min_observations=min_observations,
            since=since,
            limit=limit,
        )
        cached = self._ctx.cache.get(cache_key)
        from sigrift.bridge.cache import MISSING

        if cached is not MISSING:
            return cached

        conditions = ["tenant_id = ?"]
        params: list[Any] = [tenant_id]

        if min_confidence > 0:
            conditions.append("confidence >= ?")
            params.append(min_confidence)
        if min_observations > 0:
            conditions.append("observation_count >= ?")
            params.append(min_observations)
        if since:
            conditions.append("last_seen >= ?")
            params.append(since)

        where = " AND ".join(conditions)
        sql = f"SELECT * FROM wifi_device_clusters WHERE {where} ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)

        conn = self._ctx.get_conn()
        rows = conn.execute(sql, params).fetchall()
        result = [self._row_to_dict(r) for r in rows]
        self._ctx.cache.put(cache_key, result, ttl=15.0)
        return result

    def get_cluster_timeline(
        self,
        cluster_id: str,
        tenant_id: str = "default",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get chronological appearance history for a cluster.

        Pulls from timing signatures as appearance markers.
        """
        conn = self._ctx.get_conn()
        rows = conn.execute(
            """SELECT computed_at, node_id, mean_ifat_us, burst_freq_hz, sample_count
               FROM wifi_timing_signatures
               WHERE ie_fingerprint = (
                   SELECT ie_fingerprint FROM wifi_device_clusters
                   WHERE cluster_id = ? AND tenant_id = ?
               )
               ORDER BY computed_at DESC LIMIT ?""",
            (cluster_id, tenant_id, limit),
        ).fetchall()
        return [
            {
                "computed_at": r[0],
                "node_id": r[1],
                "mean_ifat_us": r[2],
                "burst_freq_hz": r[3],
                "sample_count": r[4],
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # IE data
    # ------------------------------------------------------------------

    def store_ie_data(
        self,
        ie_fingerprint: str,
        ie_raw_hex: str,
        *,
        htcap_hex: str = "",
        extcap_hex: str = "",
        vendor_specific: str = "[]",
        supported_rates: str = "",
        ie_order_hash: str = "",
        node_id: str = "",
        tenant_id: str = "default",
    ) -> int:
        """Store or update IE data for a fingerprint. Returns row ID."""
        now = datetime.now(timezone.utc).isoformat()
        with self._ctx.write_transaction() as conn:
            existing = conn.execute(
                "SELECT id, observation_count FROM wifi_ie_data WHERE ie_fingerprint = ? AND tenant_id = ?",
                (ie_fingerprint, tenant_id),
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE wifi_ie_data SET last_seen = ?, observation_count = ? WHERE id = ?",
                    (now, existing[1] + 1, existing[0]),
                )
                return existing[0]
            else:
                cur = conn.execute(
                    """INSERT INTO wifi_ie_data
                       (ie_fingerprint, ie_raw_hex, htcap_hex, extcap_hex,
                        vendor_specific, supported_rates, ie_order_hash,
                        first_seen, last_seen, node_id, tenant_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        ie_fingerprint,
                        ie_raw_hex,
                        htcap_hex,
                        extcap_hex,
                        vendor_specific,
                        supported_rates,
                        ie_order_hash,
                        now,
                        now,
                        node_id,
                        tenant_id,
                    ),
                )
                return cur.lastrowid

    def get_ie_data(
        self,
        ie_fingerprint: str,
        tenant_id: str = "default",
    ) -> dict[str, Any] | None:
        """Get IE data for a fingerprint."""
        conn = self._ctx.get_conn()
        row = conn.execute(
            """SELECT ie_fingerprint, ie_raw_hex, htcap_hex, extcap_hex,
                      vendor_specific, supported_rates, ie_order_hash,
                      first_seen, last_seen, observation_count, node_id
               FROM wifi_ie_data
               WHERE ie_fingerprint = ? AND tenant_id = ?""",
            (ie_fingerprint, tenant_id),
        ).fetchone()
        if row is None:
            return None
        return {
            "ie_fingerprint": row[0],
            "ie_raw_hex": row[1],
            "htcap_hex": row[2],
            "extcap_hex": row[3],
            "vendor_specific": row[4],
            "supported_rates": row[5],
            "ie_order_hash": row[6],
            "first_seen": row[7],
            "last_seen": row[8],
            "observation_count": row[9],
            "node_id": row[10],
        }

    # ------------------------------------------------------------------
    # Timing signatures
    # ------------------------------------------------------------------

    def store_timing_signature(
        self,
        ie_fingerprint: str,
        timing_sig: dict[str, float],
        *,
        sample_count: int = 0,
        node_id: str = "",
        tenant_id: str = "default",
    ) -> int:
        """Store a timing signature. Returns row ID."""
        now = datetime.now(timezone.utc).isoformat()
        with self._ctx.write_transaction() as conn:
            cur = conn.execute(
                """INSERT INTO wifi_timing_signatures
                   (ie_fingerprint, mean_ifat_us, std_ifat_us, mean_ibt_us, std_ibt_us,
                    burst_size_mean, burst_size_std, burst_freq_hz,
                    sample_count, computed_at, node_id, tenant_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ie_fingerprint,
                    timing_sig.get("mean_ifat_us", 0.0),
                    timing_sig.get("std_ifat_us", 0.0),
                    timing_sig.get("mean_ibt_us", 0.0),
                    timing_sig.get("std_ibt_us", 0.0),
                    timing_sig.get("burst_size_mean", 0.0),
                    timing_sig.get("burst_size_std", 0.0),
                    timing_sig.get("burst_freq_hz", 0.0),
                    sample_count,
                    now,
                    node_id,
                    tenant_id,
                ),
            )
        return cur.lastrowid

    # ------------------------------------------------------------------
    # PNL (Preferred Network List)
    # ------------------------------------------------------------------

    def store_pnl_entry(
        self,
        cluster_id: str,
        ssid: str,
        *,
        node_id: str = "",
        tenant_id: str = "default",
    ) -> None:
        """Record an SSID probe for a device cluster."""
        now = datetime.now(timezone.utc).isoformat()
        with self._ctx.write_transaction() as conn:
            conn.execute(
                """INSERT INTO wifi_device_pnl
                   (cluster_id, ssid, first_probed, last_probed, probe_count, node_id, tenant_id)
                   VALUES (?, ?, ?, ?, 1, ?, ?)
                   ON CONFLICT(cluster_id, ssid, node_id) DO UPDATE SET
                       last_probed = excluded.first_probed,
                       probe_count = probe_count + 1
                """,
                (cluster_id, ssid, now, now, node_id, tenant_id),
            )

    def get_pnl(
        self,
        cluster_id: str,
        tenant_id: str = "default",
    ) -> list[dict[str, Any]]:
        """Get the preferred network list for a cluster."""
        conn = self._ctx.get_conn()
        rows = conn.execute(
            """SELECT ssid, first_probed, last_probed, probe_count, node_id
               FROM wifi_device_pnl
               WHERE cluster_id = ? AND tenant_id = ?
               ORDER BY probe_count DESC""",
            (cluster_id, tenant_id),
        ).fetchall()
        return [
            {
                "ssid": r[0],
                "first_probed": r[1],
                "last_probed": r[2],
                "probe_count": r[3],
                "node_id": r[4],
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, tenant_id: str = "default") -> dict[str, Any]:
        """Return summary statistics."""
        conn = self._ctx.get_conn()
        total_clusters = conn.execute(
            "SELECT COUNT(*) FROM wifi_device_clusters WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()[0]

        total_macs = 0
        randomized_macs = 0
        rows = conn.execute(
            "SELECT mac_addresses FROM wifi_device_clusters WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchall()
        for row in rows:
            try:
                macs = json.loads(row[0])
                total_macs += len(macs)
                for mac in macs:
                    first_octet = int(mac.replace("-", ":").split(":")[0], 16)
                    if first_octet & 0x02:
                        randomized_macs += 1
            except (json.JSONDecodeError, ValueError, IndexError):
                pass

        device_classes: dict[str, int] = {}
        for row in conn.execute(
            "SELECT device_class, COUNT(*) FROM wifi_device_clusters WHERE tenant_id = ? GROUP BY device_class",
            (tenant_id,),
        ).fetchall():
            device_classes[row[0] or "Unknown"] = row[1]

        return {
            "total_clusters": total_clusters,
            "total_macs": total_macs,
            "randomized_macs": randomized_macs,
            "randomized_ratio": round(randomized_macs / total_macs, 4)
            if total_macs > 0
            else 0.0,
            "device_class_distribution": device_classes,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row) -> dict[str, Any]:
        """Convert a sqlite3.Row or tuple to dict."""
        if hasattr(row, "keys"):
            d = dict(row)
        else:
            # Positional mapping for wifi_device_clusters
            keys = [
                "cluster_id",
                "ie_fingerprint",
                "timing_signature",
                "device_class",
                "confidence",
                "first_seen",
                "last_seen",
                "mac_addresses",
                "observation_count",
                "node_id",
                "tenant_id",
            ]
            d = dict(zip(keys, row))
        # Parse JSON fields
        for jfield in ("mac_addresses",):
            if isinstance(d.get(jfield), str):
                try:
                    d[jfield] = json.loads(d[jfield])
                except json.JSONDecodeError:
                    d[jfield] = []
        if isinstance(d.get("timing_signature"), str) and d["timing_signature"]:
            try:
                d["timing_signature"] = json.loads(d["timing_signature"])
            except json.JSONDecodeError:
                d["timing_signature"] = {}
        return d
