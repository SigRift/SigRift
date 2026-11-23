"""WiFi metadata storage and queries sub-store.

Handles WiFi metadata insertion, network/client/channel aggregation,
timeline queries, hourly roll-up, and cleanup.  Extracted from the
monolithic ``DetectionStore`` to keep modules focused.

All queries merge data from both ``wifi_metadata`` (raw recent rows)
and ``wifi_metadata_hourly`` (rolled-up historical summaries) using
weighted averages for signal strength.  Raw data takes precedence
for attribute columns.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sigrift.bridge.cache import MISSING, TTLCache

logger = logging.getLogger(__name__)


class WiFiMetadataStore:
    """WiFi metadata storage and queries backed by a :class:`SharedContext`.

    Parameters
    ----------
    ctx : SharedContext
        Shared infrastructure (connection, write lock, cache).
    """

    def __init__(self, ctx) -> None:
        from sigrift.bridge.storage.base import SharedContext

        self._ctx: SharedContext = ctx

    # ------------------------------------------------------------------
    # MAC anonymization
    # ------------------------------------------------------------------

    @staticmethod
    def _anonymize_mac(mac: str, secret: bytes) -> str:
        """Pseudonymize a MAC address using HMAC-SHA256.

        Preserves the OUI (first 3 octets) for vendor identification
        and replaces the device portion with HMAC-derived hex.

        Parameters
        ----------
        mac : str
            MAC address (colon or dash separated, or raw hex).
        secret : bytes
            Per-instance secret key for HMAC.

        Returns
        -------
        str
            Pseudonymized MAC: original OUI + anonymized device portion.
        """
        if not mac:
            return mac
        # Normalize: remove separators, lowercase
        clean = mac.replace(":", "").replace("-", "").replace(".", "").lower()
        if len(clean) < 6:
            return mac
        oui = clean[:6]  # first 3 octets (6 hex chars)
        device = clean[6:]  # remaining device portion
        # HMAC the full MAC to derive pseudonym for device portion
        h = hmac.new(secret, clean.encode(), hashlib.sha256).hexdigest()
        anon_device = h[: len(device)] if device else ""
        result = oui + anon_device
        # Format as colon-separated
        return ":".join(result[i : i + 2] for i in range(0, len(result), 2))

    # ------------------------------------------------------------------
    # Insert
    # ------------------------------------------------------------------

    def insert_wifi_metadata(
        self,
        records: list[dict],
        mac_secret: bytes | None = None,
    ) -> int:
        """Bulk insert WiFi metadata rows.

        Parameters
        ----------
        records : list[dict]
            WiFi metadata records to insert.
        mac_secret : bytes or None
            If provided, anonymize client_mac fields.

        Returns
        -------
        int
            Number of rows inserted.
        """
        if not records:
            return 0

        rows = []
        for r in records:
            client_mac = r.get("client_mac", "")
            bssid = r.get("bssid", "")
            if mac_secret and client_mac:
                client_mac = self._anonymize_mac(client_mac, mac_secret)
            rows.append(
                (
                    r.get("detection_id", ""),
                    bssid,
                    r.get("ssid", ""),
                    r.get("channel", 0),
                    r.get("channel_width", 20),
                    r.get("band", "2.4GHz"),
                    r.get("security", ""),
                    r.get("signal_dbm", 0.0),
                    r.get("noise_dbm", 0.0),
                    r.get("frame_type", ""),
                    client_mac,
                    r.get("data_rate_mbps", 0.0),
                    r.get("retry_flag", 0),
                    r.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    r.get("node_id", ""),
                    self._ctx.tenant_id,
                    r.get("vendor", ""),
                    r.get("client_vendor", ""),
                )
            )

        sql = """
            INSERT INTO wifi_metadata (
                detection_id, bssid, ssid, channel, channel_width,
                band, security, signal_dbm, noise_dbm, frame_type,
                client_mac, data_rate_mbps, retry_flag, timestamp, node_id,
                tenant_id, vendor, client_vendor
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        with self._ctx.write_transaction() as conn:
            cursor = conn.executemany(sql, rows)
        # Don't invalidate cache on insert — let TTL handle staleness.
        # With 3+ nodes ingesting every ~10s, eager invalidation means
        # the cache never survives past a few seconds, defeating its purpose.
        inserted = cursor.rowcount
        logger.debug("Inserted %d wifi metadata records", inserted)
        return inserted

    # ------------------------------------------------------------------
    # Network queries
    # ------------------------------------------------------------------

    def get_wifi_networks(
        self,
        limit: int = 100,
        band: str | None = None,
        node_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Aggregate WiFi networks by BSSID (raw + hourly).

        Returns
        -------
        list[dict]
            Each entry: SSID, BSSID, channel, security, avg signal,
            client count, frame count, last seen, node IDs.
        """
        cache_key = TTLCache.make_key(
            "get_wifi_networks",
            limit=limit,
            band=band,
            node_id=node_id,
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses: list[str] = [tf_clause, "bssid != ''"]
        params: list[Any] = list(tf_params)

        if band is not None:
            clauses.append("band = ?")
            params.append(band)
        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)

        where = " AND ".join(clauses)

        # -- Raw query (recent data) --
        raw_sql = f"""
            SELECT
                bssid,
                MAX(ssid) as ssid,
                MAX(channel) as channel,
                MAX(channel_width) as channel_width,
                MAX(band) as band,
                MAX(security) as security,
                AVG(signal_dbm) as avg_signal_dbm,
                COUNT(DISTINCT CASE WHEN client_mac != '' THEN client_mac END) as client_count,
                COUNT(*) as frame_count,
                MAX(timestamp) as last_seen,
                GROUP_CONCAT(DISTINCT node_id) as node_ids,
                MAX(vendor) as vendor
            FROM wifi_metadata
            WHERE {where}
            GROUP BY bssid
        """

        # -- Hourly aggregate query (historical) --
        h_clauses = [c.replace("node_id", "node_id") for c in clauses]
        h_where = " AND ".join(h_clauses)
        hourly_sql = f"""
            SELECT
                bssid,
                MAX(ssid) as ssid,
                MAX(channel) as channel,
                MAX(channel_width) as channel_width,
                MAX(band) as band,
                MAX(security) as security,
                SUM(frame_count * avg_signal_dbm) / SUM(frame_count) as avg_signal_dbm,
                SUM(client_count) as client_count,
                SUM(frame_count) as frame_count,
                MAX(hour) as last_seen,
                GROUP_CONCAT(DISTINCT node_id) as node_ids,
                MAX(vendor) as vendor
            FROM wifi_metadata_hourly
            WHERE {h_where}
            GROUP BY bssid
        """

        conn = self._ctx.get_conn()
        raw_rows = conn.execute(raw_sql, params).fetchall()
        hourly_rows = conn.execute(hourly_sql, params).fetchall()

        # -- Merge by bssid --
        merged: dict[str, dict[str, Any]] = {}
        for r in raw_rows:
            d = dict(r)
            d["_raw_frames"] = d["frame_count"]
            d["_raw_signal_sum"] = (d.get("avg_signal_dbm") or 0.0) * d["frame_count"]
            node_str = d.get("node_ids", "")
            d["node_ids"] = {n for n in (node_str or "").split(",") if n}
            merged[d["bssid"]] = d

        for r in hourly_rows:
            h = dict(r)
            bssid = h["bssid"]
            h_frames = h["frame_count"] or 0
            h_signal_sum = (h.get("avg_signal_dbm") or 0.0) * h_frames
            h_nodes = {n for n in (h.get("node_ids") or "").split(",") if n}

            if bssid in merged:
                m = merged[bssid]
                total_frames = m["_raw_frames"] + h_frames
                m["frame_count"] = total_frames
                if total_frames > 0:
                    m["avg_signal_dbm"] = (
                        m["_raw_signal_sum"] + h_signal_sum
                    ) / total_frames
                m["client_count"] = max(m["client_count"], h.get("client_count", 0))
                m["node_ids"] |= h_nodes
                # Prefer raw for last_seen (it's more recent)
            else:
                h["_raw_frames"] = 0
                h["_raw_signal_sum"] = 0.0
                h["avg_signal_dbm"] = h.get("avg_signal_dbm") or 0.0
                node_str = h.get("node_ids", "")
                h["node_ids"] = h_nodes
                merged[bssid] = h

        # Sort by frame_count DESC, apply limit
        sorted_entries = sorted(
            merged.values(), key=lambda x: x["frame_count"], reverse=True
        )[:limit]
        results = []
        for entry in sorted_entries:
            entry.pop("_raw_frames", None)
            entry.pop("_raw_signal_sum", None)
            entry["avg_signal_dbm"] = round(entry.get("avg_signal_dbm") or 0.0, 1)
            entry["node_ids"] = (
                sorted(entry["node_ids"])
                if isinstance(entry["node_ids"], set)
                else entry["node_ids"]
            )
            results.append(entry)
        self._ctx.cache.put(cache_key, results, ttl=30.0)
        return results

    def get_wifi_network_detail(self, bssid: str) -> dict[str, Any] | None:
        """Return aggregated detail for a single WiFi network (raw + hourly).

        Parameters
        ----------
        bssid : str
            BSSID to look up.

        Returns
        -------
        dict or None
            Network info dict, or None if not found in either source.
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()

        raw_row = conn.execute(
            f"""
            SELECT
                bssid,
                MAX(ssid) as ssid,
                MAX(channel) as channel,
                MAX(channel_width) as channel_width,
                MAX(band) as band,
                MAX(security) as security,
                AVG(signal_dbm) as avg_signal_dbm,
                COUNT(DISTINCT CASE WHEN client_mac != '' THEN client_mac END) as client_count,
                COUNT(*) as frame_count,
                MAX(timestamp) as last_seen,
                GROUP_CONCAT(DISTINCT node_id) as node_ids
            FROM wifi_metadata
            WHERE {tf_clause} AND bssid = ?
            GROUP BY bssid
            """,
            tf_params + [bssid],
        ).fetchone()

        hourly_row = conn.execute(
            f"""
            SELECT
                bssid,
                MAX(ssid) as ssid,
                MAX(channel) as channel,
                MAX(channel_width) as channel_width,
                MAX(band) as band,
                MAX(security) as security,
                SUM(frame_count * avg_signal_dbm) / SUM(frame_count) as avg_signal_dbm,
                SUM(client_count) as client_count,
                SUM(frame_count) as frame_count,
                MAX(hour) as last_seen,
                GROUP_CONCAT(DISTINCT node_id) as node_ids
            FROM wifi_metadata_hourly
            WHERE {tf_clause} AND bssid = ?
            GROUP BY bssid
            """,
            tf_params + [bssid],
        ).fetchone()

        if raw_row is None and hourly_row is None:
            return None

        if raw_row is not None and hourly_row is not None:
            raw = dict(raw_row)
            hourly = dict(hourly_row)
            raw_frames = raw["frame_count"]
            h_frames = hourly["frame_count"] or 0
            total = raw_frames + h_frames
            raw_signal = (raw.get("avg_signal_dbm") or 0.0) * raw_frames
            h_signal = (hourly.get("avg_signal_dbm") or 0.0) * h_frames

            network = raw  # Prefer raw for attribute columns
            network["frame_count"] = total
            network["client_count"] = max(
                raw["client_count"], hourly.get("client_count", 0)
            )
            if total > 0:
                network["avg_signal_dbm"] = (raw_signal + h_signal) / total
            # Merge node_ids
            raw_nodes = {n for n in (raw.get("node_ids") or "").split(",") if n}
            h_nodes = {n for n in (hourly.get("node_ids") or "").split(",") if n}
            network["node_ids"] = sorted(raw_nodes | h_nodes)
        elif raw_row is not None:
            network = dict(raw_row)
            node_str = network.get("node_ids", "")
            network["node_ids"] = [n for n in (node_str or "").split(",") if n]
        else:
            network = dict(hourly_row)
            node_str = network.get("node_ids", "")
            network["node_ids"] = [n for n in (node_str or "").split(",") if n]

        network["avg_signal_dbm"] = round(network.get("avg_signal_dbm") or 0.0, 1)
        return network

    # ------------------------------------------------------------------
    # Client queries
    # ------------------------------------------------------------------

    def get_wifi_clients(
        self,
        bssid: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Return client MACs associated with WiFi networks (raw + hourly).

        Parameters
        ----------
        bssid : str or None
            Filter by BSSID.
        limit : int
            Maximum results.
        """
        cache_key = TTLCache.make_key(
            "get_wifi_clients",
            bssid=bssid,
            limit=limit,
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        tf_clause, tf_params = self._ctx.tenant_filter()
        tf_clause_c = tf_clause.replace("tenant_id", "c.tenant_id")
        clauses = [tf_clause_c, "c.client_mac != ''"]
        params: list[Any] = list(tf_params)

        if bssid is not None:
            clauses.append("c.bssid = ?")
            params.append(bssid)

        where = " AND ".join(clauses)

        # -- Raw query --
        raw_sql = f"""
            SELECT
                c.client_mac,
                c.bssid,
                COALESCE(n.ssid, '') as ssid,
                AVG(c.signal_dbm) as avg_signal_dbm,
                AVG(c.data_rate_mbps) as avg_data_rate,
                COUNT(*) as frame_count,
                MAX(c.timestamp) as last_seen,
                MAX(c.client_vendor) as client_vendor
            FROM wifi_metadata c
            LEFT JOIN (
                SELECT bssid, MAX(ssid) as ssid
                FROM wifi_metadata
                WHERE {tf_clause} AND ssid != '' AND ssid IS NOT NULL
                GROUP BY bssid
            ) n ON c.bssid = n.bssid
            WHERE {where}
            GROUP BY c.client_mac, c.bssid
        """

        # -- Hourly aggregate query (expand client_macs_json via json_each) --
        tf_clause_h = tf_clause.replace("tenant_id", "h.tenant_id")
        h_clauses = [tf_clause_h, "j.value != ''"]
        h_params: list[Any] = list(tf_params)
        if bssid is not None:
            h_clauses.append("h.bssid = ?")
            h_params.append(bssid)
        h_where = " AND ".join(h_clauses)

        hourly_sql = f"""
            SELECT
                j.value as client_mac,
                h.bssid,
                MAX(h.ssid) as ssid,
                SUM(h.frame_count * h.avg_signal_dbm) / SUM(h.frame_count) as avg_signal_dbm,
                SUM(h.frame_count * h.avg_data_rate_mbps) / SUM(h.frame_count) as avg_data_rate,
                SUM(h.frame_count) as frame_count,
                MAX(h.hour) as last_seen
            FROM wifi_metadata_hourly h, json_each(h.client_macs_json) j
            WHERE {h_where}
            GROUP BY j.value, h.bssid
        """

        conn = self._ctx.get_conn()
        # raw_sql has tf_params for subquery + params for main WHERE
        raw_rows = conn.execute(raw_sql, list(tf_params) + params).fetchall()
        hourly_rows = conn.execute(hourly_sql, h_params).fetchall()

        # -- Merge by (client_mac, bssid) --
        merged: dict[tuple[str, str], dict[str, Any]] = {}
        for r in raw_rows:
            d = dict(r)
            key = (d["client_mac"], d["bssid"])
            d["_raw_frames"] = d["frame_count"]
            d["_raw_signal_sum"] = (d.get("avg_signal_dbm") or 0.0) * d["frame_count"]
            d["_raw_rate_sum"] = (d.get("avg_data_rate") or 0.0) * d["frame_count"]
            merged[key] = d

        for r in hourly_rows:
            h = dict(r)
            key = (h["client_mac"], h["bssid"])
            h_frames = h["frame_count"] or 0
            h_signal_sum = (h.get("avg_signal_dbm") or 0.0) * h_frames
            h_rate_sum = (h.get("avg_data_rate") or 0.0) * h_frames

            if key in merged:
                m = merged[key]
                total_frames = m["_raw_frames"] + h_frames
                m["frame_count"] = total_frames
                if total_frames > 0:
                    m["avg_signal_dbm"] = (
                        m["_raw_signal_sum"] + h_signal_sum
                    ) / total_frames
                    m["avg_data_rate"] = (
                        m["_raw_rate_sum"] + h_rate_sum
                    ) / total_frames
            else:
                h["_raw_frames"] = 0
                h["_raw_signal_sum"] = 0.0
                h["_raw_rate_sum"] = 0.0
                merged[key] = h

        # Sort by last_seen DESC, apply limit
        sorted_entries = sorted(
            merged.values(), key=lambda x: x.get("last_seen") or "", reverse=True
        )[:limit]
        results = []
        for entry in sorted_entries:
            entry.pop("_raw_frames", None)
            entry.pop("_raw_signal_sum", None)
            entry.pop("_raw_rate_sum", None)
            entry["avg_signal_dbm"] = round(entry.get("avg_signal_dbm") or 0.0, 1)
            entry["avg_data_rate"] = round(entry.get("avg_data_rate") or 0.0, 1)
            results.append(entry)
        self._ctx.cache.put(cache_key, results, ttl=30.0)
        return results

    # ------------------------------------------------------------------
    # Channel utilization
    # ------------------------------------------------------------------

    def get_wifi_channel_utilization(
        self,
        band: str = "2.4GHz",
        node_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Per-channel frame count and average signal (raw + hourly).

        Parameters
        ----------
        band : str
            Band filter (2.4GHz, 5GHz, 6GHz).
        node_id : str or None
            Optional node filter.
        """
        cache_key = TTLCache.make_key(
            "get_wifi_channel_utilization",
            band=band,
            node_id=node_id,
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses = [tf_clause, "band = ?", "channel > 0"]
        params: list[Any] = list(tf_params) + [band]

        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)

        where = " AND ".join(clauses)

        raw_sql = f"""
            SELECT
                channel,
                band,
                COUNT(*) as frame_count,
                AVG(signal_dbm) as avg_signal_dbm,
                COUNT(DISTINCT bssid) as network_count
            FROM wifi_metadata
            WHERE {where}
            GROUP BY channel
        """

        hourly_sql = f"""
            SELECT
                channel,
                band,
                SUM(frame_count) as frame_count,
                SUM(frame_count * avg_signal_dbm) / SUM(frame_count) as avg_signal_dbm,
                COUNT(DISTINCT bssid) as network_count
            FROM wifi_metadata_hourly
            WHERE {where}
            GROUP BY channel
        """

        conn = self._ctx.get_conn()
        raw_rows = conn.execute(raw_sql, params).fetchall()
        hourly_rows = conn.execute(hourly_sql, params).fetchall()

        # Merge by channel
        merged: dict[int, dict[str, Any]] = {}
        for r in raw_rows:
            d = dict(r)
            d["_signal_sum"] = (d.get("avg_signal_dbm") or 0.0) * d["frame_count"]
            d["_bssids"] = d["network_count"]
            merged[d["channel"]] = d

        for r in hourly_rows:
            h = dict(r)
            ch = h["channel"]
            h_frames = h["frame_count"] or 0
            h_signal_sum = (h.get("avg_signal_dbm") or 0.0) * h_frames
            if ch in merged:
                m = merged[ch]
                total = m["frame_count"] + h_frames
                m["_signal_sum"] += h_signal_sum
                m["frame_count"] = total
                if total > 0:
                    m["avg_signal_dbm"] = m["_signal_sum"] / total
                m["network_count"] = max(m["network_count"], h.get("network_count", 0))
            else:
                h["_signal_sum"] = h_signal_sum
                merged[ch] = h

        entries = sorted(merged.values(), key=lambda x: x["channel"])
        total_frames = sum(e["frame_count"] for e in entries) or 1
        for entry in entries:
            entry.pop("_signal_sum", None)
            entry.pop("_bssids", None)
            entry["avg_signal_dbm"] = round(entry.get("avg_signal_dbm") or 0.0, 1)
            entry["utilization_pct"] = round(
                (entry["frame_count"] / total_frames) * 100, 1
            )
        self._ctx.cache.put(cache_key, entries, ttl=30.0)
        return entries

    # ------------------------------------------------------------------
    # Timeline
    # ------------------------------------------------------------------

    def get_wifi_timeline(
        self,
        bssid: str | None = None,
        hours: int = 24,
    ) -> list[dict[str, Any]]:
        """Signal strength over time for a WiFi network (raw + hourly).

        Parameters
        ----------
        bssid : str or None
            BSSID filter.
        hours : int
            Lookback window.
        """
        cache_key = TTLCache.make_key(
            "get_wifi_timeline",
            bssid=bssid,
            hours=hours,
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        cutoff_hour = cutoff[:19]  # Truncate for hourly comparison

        tf_clause, tf_params = self._ctx.tenant_filter()

        # -- Raw query --
        raw_clauses = [tf_clause, "timestamp >= ?"]
        raw_params: list[Any] = list(tf_params) + [cutoff]
        if bssid is not None:
            raw_clauses.append("bssid = ?")
            raw_params.append(bssid)
        raw_where = " AND ".join(raw_clauses)

        raw_sql = f"""
            SELECT
                strftime('%Y-%m-%dT%H:00:00', timestamp) as hour,
                AVG(signal_dbm) as avg_signal_dbm,
                COUNT(*) as frame_count,
                COUNT(DISTINCT client_mac) as client_count
            FROM wifi_metadata
            WHERE {raw_where}
            GROUP BY hour
        """

        # -- Hourly aggregate query --
        h_clauses = [tf_clause, "hour >= ?"]
        h_params: list[Any] = list(tf_params) + [cutoff_hour]
        if bssid is not None:
            h_clauses.append("bssid = ?")
            h_params.append(bssid)
        h_where = " AND ".join(h_clauses)

        hourly_sql = f"""
            SELECT
                hour,
                SUM(frame_count * avg_signal_dbm) / SUM(frame_count) as avg_signal_dbm,
                SUM(frame_count) as frame_count,
                SUM(client_count) as client_count
            FROM wifi_metadata_hourly
            WHERE {h_where}
            GROUP BY hour
        """

        conn = self._ctx.get_conn()
        raw_rows = conn.execute(raw_sql, raw_params).fetchall()
        hourly_rows = conn.execute(hourly_sql, h_params).fetchall()

        # Merge by hour -- raw takes precedence for overlapping hours
        merged: dict[str, dict[str, Any]] = {}

        # Add hourly first so raw can override
        for r in hourly_rows:
            h = dict(r)
            hour = h["hour"]
            merged[hour] = {
                "hour": hour,
                "avg_signal_dbm": h.get("avg_signal_dbm") or 0.0,
                "frame_count": h["frame_count"] or 0,
                "client_count": h["client_count"] or 0,
                "_h_frames": h["frame_count"] or 0,
                "_h_signal_sum": (h.get("avg_signal_dbm") or 0.0)
                * (h["frame_count"] or 0),
            }

        for r in raw_rows:
            d = dict(r)
            hour = d["hour"]
            if hour in merged:
                # Combine raw + hourly with weighted average
                m = merged[hour]
                raw_frames = d["frame_count"]
                raw_signal = (d.get("avg_signal_dbm") or 0.0) * raw_frames
                total = raw_frames + m["_h_frames"]
                m["frame_count"] = total
                m["client_count"] = max(d["client_count"], m["client_count"])
                if total > 0:
                    m["avg_signal_dbm"] = (raw_signal + m["_h_signal_sum"]) / total
            else:
                merged[hour] = {
                    "hour": hour,
                    "avg_signal_dbm": d.get("avg_signal_dbm") or 0.0,
                    "frame_count": d["frame_count"],
                    "client_count": d["client_count"],
                }

        result = []
        for hour in sorted(merged):
            entry = merged[hour]
            entry.pop("_h_frames", None)
            entry.pop("_h_signal_sum", None)
            entry["avg_signal_dbm"] = round(entry["avg_signal_dbm"], 1)
            result.append(entry)

        self._ctx.cache.put(cache_key, result, ttl=12.0)
        return result

    # ------------------------------------------------------------------
    # Summary stats
    # ------------------------------------------------------------------

    def get_wifi_stats(self) -> dict[str, Any]:
        """Summary WiFi statistics (bounded to recent data).

        Returns
        -------
        dict
            total_networks, total_clients, busiest_channel, band_breakdown.
        """
        cache_key = TTLCache.make_key("get_wifi_stats")
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()
        # Bound all queries to recent data -- wifi_metadata grows ~200k rows/hour
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        ts_clause = "timestamp >= ?"

        # Single combined query: networks, clients, busiest channel, band breakdown
        row = conn.execute(
            f"SELECT COUNT(DISTINCT bssid) as net, "
            f"COUNT(DISTINCT CASE WHEN client_mac != '' THEN client_mac END) as cli "
            f"FROM wifi_metadata WHERE {tf_clause} AND bssid != '' AND {ts_clause}",
            tf_params + [cutoff],
        ).fetchone()
        total_networks = row["net"] if row else 0
        total_clients = row["cli"] if row else 0

        # Busiest channel
        row = conn.execute(
            f"SELECT channel, COUNT(*) as cnt FROM wifi_metadata "
            f"WHERE {tf_clause} AND channel > 0 AND {ts_clause} "
            f"GROUP BY channel ORDER BY cnt DESC LIMIT 1",
            tf_params + [cutoff],
        ).fetchone()
        busiest_channel = row["channel"] if row else 0

        # Band breakdown
        band_rows = conn.execute(
            f"SELECT band, COUNT(DISTINCT bssid) as network_count, COUNT(*) as frame_count "
            f"FROM wifi_metadata WHERE {tf_clause} AND bssid != '' AND {ts_clause} GROUP BY band",
            tf_params + [cutoff],
        ).fetchall()
        band_breakdown = {
            r["band"]: {
                "network_count": r["network_count"],
                "frame_count": r["frame_count"],
            }
            for r in band_rows
        }

        # Active WiFi node IDs (last 1 hour)
        node_cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        wifi_nodes = conn.execute(
            f"SELECT DISTINCT node_id FROM wifi_metadata "
            f"WHERE {tf_clause} AND node_id != '' AND timestamp >= ?",
            tf_params + [node_cutoff],
        ).fetchall()
        wifi_node_ids = [r["node_id"] for r in wifi_nodes]

        result = {
            "total_networks": total_networks,
            "total_clients": total_clients,
            "busiest_channel": busiest_channel,
            "band_breakdown": band_breakdown,
            "wifi_node_ids": wifi_node_ids,
        }
        self._ctx.cache.put(cache_key, result, ttl=30.0)
        return result

    # ------------------------------------------------------------------
    # Hourly aggregation
    # ------------------------------------------------------------------

    def aggregate_wifi_hourly(self, cutoff_hours: int = 2) -> int:
        """Roll up raw wifi_metadata into hourly summaries.

        Aggregates wifi_metadata rows older than *cutoff_hours* into
        ``wifi_metadata_hourly``.  Uses INSERT OR REPLACE on the
        unique ``(hour, bssid, channel, band, node_id)`` index so
        re-runs are idempotent.

        Parameters
        ----------
        cutoff_hours : int
            Only aggregate rows whose timestamp is older than this
            many hours ago.  Default 2 provides a safety margin before
            the 4-hour raw purge.

        Returns
        -------
        int
            Number of aggregate rows written.
        """
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=cutoff_hours)
        ).isoformat()

        sql = """
            INSERT OR REPLACE INTO wifi_metadata_hourly
                (hour, bssid, ssid, channel, channel_width, band, security,
                 node_id, avg_signal_dbm, min_signal_dbm, max_signal_dbm,
                 avg_noise_dbm, frame_count, client_count,
                 avg_data_rate_mbps, retry_count, client_macs_json, vendor)
            SELECT
                strftime('%Y-%m-%dT%H:00:00', timestamp) as hour,
                bssid,
                MAX(ssid) as ssid,
                channel,
                MAX(channel_width) as channel_width,
                band,
                MAX(security) as security,
                node_id,
                AVG(signal_dbm) as avg_signal_dbm,
                MIN(signal_dbm) as min_signal_dbm,
                MAX(signal_dbm) as max_signal_dbm,
                AVG(noise_dbm) as avg_noise_dbm,
                COUNT(*) as frame_count,
                COUNT(DISTINCT CASE WHEN client_mac != '' THEN client_mac END) as client_count,
                AVG(data_rate_mbps) as avg_data_rate_mbps,
                SUM(retry_flag) as retry_count,
                '[' || COALESCE(
                    GROUP_CONCAT(DISTINCT CASE WHEN client_mac != '' THEN '"' || client_mac || '"' END),
                    ''
                ) || ']' as client_macs_json,
                MAX(vendor) as vendor
            FROM wifi_metadata
            WHERE timestamp < ? AND tenant_id = ?
            GROUP BY hour, bssid, channel, band, node_id
        """

        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(sql, [cutoff, self._ctx.tenant_id])
        self._ctx.cache.invalidate()
        count = cursor.rowcount
        if count > 0:
            logger.info("Aggregated %d wifi hourly buckets", count)
        return count

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup_wifi_metadata(self, max_age_hours: int = 24) -> int:
        """Delete WiFi metadata rows older than *max_age_hours*.

        wifi_metadata grows rapidly (~400k rows/hour from edge scans).
        Deletes in batches of 50k to avoid holding the write lock too
        long and causing SQLITE_BUSY errors on concurrent ingest.

        Parameters
        ----------
        max_age_hours : int
            Maximum age in hours for WiFi metadata rows.

        Returns
        -------
        int
            Number of rows deleted.
        """
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        ).isoformat()

        tf_clause, tf_params = self._ctx.tenant_filter()
        total_deleted = 0
        batch_size = 50_000

        while True:
            with self._ctx.write_transaction() as conn:
                cursor = conn.execute(
                    f"DELETE FROM wifi_metadata WHERE rowid IN ("
                    f"SELECT rowid FROM wifi_metadata "
                    f"WHERE {tf_clause} AND timestamp < ? LIMIT ?)",
                    tf_params + [cutoff, batch_size],
                )
            deleted = cursor.rowcount
            total_deleted += deleted
            if deleted < batch_size:
                break

        if total_deleted > 0:
            self._ctx.cache.invalidate()
            logger.info(
                "Cleaned up %d wifi metadata rows older than %d hours",
                total_deleted,
                max_age_hours,
            )
        return total_deleted

    def cleanup_wifi_hourly(self, max_age_days: int = 90) -> int:
        """Delete hourly WiFi summaries older than *max_age_days*.

        Parameters
        ----------
        max_age_days : int
            Maximum age in days for hourly summary rows.

        Returns
        -------
        int
            Number of rows deleted.
        """
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=max_age_days)
        ).isoformat()[:19]  # Truncate to match hour format YYYY-MM-DDTHH:00:00

        tf_clause, tf_params = self._ctx.tenant_filter()
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                f"DELETE FROM wifi_metadata_hourly WHERE {tf_clause} AND hour < ?",
                tf_params + [cutoff],
            )
        self._ctx.cache.invalidate()
        deleted = cursor.rowcount
        if deleted > 0:
            logger.info(
                "Cleaned up %d wifi hourly summaries older than %d days",
                deleted,
                max_age_days,
            )
        return deleted
