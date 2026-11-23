"""Spectrum occupancy analytics queries.

Sub-store that provides frequency-band occupancy, waterfall (time-frequency
matrix), pre-defined band summaries, and recent activity timeline.  Queries
run against the ``spectrum_all`` view which unifies RF detections, WiFi
metadata, Bluetooth devices, and Zigbee devices into a single virtual table
with consistent columns (freq_hz, power_dbm, signal_class, etc.).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sigrift.bridge.cache import MISSING, TTLCache

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pre-defined RF bands (label, min_hz, max_hz)
# ---------------------------------------------------------------------------

# Bands are ordered most-specific first.  ``get_band_summary()`` assigns each
# detection to the *first* matching band so that narrow/specific allocations
# take priority over broader ones, avoiding double-counting.
KNOWN_BANDS: list[tuple[str, float, float]] = [
    # --- Specific / narrow bands (matched first) ---
    ("FM Broadcast", 88_000_000, 108_000_000),
    ("VHF Air", 108_000_000, 137_000_000),
    ("Marine VHF", 156_000_000, 162_000_000),
    ("UHF 220 MHz", 220_000_000, 225_000_000),
    ("UHF 433 ISM", 433_050_000, 434_790_000),
    ("PMR446", 446_000_000, 446_200_000),
    ("UHF 70cm Ham", 420_000_000, 450_000_000),
    ("UHF 868 ISM", 863_000_000, 870_000_000),
    ("UHF 915 ISM", 902_000_000, 928_000_000),
    ("GSM 900", 880_000_000, 960_000_000),
    ("GPS L1", 1_565_000_000, 1_585_000_000),
    ("GSM 1800", 1_710_000_000, 1_880_000_000),
    ("UMTS 2100", 1_920_000_000, 2_170_000_000),
    ("Bluetooth", 2_400_000_000, 2_483_500_000),
    ("Zigbee 2.4 GHz", 2_405_000_000, 2_480_000_000),
    ("WiFi 2.4 GHz", 2_400_000_000, 2_500_000_000),
    ("LTE B7", 2_500_000_000, 2_690_000_000),
    ("WiFi 5 GHz", 5_150_000_000, 5_850_000_000),
    # --- Broad / catch-all bands (matched last) ---
    ("LF/MF", 30_000, 3_000_000),
    ("HF (Shortwave)", 3_000_000, 30_000_000),
    ("VHF Low", 30_000_000, 88_000_000),
    ("VHF High", 137_000_000, 174_000_000),
]


class SpectrumAnalyticsStore:
    """Spectrum occupancy and waterfall analytics on the spectrum_all view.

    Parameters
    ----------
    ctx : SharedContext
        Shared storage infrastructure (connection, lock, cache).
    """

    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    def _spectrum_table(self) -> str:
        """Return the best available spectrum source table.

        Prefers ``spectrum_materialized`` (a real table refreshed
        periodically by :class:`SpectrumMaterializer`) over the
        ``spectrum_all`` view which is a slow UNION ALL.  Falls back
        to the view when the materialized table doesn't exist or is
        empty.
        """
        try:
            conn = self._ctx.get_conn()
            row = conn.execute("SELECT COUNT(*) FROM spectrum_materialized").fetchone()
            if row and row[0] > 0:
                return "spectrum_materialized"
        except Exception:
            pass
        return "spectrum_all"

    # -- Occupancy ----------------------------------------------------------

    def get_occupancy(
        self,
        hours: int = 24,
        bin_width_hz: int = 1_000_000,
        node_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return frequency-band occupancy over *hours*.

        Each row represents a frequency bin of *bin_width_hz* width.
        ``occupancy_pct`` is the fraction of *time_resolution* buckets
        (60 s) that contained at least one detection.
        """
        cache_key = TTLCache.make_key(
            "spectrum_occupancy",
            tenant_id=self._ctx.tenant_id,
            hours=hours,
            bin_width_hz=bin_width_hz,
            node_id=node_id,
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        total_slots = max(1, hours * 60)  # 1-minute time slots

        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses = [tf_clause, "timestamp >= ?", "freq_hz > 0"]
        params: list[Any] = list(tf_params) + [cutoff]
        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)
        where = " AND ".join(clauses)

        table = self._spectrum_table()
        sql = f"""
            SELECT
                CAST(freq_hz / ? AS INTEGER) * ? AS center_freq_hz,
                ? AS bin_width_hz,
                COUNT(DISTINCT CAST(strftime('%s', timestamp) / 60 AS INTEGER)) * 100.0 / ? AS occupancy_pct,
                AVG(power_dbm) AS avg_power_dbm,
                MAX(power_dbm) AS peak_power_dbm,
                COUNT(*) AS signal_count,
                MIN(timestamp) AS first_seen,
                MAX(timestamp) AS last_seen
            FROM {table}
            WHERE {where}
            GROUP BY CAST(freq_hz / ? AS INTEGER)
            ORDER BY center_freq_hz
        """
        params_full = (
            [bin_width_hz, bin_width_hz, bin_width_hz, total_slots]
            + params
            + [bin_width_hz]
        )

        conn = self._ctx.get_conn()
        rows = conn.execute(sql, params_full).fetchall()

        # Second pass: dominant class per bin
        dom_sql = f"""
            SELECT
                CAST(freq_hz / ? AS INTEGER) AS freq_bin,
                signal_class,
                COUNT(*) AS cnt
            FROM {table}
            WHERE {where}
            GROUP BY freq_bin, signal_class
            ORDER BY freq_bin, cnt DESC
        """
        dom_params = [bin_width_hz] + params
        dom_rows = conn.execute(dom_sql, dom_params).fetchall()

        dominant_map: dict[int, str] = {}
        for r in dom_rows:
            fb = r["freq_bin"]
            if fb not in dominant_map:
                dominant_map[fb] = r["signal_class"]

        # Third pass: average bandwidth per bin
        bw_sql = f"""
            SELECT
                CAST(freq_hz / ? AS INTEGER) AS freq_bin,
                AVG(bandwidth_hz) AS avg_bandwidth_hz
            FROM {table}
            WHERE {where} AND bandwidth_hz IS NOT NULL AND bandwidth_hz > 0
            GROUP BY freq_bin
        """
        bw_params = [bin_width_hz] + params
        bw_rows = conn.execute(bw_sql, bw_params).fetchall()
        bw_map: dict[int, float] = {}
        for br in bw_rows:
            bw_map[br["freq_bin"]] = round(br["avg_bandwidth_hz"] or 0.0, 1)

        result = []
        for r in rows:
            bin_floor = r["center_freq_hz"]
            freq_bin = int(bin_floor / bin_width_hz)
            center = bin_floor + bin_width_hz / 2
            avg_bw = bw_map.get(freq_bin)
            entry: dict[str, Any] = {
                "center_freq_hz": center,
                "bin_width_hz": bin_width_hz,
                "occupancy_pct": round(min(r["occupancy_pct"] or 0.0, 100.0), 2),
                "avg_power_dbm": round(r["avg_power_dbm"] or 0.0, 2),
                "peak_power_dbm": round(r["peak_power_dbm"] or 0.0, 2),
                "signal_count": r["signal_count"],
                "dominant_class": dominant_map.get(freq_bin, "unknown"),
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
                "avg_bandwidth_hz": avg_bw,
            }
            result.append(entry)

        self._ctx.cache.put(cache_key, result, ttl=15.0)
        return result

    # -- Waterfall ----------------------------------------------------------

    def get_waterfall(
        self,
        hours: int = 1,
        freq_min_hz: float | None = None,
        freq_max_hz: float | None = None,
        time_resolution_sec: int = 60,
        bin_width_hz: int = 1_000_000,
        node_id: str | None = None,
    ) -> dict[str, Any]:
        """Return time-frequency power matrix for waterfall display."""
        cache_key = TTLCache.make_key(
            "spectrum_waterfall",
            tenant_id=self._ctx.tenant_id,
            hours=hours,
            freq_min_hz=freq_min_hz,
            freq_max_hz=freq_max_hz,
            time_resolution_sec=time_resolution_sec,
            bin_width_hz=bin_width_hz,
            node_id=node_id,
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses = [tf_clause, "timestamp >= ?", "freq_hz > 0"]
        params: list[Any] = list(tf_params) + [cutoff]
        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)
        if freq_min_hz is not None:
            clauses.append("freq_hz >= ?")
            params.append(freq_min_hz)
        if freq_max_hz is not None:
            clauses.append("freq_hz <= ?")
            params.append(freq_max_hz)
        where = " AND ".join(clauses)

        table = self._spectrum_table()
        sql = f"""
            SELECT
                CAST(strftime('%s', timestamp) / ? AS INTEGER) * ? AS time_bucket,
                CAST(freq_hz / ? AS INTEGER) * ? AS freq_bucket,
                AVG(power_dbm) AS avg_power,
                signal_class
            FROM {table}
            WHERE {where}
            GROUP BY time_bucket, freq_bucket
            ORDER BY time_bucket, freq_bucket
        """
        params_full = [
            time_resolution_sec,
            time_resolution_sec,
            bin_width_hz,
            bin_width_hz,
        ] + params

        conn = self._ctx.get_conn()
        rows = conn.execute(sql, params_full).fetchall()

        if not rows:
            result: dict[str, Any] = {
                "time_bins": [],
                "freq_bins": [],
                "power_matrix": [],
                "signal_matrix": [],
            }
            self._ctx.cache.put(cache_key, result, ttl=10.0)
            return result

        # Collect unique sorted bins
        time_set: set[int] = set()
        freq_set: set[int] = set()
        data_map: dict[tuple[int, int], tuple[float, str]] = {}

        for r in rows:
            tb = int(r["time_bucket"])
            fb = int(r["freq_bucket"])
            time_set.add(tb)
            freq_set.add(fb)
            data_map[(tb, fb)] = (
                round(r["avg_power"] or -100.0, 1),
                r["signal_class"] or "",
            )

        time_bins = sorted(time_set)
        freq_bins = sorted(freq_set)
        time_idx = {t: i for i, t in enumerate(time_bins)}
        freq_idx = {f: i for i, f in enumerate(freq_bins)}

        n_time = len(time_bins)
        n_freq = len(freq_bins)
        power_matrix: list[list[float | None]] = [
            [None] * n_freq for _ in range(n_time)
        ]
        signal_matrix: list[list[str | None]] = [[None] * n_freq for _ in range(n_time)]

        for (tb, fb), (pwr, sig) in data_map.items():
            ti = time_idx[tb]
            fi = freq_idx[fb]
            power_matrix[ti][fi] = pwr
            signal_matrix[ti][fi] = sig

        # Convert epoch timestamps to ISO
        time_labels = [
            datetime.fromtimestamp(t, tz=timezone.utc).isoformat() for t in time_bins
        ]

        result = {
            "time_bins": time_labels,
            "freq_bins": freq_bins,
            "power_matrix": power_matrix,
            "signal_matrix": signal_matrix,
        }
        self._ctx.cache.put(cache_key, result, ttl=10.0)
        return result

    # -- Band summary -------------------------------------------------------

    def get_band_summary(
        self,
        hours: int = 24,
        node_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return occupancy stats for pre-defined frequency bands."""
        cache_key = TTLCache.make_key(
            "spectrum_bands",
            tenant_id=self._ctx.tenant_id,
            hours=hours,
            node_id=node_id,
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        total_slots = max(1, hours * 60)

        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses = [tf_clause, "timestamp >= ?", "freq_hz > 0"]
        params: list[Any] = list(tf_params) + [cutoff]
        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)
        where = " AND ".join(clauses)

        conn = self._ctx.get_conn()
        table = self._spectrum_table()

        # Single query: fetch per-row freq/power/class/time-slot for binning
        rows = conn.execute(
            f"""
            SELECT freq_hz, power_dbm, signal_class,
                   CAST(strftime('%s', timestamp) / 60 AS INTEGER) AS time_slot,
                   timestamp
            FROM {table}
            WHERE {where}
            """,
            params,
        ).fetchall()

        # Assign each row to the first matching band (most-specific first).
        # For overlapping bands (BT/Zigbee/WiFi all near 2.4 GHz), use
        # signal_class to route to the correct band.
        from collections import defaultdict

        band_data: dict[int, list] = defaultdict(list)  # band_idx -> rows

        _CLASS_BAND_OVERRIDE: dict[str, str] = {
            "bluetooth-le": "Bluetooth",
            "bluetooth-classic": "Bluetooth",
            "zigbee": "Zigbee 2.4 GHz",
            "wifi": "WiFi 2.4 GHz",  # 5 GHz handled by freq-range fallback
        }
        _band_name_to_idx = {label: i for i, (label, _, _) in enumerate(KNOWN_BANDS)}

        for r in rows:
            fhz = r["freq_hz"]
            cls = r["signal_class"]
            # Check class-based override first
            override_band = _CLASS_BAND_OVERRIDE.get(cls)
            if override_band and override_band in _band_name_to_idx:
                bi = _band_name_to_idx[override_band]
                _, min_hz, max_hz = KNOWN_BANDS[bi]
                # Only use override if freq is plausible for the band
                if min_hz - 100e6 <= fhz <= max_hz + 100e6:
                    band_data[bi].append(r)
                    continue
            # Fallback: first matching band by frequency
            for bi, (_, min_hz, max_hz) in enumerate(KNOWN_BANDS):
                if min_hz <= fhz <= max_hz:
                    band_data[bi].append(r)
                    break
            # Rows outside all bands are silently dropped

        result = []
        for bi, (label, min_hz, max_hz) in enumerate(KNOWN_BANDS):
            brows = band_data.get(bi, [])
            signal_count = len(brows)
            if signal_count:
                time_slots = {r["time_slot"] for r in brows}
                powers = [r["power_dbm"] for r in brows if r["power_dbm"] is not None]
                timestamps = [r["timestamp"] for r in brows if r["timestamp"]]
                class_counts: dict[str, int] = defaultdict(int)
                for r in brows:
                    class_counts[r["signal_class"]] += 1
                dominant = max(class_counts, key=class_counts.get)  # type: ignore[arg-type]
                result.append(
                    {
                        "band": label,
                        "min_hz": min_hz,
                        "max_hz": max_hz,
                        "signal_count": signal_count,
                        "occupancy_pct": round(
                            len(time_slots) * 100.0 / total_slots, 2
                        ),
                        "avg_power_dbm": round(sum(powers) / len(powers), 2)
                        if powers
                        else None,
                        "peak_power_dbm": round(max(powers), 2) if powers else None,
                        "dominant_class": dominant,
                        "first_seen": min(timestamps) if timestamps else None,
                        "last_seen": max(timestamps) if timestamps else None,
                    }
                )
            else:
                result.append(
                    {
                        "band": label,
                        "min_hz": min_hz,
                        "max_hz": max_hz,
                        "signal_count": 0,
                        "occupancy_pct": 0.0,
                        "avg_power_dbm": None,
                        "peak_power_dbm": None,
                        "dominant_class": None,
                        "first_seen": None,
                        "last_seen": None,
                    }
                )

        self._ctx.cache.put(cache_key, result, ttl=60.0)
        return result

    # -- Activity timeline --------------------------------------------------

    def get_activity(
        self,
        hours: int = 4,
        node_id: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Return recent spectrum activity as individual detections."""
        cache_key = TTLCache.make_key(
            "spectrum_activity",
            tenant_id=self._ctx.tenant_id,
            hours=hours,
            node_id=node_id,
            limit=limit,
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses = [tf_clause, "timestamp >= ?", "freq_hz > 0"]
        params: list[Any] = list(tf_params) + [cutoff]
        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)
        where = " AND ".join(clauses)

        # GROUP BY collapses protocol-scanner duplicates (wifi/bt scans can
        # produce hundreds of rows per sweep sharing the same timestamp) while
        # preserving individual RF detections which have unique detection_ids.
        table = self._spectrum_table()
        sql = f"""
            SELECT
                MAX(timestamp) AS timestamp,
                freq_hz,
                signal_class,
                MIN(power_dbm) AS power_dbm,
                MAX(confidence) AS confidence,
                node_id,
                bandwidth_hz
            FROM {table}
            WHERE {where}
            GROUP BY node_id, signal_class,
                     CAST(freq_hz / 1e6 AS INTEGER),
                     strftime('%Y-%m-%dT%H:%M', timestamp)
            ORDER BY timestamp DESC
            LIMIT ?
        """
        params.append(limit)

        conn = self._ctx.get_conn()
        rows = conn.execute(sql, params).fetchall()

        result = [
            {
                "timestamp": r["timestamp"],
                "freq_hz": r["freq_hz"],
                "signal_class": r["signal_class"],
                "power_dbm": r["power_dbm"],
                "duration_sec": None,  # Not tracked per-detection
                "confidence": r["confidence"],
                "node_id": r["node_id"],
                "bandwidth_hz": r["bandwidth_hz"],
            }
            for r in rows
        ]

        self._ctx.cache.put(cache_key, result, ttl=10.0)
        return result

    # -- Bandwidth distribution ---------------------------------------------

    def get_bandwidth_distribution(
        self,
        hours: int = 24,
        node_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return bandwidth statistics grouped by signal class.

        For each signal class observed in the last *hours*, returns
        the count, average/min/max bandwidth, and total occupied
        spectrum (sum of bandwidths).
        """
        cache_key = TTLCache.make_key(
            "spectrum_bandwidth_dist",
            tenant_id=self._ctx.tenant_id,
            hours=hours,
            node_id=node_id,
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses = [
            tf_clause,
            "timestamp >= ?",
            "bandwidth_hz IS NOT NULL",
            "bandwidth_hz > 0",
        ]
        params: list[Any] = list(tf_params) + [cutoff]
        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)
        where = " AND ".join(clauses)

        table = self._spectrum_table()
        sql = f"""
            SELECT
                signal_class,
                COUNT(*) AS detection_count,
                AVG(bandwidth_hz) AS avg_bandwidth_hz,
                MIN(bandwidth_hz) AS min_bandwidth_hz,
                MAX(bandwidth_hz) AS max_bandwidth_hz,
                SUM(bandwidth_hz) AS total_bandwidth_hz
            FROM {table}
            WHERE {where}
            GROUP BY signal_class
            ORDER BY detection_count DESC
        """

        conn = self._ctx.get_conn()
        rows = conn.execute(sql, params).fetchall()

        result = [
            {
                "signal_class": r["signal_class"],
                "detection_count": r["detection_count"],
                "avg_bandwidth_hz": round(r["avg_bandwidth_hz"] or 0.0, 1),
                "min_bandwidth_hz": r["min_bandwidth_hz"],
                "max_bandwidth_hz": r["max_bandwidth_hz"],
                "total_bandwidth_hz": r["total_bandwidth_hz"],
            }
            for r in rows
        ]

        self._ctx.cache.put(cache_key, result, ttl=15.0)
        return result
