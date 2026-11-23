"""Spectrum snapshot storage for wideband FFT monitoring.

Stores raw PSD (power spectral density) snapshots from edge nodes,
provides per-node latest views, history queries, peak detection with
cross-referencing against classified detections, sweep stitching,
historical PSD comparison, and cleanup.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Maximum gap between adjacent snapshot bandwidths for stitching (Hz).
# Snapshots with edges within this tolerance are considered contiguous.
_STITCH_GAP_TOLERANCE_HZ = 50_000  # 50 kHz


class SpectrumSnapshotStore:
    """CRUD and analytics for the ``spectrum_snapshots`` table.

    Parameters
    ----------
    ctx : SharedContext
        Shared storage infrastructure (connection, lock, cache).
    """

    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    # -- Insert -------------------------------------------------------------

    def insert_snapshot(self, snapshot: dict[str, Any]) -> int:
        """Insert a single spectrum snapshot and return the row id."""
        psd_json = snapshot.get("psd_dbm")
        if isinstance(psd_json, (list, tuple)):
            psd_json = json.dumps(psd_json)

        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                """
                INSERT INTO spectrum_snapshots
                    (node_id, timestamp, center_freq_hz, bandwidth_hz,
                     fft_size, bin_width_hz, psd_dbm,
                     noise_floor_dbm, peak_freq_hz, peak_power_dbm,
                     tenant_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot["node_id"],
                    snapshot["timestamp"],
                    snapshot["center_freq_hz"],
                    snapshot["bandwidth_hz"],
                    snapshot["fft_size"],
                    snapshot.get("bin_width_hz", 0.0),
                    psd_json,
                    snapshot.get("noise_floor_dbm"),
                    snapshot.get("peak_freq_hz"),
                    snapshot.get("peak_power_dbm"),
                    self._ctx.tenant_id,
                ),
            )
        return cursor.lastrowid  # type: ignore[return-value]

    # -- Queries ------------------------------------------------------------

    def get_snapshots(
        self,
        node_id: str | None = None,
        hours: int = 1,
        center_freq_hz: float | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Return snapshots within a time window, optionally filtered."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        tf_clause, tf_params = self._ctx.tenant_filter()

        clauses = [tf_clause, "timestamp >= ?"]
        params: list[Any] = list(tf_params) + [cutoff]

        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)
        if center_freq_hz is not None:
            clauses.append("center_freq_hz = ?")
            params.append(center_freq_hz)

        where = " AND ".join(clauses)
        conn = self._ctx.get_conn()
        rows = conn.execute(
            f"""
            SELECT id, node_id, timestamp, center_freq_hz, bandwidth_hz,
                   fft_size, bin_width_hz, psd_dbm,
                   noise_floor_dbm, peak_freq_hz, peak_power_dbm
            FROM spectrum_snapshots
            WHERE {where}
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            params + [limit],
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_latest_per_node(self) -> list[dict[str, Any]]:
        """Return the most recent snapshot for each node."""
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()
        rows = conn.execute(
            f"""
            SELECT s.*
            FROM spectrum_snapshots s
            INNER JOIN (
                SELECT node_id, MAX(timestamp) AS max_ts
                FROM spectrum_snapshots
                WHERE {tf_clause}
                GROUP BY node_id
            ) latest ON s.node_id = latest.node_id AND s.timestamp = latest.max_ts
            WHERE s.{tf_clause.split("=")[0].strip()} = ?
            """,
            tf_params + tf_params,
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_wideband_view(
        self,
        node_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return latest snapshot(s) for wideband view.

        If *node_id* is given, returns only the latest for that node.
        Otherwise returns the latest per node.
        """
        if node_id is not None:
            tf_clause, tf_params = self._ctx.tenant_filter()
            conn = self._ctx.get_conn()
            rows = conn.execute(
                f"""
                SELECT *
                FROM spectrum_snapshots
                WHERE {tf_clause} AND node_id = ?
                ORDER BY timestamp DESC
                LIMIT 1
                """,
                tf_params + [node_id],
            ).fetchall()
            return [self._row_to_dict(r) for r in rows]
        return self.get_latest_per_node()

    # -- Peak detection -----------------------------------------------------

    def detect_peaks(
        self,
        hours: int = 4,
        threshold_db: float = 10.0,
        min_power_dbm: float | None = None,
    ) -> list[dict[str, Any]]:
        """Find peaks above noise floor in recent snapshots.

        Each peak is cross-referenced against the detections table
        to flag classified vs unclassified signals.
        """
        snapshots = self.get_snapshots(hours=hours, limit=5000)
        peaks: list[dict[str, Any]] = []

        for snap in snapshots:
            psd = snap.get("psd_dbm")
            if not psd or not isinstance(psd, list):
                continue

            noise_floor = snap.get("noise_floor_dbm")
            if noise_floor is None:
                # Estimate noise floor as median of PSD
                sorted_psd = sorted(psd)
                noise_floor = sorted_psd[len(sorted_psd) // 2]

            center_freq = snap["center_freq_hz"]
            bandwidth = snap["bandwidth_hz"]
            fft_size = snap["fft_size"]
            bin_width = bandwidth / fft_size if fft_size > 0 else 0
            start_freq = center_freq - bandwidth / 2

            for i, power in enumerate(psd):
                if power is None:
                    continue
                if power < noise_floor + threshold_db:
                    continue
                if min_power_dbm is not None and power < min_power_dbm:
                    continue

                freq_hz = start_freq + i * bin_width
                peaks.append(
                    {
                        "freq_hz": round(freq_hz, 0),
                        "power_dbm": round(power, 2),
                        "node_id": snap["node_id"],
                        "timestamp": snap["timestamp"],
                        "noise_floor_dbm": round(noise_floor, 2),
                        "classified": False,  # Will be updated below
                    }
                )

        # Cross-reference with detections to flag classified peaks
        if peaks:
            self._flag_classified_peaks(peaks, hours)
            return peaks

        # Fallback: derive peaks from detections when no spectrum snapshots
        return self._peaks_from_detections(hours, min_power_dbm)

    def _peaks_from_detections(
        self,
        hours: int,
        min_power_dbm: float | None = None,
    ) -> list[dict[str, Any]]:
        """Synthesize peaks from detection records when no spectrum snapshots exist."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()

        power_filter = ""
        extra_params: list[Any] = []
        if min_power_dbm is not None:
            power_filter = "AND power_dbm >= ?"
            extra_params = [min_power_dbm]

        rows = conn.execute(
            f"""
            SELECT freq_hz, node_id, signal_class, power_dbm, snr_db,
                   MAX(timestamp) as timestamp
            FROM detections
            WHERE {tf_clause} AND timestamp >= ? AND freq_hz > 0
                  AND power_dbm IS NOT NULL {power_filter}
            GROUP BY node_id, CAST(freq_hz / 100000 AS INTEGER), signal_class
            ORDER BY power_dbm DESC
            LIMIT 200
            """,
            tf_params + [cutoff] + extra_params,
        ).fetchall()

        peaks: list[dict[str, Any]] = []
        for r in rows:
            peaks.append(
                {
                    "freq_hz": round(r["freq_hz"], 0),
                    "power_dbm": round(r["power_dbm"], 2),
                    "node_id": r["node_id"],
                    "timestamp": r["timestamp"],
                    "noise_floor_dbm": round(r["power_dbm"] - (r["snr_db"] or 10.0), 2),
                    "classified": True,
                    "signal_class": r["signal_class"],
                }
            )

        return peaks

    def _flag_classified_peaks(
        self,
        peaks: list[dict[str, Any]],
        hours: int,
    ) -> None:
        """Mark peaks as classified if they match a known detection.

        Enhanced: also populates ``signal_class`` on classified peaks.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()

        rows = conn.execute(
            f"""
            SELECT freq_hz, node_id, signal_class
            FROM detections
            WHERE {tf_clause} AND timestamp >= ? AND freq_hz > 0
            """,
            tf_params + [cutoff],
        ).fetchall()

        # Build a map of (node_id, freq_bucket) -> signal_class for lookup.
        # For each bucket keep the most recent (last in results) class.
        classified_map: dict[tuple[str, int], str] = {}
        for r in rows:
            bucket = int(r["freq_hz"] / 100_000)  # 100 kHz buckets
            classified_map[(r["node_id"], bucket)] = r["signal_class"]

        for peak in peaks:
            bucket = int(peak["freq_hz"] / 100_000)
            key = (peak["node_id"], bucket)
            if key in classified_map:
                peak["classified"] = True
                peak["signal_class"] = classified_map[key]
            else:
                peak["signal_class"] = None

    # -- Sweep stitching ----------------------------------------------------

    def stitch_sweeps(
        self,
        node_id: str,
        minutes: int = 5,
    ) -> dict[str, Any] | None:
        """Stitch recent snapshots from a node into a combined wideband view.

        Finds all snapshots from *node_id* within the last *minutes*,
        sorts them by start frequency, and merges adjacent/overlapping
        segments into a single wideband PSD array.

        Returns a dict with ``start_freq_hz``, ``end_freq_hz``,
        ``total_bins``, ``bin_width_hz``, ``psd_dbm``, ``noise_floor_dbm``,
        ``node_id``, and ``timestamp`` (latest).  Returns ``None`` if no
        snapshots are available.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()

        rows = conn.execute(
            f"""
            SELECT id, node_id, timestamp, center_freq_hz, bandwidth_hz,
                   fft_size, bin_width_hz, psd_dbm,
                   noise_floor_dbm, peak_freq_hz, peak_power_dbm
            FROM spectrum_snapshots
            WHERE {tf_clause} AND node_id = ? AND timestamp >= ?
            ORDER BY center_freq_hz ASC
            """,
            tf_params + [node_id, cutoff],
        ).fetchall()

        if not rows:
            return None

        snapshots = [self._row_to_dict(r) for r in rows]

        # Deduplicate: for each center_freq, keep the latest snapshot only
        freq_map: dict[float, dict[str, Any]] = {}
        for s in snapshots:
            cf = s["center_freq_hz"]
            if cf not in freq_map or s["timestamp"] > freq_map[cf]["timestamp"]:
                freq_map[cf] = s

        segments = sorted(freq_map.values(), key=lambda s: s["center_freq_hz"])

        if len(segments) == 1:
            seg = segments[0]
            psd = seg["psd_dbm"] if isinstance(seg["psd_dbm"], list) else []
            bw = seg["bandwidth_hz"]
            start_f = seg["center_freq_hz"] - bw / 2
            return {
                "node_id": node_id,
                "timestamp": seg["timestamp"],
                "start_freq_hz": start_f,
                "end_freq_hz": start_f + bw,
                "total_bins": len(psd),
                "bin_width_hz": seg["bin_width_hz"],
                "psd_dbm": psd,
                "noise_floor_dbm": seg.get("noise_floor_dbm"),
                "segment_count": 1,
            }

        # Stitch multiple segments
        # Use the bin_width from the first segment (assumed uniform)
        bin_width = segments[0]["bin_width_hz"]
        if bin_width <= 0:
            bin_width = segments[0]["bandwidth_hz"] / max(segments[0]["fft_size"], 1)

        stitched_psd: list[float | None] = []
        global_start = segments[0]["center_freq_hz"] - segments[0]["bandwidth_hz"] / 2
        current_end = global_start
        latest_ts = segments[0]["timestamp"]

        for seg in segments:
            psd = seg["psd_dbm"] if isinstance(seg["psd_dbm"], list) else []
            if not psd:
                continue
            seg_start = seg["center_freq_hz"] - seg["bandwidth_hz"] / 2
            seg_end = seg["center_freq_hz"] + seg["bandwidth_hz"] / 2

            if seg["timestamp"] > latest_ts:
                latest_ts = seg["timestamp"]

            # Check for gap
            gap = seg_start - current_end
            if gap > _STITCH_GAP_TOLERANCE_HZ:
                # Fill gap with None values
                gap_bins = max(1, int(gap / bin_width))
                stitched_psd.extend([None] * gap_bins)
            elif gap < -_STITCH_GAP_TOLERANCE_HZ:
                # Overlap: skip overlapping bins from this segment
                overlap_bins = int(abs(gap) / bin_width)
                psd = psd[overlap_bins:]

            stitched_psd.extend(psd)
            current_end = max(current_end, seg_end)

        # Compute composite noise floor (median of all non-None values)
        valid_vals = [v for v in stitched_psd if v is not None]
        noise_floor = None
        if valid_vals:
            valid_vals.sort()
            mid = len(valid_vals) // 2
            noise_floor = (
                valid_vals[mid]
                if len(valid_vals) % 2 == 1
                else (valid_vals[mid - 1] + valid_vals[mid]) / 2
            )

        return {
            "node_id": node_id,
            "timestamp": latest_ts,
            "start_freq_hz": global_start,
            "end_freq_hz": current_end,
            "total_bins": len(stitched_psd),
            "bin_width_hz": bin_width,
            "psd_dbm": stitched_psd,
            "noise_floor_dbm": noise_floor,
            "segment_count": len(segments),
        }

    # -- Historical PSD comparison ------------------------------------------

    def compare_psd(
        self,
        node_id: str,
        hours: int = 4,
        center_freq_hz: float | None = None,
    ) -> dict[str, Any] | None:
        """Compare current PSD to historical average.

        Returns the current PSD, the historical average PSD, and a
        per-bin delta (current minus average) in dB.  Also identifies
        new peaks that appear only in the current snapshot.

        Parameters
        ----------
        node_id : str
            Edge node identifier.
        hours : int
            How many hours of history to average over.
        center_freq_hz : float or None
            If specified, restrict to snapshots at this center frequency.

        Returns
        -------
        dict or None
            ``current_psd``, ``avg_psd``, ``delta_db``, ``new_peaks``,
            frequency metadata, and ``snapshot_count``.
        """
        # Get historical snapshots
        historical = self.get_snapshots(
            node_id=node_id,
            hours=hours,
            center_freq_hz=center_freq_hz,
            limit=5000,
        )

        if not historical:
            return None

        # The most recent is the "current" snapshot
        current = historical[0]
        current_psd = current.get("psd_dbm")
        if not current_psd or not isinstance(current_psd, list):
            return None

        n_bins = len(current_psd)

        # Compute average across all historical snapshots (including current)
        sum_psd = [0.0] * n_bins
        count_psd = [0] * n_bins

        for snap in historical:
            psd = snap.get("psd_dbm")
            if not isinstance(psd, list) or len(psd) != n_bins:
                continue
            for i in range(n_bins):
                if psd[i] is not None:
                    sum_psd[i] += psd[i]
                    count_psd[i] += 1

        avg_psd: list[float | None] = []
        delta_db: list[float | None] = []
        for i in range(n_bins):
            if count_psd[i] > 0:
                avg_val = sum_psd[i] / count_psd[i]
                avg_psd.append(round(avg_val, 2))
                if current_psd[i] is not None:
                    delta_db.append(round(current_psd[i] - avg_val, 2))
                else:
                    delta_db.append(None)
            else:
                avg_psd.append(None)
                delta_db.append(None)

        # Identify new peaks: bins where delta > threshold AND current is
        # above noise floor
        noise_floor = current.get("noise_floor_dbm")
        if noise_floor is None and current_psd:
            sorted_vals = sorted(v for v in current_psd if v is not None)
            noise_floor = sorted_vals[len(sorted_vals) // 2] if sorted_vals else -100.0

        bandwidth = current["bandwidth_hz"]
        center_freq = current["center_freq_hz"]
        start_freq = center_freq - bandwidth / 2
        fft_size = current["fft_size"]
        bin_width = bandwidth / fft_size if fft_size > 0 else 0

        new_peaks: list[dict[str, Any]] = []
        _DELTA_THRESHOLD = 6.0  # dB above average to flag as new

        for i in range(n_bins):
            if delta_db[i] is None or current_psd[i] is None:
                continue
            if noise_floor is not None and current_psd[i] < noise_floor + 6.0:
                continue
            if delta_db[i] >= _DELTA_THRESHOLD:
                new_peaks.append(
                    {
                        "bin_index": i,
                        "freq_hz": round(start_freq + i * bin_width, 0),
                        "current_dbm": round(current_psd[i], 2),
                        "avg_dbm": avg_psd[i],
                        "delta_db": delta_db[i],
                    }
                )

        return {
            "node_id": node_id,
            "timestamp": current["timestamp"],
            "center_freq_hz": center_freq,
            "bandwidth_hz": bandwidth,
            "fft_size": fft_size,
            "bin_width_hz": bin_width,
            "current_psd": current_psd,
            "avg_psd": avg_psd,
            "delta_db": delta_db,
            "noise_floor_dbm": noise_floor,
            "new_peaks": new_peaks,
            "snapshot_count": len(historical),
        }

    # -- Cleanup ------------------------------------------------------------

    def cleanup_old(self, max_age_hours: int = 24) -> int:
        """Delete snapshots older than *max_age_hours*. Returns count."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        ).isoformat()
        tf_clause, tf_params = self._ctx.tenant_filter()
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                f"DELETE FROM spectrum_snapshots WHERE {tf_clause} AND timestamp < ?",
                tf_params + [cutoff],
            )
        return cursor.rowcount

    # -- Helpers ------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: Any) -> dict[str, Any]:
        """Convert a sqlite3.Row to a plain dict, parsing PSD JSON."""
        d = dict(row)
        psd_raw = d.get("psd_dbm")
        if isinstance(psd_raw, str):
            try:
                d["psd_dbm"] = json.loads(psd_raw)
            except (json.JSONDecodeError, TypeError):
                d["psd_dbm"] = []
        return d
