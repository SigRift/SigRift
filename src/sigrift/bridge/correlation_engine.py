"""N-way cross-correlation engine across all signal sources.

Correlates SDR detections with WiFi, Bluetooth, Zigbee, and aircraft
scanner events for scoring enrichment and multi-source confirmation.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sigrift.bridge.storage.base import sqlite_transaction

logger = logging.getLogger(__name__)


@dataclass
class CrossCorrelation:
    """Result of a cross-correlation check."""

    source_a: str
    source_a_id: str | None
    source_b: str
    source_b_id: str | None
    freq_hz: float
    time_delta_ms: float
    correlation_type: str  # confirmed, unmatched_sdr, unmatched_protocol, multi_source
    node_id: str
    timestamp: str


class PerNodeThrottle:
    """Lets every Nth call per ``node_id`` through; drops the rest.

    Used by the wifi/bt/zigbee ingest routers to gate cross-correlation
    so a chatty scanner doesn't peg an executor thread per ingest. The
    SDR router throttles via its own ``_node_batch_count`` in
    ``routers/detections.py`` — that path predates this helper and is
    deliberately left alone to keep diff scope tight; the semantics
    match (run on call N where N % every_n == 0).

    Per-uvicorn-worker state; counts aren't shared across workers, so a
    deployment with multiple workers fires correlation slightly more
    often than the configured ratio. Bound by ``max_nodes`` so a flood
    of distinct node_ids can't grow the map without limit.
    """

    def __init__(self, every_n: int = 5, max_nodes: int = 10_000) -> None:
        self._every_n = max(1, every_n)
        self._max_nodes = max_nodes
        self._counts: OrderedDict[str, int] = OrderedDict()

    def should_run(self, node_id: str) -> bool:
        n = self._counts.get(node_id, 0) + 1
        self._counts[node_id] = n
        self._counts.move_to_end(node_id)
        if len(self._counts) > self._max_nodes:
            self._counts.popitem(last=False)
        return n % self._every_n == 0


# WiFi channel -> center frequency (MHz)
WIFI_CHANNEL_FREQ = {
    1: 2412,
    2: 2417,
    3: 2422,
    4: 2427,
    5: 2432,
    6: 2437,
    7: 2442,
    8: 2447,
    9: 2452,
    10: 2457,
    11: 2462,
    12: 2467,
    13: 2472,
    36: 5180,
    40: 5200,
    44: 5220,
    48: 5240,
    52: 5260,
    56: 5280,
    60: 5300,
    64: 5320,
    100: 5500,
    104: 5520,
    108: 5540,
    112: 5560,
    116: 5580,
    120: 5600,
    124: 5620,
    128: 5640,
    132: 5660,
    136: 5680,
    140: 5700,
    144: 5720,
    149: 5745,
    153: 5765,
    157: 5785,
    161: 5805,
    165: 5825,
}


def _bt_channel_to_freq(channel: int) -> float:
    """Convert Bluetooth channel number to frequency in Hz."""
    return (2402 + channel) * 1e6


def _zigbee_channel_to_freq(channel: int) -> float:
    """Convert Zigbee 802.15.4 channel number to frequency in Hz."""
    if 11 <= channel <= 26:
        return (2405 + (channel - 11) * 5) * 1e6
    return 0.0


class CrossCorrelator:
    """N-way correlator across SDR, WiFi, BT, and Zigbee sources."""

    # Frequency tolerance per source pair (Hz)
    FREQ_TOLERANCE = {
        ("bt", "sdr"): 2_000_000,
        ("bt", "wifi"): 2_000_000,
        ("sdr", "wifi"): 10_000_000,
        ("sdr", "zigbee"): 5_000_000,
        ("bt", "zigbee"): 5_000_000,
        ("aircraft", "sdr"): 1_000_000,
        ("wifi", "zigbee"): 5_000_000,
    }
    DEFAULT_FREQ_TOLERANCE = 5_000_000

    def __init__(self, ctx, time_window_ms: float = 500.0):
        self.ctx = ctx
        self.time_window_ms = time_window_ms

    def _get_freq_tolerance(self, source_a: str, source_b: str) -> float:
        key = tuple(sorted([source_a, source_b]))
        return self.FREQ_TOLERANCE.get(key, self.DEFAULT_FREQ_TOLERANCE)

    def _parse_timestamp(self, ts: str) -> float:
        """Parse ISO timestamp to epoch milliseconds."""
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.timestamp() * 1000.0
        except (ValueError, AttributeError):
            return 0.0

    def _query_nearby_detections(
        self,
        conn,
        source: str,
        freq_hz: float,
        timestamp_ms: float,
        node_id: str,
        freq_tolerance: float,
    ) -> list[dict]:
        """Query a source table for events near a frequency/time."""
        time_window_s = self.time_window_ms / 1000.0
        freq_min = freq_hz - freq_tolerance
        freq_max = freq_hz + freq_tolerance
        # Precompute ISO-8601 bounds in Python so the SQL can compare
        # `timestamp >= ? AND timestamp <= ?` directly. Wrapping the
        # column in datetime() (as this used to) makes the expression
        # non-constant per row, which disables every (node_id, timestamp)
        # index on these tables — turning each call into a full scan.
        # All four tables' writers store ISO-8601 UTC strings, which sort
        # lexicographically, so plain column comparison is correct.
        ts_center_s = timestamp_ms / 1000.0
        ts_low = datetime.fromtimestamp(
            ts_center_s - time_window_s, tz=timezone.utc
        ).isoformat()
        ts_high = datetime.fromtimestamp(
            ts_center_s + time_window_s, tz=timezone.utc
        ).isoformat()

        if source == "sdr":
            sql = """SELECT detection_id, freq_hz, timestamp, signal_class
                     FROM detections
                     WHERE node_id = ? AND freq_hz BETWEEN ? AND ?
                     AND timestamp >= ? AND timestamp <= ?
                     LIMIT 10"""
            rows = conn.execute(
                sql, (node_id, freq_min, freq_max, ts_low, ts_high)
            ).fetchall()
            return [
                {"id": str(r[0]), "freq_hz": r[1], "timestamp": r[2], "source": "sdr"}
                for r in rows
            ]

        elif source == "wifi":
            sql = """SELECT id, channel, timestamp
                     FROM wifi_metadata
                     WHERE node_id = ?
                     AND timestamp >= ? AND timestamp <= ?
                     LIMIT 10"""
            rows = conn.execute(sql, (node_id, ts_low, ts_high)).fetchall()
            results = []
            for r in rows:
                ch_freq = WIFI_CHANNEL_FREQ.get(r[1], 0) * 1e6
                if freq_min <= ch_freq <= freq_max:
                    results.append(
                        {
                            "id": str(r[0]),
                            "freq_hz": ch_freq,
                            "timestamp": r[2],
                            "source": "wifi",
                        }
                    )
            return results

        elif source == "bt":
            sql = """SELECT id, channel, timestamp
                     FROM bt_devices
                     WHERE node_id = ?
                     AND timestamp >= ? AND timestamp <= ?
                     LIMIT 10"""
            rows = conn.execute(sql, (node_id, ts_low, ts_high)).fetchall()
            results = []
            for r in rows:
                bt_freq = _bt_channel_to_freq(r[1]) if r[1] is not None else 2441e6
                if freq_min <= bt_freq <= freq_max:
                    results.append(
                        {
                            "id": str(r[0]),
                            "freq_hz": bt_freq,
                            "timestamp": r[2],
                            "source": "bt",
                        }
                    )
            return results

        elif source == "zigbee":
            sql = """SELECT id, channel, timestamp
                     FROM zigbee_devices
                     WHERE node_id = ?
                     AND timestamp >= ? AND timestamp <= ?
                     LIMIT 10"""
            rows = conn.execute(sql, (node_id, ts_low, ts_high)).fetchall()
            results = []
            for r in rows:
                zb_freq = _zigbee_channel_to_freq(r[1]) if r[1] else 0
                if freq_min <= zb_freq <= freq_max:
                    results.append(
                        {
                            "id": str(r[0]),
                            "freq_hz": zb_freq,
                            "timestamp": r[2],
                            "source": "zigbee",
                        }
                    )
            return results

        return []

    def correlate(
        self,
        source: str,
        events: list[dict],
        node_id: str,
    ) -> list[CrossCorrelation]:
        """Correlate events from *source* against all other sources.

        Args:
            source: Source type ("sdr", "wifi", "bt", "zigbee", "aircraft")
            events: List of dicts with at least {freq_hz, timestamp}
                    (or {channel, timestamp} for protocol scanners)
            node_id: Node that produced the events

        Returns:
            List of CrossCorrelation results
        """
        other_sources = [s for s in ["sdr", "wifi", "bt", "zigbee"] if s != source]
        results: list[CrossCorrelation] = []

        conn = self.ctx.get_conn()

        for event in events:
            freq_hz = event.get("freq_hz", 0)
            if not freq_hz and "channel" in event:
                if source == "wifi":
                    freq_hz = WIFI_CHANNEL_FREQ.get(event["channel"], 0) * 1e6
                elif source == "zigbee":
                    freq_hz = _zigbee_channel_to_freq(event["channel"])
                elif source == "bt":
                    freq_hz = _bt_channel_to_freq(event.get("channel", 0))

            if not freq_hz:
                continue

            timestamp_ms = self._parse_timestamp(event.get("timestamp", ""))
            if not timestamp_ms:
                continue

            match_sources: set[str] = set()
            best_matches: list[tuple[str, dict, float]] = []

            for other in other_sources:
                tolerance = self._get_freq_tolerance(source, other)
                matches = self._query_nearby_detections(
                    conn,
                    other,
                    freq_hz,
                    timestamp_ms,
                    node_id,
                    tolerance,
                )
                if matches:
                    match_sources.add(other)
                    for m in matches:
                        other_ts = self._parse_timestamp(m["timestamp"])
                        delta = abs(timestamp_ms - other_ts)
                        best_matches.append((other, m, delta))

            now_iso = datetime.now(timezone.utc).isoformat()
            event_id = event.get("id", "")

            if len(match_sources) >= 2:
                for _other, m, delta in best_matches:
                    results.append(
                        CrossCorrelation(
                            source_a=source,
                            source_a_id=str(event_id),
                            source_b=m["source"],
                            source_b_id=m["id"],
                            freq_hz=freq_hz,
                            time_delta_ms=delta,
                            correlation_type="multi_source",
                            node_id=node_id,
                            timestamp=now_iso,
                        )
                    )
            elif match_sources:
                for _other, m, delta in best_matches:
                    results.append(
                        CrossCorrelation(
                            source_a=source,
                            source_a_id=str(event_id),
                            source_b=m["source"],
                            source_b_id=m["id"],
                            freq_hz=freq_hz,
                            time_delta_ms=delta,
                            correlation_type="confirmed",
                            node_id=node_id,
                            timestamp=now_iso,
                        )
                    )
            else:
                ctype = "unmatched_sdr" if source == "sdr" else "unmatched_protocol"
                results.append(
                    CrossCorrelation(
                        source_a=source,
                        source_a_id=str(event_id),
                        source_b="",
                        source_b_id=None,
                        freq_hz=freq_hz,
                        time_delta_ms=0,
                        correlation_type=ctype,
                        node_id=node_id,
                        timestamp=now_iso,
                    )
                )

        self._store_correlations(conn, results)
        return results

    def _store_correlations(self, conn, correlations: list[CrossCorrelation]):
        """Persist correlation results to cross_correlations table."""
        if not correlations:
            return
        try:
            # Rolls back on failure: a swallowed error must not leave the
            # thread-local connection holding an open write transaction.
            with sqlite_transaction(conn):
                conn.executemany(
                    """INSERT INTO cross_correlations
                       (source_a, source_a_id, source_b, source_b_id, freq_hz,
                        time_delta_ms, correlation_type, node_id, timestamp, tenant_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'default')""",
                    [
                        (
                            c.source_a,
                            c.source_a_id,
                            c.source_b,
                            c.source_b_id,
                            c.freq_hz,
                            c.time_delta_ms,
                            c.correlation_type,
                            c.node_id,
                            c.timestamp,
                        )
                        for c in correlations
                    ],
                )
        except Exception as e:
            logger.warning("Failed to store correlations: %s", e)

    def get_correlation_summary(self, node_id: str, hours: int = 1) -> dict:
        """Return correlation stats: counts by type for a node."""
        conn = self.ctx.get_conn()
        # Cutoff in the stored isoformat ('T' separator), not SQLite's
        # datetime('now', ...) (' ' separator), which text-compares as
        # earlier than every row of the same UTC date.
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        sql = """SELECT correlation_type, COUNT(*)
                 FROM cross_correlations
                 WHERE node_id = ?
                 AND timestamp >= ?
                 GROUP BY correlation_type"""
        rows = conn.execute(sql, (node_id, cutoff)).fetchall()
        return {r[0]: r[1] for r in rows}

    def get_correlation_for_detection(self, detection_id: str) -> str | None:
        """Get correlation type for a specific SDR detection.

        Returns: 'confirmed', 'unmatched_sdr', 'multi_source', or None
        """
        conn = self.ctx.get_conn()
        row = conn.execute(
            """SELECT correlation_type FROM cross_correlations
               WHERE source_a = 'sdr' AND source_a_id = ?
               ORDER BY rowid DESC LIMIT 1""",
            (detection_id,),
        ).fetchone()
        return row[0] if row else None
