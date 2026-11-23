"""Frequency-Hopping Spread Spectrum (FHSS) signal detector.

Detects FHSS patterns by analysing rapid frequency changes across
sliding time windows in detection data.  Key metrics computed:

- **Hop rate** (hops per second): distinct frequency transitions / duration
- **Hop set**: the set of frequencies used by the hopper
- **Bandwidth**: spread of the hop set (max - min frequency)
- **Dwell time**: estimated average time spent on each frequency
- **Duration**: total observed hopping activity span

The detector works on batches of ``DetectionRecord`` objects (or
equivalent dicts) grouped by ``node_id``.  It is stateless between
calls -- all analysis is done within the supplied detection window.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Minimum distinct frequencies within a 1-second window to consider FHSS
_MIN_DISTINCT_FREQS = 3

# Frequency binning resolution (Hz) -- collapses float jitter
_FREQ_BIN_HZ = 50_000  # 50 kHz bins

# Sliding window size in seconds
_DEFAULT_WINDOW_SEC = 1.0

# Minimum hop rate to report (hops/s)
_MIN_HOP_RATE = 0.5  # lowered from 2.0 — catch slow-hopping FHSS signals

# Maximum gap between detections to consider them part of the same
# hopping sequence (seconds)
_MAX_GAP_SEC = 5.0


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class FHSSEvent:
    """A detected FHSS signal event."""

    fhss_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    node_id: str = ""
    timestamp: str = ""  # ISO 8601 start of event
    hop_rate_hz: float = 0.0  # hops per second
    hop_set: list[float] = field(default_factory=list)  # list of freq_hz values
    bandwidth_hz: float = 0.0  # max(hop_set) - min(hop_set)
    dwell_time_ms: float = 0.0  # average time on each frequency (ms)
    duration_sec: float = 0.0  # total observation duration
    signal_class: str = ""  # dominant signal class if identifiable
    detection_count: int = 0  # number of detections in the event
    confidence: float = 0.0  # average confidence across detections

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        return {
            "fhss_id": self.fhss_id,
            "node_id": self.node_id,
            "timestamp": self.timestamp,
            "hop_rate_hz": round(self.hop_rate_hz, 2),
            "hop_set": [round(f, 1) for f in self.hop_set],
            "bandwidth_hz": round(self.bandwidth_hz, 1),
            "dwell_time_ms": round(self.dwell_time_ms, 2),
            "duration_sec": round(self.duration_sec, 3),
            "signal_class": self.signal_class,
            "detection_count": self.detection_count,
            "confidence": round(self.confidence, 4),
        }


# ---------------------------------------------------------------------------
# FHSSDetector
# ---------------------------------------------------------------------------


class FHSSDetector:
    """Detect frequency-hopping spread spectrum signals from detection data.

    Parameters
    ----------
    window_sec : float
        Sliding window size in seconds for counting distinct frequencies.
    min_distinct_freqs : int
        Minimum distinct frequency bins within a window to flag FHSS.
    freq_bin_hz : float
        Frequency binning resolution in Hz.
    min_hop_rate : float
        Minimum hop rate (hops/s) to include in results.
    max_gap_sec : float
        Maximum gap between detections before splitting into separate
        FHSS events.
    """

    def __init__(
        self,
        window_sec: float = _DEFAULT_WINDOW_SEC,
        min_distinct_freqs: int = _MIN_DISTINCT_FREQS,
        freq_bin_hz: float = _FREQ_BIN_HZ,
        min_hop_rate: float = _MIN_HOP_RATE,
        max_gap_sec: float = _MAX_GAP_SEC,
    ) -> None:
        self.window_sec = window_sec
        self.min_distinct_freqs = min_distinct_freqs
        self.freq_bin_hz = freq_bin_hz
        self.min_hop_rate = min_hop_rate
        self.max_gap_sec = max_gap_sec

        # Stateful: retain recent detections across analyse() calls so hopping
        # patterns spanning multiple batches are detected (Blind Spot #7).
        # Keyed by node_id → list of (timestamp, freq_bin) tuples.
        # Entries older than max_gap_sec * 3 are pruned each call.
        self._carry_buffer: dict[str, list[tuple[float, int]]] = defaultdict(list)
        self._carry_ttl = max_gap_sec * 3  # retain for 3x the gap threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyse(
        self,
        detections: list[dict[str, Any]],
    ) -> list[FHSSEvent]:
        """Analyse a list of detection dicts for FHSS patterns.

        Detections are grouped by ``node_id``, then sorted by timestamp.
        Each node's detection stream is scanned with a sliding window.

        Parameters
        ----------
        detections : list[dict]
            Detection records.  Each must have at least ``node_id``,
            ``timestamp`` (ISO str or float epoch), ``freq_hz``, and
            optionally ``signal_class`` and ``confidence``.

        Returns
        -------
        list[FHSSEvent]
            Detected FHSS events across all nodes.
        """
        # Group by node_id
        by_node: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for det in detections:
            node = det.get("node_id", "")
            if node:
                by_node[node].append(det)

        # Prune carry buffer entries older than TTL
        import time as _time

        now = _time.time()
        for nid in list(self._carry_buffer.keys()):
            self._carry_buffer[nid] = [
                (ts, fb)
                for ts, fb in self._carry_buffer[nid]
                if now - ts < self._carry_ttl
            ]
            if not self._carry_buffer[nid]:
                del self._carry_buffer[nid]

        events: list[FHSSEvent] = []
        for node_id, node_dets in by_node.items():
            node_events = self._analyse_node(node_id, node_dets)
            events.extend(node_events)

            # Store recent detections in carry buffer for next call
            for det in node_dets:
                ts = self._parse_timestamp(det.get("timestamp", ""))
                if ts is not None:
                    freq_bin = int(det.get("freq_hz", 0) / self.freq_bin_hz)
                    self._carry_buffer[node_id].append((ts, freq_bin))

        return events

    # ------------------------------------------------------------------
    # Per-node analysis
    # ------------------------------------------------------------------

    def _analyse_node(
        self,
        node_id: str,
        detections: list[dict[str, Any]],
    ) -> list[FHSSEvent]:
        """Analyse detections from a single node.

        Includes carry-buffer data from previous calls so hopping patterns
        spanning multiple batches are detected (Blind Spot #7).
        """
        # Parse timestamps and sort
        parsed: list[tuple[float, dict[str, Any]]] = []

        # Prepend carry-buffer entries as synthetic detections
        for ts, freq_bin in self._carry_buffer.get(node_id, []):
            synthetic = {
                "node_id": node_id,
                "timestamp": ts,
                "freq_hz": freq_bin * self.freq_bin_hz,
                "signal_class": "_carry",
                "confidence": 0.0,
            }
            parsed.append((ts, synthetic))

        for det in detections:
            ts = self._parse_timestamp(det.get("timestamp"))
            if ts is not None:
                parsed.append((ts, det))

        if len(parsed) < self.min_distinct_freqs:
            return []

        parsed.sort(key=lambda x: x[0])

        # Split into contiguous segments (gap < max_gap_sec)
        segments = self._split_segments(parsed)

        events: list[FHSSEvent] = []
        for segment in segments:
            evt = self._analyse_segment(node_id, segment)
            if evt is not None:
                events.append(evt)

        return events

    def _split_segments(
        self,
        sorted_dets: list[tuple[float, dict[str, Any]]],
    ) -> list[list[tuple[float, dict[str, Any]]]]:
        """Split sorted detections into contiguous segments."""
        if not sorted_dets:
            return []

        segments: list[list[tuple[float, dict[str, Any]]]] = []
        current: list[tuple[float, dict[str, Any]]] = [sorted_dets[0]]

        for i in range(1, len(sorted_dets)):
            gap = sorted_dets[i][0] - sorted_dets[i - 1][0]
            if gap > self.max_gap_sec:
                segments.append(current)
                current = []
            current.append(sorted_dets[i])

        if current:
            segments.append(current)

        return segments

    def _analyse_segment(
        self,
        node_id: str,
        segment: list[tuple[float, dict[str, Any]]],
    ) -> FHSSEvent | None:
        """Analyse a contiguous segment of detections for FHSS.

        Uses a sliding window approach: for each detection, count
        distinct frequency bins in the window [t - window_sec, t].
        If any window has >= min_distinct_freqs, the segment is
        flagged as FHSS.
        """
        if len(segment) < self.min_distinct_freqs:
            return None

        # Collect all (timestamp, freq_bin) pairs
        points: list[tuple[float, int]] = []
        for ts, det in segment:
            freq = det.get("freq_hz", 0.0)
            freq_bin = self._bin_freq(freq)
            points.append((ts, freq_bin))

        # Sliding window: check if any window contains enough distinct freqs
        fhss_detected = False
        for i, (t, _) in enumerate(points):
            window_start = t - self.window_sec
            # Collect all freq bins within [window_start, t]
            bins_in_window: set[int] = set()
            for j in range(i, -1, -1):
                if points[j][0] < window_start:
                    break
                bins_in_window.add(points[j][1])
            if len(bins_in_window) >= self.min_distinct_freqs:
                fhss_detected = True
                break

        if not fhss_detected:
            return None

        # Compute FHSS metrics for the full segment
        return self._compute_event(node_id, segment)

    def _compute_event(
        self,
        node_id: str,
        segment: list[tuple[float, dict[str, Any]]],
    ) -> FHSSEvent:
        """Compute FHSS event metrics from a flagged segment."""
        timestamps = [ts for ts, _ in segment]
        t_start = min(timestamps)
        t_end = max(timestamps)
        duration = t_end - t_start

        # Collect all frequencies (unbinned for the hop set)
        raw_freqs: list[float] = []
        for _, det in segment:
            raw_freqs.append(det.get("freq_hz", 0.0))

        # Binned hop set for accurate distinct count
        binned_freqs: dict[int, float] = {}
        for _, det in segment:
            freq = det.get("freq_hz", 0.0)
            b = self._bin_freq(freq)
            if b not in binned_freqs:
                binned_freqs[b] = freq  # representative freq

        hop_set = sorted(binned_freqs.values())
        bandwidth = max(hop_set) - min(hop_set) if len(hop_set) > 1 else 0.0

        # Count frequency transitions (consecutive different freq bins)
        transitions = 0
        prev_bin: int | None = None
        for _, det in segment:
            cur_bin = self._bin_freq(det.get("freq_hz", 0.0))
            if prev_bin is not None and cur_bin != prev_bin:
                transitions += 1
            prev_bin = cur_bin

        # Hop rate = transitions / duration
        hop_rate = transitions / duration if duration > 0 else 0.0

        # Dwell time = average time between transitions
        dwell_time_ms = (duration * 1000.0 / transitions) if transitions > 0 else 0.0

        # Dominant signal class
        class_counts: dict[str, int] = defaultdict(int)
        total_conf = 0.0
        for _, det in segment:
            sc = det.get("signal_class", "")
            if sc:
                class_counts[sc] += 1
            total_conf += det.get("confidence", 0.0)

        dominant_class = ""
        if class_counts:
            dominant_class = max(class_counts, key=class_counts.get)  # type: ignore[arg-type]

        avg_conf = total_conf / len(segment) if segment else 0.0

        # ISO timestamp for event start
        ts_iso = datetime.fromtimestamp(t_start, tz=timezone.utc).isoformat()

        return FHSSEvent(
            node_id=node_id,
            timestamp=ts_iso,
            hop_rate_hz=hop_rate,
            hop_set=hop_set,
            bandwidth_hz=bandwidth,
            dwell_time_ms=dwell_time_ms,
            duration_sec=duration,
            signal_class=dominant_class,
            detection_count=len(segment),
            confidence=avg_conf,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _bin_freq(self, freq_hz: float) -> int:
        """Bin a frequency to the configured resolution."""
        return int(round(freq_hz / self.freq_bin_hz))

    @staticmethod
    def _parse_timestamp(ts: Any) -> float | None:
        """Parse a timestamp value to epoch seconds."""
        if ts is None:
            return None
        if isinstance(ts, (int, float)):
            return float(ts)
        if isinstance(ts, datetime):
            return ts.timestamp()
        if isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts)
                return dt.timestamp()
            except (ValueError, TypeError):
                return None
        return None
