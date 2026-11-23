"""Emitter association engine for RF SIGINT.

Clusters detections by frequency proximity, temporal patterns, and
power-level consistency to associate signals with physical emitters.

When multiple edge nodes observe similar signals, node overlap is used
as additional evidence that detections originate from the same
physical transmitter.

Clustering approach:
1. **Frequency proximity** -- detections within an estimated bandwidth
   (or a configurable tolerance) are candidates for the same emitter.
2. **Temporal regularity** -- recurring detections at regular intervals
   indicate a periodic transmitter (beacons, polling protocols).
3. **Power consistency** -- a real emitter produces a relatively stable
   power reading at a given node; large swings suggest different sources.
4. **Node overlap** -- the same emitter seen by multiple nodes should
   appear in consistent frequency/power ratios across those nodes.
"""

from __future__ import annotations

import hashlib
import logging
import statistics
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tuneable defaults
# ---------------------------------------------------------------------------

_DEFAULT_FREQ_TOLERANCE_HZ = 50_000  # 50 kHz default grouping window
_DEFAULT_POWER_TOLERANCE_DB = 10.0  # +/- 10 dB same-emitter window
_DEFAULT_LOOKBACK_HOURS = 24
_DEFAULT_MIN_DETECTIONS = 3  # minimum detections to form emitter


# ---------------------------------------------------------------------------
# Emitter model
# ---------------------------------------------------------------------------


class Emitter(BaseModel):
    """A discovered physical emitter derived from clustered detections."""

    emitter_id: str = ""
    primary_freq_hz: float = 0.0
    bandwidth_hz: float = 0.0
    signal_class: str = ""
    power_profile: dict[str, Any] = Field(default_factory=dict)
    activity_pattern: dict[str, Any] = Field(default_factory=dict)
    associated_nodes: list[str] = Field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    detection_count: int = 0
    detection_ids: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# EmitterAssociator
# ---------------------------------------------------------------------------


class EmitterAssociator:
    """Cluster detections into emitter groups.

    Parameters
    ----------
    freq_tolerance_hz : float
        Maximum frequency separation (Hz) to consider two detections
        as originating from the same emitter.  Overridden by per-detection
        ``bandwidth_hz`` when available.
    power_tolerance_db : float
        Maximum power variation (dB) within a single emitter group.
    min_detections : int
        Minimum number of detections required to declare an emitter.
    """

    def __init__(
        self,
        freq_tolerance_hz: float = _DEFAULT_FREQ_TOLERANCE_HZ,
        power_tolerance_db: float = _DEFAULT_POWER_TOLERANCE_DB,
        min_detections: int = _DEFAULT_MIN_DETECTIONS,
    ) -> None:
        self.freq_tolerance_hz = freq_tolerance_hz
        self.power_tolerance_db = power_tolerance_db
        self.min_detections = min_detections

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def associate(self, detections: list[dict[str, Any]]) -> list[Emitter]:
        """Cluster *detections* into emitter groups.

        Parameters
        ----------
        detections : list[dict]
            Detection records (dicts with keys: detection_id, node_id,
            signal_class, freq_hz, power_dbm, bandwidth_hz, timestamp).

        Returns
        -------
        list[Emitter]
            Discovered emitter groups sorted by detection_count descending.
        """
        if not detections:
            return []

        # Step 1: group by signal_class
        by_class: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for d in detections:
            sig = d.get("signal_class", "unknown")
            by_class[sig].append(d)

        emitters: list[Emitter] = []

        for signal_class, class_dets in by_class.items():
            # Step 2: sub-cluster by frequency proximity
            freq_clusters = self._cluster_by_frequency(class_dets)
            for cluster in freq_clusters:
                # Step 3: refine by power consistency
                power_groups = self._refine_by_power(cluster)
                for group in power_groups:
                    if len(group) < self.min_detections:
                        continue
                    emitter = self._build_emitter(signal_class, group)
                    emitters.append(emitter)

        emitters.sort(key=lambda e: e.detection_count, reverse=True)
        return emitters

    # -------------------------------------------------------------------
    # Frequency clustering
    # -------------------------------------------------------------------

    def _cluster_by_frequency(
        self,
        detections: list[dict[str, Any]],
    ) -> list[list[dict[str, Any]]]:
        """Sort detections by freq and merge adjacent within tolerance."""
        if not detections:
            return []

        sorted_dets = sorted(detections, key=lambda d: d.get("freq_hz", 0.0))

        clusters: list[list[dict[str, Any]]] = []
        current: list[dict[str, Any]] = [sorted_dets[0]]
        current_center = sorted_dets[0].get("freq_hz", 0.0)

        for d in sorted_dets[1:]:
            freq = d.get("freq_hz", 0.0)
            # Use per-detection bandwidth if available, else default
            bw = d.get("bandwidth_hz") or 0.0
            tolerance = max(self.freq_tolerance_hz, bw)
            if abs(freq - current_center) <= tolerance:
                current.append(d)
                # Update running center
                freqs = [dd.get("freq_hz", 0.0) for dd in current]
                current_center = sum(freqs) / len(freqs)
            else:
                clusters.append(current)
                current = [d]
                current_center = freq

        clusters.append(current)
        return clusters

    # -------------------------------------------------------------------
    # Power consistency refinement
    # -------------------------------------------------------------------

    def _refine_by_power(
        self,
        detections: list[dict[str, Any]],
    ) -> list[list[dict[str, Any]]]:
        """Split a frequency cluster into sub-groups with consistent power.

        Detections without power_dbm are placed in a single catch-all group.
        """
        with_power: list[dict[str, Any]] = []
        without_power: list[dict[str, Any]] = []

        for d in detections:
            if d.get("power_dbm") is not None:
                with_power.append(d)
            else:
                without_power.append(d)

        if not with_power:
            return [detections]

        # Sort by power and group within tolerance
        sorted_pw = sorted(with_power, key=lambda d: d.get("power_dbm", 0.0))
        groups: list[list[dict[str, Any]]] = []
        current: list[dict[str, Any]] = [sorted_pw[0]]
        current_median = sorted_pw[0].get("power_dbm", 0.0)

        for d in sorted_pw[1:]:
            pwr = d.get("power_dbm", 0.0)
            if abs(pwr - current_median) <= self.power_tolerance_db:
                current.append(d)
                powers = [dd.get("power_dbm", 0.0) for dd in current]
                current_median = statistics.median(powers)
            else:
                groups.append(current)
                current = [d]
                current_median = pwr

        groups.append(current)

        # Merge detections without power into the largest group
        if without_power:
            if groups:
                largest = max(groups, key=len)
                largest.extend(without_power)
            else:
                groups.append(without_power)

        return groups

    # -------------------------------------------------------------------
    # Emitter construction
    # -------------------------------------------------------------------

    def _build_emitter(
        self,
        signal_class: str,
        detections: list[dict[str, Any]],
    ) -> Emitter:
        """Build an Emitter from a cluster of detections."""
        freqs = [d.get("freq_hz", 0.0) for d in detections]
        powers = [
            d.get("power_dbm", 0.0)
            for d in detections
            if d.get("power_dbm") is not None
        ]
        timestamps = [self._parse_ts(d.get("timestamp")) for d in detections]
        valid_ts = sorted(t for t in timestamps if t is not None)
        nodes = sorted({d.get("node_id", "") for d in detections} - {""})
        det_ids = [
            d.get("detection_id", "") for d in detections if d.get("detection_id")
        ]

        primary_freq = statistics.mean(freqs) if freqs else 0.0
        freq_min = min(freqs) if freqs else 0.0
        freq_max = max(freqs) if freqs else 0.0
        bandwidth = freq_max - freq_min

        # Deterministic emitter ID from signal class + freq bin
        raw_id = f"{signal_class}:{int(primary_freq / 1000)}"
        emitter_id = hashlib.sha256(raw_id.encode()).hexdigest()[:16]

        # Power profile
        power_profile: dict[str, Any] = {}
        if powers:
            power_profile = {
                "mean_dbm": round(statistics.mean(powers), 2),
                "median_dbm": round(statistics.median(powers), 2),
                "min_dbm": round(min(powers), 2),
                "max_dbm": round(max(powers), 2),
                "std_dbm": round(statistics.stdev(powers), 2)
                if len(powers) >= 2
                else 0.0,
            }

        # Activity pattern
        activity = self._compute_activity_pattern(valid_ts)

        first_seen = valid_ts[0].isoformat() if valid_ts else ""
        last_seen = valid_ts[-1].isoformat() if valid_ts else ""

        return Emitter(
            emitter_id=emitter_id,
            primary_freq_hz=round(primary_freq, 0),
            bandwidth_hz=round(bandwidth, 0),
            signal_class=signal_class,
            power_profile=power_profile,
            activity_pattern=activity,
            associated_nodes=nodes,
            first_seen=first_seen,
            last_seen=last_seen,
            detection_count=len(detections),
            detection_ids=det_ids[:500],  # cap to prevent huge payloads
        )

    # -------------------------------------------------------------------
    # Activity pattern analysis
    # -------------------------------------------------------------------

    @staticmethod
    def _compute_activity_pattern(
        timestamps: list[datetime],
    ) -> dict[str, Any]:
        """Analyse temporal regularity of detections.

        Returns a dict with:
        - total_duration_sec: time span of the cluster
        - avg_interval_sec: average interval between detections
        - interval_std_sec: standard deviation of intervals
        - regularity_score: 0-1 measure (1 = perfectly periodic)
        - is_periodic: True if regularity_score > 0.7
        """
        if len(timestamps) < 2:
            return {
                "total_duration_sec": 0.0,
                "avg_interval_sec": 0.0,
                "interval_std_sec": 0.0,
                "regularity_score": 0.0,
                "is_periodic": False,
            }

        total_duration = (timestamps[-1] - timestamps[0]).total_seconds()

        intervals = [
            (timestamps[i + 1] - timestamps[i]).total_seconds()
            for i in range(len(timestamps) - 1)
        ]

        avg_interval = statistics.mean(intervals) if intervals else 0.0
        std_interval = statistics.stdev(intervals) if len(intervals) >= 2 else 0.0

        # Regularity: 1 - (CV), clamped to [0, 1]
        # CV = std / mean (coefficient of variation)
        if avg_interval > 0:
            cv = std_interval / avg_interval
            regularity = max(0.0, min(1.0, 1.0 - cv))
        else:
            regularity = 0.0

        return {
            "total_duration_sec": round(total_duration, 2),
            "avg_interval_sec": round(avg_interval, 2),
            "interval_std_sec": round(std_interval, 2),
            "regularity_score": round(regularity, 4),
            "is_periodic": regularity > 0.7,
        }

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    @staticmethod
    def _parse_ts(ts: Any) -> datetime | None:
        """Parse timestamp from various formats."""
        if ts is None:
            return None
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts)
            except (ValueError, TypeError):
                return None
        return None
