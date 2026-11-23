"""Multi-node correlation for anomaly scoring.

Detects when multiple nodes observe the same signal class at similar
frequencies within a configurable time window, boosting confidence
that the signal is real (not per-node noise or local interference).

Correlation groups are formed by (signal_class, frequency_bin) and
scored based on the number of distinct nodes that participated.

Anomaly score adjustment:
- Cross-node agreement increases the anomaly score (multiplied by
  1 + confidence_boost), confirming the signal is real.
- Single-node-only detections receive a dampening factor (multiplied
  by ``single_node_factor``) because they may indicate local
  interference rather than a genuine signal of interest.

The ``correlation_score`` field on ``CorrelationResult`` gives the
ratio of confirming nodes to total known active nodes, providing a
normalised measure of cross-node agreement.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_TIME_WINDOW_SEC = (
    15  # +/- 15 seconds across nodes (widened from 5s to catch slower propagation)
)
_DEFAULT_FREQ_TOLERANCE_HZ = 100_000  # 100 kHz


def _freq_bin(freq_hz: float, tolerance: float = _DEFAULT_FREQ_TOLERANCE_HZ) -> int:
    """Bucket a frequency into bins of *tolerance* width."""
    if tolerance <= 0:
        return int(freq_hz)
    return int(freq_hz / tolerance)


# ---------------------------------------------------------------------------
# Correlation result model
# ---------------------------------------------------------------------------


class CorrelationResult(BaseModel):
    """Result of a cross-node correlation check."""

    correlated: bool = False
    node_count: int = 1
    total_active_nodes: int = 1
    node_ids: list[str] = Field(default_factory=list)
    confidence_boost: float = 0.0
    correlation_score: float = 0.0
    adjusted_anomaly_score: float | None = None


class CorrelationGroup(BaseModel):
    """A group of correlated detections across nodes."""

    signal_class: str
    freq_hz: float
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    duration_sec: float = 0.0
    correlation_score: float = 0.0


# ---------------------------------------------------------------------------
# NodeCorrelator
# ---------------------------------------------------------------------------


class NodeCorrelator:
    """Checks for cross-node detection correlations.

    When a detection arrives, queries recent detections from other nodes
    to see if the same signal class was observed at a similar frequency
    within a configurable time window.

    Parameters
    ----------
    time_window_sec : int
        Maximum seconds between detections to consider them correlated.
        Default is 5 seconds (detections within +/-5s are candidates).
    freq_tolerance_hz : float
        Frequency tolerance in Hz.  Detections whose frequencies fall
        into the same bin (binned at this resolution) are candidates.
    single_node_factor : float
        Dampening multiplier applied to the anomaly score when only a
        single node detects the signal (potential local interference).
        Default 0.8 (20% reduction).
    total_active_nodes : int
        Total number of known active edge nodes in the network.
        Used to compute ``correlation_score`` as the ratio of
        confirming nodes to total active nodes.  Updated at runtime
        via :meth:`set_active_node_count`.
    """

    def __init__(
        self,
        time_window_sec: int = _DEFAULT_TIME_WINDOW_SEC,
        freq_tolerance_hz: float = _DEFAULT_FREQ_TOLERANCE_HZ,
        single_node_factor: float = 0.9,  # reduced dampening: 10% (was 20%) — single-node detections are still valuable
        total_active_nodes: int = 1,
    ) -> None:
        self.time_window_sec = time_window_sec
        self.freq_tolerance_hz = freq_tolerance_hz
        self.single_node_factor = single_node_factor
        self._total_active_nodes = max(1, total_active_nodes)
        # TDOA callback: called with a list of detections when 3+ nodes
        # detect the same signal within a tight time window (100 ms).
        self._tdoa_callback: Any | None = None

    def set_tdoa_callback(self, callback: Any) -> None:
        """Register a callback for TDOA-eligible clusters.

        The callback receives a list of detection dicts forming a
        tight cluster (3+ nodes, <=100ms spread).  It should be a
        callable accepting ``(detections: list[dict]) -> None``.
        """
        self._tdoa_callback = callback

    def set_active_node_count(self, count: int) -> None:
        """Update the total number of known active nodes.

        Called by the ingestion pipeline when node counts change.
        """
        self._total_active_nodes = max(1, count)

    # -----------------------------------------------------------------------
    # Core correlation check
    # -----------------------------------------------------------------------

    def check_correlation(
        self,
        detection: dict[str, Any],
        recent_detections: list[dict[str, Any]],
    ) -> CorrelationResult:
        """Check if a detection correlates with recent detections from other nodes.

        Parameters
        ----------
        detection : dict
            The incoming detection with keys: node_id, signal_class,
            freq_hz, timestamp, and optionally anomaly_score.
        recent_detections : list[dict]
            Recent detections from the database (all nodes).

        Returns
        -------
        CorrelationResult
            Correlation info including node count, confidence boost,
            correlation_score, and adjusted_anomaly_score.
        """
        det_node = detection.get("node_id", "")
        det_class = detection.get("signal_class", "")
        det_family = detection.get("family", "")
        det_freq = detection.get("freq_hz", 0.0)
        det_ts = self._parse_timestamp(detection.get("timestamp"))
        det_anomaly = detection.get("anomaly_score", 0.0)

        det_bin = _freq_bin(det_freq, self.freq_tolerance_hz)

        correlated_nodes: set[str] = set()

        for other in recent_detections:
            other_node = other.get("node_id", "")
            if other_node == det_node:
                continue

            other_class = other.get("signal_class", "")
            other_family = other.get("family", "")
            other_freq = other.get("freq_hz", 0.0)
            other_ts = self._parse_timestamp(other.get("timestamp"))

            # Check signal match: same class or same family
            class_match = det_class == other_class or (
                det_family and det_family == other_family
            )
            if not class_match:
                continue

            # Check frequency match
            other_bin = _freq_bin(other_freq, self.freq_tolerance_hz)
            if det_bin != other_bin:
                continue

            # Check time window
            if det_ts and other_ts:
                delta = abs((det_ts - other_ts).total_seconds())
                if delta > self.time_window_sec:
                    continue

            correlated_nodes.add(other_node)

        total_active = self._total_active_nodes

        if not correlated_nodes:
            # Single-node-only detection: may indicate local interference.
            # Apply dampening factor to anomaly score.
            adjusted = self.adjust_anomaly_score(det_anomaly, correlated=False)
            corr_score = 1.0 / total_active if total_active > 1 else 0.0
            return CorrelationResult(
                correlated=False,
                node_count=1,
                total_active_nodes=total_active,
                node_ids=[det_node] if det_node else [],
                confidence_boost=0.0,
                correlation_score=round(corr_score, 4),
                adjusted_anomaly_score=round(adjusted, 4),
            )

        all_nodes = sorted({det_node} | correlated_nodes)
        node_count = len(all_nodes)
        boost = self._compute_boost(node_count)

        # Correlation score: confirming nodes / total active nodes
        corr_score = node_count / total_active if total_active > 0 else 1.0
        corr_score = min(1.0, corr_score)

        # Adjust anomaly score: boost it by correlation confidence
        adjusted = self.adjust_anomaly_score(
            det_anomaly,
            correlated=True,
            confidence_boost=boost,
        )

        return CorrelationResult(
            correlated=True,
            node_count=node_count,
            total_active_nodes=total_active,
            node_ids=all_nodes,
            confidence_boost=round(boost, 4),
            correlation_score=round(corr_score, 4),
            adjusted_anomaly_score=round(adjusted, 4),
        )

    # -----------------------------------------------------------------------
    # Anomaly score adjustment
    # -----------------------------------------------------------------------

    def adjust_anomaly_score(
        self,
        anomaly_score: float,
        *,
        correlated: bool,
        confidence_boost: float = 0.0,
    ) -> float:
        """Adjust an anomaly score based on cross-node correlation.

        Cross-node agreement increases the score (the signal is
        confirmed real by multiple observers).  Single-node-only
        detections get dampened since they may be local interference.

        Parameters
        ----------
        anomaly_score : float
            Original anomaly score [0, 1].
        correlated : bool
            Whether the detection was confirmed by other nodes.
        confidence_boost : float
            Boost factor from :meth:`_compute_boost` (0.0 – 0.2).

        Returns
        -------
        float
            Adjusted anomaly score, clamped to [0, 1].
        """
        if correlated:
            adjusted = anomaly_score * (1.0 + confidence_boost)
        else:
            # Dampen single-node detections when multiple nodes are active
            if self._total_active_nodes > 1:
                adjusted = anomaly_score * self.single_node_factor
            else:
                adjusted = anomaly_score
        return max(0.0, min(1.0, adjusted))

    # -----------------------------------------------------------------------
    # Correlation groups (for the API)
    # -----------------------------------------------------------------------

    def find_correlation_groups(
        self,
        detections: list[dict[str, Any]],
        min_nodes: int = 2,
    ) -> list[CorrelationGroup]:
        """Find all correlation groups in a set of detections.

        Groups detections by (signal_class, freq_bin) and returns
        groups where >= min_nodes distinct nodes participated.

        Parameters
        ----------
        detections : list[dict]
            All detections to analyse.
        min_nodes : int
            Minimum distinct nodes for a group to qualify.

        Returns
        -------
        list[CorrelationGroup]
            Correlated detection groups.
        """
        # Group by (signal_class, freq_bin)
        groups: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
        for det in detections:
            sig = det.get("signal_class", "")
            freq = det.get("freq_hz", 0.0)
            fbin = _freq_bin(freq, self.freq_tolerance_hz)
            groups[(sig, fbin)].append(det)

        result: list[CorrelationGroup] = []

        for (sig_class, fbin), group_dets in groups.items():
            # Sub-group by time window using a simple sliding window
            time_clusters = self._cluster_by_time(group_dets)
            for cluster in time_clusters:
                nodes = {d.get("node_id", "") for d in cluster}
                if len(nodes) < min_nodes:
                    continue

                # Build node info list
                node_info: list[dict[str, Any]] = []
                for d in cluster:
                    node_info.append(
                        {
                            "node_id": d.get("node_id", ""),
                            "timestamp": d.get("timestamp", ""),
                            "confidence": d.get("confidence", 0.0),
                            "snr_db": d.get("snr_db"),
                        }
                    )

                # Compute duration of the cluster
                timestamps = [
                    self._parse_timestamp(d.get("timestamp")) for d in cluster
                ]
                valid_ts = [t for t in timestamps if t is not None]
                if len(valid_ts) >= 2:
                    duration = (max(valid_ts) - min(valid_ts)).total_seconds()
                else:
                    duration = 0.0

                # Average frequency of the cluster
                freqs = [d.get("freq_hz", 0.0) for d in cluster]
                avg_freq = sum(freqs) / len(freqs) if freqs else 0.0

                # Correlation score: distinct nodes / total active
                total_active = self._total_active_nodes
                c_score = len(nodes) / total_active if total_active > 0 else 1.0
                c_score = min(1.0, c_score)

                result.append(
                    CorrelationGroup(
                        signal_class=sig_class,
                        freq_hz=round(avg_freq, 0),
                        nodes=node_info,
                        duration_sec=round(duration, 2),
                        correlation_score=round(c_score, 4),
                    )
                )

        # Sort by number of nodes descending
        result.sort(key=lambda g: len(g.nodes), reverse=True)

        # Trigger TDOA callback for clusters with 3+ nodes and tight timing
        if self._tdoa_callback is not None:
            tdoa_candidates = self.find_tdoa_candidates(
                detections,
                min_nodes=3,
                max_time_spread_sec=0.100,
            )
            for candidate in tdoa_candidates:
                try:
                    self._tdoa_callback(candidate)
                except Exception as exc:
                    logger.warning("TDOA callback failed: %s", exc)

        return result

    # -----------------------------------------------------------------------
    # TDOA candidate detection
    # -----------------------------------------------------------------------

    def find_tdoa_candidates(
        self,
        detections: list[dict[str, Any]],
        min_nodes: int = 3,
        max_time_spread_sec: float = 0.100,
    ) -> list[list[dict[str, Any]]]:
        """Find clusters of detections eligible for TDOA geolocation.

        A TDOA candidate is a group of detections with the same signal
        class at similar frequencies, from 3+ distinct nodes, all
        within *max_time_spread_sec* of each other.

        Parameters
        ----------
        detections : list[dict]
            All detections to analyse.
        min_nodes : int
            Minimum distinct nodes (default 3).
        max_time_spread_sec : float
            Maximum time spread in seconds (default 0.1 = 100 ms).

        Returns
        -------
        list[list[dict]]
            Each inner list is a TDOA-eligible cluster of detections.
        """
        # Group by (signal_class, freq_bin)
        groups: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
        for det in detections:
            sig = det.get("signal_class", "")
            freq = det.get("freq_hz", 0.0)
            fbin = _freq_bin(freq, self.freq_tolerance_hz)
            groups[(sig, fbin)].append(det)

        candidates: list[list[dict[str, Any]]] = []

        for (_sig_class, _fbin), group_dets in groups.items():
            # Tight clustering with the TDOA time window
            tight_clusters = self._cluster_by_time_window(
                group_dets,
                max_time_spread_sec,
            )
            for cluster in tight_clusters:
                nodes = {d.get("node_id", "") for d in cluster} - {""}
                if len(nodes) >= min_nodes:
                    candidates.append(cluster)

        return candidates

    def _cluster_by_time_window(
        self,
        detections: list[dict[str, Any]],
        window_sec: float,
    ) -> list[list[dict[str, Any]]]:
        """Cluster detections into groups within a tight time window.

        Similar to ``_cluster_by_time`` but uses a specified window
        in seconds (not the default multi-second correlation window).
        """
        if not detections:
            return []

        with_ts = []
        for d in detections:
            ts = self._parse_timestamp(d.get("timestamp"))
            if ts is not None:
                with_ts.append((ts, d))

        if not with_ts:
            return []

        with_ts.sort(key=lambda x: x[0])

        clusters: list[list[dict[str, Any]]] = []
        current_cluster: list[dict[str, Any]] = [with_ts[0][1]]
        cluster_start = with_ts[0][0]

        for ts, det in with_ts[1:]:
            if (ts - cluster_start).total_seconds() <= window_sec:
                current_cluster.append(det)
            else:
                clusters.append(current_cluster)
                current_cluster = [det]
                cluster_start = ts

        clusters.append(current_cluster)
        return clusters

    # -----------------------------------------------------------------------
    # Summary statistics
    # -----------------------------------------------------------------------

    def correlation_summary(
        self,
        detections: list[dict[str, Any]],
        min_nodes: int = 2,
    ) -> dict[str, Any]:
        """Compute summary statistics for correlation groups.

        Parameters
        ----------
        detections : list[dict]
            All detections to analyse.
        min_nodes : int
            Minimum distinct nodes for a group to qualify.

        Returns
        -------
        dict
            Summary with total_correlations_24h, avg_nodes_per_correlation,
            top_correlated_classes.
        """
        groups = self.find_correlation_groups(detections, min_nodes=min_nodes)

        if not groups:
            return {
                "total_correlations_24h": 0,
                "avg_nodes_per_correlation": 0.0,
                "top_correlated_classes": [],
            }

        total = len(groups)
        avg_nodes = sum(len(g.nodes) for g in groups) / total

        # Count signal classes
        class_counts: dict[str, int] = defaultdict(int)
        for g in groups:
            class_counts[g.signal_class] += 1

        top_classes = sorted(
            class_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        return {
            "total_correlations_24h": total,
            "avg_nodes_per_correlation": round(avg_nodes, 2),
            "top_correlated_classes": [
                {"signal_class": cls, "count": cnt} for cls, cnt in top_classes
            ],
        }

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _compute_boost(node_count: int) -> float:
        """Compute confidence boost based on number of correlated nodes.

        2 nodes: +0.1  (10% boost)
        3 nodes: +0.15
        4+ nodes: +0.2 (capped)
        """
        if node_count <= 1:
            return 0.0
        if node_count == 2:
            return 0.1
        if node_count == 3:
            return 0.15
        return 0.2

    @staticmethod
    def _parse_timestamp(ts: Any) -> datetime | None:
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

    def _cluster_by_time(
        self,
        detections: list[dict[str, Any]],
    ) -> list[list[dict[str, Any]]]:
        """Cluster detections into groups within the time window.

        Uses a simple approach: sort by timestamp, then merge adjacent
        detections that fall within the time window.
        """
        if not detections:
            return []

        # Sort by timestamp
        with_ts = []
        for d in detections:
            ts = self._parse_timestamp(d.get("timestamp"))
            if ts is not None:
                with_ts.append((ts, d))

        if not with_ts:
            # No parseable timestamps: treat all as one cluster
            return [detections]

        with_ts.sort(key=lambda x: x[0])

        clusters: list[list[dict[str, Any]]] = []
        current_cluster: list[dict[str, Any]] = [with_ts[0][1]]
        cluster_start = with_ts[0][0]

        for ts, det in with_ts[1:]:
            if (ts - cluster_start).total_seconds() <= self.time_window_sec:
                current_cluster.append(det)
            else:
                clusters.append(current_cluster)
                current_cluster = [det]
                cluster_start = ts

        clusters.append(current_cluster)
        return clusters
