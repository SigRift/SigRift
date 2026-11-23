"""Multi-protocol device correlation.

Identifies physical devices that emit on multiple protocols simultaneously
(e.g., phone = WiFi + BLE, IoT hub = WiFi + Zigbee + BLE) by correlating
temporal co-appearance, RSSI patterns, and observation frequency across
protocol boundaries.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class Observation:
    """Single protocol observation."""

    protocol: str
    device_id: str
    timestamp: float
    node_id: str
    rssi_dbm: float


@dataclass
class CorrelationResult:
    """Cross-protocol device correlation result."""

    protocol_a: str
    device_a: str
    protocol_b: str
    device_b: str
    confidence: float
    evidence: dict[str, float] = field(default_factory=dict)


class CrossProtocolCorrelator:
    """Correlate devices across WiFi, BLE, Zigbee, and other protocols.

    Devices that are physically co-located tend to appear and disappear
    together, have correlated RSSI trajectories, and are observed by
    the same edge nodes.
    """

    def __init__(self) -> None:
        self._observations: list[Observation] = []

    def add_observation(
        self,
        protocol: str,
        device_id: str,
        timestamp: float,
        node_id: str,
        rssi_dbm: float,
    ) -> None:
        """Record a protocol observation.

        Parameters
        ----------
        protocol : str
            Protocol name (e.g., "wifi", "ble", "zigbee").
        device_id : str
            Protocol-specific device identifier.
        timestamp : float
            Unix timestamp of the observation.
        node_id : str
            Edge node that made the observation.
        rssi_dbm : float
            Received signal strength in dBm.
        """
        self._observations.append(
            Observation(
                protocol=protocol,
                device_id=device_id,
                timestamp=timestamp,
                node_id=node_id,
                rssi_dbm=rssi_dbm,
            )
        )

    def find_correlations(
        self,
        time_window_s: float = 30.0,
        rssi_tolerance_db: float = 10.0,
    ) -> list[CorrelationResult]:
        """Find cross-protocol device correlations.

        For each pair of devices on different protocols observed by the
        same node, compute temporal overlap, RSSI correlation, and
        co-appearance count.

        Parameters
        ----------
        time_window_s : float
            Maximum time difference (seconds) to consider observations
            as temporally correlated.
        rssi_tolerance_db : float
            Maximum RSSI difference (dB) to consider observations as
            spatially correlated.

        Returns
        -------
        list[CorrelationResult]
            Correlations sorted by descending confidence.
        """
        # Group observations by (protocol, device_id)
        by_device: dict[tuple[str, str], list[Observation]] = {}
        for obs in self._observations:
            key = (obs.protocol, obs.device_id)
            by_device.setdefault(key, []).append(obs)

        device_keys = list(by_device.keys())
        results: list[CorrelationResult] = []

        for i in range(len(device_keys)):
            for j in range(i + 1, len(device_keys)):
                key_a = device_keys[i]
                key_b = device_keys[j]

                # Only correlate across different protocols
                if key_a[0] == key_b[0]:
                    continue

                obs_a = by_device[key_a]
                obs_b = by_device[key_b]

                evidence = self._compute_evidence(
                    obs_a,
                    obs_b,
                    time_window_s,
                    rssi_tolerance_db,
                )

                if evidence["co_appearance_count"] == 0:
                    continue

                confidence = self._compute_confidence(evidence)
                if confidence < 0.1:
                    continue

                results.append(
                    CorrelationResult(
                        protocol_a=key_a[0],
                        device_a=key_a[1],
                        protocol_b=key_b[0],
                        device_b=key_b[1],
                        confidence=confidence,
                        evidence=evidence,
                    )
                )

        results.sort(key=lambda r: r.confidence, reverse=True)
        return results

    def _compute_evidence(
        self,
        obs_a: list[Observation],
        obs_b: list[Observation],
        time_window_s: float,
        rssi_tolerance_db: float,
    ) -> dict[str, float]:
        """Compute correlation evidence between two device observation sets."""
        co_appearances = 0
        temporal_overlaps = 0
        rssi_diffs: list[float] = []
        common_nodes: set[str] = set()

        # Check each pair of observations for temporal proximity
        total_pairs = 0
        for a in obs_a:
            for b in obs_b:
                if a.node_id != b.node_id:
                    continue
                common_nodes.add(a.node_id)
                total_pairs += 1
                dt = abs(a.timestamp - b.timestamp)
                if dt <= time_window_s:
                    co_appearances += 1
                    rssi_diffs.append(abs(a.rssi_dbm - b.rssi_dbm))
                    if dt <= time_window_s / 2:
                        temporal_overlaps += 1

        if total_pairs == 0:
            return {
                "temporal_overlap_ratio": 0.0,
                "rssi_correlation": 0.0,
                "co_appearance_count": 0.0,
            }

        temporal_overlap_ratio = (
            temporal_overlaps / total_pairs if total_pairs > 0 else 0.0
        )

        # RSSI correlation: fraction of co-appearances within tolerance
        if rssi_diffs:
            rssi_within = sum(1 for d in rssi_diffs if d <= rssi_tolerance_db)
            rssi_correlation = rssi_within / len(rssi_diffs)
        else:
            rssi_correlation = 0.0

        return {
            "temporal_overlap_ratio": round(temporal_overlap_ratio, 4),
            "rssi_correlation": round(rssi_correlation, 4),
            "co_appearance_count": float(co_appearances),
        }

    @staticmethod
    def _compute_confidence(evidence: dict[str, float]) -> float:
        """Combine evidence signals into a single confidence score [0, 1]."""
        temporal = evidence.get("temporal_overlap_ratio", 0.0)
        rssi = evidence.get("rssi_correlation", 0.0)
        count = evidence.get("co_appearance_count", 0.0)

        # Count factor: logarithmic scaling, saturates around 20 co-appearances
        count_factor = min(1.0, math.log2(count + 1) / math.log2(21))

        # Weighted combination
        confidence = 0.4 * temporal + 0.3 * rssi + 0.3 * count_factor
        return round(min(1.0, confidence), 4)

    @property
    def observation_count(self) -> int:
        """Total number of recorded observations."""
        return len(self._observations)

    def clear(self) -> None:
        """Remove all observations."""
        self._observations.clear()
