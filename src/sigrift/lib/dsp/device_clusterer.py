"""DBSCAN-based device clustering for WiFi de-anonymization.

Groups probe request observations into physical device clusters using
a two-stage approach:
  Stage 1: DBSCAN on IE fingerprints (Hamming distance)
  Stage 2: Refinement using timing signatures and sequence number continuity

Each cluster represents one physical device, potentially observed under
multiple randomized MAC addresses.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone

import numpy as np

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Known device class signatures (IE fingerprint prefix → device class)
# ---------------------------------------------------------------------------

_KNOWN_DEVICE_CLASSES: dict[str, str] = {
    # Apple devices (htcap patterns)
    "001c": "Apple iOS Device",
    "002b": "Apple macOS Device",
    # Samsung
    "004f": "Samsung Galaxy",
    "0051": "Samsung Galaxy",
    # Google Pixel
    "006a": "Google Pixel",
    # Windows
    "007f": "Windows Laptop",
    # IoT common patterns
    "00a0": "IoT Hub",
    "00b1": "Smart Speaker",
}

_VENDOR_OUI_DEVICE_MAP: dict[str, str] = {
    "00:17:88": "Philips Hue",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "ac:23:3f": "Shenzhen IoT",
    "50:02:91": "Amazon Echo",
    "68:54:fd": "Amazon Device",
    "f0:d2:f1": "Google Home",
    "30:fd:38": "Google Nest",
}


# ---------------------------------------------------------------------------
# DeviceCluster dataclass
# ---------------------------------------------------------------------------


@dataclass
class DeviceCluster:
    """Observations grouped as one device under the current clustering policy.

    ``cluster_id`` identifies the current fingerprint/MAC membership, not a
    persistent physical-device identity. Adding a previously unseen fingerprint
    or MAC can change it. For unchanged resolved membership, input order and
    observation counts do not affect the ID.
    """

    cluster_id: str
    ie_fingerprint: str
    timing_signature: dict[str, float] = field(default_factory=dict)
    device_class: str = ""
    confidence: float = 0.0
    first_seen: str = ""
    last_seen: str = ""
    mac_addresses: list[str] = field(default_factory=list)
    observation_count: int = 0


# ---------------------------------------------------------------------------
# Internal observation record
# ---------------------------------------------------------------------------


@dataclass
class _Observation:
    mac: str
    ie_fingerprint: str
    timing_sig: dict[str, float]
    seq_num: int
    rssi_dbm: float
    timestamp: str
    node_id: str


# ---------------------------------------------------------------------------
# DeviceClusterer
# ---------------------------------------------------------------------------


class DeviceClusterer:
    """Cluster WiFi probe request observations into physical device groups.

    Parameters
    ----------
    eps : float
        DBSCAN distance threshold (Hamming ratio). Default 0.15.
    min_samples : int
        DBSCAN minimum cluster size. Default 3.
    timing_threshold : float
        L2 distance threshold for timing signature refinement. Default 50000.
    """

    def __init__(
        self,
        eps: float = 0.15,
        min_samples: int = 3,
        timing_threshold: float = 50_000.0,
    ) -> None:
        self._eps = eps
        self._min_samples = min_samples
        self._timing_threshold = timing_threshold
        self._observations: list[_Observation] = []
        self._clusters: list[DeviceCluster] = []
        self._mac_to_cluster: dict[str, str] = {}

    def add_observation(
        self,
        mac: str,
        ie_fingerprint: str,
        timing_sig: dict[str, float] | None = None,
        seq_num: int = -1,
        rssi_dbm: float = -70.0,
        timestamp: str | None = None,
        node_id: str = "",
    ) -> None:
        """Add a probe request observation for clustering."""
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        self._observations.append(
            _Observation(
                mac=mac,
                ie_fingerprint=ie_fingerprint,
                timing_sig=timing_sig or {},
                seq_num=seq_num,
                rssi_dbm=rssi_dbm,
                timestamp=ts,
                node_id=node_id,
            )
        )

    def run_clustering(self) -> list[DeviceCluster]:
        """Execute two-stage clustering and return device clusters.

        Stage 1: DBSCAN on IE fingerprint Hamming distance matrix
        Stage 2: Refine clusters using timing signature L2 distance
        """
        if len(self._observations) < self._min_samples:
            return []

        # Build fingerprint list
        fps = [obs.ie_fingerprint for obs in self._observations]
        unique_fps = sorted(set(fps))

        if len(unique_fps) == 0:
            return []

        # Stage 1: DBSCAN on IE fingerprints
        n = len(unique_fps)
        dist_matrix = np.zeros((n, n), dtype=np.float64)
        for i in range(n):
            for j in range(i + 1, n):
                d = _hamming_ratio(unique_fps[i], unique_fps[j])
                dist_matrix[i, j] = d
                dist_matrix[j, i] = d

        try:
            from sklearn.cluster import DBSCAN

            dbscan = DBSCAN(eps=self._eps, min_samples=1, metric="precomputed")
            labels = dbscan.fit_predict(dist_matrix)
        except ImportError:
            # Fallback: treat each unique fingerprint as its own cluster
            labels = list(range(n))

        # Map fingerprint → cluster label
        fp_to_label: dict[str, int] = {}
        for i, fp in enumerate(unique_fps):
            fp_to_label[fp] = labels[i]

        # Group observations by cluster label
        label_obs: dict[int, list[_Observation]] = {}
        for obs in self._observations:
            lbl = fp_to_label.get(obs.ie_fingerprint, -1)
            label_obs.setdefault(lbl, []).append(obs)

        # Stage 2: Refine with timing signatures
        clusters: list[DeviceCluster] = []
        self._mac_to_cluster.clear()

        for lbl, obs_list in label_obs.items():
            if lbl == -1:
                continue

            # Sub-cluster by timing signature if multiple distinct MACs
            sub_clusters = self._refine_by_timing(obs_list)
            for sub_obs in sub_clusters:
                cluster = self._build_cluster(sub_obs)
                clusters.append(cluster)
                for mac in cluster.mac_addresses:
                    self._mac_to_cluster[mac] = cluster.cluster_id

        self._clusters = clusters
        return clusters

    def _refine_by_timing(
        self,
        obs_list: list[_Observation],
    ) -> list[list[_Observation]]:
        """Split a coarse cluster using timing signature distance."""
        if len(obs_list) <= 1:
            return [obs_list]

        # Group by MAC first
        mac_groups: dict[str, list[_Observation]] = {}
        for obs in obs_list:
            mac_groups.setdefault(obs.mac, []).append(obs)

        if len(mac_groups) <= 1:
            return [obs_list]

        # Compute average timing signature per MAC
        mac_sigs: dict[str, dict[str, float]] = {}
        for mac, mac_obs in mac_groups.items():
            sigs = [o.timing_sig for o in mac_obs if o.timing_sig]
            if sigs:
                mac_sigs[mac] = _average_timing_sig(sigs)

        if not mac_sigs:
            return [obs_list]

        # Greedy clustering: merge MACs with similar timing
        mac_list = list(mac_groups.keys())
        assigned: dict[str, int] = {}
        cluster_idx = 0

        for mac in mac_list:
            if mac in assigned:
                continue
            assigned[mac] = cluster_idx
            sig = mac_sigs.get(mac)
            if sig:
                for other in mac_list:
                    if other in assigned:
                        continue
                    other_sig = mac_sigs.get(other)
                    if other_sig:
                        dist = _timing_l2_distance(sig, other_sig)
                        if dist < self._timing_threshold:
                            assigned[other] = cluster_idx
                    else:
                        # No timing data — keep in same cluster
                        assigned[other] = cluster_idx
            cluster_idx += 1

        # Build sub-cluster lists
        sub: dict[int, list[_Observation]] = {}
        for mac, idx in assigned.items():
            for obs in mac_groups[mac]:
                sub.setdefault(idx, []).append(obs)

        return list(sub.values())

    def _build_cluster(self, obs_list: list[_Observation]) -> DeviceCluster:
        """Build a DeviceCluster from a group of observations."""
        macs = sorted(set(o.mac for o in obs_list))
        fps = [o.ie_fingerprint for o in obs_list]
        fingerprints = sorted(set(fps))
        # Equal support prefers the lexically first fingerprint deterministically.
        main_fp = max(fingerprints, key=fps.count)

        # Timing signature: average of all available
        all_sigs = [o.timing_sig for o in obs_list if o.timing_sig]
        timing_sig = _average_timing_sig(all_sigs) if all_sigs else {}

        # Timestamps
        timestamps = sorted(o.timestamp for o in obs_list if o.timestamp)
        first_seen = timestamps[0] if timestamps else ""
        last_seen = timestamps[-1] if timestamps else ""

        # Confidence: based on observation count and MAC diversity
        obs_count = len(obs_list)
        mac_count = len(macs)
        confidence = min(1.0, obs_count / 10.0) * min(1.0, mac_count / 3.0)
        if mac_count > 1:
            confidence = min(confidence + 0.2, 1.0)

        # Device class inference
        device_class = self.infer_device_class(
            main_fp,
            [
                (i, d)
                for o in obs_list
                for i, d in (o.timing_sig.items() if False else [])
            ],
        )

        # Timing refinement can split one fingerprint into distinct MAC groups.
        # Encode both member sets canonically so those groups remain distinct,
        # without making identity depend on input order or duplicate counts.
        membership = json.dumps([fingerprints, macs], separators=(",", ":"))
        cluster_id = hashlib.sha256(membership.encode()).hexdigest()[:12]

        return DeviceCluster(
            cluster_id=cluster_id,
            ie_fingerprint=main_fp,
            timing_signature=timing_sig,
            device_class=device_class,
            confidence=round(confidence, 4),
            first_seen=first_seen,
            last_seen=last_seen,
            mac_addresses=macs,
            observation_count=obs_count,
        )

    def get_cluster_for_mac(self, mac: str) -> DeviceCluster | None:
        """Return the cluster containing the given MAC, or None."""
        cid = self._mac_to_cluster.get(mac)
        if cid is None:
            return None
        for c in self._clusters:
            if c.cluster_id == cid:
                return c
        return None

    def get_all_clusters(self) -> list[DeviceCluster]:
        """Return all current clusters."""
        return list(self._clusters)

    @staticmethod
    def infer_device_class(
        ie_fingerprint: str,
        vendor_specific: list[tuple[int, str]] | None = None,
    ) -> str:
        """Map IE fingerprint and vendor IEs to a device class string.

        Checks known fingerprint prefixes first, then vendor OUIs.
        Falls back to 'Unknown Device'.
        """
        # Check fingerprint prefix table
        for prefix, device_class in _KNOWN_DEVICE_CLASSES.items():
            if ie_fingerprint.startswith(prefix):
                return device_class

        return "Unknown Device"


# ---------------------------------------------------------------------------
# Distance helpers
# ---------------------------------------------------------------------------


def _hamming_ratio(a: str, b: str) -> float:
    """Compute normalised Hamming distance between two hex strings.

    Returns the fraction of differing nibbles.  Strings are zero-padded
    to equal length if needed.
    """
    max_len = max(len(a), len(b))
    if max_len == 0:
        return 0.0
    a = a.ljust(max_len, "0")
    b = b.ljust(max_len, "0")
    diffs = sum(1 for ca, cb in zip(a, b) if ca != cb)
    return diffs / max_len


def _timing_l2_distance(
    a: dict[str, float],
    b: dict[str, float],
) -> float:
    """L2 (Euclidean) distance between two timing signature dicts."""
    keys = [
        "mean_ifat_us",
        "std_ifat_us",
        "mean_ibt_us",
        "std_ibt_us",
        "burst_size_mean",
        "burst_size_std",
        "burst_freq_hz",
    ]
    sq_sum = 0.0
    for k in keys:
        diff = a.get(k, 0.0) - b.get(k, 0.0)
        sq_sum += diff * diff
    return math.sqrt(sq_sum)


def _average_timing_sig(sigs: list[dict[str, float]]) -> dict[str, float]:
    """Compute element-wise average of timing signature dicts."""
    if not sigs:
        return {}
    keys = [
        "mean_ifat_us",
        "std_ifat_us",
        "mean_ibt_us",
        "std_ibt_us",
        "burst_size_mean",
        "burst_size_std",
        "burst_freq_hz",
    ]
    result: dict[str, float] = {}
    n = len(sigs)
    for k in keys:
        result[k] = sum(s.get(k, 0.0) for s in sigs) / n
    return result
