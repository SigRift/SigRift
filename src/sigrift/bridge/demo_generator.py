"""Demo data generator for The Bridge (P3-18).

Generates realistic synthetic RF detection data for demos and testing.
Produces detection dicts compatible with the batch ingest API, with
configurable anomaly injection scenarios.

Usage:
    gen = DemoGenerator(anomaly_rate=0.1)
    batch = gen.generate_batch(n=20)
    # -> list of detection dicts ready for POST /api/detections/batch
"""

from __future__ import annotations

import logging
import random
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# ISM band center frequencies (Hz)
ISM_BANDS: dict[str, float] = {
    "433MHz": 433.92e6,
    "868MHz": 868.0e6,
    "915MHz": 915.0e6,
    "2.4GHz": 2.4e9,
    "5.8GHz": 5.8e9,
}

# Signal classes with typical family groupings
SIGNAL_CLASSES: dict[str, str] = {
    "bpsk": "psk",
    "qpsk": "psk",
    "ofdm": "ofdm",
    "fsk": "fsk",
    "ook": "ook",
    "bluetooth": "bluetooth",
    "wifi": "wifi",
    "zigbee": "zigbee",
    "unknown": "",
}

# Typical power/SNR ranges per band (power_dbm_range, snr_db_range)
_BAND_PROFILES: dict[str, tuple[tuple[float, float], tuple[float, float]]] = {
    "433MHz": ((-90.0, -50.0), (5.0, 25.0)),
    "868MHz": ((-85.0, -45.0), (8.0, 30.0)),
    "915MHz": ((-85.0, -45.0), (8.0, 30.0)),
    "2.4GHz": ((-80.0, -30.0), (10.0, 35.0)),
    "5.8GHz": ((-75.0, -25.0), (12.0, 40.0)),
}

# Typical bandwidth per signal class (Hz)
_CLASS_BANDWIDTH: dict[str, float] = {
    "bpsk": 25e3,
    "qpsk": 50e3,
    "ofdm": 20e6,
    "fsk": 50e3,
    "ook": 10e3,
    "bluetooth": 1e6,
    "wifi": 20e6,
    "zigbee": 2e6,
    "unknown": 100e3,
}

# Demo edge nodes
DEFAULT_NODES = ["node-demo-1", "node-demo-2", "node-demo-3"]

# Anomaly types
ANOMALY_TYPES = ["novel_class", "power_spike", "evil_twin", "quiet_frequency"]


# ---------------------------------------------------------------------------
# DemoGenerator
# ---------------------------------------------------------------------------


class DemoGenerator:
    """Generates synthetic RF detection data for demos and testing.

    Args:
        nodes: List of edge node IDs to distribute detections across.
        anomaly_rate: Fraction of detections that are anomalous (0.0-1.0).
        seed: Optional random seed for reproducibility.
    """

    def __init__(
        self,
        nodes: list[str] | None = None,
        anomaly_rate: float = 0.1,
        seed: int | None = None,
    ) -> None:
        if not 0.0 <= anomaly_rate <= 1.0:
            raise ValueError(f"anomaly_rate must be 0.0-1.0, got {anomaly_rate}")
        self.nodes = nodes or list(DEFAULT_NODES)
        self.anomaly_rate = anomaly_rate
        self._rng = random.Random(seed)

    def _random_band(self) -> str:
        """Pick a random ISM band name."""
        return self._rng.choice(list(ISM_BANDS.keys()))

    def _random_signal_class(self) -> str:
        """Pick a random signal class (excluding 'unknown' for normal detections)."""
        classes = [c for c in SIGNAL_CLASSES if c != "unknown"]
        return self._rng.choice(classes)

    def _generate_one(self) -> dict[str, Any]:
        """Generate a single normal detection dict."""
        band = self._random_band()
        freq_hz = ISM_BANDS[band]
        # Add slight frequency offset for realism
        freq_hz += self._rng.gauss(0, 50e3)

        signal_class = self._random_signal_class()
        family = SIGNAL_CLASSES[signal_class]
        node_id = self._rng.choice(self.nodes)

        power_range, snr_range = _BAND_PROFILES[band]
        power_dbm = self._rng.uniform(*power_range)
        snr_db = self._rng.uniform(*snr_range)
        confidence = self._rng.uniform(0.7, 0.99)
        bandwidth_hz = _CLASS_BANDWIDTH.get(signal_class, 100e3)

        return {
            "detection_id": uuid.uuid4().hex[:16],
            "node_id": node_id,
            "signal_class": signal_class,
            "confidence": round(confidence, 4),
            "freq_hz": round(freq_hz, 2),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "power_dbm": round(power_dbm, 2),
            "snr_db": round(snr_db, 2),
            "bandwidth_hz": bandwidth_hz,
            "family": family,
            "anomaly_score": 0.0,
        }

    def inject_anomaly(
        self,
        detection: dict[str, Any],
        anomaly_type: str,
    ) -> dict[str, Any]:
        """Modify a detection dict to represent an anomalous observation.

        Args:
            detection: A normal detection dict (will be modified in place
                and also returned).
            anomaly_type: One of "novel_class", "power_spike", "evil_twin",
                or "quiet_frequency".

        Returns:
            The modified detection dict with elevated anomaly_score.

        Raises:
            ValueError: If anomaly_type is not recognized.
        """
        if anomaly_type not in ANOMALY_TYPES:
            raise ValueError(
                f"Unknown anomaly_type {anomaly_type!r}, must be one of {ANOMALY_TYPES}"
            )

        if anomaly_type == "novel_class":
            detection["signal_class"] = "unknown"
            detection["family"] = ""
            detection["confidence"] = round(self._rng.uniform(0.1, 0.4), 4)
            detection["anomaly_score"] = round(self._rng.uniform(0.7, 1.0), 4)

        elif anomaly_type == "power_spike":
            # Sudden +20 dB power increase
            current_power = detection.get("power_dbm", -60.0)
            detection["power_dbm"] = round(current_power + 20.0, 2)
            detection["anomaly_score"] = round(self._rng.uniform(0.6, 0.9), 4)

        elif anomaly_type == "evil_twin":
            # WiFi with slightly shifted frequency
            detection["signal_class"] = "wifi"
            detection["family"] = "wifi"
            detection["freq_hz"] = round(2.412e9 + self._rng.uniform(1e3, 5e3), 2)
            detection["bandwidth_hz"] = 20e6
            detection["anomaly_score"] = round(self._rng.uniform(0.5, 0.8), 4)

        elif anomaly_type == "quiet_frequency":
            # Detection on a normally-silent frequency
            detection["freq_hz"] = round(self._rng.uniform(400e6, 410e6), 2)
            detection["anomaly_score"] = round(self._rng.uniform(0.5, 0.9), 4)

        return detection

    def generate_batch(self, n: int = 10) -> list[dict[str, Any]]:
        """Generate a batch of detection dicts.

        A fraction of detections (controlled by anomaly_rate) will have
        anomalies injected. The anomaly type is chosen randomly.

        Args:
            n: Number of detections to generate (must be >= 1).

        Returns:
            List of detection dicts compatible with the ingest API.
        """
        if n < 1:
            raise ValueError(f"n must be >= 1, got {n}")

        batch: list[dict[str, Any]] = []
        for _ in range(n):
            det = self._generate_one()
            if self._rng.random() < self.anomaly_rate:
                anomaly_type = self._rng.choice(ANOMALY_TYPES)
                self.inject_anomaly(det, anomaly_type)
            batch.append(det)

        return batch
