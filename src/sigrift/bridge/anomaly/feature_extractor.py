"""Feature extraction for autoencoder (Tier 3) anomaly detection.

Produces a fixed 32-dimensional feature vector from detection dicts,
suitable for feeding into the AnomalyAutoencoder.  Normalizes all
features to approximately [0, 1] range.

Feature layout (32 dimensions):
  0-3:   Frequency features (log-normalized, sin/cos band position)
  4-7:   Power/SNR/confidence/bandwidth (normalized)
  8-15:  Signal class one-hot (top 8 classes)
  16-19: Time features (hour sin/cos, day-of-week sin/cos)
  20-23: IQ features (spectral_flatness, dc_offset, iq_imbalance, cfo)
  24-31: Reserved (zeros for future use)
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FEATURE_DIM = 32

# Top 8 signal classes for one-hot encoding (covers most common
# detections in typical RF environments)
_TOP_CLASSES: list[str] = [
    "fm",
    "am",
    "bpsk",
    "qpsk",
    "ofdm",
    "fsk",
    "ook",
    "gmsk",
]
_CLASS_TO_IDX: dict[str, int] = {c: i for i, c in enumerate(_TOP_CLASSES)}

# Frequency normalization: log10(freq_hz) mapped to [0, 1]
# Range: 1 MHz (6.0) to 6 GHz (9.78)
_FREQ_LOG_MIN = 6.0  # log10(1 MHz)
_FREQ_LOG_MAX = 9.8  # log10(~6.3 GHz)

# Power normalization
_POWER_MIN = -120.0
_POWER_MAX = 0.0

# Bandwidth normalization (log scale)
_BW_LOG_MIN = 3.0  # log10(1 kHz)
_BW_LOG_MAX = 7.5  # log10(~30 MHz)


class FeatureExtractor:
    """Extract fixed-size feature vectors from detection dicts for autoencoder.

    Produces a 32-dimensional feature vector from detection attributes,
    normalizing all values to approximately [0, 1].
    """

    FEATURE_DIM = FEATURE_DIM

    def extract(self, detection: dict[str, Any]) -> list[float]:
        """Extract 32-dim feature vector from a detection dict.

        Parameters
        ----------
        detection : dict
            Detection data with keys: freq_hz, power_dbm, snr_db,
            confidence, bandwidth_hz, signal_class, timestamp,
            and optionally iq_data (dict).

        Returns
        -------
        list[float]
            32-dimensional feature vector.
        """
        features = [0.0] * FEATURE_DIM

        freq_hz = float(detection.get("freq_hz", 0.0))
        power_dbm = detection.get("power_dbm")
        snr_db = detection.get("snr_db")
        confidence = float(detection.get("confidence", 0.0))
        bandwidth_hz = detection.get("bandwidth_hz")
        signal_class = str(detection.get("signal_class", "")).lower()
        timestamp = detection.get("timestamp")
        iq_data = detection.get("iq_data")

        # --- Features 0-3: Frequency ---
        if freq_hz > 0:
            log_freq = math.log10(max(freq_hz, 1.0))
            features[0] = _clamp(
                (log_freq - _FREQ_LOG_MIN) / (_FREQ_LOG_MAX - _FREQ_LOG_MIN)
            )
            # Band position as fraction of the spectrum
            features[1] = _clamp(freq_hz / 6_000_000_000)
            # Sin/cos of band position (captures cyclic structure)
            band_pos = freq_hz / 6_000_000_000 * 2 * math.pi
            features[2] = (math.sin(band_pos) + 1.0) / 2.0
            features[3] = (math.cos(band_pos) + 1.0) / 2.0

        # --- Features 4-7: Power, SNR, confidence, bandwidth ---
        if power_dbm is not None:
            features[4] = _clamp(
                (float(power_dbm) - _POWER_MIN) / (_POWER_MAX - _POWER_MIN)
            )
        else:
            features[4] = 0.5  # neutral

        if snr_db is not None:
            # SNR typically 0-40 dB
            features[5] = _clamp(float(snr_db) / 40.0)
        else:
            features[5] = 0.5

        features[6] = _clamp(confidence)

        if bandwidth_hz is not None and bandwidth_hz > 0:
            log_bw = math.log10(max(float(bandwidth_hz), 1.0))
            features[7] = _clamp((log_bw - _BW_LOG_MIN) / (_BW_LOG_MAX - _BW_LOG_MIN))
        else:
            features[7] = 0.0

        # --- Features 8-15: Signal class one-hot ---
        idx = _CLASS_TO_IDX.get(signal_class)
        if idx is not None:
            features[8 + idx] = 1.0

        # --- Features 16-19: Time features ---
        hour = _extract_hour(timestamp)
        dow = _extract_dow(timestamp)
        features[16] = (math.sin(2 * math.pi * hour / 24.0) + 1.0) / 2.0
        features[17] = (math.cos(2 * math.pi * hour / 24.0) + 1.0) / 2.0
        features[18] = (math.sin(2 * math.pi * dow / 7.0) + 1.0) / 2.0
        features[19] = (math.cos(2 * math.pi * dow / 7.0) + 1.0) / 2.0

        # --- Features 20-23: IQ features ---
        if isinstance(iq_data, dict):
            flatness = iq_data.get("spectral_flatness")
            if flatness is not None:
                features[20] = _clamp(float(flatness))

            dc_offset = iq_data.get("dc_offset")
            if dc_offset is not None:
                features[21] = _clamp(abs(float(dc_offset)))

            imbalance = iq_data.get("iq_imbalance")
            if imbalance is not None:
                features[22] = _clamp(abs(float(imbalance)) / 0.5)

            cfo_hz = iq_data.get("cfo_hz")
            if cfo_hz is not None:
                features[23] = _clamp(abs(float(cfo_hz)) / 5000.0)

        # Features 24-31: reserved (zeros)

        return features

    def extract_batch(self, detections: list[dict[str, Any]]) -> list[list[float]]:
        """Extract features for multiple detections.

        Parameters
        ----------
        detections : list[dict]
            List of detection dicts.

        Returns
        -------
        list[list[float]]
            List of 32-dim feature vectors.
        """
        return [self.extract(d) for d in detections]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    """Clamp value to [lo, hi]."""
    return max(lo, min(hi, value))


def _extract_hour(timestamp: Any) -> int:
    """Extract hour from timestamp."""
    if isinstance(timestamp, datetime):
        return timestamp.hour
    if isinstance(timestamp, str):
        try:
            return datetime.fromisoformat(timestamp).hour
        except (ValueError, TypeError):
            pass
    return datetime.now(timezone.utc).hour


def _extract_dow(timestamp: Any) -> int:
    """Extract day of week (0=Monday) from timestamp."""
    if isinstance(timestamp, datetime):
        return timestamp.weekday()
    if isinstance(timestamp, str):
        try:
            return datetime.fromisoformat(timestamp).weekday()
        except (ValueError, TypeError):
            pass
    return datetime.now(timezone.utc).weekday()
