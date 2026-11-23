"""Tier 2 Isolation Forest anomaly detector for RF signal detections.

Edge-side ML anomaly detection using scikit-learn's Isolation Forest.
Builds a 13-dimensional feature vector from detection attributes and
Tier 1 dimensional breakdowns.  Gracefully degrades if scikit-learn is
not installed.

DS-R7: tier1 overall score removed from features to preserve ensemble
diversity between Tier 1 and Tier 2.
DS-R8: Default contamination changed from 0.05 to "auto".
P2-4: Cyclical sin/cos encoding for hour and day_of_week.

Feature vector (13 dimensions):
  0: confidence
  1: entropy of softmax (from class probs if available, else 0)
  2: class_index / NUM_CLASSES
  3: family_index / NUM_FAMILIES
  4: super_family_index / NUM_SUPER_FAMILIES
  5: sin(2*pi*hour/24)
  6: cos(2*pi*hour/24)
  7: sin(2*pi*dow/7)
  8: cos(2*pi*dow/7)
  9: frequency_mhz / 3000
  10: power_normalized
  11: class_baseline_frequency
  12: seconds_since_last_detection
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import random
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sigrift.lib.taxonomy import (
    CLASS_TO_FAMILY,
    CLASS_TO_IDX,
    FAMILY_TO_IDX,
    FAMILY_TO_SF,
    NUM_CLASSES,
    NUM_FAMILIES,
    NUM_SUPER_FAMILIES,
    SF_TO_IDX,
)

try:
    import joblib

    HAS_JOBLIB = True
except ImportError:
    HAS_JOBLIB = False

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional sklearn import
# ---------------------------------------------------------------------------

try:
    from sklearn.ensemble import IsolationForest as _SKLearnIF

    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    _SKLearnIF = None  # type: ignore[assignment,misc]

# ---------------------------------------------------------------------------
# Taxonomy index mappings — derived from sigrift.lib.taxonomy
# ---------------------------------------------------------------------------

_CLASS_INDEX: dict[str, int] = CLASS_TO_IDX
_NUM_CLASSES: int = NUM_CLASSES

_FAMILY_INDEX: dict[str, int] = FAMILY_TO_IDX
_NUM_FAMILIES: int = NUM_FAMILIES

_SF_INDEX: dict[str, int] = SF_TO_IDX
_NUM_SF: int = NUM_SUPER_FAMILIES

# Class -> family uses lowercase family names for feature extraction;
# taxonomy uses uppercase.  Build a lowercase lookup for the scorer.
_CLASS_TO_FAMILY: dict[str, str] = {c: f.lower() for c, f in CLASS_TO_FAMILY.items()}
_FAMILY_INDEX_LOWER: dict[str, int] = {f.lower(): i for f, i in FAMILY_TO_IDX.items()}

# Family -> super-family (lowercase keys for scorer compatibility)
_FAMILY_TO_SF: dict[str, str] = {
    f.lower(): sf.lower() for f, sf in FAMILY_TO_SF.items()
}
_SF_INDEX_LOWER: dict[str, int] = {sf.lower(): i for sf, i in SF_TO_IDX.items()}

# Default power range for normalization
_POWER_MIN = -120.0
_POWER_MAX = 0.0

# P2-4: Feature vector metadata
FEATURE_VERSION = 2
NUM_IF_FEATURES = 13


def _write_checksum(model_path: Path) -> None:
    """Write SHA-256 checksum file alongside the model."""
    digest = hashlib.sha256(model_path.read_bytes()).hexdigest()
    model_path.with_suffix(".sha256").write_text(digest)


def _verify_checksum(model_path: Path) -> bool:
    """Verify SHA-256 checksum. Returns True if valid or no checksum file."""
    checksum_path = model_path.with_suffix(".sha256")
    if not checksum_path.exists():
        return True  # No checksum file = legacy model, allow loading
    expected = checksum_path.read_text().strip()
    actual = hashlib.sha256(model_path.read_bytes()).hexdigest()
    return actual == expected


# ---------------------------------------------------------------------------
# IsolationForestDetector
# ---------------------------------------------------------------------------


class IsolationForestDetector:
    """Tier 2 anomaly detection using Isolation Forest.

    Parameters
    ----------
    n_estimators : int
        Number of trees in the forest.
    max_samples : int
        Number of samples to draw for each tree.
    contamination : float
        Expected proportion of anomalies.
    min_training_samples : int
        Minimum samples required before training.
    """

    def __init__(
        self,
        n_estimators: int = 100,
        max_samples: int = 256,
        contamination: float | str = "auto",
        min_training_samples: int = 2000,
        max_buffer_size: int = 10_000,
    ) -> None:
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.min_training_samples = min_training_samples
        self.max_buffer_size = max_buffer_size  # DS-R13: cap training buffer

        self._model: Any = None
        self._trained = False
        self._training_buffer: list[list[float]] = []
        self._total_seen: int = 0  # DS-R13: total samples seen (for reservoir sampling)
        self._rng = random.Random(os.urandom(8))
        self._buffer_lock = threading.Lock()
        self._last_detection_time: float | None = None
        self._feature_version_stale: bool = False

    def is_ready(self) -> bool:
        """Return True if the model is trained and ready for scoring."""
        if not HAS_SKLEARN:
            return False
        return self._trained and self._model is not None

    def needs_training(self) -> bool:
        """Return True if enough samples are collected but not yet trained."""
        return (
            len(self._training_buffer) >= self.min_training_samples
            and not self._trained
        )

    def add_sample(self, features: list[float]) -> None:
        """Add a feature vector to the training buffer.

        Uses reservoir sampling (Algorithm R) when the buffer is full
        to maintain a representative sample without unbounded growth.

        Parameters
        ----------
        features : list[float]
            Feature vector.
        """
        with self._buffer_lock:
            self._total_seen += 1
            if len(self._training_buffer) < self.max_buffer_size:
                self._training_buffer.append(features)
            else:
                # DS-R13: Reservoir sampling — each new sample has a
                # max_buffer_size / total_seen probability of replacing
                # an existing sample, keeping the buffer representative.
                j = self._rng.randint(0, self._total_seen - 1)
                if j < self.max_buffer_size:
                    self._training_buffer[j] = features

    def train(self) -> None:
        """Fit the Isolation Forest on collected samples.

        Raises
        ------
        RuntimeError
            If scikit-learn is not installed or insufficient samples.
        """
        if not HAS_SKLEARN:
            raise RuntimeError("scikit-learn is required for Isolation Forest")

        if len(self._training_buffer) < self.min_training_samples:
            raise RuntimeError(
                f"Need {self.min_training_samples} samples, "
                f"have {len(self._training_buffer)}"
            )

        import numpy as np

        with self._buffer_lock:
            X = np.array(self._training_buffer, dtype=np.float32)

        self._model = _SKLearnIF(
            n_estimators=self.n_estimators,
            max_samples=min(self.max_samples, len(X)),
            contamination=self.contamination,
            random_state=42,
            n_jobs=1,
        )
        self._model.fit(X)
        self._trained = True

        logger.info(
            "Isolation Forest trained on %d samples (%d estimators)",
            len(X),
            self.n_estimators,
        )

    def score(self, features: list[float]) -> float:
        """Compute anomaly score for a feature vector.

        Parameters
        ----------
        features : list[float]
            12-dimensional feature vector.

        Returns
        -------
        float
            Anomaly score in [0, 1].  Higher = more anomalous.
            Returns 0.0 if model is not ready.
        """
        if not self.is_ready():
            return 0.0

        import numpy as np

        X = np.array([features], dtype=np.float32)

        # sklearn returns scores in [-1, 1] via decision_function
        # More negative = more anomalous
        raw_score = self._model.decision_function(X)[0]

        # Map from sklearn convention: negative = anomalous
        # decision_function: lower (more negative) = more anomalous
        # We want: higher = more anomalous, in [0, 1]
        # Use sigmoid-like mapping: score = 1 / (1 + exp(raw_score * k))
        # With k=5, score of 0 maps to 0.5
        mapped = 1.0 / (1.0 + math.exp(raw_score * 5.0))

        return max(0.0, min(1.0, mapped))

    def extract_features(
        self,
        detection: dict[str, Any],
        tier1_result: dict[str, Any] | None = None,
    ) -> list[float]:
        """Build an 11-dimensional feature vector from a detection.

        Parameters
        ----------
        detection : dict
            Detection data with keys: signal_class, confidence,
            freq_hz, power_dbm, timestamp, family.
        tier1_result : dict or None
            Tier 1 scoring result with keys: dimensions.

        Returns
        -------
        list[float]
            11-dimensional feature vector.
        """
        class_name = str(detection.get("signal_class", "")).lower()
        confidence = float(detection.get("confidence", 0.0))
        freq_hz = float(detection.get("freq_hz", 0.0))
        power_dbm = detection.get("power_dbm")
        timestamp = detection.get("timestamp")

        # Feature 0: confidence
        f0 = confidence

        # Feature 1: entropy of softmax probs (if available)
        class_probs = detection.get("class_probs")
        if class_probs and isinstance(class_probs, (list, dict)):
            probs = (
                list(class_probs.values())
                if isinstance(class_probs, dict)
                else class_probs
            )
            # Compute entropy: -sum(p * log(p))
            entropy = 0.0
            for p in probs:
                if p > 1e-10:
                    entropy -= p * math.log(p)
            # Normalize by max entropy (log(n_classes))
            max_entropy = math.log(max(len(probs), 2))
            f1 = entropy / max_entropy if max_entropy > 0 else 0.0
        else:
            f1 = 0.0

        # Feature 2: class index / num_classes
        f2 = _CLASS_INDEX.get(class_name, _NUM_CLASSES - 1) / max(_NUM_CLASSES, 1)

        # Feature 3: family index / num_families
        family = _CLASS_TO_FAMILY.get(class_name, "noise")
        f3 = _FAMILY_INDEX_LOWER.get(family, _NUM_FAMILIES - 1) / max(_NUM_FAMILIES, 1)

        # Feature 4: super-family index / num_sf
        sf = _FAMILY_TO_SF.get(family, "noise")
        f4 = _SF_INDEX_LOWER.get(sf, _NUM_SF - 1) / max(_NUM_SF, 1)

        # Features 5-6: cyclical hour encoding (sin/cos)
        hour = self._extract_hour(timestamp)
        f5 = math.sin(2 * math.pi * hour / 24.0)
        f6 = math.cos(2 * math.pi * hour / 24.0)

        # Features 7-8: cyclical day-of-week encoding (sin/cos)
        dow = self._extract_day_of_week(timestamp)
        f7 = math.sin(2 * math.pi * dow / 7.0)
        f8 = math.cos(2 * math.pi * dow / 7.0)

        # Feature 9: frequency_mhz / 3000
        f9 = (freq_hz / 1e6) / 3000.0

        # Feature 10: power normalized to [0, 1]
        if power_dbm is not None:
            f10 = (float(power_dbm) - _POWER_MIN) / (_POWER_MAX - _POWER_MIN)
            f10 = max(0.0, min(1.0, f10))
        else:
            f10 = 0.5  # neutral

        # Feature 11: class baseline frequency (how often this class appears)
        # DS-R7: tier1 overall score removed to avoid leaking Tier 1 into
        # Tier 2, which reduces ensemble diversity.
        f11 = 0.0
        if tier1_result is not None:
            dims = tier1_result.get("dimensions", {})
            rare_score = dims.get("rare_class", 0.0)
            f11 = 1.0 - rare_score

        # Feature 12: seconds since last detection
        now_ts = datetime.now(timezone.utc).timestamp()
        if self._last_detection_time is not None:
            delta = now_ts - self._last_detection_time
            f12 = min(delta / 3600.0, 1.0)
        else:
            f12 = 1.0  # first detection
        self._last_detection_time = now_ts

        return [f0, f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12]

    def retrain(self, samples: list[list[float]] | None = None) -> None:
        """Retrain the model on new or existing buffer data.

        Parameters
        ----------
        samples : list[list[float]] or None
            Training feature vectors. If None, retrains on the
            current buffer (DS-R13: useful for drift-triggered retrain).
        """
        if samples is not None:
            self._training_buffer = list(samples)
        self._trained = False
        self.train()

    @property
    def buffer_size(self) -> int:
        """Current training buffer size."""
        return len(self._training_buffer)

    @property
    def total_seen(self) -> int:
        """Total samples ever seen (including those evicted by reservoir sampling)."""
        return self._total_seen

    def save(self, path: str) -> None:
        """Save the trained model via joblib.

        Parameters
        ----------
        path : str
            Output file path.

        Raises
        ------
        RuntimeError
            If joblib is not installed.
        """
        if not self.is_ready():
            logger.warning("Cannot save: model is not trained")
            return

        if not HAS_JOBLIB:
            raise RuntimeError(
                "joblib is required to save Isolation Forest models "
                "(pickle fallback removed for security, see FIX-014)"
            )

        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "model": self._model,
            "n_estimators": self.n_estimators,
            "max_samples": self.max_samples,
            "contamination": self.contamination,
            "min_training_samples": self.min_training_samples,
            "feature_version": FEATURE_VERSION,
        }

        joblib.dump(data, str(p))

        # Write SHA-256 checksum alongside the model file
        _write_checksum(p)
        logger.info("Isolation Forest saved to %s", path)

    def load(self, path: str) -> None:
        """Load a trained model via joblib.

        Parameters
        ----------
        path : str
            Input file path.

        Raises
        ------
        RuntimeError
            If joblib is not installed.
        """
        if not HAS_SKLEARN:
            logger.warning("Cannot load IF model: scikit-learn not installed")
            return

        if not HAS_JOBLIB:
            raise RuntimeError(
                "joblib is required to load Isolation Forest models "
                "(pickle fallback removed for security, see FIX-014)"
            )

        p = Path(path)
        if not p.exists():
            logger.warning("IF model file not found: %s", path)
            return

        try:
            # Verify checksum before deserializing
            if not _verify_checksum(p):
                logger.warning("IF model checksum verification failed: %s", path)
                return

            data = joblib.load(str(p))

            self._model = data["model"]
            self.n_estimators = data.get("n_estimators", self.n_estimators)
            self.max_samples = data.get("max_samples", self.max_samples)
            self.contamination = data.get("contamination", self.contamination)
            self.min_training_samples = data.get(
                "min_training_samples", self.min_training_samples
            )
            self._trained = True

            saved_version = data.get("feature_version", 1)
            if saved_version != FEATURE_VERSION:
                logger.warning(
                    "IF model feature version mismatch: saved=%d, current=%d. "
                    "Retrain recommended.",
                    saved_version,
                    FEATURE_VERSION,
                )
                self._feature_version_stale = True
            else:
                self._feature_version_stale = False

            logger.info("Isolation Forest loaded from %s", path)
        except (KeyError, OSError, Exception) as exc:
            logger.warning("Failed to load IF model from %s: %s", path, exc)

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
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

    @staticmethod
    def _extract_day_of_week(timestamp: Any) -> int:
        """Extract day of week (0=Monday) from timestamp."""
        if isinstance(timestamp, datetime):
            return timestamp.weekday()
        if isinstance(timestamp, str):
            try:
                return datetime.fromisoformat(timestamp).weekday()
            except (ValueError, TypeError):
                pass
        return datetime.now(timezone.utc).weekday()
