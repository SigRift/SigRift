"""IF drift detection and auto-retraining trigger.

Monitors Isolation Forest score distribution for concept drift.
Tracks rolling mean and variance of anomaly scores over configurable
windows.  Triggers retraining when the current window's mean diverges
more than sigma_threshold standard deviations from the reference
distribution.
"""

from __future__ import annotations

import collections
import logging
import math
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


class DriftDetector:
    """Monitors IF score distribution for concept drift.

    Tracks rolling mean and variance of anomaly scores.  When the
    current window's mean diverges beyond ``sigma_threshold`` standard
    deviations from the reference distribution, ``has_drift()`` returns
    True to signal that retraining is needed.

    Parameters
    ----------
    window_size : int
        Number of scores in the rolling window (default 3600,
        roughly 1 hour at 1 detection/sec).
    sigma_threshold : float
        Number of standard deviations for drift detection (default 2.0).
    min_reference_samples : int
        Minimum samples needed to establish a reference distribution.
    cooldown_sec : float
        Minimum seconds between retraining triggers (default 3600).
    """

    def __init__(
        self,
        window_size: int = 3600,
        sigma_threshold: float = 2.0,
        min_reference_samples: int = 100,
        cooldown_sec: float = 3600.0,
    ) -> None:
        self.window_size = window_size
        self.sigma_threshold = sigma_threshold
        self.min_reference_samples = min_reference_samples
        self.cooldown_sec = cooldown_sec

        self._reference_mean: float | None = None
        self._reference_var: float | None = None
        self._reference_count: int = 0
        self._current_scores: collections.deque[float] = collections.deque(
            maxlen=window_size,
        )
        self._last_retrain: datetime | None = None
        self._drift_count: int = 0

    def add_score(self, score: float) -> None:
        """Add a new IF score to the rolling window.

        If no reference distribution exists and the window is full
        enough, automatically sets the reference.

        Parameters
        ----------
        score : float
            Anomaly score in [0, 1].
        """
        self._current_scores.append(score)

        # Auto-establish reference once we have enough samples
        if (
            self._reference_mean is None
            and len(self._current_scores) >= self.min_reference_samples
        ):
            self.update_reference()

    def has_drift(self) -> bool:
        """Check if current distribution has drifted beyond threshold.

        Returns False if insufficient data for comparison.

        Returns
        -------
        bool
            True if drift detected (current mean diverges beyond
            sigma_threshold standard deviations from reference).
        """
        if self._reference_mean is None or self._reference_var is None:
            return False
        if len(self._current_scores) < self.min_reference_samples:
            return False

        ref_std = math.sqrt(self._reference_var) if self._reference_var > 0 else 0.0
        if ref_std < 1e-9:
            # Zero variance reference: any difference counts as drift
            current_mean = sum(self._current_scores) / len(self._current_scores)
            return abs(current_mean - self._reference_mean) > 1e-6

        current_mean = sum(self._current_scores) / len(self._current_scores)
        # Standard error of the current window mean
        z = abs(current_mean - self._reference_mean) / ref_std
        return z > self.sigma_threshold

    def should_retrain(self) -> bool:
        """Check if retraining should be triggered.

        Returns True only if drift is detected AND the cooldown period
        since the last retrain has elapsed.

        Returns
        -------
        bool
        """
        if not self.has_drift():
            return False
        if self._last_retrain is not None:
            elapsed = (datetime.now(timezone.utc) - self._last_retrain).total_seconds()
            if elapsed < self.cooldown_sec:
                return False
        return True

    def update_reference(self) -> None:
        """Set current distribution as the new reference baseline.

        Computes mean and variance of the current rolling window and
        stores them as the reference distribution.
        """
        if len(self._current_scores) == 0:
            return

        n = len(self._current_scores)
        mean = sum(self._current_scores) / n
        var = sum((s - mean) ** 2 for s in self._current_scores) / n

        self._reference_mean = mean
        self._reference_var = var
        self._reference_count = n
        self._last_retrain = datetime.now(timezone.utc)
        self._drift_count = 0

        logger.info(
            "Drift detector reference updated: mean=%.4f, var=%.6f, n=%d",
            mean,
            var,
            n,
        )

    def mark_retrained(self) -> None:
        """Record that retraining has occurred.

        Resets the reference distribution to the current window and
        updates the cooldown timer.
        """
        self.update_reference()
        self._drift_count += 1

    def status(self) -> dict[str, Any]:
        """Return drift detection status.

        Returns
        -------
        dict
            Keys: reference_mean, reference_var, current_mean,
            current_var, current_window_size, has_drift,
            drift_count, last_retrain.
        """
        n = len(self._current_scores)
        if n > 0:
            current_mean = sum(self._current_scores) / n
            current_var = sum((s - current_mean) ** 2 for s in self._current_scores) / n
        else:
            current_mean = None
            current_var = None

        return {
            "reference_mean": self._reference_mean,
            "reference_var": self._reference_var,
            "reference_count": self._reference_count,
            "current_mean": round(current_mean, 6)
            if current_mean is not None
            else None,
            "current_var": round(current_var, 6) if current_var is not None else None,
            "current_window_size": n,
            "window_capacity": self.window_size,
            "has_drift": self.has_drift(),
            "drift_count": self._drift_count,
            "last_retrain": (
                self._last_retrain.isoformat() if self._last_retrain else None
            ),
        }
