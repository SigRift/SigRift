"""Platt scaling / score calibration for anomaly scores.

Maps raw anomaly scores to calibrated P(anomaly) using operator
feedback (TP/FP labels).  Fits a logistic sigmoid per frequency band:

    P(anomaly|score) = 1 / (1 + exp(-(a*score + b)))

Uses gradient descent on log-loss to fit (a, b) — no scipy/sklearn
dependency required.
"""

from __future__ import annotations

import logging
import math
from typing import Any

from sigrift.bridge.anomaly.bands import get_band as _get_band

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sigmoid helpers
# ---------------------------------------------------------------------------


def _sigmoid(x: float) -> float:
    """Numerically stable sigmoid."""
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    ex = math.exp(x)
    return ex / (1.0 + ex)


def _log_loss(a: float, b: float, data: list[tuple[float, bool]]) -> float:
    """Compute average log-loss for the sigmoid model."""
    eps = 1e-15
    total = 0.0
    for score, label in data:
        p = _sigmoid(a * score + b)
        p = max(eps, min(1.0 - eps, p))
        if label:
            total -= math.log(p)
        else:
            total -= math.log(1.0 - p)
    return total / max(len(data), 1)


# ---------------------------------------------------------------------------
# ScoreCalibrator
# ---------------------------------------------------------------------------


class ScoreCalibrator:
    """Maps raw anomaly scores to calibrated P(anomaly) via Platt scaling.

    Uses logistic regression on operator feedback (TP/FP labels) to fit
    a sigmoid: P(anomaly|score) = 1 / (1 + exp(-(a*score + b)))

    Maintains per-frequency-band calibration curves.

    Parameters
    ----------
    min_samples : int
        Minimum feedback samples per band before fitting a curve.
    """

    def __init__(self, min_samples: int = 30) -> None:
        self._curves: dict[str, tuple[float, float]] = {}  # band -> (a, b)
        self._feedback: dict[str, list[tuple[float, bool]]] = {}
        self.min_samples = min_samples

    def add_feedback(self, score: float, is_anomaly: bool, freq_hz: float) -> None:
        """Record operator feedback for calibration.

        Parameters
        ----------
        score : float
            Raw anomaly score in [0, 1].
        is_anomaly : bool
            True if operator confirmed anomaly (TP), False if FP.
        freq_hz : float
            Detection frequency in Hz (determines band).
        """
        band = self.get_band(freq_hz)
        if band not in self._feedback:
            self._feedback[band] = []
        self._feedback[band].append((score, is_anomaly))

    def calibrate(self, score: float, freq_hz: float) -> float:
        """Return calibrated P(anomaly) for a raw score.

        If the band is not yet calibrated (insufficient feedback),
        returns the raw score unchanged.

        Parameters
        ----------
        score : float
            Raw anomaly score in [0, 1].
        freq_hz : float
            Detection frequency in Hz.

        Returns
        -------
        float
            Calibrated probability in [0, 1].
        """
        band = self.get_band(freq_hz)
        if band not in self._curves:
            return score
        a, b = self._curves[band]
        return _sigmoid(a * score + b)

    def fit_band(self, band: str) -> bool:
        """Fit sigmoid for a frequency band using gradient descent.

        Returns True if enough samples existed and fitting succeeded.

        Parameters
        ----------
        band : str
            Band name (e.g. "sub_1ghz").

        Returns
        -------
        bool
            True if the curve was fitted successfully.
        """
        data = self._feedback.get(band, [])
        if len(data) < self.min_samples:
            return False

        # Check that we have both positive and negative labels
        positives = sum(1 for _, lbl in data if lbl)
        negatives = len(data) - positives
        if positives == 0 or negatives == 0:
            return False

        # Gradient descent on log-loss
        a = 1.0
        b = 0.0
        lr = 0.1
        eps = 1e-15
        n = len(data)

        for _ in range(500):
            grad_a = 0.0
            grad_b = 0.0
            for score, label in data:
                p = _sigmoid(a * score + b)
                p = max(eps, min(1.0 - eps, p))
                err = p - (1.0 if label else 0.0)
                grad_a += err * score
                grad_b += err
            grad_a /= n
            grad_b /= n

            a -= lr * grad_a
            b -= lr * grad_b

        self._curves[band] = (a, b)
        logger.info(
            "Calibrator fitted band %s: a=%.4f, b=%.4f (n=%d)",
            band,
            a,
            b,
            n,
        )
        return True

    def fit_all(self) -> dict[str, bool]:
        """Fit calibration curves for all bands with sufficient data.

        Returns
        -------
        dict[str, bool]
            Mapping of band name to fit success.
        """
        results = {}
        for band in self._feedback:
            results[band] = self.fit_band(band)
        return results

    def get_band(self, freq_hz: float) -> str:
        """Map frequency to band name.

        Parameters
        ----------
        freq_hz : float
            Frequency in Hz.

        Returns
        -------
        str
            One of: sub_1ghz, ism_2_4ghz, ism_5ghz, other.
        """
        return _get_band(freq_hz)

    def is_calibrated(self, freq_hz: float) -> bool:
        """Check if the band containing freq_hz has a fitted curve.

        Parameters
        ----------
        freq_hz : float
            Frequency in Hz.

        Returns
        -------
        bool
        """
        return self.get_band(freq_hz) in self._curves

    def status(self) -> dict[str, Any]:
        """Return calibration status for all bands.

        Returns
        -------
        dict
            Keys: bands (dict of band -> info), total_feedback.
        """
        bands: dict[str, dict[str, Any]] = {}
        for band, data in self._feedback.items():
            positives = sum(1 for _, lbl in data if lbl)
            negatives = len(data) - positives
            info: dict[str, Any] = {
                "samples": len(data),
                "positives": positives,
                "negatives": negatives,
                "calibrated": band in self._curves,
            }
            if band in self._curves:
                a, b = self._curves[band]
                info["a"] = round(a, 4)
                info["b"] = round(b, 4)
            bands[band] = info

        total = sum(len(d) for d in self._feedback.values())
        return {"bands": bands, "total_feedback": total}
