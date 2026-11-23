"""Adaptive quantile-based thresholds for anomaly scoring (DS-R11).

Replaces fixed priority thresholds (0.3/0.5/0.7) with per-frequency-band
quantile thresholds derived from observed score distributions.  This allows
data-driven, environment-specific alert levels instead of universal cutoffs.

Each frequency band accumulates anomaly scores in a ring buffer and
computes quantile thresholds dynamically:
    Normal      < Q(75)
    Interesting Q(75) – Q(90)
    Anomalous   Q(90) – Q(97)
    Critical    > Q(97)
"""

from __future__ import annotations

import logging
import math
from typing import Any

from sigrift.bridge.anomaly.bands import get_band

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# QuantileTracker
# ---------------------------------------------------------------------------


class QuantileTracker:
    """Track anomaly score distributions per frequency band and compute
    adaptive quantile-based priority thresholds.

    Parameters
    ----------
    max_samples : int
        Maximum scores to retain per band (ring buffer).
    min_samples : int
        Minimum scores before adaptive thresholds activate.
        Below this count, fixed thresholds are used.
    quantiles : tuple[float, float, float]
        Quantiles for (interesting, anomalous, critical) boundaries.
        Default: (0.75, 0.90, 0.97).
    """

    DEFAULT_QUANTILES = (0.75, 0.90, 0.97)

    def __init__(
        self,
        max_samples: int = 5000,
        min_samples: int = 100,
        quantiles: tuple[float, float, float] | None = None,
        min_thresholds: tuple[float, float, float] = (0.2, 0.4, 0.6),
    ) -> None:
        self.max_samples = max_samples
        self.min_samples = min_samples
        self.quantiles = quantiles or self.DEFAULT_QUANTILES
        self.min_thresholds = min_thresholds
        self._buffers: dict[str, list[float]] = {}
        self._counts: dict[str, int] = {}  # total seen per band
        self._prev_thresholds: dict[str, tuple[float, float, float]] = {}

    def add_score(self, score: float, freq_hz: float) -> None:
        """Record an anomaly score for the appropriate frequency band."""
        band = get_band(freq_hz)
        if band not in self._buffers:
            self._buffers[band] = []
            self._counts[band] = 0

        self._counts[band] += 1
        buf = self._buffers[band]
        if len(buf) < self.max_samples:
            buf.append(score)
        else:
            buf[self._counts[band] % self.max_samples] = score

    def get_thresholds(self, freq_hz: float) -> tuple[float, float, float]:
        """Return (interesting, anomalous, critical) thresholds for a band.

        Falls back to fixed thresholds (0.3, 0.5, 0.7) when insufficient
        data has been collected.

        Returns
        -------
        tuple[float, float, float]
            Threshold boundaries for interesting, anomalous, critical.
        """
        band = get_band(freq_hz)
        buf = self._buffers.get(band, [])
        if len(buf) < self.min_samples:
            return (0.3, 0.5, 0.7)

        sorted_scores = sorted(buf)
        n = len(sorted_scores)
        q_int = self._percentile(sorted_scores, n, self.quantiles[0])
        q_anom = self._percentile(sorted_scores, n, self.quantiles[1])
        q_crit = self._percentile(sorted_scores, n, self.quantiles[2])

        # Enforce threshold floors to prevent manipulation via score flooding
        q_int = max(q_int, self.min_thresholds[0])
        q_anom = max(q_anom, self.min_thresholds[1])
        q_crit = max(q_crit, self.min_thresholds[2])

        # Ensure monotonicity
        q_anom = max(q_anom, q_int + 0.01)
        q_crit = max(q_crit, q_anom + 0.01)

        # Check for suspicious threshold shift (>30% drop from previous)
        prev = self._prev_thresholds.get(band)
        if prev is not None:
            for i, (cur, prv, name) in enumerate(
                zip(
                    (q_int, q_anom, q_crit),
                    prev,
                    ("interesting", "anomalous", "critical"),
                )
            ):
                if prv > 0 and (prv - cur) / prv > 0.30:
                    logger.warning(
                        "Threshold shift >30%% for band %s %s: %.4f -> %.4f",
                        band,
                        name,
                        prv,
                        cur,
                    )
        self._prev_thresholds[band] = (q_int, q_anom, q_crit)

        return (q_int, q_anom, q_crit)

    def priority_label(self, score: float, freq_hz: float) -> str:
        """Return adaptive priority label for a score at a frequency."""
        t_int, t_anom, t_crit = self.get_thresholds(freq_hz)
        if score >= t_crit:
            return "critical"
        if score >= t_anom:
            return "anomalous"
        if score >= t_int:
            return "interesting"
        return "normal"

    def status(self) -> dict[str, Any]:
        """Return status for all tracked bands."""
        result: dict[str, Any] = {}
        for band, buf in self._buffers.items():
            n = len(buf)
            info: dict[str, Any] = {
                "samples": n,
                "total_seen": self._counts.get(band, 0),
                "active": n >= self.min_samples,
            }
            if n >= self.min_samples:
                sorted_scores = sorted(buf)
                info["thresholds"] = {
                    "interesting": round(
                        self._percentile(sorted_scores, n, self.quantiles[0]), 4
                    ),
                    "anomalous": round(
                        self._percentile(sorted_scores, n, self.quantiles[1]), 4
                    ),
                    "critical": round(
                        self._percentile(sorted_scores, n, self.quantiles[2]), 4
                    ),
                }
                info["median"] = round(self._percentile(sorted_scores, n, 0.5), 4)
                info["mean"] = round(sum(buf) / n, 4)
            result[band] = info
        return result

    @staticmethod
    def _percentile(sorted_vals: list[float], n: int, q: float) -> float:
        """Compute the q-th percentile using linear interpolation."""
        pos = q * (n - 1)
        lo = int(math.floor(pos))
        hi = min(lo + 1, n - 1)
        frac = pos - lo
        return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac
