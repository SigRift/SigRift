"""Statistical baseline engine for RF signal anomaly detection.

Tracks per-frequency baselines using EWMA (exponentially weighted
moving average) for class distribution, detection rate, and signal
power.  Supports cold-start learning phase, hourly pattern tracking,
and JSON persistence.

This is Tier 1 anomaly detection — runs on both edge nodes and
the central server.
"""

from __future__ import annotations

import json
import uuid
import logging
import math
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MIN_LEARNING_DETECTIONS = 300
_FREQ_BIN_HZ = 100_000  # 100 kHz bins (legacy default, see _adaptive_bin_hz)


def json_snapshot(value: Any) -> Any:
    """Copy a JSON-shaped value (dicts, lists, tuples, sets, scalars).

    Used to take a consistent snapshot of baseline state under a manager's
    lock so it can be serialised after the lock is released; much cheaper
    than ``copy.deepcopy`` for this data.  Sets become sorted lists.
    """
    if isinstance(value, dict):
        return {k: json_snapshot(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_snapshot(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted(json_snapshot(v) for v in value)
    return value


def write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    """Write *data* to *path* via a unique temp file, fsync and rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # Unique temp name so a concurrent save (e.g. a bundle apply racing the
    # periodic autosave) cannot clobber a half-written shared tmp file.
    tmp = path.parent / f"{path.name}.{uuid.uuid4().hex}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        tmp.replace(path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def _adaptive_bin_hz(freq_hz: float) -> int:
    """Return the bin width in Hz based on frequency range.

    Sub-GHz bands (< 1 GHz) use 25 kHz bins for fine resolution.
    Bands >= 1 GHz use 500 kHz bins (wider channels, more spread).
    """
    if freq_hz < 1_000_000_000:
        return 25_000
    return 500_000


_MAX_POWER_SAMPLES = 500  # Cap for MAD sample buffer
_MAD_NORMAL_SCALE = 0.6745  # 1/Φ⁻¹(3/4) for consistency with normal distribution

# DS-R10: CUSUM changepoint detection thresholds
_CUSUM_DRIFT = 1.0  # Allowance parameter (k) — one standard deviation slack
_CUSUM_THRESHOLD = 8.0  # Decision threshold (h) — triggers changepoint alarm


# ---------------------------------------------------------------------------
# FrequencyBaseline
# ---------------------------------------------------------------------------


@dataclass
class FrequencyBaseline:
    """Tracks baseline statistics for a single frequency bin.

    Parameters
    ----------
    alpha : float
        EWMA decay factor.  Smaller = slower adaptation.
        Default 0.01 gives ~100-sample half-life.
    """

    alpha: float = 0.01

    # Total count per class ever seen
    class_counts: dict[str, int] = field(default_factory=dict)

    # EWMA of recent detection rate per class
    class_ewma: dict[str, float] = field(default_factory=dict)

    # 24-hour histogram: hour (0-23) → class → count
    hourly_counts: dict[int, dict[str, int]] = field(default_factory=dict)

    # Power baseline (EWMA)
    power_ewma: float = 0.0
    power_var: float = 0.0

    # SNR baseline (EWMA)
    snr_ewma: float = 0.0
    snr_var: float = 0.0

    # Total detections at this frequency
    total_detections: int = 0

    # Sample buffers for MAD scoring (capped at _MAX_POWER_SAMPLES)
    power_samples: list[float] = field(default_factory=list)
    snr_samples: list[float] = field(default_factory=list)
    bandwidth_samples: list[float] = field(default_factory=list)

    # Welford's online variance state (used during learning phase)
    _welford_power_count: int = 0
    _welford_power_mean: float = 0.0
    _welford_power_m2: float = 0.0
    _welford_snr_count: int = 0
    _welford_snr_mean: float = 0.0
    _welford_snr_m2: float = 0.0

    # DS-R10: CUSUM changepoint detection state
    # Tracks cumulative sums for upward and downward power shifts.
    # When either exceeds _CUSUM_THRESHOLD, a regime change is detected.
    cusum_pos: float = 0.0  # Upward shift accumulator
    cusum_neg: float = 0.0  # Downward shift accumulator
    cusum_changepoints: int = 0  # Total changepoints detected
    cusum_last_changepoint: int = 0  # Detection index of last changepoint

    # DS-R14: Per-class bandwidth tracking
    # Maps class_name -> [ewma, var, count]
    bandwidth_by_class: dict[str, list[float]] = field(default_factory=dict)

    # DS-R14: Inter-arrival time tracking
    last_detection_time: float = 0.0
    last_inter_arrival: float = 0.0
    inter_arrival_ewma: float = 0.0
    inter_arrival_var: float = 0.0
    _ia_count: int = 0

    def update(
        self,
        class_name: str,
        confidence: float,
        power_dbm: float | None,
        hour: int,
        snr_db: float | None = None,
        bandwidth_hz: float | None = None,
        timestamp_epoch: float | None = None,
    ) -> None:
        """Update all trackers with a new detection.

        Parameters
        ----------
        class_name : str
            Detected signal class.
        confidence : float
            Classification confidence (0-1).
        power_dbm : float or None
            Signal power in dBm.
        hour : int
            Hour of day (0-23) for temporal pattern tracking.
        snr_db : float or None
            Signal-to-Noise Ratio in dB.
        """
        self.total_detections += 1

        # --- Class counts ---
        self.class_counts[class_name] = self.class_counts.get(class_name, 0) + 1

        # --- Class EWMA ---
        # For each known class, update its EWMA: 1.0 if this class, 0.0 otherwise
        for cls in list(self.class_ewma):
            indicator = 1.0 if cls == class_name else 0.0
            self.class_ewma[cls] = (
                self.alpha * indicator + (1 - self.alpha) * self.class_ewma[cls]
            )
        # If new class, initialise its EWMA
        if class_name not in self.class_ewma:
            self.class_ewma[class_name] = self.alpha

        # --- Hourly counts ---
        hour = hour % 24
        if hour not in self.hourly_counts:
            self.hourly_counts[hour] = {}
        self.hourly_counts[hour][class_name] = (
            self.hourly_counts[hour].get(class_name, 0) + 1
        )

        # --- Power: Welford (learning) or EWMA (post-learning) + CUSUM ---
        if power_dbm is not None:
            self._welford_power_count += 1
            if self._welford_power_count <= _MIN_LEARNING_DETECTIONS:
                # Welford's online algorithm for unbiased variance
                delta = power_dbm - self._welford_power_mean
                self._welford_power_mean += delta / self._welford_power_count
                delta2 = power_dbm - self._welford_power_mean
                self._welford_power_m2 += delta * delta2
                # Expose as power_ewma/power_var for scorer compatibility
                self.power_ewma = self._welford_power_mean
                if self._welford_power_count >= 2:
                    self.power_var = self._welford_power_m2 / self._welford_power_count
                else:
                    self.power_var = 0.0
            else:
                # EWMA phase
                delta = power_dbm - self.power_ewma
                self.power_ewma = (
                    self.alpha * power_dbm + (1 - self.alpha) * self.power_ewma
                )
                self.power_var = (1 - self.alpha) * (
                    self.power_var + self.alpha * delta * delta
                )

                # DS-R10: CUSUM changepoint detection
                std = math.sqrt(self.power_var) if self.power_var > 0 else 1.0
                if std > 1e-9:
                    z = delta / std
                    self.cusum_pos = max(0.0, self.cusum_pos + z - _CUSUM_DRIFT)
                    self.cusum_neg = max(0.0, self.cusum_neg - z - _CUSUM_DRIFT)

                    if (
                        self.cusum_pos > _CUSUM_THRESHOLD
                        or self.cusum_neg > _CUSUM_THRESHOLD
                    ):
                        self.cusum_changepoints += 1
                        self.cusum_last_changepoint = self.total_detections
                        self.cusum_pos = 0.0
                        self.cusum_neg = 0.0

            # MAD sample buffer (ring-buffer style)
            if len(self.power_samples) < _MAX_POWER_SAMPLES:
                self.power_samples.append(power_dbm)
            else:
                self.power_samples[(self.total_detections - 1) % _MAX_POWER_SAMPLES] = (
                    power_dbm
                )

        # --- DS-R14: Bandwidth tracking per class ---
        if bandwidth_hz is not None and bandwidth_hz > 0:
            if class_name not in self.bandwidth_by_class:
                self.bandwidth_by_class[class_name] = [float(bandwidth_hz), 0.0, 1]
            else:
                bw_ewma, bw_var, bw_count = self.bandwidth_by_class[class_name]
                bw_count += 1
                delta = bandwidth_hz - bw_ewma
                bw_ewma = self.alpha * bandwidth_hz + (1 - self.alpha) * bw_ewma
                bw_var = (1 - self.alpha) * (bw_var + self.alpha * delta * delta)
                self.bandwidth_by_class[class_name] = [bw_ewma, bw_var, bw_count]

            # MAD sample buffer for bandwidth (ring-buffer style)
            if len(self.bandwidth_samples) < _MAX_POWER_SAMPLES:
                self.bandwidth_samples.append(bandwidth_hz)
            else:
                self.bandwidth_samples[
                    (self.total_detections - 1) % _MAX_POWER_SAMPLES
                ] = bandwidth_hz

        # --- DS-R14: Inter-arrival time tracking ---
        if timestamp_epoch is not None and timestamp_epoch > 0:
            if self.last_detection_time > 0:
                ia = timestamp_epoch - self.last_detection_time
                if ia >= 0:
                    self.last_inter_arrival = ia
                    self._ia_count += 1
                    if self._ia_count == 1:
                        self.inter_arrival_ewma = ia
                        self.inter_arrival_var = 0.0
                    else:
                        delta = ia - self.inter_arrival_ewma
                        self.inter_arrival_ewma = (
                            self.alpha * ia + (1 - self.alpha) * self.inter_arrival_ewma
                        )
                        self.inter_arrival_var = (1 - self.alpha) * (
                            self.inter_arrival_var + self.alpha * delta * delta
                        )
            self.last_detection_time = timestamp_epoch

        # --- SNR: Welford (learning) or EWMA (post-learning) ---
        if snr_db is not None:
            self._welford_snr_count += 1
            if self._welford_snr_count <= _MIN_LEARNING_DETECTIONS:
                delta = snr_db - self._welford_snr_mean
                self._welford_snr_mean += delta / self._welford_snr_count
                delta2 = snr_db - self._welford_snr_mean
                self._welford_snr_m2 += delta * delta2
                self.snr_ewma = self._welford_snr_mean
                if self._welford_snr_count >= 2:
                    self.snr_var = self._welford_snr_m2 / self._welford_snr_count
                else:
                    self.snr_var = 0.0
            else:
                delta = snr_db - self.snr_ewma
                self.snr_ewma = self.alpha * snr_db + (1 - self.alpha) * self.snr_ewma
                self.snr_var = (1 - self.alpha) * (
                    self.snr_var + self.alpha * delta * delta
                )
            if len(self.snr_samples) < _MAX_POWER_SAMPLES:
                self.snr_samples.append(snr_db)
            else:
                self.snr_samples[(self.total_detections - 1) % _MAX_POWER_SAMPLES] = (
                    snr_db
                )

    def is_learning(self) -> bool:
        """Return True if still in cold-start learning phase."""
        return self.total_detections < _MIN_LEARNING_DETECTIONS

    def class_probability(self, class_name: str) -> float:
        """Return P(class | frequency) from lifetime counts.

        Parameters
        ----------
        class_name : str
            Signal class name.

        Returns
        -------
        float
            Probability in [0, 1].  Returns 0.0 for unseen classes.
        """
        if self.total_detections == 0:
            return 0.0
        return self.class_counts.get(class_name, 0) / self.total_detections

    def class_probability_smoothed(self, class_name: str) -> float:
        """Return P(class | frequency) with Laplace (add-one) smoothing.

        Prevents zero-probability cells from producing maximum 1.0
        anomaly scores.  Used by the scorer for the rare_class
        dimension instead of ``class_probability``.

        ``P(class) = (count + 1) / (total + num_classes + 1)``

        Parameters
        ----------
        class_name : str
            Signal class name.

        Returns
        -------
        float
            Smoothed probability in (0, 1].
        """
        if self.total_detections == 0:
            return 0.0
        num_classes = len(self.class_counts)
        denominator = self.total_detections + num_classes + 1
        count = self.class_counts.get(class_name, 0)
        return (count + 1) / denominator

    def hourly_probability(self, class_name: str, hour: int) -> float:
        """Return P(class | frequency, hour) from hourly histogram.

        Parameters
        ----------
        class_name : str
            Signal class name.
        hour : int
            Hour of day (0-23).

        Returns
        -------
        float
            Probability in [0, 1].
        """
        hour = hour % 24
        hour_data = self.hourly_counts.get(hour, {})
        total_at_hour = sum(hour_data.values())
        if total_at_hour == 0:
            return 0.0
        return hour_data.get(class_name, 0) / total_at_hour

    def hourly_probability_smoothed(self, class_name: str, hour: int) -> float:
        """Return P(class | frequency, hour) with Laplace smoothing.

        Prevents zero-count (class, hour) cells from producing
        maximum 1.0 timing anomaly scores.  Used by the scorer for
        the timing_anomaly dimension.

        Parameters
        ----------
        class_name : str
            Signal class name.
        hour : int
            Hour of day (0-23).

        Returns
        -------
        float
            Smoothed probability in (0, 1].
        """
        hour = hour % 24
        hour_data = self.hourly_counts.get(hour, {})
        total_at_hour = sum(hour_data.values())
        if total_at_hour == 0:
            return 0.0
        num_classes_at_hour = len(hour_data)
        denominator = total_at_hour + num_classes_at_hour + 1
        count = hour_data.get(class_name, 0)
        return (count + 1) / denominator

    def power_zscore(self, power_dbm: float) -> float:
        """Return z-score of power_dbm vs the running baseline.

        Parameters
        ----------
        power_dbm : float
            Signal power in dBm.

        Returns
        -------
        float
            Z-score.  Returns 0.0 if variance is zero or baseline
            has insufficient data.
        """
        if self.total_detections < 2 or self.power_var <= 0:
            return 0.0
        std = math.sqrt(self.power_var)
        if std < 1e-9:
            return 0.0
        return (power_dbm - self.power_ewma) / std

    def snr_zscore(self, snr_db: float) -> float:
        """Return z-score of snr_db vs the running baseline.

        Parameters
        ----------
        snr_db : float
            Signal-to-Noise Ratio in dB.

        Returns
        -------
        float
            Z-score.  Returns 0.0 if variance is zero or baseline
            has insufficient data.
        """
        if self.total_detections < 2 or self.snr_var <= 0:
            return 0.0
        std = math.sqrt(self.snr_var)
        if std < 1e-9:
            return 0.0
        return (snr_db - self.snr_ewma) / std

    @staticmethod
    def _median(values: list[float]) -> float:
        """Compute median of a list of floats."""
        n = len(values)
        if n == 0:
            return 0.0
        s = sorted(values)
        mid = n // 2
        if n % 2 == 0:
            return (s[mid - 1] + s[mid]) / 2.0
        return s[mid]

    @staticmethod
    def _mad(values: list[float]) -> float:
        """Compute Median Absolute Deviation."""
        if len(values) < 2:
            return 0.0
        n = len(values)
        s = sorted(values)
        mid = n // 2
        if n % 2 == 0:
            median = (s[mid - 1] + s[mid]) / 2.0
        else:
            median = s[mid]
        abs_devs = sorted(abs(v - median) for v in values)
        m = len(abs_devs) // 2
        if n % 2 == 0:
            return (abs_devs[m - 1] + abs_devs[m]) / 2.0
        return abs_devs[m]

    def power_mad_score(self, power_dbm: float) -> float:
        """Return MAD-based anomaly score for power_dbm.

        Uses modified z-score: ``0.6745 * (x - median) / MAD``.
        Maps to [0, 1] via sigmoid: ``1 / (1 + exp(-|z|/2 + 2))``.
        Returns 0.0 if insufficient samples.
        """
        if len(self.power_samples) < 10:
            return 0.0
        median = self._median(self.power_samples)
        mad = self._mad(self.power_samples)
        if mad < 1e-9:
            return 0.0
        z = abs(_MAD_NORMAL_SCALE * (power_dbm - median) / mad)
        return 1.0 / (1.0 + math.exp(-z / 2.0 + 2.0))

    def snr_mad_score(self, snr_db: float) -> float:
        """Return MAD-based anomaly score for snr_db.

        Same methodology as power_mad_score but applied to SNR samples.
        Returns 0.0 if insufficient samples.
        """
        if len(self.snr_samples) < 10:
            return 0.0
        median = self._median(self.snr_samples)
        mad = self._mad(self.snr_samples)
        if mad < 1e-9:
            return 0.0
        z = abs(_MAD_NORMAL_SCALE * (snr_db - median) / mad)
        return 1.0 / (1.0 + math.exp(-z / 2.0 + 2.0))

    def bandwidth_mad_score(self, bandwidth_hz: float) -> float:
        """Return MAD-based anomaly score for bandwidth_hz."""
        if len(self.bandwidth_samples) < 10:
            return 0.0
        median = self._median(self.bandwidth_samples)
        mad = self._mad(self.bandwidth_samples)
        if mad < 1e-9:
            return 0.0
        z = abs(_MAD_NORMAL_SCALE * (bandwidth_hz - median) / mad)
        return 1.0 / (1.0 + math.exp(-z / 2.0 + 2.0))

    def cusum_score(self) -> float:
        """Return CUSUM-based changepoint anomaly score.

        Maps the maximum of the positive/negative CUSUM accumulators
        to [0, 1] using a sigmoid.  Higher values indicate a regime
        change is building or just occurred.
        """
        peak = max(self.cusum_pos, self.cusum_neg)
        if peak < 1e-9:
            return 0.0
        # Sigmoid mapping: score approaches 1.0 near threshold
        return 1.0 / (1.0 + math.exp(-peak + _CUSUM_THRESHOLD / 2))

    def has_recent_changepoint(self, lookback: int = 50) -> bool:
        """Return True if a changepoint was detected within the last N detections."""
        if self.cusum_changepoints == 0:
            return False
        return (self.total_detections - self.cusum_last_changepoint) <= lookback

    def bandwidth_zscore(self, class_name: str, bandwidth_hz: float) -> float:
        """Return z-score of bandwidth vs baseline for this signal class.

        Returns 0.0 if fewer than 10 observations for the class.
        """
        data = self.bandwidth_by_class.get(class_name)
        if data is None or data[2] < 10:
            return 0.0
        ewma, var, _count = data
        if var <= 0:
            return 0.0
        std = math.sqrt(var)
        if std < 1e-9:
            return 0.0
        return (bandwidth_hz - ewma) / std

    def inter_arrival_zscore(self) -> float:
        """Return z-score of last inter-arrival vs the running baseline.

        Returns 0.0 if fewer than 10 inter-arrival observations.
        """
        if self._ia_count < 10 or self.inter_arrival_var <= 0:
            return 0.0
        std = math.sqrt(self.inter_arrival_var)
        if std < 1e-9:
            return 0.0
        return (self.last_inter_arrival - self.inter_arrival_ewma) / std

    def is_novel_class(self, class_name: str) -> bool:
        """Return True if class_name has never been seen at this frequency."""
        return class_name not in self.class_counts

    def to_dict(self) -> dict[str, Any]:
        """Serialize baseline to a JSON-compatible dict."""
        return {
            "alpha": self.alpha,
            "class_counts": self.class_counts,
            "class_ewma": self.class_ewma,
            "hourly_counts": {
                str(h): counts for h, counts in self.hourly_counts.items()
            },
            "power_ewma": self.power_ewma,
            "power_var": self.power_var,
            "snr_ewma": self.snr_ewma,
            "snr_var": self.snr_var,
            "total_detections": self.total_detections,
            "power_samples": self.power_samples,
            "snr_samples": self.snr_samples,
            "bandwidth_samples": self.bandwidth_samples,
            "cusum_pos": self.cusum_pos,
            "cusum_neg": self.cusum_neg,
            "cusum_changepoints": self.cusum_changepoints,
            "cusum_last_changepoint": self.cusum_last_changepoint,
            "welford_power_count": self._welford_power_count,
            "welford_power_mean": self._welford_power_mean,
            "welford_power_m2": self._welford_power_m2,
            "welford_snr_count": self._welford_snr_count,
            "welford_snr_mean": self._welford_snr_mean,
            "welford_snr_m2": self._welford_snr_m2,
            "bandwidth_by_class": self.bandwidth_by_class,
            "last_detection_time": self.last_detection_time,
            "last_inter_arrival": self.last_inter_arrival,
            "inter_arrival_ewma": self.inter_arrival_ewma,
            "inter_arrival_var": self.inter_arrival_var,
            "ia_count": self._ia_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FrequencyBaseline:
        """Deserialize baseline from a dict."""
        fb = cls(alpha=data.get("alpha", 0.01))
        fb.class_counts = data.get("class_counts", {})
        fb.class_ewma = data.get("class_ewma", {})
        raw_hourly = data.get("hourly_counts", {})
        fb.hourly_counts = {int(h): counts for h, counts in raw_hourly.items()}
        fb.power_ewma = data.get("power_ewma", 0.0)
        fb.power_var = data.get("power_var", 0.0)
        fb.snr_ewma = data.get("snr_ewma", 0.0)
        fb.snr_var = data.get("snr_var", 0.0)
        fb.total_detections = data.get("total_detections", 0)
        fb.power_samples = data.get("power_samples", [])
        fb.snr_samples = data.get("snr_samples", [])
        fb.bandwidth_samples = data.get("bandwidth_samples", [])
        fb.cusum_pos = data.get("cusum_pos", 0.0)
        fb.cusum_neg = data.get("cusum_neg", 0.0)
        fb.cusum_changepoints = data.get("cusum_changepoints", 0)
        fb.cusum_last_changepoint = data.get("cusum_last_changepoint", 0)
        fb._welford_power_count = data.get("welford_power_count", 0)
        fb._welford_power_mean = data.get("welford_power_mean", 0.0)
        fb._welford_power_m2 = data.get("welford_power_m2", 0.0)
        fb._welford_snr_count = data.get("welford_snr_count", 0)
        fb._welford_snr_mean = data.get("welford_snr_mean", 0.0)
        fb._welford_snr_m2 = data.get("welford_snr_m2", 0.0)
        fb.bandwidth_by_class = data.get("bandwidth_by_class", {})
        fb.last_detection_time = data.get("last_detection_time", 0.0)
        fb.last_inter_arrival = data.get("last_inter_arrival", 0.0)
        fb.inter_arrival_ewma = data.get("inter_arrival_ewma", 0.0)
        fb.inter_arrival_var = data.get("inter_arrival_var", 0.0)
        fb._ia_count = data.get("ia_count", 0)
        return fb

    # -- Preset sanitation --------------------------------------------------
    # These make a learned baseline safe to ship as a site-transferable preset.
    # They are deterministic in the retained fields so a validator can re-run
    # them as an idempotence check (see sigrift.bridge.bundles).

    def strip_site_transients(self) -> None:
        """Zero transient run-state that must not carry into a preset.

        CUSUM accumulators and last-detection clocks describe a specific
        capture session, not the environment. Inter-arrival *rate* statistics
        (ewma/var/count) are kept — they are transferable and the
        inter_arrival_anomaly dimension weight defaults to 0.0 anyway.
        """
        self.cusum_pos = 0.0
        self.cusum_neg = 0.0
        self.cusum_changepoints = 0
        self.cusum_last_changepoint = 0
        self.last_detection_time = 0.0
        self.last_inter_arrival = 0.0

    def neutral_hourly_prior(self) -> None:
        """Replace hourly_counts with a class-proportional neutral prior.

        Real hourly_counts encode the source site's UTC activity schedule, so
        presets must not carry them. But dropping them entirely is a bug: an
        empty hourly_counts makes hourly_probability_smoothed() return 0.0,
        which the scorer turns into a maximum (1.0) timing-anomaly score on
        every detection until the bin relearns. Instead spread each class's
        lifetime count flat across all 24 hours (>=1 per cell) so the timing
        dimension reads as class prevalence — neutral and timezone-agnostic.
        """
        prior: dict[int, dict[str, int]] = {}
        for hour in range(24):
            prior[hour] = {
                cls: max(1, count // 24) for cls, count in self.class_counts.items()
            }
        self.hourly_counts = prior


# ---------------------------------------------------------------------------
# BaselineManager
# ---------------------------------------------------------------------------


class BaselineManager:
    """Manages per-frequency baselines for anomaly detection.

    Parameters
    ----------
    alpha : float
        EWMA decay factor for all frequency baselines.
    """

    # On-disk state format version. Absent in legacy files (treated as 0);
    # from_dict/.get() tolerance keeps old and new files mutually loadable.
    SCHEMA_VERSION = 1

    def __init__(self, alpha: float = 0.01) -> None:
        self.alpha = alpha
        self.baselines: dict[float, FrequencyBaseline] = {}
        # Guards ``baselines`` and every FrequencyBaseline in it: held by
        # update(), by scorers while they read a baseline, and by save()
        # while it snapshots (update and save run in different threads).
        self._lock = threading.RLock()
        # Number of update() calls since the last save(); drives the periodic
        # autosave in the bridge lifespan (avoids rewriting an unchanged file).
        self.updates_since_save = 0

    def replace_state(
        self, baselines: dict[float, FrequencyBaseline], alpha: float | None = None
    ) -> None:
        """Atomically swap in a new baseline set (e.g. from a bundle apply).

        Holds the manager lock for the swap. Marks the manager dirty so the
        next autosave persists the applied state.
        """
        with self._lock:
            self.baselines = baselines
            if alpha is not None:
                self.alpha = alpha
            self.updates_since_save += 1

    @property
    def dirty(self) -> bool:
        """True if there are unsaved updates since the last save()."""
        return self.updates_since_save > 0

    @property
    def lock(self) -> threading.RLock:
        """The manager lock (re-entrant); hold it while reading baselines."""
        return self._lock

    @staticmethod
    def freq_bin(freq_hz: float) -> float:
        """Round frequency to the nearest adaptive bin.

        Sub-GHz uses 25 kHz bins; >= 1 GHz uses 500 kHz bins.

        Parameters
        ----------
        freq_hz : float
            Frequency in Hz.

        Returns
        -------
        float
            Binned frequency in Hz.
        """
        bin_hz = _adaptive_bin_hz(freq_hz)
        return round(freq_hz / bin_hz) * bin_hz

    def update(
        self,
        freq_hz: float,
        class_name: str,
        confidence: float,
        power_dbm: float | None = None,
        hour: int | None = None,
        snr_db: float | None = None,
        bandwidth_hz: float | None = None,
        timestamp_epoch: float | None = None,
    ) -> FrequencyBaseline:
        """Update or create baseline for a frequency.

        Parameters
        ----------
        freq_hz : float
            Detection frequency in Hz.
        class_name : str
            Detected signal class.
        confidence : float
            Classification confidence.
        power_dbm : float or None
            Signal power in dBm.
        hour : int or None
            Hour of day (0-23).  If None, uses current UTC hour.
        snr_db : float or None
            Signal-to-Noise Ratio in dB.
        bandwidth_hz : float or None
            Signal bandwidth in Hz (DS-R14).
        timestamp_epoch : float or None
            Detection timestamp as Unix epoch seconds (DS-R14).

        Returns
        -------
        FrequencyBaseline
            The updated baseline.
        """
        binned = self.freq_bin(freq_hz)
        if hour is None:
            hour = datetime.now(timezone.utc).hour

        with self._lock:
            if binned not in self.baselines:
                self.baselines[binned] = FrequencyBaseline(alpha=self.alpha)
            baseline = self.baselines[binned]
            baseline.update(
                class_name,
                confidence,
                power_dbm,
                hour,
                snr_db,
                bandwidth_hz=bandwidth_hz,
                timestamp_epoch=timestamp_epoch,
            )
            self.updates_since_save += 1
        return baseline

    def get_baseline(self, freq_hz: float) -> FrequencyBaseline | None:
        """Get baseline for a frequency, or None if not tracked.

        Parameters
        ----------
        freq_hz : float
            Frequency in Hz (will be binned).

        Returns
        -------
        FrequencyBaseline or None
        """
        return self.baselines.get(self.freq_bin(freq_hz))

    def save(self, path: str) -> None:
        """Serialize all baselines to JSON file.

        Parameters
        ----------
        path : str
            Output file path.
        """
        # Snapshot under the lock (update() mutates these dicts from another
        # thread); serialise and write after releasing it.
        with self._lock:
            data = {
                "schema_version": self.SCHEMA_VERSION,
                "alpha": self.alpha,
                "baselines": {
                    str(freq): json_snapshot(bl.to_dict())
                    for freq, bl in self.baselines.items()
                },
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }
            saved_updates = self.updates_since_save
        write_json_atomic(Path(path), data)
        with self._lock:
            # Updates made while writing stay pending for the next save.
            self.updates_since_save = max(0, self.updates_since_save - saved_updates)
        logger.info(
            "Baselines saved: %d frequencies → %s", len(data["baselines"]), path
        )

    def load(self, path: str) -> None:
        """Load baselines from JSON file.

        Parameters
        ----------
        path : str
            Input file path.
        """
        p = Path(path)
        if not p.exists():
            logger.warning("Baseline file not found: %s", path)
            return
        try:
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            raw = data.get("baselines", {})
            loaded: dict[float, FrequencyBaseline] = {}
            for freq_str, bl_data in raw.items():
                freq = float(freq_str)
                loaded[freq] = FrequencyBaseline.from_dict(bl_data)
            with self._lock:
                self.alpha = data.get("alpha", self.alpha)
                self.baselines = loaded
            logger.info(
                "Baselines loaded: %d frequencies from %s", len(self.baselines), path
            )
        except (json.JSONDecodeError, OSError, KeyError) as exc:
            logger.warning("Failed to load baselines from %s: %s", path, exc)
