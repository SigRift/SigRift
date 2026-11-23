"""Tier 1 anomaly scorer for RF signal detections.

Computes a composite anomaly score [0, 1] from multiple dimensions:
novel class, rare class, low confidence, power z-score, timing
anomaly, quiet frequency, IQ quality, spectral anomaly, and
modulation anomaly.  Each dimension produces a sub-score that is
combined with configurable weights.

Priority levels:
    Normal      0.0 – 0.3
    Interesting 0.3 – 0.5
    Anomalous   0.5 – 0.7
    Critical    0.7 – 1.0
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from sigrift.bridge.anomaly.baseline import BaselineManager, FrequencyBaseline

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AnomalyDimension(str, Enum):
    """Dimensions contributing to anomaly score."""

    NOVEL_CLASS = "novel_class"
    RARE_CLASS = "rare_class"
    LOW_CONFIDENCE = "low_confidence"
    POWER_ZSCORE = "power_zscore"
    SNR_ZSCORE = "snr_zscore"
    TIMING_ANOMALY = "timing_anomaly"
    QUIET_FREQUENCY = "quiet_frequency"
    IQ_QUALITY = "iq_quality"
    SPECTRAL_ANOMALY = "spectral_anomaly"
    MODULATION_ANOMALY = "modulation_anomaly"
    CORRELATION = "correlation"
    SIGNATURE_MATCH = "signature_match"
    BANDWIDTH_ANOMALY = "bandwidth_anomaly"
    INTER_ARRIVAL_ANOMALY = "inter_arrival_anomaly"


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Canonical default dimension weights.  persistence.py imports these
# via DEFAULT_RF_DIMENSION_WEIGHTS so there is exactly one source of
# truth.  Do NOT duplicate these values elsewhere.
_DEFAULT_WEIGHTS: dict[AnomalyDimension, float] = {
    AnomalyDimension.NOVEL_CLASS: 0.22,
    AnomalyDimension.RARE_CLASS: 0.12,
    AnomalyDimension.LOW_CONFIDENCE: 0.14,
    AnomalyDimension.POWER_ZSCORE: 0.13,
    AnomalyDimension.SNR_ZSCORE: 0.10,
    AnomalyDimension.TIMING_ANOMALY: 0.05,
    AnomalyDimension.QUIET_FREQUENCY: 0.04,
    AnomalyDimension.IQ_QUALITY: 0.08,
    AnomalyDimension.SPECTRAL_ANOMALY: 0.07,
    AnomalyDimension.MODULATION_ANOMALY: 0.05,
    AnomalyDimension.CORRELATION: 0.03,  # active; cross-source correlation scoring
    AnomalyDimension.SIGNATURE_MATCH: 0.15,  # active; matches against 64 curated TSCM threat signatures
    AnomalyDimension.BANDWIDTH_ANOMALY: 0.0,  # opt-in; requires bandwidth_hz in detections
    AnomalyDimension.INTER_ARRIVAL_ANOMALY: 0.0,  # opt-in; requires timestamp-based inter-arrival tracking
}

# Plain-string version for persistence.py (and any other consumer that
# doesn't use AnomalyDimension enums).
DEFAULT_RF_DIMENSION_WEIGHTS: dict[str, float] = {
    dim.value: weight for dim, weight in _DEFAULT_WEIGHTS.items()
}


# Expected bandwidths per signal class (Hz) for modulation anomaly scoring
_EXPECTED_CLASS_BANDWIDTH: dict[str, float] = {
    "fm": 200_000,
    "am": 10_000,
    "bpsk": 25_000,
    "qpsk": 50_000,
    "8psk": 75_000,
    "16psk": 100_000,
    "ook": 10_000,
    "fsk": 25_000,
    "gmsk": 200_000,
    "ofdm": 20_000_000,
    "qam16": 100_000,
    "qam64": 200_000,
    "qam256": 400_000,
}


class ScorerConfig(BaseModel):
    """Configuration for the anomaly scorer."""

    model_config = {"extra": "ignore"}

    weights: dict[AnomalyDimension, float] = Field(
        default_factory=lambda: dict(_DEFAULT_WEIGHTS)
    )
    min_learning_detections: int = 300
    decorrelate_classification: bool = (
        True  # DS-R9: diminishing returns on correlated dims
    )
    decorrelation_decay: float = 0.5
    decorrelation_threshold: float = 0.5


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------


class AnomalyResult(BaseModel):
    """Result of anomaly scoring for a single detection."""

    score: float = Field(ge=0.0, le=1.0)
    priority: str
    dimensions: dict[str, float] = Field(default_factory=dict)
    reasons: list[str] = Field(default_factory=list)
    baseline_status: str = "stable"


# ---------------------------------------------------------------------------
# AnomalyScorer
# ---------------------------------------------------------------------------


class FeedbackCalibrator:
    """Adjusts anomaly score threshold based on operator TP/FP feedback.

    Parameters
    ----------
    target_fp_rate : float
        Desired false-positive rate (default 15%).
    min_samples : int
        Minimum TP+FP labels before any adjustment is applied.
    """

    def __init__(self, target_fp_rate: float = 0.15, min_samples: int = 20) -> None:
        self.target_fp_rate = target_fp_rate
        self.min_samples = min_samples
        self._threshold_offset: float = 0.0

    def calibrate(self, fp_count: int, tp_count: int) -> float:
        """Compute threshold offset from feedback balance.

        Positive offset raises the effective threshold (too many FPs).
        Negative offset lowers it (too few FPs — possibly missing anomalies).
        """
        total = fp_count + tp_count
        if total < self.min_samples:
            self._threshold_offset = 0.0
            return 0.0
        actual_fp_rate = fp_count / total
        self._threshold_offset = (actual_fp_rate - self.target_fp_rate) * 0.1
        return self._threshold_offset

    @property
    def offset(self) -> float:
        return self._threshold_offset


class AnomalyScorer:
    """Tier 1 anomaly scorer using statistical baselines.

    Parameters
    ----------
    baseline_manager : BaselineManager
        Manager holding per-frequency baselines.
    config : ScorerConfig or None
        Scoring configuration.  Uses defaults if None.
    calibrator : FeedbackCalibrator or None
        Optional feedback calibrator that shifts scores based on
        operator TP/FP feedback.
    """

    def __init__(
        self,
        baseline_manager: BaselineManager,
        config: ScorerConfig | None = None,
        calibrator: FeedbackCalibrator | None = None,
    ) -> None:
        self.baseline_manager = baseline_manager
        self.config = config or ScorerConfig()
        self._calibrator = calibrator

    def update_weights(self, weights: dict[str, float]) -> None:
        """Update dimension weights at runtime.

        Parameters
        ----------
        weights : dict[str, float]
            New dimension weights keyed by dimension value string
            (e.g. ``"novel_class"``).
        """
        new_weights: dict[AnomalyDimension, float] = {}
        for dim in AnomalyDimension:
            if dim.value in weights:
                new_weights[dim] = weights[dim.value]
            elif dim in self.config.weights:
                new_weights[dim] = self.config.weights[dim]
        self.config.weights = new_weights

    def score(self, detection: dict[str, Any]) -> AnomalyResult:
        """Score *detection*; see :meth:`_score_locked`.

        Holds the baseline manager's lock for the whole computation, so
        an update() in another thread cannot change the baseline (its
        class and hour dicts) while it is being read.
        """
        lock = getattr(self.baseline_manager, "lock", None)
        if lock is None:
            return self._score_locked(detection)
        with lock:
            return self._score_locked(detection)

    def _score_locked(self, detection: dict[str, Any]) -> AnomalyResult:
        """Compute anomaly score for a detection.

        Parameters
        ----------
        detection : dict
            Detection data with keys: signal_class, confidence,
            freq_hz, power_dbm (optional), timestamp (optional).

        Returns
        -------
        AnomalyResult
            Composite anomaly score with dimension breakdown.
        """
        class_name = detection.get("signal_class", "")
        confidence = detection.get("confidence", 0.0)
        freq_hz = detection.get("freq_hz", 0.0)
        power_dbm = detection.get("power_dbm")
        snr_db = detection.get("snr_db")
        timestamp = detection.get("timestamp")
        gain_db = detection.get("gain_db")
        iq_data = detection.get("iq_data")

        # Normalize power by receiver gain to get received signal power
        if power_dbm is not None and gain_db is not None:
            power_dbm = power_dbm - gain_db

        # Extract hour from timestamp
        hour = self._extract_hour(timestamp)

        # Get or create baseline
        baseline = self.baseline_manager.get_baseline(freq_hz)
        min_learn = self.config.min_learning_detections
        is_learning = baseline is None or baseline.total_detections < min_learn
        baseline_status = "learning" if is_learning else "stable"

        # Compute dimension scores
        dimensions: dict[str, float] = {}
        reasons: list[str] = []

        # Novel class
        novel = self._novel_class_score(baseline, class_name)
        dimensions[AnomalyDimension.NOVEL_CLASS.value] = novel
        if novel > 0.5:
            reasons.append(f"Novel class '{class_name}' at this frequency")

        # Rare class
        rare = self._rare_class_score(baseline, class_name)
        dimensions[AnomalyDimension.RARE_CLASS.value] = rare
        if rare > 0.5:
            reasons.append(f"Rare class '{class_name}' (low historical probability)")

        # Low confidence
        low_conf = self._low_confidence_score(confidence)
        dimensions[AnomalyDimension.LOW_CONFIDENCE.value] = low_conf
        if low_conf > 0.5:
            reasons.append(f"Low confidence ({confidence:.2f})")

        # Power z-score
        power = self._power_zscore_score(baseline, power_dbm)
        dimensions[AnomalyDimension.POWER_ZSCORE.value] = power
        if power > 0.5:
            reasons.append(f"Unusual signal power (power_dbm={power_dbm})")

        # SNR z-score
        snr = self._snr_zscore_score(baseline, snr_db)
        dimensions[AnomalyDimension.SNR_ZSCORE.value] = snr
        if snr > 0.5:
            reasons.append(f"Unusual SNR (snr_db={snr_db})")

        # CUSUM changepoint boost: amplify power/SNR scores during regime changes
        if baseline is not None and baseline.has_recent_changepoint(lookback=50):
            power = min(1.0, power * 1.5)
            snr = min(1.0, snr * 1.5)
            dimensions[AnomalyDimension.POWER_ZSCORE.value] = power
            dimensions[AnomalyDimension.SNR_ZSCORE.value] = snr

        # Timing anomaly
        timing = self._timing_anomaly_score(baseline, class_name, hour)
        dimensions[AnomalyDimension.TIMING_ANOMALY.value] = timing
        if timing > 0.5:
            reasons.append(f"Unusual timing for '{class_name}' at hour {hour}")

        # Quiet frequency
        quiet = self._quiet_frequency_score(baseline)
        dimensions[AnomalyDimension.QUIET_FREQUENCY.value] = quiet
        if quiet > 0.5:
            reasons.append("Rarely-used frequency")

        # IQ quality anomaly
        iq_qual = self._iq_quality_score(detection, iq_data)
        dimensions[AnomalyDimension.IQ_QUALITY.value] = iq_qual
        if iq_qual > 0.5:
            reasons.append("Poor IQ data quality (possible interference)")

        # Spectral anomaly
        spectral = self._spectral_anomaly_score(detection, iq_data)
        dimensions[AnomalyDimension.SPECTRAL_ANOMALY.value] = spectral
        if spectral > 0.5:
            reasons.append("Unusual spectral characteristics")

        # Modulation anomaly
        mod = self._modulation_anomaly_score(detection, iq_data)
        dimensions[AnomalyDimension.MODULATION_ANOMALY.value] = mod
        if mod > 0.5:
            reasons.append("Unexpected modulation parameters")

        # Bandwidth anomaly (DS-R14)
        bw_score = self._bandwidth_anomaly_score(
            baseline,
            class_name,
            detection.get("bandwidth_hz"),
        )
        dimensions[AnomalyDimension.BANDWIDTH_ANOMALY.value] = bw_score
        if bw_score > 0.5:
            reasons.append("Unusual bandwidth for this signal class")

        # Inter-arrival anomaly (DS-R14)
        dc_score = self._inter_arrival_anomaly_score(baseline)
        dimensions[AnomalyDimension.INTER_ARRIVAL_ANOMALY.value] = dc_score
        if dc_score > 0.5:
            reasons.append("Unusual inter-arrival timing pattern")

        # Correlation dimension: score based on cross-source confirmation status
        correlation_status = detection.get("correlation_status")
        _CORRELATION_SCORES = {
            "unmatched_sdr": 0.8,
            "unmatched_protocol": 0.3,
            "confirmed": 0.1,
            "multi_source": 0.0,
        }
        corr_score = _CORRELATION_SCORES.get(correlation_status, 0.5)
        dimensions[AnomalyDimension.CORRELATION.value] = corr_score
        if corr_score > 0.5:
            reasons.append(
                f"Unconfirmed cross-source correlation ({correlation_status})"
            )

        # Signature match — check detection against threat signature library
        sig_score = self._signature_match_score(detection)
        dimensions[AnomalyDimension.SIGNATURE_MATCH.value] = sig_score
        if sig_score > 0.5:
            reasons.append(f"Matches known threat signature (score={sig_score:.2f})")

        # Composite score — with weight re-normalization for missing IQ
        # and selective dampening during learning phase.
        weights = dict(self.config.weights)

        # DS-R3: When IQ data is absent AND the baseline is stable,
        # IQ-dependent dimensions score 0.0 by definition.  Redistribute
        # their weight proportionally among the remaining dimensions so
        # the total still sums to 1.0.  During learning we skip
        # redistribution because baseline-dependent dimensions are also
        # near-zero, and inflating classification weights would
        # over-score before the baseline is established.
        if iq_data is None and not is_learning:
            iq_dims = {
                AnomalyDimension.IQ_QUALITY,
                AnomalyDimension.SPECTRAL_ANOMALY,
                AnomalyDimension.MODULATION_ANOMALY,
            }
            iq_weight = sum(weights.get(d, 0.0) for d in iq_dims)
            non_iq_weight = sum(w for d, w in weights.items() if d not in iq_dims)
            if non_iq_weight > 0 and iq_weight > 0:
                scale = 1.0 / non_iq_weight
                weights = {
                    d: (0.0 if d in iq_dims else w * scale) for d, w in weights.items()
                }

        # DS-R9: Decorrelation for classification cluster.
        # novel_class, rare_class, and low_confidence are correlated
        # (a truly novel class is also rare and often low-confidence).
        # When 2+ fire simultaneously, apply diminishing returns to
        # prevent triple-counting the same "unusual classification" signal.
        if self.config.decorrelate_classification:
            _CLASSIF_CLUSTER = (
                AnomalyDimension.NOVEL_CLASS,
                AnomalyDimension.RARE_CLASS,
                AnomalyDimension.LOW_CONFIDENCE,
            )
            cluster_scores = sorted(
                [(d, dimensions.get(d.value, 0.0)) for d in _CLASSIF_CLUSTER],
                key=lambda x: x[1],
                reverse=True,
            )
            _threshold = self.config.decorrelation_threshold
            active_count = sum(1 for _, s in cluster_scores if s > _threshold)
            if active_count > 1:
                _decay = self.config.decorrelation_decay
                for i, (dim, _) in enumerate(cluster_scores):
                    if i > 0 and dim in weights:
                        weights[dim] = weights[dim] * (_decay**i)

        # Auto-normalize weights if they don't sum to 1.0
        total_weight = sum(weights.values())
        if total_weight > 0 and abs(total_weight - 1.0) > 0.01:
            weights = {d: w / total_weight for d, w in weights.items()}

        composite = 0.0
        for dim, weight in weights.items():
            composite += weight * dimensions.get(dim.value, 0.0)

        # DS-R6: During learning, only dampen BASELINE-DEPENDENT
        # dimensions.  Classification-based and IQ-based dimensions
        # don't depend on baseline statistics, so novel threats remain
        # visible even during the cold-start window.
        if is_learning:
            # Security: only dampen baseline-dependent dimensions during
            # learning phase.  novel_class is NEVER dampened — unknown
            # signals must score at full weight even during cold-start
            # to avoid blind spots for new threats.
            _BASELINE_DEPENDENT = {
                AnomalyDimension.POWER_ZSCORE,
                AnomalyDimension.SNR_ZSCORE,
                AnomalyDimension.TIMING_ANOMALY,
                AnomalyDimension.QUIET_FREQUENCY,
                AnomalyDimension.BANDWIDTH_ANOMALY,
                AnomalyDimension.INTER_ARRIVAL_ANOMALY,
            }
            dampened = 0.0
            for dim, weight in weights.items():
                dim_score = dimensions.get(dim.value, 0.0)
                if dim in _BASELINE_DEPENDENT:
                    # 25% reduction (was 50%) — less aggressive dampening
                    # so real anomalies surface sooner during learning
                    dampened += weight * dim_score * 0.75
                else:
                    dampened += weight * dim_score
            composite = dampened

        composite = max(0.0, min(1.0, composite))

        # Security: boost score for unrecognized signal classes — unknown signals
        # should be flagged, not ignored (Blind Spot #5)
        family = detection.get("family", "")
        if not family:
            from sigrift.bridge.class_map import normalize_family

            family = normalize_family(class_name)
        if family == "UNKNOWN":
            composite = min(1.0, composite + 0.3)
            reasons.append("Unknown signal classification — elevated for review")

        # Apply feedback calibrator offset (positive = raise threshold = lower score)
        if self._calibrator is not None:
            composite = max(0.0, min(1.0, composite - self._calibrator.offset))

        priority = self._priority_label(composite)

        return AnomalyResult(
            score=round(composite, 4),
            priority=priority,
            dimensions={k: round(v, 4) for k, v in dimensions.items()},
            reasons=reasons,
            baseline_status=baseline_status,
        )

    # -----------------------------------------------------------------------
    # Dimension scorers
    # -----------------------------------------------------------------------

    @staticmethod
    def _novel_class_score(
        baseline: FrequencyBaseline | None,
        class_name: str,
    ) -> float:
        """1.0 if class was never seen at this frequency, 0.0 otherwise."""
        if baseline is None:
            return 0.0  # No baseline yet = can't determine novelty
        return 1.0 if baseline.is_novel_class(class_name) else 0.0

    @staticmethod
    def _rare_class_score(
        baseline: FrequencyBaseline | None,
        class_name: str,
    ) -> float:
        """Score based on how rare this class is at this frequency.

        Returns 1 - P(class | frequency), so common classes score
        near 0 and rare classes score near 1.
        """
        if baseline is None or baseline.total_detections == 0:
            return 0.0
        prob = baseline.class_probability_smoothed(class_name)
        return 1.0 - prob

    @staticmethod
    def _low_confidence_score(confidence: float) -> float:
        """Score based on classification confidence: 1 - confidence."""
        return max(0.0, min(1.0, 1.0 - confidence))

    @staticmethod
    def _power_zscore_score(
        baseline: FrequencyBaseline | None,
        power_dbm: float | None,
    ) -> float:
        """Score based on signal power deviation, normalized to [0, 1].

        Prefers MAD-based robust scoring when >= 30 power samples
        are available (same pattern as bandwidth scoring per P0-3).
        Falls back to z-score with sigmoid mapping otherwise.
        """
        if baseline is None or power_dbm is None:
            return 0.0
        if len(baseline.power_samples) >= 30:
            return min(1.0, baseline.power_mad_score(power_dbm))
        z = baseline.power_zscore(power_dbm)
        abs_z = abs(z)
        return min(1.0, abs_z / (abs_z + 3.0))

    @staticmethod
    def _snr_zscore_score(
        baseline: FrequencyBaseline | None,
        snr_db: float | None,
    ) -> float:
        """Score based on SNR deviation, normalized to [0, 1].

        Prefers MAD-based robust scoring when >= 30 SNR samples
        are available (same pattern as bandwidth scoring per P0-3).
        Falls back to z-score with sigmoid mapping otherwise.
        """
        if baseline is None or snr_db is None:
            return 0.0
        if len(baseline.snr_samples) >= 30:
            return min(1.0, baseline.snr_mad_score(snr_db))
        z = baseline.snr_zscore(snr_db)
        abs_z = abs(z)
        return min(1.0, abs_z / (abs_z + 3.0))

    @staticmethod
    def _timing_anomaly_score(
        baseline: FrequencyBaseline | None,
        class_name: str,
        hour: int,
    ) -> float:
        """Score based on how unusual this class is at this hour.

        Uses Laplace-smoothed probability so that a known class
        appearing at a new hour does not immediately score 1.0.
        """
        if baseline is None or baseline.total_detections == 0:
            return 0.0
        prob = baseline.hourly_probability_smoothed(class_name, hour)
        return 1.0 - prob

    @staticmethod
    def _quiet_frequency_score(
        baseline: FrequencyBaseline | None,
    ) -> float:
        """Score based on how rarely this frequency is used.

        Uses exponential decay: score = exp(-n / tau) where tau=20.
        This gives smooth transition instead of harsh steps:
          n=0  -> 1.0
          n=10 -> 0.61
          n=20 -> 0.37
          n=50 -> 0.08
          n=100 -> 0.007
        """
        if baseline is None:
            return 1.0
        n = baseline.total_detections
        if n == 0:
            return 1.0
        return math.exp(-n / 20.0)

    @staticmethod
    def _iq_quality_score(
        detection: dict[str, Any],
        iq_data: Any | None = None,
    ) -> float:
        """Score based on IQ data quality metrics.

        Evaluates three sub-metrics and averages them:
        - SNR quality: low SNR indicates poor signal quality
        - DC offset magnitude: large DC offset suggests receiver issues
        - IQ imbalance: amplitude/phase imbalance between I and Q

        If ``iq_data`` is a dict it may contain pre-computed keys:
        ``dc_offset``, ``iq_imbalance``, ``snr_db``.  If ``iq_data``
        is a list/array of complex samples, metrics are computed from
        the raw samples.

        When no raw IQ data is available, falls back to lightweight IQ
        features from the detection record (computed on edge).
        """
        if iq_data is None:
            # Fallback: use lightweight IQ features from detection record
            dc = detection.get("iq_dc_offset")
            imb = detection.get("iq_iq_imbalance")
            if dc is not None or imb is not None:
                scores = []
                if dc is not None:
                    scores.append(min(1.0, abs(dc) * 5.0))
                if imb is not None:
                    scores.append(min(1.0, abs(imb) * 5.0))
                snr = detection.get("snr_db")
                if snr is not None and snr < 10.0:
                    scores.append(max(0.0, 1.0 - snr / 10.0))
                return sum(scores) / max(len(scores), 1)
            return 0.0

        scores: list[float] = []

        if isinstance(iq_data, dict):
            # Pre-computed metrics
            dc_offset = iq_data.get("dc_offset")
            iq_imbalance = iq_data.get("iq_imbalance")
            snr_val = iq_data.get("snr_db")

            # DC offset score: magnitude > 0.1 is suspicious, > 0.5 is bad
            if dc_offset is not None:
                dc_mag = abs(dc_offset)
                dc_score = min(1.0, dc_mag / 0.5)
                scores.append(dc_score)

            # IQ imbalance score: > 0.05 (5%) is suspicious, > 0.3 is bad
            if iq_imbalance is not None:
                imb_score = min(1.0, abs(iq_imbalance) / 0.3)
                scores.append(imb_score)

            # SNR quality: low SNR = poor quality
            if snr_val is not None:
                # SNR < 10 dB is very poor, > 20 dB is good
                snr_score = max(0.0, min(1.0, 1.0 - (snr_val - 10.0) / 10.0))
                scores.append(snr_score)
        elif isinstance(iq_data, (list, tuple)) and len(iq_data) > 0:
            # Raw IQ samples — compute metrics
            try:
                samples = [complex(s) for s in iq_data]
                n = len(samples)

                # DC offset: |mean(samples)| / rms
                mean_val = sum(samples) / n
                rms = math.sqrt(sum(abs(s) ** 2 for s in samples) / n)
                if rms > 1e-12:
                    dc_ratio = abs(mean_val) / rms
                    scores.append(min(1.0, dc_ratio / 0.5))

                # IQ imbalance: ratio of I power to Q power deviation from 1
                i_power = sum(s.real**2 for s in samples) / n
                q_power = sum(s.imag**2 for s in samples) / n
                if q_power > 1e-12 and i_power > 1e-12:
                    ratio = i_power / q_power
                    imbalance = abs(ratio - 1.0)
                    scores.append(min(1.0, imbalance / 0.5))
            except (TypeError, ValueError):
                return 0.0

        if not scores:
            return 0.0
        return max(0.0, min(1.0, sum(scores) / len(scores)))

    @staticmethod
    def _spectral_anomaly_score(
        detection: dict[str, Any],
        iq_data: Any | None = None,
    ) -> float:
        """Score based on unusual spectral characteristics.

        Evaluates:
        - Spectral flatness: ratio of geometric to arithmetic mean of
          power spectrum.  Flat spectrum (noise-like) scores higher.
        - Unexpected bandwidth: declared bandwidth vs measured bandwidth.
        - Peak count: too many or too few spectral peaks.

        If ``iq_data`` is a dict it may contain pre-computed keys:
        ``spectral_flatness``, ``bandwidth_hz``, ``expected_bandwidth_hz``,
        ``num_peaks``, ``expected_peaks``.

        Falls back to edge-computed IQ features when raw IQ unavailable.
        """
        if iq_data is None:
            sf = detection.get("iq_spectral_flatness")
            bw = detection.get("iq_bandwidth_measured")
            if sf is not None:
                return min(1.0, max(0.0, (sf - 0.5) * 2.0)) if sf > 0.5 else 0.0
            if bw is not None:
                declared_bw = detection.get("bandwidth_hz", 0)
                if declared_bw and declared_bw > 0:
                    ratio = bw / declared_bw
                    if ratio > 2.0 or ratio < 0.3:
                        return min(1.0, abs(ratio - 1.0) / 2.0)
            return 0.0

        scores: list[float] = []

        if isinstance(iq_data, dict):
            # Spectral flatness: 1.0 = perfectly flat (noise), 0.0 = tonal
            # Normal signals have flatness 0.1-0.6; very high is anomalous
            flatness = iq_data.get("spectral_flatness")
            if flatness is not None:
                # Deviation from expected range [0.1, 0.6]
                if flatness > 0.6:
                    flat_score = min(1.0, (flatness - 0.6) / 0.4)
                elif flatness < 0.1:
                    flat_score = min(1.0, (0.1 - flatness) / 0.1)
                else:
                    flat_score = 0.0
                scores.append(flat_score)

            # Bandwidth mismatch
            bw = iq_data.get("bandwidth_hz")
            expected_bw = iq_data.get("expected_bandwidth_hz")
            if bw is not None and expected_bw is not None and expected_bw > 0:
                ratio = bw / expected_bw
                # Ratio outside [0.5, 2.0] is anomalous
                if ratio > 2.0:
                    bw_score = min(1.0, (ratio - 2.0) / 3.0)
                elif ratio < 0.5:
                    bw_score = min(1.0, (0.5 - ratio) / 0.5)
                else:
                    bw_score = 0.0
                scores.append(bw_score)

            # Peak count anomaly
            num_peaks = iq_data.get("num_peaks")
            expected_peaks = iq_data.get("expected_peaks")
            if (
                num_peaks is not None
                and expected_peaks is not None
                and expected_peaks > 0
            ):
                peak_ratio = abs(num_peaks - expected_peaks) / expected_peaks
                scores.append(min(1.0, peak_ratio / 2.0))

        elif isinstance(iq_data, (list, tuple)) and len(iq_data) >= 4:
            # Compute spectral flatness from raw IQ
            try:
                samples = [complex(s) for s in iq_data]
                n = len(samples)
                # Power spectrum via FFT (O(n log n)) with naive fallback
                try:
                    import numpy as np

                    fft_out = np.fft.fft(samples)
                    power_spec = (np.abs(fft_out) ** 2 / n).tolist()
                except ImportError:
                    # Cap naive DFT at 1024 samples to bound O(n^2) cost
                    if n > 1024:
                        samples = samples[:1024]
                        n = 1024
                    power_spec = []
                    for k in range(n):
                        acc = 0.0 + 0.0j
                        for idx, s in enumerate(samples):
                            acc += s * (
                                math.cos(2 * math.pi * k * idx / n)
                                - 1j * math.sin(2 * math.pi * k * idx / n)
                            )
                        power_spec.append(abs(acc) ** 2 / n)

                # Spectral flatness = exp(mean(log(x))) / mean(x)
                ps_pos = [p for p in power_spec if p > 1e-30]
                if len(ps_pos) > 0:
                    log_mean = sum(math.log(p) for p in ps_pos) / len(ps_pos)
                    arith_mean = sum(ps_pos) / len(ps_pos)
                    if arith_mean > 1e-30:
                        flatness = math.exp(log_mean) / arith_mean
                        # Score: very flat (>0.8) or very tonal (<0.05) is anomalous
                        if flatness > 0.6:
                            scores.append(min(1.0, (flatness - 0.6) / 0.4))
                        elif flatness < 0.1:
                            scores.append(min(1.0, (0.1 - flatness) / 0.1))
                        else:
                            scores.append(0.0)
            except (TypeError, ValueError):
                return 0.0

        if not scores:
            return 0.0
        return max(0.0, min(1.0, sum(scores) / len(scores)))

    @staticmethod
    def _modulation_anomaly_score(
        detection: dict[str, Any],
        iq_data: Any | None = None,
    ) -> float:
        """Score based on unexpected modulation parameters.

        Evaluates:
        - Symbol rate mismatch: declared vs measured symbol rate
        - Excessive CFO (carrier frequency offset)
        - Bandwidth mismatch with declared signal class

        If ``iq_data`` is a dict it may contain pre-computed keys:
        ``symbol_rate``, ``expected_symbol_rate``, ``cfo_hz``,
        ``bandwidth_hz``, ``signal_class``.

        Falls back to edge-computed IQ features when raw IQ unavailable.
        """
        if iq_data is None:
            # Fallback: use edge-computed modulation features
            sr = detection.get("iq_symbol_rate")
            cfo = detection.get("iq_cfo_hz")
            scores = []
            if cfo is not None and abs(cfo) > 500:
                scores.append(min(1.0, abs(cfo) / 5000.0))
            if sr is not None and sr > 0:
                # Check if symbol rate is unusual for the signal class
                # (simple heuristic: very high or very low is suspicious)
                if sr > 1e6 or sr < 100:
                    scores.append(0.5)
            if scores:
                return sum(scores) / len(scores)
            return 0.0

        scores: list[float] = []

        if isinstance(iq_data, dict):
            # Symbol rate mismatch
            sym_rate = iq_data.get("symbol_rate")
            expected_sym = iq_data.get("expected_symbol_rate")
            if sym_rate is not None and expected_sym is not None and expected_sym > 0:
                ratio = abs(sym_rate - expected_sym) / expected_sym
                scores.append(min(1.0, ratio / 1.0))

            # Excessive CFO
            cfo_hz = iq_data.get("cfo_hz")
            if cfo_hz is not None:
                # CFO > 1000 Hz is suspicious, > 5000 Hz is very anomalous
                cfo_score = min(1.0, abs(cfo_hz) / 5000.0)
                scores.append(cfo_score)

            # Bandwidth vs signal class expected bandwidth
            bw = iq_data.get("bandwidth_hz")
            sig_class = detection.get("signal_class", "")
            expected_bw = _EXPECTED_CLASS_BANDWIDTH.get(sig_class)
            if bw is not None and expected_bw is not None and expected_bw > 0:
                ratio = bw / expected_bw
                if ratio > 2.0:
                    bw_score = min(1.0, (ratio - 2.0) / 3.0)
                elif ratio < 0.5:
                    bw_score = min(1.0, (0.5 - ratio) / 0.5)
                else:
                    bw_score = 0.0
                scores.append(bw_score)

        elif isinstance(iq_data, (list, tuple)) and len(iq_data) >= 4:
            # Estimate CFO from raw IQ by phase difference
            try:
                samples = [complex(s) for s in iq_data]
                # Average phase rotation between consecutive samples
                phase_diffs = []
                for i in range(1, len(samples)):
                    if abs(samples[i - 1]) > 1e-12:
                        conj_prod = samples[i] * samples[i - 1].conjugate()
                        phase_diffs.append(math.atan2(conj_prod.imag, conj_prod.real))
                if phase_diffs:
                    avg_phase = sum(phase_diffs) / len(phase_diffs)
                    # Normalize: pi radians/sample = max CFO
                    cfo_score = min(1.0, abs(avg_phase) / math.pi)
                    scores.append(cfo_score)
            except (TypeError, ValueError):
                return 0.0

        if not scores:
            return 0.0
        return max(0.0, min(1.0, sum(scores) / len(scores)))

    def _signature_match_score(self, detection: dict[str, Any]) -> float:
        """Score detection against threat signature library.

        Returns 0.0-1.0 based on best match against known threat signatures.
        Uses parameter-based matching (freq, class, power, bandwidth).
        """
        sig_store = getattr(self, "_sig_store", None)
        if sig_store is None:
            return 0.0
        try:
            freq_hz = detection.get("freq_hz", 0.0)
            signal_class = detection.get("signal_class", "")
            power_dbm = detection.get("power_dbm")
            bandwidth_hz = detection.get("bandwidth_hz")

            matches = sig_store.match_by_parameters(
                freq_hz=freq_hz,
                signal_class=signal_class,
                power_dbm=power_dbm,
                bandwidth_hz=bandwidth_hz,
            )
            if matches:
                best = matches[0].get("match_score", 0.0)
                if best >= 0.3:
                    return min(1.0, best)
        except Exception:
            pass
        return 0.0

    @staticmethod
    def _bandwidth_anomaly_score(
        baseline: FrequencyBaseline | None,
        class_name: str,
        bandwidth_hz: float | None,
    ) -> float:
        """Score based on bandwidth deviation from per-class baseline.

        Prefers MAD-based robust scoring when >= 30 bandwidth samples
        are available (same pattern as power scoring per P0-3).
        Falls back to per-class z-score otherwise.
        Returns 0.0 when no bandwidth data or insufficient baseline.
        """
        if baseline is None or bandwidth_hz is None or bandwidth_hz <= 0:
            return 0.0
        # Prefer MAD when sufficient samples
        if len(baseline.bandwidth_samples) >= 30:
            return baseline.bandwidth_mad_score(bandwidth_hz)
        # Fall back to per-class z-score
        z = baseline.bandwidth_zscore(class_name, bandwidth_hz)
        abs_z = abs(z)
        return min(1.0, abs_z / (abs_z + 3.0))

    @staticmethod
    def _inter_arrival_anomaly_score(
        baseline: FrequencyBaseline | None,
    ) -> float:
        """Score based on inter-arrival time anomaly.

        Compares the most recent inter-arrival time against the
        running baseline using z-score with sigmoid mapping.
        Returns 0.0 when insufficient inter-arrival data.
        """
        if baseline is None:
            return 0.0
        z = baseline.inter_arrival_zscore()
        abs_z = abs(z)
        return min(1.0, abs_z / (abs_z + 3.0))

    # -----------------------------------------------------------------------
    # Priority
    # -----------------------------------------------------------------------

    @staticmethod
    def _priority_label(score: float) -> str:
        """Map composite score to priority label.

        Normal      0.0 – 0.3
        Interesting 0.3 – 0.5
        Anomalous   0.5 – 0.7
        Critical    0.7 – 1.0
        """
        if score < 0.3:
            return "normal"
        elif score < 0.5:
            return "interesting"
        elif score < 0.7:
            return "anomalous"
        return "critical"

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _extract_hour(timestamp: Any) -> int:
        """Extract hour of day from various timestamp formats."""
        if isinstance(timestamp, datetime):
            return timestamp.hour
        if isinstance(timestamp, str):
            try:
                dt = datetime.fromisoformat(timestamp)
                return dt.hour
            except (ValueError, TypeError):
                pass
        return datetime.now(timezone.utc).hour


# ---------------------------------------------------------------------------
# Correlation score adjustment
# ---------------------------------------------------------------------------


def _correlation_adjustment(correlation_score: float) -> float:
    """Map a correlation score (0.0-1.0) to a composite score adjustment.

    >0.5  (multi-node correlated): linear boost up to +0.15
    <0.2  (single-node only):      linear dampen down to -0.05
    0.2-0.5: linear interpolation crossing zero near 0.35

    Parameters
    ----------
    correlation_score : float
        Cross-node correlation score from NodeCorrelator.

    Returns
    -------
    float
        Additive adjustment to apply to the composite score.
    """
    if correlation_score > 0.5:
        # Linear interpolation from 0.0 at 0.5 to +0.15 at 1.0
        return 0.15 * (correlation_score - 0.5) / 0.5
    if correlation_score < 0.2:
        # Linear interpolation from -0.05 at 0.0 to 0.0 at 0.2
        return -0.05 * (1.0 - correlation_score / 0.2)
    # Neutral zone 0.2–0.5: linear from 0.0 at 0.2 to 0.0 at 0.5
    return 0.0


# ---------------------------------------------------------------------------
# CompositeScorer — combines Tier 1, 2, and 3 scores
# ---------------------------------------------------------------------------


class CompositeScorer:
    """Combine scores from all available tiers into a final priority score.

    Dynamically adjusts weights based on which tiers are available:
    - All 3 tiers: 0.3 / 0.3 / 0.4
    - 2 tiers: 0.5 / 0.5
    - 1 tier: 1.0

    Context boosts are applied additively (capped at MAX_CONTEXT_BOOST)
    to prevent mid-range scores from being inflated to 1.0:
    - novel_class: +0.10
    - quiet_frequency: +0.08
    - multiple_nodes: +0.05
    - regulatory_band: +0.10

    Parameters
    ----------
    weights_3tier : tuple[float, float, float]
        Weights for (tier1, tier2, tier3) when all 3 are available.
    weights_2tier : tuple[float, float]
        Weights when only 2 tiers are available.
    context_multipliers : dict[str, float] or None
        Overrides for context boost values.
    """

    # Default weights
    DEFAULT_WEIGHTS_3 = (0.3, 0.3, 0.4)
    DEFAULT_WEIGHTS_2 = (0.5, 0.5)

    # Additive context boosts (not multipliers) to avoid score inflation.
    # Total boost is capped at MAX_CONTEXT_BOOST to prevent mid-range
    # scores from being pushed to 1.0.
    MAX_CONTEXT_BOOST = 0.25

    DEFAULT_CONTEXT_BOOSTS = {
        "novel_class": 0.10,
        "quiet_frequency": 0.08,
        "multiple_nodes": 0.05,
        "regulatory_band": 0.10,
    }

    def __init__(
        self,
        weights_3tier: tuple[float, float, float] | None = None,
        weights_2tier: tuple[float, float] | None = None,
        context_multipliers: dict[str, float] | None = None,
    ) -> None:
        self.weights_3 = weights_3tier or self.DEFAULT_WEIGHTS_3
        self.weights_2 = weights_2tier or self.DEFAULT_WEIGHTS_2
        self.context_boosts = dict(self.DEFAULT_CONTEXT_BOOSTS)
        if context_multipliers:
            self.context_boosts.update(context_multipliers)

    def score(
        self,
        tier1_result: AnomalyResult,
        tier2_score: float | None = None,
        tier3_score: float | None = None,
        context: dict[str, Any] | None = None,
        correlation_score: float | None = None,
    ) -> float:
        """Compute composite priority score from all available tiers.

        Parameters
        ----------
        tier1_result : AnomalyResult
            Tier 1 statistical scoring result.
        tier2_score : float or None
            Tier 2 (Isolation Forest) anomaly score, or None if unavailable.
        tier3_score : float or None
            Tier 3 (Autoencoder) anomaly score, or None if unavailable.
        context : dict or None
            Contextual flags: novel_class, quiet_frequency,
            multiple_nodes, regulatory_band.
        correlation_score : float or None
            Cross-node correlation score from NodeCorrelator (0.0-1.0).
            When provided, adjusts the composite score:
            - >0.5 (correlated): boost up to +0.15
            - <0.2 (single-node): dampen up to -0.05
            - 0.2-0.5: linear interpolation (no adjustment at 0.35)

        Returns
        -------
        float
            Composite score clamped to [0, 1].
        """
        has_t2 = tier2_score is not None
        has_t3 = tier3_score is not None

        if has_t2 and has_t3:
            # All 3 tiers available
            w1, w2, w3 = self.weights_3
            composite = w1 * tier1_result.score + w2 * tier2_score + w3 * tier3_score
        elif has_t2:
            w1, w2 = self.weights_2
            composite = w1 * tier1_result.score + w2 * tier2_score
        elif has_t3:
            w1, w2 = self.weights_2
            composite = w1 * tier1_result.score + w2 * tier3_score
        else:
            # Only tier 1
            composite = tier1_result.score

        # Apply context boosts additively (capped to avoid score inflation)
        if context:
            total_boost = 0.0
            for flag, boost in self.context_boosts.items():
                if context.get(flag):
                    total_boost += boost
            composite += min(total_boost, self.MAX_CONTEXT_BOOST)

        # Apply correlation score adjustment
        if correlation_score is not None:
            composite += _correlation_adjustment(correlation_score)

        return max(0.0, min(1.0, composite))
