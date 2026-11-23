"""ROC / AUC evaluation framework for anomaly scoring (DS-R12).

Connects operator feedback (true_positive / false_positive labels) to
scoring evaluation.  Computes ROC curves, AUC, and optimal threshold
selection based on target false-positive rates — answering the question
"what does a 0.65 score mean in terms of false positive rate?"

No external dependencies (no scipy/sklearn needed for basic ROC).
"""

from __future__ import annotations

import bisect
import logging
import math
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ROCPoint:
    """Single point on the ROC curve."""

    threshold: float
    tpr: float  # true positive rate (sensitivity / recall)
    fpr: float  # false positive rate (1 - specificity)


@dataclass
class EvaluationResult:
    """Result of scoring evaluation."""

    auc: float
    n_positive: int
    n_negative: int
    roc_curve: list[ROCPoint] = field(default_factory=list)
    optimal_threshold: float = 0.5
    optimal_f1: float = 0.0


# ---------------------------------------------------------------------------
# ScoringEvaluator
# ---------------------------------------------------------------------------


class ScoringEvaluator:
    """Evaluate anomaly scoring quality using labeled feedback.

    Accumulates (score, is_anomaly) pairs and computes ROC/AUC metrics.
    """

    def __init__(self, max_samples: int = 10_000) -> None:
        self._samples: list[tuple[float, bool]] = []
        self.max_samples = max_samples

    def add_labeled_sample(self, score: float, is_anomaly: bool) -> None:
        """Record a labeled detection for evaluation.

        Parameters
        ----------
        score : float
            Anomaly score assigned by the scorer.
        is_anomaly : bool
            Ground truth: True if confirmed anomaly (TP), False if FP.
        """
        if len(self._samples) >= self.max_samples:
            self._samples.pop(0)  # FIFO eviction
        self._samples.append((score, is_anomaly))

    def add_feedback_batch(
        self,
        detections: list[dict[str, Any]],
        feedback: list[dict[str, Any]],
    ) -> int:
        """Load labeled samples from detection + feedback records.

        Joins detections with their feedback labels. Only considers
        'true_positive' and 'false_positive' labels.

        Parameters
        ----------
        detections : list[dict]
            Detection records with 'detection_id' and 'anomaly_score'.
        feedback : list[dict]
            Feedback records with 'detection_id' and 'label'.

        Returns
        -------
        int
            Number of labeled samples added.
        """
        score_map: dict[str, float] = {}
        for det in detections:
            did = det.get("detection_id", "")
            score = det.get("anomaly_score")
            if did and score is not None:
                score_map[did] = float(score)

        count = 0
        for fb in feedback:
            did = fb.get("detection_id", "")
            label = fb.get("label", "")
            if did in score_map and label in ("true_positive", "false_positive"):
                self._samples.append((score_map[did], label == "true_positive"))
                count += 1
        return count

    @property
    def sample_count(self) -> int:
        return len(self._samples)

    def check_label_quality(self) -> dict[str, Any]:
        """Check for suspicious label patterns."""
        if not self._samples:
            return {"warnings": [], "total": 0}

        warnings = []
        positives = sum(1 for _, lbl in self._samples if lbl)
        negatives = len(self._samples) - positives
        total = len(self._samples)

        # Flag extreme imbalance
        if total >= 20:
            fp_rate = negatives / total
            if fp_rate > 0.9:
                warnings.append(
                    "Over 90% of labels are false_positive — possible label poisoning"
                )
            elif fp_rate < 0.1:
                warnings.append(
                    "Over 90% of labels are true_positive — possible label inflation"
                )

        return {
            "warnings": warnings,
            "total": total,
            "positive_rate": positives / max(total, 1),
        }

    def compute_roc(self, n_thresholds: int = 200) -> EvaluationResult:
        """Compute ROC curve and AUC from accumulated labeled samples.

        Parameters
        ----------
        n_thresholds : int
            Number of threshold points for the ROC curve.

        Returns
        -------
        EvaluationResult
            ROC curve, AUC, and optimal threshold.
        """
        if not self._samples:
            return EvaluationResult(auc=0.0, n_positive=0, n_negative=0)

        positives = [s for s, lbl in self._samples if lbl]
        negatives = [s for s, lbl in self._samples if not lbl]
        n_pos = len(positives)
        n_neg = len(negatives)

        if n_pos == 0 or n_neg == 0:
            return EvaluationResult(auc=0.0, n_positive=n_pos, n_negative=n_neg)

        # Generate thresholds spanning the score range
        all_scores = [s for s, _ in self._samples]
        min_s = min(all_scores)
        max_s = max(all_scores)
        step = (max_s - min_s) / n_thresholds if n_thresholds > 0 else 0.01
        thresholds = [min_s + i * step for i in range(n_thresholds + 1)]

        # O(n log n) sort once, then O(m log n) threshold sweep via bisect
        positives_sorted = sorted(positives)  # ascending for bisect
        negatives_sorted = sorted(negatives)

        roc_points: list[ROCPoint] = []
        best_f1 = 0.0
        best_threshold = 0.5

        for thresh in thresholds:
            # bisect_left gives count of values < thresh
            tp = n_pos - bisect.bisect_left(positives_sorted, thresh)
            fp = n_neg - bisect.bisect_left(negatives_sorted, thresh)
            tpr = tp / n_pos
            fpr = fp / n_neg
            roc_points.append(ROCPoint(threshold=round(thresh, 4), tpr=tpr, fpr=fpr))

            # F1 score for optimal threshold selection
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tpr
            if precision + recall > 0:
                f1 = 2 * precision * recall / (precision + recall)
                if f1 > best_f1:
                    best_f1 = f1
                    best_threshold = thresh

        # Sort by FPR for AUC computation (trapezoidal rule)
        roc_points.sort(key=lambda p: (p.fpr, p.tpr))
        auc = self._trapezoidal_auc(roc_points)

        return EvaluationResult(
            auc=round(auc, 4),
            n_positive=n_pos,
            n_negative=n_neg,
            roc_curve=roc_points,
            optimal_threshold=round(best_threshold, 4),
            optimal_f1=round(best_f1, 4),
        )

    def threshold_for_fpr(self, target_fpr: float) -> float | None:
        """Find the threshold that achieves a target false-positive rate.

        Parameters
        ----------
        target_fpr : float
            Desired false positive rate (e.g. 0.05 for 5%).

        Returns
        -------
        float or None
            Threshold value, or None if insufficient data.
        """
        negatives = sorted(
            [s for s, lbl in self._samples if not lbl],
            reverse=True,
        )
        if not negatives:
            return None
        # FPR = fraction of negatives above threshold
        # Find the score at the target_fpr quantile from the top
        idx = int(math.ceil(target_fpr * len(negatives))) - 1
        idx = max(0, min(idx, len(negatives) - 1))
        return negatives[idx]

    def confusion_matrix(self, threshold: float) -> dict[str, int]:
        """Compute confusion matrix at a specific threshold.

        Returns
        -------
        dict
            Keys: tp, fp, tn, fn.
        """
        tp = fp = tn = fn = 0
        for score, is_anomaly in self._samples:
            predicted = score >= threshold
            if is_anomaly and predicted:
                tp += 1
            elif is_anomaly and not predicted:
                fn += 1
            elif not is_anomaly and predicted:
                fp += 1
            else:
                tn += 1
        return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}

    def clear(self) -> None:
        """Clear all accumulated samples."""
        self._samples.clear()

    @staticmethod
    def _trapezoidal_auc(points: list[ROCPoint]) -> float:
        """Compute AUC using trapezoidal rule on sorted ROC points."""
        if len(points) < 2:
            return 0.0
        auc = 0.0
        for i in range(1, len(points)):
            dx = points[i].fpr - points[i - 1].fpr
            avg_y = (points[i].tpr + points[i - 1].tpr) / 2
            auc += dx * avg_y
        return max(0.0, min(1.0, auc))
