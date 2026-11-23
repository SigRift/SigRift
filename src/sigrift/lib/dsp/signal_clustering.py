"""HDBSCAN-based clustering for signal fingerprint embeddings.

Groups unknown/unclassified signals by their 32-dimensional embeddings
using density-based clustering.  Falls back to agglomerative clustering
via scipy if sklearn HDBSCAN is unavailable.
"""

from __future__ import annotations

import logging

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------

_BACKEND: str = "none"

try:
    from sklearn.cluster import HDBSCAN as _SklearnHDBSCAN

    _BACKEND = "sklearn"
except ImportError:
    pass

if _BACKEND == "none":
    try:
        import hdbscan as _hdbscan_pkg

        _BACKEND = "hdbscan"
    except ImportError:
        pass

if _BACKEND == "none":
    try:
        from scipy.cluster.hierarchy import fcluster, linkage
        from scipy.spatial.distance import pdist

        _BACKEND = "scipy"
    except ImportError:
        pass

logger.debug("SignalClusterer backend: %s", _BACKEND)


# ---------------------------------------------------------------------------
# SignalClusterer
# ---------------------------------------------------------------------------


class SignalClusterer:
    """HDBSCAN-based clustering for signal fingerprint embeddings.

    Parameters
    ----------
    min_cluster_size : int
        Minimum number of points to form a cluster.
    min_samples : int
        Minimum neighbourhood density parameter.
    metric : str
        Distance metric (default ``'cosine'``).
    cluster_selection_epsilon : float
        HDBSCAN epsilon parameter for merging clusters.
    """

    def __init__(
        self,
        min_cluster_size: int = 5,
        min_samples: int = 3,
        metric: str = "cosine",
        cluster_selection_epsilon: float = 0.0,
    ) -> None:
        self.min_cluster_size = min_cluster_size
        self.min_samples = min_samples
        self.metric = metric
        self.cluster_selection_epsilon = cluster_selection_epsilon
        self.labels_: np.ndarray | None = None
        self.probabilities_: np.ndarray | None = None
        self.n_clusters_: int = 0
        self._centroids: np.ndarray | None = None

    # ------------------------------------------------------------------
    # Fit
    # ------------------------------------------------------------------

    def fit(self, embeddings: np.ndarray) -> "SignalClusterer":
        """Cluster embeddings using HDBSCAN (or fallback).

        Args:
            embeddings: (N, D) array of L2-normalized embeddings.

        Returns:
            self with ``labels_``, ``probabilities_``, ``n_clusters_`` set.
        """
        if (
            embeddings.size == 0
            or len(embeddings.shape) < 2
            or embeddings.shape[0] == 0
        ):
            self.labels_ = np.array([], dtype=np.intp)
            self.probabilities_ = np.array([], dtype=np.float64)
            self.n_clusters_ = 0
            self._centroids = np.empty((0, 0))
            return self

        n_samples = embeddings.shape[0]

        # Not enough points for any cluster
        if n_samples < self.min_cluster_size:
            self.labels_ = np.full(n_samples, -1, dtype=np.intp)
            self.probabilities_ = np.zeros(n_samples, dtype=np.float64)
            self.n_clusters_ = 0
            self._centroids = np.empty((0, embeddings.shape[1]))
            return self

        if _BACKEND == "sklearn":
            self._fit_sklearn(embeddings)
        elif _BACKEND == "hdbscan":
            self._fit_hdbscan(embeddings)
        elif _BACKEND == "scipy":
            self._fit_scipy(embeddings)
        else:
            # No clustering library available at all
            logger.warning("No clustering backend available; labelling all as noise")
            self.labels_ = np.full(n_samples, -1, dtype=np.intp)
            self.probabilities_ = np.zeros(n_samples, dtype=np.float64)
            self.n_clusters_ = 0

        # Compute centroids
        self._compute_centroids(embeddings)
        return self

    def fit_predict(self, embeddings: np.ndarray) -> np.ndarray:
        """Fit and return cluster labels.  -1 = noise/unclustered."""
        self.fit(embeddings)
        return self.labels_

    # ------------------------------------------------------------------
    # Backend implementations
    # ------------------------------------------------------------------

    def _fit_sklearn(self, embeddings: np.ndarray) -> None:
        clusterer = _SklearnHDBSCAN(
            min_cluster_size=self.min_cluster_size,
            min_samples=self.min_samples,
            metric=self.metric,
            cluster_selection_epsilon=self.cluster_selection_epsilon,
        )
        clusterer.fit(embeddings)
        self.labels_ = clusterer.labels_
        self.probabilities_ = getattr(
            clusterer, "probabilities_", np.ones(len(embeddings))
        )
        self.n_clusters_ = (
            int(self.labels_.max() + 1)
            if len(self.labels_) > 0 and self.labels_.max() >= 0
            else 0
        )

    def _fit_hdbscan(self, embeddings: np.ndarray) -> None:
        clusterer = _hdbscan_pkg.HDBSCAN(
            min_cluster_size=self.min_cluster_size,
            min_samples=self.min_samples,
            metric=self.metric,
            cluster_selection_epsilon=self.cluster_selection_epsilon,
        )
        clusterer.fit(embeddings)
        self.labels_ = clusterer.labels_
        self.probabilities_ = clusterer.probabilities_
        self.n_clusters_ = (
            int(self.labels_.max() + 1)
            if len(self.labels_) > 0 and self.labels_.max() >= 0
            else 0
        )

    def _fit_scipy(self, embeddings: np.ndarray) -> None:
        """Agglomerative clustering fallback using scipy."""
        # Compute pairwise cosine distances
        if self.metric == "cosine":
            dists = pdist(embeddings, metric="cosine")
        else:
            dists = pdist(embeddings, metric=self.metric)

        # Replace NaN distances (from zero-norm vectors) with 1.0
        dists = np.nan_to_num(dists, nan=1.0)

        Z = linkage(dists, method="average")

        # Use a distance threshold; for cosine, 0.5 is a reasonable default
        threshold = (
            max(self.cluster_selection_epsilon, 0.5)
            if self.cluster_selection_epsilon > 0
            else 0.5
        )
        raw_labels = fcluster(Z, t=threshold, criterion="distance")

        # Convert to 0-based labels; mark small clusters as noise (-1)
        from collections import Counter

        counts = Counter(raw_labels)
        label_map: dict[int, int] = {}
        next_id = 0
        for lbl, cnt in sorted(counts.items()):
            if cnt >= self.min_cluster_size:
                label_map[lbl] = next_id
                next_id += 1
            else:
                label_map[lbl] = -1

        self.labels_ = np.array([label_map[l] for l in raw_labels], dtype=np.intp)  # noqa: E741
        self.probabilities_ = np.where(self.labels_ >= 0, 1.0, 0.0).astype(np.float64)
        self.n_clusters_ = next_id

    # ------------------------------------------------------------------
    # Centroids
    # ------------------------------------------------------------------

    def _compute_centroids(self, embeddings: np.ndarray) -> None:
        """Compute mean embedding (centroid) per cluster."""
        if self.n_clusters_ == 0:
            self._centroids = np.empty((0, embeddings.shape[1]))
            return

        dim = embeddings.shape[1]
        centroids = np.zeros((self.n_clusters_, dim))
        for cid in range(self.n_clusters_):
            mask = self.labels_ == cid
            if mask.any():
                centroid = embeddings[mask].mean(axis=0)
                norm = np.linalg.norm(centroid)
                if norm > 1e-12:
                    centroid /= norm
                centroids[cid] = centroid
        self._centroids = centroids

    # ------------------------------------------------------------------
    # Cluster summary
    # ------------------------------------------------------------------

    def get_cluster_summary(
        self,
        embeddings: np.ndarray,
        metadata: list[dict],
    ) -> list[dict]:
        """Get summary for each cluster.

        Parameters
        ----------
        embeddings : np.ndarray
            (N, D) embeddings that were fitted.
        metadata : list[dict]
            Per-sample metadata dicts.  Expected keys: ``fingerprint_id``,
            ``signal_class`` (optional), ``confidence`` (optional),
            ``freq_hz`` (optional).

        Returns
        -------
        list[dict]
            One summary per cluster with keys: cluster_id, size, centroid,
            members, dominant_class, class_distribution, mean_confidence,
            freq_range.
        """
        if self.labels_ is None or self.n_clusters_ == 0:
            return []

        summaries: list[dict] = []
        for cid in range(self.n_clusters_):
            mask = self.labels_ == cid
            indices = np.where(mask)[0]

            members = []
            classes: dict[str, int] = {}
            confidences: list[float] = []
            freqs: list[float] = []

            for idx in indices:
                meta = metadata[idx] if idx < len(metadata) else {}
                fp_id = meta.get("fingerprint_id", f"fp_{idx}")
                members.append(fp_id)

                sig_cls = meta.get("signal_class")
                if sig_cls:
                    classes[sig_cls] = classes.get(sig_cls, 0) + 1

                conf = meta.get("confidence")
                if conf is not None:
                    confidences.append(float(conf))

                freq = meta.get("freq_hz")
                if freq is not None:
                    freqs.append(float(freq))

            centroid = (
                self._centroids[cid].tolist() if self._centroids is not None else []
            )

            dominant_class = max(classes, key=classes.get) if classes else None
            mean_conf = float(np.mean(confidences)) if confidences else 0.0
            freq_range = [min(freqs), max(freqs)] if freqs else [0.0, 0.0]

            summaries.append(
                {
                    "cluster_id": int(cid),
                    "size": int(mask.sum()),
                    "centroid": centroid,
                    "members": members,
                    "dominant_class": dominant_class,
                    "class_distribution": classes,
                    "mean_confidence": round(mean_conf, 4),
                    "freq_range": freq_range,
                }
            )

        return summaries

    # ------------------------------------------------------------------
    # Predict nearest cluster
    # ------------------------------------------------------------------

    def predict_cluster(
        self,
        embedding: np.ndarray,
        threshold: float = 0.3,
    ) -> tuple[int, float]:
        """Assign a new embedding to the nearest existing cluster.

        Uses cosine similarity to cluster centroids.

        Parameters
        ----------
        embedding : np.ndarray
            (D,) embedding vector.
        threshold : float
            Minimum cosine similarity to assign to a cluster.

        Returns
        -------
        tuple[int, float]
            (cluster_id, similarity).  cluster_id = -1 if no cluster
            is close enough.
        """
        if self._centroids is None or self._centroids.shape[0] == 0:
            return -1, 0.0

        # L2-normalise the query embedding
        norm = np.linalg.norm(embedding)
        if norm < 1e-12:
            return -1, 0.0
        emb_normed = embedding / norm

        # Cosine similarities to all centroids
        sims = self._centroids @ emb_normed
        best_idx = int(np.argmax(sims))
        best_sim = float(sims[best_idx])

        if best_sim < threshold:
            return -1, best_sim

        return best_idx, best_sim
