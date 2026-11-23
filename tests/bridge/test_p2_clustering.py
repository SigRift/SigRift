"""Tests for HDBSCAN signal clustering and cluster management endpoints."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import numpy as np
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.lib.dsp.signal_clustering import SignalClusterer


# ---------------------------------------------------------------------------
# Helpers — synthetic embedding generation
# ---------------------------------------------------------------------------

def _make_tight_cluster(center: np.ndarray, n: int, noise_std: float = 0.01) -> np.ndarray:
    """Generate *n* embeddings tightly scattered around *center*."""
    rng = np.random.RandomState(42)
    pts = center + rng.randn(n, len(center)) * noise_std
    # L2 normalise
    norms = np.linalg.norm(pts, axis=1, keepdims=True)
    norms[norms < 1e-12] = 1.0
    return pts / norms


def _random_embeddings(n: int, dim: int = 32, seed: int = 99) -> np.ndarray:
    """Generate *n* random unit embeddings."""
    rng = np.random.RandomState(seed)
    pts = rng.randn(n, dim)
    norms = np.linalg.norm(pts, axis=1, keepdims=True)
    norms[norms < 1e-12] = 1.0
    return pts / norms


def _make_three_groups(n_per_group: int = 20, dim: int = 32) -> tuple[np.ndarray, list[dict]]:
    """Create 3 well-separated groups of embeddings with metadata."""
    rng = np.random.RandomState(7)
    centers = []
    for _ in range(3):
        c = rng.randn(dim)
        c /= np.linalg.norm(c)
        centers.append(c)

    all_emb: list[np.ndarray] = []
    all_meta: list[dict] = []
    class_names = ["bpsk", "qpsk", "ofdm"]
    freqs = [433e6, 915e6, 2.4e9]

    for gi, center in enumerate(centers):
        pts = _make_tight_cluster(center, n_per_group, noise_std=0.02)
        for i, pt in enumerate(pts):
            all_emb.append(pt)
            all_meta.append({
                "fingerprint_id": f"fp_g{gi}_{i}",
                "signal_class": class_names[gi],
                "confidence": 0.9 + rng.rand() * 0.1,
                "freq_hz": freqs[gi] + rng.randn() * 1000,
            })

    return np.array(all_emb), all_meta


# ===========================================================================
# TestSignalClusterer
# ===========================================================================

class TestSignalClusterer:
    """Unit tests for the SignalClusterer engine."""

    def test_cluster_identical_signals(self):
        """A tight group of similar signals plus sparse noise yields cluster(s)."""
        rng = np.random.RandomState(1)
        center = rng.randn(32)
        center /= np.linalg.norm(center)
        # 25 tight points around center + 10 scattered noise points
        tight = _make_tight_cluster(center, 25, noise_std=0.05)
        scattered = _random_embeddings(10, dim=32, seed=55)
        embs = np.vstack([tight, scattered])

        clusterer = SignalClusterer(min_cluster_size=5, min_samples=2)
        labels = clusterer.fit_predict(embs)

        # The tight group should be clustered (non-noise)
        non_noise = labels[labels >= 0]
        assert len(non_noise) > 0, "Expected at least some points to be clustered"
        # The tight points (first 25) should mostly be in cluster(s)
        tight_labels = labels[:25]
        assert (tight_labels >= 0).sum() >= 15, "Most tight points should be clustered"

    def test_cluster_distinct_groups(self):
        """3 well-separated groups should yield 3 clusters."""
        embs, meta = _make_three_groups(n_per_group=20)

        clusterer = SignalClusterer(min_cluster_size=5, min_samples=3)
        labels = clusterer.fit_predict(embs)

        assert clusterer.n_clusters_ == 3, f"Expected 3 clusters, got {clusterer.n_clusters_}"

    def test_noise_points_labeled_minus_one(self):
        """Scattered random points with a few tight groups should produce noise labels."""
        # Make 1 tight cluster + many scattered points
        center = np.zeros(32)
        center[0] = 1.0
        tight = _make_tight_cluster(center, 10, noise_std=0.01)
        scattered = _random_embeddings(30, dim=32, seed=77)
        embs = np.vstack([tight, scattered])

        clusterer = SignalClusterer(min_cluster_size=5, min_samples=3)
        labels = clusterer.fit_predict(embs)

        # Some points should be labelled -1
        assert (labels == -1).any(), "Expected some noise points with label -1"

    def test_cluster_summary_correct(self):
        """Summary should include size, centroid, and members."""
        embs, meta = _make_three_groups(n_per_group=20)

        clusterer = SignalClusterer(min_cluster_size=5, min_samples=3)
        clusterer.fit(embs)
        summaries = clusterer.get_cluster_summary(embs, meta)

        assert len(summaries) == 3
        for s in summaries:
            assert "cluster_id" in s
            assert isinstance(s["cluster_id"], int)
            assert s["size"] > 0
            assert isinstance(s["size"], int)
            assert len(s["centroid"]) == 32
            assert isinstance(s["centroid"], list)
            assert len(s["members"]) == s["size"]
            assert isinstance(s["members"], list)
            assert s["dominant_class"] in ("bpsk", "qpsk", "ofdm")
            assert isinstance(s["mean_confidence"], float)
            assert s["mean_confidence"] > 0.0
            assert len(s["freq_range"]) == 2
            assert isinstance(s["freq_range"], list)

    def test_predict_nearest_cluster(self):
        """A new point near a cluster centroid should be assigned to that cluster."""
        embs, meta = _make_three_groups(n_per_group=20)

        clusterer = SignalClusterer(min_cluster_size=5, min_samples=3)
        clusterer.fit(embs)

        # Pick a point from group 0 and verify prediction
        test_point = embs[0]  # Should be near cluster containing group 0
        cid, sim = clusterer.predict_cluster(test_point, threshold=0.3)

        assert cid >= 0, "Expected assignment to a cluster"
        assert sim > 0.5, f"Expected high similarity, got {sim}"

    def test_predict_outlier_returns_minus_one(self):
        """A distant point should return cluster_id = -1."""
        embs, meta = _make_three_groups(n_per_group=20)

        clusterer = SignalClusterer(min_cluster_size=5, min_samples=3)
        clusterer.fit(embs)

        # Very high threshold that nothing can meet
        random_point = _random_embeddings(1, dim=32, seed=123)[0]
        cid, sim = clusterer.predict_cluster(random_point, threshold=0.999)

        assert cid == -1, "Expected -1 for distant point with high threshold"

    def test_empty_input(self):
        """Empty array should return empty labels."""
        clusterer = SignalClusterer()
        embs = np.empty((0, 32))
        labels = clusterer.fit_predict(embs)

        assert len(labels) == 0
        assert clusterer.n_clusters_ == 0

    def test_single_point(self):
        """Single point cannot form a cluster, should get label -1."""
        clusterer = SignalClusterer(min_cluster_size=5)
        embs = _random_embeddings(1, dim=32)
        labels = clusterer.fit_predict(embs)

        assert len(labels) == 1
        assert labels[0] == -1
        assert clusterer.n_clusters_ == 0


# ===========================================================================
# TestClusterEndpoints
# ===========================================================================

class TestClusterEndpoints:
    """Integration tests for the /api/clusters endpoints."""

    @pytest.fixture(autouse=True)
    def _patch_clusters_file(self, tmp_path: Path):
        """Redirect cluster storage to temp directory for test isolation."""
        clusters_file = tmp_path / "clusters.json"
        with patch("sigrift.bridge.routers.clusters._CLUSTERS_FILE", clusters_file):
            self._clusters_file = clusters_file
            yield

    def test_list_clusters_empty(self, client: TestClient):
        """GET /api/clusters/ before any run returns empty list."""
        resp = client.get("/api/clusters/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["clusters"] == []
        assert data["n_clusters"] == 0

    def test_stats_endpoint_empty(self, client: TestClient):
        """GET /api/clusters/stats before any run returns zeroes."""
        resp = client.get("/api/clusters/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["n_clusters"] == 0
        assert data["n_unclustered"] == 0
        assert data["largest_cluster"] == 0
        assert data["last_run"] is None

    def test_run_clustering_returns_job_id(self, client: TestClient, bridge_app: FastAPI):
        """POST /api/clusters/run returns a job_id (job is submitted to queue)."""
        embs, meta = _make_three_groups(n_per_group=10)
        resp = client.post("/api/clusters/run", json={
            "embeddings": embs.tolist(),
            "metadata": meta,
            "min_cluster_size": 5,
            "min_samples": 3,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "job_id" in data
        assert isinstance(data["job_id"], str)
        assert len(data["job_id"]) > 0

        # Verify the job was registered in the queue
        job_queue = bridge_app.state.job_queue
        job_status = job_queue.get_job_status(data["job_id"])
        assert job_status is not None
        assert isinstance(job_status, dict)
        assert job_status["job_type"] == "clustering"

    def test_list_clusters_after_run(self, client: TestClient, bridge_app: FastAPI):
        """GET /api/clusters/ after a clustering run returns clusters."""
        # Run clustering directly via the handler
        from sigrift.bridge.routers.clusters import _run_clustering_job

        embs, meta = _make_three_groups(n_per_group=20)
        # Override _save_clusters to write to our temp file
        with patch("sigrift.bridge.routers.clusters._CLUSTERS_FILE", self._clusters_file):
            _run_clustering_job("test-job", {
                "embeddings": embs.tolist(),
                "metadata": meta,
                "min_cluster_size": 5,
                "min_samples": 3,
            })

        resp = client.get("/api/clusters/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["n_clusters"] == 3
        assert len(data["clusters"]) == 3

    def test_cluster_detail(self, client: TestClient):
        """GET /api/clusters/{id} returns the full cluster with members."""
        from sigrift.bridge.routers.clusters import _run_clustering_job

        embs, meta = _make_three_groups(n_per_group=20)
        with patch("sigrift.bridge.routers.clusters._CLUSTERS_FILE", self._clusters_file):
            _run_clustering_job("test-job", {
                "embeddings": embs.tolist(),
                "metadata": meta,
                "min_cluster_size": 5,
                "min_samples": 3,
            })

        resp = client.get("/api/clusters/0")
        assert resp.status_code == 200
        data = resp.json()
        assert data["cluster_id"] == 0
        assert isinstance(data["size"], int)
        assert data["size"] > 0
        assert isinstance(data["members"], list)
        assert len(data["members"]) == data["size"]
        assert isinstance(data["centroid"], list)
        assert len(data["centroid"]) == 32

    def test_predict_endpoint(self, client: TestClient):
        """POST /api/clusters/predict returns a cluster assignment."""
        from sigrift.bridge.routers.clusters import _run_clustering_job

        embs, meta = _make_three_groups(n_per_group=20)
        with patch("sigrift.bridge.routers.clusters._CLUSTERS_FILE", self._clusters_file):
            _run_clustering_job("test-job", {
                "embeddings": embs.tolist(),
                "metadata": meta,
                "min_cluster_size": 5,
                "min_samples": 3,
            })

        # Use a point from the first group
        test_emb = embs[0].tolist()
        resp = client.post("/api/clusters/predict", json={"embedding": test_emb})
        assert resp.status_code == 200
        data = resp.json()
        assert "cluster_id" in data
        assert isinstance(data["cluster_id"], int)
        assert "similarity" in data
        assert isinstance(data["similarity"], float)
        assert data["cluster_id"] >= 0

    def test_label_cluster(self, client: TestClient):
        """PUT /api/clusters/{id}/label updates the cluster label."""
        from sigrift.bridge.routers.clusters import _run_clustering_job

        embs, meta = _make_three_groups(n_per_group=20)
        with patch("sigrift.bridge.routers.clusters._CLUSTERS_FILE", self._clusters_file):
            _run_clustering_job("test-job", {
                "embeddings": embs.tolist(),
                "metadata": meta,
                "min_cluster_size": 5,
                "min_samples": 3,
            })

        resp = client.put("/api/clusters/0/label", json={"label": "drone_control"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["label"] == "drone_control"

        # Verify label persisted
        resp2 = client.get("/api/clusters/0")
        assert resp2.status_code == 200
        assert resp2.json()["label"] == "drone_control"

    def test_stats_endpoint(self, client: TestClient):
        """GET /api/clusters/stats returns correct counts after clustering."""
        from sigrift.bridge.routers.clusters import _run_clustering_job

        embs, meta = _make_three_groups(n_per_group=20)
        with patch("sigrift.bridge.routers.clusters._CLUSTERS_FILE", self._clusters_file):
            _run_clustering_job("test-job", {
                "embeddings": embs.tolist(),
                "metadata": meta,
                "min_cluster_size": 5,
                "min_samples": 3,
            })

        resp = client.get("/api/clusters/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["n_clusters"] == 3
        assert isinstance(data["largest_cluster"], int)
        assert data["largest_cluster"] > 0
        assert data["last_run"] is not None
        assert isinstance(data["last_run"], str)

    def test_run_requires_analyst(self, bridge_app: FastAPI, persistence):
        """VIEWER role should get 403 on POST /api/clusters/run."""
        from sigrift.lib.security.credentials import generate_api_key, hash_credential

        viewer_key = generate_api_key(length=32)
        h, s = hash_credential(viewer_key)
        persistence.set_key("viewer_key", h, s)
        persistence.set_key_meta("viewer_key", {"role": "viewer"})

        viewer_client = TestClient(
            bridge_app,
            headers={"X-API-Key": viewer_key},
        )

        resp = viewer_client.post("/api/clusters/run", json={})
        assert resp.status_code == 403

    def test_label_requires_analyst(self, bridge_app: FastAPI, persistence):
        """VIEWER role should get 403 on PUT /api/clusters/{id}/label."""
        from sigrift.lib.security.credentials import generate_api_key, hash_credential

        viewer_key = generate_api_key(length=32)
        h, s = hash_credential(viewer_key)
        persistence.set_key("viewer_key2", h, s)
        persistence.set_key_meta("viewer_key2", {"role": "viewer"})

        viewer_client = TestClient(
            bridge_app,
            headers={"X-API-Key": viewer_key},
        )

        resp = viewer_client.put("/api/clusters/0/label", json={"label": "test"})
        assert resp.status_code == 403
