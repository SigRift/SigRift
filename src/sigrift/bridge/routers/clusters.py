"""Cluster management endpoints for signal fingerprint embeddings.

Provides endpoints to trigger HDBSCAN clustering, browse cluster
summaries, predict cluster assignments, and label clusters.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from sigrift.bridge.dependencies import Role, require_role

try:  # POSIX advisory locks (several bridge workers share the data dir)
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - non-POSIX
    _fcntl = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

router = APIRouter()

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_CLUSTERS_FILE = _DATA_DIR / "clusters.json"

#: Serialises writers of clusters.json in this process.  Clustering jobs
#: run in job-queue worker threads (two at a time by default), and a label
#: update is a load-modify-save, so without it a save could interleave
#: with another or undo a label written meanwhile.
_CLUSTERS_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------


def _atomic_write(path: Path, data: dict[str, Any]) -> None:
    """Write *data* as JSON to *path* atomically and durably.

    The JSON goes to a uniquely named temp file in the same directory (a
    fixed ``clusters.tmp`` was shared by concurrent writers: both truncated
    and wrote the same inode, and the second rename found no file), which
    is fsync-ed and renamed over *path*; the directory is then fsync-ed.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.stem}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


@contextlib.contextmanager
def _clusters_write_lock() -> Iterator[None]:
    """Hold the writer lock for clusters.json (this process and, via
    ``flock`` on ``.clusters.lock``, the other bridge workers)."""
    with _CLUSTERS_LOCK:
        if _fcntl is None:
            yield
            return
        lock_path = _CLUSTERS_FILE.with_name(".clusters.lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            _fcntl.flock(fd, _fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)  # releases the flock


def _load_clusters() -> dict[str, Any]:
    """Load cluster state from disk, returning empty state if absent."""
    if not _CLUSTERS_FILE.exists():
        return {}
    try:
        with open(_CLUSTERS_FILE, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to load clusters.json: %s", exc)
    return {}


def _save_clusters(data: dict[str, Any]) -> None:
    """Persist cluster state to disk atomically (serialised with other writers)."""
    with _clusters_write_lock():
        _atomic_write(_CLUSTERS_FILE, data)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class PredictRequest(BaseModel):
    """Body for POST /predict."""

    model_config = {"extra": "forbid"}

    embedding: list[float] = Field(..., min_length=1, description="Embedding vector")


class LabelRequest(BaseModel):
    """Body for PUT /{cluster_id}/label."""

    model_config = {"extra": "forbid"}

    label: str = Field(..., min_length=1, max_length=200, description="Human label")


# ---------------------------------------------------------------------------
# Clustering job handler
# ---------------------------------------------------------------------------


def _run_clustering_job(job_id: str, params: dict) -> dict[str, Any]:
    """Synchronous handler executed by the job queue worker.

    Loads fingerprint embeddings from cluster state (or params),
    runs HDBSCAN, and persists the results.
    """
    import numpy as np
    from sigrift.lib.dsp.signal_clustering import SignalClusterer

    embeddings_list = params.get("embeddings", [])
    metadata = params.get("metadata", [])
    min_cluster_size = params.get("min_cluster_size", 5)
    min_samples = params.get("min_samples", 3)

    if not embeddings_list:
        # Nothing to cluster
        result: dict[str, Any] = {
            "last_run": datetime.now(timezone.utc).isoformat(),
            "n_clusters": 0,
            "clusters": [],
            "unclustered": [],
        }
        _save_clusters(result)
        return {"n_clusters": 0, "n_unclustered": 0}

    embeddings = np.array(embeddings_list, dtype=np.float64)

    clusterer = SignalClusterer(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
    )
    clusterer.fit(embeddings)

    summaries = clusterer.get_cluster_summary(embeddings, metadata)

    # Build unclustered list
    unclustered: list[str] = []
    if clusterer.labels_ is not None:
        for i, lbl in enumerate(clusterer.labels_):
            if lbl == -1:
                meta = metadata[i] if i < len(metadata) else {}
                unclustered.append(meta.get("fingerprint_id", f"fp_{i}"))

    clusters_data: list[dict[str, Any]] = []
    for s in summaries:
        clusters_data.append(
            {
                "cluster_id": s["cluster_id"],
                "centroid": s["centroid"],
                "size": s["size"],
                "label": None,
                "dominant_class": s["dominant_class"],
                "class_distribution": s["class_distribution"],
                "mean_confidence": s["mean_confidence"],
                "freq_range": s["freq_range"],
                "members": s["members"],
            }
        )

    result = {
        "last_run": datetime.now(timezone.utc).isoformat(),
        "n_clusters": len(clusters_data),
        "clusters": clusters_data,
        "unclustered": unclustered,
    }
    _save_clusters(result)

    return {
        "n_clusters": len(clusters_data),
        "n_unclustered": len(unclustered),
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/run")
async def run_clustering(
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Trigger a clustering job.

    Fetches fingerprint embeddings from storage and submits an
    HDBSCAN clustering job to the analysis queue.  Returns the
    job_id for status polling.
    """
    job_queue = getattr(request.app.state, "job_queue", None)
    if job_queue is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Job queue not initialised",
        )

    # Register handler if not already registered
    if "clustering" not in job_queue._handlers:
        job_queue.register_handler("clustering", _run_clustering_job)

    # Collect embeddings from request body (optional) or from stored data
    # For now, callers pass embeddings in the request body if available.
    # If the body is empty, use whatever is in the current cluster state.
    body: dict[str, Any] = {}
    try:
        body = await request.json()
    except (ValueError, UnicodeDecodeError):
        pass

    embeddings = body.get("embeddings", [])
    metadata = body.get("metadata", [])
    min_cluster_size = body.get("min_cluster_size", 5)
    min_samples = body.get("min_samples", 3)

    job_id = await job_queue.submit(
        "clustering",
        {
            "embeddings": embeddings,
            "metadata": metadata,
            "min_cluster_size": min_cluster_size,
            "min_samples": min_samples,
        },
    )

    return {"ok": True, "job_id": job_id}


@router.get("/")
def list_clusters(
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """List all clusters with summaries."""
    data = _load_clusters()
    if not data:
        return {"clusters": [], "n_clusters": 0}

    # Strip centroids and members for the list view (lighter payload)
    clusters_summary: list[dict[str, Any]] = []
    for c in data.get("clusters", []):
        clusters_summary.append(
            {
                "cluster_id": c.get("cluster_id"),
                "size": c.get("size"),
                "label": c.get("label"),
                "dominant_class": c.get("dominant_class"),
                "freq_range": c.get("freq_range"),
                "mean_confidence": c.get("mean_confidence"),
                "class_distribution": c.get("class_distribution"),
            }
        )

    return {
        "clusters": clusters_summary,
        "n_clusters": data.get("n_clusters", 0),
        "last_run": data.get("last_run"),
    }


@router.get("/stats")
def cluster_stats(
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return clustering statistics."""
    data = _load_clusters()
    if not data:
        return {
            "n_clusters": 0,
            "n_unclustered": 0,
            "largest_cluster": 0,
            "last_run": None,
        }

    clusters = data.get("clusters", [])
    largest = max((c.get("size", 0) for c in clusters), default=0)

    return {
        "n_clusters": data.get("n_clusters", 0),
        "n_unclustered": len(data.get("unclustered", [])),
        "largest_cluster": largest,
        "last_run": data.get("last_run"),
    }


@router.get("/{cluster_id}")
def get_cluster_detail(
    cluster_id: int,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Get detailed info for a single cluster including members."""
    data = _load_clusters()
    for c in data.get("clusters", []):
        if c.get("cluster_id") == cluster_id:
            return c

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Cluster {cluster_id} not found",
    )


@router.get("/{cluster_id}/centroid")
def get_cluster_centroid(
    cluster_id: int,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return the centroid embedding for a cluster."""
    data = _load_clusters()
    for c in data.get("clusters", []):
        if c.get("cluster_id") == cluster_id:
            return {
                "cluster_id": cluster_id,
                "centroid": c.get("centroid", []),
            }

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Cluster {cluster_id} not found",
    )


@router.post("/predict")
def predict_cluster(
    body: PredictRequest,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Assign a single embedding to the nearest existing cluster."""
    import numpy as np
    from sigrift.lib.dsp.signal_clustering import SignalClusterer

    data = _load_clusters()
    clusters = data.get("clusters", [])
    if not clusters:
        return {"cluster_id": -1, "similarity": 0.0, "cluster_info": None}

    # Rebuild centroids from stored data
    centroids = []
    for c in clusters:
        centroid = c.get("centroid", [])
        if centroid:
            centroids.append(centroid)
        else:
            # Use zero vector as placeholder
            centroids.append([0.0] * len(body.embedding))

    centroids_arr = np.array(centroids, dtype=np.float64)
    emb = np.array(body.embedding, dtype=np.float64)

    # Create a clusterer with pre-set centroids
    clusterer = SignalClusterer()
    clusterer._centroids = centroids_arr
    clusterer.n_clusters_ = len(centroids)

    cid, sim = clusterer.predict_cluster(emb)

    cluster_info = None
    if cid >= 0:
        for c in clusters:
            if c.get("cluster_id") == cid:
                cluster_info = {
                    "cluster_id": c.get("cluster_id"),
                    "size": c.get("size"),
                    "label": c.get("label"),
                    "dominant_class": c.get("dominant_class"),
                }
                break

    return {
        "cluster_id": cid,
        "similarity": round(sim, 4),
        "cluster_info": cluster_info,
    }


@router.put("/{cluster_id}/label")
def label_cluster(
    cluster_id: int,
    body: LabelRequest,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Label a cluster.  Updates the stored label for this cluster."""
    # Load-modify-save under the writer lock: a clustering run saving at
    # the same moment cannot interleave with it.
    with _clusters_write_lock():
        data = _load_clusters()
        found = False
        for c in data.get("clusters", []):
            if c.get("cluster_id") == cluster_id:
                c["label"] = body.label
                found = True
                break
        if found:
            _atomic_write(_CLUSTERS_FILE, data)

    if not found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Cluster {cluster_id} not found",
        )

    return {
        "ok": True,
        "cluster_id": cluster_id,
        "label": body.label,
    }
