"""Cross-node correlation API endpoints for The Bridge.

Provides endpoints to query multi-node signal correlations,
correlation matrix, timeline, clusters, and summary statistics.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query, Request

from sigrift.bridge.anomaly.correlator import NodeCorrelator, _freq_bin
from sigrift.bridge.dependencies import Role, require_role
from sigrift.bridge.utils import get_detection_store

logger = logging.getLogger(__name__)

router = APIRouter()


def _parse_ts(ts: Any) -> datetime | None:
    """Parse a timestamp from various formats."""
    if ts is None:
        return None
    if isinstance(ts, datetime):
        return ts
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts)
        except (ValueError, TypeError):
            return None
    return None


# ---------------------------------------------------------------------------
# GET /correlations — recent cross-node correlations
# ---------------------------------------------------------------------------


@router.get("/correlations")
async def get_correlations(
    request: Request,
    hours: int = Query(4, ge=1, le=168),
    min_nodes: int = Query(2, ge=2, le=50),
    signal_class: str | None = Query(None),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return recent cross-node correlation groups.

    Parameters
    ----------
    hours : int
        Lookback window in hours (default 4, max 168 = 7 days).
    min_nodes : int
        Minimum distinct nodes for a correlation group (default 2).
    signal_class : str or None
        Optional filter for a specific signal class.
    """
    store = get_detection_store(request)
    correlator: NodeCorrelator = getattr(
        request.app.state,
        "correlator",
        NodeCorrelator(),
    )

    minutes = hours * 60
    detections = await asyncio.to_thread(
        store.get_recent,
        minutes=minutes,
        limit=10000,
    )

    # Optional signal_class filter
    if signal_class:
        detections = [d for d in detections if d.get("signal_class") == signal_class]

    groups = correlator.find_correlation_groups(detections, min_nodes=min_nodes)

    return {
        "hours": hours,
        "min_nodes": min_nodes,
        "signal_class": signal_class,
        "count": len(groups),
        "correlations": [g.model_dump() for g in groups],
    }


# ---------------------------------------------------------------------------
# GET /correlations/summary — correlation statistics
# ---------------------------------------------------------------------------


@router.get("/correlations/summary")
async def get_correlation_summary(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return summary statistics for cross-node correlations over 24 hours."""
    store = get_detection_store(request)
    correlator: NodeCorrelator = getattr(
        request.app.state,
        "correlator",
        NodeCorrelator(),
    )

    # Query last 24 hours
    detections = await asyncio.to_thread(
        store.get_recent,
        minutes=1440,
        limit=50000,
    )

    summary = correlator.correlation_summary(detections, min_nodes=2)
    return summary


# ---------------------------------------------------------------------------
# GET /correlations/recent — per-detection correlation results
# ---------------------------------------------------------------------------


@router.get("/correlations/recent")
async def get_recent_correlations(
    request: Request,
    minutes: int = Query(15, ge=1, le=1440),
    limit: int = Query(200, ge=1, le=5000),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return recent detections annotated with per-detection correlation info.

    For each detection in the lookback window, runs a correlation check
    against other detections and returns the correlation result alongside
    the detection data.  This gives operators visibility into which
    detections were confirmed by multiple nodes and how their anomaly
    scores were adjusted.

    Parameters
    ----------
    minutes : int
        Lookback window in minutes (default 15, max 1440 = 24h).
    limit : int
        Maximum detections to return (default 200, max 5000).
    """
    store = get_detection_store(request)
    correlator: NodeCorrelator = getattr(
        request.app.state,
        "correlator",
        NodeCorrelator(),
    )

    detections = await asyncio.to_thread(
        store.get_recent,
        minutes=minutes,
        limit=limit,
    )

    # Annotate each detection with correlation info
    annotated: list[dict[str, Any]] = []
    for det in detections:
        result = correlator.check_correlation(det, detections)
        entry: dict[str, Any] = {
            "detection_id": det.get("detection_id", ""),
            "node_id": det.get("node_id", ""),
            "signal_class": det.get("signal_class", ""),
            "family": det.get("family", ""),
            "freq_hz": det.get("freq_hz", 0.0),
            "timestamp": det.get("timestamp", ""),
            "confidence": det.get("confidence", 0.0),
            "anomaly_score": det.get("anomaly_score", 0.0),
            "snr_db": det.get("snr_db"),
            "correlation": result.model_dump(),
        }
        annotated.append(entry)

    correlated_count = sum(1 for a in annotated if a["correlation"]["correlated"])

    return {
        "minutes": minutes,
        "total": len(annotated),
        "correlated_count": correlated_count,
        "detections": annotated,
    }


# ---------------------------------------------------------------------------
# GET /correlations/matrix — node-to-node correlation matrix
# ---------------------------------------------------------------------------


@router.get("/correlations/matrix")
async def get_correlation_matrix(
    request: Request,
    hours: int = Query(4, ge=1, le=168),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return a node-to-node correlation matrix.

    For each pair of nodes, computes a Jaccard similarity coefficient
    over the set of (signal_class, freq_bin) tuples each node has
    observed in the lookback window.  Values range from 0.0 (no overlap)
    to 1.0 (identical detection profiles).

    Parameters
    ----------
    hours : int
        Lookback window in hours (default 4, max 168).
    """
    store = get_detection_store(request)
    correlator: NodeCorrelator = getattr(
        request.app.state,
        "correlator",
        NodeCorrelator(),
    )

    minutes = hours * 60
    detections = await asyncio.to_thread(
        store.get_recent,
        minutes=minutes,
        limit=10000,
    )

    # Build per-node signal fingerprints: set of (signal_class, freq_bin)
    node_sigs: dict[str, set[tuple[str, int]]] = defaultdict(set)
    for d in detections:
        nid = d.get("node_id", "")
        sig = d.get("signal_class", "")
        freq = d.get("freq_hz", 0.0)
        fbin = _freq_bin(freq, correlator.freq_tolerance_hz)
        node_sigs[nid].add((sig, fbin))

    node_ids = sorted(node_sigs.keys())

    # Compute pairwise Jaccard similarity
    matrix: dict[str, float] = {}
    for i, n1 in enumerate(node_ids):
        for j, n2 in enumerate(node_ids):
            if i >= j:
                continue
            s1 = node_sigs[n1]
            s2 = node_sigs[n2]
            union = len(s1 | s2)
            if union == 0:
                sim = 0.0
            else:
                sim = len(s1 & s2) / union
            key = n1 + "|" + n2
            matrix[key] = round(sim, 4)

    # Per-node detection counts for display
    node_counts = {nid: len(sigs) for nid, sigs in node_sigs.items()}

    return {
        "hours": hours,
        "node_ids": node_ids,
        "matrix": matrix,
        "node_signal_counts": node_counts,
    }


# ---------------------------------------------------------------------------
# GET /correlations/timeline — time-synced detection timeline
# ---------------------------------------------------------------------------


@router.get("/correlations/timeline")
async def get_correlation_timeline(
    request: Request,
    hours: int = Query(4, ge=1, le=168),
    buckets: int = Query(60, ge=10, le=360),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return a time-synced detection timeline across all nodes.

    Divides the lookback window into *buckets* time slots and counts
    detections per node per slot, enabling aligned timeline visualization.

    Parameters
    ----------
    hours : int
        Lookback window in hours (default 4).
    buckets : int
        Number of time buckets (default 60).
    """
    store = get_detection_store(request)
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)

    minutes = hours * 60
    detections = await asyncio.to_thread(
        store.get_recent,
        minutes=minutes,
        limit=10000,
    )

    bucket_sec = (hours * 3600) / buckets

    # Build per-node bucket counts
    node_buckets: dict[str, list[int]] = defaultdict(lambda: [0] * buckets)
    # Also track per-node frequency set per bucket for overlap detection
    node_freq_buckets: dict[str, list[set]] = defaultdict(
        lambda: [set() for _ in range(buckets)],
    )

    for d in detections:
        nid = d.get("node_id", "")
        ts = _parse_ts(d.get("timestamp"))
        if ts is None:
            continue
        elapsed = (ts - start).total_seconds()
        if elapsed < 0:
            continue
        idx = min(int(elapsed / bucket_sec), buckets - 1)
        node_buckets[nid][idx] += 1

        sig = d.get("signal_class", "")
        freq = d.get("freq_hz", 0.0)
        node_freq_buckets[nid][idx].add((sig, int(freq / 100_000)))

    node_ids = sorted(node_buckets.keys())

    # Compute overlap buckets: count of time slots where 2+ nodes see same signal
    overlap = [0] * buckets
    for bi in range(buckets):
        # Collect all (sig, fbin) sets across nodes for this bucket
        all_sigs: set[tuple[str, int]] = set()
        any_overlap = False
        for nid in node_ids:
            sigs = node_freq_buckets[nid][bi]
            if sigs & all_sigs:
                any_overlap = True
            all_sigs |= sigs
        if any_overlap:
            # Count how many nodes contributed to the overlap
            overlapping = 0
            for nid in node_ids:
                for nid2 in node_ids:
                    if nid >= nid2:
                        continue
                    if node_freq_buckets[nid][bi] & node_freq_buckets[nid2][bi]:
                        overlapping += 1
                        break
            overlap[bi] = max(1, overlapping)

    # Time labels
    time_labels = []
    for i in range(buckets):
        t = start + timedelta(seconds=i * bucket_sec)
        time_labels.append(t.strftime("%H:%M"))

    return {
        "hours": hours,
        "buckets": buckets,
        "node_ids": node_ids,
        "series": {nid: node_buckets[nid] for nid in node_ids},
        "overlap": overlap,
        "time_labels": time_labels,
    }


# ---------------------------------------------------------------------------
# GET /correlations/clusters — grouped correlated detections
# ---------------------------------------------------------------------------


@router.get("/correlations/clusters")
async def get_correlation_clusters(
    request: Request,
    hours: int = Query(4, ge=1, le=168),
    min_nodes: int = Query(2, ge=2, le=50),
    limit: int = Query(20, ge=1, le=100),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return correlated detection clusters with enriched metadata.

    Each cluster groups detections of the same signal class at similar
    frequencies seen by multiple nodes.  Includes node agreement score,
    frequency spread, and time span.

    Parameters
    ----------
    hours : int
        Lookback window (default 4).
    min_nodes : int
        Minimum nodes for a cluster (default 2).
    limit : int
        Maximum clusters to return (default 20).
    """
    store = get_detection_store(request)
    correlator: NodeCorrelator = getattr(
        request.app.state,
        "correlator",
        NodeCorrelator(),
    )

    minutes = hours * 60
    detections = await asyncio.to_thread(
        store.get_recent,
        minutes=minutes,
        limit=10000,
    )

    groups = correlator.find_correlation_groups(detections, min_nodes=min_nodes)

    # Enrich each group with additional metadata
    # Determine total unique nodes in dataset
    all_nodes = {d.get("node_id", "") for d in detections} - {""}
    total_nodes = len(all_nodes) if all_nodes else 1

    clusters = []
    for g in groups[:limit]:
        node_ids = list({n.get("node_id", "") for n in g.nodes} - {""})
        confidences = [n.get("confidence", 0.0) for n in g.nodes]
        avg_conf = sum(confidences) / len(confidences) if confidences else 0.0

        # Frequency spread across nodes
        freqs = [n.get("freq_hz", g.freq_hz) for n in g.nodes if n.get("freq_hz")]
        if not freqs:
            freqs = [g.freq_hz]
        freq_min = min(freqs) if freqs else g.freq_hz
        freq_max = max(freqs) if freqs else g.freq_hz

        # Agreement score: fraction of all active nodes that see this signal
        agreement = len(node_ids) / total_nodes if total_nodes > 0 else 0.0

        # Time range of the cluster
        timestamps = []
        for n in g.nodes:
            ts = _parse_ts(n.get("timestamp"))
            if ts:
                timestamps.append(ts)
        first_seen = min(timestamps).isoformat() if timestamps else ""
        last_seen = max(timestamps).isoformat() if timestamps else ""

        clusters.append(
            {
                "signal_class": g.signal_class,
                "freq_hz": g.freq_hz,
                "node_count": len(node_ids),
                "node_ids": sorted(node_ids),
                "agreement": round(agreement, 4),
                "avg_confidence": round(avg_conf, 4),
                "detection_count": len(g.nodes),
                "duration_sec": g.duration_sec,
                "freq_min_hz": freq_min,
                "freq_max_hz": freq_max,
                "first_seen": first_seen,
                "last_seen": last_seen,
            }
        )

    return {
        "hours": hours,
        "min_nodes": min_nodes,
        "total_active_nodes": len(all_nodes),
        "cluster_count": len(clusters),
        "clusters": clusters,
    }
