"""Adapters between detection dicts and provider data types.

Converts internal detection dicts (used by correlator, storage, routers)
to/from the provider-neutral ``SignalObservation`` and ``GeoEstimate``
types so that geolocation providers can operate without knowledge of
SigRift internals.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sigrift.providers.base import GeoEstimate, SignalObservation


def detections_to_observations(
    detections: list[dict[str, Any]],
    node_positions: dict[str, dict[str, float]],
) -> list[SignalObservation]:
    """Convert detection dicts + node positions to SignalObservations.

    Skips detections whose ``node_id`` is not in *node_positions*.
    Timestamps are parsed from ISO strings, epoch floats, or datetime
    objects and converted to nanosecond integers.
    """
    observations: list[SignalObservation] = []
    for det in detections:
        node_id = det.get("node_id", "")
        if node_id not in node_positions:
            continue

        ts = _parse_timestamp_ns(det.get("timestamp"))
        if ts is None:
            continue

        observations.append(
            SignalObservation(
                frequency_hz=float(det.get("freq_hz", 0.0)),
                timestamp_ns=ts,
                power_dbm=float(det.get("power_dbm", 0.0)),
                node_id=node_id,
                signal_class=det.get("signal_class", ""),
                confidence=float(det.get("confidence", 0.0)),
                metadata={"node_position": node_positions[node_id]},
            )
        )
    return observations


def geo_estimate_to_tdoa_dict(estimate: GeoEstimate) -> dict[str, Any]:
    """Convert a GeoEstimate back to the dict format expected by TDOAStore.

    Reconstructs the full TDOA result dict from ``GeoEstimate.metadata``
    so that the storage layer (``tdoa_store.store_tdoa_estimate``) can
    persist it without changes.
    """
    meta = estimate.metadata or {}

    location = meta.get("location", {})
    if not location:
        if estimate.latitude is not None and estimate.longitude is not None:
            location = {"lat": estimate.latitude, "lon": estimate.longitude}

    return {
        "estimate_id": meta.get("estimate_id", str(uuid.uuid4())),
        "timestamp": meta.get(
            "timestamp",
            datetime.now(timezone.utc).isoformat(),
        ),
        "signal_class": meta.get("signal_class", ""),
        "freq_hz": meta.get("freq_hz", 0.0),
        "location": location,
        "cep_m": meta.get("cep_m", estimate.error_radius_m),
        "gdop": meta.get("gdop"),
        "confidence": estimate.confidence,
        "node_count": meta.get("node_count", 0),
        "contributing_nodes": meta.get("contributing_nodes", []),
        "time_spread_ms": meta.get("time_spread_ms", 0.0),
        "tdoa_pairs": meta.get("tdoa_pairs", []),
        "coordinate_mode": meta.get("coordinate_mode", "2d"),
    }


def _parse_timestamp_ns(ts: Any) -> int | None:
    """Parse a timestamp to nanosecond epoch integer."""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return int(ts * 1_000_000_000)
    if isinstance(ts, datetime):
        return int(ts.timestamp() * 1_000_000_000)
    if isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return int(dt.timestamp() * 1_000_000_000)
        except (ValueError, TypeError):
            return None
    return None
