"""Server-owned RF identities used by the operator's known-signal workflow."""

from __future__ import annotations

import math
from typing import Any

from fastapi import HTTPException

from sigrift.bridge.storage.known_signals import KnownSignalPattern
from sigrift.bridge.utils import get_detection_store


def authorized_store(request, key_id: str):
    """Keep this workflow within the configured store's fixed tenant.

    This is not per-request tenant routing. Legacy credentials without an
    explicit tenant inherit the instance; trusted explicit identities must
    match it. Never read tenant scope from client headers or request bodies.
    """
    store = get_detection_store(request)
    tenants = [getattr(request.state, "key_tenant", None)]
    token = getattr(request.state, "session_token", None)
    if token:
        session = store.get_session(token)
        if session is None:
            raise HTTPException(403, "Known RF patterns require a current session")
        tenants.append(session.get("tenant_id"))
    else:
        persistence = request.app.state.persistence
        meta = persistence.get_key_meta().get(key_id, {})
        tenants.append(meta.get("tenant_id"))
    if any(tenant is not None and tenant != store.tenant_id for tenant in tenants):
        raise HTTPException(403, "Known RF patterns belong to another tenant")
    return store


def detection_target(store, detection_id: str) -> dict[str, Any]:
    detection = store.get_detection_by_id(detection_id)
    if not detection:
        raise HTTPException(404, "RF detection not found")
    frequency = detection.get("freq_hz")
    if (
        not isinstance(frequency, (float, int))
        or not math.isfinite(frequency)
        or frequency <= 0
    ):
        raise HTTPException(422, "This detection has no usable RF frequency")
    try:
        defaults = KnownSignalPattern(
            freq_min_hz=max(0, frequency - 50_000),
            freq_max_hz=frequency + 50_000,
            signal_class=detection.get("signal_class"),
            node_id=detection.get("node_id"),
        )
    except ValueError as exc:
        raise HTTPException(
            422, "This detection has no usable RF class or node"
        ) from exc
    # Never silently broaden an absent detection node to every node.
    if defaults.node_id is None:
        raise HTTPException(422, "This detection has no usable RF node")
    return {
        "detection_id": detection_id,
        "freq_hz": frequency,
        "defaults": defaults.model_dump(),
    }


def rf_alert_detection_ref(alert: dict[str, Any]) -> str | None:
    """The detection id an RF post-ingest alert names, without checking it exists.

    Only records emitted by the three RF post-ingest alert producers qualify.
    No message parsing or frequency guessing: System/node/Wi-Fi/Bluetooth
    alerts lack this producer identity and remain ineligible even if their
    text mentions RF.
    """
    name = alert.get("name", "")
    eligible = name == "anomaly_detected" or (
        isinstance(name, str)
        and (
            (name.startswith("rule_") and bool(alert.get("rule_id")))
            or (name.startswith("watch_band_") and bool(alert.get("watch_id")))
        )
    )
    detection_id = alert.get("detection_id")
    if not eligible or not isinstance(detection_id, str) or not detection_id:
        return None
    return detection_id


def alert_detection_id(alert: dict[str, Any], store) -> str | None:
    """The linked RF detection id, only while it still exists and is tenant-visible."""
    detection_id = rf_alert_detection_ref(alert)
    if detection_id is None or store is None:
        return None
    try:
        detection_target(store, detection_id)
    except HTTPException:
        return None
    return detection_id
