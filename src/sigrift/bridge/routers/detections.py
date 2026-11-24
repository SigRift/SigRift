"""Detection ingestion, query, and real-time WebSocket endpoints for The Bridge.

Provides batch ingestion from edge nodes, filtered queries, recent detections,
total count, and real-time WebSocket streams for live detection and anomaly
events.

Analytics (timeline, heatmap, distribution, node compare, aggregation) have
been split into detection_analytics.py.  IQ capture endpoints are in
detection_iq.py.  Audit, feedback, and anomaly management endpoints are in
detection_audit.py.
"""

from __future__ import annotations

import asyncio
import html
import logging
import time
from collections import OrderedDict
from typing import Any, Callable

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)

from sigrift.bridge.dependencies import (
    Role,
    enforce_node_binding,
    get_ws_limiter,
    require_role,
    require_ws_auth,
)
from sigrift.bridge.models import (
    DetectionBatch,
    DetectionQuery,
    DetectionSummaryBatch,
)
from sigrift.bridge.alert_engine import decode_html_escaped_text
from sigrift.bridge.alert_engine import evaluate_detection as _evaluate_detection_rules
from sigrift.bridge.instrumentation import get_tracer, trace_span
from sigrift.bridge.anomaly.correlator import NodeCorrelator
from sigrift.bridge.anomaly.fhss import FHSSDetector
from sigrift.bridge.anomaly.scorer import AnomalyDimension
from sigrift.bridge.class_map import normalize_class, normalize_family
from sigrift.bridge.classification_refiner import refine_classification
from sigrift.bridge.rf_utils import estimate_bandwidth
from sigrift.bridge.state import AppState
from sigrift.bridge.utils import get_detection_store, utcnow

# Re-export request models for backward compatibility
from sigrift.bridge.routers.detection_audit import (  # noqa: F401
    BulkActionRequest,
    BulkRfDismissRequest,
    BulkRfSnoozeRequest,
    FeedbackRequest,
)

logger = logging.getLogger(__name__)
_tracer = get_tracer(__name__)

router = APIRouter()

# Aliases for backward compatibility within this module
_utcnow = utcnow
_get_detection_store = get_detection_store

# Per-node batch counter for throttling expensive analysis
_node_batch_count: OrderedDict[str, int] = OrderedDict()
_NODE_BATCH_MAX_ENTRIES = 10_000
_ANALYSIS_EVERY_N = 5  # run FHSS + correlation every Nth batch per node
# Whether the last recent-detections fetch for that analysis failed, so a
# lasting failure is logged once rather than on every Nth batch.
_recent_fetch_state = {"failing": False}


# ---------------------------------------------------------------------------
# Alert auto-creation defaults (overridden by detection_config at runtime)
# ---------------------------------------------------------------------------

_ANOMALY_ALERT_THRESHOLD = 0.7
_ANOMALY_CRITICAL_THRESHOLD = 0.85
_ANOMALY_ALERT_COOLDOWN_SECONDS = 300  # 5 minutes for warning severity
_ANOMALY_ALERT_COOLDOWN_CRITICAL_SECONDS = (
    60  # 60 seconds for critical severity (score >= 0.85)
)
_RF_MIN_CONFIDENCE_FLOOR = 0.0


def _freq_bucket(freq_hz: float) -> int:
    """Bucket a frequency to 100 kHz resolution for cooldown keys."""
    return int(freq_hz / 100_000)


def _extract_hour(timestamp: Any) -> int:
    """Extract hour of day from various timestamp formats."""
    from datetime import datetime as _dt, timezone as _tz

    if isinstance(timestamp, _dt):
        return timestamp.hour
    if isinstance(timestamp, str):
        try:
            return _dt.fromisoformat(timestamp).hour
        except (ValueError, TypeError):
            pass
    return _dt.now(_tz.utc).hour


def _to_epoch(timestamp: Any) -> float:
    """Convert ISO timestamp string or datetime to Unix epoch float."""
    from datetime import datetime as _dt, timezone as _tz

    if isinstance(timestamp, (int, float)):
        return float(timestamp)
    if isinstance(timestamp, _dt):
        return timestamp.timestamp()
    if isinstance(timestamp, str):
        try:
            return _dt.fromisoformat(timestamp).timestamp()
        except (ValueError, TypeError):
            pass
    return _dt.now(_tz.utc).timestamp()


#: Edge-decoded messages kept per detection and per batch; the rest are
#: dropped (and counted in a warning).  Each one becomes a database row.
_EDGE_DECODED_MAX_PER_DETECTION = 50
_EDGE_DECODED_MAX_PER_BATCH = 1000


def _extract_edge_decoded(payload: Any) -> dict[str, list[dict]]:
    """Collect the ``decoded_messages`` edges attach to detections, bounded.

    Returns ``{detection_id: [message dict, ...]}`` holding at most
    ``_EDGE_DECODED_MAX_PER_DETECTION`` messages per detection and
    ``_EDGE_DECODED_MAX_PER_BATCH`` in all; entries that are not objects
    and the excess are dropped and logged.
    """
    found: dict[str, list[dict]] = {}
    raw_dets = payload.get("detections") if isinstance(payload, dict) else None
    if not isinstance(raw_dets, list):
        return found
    kept = dropped = 0
    for raw_det in raw_dets:
        if not isinstance(raw_det, dict):
            continue
        dm_list = raw_det.get("decoded_messages")
        # Edges send the detection id as ``id``; the gateway (ingest hook)
        # as ``detection_id``.
        det_id = raw_det.get("id") or raw_det.get("detection_id") or ""
        if not dm_list or not isinstance(dm_list, list):
            continue
        if not det_id or not isinstance(det_id, str):
            continue
        room = max(
            0,
            min(_EDGE_DECODED_MAX_PER_DETECTION, _EDGE_DECODED_MAX_PER_BATCH - kept),
        )
        msgs = [dm for dm in dm_list if isinstance(dm, dict)][:room]
        dropped += len(dm_list) - len(msgs)
        if msgs:
            kept += len(msgs)
            found[det_id] = msgs
    if dropped:
        logger.warning(
            "Detection batch from %r: dropped %d edge-decoded messages "
            "(max %d per detection, %d per batch)",
            str(payload.get("node_id", ""))[:64],
            dropped,
            _EDGE_DECODED_MAX_PER_DETECTION,
            _EDGE_DECODED_MAX_PER_BATCH,
        )
    return found


def _edge_decoded_from_hook(
    payload: dict[str, Any], only: set[str] | None = None
) -> dict[str, list[dict]]:
    """Collect edge-decoded messages from a gateway ingest-hook body (K8).

    The gateway forwards the messages the edge attached to its detections.
    Accepted shapes (all bounded like :func:`_extract_edge_decoded`):

    * nested in each detection object, as the edge sends them
      (``detections[i].decoded_messages``);
    * a top-level ``decoded_messages`` list of message objects that each
      name their ``detection_id``;
    * a top-level list of ``{"detection_id": ..., "decoded_messages": [...]}``
      groups;
    * a top-level object mapping detection ids to message lists;
    * a top-level list of message lists, one per detection, in the same
      order as ``detections``.

    Messages are attributed to the detection they name; which node and
    detection a stored message belongs to is set from the accepted
    detection, never from the message (see :func:`_store_edge_decoded`).
    *only* restricts the result to those detection ids (before the bounds
    are applied).
    """
    raw_dets = payload.get("detections")
    raw_dets = raw_dets if isinstance(raw_dets, list) else []
    groups: dict[str, list[Any]] = {}

    def _add(det_id: Any, msgs: Any) -> None:
        if not (isinstance(det_id, str) and det_id and isinstance(msgs, list)):
            return
        if only is None or det_id in only:
            groups.setdefault(det_id, []).extend(msgs)

    for raw_det in raw_dets:
        if isinstance(raw_det, dict):
            _add(
                raw_det.get("detection_id") or raw_det.get("id"),
                raw_det.get("decoded_messages"),
            )
    top = payload.get("decoded_messages")
    if isinstance(top, dict):
        for det_id, msgs in top.items():
            _add(det_id, msgs)
    elif isinstance(top, list):
        parallel = len(top) == len(raw_dets) and all(
            isinstance(item, list) for item in top
        )
        for index, item in enumerate(top):
            if parallel:
                raw_det = raw_dets[index]
                if isinstance(raw_det, dict):
                    _add(raw_det.get("detection_id") or raw_det.get("id"), item)
            elif isinstance(item, dict) and isinstance(
                item.get("decoded_messages"), list
            ):
                _add(item.get("detection_id"), item["decoded_messages"])
            elif isinstance(item, dict):
                _add(item.get("detection_id"), [item])
    return _extract_edge_decoded(
        {
            "node_id": payload.get("node_id", ""),
            "detections": [
                {"detection_id": det_id, "decoded_messages": msgs}
                for det_id, msgs in groups.items()
            ],
        }
    )


def _store_edge_decoded(
    decoded_store: Any,
    aircraft_store: Any,
    detections: list[Any],
    edge_decoded: dict[str, list[dict]],
) -> int:
    """Persist edge-decoded messages in one transaction (blocking).

    Each message is attributed to its detection and that detection's
    (batch-verified) node, and stored under the bridge's own tenant (the
    stores' context), whatever node, detection or tenant the message
    names.  ADS-B messages also feed the aircraft track store, attributed
    the same way.  Returns the number of messages stored.
    """
    now = _utcnow().isoformat()
    records: list[dict] = []
    for det in detections:
        for dm in edge_decoded.get(det.detection_id) or ():
            dm.pop("tenant_id", None)
            dm["node_id"] = det.node_id
            dm["detection_id"] = det.detection_id
            dm.setdefault("freq_hz", det.freq_hz)
            dm.setdefault("timestamp", now)
            records.append(dm)
    if not records:
        return 0
    stored = 0
    try:
        stored = sum(1 for i in decoded_store.store_messages(records) if i is not None)
    except Exception:
        logger.warning(
            "Failed to store %d edge-decoded messages", len(records), exc_info=True
        )
    if aircraft_store is not None:
        # ADS-B: also feed the aircraft track store for the ADS-B tab
        for dm in records:
            if dm.get("protocol") == "adsb" and isinstance(dm.get("metadata"), dict):
                track = {**dm["metadata"], "node_id": dm["node_id"]}
                track.pop("tenant_id", None)
                try:
                    aircraft_store.insert_position(track)
                except Exception:
                    logger.debug("Failed to insert aircraft track", exc_info=True)
    return stored


_COOLDOWN_EVICT_INTERVAL = 600.0  # evict stale cooldowns every 10 min
_cooldown_last_evict = 0.0
_COOLDOWN_MAX_ENTRIES = 50_000


async def _broadcast_new_alert(app_state: Any, alert: dict[str, Any]) -> None:
    """Push a newly created alert to the alert WebSocket feed (best effort).

    ``/api/alerts/ws/alerts`` (proxied by the gateway) is the dashboard's
    live alert stream; alerts created on ingest are sent there like
    alerts created through the alerts API.
    """
    clients = getattr(app_state, "ws_alert_clients", None)
    if clients is None:
        return
    try:
        await clients.broadcast(alert)
    except Exception:
        logger.debug("Alert WebSocket broadcast failed", exc_info=True)


def _dispatch_alert(
    app_state: Any,
    notifier: Any,
    alert: dict[str, Any],
    *,
    webhook: bool = True,
    syslog_fields: dict[str, Any] | None = None,
) -> None:
    """Hand a new alert to its webhooks and syslog targets, in the background.

    Never waits for a third-party endpoint (contract K8b): webhook delivery
    (with its retries and retry queue) and syslog forwarding run in
    bounded background tasks, so an unreachable webhook or syslog server
    cannot hold up the ingest request or the gateway's ingest hook.
    *syslog_fields* are added to the syslog copy of the alert; ``None``
    means the alert is not forwarded to syslog.
    """
    if webhook and notifier is not None:
        try:
            notifier.submit(alert)
        except Exception as exc:
            logger.warning("Webhook notification failed: %s", exc)
    syslog_fwd = getattr(app_state, "_syslog_forwarder", None)
    if syslog_fwd is not None and syslog_fields is not None:
        try:
            syslog_fwd.submit({**alert, **syslog_fields})
        except Exception as exc:
            logger.warning("Syslog forwarding failed: %s", exc)


# How many escalated anomalies an escalation alert describes in its message;
# it counts the others and names them all in ``anomaly_ids``.
ESCALATION_DESCRIBED = 5


def shared_value(rows: list[dict[str, Any]], key: str) -> Any:
    """The value of *key* when every row has the same one, else ``None``."""
    values = {row.get(key) for row in rows}
    return values.pop() if len(values) == 1 else None


async def escalate_anomalies(
    request: Request,
    *,
    rows: dict[int, dict[str, Any]],
    ids: list[int],
    alert_name: str,
    kind: str,
    describe: Callable[[dict[str, Any]], str],
    details: Callable[[list[dict[str, Any]]], tuple[dict[str, Any], dict[str, Any]]],
    operator: str,
) -> dict[str, Any]:
    """Raise one critical alert for the anomalies an operator escalated.

    Dismisses none.  *rows* maps the requested *ids* that exist to their
    anomaly rows.  An anomaly that an *alert_name* alert still
    unacknowledged names (in its ``anomaly_ids``) is not alerted again.
    The others share one new alert, so a request adds a single alert to
    the bounded alert store (``MAX_ALERTS``) and sends a single webhook
    and syslog message, however many anomalies it escalates.  The alert
    names them all in ``anomaly_ids`` and describes the first
    ``ESCALATION_DESCRIBED`` in its message (``describe(row)`` each, for
    *kind* anomalies); ``details(rows)`` gives its extra fields and the
    fields added to its syslog copy.  It is stored, pushed to the live
    alert feed and handed to webhooks and syslog like every other alert.
    """
    app_state = request.app.state.app_state
    persistence = request.app.state.persistence
    notifier = getattr(request.app.state, "notifier", None)
    still_open: set[Any] = set()
    for a in persistence.get_alerts():
        named = a.get("anomaly_ids")
        if (
            a.get("name") == alert_name
            and not a.get("acknowledged")
            and isinstance(named, list)
        ):
            still_open.update(named)
    escalated: list[dict[str, Any]] = []
    already: list[int] = []
    not_found: list[int] = []
    for anomaly_id in dict.fromkeys(ids):
        row = rows.get(anomaly_id)
        if row is None:
            not_found.append(anomaly_id)
        elif anomaly_id in still_open:
            already.append(anomaly_id)
        else:
            escalated.append(row)

    alert_id = None
    if escalated:
        count = len(escalated)
        described = "; ".join(describe(row) for row in escalated[:ESCALATION_DESCRIBED])
        if count > ESCALATION_DESCRIBED:
            described += f"; and {count - ESCALATION_DESCRIBED} more"
        message = (
            f"Escalated by an operator: {count} {kind} "
            f"anomal{'y' if count == 1 else 'ies'}: {described}"
        )
        fields, syslog_fields = details(escalated)
        alert_id = app_state.next_alert_id()
        alert = {
            **fields,
            "alert_id": alert_id,
            "name": alert_name,
            "severity": "critical",
            "message": html.escape(message),
            # One node only when every escalated anomaly is from it.
            "node_id": shared_value(escalated, "node_id") or None,
            "triggered_at": _utcnow().isoformat(),
            "acknowledged": False,
            "acknowledged_at": None,
            "anomaly_ids": [row["id"] for row in escalated],
            "anomaly_score": max(
                float(row.get("anomaly_score") or 0.0) for row in escalated
            ),
            "escalated_by": operator,
        }
        persistence.add_alert(alert)
        await _broadcast_new_alert(app_state, alert)
        _dispatch_alert(app_state, notifier, alert, syslog_fields=syslog_fields)
    return {
        "ok": True,
        "alert_id": alert_id,
        "escalated_count": len(escalated),
        "escalated": [row["id"] for row in escalated],
        "already_escalated": already,
        "not_found": not_found,
    }


async def _maybe_create_anomaly_alerts(
    app_state: AppState,
    persistence: Any,
    detections: list[Any],
    node_id: str,
    notifier: Any = None,
) -> int:
    """Auto-create alerts for high-anomaly detections with rate limiting.

    Returns the number of alerts created.
    """
    global _cooldown_last_evict
    now = time.monotonic()
    created = 0

    # Read configurable thresholds (fall back to module defaults)
    det_config = getattr(app_state, "_detection_config", None) or {}
    alert_threshold = det_config.get(
        "rf_anomaly_alert_threshold", _ANOMALY_ALERT_THRESHOLD
    )
    critical_threshold = det_config.get(
        "rf_anomaly_critical_threshold", _ANOMALY_CRITICAL_THRESHOLD
    )
    confidence_floor = det_config.get(
        "rf_min_confidence_floor", _RF_MIN_CONFIDENCE_FLOOR
    )

    # Amortized eviction of stale cooldown entries
    if now - _cooldown_last_evict > _COOLDOWN_EVICT_INTERVAL:
        cutoff = now - 2 * _ANOMALY_ALERT_COOLDOWN_SECONDS
        stale = [k for k, v in app_state.anomaly_alert_cooldowns.items() if v < cutoff]
        for k in stale:
            del app_state.anomaly_alert_cooldowns[k]
        # Hard cap: if still over limit, drop oldest entries
        if len(app_state.anomaly_alert_cooldowns) > _COOLDOWN_MAX_ENTRIES:
            by_age = sorted(
                app_state.anomaly_alert_cooldowns,
                key=app_state.anomaly_alert_cooldowns.get,
            )
            for k in by_age[
                : len(app_state.anomaly_alert_cooldowns) - _COOLDOWN_MAX_ENTRIES
            ]:
                del app_state.anomaly_alert_cooldowns[k]
        _cooldown_last_evict = now

    for det in detections:
        score = getattr(det, "anomaly_score", 0.0)
        if score < alert_threshold:
            continue

        # Skip low-confidence detections if confidence floor is set
        confidence = getattr(det, "confidence", 1.0)
        if confidence < confidence_floor:
            continue

        freq = getattr(det, "freq_hz", 0.0)
        bucket = _freq_bucket(freq)
        cooldown_key = (node_id, bucket)

        # Severity first: it decides the cooldown.  A critical alert waits
        # only the short critical cooldown since the bucket's last alert,
        # so an earlier warning cannot hold back a critical escalation for
        # the full warning cooldown.
        severity = "critical" if score >= critical_threshold else "warning"
        cooldown = (
            _ANOMALY_ALERT_COOLDOWN_CRITICAL_SECONDS
            if severity == "critical"
            else _ANOMALY_ALERT_COOLDOWN_SECONDS
        )

        # Check cooldown.  A key that never alerted has no cooldown: a
        # 0.0 default would count as "alerted at monotonic 0", i.e. at
        # host boot, and suppress the first alert of every bucket for the
        # first cooldown period after a (re)boot.
        last_alert = app_state.anomaly_alert_cooldowns.get(cooldown_key)
        if last_alert is not None and now - last_alert < cooldown:
            continue

        signal_class = getattr(det, "signal_class", "unknown")
        alert = {
            "alert_id": app_state.next_alert_id(),
            "name": "anomaly_detected",
            "severity": severity,
            "message": html.escape(
                f"High anomaly score {score:.2f} for {signal_class} "
                f"at {freq / 1e6:.2f} MHz on {node_id}"
            ),
            "node_id": node_id,
            "triggered_at": _utcnow().isoformat(),
            "acknowledged": False,
            "acknowledged_at": None,
            "detection_id": getattr(det, "detection_id", ""),
            "anomaly_score": score,
        }

        persistence.add_alert(alert)
        app_state.anomaly_alert_cooldowns[cooldown_key] = now
        created += 1
        await _broadcast_new_alert(app_state, alert)

        # Webhooks and syslog, in the background (never awaited here)
        _dispatch_alert(
            app_state,
            notifier,
            alert,
            syslog_fields={"signal_class": signal_class, "freq_hz": freq},
        )

        app_state.log_activity(
            event_type="anomaly_alert",
            node_id=node_id,
            message=f"Auto-alert: anomaly score {score:.2f} for {signal_class}",
            details={
                "detection_id": getattr(det, "detection_id", ""),
                "anomaly_score": score,
                "severity": severity,
                "freq_hz": freq,
            },
        )

        logger.info(
            "Auto-alert created: %s score=%.2f class=%s node=%s",
            severity,
            score,
            signal_class,
            node_id,
        )

    return created


async def _evaluate_watch_band_alerts(
    app_state: AppState,
    persistence: Any,
    detections: list[Any],
    notifier: Any = None,
) -> int:
    """Evaluate the configured watch bands against detections.

    Creates one alert per triggered band (cooldowns and count windows live
    on ``app_state``).  Returns the number of alerts created.
    """
    bands = persistence.get_watch_bands()
    if not bands:
        return 0
    from sigrift.bridge.alert_engine import build_watch_band_alert, evaluate_watch_bands

    now = time.monotonic()
    created = 0
    for det in detections:
        det_dict: dict[str, Any] = {
            "detection_id": getattr(det, "detection_id", ""),
            "signal_class": det.signal_class,
            "freq_hz": det.freq_hz,
            "power_dbm": det.power_dbm,
            "node_id": det.node_id,
        }
        for band in evaluate_watch_bands(
            det_dict,
            bands,
            app_state.watch_band_cooldowns,
            app_state.watch_band_counts,
            now,
        ):
            alert = build_watch_band_alert(
                band, det_dict, app_state.next_alert_id(), _utcnow().isoformat()
            )
            persistence.add_alert(alert)
            created += 1
            await _broadcast_new_alert(app_state, alert)
            _dispatch_alert(
                app_state,
                notifier,
                alert,
                webhook=bool(band.get("notify_webhook", True)),
            )
            app_state.log_activity(
                event_type="watch_band_alert",
                node_id=det.node_id,
                message=alert["message"],
                details={"watch_id": band.get("watch_id", "")},
            )
    return created


async def _evaluate_condition_rules(
    app_state: AppState,
    persistence: Any,
    detections: list[Any],
    node_id: str,
    notifier: Any = None,
) -> int:
    """Evaluate condition-based alert rules against detections.

    Returns the number of rule-triggered alerts created.
    """
    import html as _html

    rules = persistence.get_alert_rules()
    if not rules:
        return 0

    # Get or create the cooldown tracker on app_state
    if not hasattr(app_state, "rule_cooldowns"):
        app_state.rule_cooldowns = {}

    now = time.monotonic()
    created = 0

    for det in detections:
        det_dict: dict[str, Any] = {
            "signal_class": det.signal_class,
            "freq_hz": det.freq_hz,
            "snr_db": det.snr_db,
            "power_dbm": det.power_dbm,
            "anomaly_score": det.anomaly_score,
            "node_id": det.node_id,
            "family": det.family,
            "confidence": det.confidence,
        }

        triggered = _evaluate_detection_rules(
            det_dict,
            rules,
            app_state.rule_cooldowns,
            now,
        )

        for rule in triggered:
            rule_id = rule.get("rule_id", "")
            rule_name = rule.get("name", rule_id)
            severity = rule.get("severity", "warning")

            # Update rule trigger stats on the stored rule: ``rules`` are
            # copies (get_alert_rules), so counting on them never persisted.
            triggered_at = _utcnow().isoformat()
            rule["trigger_count"] = rule.get("trigger_count", 0) + 1
            rule["last_triggered_at"] = triggered_at
            persistence.record_alert_rule_trigger(rule_id, triggered_at)

            # Build condition summary for the alert message
            cond_summary = []
            for c in rule.get("conditions", []):
                cond_summary.append(
                    f"{c.get('field')} {c.get('operator')} {c.get('value')}"
                )
            cond_str = " AND ".join(cond_summary) if cond_summary else "no conditions"

            alert = {
                "alert_id": app_state.next_alert_id(),
                "name": f"rule_{rule_name}",
                "severity": severity,
                "message": _html.escape(
                    f"Rule '{decode_html_escaped_text(rule_name)}' triggered on {node_id}: "
                    f"{det.signal_class} at {det.freq_hz / 1e6:.2f} MHz "
                    f"({cond_str})"
                ),
                "node_id": node_id,
                "triggered_at": _utcnow().isoformat(),
                "acknowledged": False,
                "acknowledged_at": None,
                "rule_id": rule_id,
                "detection_id": getattr(det, "detection_id", ""),
            }

            persistence.add_alert(alert)
            created += 1
            await _broadcast_new_alert(app_state, alert)

            # Webhook (if the rule asks for one) and syslog, in the background
            _dispatch_alert(
                app_state,
                notifier,
                alert,
                webhook=bool(rule.get("notify_webhook", True)),
                syslog_fields={
                    "signal_class": det_dict.get("signal_class", ""),
                    "freq_hz": det_dict.get("freq_hz", 0),
                    "anomaly_score": det_dict.get("anomaly_score", 0),
                },
            )

            app_state.log_activity(
                event_type="rule_alert",
                node_id=node_id,
                message=f"Rule '{rule_name}' triggered: {det.signal_class}",
                details={
                    "rule_id": rule_id,
                    "severity": severity,
                    "detection_id": getattr(det, "detection_id", ""),
                },
            )

            logger.info(
                "Rule alert: %s rule=%s class=%s node=%s",
                severity,
                rule_name,
                det.signal_class,
                node_id,
            )

    return created


# ---------------------------------------------------------------------------
# POST /batch -- ingest a batch of detections from an edge node
# ---------------------------------------------------------------------------


@router.post("/batch", status_code=status.HTTP_201_CREATED)
async def ingest_batch(
    request: Request,
    _key_id: str = Depends(require_role(Role.SENSOR)),
) -> dict[str, Any]:
    """Ingest a batch of detections from an edge node.

    Supports gzip-compressed request bodies (Content-Encoding: gzip)
    from the edge detection reporter.

    Validates that the node is registered, stores detections, and
    broadcasts to connected WebSocket clients.
    """
    import gzip as _gzip
    import json as _json
    import zlib as _zlib

    # Request body size validation (max 1MB)
    raw_body = await request.body()
    if len(raw_body) > 1_048_576:  # 1MB
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Request body exceeds 1MB limit",
        )

    # Decompress gzip if needed (with bomb protection -- 50MB limit)
    if request.headers.get("content-encoding") == "gzip":
        try:
            from io import BytesIO as _BytesIO

            _MAX_DECOMPRESSED = 50 * 1024 * 1024  # 50 MB
            dec = _gzip.GzipFile(fileobj=_BytesIO(raw_body))
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = dec.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_DECOMPRESSED:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="Decompressed payload exceeds 50MB limit",
                    )
                chunks.append(chunk)
            raw_body = b"".join(chunks)
        except HTTPException:
            raise
        except (OSError, ValueError, EOFError, _zlib.error):
            # EOFError: truncated stream; zlib.error: corrupt deflate
            # behind a valid header — client garbage, 400 not 500.
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to decompress gzip body",
            )

    try:
        payload = _json.loads(raw_body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON: {exc}",
        )

    # Extract edge-decoded messages before pydantic strips extra fields
    _edge_decoded = _extract_edge_decoded(payload)

    try:
        body = DetectionBatch(**payload)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    with trace_span(
        _tracer,
        "ingest_batch",
        attributes={
            "batch.node_id": body.node_id,
            "batch.id": body.batch_id,
            "batch.size": len(body.detections),
        },
    ) as _span:
        return await _ingest_batch_process(
            request,
            body,
            _key_id,
            _span,
            edge_decoded=_edge_decoded,
        )


def _normalize_detections(detections: list[Any], node_id: str) -> None:
    """Prepare edge detections for storage, in place.

    Every record gets the batch's node, its signal class normalized to the
    canonical taxonomy (with family and refined class), and an estimated
    bandwidth when the edge sent none.
    """
    for det in detections:
        if det.node_id != node_id:
            det.node_id = node_id
        det.signal_class = normalize_class(det.signal_class)
        det.family = normalize_family(det.signal_class)
        det.refined_class = refine_classification(det.signal_class, det.freq_hz)
        if det.bandwidth_hz is None:
            det.bandwidth_hz = estimate_bandwidth(det.signal_class, det.freq_hz)


async def _ingest_batch_process(
    request: Request,
    body: DetectionBatch,
    _key_id: str,
    span: Any,
    edge_decoded: dict[str, list[dict]] | None = None,
) -> dict[str, Any]:
    """The bridge's own batch ingest: (a) insert, then (b) :func:`post_ingest`."""
    persistence = request.app.state.persistence
    app_state: AppState = request.app.state.app_state
    store = _get_detection_store(request)

    # Verify node is registered
    nodes = persistence.get_nodes()
    if body.node_id not in nodes:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {body.node_id!r} not registered",
        )

    # SEC-M14 / K4: the credential must be allowed to act for this node
    # (bound to it, or bound to it now on first use).
    await enforce_node_binding(request, _key_id, body.node_id)

    # Track raw ingest usage for deprecation monitoring
    _raw_ingest_nodes[body.node_id] = time.time()
    while len(_raw_ingest_nodes) > _RAW_INGEST_MAX_ENTRIES:
        oldest = min(_raw_ingest_nodes, key=_raw_ingest_nodes.get)
        del _raw_ingest_nodes[oldest]
    logger.info(
        "Raw batch ingest from node %s — consider enabling MLRF_SUMMARIZE=1",
        body.node_id,
    )

    _normalize_detections(body.detections, body.node_id)

    # Direct insert — WriteQueue's async flush loop has reliability issues
    # under uvicorn, so bypass it and write synchronously via thread pool.
    inserted = await asyncio.to_thread(store.insert_batch, body.detections)
    span.set_attribute("batch.inserted", inserted)

    result = await post_ingest(
        request.app,
        body.detections,
        body.node_id,
        edge_decoded,
        batch_id=body.batch_id,
        inserted=inserted,
    )
    alerts_created = result["alerts_created"]

    # Broadcast to detection WebSocket clients
    await _broadcast_detections(
        app_state,
        {
            "type": "batch",
            "node_id": body.node_id,
            "batch_id": body.batch_id,
            "count": inserted,
            "timestamp": _utcnow().isoformat(),
        },
    )

    logger.info(
        "Detection batch %s from %s: %d/%d inserted, %d alerts",
        body.batch_id,
        body.node_id,
        inserted,
        len(body.detections),
        alerts_created,
    )

    return {
        "accepted": True,
        "batch_id": body.batch_id,
        "inserted": inserted,
        "total": len(body.detections),
        "alerts_created": alerts_created,
        "correlation_count": result["correlation_count"],
        "fhss_events": result["fhss_events"],
    }


async def _queue_stored_iq_decodes(
    state: Any, job_queue: Any, iq_store: Any, detections: list[Any]
) -> int:
    """Queue the decode of every decodable detection whose IQ is indexed.

    The capture's sample rate and length come from its IQ metadata, which
    the IQ upload route writes before it tries to queue the decode itself:
    a capture stored but not indexed yet is left to that route, so a
    decode is never queued at a guessed rate.  Returns the jobs queued.
    """
    from sigrift.bridge.decode_pipeline import is_decodable, queue_protocol_decode_once
    from sigrift.bridge.storage.ingest_claims import get_ingest_claims

    candidates = [
        det
        for det in detections
        if is_decodable(det.signal_class) and iq_store.exists(det.detection_id)
    ]
    meta_store = getattr(state, "iq_metadata_store", None)
    if not candidates or meta_store is None:
        return 0
    claims = get_ingest_claims(state)
    queued = 0
    for det in candidates:
        meta = await asyncio.to_thread(meta_store.get_metadata, det.detection_id)
        if not meta or not meta.get("sample_rate"):
            continue
        n_samples = meta.get("n_samples")
        if not n_samples:
            # Indexed without a length (a stub capture that named none).
            n_samples = await asyncio.to_thread(iq_store.sample_count, det.detection_id)
        decode = await queue_protocol_decode_once(
            job_queue,
            claims,
            detection_id=det.detection_id,
            signal_class=det.signal_class,
            freq_hz=det.freq_hz,
            node_id=det.node_id,
            sample_rate=meta["sample_rate"],
            n_samples=n_samples,
            source="post_ingest",
        )
        queued += decode.job_id is not None
    return queued


class _Stage:
    """Run one post-ingest stage; log and swallow its failure.

    The detections are already stored when :func:`post_ingest` runs, so a
    failing stage (a broken rule, a store error) must not abort the stages
    after it, nor fail the request: the edge — or the gateway's hook
    queue — would resend a batch that is already stored.
    """

    def __init__(self, name: str, node_id: str) -> None:
        self.name = name
        self.node_id = node_id

    def __enter__(self) -> _Stage:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        if exc_type is None or not issubclass(exc_type, Exception):
            return False
        logger.error(
            "Post-ingest stage %r failed for node %s",
            self.name,
            self.node_id,
            exc_info=(exc_type, exc, tb),
        )
        return True


async def post_ingest(
    app: Any,
    detections: list[Any],
    node_id: str,
    edge_decoded: dict[str, list[dict]] | None = None,
    *,
    batch_id: str = "",
    inserted: int | None = None,
    native_analysis: bool = False,
) -> dict[str, Any]:
    """Everything that happens after a detection batch is stored (contract K8).

    Called by the bridge's own ``POST /api/detections/batch`` after its
    insert, and by ``POST /api/internal/ingest-hook`` for batches the
    gateway ingested natively (the gateway serves ``/api/detections/batch``
    in the shipped deployment).  It never inserts *detections* and never
    broadcasts them on the detection feed; the caller did both.

    Stages: edge-decoded message storage, ``protocol_decode`` job queueing,
    RF baseline updates, the activity log, FHSS and cross-node correlation
    (every ``_ANALYSIS_EVERY_N``-th batch per node), cross-sensor
    correlation, whitelist / calibration / drift, signature matching, the
    ``rf_anomalies`` rows, anomaly alerts, condition alert rules (their
    ``trigger_count`` is persisted) and watch-band alerts — with webhooks,
    syslog and the alert WebSocket feed for every alert created.

    *native_analysis*: the gateway already ran FHSS detection, cross-node
    correlation and the ``rf_anomalies`` upsert for this batch, so those
    stages (and the signature matching that only feeds ``rf_anomalies``)
    are skipped instead of storing everything twice.

    Each stage is isolated (:class:`_Stage`).  Returns ``alerts_created``,
    ``correlation_count``, ``fhss_events``, ``decoded_stored`` and
    ``decode_jobs``.
    """
    state = app.state
    persistence = state.persistence
    app_state: AppState = state.app_state
    store = getattr(state, "detection_store", None)
    total = len(detections)
    if inserted is None:
        inserted = total
    result: dict[str, Any] = {
        "alerts_created": 0,
        "correlation_count": 0,
        "fhss_events": 0,
        "decoded_stored": 0,
        "decode_jobs": 0,
    }

    # Store edge-decoded messages (bounded when extracted) in one
    # transaction, off the event loop.
    _decoded_msg_store = getattr(state, "decoded_message_store", None)
    if _decoded_msg_store is not None and edge_decoded:
        with _Stage("edge_decoded", node_id):
            result["decoded_stored"] = await asyncio.to_thread(
                _store_edge_decoded,
                _decoded_msg_store,
                getattr(store, "_aircraft", None),
                detections,
                edge_decoded,
            )

    # Queue protocol_decode jobs for decodable detections whose IQ is
    # already stored.  Usually the IQ arrives after the detection and the
    # IQ upload route queues the decode then; whichever of the two comes
    # first queues it, once per detection across every worker process
    # (decode_pipeline.queue_protocol_decode_once, contract K8b).
    _job_queue = getattr(state, "job_queue", None)
    _iq_store = getattr(state, "iq_store", None)
    if _job_queue is not None and _iq_store is not None:
        with _Stage("protocol_decode", node_id):
            result["decode_jobs"] = await _queue_stored_iq_decodes(
                state, _job_queue, _iq_store, detections
            )

    # Update RF baselines from ingested detections (feeds MAD/CUSUM scoring)
    rf_baseline_mgr = getattr(state, "rf_baseline_mgr", None)
    if rf_baseline_mgr is not None:
        with _Stage("rf_baselines", node_id):
            for det in detections:
                rf_baseline_mgr.update(
                    det.freq_hz,
                    det.signal_class,
                    det.confidence,
                    det.power_dbm,
                    _extract_hour(det.timestamp),
                    snr_db=det.snr_db,
                    bandwidth_hz=det.bandwidth_hz,
                    timestamp_epoch=_to_epoch(det.timestamp),
                )

    batch_label = batch_id or "(gateway)"
    app_state.log_activity(
        event_type="detection_batch",
        node_id=node_id,
        message=f"Batch {batch_label}: {inserted}/{total} detections stored",
        details={
            "batch_id": batch_id,
            "inserted": inserted,
            "total": total,
        },
    )

    # Throttle expensive FHSS + correlation to every Nth batch per node
    _node_batch_count[node_id] = _node_batch_count.get(node_id, 0) + 1
    _node_batch_count.move_to_end(node_id)
    while len(_node_batch_count) > _NODE_BATCH_MAX_ENTRIES:
        _node_batch_count.popitem(last=False)
    _run_analysis = (_node_batch_count[node_id] % _ANALYSIS_EVERY_N) == 0

    # FHSS + correlation are expensive — only run every Nth batch per node.
    # The gateway runs both natively for the batches it ingests.
    if _run_analysis and not native_analysis:
        # Fetch recent detections once for both FHSS and correlation analysis
        recent_all: list[dict[str, Any]] = []
        try:
            recent_all = await asyncio.to_thread(
                store.get_recent,
                minutes=1,
                limit=500,
            )
        except Exception:
            # FHSS then sees only this batch and correlation is skipped;
            # warn once per failure streak so that does not go unnoticed.
            if not _recent_fetch_state["failing"]:
                _recent_fetch_state["failing"] = True
                logger.warning(
                    "Could not load recent detections; FHSS analysis uses only "
                    "the current batch and correlation is skipped until it works",
                    exc_info=True,
                )
        else:
            if _recent_fetch_state["failing"]:
                _recent_fetch_state["failing"] = False
                logger.info("Loading recent detections works again")

        try:
            fhss_detector: FHSSDetector | None = getattr(
                state,
                "fhss_detector",
                None,
            )
            if fhss_detector is None:
                fhss_detector = FHSSDetector()
            recent_for_fhss = [r for r in recent_all if r.get("node_id") == node_id]
            batch_dicts = [
                {
                    "node_id": d.node_id,
                    "timestamp": d.timestamp,
                    "freq_hz": d.freq_hz,
                    "signal_class": d.signal_class,
                    "confidence": d.confidence,
                }
                for d in detections
            ]
            combined = recent_for_fhss + batch_dicts
            fhss_events = fhss_detector.analyse(combined)
            if fhss_events:
                fhss_dicts = [evt.to_dict() for evt in fhss_events]
                await asyncio.to_thread(store.insert_fhss_events, fhss_dicts)
                result["fhss_events"] = len(fhss_events)
                logger.info(
                    "FHSS detected: %d events from node %s",
                    len(fhss_events),
                    node_id,
                )
        except Exception as exc:
            logger.debug("FHSS analysis failed: %s", exc)

        # Cross-node correlation
        correlator: NodeCorrelator | None = getattr(state, "correlator", None)
        if correlator is not None and recent_all:
            try:
                all_nodes = persistence.get_nodes()
                active_count = sum(
                    1
                    for n in all_nodes.values()
                    if AppState.get_node_status(n).value in ("active", "stale")
                )
                correlator.set_active_node_count(max(1, active_count))

                for det in detections:
                    det_dict = {
                        "node_id": det.node_id,
                        "signal_class": det.signal_class,
                        "family": det.family,
                        "freq_hz": det.freq_hz,
                        "timestamp": det.timestamp,
                        "anomaly_score": det.anomaly_score,
                    }
                    corr = correlator.check_correlation(det_dict, recent_all)
                    if corr.correlated:
                        result["correlation_count"] += 1
                    if corr.adjusted_anomaly_score is not None:
                        det.anomaly_score = corr.adjusted_anomaly_score
            except Exception as exc:
                logger.debug("Correlation check failed: %s", exc)

    # -- Cross-correlation (fire-and-forget) --------------------------------
    cross_correlator = getattr(state, "cross_correlator", None)
    if cross_correlator and _run_analysis:
        try:
            sdr_events = [
                {"freq_hz": d.freq_hz, "timestamp": d.timestamp, "id": d.detection_id}
                for d in detections
            ]
            await asyncio.to_thread(
                cross_correlator.correlate, "sdr", sdr_events, node_id
            )
        except Exception as e:
            logger.debug("Cross-correlation error: %s", e)

    with _Stage("score_adjustments", node_id):
        # Apply whitelist reduction before anomaly filtering
        signal_whitelist = getattr(state, "signal_whitelist", None)
        if signal_whitelist is not None:
            for det in detections:
                det.anomaly_score = signal_whitelist.apply_reduction(
                    det.anomaly_score,
                    det.freq_hz,
                    det.signal_class,
                    node_id=det.node_id,
                )

        # Apply score calibration (Platt scaling) when a fitted curve exists
        score_calibrator = getattr(state, "score_calibrator", None)
        if score_calibrator is not None:
            for det in detections:
                det.anomaly_score = score_calibrator.calibrate(
                    det.anomaly_score,
                    det.freq_hz,
                )

        # Feed scores to drift detector and check for IF retrain trigger
        drift_detector = getattr(state, "drift_detector", None)
        if drift_detector is not None:
            for det in detections:
                drift_detector.add_score(det.anomaly_score)
            if drift_detector.should_retrain():
                logger.warning(
                    "Drift detector triggered retrain signal for node %s "
                    "(batch %s, drift status: %s)",
                    node_id,
                    batch_label,
                    drift_detector.status(),
                )
                drift_detector.mark_retrained()

    # Match against threat signature library (opt-in: only boost scores
    # when SIGNATURE_MATCH weight is non-zero in scorer config).  The
    # matches only enrich the rf_anomalies rows below.
    sig_store = getattr(state, "signature_library_store", None)
    _sig_weight = 0.0
    rf_scorer_obj = getattr(state, "rf_scorer", None)
    if rf_scorer_obj is not None:
        _sig_weight = rf_scorer_obj.config.weights.get(
            AnomalyDimension.SIGNATURE_MATCH, 0.0
        )
    # Cache signature match results per detection for use in both
    # the anomaly_score pipeline and rf_anomalies enrichment below.
    _sig_match_cache: dict[str, dict[str, Any]] = {}
    if sig_store is not None and _sig_weight > 0 and not native_analysis:
        for det in detections:
            try:
                matches = sig_store.match_by_parameters(
                    freq_hz=det.freq_hz,
                    signal_class=det.signal_class,
                    bandwidth_hz=det.bandwidth_hz,
                    power_dbm=det.power_dbm,
                )
                if matches:
                    _sig_match_cache[det.detection_id] = matches[0]
            except Exception as exc:
                logger.warning(
                    "Signature matching failed for %s: %s",
                    det.detection_id,
                    exc,
                )

    # Protocol detection filtering — disabled protocols skip scoring/alerting
    # but are still stored above for audit purposes.
    det_cfg = getattr(state, "detection_config", None) or {}
    _proto_cfg = det_cfg.get("protocol_detection", {})
    _disabled_protos: set[str] = set()
    for _pname, _penabled in _proto_cfg.items():
        if not _penabled:
            # Map protocol config names to underscore-normalised signal classes
            _disabled_protos.add(_pname)
            _disabled_protos.add(_pname.replace("_", "-"))
    _scoring_dets = detections
    if _disabled_protos:
        _skipped = [
            d
            for d in detections
            if d.signal_class.replace("-", "_") in _disabled_protos
            or d.signal_class in _disabled_protos
        ]
        if _skipped:
            logger.debug(
                "Protocol filter: skipping scoring for %d detections "
                "(disabled protocols)",
                len(_skipped),
            )
            _skip_ids = {id(d) for d in _skipped}
            _scoring_dets = [d for d in detections if id(d) not in _skip_ids]

    # Populate rf_anomalies table for anomalous detections (always runs;
    # the gateway upserts these rows itself for the batches it ingests)
    rf_insert_threshold = det_cfg.get("rf_anomaly_insert_threshold", 0.3)
    rf_conf_floor = det_cfg.get("rf_min_confidence_floor", 0.0)
    anomalous_dets = [
        d
        for d in _scoring_dets
        if d.anomaly_score >= rf_insert_threshold and d.confidence >= rf_conf_floor
    ]
    if anomalous_dets and not native_analysis:
        with _Stage("rf_anomalies", node_id):
            await _insert_rf_anomalies(
                state, app_state, store, anomalous_dets, _sig_match_cache
            )

    # Operator-known RF patterns affect alerts only. Detections, learned
    # statistics, original scores and rf_anomalies remain available for review.
    # Query per batch so another worker's committed edit/removal takes effect.
    alerting_dets = _scoring_dets
    if store is not None:
        with _Stage("known_signal_alert_filter", node_id):
            from sigrift.bridge.storage.known_signals import matches

            patterns = await asyncio.to_thread(store.known_signals.list)
            alerting_dets = [
                d
                for d in _scoring_dets
                if not any(matches(pattern, d) for pattern in patterns)
            ]

    # Auto-create alerts for high-anomaly detections (skip disabled protocols)
    notifier = getattr(state, "notifier", None)
    with _Stage("anomaly_alerts", node_id):
        result["alerts_created"] += await _maybe_create_anomaly_alerts(
            app_state,
            persistence,
            alerting_dets,
            node_id,
            notifier=notifier,
        )

    # Evaluate condition-based alert rules against each detection
    with _Stage("alert_rules", node_id):
        result["alerts_created"] += await _evaluate_condition_rules(
            app_state,
            persistence,
            alerting_dets,
            node_id,
            notifier=notifier,
        )
    with _Stage("watch_bands", node_id):
        result["alerts_created"] += await _evaluate_watch_band_alerts(
            app_state, persistence, alerting_dets, notifier=notifier
        )

    return result


async def _insert_rf_anomalies(
    state: Any,
    app_state: AppState,
    store: Any,
    anomalous_dets: list[Any],
    sig_match_cache: dict[str, dict[str, Any]],
) -> None:
    """Score *anomalous_dets* and upsert them as ``rf_anomalies`` rows."""
    rf_scorer = getattr(state, "rf_scorer", None)
    rf_anomaly_dicts = []
    for det in anomalous_dets:
        d: dict[str, Any] = {
            "detection_id": det.detection_id,
            "signal_class": det.signal_class,
            "family": det.family,
            "freq_hz": det.freq_hz,
            "node_id": det.node_id,
            "timestamp": det.timestamp,
            "confidence": det.confidence,
            "snr_db": det.snr_db,
            "power_dbm": det.power_dbm,
            "anomaly_score": det.anomaly_score,
            "baseline_status": det.baseline_status,
        }
        if rf_scorer:
            try:
                # Inject cached signature match score into the record
                # BEFORE scoring so it flows through the scorer pipeline
                cached_sig = sig_match_cache.get(det.detection_id)
                if cached_sig is not None:
                    d["signature_match_score"] = cached_sig["match_score"]
                result = rf_scorer.score(d)
                d["priority"] = result.priority
                d["dimensions"] = result.dimensions
                d["reasons"] = list(result.reasons)
                # Enrich dimensions and metadata from cached match
                if cached_sig is not None:
                    d["dimensions"]["signature_match"] = cached_sig["match_score"]
                    d["reasons"].append(
                        f"Matches threat signature: {cached_sig['name']} "
                        f"({cached_sig.get('threat_category', 'unknown')})"
                    )
                    d["signature_match"] = {
                        "name": cached_sig["name"],
                        "threat_category": cached_sig.get("threat_category", ""),
                        "threat_level": cached_sig.get("threat_level", ""),
                        "match_score": cached_sig["match_score"],
                    }
            except Exception as exc:
                logger.warning(
                    "Scorer/signature enrichment failed for %s: %s",
                    det.detection_id,
                    exc,
                )
        rf_anomaly_dicts.append(d)
    # RF auto-snooze: if an anomaly has been seen many times with a
    # low score, it's a baseline signal — snooze it automatically.
    det_config = getattr(app_state, "_detection_config", None) or {}
    # Security: raised seen_count threshold from 10→100 and lowered
    # max_score from 0.55→0.3 to prevent premature auto-snooze of
    # genuine threats that recur at moderate anomaly scores.
    _rf_snooze_seen = int(det_config.get("rf_auto_snooze_seen_count", 100))
    _rf_snooze_score = float(det_config.get("rf_auto_snooze_max_score", 0.3))
    _rf_snooze_hours = int(det_config.get("rf_auto_snooze_hours", 24))
    await asyncio.to_thread(
        store.insert_rf_anomalies_batch,
        rf_anomaly_dicts,
        auto_snooze_seen_count=_rf_snooze_seen,
        auto_snooze_max_score=_rf_snooze_score,
        auto_snooze_hours=_rf_snooze_hours,
    )


# ---------------------------------------------------------------------------
# Raw ingest deprecation tracking
# ---------------------------------------------------------------------------

# Track which nodes use raw vs summary endpoints
_raw_ingest_nodes: dict[str, float] = {}  # node_id -> last_raw_ingest_time
_summary_ingest_nodes: dict[str, float] = {}  # node_id -> last_summary_ingest_time
_RAW_INGEST_MAX_ENTRIES = 500


def get_raw_ingest_nodes() -> dict[str, float]:
    """Return nodes still using raw batch ingest."""
    return dict(_raw_ingest_nodes)


def get_summary_ingest_nodes() -> dict[str, float]:
    """Return nodes using summary ingest."""
    return dict(_summary_ingest_nodes)


# ---------------------------------------------------------------------------
# POST /ingest-summary -- edge-pre-aggregated hourly summaries
# ---------------------------------------------------------------------------


@router.post("/ingest-summary", status_code=status.HTTP_201_CREATED)
async def ingest_detection_summary(
    request: Request,
    _key_id: str = Depends(require_role(Role.SENSOR)),
) -> dict[str, Any]:
    """Ingest pre-aggregated hourly detection summaries from an edge node.

    Preferred over /batch for nodes with MLRF_SUMMARIZE=1 enabled.
    Reduces write volume by ~45x compared to raw detection ingestion.

    The raw ``high_anomaly_detections`` are stored like ``/batch`` stores
    detections and run the same :func:`post_ingest` (alert rules, watch
    bands, anomaly alerts, webhooks, ...), once per detection: a
    detection already stored (an earlier snapshot of the same hour) is
    not processed again.  The gateway proxies this route to the bridge.
    """
    import gzip as _gzip
    import json as _json
    import zlib as _zlib

    raw_body = await request.body()
    if len(raw_body) > 1_048_576:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Request body exceeds 1MB limit",
        )

    if request.headers.get("content-encoding") == "gzip":
        try:
            from io import BytesIO as _BytesIO

            dec = _gzip.GzipFile(fileobj=_BytesIO(raw_body))
            raw_body = dec.read(50 * 1024 * 1024)
        except (OSError, ValueError, EOFError, _zlib.error):
            # EOFError: truncated stream; zlib.error: corrupt deflate
            # behind a valid header — client garbage, 400 not 500.
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to decompress gzip body",
            )

    try:
        payload = _json.loads(raw_body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON: {exc}",
        )

    versioned = isinstance(payload, dict) and "protocol" in payload
    if versioned:
        from sigrift.edge.summary_protocol import validate

        try:
            validate(payload)
        except (ValueError, TypeError, OverflowError, KeyError):
            raise HTTPException(status_code=422, detail="Invalid versioned RF summary")

    try:
        body = DetectionSummaryBatch(**payload)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    persistence = request.app.state.persistence
    store = _get_detection_store(request)
    app_state: AppState = request.app.state.app_state

    # Verify node registered
    nodes = persistence.get_nodes()
    if body.node_id not in nodes:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {body.node_id!r} not registered",
        )
    await enforce_node_binding(request, _key_id, body.node_id)

    # Track summary ingest usage
    _summary_ingest_nodes[body.node_id] = time.time()
    while len(_summary_ingest_nodes) > _RAW_INGEST_MAX_ENTRIES:
        oldest = min(_summary_ingest_nodes, key=_summary_ingest_nodes.get)
        del _summary_ingest_nodes[oldest]

    # Insert summaries
    summary_store = getattr(store, "_detection_summaries", None)
    inserted_summaries = 0
    summary_receipt = None
    if versioned and summary_store is None:
        raise HTTPException(status_code=503, detail="RF summary storage unavailable")
    if summary_store is not None:
        from sigrift.bridge.storage.detection_summaries import SummaryConflict

        try:
            if versioned:
                summary_receipt = await asyncio.to_thread(
                    summary_store.accept_snapshot, payload
                )
                inserted_summaries = len(body.summaries)
            else:
                summary_dicts = [s.model_dump() for s in body.summaries]
                inserted_summaries = await asyncio.to_thread(
                    summary_store.insert_summaries, body.node_id, summary_dicts
                )
        except SummaryConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    # High-anomaly raw detections go through the normal pipeline: stored
    # like /batch stores them, then the post-ingest work (alert rules,
    # watch bands, anomaly alerts, webhooks, edge-decoded messages, decode
    # jobs).  The edge re-sends the hour's high-anomaly detections with
    # every per-flush snapshot, so only the ones stored now — new to the
    # detections table, which every worker shares — run it.
    inserted_raw = 0
    alerts_created = 0
    if body.high_anomaly_detections:
        _normalize_detections(body.high_anomaly_detections, body.node_id)
        new_ids = await asyncio.to_thread(
            store.insert_batch_new_ids,
            body.high_anomaly_detections,
        )
        inserted_raw = len(new_ids)
        fresh = []
        for det in body.high_anomaly_detections:
            if det.detection_id in new_ids:
                new_ids.discard(det.detection_id)  # a repeat inside the body
                fresh.append(det)
        if fresh:
            fresh_ids = {det.detection_id for det in fresh}
            edge_decoded = {
                det_id: msgs
                for det_id, msgs in _extract_edge_decoded(
                    {
                        "node_id": body.node_id,
                        "detections": payload.get("high_anomaly_detections"),
                    }
                ).items()
                if det_id in fresh_ids
            }
            result = await post_ingest(
                request.app,
                fresh,
                body.node_id,
                edge_decoded,
                batch_id="summary",
            )
            alerts_created = result["alerts_created"]

    app_state.log_activity(
        event_type="detection_summary_batch",
        node_id=body.node_id,
        message=f"Summary: {inserted_summaries} hourly bins, {inserted_raw} high-anomaly raw",
    )

    result = {
        "inserted_summaries": inserted_summaries,
        "inserted_raw": inserted_raw,
        "alerts_created": alerts_created,
    }
    if summary_receipt is not None:
        result["summary_receipt"] = summary_receipt
    return result


# ---------------------------------------------------------------------------
# GET /ingest-status -- raw vs summary ingest node tracking
# ---------------------------------------------------------------------------


@router.get("/ingest-status")
async def get_ingest_status(
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return nodes using raw batch ingest vs summary ingest."""
    return {
        "raw_ingest_nodes": get_raw_ingest_nodes(),
        "summary_ingest_nodes": get_summary_ingest_nodes(),
    }


# ---------------------------------------------------------------------------
# POST /query -- filtered detection query
# ---------------------------------------------------------------------------


@router.post("/query")
async def query_detections(
    body: DetectionQuery,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Query stored detections with filters."""
    store = _get_detection_store(request)
    results = await asyncio.to_thread(store.query, body)
    return {
        "count": len(results),
        "detections": results,
    }


# ---------------------------------------------------------------------------
# GET /recent -- recent detections
# ---------------------------------------------------------------------------


@router.get("/recent")
async def get_recent(
    request: Request,
    minutes: int = Query(5, ge=1, le=10080),
    node_id: str | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return recent detections within a time window."""
    store = _get_detection_store(request)
    results = await asyncio.to_thread(
        store.get_recent, minutes=minutes, node_id=node_id, limit=limit
    )
    return {
        "count": len(results),
        "minutes": minutes,
        "detections": results,
    }


# ---------------------------------------------------------------------------
# GET /count -- total row count
# ---------------------------------------------------------------------------


@router.get("/count")
async def get_count(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, int]:
    """Return total number of raw detection rows."""
    store = _get_detection_store(request)
    total = await asyncio.to_thread(store.row_count)
    return {"total": total}


# ---------------------------------------------------------------------------
# GET /{detection_id} -- single detection with fingerprint enrichment
# ---------------------------------------------------------------------------


@router.get("/{detection_id}")
async def get_detection(
    detection_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return a single detection by ID, enriched with fingerprint data if available."""
    store = _get_detection_store(request)
    detection = await asyncio.to_thread(store.get_detection_by_id, detection_id)
    if detection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection {detection_id!r} not found",
        )

    # Enrich with fingerprint info if available
    fingerprint_store = getattr(request.app.state, "fingerprint_store", None)
    if fingerprint_store is not None:
        try:
            fp = fingerprint_store.get_by_detection(detection_id)
            if fp is not None:
                detection["fingerprint_id"] = fp.get("id")
                detection["fingerprint_embedding"] = fp.get("embedding")
        except Exception:
            pass

    return detection


# ---------------------------------------------------------------------------
# WebSocket: real-time detection stream
# ---------------------------------------------------------------------------


@router.websocket("/ws/feed")
async def ws_detections(websocket: WebSocket) -> None:
    """Stream detection events to authenticated WebSocket clients."""
    key_id, subprotocol = await require_ws_auth(websocket)
    if subprotocol:
        await websocket.accept(subprotocol=subprotocol)
    else:
        await websocket.accept()

    app_state: AppState = websocket.app.state.app_state
    await app_state.ws_detection_clients.add(websocket)
    logger.info("Detection WS client connected: %s", key_id)

    try:
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                continue
            if data == "ping":
                await websocket.send_text("pong")
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        await app_state.ws_detection_clients.remove(websocket)
        client_ip = getattr(websocket.state, "ws_client_ip", None)
        if client_ip:
            get_ws_limiter().release(client_ip)
        logger.info("Detection WS client disconnected: %s", key_id)


# ---------------------------------------------------------------------------
# WebSocket: real-time anomaly stream
# ---------------------------------------------------------------------------


@router.websocket("/ws/anomalies")
async def ws_anomalies(websocket: WebSocket) -> None:
    """Stream anomaly events to authenticated WebSocket clients."""
    key_id, subprotocol = await require_ws_auth(websocket)
    if subprotocol:
        await websocket.accept(subprotocol=subprotocol)
    else:
        await websocket.accept()

    app_state: AppState = websocket.app.state.app_state
    await app_state.ws_anomaly_clients.add(websocket)
    logger.info("Anomaly WS client connected: %s", key_id)

    try:
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                continue
            if data == "ping":
                await websocket.send_text("pong")
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        await app_state.ws_anomaly_clients.remove(websocket)
        client_ip = getattr(websocket.state, "ws_client_ip", None)
        if client_ip:
            get_ws_limiter().release(client_ip)
        logger.info("Anomaly WS client disconnected: %s", key_id)


# ---------------------------------------------------------------------------
# Broadcast helpers
# ---------------------------------------------------------------------------


async def _broadcast_detections(
    app_state: AppState,
    data: dict[str, Any],
) -> None:
    """Push detection event to all connected detection WS clients."""
    await app_state.ws_detection_clients.broadcast(data)


async def _broadcast_anomalies(
    app_state: AppState,
    data: dict[str, Any],
) -> None:
    """Push anomaly event to all connected anomaly WS clients."""
    await app_state.ws_anomaly_clients.broadcast(data)
