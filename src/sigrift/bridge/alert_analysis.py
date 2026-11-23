"""Alert analysis: which alert types and RF frequencies recur, and what is open.

Groups the bridge's retained alerts (at most ``MAX_ALERTS``) two ways:

* by alert type (the alert ``name``), for every alert;
* by node and 100 kHz frequency bucket, for alerts produced by the RF
  post-ingest path whose linked detection still exists.

Each frequency group carries a suggested known RF pattern covering its bucket.
Saving that pattern uses the normal known-pattern store (audited, tenant
scoped), so it suppresses future matching alerts only; acknowledging the open
alerts it covers is a separate, explicit choice. Nothing here changes
detections, scores or alert history.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException

from sigrift.bridge.known_signals import detection_target, rf_alert_detection_ref
from sigrift.bridge.storage.known_signals import matches

BUCKET_HZ = 100_000
MAX_LISTED_NODES = 10
MAX_LISTED_NAMES = 5
MAX_ACK_IDS_RETURNED = 500


def parse_time(value: Any) -> datetime | None:
    """An aware UTC datetime for an alert timestamp, or ``None``."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class RFTargets:
    """Look up each linked RF detection once per request."""

    def __init__(self, store):
        self._store = store
        self._cache: dict[str, dict[str, Any] | None] = {}

    def for_alert(self, alert: dict[str, Any]) -> dict[str, Any] | None:
        """``{"freq_hz", "signal_class", "node_id"}`` for an RF alert, else ``None``."""
        detection_id = rf_alert_detection_ref(alert)
        if detection_id is None or self._store is None:
            return None
        if detection_id not in self._cache:
            try:
                target = detection_target(self._store, detection_id)
            except HTTPException:
                self._cache[detection_id] = None
            else:
                self._cache[detection_id] = {
                    "freq_hz": target["freq_hz"],
                    "signal_class": target["defaults"]["signal_class"],
                    "node_id": target["defaults"]["node_id"],
                }
        return self._cache[detection_id]


def _later(current: str | None, candidate: datetime | None) -> str | None:
    if candidate is None:
        return current
    if current is None or candidate > parse_time(current):
        return candidate.isoformat()
    return current


def _top(counter: Counter, key: str, limit: int) -> list[dict[str, Any]]:
    return [{key: value, "count": n} for value, n in counter.most_common(limit)]


def analyse(
    alerts: list[dict[str, Any]],
    targets: RFTargets,
    patterns: list[dict[str, Any]],
    *,
    hours: int | None,
    include_acknowledged: bool,
    limit: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Group alerts by type and by RF frequency bucket; most frequent first."""
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=hours) if hours else None

    types: dict[str, dict[str, Any]] = {}
    freqs: dict[tuple[str, int], dict[str, Any]] = {}
    considered = 0
    unlinked_open = 0

    for alert in alerts:
        acknowledged = alert.get("acknowledged") is True
        if acknowledged and not include_acknowledged:
            continue
        triggered = parse_time(alert.get("triggered_at"))
        if cutoff is not None and (triggered is None or triggered < cutoff):
            continue
        considered += 1
        is_open = not acknowledged
        name = alert.get("name") or "unnamed"

        kind = types.setdefault(
            name,
            {
                "name": name,
                "count": 0,
                "open": 0,
                "severities": Counter(),
                "nodes": Counter(),
                "frequencies": Counter(),
                "latest": None,
            },
        )
        kind["count"] += 1
        kind["open"] += is_open
        kind["severities"][str(alert.get("severity") or "info").lower()] += 1
        if alert.get("node_id"):
            kind["nodes"][alert["node_id"]] += 1
        kind["latest"] = _later(kind["latest"], triggered)

        target = targets.for_alert(alert)
        if target is None:
            unlinked_open += is_open
            continue
        bucket = int(target["freq_hz"] // BUCKET_HZ)
        kind["frequencies"][(target["node_id"], bucket)] += 1
        group = freqs.setdefault(
            (target["node_id"], bucket),
            {
                "node_id": target["node_id"],
                "bucket": bucket,
                "count": 0,
                "open": 0,
                "classes": Counter(),
                "alert_types": Counter(),
                "freq_min_hz": target["freq_hz"],
                "freq_max_hz": target["freq_hz"],
                "latest": None,
                "members": [],
            },
        )
        group["count"] += 1
        group["open"] += is_open
        group["classes"][target["signal_class"]] += 1
        group["alert_types"][name] += 1
        group["freq_min_hz"] = min(group["freq_min_hz"], target["freq_hz"])
        group["freq_max_hz"] = max(group["freq_max_hz"], target["freq_hz"])
        group["latest"] = _later(group["latest"], triggered)
        group["members"].append(target)

    def order(group):
        return (-group["open"], -group["count"], group["latest"] or "")

    frequency_rows = []
    for group in sorted(freqs.values(), key=order)[:limit]:
        classes = group["classes"]
        suggestion = {
            "freq_min_hz": group["bucket"] * BUCKET_HZ,
            "freq_max_hz": (group["bucket"] + 1) * BUCKET_HZ,
            "signal_class": next(iter(classes)) if len(classes) == 1 else "*",
            "node_id": group["node_id"],
        }
        covered_by = [
            p["pattern_id"]
            for p in patterns
            if all(matches(p, member) for member in group["members"])
        ]
        frequency_rows.append(
            {
                "node_id": group["node_id"],
                "freq_min_hz": group["freq_min_hz"],
                "freq_max_hz": group["freq_max_hz"],
                "count": group["count"],
                "open": group["open"],
                "classes": _top(classes, "signal_class", len(classes)),
                "alert_types": _top(group["alert_types"], "name", MAX_LISTED_NAMES),
                "latest": group["latest"],
                "suggested_pattern": suggestion,
                "covered_by": covered_by,
            }
        )

    type_rows = []
    for kind in sorted(types.values(), key=order)[:limit]:
        type_rows.append(
            {
                "name": kind["name"],
                "count": kind["count"],
                "open": kind["open"],
                "severities": dict(kind["severities"]),
                "nodes": _top(kind["nodes"], "node_id", MAX_LISTED_NODES),
                "top_frequencies": [
                    {
                        "node_id": node_id,
                        "freq_min_hz": bucket * BUCKET_HZ,
                        "freq_max_hz": (bucket + 1) * BUCKET_HZ,
                        "count": n,
                    }
                    for (node_id, bucket), n in kind["frequencies"].most_common(3)
                ],
                "latest": kind["latest"],
            }
        )

    return {
        "window_hours": hours,
        "include_acknowledged": include_acknowledged,
        "alerts_considered": considered,
        "unlinked_open": unlinked_open,
        "bucket_hz": BUCKET_HZ,
        "alert_types": type_rows,
        "alert_types_total": len(types),
        "frequencies": frequency_rows,
        "frequencies_total": len(freqs),
    }


def covered_open_alerts(
    alerts: list[dict[str, Any]], targets: RFTargets, pattern: dict[str, Any]
) -> list[str]:
    """Ids of unacknowledged RF alerts whose linked detection the pattern matches."""
    covered = []
    for alert in alerts:
        if alert.get("acknowledged") is True or not alert.get("alert_id"):
            continue
        target = targets.for_alert(alert)
        if target is not None and matches(pattern, target):
            covered.append(alert["alert_id"])
    return covered
