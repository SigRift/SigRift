"""Central in-memory ephemeral state shared across all Bridge routers.

Persistent data (nodes, keys, alerts, jobs, schedules) lives in
``PersistenceManager``.  Detection data lives in ``DetectionStore``.
This module holds only ephemeral runtime state: WebSocket clients,
sessions, rate limiting, and activity log.

Adapted from sigrift.lib.shiny.state with detection-specific additions.
Injected via ``app.state.app_state`` for testability.
"""

from __future__ import annotations

import asyncio
import html
import logging
import secrets
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sigrift.lib.shiny.models import NodeStatus
from sigrift.lib.shiny.node_metrics import (
    parse_timestamp,
    status_from_last_seen,
    stored_metric,
)
from sigrift.bridge.utils import BoundedDict, utcnow

if TYPE_CHECKING:
    from sigrift.bridge.dependencies import WSConnectionLimiter
    from sigrift.bridge.persistence import PersistenceManager

_utcnow = utcnow

logger = logging.getLogger(__name__)


class WebSocketClientSet:
    """Async-safe set of WebSocket connections with broadcast support.

    Uses a set for O(1) add/discard and an asyncio.Lock to prevent
    concurrent modification during iteration (broadcast loops).

    Supports ``len()``, ``bool()``, ``in``, and iteration so existing
    code that reads ``.ws_*_clients`` keeps working.
    """

    __slots__ = ("_clients", "_lock")

    def __init__(self) -> None:
        self._clients: set = set()
        self._lock = asyncio.Lock()

    # -- Collection protocol --------------------------------------------------

    def __len__(self) -> int:
        return len(self._clients)

    def __bool__(self) -> bool:
        return bool(self._clients)

    def __contains__(self, item: object) -> bool:
        return item in self._clients

    def __iter__(self):
        return iter(list(self._clients))

    # -- Async mutators -------------------------------------------------------

    async def add(self, ws: Any) -> None:
        async with self._lock:
            self._clients.add(ws)

    async def remove(self, ws: Any) -> None:
        async with self._lock:
            self._clients.discard(ws)

    async def broadcast(self, data: Any) -> None:
        async with self._lock:
            snapshot = list(self._clients)
        if not snapshot:
            return

        async def _send(ws: Any) -> Any | None:
            try:
                if isinstance(data, dict):
                    await asyncio.wait_for(ws.send_json(data), timeout=5.0)
                else:
                    await asyncio.wait_for(ws.send_text(data), timeout=5.0)
                return None
            except Exception:
                return ws

        results = await asyncio.gather(*[_send(ws) for ws in snapshot])
        disconnected = [ws for ws in results if ws is not None]
        if disconnected:
            async with self._lock:
                for ws in disconnected:
                    self._clients.discard(ws)

    def snapshot(self) -> list:
        """Return a point-in-time copy safe for iteration during broadcast."""
        return list(self._clients)


def _ws_set_factory() -> WebSocketClientSet:
    return WebSocketClientSet()


@dataclass
class AppState:
    """Ephemeral runtime state shared across all Bridge routers.

    Persistent data is delegated to ``PersistenceManager`` via
    ``app.state.persistence``.  Detection storage is handled by
    ``DetectionStore`` via ``app.state.detection_store``.

    This class holds WebSocket client sets, sessions, rate limiting,
    and the activity log.
    """

    # Session auth  --  {token: {"key_id": ..., "expires": ...}}
    sessions: dict[str, dict[str, Any]] = field(default_factory=dict)

    # Activity log (bounded ring buffer)
    activity_log: deque = field(default_factory=lambda: deque(maxlen=1000))

    # Pending commands per node  --  {node_id: [cmd_dict, ...]}
    pending_commands: dict[str, list[dict]] = field(default_factory=dict)

    # Command history (ring buffer) — tracks queued, dispatched, completed
    command_history: deque = field(default_factory=lambda: deque(maxlen=200))

    # WebSocket client sets — inherited from shiny
    ws_status_clients: WebSocketClientSet = field(
        default_factory=_ws_set_factory, repr=False
    )
    ws_alert_clients: WebSocketClientSet = field(
        default_factory=_ws_set_factory, repr=False
    )
    ws_activity_clients: WebSocketClientSet = field(
        default_factory=_ws_set_factory, repr=False
    )
    ws_spectrum_clients: WebSocketClientSet = field(
        default_factory=_ws_set_factory, repr=False
    )
    ws_training_clients: WebSocketClientSet = field(
        default_factory=_ws_set_factory, repr=False
    )

    # WebSocket client sets — detection-specific (The Bridge)
    ws_detection_clients: WebSocketClientSet = field(
        default_factory=_ws_set_factory, repr=False
    )
    ws_anomaly_clients: WebSocketClientSet = field(
        default_factory=_ws_set_factory, repr=False
    )
    ws_spectrum_monitor_clients: WebSocketClientSet = field(
        default_factory=_ws_set_factory, repr=False
    )
    ws_bluetooth_clients: WebSocketClientSet = field(
        default_factory=_ws_set_factory, repr=False
    )
    ws_wifi_clients: WebSocketClientSet = field(
        default_factory=_ws_set_factory, repr=False
    )

    # WebSocket connection rate limiter
    ws_limiter: WSConnectionLimiter | None = field(default=None, repr=False)

    # Dismissed anomaly IDs (ephemeral, survives until server restart)
    dismissed_anomalies: set = field(default_factory=set, repr=False)

    # Anomaly alert cooldowns  --  {(node_id, freq_bucket): last_alert_timestamp}
    anomaly_alert_cooldowns: dict[tuple[str, int], float] = field(
        default_factory=lambda: BoundedDict(max_size=50_000),
        repr=False,
    )

    # Condition-based alert rule cooldowns  --  {rule_id: last_trigger_monotonic}
    rule_cooldowns: dict[str, float] = field(
        default_factory=lambda: BoundedDict(max_size=10_000),
        repr=False,
    )

    # Watch band cooldowns  --  {watch_id: last_trigger_monotonic}
    watch_band_cooldowns: dict[str, float] = field(
        default_factory=lambda: BoundedDict(max_size=10_000),
        repr=False,
    )

    # Watch band detection counts  --  {watch_id: [(timestamp_monotonic, det_id), ...]}
    watch_band_counts: dict[str, list[tuple[float, str]]] = field(
        default_factory=lambda: BoundedDict(max_size=10_000),
        repr=False,
    )

    # Startup timestamp
    started_at: datetime = field(default_factory=_utcnow)

    # Maintenance job log (bounded ring buffer)
    job_log: deque = field(default_factory=lambda: deque(maxlen=100))

    # Alert counter (restored from persistence on startup)
    _alert_counter: int = field(default=0, repr=False)

    # -----------------------------------------------------------------------
    # Job tracking
    # -----------------------------------------------------------------------

    def start_job(self, task: str, trigger: str = "manual") -> dict:
        """Record a maintenance job start. Returns the job dict."""
        job = {
            "id": secrets.token_hex(4),
            "task": task,
            "trigger": trigger,  # "manual", "scheduled", "api"
            "status": "running",
            "started_at": _utcnow().isoformat(),
            "finished_at": None,
            "duration_s": None,
            "result": None,
            "error": None,
        }
        self.job_log.append(job)
        return job

    def finish_job(
        self,
        job: dict,
        result: dict | None = None,
        error: str | None = None,
    ) -> None:
        """Mark a job as completed or failed."""
        now = _utcnow()
        job["finished_at"] = now.isoformat()
        started = datetime.fromisoformat(job["started_at"])
        job["duration_s"] = round((now - started).total_seconds(), 1)
        if error:
            job["status"] = "failed"
            job["error"] = error
        else:
            job["status"] = "completed"
            job["result"] = result

    # -----------------------------------------------------------------------
    # Session management
    # -----------------------------------------------------------------------

    #: Default idle timeout in minutes (NIST 800-63B).
    #: Override via BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES env var.
    _IDLE_TIMEOUT_MINUTES: int = 30

    def create_session(self, key_id: str, ttl_hours: float = 8.0) -> str:
        """Deprecated: sessions consolidated to SQLite via UserStore."""
        logger.warning(
            "AppState.create_session() called — sessions are now SQLite-only"
        )
        return ""

    def validate_session(self, token: str) -> str | None:
        """Deprecated: sessions consolidated to SQLite via UserStore."""
        return None

    def destroy_session(self, token: str) -> None:
        """Deprecated: sessions consolidated to SQLite via UserStore."""
        pass

    # -----------------------------------------------------------------------
    # Activity logging
    # -----------------------------------------------------------------------

    def log_activity(
        self,
        event_type: str,
        node_id: str | None = None,
        message: str = "",
        details: dict | None = None,
    ) -> dict:
        """Log a sanitized activity event and return it."""
        event = {
            "timestamp": _utcnow().isoformat(),
            "event_type": html.escape(str(event_type)),
            "node_id": html.escape(str(node_id)) if node_id else None,
            "message": html.escape(str(message)),
            "details": details or {},
        }
        self.activity_log.append(event)
        return event

    # -----------------------------------------------------------------------
    # Alert helpers (uses PersistenceManager for storage)
    # -----------------------------------------------------------------------

    def next_alert_id(self) -> str:
        self._alert_counter += 1
        return f"alert_{self._alert_counter}"

    def restore_alert_counter(self, persistence: PersistenceManager) -> None:
        """Set alert counter from persisted alerts."""
        alerts = persistence.get_alerts()
        max_id = 0
        for a in alerts:
            aid = a.get("alert_id", "")
            if isinstance(aid, str) and aid.startswith("alert_"):
                try:
                    num = int(aid.split("_")[1])
                    if num > max_id:
                        max_id = num
                except (IndexError, ValueError):
                    pass
        self._alert_counter = max_id

    # -----------------------------------------------------------------------
    # Node status
    # -----------------------------------------------------------------------

    @staticmethod
    def get_node_status(node_data: dict) -> NodeStatus:
        """Compute current status of a node based on last_seen.

        Active under 120 s, stale under 300 s, then offline.  A missing or
        unreadable ``last_seen``, or one more than a minute ahead of the
        server's clock, is unknown: never an error, so one bad stored record
        cannot fail a node listing, ``/api/status`` or start-up.
        """
        return status_from_last_seen(
            node_data.get("last_seen"),
            _utcnow(),
            active_seconds=120,
            stale_seconds=300,
        )

    # -----------------------------------------------------------------------
    # Alert threshold checking
    # -----------------------------------------------------------------------

    def _create_alert_if_new(
        self,
        name: str,
        severity: str,
        message: str,
        node_id: str,
        persistence: PersistenceManager,
    ) -> bool:
        """Create an alert if no unacknowledged alert with this name+node exists."""
        existing = [
            a
            for a in persistence.get_alerts()
            if a.get("name") == name
            and a.get("node_id") == node_id
            and not a.get("acknowledged")
        ]
        if existing:
            return False
        persistence.add_alert(
            {
                "alert_id": self.next_alert_id(),
                "name": name,
                "severity": severity,
                "message": html.escape(message),
                "node_id": node_id,
                "triggered_at": _utcnow().isoformat(),
                "acknowledged": False,
                "acknowledged_at": None,
            }
        )
        return True

    def check_node_alerts(
        self,
        node_id: str,
        node_data: dict,
        persistence: PersistenceManager,
    ) -> None:
        """Check node metrics against built-in thresholds and user-defined rules.

        Metrics are read through their checks (``node_metrics``): a record
        saved before heartbeat metrics were checked can hold a value of
        another type, which reads as not reported.
        """
        # -- Built-in hard limits (always active) --
        disk = stored_metric(node_data, "disk_percent")
        if disk is not None and disk > 90:
            self._create_alert_if_new(
                "disk_high",
                "critical",
                f"Disk usage {disk:.1f}% on {node_id}",
                node_id,
                persistence,
            )

        mem = stored_metric(node_data, "mem_percent")
        if mem is not None and mem > 95:
            self._create_alert_if_new(
                "memory_high",
                "critical",
                f"Memory usage {mem:.1f}% on {node_id}",
                node_id,
                persistence,
            )

        gpu_temp = stored_metric(node_data, "gpu_temp")
        if gpu_temp is not None:
            temp_val = gpu_temp
            if isinstance(gpu_temp, str) and "\u00b0C" in gpu_temp:
                try:
                    temp_val = int(gpu_temp.replace("\u00b0C", ""))
                except ValueError:
                    temp_val = None
            if isinstance(temp_val, (int, float)) and temp_val > 85:
                self._create_alert_if_new(
                    "gpu_temp_high",
                    "warning",
                    f"GPU temp {temp_val}\u00b0C on {node_id}",
                    node_id,
                    persistence,
                )

        # -- User-defined alert rules (from /api/alerts/rules) --
        self._evaluate_user_rules(node_id, node_data, persistence)

    def _evaluate_user_rules(
        self,
        node_id: str,
        node_data: dict,
        persistence: PersistenceManager,
    ) -> None:
        """Evaluate user-created alert rules against current node metrics."""
        alerts = persistence.get_alerts()
        rules = [a for a in alerts if a.get("is_rule") or a.get("thresholds")]

        # Map node metrics to threshold keys
        cpu = stored_metric(node_data, "cpu_percent")
        mem_mb = stored_metric(node_data, "memory_mb")
        disk = stored_metric(node_data, "disk_percent")
        gpu = stored_metric(node_data, "gpu_percent")
        cls_rate = stored_metric(node_data, "classifications_per_sec") or 0

        last_seen = parse_timestamp(node_data.get("last_seen"))
        stale_seconds = 0.0
        if last_seen is not None:
            stale_seconds = (_utcnow() - last_seen).total_seconds()

        for rule in rules:
            # Skip rules targeting a different node
            rule_node = rule.get("node_id")
            if rule_node and rule_node != node_id:
                continue

            thresholds = rule.get("thresholds", {})
            if not thresholds:
                continue

            rule_name = rule.get("name", rule.get("alert_id", "rule"))
            severity = rule.get("severity", "warning")
            violations: list[str] = []

            t = thresholds.get("cpu_percent")
            if t is not None and cpu is not None and cpu > t:
                violations.append(f"CPU {cpu:.1f}% > {t}%")

            t = thresholds.get("memory_mb")
            if t is not None and mem_mb is not None and mem_mb > t:
                violations.append(f"Memory {mem_mb:.0f}MB > {t}MB")

            t = thresholds.get("disk_percent")
            if t is not None and disk is not None and disk > t:
                violations.append(f"Disk {disk:.1f}% > {t}%")

            t = thresholds.get("gpu_percent")
            if t is not None and gpu is not None and gpu > t:
                violations.append(f"GPU {gpu:.1f}% > {t}%")

            t = thresholds.get("classification_rate_min")
            if t is not None and t > 0 and cls_rate < t:
                violations.append(f"Classification rate {cls_rate:.1f}/s < {t}/s")

            t = thresholds.get("stale_timeout_s")
            if t is not None and t > 0 and stale_seconds > t:
                violations.append(f"Stale {stale_seconds:.0f}s > {t}s")

            if violations:
                msg = (
                    f"Rule '{rule_name}' violated on {node_id}: {'; '.join(violations)}"
                )
                self._create_alert_if_new(
                    f"rule_{rule_name}",
                    severity,
                    msg,
                    node_id,
                    persistence,
                )
