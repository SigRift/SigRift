"""Central in-memory ephemeral state shared across all routers.

Persistent data (nodes, keys, alerts, jobs, schedules) lives in
``PersistenceManager``.  This module holds only ephemeral runtime
state: WebSocket clients, sessions, rate limiting, and activity log.

Injected via ``app.state.app_state`` for testability.
"""

from __future__ import annotations

import asyncio
import html
import logging
import secrets
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from sigrift.lib.shiny.models import NodeStatus
from sigrift.lib.shiny.node_metrics import status_from_last_seen, stored_metric

if TYPE_CHECKING:
    from sigrift.lib.shiny.persistence import PersistenceManager

logger = logging.getLogger(__name__)


class WebSocketClientSet:
    """Async-safe collection of WebSocket clients with broadcast support."""

    def __init__(self) -> None:
        self._clients: set = set()
        self._lock = asyncio.Lock()

    async def add(self, ws: Any) -> None:
        async with self._lock:
            self._clients.add(ws)

    async def remove(self, ws: Any) -> None:
        async with self._lock:
            self._clients.discard(ws)

    async def broadcast(self, data: Any) -> None:
        async with self._lock:
            snapshot = list(self._clients)
        disconnected: list = []
        for ws in snapshot:
            try:
                if isinstance(data, dict):
                    await ws.send_json(data)
                else:
                    await ws.send_text(data)
            except Exception:
                disconnected.append(ws)
        if disconnected:
            async with self._lock:
                for ws in disconnected:
                    self._clients.discard(ws)

    def snapshot(self) -> list:
        return list(self._clients)

    def __len__(self) -> int:
        return len(self._clients)

    def __bool__(self) -> bool:
        return bool(self._clients)


def _ws_set_factory() -> WebSocketClientSet:
    return WebSocketClientSet()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class AppState:
    """Ephemeral runtime state shared across all routers.

    Persistent data is delegated to ``PersistenceManager`` via
    ``app.state.persistence``.  This class holds WebSocket client
    sets, sessions, rate limiting, and the activity log.
    """

    # Session auth  --  {token: {"key_id": ..., "expires": ...}}
    sessions: dict[str, dict[str, Any]] = field(default_factory=dict)

    # Activity log (bounded ring buffer)
    activity_log: deque = field(default_factory=lambda: deque(maxlen=1000))

    # Pending commands per node  --  {node_id: [cmd_dict, ...]}
    pending_commands: dict[str, list[dict]] = field(default_factory=dict)

    # WebSocket client sets (not serialized, async-safe)
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

    # Startup timestamp
    started_at: datetime = field(default_factory=_utcnow)

    # Alert counter (restored from persistence on startup)
    _alert_counter: int = field(default=0, repr=False)

    # -----------------------------------------------------------------------
    # Session management
    # -----------------------------------------------------------------------

    def create_session(self, key_id: str, ttl_hours: float = 8.0) -> str:
        """Create session token for browser-based auth.

        Returns the raw session token (set as httponly cookie).
        """
        token = secrets.token_urlsafe(32)
        now = _utcnow()
        self.sessions[token] = {
            "key_id": key_id,
            "created": now.isoformat(),
            "expires": (now + timedelta(hours=ttl_hours)).isoformat(),
        }
        return token

    def validate_session(self, token: str) -> str | None:
        """Validate session token.  Returns key_id or None."""
        sess = self.sessions.get(token)
        if sess is None:
            return None
        expires = datetime.fromisoformat(sess["expires"])
        if _utcnow() > expires:
            del self.sessions[token]
            return None
        return sess["key_id"]

    def destroy_session(self, token: str) -> None:
        """Remove session token."""
        self.sessions.pop(token, None)

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

        Active under 60 s, stale under 120 s, then offline.  A missing or
        unreadable ``last_seen``, or one more than a minute ahead of the
        server's clock, is unknown (never an error).
        """
        return status_from_last_seen(
            node_data.get("last_seen"),
            _utcnow(),
            active_seconds=60,
            stale_seconds=120,
        )

    # -----------------------------------------------------------------------
    # Alert threshold checking
    # -----------------------------------------------------------------------

    def check_node_alerts(
        self,
        node_id: str,
        node_data: dict,
        persistence: PersistenceManager,
    ) -> None:
        """Check node metrics against alert rules and create alerts."""
        persistence.get_alerts()  # Rules stored alongside alerts
        # Simple threshold checking for core metrics
        # Read through the metric checks: a record saved before heartbeat
        # metrics were checked can hold a value of another type.
        disk = stored_metric(node_data, "disk_percent")
        if disk is not None and disk > 90:
            existing = [
                a
                for a in persistence.get_alerts()
                if a.get("name") == "disk_high"
                and a.get("node_id") == node_id
                and not a.get("acknowledged")
            ]
            if not existing:
                alert = {
                    "alert_id": self.next_alert_id(),
                    "name": "disk_high",
                    "severity": "critical",
                    "message": html.escape(f"Disk usage {disk:.1f}% on {node_id}"),
                    "node_id": node_id,
                    "triggered_at": _utcnow().isoformat(),
                    "acknowledged": False,
                    "acknowledged_at": None,
                }
                persistence.add_alert(alert)

        mem = stored_metric(node_data, "mem_percent")
        if mem is not None and mem > 95:
            existing = [
                a
                for a in persistence.get_alerts()
                if a.get("name") == "memory_high"
                and a.get("node_id") == node_id
                and not a.get("acknowledged")
            ]
            if not existing:
                alert = {
                    "alert_id": self.next_alert_id(),
                    "name": "memory_high",
                    "severity": "critical",
                    "message": html.escape(f"Memory usage {mem:.1f}% on {node_id}"),
                    "node_id": node_id,
                    "triggered_at": _utcnow().isoformat(),
                    "acknowledged": False,
                    "acknowledged_at": None,
                }
                persistence.add_alert(alert)

        gpu_temp = stored_metric(node_data, "gpu_temp")
        if gpu_temp is not None:
            temp_val = gpu_temp
            if isinstance(gpu_temp, str) and "\u00b0C" in gpu_temp:
                try:
                    temp_val = int(gpu_temp.replace("\u00b0C", ""))
                except ValueError:
                    temp_val = None
            if isinstance(temp_val, (int, float)) and temp_val > 85:
                existing = [
                    a
                    for a in persistence.get_alerts()
                    if a.get("name") == "gpu_temp_high"
                    and a.get("node_id") == node_id
                    and not a.get("acknowledged")
                ]
                if not existing:
                    alert = {
                        "alert_id": self.next_alert_id(),
                        "name": "gpu_temp_high",
                        "severity": "warning",
                        "message": html.escape(
                            f"GPU temp {temp_val}\u00b0C on {node_id}"
                        ),
                        "node_id": node_id,
                        "triggered_at": _utcnow().isoformat(),
                        "acknowledged": False,
                        "acknowledged_at": None,
                    }
                    persistence.add_alert(alert)
