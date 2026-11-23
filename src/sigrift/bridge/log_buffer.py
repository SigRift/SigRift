"""In-memory ring buffer log handler and structured JSON formatter.

Captures recent log entries in a bounded deque so the admin panel
can display them without needing file access or external log services.

Set BRIDGE_LOG_FORMAT=json to enable structured JSON logging on stdout.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any


class LogBuffer(logging.Handler):
    """Log handler that stores entries in a thread-safe ring buffer.

    Parameters
    ----------
    max_entries : int
        Maximum number of log entries to retain.
    """

    def __init__(self, max_entries: int = 5000) -> None:
        super().__init__()
        self._entries: deque[dict[str, Any]] = deque(maxlen=max_entries)
        self._lock = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        entry = {
            "timestamp": self.format_time(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            entry["exception"] = (
                self.format(record).split("\n", 1)[-1]
                if record.exc_text
                else str(record.exc_info[1])
            )
        with self._lock:
            self._entries.append(entry)

    @staticmethod
    def format_time(record: logging.LogRecord) -> str:
        from datetime import datetime, timezone

        return datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()

    def get_entries(
        self,
        limit: int = 200,
        level: str | None = None,
        search: str | None = None,
        logger_name: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return recent entries, newest first, with optional filters."""
        with self._lock:
            entries = list(self._entries)

        # Apply filters
        if level:
            level_upper = level.upper()
            entries = [e for e in entries if e["level"] == level_upper]
        if logger_name:
            entries = [e for e in entries if e.get("logger", "") == logger_name]
        if search:
            search_lower = search.lower()
            entries = [
                e
                for e in entries
                if search_lower in e["message"].lower()
                or search_lower in e.get("logger", "").lower()
            ]

        # Return newest first, limited
        return list(reversed(entries))[:limit]

    def get_loggers(self) -> list[str]:
        """Return distinct logger names in the buffer, sorted."""
        with self._lock:
            return sorted({e.get("logger", "") for e in self._entries} - {""})

    def size(self) -> int:
        with self._lock:
            return len(self._entries)


# Singleton
_buffer: LogBuffer | None = None


class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter for production observability.

    Outputs one JSON object per line with: timestamp, level, logger,
    message, module, function, line, and optional exception, request
    context, and extra fields.
    """

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info and record.exc_info[1]:
            entry["exception"] = self.formatException(record.exc_info)
        # Include request context fields when available
        for key in (
            "request_id",
            "method",
            "path",
            "status_code",
            "duration_ms",
        ):
            val = getattr(record, key, None)
            if val is not None:
                entry[key] = val
        # Include extra fields passed via logger.info("msg", extra={...})
        for key in ("run_id", "node_id", "action", "operator", "details"):
            val = getattr(record, key, None)
            if val is not None:
                entry[key] = val
        return json.dumps(entry, default=str)


def init_log_buffer(max_entries: int = 5000) -> LogBuffer:
    """Initialize the global log buffer and attach to root logger.

    If BRIDGE_LOG_FORMAT=json, also configures structured JSON output
    on the root logger's stream handler for production observability.
    """
    global _buffer
    _buffer = LogBuffer(max_entries=max_entries)
    _buffer.setLevel(logging.DEBUG)
    root = logging.getLogger()
    root.addHandler(_buffer)

    if os.environ.get("BRIDGE_LOG_FORMAT", "").lower() == "json":
        json_fmt = JSONFormatter()
        for handler in root.handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(
                handler, LogBuffer
            ):
                handler.setFormatter(json_fmt)
        # If no stream handler exists, add one
        if not any(
            isinstance(h, logging.StreamHandler) and not isinstance(h, LogBuffer)
            for h in root.handlers
        ):
            sh = logging.StreamHandler()
            sh.setFormatter(json_fmt)
            sh.setLevel(logging.INFO)
            root.addHandler(sh)

    return _buffer


def get_log_buffer() -> LogBuffer:
    """Return the global log buffer, initializing if needed."""
    global _buffer
    if _buffer is None:
        _buffer = init_log_buffer()
    return _buffer
