"""Durable, tenant-scoped operator rules that suppress only matching RF alerts.

These are deliberately separate from learned baselines and score calibration.
Every mutation and its audit event commit together; no in-memory rule cache can
hide a failed save or keep a removed rule active in another worker.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, model_validator

from sigrift.bridge.storage.audit import AuditStore
from sigrift.bridge.storage.base import SharedContext


class KnownSignalPattern(BaseModel):
    model_config = {"extra": "forbid", "allow_inf_nan": False}

    freq_min_hz: float = Field(ge=0, le=1e12)
    freq_max_hz: float = Field(gt=0, le=1e12)
    signal_class: str = Field(pattern=r"^(?:\*|[a-zA-Z0-9_/.-]{1,128})$")
    node_id: str | None = Field(default=None, min_length=1, max_length=128)
    note: str = Field(default="", max_length=500)

    @model_validator(mode="after")
    def ordered_range(self):
        if self.freq_min_hz >= self.freq_max_hz:
            raise ValueError("Minimum frequency must be less than maximum frequency")
        return self


def matches(pattern: dict[str, Any], detection: Any) -> bool:
    """Inclusive range and node; only explicit ``*`` ignores modulation class.

    Power is never part of a known-pattern match. Legacy classes remain exact.
    """
    get = (
        detection.get
        if isinstance(detection, dict)
        else lambda k: getattr(detection, k)
    )
    return (
        pattern["freq_min_hz"] <= get("freq_hz") <= pattern["freq_max_hz"]
        and (
            pattern["signal_class"] == "*"
            or pattern["signal_class"] == get("signal_class")
        )
        and (pattern["node_id"] is None or pattern["node_id"] == get("node_id"))
    )


class KnownSignalStore:
    def __init__(self, ctx: SharedContext):
        self._ctx = ctx
        self._audit = AuditStore(ctx)

    def list(self) -> list[dict[str, Any]]:
        rows = self._ctx.get_conn().execute(
            "SELECT * FROM known_rf_signals WHERE tenant_id = ? ORDER BY created_at, pattern_id",
            (self._ctx.tenant_id,),
        )
        return [self._public(row) for row in rows]

    @staticmethod
    def _public(row) -> dict[str, Any]:
        public = {key: row[key] for key in row.keys() if key != "tenant_id"}
        # Direct operator ranges have no source observation. The existing
        # NOT NULL column stores an empty value; expose the absence explicitly.
        if public["source_detection_id"] == "":
            public["source_detection_id"] = None
        return public

    def create(self, pattern: KnownSignalPattern, operator: str):
        """Create an explicitly reviewed range without inventing a detection."""
        return self.create_many([(None, pattern)], operator)[0]

    def create_many(
        self, items: list[tuple[str | None, KnownSignalPattern]], operator: str
    ):
        """Idempotently create reviewed patterns and their audit records, all or none.

        The unique match identity is tenant + node + class + exact bounds. An
        identical retry returns its existing rule (including its original note).
        Edit is explicit and never an implicit side effect of a repeated create.
        """
        result = []
        changed = False
        with self._ctx.write_transaction(immediate=True) as conn:
            for detection_id, pattern in items:
                values = pattern.model_dump()
                row = conn.execute(
                    "SELECT * FROM known_rf_signals WHERE tenant_id = ? "
                    "AND node_id IS ? AND signal_class = ? AND freq_min_hz = ? AND freq_max_hz = ?",
                    (
                        self._ctx.tenant_id,
                        pattern.node_id,
                        pattern.signal_class,
                        pattern.freq_min_hz,
                        pattern.freq_max_hz,
                    ),
                ).fetchone()
                if row is None:
                    now = datetime.now(timezone.utc).isoformat()
                    pattern_id = uuid.uuid4().hex
                    conn.execute(
                        "INSERT INTO known_rf_signals "
                        "(pattern_id,tenant_id,freq_min_hz,freq_max_hz,signal_class,node_id,note,"
                        "source_detection_id,created_by,created_at,updated_at,revision) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,1)",
                        (
                            pattern_id,
                            self._ctx.tenant_id,
                            pattern.freq_min_hz,
                            pattern.freq_max_hz,
                            pattern.signal_class,
                            pattern.node_id,
                            pattern.note,
                            detection_id or "",
                            operator,
                            now,
                            now,
                        ),
                    )
                    self._audit._log_audit_in_transaction(
                        conn,
                        "baseline"
                        if detection_id is not None
                        else "known_signal_create",
                        detection_id if detection_id is not None else pattern_id,
                        signal_class=pattern.signal_class,
                        node_id=pattern.node_id or "",
                        operator=operator,
                        details={
                            "pattern_id": pattern_id,
                            "pattern": values,
                            "effect": "suppress_matching_rf_alerts",
                        },
                    )
                    row = conn.execute(
                        "SELECT * FROM known_rf_signals WHERE pattern_id = ?",
                        (pattern_id,),
                    ).fetchone()
                    changed = True
                result.append(self._public(row))
        if changed:
            self._audit._after_commit(
                "baseline"
                if any(item[0] is not None for item in items)
                else "known_signal_create",
                "known_rf_signals",
            )
        return result

    def update(
        self, pattern_id: str, pattern: KnownSignalPattern, revision: int, operator: str
    ):
        return self._mutate(pattern_id, pattern, revision, operator)

    def remove(self, pattern_id: str, revision: int, operator: str):
        return self._mutate(pattern_id, None, revision, operator)

    def _mutate(self, pattern_id, pattern, revision, operator):
        action = "known_signal_remove" if pattern is None else "known_signal_update"
        with self._ctx.write_transaction(immediate=True) as conn:
            row = conn.execute(
                "SELECT * FROM known_rf_signals WHERE pattern_id = ? AND tenant_id = ?",
                (pattern_id, self._ctx.tenant_id),
            ).fetchone()
            if row is None:
                raise KeyError(pattern_id)
            before = self._public(row)
            if before["revision"] != revision:
                raise ValueError(
                    "This pattern changed. Refresh it before editing or removing it."
                )
            after = None
            if pattern is None:
                conn.execute(
                    "DELETE FROM known_rf_signals WHERE pattern_id = ? AND tenant_id = ?",
                    (pattern_id, self._ctx.tenant_id),
                )
            else:
                conn.execute(
                    "UPDATE known_rf_signals SET freq_min_hz=?,freq_max_hz=?,signal_class=?,"
                    "node_id=?,note=?,updated_at=?,revision=revision+1 WHERE pattern_id=? AND tenant_id=?",
                    (
                        pattern.freq_min_hz,
                        pattern.freq_max_hz,
                        pattern.signal_class,
                        pattern.node_id,
                        pattern.note,
                        datetime.now(timezone.utc).isoformat(),
                        pattern_id,
                        self._ctx.tenant_id,
                    ),
                )
                after = self._public(
                    conn.execute(
                        "SELECT * FROM known_rf_signals WHERE pattern_id=?",
                        (pattern_id,),
                    ).fetchone()
                )
            self._audit._log_audit_in_transaction(
                conn,
                action,
                pattern_id,
                operator=operator,
                details={"before": before, "after": after},
            )
        self._audit._after_commit(action, pattern_id)
        return after or before
