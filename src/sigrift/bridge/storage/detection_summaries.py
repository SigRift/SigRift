"""Storage for pre-aggregated hourly detection summaries.

Edge nodes send hourly summary batches instead of individual detections,
reducing write volume by ~45x.
"""

from __future__ import annotations

import logging
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from sigrift.edge.summary_protocol import canonical_json, extends, receipt, validate

logger = logging.getLogger(__name__)


class SummaryConflict(ValueError):
    """A stale/incompatible sender cannot replace accepted summary state."""


class DetectionSummaryStore:
    """Sub-store for detection_summaries_hourly table."""

    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    def accept_snapshot(self, payload: dict) -> dict:
        """Atomically bind a stream/freeze the base and accept one generation.

        Raw-ID ingestion and its existing hooks remain the route's responsibility.
        An identical replay returns the same receipt so that work can be retried.
        """
        validate(payload)
        node, stream, hour = payload["node_id"], payload["stream_id"], payload["hour"]
        tenant = self._ctx.tenant_id
        with self._ctx.write_transaction(immediate=True) as conn:
            registered = conn.execute(
                "SELECT stream_id FROM rf_summary_streams WHERE tenant_id=? AND node_id=?",
                (tenant, node),
            ).fetchone()
            if registered is None:
                conn.execute(
                    "INSERT INTO rf_summary_streams VALUES (?,?,?)",
                    (tenant, node, stream),
                )
            elif registered[0] != stream:
                raise SummaryConflict(
                    "RF summary journal differs from registered stream; preserve both and recover the journal"
                )
            old = conn.execute(
                "SELECT generation,digest,payload,retired FROM rf_summary_generations WHERE tenant_id=? AND node_id=? AND hour=?",
                (tenant, node, hour),
            ).fetchone()
            if old is not None:
                if old[3]:
                    raise SummaryConflict(
                        "RF summary hour was retired; stale snapshots cannot resurrect it"
                    )
                if payload["generation"] < old[0] or (
                    payload["generation"] == old[0]
                    and payload["payload_digest"] != old[1]
                ):
                    raise SummaryConflict("Stale or conflicting RF summary generation")
                if payload["generation"] == old[0]:
                    return receipt(payload)
                try:
                    extends(json.loads(old[2]), payload)
                except ValueError as exc:
                    raise SummaryConflict(str(exc)) from exc
            conn.execute(
                "DELETE FROM rf_summary_components WHERE tenant_id=? AND node_id=? AND stream_id=? AND component='stream_summary' AND hour=?",
                (tenant, node, stream, hour),
            )
            for row in payload["summaries"]:
                self._insert_component(
                    conn, tenant, node, stream, "stream_summary", row
                )
            conn.execute(
                "INSERT INTO rf_summary_generations(tenant_id,node_id,stream_id,hour,generation,digest,payload) VALUES (?,?,?,?,?,?,?) ON CONFLICT(tenant_id,node_id,hour) DO UPDATE SET generation=excluded.generation,digest=excluded.digest,payload=excluded.payload",
                (
                    tenant,
                    node,
                    stream,
                    hour,
                    payload["generation"],
                    payload["payload_digest"],
                    canonical_json(payload),
                ),
            )
        return receipt(payload)

    @staticmethod
    def _insert_component(conn, tenant, node, stream, component, row):
        conn.execute(
            "INSERT OR REPLACE INTO rf_summary_components VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                tenant,
                node,
                stream,
                component,
                row["hour"],
                row["signal_class"],
                row["family"],
                row["freq_bin_hz"],
                row["detection_count"],
                canonical_json(row).decode(),
            ),
        )

    def insert_summaries(self, node_id: str, summaries: list[dict]) -> int:
        """INSERT OR REPLACE hourly summary rows.

        Returns the number of rows inserted.
        """
        if not summaries:
            return 0

        sql = """
            INSERT OR REPLACE INTO detection_summaries_hourly
                (hour, node_id, signal_class, family, freq_bin_hz,
                 detection_count, avg_confidence, min_confidence, max_confidence,
                 avg_snr_db, avg_power_dbm, avg_anomaly, max_anomaly, tenant_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        rows = []
        for s in summaries:
            rows.append(
                (
                    s.get("hour", ""),
                    node_id,
                    s.get("signal_class", ""),
                    s.get("family", ""),
                    s.get("freq_bin_hz", 0.0),
                    s.get("detection_count", 0),
                    s.get("avg_confidence", 0.0),
                    s.get("min_confidence", 0.0),
                    s.get("max_confidence", 0.0),
                    s.get("avg_snr_db"),
                    s.get("avg_power_dbm"),
                    s.get("avg_anomaly", 0.0),
                    s.get("max_anomaly", 0.0),
                    self._ctx.tenant_id,
                )
            )

        with self._ctx.write_transaction(immediate=True) as conn:
            if conn.execute(
                "SELECT 1 FROM rf_summary_streams WHERE tenant_id=? AND node_id=?",
                (self._ctx.tenant_id, node_id),
            ).fetchone():
                raise SummaryConflict("Versioned RF summary node rejects legacy writes")
            conn.executemany(sql, rows)

        logger.info("Inserted %d detection summaries for node %s", len(rows), node_id)
        return len(rows)

    def get_summaries(
        self,
        hours: int = 24,
        node_id: str | None = None,
        signal_class: str | None = None,
    ) -> list[dict]:
        """Query hourly summaries."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime(
            "%Y-%m-%dT%H:00:00Z"
        )
        clauses = ["hour >= ?", "tenant_id = ?"]
        params: list[Any] = [cutoff, self._ctx.tenant_id]
        if node_id:
            clauses.append("node_id = ?")
            params.append(node_id)
        if signal_class:
            clauses.append("signal_class = ?")
            params.append(signal_class)
        where = " AND ".join(clauses)
        conn = self._ctx.get_conn()
        registered = {
            row[0]
            for row in conn.execute(
                "SELECT node_id FROM rf_summary_streams WHERE tenant_id=?",
                (self._ctx.tenant_id,),
            )
        }
        cursor = conn.execute(
            "SELECT * FROM detection_summaries_hourly WHERE "
            + where
            + " ORDER BY hour DESC LIMIT 10000",
            params,
        )
        names = [column[0] for column in cursor.description]
        results = [dict(zip(names, tuple(row))) for row in cursor]
        for row in results:
            if row["node_id"] in registered:
                row.update(
                    component="legacy_base", legacy_overlap="unknown", stream_id=None
                )
        cursor = conn.execute(
            "SELECT node_id,stream_id,component,data FROM rf_summary_components WHERE "
            + where
            + " ORDER BY hour DESC LIMIT 10000",
            params,
        )
        for node, stream, component, data in cursor:
            row = json.loads(data)
            row.update(
                node_id=node,
                tenant_id=self._ctx.tenant_id,
                component=component,
                stream_id=stream,
                # Registration identifies a new independent writer. It cannot
                # prove which observations an old writer included in its base.
                legacy_overlap="unknown",
            )
            results.append(row)
        return sorted(results, key=lambda row: row["hour"], reverse=True)[:10000]

    def rollup_from_raw(self, cutoff_hours: int = 1) -> int:
        """Server-side rollup of raw detections into hourly summaries.

        For nodes that don't use edge-side summarization.
        Groups detections older than cutoff_hours into hourly bins.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=cutoff_hours)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        sql = """
            INSERT OR REPLACE INTO detection_summaries_hourly
                (hour, node_id, signal_class, family, freq_bin_hz,
                 detection_count, avg_confidence, min_confidence, max_confidence,
                 avg_snr_db, avg_power_dbm, avg_anomaly, max_anomaly, tenant_id)
            SELECT
                strftime('%Y-%m-%dT%H:00:00Z', timestamp) AS hour,
                node_id,
                signal_class,
                family,
                CASE WHEN freq_hz < 1e9
                     THEN ROUND(freq_hz / 25000) * 25000
                     ELSE ROUND(freq_hz / 500000) * 500000
                END AS freq_bin_hz,
                COUNT(*) AS detection_count,
                AVG(confidence) AS avg_confidence,
                MIN(confidence) AS min_confidence,
                MAX(confidence) AS max_confidence,
                AVG(snr_db) AS avg_snr_db,
                AVG(power_dbm) AS avg_power_dbm,
                AVG(anomaly_score) AS avg_anomaly,
                MAX(anomaly_score) AS max_anomaly,
                ? AS tenant_id
            FROM detections
            WHERE timestamp < ? AND detections.tenant_id = ?
              AND NOT EXISTS (SELECT 1 FROM rf_summary_streams r WHERE r.tenant_id=detections.tenant_id AND r.node_id=detections.node_id)
            GROUP BY hour, node_id, signal_class, family, freq_bin_hz
        """
        with self._ctx.write_transaction(immediate=True) as conn:
            cursor = conn.execute(
                sql, (self._ctx.tenant_id, cutoff, self._ctx.tenant_id)
            )
            count = cursor.rowcount
            # Keep registered-node raw rollup explicitly separate. Its historical
            # overlap with the immutable base is unknowable, so never add it to
            # the base/stream count or invent a pooled confidence/SNR mean.
            raw_sql = sql[sql.index("            SELECT") :].replace(
                "AND NOT EXISTS", "AND EXISTS"
            )
            raw = conn.execute(
                raw_sql, (self._ctx.tenant_id, cutoff, self._ctx.tenant_id)
            )
            names = [column[0] for column in raw.description]
            rows = [dict(zip(names, tuple(row))) for row in raw]
            for row in rows:
                node = row.pop("node_id")
                row.pop("tenant_id")
                self._insert_component(
                    conn, self._ctx.tenant_id, node, "raw", "raw_rollup", row
                )
            count += len(rows)

        if count > 0:
            logger.info("Rolled up %d hourly summary rows from raw detections", count)
        return count

    def cleanup_summaries(self, max_age_days: int = 90) -> int:
        """Delete summaries older than max_age_days."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).strftime(
            "%Y-%m-%dT%H:00:00Z"
        )
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM detection_summaries_hourly WHERE hour < ? AND tenant_id=?",
                (cutoff, self._ctx.tenant_id),
            )
            count = cursor.rowcount
            count += conn.execute(
                "DELETE FROM rf_summary_components WHERE hour < ? AND tenant_id=?",
                (cutoff, self._ctx.tenant_id),
            ).rowcount
            conn.execute(
                "UPDATE rf_summary_generations SET retired=1,payload='{}' WHERE hour < ? AND tenant_id=?",
                (cutoff, self._ctx.tenant_id),
            )
            # Retain generation fences; cleanup must not turn an old replay into
            # a new stream or resurrect contributions removed by retention.

        if count > 0:
            logger.info("Cleaned up %d old detection summaries", count)
        return count


def _dict_factory(cursor, row):
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}
