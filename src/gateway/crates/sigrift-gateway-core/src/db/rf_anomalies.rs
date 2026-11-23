//! RF anomaly database operations with deduplication.

use crate::db::manager::SqliteConnectionManager;
use crate::models::anomaly::RFAnomaly;
use r2d2::PooledConnection;
use rusqlite::params;
use tracing::debug;

pub fn upsert(
    conn: &PooledConnection<SqliteConnectionManager>,
    anomaly: &RFAnomaly,
) -> Result<(), rusqlite::Error> {
    let existing_id: Option<i64> = conn
        .query_row(
            "SELECT id FROM rf_anomalies WHERE dedup_key = ?1 AND dismissed = 0 ORDER BY id DESC LIMIT 1",
            [&anomaly.dedup_key],
            |row| row.get(0),
        )
        .ok();

    if let Some(id) = existing_id {
        conn.execute(
            "UPDATE rf_anomalies SET
                anomaly_score=?1, priority=?2, dimensions=?3, reasons=?4,
                timestamp=?5, confidence=?6, snr_db=?7, power_dbm=?8,
                seen_count=seen_count+1, baseline_status=?9, detection_id=?10
             WHERE id=?11",
            params![
                anomaly.anomaly_score,
                anomaly.priority,
                anomaly.dimensions,
                anomaly.reasons,
                anomaly.timestamp,
                anomaly.confidence,
                anomaly.snr_db,
                anomaly.power_dbm,
                anomaly.baseline_status,
                anomaly.detection_id,
                id,
            ],
        )?;
        debug!(id = id, dedup_key = %anomaly.dedup_key, "RF anomaly updated");
    } else {
        conn.execute(
            "INSERT INTO rf_anomalies (
                detection_id, signal_class, family, freq_hz, dedup_key,
                node_id, timestamp, confidence, snr_db, power_dbm,
                anomaly_score, priority, dimensions, reasons,
                baseline_status, has_iq_capture, seen_count, first_seen, tenant_id
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,1,?7,?17)",
            params![
                anomaly.detection_id,
                anomaly.signal_class,
                anomaly.family,
                anomaly.freq_hz,
                anomaly.dedup_key,
                anomaly.node_id,
                anomaly.timestamp,
                anomaly.confidence,
                anomaly.snr_db,
                anomaly.power_dbm,
                anomaly.anomaly_score,
                anomaly.priority,
                anomaly.dimensions,
                anomaly.reasons,
                anomaly.baseline_status,
                anomaly.has_iq_capture as i32,
                anomaly.tenant_id,
            ],
        )?;
        debug!(dedup_key = %anomaly.dedup_key, "RF anomaly inserted");
    }
    Ok(())
}
