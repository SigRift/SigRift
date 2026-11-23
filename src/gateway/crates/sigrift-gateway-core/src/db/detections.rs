//! Detection database operations.

use crate::db::manager::SqliteConnectionManager;
use crate::models::detection::DetectionRecord;
use r2d2::PooledConnection;
use rusqlite::params;
use tracing::debug;

pub fn insert_batch(
    conn: &PooledConnection<SqliteConnectionManager>,
    detections: &[DetectionRecord],
) -> Result<usize, rusqlite::Error> {
    Ok(insert_batch_marking(conn, detections)?
        .into_iter()
        .filter(|&new| new)
        .count())
}

/// [`insert_batch`], returning for each detection whether it was inserted
/// (`false`: a detection with that id was already stored, e.g. a batch the
/// edge sent again after a lost response).
pub fn insert_batch_marking(
    conn: &PooledConnection<SqliteConnectionManager>,
    detections: &[DetectionRecord],
) -> Result<Vec<bool>, rusqlite::Error> {
    let mut inserted = Vec::with_capacity(detections.len());
    let tx = conn.unchecked_transaction()?;
    {
        // A detection whose IQ upload reached the bridge first already has
        // a placeholder row (signal_class `iq_capture`, confidence and
        // anomaly score 0, same node): upgrade it in place, exactly as the
        // bridge's own insert does (storage/detection_crud.py), instead of
        // ignoring the real detection — which also kept it from ever being
        // hooked (K8). Any other existing row is left alone. SQLite counts
        // the upgrade as a change, so it is marked new like an insert.
        let mut stmt = tx.prepare_cached(
            "INSERT INTO detections (
                detection_id, node_id, timestamp, signal_class, confidence,
                family, freq_hz, snr_db, power_dbm, inference_ms,
                backend, anomaly_score, baseline_status, has_iq_capture,
                gain_db, lna_state, bandwidth_hz, tenant_id
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,'default')
            ON CONFLICT(detection_id) DO UPDATE SET
                timestamp = excluded.timestamp,
                signal_class = excluded.signal_class,
                confidence = excluded.confidence,
                family = excluded.family,
                freq_hz = excluded.freq_hz,
                snr_db = excluded.snr_db,
                power_dbm = excluded.power_dbm,
                inference_ms = excluded.inference_ms,
                backend = excluded.backend,
                anomaly_score = excluded.anomaly_score,
                baseline_status = excluded.baseline_status,
                gain_db = excluded.gain_db,
                lna_state = excluded.lna_state,
                bandwidth_hz = excluded.bandwidth_hz
            WHERE detections.signal_class = 'iq_capture'
              AND excluded.signal_class != 'iq_capture'
              AND detections.confidence = 0
              AND detections.anomaly_score = 0
              AND detections.node_id = excluded.node_id
              AND detections.tenant_id = excluded.tenant_id",
        )?;
        for det in detections {
            let rows = stmt.execute(params![
                det.detection_id,
                det.node_id,
                det.timestamp,
                det.signal_class,
                det.confidence,
                det.family,
                det.freq_hz,
                det.snr_db,
                det.power_dbm,
                det.inference_ms,
                det.backend,
                det.anomaly_score,
                det.baseline_status,
                det.has_iq_capture as i32,
                det.gain_db,
                det.lna_state,
                det.bandwidth_hz,
            ])?;
            inserted.push(rows > 0);
        }
    }
    tx.commit()?;
    debug!(
        count = inserted.iter().filter(|&&new| new).count(),
        "Detections inserted"
    );
    Ok(inserted)
}

/// The `timestamp >=` cutoff for "the last `seconds` seconds", formatted
/// like the stored values (Python `isoformat()` of an aware UTC datetime,
/// `T` separator, `+00:00`). `datetime('now', ...)` would produce a
/// space-separated value, and as text every timestamp on the cutoff date
/// compares greater than it, so the window silently grew to "since
/// midnight UTC". Binding a string in the stored format keeps the
/// comparison correct and the timestamp index usable.
fn recent_cutoff(now: chrono::DateTime<chrono::Utc>, seconds: i64) -> String {
    (now - chrono::Duration::seconds(seconds.max(0)))
        .format("%Y-%m-%dT%H:%M:%S%.6f+00:00")
        .to_string()
}

pub fn get_recent(
    conn: &PooledConnection<SqliteConnectionManager>,
    seconds: i64,
    limit: usize,
) -> Result<Vec<DetectionRecord>, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "SELECT detection_id, node_id, timestamp, signal_class, confidence,
                family, freq_hz, snr_db, power_dbm, inference_ms,
                backend, anomaly_score, baseline_status, has_iq_capture,
                gain_db, lna_state, bandwidth_hz
         FROM detections WHERE timestamp >= ?1
         ORDER BY timestamp DESC LIMIT ?2",
    )?;
    let cutoff = recent_cutoff(chrono::Utc::now(), seconds);
    let rows = stmt.query_map(params![cutoff, limit as i64], |row| {
        Ok(DetectionRecord {
            detection_id: row.get(0)?,
            node_id: row.get(1)?,
            timestamp: row.get(2)?,
            signal_class: row.get(3)?,
            confidence: row.get(4)?,
            family: row.get(5)?,
            freq_hz: row.get(6)?,
            snr_db: row.get(7)?,
            power_dbm: row.get(8)?,
            inference_ms: row.get(9)?,
            backend: row.get(10)?,
            anomaly_score: row.get(11)?,
            baseline_status: row.get::<_, String>(12).unwrap_or_else(|_| "stable".into()),
            has_iq_capture: row.get::<_, i32>(13).map(|v| v != 0).unwrap_or(false),
            gain_db: row.get(14)?,
            lna_state: row.get(15)?,
            bandwidth_hz: row.get(16)?,
            edge_id: None,
            decoded_messages: None,
        })
    })?;
    rows.collect()
}

pub fn get_total_count(
    conn: &PooledConnection<SqliteConnectionManager>,
) -> Result<i64, rusqlite::Error> {
    conn.query_row("SELECT COUNT(*) FROM detections", [], |row| row.get(0))
}

#[cfg(test)]
mod recent_cutoff_tests {
    use super::recent_cutoff;
    use chrono::TimeZone;

    #[test]
    fn cutoff_uses_the_stored_iso_format_and_orders_correctly() {
        let now = chrono::Utc
            .with_ymd_and_hms(2026, 11, 5, 10, 0, 30)
            .unwrap();
        let cutoff = recent_cutoff(now, 10);
        assert_eq!(cutoff, "2026-11-05T10:00:20.000000+00:00");
        // A detection 15 s old is outside the window, 5 s old inside it —
        // as text, which is how SQLite compares the TEXT column.
        assert!("2026-11-05T10:00:15.000000+00:00" < cutoff.as_str());
        assert!("2026-11-05T10:00:25.000000+00:00" >= cutoff.as_str());
        // The old `datetime('now', '-10 seconds')` value: every timestamp
        // earlier that same day compared greater (the bug).
        assert!("2026-11-05T01:00:00+00:00" > "2026-11-05 10:00:20");
        assert!("2026-11-05T01:00:00+00:00" < cutoff.as_str());
    }
}
