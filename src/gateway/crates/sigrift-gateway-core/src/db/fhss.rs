//! FHSS event database operations.

use crate::db::manager::SqliteConnectionManager;
use crate::models::fhss::FHSSEvent;
use r2d2::PooledConnection;
use rusqlite::params;
use tracing::debug;

pub fn insert_event(
    conn: &PooledConnection<SqliteConnectionManager>,
    event: &FHSSEvent,
) -> Result<bool, rusqlite::Error> {
    let hop_set_json = serde_json::to_string(&event.hop_set).unwrap_or_else(|_| "[]".to_string());
    let rows = conn.execute(
        "INSERT OR IGNORE INTO fhss_events (
            fhss_id, node_id, timestamp, hop_rate_hz, hop_set,
            bandwidth_hz, dwell_time_ms, duration_sec, signal_class,
            detection_count, confidence, tenant_id
        ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        params![
            event.fhss_id,
            event.node_id,
            event.timestamp,
            event.hop_rate_hz,
            hop_set_json,
            event.bandwidth_hz,
            event.dwell_time_ms,
            event.duration_sec,
            event.signal_class,
            event.detection_count as i64,
            event.confidence,
            event.tenant_id,
        ],
    )?;
    let inserted = rows > 0;
    if inserted {
        debug!(fhss_id = %event.fhss_id, "FHSS event inserted");
    }
    Ok(inserted)
}
