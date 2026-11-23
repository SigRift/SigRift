//! Read-only protocol queries — Bluetooth and alert data.
//!
//! These query Python-managed tables directly for read-only dashboard
//! endpoints.  If a table doesn't exist (Python migrations haven't run),
//! functions return empty results rather than errors.

use crate::db::manager::SqliteConnectionManager;
use r2d2::PooledConnection;
use rusqlite::params;
use serde_json::{json, Value};

type Conn = PooledConnection<SqliteConnectionManager>;

/// Check whether a table exists in the database.
fn table_exists(conn: &Conn, table: &str) -> bool {
    conn.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1")
        .and_then(|mut stmt| stmt.exists(params![table]))
        .unwrap_or(false)
}

// ── Bluetooth ───────────────────────────────────────────────────────────

/// Aggregate Bluetooth stats: total devices, grouped by type.
pub fn get_bt_stats(conn: &Conn, _tenant_id: &str) -> Result<Value, rusqlite::Error> {
    if !table_exists(conn, "bt_devices") {
        return Ok(json!({
            "total": 0,
            "by_type": {},
            "recent_1h": 0,
            "unique_addrs": 0,
        }));
    }

    let total: i64 = conn.query_row("SELECT COUNT(*) FROM bt_devices", [], |r| r.get(0))?;

    let unique_addrs: i64 = conn.query_row(
        "SELECT COUNT(DISTINCT device_addr) FROM bt_devices WHERE device_addr != ''",
        [],
        |r| r.get(0),
    )?;

    let recent_1h: i64 = conn.query_row(
        "SELECT COUNT(*) FROM bt_devices WHERE timestamp > strftime('%Y-%m-%dT%H:%M:%S', 'now', '-1 hour')",
        [],
        |r| r.get(0),
    )?;

    let mut by_type = serde_json::Map::new();
    {
        let mut stmt = conn.prepare(
            "SELECT COALESCE(device_type, 'unknown'), COUNT(*) FROM bt_devices GROUP BY device_type ORDER BY COUNT(*) DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (dtype, count) = row?;
            by_type.insert(dtype, json!(count));
        }
    }

    Ok(json!({
        "total": total,
        "by_type": by_type,
        "recent_1h": recent_1h,
        "unique_addrs": unique_addrs,
    }))
}

/// List Bluetooth devices with pagination.
pub fn get_bt_devices(
    conn: &Conn,
    _tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<Value>, rusqlite::Error> {
    if !table_exists(conn, "bt_devices") {
        return Ok(vec![]);
    }

    let mut stmt = conn.prepare(
        "SELECT id, device_addr, device_name, device_type, device_class,
                device_class_name, rssi_dbm, manufacturer, vendor,
                connectable, timestamp, node_id
         FROM bt_devices
         ORDER BY timestamp DESC
         LIMIT ?1 OFFSET ?2",
    )?;

    let rows = stmt.query_map(params![limit, offset], |row| {
        Ok(json!({
            "id": row.get::<_, i64>(0)?,
            "device_addr": row.get::<_, String>(1)?,
            "device_name": row.get::<_, String>(2)?,
            "device_type": row.get::<_, String>(3)?,
            "device_class": row.get::<_, i64>(4)?,
            "device_class_name": row.get::<_, String>(5)?,
            "rssi_dbm": row.get::<_, f64>(6)?,
            "manufacturer": row.get::<_, String>(7)?,
            "vendor": row.get::<_, String>(8)?,
            "connectable": row.get::<_, i64>(9)?,
            "timestamp": row.get::<_, String>(10)?,
            "node_id": row.get::<_, String>(11)?,
        }))
    })?;

    rows.collect()
}

// ── Alerts (high-score anomalies from rf_anomalies + wifi_anomalies) ────

/// List recent high-priority anomalies as "alerts".
///
/// Alerts are not stored in a dedicated table — they live in Python's
/// JSON persistence.  This endpoint surfaces active (undismissed)
/// anomalies with score >= 0.5 from both RF and WiFi anomaly tables
/// as a useful read-only approximation.
pub fn get_alerts_list(
    conn: &Conn,
    _tenant_id: &str,
    limit: i64,
) -> Result<Vec<Value>, rusqlite::Error> {
    let mut alerts: Vec<Value> = Vec::new();

    // RF anomalies
    if table_exists(conn, "rf_anomalies") {
        let mut stmt = conn.prepare(
            "SELECT id, signal_class, family, freq_hz, node_id, timestamp,
                    anomaly_score, priority, reasons, baseline_status
             FROM rf_anomalies
             WHERE dismissed = 0 AND anomaly_score >= 0.5
             ORDER BY timestamp DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok(json!({
                "source": "rf",
                "id": row.get::<_, i64>(0)?,
                "signal_class": row.get::<_, String>(1)?,
                "family": row.get::<_, String>(2)?,
                "freq_hz": row.get::<_, f64>(3)?,
                "node_id": row.get::<_, String>(4)?,
                "timestamp": row.get::<_, String>(5)?,
                "anomaly_score": row.get::<_, f64>(6)?,
                "priority": row.get::<_, String>(7)?,
                "reasons": row.get::<_, String>(8)?,
                "baseline_status": row.get::<_, String>(9)?,
            }))
        })?;
        for row in rows {
            alerts.push(row?);
        }
    }

    // WiFi anomalies
    if table_exists(conn, "wifi_anomalies") {
        let mut stmt = conn.prepare(
            "SELECT id, bssid, ssid, channel, band, node_id, timestamp,
                    anomaly_score, priority, reasons, baseline_status
             FROM wifi_anomalies
             WHERE dismissed = 0 AND anomaly_score >= 0.5
             ORDER BY timestamp DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok(json!({
                "source": "wifi",
                "id": row.get::<_, i64>(0)?,
                "bssid": row.get::<_, String>(1)?,
                "ssid": row.get::<_, String>(2)?,
                "channel": row.get::<_, i64>(3)?,
                "band": row.get::<_, String>(4)?,
                "node_id": row.get::<_, String>(5)?,
                "timestamp": row.get::<_, String>(6)?,
                "anomaly_score": row.get::<_, f64>(7)?,
                "priority": row.get::<_, String>(8)?,
                "reasons": row.get::<_, String>(9)?,
                "baseline_status": row.get::<_, String>(10)?,
            }))
        })?;
        for row in rows {
            alerts.push(row?);
        }
    }

    // Sort combined by timestamp DESC, then truncate
    alerts.sort_by(|a, b| {
        let ta = a["timestamp"].as_str().unwrap_or("");
        let tb = b["timestamp"].as_str().unwrap_or("");
        tb.cmp(ta)
    });
    alerts.truncate(limit as usize);

    Ok(alerts)
}
