//! Read-only dashboard queries — offloads heavy SELECTs from Python.

use crate::db::manager::SqliteConnectionManager;
use r2d2::PooledConnection;
use rusqlite::params;
use serde::Serialize;

/// SQLite datetime with T separator to match stored ISO-8601 timestamps.
const NOW_EXPR: &str = "strftime('%Y-%m-%dT%H:%M:%S', 'now')";

fn now_offset_expr(offset_param: &str) -> String {
    format!("strftime('%Y-%m-%dT%H:%M:%S', 'now', {})", offset_param)
}

// ── Recent detections ────────────────────────────────────────────────

pub fn get_recent_detections(
    conn: &PooledConnection<SqliteConnectionManager>,
    minutes: i64,
    node_id: Option<&str>,
    limit: i64,
) -> Result<Vec<serde_json::Value>, rusqlite::Error> {
    let offset = format!("-{} minutes", minutes);

    if let Some(nid) = node_id {
        let sql = format!(
            "SELECT detection_id, node_id, timestamp, signal_class, confidence,
                    family, freq_hz, snr_db, power_dbm, inference_ms,
                    backend, anomaly_score, baseline_status, has_iq_capture,
                    gain_db, lna_state, bandwidth_hz
             FROM detections
             WHERE tenant_id = 'default' AND timestamp >= {}
               AND node_id = ?3
             ORDER BY timestamp DESC LIMIT ?2",
            now_offset_expr("?1")
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(params![offset, limit, nid], row_to_json)?;
        rows.collect()
    } else {
        let sql = format!(
            "SELECT detection_id, node_id, timestamp, signal_class, confidence,
                    family, freq_hz, snr_db, power_dbm, inference_ms,
                    backend, anomaly_score, baseline_status, has_iq_capture,
                    gain_db, lna_state, bandwidth_hz
             FROM detections
             WHERE tenant_id = 'default' AND timestamp >= {}
             ORDER BY timestamp DESC LIMIT ?2",
            now_offset_expr("?1")
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map(params![offset, limit], row_to_json)?;
        rows.collect()
    }
}

fn row_to_json(row: &rusqlite::Row) -> Result<serde_json::Value, rusqlite::Error> {
    Ok(serde_json::json!({
        "detection_id": row.get::<_, String>(0)?,
        "node_id": row.get::<_, String>(1)?,
        "timestamp": row.get::<_, String>(2)?,
        "signal_class": row.get::<_, String>(3)?,
        "confidence": row.get::<_, f64>(4)?,
        "family": row.get::<_, Option<String>>(5)?.unwrap_or_default(),
        "freq_hz": row.get::<_, f64>(6)?,
        "snr_db": row.get::<_, Option<f64>>(7)?,
        "power_dbm": row.get::<_, Option<f64>>(8)?,
        "inference_ms": row.get::<_, Option<f64>>(9)?,
        "backend": row.get::<_, Option<String>>(10)?,
        "anomaly_score": row.get::<_, f64>(11)?,
        "baseline_status": row.get::<_, Option<String>>(12)?.unwrap_or_else(|| "stable".into()),
        "has_iq_capture": row.get::<_, i32>(13).unwrap_or(0) != 0,
        "gain_db": row.get::<_, Option<f64>>(14)?,
        "lna_state": row.get::<_, Option<String>>(15)?,
        "bandwidth_hz": row.get::<_, Option<f64>>(16)?,
    }))
}

// ── Timeline ─────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct TimelineBucket {
    pub bucket: String,
    pub count: i64,
    pub avg_confidence: f64,
    pub classes: String,
}

pub fn get_timeline(
    conn: &PooledConnection<SqliteConnectionManager>,
    hours: i64,
    resolution_secs: i64,
    node_id: Option<&str>,
) -> Result<Vec<TimelineBucket>, rusqlite::Error> {
    let offset = format!("-{} hours", hours);
    let start_time: String = conn.query_row(
        &format!("SELECT {}", now_offset_expr("?1")),
        params![offset],
        |row| row.get(0),
    )?;

    let results = if let Some(nid) = node_id {
        let sql = "SELECT
                CAST((julianday(timestamp) - julianday(?1)) * 86400 / ?2 AS INTEGER) as bucket_idx,
                COUNT(*) as count,
                AVG(confidence) as avg_confidence,
                GROUP_CONCAT(DISTINCT signal_class) as classes
            FROM detections
            WHERE tenant_id = 'default' AND timestamp >= ?1 AND node_id = ?3
            GROUP BY bucket_idx
            ORDER BY bucket_idx";
        let mut stmt = conn.prepare_cached(sql)?;
        let rows = stmt.query_map(params![start_time, resolution_secs, nid], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, f64>(2)?,
                row.get::<_, Option<String>>(3)?.unwrap_or_default(),
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    } else {
        let sql = "SELECT
                CAST((julianday(timestamp) - julianday(?1)) * 86400 / ?2 AS INTEGER) as bucket_idx,
                COUNT(*) as count,
                AVG(confidence) as avg_confidence,
                GROUP_CONCAT(DISTINCT signal_class) as classes
            FROM detections
            WHERE tenant_id = 'default' AND timestamp >= ?1
            GROUP BY bucket_idx
            ORDER BY bucket_idx";
        let mut stmt = conn.prepare_cached(sql)?;
        let rows = stmt.query_map(params![start_time, resolution_secs], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, f64>(2)?,
                row.get::<_, Option<String>>(3)?.unwrap_or_default(),
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };

    // Convert bucket indices to ISO timestamps
    let base = chrono::NaiveDateTime::parse_from_str(&start_time, "%Y-%m-%dT%H:%M:%S")
        .unwrap_or_else(|_| chrono::Utc::now().naive_utc());
    let buckets = results
        .into_iter()
        .map(|(idx, count, avg_conf, classes)| {
            let bucket_time = base + chrono::Duration::seconds(idx * resolution_secs);
            TimelineBucket {
                bucket: bucket_time.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                count,
                avg_confidence: (avg_conf * 10000.0_f64).round() / 10000.0,
                classes,
            }
        })
        .collect();
    Ok(buckets)
}

// ── Distribution ─────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct DistributionEntry {
    pub signal_class: String,
    pub family: String,
    pub count: i64,
    pub avg_confidence: f64,
}

pub fn get_distribution(
    conn: &PooledConnection<SqliteConnectionManager>,
    hours: i64,
    min_confidence: f64,
) -> Result<Vec<DistributionEntry>, rusqlite::Error> {
    let offset = format!("-{} hours", hours);
    let sql = format!(
        "SELECT signal_class, family, COUNT(*) as count, AVG(confidence) as avg_confidence
         FROM detections
         WHERE tenant_id = 'default' AND timestamp >= {} AND confidence >= ?2
         GROUP BY signal_class, family
         ORDER BY count DESC",
        now_offset_expr("?1")
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map(params![offset, min_confidence], |row| {
        Ok(DistributionEntry {
            signal_class: row.get(0)?,
            family: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
            count: row.get(2)?,
            avg_confidence: row.get(3)?,
        })
    })?;
    rows.collect()
}

// ── Heatmap ──────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct HeatmapCell {
    pub time_bucket: i64,
    pub freq_bucket_mhz: i64,
    pub count: i64,
    pub dominant_class: String,
}

pub fn get_heatmap(
    conn: &PooledConnection<SqliteConnectionManager>,
    hours: i64,
    resolution_min: i64,
) -> Result<Vec<HeatmapCell>, rusqlite::Error> {
    let offset = format!("-{} hours", hours);
    let start_time: String = conn.query_row(
        &format!("SELECT {}", now_offset_expr("?1")),
        params![offset],
        |row| row.get(0),
    )?;
    let end_time: String = conn.query_row(&format!("SELECT {}", NOW_EXPR), [], |row| row.get(0))?;
    let mut stmt = conn.prepare_cached(
        "SELECT
            CAST((julianday(timestamp) - julianday(?1)) * 1440 / ?3 AS INTEGER) as time_bucket,
            CAST(freq_hz / 1000000.0 AS INTEGER) as freq_bucket_mhz,
            COUNT(*) as count,
            signal_class as dominant_class
         FROM detections
         WHERE tenant_id = 'default' AND timestamp >= ?1 AND timestamp <= ?2 AND freq_hz > 0
         GROUP BY time_bucket, freq_bucket_mhz
         ORDER BY time_bucket, freq_bucket_mhz",
    )?;
    let rows = stmt.query_map(params![start_time, end_time, resolution_min], |row| {
        Ok(HeatmapCell {
            time_bucket: row.get(0)?,
            freq_bucket_mhz: row.get(1)?,
            count: row.get(2)?,
            dominant_class: row.get(3)?,
        })
    })?;
    rows.collect()
}

// ── Summary / stats ──────────────────────────────────────────────────

#[derive(Serialize)]
pub struct DetectionStats {
    pub total_24h: i64,
    pub avg_confidence: f64,
    pub unique_classes: i64,
    pub unique_nodes: i64,
    pub active_anomalies: i64,
    pub active_frequencies: i64,
    pub detections_per_second: f64,
}

pub fn get_stats(
    conn: &PooledConnection<SqliteConnectionManager>,
    hours: i64,
) -> Result<DetectionStats, rusqlite::Error> {
    let offset = format!("-{} hours", hours);
    let sql = format!(
        "SELECT COUNT(*) as cnt, COALESCE(AVG(confidence), 0) as avg_conf,
                COUNT(DISTINCT signal_class) as ucls, COUNT(DISTINCT node_id) as unodes
         FROM detections WHERE tenant_id = 'default' AND timestamp >= {}",
        now_offset_expr("?1")
    );
    let row = conn.query_row(&sql, params![offset], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, f64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;
    let (total_24h, avg_confidence, unique_classes, unique_nodes) = row;

    let active_anomalies: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM rf_anomalies WHERE tenant_id = 'default' AND dismissed = 0
         AND (snoozed_until IS NULL OR COALESCE(julianday(snoozed_until) <= julianday('now'), 1))",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let freq_sql = format!(
        "SELECT COUNT(DISTINCT CAST(freq_hz / 100000 AS INTEGER))
         FROM detections WHERE tenant_id = 'default' AND timestamp >= {} AND freq_hz > 0",
        now_offset_expr("'-1 hours'")
    );
    let active_frequencies: i64 = conn.query_row(&freq_sql, [], |row| row.get(0)).unwrap_or(0);

    let dps = total_24h as f64 / (hours as f64 * 3600.0);

    Ok(DetectionStats {
        total_24h,
        avg_confidence: (avg_confidence * 10000.0).round() / 10000.0,
        unique_classes,
        unique_nodes,
        active_anomalies,
        active_frequencies,
        detections_per_second: (dps * 100.0).round() / 100.0,
    })
}

// ── Anomaly summary ──────────────────────────────────────────────────

#[derive(Serialize)]
pub struct AnomalySummary {
    pub total: i64,
    pub by_priority: serde_json::Value,
    pub by_family: Vec<serde_json::Value>,
    pub by_node: Vec<serde_json::Value>,
}

// Snooze filter: `snoozed_until` is stored as an ISO-8601 string with a
// `T` separator (Python `isoformat()`), while `CURRENT_TIMESTAMP` /
// `datetime('now')` use a space; comparing the two as text treats every
// snooze on the current date as still active until midnight UTC. Compare
// as julian days instead, and treat an unparseable value as not snoozed —
// the same filter as the bridge's `ACTIVE_FILTER`.
pub fn get_anomaly_summary(
    conn: &PooledConnection<SqliteConnectionManager>,
    min_score: f64,
) -> Result<AnomalySummary, rusqlite::Error> {
    let where_clause = "WHERE tenant_id = 'default' AND dismissed = 0
        AND (snoozed_until IS NULL OR COALESCE(julianday(snoozed_until) <= julianday('now'), 1))
        AND anomaly_score >= ?1";

    let total: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM rf_anomalies {}", where_clause),
            params![min_score],
            |row| row.get(0),
        )
        .unwrap_or(0);

    // By priority
    let mut by_priority = serde_json::Map::new();
    {
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT priority, COUNT(*) as count FROM rf_anomalies {} GROUP BY priority",
            where_clause
        ))?;
        let rows = stmt.query_map(params![min_score], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (p, c) = row?;
            by_priority.insert(p, serde_json::Value::from(c));
        }
    }

    // By family
    let by_family = {
        let mut stmt = conn.prepare_cached(
            &format!("SELECT family, COUNT(*) as count FROM rf_anomalies {} GROUP BY family ORDER BY count DESC LIMIT 10", where_clause),
        )?;
        let rows = stmt.query_map(params![min_score], |row| {
            Ok(serde_json::json!({"family": row.get::<_, String>(0)?, "count": row.get::<_, i64>(1)?}))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };

    // By node
    let by_node = {
        let mut stmt = conn.prepare_cached(
            &format!("SELECT node_id, COUNT(*) as count FROM rf_anomalies {} GROUP BY node_id ORDER BY count DESC", where_clause),
        )?;
        let rows = stmt.query_map(params![min_score], |row| {
            Ok(serde_json::json!({"node_id": row.get::<_, String>(0)?, "count": row.get::<_, i64>(1)?}))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };

    Ok(AnomalySummary {
        total,
        by_priority: serde_json::Value::Object(by_priority),
        by_family,
        by_node,
    })
}

#[cfg(test)]
mod snooze_filter_tests {
    use super::get_anomaly_summary;
    use crate::db::manager::SqliteConnectionManager;

    fn iso(t: chrono::DateTime<chrono::Utc>) -> String {
        // The format the bridge writes: Python isoformat() of an aware UTC datetime.
        t.format("%Y-%m-%dT%H:%M:%S%.6f+00:00").to_string()
    }

    #[test]
    fn expired_snooze_earlier_today_counts_as_active() {
        let pool = r2d2::Pool::builder()
            .max_size(1)
            .build(SqliteConnectionManager::memory())
            .unwrap();
        let conn = pool.get().unwrap();
        conn.execute_batch(
            "CREATE TABLE rf_anomalies (tenant_id TEXT, dismissed INTEGER, snoozed_until TEXT,
                 anomaly_score REAL, priority TEXT, family TEXT, node_id TEXT);",
        )
        .unwrap();
        let now = chrono::Utc::now();
        // The expired snooze must be on the current UTC date for the old
        // text comparison ('T' > ' ') to have hidden it.
        let expired = std::cmp::max(
            now - chrono::Duration::seconds(30),
            now.date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc(),
        );
        for snoozed in [
            None,
            Some(iso(expired)),
            Some(iso(now + chrono::Duration::hours(1))),
            Some("not a timestamp".to_string()),
        ] {
            conn.execute(
                "INSERT INTO rf_anomalies VALUES ('default', 0, ?1, 0.9, 'high', 'fsk', 'n1')",
                [snoozed],
            )
            .unwrap();
        }
        let summary = get_anomaly_summary(&conn, 0.0).unwrap();
        // Active: never snoozed, snooze expired, unparseable (as the bridge
        // treats it). Hidden: snoozed until an hour from now.
        assert_eq!(summary.total, 3);
    }
}
