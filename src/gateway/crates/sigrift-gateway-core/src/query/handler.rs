//! Read-only dashboard query endpoints.
//!
//! These mirror the Python endpoints so the dashboard JS can query
//! upperCrust directly for the heavy reads, leaving Python free for
//! admin/config work.

use axum::{
    body::Body,
    extract::{Query, State},
    http::{Request, StatusCode},
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::auth::rbac::Role;
use crate::db::queries;
use crate::middleware::auth::require_auth;
use crate::AppState;

/// Check auth if auth is enabled. Returns Err(status) on failure.
fn check_query_auth(state: &AppState, req: &Request<Body>) -> Result<(), StatusCode> {
    if state.auth_enabled {
        require_auth(req, Role::Viewer)?;
    }
    Ok(())
}

// ── GET /api/detections/recent ───────────────────────────────────────

#[derive(Deserialize)]
pub struct RecentParams {
    #[serde(default = "default_5")]
    pub minutes: i64,
    pub node_id: Option<String>,
    #[serde(default = "default_100")]
    pub limit: i64,
}

fn default_5() -> i64 {
    5
}
fn default_100() -> i64 {
    100
}

pub async fn get_recent(
    State(state): State<Arc<AppState>>,
    Query(params): Query<RecentParams>,
    req: Request<Body>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_query_auth(&state, &req)?;

    let minutes = params.minutes.clamp(1, 10080);
    let limit = params.limit.clamp(1, 1000);

    let conn = state
        .db_pool
        .get()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let detections = tokio::task::spawn_blocking(move || {
        queries::get_recent_detections(&conn, minutes, params.node_id.as_deref(), limit)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "count": detections.len(),
        "minutes": minutes,
        "detections": detections,
    })))
}

// ── GET /api/detections/timeline ─────────────────────────────────────

#[derive(Deserialize)]
pub struct TimelineParams {
    #[serde(default = "default_24")]
    pub hours: i64,
    #[serde(default = "default_300")]
    pub resolution: i64,
    pub node_id: Option<String>,
}

fn default_24() -> i64 {
    24
}
fn default_300() -> i64 {
    300
}

pub async fn get_timeline(
    State(state): State<Arc<AppState>>,
    Query(params): Query<TimelineParams>,
    req: Request<Body>,
) -> Result<Json<Vec<queries::TimelineBucket>>, StatusCode> {
    check_query_auth(&state, &req)?;

    let hours = params.hours.clamp(1, 168);
    let resolution = params.resolution.clamp(60, 3600);

    let conn = state
        .db_pool
        .get()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let buckets = tokio::task::spawn_blocking(move || {
        queries::get_timeline(&conn, hours, resolution, params.node_id.as_deref())
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(buckets))
}

// ── GET /api/detections/distribution ─────────────────────────────────

#[derive(Deserialize)]
pub struct DistributionParams {
    #[serde(default = "default_24")]
    pub hours: i64,
    #[serde(default)]
    pub min_confidence: f64,
}

pub async fn get_distribution(
    State(state): State<Arc<AppState>>,
    Query(params): Query<DistributionParams>,
    req: Request<Body>,
) -> Result<Json<Vec<queries::DistributionEntry>>, StatusCode> {
    check_query_auth(&state, &req)?;

    let hours = params.hours.clamp(1, 168);
    let min_confidence = params.min_confidence.clamp(0.0, 1.0);

    let conn = state
        .db_pool
        .get()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let dist = tokio::task::spawn_blocking(move || {
        queries::get_distribution(&conn, hours, min_confidence)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(dist))
}

// ── GET /api/detections/heatmap ──────────────────────────────────────

#[derive(Deserialize)]
pub struct HeatmapParams {
    #[serde(default = "default_24")]
    pub hours: i64,
    #[serde(default = "default_15")]
    pub resolution: i64,
}

fn default_15() -> i64 {
    15
}

pub async fn get_heatmap(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HeatmapParams>,
    req: Request<Body>,
) -> Result<Json<Vec<queries::HeatmapCell>>, StatusCode> {
    check_query_auth(&state, &req)?;

    let hours = params.hours.clamp(1, 168);
    let resolution = params.resolution.clamp(1, 60);

    let conn = state
        .db_pool
        .get()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let cells = tokio::task::spawn_blocking(move || queries::get_heatmap(&conn, hours, resolution))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(cells))
}

// ── GET /api/detections/summary + /api/detections/stats ──────────────

#[derive(Deserialize)]
pub struct StatsParams {
    #[serde(default = "default_24")]
    pub hours: i64,
}

pub async fn get_summary(
    State(state): State<Arc<AppState>>,
    Query(params): Query<StatsParams>,
    req: Request<Body>,
) -> Result<Json<queries::DetectionStats>, StatusCode> {
    check_query_auth(&state, &req)?;

    let hours = params.hours.clamp(1, 168);
    let conn = state
        .db_pool
        .get()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let stats = tokio::task::spawn_blocking(move || queries::get_stats(&conn, hours))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(stats))
}

// ── GET /api/detections/anomalies/summary ────────────────────────────

#[derive(Deserialize)]
pub struct AnomalySummaryParams {
    #[serde(default = "default_min_score")]
    pub min_score: f64,
}

fn default_min_score() -> f64 {
    0.0
} // Show all anomalies by default (was 0.3)

pub async fn get_anomaly_summary(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AnomalySummaryParams>,
    req: Request<Body>,
) -> Result<Json<queries::AnomalySummary>, StatusCode> {
    check_query_auth(&state, &req)?;

    let min_score = params.min_score.clamp(0.0, 1.0);

    let conn = state
        .db_pool
        .get()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let summary =
        tokio::task::spawn_blocking(move || queries::get_anomaly_summary(&conn, min_score))
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(summary))
}

// ── GET /api/status ──────────────────────────────────────────────────

pub async fn get_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let conn = state
        .db_pool
        .get()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let stats = tokio::task::spawn_blocking(move || queries::get_stats(&conn, 24))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "total_detections_24h": stats.total_24h,
        "detections_per_second": stats.detections_per_second,
        "active_anomalies": stats.active_anomalies,
        "active_frequencies": stats.active_frequencies,
        "unique_nodes": stats.unique_nodes,
        "unique_classes": stats.unique_classes,
        "avg_confidence": stats.avg_confidence,
        "uppercrust": true,
    })))
}

#[cfg(test)]
mod active_frequency_tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, Arc<AppState>) {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::test_support::app_state(&dir);
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch(
                "CREATE TABLE detections (
                tenant_id TEXT, timestamp TEXT, freq_hz REAL,
                node_id TEXT, signal_class TEXT, confidence REAL);
             CREATE TABLE rf_anomalies (
                tenant_id TEXT, dismissed INTEGER, snoozed_until TEXT);",
            )
            .unwrap();
        (dir, state)
    }

    #[tokio::test]
    async fn active_frequency_stats_empty_hour_is_zero() {
        let (_dir, state) = fixture();
        let stats = get_summary(
            State(state),
            Query(StatsParams { hours: 24 }),
            Request::new(Body::empty()),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(stats.active_frequencies, 0);
        assert_eq!(stats.total_24h, 0);
    }

    #[tokio::test]
    async fn active_frequency_stats_are_raw_last_hour_floor_buckets() {
        let (_dir, state) = fixture();
        let conn = state.db_pool.get().unwrap();
        // Deliberately straddle the rounding midpoint and exact bucket edge.
        // Old/foreign/invalid frequencies must not inflate the last-hour count.
        for (frequency, age, tenant, class) in [
            (Some(433_900_000.0), 0, "default", "bpsk"),
            (Some(433_949_999.0), 0, "default", "bpsk"),
            (Some(433_999_999.0), 0, "default", "qam16"),
            (Some(434_000_000.0), 0, "default", "bpsk"),
            (Some(500_000_000.0), 3590, "default", "bpsk"),
            (Some(600_000_000.0), 3610, "default", "bpsk"),
            (Some(700_000_000.0), 7200, "default", "bpsk"),
            (Some(800_000_000.0), 0, "other", "bpsk"),
            (Some(0.0), 0, "default", "bpsk"),
            (Some(-1.0), 0, "default", "bpsk"),
            (None, 0, "default", "bpsk"),
        ] {
            conn.execute(
                "INSERT INTO detections VALUES
                (?1, strftime('%Y-%m-%dT%H:%M:%f+00:00','now',?2), ?3, 'radio-a', ?4, 0.9)",
                rusqlite::params![tenant, format!("-{age} seconds"), frequency, class],
            )
            .unwrap();
        }
        for hours in [1, 6, 24] {
            let stats = get_summary(
                State(state.clone()),
                Query(StatsParams { hours }),
                Request::new(Body::empty()),
            )
            .await
            .unwrap()
            .0;
            assert_eq!(stats.active_frequencies, 3);
            assert_eq!(stats.total_24h, if hours == 1 { 8 } else { 10 });
        }
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM detections", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            11
        );
    }
}
