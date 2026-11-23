//! Read-only protocol query endpoints — Bluetooth and alerts.
//!
//! Pattern mirrors `query::handler` — check auth, spawn_blocking, return Json.

use axum::{
    body::Body,
    extract::{Query, State},
    http::{Request, StatusCode},
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::auth::rbac::Role;
use crate::db::protocol_queries;
use crate::middleware::auth::require_auth;
use crate::AppState;

fn check_query_auth(state: &AppState, req: &Request<Body>) -> Result<(), StatusCode> {
    if state.auth_enabled {
        require_auth(req, Role::Viewer)?;
    }
    Ok(())
}

// ── Query param structs ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PaginationParams {
    #[serde(default = "default_50")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_50() -> i64 {
    50
}

#[derive(Deserialize)]
pub struct AlertParams {
    #[serde(default = "default_50")]
    pub limit: i64,
}

// ── GET /api/bluetooth/stats ────────────────────────────────────────────

pub async fn get_bt_stats_handler(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_query_auth(&state, &req)?;

    let conn = state
        .db_pool
        .get()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let stats =
        tokio::task::spawn_blocking(move || protocol_queries::get_bt_stats(&conn, "default"))
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(stats))
}

// ── GET /api/bluetooth/devices ──────────────────────────────────────────

pub async fn get_bt_devices_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PaginationParams>,
    req: Request<Body>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_query_auth(&state, &req)?;

    let limit = params.limit.clamp(1, 500);
    let offset = params.offset.max(0);

    let conn = state
        .db_pool
        .get()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let devices = tokio::task::spawn_blocking(move || {
        protocol_queries::get_bt_devices(&conn, "default", limit, offset)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "count": devices.len(),
        "limit": limit,
        "offset": offset,
        "devices": devices,
    })))
}

// ── GET /api/alerts ─────────────────────────────────────────────────────

pub async fn get_alerts_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AlertParams>,
    req: Request<Body>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_query_auth(&state, &req)?;

    let limit = params.limit.clamp(1, 500);

    let conn = state
        .db_pool
        .get()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let alerts = tokio::task::spawn_blocking(move || {
        protocol_queries::get_alerts_list(&conn, "default", limit)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "count": alerts.len(),
        "alerts": alerts,
    })))
}
