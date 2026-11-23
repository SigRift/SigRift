//! WebSocket anomaly feed — broadcasts RF anomalies to connected clients.
//!
//! Authentication, re-validation and lag handling are those of every
//! broadcast feed (see [`crate::ws::feed`]).

use axum::{body::Body, extract::State, http::Request, response::Response};
use std::sync::Arc;

use crate::auth::rbac::Role;
use crate::ws::feed::serve_feed;
use crate::AppState;

pub async fn ws_anomaly_feed(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    serve_feed(state, req, Role::Viewer, "anomalies", |s| {
        s.anomaly_tx.subscribe()
    })
    .await
}
