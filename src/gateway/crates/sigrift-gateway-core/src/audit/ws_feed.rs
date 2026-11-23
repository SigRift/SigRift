//! Real-time audit WebSocket feed — broadcasts new audit entries to admin
//! clients.
//!
//! Every entry the gateway writes is published on `AppState::audit_tx`
//! (see [`crate::audit::store::set_event_sink`]). Authentication (Admin),
//! re-validation and lag handling are those of every broadcast feed (see
//! [`crate::ws::feed`]).

use axum::{body::Body, extract::State, http::Request, response::Response};
use std::sync::Arc;

use crate::auth::rbac::Role;
use crate::ws::feed::serve_feed;
use crate::AppState;

pub async fn ws_audit_feed(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    // Admin only — audit data is sensitive.
    serve_feed(state, req, Role::Admin, "audit", |s| s.audit_tx.subscribe()).await
}
