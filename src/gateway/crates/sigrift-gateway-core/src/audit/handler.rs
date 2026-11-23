//! Admin audit HTTP endpoints — log viewer, chain verification, archive, export.

use axum::{
    body::Body,
    extract::{Query, State},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{info, warn};

use crate::audit::chain;
use crate::audit::store;
use crate::auth::rbac::Role;
use crate::middleware::auth::{require_auth, AuthConfig, AuthInfo};
use crate::storage::security_state::MAX_LOCKOUT_WINDOW_SECS;
use crate::storage::sessions;
use crate::AppState;

// The Err is the ready-made HTTP error response, returned as-is by handlers.
#[allow(clippy::result_large_err)]
fn get_secret(state: &AppState) -> Result<Vec<u8>, Response> {
    chain::get_audit_secret(&state.config.audit_key, &state.config.bridge_env).map_err(|e| {
        warn!(error = %e, "Failed to derive audit secret");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })
}

// ── GET /api/admin/audit ──────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AuditLogParams {
    #[serde(default = "default_200")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    pub action: Option<String>,
    pub operator: Option<String>,
    pub node_id: Option<String>,
    pub target_id: Option<String>,
    pub search: Option<String>,
    pub start: Option<String>,
    pub end: Option<String>,
    pub severity: Option<String>,
}

fn default_200() -> i64 {
    200
}

pub async fn get_audit_log(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuditLogParams>,
    req: Request<Body>,
) -> Response {
    if let Err(e) = require_auth(&req, Role::Admin) {
        return e.into_response();
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let limit = params.limit.clamp(1, 1000);
    let offset = params.offset.max(0);

    // `total` counts what the same filters select over all pages, as on the
    // bridge (routers/admin.py `get_audit_log`).
    let (entries, total) = match tokio::task::spawn_blocking(move || {
        let filter = store::AuditFilter {
            action: params.action.as_deref(),
            target_id: params.target_id.as_deref(),
            operator: params.operator.as_deref(),
            node_id: params.node_id.as_deref(),
            search: params.search.as_deref(),
            start: params.start.as_deref(),
            end: params.end.as_deref(),
            // `severity=` (empty) is no severity filter, as on the bridge
            // (`sev = severity if severity else None`); other empty
            // filters match empty values there too, so they stay as given.
            severity: params.severity.as_deref().filter(|s| !s.is_empty()),
        };
        store::get_audit_page(&conn, "default", &filter, limit, offset)
    })
    .await
    {
        Ok(Ok(page)) => page,
        Ok(Err(e)) => {
            warn!(error = %e, "Audit log query failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "count": entries.len(),
            "total": total,
            "offset": offset,
            "limit": limit,
            "entries": entries,
        })),
    )
        .into_response()
}

// ── GET /api/admin/audit/verify ───────────────────────────────────────

pub async fn verify_chain(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    if let Err(e) = require_auth(&req, Role::Admin) {
        return e.into_response();
    }

    let secret = match get_secret(&state) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let result =
        match tokio::task::spawn_blocking(move || store::verify_chain(&conn, "default", &secret))
            .await
        {
            Ok(Ok(r)) => r,
            _ => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };

    (StatusCode::OK, Json(result)).into_response()
}

// ── GET /api/admin/audit/filters ──────────────────────────────────────

pub async fn get_audit_filters(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    if let Err(e) = require_auth(&req, Role::Admin) {
        return e.into_response();
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let tenant_id = "default";
    let actions = store::get_audit_actions(&conn, tenant_id).unwrap_or_default();
    let operators = store::get_audit_operators(&conn, tenant_id).unwrap_or_default();
    let node_ids = store::get_audit_node_ids(&conn, tenant_id).unwrap_or_default();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "actions": actions,
            "operators": operators,
            "node_ids": node_ids,
        })),
    )
        .into_response()
}

// ── GET /api/admin/audit/actions ──────────────────────────────────────

pub async fn get_audit_actions(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    if let Err(e) = require_auth(&req, Role::Admin) {
        return e.into_response();
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let actions = store::get_audit_actions(&conn, "default").unwrap_or_default();
    (StatusCode::OK, Json(actions)).into_response()
}

// ── POST /api/admin/audit/archive ─────────────────────────────────────

#[derive(Deserialize)]
pub struct ArchiveParams {
    #[serde(default = "default_90")]
    pub days: u32,
}

fn default_90() -> u32 {
    90
}

/// Who performed an admin action, for the audit trail.
fn operator_of(auth: &AuthInfo) -> String {
    match auth {
        AuthInfo::Session { username, .. } => username.clone(),
        AuthInfo::ApiKey { key_id, .. } => key_id.clone(),
        AuthInfo::Unauthenticated => "unknown".into(),
    }
}

/// HTTP response for a failed archive/purge.
fn op_error_response(e: store::AuditOpError) -> Response {
    let status = match &e {
        store::AuditOpError::Invalid(_) => StatusCode::BAD_REQUEST,
        store::AuditOpError::Refused(_) => StatusCode::CONFLICT,
        store::AuditOpError::Db(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    (status, Json(serde_json::json!({"detail": e.to_string()}))).into_response()
}

pub async fn archive_audit(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    let auth = match require_auth(&req, Role::Admin) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let operator = operator_of(&auth);

    let body_bytes = match axum::body::to_bytes(req.into_body(), 4096).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let params: ArchiveParams =
        serde_json::from_slice(&body_bytes).unwrap_or(ArchiveParams { days: 90 });

    let secret = match get_secret(&state) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let days = params.days;
    let result = tokio::task::spawn_blocking(move || {
        store::archive_audit_log(
            &conn,
            "default",
            days,
            store::min_retention_days(),
            &secret,
            &operator,
        )
    })
    .await;
    match result {
        Ok(Ok(outcome)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "archived",
                "entries_moved": outcome.moved,
                "days_threshold": days,
                "last_archived_id": outcome.last_archived_id,
            })),
        )
            .into_response(),
        Ok(Err(e)) => op_error_response(e),
        Err(e) => {
            warn!(error = %e, "Archive task failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ── DELETE /api/admin/audit ───────────────────────────────────────────

pub async fn purge_archived(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ArchiveParams>,
    req: Request<Body>,
) -> Response {
    let auth = match require_auth(&req, Role::Admin) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let operator = operator_of(&auth);

    let secret = match get_secret(&state) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let days = params.days;
    let result = tokio::task::spawn_blocking(move || {
        store::purge_archived(
            &conn,
            "default",
            days,
            store::min_retention_days(),
            &secret,
            &operator,
        )
    })
    .await;
    match result {
        Ok(Ok(outcome)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "purged",
                "entries_deleted": outcome.deleted,
            })),
        )
            .into_response(),
        Ok(Err(e)) => op_error_response(e),
        Err(e) => {
            warn!(error = %e, "Purge task failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ── POST /api/admin/audit/export ──────────────────────────────────────

#[derive(Deserialize)]
pub struct ExportParams {
    pub start: Option<String>,
    pub end: Option<String>,
}

pub async fn export_audit(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    if let Err(e) = require_auth(&req, Role::Admin) {
        return e.into_response();
    }

    let body_bytes = match axum::body::to_bytes(req.into_body(), 4096).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let params: ExportParams = serde_json::from_slice(&body_bytes).unwrap_or(ExportParams {
        start: None,
        end: None,
    });

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    match store::export_audit_log(
        &conn,
        "default",
        params.start.as_deref(),
        params.end.as_deref(),
    ) {
        Ok(entries) => (StatusCode::OK, Json(entries)).into_response(),
        Err(e) => {
            warn!(error = %e, "Export failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ── GET /api/admin/settings/security ──────────────────────────────────

/// The adjustable security settings, as reported and as audited.
fn security_settings(config: &AuthConfig) -> serde_json::Map<String, serde_json::Value> {
    let serde_json::Value::Object(map) = serde_json::json!({
        "session_binding_mode": format!("{:?}", config.binding_mode).to_lowercase(),
        "session_absolute_timeout_hours": config.session_config.absolute_timeout_hours,
        "session_idle_timeout_minutes": config.session_config.idle_timeout_minutes,
        "csrf_enabled": config.csrf_enabled,
        "rate_limit_max": config.security_limits.rate_limit_max,
        "rate_limit_window_secs": config.security_limits.rate_limit_window_secs,
        "lockout_max": config.security_limits.lockout_max,
        "lockout_window_secs": config.security_limits.lockout_window_secs,
    }) else {
        unreachable!("json! object literal")
    };
    map
}

fn settings_response(
    config: &AuthConfig,
    state: &AppState,
    status: Option<&str>,
) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    if let Some(status) = status {
        map.insert("status".into(), status.into());
    }
    map.extend(security_settings(config));
    map.insert(
        "audit_archive_days".into(),
        state.config.audit_archive_days.into(),
    );
    serde_json::Value::Object(map)
}

pub async fn get_security_settings(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Response {
    if let Err(e) = require_auth(&req, Role::Admin) {
        return e.into_response();
    }

    let config = state.auth_config.read().await;
    (
        StatusCode::OK,
        Json(settings_response(&config, &state, None)),
    )
        .into_response()
}

// ── PUT /api/admin/settings/security ──────────────────────────────────

/// The session timeout settings, each with the largest value it accepts.
///
/// - An absolute timeout above [`sessions::MAX_ABSOLUTE_TIMEOUT_HOURS`]
///   used to overflow at session creation (a panic for every login), or
///   give an expiry past year 9999 that neither service can read.
/// - A huge idle timeout means no idle limit, and is used as `i64::MAX`.
///   Any integer serde_json reads is accepted (up to `u64::MAX`), so a
///   client that reads `i64::MAX` back as a JavaScript number and sends
///   it again (`9223372036854776000`) is not refused.
const SESSION_TIMEOUT_SETTINGS: [(&str, u64); 2] = [
    (
        "session_absolute_timeout_hours",
        sessions::MAX_ABSOLUTE_TIMEOUT_HOURS.unsigned_abs(),
    ),
    ("session_idle_timeout_minutes", u64::MAX),
];

/// The value a session timeout setting `key` (accepting at most `max`)
/// gets from `value`, or why `value` is refused:
///
/// - A number below 1, whatever it is written as. A non-positive idle
///   timeout makes every session idle at its next request (and deletes
///   it), a non-positive absolute one makes every new session expire as it
///   is created. Either locks session logins out until the setting is
///   reset. The bridge ignores such values of its
///   `BRIDGE_SESSION_*_TIMEOUT_*` variables in the same way (`val > 0`),
///   and so does the gateway (`Config::session_config`).
/// - A number above `max`, whatever it is written as: serde_json holds an
///   integer beyond `u64::MAX` written out in full as an f64.
/// - Anything else that is not a JSON integer (a string, `null`, a number
///   written with a fraction or an exponent, such as `1.5`, `24.0` or
///   `1e3`), which used to be silently ignored, so the request
///   "succeeded" without the change.
///
/// An integer above `i64::MAX` is used as `i64::MAX`.
fn session_timeout(key: &str, max: u64, value: &serde_json::Value) -> Result<i64, String> {
    let at_least_one = || format!("{key} must be at least 1");
    let at_most_max = || format!("{key} must be at most {max}");
    let serde_json::Value::Number(number) = value else {
        return Err(format!("{key} must be an integer"));
    };
    if let Some(v) = number.as_i64() {
        return if v < 1 {
            Err(at_least_one())
        } else if v.unsigned_abs() > max {
            Err(at_most_max())
        } else {
            Ok(v)
        };
    }
    if let Some(v) = number.as_u64() {
        // Above i64::MAX.
        return if v > max {
            Err(at_most_max())
        } else {
            Ok(i64::MAX)
        };
    }
    // An f64. `as i128` saturates, so 1e300 and 2^64 (the first f64 above
    // u64::MAX) are above `max`, and so is 10000000.5, rounded up.
    let v = number.as_f64().unwrap_or(f64::NAN);
    if v < 1.0 {
        Err(at_least_one())
    } else if v.ceil() as i128 > i128::from(max) {
        Err(at_most_max())
    } else {
        Err(format!("{key} must be an integer"))
    }
}

/// The login limit counts: attempts per client IP (`UC_RATE_LIMIT_MAX`)
/// and failed attempts per account (`UC_LOCKOUT_MAX`), both `u32`.
const LIMIT_COUNT_SETTINGS: [&str; 2] = ["rate_limit_max", "lockout_max"];

/// The login limit windows in seconds (`UC_RATE_LIMIT_WINDOW`,
/// `UC_LOCKOUT_WINDOW`), each with the largest value it accepts, if any.
/// The lockout window is at most [`MAX_LOCKOUT_WINDOW_SECS`]: the bridge
/// prunes the shared `account_lockout` table after that long, so a longer
/// window would not hold. The rate-limit window has no upper bound here
/// (the bridge's cleanup prunes its table to 60 seconds anyway; see
/// "Login rate limit" in the gateway README).
const LIMIT_WINDOW_SETTINGS: [(&str, Option<u64>); 2] = [
    ("rate_limit_window_secs", None),
    ("lockout_window_secs", Some(MAX_LOCKOUT_WINDOW_SECS)),
];

/// The value a login limit count `key` gets from `value`, or why `value`
/// is refused: anything but a JSON integer from 1 to `u32::MAX`, which is
/// what `UC_RATE_LIMIT_MAX` and `UC_LOCKOUT_MAX` accept.
///
/// - Above `u32::MAX`, whatever it is written as: it used to wrap, so
///   4294967296 was applied as 0.
/// - Below 1, whatever it is written as (`0`, `-1`, `0.5`): 0 refuses
///   every login, administrators' included (`reserve_account_attempt` and
///   `reserve_login_attempt` allow an attempt only below the count), until
///   the setting is reset or the gateway restarted. A negative one used to
///   be silently ignored, so the request "succeeded" without the change.
/// - Not an integer (a string, `null`, `1.5`, `7.0`): it used to be
///   silently ignored too.
fn limit_count(key: &str, value: &serde_json::Value) -> Result<u32, String> {
    let at_least_one = || format!("{key} must be at least 1");
    let at_most_max = || format!("{key} must be at most {}", u32::MAX);
    let serde_json::Value::Number(number) = value else {
        return Err(format!("{key} must be an integer"));
    };
    if let Some(v) = number.as_u64() {
        return match u32::try_from(v) {
            Ok(0) => Err(at_least_one()),
            Ok(v) => Ok(v),
            Err(_) => Err(at_most_max()),
        };
    }
    if number.is_i64() {
        // Negative (a non-negative one is a u64).
        return Err(at_least_one());
    }
    let v = number.as_f64().unwrap_or(f64::NAN);
    if v < 1.0 {
        Err(at_least_one())
    } else if v > f64::from(u32::MAX) {
        Err(at_most_max())
    } else {
        Err(format!("{key} must be an integer"))
    }
}

/// The value a login limit window `key` (accepting at most `max`, if any)
/// gets from `value`, or why `value` is refused: anything but a JSON
/// number from 1 to `max`. A fraction is accepted (the window is held as
/// an f64).
///
/// - Below 1 second (`0`, `0.5`, `1e-9`, `-1`): attempts are counted only
///   within the window before each new one, so such a window counts
///   practically no attempt, and a negative one (which used to be applied)
///   puts the cutoff in the future and counts none at all. Either turns
///   the rate limit or the lockout off. `UC_RATE_LIMIT_WINDOW` and
///   `UC_LOCKOUT_WINDOW` are at least 1 too.
/// - Above `max` (see [`LIMIT_WINDOW_SETTINGS`]).
/// - Not a number (a string, `null`): it used to be silently ignored.
fn limit_window(key: &str, max: Option<u64>, value: &serde_json::Value) -> Result<f64, String> {
    let Some(v) = value.as_f64() else {
        return Err(format!("{key} must be a number"));
    };
    if v < 1.0 {
        return Err(format!("{key} must be at least 1"));
    }
    if let Some(max) = max {
        if v > max as f64 {
            return Err(format!("{key} must be at most {max}"));
        }
    }
    Ok(v)
}

/// Refuse a session timeout (see [`session_timeout`]), login limit count
/// ([`limit_count`]) or login limit window ([`limit_window`]) that cannot
/// be applied as given.
fn check_security_updates(updates: &serde_json::Value) -> Result<(), String> {
    for (key, max) in SESSION_TIMEOUT_SETTINGS {
        if let Some(value) = updates.get(key) {
            session_timeout(key, max, value)?;
        }
    }
    for key in LIMIT_COUNT_SETTINGS {
        if let Some(value) = updates.get(key) {
            limit_count(key, value)?;
        }
    }
    for (key, max) in LIMIT_WINDOW_SETTINGS {
        if let Some(value) = updates.get(key) {
            limit_window(key, max, value)?;
        }
    }
    Ok(())
}

/// Apply the recognised fields of `updates` to `config`.
fn apply_security_updates(config: &mut AuthConfig, updates: &serde_json::Value) {
    if let Some(v) = updates.get("csrf_enabled").and_then(|v| v.as_bool()) {
        config.csrf_enabled = v;
    }
    if let Some(v) = updates.get("session_binding_mode").and_then(|v| v.as_str()) {
        config.binding_mode = crate::middleware::auth::SessionBindingMode::from(v);
    }
    let [absolute, idle] = SESSION_TIMEOUT_SETTINGS.map(|(key, max)| {
        updates
            .get(key)
            .and_then(|value| session_timeout(key, max, value).ok())
    });
    if let Some(v) = absolute {
        config.session_config.absolute_timeout_hours = v;
    }
    if let Some(v) = idle {
        config.session_config.idle_timeout_minutes = v;
    }
    let [rate_limit_max, lockout_max] = LIMIT_COUNT_SETTINGS.map(|key| {
        updates
            .get(key)
            .and_then(|value| limit_count(key, value).ok())
    });
    let [rate_limit_window, lockout_window] = LIMIT_WINDOW_SETTINGS.map(|(key, max)| {
        updates
            .get(key)
            .and_then(|value| limit_window(key, max, value).ok())
    });
    let limits = &mut config.security_limits;
    if let Some(v) = rate_limit_max {
        limits.rate_limit_max = v;
    }
    if let Some(v) = rate_limit_window {
        limits.rate_limit_window_secs = v;
    }
    if let Some(v) = lockout_max {
        limits.lockout_max = v;
    }
    if let Some(v) = lockout_window {
        limits.lockout_window_secs = v;
    }
}

/// `{setting: {"old": …, "new": …}}` for every setting that differs.
fn settings_diff(
    old: &serde_json::Map<String, serde_json::Value>,
    new: &serde_json::Map<String, serde_json::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    new.iter()
        .filter(|(key, value)| old.get(*key) != Some(*value))
        .map(|(key, value)| {
            (
                key.clone(),
                serde_json::json!({"old": old.get(key), "new": value}),
            )
        })
        .collect()
}

/// Serialises settings changes, so the audited old → new values are the
/// ones actually applied.
static SETTINGS_UPDATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Update the security settings. Every change is written to the audit log
/// (operator, old → new values) **before** it is applied; if that write
/// fails, nothing is changed.
pub async fn set_security_settings(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Response {
    let auth = match require_auth(&req, Role::Admin) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let operator = operator_of(&auth);

    let body_bytes = match axum::body::to_bytes(req.into_body(), 4096).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let updates: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"detail": "Invalid JSON body"})),
            )
                .into_response();
        }
    };
    if let Err(detail) = check_security_updates(&updates) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "detail": detail })),
        )
            .into_response();
    }

    // Audit-then-apply runs as its own task. If the client goes away, the
    // server drops this handler's future at its next await; were the audit
    // write awaited here, the entry could be committed (the blocking write
    // runs to completion regardless) and the change never applied. The
    // spawned task is not cancelled with the request, so a change that was
    // recorded is always applied.
    let task = tokio::spawn(audit_and_apply_security_updates(
        Arc::clone(&state),
        operator,
        updates,
    ));
    match task.await {
        Ok(Ok(())) => {}
        Ok(Err(refused)) => return refused,
        Err(e) => {
            warn!(error = %e, "Security settings task failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    // Return updated settings
    let config = state.auth_config.read().await;
    (
        StatusCode::OK,
        Json(settings_response(&config, &state, Some("updated"))),
    )
        .into_response()
}

/// Write the audit entry for `updates` (if they change anything) and then
/// apply them. The `Err` is the response for a change that could not be
/// recorded, and so was not applied.
#[allow(clippy::result_large_err)] // the Err is the ready-made response
async fn audit_and_apply_security_updates(
    state: Arc<AppState>,
    operator: String,
    updates: serde_json::Value,
) -> Result<(), Response> {
    let _serialised = SETTINGS_UPDATE.lock().await;
    let (old, new) = {
        let current = state.auth_config.read().await;
        let mut proposed = current.clone();
        apply_security_updates(&mut proposed, &updates);
        (security_settings(&current), security_settings(&proposed))
    };
    let changes = settings_diff(&old, &new);
    if changes.is_empty() {
        return Ok(());
    }

    let changed: Vec<String> = changes.keys().cloned().collect();
    let details = serde_json::json!({ "changes": changes }).to_string();
    let note = format!("Security settings changed: {}", changed.join(", "));
    let recorded = match (get_secret(&state), state.db_pool.get()) {
        (Ok(secret), Ok(conn)) => tokio::task::spawn_blocking(move || {
            store::log_audit(
                &conn,
                &secret,
                "security_settings_changed",
                "settings/security",
                &operator,
                &note,
                &details,
                "",
                0.0,
                "",
                "default",
            )
            .is_ok()
        })
        .await
        .unwrap_or(false),
        _ => false,
    };
    if !recorded {
        warn!(
            settings = ?changed,
            "Security settings change refused: it could not be written to the audit log"
        );
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "detail": "The change could not be recorded in the audit log; nothing was changed."
            })),
        )
            .into_response());
    }
    info!(settings = ?changed, "Security settings changed");
    apply_security_updates(&mut *state.auth_config.write().await, &updates);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;

    fn admin_request(method: &str, uri: &str, body: serde_json::Value) -> Request<Body> {
        admin_request_text(method, uri, body.to_string())
    }

    /// [`admin_request`] with the body as JSON text, for numbers that a
    /// `serde_json::Value` would write differently (`1e20` for
    /// `100000000000000000000`).
    fn admin_request_text(method: &str, uri: &str, body: String) -> Request<Body> {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        req.extensions_mut().insert(AuthInfo::Session {
            username: "alice".into(),
            user_id: 1,
            role: Role::Admin,
            session_token: "tok".into(),
            expires_at: "2099-01-01T00:00:00+00:00".into(),
            tenant_id: "default".into(),
            scope: String::new(),
        });
        req
    }

    fn latest(state: &AppState, action: &str) -> store::AuditEntry {
        let conn = state.db_pool.get().unwrap();
        let filter = store::AuditFilter {
            action: Some(action),
            ..Default::default()
        };
        store::get_audit_log(&conn, "default", &filter, 1, 0)
            .unwrap()
            .remove(0)
    }

    async fn json_body(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn security_settings_changes_are_audited_with_old_and_new_values() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        assert!(!state.auth_config.read().await.csrf_enabled);

        let req = admin_request(
            "PUT",
            "/api/admin/settings/security",
            serde_json::json!({"csrf_enabled": true, "session_binding_mode": "strict",
                               "lockout_max": 100}),
        );
        let resp = set_security_settings(State(state.clone()), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(state.auth_config.read().await.csrf_enabled);

        let entry = latest(&state, "security_settings_changed");
        assert_eq!(entry.operator, "alice");
        assert_eq!(entry.details["severity"], "warning");
        let changes = &entry.details["changes"];
        assert_eq!(
            changes["csrf_enabled"],
            serde_json::json!({"old": false, "new": true})
        );
        assert_eq!(
            changes["session_binding_mode"],
            serde_json::json!({"old": "none", "new": "strict"})
        );
        // lockout_max was already 100: unchanged settings are not listed.
        assert!(changes.get("lockout_max").is_none(), "{changes}");

        // A request that changes nothing writes nothing.
        let req = admin_request(
            "PUT",
            "/api/admin/settings/security",
            serde_json::json!({"csrf_enabled": true}),
        );
        let resp = set_security_settings(State(state.clone()), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            test_support::audit_count(&state, "security_settings_changed"),
            1
        );
    }

    /// A session timeout below 1 would end every session at once, so the
    /// request is refused (400) and nothing in it is applied or recorded.
    /// The smallest valid values are applied, and so is a huge idle
    /// timeout, which is no idle limit: a session keeps validating.
    #[tokio::test]
    async fn session_timeouts_below_one_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let put = |body: serde_json::Value| {
            set_security_settings(
                State(state.clone()),
                admin_request("PUT", "/api/admin/settings/security", body),
            )
        };

        for body in [
            serde_json::json!({"session_idle_timeout_minutes": 0}),
            serde_json::json!({"session_idle_timeout_minutes": -1}),
            serde_json::json!({"session_idle_timeout_minutes": i64::MIN}),
            serde_json::json!({"session_absolute_timeout_hours": 0}),
            serde_json::json!({"session_absolute_timeout_hours": -24}),
            serde_json::json!({"csrf_enabled": true, "session_idle_timeout_minutes": -5}),
        ] {
            let resp = put(body.clone()).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{body}");
            let detail = json_body(resp).await["detail"].to_string();
            assert!(detail.contains("must be at least 1"), "{body}: {detail}");
        }
        {
            let config = state.auth_config.read().await;
            assert_eq!(config.session_config.absolute_timeout_hours, 24);
            assert_eq!(config.session_config.idle_timeout_minutes, 30);
            assert!(!config.csrf_enabled, "nothing in a refused request");
        }
        assert_eq!(
            test_support::audit_count(&state, "security_settings_changed"),
            0
        );

        for (key, value) in [
            ("session_absolute_timeout_hours", 1),
            ("session_idle_timeout_minutes", 1),
            ("session_idle_timeout_minutes", i64::MAX),
        ] {
            let resp = put(serde_json::json!({ key: value })).await;
            assert_eq!(resp.status(), StatusCode::OK, "{key} = {value}");
            assert_eq!(json_body(resp).await[key], value, "{key} = {value}");
        }
        let config = state.auth_config.read().await.session_config.clone();
        assert_eq!(config.idle_timeout_minutes, i64::MAX);
        let conn = state.db_pool.get().unwrap();
        let user = crate::storage::users::tests::insert_user(&conn, "alice", "viewer", true);
        let (token, _) = sessions::create_session(&conn, user, "", "", &config).unwrap();
        assert!(sessions::validate_session(&conn, &token, &config)
            .unwrap()
            .is_some());
    }

    /// Regression: any i64 absolute timeout was applied and audited, so
    /// `i64::MAX` or 3e9 hours made every login panic and 1e8 hours gave
    /// sessions an expiry no request could read. A timeout that is not an
    /// i64 (`1.5`, `"abc"`) was ignored with 200. Both are now refused
    /// (400), and nothing in the request is applied or recorded. Each is
    /// told why: a number outside the range is out of range whatever it is
    /// written as (an integer above `i64::MAX` was "not an integer"). The
    /// ceiling itself is applied.
    #[tokio::test]
    async fn session_timeouts_too_large_or_not_integers_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let put = |key: &str, value: &str| {
            set_security_settings(
                State(state.clone()),
                admin_request_text(
                    "PUT",
                    "/api/admin/settings/security",
                    format!(r#"{{"csrf_enabled": true, "{key}": {value}}}"#),
                ),
            )
        };

        const ABSOLUTE: &str = "session_absolute_timeout_hours";
        const IDLE: &str = "session_idle_timeout_minutes";
        let not_integers = [
            "1.0", "1.5", "24.0", "1e3", r#""24""#, r#""abc""#, "null", "true", "[24]", "{}",
        ];
        let below_one = ["0.5", "0.0", "-0.0", "-1e20", "-9223372036854775809"];
        let mut refused: Vec<(&str, &str, &str)> = Vec::new();
        for key in [ABSOLUTE, IDLE] {
            refused.extend(not_integers.map(|v| (key, v, "must be an integer")));
            refused.extend(below_one.map(|v| (key, v, "must be at least 1")));
        }
        for hours in [
            "10000001",
            "100000000",
            "3000000000",
            "9223372036854775807",
            "9223372036854775808",
            "18446744073709551615",
            "100000000000000000000",
            "10000001.0",
            "10000000.5",
            "1e20",
            "1.5e300",
        ] {
            refused.push((ABSOLUTE, hours, "must be at most 10000000"));
        }
        // Within the range, so not an integer is what is wrong with them.
        refused.push((ABSOLUTE, "10000000.0", "must be an integer"));
        refused.push((IDLE, "9.3e18", "must be an integer"));
        // Above the largest integer serde_json holds.
        for minutes in ["18446744073709551616", "100000000000000000000", "1e20"] {
            refused.push((IDLE, minutes, "must be at most 18446744073709551615"));
        }
        for (key, value, expected) in refused {
            let resp = put(key, value).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{key}: {value}");
            assert_eq!(
                json_body(resp).await["detail"],
                format!("{key} {expected}"),
                "{key}: {value}"
            );
        }
        {
            let config = state.auth_config.read().await;
            assert_eq!(config.session_config.absolute_timeout_hours, 24);
            assert_eq!(config.session_config.idle_timeout_minutes, 30);
            assert!(!config.csrf_enabled, "nothing in a refused request");
        }
        assert_eq!(
            test_support::audit_count(&state, "security_settings_changed"),
            0
        );

        let resp = put(ABSOLUTE, "10000000").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(json_body(resp).await[ABSOLUTE], 10_000_000);
        assert_eq!(
            test_support::audit_count(&state, "security_settings_changed"),
            1
        );
    }

    /// Regression: a huge idle timeout is reported as `i64::MAX` (set
    /// through this API, or `BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES` with 20
    /// digits). A JavaScript client reads that as 2^63 and writes it back
    /// as `9223372036854776000`, which was refused with 400 ("must be an
    /// integer"), and so was every other setting in the request. Every
    /// integer serde_json holds, up to `u64::MAX`, is now accepted for the
    /// idle timeout and used as `i64::MAX`, which is no idle limit.
    #[tokio::test]
    async fn an_idle_timeout_above_i64_max_is_used_as_i64_max() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let put = |body: &str| {
            set_security_settings(
                State(state.clone()),
                admin_request_text("PUT", "/api/admin/settings/security", body.to_string()),
            )
        };
        const IDLE: &str = "session_idle_timeout_minutes";

        let resp = put(r#"{"session_idle_timeout_minutes": 18446744073709551615}"#).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(json_body(resp).await[IDLE], i64::MAX);
        assert_eq!(
            state
                .auth_config
                .read()
                .await
                .session_config
                .idle_timeout_minutes,
            i64::MAX
        );
        assert_eq!(
            test_support::audit_count(&state, "security_settings_changed"),
            1
        );
        let details = latest(&state, "security_settings_changed").details;
        assert_eq!(
            details["changes"][IDLE],
            serde_json::json!({"old": 30, "new": i64::MAX})
        );

        // What a JavaScript client sends back: `String(9223372036854775807)`.
        let written_back = "9223372036854776000";
        assert_eq!(written_back.parse::<f64>().unwrap(), i64::MAX as f64);
        let get = get_security_settings(
            State(state.clone()),
            admin_request("GET", "/api/admin/settings/security", serde_json::json!({})),
        )
        .await;
        assert_eq!(json_body(get).await[IDLE], i64::MAX);
        let resp = put(&format!(
            r#"{{"csrf_enabled": true, "{IDLE}": {written_back}}}"#
        ))
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(json_body(resp).await[IDLE], i64::MAX);
        let config = state.auth_config.read().await;
        assert!(config.csrf_enabled);
        assert_eq!(config.session_config.idle_timeout_minutes, i64::MAX);
        drop(config);
        // Only csrf_enabled changed.
        let details = latest(&state, "security_settings_changed").details;
        let changed: Vec<&String> = details["changes"].as_object().unwrap().keys().collect();
        assert_eq!(changed, ["csrf_enabled"]);
    }

    /// Regression: any `lockout_window_secs` was applied, but the bridge's
    /// cleanup prunes `account_lockout` rows older than
    /// [`MAX_LOCKOUT_WINDOW_SECS`], so a longer window did not hold. Such a
    /// request is refused (400) and nothing in it is applied or recorded;
    /// the ceiling itself is applied.
    #[tokio::test]
    async fn a_lockout_window_longer_than_the_bridge_keeps_failures_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let put = |value: &str| {
            set_security_settings(
                State(state.clone()),
                admin_request_text(
                    "PUT",
                    "/api/admin/settings/security",
                    format!(r#"{{"csrf_enabled": true, "lockout_window_secs": {value}}}"#),
                ),
            )
        };
        let before = state
            .auth_config
            .read()
            .await
            .security_limits
            .lockout_window_secs;
        for value in ["86401", "86400.5", "604800", "1e300"] {
            let resp = put(value).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{value}");
            assert_eq!(
                json_body(resp).await["detail"],
                "lockout_window_secs must be at most 86400",
                "{value}"
            );
        }
        {
            let config = state.auth_config.read().await;
            assert_eq!(config.security_limits.lockout_window_secs, before);
            assert!(!config.csrf_enabled, "nothing in a refused request");
        }
        assert_eq!(
            test_support::audit_count(&state, "security_settings_changed"),
            0
        );

        for (value, applied) in [("86400", 86_400.0), ("3600.5", 3600.5)] {
            let resp = put(value).await;
            assert_eq!(resp.status(), StatusCode::OK, "{value}");
            assert_eq!(json_body(resp).await["lockout_window_secs"], applied);
            let config = state.auth_config.read().await;
            assert_eq!(config.security_limits.lockout_window_secs, applied);
        }
    }

    #[tokio::test]
    async fn security_settings_are_not_changed_when_the_change_cannot_be_audited() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch("DROP TABLE audit_log")
            .unwrap();

        let req = admin_request(
            "PUT",
            "/api/admin/settings/security",
            serde_json::json!({"csrf_enabled": true}),
        );
        let resp = set_security_settings(State(state.clone()), req).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!state.auth_config.read().await.csrf_enabled);
    }

    /// A client that disconnects while the audit entry is being written
    /// must not leave a recorded change unapplied.
    #[tokio::test]
    async fn a_recorded_security_settings_change_is_applied_even_if_the_client_goes_away() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        assert!(!state.auth_config.read().await.csrf_enabled);

        // Another writer holds the database, so the audit write waits
        // (busy_timeout) ...
        let blocker = rusqlite::Connection::open(dir.path().join("auth.db")).unwrap();
        blocker.execute_batch("BEGIN IMMEDIATE").unwrap();

        // ... while the client gives up: the handler's future is dropped.
        let req = admin_request(
            "PUT",
            "/api/admin/settings/security",
            serde_json::json!({"csrf_enabled": true}),
        );
        let cancelled = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            set_security_settings(State(state.clone()), req),
        )
        .await;
        assert!(cancelled.is_err(), "the request was still waiting");
        assert_eq!(
            test_support::audit_count(&state, "security_settings_changed"),
            0
        );

        // The writer finishes; the audit write goes through.
        blocker.execute_batch("ROLLBACK").unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while test_support::audit_count(&state, "security_settings_changed") == 0
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(
            test_support::audit_count(&state, "security_settings_changed"),
            1
        );
        // The recorded change was applied too.
        while !state.auth_config.read().await.csrf_enabled && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            state.auth_config.read().await.csrf_enabled,
            "the audit log records a change that was never applied"
        );
    }

    /// The admin UI's severity filter against a log the bridge also writes:
    /// its entries logged without details store details = ''.
    #[tokio::test]
    async fn audit_severity_filter_serves_logs_holding_bridge_entries_without_details() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        {
            let conn = state.db_pool.get().unwrap();
            conn.execute(
                "INSERT INTO audit_log (timestamp, action, target_id, details, tenant_id) \
                 VALUES ('2026-01-01T00:00:00+00:00', 'dismiss', 'det-1', '', 'default')",
                [],
            )
            .unwrap();
        }
        let req = admin_request(
            "PUT",
            "/api/admin/settings/security",
            serde_json::json!({"csrf_enabled": true}),
        );
        let resp = set_security_settings(State(state.clone()), req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        for (severity, actions) in [
            ("warning", vec!["security_settings_changed"]),
            ("info", vec!["dismiss"]),
            ("critical", vec![]),
        ] {
            let params: AuditLogParams =
                serde_json::from_value(serde_json::json!({ "severity": severity })).unwrap();
            let req = admin_request(
                "GET",
                &format!("/api/admin/audit?severity={severity}"),
                serde_json::json!({}),
            );
            let resp = get_audit_log(State(state.clone()), Query(params), req).await;
            assert_eq!(resp.status(), StatusCode::OK, "{severity}");
            let body = json_body(resp).await;
            let listed: Vec<&str> = body["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["action"].as_str().unwrap())
                .collect();
            assert_eq!(listed, actions, "{severity}");
        }
    }

    /// `GET /api/admin/audit?{query}`: the notes listed, in order, with
    /// `count` and `total`.
    async fn audit_page(state: &Arc<AppState>, query: &str) -> (Vec<String>, i64, i64) {
        let uri: axum::http::Uri = format!("/api/admin/audit?{query}").parse().unwrap();
        let Query(params) = Query::<AuditLogParams>::try_from_uri(&uri).unwrap();
        let req = admin_request("GET", &uri.to_string(), serde_json::json!({}));
        let resp = get_audit_log(State(state.clone()), Query(params), req).await;
        assert_eq!(resp.status(), StatusCode::OK, "{query}");
        let body = json_body(resp).await;
        let notes = body["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["note"].as_str().unwrap().to_string())
            .collect();
        (
            notes,
            body["count"].as_i64().unwrap(),
            body["total"].as_i64().unwrap(),
        )
    }

    /// Assert the gateway answers each query as the bridge does: the notes
    /// it lists, in order, `count`, and `total`. Each case holds the
    /// bridge's answer over the same rows
    /// ([`store::tests::insert_bridge_audit_rows`]), recorded from its
    /// `GET /api/admin/audit` (sigrift/bridge/routers/admin.py) with its
    /// TestClient.
    async fn assert_audit_pages_match_the_bridge(cases: &[(&str, &[&str], i64)]) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        store::tests::insert_bridge_audit_rows(&state.db_pool.get().unwrap());
        let mut mismatches = Vec::new();
        for &(query, notes, total) in cases {
            let (listed, count, got_total) = audit_page(&state, query).await;
            if listed != notes || count != notes.len() as i64 || got_total != total {
                mismatches.push(format!(
                    "{query:?}: gateway lists {listed:?} (count {count}, total {got_total}), \
                     bridge {notes:?} (total {total})"
                ));
            }
        }
        assert!(mismatches.is_empty(), "\n{}", mismatches.join("\n"));
    }

    const ALL_NOTES: [&str; 8] = [
        "C:\\temp",
        "a_b",
        "100% done",
        "x",
        "crit",
        "pw",
        "false positive",
        "hello",
    ];

    /// `total` is what a UI paginates on: the entries the filters select
    /// over all pages, as on the bridge, not the size of the whole log.
    #[tokio::test]
    async fn audit_total_counts_the_entries_every_filter_selects_as_on_the_bridge() {
        let info: &[&str] = &[
            "C:\\temp",
            "a_b",
            "100% done",
            "x",
            "false positive",
            "hello",
        ];
        assert_audit_pages_match_the_bridge(&[
            ("", &ALL_NOTES, 8),
            ("action=login", &["100% done", "hello"], 2),
            ("action=dismiss", &["a_b", "false positive"], 2),
            ("operator=alice", &["100% done", "pw", "hello"], 3),
            ("operator=bob", &["a_b", "x", "false positive"], 3),
            ("node_id=n2", &["a_b", "x", "false positive"], 3),
            ("target_id=t1", &["a_b", "crit", "hello"], 3),
            ("target_id=det_42", &["C:\\temp"], 1),
            ("search=pw", &["pw"], 1),
            ("start=2026-03-01T00:00:00%2B00:00", &ALL_NOTES[..6], 6),
            (
                "end=2026-03-01T00:00:00%2B00:00",
                &["pw", "false positive", "hello"],
                3,
            ),
            (
                "start=2026-02-01T00:00:00%2B00:00&end=2026-05-01T00:00:00%2B00:00",
                &["x", "crit", "pw", "false positive"],
                4,
            ),
            ("severity=info", info, 6),
            ("severity=warning", &["pw"], 1),
            ("severity=critical", &["crit"], 1),
            ("severity=%27%20OR%20%271%27%3D%271", &[], 0),
            (
                "action=dismiss&operator=bob&severity=info",
                &["a_b", "false positive"],
                2,
            ),
            // Pages: `total` stays the filtered total.
            ("action=login&limit=1", &["100% done"], 2),
            ("limit=5&offset=6", &["false positive", "hello"], 8),
        ])
        .await;
    }

    /// Like the bridge, `search` is a literal substring of the note, the
    /// target id or the action: `%`, `_` and `\` in it match only
    /// themselves, in each of the three.
    #[tokio::test]
    async fn audit_search_matches_like_wildcards_literally_as_on_the_bridge() {
        assert_audit_pages_match_the_bridge(&[
            ("search=%25", &["100% done"], 1),
            // `_` is in the note of a_b, the action of crit and pw, and
            // the target id (det_42) of C:\temp.
            ("search=_", &["C:\\temp", "a_b", "crit", "pw"], 4),
            ("search=det_42", &["C:\\temp"], 1),
            ("search=a_b", &["a_b"], 1),
            ("search=100%25", &["100% done"], 1),
            ("search=%5Ct", &["C:\\temp"], 1),
            ("search=%5C", &["C:\\temp"], 1),
            ("search=%25&limit=1", &["100% done"], 1),
        ])
        .await;
    }

    /// The bridge reads `severity=` (empty) as no severity filter.
    #[tokio::test]
    async fn an_empty_audit_severity_is_no_filter_as_on_the_bridge() {
        assert_audit_pages_match_the_bridge(&[
            ("severity=", &ALL_NOTES, 8),
            ("severity=&limit=2", &ALL_NOTES[..2], 8),
        ])
        .await;
    }

    /// Every other empty filter, and a blank severity, applies as given, as
    /// on the bridge: an empty exact filter, `end` or a blank severity
    /// selects nothing; an empty `start` or `search` selects everything.
    #[tokio::test]
    async fn other_empty_or_blank_audit_filters_apply_as_given_as_on_the_bridge() {
        assert_audit_pages_match_the_bridge(&[
            ("action=", &[], 0),
            ("operator=", &[], 0),
            ("node_id=", &[], 0),
            ("target_id=", &[], 0),
            ("end=", &[], 0),
            ("severity=%20", &[], 0),
            ("start=", &ALL_NOTES, 8),
            ("search=", &ALL_NOTES, 8),
        ])
        .await;
    }

    /// An audit log that cannot be read is a 500, never a 200 with an empty
    /// page and `total: 0`, which would show an empty, clean log.
    #[tokio::test]
    async fn an_audit_log_that_cannot_be_read_is_a_500_not_an_empty_page() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        store::tests::insert_bridge_audit_rows(&state.db_pool.get().unwrap());
        assert_eq!(audit_page(&state, "").await.2, 8);
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch("DROP TABLE audit_log")
            .unwrap();

        for query in ["", "severity=info&limit=1", "search=pw"] {
            let uri: axum::http::Uri = format!("/api/admin/audit?{query}").parse().unwrap();
            let Query(params) = Query::<AuditLogParams>::try_from_uri(&uri).unwrap();
            let req = admin_request("GET", &uri.to_string(), serde_json::json!({}));
            let resp = get_audit_log(State(state.clone()), Query(params), req).await;
            assert_eq!(
                resp.status(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "{query:?}"
            );
        }
    }

    #[tokio::test]
    async fn archive_and_purge_endpoints_enforce_the_minimum_retention() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);

        let req = admin_request(
            "POST",
            "/api/admin/audit/archive",
            serde_json::json!({"days": 0}),
        );
        let resp = archive_audit(State(state.clone()), req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(json_body(resp).await["detail"]
            .as_str()
            .unwrap()
            .contains("at least"));

        let req = admin_request("DELETE", "/api/admin/audit?days=0", serde_json::json!({}));
        let resp =
            purge_archived(State(state.clone()), Query(ArchiveParams { days: 0 }), req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // A valid archive and purge succeed and are recorded with the operator.
        let req = admin_request(
            "POST",
            "/api/admin/audit/archive",
            serde_json::json!({"days": 30}),
        );
        let resp = archive_audit(State(state.clone()), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(json_body(resp).await["entries_moved"], 0);
        assert_eq!(latest(&state, "audit_archive").operator, "alice");

        let req = admin_request("DELETE", "/api/admin/audit?days=30", serde_json::json!({}));
        let resp =
            purge_archived(State(state.clone()), Query(ArchiveParams { days: 30 }), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(latest(&state, "audit_purge").operator, "alice");

        // Both are part of a chain that still verifies.
        let req = admin_request("GET", "/api/admin/audit/verify", serde_json::json!({}));
        let resp = verify_chain(State(state.clone()), req).await;
        assert_eq!(json_body(resp).await["valid"], true);
    }

    #[test]
    fn settings_diff_lists_only_changed_values() {
        let old = serde_json::json!({"a": 1, "b": true});
        let new = serde_json::json!({"a": 2, "b": true});
        let diff = settings_diff(old.as_object().unwrap(), new.as_object().unwrap());
        assert_eq!(
            serde_json::Value::Object(diff),
            serde_json::json!({"a": {"old": 1, "new": 2}})
        );
    }

    // ── Through the routes ────────────────────────────────────────────

    /// The audit and security-settings routes, mounted as builder.rs
    /// mounts them. Each request carries the `AuthInfo` the auth
    /// middleware would resolve for it (none: no credentials).
    fn audit_routes(state: &Arc<AppState>) -> axum::Router {
        use axum::routing::{get, post};
        axum::Router::new()
            .route(
                "/api/admin/audit",
                get(get_audit_log).delete(purge_archived),
            )
            .route("/api/admin/audit/verify", get(verify_chain))
            .route("/api/admin/audit/filters", get(get_audit_filters))
            .route("/api/admin/audit/actions", get(get_audit_actions))
            .route("/api/admin/audit/archive", post(archive_audit))
            .route("/api/admin/audit/export", post(export_audit))
            .route(
                "/api/admin/settings/security",
                get(get_security_settings).put(set_security_settings),
            )
            .with_state(Arc::clone(state))
    }

    /// Every route of [`audit_routes`]: method, URI and body.
    const ADMIN_ROUTES: [(&str, &str, &str); 9] = [
        ("GET", "/api/admin/audit", ""),
        ("DELETE", "/api/admin/audit?days=30", ""),
        ("GET", "/api/admin/audit/verify", ""),
        ("GET", "/api/admin/audit/filters", ""),
        ("GET", "/api/admin/audit/actions", ""),
        ("POST", "/api/admin/audit/archive", r#"{"days": 30}"#),
        ("POST", "/api/admin/audit/export", "{}"),
        ("GET", "/api/admin/settings/security", ""),
        (
            "PUT",
            "/api/admin/settings/security",
            r#"{"csrf_enabled": true}"#,
        ),
    ];

    async fn send(
        app: &axum::Router,
        auth: Option<&AuthInfo>,
        method: &str,
        uri: &str,
        body: impl Into<Body>,
    ) -> (StatusCode, serde_json::Value) {
        use tower::ServiceExt as _;
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(body.into())
            .unwrap();
        if let Some(auth) = auth {
            req.extensions_mut().insert(auth.clone());
        }
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    fn session(role: Role) -> AuthInfo {
        AuthInfo::Session {
            username: format!("{}-user", role.as_str()),
            user_id: 7,
            role,
            session_token: "tok".into(),
            expires_at: "2099-01-01T00:00:00+00:00".into(),
            tenant_id: "default".into(),
            scope: String::new(),
        }
    }

    fn api_key(key_id: &str, role: Role) -> AuthInfo {
        AuthInfo::ApiKey {
            key_id: key_id.into(),
            role,
        }
    }

    fn audit_secret(state: &AppState) -> Vec<u8> {
        chain::get_audit_secret(&state.config.audit_key, &state.config.bridge_env).unwrap()
    }

    fn days_ago(days: i64) -> String {
        (chrono::Utc::now() - chrono::Duration::days(days))
            .format("%Y-%m-%dT%H:%M:%S+00:00")
            .to_string()
    }

    /// Append an entry of tenant `default` signed (v3) under `secret` and
    /// chained from the newest one, as the bridge writes it. Returns its id.
    fn insert_signed(state: &AppState, secret: &[u8], action: &str, timestamp: &str) -> i64 {
        use rusqlite::OptionalExtension as _;
        let conn = state.db_pool.get().unwrap();
        let previous: String = conn
            .query_row(
                "SELECT hmac_chain FROM audit_log WHERE tenant_id = 'default' \
                 ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()
            .unwrap()
            .unwrap_or_default();
        let hmac = chain::compute_hmac_v3(
            secret, &previous, action, "t", "bridge", timestamp, "", "", "", "0.0", "", "",
            "default",
        );
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, target_id, operator, tenant_id, \
             hmac_chain) VALUES (?1, ?2, 't', 'bridge', 'default', ?3)",
            rusqlite::params![timestamp, action, hmac],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    fn rows(state: &AppState, table: &str) -> i64 {
        state
            .db_pool
            .get()
            .unwrap()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    /// The handlers are the only role check these routes have (the auth
    /// middleware only resolves who is calling): no credentials is 401, and
    /// every role below ADMIN, session or API key, is 403 on every route,
    /// with nothing archived, purged, changed or recorded. ADMIN and
    /// KEYMASTER get through, and what they change is recorded under the
    /// session's user or the key's id.
    #[tokio::test]
    async fn every_audit_and_security_settings_route_requires_an_admin() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let secret = audit_secret(&state);
        for i in 0..3 {
            insert_signed(&state, &secret, &format!("old_{i}"), &days_ago(60));
        }
        let app = audit_routes(&state);

        let refused = [
            (None, StatusCode::UNAUTHORIZED),
            (Some(session(Role::Viewer)), StatusCode::FORBIDDEN),
            (Some(session(Role::Analyst)), StatusCode::FORBIDDEN),
            (Some(session(Role::Sensor)), StatusCode::FORBIDDEN),
            (
                Some(api_key("analyst-key", Role::Analyst)),
                StatusCode::FORBIDDEN,
            ),
            (Some(api_key("node-key", Role::Node)), StatusCode::FORBIDDEN),
        ];
        for (auth, expected) in &refused {
            for (method, uri, body) in ADMIN_ROUTES {
                let (status, _) = send(&app, auth.as_ref(), method, uri, body).await;
                assert_eq!(status, *expected, "{auth:?}: {method} {uri}");
            }
        }
        assert_eq!(rows(&state, "audit_log"), 3, "nothing recorded or archived");
        assert!(!state.auth_config.read().await.csrf_enabled);

        for auth in [api_key("ops-key", Role::Admin), session(Role::Keymaster)] {
            for (method, uri, body) in ADMIN_ROUTES {
                let (status, body) = send(&app, Some(&auth), method, uri, body).await;
                assert_eq!(status, StatusCode::OK, "{auth:?}: {method} {uri}: {body}");
            }
        }
        // The key archived the old entries and changed the setting; the
        // keymaster's archive moved nothing and its PUT changed nothing.
        assert_eq!(latest(&state, "archive_marker").operator, "ops-key");
        assert_eq!(latest(&state, "audit_archive").operator, "keymaster-user");
        assert_eq!(
            latest(&state, "security_settings_changed").operator,
            "ops-key"
        );
        assert_eq!(
            test_support::audit_count(&state, "security_settings_changed"),
            1
        );
        assert!(state.auth_config.read().await.csrf_enabled);
    }

    /// An archive or purge that cannot be recorded in the audit log (here a
    /// trigger refuses the entry) is a 500 that changes nothing; recorded,
    /// they move and then delete the old entries, keeping the chain
    /// verifiable. A forged anchor stops both with 409.
    #[tokio::test]
    async fn archive_and_purge_change_nothing_unless_recorded_and_stop_at_a_forged_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let secret = audit_secret(&state);
        let old: Vec<i64> = (0..3)
            .map(|i| insert_signed(&state, &secret, &format!("old_{i}"), &days_ago(60)))
            .collect();
        insert_signed(&state, &secret, "recent", &days_ago(0));
        let app = audit_routes(&state);
        let admin = session(Role::Admin);
        let refuse = |action: &str| {
            state
                .db_pool
                .get()
                .unwrap()
                .execute_batch(&format!(
                    "CREATE TRIGGER refuse_{action} BEFORE INSERT ON audit_log \
                     WHEN NEW.action = '{action}' \
                     BEGIN SELECT RAISE(ABORT, 'audit write unavailable'); END;"
                ))
                .unwrap();
        };
        let allow = |action: &str| {
            state
                .db_pool
                .get()
                .unwrap()
                .execute_batch(&format!("DROP TRIGGER refuse_{action}"))
                .unwrap();
        };
        let archive = || {
            send(
                &app,
                Some(&admin),
                "POST",
                "/api/admin/audit/archive",
                r#"{"days": 30}"#,
            )
        };
        let purge = || send(&app, Some(&admin), "DELETE", "/api/admin/audit?days=30", "");
        let anchor = || store::load_anchor(&state.db_pool.get().unwrap(), "default").unwrap();

        refuse("archive_marker");
        assert_eq!(archive().await.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(rows(&state, "audit_log"), 4, "nothing moved");
        assert!(anchor().is_none());
        allow("archive_marker");

        let (status, body) = archive().await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["entries_moved"], 3);
        assert_eq!(body["last_archived_id"], old[2]);
        assert_eq!(rows(&state, "audit_log_archive"), 3);

        refuse("audit_purge");
        assert_eq!(purge().await.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(rows(&state, "audit_log_archive"), 3, "nothing deleted");
        allow("audit_purge");

        let (status, body) = purge().await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["entries_deleted"], 3);
        assert_eq!(rows(&state, "audit_log_archive"), 0);
        let (_, report) = send(&app, Some(&admin), "GET", "/api/admin/audit/verify", "").await;
        assert_eq!(report["valid"], true, "{report}");
        assert_eq!(report["anchor"]["authentic"], true);
        assert_eq!(report["anchor"]["archived_total"], 3);

        // An anchor moved forward would hide the entry after it.
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch("UPDATE audit_anchor SET last_archived_id = last_archived_id + 1")
            .unwrap();
        let before = rows(&state, "audit_log");
        for (status, body) in [archive().await, purge().await] {
            assert_eq!(status, StatusCode::CONFLICT, "{body}");
            let detail = body["detail"].as_str().unwrap();
            assert!(detail.contains("anchor fails verification"), "{detail}");
        }
        assert_eq!(rows(&state, "audit_log"), before);
        let (_, report) = send(&app, Some(&admin), "GET", "/api/admin/audit/verify", "").await;
        assert_eq!(report["valid"], false, "{report}");
        assert_eq!(report["anchor"]["authentic"], false);
    }

    /// In production without an audit key the routes that sign or check
    /// entries answer 500: they never fall back to a key of their own (an
    /// ephemeral key would report the whole log as tampered, or sign
    /// entries nobody can verify), and a security setting whose change
    /// cannot be recorded is not changed.
    #[tokio::test]
    async fn without_an_audit_key_in_production_audit_routes_fail_closed() {
        if ["BRIDGE_AUDIT_SECRET", "BRIDGE_MASTER_KEY"]
            .iter()
            .any(|name| std::env::var(name).is_ok_and(|v| !v.trim().is_empty()))
        {
            eprintln!("skipped: a fallback audit key is set in this environment");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let Ok(mut state) = Arc::try_unwrap(test_support::app_state(&dir)) else {
            unreachable!("fresh state has one owner")
        };
        let secret = audit_secret(&state);
        state.config.bridge_env = "production".into();
        state.config.audit_key = String::new();
        let state = Arc::new(state);
        for i in 0..3 {
            insert_signed(&state, &secret, &format!("old_{i}"), &days_ago(60));
        }
        let app = audit_routes(&state);
        let admin = session(Role::Admin);

        for (method, uri, body) in [
            ("GET", "/api/admin/audit/verify", ""),
            ("POST", "/api/admin/audit/archive", r#"{"days": 30}"#),
            ("DELETE", "/api/admin/audit?days=30", ""),
        ] {
            let (status, _) = send(&app, Some(&admin), method, uri, body).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{method} {uri}");
        }
        let (status, body) = send(
            &app,
            Some(&admin),
            "PUT",
            "/api/admin/settings/security",
            r#"{"csrf_enabled": true}"#,
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body["detail"]
            .as_str()
            .unwrap()
            .contains("nothing was changed"));
        assert!(!state.auth_config.read().await.csrf_enabled);
        assert_eq!(rows(&state, "audit_log"), 3, "nothing written or moved");
    }

    /// `POST /api/admin/audit/export`: the entries of tenant `default`
    /// (never another tenant's) in the inclusive range, oldest first. The
    /// bounds are bound values, never SQL.
    #[tokio::test]
    async fn export_returns_the_tenants_entries_in_the_range_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        store::tests::insert_bridge_audit_rows(&state.db_pool.get().unwrap());
        let app = audit_routes(&state);
        let admin = session(Role::Admin);
        let oldest_first: Vec<&str> = ALL_NOTES.iter().rev().copied().collect();

        let cases: [(&str, &[&str]); 5] = [
            ("{}", oldest_first.as_slice()),
            (
                r#"{"start": "2026-02-01T00:00:00+00:00", "end": "2026-05-01T00:00:00+00:00"}"#,
                &["false positive", "pw", "crit", "x"],
            ),
            (
                r#"{"start": "2026-07-01T00:00:00+00:00"}"#,
                &["a_b", "C:\\temp"],
            ),
            (r#"{"end": "2026-01-01T00:00:00+00:00"}"#, &["hello"]),
            (r#"{"end": "' OR '1'='1"}"#, &[]),
        ];
        for (body, expected) in cases {
            let (status, entries) =
                send(&app, Some(&admin), "POST", "/api/admin/audit/export", body).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let entries = entries.as_array().unwrap();
            let notes: Vec<&str> = entries
                .iter()
                .map(|e| e["note"].as_str().unwrap())
                .collect();
            assert_eq!(notes, expected, "{body}");
            assert!(
                entries.iter().all(|e| e["tenant_id"] == "default"),
                "{body}"
            );
        }

        let oversized = format!(r#"{{"start": "{}"}}"#, "x".repeat(5000));
        let (status, _) = send(
            &app,
            Some(&admin),
            "POST",
            "/api/admin/audit/export",
            oversized,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// The filter dropdowns list the distinct values of tenant `default`
    /// only, sorted, without empty operators or node ids.
    #[tokio::test]
    async fn audit_filters_list_the_tenants_distinct_values() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        {
            let conn = state.db_pool.get().unwrap();
            store::tests::insert_bridge_audit_rows(&conn);
            conn.execute_batch(
                "INSERT INTO audit_log (timestamp, action, target_id, tenant_id) \
                 VALUES ('2026-09-01T00:00:00+00:00', 'system', '', 'default'); \
                 INSERT INTO audit_log (timestamp, action, target_id, operator, node_id, \
                 tenant_id) VALUES ('2026-09-01T00:00:00+00:00', 'tenant_b_only', 't', \
                 'mallory', 'n9', 'tenant-b');",
            )
            .unwrap();
        }
        let app = audit_routes(&state);
        let admin = session(Role::Admin);
        let actions = serde_json::json!([
            "broken",
            "critical_thing",
            "dismiss",
            "export",
            "login",
            "password_change",
            "system"
        ]);

        let (status, filters) =
            send(&app, Some(&admin), "GET", "/api/admin/audit/filters", "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            filters,
            serde_json::json!({
                "actions": actions.clone(),
                "operators": ["alice", "bob", "carol"],
                "node_ids": ["n1", "n2", "n3"],
            })
        );
        let (status, listed) =
            send(&app, Some(&admin), "GET", "/api/admin/audit/actions", "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed, actions);
    }

    /// The login rate limit and the account lockout are applied and
    /// audited like every other setting; a body that is not JSON, or too
    /// large, changes and records nothing.
    #[tokio::test]
    async fn rate_limit_and_lockout_settings_are_applied_and_audited() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let app = audit_routes(&state);
        let admin = session(Role::Admin);
        const URI: &str = "/api/admin/settings/security";

        let (status, body) = send(&app, Some(&admin), "PUT", URI, "{\"csrf_enabled\": true").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, serde_json::json!({"detail": "Invalid JSON body"}));
        let oversized = format!(r#"{{"csrf_enabled": true, "pad": "{}"}}"#, "x".repeat(5000));
        let (status, _) = send(&app, Some(&admin), "PUT", URI, oversized).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!state.auth_config.read().await.csrf_enabled);
        assert_eq!(
            test_support::audit_count(&state, "security_settings_changed"),
            0
        );

        let (status, body) = send(
            &app,
            Some(&admin),
            "PUT",
            URI,
            r#"{"rate_limit_max": 7, "rate_limit_window_secs": 90.5, "lockout_max": 3,
                "lockout_window_secs": 600}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["rate_limit_max"], 7);
        assert_eq!(body["rate_limit_window_secs"], 90.5);
        let limits = state.auth_config.read().await.security_limits.clone();
        assert_eq!(
            (
                limits.rate_limit_max,
                limits.rate_limit_window_secs,
                limits.lockout_max,
                limits.lockout_window_secs
            ),
            (7, 90.5, 3, 600.0)
        );
        let changes = latest(&state, "security_settings_changed").details["changes"].clone();
        assert_eq!(
            changes,
            serde_json::json!({
                "rate_limit_max": {"old": 100, "new": 7},
                "rate_limit_window_secs": {"old": 60.0, "new": 90.5},
                "lockout_max": {"old": 100, "new": 3},
                "lockout_window_secs": {"old": 60.0, "new": 600.0},
            })
        );
    }

    /// A rate limit or lockout the gateway's own configuration could not
    /// hold must be refused like an out-of-range session timeout: a count
    /// above `u32::MAX` must not wrap (2^32 becomes 0, which refuses every
    /// login, administrators' included), and a negative window counts no
    /// attempt at all, so it turns the limit off. `UC_RATE_LIMIT_MAX`,
    /// `UC_LOCKOUT_MAX`, `UC_RATE_LIMIT_WINDOW` and `UC_LOCKOUT_WINDOW`
    /// accept neither.
    #[tokio::test]
    async fn rate_limit_and_lockout_settings_out_of_range_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let app = audit_routes(&state);
        let admin = session(Role::Admin);
        let mut accepted = Vec::new();
        for (key, value) in [
            ("lockout_max", "4294967296"),
            ("lockout_max", "4294967297"),
            ("rate_limit_max", "4294967296"),
            ("lockout_window_secs", "-1"),
            ("rate_limit_window_secs", "-60"),
        ] {
            let body = format!(r#"{{"csrf_enabled": true, "{key}": {value}}}"#);
            let (status, resp) = send(
                &app,
                Some(&admin),
                "PUT",
                "/api/admin/settings/security",
                body,
            )
            .await;
            if status != StatusCode::BAD_REQUEST {
                accepted.push(format!("{key}={value}: {status}, applied as {}", resp[key]));
            }
        }
        assert!(accepted.is_empty(), "{accepted:#?}");
        let config = state.auth_config.read().await;
        let limits = &config.security_limits;
        assert_eq!((limits.rate_limit_max, limits.lockout_max), (100, 100));
        assert_eq!(
            (limits.rate_limit_window_secs, limits.lockout_window_secs),
            (60.0, 60.0)
        );
        assert!(!config.csrf_enabled, "nothing in a refused request");
    }

    /// Every rate limit and lockout value outside what the gateway's own
    /// configuration holds is refused with a `detail` naming the setting
    /// and the bound, before anything in the request is applied or
    /// recorded, also the ones that used to be silently ignored (a
    /// negative count, a fraction, a string). The bounds themselves (1 and
    /// `u32::MAX` attempts, a window of 1 or with a fraction, a lockout
    /// window of 86400) are applied.
    #[tokio::test]
    async fn every_out_of_range_rate_limit_or_lockout_value_is_refused_with_its_bound() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let app = audit_routes(&state);
        let admin = session(Role::Admin);
        const URI: &str = "/api/admin/settings/security";
        for key in ["rate_limit_max", "lockout_max"] {
            for (value, detail) in [
                ("4294967296", "must be at most 4294967295"),
                ("18446744073709551615", "must be at most 4294967295"),
                ("1e20", "must be at most 4294967295"),
                ("4294967295.5", "must be at most 4294967295"),
                ("0", "must be at least 1"),
                ("-0", "must be at least 1"),
                ("-0.0", "must be at least 1"),
                ("0.5", "must be at least 1"),
                ("0.999", "must be at least 1"),
                ("-1", "must be at least 1"),
                ("-9223372036854775808", "must be at least 1"),
                ("-1e20", "must be at least 1"),
                ("-0.5", "must be at least 1"),
                ("1.0", "must be an integer"),
                ("1.5", "must be an integer"),
                ("7.0", "must be an integer"),
                ("1e3", "must be an integer"),
                ("\"7\"", "must be an integer"),
                ("null", "must be an integer"),
                ("true", "must be an integer"),
            ] {
                let body = format!(r#"{{"csrf_enabled": true, "{key}": {value}}}"#);
                let (status, resp) = send(&app, Some(&admin), "PUT", URI, body).await;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{key}={value}: {resp}");
                assert_eq!(resp["detail"], format!("{key} {detail}"), "{key}={value}");
            }
        }
        for (key, max) in [
            ("rate_limit_window_secs", None),
            ("lockout_window_secs", Some("86400")),
        ] {
            let mut cases = vec![
                ("0", "must be at least 1".to_string()),
                ("-0", "must be at least 1".to_string()),
                ("-0.0", "must be at least 1".to_string()),
                ("1e-9", "must be at least 1".to_string()),
                ("0.999", "must be at least 1".to_string()),
                ("-1", "must be at least 1".to_string()),
                ("-0.001", "must be at least 1".to_string()),
                ("-1e300", "must be at least 1".to_string()),
                ("-18446744073709551615", "must be at least 1".to_string()),
                ("\"60\"", "must be a number".to_string()),
                ("null", "must be a number".to_string()),
                ("[60]", "must be a number".to_string()),
            ];
            if let Some(max) = max {
                cases.push(("86400.001", format!("must be at most {max}")));
            }
            for (value, detail) in cases {
                let body = format!(r#"{{"csrf_enabled": true, "{key}": {value}}}"#);
                let (status, resp) = send(&app, Some(&admin), "PUT", URI, body).await;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{key}={value}: {resp}");
                assert_eq!(resp["detail"], format!("{key} {detail}"), "{key}={value}");
            }
        }
        {
            let config = state.auth_config.read().await;
            let limits = &config.security_limits;
            assert_eq!(
                (
                    limits.rate_limit_max,
                    limits.rate_limit_window_secs,
                    limits.lockout_max,
                    limits.lockout_window_secs
                ),
                (100, 60.0, 100, 60.0)
            );
            assert!(!config.csrf_enabled, "nothing in a refused request");
        }
        assert_eq!(
            test_support::audit_count(&state, "security_settings_changed"),
            0
        );

        for (body, applied) in [
            (
                r#"{"rate_limit_max": 4294967295, "rate_limit_window_secs": 1,
                    "lockout_max": 1, "lockout_window_secs": 86400}"#,
                (u32::MAX, 1.0, 1, 86_400.0),
            ),
            (
                r#"{"rate_limit_max": 1, "rate_limit_window_secs": 1.25,
                    "lockout_max": 4294967295, "lockout_window_secs": 1.0}"#,
                (1, 1.25, u32::MAX, 1.0),
            ),
        ] {
            let (status, resp) = send(&app, Some(&admin), "PUT", URI, body).await;
            assert_eq!(status, StatusCode::OK, "{body}: {resp}");
            let limits = state.auth_config.read().await.security_limits.clone();
            let got = (
                limits.rate_limit_max,
                limits.rate_limit_window_secs,
                limits.lockout_max,
                limits.lockout_window_secs,
            );
            assert_eq!(got, applied, "{body}");
            assert_eq!(resp["lockout_max"], applied.2, "{body}");
        }
    }

    /// Regression: a count of 0 and a window below 1 second were applied
    /// with 200. `rate_limit_max: 0` or `lockout_max: 0` refuses every
    /// login, administrators' included (an attempt is allowed only below
    /// the count); a `rate_limit_window_secs` or `lockout_window_secs` of
    /// 0 (or `1e-9`) counts no earlier attempt, so a stolen admin session
    /// could turn the rate limit or the lockout off with it as with the
    /// negative window it may no longer send. Each is refused with 400
    /// (`must be at least 1`), and nothing is applied or recorded.
    #[tokio::test]
    async fn a_login_limit_that_refuses_every_login_or_counts_none_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let app = audit_routes(&state);
        let admin = session(Role::Admin);
        let mut accepted = Vec::new();
        for (key, value) in [
            ("rate_limit_max", "0"),
            ("lockout_max", "0"),
            ("rate_limit_window_secs", "0"),
            ("lockout_window_secs", "0"),
            ("rate_limit_window_secs", "1e-9"),
            ("lockout_window_secs", "1e-9"),
        ] {
            let body = format!(r#"{{"csrf_enabled": true, "{key}": {value}}}"#);
            let (status, resp) = send(
                &app,
                Some(&admin),
                "PUT",
                "/api/admin/settings/security",
                body,
            )
            .await;
            if status != StatusCode::BAD_REQUEST {
                accepted.push(format!("{key}={value}: {status}, applied as {}", resp[key]));
            } else {
                assert_eq!(resp["detail"], format!("{key} must be at least 1"));
            }
        }
        assert!(accepted.is_empty(), "{accepted:#?}");
        let limits = state.auth_config.read().await.security_limits.clone();
        assert_eq!(
            (
                limits.rate_limit_max,
                limits.rate_limit_window_secs,
                limits.lockout_max,
                limits.lockout_window_secs
            ),
            (100, 60.0, 100, 60.0)
        );
        assert_eq!(
            test_support::audit_count(&state, "security_settings_changed"),
            0
        );
    }

    /// Like the listing, verification and export of a log that cannot be
    /// read are a 500, never a clean report or an empty export.
    #[tokio::test]
    async fn verify_and_export_of_an_unreadable_log_are_500s() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch("DROP TABLE audit_log")
            .unwrap();
        let app = audit_routes(&state);
        let admin = session(Role::Admin);
        for (method, uri) in [
            ("GET", "/api/admin/audit/verify"),
            ("POST", "/api/admin/audit/export"),
        ] {
            let (status, body) = send(&app, Some(&admin), method, uri, "{}").await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{uri}: {body}");
        }
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use crate::test_support;
    use std::time::Duration;
    use tower::ServiceExt as _;

    /// The audit and security-settings routes, mounted as builder.rs
    /// mounts them.
    fn routes(state: &Arc<AppState>) -> axum::Router {
        use axum::routing::{get, post};
        axum::Router::new()
            .route(
                "/api/admin/audit",
                get(get_audit_log).delete(purge_archived),
            )
            .route("/api/admin/audit/verify", get(verify_chain))
            .route("/api/admin/audit/filters", get(get_audit_filters))
            .route("/api/admin/audit/actions", get(get_audit_actions))
            .route("/api/admin/audit/archive", post(archive_audit))
            .route("/api/admin/audit/export", post(export_audit))
            .route(
                "/api/admin/settings/security",
                get(get_security_settings).put(set_security_settings),
            )
            .with_state(Arc::clone(state))
    }

    /// Send a request as an ADMIN session (the `AuthInfo` the auth
    /// middleware would resolve).
    async fn send(
        app: &axum::Router,
        method: &str,
        uri: &str,
        body: impl Into<Body>,
    ) -> (StatusCode, serde_json::Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(body.into())
            .unwrap();
        req.extensions_mut().insert(AuthInfo::Session {
            username: "alice".into(),
            user_id: 1,
            role: Role::Admin,
            session_token: "tok".into(),
            expires_at: "2099-01-01T00:00:00+00:00".into(),
            tenant_id: "default".into(),
            scope: String::new(),
        });
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    fn latest(state: &AppState, action: &str) -> store::AuditEntry {
        let conn = state.db_pool.get().unwrap();
        let filter = store::AuditFilter {
            action: Some(action),
            ..Default::default()
        };
        store::get_audit_log(&conn, "default", &filter, 1, 0)
            .unwrap()
            .remove(0)
    }

    /// A pool that never hands out a connection: its database is in a
    /// directory that does not exist, and is not created.
    fn unavailable_pool(dir: &tempfile::TempDir) -> crate::db::pool::DbPool {
        let manager = crate::db::manager::SqliteConnectionManager::file(
            dir.path().join("missing").join("audit.db"),
        )
        .with_flags(rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE);
        r2d2::Pool::builder()
            .max_size(1)
            .min_idle(Some(0))
            .connection_timeout(Duration::from_millis(50))
            .build_unchecked(manager)
    }

    /// Without a database connection every audit route answers 503, and
    /// archives, purges or exports nothing.
    #[tokio::test]
    async fn audit_routes_answer_503_without_a_database_connection() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = test_support::app_state(&dir);
        Arc::get_mut(&mut state).unwrap().db_pool = unavailable_pool(&dir);
        let app = routes(&state);
        for (method, uri, body) in [
            ("GET", "/api/admin/audit", ""),
            ("GET", "/api/admin/audit/verify", ""),
            ("GET", "/api/admin/audit/filters", ""),
            ("GET", "/api/admin/audit/actions", ""),
            ("POST", "/api/admin/audit/archive", r#"{"days": 30}"#),
            ("DELETE", "/api/admin/audit?days=30", ""),
            ("POST", "/api/admin/audit/export", "{}"),
        ] {
            let (status, _) = send(&app, method, uri, body).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{method} {uri}");
        }
    }

    /// A security settings change that cannot be recorded (no database
    /// connection) is refused with 500 and not applied, and the log says
    /// which settings were left unchanged and why.
    #[test]
    fn a_settings_change_that_cannot_be_recorded_is_refused_and_logged() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = test_support::app_state(&dir);
        Arc::get_mut(&mut state).unwrap().db_pool = unavailable_pool(&dir);
        let app = routes(&state);
        let ((status, body), logs) = test_support::logs_of(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(send(
                    &app,
                    "PUT",
                    "/api/admin/settings/security",
                    r#"{"csrf_enabled": true}"#,
                ))
        });
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert!(
            body["detail"]
                .as_str()
                .unwrap()
                .contains("nothing was changed"),
            "{body}"
        );
        assert!(
            logs.contains(
                "Security settings change refused: it could not be written to the audit log"
            ),
            "{logs}"
        );
        assert!(logs.contains("csrf_enabled"), "{logs}");
        assert!(!state.auth_config.try_read().unwrap().csrf_enabled);
    }

    /// The archive and export bodies are read up to 4 KiB: a larger one is
    /// refused (400), and nothing is archived or recorded. A body without a
    /// usable `days` archives at the 90-day default, and a purge without
    /// `days` purges at 90 days: a missing value never means 0 days.
    #[tokio::test]
    async fn oversized_bodies_are_refused_and_a_missing_days_means_90() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let app = routes(&state);
        let padded = format!(r#"{{"days": 30, "pad": "{}"}}"#, "x".repeat(5000));
        for uri in ["/api/admin/audit/archive", "/api/admin/audit/export"] {
            let (status, body) = send(&app, "POST", uri, padded.clone()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
        }
        assert_eq!(test_support::audit_count(&state, "audit_archive"), 0);

        for body in ["{}", "not json"] {
            let (status, json) = send(&app, "POST", "/api/admin/audit/archive", body).await;
            assert_eq!(status, StatusCode::OK, "{body}: {json}");
            assert_eq!(json["days_threshold"], 90, "{body}: {json}");
            assert_eq!(latest(&state, "audit_archive").details["days"], 90);
        }
        let (status, json) = send(&app, "DELETE", "/api/admin/audit", "").await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["status"], "purged");
        let purge = latest(&state, "audit_purge");
        assert_eq!(purge.details["days"], 90);
        assert_eq!(purge.operator, "alice");
    }
}
