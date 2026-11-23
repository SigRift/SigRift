//! MFA endpoint handlers — setup, verify, disable, backup codes, admin settings.
//!
//! Every second-factor check (TOTP or backup code: login verification,
//! verify-setup, disable, regenerate-backup-codes) is limited per user: the
//! attempt is reserved up front in `mfa_attempts`
//! ([`mfa::reserve_mfa_attempt`]) and once a user has `UC_LOCKOUT_MAX`
//! failed checks within `UC_LOCKOUT_WINDOW` seconds further checks are
//! refused with 429 until the window passes; a successful check clears the
//! count. Codes are single-use under concurrency: the login token is
//! claimed with `DELETE … RETURNING`, a TOTP code with an insert-or-fail
//! into the replay cache, a backup code with `UPDATE … WHERE used = 0`.

use axum::{
    body::Body,
    extract::State,
    http::{header, Request, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

use crate::audit::{chain as audit_chain, store as audit_store};
use crate::auth::rbac::Role;
use crate::auth::session_handler::{
    declares_json_body, issue_session, json_body_required, LoginClient,
};
use crate::auth::{password, totp};
use crate::db::pool::{with_conn_blocking, PooledConn};
use crate::middleware::auth::AuthInfo;
use crate::storage::mfa;
use crate::storage::security_state::SecurityLimits;
use crate::AppState;

fn audit_event(
    state: &AppState,
    conn: &r2d2::PooledConnection<crate::db::manager::SqliteConnectionManager>,
    action: &str,
    target: &str,
    operator: &str,
    client_ip: &str,
) {
    if let Ok(secret) =
        audit_chain::get_audit_secret(&state.config.audit_key, &state.config.bridge_env)
    {
        if let Err(e) = audit_store::log_auth_event(
            conn, &secret, action, target, operator, client_ip, "default",
        ) {
            tracing::warn!(error = %e, action, "Failed to log audit event");
        }
    }
}

// ── Request/Response types ────────────────────────────────────────────

#[derive(Serialize)]
pub struct MFASetupResponse {
    pub secret: String,
    pub provisioning_uri: String,
    pub backup_codes: Vec<String>,
}

#[derive(Deserialize)]
pub struct VerifySetupRequest {
    pub totp_code: String,
}

#[derive(Deserialize)]
pub struct MFAVerifyLoginRequest {
    pub mfa_token: String,
    pub totp_code: String,
}

#[derive(Deserialize)]
pub struct MFADisableRequest {
    pub totp_code: String,
}

#[derive(Deserialize)]
pub struct RegenerateBackupRequest {
    pub totp_code: String,
}

#[derive(Deserialize)]
pub struct TenantMFARequest {
    pub mfa_required: bool,
}

// ── Helpers ───────────────────────────────────────────────────────────

/// PBKDF2-hash freshly generated backup codes (one 600k-iteration hash
/// per code) on the blocking pool instead of an async worker.
async fn hash_backup_codes(raw_codes: &[String]) -> Option<Vec<(String, Vec<u8>)>> {
    let codes = raw_codes.to_vec();
    match tokio::task::spawn_blocking(move || {
        codes
            .iter()
            .map(|c| password::hash_credential(&c.to_lowercase(), None))
            .collect()
    })
    .await
    {
        Ok(hashes) => Some(hashes),
        Err(e) => {
            warn!(error = %e, "Backup code hashing task failed");
            None
        }
    }
}

/// Verify a backup code (one PBKDF2 per unused stored code) on the
/// blocking pool; hands the connection back with the result.
async fn verify_backup_code_blocking(
    conn: PooledConn,
    user_id: i64,
    code: &str,
) -> Option<(PooledConn, Result<bool, rusqlite::Error>)> {
    let code = code.to_owned();
    with_conn_blocking(conn, move |conn| {
        mfa::verify_backup_code(conn, user_id, &code)
    })
    .await
}

fn get_session_info(req: &axum::http::Request<axum::body::Body>) -> Option<(String, i64, String)> {
    match req.extensions().get::<AuthInfo>()? {
        AuthInfo::Session {
            username,
            user_id,
            tenant_id,
            ..
        } => Some((username.clone(), *user_id, tenant_id.clone())),
        _ => None,
    }
}

// The Err is the ready-made HTTP error response, returned as-is by handlers.
#[allow(clippy::result_large_err)]
fn require_session(
    req: &axum::http::Request<axum::body::Body>,
) -> Result<(String, i64, String), Response> {
    get_session_info(req).ok_or_else(|| {
        (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"detail": "Session authentication required"})),
        )
            .into_response()
    })
}

#[allow(clippy::result_large_err)] // see require_session
fn require_admin(
    req: &axum::http::Request<axum::body::Body>,
) -> Result<(String, i64, String), Response> {
    match req.extensions().get::<AuthInfo>() {
        Some(AuthInfo::Session {
            username,
            user_id,
            role,
            tenant_id,
            ..
        }) if role.has_at_least(crate::auth::rbac::Role::Admin) => {
            Ok((username.clone(), *user_id, tenant_id.clone()))
        }
        Some(AuthInfo::ApiKey { role, .. })
            if role.has_at_least(crate::auth::rbac::Role::Admin) =>
        {
            Ok(("api_key".into(), 0, "default".into()))
        }
        _ => Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"detail": "Admin role required"})),
        )
            .into_response()),
    }
}

/// Parse a small JSON request body; the Err is the 400 to return.
#[allow(clippy::result_large_err)] // see require_session
async fn parse_body<T: serde::de::DeserializeOwned>(req: Request<Body>) -> Result<T, Response> {
    let bytes = axum::body::to_bytes(req.into_body(), 4096)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
    serde_json::from_slice(&bytes).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"detail": "Invalid request"})),
        )
            .into_response()
    })
}

fn unauthorized(detail: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "detail": detail })),
    )
        .into_response()
}

/// The per-user limits for second-factor checks: the account-lockout
/// settings (`UC_LOCKOUT_MAX` failures per `UC_LOCKOUT_WINDOW` seconds).
async fn attempt_limits(state: &AppState) -> SecurityLimits {
    state.auth_config.read().await.security_limits.clone()
}

/// Reserve one second-factor check for `user_id` (see the module docs).
/// The Err is the response to return: 429 when the user is locked out, 500
/// on a database error.
#[allow(clippy::result_large_err)] // see require_session
fn reserve_attempt(
    limits: &SecurityLimits,
    conn: &PooledConn,
    user_id: i64,
    tenant_id: &str,
) -> Result<(), Response> {
    match mfa::reserve_mfa_attempt(
        conn,
        user_id,
        tenant_id,
        limits.lockout_max,
        limits.lockout_window_secs,
    ) {
        Ok(true) => Ok(()),
        Ok(false) => {
            warn!(user_id, "MFA attempt limit reached — check refused");
            let retry_after = (limits.lockout_window_secs.ceil() as u64).to_string();
            Err((
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, retry_after)],
                Json(serde_json::json!({
                    "detail": "Too many MFA attempts. Try again later."
                })),
            )
                .into_response())
        }
        Err(e) => {
            warn!(error = %e, "MFA attempt reservation failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

/// A successful check: forget the user's counted attempts.
fn clear_attempts(conn: &PooledConn, user_id: i64, tenant_id: &str) {
    if let Err(e) = mfa::clear_mfa_attempts(conn, user_id, tenant_id) {
        warn!(error = %e, user_id, "Failed to clear MFA attempts");
    }
}

/// Result of checking a submitted second factor.
#[derive(Debug, PartialEq, Eq)]
enum SecondFactor {
    /// A valid TOTP code, now recorded as used.
    Totp,
    /// A valid backup code, now marked used.
    BackupCode,
    /// A valid TOTP code that was already used within the replay window.
    Replayed,
    Invalid,
}

/// Whether a stored TOTP secret can verify any code. If not (not Base32,
/// or an empty or all-zero key: [`totp::check_secret`]), log why, without
/// the secret: [`totp::verify_totp`] refuses every code for it.
fn totp_secret_usable(secret: &str, username: &str) -> bool {
    match totp::check_secret(secret) {
        Ok(()) => true,
        Err(e) => {
            warn!(
                error = %e,
                username,
                "Stored TOTP secret is unusable — no TOTP code can verify until MFA is set up again"
            );
            false
        }
    }
}

/// Check a 6-digit TOTP code against `secret` and, if valid, claim it in
/// the replay cache atomically.
fn check_totp(
    conn: &PooledConn,
    secret: Option<&str>,
    username: &str,
    tenant_id: &str,
    code: &str,
) -> Result<SecondFactor, rusqlite::Error> {
    let Some(secret) = secret else {
        return Ok(SecondFactor::Invalid);
    };
    if !totp_secret_usable(secret, username) {
        return Ok(SecondFactor::Invalid);
    }
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(SecondFactor::Invalid);
    }
    if !totp::verify_totp(secret, code, 1, None, 30, 6) {
        return Ok(SecondFactor::Invalid);
    }
    Ok(if mfa::claim_totp_code(conn, username, code, tenant_id)? {
        SecondFactor::Totp
    } else {
        SecondFactor::Replayed
    })
}

/// Check a TOTP code, falling back to a backup code. Hands the connection
/// back (the backup-code PBKDF2 runs on the blocking pool); `None` if that
/// task failed.
async fn check_totp_or_backup(
    conn: PooledConn,
    secret: Option<&str>,
    user_id: i64,
    username: &str,
    tenant_id: &str,
    code: &str,
) -> Option<(PooledConn, Result<SecondFactor, rusqlite::Error>)> {
    match check_totp(&conn, secret, username, tenant_id, code) {
        Ok(SecondFactor::Invalid) => {}
        other => return Some((conn, other)),
    }
    let (conn, backup) = verify_backup_code_blocking(conn, user_id, code).await?;
    let result = backup.map(|ok| {
        if ok {
            SecondFactor::BackupCode
        } else {
            SecondFactor::Invalid
        }
    });
    Some((conn, result))
}

// ── POST /api/auth/mfa/setup ──────────────────────────────────────────

pub async fn mfa_setup(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Response {
    let (username, user_id, _tenant_id) = match require_session(&req) {
        Ok(info) => info,
        Err(resp) => return resp,
    };

    let mut conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let already_enabled = || {
        (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"detail": "MFA is already enabled"})),
        )
            .into_response()
    };
    let user_not_found = || {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"detail": "User not found"})),
        )
            .into_response()
    };

    // Check MFA not already enabled before the backup codes are hashed (the
    // write checks again). Fail closed: if the check cannot be made, setup
    // must not replace an enrolled factor with a secret and backup codes
    // the caller would then know.
    match mfa::get_user_by_id(&conn, user_id) {
        Ok(Some(user)) if user.mfa_enabled => return already_enabled(),
        Ok(Some(_)) => {}
        Ok(None) => return user_not_found(),
        Err(e) => {
            warn!(error = %e, user_id, "MFA setup user lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    // Generate secret and backup codes
    let secret = totp::generate_secret(20);
    let provisioning_uri = totp::get_provisioning_uri(&secret, &username, "SigRift", 30, 6, "SHA1");
    let raw_codes = totp::generate_backup_codes(10, 8);

    // Hash backup codes with PBKDF2
    let Some(code_hashes) = hash_backup_codes(&raw_codes).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    // Store the encrypted secret and the hashed backup codes together, and
    // only while MFA is still off: hashing takes seconds, and verify-setup
    // (another tab, a retried request) may have enabled MFA meanwhile.
    match mfa::store_pending_enrolment(
        &mut conn,
        user_id,
        &secret,
        &state.config.mfa_key,
        state.config.is_production(),
        &code_hashes,
    ) {
        Ok(mfa::PendingEnrolment::Stored) => {}
        Ok(mfa::PendingEnrolment::MfaEnabled) => {
            info!(
                user_id,
                "MFA was enabled while setup ran — its new secret and backup codes were discarded"
            );
            return already_enabled();
        }
        Ok(mfa::PendingEnrolment::NoSuchUser) => return user_not_found(),
        Err(e) => {
            warn!(error = %e, user_id, "Failed to store the MFA enrolment");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    info!(username = username, "MFA setup initiated");

    (
        StatusCode::OK,
        Json(MFASetupResponse {
            secret,
            provisioning_uri,
            backup_codes: raw_codes,
        }),
    )
        .into_response()
}

// ── POST /api/auth/mfa/verify-setup ───────────────────────────────────

pub async fn mfa_verify_setup(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Response {
    let (username, user_id, tenant_id) = match require_session(&req) {
        Ok(info) => info,
        Err(resp) => return resp,
    };
    let body: VerifySetupRequest = match parse_body(req).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let limits = attempt_limits(&state).await;

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    // Get stored secret
    let secret = match mfa::get_totp_secret(&conn, user_id, &state.config.mfa_key) {
        Ok(Some(s)) => s,
        _ => return (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"detail": "No TOTP secret configured. Call /mfa/setup first."}),
            ),
        )
            .into_response(),
    };

    if let Err(resp) = reserve_attempt(&limits, &conn, user_id, &tenant_id) {
        return resp;
    }

    // Verify TOTP code (no replay check during setup per Python behavior)
    if !totp_secret_usable(&secret, &username)
        || !totp::verify_totp(&secret, body.totp_code.trim(), 1, None, 30, 6)
    {
        return unauthorized("Invalid TOTP code");
    }
    clear_attempts(&conn, user_id, &tenant_id);

    // Enable MFA
    if let Err(e) = mfa::enable_mfa(&conn, user_id) {
        warn!(error = %e, "Failed to enable MFA");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let remaining = mfa::get_backup_code_count(&conn, user_id).unwrap_or(0);
    audit_event(&state, &conn, "mfa_enable", &username, &username, "");
    info!(user_id, "MFA enabled via setup verification");

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "mfa_enabled",
            "backup_codes_remaining": remaining,
        })),
    )
        .into_response()
}

// ── POST /api/auth/mfa/verify (two-step login) ───────────────────────

/// Second login step: the `mfa_token` from the password step plus a TOTP
/// or backup code. On success the session is issued exactly as for a
/// password-only login ([`issue_session`]): bound to this client's IP and
/// User-Agent, with the same scope rules, cookies and CSRF token.
pub async fn mfa_verify_login(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    // Login CSRF, as for the password step: a body not declared JSON is
    // refused before the challenge is claimed or an attempt is counted.
    // (Only this step: the MFA management routes need a session, and so
    // the CSRF token, already.)
    if !declares_json_body(req.headers()) {
        return json_body_required();
    }
    let (trusted_proxies, session_config, limits) = {
        let cfg = state.auth_config.read().await;
        (
            cfg.trusted_proxies.clone(),
            cfg.session_config.clone(),
            cfg.security_limits.clone(),
        )
    };
    let client = LoginClient::of(&req, &trusted_proxies);
    let body: MFAVerifyLoginRequest = match parse_body(req).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    // Claim the MFA token (single-use, atomically), with the credential its
    // password step verified: the session is issued only while that is
    // still the stored password.
    let credential = match mfa::verify_mfa_token(&conn, &body.mfa_token) {
        Ok(Some(credential)) => credential,
        Ok(None) => return unauthorized("Invalid or expired MFA token"),
        Err(e) => {
            warn!(error = %e, "MFA token verification error");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let user_id = credential.user_id;

    let user = match mfa::get_user_by_id(&conn, user_id) {
        Ok(Some(u)) if u.enabled => u,
        Ok(_) => return unauthorized("Invalid or expired MFA token"),
        Err(e) => {
            warn!(error = %e, "MFA login user lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let tenant_id = user.tenant_id.clone();

    if let Err(resp) = reserve_attempt(&limits, &conn, user_id, &tenant_id) {
        return resp;
    }

    // Get TOTP secret. `None` when it is missing or cannot be decrypted
    // (e.g. it was encrypted under a BRIDGE_MFA_KEY that has since been
    // replaced): TOTP cannot verify then, but a backup code still can, as
    // on the bridge — the user is not locked out with a 500.
    let secret = match mfa::get_totp_secret(&conn, user_id, &state.config.mfa_key) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "Failed to read TOTP secret");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if secret.is_none() {
        warn!(
            user_id,
            "TOTP secret missing or unreadable — only a backup code can complete this login"
        );
    }

    let code = body.totp_code.trim();
    let Some((conn, checked)) = check_totp_or_backup(
        conn,
        secret.as_deref(),
        user_id,
        &user.username,
        &tenant_id,
        code,
    )
    .await
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    match checked {
        Ok(SecondFactor::Totp | SecondFactor::BackupCode) => {}
        Ok(SecondFactor::Replayed) => return unauthorized("TOTP code already used"),
        Ok(SecondFactor::Invalid) => return unauthorized("Invalid TOTP code or backup code"),
        Err(e) => {
            warn!(error = %e, "Second-factor verification error");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    clear_attempts(&conn, user_id, &tenant_id);

    let resp = match issue_session(&state, &conn, &credential, &client, &session_config) {
        Ok(resp) => resp,
        Err(error) => return error.into_response(),
    };

    audit_event(
        &state,
        &conn,
        "user_login_mfa",
        &user.username,
        &user.username,
        &client.ip,
    );
    info!(
        username = user.username,
        client_ip = client.ip,
        "MFA login successful"
    );
    resp
}

// ── POST /api/auth/mfa/disable ────────────────────────────────────────

pub async fn mfa_disable(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Response {
    let (username, user_id, tenant_id) = match require_session(&req) {
        Ok(info) => info,
        Err(resp) => return resp,
    };
    let body: MFADisableRequest = match parse_body(req).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let limits = attempt_limits(&state).await;

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    if let Err(resp) = reserve_attempt(&limits, &conn, user_id, &tenant_id) {
        return resp;
    }

    // Verify TOTP or backup code
    let secret = mfa::get_totp_secret(&conn, user_id, &state.config.mfa_key)
        .ok()
        .flatten();
    let code = body.totp_code.trim();
    let Some((conn, checked)) = check_totp_or_backup(
        conn,
        secret.as_deref(),
        user_id,
        &username,
        &tenant_id,
        code,
    )
    .await
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    match checked {
        Ok(SecondFactor::Totp | SecondFactor::BackupCode) => {}
        Ok(SecondFactor::Replayed) => return unauthorized("TOTP code already used"),
        Ok(SecondFactor::Invalid) => return unauthorized("Valid TOTP or backup code required"),
        Err(e) => {
            warn!(error = %e, "Second-factor verification error");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    clear_attempts(&conn, user_id, &tenant_id);

    if let Err(e) = mfa::disable_mfa(&conn, user_id) {
        warn!(error = %e, user_id, "Failed to disable MFA");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    audit_event(&state, &conn, "mfa_disable", &username, &username, "");
    info!(username = username, "MFA disabled");

    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "mfa_disabled"})),
    )
        .into_response()
}

// ── POST /api/auth/mfa/regenerate-backup-codes ────────────────────────

pub async fn mfa_regenerate_backup_codes(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Response {
    let (username, user_id, tenant_id) = match require_session(&req) {
        Ok(info) => info,
        Err(resp) => return resp,
    };
    let body: RegenerateBackupRequest = match parse_body(req).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let limits = attempt_limits(&state).await;

    let mut conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    // Verify TOTP code (with replay check)
    let secret = match mfa::get_totp_secret(&conn, user_id, &state.config.mfa_key) {
        Ok(Some(s)) => s,
        _ => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    if let Err(resp) = reserve_attempt(&limits, &conn, user_id, &tenant_id) {
        return resp;
    }

    let code = body.totp_code.trim();
    match check_totp(&conn, Some(&secret), &username, &tenant_id, code) {
        Ok(SecondFactor::Totp) => {}
        Ok(SecondFactor::Replayed) => return unauthorized("TOTP code already used"),
        Ok(_) => return unauthorized("Invalid TOTP code"),
        Err(e) => {
            warn!(error = %e, "TOTP verification error");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    clear_attempts(&conn, user_id, &tenant_id);

    // Generate new backup codes
    let raw_codes = totp::generate_backup_codes(10, 8);
    let Some(code_hashes) = hash_backup_codes(&raw_codes).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    if let Err(e) = mfa::store_backup_codes(&mut conn, user_id, &code_hashes) {
        warn!(error = %e, "Failed to store new backup codes");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    audit_event(
        &state,
        &conn,
        "mfa_regenerate_backup_codes",
        &username,
        &username,
        "",
    );
    info!(username = username, "Backup codes regenerated");

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "backup_codes_regenerated",
            "backup_codes": raw_codes,
            "backup_codes_remaining": raw_codes.len(),
        })),
    )
        .into_response()
}

// ── Admin endpoints ───────────────────────────────────────────────────

pub async fn set_tenant_mfa(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Response {
    let _ = match require_admin(&req) {
        Ok(info) => info,
        Err(resp) => return resp,
    };

    let body: TenantMFARequest = match parse_body(req).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let tenant_id = "default";
    if let Err(e) = mfa::set_tenant_mfa_required(&conn, tenant_id, body.mfa_required) {
        warn!(error = %e, "Failed to set tenant MFA setting");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    audit_event(&state, &conn, "tenant_mfa_policy_change", tenant_id, "", "");
    info!(
        tenant_id,
        mfa_required = body.mfa_required,
        "Tenant MFA policy updated"
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "tenant_id": tenant_id,
            "mfa_required": body.mfa_required,
        })),
    )
        .into_response()
}

pub async fn get_tenant_mfa(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Response {
    let _ = match require_admin(&req) {
        Ok(info) => info,
        Err(resp) => return resp,
    };

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let tenant_id = "default";
    let required = mfa::get_tenant_mfa_required(&conn, tenant_id).unwrap_or(false);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "tenant_id": tenant_id,
            "mfa_required": required,
        })),
    )
        .into_response()
}

pub async fn admin_disable_user_mfa(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(username): axum::extract::Path<String>,
    req: axum::http::Request<axum::body::Body>,
) -> Response {
    let _ = match require_admin(&req) {
        Ok(info) => info,
        Err(resp) => return resp,
    };
    let caller_role = req
        .extensions()
        .get::<AuthInfo>()
        .and_then(AuthInfo::role)
        .unwrap_or(Role::Viewer);

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let user = match crate::storage::users::get_user_by_username(&conn, &username, "default") {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"detail": "User not found"})),
            )
                .into_response()
        }
        Err(e) => {
            warn!(error = %e, "User lookup error");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // K5: an admin may not weaken the account of a user above its role.
    if !caller_role.may_manage(Role::parse_stored_for_ceiling(&user.role)) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "detail": "Cannot modify a user with a role above your own"
            })),
        )
            .into_response();
    }

    if let Err(e) = mfa::disable_mfa(&conn, user.id) {
        warn!(error = %e, user_id = user.id, "Failed to disable MFA by admin");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    audit_event(&state, &conn, "admin_disable_mfa", &username, "admin", "");
    info!(username = username, "MFA disabled by admin");

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "mfa_disabled",
            "username": username,
        })),
    )
        .into_response()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::auth::fernet_enc;
    use crate::storage::users;
    use crate::test_support;
    use axum::extract::ConnectInfo;
    use std::net::SocketAddr;

    pub(crate) const SECRET: &str = "JBSWY3DPEHPK3PXP";

    /// A user with MFA on and a readable (dev-mode `b64:`) TOTP secret.
    pub(crate) fn mfa_user(state: &AppState, username: &str) -> i64 {
        let conn = state.db_pool.get().unwrap();
        let user_id = users::tests::insert_user(&conn, username, "viewer", true);
        mfa::set_totp_secret(&conn, user_id, SECRET, "", false).unwrap();
        mfa::enable_mfa(&conn, user_id).unwrap();
        user_id
    }

    /// The TOTP code of [`mfa_user`]'s secret right now.
    pub(crate) fn current_code() -> String {
        totp::compute_totp(SECRET, None, 30, 6).unwrap()
    }

    /// A code that is not valid now (±1 step), for wrong-code attempts.
    fn wrong_code() -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (0..1_000_000u32)
            .map(|n| format!("{n:06}"))
            .find(|c| !totp::verify_totp(SECRET, c, 1, Some(now), 30, 6))
            .unwrap()
    }

    fn json_request(path: &str, body: serde_json::Value) -> Request<Body> {
        Request::post(path)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::USER_AGENT, "test-agent/1.0")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    pub(crate) fn verify_request(mfa_token: &str, code: &str) -> Request<Body> {
        let mut req = json_request(
            "/api/auth/mfa/verify",
            serde_json::json!({"mfa_token": mfa_token, "totp_code": code}),
        );
        let peer: SocketAddr = "203.0.113.9:40000".parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        req
    }

    fn session_request(path: &str, user_id: i64, username: &str, code: &str) -> Request<Body> {
        let mut req = json_request(path, serde_json::json!({"totp_code": code}));
        req.extensions_mut().insert(AuthInfo::Session {
            username: username.to_string(),
            user_id,
            role: Role::Viewer,
            session_token: "irrelevant".into(),
            expires_at: String::new(),
            tenant_id: "default".into(),
            scope: String::new(),
        });
        req
    }

    async fn json_body(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn set_cookies(resp: &Response) -> Vec<String> {
        resp.headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    /// A user with MFA on whose TOTP secret was encrypted under a key that
    /// is no longer configured, plus one backup code; returns a pending
    /// MFA login token.
    fn user_with_unreadable_secret(state: &AppState, backup_code: &str) -> String {
        let mut conn = state.db_pool.get().unwrap();
        let user_id = users::tests::insert_user(&conn, "alice", "viewer", true);
        let old_key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        let stored = fernet_enc::encrypt_totp_secret("JBSWY3DPEHPK3PXP", old_key, true).unwrap();
        conn.execute(
            "UPDATE users SET totp_secret = ?1, mfa_enabled = 1 WHERE id = ?2",
            rusqlite::params![stored, user_id],
        )
        .unwrap();
        let code_hash = password::hash_credential(backup_code, None);
        mfa::store_backup_codes(&mut conn, user_id, &[code_hash]).unwrap();
        mfa::create_mfa_token_unchecked(&conn, user_id, 5).unwrap()
    }

    #[tokio::test]
    async fn mfa_login_falls_back_to_backup_code_when_secret_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        assert!(state.config.mfa_key.is_empty(), "the old key is gone");
        let mfa_token = user_with_unreadable_secret(&state, "abcd1234");

        let resp = mfa_verify_login(
            State(Arc::clone(&state)),
            verify_request(&mfa_token, "abcd1234"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "backup code completes login");
        assert_eq!(test_support::audit_count(&state, "user_login_mfa"), 1);
    }

    #[tokio::test]
    async fn unreadable_secret_with_wrong_code_is_unauthorized_not_500() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let mfa_token = user_with_unreadable_secret(&state, "abcd1234");

        let resp = mfa_verify_login(
            State(Arc::clone(&state)),
            verify_request(&mfa_token, "123456"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Regression (G4): the MFA login created its session with an empty IP
    /// and User-Agent (no binding for exactly the MFA users) and set no
    /// cookies, answering `csrf_token: ""` — every later POST was a 403.
    #[tokio::test]
    async fn mfa_login_issues_a_bound_session_with_cookies_and_csrf() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "alice");
        let token =
            mfa::create_mfa_token_unchecked(&state.db_pool.get().unwrap(), user_id, 5).unwrap();

        let resp = mfa_verify_login(
            State(Arc::clone(&state)),
            verify_request(&token, &current_code()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let cookies = set_cookies(&resp);
        let body = json_body(resp).await;

        let session_token = body["session_token"].as_str().unwrap().to_string();
        let csrf = body["csrf_token"].as_str().unwrap().to_string();
        assert_eq!(csrf.len(), 64, "a real CSRF token: {body}");
        assert!(cookies.iter().any(
            |c| c.starts_with(&format!("session_token={session_token};")) && c.contains("HttpOnly")
        ));
        assert!(cookies
            .iter()
            .any(|c| c.starts_with(&format!("csrf_token={csrf};"))));
        assert!(
            !cookies
                .iter()
                .any(|c| c.contains(&format!("={session_token}"))
                    && !c.starts_with("session_token=")),
            "the token is in no JS-readable cookie: {cookies:?}"
        );

        let conn = state.db_pool.get().unwrap();
        let (ip, ua): (String, String) = conn
            .query_row(
                "SELECT ip_address, user_agent FROM sessions WHERE user_id = ?1",
                [user_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(ip, "203.0.113.9");
        assert_eq!(ua, "test-agent/1.0");
        assert_eq!(test_support::audit_count(&state, "user_login_mfa"), 1);
    }

    /// Login CSRF on the second step: MFA verify is CSRF-exempt like the
    /// password login and read any body as JSON, so a cross-site
    /// `text/plain` form could complete an attacker's MFA challenge in the
    /// victim's browser. A body not declared `application/json` is now
    /// refused with 415 before the challenge is claimed, so it stays
    /// usable, and no attempt is counted.
    #[tokio::test]
    async fn mfa_verify_refuses_a_body_not_declared_json() {
        use crate::auth::session_handler::tests::{JSON_CONTENT_TYPES, NOT_JSON_CONTENT_TYPES};
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "alice");
        let token =
            mfa::create_mfa_token_unchecked(&state.db_pool.get().unwrap(), user_id, 5).unwrap();
        let body = serde_json::json!({"mfa_token": token, "totp_code": current_code()});
        let request = |content_type: Option<&str>| {
            let mut builder = Request::post("/api/auth/mfa/verify")
                .header(header::USER_AGENT, "test-agent/1.0")
                .header("origin", "https://evil.example");
            if let Some(content_type) = content_type {
                builder = builder.header(header::CONTENT_TYPE, content_type);
            }
            let mut req = builder.body(Body::from(body.to_string())).unwrap();
            req.extensions_mut().insert(ConnectInfo(
                "203.0.113.9:40000".parse::<SocketAddr>().unwrap(),
            ));
            req
        };
        for content_type in NOT_JSON_CONTENT_TYPES {
            let resp = mfa_verify_login(State(Arc::clone(&state)), request(*content_type)).await;
            assert_eq!(
                resp.status(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "{content_type:?}"
            );
            assert!(set_cookies(&resp).is_empty(), "{content_type:?}");
            assert_eq!(
                json_body(resp).await["detail"],
                "Content-Type must be application/json"
            );
        }
        let conn = state.db_pool.get().unwrap();
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        drop(conn);
        assert_eq!(test_support::audit_count(&state, "user_login_mfa"), 0);

        // The challenge was not spent: declared as JSON, it completes.
        let resp = mfa_verify_login(
            State(Arc::clone(&state)),
            request(Some(JSON_CONTENT_TYPES[3])),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(set_cookies(&resp)
            .iter()
            .any(|c| c.starts_with("session_token=") && c.contains("HttpOnly")));
    }

    /// Regression (G5): the MFA token was checked with SELECT and deleted
    /// without looking at the row count, so parallel requests could all
    /// claim one token. Exactly one claim may succeed.
    #[test]
    fn mfa_token_is_claimed_once_under_concurrency() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = {
            let conn = state.db_pool.get().unwrap();
            users::tests::insert_user(&conn, "alice", "viewer", true)
        };
        for round in 0..20 {
            let token =
                mfa::create_mfa_token_unchecked(&state.db_pool.get().unwrap(), user_id, 5).unwrap();
            let barrier = Arc::new(std::sync::Barrier::new(4));
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let (state, barrier, token) =
                        (Arc::clone(&state), Arc::clone(&barrier), token.clone());
                    std::thread::spawn(move || {
                        let conn = state.db_pool.get().unwrap();
                        barrier.wait();
                        mfa::verify_mfa_token(&conn, &token).unwrap()
                    })
                })
                .collect();
            let claimed = handles
                .into_iter()
                .filter_map(|h| h.join().unwrap())
                .count();
            assert_eq!(claimed, 1, "round {round}: one token, one claim");
        }
    }

    #[test]
    fn expired_mfa_token_is_consumed_but_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user_id = users::tests::insert_user(&conn, "alice", "viewer", true);
        let token = mfa::create_mfa_token_unchecked(&conn, user_id, -1).unwrap();
        assert_eq!(mfa::verify_mfa_token(&conn, &token).unwrap(), None);
        let left: i64 = conn
            .query_row("SELECT COUNT(*) FROM mfa_tokens", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 0);
        let token = mfa::create_mfa_token_unchecked(&conn, user_id, 5).unwrap();
        assert_eq!(
            mfa::verify_mfa_token(&conn, &token)
                .unwrap()
                .map(|c| c.user_id),
            Some(user_id)
        );
        assert_eq!(mfa::verify_mfa_token(&conn, &token).unwrap(), None);
    }

    /// G5, end to end: parallel logins presenting one TOTP code (each with
    /// its own MFA token) yield one session. The handler's earlier database
    /// writes spread the requests apart, so this does not reliably catch a
    /// check-then-record replay race; the storage-level
    /// `concurrent_claims_of_one_totp_code_have_one_winner` does.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn one_totp_code_logs_in_once_under_concurrency() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        for round in 0..8 {
            let username = format!("user{round}");
            let user_id = mfa_user(&state, &username);
            let tokens: Vec<String> = {
                let conn = state.db_pool.get().unwrap();
                (0..4)
                    .map(|_| mfa::create_mfa_token_unchecked(&conn, user_id, 5).unwrap())
                    .collect()
            };
            let code = current_code();
            let barrier = Arc::new(tokio::sync::Barrier::new(4));
            let tasks: Vec<_> = tokens
                .into_iter()
                .map(|token| {
                    let (state, barrier, code) =
                        (Arc::clone(&state), Arc::clone(&barrier), code.clone());
                    tokio::spawn(async move {
                        let req = verify_request(&token, &code);
                        barrier.wait().await;
                        mfa_verify_login(State(state), req).await.status()
                    })
                })
                .collect();
            let mut ok = 0;
            for task in tasks {
                if task.await.unwrap() == StatusCode::OK {
                    ok += 1;
                }
            }
            assert_eq!(ok, 1, "round {round}: one TOTP code, one login");
        }
    }

    /// Regression (G5): a backup code was marked used without checking it
    /// was still unused, so parallel requests that all read it as unused
    /// (each then spending ~a PBKDF2 verifying it) could all spend it.
    #[test]
    fn backup_code_is_spent_once_under_concurrency() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = {
            let mut conn = state.db_pool.get().unwrap();
            let user_id = users::tests::insert_user(&conn, "alice", "viewer", true);
            let hash = password::hash_credential("abcd1234", None);
            mfa::store_backup_codes(&mut conn, user_id, &[hash]).unwrap();
            user_id
        };
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let handles: Vec<_> = (0..3)
            .map(|_| {
                let (state, barrier) = (Arc::clone(&state), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    let conn = state.db_pool.get().unwrap();
                    barrier.wait();
                    mfa::verify_backup_code(&conn, user_id, "ABCD1234").unwrap()
                })
            })
            .collect();
        let spent = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|&ok| ok)
            .count();
        assert_eq!(spent, 1, "one backup code, one use");
        let conn = state.db_pool.get().unwrap();
        assert!(!mfa::verify_backup_code(&conn, user_id, "abcd1234").unwrap());
    }

    async fn set_lockout_max(state: &AppState, max: u32) {
        state.auth_config.write().await.security_limits.lockout_max = max;
    }

    /// Regression (G5): disable and regenerate-backup-codes had no attempt
    /// limit, so a session holder could walk the 10^6 TOTP space. After
    /// `UC_LOCKOUT_MAX` failed checks every second-factor check of that
    /// user is refused — even with the right code — until the window ends.
    #[tokio::test]
    async fn second_factor_checks_are_limited_per_user() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        set_lockout_max(&state, 3).await;
        let user_id = mfa_user(&state, "alice");
        let wrong = wrong_code();

        for _ in 0..3 {
            let resp = mfa_disable(
                State(Arc::clone(&state)),
                session_request("/api/auth/mfa/disable", user_id, "alice", &wrong),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
        for path in [
            "/api/auth/mfa/disable",
            "/api/auth/mfa/regenerate-backup-codes",
        ] {
            let req = session_request(path, user_id, "alice", &current_code());
            let resp = if path.ends_with("disable") {
                mfa_disable(State(Arc::clone(&state)), req).await
            } else {
                mfa_regenerate_backup_codes(State(Arc::clone(&state)), req).await
            };
            assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS, "{path}");
            assert!(resp.headers().contains_key(header::RETRY_AFTER));
        }
        // The login step is limited for the same user too.
        let token =
            mfa::create_mfa_token_unchecked(&state.db_pool.get().unwrap(), user_id, 5).unwrap();
        let resp = mfa_verify_login(
            State(Arc::clone(&state)),
            verify_request(&token, &current_code()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        // MFA is still on: nothing was disabled.
        let conn = state.db_pool.get().unwrap();
        assert!(
            mfa::get_user_by_id(&conn, user_id)
                .unwrap()
                .unwrap()
                .mfa_enabled
        );
    }

    #[tokio::test]
    async fn success_clears_the_attempt_count() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        set_lockout_max(&state, 3).await;
        let user_id = mfa_user(&state, "alice");
        let wrong = wrong_code();
        let conn = state.db_pool.get().unwrap();
        for _ in 0..2 {
            assert!(mfa::reserve_mfa_attempt(&conn, user_id, "default", 3, 60.0).unwrap());
        }
        drop(conn);
        // Third (and last allowed) check succeeds and resets the count …
        let token =
            mfa::create_mfa_token_unchecked(&state.db_pool.get().unwrap(), user_id, 5).unwrap();
        let resp = mfa_verify_login(
            State(Arc::clone(&state)),
            verify_request(&token, &current_code()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        // … so three more failures are allowed before the lockout.
        for expected in [
            StatusCode::UNAUTHORIZED,
            StatusCode::UNAUTHORIZED,
            StatusCode::UNAUTHORIZED,
            StatusCode::TOO_MANY_REQUESTS,
        ] {
            let resp = mfa_disable(
                State(Arc::clone(&state)),
                session_request("/api/auth/mfa/disable", user_id, "alice", &wrong),
            )
            .await;
            assert_eq!(resp.status(), expected);
        }
    }

    #[test]
    fn attempt_reservations_are_atomic_and_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let barrier = Arc::new(std::sync::Barrier::new(4));
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let (state, barrier) = (Arc::clone(&state), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    let conn = state.db_pool.get().unwrap();
                    barrier.wait();
                    (0..10)
                        .filter(|_| mfa::reserve_mfa_attempt(&conn, 7, "default", 5, 60.0).unwrap())
                        .count()
                })
            })
            .collect();
        let reserved: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(reserved, 5, "40 parallel attempts, limit 5");
        let conn = state.db_pool.get().unwrap();
        assert_eq!(mfa::clear_mfa_attempts(&conn, 7, "default").unwrap(), 5);
        assert!(mfa::reserve_mfa_attempt(&conn, 7, "default", 5, 60.0).unwrap());
    }

    #[tokio::test]
    async fn replayed_totp_code_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "alice");
        let code = current_code();
        let conn = state.db_pool.get().unwrap();
        assert!(mfa::claim_totp_code(&conn, "alice", &code, "default").unwrap());
        assert!(!mfa::claim_totp_code(&conn, "alice", &code, "default").unwrap());
        assert!(mfa::claim_totp_code(&conn, "bob", &code, "default").unwrap());
        drop(conn);
        let token =
            mfa::create_mfa_token_unchecked(&state.db_pool.get().unwrap(), user_id, 5).unwrap();
        let resp = mfa_verify_login(State(Arc::clone(&state)), verify_request(&token, &code)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(resp).await["detail"], "TOTP code already used");
    }

    #[tokio::test]
    async fn admin_cannot_disable_mfa_of_a_keymaster() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        users::tests::insert_user(&conn, "root", "keymaster", true);
        drop(conn);
        for (role, expected) in [
            (Role::Admin, StatusCode::FORBIDDEN),
            (Role::Keymaster, StatusCode::OK),
        ] {
            let mut req = Request::post("/api/admin/users/root/disable-mfa")
                .body(Body::empty())
                .unwrap();
            req.extensions_mut().insert(AuthInfo::ApiKey {
                key_id: "k".into(),
                role,
            });
            let resp = admin_disable_user_mfa(
                State(Arc::clone(&state)),
                axum::extract::Path("root".to_string()),
                req,
            )
            .await;
            assert_eq!(resp.status(), expected, "{role}");
        }
    }

    fn admin_request(body: serde_json::Value, role: Role) -> Request<Body> {
        let mut req = json_request("/api/admin/mfa", body);
        req.extensions_mut().insert(AuthInfo::Session {
            username: "operator".into(),
            user_id: 99,
            role,
            session_token: "handler-fixture".into(),
            expires_at: String::new(),
            tenant_id: "default".into(),
            scope: String::new(),
        });
        req
    }

    #[derive(Clone, Copy, Debug)]
    enum Endpoint {
        Setup,
        VerifySetup,
        Verify,
        Disable,
        Regenerate,
        PolicySet,
        PolicyGet,
        AdminDisable,
    }

    async fn endpoint(state: Arc<AppState>, name: Endpoint, req: Request<Body>) -> Response {
        match name {
            Endpoint::Setup => mfa_setup(State(state), req).await,
            Endpoint::VerifySetup => mfa_verify_setup(State(state), req).await,
            Endpoint::Verify => mfa_verify_login(State(state), req).await,
            Endpoint::Disable => mfa_disable(State(state), req).await,
            Endpoint::Regenerate => mfa_regenerate_backup_codes(State(state), req).await,
            Endpoint::PolicySet => set_tenant_mfa(State(state), req).await,
            Endpoint::PolicyGet => get_tenant_mfa(State(state), req).await,
            Endpoint::AdminDisable => {
                admin_disable_user_mfa(State(state), axum::extract::Path("alice".into()), req).await
            }
        }
    }

    #[tokio::test]
    async fn management_endpoints_require_the_right_authentication_before_writes() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "alice");
        for name in [
            Endpoint::Setup,
            Endpoint::VerifySetup,
            Endpoint::Disable,
            Endpoint::Regenerate,
        ] {
            for api_key in [false, true] {
                let mut req = json_request("/", serde_json::json!({"totp_code": current_code()}));
                if api_key {
                    req.extensions_mut().insert(AuthInfo::ApiKey {
                        key_id: "admin-key".into(),
                        role: Role::Admin,
                    });
                }
                let response = endpoint(Arc::clone(&state), name, req).await;
                assert_eq!(
                    response.status(),
                    StatusCode::FORBIDDEN,
                    "{name:?}, api_key={api_key}"
                );
                assert_eq!(
                    json_body(response).await["detail"],
                    "Session authentication required"
                );
            }
        }
        for name in [
            Endpoint::PolicySet,
            Endpoint::PolicyGet,
            Endpoint::AdminDisable,
        ] {
            let response = endpoint(
                Arc::clone(&state),
                name,
                admin_request(serde_json::json!({"mfa_required": true}), Role::Viewer),
            )
            .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{name:?}");
            assert_eq!(json_body(response).await["detail"], "Admin role required");
        }
        let conn = state.db_pool.get().unwrap();
        assert!(
            mfa::get_user_by_id(&conn, user_id)
                .unwrap()
                .unwrap()
                .mfa_enabled
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM audit_log", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn malformed_and_oversized_mfa_bodies_are_rejected_before_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "alice");
        for name in [
            Endpoint::VerifySetup,
            Endpoint::Verify,
            Endpoint::Disable,
            Endpoint::Regenerate,
            Endpoint::PolicySet,
        ] {
            for body in ["{invalid json".to_string(), "x".repeat(4097)] {
                let mut req = admin_request(serde_json::json!({}), Role::Admin);
                *req.body_mut() = Body::from(body);
                let response = endpoint(Arc::clone(&state), name, req).await;
                assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{name:?}");
            }
        }
        let conn = state.db_pool.get().unwrap();
        assert!(
            mfa::get_user_by_id(&conn, user_id)
                .unwrap()
                .unwrap()
                .mfa_enabled
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM sessions", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn enrollment_stays_pending_until_verified_and_preserves_enabled_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id =
            users::tests::insert_user(&state.db_pool.get().unwrap(), "alice", "viewer", true);
        let missing = mfa_verify_setup(
            State(Arc::clone(&state)),
            session_request("/", user_id, "alice", &current_code()),
        )
        .await;
        assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
        let setup = mfa_setup(
            State(Arc::clone(&state)),
            session_request("/", user_id, "alice", ""),
        )
        .await;
        assert_eq!(setup.status(), StatusCode::OK);
        let body = json_body(setup).await;
        let secret = body["secret"].as_str().unwrap();
        let codes = body["backup_codes"].as_array().unwrap();
        assert_eq!(codes.len(), 10);
        assert_eq!(
            codes
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect::<std::collections::HashSet<_>>()
                .len(),
            10
        );
        assert!(body["provisioning_uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/"));
        let conn = state.db_pool.get().unwrap();
        assert!(
            !mfa::get_user_by_id(&conn, user_id)
                .unwrap()
                .unwrap()
                .mfa_enabled
        );
        let stored: String = conn
            .query_row(
                "SELECT code_hash FROM mfa_backup_codes LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!codes
            .iter()
            .any(|code| code.as_str() == Some(stored.as_str())));
        drop(conn);
        let invalid = mfa_verify_setup(
            State(Arc::clone(&state)),
            session_request("/", user_id, "alice", "not-a-code"),
        )
        .await;
        assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(test_support::audit_count(&state, "mfa_enable"), 0);
        let code = totp::compute_totp(secret, None, 30, 6).unwrap();
        let verified = mfa_verify_setup(
            State(Arc::clone(&state)),
            session_request("/", user_id, "alice", &format!(" {code} ")),
        )
        .await;
        assert_eq!(verified.status(), StatusCode::OK);
        assert_eq!(
            json_body(verified).await,
            serde_json::json!({"status":"mfa_enabled","backup_codes_remaining":10})
        );
        assert_eq!(test_support::audit_count(&state, "mfa_enable"), 1);
        let repeated = mfa_setup(
            State(Arc::clone(&state)),
            session_request("/", user_id, "alice", ""),
        )
        .await;
        assert_eq!(repeated.status(), StatusCode::CONFLICT);
        let conn = state.db_pool.get().unwrap();
        assert_eq!(
            mfa::get_totp_secret(&conn, user_id, "").unwrap().as_deref(),
            Some(secret)
        );
        assert_eq!(mfa::get_backup_code_count(&conn, user_id).unwrap(), 10);
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM mfa_attempts WHERE user_id=?1",
                [user_id],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn backup_regeneration_replaces_old_codes_and_refuses_totp_replay() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "alice");
        mfa::store_backup_codes(
            &mut state.db_pool.get().unwrap(),
            user_id,
            &[password::hash_credential("old-code", None)],
        )
        .unwrap();
        let wrong = mfa_regenerate_backup_codes(
            State(Arc::clone(&state)),
            session_request("/", user_id, "alice", &wrong_code()),
        )
        .await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        let code = current_code();
        let response = mfa_regenerate_backup_codes(
            State(Arc::clone(&state)),
            session_request("/", user_id, "alice", &code),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["backup_codes_remaining"], 10);
        let new_code = body["backup_codes"][0].as_str().unwrap();
        let conn = state.db_pool.get().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM totp_replay_cache WHERE username='alice' AND totp_code=?1 AND tenant_id='default'",
                [&code],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1,
            "Successful regeneration records its second factor"
        );
        // Generating ten PBKDF2 hashes can outlive a TOTP window under
        // instrumentation. Test exact replay handling with a current claimed
        // factor, before the remaining expensive backup-code checks.
        let replay_code = current_code();
        mfa::claim_totp_code(&conn, "alice", &replay_code, "default").unwrap();
        drop(conn);
        let replay = mfa_regenerate_backup_codes(
            State(Arc::clone(&state)),
            session_request("/", user_id, "alice", &replay_code),
        )
        .await;
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(replay).await["detail"], "TOTP code already used");
        assert_eq!(
            test_support::audit_count(&state, "mfa_regenerate_backup_codes"),
            1
        );
        let conn = state.db_pool.get().unwrap();
        assert!(!mfa::verify_backup_code(&conn, user_id, "old-code").unwrap());
        assert!(mfa::verify_backup_code(&conn, user_id, new_code).unwrap());
        assert_eq!(mfa::get_backup_code_count(&conn, user_id).unwrap(), 9);
    }

    #[tokio::test]
    async fn failed_backup_regeneration_preserves_codes_but_consumes_the_verified_factor() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "alice");
        let mut conn = state.db_pool.get().unwrap();
        mfa::store_backup_codes(
            &mut conn,
            user_id,
            &[
                password::hash_credential("already-used", None),
                password::hash_credential("still-usable", None),
            ],
        )
        .unwrap();
        assert!(mfa::verify_backup_code(&conn, user_id, "already-used").unwrap());
        conn.execute_batch(
            "CREATE TRIGGER reject_second_replacement BEFORE INSERT ON mfa_backup_codes
             WHEN (SELECT COUNT(*) FROM mfa_backup_codes WHERE user_id=NEW.user_id)=1
             BEGIN SELECT RAISE(ABORT, 'fixture second insert failure'); END",
        )
        .unwrap();
        drop(conn);

        let factor = current_code();
        let response = mfa_regenerate_backup_codes(
            State(Arc::clone(&state)),
            session_request("/", user_id, "alice", &factor),
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            test_support::audit_count(&state, "mfa_regenerate_backup_codes"),
            0
        );
        let conn = state.db_pool.get().unwrap();
        // Count the exact claim instead of relying on wall-clock TOTP validity
        // after the handler's ten potentially slow PBKDF2 hashes.
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM totp_replay_cache WHERE username='alice' AND totp_code=?1 AND tenant_id='default'",
                [&factor],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1
        );
        assert!(
            mfa::get_user_by_id(&conn, user_id)
                .unwrap()
                .unwrap()
                .mfa_enabled
        );
        assert_eq!(
            mfa::get_totp_secret(&conn, user_id, "").unwrap(),
            Some(SECRET.into())
        );
        assert_eq!(mfa::get_backup_code_count(&conn, user_id).unwrap(), 1);
        assert!(!mfa::verify_backup_code(&conn, user_id, "already-used").unwrap());
        assert!(mfa::verify_backup_code(&conn, user_id, "still-usable").unwrap());
        assert!(!mfa::verify_backup_code(&conn, user_id, "still-usable").unwrap());
    }

    #[tokio::test]
    async fn disabling_with_a_backup_code_removes_secret_and_all_remaining_codes() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "alice");
        mfa::store_backup_codes(
            &mut state.db_pool.get().unwrap(),
            user_id,
            &[
                password::hash_credential("abcd1234", None),
                password::hash_credential("unused-code", None),
            ],
        )
        .unwrap();
        let response = mfa_disable(
            State(Arc::clone(&state)),
            session_request("/", user_id, "alice", " ABCD1234 "),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await["status"], "mfa_disabled");
        let conn = state.db_pool.get().unwrap();
        assert!(
            !mfa::get_user_by_id(&conn, user_id)
                .unwrap()
                .unwrap()
                .mfa_enabled
        );
        assert_eq!(mfa::get_totp_secret(&conn, user_id, "").unwrap(), None);
        assert_eq!(mfa::get_backup_code_count(&conn, user_id).unwrap(), 0);
        assert_eq!(test_support::audit_count(&state, "mfa_disable"), 1);
    }

    #[tokio::test]
    async fn tenant_mfa_policy_round_trips_for_admin_sessions_and_reports_write_failures() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        state.db_pool.get().unwrap().execute_batch("CREATE TABLE tenant_settings (tenant_id TEXT PRIMARY KEY, mfa_required BOOLEAN NOT NULL, updated_at TEXT NOT NULL)").unwrap();
        let initial = get_tenant_mfa(
            State(Arc::clone(&state)),
            admin_request(serde_json::json!({}), Role::Admin),
        )
        .await;
        assert_eq!(initial.status(), StatusCode::OK);
        assert_eq!(json_body(initial).await["mfa_required"], false);
        for required in [true, false] {
            let response = set_tenant_mfa(
                State(Arc::clone(&state)),
                admin_request(serde_json::json!({"mfa_required":required}), Role::Admin),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                json_body(response).await,
                serde_json::json!({"tenant_id":"default","mfa_required":required})
            );
            let persisted = get_tenant_mfa(
                State(Arc::clone(&state)),
                admin_request(serde_json::json!({}), Role::Admin),
            )
            .await;
            assert_eq!(json_body(persisted).await["mfa_required"], required);
        }
        assert_eq!(
            test_support::audit_count(&state, "tenant_mfa_policy_change"),
            2
        );
        state.db_pool.get().unwrap().execute_batch("CREATE TRIGGER reject_policy BEFORE INSERT ON tenant_settings BEGIN SELECT RAISE(ABORT, 'fixture write failure'); END").unwrap();
        let response = set_tenant_mfa(
            State(Arc::clone(&state)),
            admin_request(serde_json::json!({"mfa_required":true}), Role::Admin),
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!mfa::get_tenant_mfa_required(&state.db_pool.get().unwrap(), "default").unwrap());
        assert_eq!(
            test_support::audit_count(&state, "tenant_mfa_policy_change"),
            2
        );
    }

    #[tokio::test]
    async fn rejected_and_failed_login_checks_never_issue_sessions_or_success_audits() {
        for scenario in [
            "unknown-token",
            "disabled-user",
            "invalid-code",
            "replay-store-failure",
            "token-store-failure",
            "session-store-failure",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let state = test_support::app_state(&dir);
            let user_id = mfa_user(&state, "alice");
            let conn = state.db_pool.get().unwrap();
            let token = mfa::create_mfa_token_unchecked(&conn, user_id, 5).unwrap();
            match scenario {
                "disabled-user" => {
                    conn.execute("UPDATE users SET enabled=0 WHERE id=?1", [user_id])
                        .unwrap();
                }
                "replay-store-failure" => {
                    conn.execute_batch("DROP TABLE totp_replay_cache").unwrap();
                }
                "token-store-failure" => {
                    conn.execute_batch("CREATE TRIGGER reject_token BEFORE DELETE ON mfa_tokens BEGIN SELECT RAISE(ABORT, 'fixture token failure'); END").unwrap();
                }
                "session-store-failure" => {
                    conn.execute_batch("CREATE TRIGGER reject_session BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT, 'fixture session failure'); END").unwrap();
                }
                _ => {}
            }
            drop(conn);
            let current = current_code();
            let request = verify_request(
                if scenario == "unknown-token" {
                    "unknown"
                } else {
                    &token
                },
                if scenario == "invalid-code" {
                    "abcdef"
                } else {
                    &current
                },
            );
            let response = mfa_verify_login(State(Arc::clone(&state)), request).await;
            let expected = if scenario.ends_with("failure") {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::UNAUTHORIZED
            };
            assert_eq!(response.status(), expected, "{scenario}");
            assert!(set_cookies(&response).is_empty(), "{scenario}");
            assert_eq!(
                state
                    .db_pool
                    .get()
                    .unwrap()
                    .query_row("SELECT COUNT(*) FROM sessions", [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                0,
                "{scenario}"
            );
            assert_eq!(
                test_support::audit_count(&state, "user_login_mfa"),
                0,
                "{scenario}"
            );
        }
    }

    #[tokio::test]
    async fn disable_write_failures_do_not_claim_success_or_emit_success_audits() {
        for admin in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let state = test_support::app_state(&dir);
            let user_id = mfa_user(&state, "alice");
            state.db_pool.get().unwrap().execute_batch("CREATE TRIGGER reject_disable BEFORE UPDATE OF mfa_enabled ON users BEGIN SELECT RAISE(ABORT, 'fixture write failure'); END").unwrap();
            let response = if admin {
                admin_disable_user_mfa(
                    State(Arc::clone(&state)),
                    axum::extract::Path("alice".into()),
                    admin_request(serde_json::json!({}), Role::Admin),
                )
                .await
            } else {
                mfa_disable(
                    State(Arc::clone(&state)),
                    session_request("/", user_id, "alice", &current_code()),
                )
                .await
            };
            assert_eq!(
                response.status(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "admin={admin}"
            );
            assert!(
                mfa::get_user_by_id(&state.db_pool.get().unwrap(), user_id)
                    .unwrap()
                    .unwrap()
                    .mfa_enabled
            );
            assert_eq!(
                test_support::audit_count(
                    &state,
                    if admin {
                        "admin_disable_mfa"
                    } else {
                        "mfa_disable"
                    }
                ),
                0
            );
        }
    }

    #[tokio::test]
    async fn backup_cleanup_failure_cannot_partially_disable_mfa() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "alice");
        let mut conn = state.db_pool.get().unwrap();
        mfa::store_backup_codes(
            &mut conn,
            user_id,
            &[password::hash_credential("unused-code", None)],
        )
        .unwrap();
        conn.execute_batch("CREATE TRIGGER reject_cleanup BEFORE DELETE ON mfa_backup_codes BEGIN SELECT RAISE(ABORT, 'fixture cleanup failure'); END").unwrap();
        drop(conn);
        let response = admin_disable_user_mfa(
            State(Arc::clone(&state)),
            axum::extract::Path("alice".into()),
            admin_request(serde_json::json!({}), Role::Admin),
        )
        .await;
        let conn = state.db_pool.get().unwrap();
        assert_eq!(
            (
                response.status(),
                mfa::get_user_by_id(&conn, user_id)
                    .unwrap()
                    .unwrap()
                    .mfa_enabled,
                mfa::get_totp_secret(&conn, user_id, "").unwrap(),
                mfa::get_backup_code_count(&conn, user_id).unwrap()
            ),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                true,
                Some(SECRET.into()),
                1
            )
        );
        assert_eq!(test_support::audit_count(&state, "admin_disable_mfa"), 0);
    }

    #[tokio::test]
    async fn a_backup_factor_is_single_use_even_when_the_protected_write_fails() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "alice");
        let mut conn = state.db_pool.get().unwrap();
        mfa::store_backup_codes(
            &mut conn,
            user_id,
            &[password::hash_credential("abcd1234", None)],
        )
        .unwrap();
        conn.execute_batch("CREATE TRIGGER reject_disable BEFORE UPDATE OF mfa_enabled ON users BEGIN SELECT RAISE(ABORT, 'fixture write failure'); END").unwrap();
        drop(conn);
        let failed = mfa_disable(
            State(Arc::clone(&state)),
            session_request("/", user_id, "alice", "abcd1234"),
        )
        .await;
        assert_eq!(failed.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let conn = state.db_pool.get().unwrap();
        assert!(
            mfa::get_user_by_id(&conn, user_id)
                .unwrap()
                .unwrap()
                .mfa_enabled
        );
        assert_eq!(mfa::get_backup_code_count(&conn, user_id).unwrap(), 0);
        conn.execute_batch("DROP TRIGGER reject_disable").unwrap();
        drop(conn);
        let replay = mfa_disable(
            State(Arc::clone(&state)),
            session_request("/", user_id, "alice", "abcd1234"),
        )
        .await;
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(test_support::audit_count(&state, "mfa_disable"), 0);
    }

    #[tokio::test]
    async fn tenant_boundary_foreign_mfa_challenge_is_not_consumed_or_issued_a_session() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user = mfa_user(&state, "foreign-mfa");
        let conn = state.db_pool.get().unwrap();
        conn.execute("UPDATE users SET tenant_id='other' WHERE id=?1", [user])
            .unwrap();
        let token = mfa::create_mfa_token_unchecked(&conn, user, 5).unwrap();
        let response = mfa_verify_login(
            State(Arc::clone(&state)),
            verify_request(&token, &current_code()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM mfa_tokens WHERE user_id=?1",
                [user],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM sessions WHERE user_id=?1",
                [user],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }

    async fn issuance_mfa_rechecks_user(change: &str) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user = mfa_user(&state, "moving-mfa");
        let conn = state.db_pool.get().unwrap();
        mfa::ensure_mfa_attempts_table(&conn).unwrap();
        let token = mfa::create_mfa_token_unchecked(&conn, user, 5).unwrap();
        // This real SQLite trigger deterministically models an account change
        // after the local challenge is claimed, before final session issuance.
        conn.execute_batch(&format!(
            "CREATE TRIGGER change_account AFTER INSERT ON mfa_attempts
            BEGIN UPDATE users SET {change} WHERE id=NEW.user_id; END"
        ))
        .unwrap();
        let response = mfa_verify_login(
            State(Arc::clone(&state)),
            verify_request(&token, &current_code()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM sessions WHERE user_id=?1",
                [user],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM mfa_tokens WHERE user_id=?1",
                [user],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0,
            "the previously local challenge stays single-use"
        );
        assert_eq!(
            conn.query_row("SELECT last_login FROM users WHERE id=?1", [user], |r| {
                r.get::<_, Option<String>>(0)
            })
            .unwrap(),
            None
        );
        assert_eq!(test_support::audit_count(&state, "user_login_mfa"), 0);
    }

    #[tokio::test]
    async fn tenant_boundary_issuance_rechecks_mfa_tenant() {
        issuance_mfa_rechecks_user("tenant_id='other'").await;
    }

    #[tokio::test]
    async fn tenant_boundary_issuance_rechecks_mfa_enabled() {
        issuance_mfa_rechecks_user("enabled=0").await;
    }

    /// A password reset committed after the challenge was claimed, while the
    /// second factor is checked, refuses the session too.
    #[tokio::test]
    async fn issuance_rechecks_the_mfa_login_password() {
        issuance_mfa_rechecks_user(&format!("password_hash='{}'", "ab".repeat(32))).await;
    }

    /// Regression: a pending MFA login outlived a password reset. With the
    /// password and the second factor (say, from a phishing proxy), an
    /// attacker who had started a login before the admin reset the
    /// password could still finish it within the challenge's 5 minutes
    /// and get a full session, from a password no longer valid.
    #[tokio::test]
    async fn an_mfa_challenge_from_before_a_password_reset_cannot_complete_the_login() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "alice");
        let token =
            mfa::create_mfa_token_unchecked(&state.db_pool.get().unwrap(), user_id, 5).unwrap();

        // What reset_password_handler runs.
        assert!(users::set_password_and_revoke_sessions(
            &state.db_pool.get().unwrap(),
            "alice",
            "Adm1n-reset-passw0rd",
            "default"
        )
        .unwrap());

        let resp = mfa_verify_login(
            State(Arc::clone(&state)),
            verify_request(&token, &current_code()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(set_cookies(&resp).is_empty());
        assert_eq!(count(&state, "SELECT COUNT(*) FROM sessions"), 0);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM mfa_tokens"), 0);
        assert_eq!(test_support::audit_count(&state, "user_login_mfa"), 0);
    }

    // ── Security paths: challenge lifecycle, factor reuse, fail-closed ──

    fn count(state: &AppState, sql: &str) -> i64 {
        state
            .db_pool
            .get()
            .unwrap()
            .query_row(sql, [], |row| row.get(0))
            .unwrap()
    }

    fn mfa_enabled(state: &AppState, user_id: i64) -> bool {
        mfa::get_user_by_id(&state.db_pool.get().unwrap(), user_id)
            .unwrap()
            .unwrap()
            .mfa_enabled
    }

    fn new_challenge(state: &AppState, user_id: i64, minutes: i64) -> String {
        mfa::create_mfa_token_unchecked(&state.db_pool.get().unwrap(), user_id, minutes).unwrap()
    }

    fn api_key_request(role: Role) -> Request<Body> {
        let mut req = Request::post("/api/admin/users/x/disable-mfa")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(AuthInfo::ApiKey {
            key_id: "k".into(),
            role,
        });
        req
    }

    async fn admin_disable(state: &Arc<AppState>, username: &str, role: Role) -> Response {
        admin_disable_user_mfa(
            State(Arc::clone(state)),
            axum::extract::Path(username.to_string()),
            api_key_request(role),
        )
        .await
    }

    /// Each password login buys one round of second-factor guesses: a wrong
    /// code consumes the challenge, so the right code cannot follow on it.
    #[tokio::test]
    async fn a_wrong_second_factor_burns_the_login_challenge() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "alice");
        let token = new_challenge(&state, user_id, 5);

        let wrong = mfa_verify_login(
            State(Arc::clone(&state)),
            verify_request(&token, &wrong_code()),
        )
        .await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            json_body(wrong).await["detail"],
            "Invalid TOTP code or backup code"
        );

        let retry = mfa_verify_login(
            State(Arc::clone(&state)),
            verify_request(&token, &current_code()),
        )
        .await;
        assert_eq!(retry.status(), StatusCode::UNAUTHORIZED);
        assert!(set_cookies(&retry).is_empty());
        assert_eq!(
            json_body(retry).await["detail"],
            "Invalid or expired MFA token"
        );
        assert_eq!(count(&state, "SELECT COUNT(*) FROM sessions"), 0);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM mfa_tokens"), 0);
        assert_eq!(test_support::audit_count(&state, "user_login_mfa"), 0);
    }

    /// A completed challenge cannot be presented again for a second session.
    #[tokio::test]
    async fn a_completed_login_challenge_cannot_be_replayed() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "alice");
        let token = new_challenge(&state, user_id, 5);
        let code = current_code();

        let first =
            mfa_verify_login(State(Arc::clone(&state)), verify_request(&token, &code)).await;
        assert_eq!(first.status(), StatusCode::OK);
        let replay =
            mfa_verify_login(State(Arc::clone(&state)), verify_request(&token, &code)).await;
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
        assert!(set_cookies(&replay).is_empty());
        assert_eq!(
            json_body(replay).await["detail"],
            "Invalid or expired MFA token"
        );
        assert_eq!(count(&state, "SELECT COUNT(*) FROM sessions"), 1);
        assert_eq!(test_support::audit_count(&state, "user_login_mfa"), 1);
    }

    /// An expired challenge is refused before the code is looked at: no
    /// session, no counted attempt, and the code is not spent, so the user
    /// can still complete a fresh challenge with it.
    #[tokio::test]
    async fn an_expired_login_challenge_is_refused_without_spending_the_code() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "alice");
        mfa::ensure_mfa_attempts_table(&state.db_pool.get().unwrap()).unwrap();
        let expired = new_challenge(&state, user_id, -1);
        let code = current_code();

        let resp =
            mfa_verify_login(State(Arc::clone(&state)), verify_request(&expired, &code)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(set_cookies(&resp).is_empty());
        assert_eq!(
            json_body(resp).await["detail"],
            "Invalid or expired MFA token"
        );
        assert_eq!(count(&state, "SELECT COUNT(*) FROM sessions"), 0);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM mfa_attempts"), 0);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM totp_replay_cache"), 0);

        let fresh = new_challenge(&state, user_id, 5);
        let resp = mfa_verify_login(State(Arc::clone(&state)), verify_request(&fresh, &code)).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// The replay cache is shared by every second-factor check: a TOTP code
    /// spent on a login cannot then disable MFA.
    #[tokio::test]
    async fn a_totp_code_spent_on_login_cannot_disable_mfa() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "alice");
        let code = current_code();
        let token = new_challenge(&state, user_id, 5);
        let login =
            mfa_verify_login(State(Arc::clone(&state)), verify_request(&token, &code)).await;
        assert_eq!(login.status(), StatusCode::OK);

        let disable = mfa_disable(
            State(Arc::clone(&state)),
            session_request("/api/auth/mfa/disable", user_id, "alice", &code),
        )
        .await;
        assert_eq!(disable.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(disable).await["detail"], "TOTP code already used");
        assert!(mfa_enabled(&state, user_id));
        assert_eq!(
            mfa::get_totp_secret(&state.db_pool.get().unwrap(), user_id, "")
                .unwrap()
                .as_deref(),
            Some(SECRET)
        );
        assert_eq!(test_support::audit_count(&state, "mfa_disable"), 0);
    }

    /// A backup code completes exactly one login.
    #[tokio::test]
    async fn a_backup_code_completes_one_login_only() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "alice");
        mfa::store_backup_codes(
            &mut state.db_pool.get().unwrap(),
            user_id,
            &[password::hash_credential("abcd1234", None)],
        )
        .unwrap();
        let first = new_challenge(&state, user_id, 5);
        let second = new_challenge(&state, user_id, 5);

        let ok = mfa_verify_login(
            State(Arc::clone(&state)),
            verify_request(&first, " ABCD1234 "),
        )
        .await;
        assert_eq!(ok.status(), StatusCode::OK);
        assert_eq!(
            mfa::get_backup_code_count(&state.db_pool.get().unwrap(), user_id).unwrap(),
            0
        );

        let again = mfa_verify_login(
            State(Arc::clone(&state)),
            verify_request(&second, "abcd1234"),
        )
        .await;
        assert_eq!(again.status(), StatusCode::UNAUTHORIZED);
        assert!(set_cookies(&again).is_empty());
        assert_eq!(count(&state, "SELECT COUNT(*) FROM sessions"), 1);
        assert_eq!(test_support::audit_count(&state, "user_login_mfa"), 1);
    }

    /// Regenerating recovery codes needs the TOTP factor itself: a backup
    /// code is refused and not spent, and no new codes are issued.
    #[tokio::test]
    async fn a_backup_code_cannot_regenerate_backup_codes() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "alice");
        mfa::store_backup_codes(
            &mut state.db_pool.get().unwrap(),
            user_id,
            &[password::hash_credential("abcd1234", None)],
        )
        .unwrap();

        let resp = mfa_regenerate_backup_codes(
            State(Arc::clone(&state)),
            session_request("/", user_id, "alice", "abcd1234"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = json_body(resp).await;
        assert_eq!(body["detail"], "Invalid TOTP code");
        assert!(body.get("backup_codes").is_none());
        assert_eq!(
            mfa::get_backup_code_count(&state.db_pool.get().unwrap(), user_id).unwrap(),
            1,
            "the presented backup code is neither spent nor replaced"
        );
        assert_eq!(
            test_support::audit_count(&state, "mfa_regenerate_backup_codes"),
            0
        );
    }

    /// Without an enrolled TOTP secret there is nothing to prove, so no
    /// recovery codes can be minted.
    #[tokio::test]
    async fn regeneration_without_an_enrolled_factor_issues_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id =
            users::tests::insert_user(&state.db_pool.get().unwrap(), "alice", "viewer", true);

        let resp = mfa_regenerate_backup_codes(
            State(Arc::clone(&state)),
            session_request("/", user_id, "alice", &current_code()),
        )
        .await;
        // Pins current behaviour: a client error ("MFA is not enabled")
        // that the handler reports as a server error.
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM mfa_backup_codes"), 0);
        assert_eq!(
            test_support::audit_count(&state, "mfa_regenerate_backup_codes"),
            0
        );
    }

    /// Verify-setup is a second-factor check like the others: failures count
    /// toward the lockout, and once locked out even the right code does not
    /// enable MFA.
    #[tokio::test]
    async fn verify_setup_is_attempt_limited_and_a_locked_enrolment_stays_off() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        set_lockout_max(&state, 2).await;
        let user_id = {
            let conn = state.db_pool.get().unwrap();
            let user_id = users::tests::insert_user(&conn, "alice", "viewer", true);
            mfa::set_totp_secret(&conn, user_id, SECRET, "", false).unwrap();
            user_id
        };
        let wrong = wrong_code();
        for _ in 0..2 {
            let resp = mfa_verify_setup(
                State(Arc::clone(&state)),
                session_request("/", user_id, "alice", &wrong),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
        let resp = mfa_verify_setup(
            State(Arc::clone(&state)),
            session_request("/", user_id, "alice", &current_code()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers()[header::RETRY_AFTER], "60");
        assert!(!mfa_enabled(&state, user_id));
        assert_eq!(test_support::audit_count(&state, "mfa_enable"), 0);
    }

    /// A secret that cannot be decrypted cannot be verified against, so the
    /// enrolment is refused rather than enabled.
    #[tokio::test]
    async fn verify_setup_with_an_unreadable_secret_does_not_enable_mfa() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = {
            let conn = state.db_pool.get().unwrap();
            let user_id = users::tests::insert_user(&conn, "alice", "viewer", true);
            let old_key = data_encoding::BASE64.encode(&[0x44; 32]);
            let stored = fernet_enc::encrypt_totp_secret(SECRET, &old_key, true).unwrap();
            conn.execute(
                "UPDATE users SET totp_secret = ?1 WHERE id = ?2",
                rusqlite::params![stored, user_id],
            )
            .unwrap();
            user_id
        };
        let resp = mfa_verify_setup(
            State(Arc::clone(&state)),
            session_request("/", user_id, "alice", &current_code()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(!mfa_enabled(&state, user_id));
        assert_eq!(test_support::audit_count(&state, "mfa_enable"), 0);
    }

    /// A failed enable is reported as a failure, not as an enabled factor.
    #[tokio::test]
    async fn verify_setup_enable_failure_is_not_reported_as_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = {
            let conn = state.db_pool.get().unwrap();
            let user_id = users::tests::insert_user(&conn, "alice", "viewer", true);
            mfa::set_totp_secret(&conn, user_id, SECRET, "", false).unwrap();
            conn.execute_batch(
                "CREATE TRIGGER reject_enable BEFORE UPDATE OF mfa_enabled ON users \
                 BEGIN SELECT RAISE(ABORT, 'fixture enable failure'); END",
            )
            .unwrap();
            user_id
        };
        let resp = mfa_verify_setup(
            State(Arc::clone(&state)),
            session_request("/", user_id, "alice", &current_code()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!mfa_enabled(&state, user_id));
        assert_eq!(test_support::audit_count(&state, "mfa_enable"), 0);
    }

    /// When the attempt limiter or the replay cache cannot be written, every
    /// second-factor check fails closed: no session, MFA stays on, the
    /// recovery codes stay as they were.
    #[tokio::test]
    async fn second_factor_store_failures_fail_closed() {
        for broken in ["attempts-schema", "attempts-insert", "replay"] {
            let dir = tempfile::tempdir().unwrap();
            let state = test_support::app_state(&dir);
            let user_id = mfa_user(&state, "alice");
            mfa::store_backup_codes(
                &mut state.db_pool.get().unwrap(),
                user_id,
                &[("stored-hash".into(), vec![1; 32])],
            )
            .unwrap();
            let token = new_challenge(&state, user_id, 5);
            state
                .db_pool
                .get()
                .unwrap()
                .execute_batch(match broken {
                    // A view of the same name: the limiter's CREATE TABLE IF
                    // NOT EXISTS is a no-op and its CREATE INDEX on the view
                    // fails, before any reservation is attempted.
                    "attempts-schema" => "CREATE VIEW mfa_attempts AS SELECT 1 AS user_id",
                    // The real table, whose reservation insert fails.
                    "attempts-insert" => {
                        "CREATE TABLE mfa_attempts (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER NOT NULL,
                            attempt_at REAL NOT NULL,
                            tenant_id TEXT NOT NULL DEFAULT 'default'
                        );
                        CREATE TRIGGER reject_attempt BEFORE INSERT ON mfa_attempts
                        BEGIN SELECT RAISE(ABORT, 'fixture attempt failure'); END"
                    }
                    _ => "DROP TABLE totp_replay_cache",
                })
                .unwrap();
            let code = current_code();

            let login =
                mfa_verify_login(State(Arc::clone(&state)), verify_request(&token, &code)).await;
            let disable = mfa_disable(
                State(Arc::clone(&state)),
                session_request("/", user_id, "alice", &code),
            )
            .await;
            let regenerate = mfa_regenerate_backup_codes(
                State(Arc::clone(&state)),
                session_request("/", user_id, "alice", &code),
            )
            .await;
            for (name, resp) in [
                ("login", login),
                ("disable", disable),
                ("regenerate", regenerate),
            ] {
                assert_eq!(
                    resp.status(),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "{broken}: {name}"
                );
                assert!(set_cookies(&resp).is_empty(), "{broken}: {name}");
            }
            assert_eq!(
                count(&state, "SELECT COUNT(*) FROM sessions"),
                0,
                "{broken}"
            );
            assert!(mfa_enabled(&state, user_id), "{broken}");
            assert_eq!(
                count(
                    &state,
                    "SELECT COUNT(*) FROM mfa_backup_codes WHERE code_hash = 'stored-hash'"
                ),
                1,
                "{broken}"
            );
        }
    }

    /// An admin disabling a user's MFA removes the whole factor; a user the
    /// instance does not know (including one of another tenant) is 404 and
    /// left untouched.
    #[tokio::test]
    async fn admin_disable_clears_the_factor_of_local_users_only() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let alice = mfa_user(&state, "alice");
        let foreign = mfa_user(&state, "foreign");
        {
            let mut conn = state.db_pool.get().unwrap();
            mfa::store_backup_codes(&mut conn, alice, &[("h".into(), vec![1; 32])]).unwrap();
            conn.execute("UPDATE users SET tenant_id='other' WHERE id=?1", [foreign])
                .unwrap();
        }

        let resp = admin_disable(&state, "alice", Role::Admin).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            json_body(resp).await,
            serde_json::json!({"status": "mfa_disabled", "username": "alice"})
        );
        assert!(!mfa_enabled(&state, alice));
        let conn = state.db_pool.get().unwrap();
        assert_eq!(mfa::get_totp_secret(&conn, alice, "").unwrap(), None);
        assert_eq!(mfa::get_backup_code_count(&conn, alice).unwrap(), 0);
        drop(conn);
        assert_eq!(test_support::audit_count(&state, "admin_disable_mfa"), 1);

        for username in ["nobody", "foreign"] {
            let resp = admin_disable(&state, username, Role::Keymaster).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{username}");
        }
        assert!(mfa_enabled(&state, foreign));
        assert_eq!(test_support::audit_count(&state, "admin_disable_mfa"), 1);
    }

    /// The role ceiling covers unknown stored roles (treated as KEYMASTER),
    /// and a non-admin API key cannot use the admin endpoint at all.
    #[tokio::test]
    async fn admin_disable_respects_the_role_ceiling_for_unknown_roles_and_keys() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "odd");
        state
            .db_pool
            .get()
            .unwrap()
            .execute("UPDATE users SET role='superuser' WHERE id=?1", [user_id])
            .unwrap();

        let analyst = admin_disable(&state, "odd", Role::Analyst).await;
        assert_eq!(analyst.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_body(analyst).await["detail"], "Admin role required");
        let admin = admin_disable(&state, "odd", Role::Admin).await;
        assert_eq!(admin.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(admin).await["detail"],
            "Cannot modify a user with a role above your own"
        );
        assert!(mfa_enabled(&state, user_id));
        assert_eq!(test_support::audit_count(&state, "admin_disable_mfa"), 0);

        let keymaster = admin_disable(&state, "odd", Role::Keymaster).await;
        assert_eq!(keymaster.status(), StatusCode::OK);
        assert!(!mfa_enabled(&state, user_id));
    }

    /// End to end impact of the TOTP empty-key fallback: a stored secret
    /// that is not base32 (legacy plaintext) must not let a code computed
    /// without any secret complete the login.
    #[tokio::test]
    async fn an_undecodable_stored_secret_cannot_be_satisfied_without_the_secret() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = {
            let conn = state.db_pool.get().unwrap();
            let user_id = users::tests::insert_user(&conn, "alice", "viewer", true);
            conn.execute(
                "UPDATE users SET totp_secret = 'not-a-base32-secret!', mfa_enabled = 1 \
                 WHERE id = ?1",
                [user_id],
            )
            .unwrap();
            user_id
        };
        let token = new_challenge(&state, user_id, 5);
        let no_secret_code = totp::tests::empty_key_hotp(current_step(), 6);
        let resp = mfa_verify_login(
            State(Arc::clone(&state)),
            verify_request(&token, &no_secret_code),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM sessions"), 0);
    }

    /// A user `username` whose stored (dev-mode `b64:`) TOTP secret is
    /// `secret` verbatim, as the TOTP check will see it.
    fn user_with_secret(state: &AppState, username: &str, secret: &str) -> i64 {
        let conn = state.db_pool.get().unwrap();
        let user_id = users::tests::insert_user(&conn, username, "viewer", true);
        mfa::set_totp_secret(&conn, user_id, secret, "", false).unwrap();
        assert_eq!(
            mfa::get_totp_secret(&conn, user_id, "").unwrap().as_deref(),
            Some(secret),
            "fixture: the secret reaches the TOTP check"
        );
        user_id
    }

    /// No second-factor check accepts the empty-key code for a stored secret
    /// that is not a usable key (not Base32, empty, all-zero key): login,
    /// disable, backup regeneration and verify-setup all answer 401 and
    /// change nothing.
    #[tokio::test]
    async fn unusable_stored_secrets_verify_no_totp_code_on_any_endpoint() {
        let all_zero = "A".repeat(32);
        for secret in [
            "not-a-base32-secret!",
            "JBSWY3DP EHPK3PXP",
            "",
            all_zero.as_str(),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let state = test_support::app_state(&dir);
            let alice = user_with_secret(&state, "alice", secret);
            mfa::enable_mfa(&state.db_pool.get().unwrap(), alice).unwrap();
            let bob = user_with_secret(&state, "bob", secret);
            let no_secret_code = totp::tests::empty_key_hotp(current_step(), 6);

            let token = new_challenge(&state, alice, 5);
            let login = mfa_verify_login(
                State(Arc::clone(&state)),
                verify_request(&token, &no_secret_code),
            )
            .await;
            assert_eq!(login.status(), StatusCode::UNAUTHORIZED, "{secret:?}");
            assert_eq!(
                json_body(login).await["detail"],
                "Invalid TOTP code or backup code"
            );

            let disable = mfa_disable(
                State(Arc::clone(&state)),
                session_request("/", alice, "alice", &no_secret_code),
            )
            .await;
            assert_eq!(disable.status(), StatusCode::UNAUTHORIZED, "{secret:?}");

            let regenerate = mfa_regenerate_backup_codes(
                State(Arc::clone(&state)),
                session_request("/", alice, "alice", &no_secret_code),
            )
            .await;
            assert_eq!(regenerate.status(), StatusCode::UNAUTHORIZED, "{secret:?}");
            assert_eq!(json_body(regenerate).await["detail"], "Invalid TOTP code");

            let setup = mfa_verify_setup(
                State(Arc::clone(&state)),
                session_request("/", bob, "bob", &no_secret_code),
            )
            .await;
            assert_eq!(setup.status(), StatusCode::UNAUTHORIZED, "{secret:?}");
            assert_eq!(json_body(setup).await["detail"], "Invalid TOTP code");

            assert_eq!(count(&state, "SELECT COUNT(*) FROM sessions"), 0);
            assert_eq!(count(&state, "SELECT COUNT(*) FROM totp_replay_cache"), 0);
            assert!(mfa_enabled(&state, alice), "MFA stays on");
            assert!(!mfa_enabled(&state, bob), "enrolment stays pending");
            assert_eq!(
                count(&state, "SELECT COUNT(*) FROM mfa_backup_codes"),
                0,
                "no recovery codes minted"
            );
            for action in [
                "user_login_mfa",
                "mfa_disable",
                "mfa_regenerate_backup_codes",
                "mfa_enable",
            ] {
                assert_eq!(test_support::audit_count(&state, action), 0, "{action}");
            }
        }
    }

    /// What this thread logs (INFO and above) while it is alive. A
    /// `#[tokio::test]` runs the handlers and the tasks they spawn on this
    /// thread (not the blocking pool's work). No timestamps: their digits
    /// could look like a logged code.
    struct Logs {
        buffer: Arc<std::sync::Mutex<Vec<u8>>>,
        _guard: tracing::subscriber::DefaultGuard,
    }

    impl Logs {
        fn capture() -> Self {
            #[derive(Clone)]
            struct Buffer(Arc<std::sync::Mutex<Vec<u8>>>);
            impl std::io::Write for Buffer {
                fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                    self.0.lock().unwrap().extend_from_slice(bytes);
                    Ok(bytes.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            let buffer = Arc::new(std::sync::Mutex::new(Vec::new()));
            let writer = Buffer(Arc::clone(&buffer));
            let subscriber = tracing_subscriber::fmt()
                .with_writer(move || writer.clone())
                .with_ansi(false)
                .without_time()
                .with_max_level(tracing::Level::INFO)
                .finish();
            crate::test_support::keep_log_capture_reliable();
            Self {
                buffer,
                _guard: tracing::subscriber::set_default(subscriber),
            }
        }

        /// The lines logged since the last call.
        fn take(&self) -> String {
            String::from_utf8(std::mem::take(&mut *self.buffer.lock().unwrap())).unwrap()
        }
    }

    /// Why a stored secret verifies no code is logged once per check, as a
    /// warning naming the user and the reason, never the secret or the
    /// submitted code: by login, disable and backup regeneration (through
    /// `check_totp`) and by verify-setup.
    #[tokio::test]
    async fn an_unusable_stored_secret_is_logged_on_every_endpoint_without_the_secret() {
        let all_zero = "A".repeat(32);
        for (secret, reason) in [
            ("not-a-base32-secret!", "TOTP secret is not valid Base32"),
            (
                all_zero.as_str(),
                "TOTP secret decodes to an empty or all-zero key",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let state = test_support::app_state(&dir);
            let alice = user_with_secret(&state, "alice", secret);
            mfa::enable_mfa(&state.db_pool.get().unwrap(), alice).unwrap();
            let bob = user_with_secret(&state, "bob", secret);
            let code = totp::tests::empty_key_hotp(current_step(), 6);
            let logs = Logs::capture();
            let assert_logged = |endpoint: &str, username: &str| {
                let text = logs.take();
                let warnings: Vec<&str> = text
                    .lines()
                    .filter(|line| line.contains("Stored TOTP secret is unusable"))
                    .collect();
                assert_eq!(warnings.len(), 1, "{endpoint}, {secret:?}: {text}");
                let warning = warnings[0];
                assert!(warning.contains("WARN"), "{endpoint}: {warning}");
                assert!(warning.contains(reason), "{endpoint}: {warning}");
                assert!(
                    warning.contains(&format!("username=\"{username}\"")),
                    "{endpoint}: {warning}"
                );
                assert!(!text.contains(secret), "{endpoint} logged the secret");
                assert!(!text.contains(&code), "{endpoint} logged the code");
            };

            let token = new_challenge(&state, alice, 5);
            let login =
                mfa_verify_login(State(Arc::clone(&state)), verify_request(&token, &code)).await;
            assert_eq!(login.status(), StatusCode::UNAUTHORIZED);
            assert_logged("login", "alice");

            let disable = mfa_disable(
                State(Arc::clone(&state)),
                session_request("/", alice, "alice", &code),
            )
            .await;
            assert_eq!(disable.status(), StatusCode::UNAUTHORIZED);
            assert_logged("disable", "alice");

            let regenerate = mfa_regenerate_backup_codes(
                State(Arc::clone(&state)),
                session_request("/", alice, "alice", &code),
            )
            .await;
            assert_eq!(regenerate.status(), StatusCode::UNAUTHORIZED);
            assert_logged("regenerate-backup-codes", "alice");

            let setup = mfa_verify_setup(
                State(Arc::clone(&state)),
                session_request("/", bob, "bob", &code),
            )
            .await;
            assert_eq!(setup.status(), StatusCode::UNAUTHORIZED);
            assert_logged("verify-setup", "bob");
        }
    }

    /// With an unusable stored secret a backup code still completes the
    /// login, as it does when the secret cannot be decrypted.
    #[tokio::test]
    async fn mfa_login_falls_back_to_backup_code_when_secret_is_unusable() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = user_with_secret(&state, "alice", "not-a-base32-secret!");
        {
            let mut conn = state.db_pool.get().unwrap();
            mfa::enable_mfa(&conn, user_id).unwrap();
            let code_hash = password::hash_credential("abcd1234", None);
            mfa::store_backup_codes(&mut conn, user_id, &[code_hash]).unwrap();
        }
        let token = new_challenge(&state, user_id, 5);
        let resp = mfa_verify_login(
            State(Arc::clone(&state)),
            verify_request(&token, "abcd1234"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "backup code completes login");
        assert_eq!(test_support::audit_count(&state, "user_login_mfa"), 1);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM totp_replay_cache"), 0);
    }

    // ── Security paths: the verification window and enrolment input ──

    /// A user with a stored TOTP secret ([`SECRET`]) whose MFA is not on.
    fn enrolling_user(state: &AppState, username: &str) -> i64 {
        let conn = state.db_pool.get().unwrap();
        let user_id = users::tests::insert_user(&conn, username, "viewer", true);
        mfa::set_totp_secret(&conn, user_id, SECRET, "", false).unwrap();
        user_id
    }

    fn current_step() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 30
    }

    /// A code of [`SECRET`] from three or more steps ago that is not also
    /// the code of a step valid now or after crossing into the next step
    /// (T-1 ..= T+2), so it is outside the window however the test is timed.
    fn stale_code() -> String {
        let step = current_step();
        let valid: std::collections::HashSet<String> = (step - 1..=step + 2)
            .map(|counter| totp::compute_hotp(SECRET, counter, 6).unwrap())
            .collect();
        (3..=9)
            .map(|back| totp::compute_hotp(SECRET, step - back, 6).unwrap())
            .find(|code| !valid.contains(code))
            .unwrap()
    }

    /// Every second-factor check verifies with a one-step window: a code
    /// three steps (90 s) old is refused by login, disable, backup-code
    /// regeneration and verify-setup alike, and none of them changes state.
    #[tokio::test]
    async fn every_second_factor_check_refuses_a_code_older_than_one_step() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "alice");
        let enrolling = enrolling_user(&state, "bob");
        let stale = stale_code();

        let token = new_challenge(&state, user_id, 5);
        let login =
            mfa_verify_login(State(Arc::clone(&state)), verify_request(&token, &stale)).await;
        assert_eq!(login.status(), StatusCode::UNAUTHORIZED);
        assert!(set_cookies(&login).is_empty());
        assert_eq!(
            json_body(login).await["detail"],
            "Invalid TOTP code or backup code"
        );

        let disable = mfa_disable(
            State(Arc::clone(&state)),
            session_request("/api/auth/mfa/disable", user_id, "alice", &stale),
        )
        .await;
        assert_eq!(disable.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            json_body(disable).await["detail"],
            "Valid TOTP or backup code required"
        );

        let regenerate = mfa_regenerate_backup_codes(
            State(Arc::clone(&state)),
            session_request("/", user_id, "alice", &stale),
        )
        .await;
        assert_eq!(regenerate.status(), StatusCode::UNAUTHORIZED);
        let body = json_body(regenerate).await;
        assert_eq!(body["detail"], "Invalid TOTP code");
        assert!(body.get("backup_codes").is_none());

        let setup = mfa_verify_setup(
            State(Arc::clone(&state)),
            session_request("/", enrolling, "bob", &stale),
        )
        .await;
        assert_eq!(setup.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(setup).await["detail"], "Invalid TOTP code");

        assert_eq!(count(&state, "SELECT COUNT(*) FROM sessions"), 0);
        assert!(mfa_enabled(&state, user_id), "MFA stays on");
        assert_eq!(
            mfa::get_totp_secret(&state.db_pool.get().unwrap(), user_id, "")
                .unwrap()
                .as_deref(),
            Some(SECRET)
        );
        assert_eq!(
            count(&state, "SELECT COUNT(*) FROM mfa_backup_codes"),
            0,
            "no recovery codes minted"
        );
        assert!(!mfa_enabled(&state, enrolling), "enrolment stays pending");
        assert_eq!(count(&state, "SELECT COUNT(*) FROM totp_replay_cache"), 0);
        for action in [
            "user_login_mfa",
            "mfa_disable",
            "mfa_regenerate_backup_codes",
            "mfa_enable",
        ] {
            assert_eq!(test_support::audit_count(&state, action), 0, "{action}");
        }
    }

    /// Verify-setup has no 6-digit guard of its own (login, disable and
    /// regeneration go through `check_totp`'s): enrolment must still refuse
    /// an empty, truncated or extended form of the valid code, and the
    /// 8-digit code it is the suffix of.
    #[tokio::test]
    async fn verify_setup_refuses_malformed_forms_of_the_valid_code() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = enrolling_user(&state, "alice");
        let step = current_step();
        let code = totp::compute_hotp(SECRET, step, 6).unwrap();
        let eight = totp::compute_hotp(SECRET, step, 8).unwrap();
        assert!(eight.ends_with(&code));

        for bad in [
            String::new(),
            code[..5].to_string(),
            format!("{code}0"),
            format!("0{code}"),
            eight,
        ] {
            let resp = mfa_verify_setup(
                State(Arc::clone(&state)),
                session_request("/", user_id, "alice", &bad),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{bad:?}");
        }
        assert!(!mfa_enabled(&state, user_id));
        assert_eq!(test_support::audit_count(&state, "mfa_enable"), 0);

        // The fixture is sound: the code itself does enable MFA.
        let ok = mfa_verify_setup(
            State(Arc::clone(&state)),
            session_request("/", user_id, "alice", &current_code()),
        )
        .await;
        assert_eq!(ok.status(), StatusCode::OK);
        assert!(mfa_enabled(&state, user_id));
    }

    /// Enrolment must not reset an enabled factor. When the user row cannot
    /// be read (here: a display_name stored as a blob), the "already
    /// enabled" check cannot be made, so setup must fail closed and leave
    /// the enrolled secret and recovery codes in place instead of replacing
    /// them with a secret the caller now knows.
    #[tokio::test]
    async fn setup_fails_closed_when_the_enabled_check_cannot_be_made() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "alice");
        {
            let mut conn = state.db_pool.get().unwrap();
            mfa::store_backup_codes(&mut conn, user_id, &[("stored-hash".into(), vec![1; 32])])
                .unwrap();
            conn.execute(
                "UPDATE users SET display_name = X'00' WHERE id = ?1",
                [user_id],
            )
            .unwrap();
            assert!(mfa::get_user_by_id(&conn, user_id).is_err(), "lookup fails");
        }

        let resp = mfa_setup(
            State(Arc::clone(&state)),
            session_request("/", user_id, "alice", ""),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let conn = state.db_pool.get().unwrap();
        assert_eq!(
            mfa::get_totp_secret(&conn, user_id, "").unwrap().as_deref(),
            Some(SECRET)
        );
        assert_eq!(
            count(
                &state,
                "SELECT COUNT(*) FROM mfa_backup_codes WHERE code_hash = 'stored-hash'"
            ),
            1
        );
        assert_eq!(count(&state, "SELECT COUNT(*) FROM mfa_backup_codes"), 1);
    }

    /// Setup writes nothing unless the "already enabled" check was made:
    /// not for a session whose user no longer exists (404, as on the
    /// bridge) and not when another column of an enabled user's row cannot
    /// be read (500); neither reports a secret or counts as an MFA attempt.
    #[tokio::test]
    async fn setup_writes_nothing_for_a_missing_or_unreadable_user() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        mfa::ensure_mfa_attempts_table(&state.db_pool.get().unwrap()).unwrap();
        let missing = mfa_setup(
            State(Arc::clone(&state)),
            session_request("/", 4242, "ghost", ""),
        )
        .await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            json_body(missing).await,
            serde_json::json!({"detail": "User not found"})
        );
        assert_eq!(count(&state, "SELECT COUNT(*) FROM mfa_backup_codes"), 0);

        let user_id = mfa_user(&state, "alice");
        {
            let mut conn = state.db_pool.get().unwrap();
            mfa::store_backup_codes(&mut conn, user_id, &[("stored-hash".into(), vec![1; 32])])
                .unwrap();
            conn.execute("UPDATE users SET enabled = 'yes' WHERE id = ?1", [user_id])
                .unwrap();
            assert!(mfa::get_user_by_id(&conn, user_id).is_err(), "lookup fails");
        }
        let unreadable = mfa_setup(
            State(Arc::clone(&state)),
            session_request("/", user_id, "alice", ""),
        )
        .await;
        assert_eq!(unreadable.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(unreadable.into_body(), 1 << 20)
            .await
            .unwrap();
        assert!(body.is_empty(), "no secret or backup codes reported");

        let conn = state.db_pool.get().unwrap();
        assert_eq!(
            mfa::get_totp_secret(&conn, user_id, "").unwrap().as_deref(),
            Some(SECRET)
        );
        assert_eq!(
            count(
                &state,
                "SELECT COUNT(*) FROM mfa_backup_codes WHERE code_hash = 'stored-hash'"
            ),
            1
        );
        assert_eq!(count(&state, "SELECT COUNT(*) FROM mfa_backup_codes"), 1);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM mfa_attempts"), 0);
    }

    /// Setup checks that MFA is off, then hashes its backup codes (seconds
    /// on a Pi) before writing. MFA enabled meanwhile, by verify-setup in
    /// another tab, keeps the secret and recovery codes it was enabled
    /// with, and setup answers 409 without reporting a secret; a user
    /// deleted meanwhile gets 404 and no backup codes. Either way the
    /// enrolment is not written.
    #[tokio::test]
    async fn setup_keeps_a_factor_enabled_while_it_hashed_its_codes() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let alice = enrolling_user(&state, "alice");
        let ghost = enrolling_user(&state, "ghost");
        mfa::store_backup_codes(
            &mut state.db_pool.get().unwrap(),
            alice,
            &[("enrolled-hash".into(), vec![1; 32])],
        )
        .unwrap();
        let logs = Logs::capture();
        let spawn_setup = |user_id, username: &str| {
            tokio::spawn(mfa_setup(
                State(Arc::clone(&state)),
                session_request("/", user_id, username, ""),
            ))
        };
        let alice_setup = spawn_setup(alice, "alice");
        let ghost_setup = spawn_setup(ghost, "ghost");
        // On this single-threaded runtime one yield runs both tasks to
        // their first await: past the check, hashing on the blocking pool.
        tokio::task::yield_now().await;
        assert!(!alice_setup.is_finished() && !ghost_setup.is_finished());

        let verified = mfa_verify_setup(
            State(Arc::clone(&state)),
            session_request("/", alice, "alice", &current_code()),
        )
        .await;
        assert_eq!(verified.status(), StatusCode::OK);
        state
            .db_pool
            .get()
            .unwrap()
            .execute("DELETE FROM users WHERE id = ?1", [ghost])
            .unwrap();

        let refused = alice_setup.await.unwrap();
        assert_eq!(refused.status(), StatusCode::CONFLICT);
        assert_eq!(
            json_body(refused).await,
            serde_json::json!({"detail": "MFA is already enabled"})
        );
        let gone = ghost_setup.await.unwrap();
        assert_eq!(gone.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            json_body(gone).await,
            serde_json::json!({"detail": "User not found"})
        );
        let text = logs.take();
        assert_eq!(
            text.matches("MFA was enabled while setup ran").count(),
            1,
            "the write, not the first check, refused: {text}"
        );

        assert!(mfa_enabled(&state, alice));
        assert_eq!(
            mfa::get_totp_secret(&state.db_pool.get().unwrap(), alice, "")
                .unwrap()
                .as_deref(),
            Some(SECRET),
            "the enrolled secret stays"
        );
        assert_eq!(
            count(
                &state,
                "SELECT COUNT(*) FROM mfa_backup_codes WHERE code_hash = 'enrolled-hash'"
            ),
            1
        );
        assert_eq!(count(&state, "SELECT COUNT(*) FROM mfa_backup_codes"), 1);
    }

    /// An enrolment whose backup codes cannot be stored is refused with
    /// 500 and reports no secret or codes, and its secret is not stored
    /// without them: the pending secret and codes stay as they were.
    #[tokio::test]
    async fn setup_whose_backup_codes_cannot_be_stored_stores_and_reports_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = enrolling_user(&state, "alice");
        {
            let mut conn = state.db_pool.get().unwrap();
            mfa::store_backup_codes(&mut conn, user_id, &[("pending-hash".into(), vec![1; 32])])
                .unwrap();
            conn.execute_batch(
                "CREATE TRIGGER no_codes BEFORE INSERT ON mfa_backup_codes \
                 BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
            )
            .unwrap();
        }

        let resp = mfa_setup(
            State(Arc::clone(&state)),
            session_request("/", user_id, "alice", ""),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        assert!(body.is_empty(), "no secret or backup codes reported");
        assert!(!mfa_enabled(&state, user_id));
        assert_eq!(
            mfa::get_totp_secret(&state.db_pool.get().unwrap(), user_id, "")
                .unwrap()
                .as_deref(),
            Some(SECRET),
            "the pending secret stays"
        );
        assert_eq!(
            count(
                &state,
                "SELECT COUNT(*) FROM mfa_backup_codes WHERE code_hash = 'pending-hash'"
            ),
            1
        );
        assert_eq!(count(&state, "SELECT COUNT(*) FROM mfa_backup_codes"), 1);
    }

    /// The second login step fails closed when its user cannot be read (a
    /// storage error, here a stored value of the wrong type): 500, no
    /// session, cookie or success audit, and the challenge stays spent, so
    /// the code cannot be tried on it again.
    #[tokio::test]
    async fn mfa_login_whose_user_cannot_be_read_gets_no_session() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "alice");
        let token = new_challenge(&state, user_id, 5);
        let enabled = |value: &str| {
            state
                .db_pool
                .get()
                .unwrap()
                .execute(
                    "UPDATE users SET enabled = ?1 WHERE id = ?2",
                    rusqlite::params![value, user_id],
                )
                .unwrap();
        };
        enabled("yes");
        assert!(mfa::get_user_by_id(&state.db_pool.get().unwrap(), user_id).is_err());

        let code = current_code();
        let resp = mfa_verify_login(State(Arc::clone(&state)), verify_request(&token, &code)).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(set_cookies(&resp).is_empty());
        assert_eq!(count(&state, "SELECT COUNT(*) FROM sessions"), 0);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM mfa_tokens"), 0);
        assert_eq!(test_support::audit_count(&state, "user_login_mfa"), 0);

        enabled("1");
        let retry =
            mfa_verify_login(State(Arc::clone(&state)), verify_request(&token, &code)).await;
        assert_eq!(retry.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(count(&state, "SELECT COUNT(*) FROM sessions"), 0);
    }
}

#[cfg(test)]
mod coverage_tests {
    //! Fail-closed and best-effort paths of the MFA endpoints that the main
    //! suite leaves untaken.

    use super::tests::{current_code, mfa_user, SECRET};
    use super::*;
    use crate::db::pool::DbPool;
    use crate::storage::users;
    use crate::test_support;
    use std::time::Duration;

    fn sql(state: &AppState, statements: &str) {
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch(statements)
            .unwrap();
    }

    fn count(pool: &DbPool, query: &str) -> i64 {
        pool.get()
            .unwrap()
            .query_row(query, [], |row| row.get(0))
            .unwrap()
    }

    fn mfa_enabled(pool: &DbPool, user_id: i64) -> bool {
        pool.get()
            .unwrap()
            .query_row(
                "SELECT mfa_enabled FROM users WHERE id = ?1",
                [user_id],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn json_request(path: &str, body: serde_json::Value) -> Request<Body> {
        Request::post(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    /// `req` from `alice`'s full session.
    fn as_alice(mut req: Request<Body>, user_id: i64) -> Request<Body> {
        req.extensions_mut().insert(AuthInfo::Session {
            username: "alice".into(),
            user_id,
            role: Role::Viewer,
            session_token: "irrelevant".into(),
            expires_at: String::new(),
            tenant_id: "default".into(),
            scope: String::new(),
        });
        req
    }

    /// `req` from an admin API key.
    fn as_admin(mut req: Request<Body>) -> Request<Body> {
        req.extensions_mut().insert(AuthInfo::ApiKey {
            key_id: "admin-key".into(),
            role: Role::Admin,
        });
        req
    }

    async fn admin_disable_alice(state: &Arc<AppState>) -> Response {
        let req = as_admin(Request::post("/").body(Body::empty()).unwrap());
        admin_disable_user_mfa(
            State(Arc::clone(state)),
            axum::extract::Path("alice".to_string()),
            req,
        )
        .await
    }

    /// `state` with a pool that can open no connection (a database file
    /// that cannot be opened), and the pool it had, to inspect the database
    /// with. Every `db_pool.get()` fails: the 50 ms timeout only bounds the
    /// wait, as no connection can ever be established.
    fn without_database(state: Arc<AppState>) -> (Arc<AppState>, DbPool) {
        let mut state = Arc::into_inner(state).expect("a fresh state has one owner");
        let refusing = crate::db::manager::SqliteConnectionManager::file(&state.config.db_path)
            .with_init(|_| Err(rusqlite::Error::InvalidQuery));
        let unavailable = r2d2::Pool::builder()
            .max_size(1)
            .connection_timeout(Duration::from_millis(50))
            .build_unchecked(refusing);
        let database = std::mem::replace(&mut state.db_pool, unavailable);
        (Arc::new(state), database)
    }

    /// Without a database connection every MFA endpoint answers 503 before
    /// it checks or changes anything: MFA stays on, the pending login's
    /// challenge is not claimed, no attempt is counted, no code is spent
    /// and no tenant policy is written.
    #[tokio::test]
    async fn mfa_endpoints_answer_503_when_the_database_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "alice");
        let challenge =
            mfa::create_mfa_token_unchecked(&state.db_pool.get().unwrap(), user_id, 5).unwrap();
        let (state, database) = without_database(state);
        let unavailable = StatusCode::SERVICE_UNAVAILABLE;
        let code = serde_json::json!({"totp_code": current_code()});
        let st = || State(Arc::clone(&state));

        let req = as_alice(json_request("/api/auth/mfa/setup", code.clone()), user_id);
        assert_eq!(mfa_setup(st(), req).await.status(), unavailable, "setup");
        let req = as_alice(
            json_request("/api/auth/mfa/verify-setup", code.clone()),
            user_id,
        );
        assert_eq!(mfa_verify_setup(st(), req).await.status(), unavailable);
        let req = json_request(
            "/api/auth/mfa/verify",
            serde_json::json!({"mfa_token": challenge, "totp_code": current_code()}),
        );
        assert_eq!(mfa_verify_login(st(), req).await.status(), unavailable);
        let req = as_alice(json_request("/api/auth/mfa/disable", code.clone()), user_id);
        assert_eq!(mfa_disable(st(), req).await.status(), unavailable);
        let req = as_alice(json_request("/api/auth/mfa/regenerate", code), user_id);
        let resp = mfa_regenerate_backup_codes(st(), req).await;
        assert_eq!(resp.status(), unavailable, "regenerate");
        let req = as_admin(json_request(
            "/api/admin/mfa",
            serde_json::json!({"mfa_required": true}),
        ));
        assert_eq!(set_tenant_mfa(st(), req).await.status(), unavailable);
        let req = as_admin(Request::get("/api/admin/mfa").body(Body::empty()).unwrap());
        assert_eq!(get_tenant_mfa(st(), req).await.status(), unavailable);
        assert_eq!(admin_disable_alice(&state).await.status(), unavailable);

        assert!(mfa_enabled(&database, user_id));
        assert_eq!(count(&database, "SELECT COUNT(*) FROM mfa_tokens"), 1);
        assert_eq!(
            count(&database, "SELECT COUNT(*) FROM totp_replay_cache"),
            0
        );
        assert_eq!(
            count(
                &database,
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE name IN ('mfa_attempts', 'tenant_settings')"
            ),
            0,
            "no attempt reserved, no policy written"
        );
    }

    async fn assert_admin_disable_with_audit_records(state: &Arc<AppState>, records: i64) {
        let user_id = mfa_user(state, "alice");
        assert_eq!(admin_disable_alice(state).await.status(), StatusCode::OK);
        assert!(!mfa_enabled(&state.db_pool, user_id), "MFA is off");
        assert_eq!(
            test_support::audit_count(state, "admin_disable_mfa"),
            records
        );
    }

    /// Audit logging is best effort: an admin's MFA disable whose record
    /// cannot be signed (production without an audit key) or cannot be
    /// written still turns the user's MFA off.
    #[tokio::test]
    async fn an_admin_mfa_disable_applies_when_its_audit_record_cannot_be_kept() {
        // Without a configured key, production signs with a legacy
        // fallback from the environment if one is set (CI sets none).
        let signed_without_key = i64::from(audit_chain::get_audit_secret("", "production").is_ok());
        let dir = tempfile::tempdir().unwrap();
        let mut unsigned =
            Arc::into_inner(test_support::app_state(&dir)).expect("a fresh state has one owner");
        unsigned.config.bridge_env = "production".into();
        unsigned.config.audit_key = String::new();
        assert_admin_disable_with_audit_records(&Arc::new(unsigned), signed_without_key).await;

        let dir = tempfile::tempdir().unwrap();
        let unwritable = test_support::app_state(&dir);
        sql(
            &unwritable,
            "CREATE TRIGGER no_audit BEFORE INSERT ON audit_log \
             BEGIN SELECT RAISE(ABORT, 'audit log unavailable'); END;",
        );
        assert_admin_disable_with_audit_records(&unwritable, 0).await;
    }

    /// An admin's MFA disable for an account whose row cannot be read
    /// fails with 500: MFA stays on and nothing is audited.
    #[tokio::test]
    async fn an_admin_mfa_disable_fails_closed_when_the_account_cannot_be_read() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = mfa_user(&state, "alice");
        // A display name stored as a blob: no account row reads.
        sql(
            &state,
            &format!("UPDATE users SET display_name = X'00ff' WHERE id = {user_id}"),
        );

        let resp = admin_disable_alice(&state).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(mfa_enabled(&state.db_pool, user_id), "MFA stays on");
        assert_eq!(test_support::audit_count(&state, "admin_disable_mfa"), 0);
    }

    /// A second factor that verifies still succeeds when its counted
    /// attempts cannot be cleared afterwards, and the attempt stays counted
    /// (the failure errs toward the lockout, never toward more guesses).
    #[tokio::test]
    async fn a_verified_code_whose_attempt_cannot_be_cleared_stays_counted() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = {
            let conn = state.db_pool.get().unwrap();
            let user_id = users::tests::insert_user(&conn, "alice", "viewer", true);
            mfa::set_totp_secret(&conn, user_id, SECRET, "", false).unwrap();
            mfa::ensure_mfa_attempts_table(&conn).unwrap();
            user_id
        };
        // The reservation's sweep of old attempts deletes no row (there is
        // none), so only the clearing after the check hits the trigger.
        sql(
            &state,
            "CREATE TRIGGER keep_mfa_attempts BEFORE DELETE ON mfa_attempts \
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        );

        let req = as_alice(
            json_request(
                "/api/auth/mfa/verify-setup",
                serde_json::json!({"totp_code": current_code()}),
            ),
            user_id,
        );
        let resp = mfa_verify_setup(State(Arc::clone(&state)), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(mfa_enabled(&state.db_pool, user_id));
        assert_eq!(
            count(&state.db_pool, "SELECT COUNT(*) FROM mfa_attempts"),
            1,
            "the attempt stays counted"
        );
        assert_eq!(test_support::audit_count(&state, "mfa_enable"), 1);
    }
}
