//! Auth endpoint handlers.
//!
//! POST /api/auth/login — rate limit, lockout, verify password, create session, set cookies.
//! POST /api/auth/logout — delete session.
//! POST /api/auth/change-password — lockout, verify current, set new, invalidate sessions.
//!
//! [`issue_session`] is the one place a login session is created: the
//! password login here and the MFA login (`mfa_handler`) both end in it, so
//! both bind the session to the client's IP and User-Agent, give it the
//! same restricted scope when one applies, cap the user's sessions, and set
//! the same cookies and CSRF token.

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

use crate::audit::{chain as audit_chain, store as audit_store};
use crate::db::pool::{with_conn_blocking, PooledConn};
use crate::middleware::auth::{SCOPE_MFA_SETUP_ONLY, SCOPE_PASSWORD_CHANGE_ONLY};
use crate::middleware::client_ip::{client_ip_of, TrustedProxies};
use crate::storage::{mfa, password_history, security_state, sessions, users};
use crate::AppState;

/// Best-effort audit logging — never fails the auth operation.
fn audit_event(
    state: &AppState,
    conn: &r2d2::PooledConnection<crate::db::manager::SqliteConnectionManager>,
    action: &str,
    target: &str,
    operator: &str,
    ip: &str,
) {
    if let Ok(secret) =
        audit_chain::get_audit_secret(&state.config.audit_key, &state.config.bridge_env)
    {
        if let Err(e) =
            audit_store::log_auth_event(conn, &secret, action, target, operator, ip, "default")
        {
            tracing::warn!(error = %e, action, "Failed to log audit event");
        }
    }
}

// ── Request/Response types ────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub session_token: String,
    pub expires_at: String,
    pub csrf_token: String,
    pub user: UserInfo,
    pub mfa_required: bool,
    pub mfa_token: String,
    pub mfa_setup_required: bool,
    /// The session is limited to changing the password (K3).
    pub password_change_required: bool,
}

#[derive(Serialize)]
pub struct UserInfo {
    pub username: String,
    pub role: String,
    pub display_name: String,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

// ── Login ─────────────────────────────────────────────────────────────

/// True when `headers` declare the body `application/json`: exactly one
/// `Content-Type` whose media type (the part before any `;` parameter,
/// spaces trimmed) is `application/json` in any letter case.
///
/// The two login steps are CSRF-exempt (a browser has no CSRF token before
/// it signs in), so this is their login-CSRF defence. A cross-site page can
/// post a body without a CORS preflight only as `text/plain`,
/// `application/x-www-form-urlencoded` or `multipart/form-data`; with
/// `application/json` the browser sends a preflight first, which the
/// gateway's CORS layer never grants with credentials. The media type is
/// compared whole, not searched: `text/plain;charset=application/json`
/// is still `text/plain`, and a `no-cors` fetch can send it.
pub(crate) fn declares_json_body(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().is_ok_and(|value| {
            let essence = value.split(';').next().unwrap_or_default();
            essence.trim().eq_ignore_ascii_case("application/json")
        }),
        _ => false,
    }
}

/// The 415 a login step answers to a body not declared JSON
/// ([`declares_json_body`]), before it reads the body or checks anything.
pub(crate) fn json_body_required() -> Response {
    (
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        Json(serde_json::json!({"detail": "Content-Type must be application/json"})),
    )
        .into_response()
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Response {
    // Login CSRF: refused before any limiter records an attempt, so a
    // cross-site form can neither sign a browser in nor use up its budget.
    if !declares_json_body(req.headers()) {
        return json_body_required();
    }
    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    // Read auth config once, clone needed fields, drop lock
    let (trusted_proxies, security_limits, session_config) = {
        let cfg = state.auth_config.read().await;
        (
            cfg.trusted_proxies.clone(),
            cfg.security_limits.clone(),
            cfg.session_config.clone(),
        )
    };

    let client = LoginClient::of(&req, &trusted_proxies);
    let client_ip = client.ip.clone();

    // Parse JSON body
    let body_bytes = match axum::body::to_bytes(req.into_body(), 4096).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let body: LoginRequest = match serde_json::from_slice(&body_bytes) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"detail": "Invalid request body"})),
            )
                .into_response();
        }
    };
    let tenant_id = "default";
    let limits = &security_limits;

    // Both limiters fail closed: if their state cannot be written or read
    // (any storage error, a missing bridge-owned table included) the login
    // is refused before its password is checked — treating it as "no
    // attempts" would lift every rate limit and lockout.

    // IP rate limit, as the bridge's `_check_login_rate`: an IP that already
    // has `rate_limit_max` attempts in the window is refused, else this
    // attempt is recorded. So exactly `rate_limit_max` attempts are allowed
    // per window, and a refused one is not recorded (it would keep a client
    // that keeps trying limited for as long as it tries). The check and the
    // record are one atomic statement, so parallel attempts cannot all get
    // in below the limit.
    match security_state::reserve_login_attempt(
        &conn,
        &client_ip,
        tenant_id,
        limits.rate_limit_max,
        limits.rate_limit_window_secs,
    ) {
        Ok(true) => {}
        Ok(false) => {
            warn!(
                client_ip = client_ip,
                limit = limits.rate_limit_max,
                "Login rate limit exceeded"
            );
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::HeaderName::from_static("retry-after"), "60")],
                Json(serde_json::json!({"detail": "Too many login attempts. Try again later."})),
            )
                .into_response();
        }
        Err(e) => {
            warn!(error = %e, "Login rate limit state unavailable — login refused");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }

    // Account lockout: count this attempt against the account *before* its
    // (slow, off-thread) password check, in one atomic statement with the
    // lockout check (as the bridge's `_reserve_login_attempt` does), so
    // parallel guesses already see it and can never all get past
    // `lockout_max`. It commits here, outside any transaction, so other
    // connections see it while the check runs. Unknown and disabled
    // usernames are counted too (no enumeration oracle). Only a successful
    // check clears it below; a failed, erroring or abandoned check (client
    // disconnect mid-PBKDF2) leaves it counted. A locked account records
    // nothing more.
    match security_state::reserve_account_attempt(
        &conn,
        &body.username,
        tenant_id,
        limits.lockout_max,
        limits.lockout_window_secs,
    ) {
        Ok(true) => {}
        Ok(false) => {
            warn!(
                username = body.username,
                limit = limits.lockout_max,
                "Account locked out"
            );
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::HeaderName::from_static("retry-after"), "1800")],
                Json(serde_json::json!({"detail": "Account temporarily locked due to too many failed attempts."})),
            )
                .into_response();
        }
        Err(e) => {
            warn!(error = %e, "Account lockout state unavailable — login refused");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }

    // Verify password — PBKDF2, so it runs on the blocking pool.
    let (username, password) = (body.username.clone(), body.password.clone());
    let Some((conn, verified)) = with_conn_blocking(conn, move |conn| {
        users::verify_password_credential(conn, &username, &password, tenant_id)
    })
    .await
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    // What follows — the MFA challenge or the session — is created only
    // while this credential is still the stored one: a reset or change
    // committed since the check refuses the login.
    let credential = match verified {
        Ok(Some(credential)) => credential,
        Ok(None) => {
            // The failure was already counted by the reservation above.
            audit_event(
                &state,
                &conn,
                "auth_failure",
                &body.username,
                "",
                &client_ip,
            );
            warn!(
                username = body.username,
                client_ip = client_ip,
                "Login failed: invalid credentials"
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"detail": "Invalid username or password"})),
            )
                .into_response();
        }
        Err(e) => {
            warn!(error = %e, "Password verification error");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Success — clear lockout failures, this attempt's reservation included.
    // On error the rows stay counted (fail closed), so the login goes on.
    if let Err(e) = security_state::clear_account_failures(&conn, &body.username, tenant_id) {
        warn!(error = %e, username = body.username, "Failed to clear account lockout failures");
    }

    // Check if MFA is enabled for this user. Fail closed: a lookup error
    // (SQLITE_BUSY, an unreadable row) or a user deleted since the check
    // must not read as "no MFA" and hand out a session on the password
    // alone.
    let user = match users::get_user_by_username(&conn, &body.username, tenant_id) {
        Ok(Some(user)) => user,
        Ok(None) => {
            warn!(
                username = body.username,
                "Login refused: the account disappeared after its password check"
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"detail": "Invalid username or password"})),
            )
                .into_response();
        }
        Err(e) => {
            warn!(error = %e, username = body.username, "MFA state unavailable — login refused");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let mfa_enabled = user.mfa_enabled;

    if mfa_enabled {
        // MFA required — create temporary MFA token for two-step login
        let mfa_token = match mfa::create_mfa_token(&conn, &credential, 5) {
            Ok(Some(t)) => t,
            Ok(None) => {
                warn!(
                    username = body.username,
                    "Login refused: the password changed after its check"
                );
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"detail": "Invalid username or password"})),
                )
                    .into_response();
            }
            Err(e) => {
                warn!(error = %e, "Failed to create MFA token");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        audit_event(
            &state,
            &conn,
            "user_login_mfa_pending",
            &body.username,
            &body.username,
            &client_ip,
        );
        info!(username = body.username, "Login requires MFA verification");
        return (
            StatusCode::OK,
            Json(LoginResponse {
                session_token: String::new(),
                expires_at: String::new(),
                csrf_token: String::new(),
                user: UserInfo {
                    username: body.username.clone(),
                    role: user.role.clone(),
                    display_name: user.display_name.clone(),
                },
                mfa_required: true,
                mfa_token,
                mfa_setup_required: false,
                password_change_required: false,
            }),
        )
            .into_response();
    }

    let resp = match issue_session(&state, &conn, &credential, &client, &session_config) {
        Ok(resp) => resp,
        Err(error) => return error.into_response(),
    };

    audit_event(
        &state,
        &conn,
        "user_login",
        &body.username,
        &body.username,
        &client_ip,
    );
    info!(
        username = body.username,
        client_ip = client_ip,
        "Login successful"
    );
    resp
}

// ── Issuing a session (shared by password and MFA login) ──────────────

/// Where a login comes from: the client IP (resolved through trusted
/// proxies, see [`crate::middleware::client_ip`]) and User-Agent the new
/// session is bound to.
#[derive(Debug, Clone)]
pub(crate) struct LoginClient {
    pub ip: String,
    pub user_agent: String,
}

impl LoginClient {
    pub(crate) fn of<B>(req: &axum::http::Request<B>, trusted: &TrustedProxies) -> Self {
        Self {
            ip: client_ip_of(req, trusted),
            user_agent: req
                .headers()
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string(),
        }
    }
}

/// Whether the tenant requires every user to have MFA. A missing
/// `tenant_settings` table means no policy was ever set; any other error is
/// returned, so the caller fails rather than skip the restriction.
fn tenant_requires_mfa(conn: &PooledConn, tenant_id: &str) -> Result<bool, rusqlite::Error> {
    match mfa::get_tenant_mfa_required(conn, tenant_id) {
        Err(e) if users::is_missing_schema(&e) => Ok(false),
        other => other,
    }
}

/// The scope a fresh login session gets: [`SCOPE_PASSWORD_CHANGE_ONLY`] when
/// the user must change their password (this wins, as on the bridge),
/// else [`SCOPE_MFA_SETUP_ONLY`] when the tenant requires MFA the user has
/// not set up, else full access (`""`).
fn login_scope(conn: &PooledConn, user: &users::User) -> Result<&'static str, rusqlite::Error> {
    if users::must_change_password(conn, user.id)? {
        return Ok(SCOPE_PASSWORD_CHANGE_ONLY);
    }
    if !user.mfa_enabled && tenant_requires_mfa(conn, &user.tenant_id)? {
        return Ok(SCOPE_MFA_SETUP_ONLY);
    }
    Ok("")
}

/// Refusal after credentials were checked, or a genuine storage failure.
#[derive(Debug)]
pub(crate) enum SessionIssueError {
    PrincipalChanged,
    Storage(rusqlite::Error),
}

impl From<rusqlite::Error> for SessionIssueError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error)
    }
}

impl IntoResponse for SessionIssueError {
    fn into_response(self) -> Response {
        match self {
            Self::PrincipalChanged => (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"detail": "Invalid credentials"})),
            )
                .into_response(),
            Self::Storage(error) => {
                warn!(error = %error, "Failed to create session — login refused");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

/// Create the session for a user who has passed every login step and build
/// the login response: the session bound to `client`'s IP and User-Agent,
/// created with its restricted scope already set (so a failure can never
/// leave a full-scope session behind — the login fails instead), the user's
/// oldest sessions evicted beyond `max_sessions_per_user`, the HttpOnly
/// `session_token` cookie and the `csrf_token` double-submit cookie set.
///
/// Recheck the user's instance, enabled status and credential inside the
/// same IMMEDIATE transaction as every issuance write. The earlier steps
/// (the PBKDF2 password check, the second factor) may have overlapped an
/// account change: a disable, a tenant change, or a password reset or
/// change, which leaves `credential` — the password the login proved —
/// no longer the stored one. On refusal or error nothing is created.
pub(crate) fn issue_session(
    state: &AppState,
    conn: &PooledConn,
    credential: &users::VerifiedCredential,
    client: &LoginClient,
    session_config: &sessions::SessionConfig,
) -> Result<Response, SessionIssueError> {
    let user_id = credential.user_id;
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let user = mfa::get_user_by_id(conn, user_id)?
        .filter(|user| user.enabled && user.tenant_id == crate::auth::api_key::INSTANCE_TENANT)
        .ok_or(SessionIssueError::PrincipalChanged)?;
    if !users::credential_is_current(conn, credential)? {
        return Err(SessionIssueError::PrincipalChanged);
    }
    let scope = login_scope(conn, &user)?;
    let (raw_token, session) = sessions::create_session_scoped(
        conn,
        user_id,
        &client.ip,
        &client.user_agent,
        scope,
        session_config,
    )?;
    let max_sessions = state.config.max_sessions_per_user;
    if max_sessions > 0 {
        let evicted = sessions::delete_oldest_sessions(conn, user_id, i64::from(max_sessions))?;
        if evicted > 0 {
            info!(
                user_id,
                evicted, max_sessions, "Session cap reached — oldest sessions evicted"
            );
        }
    }
    users::touch_last_login(conn, user_id)?;
    tx.commit()?;

    let csrf_token = generate_csrf_token();
    // Only set the Secure flag in production with real TLS certs:
    // browsers reject Secure cookies from a self-signed origin.
    let is_secure = state.config.tls_enabled() && state.config.is_production();
    let cookies = [
        format_cookie("session_token", &raw_token, true, is_secure),
        format_cookie("csrf_token", &csrf_token, false, is_secure),
        // Older gateways copied the session token into this JS-readable
        // cookie; remove any copy the browser still holds.
        expire_cookie(LEGACY_TOKEN_COOKIE, is_secure),
    ];

    let response_body = LoginResponse {
        session_token: raw_token,
        expires_at: session.expires_at,
        csrf_token,
        user: UserInfo {
            username: session.username,
            role: session.role,
            display_name: session.display_name,
        },
        mfa_required: false,
        mfa_token: String::new(),
        mfa_setup_required: scope == SCOPE_MFA_SETUP_ONLY,
        password_change_required: scope == SCOPE_PASSWORD_CHANGE_ONLY,
    };
    let mut resp = (StatusCode::OK, Json(response_body)).into_response();
    append_cookies(&mut resp, &cookies);
    Ok(resp)
}

/// The JS-readable session-token cookie older gateways set. Never set any
/// more (an XSS could read it); expired on login and logout.
pub(crate) const LEGACY_TOKEN_COOKIE: &str = "bridge_token";

fn append_cookies(resp: &mut Response, cookies: &[String]) {
    for cookie in cookies {
        if let Ok(val) = HeaderValue::from_str(cookie) {
            resp.headers_mut().append(header::SET_COOKIE, val);
        }
    }
}

// ── Logout ────────────────────────────────────────────────────────────

/// The cookies logout expires: the session, its CSRF token and the legacy
/// `bridge_token`.
const LOGOUT_COOKIES: [&str; 3] = [
    crate::middleware::auth::SESSION_COOKIE,
    "csrf_token",
    LEGACY_TOKEN_COOKIE,
];

/// True when a `Cookie` field in `headers` carries one of
/// [`LOGOUT_COOKIES`], its name read as [`cookie_pair`] reads it: before
/// the first `=`, without the spaces around it, case-sensitive. Read as
/// bytes, so a field that also carries a cookie that is not visible ASCII
/// still counts.
///
/// [`cookie_pair`]: crate::middleware::auth::cookie_pair
fn carries_a_logout_cookie(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::COOKIE)
        .iter()
        .flat_map(|field| field.as_bytes().split(|&b| b == b';'))
        .filter_map(|pair| {
            let eq = pair.iter().position(|&b| b == b'=')?;
            Some(pair[..eq].trim_ascii())
        })
        .any(|name| {
            LOGOUT_COOKIES
                .iter()
                .any(|cookie| name == cookie.as_bytes())
        })
}

/// Logout: end the session the request presents, as the auth middleware
/// would resolve it.
///
/// The outcomes that leave the caller signed out expire the
/// `session_token`, `csrf_token` and legacy `bridge_token` cookies
/// ([`LOGOUT_COOKIES`]): the session ended (200), and a 401 (no session
/// token, or one that names no session) when the request carried one of
/// those cookies. A stale HttpOnly cookie would otherwise outlive the
/// session, and the page's JavaScript cannot clear it.
///
/// A 401 for a request that carried none of them sets no cookie. Logout
/// is CSRF-exempt, and a cross-site form post carries no `SameSite=Lax`
/// cookie, so it lands here; browsers apply the `Set-Cookie` fields of a
/// top-level navigation's response whatever their `SameSite`, so expiring
/// the cookies on that 401 would let any page sign a visitor's dashboard
/// out (while the session lived on). A request from the dashboard's own
/// site always carries its stale cookies.
///
/// A 503 or 500 keeps them: the session may still exist, and the retry
/// the dashboard offers needs the cookie to end it.
pub async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (status, body) = match extract_token_from_headers(&headers) {
        None => (
            StatusCode::UNAUTHORIZED,
            serde_json::json!({"detail": "No session token provided"}),
        ),
        Some(token) => {
            let conn = match state.db_pool.get() {
                Ok(c) => c,
                Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
            };
            match sessions::delete_session(&conn, &token) {
                Ok(true) => {
                    audit_event(&state, &conn, "user_logout", "", "", "");
                    info!("Session logged out");
                    (StatusCode::OK, serde_json::json!({"status": "logged_out"}))
                }
                Ok(false) => (
                    StatusCode::UNAUTHORIZED,
                    serde_json::json!({"detail": "Session not found"}),
                ),
                Err(e) => {
                    warn!(error = %e, "Logout error");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }
        }
    };
    let mut resp = (status, Json(body)).into_response();
    if status == StatusCode::OK || carries_a_logout_cookie(&headers) {
        let is_secure = state.config.tls_enabled() && state.config.is_production();
        let expired: Vec<String> = LOGOUT_COOKIES
            .iter()
            .map(|name| expire_cookie(name, is_secure))
            .collect();
        append_cookies(&mut resp, &expired);
    }
    resp
}

// ── GET /api/auth/me ──────────────────────────────────────────────────

pub async fn me(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Response {
    let auth_info = req
        .extensions()
        .get::<crate::middleware::auth::AuthInfo>()
        .cloned()
        .unwrap_or(crate::middleware::auth::AuthInfo::Unauthenticated);

    match auth_info {
        crate::middleware::auth::AuthInfo::Session { username, role, .. } => {
            let conn = match state.db_pool.get() {
                Ok(c) => c,
                Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
            };
            let user = users::get_user_by_username(&conn, &username, "default")
                .ok()
                .flatten();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "auth_type": "session",
                    "username": username,
                    "role": role.as_str(),
                    "display_name": user.as_ref().map_or("", |u| &u.display_name),
                    "email": user.as_ref().map_or("", |u| &u.email),
                    "last_login": user.as_ref().and_then(|u| u.last_login.as_deref()),
                    "mfa_enabled": user.as_ref().is_some_and(|u| u.mfa_enabled),
                    "backup_codes_remaining": 0,
                })),
            )
                .into_response()
        }
        crate::middleware::auth::AuthInfo::ApiKey { key_id, role } => (
            StatusCode::OK,
            Json(serde_json::json!({
                "auth_type": "api_key",
                "key_id": key_id,
                "role": role.as_str(),
            })),
        )
            .into_response(),
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"detail": "Not authenticated"})),
        )
            .into_response(),
    }
}

// ── Change password ───────────────────────────────────────────────────

pub async fn change_password(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Response {
    change_password_with(state, req, |new_password| {
        crate::auth::password::hash_credential(new_password, None)
    })
    .await
}

/// [`change_password`] with the PBKDF2 hashing of the new password
/// injectable (tests use it to hold the request at that await).
///
/// The current-password check counts toward the account lockout, as a
/// login does (see the reservation below): a locked account gets 429 and
/// no check, and only a right current password clears the failures.
///
/// Cancel-safe: hashing is the last await. Every write — password
/// history, the new hash, invalidating the other sessions — then commits
/// in one transaction, followed by the audit event, with no await in
/// between, so a request dropped mid-way (client disconnect) changes
/// either nothing or all of it.
///
/// The commit happens only if, by then, the current password verified at
/// the start is still the stored one and the session making the request
/// still exists ([`commit_password_change`]): the PBKDF2 steps take
/// seconds, and a reset, another change or a session revocation committed
/// meanwhile must not be overwritten by this stale request.
async fn change_password_with<H>(
    state: Arc<AppState>,
    req: axum::http::Request<axum::body::Body>,
    hash_new_password: H,
) -> Response
where
    H: FnOnce(&str) -> (String, Vec<u8>) + Send + 'static,
{
    // Require session auth (not API key) — matches Python behavior
    let auth_info = req
        .extensions()
        .get::<crate::middleware::auth::AuthInfo>()
        .cloned()
        .unwrap_or(crate::middleware::auth::AuthInfo::Unauthenticated);

    let (username, user_id, tenant_id, current_session_token, session_scope) = match auth_info {
        crate::middleware::auth::AuthInfo::Session {
            username,
            user_id,
            tenant_id,
            session_token,
            scope,
            ..
        } => (username, user_id, tenant_id, Some(session_token), scope),
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"detail": "Password change requires session authentication"})),
            )
                .into_response();
        }
    };

    let (trusted_proxies, limits) = {
        let cfg = state.auth_config.read().await;
        (cfg.trusted_proxies.clone(), cfg.security_limits.clone())
    };
    let client_ip = client_ip_of(&req, &trusted_proxies);

    // Parse body
    let body_bytes = match axum::body::to_bytes(req.into_body(), 4096).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let body: ChangePasswordRequest = match serde_json::from_slice(&body_bytes) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"detail": "Invalid request body"})),
            )
                .into_response();
        }
    };

    if let Err(e) = crate::auth::password::validate_password_strength(&body.new_password) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"detail": e})),
        )
            .into_response();
    }

    let conn = match state.db_pool.get() {
        Ok(c) => c,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    // The current password is a password guess like a login's: it counts
    // toward the account's lockout, the one the login counts toward, so a
    // stolen session gets no more guesses than a login does. As there, the
    // attempt is reserved before the (slow, off-thread) check, atomically
    // with the lockout check, and only a successful check clears it; a
    // locked account is refused, even with the right current password,
    // without checking or recording anything; and if the lockout state
    // cannot be read or written the change is refused (fail closed). A
    // request refused before this point (a weak new password, a malformed
    // body) checks no password and is not counted.
    match security_state::reserve_account_attempt(
        &conn,
        &username,
        &tenant_id,
        limits.lockout_max,
        limits.lockout_window_secs,
    ) {
        Ok(true) => {}
        Ok(false) => {
            warn!(
                username = %username,
                limit = limits.lockout_max,
                "Password change refused: account locked out"
            );
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::HeaderName::from_static("retry-after"), "1800")],
                Json(serde_json::json!({"detail": "Account temporarily locked due to too many failed attempts."})),
            )
                .into_response();
        }
        Err(e) => {
            warn!(error = %e, "Account lockout state unavailable — password change refused");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }

    // Verify current password — PBKDF2, so it runs on the blocking pool.
    let (user, tenant, current) = (
        username.clone(),
        tenant_id.clone(),
        body.current_password.clone(),
    );
    let Some((conn, verified)) = with_conn_blocking(conn, move |conn| {
        users::verify_password_credential(conn, &user, &current, &tenant)
    })
    .await
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let credential = match verified {
        Ok(Some(credential)) => credential,
        Ok(None) => {
            // The failure was already counted by the reservation above.
            audit_event(
                &state,
                &conn,
                "auth_failure",
                &username,
                &username,
                &client_ip,
            );
            warn!(
                username = %username,
                client_ip = %client_ip,
                "Password change refused: the current password is incorrect"
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"detail": "Current password is incorrect"})),
            )
                .into_response();
        }
        Err(e) => {
            warn!(error = %e, "Password verification error");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    // The current password is right: clear the lockout failures, this
    // attempt's reservation included (on error they stay counted).
    if let Err(e) = security_state::clear_account_failures(&conn, &username, &tenant_id) {
        warn!(error = %e, username = %username, "Failed to clear account lockout failures");
    }

    // Reuse checks — PBKDF2, so on the blocking pool. They also ensure the
    // password_history table the commit writes to.
    let reuse = ReuseCheck {
        user_id,
        username: username.clone(),
        tenant_id: tenant_id.clone(),
        history_count: state.config.password_history_count,
        restricted_session: session_scope == SCOPE_PASSWORD_CHANGE_ONLY,
    };
    let new_password = body.new_password.clone();
    let Some((conn, reused)) =
        with_conn_blocking(conn, move |conn| reuse.refuses(conn, &new_password)).await
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    match reused {
        Ok(true) => return password_reused(),
        Ok(false) => {}
        Err(e) => {
            warn!(error = %e, "Password reuse check error");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    // Hash the new password — PBKDF2, so on the blocking pool. Nothing has
    // been written yet: a request dropped during this await changes nothing.
    let new_password = body.new_password.clone();
    let (new_hash, new_salt) =
        match tokio::task::spawn_blocking(move || hash_new_password(&new_password)).await {
            Ok(hashed) => hashed,
            Err(e) => {
                warn!(error = %e, "Password hashing task failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

    // No await from here on: the change cannot be split by cancellation.
    let invalidated = match commit_password_change(
        &conn,
        &credential,
        &username,
        &tenant_id,
        &new_hash,
        &new_salt,
        current_session_token.as_deref(),
    ) {
        Ok(PasswordCommit::Changed(invalidated)) => invalidated,
        Ok(PasswordCommit::NoSuchUser) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"detail": "User not found"})),
            )
                .into_response();
        }
        Ok(PasswordCommit::CredentialChanged) => {
            warn!(
                username = %username,
                "Password change refused: the password changed while the request ran"
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"detail": "Current password is incorrect"})),
            )
                .into_response();
        }
        Ok(PasswordCommit::SessionEnded) => {
            warn!(
                username = %username,
                "Password change refused: its session or account was revoked while the request ran"
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"detail": "Not authenticated"})),
            )
                .into_response();
        }
        Err(e) => {
            warn!(error = %e, "Password change failed — nothing was changed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    audit_event(&state, &conn, "password_change", &username, &username, "");
    info!(
        username = %username,
        invalidated,
        "Password changed; other sessions invalidated"
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "password_changed"})),
    )
        .into_response()
}

/// The refusal of a new password that is the current one or in the history.
fn password_reused() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"detail": "Password has been used recently. Choose a different password."})),
    )
        .into_response()
}

/// The reuse checks of a password change, run after the current password
/// was verified and before anything is hashed or committed.
struct ReuseCheck {
    user_id: i64,
    username: String,
    tenant_id: String,
    /// `UC_PASSWORD_HISTORY_COUNT`: how many earlier passwords are refused
    /// (0 = no reuse checks for a voluntary change).
    history_count: usize,
    /// The request comes from a [`SCOPE_PASSWORD_CHANGE_ONLY`] session.
    restricted_session: bool,
}

impl ReuseCheck {
    /// Whether `new_password` is refused as reused. One PBKDF2 per password
    /// it is compared with, so this runs on the blocking pool.
    ///
    /// The current password counts as the newest history entry: it enters
    /// the history only when the change commits. It is refused whenever the
    /// reuse policy is on, and always for a forced change (K3: the user is
    /// flagged `must_change_password`, or the session is restricted to the
    /// change) — "changing" to it would clear the flag and lift the
    /// restriction while keeping the exposed password, so that guard is part
    /// of K3, not of the reuse policy. It is compared with the stored hash,
    /// not with the submitted current password: the hash cannot tell some
    /// distinct strings apart (PBKDF2 keys HMAC with the password, and HMAC
    /// zero-pads a key shorter than its 64-byte block, so `P` and `P + "\0"`
    /// are one credential), and a string comparison would let those
    /// through.
    ///
    /// Nothing is written before the current password is refused. Then the
    /// `password_history` table is ensured (the history check and the
    /// commit need it), and the last `history_count` entries are checked.
    fn refuses(&self, conn: &PooledConn, new_password: &str) -> Result<bool, rusqlite::Error> {
        let check_current = self.history_count > 0
            || self.restricted_session
            || users::must_change_password(conn, self.user_id)?;
        if check_current && self.is_current_password(conn, new_password)? {
            return Ok(true);
        }
        password_history::ensure_password_history_table(conn)?;
        if self.history_count == 0 {
            return Ok(false);
        }
        password_history::check_password_reuse(conn, self.user_id, new_password, self.history_count)
    }

    /// Whether `password` matches the user's stored credential. A user gone
    /// since the verification matches nothing (the commit then finds no
    /// user and changes nothing).
    fn is_current_password(
        &self,
        conn: &PooledConn,
        password: &str,
    ) -> Result<bool, rusqlite::Error> {
        let Some(user) = users::get_user_full(conn, &self.username, &self.tenant_id)? else {
            return Ok(false);
        };
        let (matches, _) =
            crate::auth::password::verify_credential(password, &user.password_hash, &user.salt_raw);
        Ok(matches)
    }
}

/// Outcome of [`commit_password_change`].
#[derive(Debug, PartialEq, Eq)]
enum PasswordCommit {
    /// The password changed; this many sessions were deleted.
    Changed(usize),
    /// The user is gone: nothing changed.
    NoSuchUser,
    /// The stored password is no longer the one the request verified (a
    /// reset or another change committed meanwhile): nothing changed.
    CredentialChanged,
    /// The session making the request was revoked, or the account
    /// disabled, meanwhile: nothing changed.
    SessionEnded,
}

/// Apply a password change in one transaction: save the old hash to the
/// history, store the new one (which ends the user's pending MFA logins),
/// clear the forced-change flag (`must_change_password`), delete the
/// user's other sessions (all of them when `keep_session` is `None`) and —
/// when the kept session was limited to [`SCOPE_PASSWORD_CHANGE_ONLY`] —
/// lift that restriction (K3): it becomes a full session, or
/// [`SCOPE_MFA_SETUP_ONLY`] when the tenant requires MFA the user has not
/// set up. On error, and on every outcome but
/// [`Changed`](PasswordCommit::Changed), nothing is changed.
///
/// The change applies only to the state the request was authorised
/// against, checked under the write lock: `credential` (the current
/// password the request verified) must still be the stored one, the
/// account still enabled, and `keep_session` (the session making the
/// request) must still exist. Otherwise a reset, another change or a
/// revocation committed while the request ran would be undone by it.
fn commit_password_change(
    conn: &crate::db::pool::PooledConn,
    credential: &users::VerifiedCredential,
    username: &str,
    tenant_id: &str,
    new_hash: &str,
    new_salt: &[u8],
    keep_session: Option<&str>,
) -> Result<PasswordCommit, rusqlite::Error> {
    let user_id = credential.user_id;
    // IMMEDIATE: take the write lock up front rather than upgrading a read
    // transaction, which can fail under WAL if another writer got in first.
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let Some(old_user) = users::get_user_full(conn, username, tenant_id)? else {
        return Ok(PasswordCommit::NoSuchUser);
    };
    if old_user.id != user_id || old_user.password_hash != credential.password_hash {
        return Ok(PasswordCommit::CredentialChanged);
    }
    let keep_session = keep_session.map(crate::auth::password::sha256_hex);
    let session_alive = match &keep_session {
        Some(token_hash) => conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM sessions WHERE session_token = ?1 AND user_id = ?2)",
            rusqlite::params![token_hash, user_id],
            |row| row.get(0),
        )?,
        None => true,
    };
    if !old_user.enabled || !session_alive {
        return Ok(PasswordCommit::SessionEnded);
    }
    password_history::add_password_history(
        conn,
        user_id,
        &old_user.password_hash,
        &old_user.salt_raw,
    )?;
    if !users::set_password_hash(conn, username, new_hash, new_salt, tenant_id)? {
        return Ok(PasswordCommit::NoSuchUser);
    }
    users::clear_must_change_password(conn, user_id)?;
    let invalidated = match keep_session {
        Some(token_hash) => {
            let next_scope =
                if !old_user.mfa_enabled && tenant_requires_mfa(conn, &old_user.tenant_id)? {
                    SCOPE_MFA_SETUP_ONLY
                } else {
                    ""
                };
            conn.execute(
                "UPDATE sessions SET scope = ?1 WHERE session_token = ?2 AND scope = ?3",
                rusqlite::params![next_scope, token_hash, SCOPE_PASSWORD_CHANGE_ONLY],
            )?;
            sessions::delete_other_sessions(conn, user_id, &token_hash)?
        }
        None => sessions::delete_user_sessions(conn, user_id)?,
    };
    tx.commit()?;
    Ok(PasswordCommit::Changed(invalidated))
}

// ── Helpers ───────────────────────────────────────────────────────────

/// Extract session token from headers (for logout, which reads the request
/// headers itself): the one the auth middleware would resolve.
fn extract_token_from_headers(headers: &HeaderMap) -> Option<String> {
    crate::middleware::auth::session_token_from_headers(headers)
}

/// Generate a CSRF token (64 hex characters, matching Python's secrets.token_hex(32)).
fn generate_csrf_token() -> String {
    let mut buf = [0u8; 32];
    rand::rng().fill(&mut buf[..]);
    hex::encode(buf)
}

/// Format a Set-Cookie header value.
fn format_cookie(name: &str, value: &str, httponly: bool, secure: bool) -> String {
    let mut parts = vec![
        format!("{}={}", name, value),
        "Path=/".to_string(),
        "SameSite=Lax".to_string(),
    ];
    if httponly {
        parts.push("HttpOnly".to_string());
    }
    if secure {
        parts.push("Secure".to_string());
    }
    parts.join("; ")
}

/// A Set-Cookie value that deletes cookie `name`.
fn expire_cookie(name: &str, secure: bool) -> String {
    let mut cookie = format!("{name}=; Path=/; Max-Age=0; SameSite=Lax");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn test_generate_csrf_token_format() {
        let token = generate_csrf_token();
        assert_eq!(token.len(), 64, "Should be 64 hex chars");
        assert!(hex::decode(&token).is_ok(), "Should be valid hex");
    }

    #[test]
    fn test_generate_csrf_token_unique() {
        let t1 = generate_csrf_token();
        let t2 = generate_csrf_token();
        assert_ne!(t1, t2, "Two tokens should be different");
    }

    #[test]
    fn test_format_cookie_session() {
        let cookie = format_cookie("session_token", "abc123", true, true);
        assert!(cookie.contains("session_token=abc123"));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
    }

    #[test]
    fn test_format_cookie_csrf_not_httponly() {
        let cookie = format_cookie("csrf_token", "tok456", false, false);
        assert!(cookie.contains("csrf_token=tok456"));
        assert!(!cookie.contains("HttpOnly"));
        assert!(!cookie.contains("Secure"));
    }

    #[test]
    fn test_format_cookie_secure_without_httponly() {
        let cookie = format_cookie("test", "val", false, true);
        assert!(!cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
    }

    #[test]
    fn test_extract_token_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer my_token".parse().unwrap());
        assert_eq!(
            extract_token_from_headers(&headers),
            Some("my_token".into())
        );
    }

    #[test]
    fn test_extract_token_x_session_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-session-token", "sess_tok".parse().unwrap());
        assert_eq!(
            extract_token_from_headers(&headers),
            Some("sess_tok".into())
        );
    }

    #[test]
    fn test_extract_token_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            "session_token=cook_tok; other=val".parse().unwrap(),
        );
        assert_eq!(
            extract_token_from_headers(&headers),
            Some("cook_tok".into())
        );
    }

    #[test]
    fn test_logout_extracts_session_from_split_cookie_fields() {
        let mut headers = HeaderMap::new();
        headers.append("cookie", "csrf_token=csrf; theme=dark".parse().unwrap());
        headers.append("cookie", "session_token=cook_tok".parse().unwrap());
        assert_eq!(
            extract_token_from_headers(&headers),
            Some("cook_tok".into())
        );
        headers.insert("authorization", "Bearer bearer_tok".parse().unwrap());
        assert_eq!(
            extract_token_from_headers(&headers),
            Some("bearer_tok".into())
        );
    }

    #[test]
    fn test_extract_token_none() {
        let headers = HeaderMap::new();
        assert_eq!(extract_token_from_headers(&headers), None);
    }

    #[test]
    fn test_extract_token_empty_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer ".parse().unwrap());
        assert_eq!(extract_token_from_headers(&headers), None);
    }

    // ── change_password: atomic and cancel-safe ───────────────────────

    use crate::middleware::auth::AuthInfo;
    use crate::storage::sessions::SessionConfig;
    use crate::test_support;
    use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
    use std::sync::{Condvar, Mutex};
    use std::time::{Duration, Instant};

    const OLD_PASSWORD: &str = "Old-passw0rd-correct-horse";
    const NEW_PASSWORD: &str = "New-passw0rd-battery-staple";
    /// What the injected hasher "computes" for the new password.
    const NEW_HASH: &str = "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface";

    struct Fixture {
        _dir: tempfile::TempDir,
        state: Arc<AppState>,
        user_id: i64,
        old_hash: String,
        current_session: String,
        other_session: String,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        // The change's current-password check counts toward the lockout.
        security_tables(&state);
        let conn = state.db_pool.get().unwrap();
        let user_id =
            users::create_user(&conn, "alice", OLD_PASSWORD, "viewer", "", "", "default").unwrap();
        let config = SessionConfig::default();
        let (current_session, _) =
            sessions::create_session(&conn, user_id, "", "", &config).unwrap();
        let (other_session, _) = sessions::create_session(&conn, user_id, "", "", &config).unwrap();
        let old_hash = password_hash(&state);
        Fixture {
            _dir: dir,
            state,
            user_id,
            old_hash,
            current_session,
            other_session,
        }
    }

    impl Fixture {
        /// What verifying [`OLD_PASSWORD`] yields.
        fn credential(&self) -> users::VerifiedCredential {
            users::VerifiedCredential {
                user_id: self.user_id,
                password_hash: self.old_hash.clone(),
            }
        }
    }

    fn password_hash(state: &AppState) -> String {
        let conn = state.db_pool.get().unwrap();
        users::get_user_full(&conn, "alice", "default")
            .unwrap()
            .unwrap()
            .password_hash
    }

    fn session_alive(state: &AppState, token: &str) -> bool {
        let conn = state.db_pool.get().unwrap();
        sessions::validate_session(&conn, token, &SessionConfig::default())
            .unwrap()
            .is_some()
    }

    fn history_len(state: &AppState) -> i64 {
        let conn = state.db_pool.get().unwrap();
        password_history::ensure_password_history_table(&conn).unwrap();
        conn.query_row("SELECT COUNT(*) FROM password_history", [], |row| {
            row.get(0)
        })
        .unwrap()
    }

    fn change_request(f: &Fixture) -> axum::http::Request<axum::body::Body> {
        let body = serde_json::json!({
            "current_password": OLD_PASSWORD,
            "new_password": NEW_PASSWORD,
        });
        let mut req = axum::http::Request::post("/api/auth/change-password")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        req.extensions_mut().insert(AuthInfo::Session {
            username: "alice".to_string(),
            user_id: f.user_id,
            role: crate::auth::rbac::Role::Viewer,
            session_token: f.current_session.clone(),
            expires_at: String::new(),
            tenant_id: "default".to_string(),
            scope: String::new(),
        });
        req
    }

    fn fake_hasher(new_password: &str) -> (String, Vec<u8>) {
        assert_eq!(new_password, NEW_PASSWORD);
        (NEW_HASH.to_string(), vec![7u8; 32])
    }

    #[tokio::test]
    async fn change_password_commits_everything_together() {
        let f = fixture();
        let resp =
            change_password_with(Arc::clone(&f.state), change_request(&f), fake_hasher).await;
        assert_eq!(resp.status(), StatusCode::OK);

        assert_eq!(password_hash(&f.state), NEW_HASH);
        assert_eq!(history_len(&f.state), 1, "old hash kept for reuse checks");
        assert!(session_alive(&f.state, &f.current_session));
        assert!(
            !session_alive(&f.state, &f.other_session),
            "other sessions are invalidated"
        );
        assert_eq!(test_support::audit_count(&f.state, "password_change"), 1);
    }

    /// Blocks the injected hasher until opened; opens itself when dropped,
    /// so a failing assertion cannot leave a blocking thread (and with it
    /// the runtime's shutdown) waiting forever.
    #[derive(Default)]
    struct Gate(Mutex<bool>, Condvar);

    impl Gate {
        fn wait(&self) {
            let mut open = self.0.lock().unwrap();
            while !*open {
                open = self.1.wait(open).unwrap();
            }
        }

        fn open(&self) {
            *self.0.lock().unwrap() = true;
            self.1.notify_all();
        }
    }

    struct OpenOnDrop(Arc<Gate>);

    impl Drop for OpenOnDrop {
        fn drop(&mut self) {
            self.0.open();
        }
    }

    #[tokio::test]
    async fn dropped_password_change_changes_nothing() {
        let f = fixture();
        // Hold the request inside the hashing step, the last await.
        let gate = OpenOnDrop(Arc::new(Gate::default()));
        let hashed = Arc::new(AtomicBool::new(false));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let hasher = {
            let (gate, hashed) = (Arc::clone(&gate.0), Arc::clone(&hashed));
            move |new_password: &str| {
                entered_tx.send(()).unwrap();
                gate.wait();
                let out = fake_hasher(new_password);
                hashed.store(true, SeqCst);
                out
            }
        };
        let task = tokio::spawn(change_password_with(
            Arc::clone(&f.state),
            change_request(&f),
            hasher,
        ));
        entered_rx.await.unwrap();

        // The client disconnects while the new password is being hashed.
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        gate.0.open();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !hashed.load(SeqCst) {
            assert!(Instant::now() < deadline, "hashing never finished");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        // Give a (wrongly) detached commit every chance to land.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // The hashing finished on the blocking pool, but nothing was
        // written: no half-applied change (new password, attacker's
        // session still alive, no audit record).
        assert_eq!(password_hash(&f.state), f.old_hash);
        assert_eq!(history_len(&f.state), 0);
        assert!(session_alive(&f.state, &f.current_session));
        assert!(session_alive(&f.state, &f.other_session));
        assert_eq!(test_support::audit_count(&f.state, "password_change"), 0);

        // The user retries and the change goes through as a whole.
        let resp =
            change_password_with(Arc::clone(&f.state), change_request(&f), fake_hasher).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(password_hash(&f.state), NEW_HASH);
        assert!(!session_alive(&f.state, &f.other_session));
        assert_eq!(test_support::audit_count(&f.state, "password_change"), 1);
    }

    #[test]
    fn commit_password_change_rolls_back_on_error() {
        let f = fixture();
        let conn = f.state.db_pool.get().unwrap();
        password_history::ensure_password_history_table(&conn).unwrap();
        // Make the session invalidation (the last write) fail.
        conn.execute_batch(
            "CREATE TRIGGER fail_session_delete BEFORE DELETE ON sessions \
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .unwrap();
        let result = commit_password_change(
            &conn,
            &f.credential(),
            "alice",
            "default",
            NEW_HASH,
            &[7u8; 32],
            Some(&f.current_session),
        );
        assert!(result.is_err());
        drop(conn);
        assert_eq!(password_hash(&f.state), f.old_hash, "password rolled back");
        assert_eq!(history_len(&f.state), 0, "history rolled back");
        assert!(session_alive(&f.state, &f.other_session));
    }

    // ── login: cookies, scopes, session cap, client IP ────────────────

    use axum::extract::ConnectInfo;
    use std::net::SocketAddr;

    /// Golden PBKDF2 vector (see `password::tests`): the hash of
    /// `"test_password"` under a salt of 32 × 0xaa, so fixtures need no
    /// PBKDF2 of their own.
    const LOGIN_PASSWORD: &str = "test_password";
    const LOGIN_HASH: &str = "c23370bdfca8944baf8868776098f74c72a43de350d49fc65c0d3000ab9d7669";

    fn insert_login_user(state: &AppState, username: &str) -> i64 {
        let conn = state.db_pool.get().unwrap();
        conn.execute(
            "INSERT INTO users (username, password_hash, salt, role, enabled, created_at, tenant_id) \
             VALUES (?1, ?2, ?3, 'admin', 1, '2026-01-01T00:00:00+00:00', 'default')",
            rusqlite::params![username, LOGIN_HASH, vec![0xaau8; 32]],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    fn login_request(
        username: &str,
        peer: &str,
        xff: Option<&str>,
    ) -> axum::http::Request<axum::body::Body> {
        let body = serde_json::json!({"username": username, "password": LOGIN_PASSWORD});
        let mut builder = axum::http::Request::post("/api/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::USER_AGENT, "login-test/2.0");
        if let Some(xff) = xff {
            builder = builder.header("x-forwarded-for", xff);
        }
        let mut req = builder
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        let peer: SocketAddr = peer.parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        req
    }

    async fn into_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn cookies_of(resp: &Response) -> Vec<String> {
        resp.headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    fn session_scope(state: &AppState, raw_token: &str) -> String {
        state
            .db_pool
            .get()
            .unwrap()
            .query_row(
                "SELECT COALESCE(scope, '') FROM sessions WHERE session_token = ?1",
                [crate::auth::password::hash_session_token(raw_token)],
                |r| r.get(0),
            )
            .unwrap()
    }

    /// Regression (G11): the raw session token was also set in a
    /// JS-readable `bridge_token` cookie, so any XSS could steal the
    /// session. Only the HttpOnly `session_token` cookie may carry it; a
    /// stale `bridge_token` is expired.
    #[tokio::test]
    async fn login_keeps_the_session_token_out_of_js_readable_cookies() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        insert_login_user(&state, "alice");

        let resp = login(
            State(Arc::clone(&state)),
            login_request("alice", "198.51.100.20:5555", None),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let cookies = cookies_of(&resp);
        let body = into_json(resp).await;
        let token = body["session_token"].as_str().unwrap();
        let csrf = body["csrf_token"].as_str().unwrap();

        for cookie in &cookies {
            if cookie.starts_with("session_token=") {
                assert!(cookie.starts_with(&format!("session_token={token};")));
                assert!(cookie.contains("HttpOnly"), "{cookie}");
            } else {
                assert!(!cookie.contains(token), "token leaked into {cookie}");
            }
        }
        assert!(cookies
            .iter()
            .any(|c| c.starts_with(&format!("csrf_token={csrf};"))));
        assert!(
            cookies
                .iter()
                .any(|c| c.starts_with("bridge_token=;") && c.contains("Max-Age=0")),
            "a stale bridge_token is deleted: {cookies:?}"
        );
        assert_eq!(body["password_change_required"], false);
        assert_eq!(session_scope(&state, token), "");
        // The session is bound to the client it was issued to.
        let binding: (String, String) = state
            .db_pool
            .get()
            .unwrap()
            .query_row(
                "SELECT ip_address, user_agent FROM sessions WHERE session_token = ?1",
                [crate::auth::password::hash_session_token(token)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            (binding.0.as_str(), binding.1.as_str()),
            ("198.51.100.20", "login-test/2.0")
        );
    }

    /// K3 (contract): a user flagged `must_change_password` gets a
    /// `password_change_only` session; changing the password clears the
    /// flag and lifts the restriction on that session.
    #[tokio::test]
    async fn must_change_password_login_is_restricted_until_the_change() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        let user_id = insert_login_user(&state, "alice");
        {
            let conn = state.db_pool.get().unwrap();
            conn.execute_batch(
                "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0",
            )
            .unwrap();
            conn.execute(
                "UPDATE users SET must_change_password = 1 WHERE id = ?1",
                [user_id],
            )
            .unwrap();
        }

        let resp = login(
            State(Arc::clone(&state)),
            login_request("alice", "198.51.100.20:5555", None),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = into_json(resp).await;
        assert_eq!(body["password_change_required"], true);
        let token = body["session_token"].as_str().unwrap().to_string();
        assert_eq!(session_scope(&state, &token), SCOPE_PASSWORD_CHANGE_ONLY);

        let body = serde_json::json!({
            "current_password": LOGIN_PASSWORD,
            "new_password": NEW_PASSWORD,
        });
        let mut req = axum::http::Request::post("/api/auth/change-password")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        req.extensions_mut().insert(AuthInfo::Session {
            username: "alice".into(),
            user_id,
            role: crate::auth::rbac::Role::Admin,
            session_token: token.clone(),
            expires_at: String::new(),
            tenant_id: "default".into(),
            scope: SCOPE_PASSWORD_CHANGE_ONLY.into(),
        });
        let resp = change_password_with(Arc::clone(&state), req, fake_hasher).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(session_scope(&state, &token), "", "restriction lifted");
        let conn = state.db_pool.get().unwrap();
        assert!(!users::must_change_password(&conn, user_id).unwrap());
    }

    fn tenant_requires_mfa_fixture(state: &AppState) {
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch(
                "CREATE TABLE tenant_settings (tenant_id TEXT PRIMARY KEY, \
                 mfa_required BOOLEAN NOT NULL DEFAULT 0, updated_at TEXT NOT NULL DEFAULT ''); \
                 INSERT INTO tenant_settings VALUES ('default', 1, '');",
            )
            .unwrap();
    }

    /// Regression (G13): the `mfa_setup_only` scope was set after the
    /// session was created, ignoring a failure (`let _ =`), which left a
    /// full-scope session. The scope is now part of the session INSERT.
    #[tokio::test]
    async fn restricted_scope_cannot_be_lost_after_session_creation() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        insert_login_user(&state, "alice");
        tenant_requires_mfa_fixture(&state);
        // Any later scope update fails.
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER no_scope_update BEFORE UPDATE OF scope ON sessions \
                 BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
            )
            .unwrap();

        let resp = login(
            State(Arc::clone(&state)),
            login_request("alice", "198.51.100.20:5555", None),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = into_json(resp).await;
        assert_eq!(body["mfa_setup_required"], true);
        let token = body["session_token"].as_str().unwrap();
        assert_eq!(session_scope(&state, token), SCOPE_MFA_SETUP_ONLY);
    }

    #[test]
    fn failed_session_creation_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = insert_login_user(&state, "alice");
        let conn = state.db_pool.get().unwrap();
        conn.execute_batch(
            "CREATE TRIGGER no_touch BEFORE UPDATE OF last_login ON users \
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .unwrap();
        let client = LoginClient {
            ip: "198.51.100.20".into(),
            user_agent: "ua".into(),
        };
        let credential = users::VerifiedCredential {
            user_id,
            password_hash: LOGIN_HASH.into(),
        };
        let config = SessionConfig::default();
        assert!(issue_session(&state, &conn, &credential, &client, &config).is_err());
        assert_eq!(sessions::count_user_sessions(&conn, user_id).unwrap(), 0);
    }

    /// A credential that is no longer the stored password (its check was
    /// overtaken by a reset) gets no session, and nothing is written.
    #[test]
    fn issuance_refuses_a_credential_no_longer_stored() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = insert_login_user(&state, "alice");
        let conn = state.db_pool.get().unwrap();
        let client = LoginClient {
            ip: "198.51.100.20".into(),
            user_agent: "ua".into(),
        };
        let stale = users::VerifiedCredential {
            user_id,
            password_hash: RESET_HASH.into(),
        };
        let issued = issue_session(&state, &conn, &stale, &client, &SessionConfig::default());
        assert!(matches!(issued, Err(SessionIssueError::PrincipalChanged)));
        assert!(conn.is_autocommit());
        assert_eq!(sessions::count_user_sessions(&conn, user_id).unwrap(), 0);
        let last_login: Option<String> = conn
            .query_row(
                "SELECT last_login FROM users WHERE id = ?1",
                [user_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(last_login, None);
    }

    /// Regression (G13): `UC_MAX_SESSIONS_PER_USER` was never enforced.
    #[tokio::test]
    async fn login_evicts_the_oldest_sessions_beyond_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = test_support::app_state(&dir);
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .max_sessions_per_user = 2;
        security_tables(&state);
        let user_id = insert_login_user(&state, "alice");
        let (oldest, middle) = {
            let conn = state.db_pool.get().unwrap();
            let config = SessionConfig::default();
            let (a, _) = sessions::create_session(&conn, user_id, "", "", &config).unwrap();
            let (b, _) = sessions::create_session(&conn, user_id, "", "", &config).unwrap();
            (a, b)
        };

        let resp = login(
            State(Arc::clone(&state)),
            login_request("alice", "198.51.100.20:5555", None),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let token = into_json(resp).await["session_token"]
            .as_str()
            .unwrap()
            .to_string();
        let conn = state.db_pool.get().unwrap();
        assert_eq!(sessions::count_user_sessions(&conn, user_id).unwrap(), 2);
        drop(conn);
        assert!(!session_alive(&state, &oldest), "oldest evicted");
        assert!(session_alive(&state, &middle));
        assert!(session_alive(&state, &token));
    }

    /// Regression: with a huge absolute session timeout (from
    /// `BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS` or the settings API) the
    /// login task panicked computing the expiry, so every login lost its
    /// connection, or (from about 7e7 hours) it answered with an expiry
    /// past year 9999 that no later request could read. The login now
    /// succeeds with an expiry saturated at the end of year 9999, and the
    /// session works.
    #[tokio::test]
    async fn login_with_a_huge_absolute_timeout_issues_a_working_session() {
        for hours in [100_000_000, 3_000_000_000, i64::MAX] {
            let dir = tempfile::tempdir().unwrap();
            let state = test_support::app_state(&dir);
            security_tables(&state);
            insert_login_user(&state, "alice");
            state
                .auth_config
                .write()
                .await
                .session_config
                .absolute_timeout_hours = hours;

            let login = tokio::spawn(login(
                State(Arc::clone(&state)),
                login_request("alice", "198.51.100.20:5555", None),
            ));
            let resp = login
                .await
                .unwrap_or_else(|e| panic!("{hours} h: the login task failed: {e}"));
            assert_eq!(resp.status(), StatusCode::OK, "{hours} h");
            let body = into_json(resp).await;
            assert_eq!(body["expires_at"], "9999-12-31T23:59:59+00:00", "{hours} h");
            let token = body["session_token"].as_str().unwrap();
            assert!(session_alive(&state, token), "{hours} h");
        }
    }

    /// Regression (G3): behind a trusted proxy the leftmost
    /// X-Forwarded-For entry — chosen by the client — was the rate-limit
    /// key, so rotating it bypassed the per-IP login limit.
    #[tokio::test]
    async fn login_rate_limit_keys_on_the_real_client_behind_a_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        rate_limit_only(&state, 1).await;
        state.auth_config.write().await.trusted_proxies = TrustedProxies::parse("127.0.0.1").0;

        // The proxy appends the real client (198.51.100.7) to whatever the
        // client sent.
        let first = login(
            State(Arc::clone(&state)),
            login_request("nobody", "127.0.0.1:443", Some("6.6.6.1, 198.51.100.7")),
        )
        .await;
        assert_eq!(refused_by(&first), "lockout", "within the rate limit");
        let second = login(
            State(Arc::clone(&state)),
            login_request("nobody", "127.0.0.1:443", Some("6.6.6.2, 198.51.100.7")),
        )
        .await;
        assert_eq!(
            refused_by(&second),
            "rate limit",
            "a forged leftmost entry does not open a new rate-limit bucket"
        );
        let ips: Vec<String> = {
            let conn = state.db_pool.get().unwrap();
            let mut stmt = conn
                .prepare("SELECT DISTINCT client_ip FROM rate_limit_login")
                .unwrap();
            stmt.query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        assert_eq!(ips, ["198.51.100.7"]);
    }

    #[test]
    fn expire_cookie_format() {
        let c = expire_cookie("bridge_token", true);
        assert_eq!(c, "bridge_token=; Path=/; Max-Age=0; SameSite=Lax; Secure");
        assert!(!expire_cookie("x", false).contains("Secure"));
    }

    #[test]
    fn commit_password_change_for_missing_user_changes_nothing() {
        let f = fixture();
        let conn = f.state.db_pool.get().unwrap();
        password_history::ensure_password_history_table(&conn).unwrap();
        let result = commit_password_change(
            &conn,
            &f.credential(),
            "bob",
            "default",
            NEW_HASH,
            &[7u8; 32],
            None,
        );
        assert_eq!(result.unwrap(), PasswordCommit::NoSuchUser);
        drop(conn);
        assert_eq!(history_len(&f.state), 0);
        assert!(session_alive(&f.state, &f.current_session));
    }

    async fn issuance_password_rechecks_user(change: &str) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        let user = insert_login_user(&state, "moving-password");
        let conn = state.db_pool.get().unwrap();
        // Independent legacy credential golden from password::tests. The real
        // login verifies it and upgrades it with PBKDF2 before issuing a session.
        conn.execute(
            "UPDATE users SET password_hash=?1,salt=?2 WHERE id=?3",
            rusqlite::params![
                "226a301654835f8b229491de1c4bcdfb5c6f0fc3372d49550247adf47e909230",
                vec![0xbbu8; 32],
                user
            ],
        )
        .unwrap();
        conn.execute_batch(&format!(
            "CREATE TRIGGER change_account AFTER UPDATE OF password_hash ON users
            BEGIN UPDATE users SET {change} WHERE id=NEW.id; END"
        ))
        .unwrap();
        let request = axum::http::Request::post("/api/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({"username":"moving-password","password":"legacy_pass"})
                    .to_string(),
            ))
            .unwrap();
        let response = login(State(Arc::clone(&state)), request).await;
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
            conn.query_row("SELECT last_login FROM users WHERE id=?1", [user], |r| {
                r.get::<_, Option<String>>(0)
            })
            .unwrap(),
            None
        );
        assert_eq!(test_support::audit_count(&state, "user_login"), 0);
        let persisted: (String, bool) = conn
            .query_row(
                "SELECT tenant_id,enabled FROM users WHERE id=?1",
                [user],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(
            persisted.0 == "other" || !persisted.1,
            "real credential-upgrade trigger ran"
        );
    }

    #[tokio::test]
    async fn tenant_boundary_issuance_rechecks_password_tenant() {
        issuance_password_rechecks_user("tenant_id='other'").await;
    }

    #[tokio::test]
    async fn tenant_boundary_issuance_rechecks_password_enabled() {
        issuance_password_rechecks_user("enabled=0").await;
    }

    // ── a password reset or change racing a login or another change ───

    /// A password hash no login password matches: what a reset stores.
    const RESET_HASH: &str = "abababababababababababababababababababababababababababababababab";

    /// Model an admin password reset (`set_password_and_revoke_sessions`:
    /// new hash, every session revoked) committing right after the login's
    /// password check: the login clears its lockout reservation then.
    fn reset_password_after_the_check(state: &AppState) {
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch(&format!(
                "CREATE TRIGGER reset_after_check AFTER DELETE ON account_lockout BEGIN \
                 UPDATE users SET password_hash = '{RESET_HASH}' WHERE username = OLD.username; \
                 DELETE FROM sessions WHERE user_id IN \
                 (SELECT id FROM users WHERE username = OLD.username); END"
            ))
            .unwrap();
    }

    fn mfa_token_rows(state: &AppState, user_id: i64) -> i64 {
        state
            .db_pool
            .get()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM mfa_tokens WHERE user_id = ?1",
                [user_id],
                |r| r.get(0),
            )
            .unwrap()
    }

    /// Regression: issuance rechecked only the account's instance and
    /// enabled flag, not its credential, so a login whose password check
    /// was under way when an admin reset the password (revoking every
    /// session) still got a full session afterwards, from the old password.
    #[tokio::test]
    async fn a_password_reset_during_the_password_check_gets_no_session() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        let user_id = insert_login_user(&state, "alice");
        reset_password_after_the_check(&state);

        let resp = login(
            State(Arc::clone(&state)),
            login_request("alice", "198.51.100.20:5555", None),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(!sets_session_cookie(&resp));
        assert_eq!(session_rows(&state), 0);
        assert_eq!(stored_hash(&state, user_id), RESET_HASH, "the reset ran");
        assert_eq!(test_support::audit_count(&state, "user_login"), 0);
    }

    /// The same race for an MFA user: the old password must not buy the
    /// MFA challenge that a second factor would turn into a session.
    #[tokio::test]
    async fn a_password_reset_during_the_password_check_gets_no_mfa_challenge() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        let user_id = crate::auth::mfa_handler::tests::mfa_user(&state, "alice");
        state
            .db_pool
            .get()
            .unwrap()
            .execute(
                "UPDATE users SET password_hash = ?1, salt = ?2 WHERE id = ?3",
                rusqlite::params![LOGIN_HASH, vec![0xaau8; 32], user_id],
            )
            .unwrap();
        reset_password_after_the_check(&state);

        let resp = login(
            State(Arc::clone(&state)),
            login_request("alice", "198.51.100.20:5555", None),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(mfa_token_rows(&state, user_id), 0, "no challenge issued");
        assert_eq!(session_rows(&state), 0);
        assert_eq!(stored_hash(&state, user_id), RESET_HASH, "the reset ran");
    }

    /// Run `during` while a password change of `f`'s user is held in its
    /// last step (hashing the new password), then let it finish.
    async fn change_password_around(f: &Fixture, during: impl FnOnce()) -> Response {
        let gate = OpenOnDrop(Arc::new(Gate::default()));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let hasher = {
            let gate = Arc::clone(&gate.0);
            move |new_password: &str| {
                entered_tx.send(()).unwrap();
                gate.wait();
                fake_hasher(new_password)
            }
        };
        let task = tokio::spawn(change_password_with(
            Arc::clone(&f.state),
            change_request(f),
            hasher,
        ));
        entered_rx.await.unwrap();
        during();
        gate.0.open();
        task.await.unwrap()
    }

    /// Regression: a password change committed whatever happened to the
    /// account while it was verifying and hashing. An admin reset landing
    /// then (new password, every session revoked — the caller's own
    /// included) was silently overwritten by the stale request: the caller,
    /// say an attacker with a stolen session and the old password, kept
    /// the account under a password of their choosing.
    #[tokio::test]
    async fn an_admin_reset_during_a_password_change_is_not_overwritten() {
        let f = fixture();
        let resp = change_password_around(&f, || {
            let conn = f.state.db_pool.get().unwrap();
            assert!(users::set_password_and_revoke_sessions(
                &conn,
                "alice",
                "Adm1n-reset-passw0rd",
                "default"
            )
            .unwrap());
        })
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let conn = f.state.db_pool.get().unwrap();
        assert!(
            users::verify_password(&conn, "alice", "Adm1n-reset-passw0rd", "default")
                .unwrap()
                .is_some(),
            "the admin's reset stands"
        );
        drop(conn);
        assert_ne!(password_hash(&f.state), NEW_HASH);
        assert_eq!(history_len(&f.state), 0);
        assert!(!session_alive(&f.state, &f.current_session));
        assert!(!session_alive(&f.state, &f.other_session));
        assert_eq!(test_support::audit_count(&f.state, "password_change"), 0);
    }

    /// A change whose own session was revoked meanwhile (logged out, or
    /// revoked by an admin) changes nothing either.
    #[tokio::test]
    async fn a_password_change_from_a_session_revoked_meanwhile_changes_nothing() {
        let f = fixture();
        let resp = change_password_around(&f, || {
            let conn = f.state.db_pool.get().unwrap();
            sessions::delete_session(&conn, &f.current_session).unwrap();
        })
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(password_hash(&f.state), f.old_hash);
        assert_eq!(history_len(&f.state), 0);
        assert!(session_alive(&f.state, &f.other_session));
        assert_eq!(test_support::audit_count(&f.state, "password_change"), 0);
    }

    /// Regression: a pending MFA login (password step done, second factor
    /// not yet) outlived a change of the password it was started with, and
    /// the second factor still turned it into a session.
    #[tokio::test]
    async fn a_password_change_ends_pending_mfa_logins() {
        use crate::auth::mfa_handler::tests as mfa_tests;
        let f = fixture();
        let challenge = {
            let conn = f.state.db_pool.get().unwrap();
            mfa::set_totp_secret(&conn, f.user_id, mfa_tests::SECRET, "", false).unwrap();
            mfa::enable_mfa(&conn, f.user_id).unwrap();
            mfa::create_mfa_token_unchecked(&conn, f.user_id, 5).unwrap()
        };

        let resp =
            change_password_with(Arc::clone(&f.state), change_request(&f), fake_hasher).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(mfa_token_rows(&f.state, f.user_id), 0);

        let resp = crate::auth::mfa_handler::mfa_verify_login(
            State(Arc::clone(&f.state)),
            mfa_tests::verify_request(&challenge, &mfa_tests::current_code()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(session_alive(&f.state, &f.current_session));
        let conn = f.state.db_pool.get().unwrap();
        assert_eq!(sessions::count_user_sessions(&conn, f.user_id).unwrap(), 1);
    }

    // ── login: lockout, refusals, session fixation ─────────────────────

    /// The bridge-owned rate-limit and lockout tables.
    fn security_tables(state: &AppState) {
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch(
                "CREATE TABLE rate_limit_login (id INTEGER PRIMARY KEY AUTOINCREMENT, \
                 client_ip TEXT NOT NULL, attempt_at REAL NOT NULL, \
                 tenant_id TEXT NOT NULL DEFAULT 'default'); \
                 CREATE TABLE account_lockout (id INTEGER PRIMARY KEY AUTOINCREMENT, \
                 username TEXT NOT NULL, failure_at REAL NOT NULL, \
                 tenant_id TEXT NOT NULL DEFAULT 'default');",
            )
            .unwrap();
    }

    /// Set the login limits, with hour-long windows so that a slow PBKDF2
    /// on a loaded test run cannot age an earlier attempt out mid-test.
    async fn set_limits(state: &AppState, rate_limit_max: u32, lockout_max: u32) {
        state.auth_config.write().await.security_limits = security_state::SecurityLimits {
            rate_limit_max,
            rate_limit_window_secs: 3600.0,
            lockout_max,
            lockout_window_secs: 3600.0,
        };
    }

    /// Limits for a test of the rate limit alone: `rate_limit_max` attempts
    /// per IP, the hour-long windows of [`set_limits`], and an account
    /// lockout of zero attempts. An attempt the rate limit lets through is
    /// then refused by the lockout (429, `Retry-After: 1800`) instead of
    /// running a full-cost PBKDF2, which takes seconds in a debug build and
    /// far longer on a loaded runner; the rate limit's own refusal says
    /// `Retry-After: 60`. See [`refused_by`].
    async fn rate_limit_only(state: &AppState, rate_limit_max: u32) {
        set_limits(state, rate_limit_max, 0).await;
    }

    /// Which limiter refused this login: "rate limit" or "lockout".
    fn refused_by(resp: &Response) -> &'static str {
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        match resp.headers()["retry-after"].to_str().unwrap() {
            "60" => "rate limit",
            "1800" => "lockout",
            other => panic!("unexpected Retry-After: {other}"),
        }
    }

    fn login_as(
        username: &str,
        password: &str,
        headers: &[(&str, &str)],
    ) -> axum::http::Request<axum::body::Body> {
        let body = serde_json::json!({"username": username, "password": password});
        let mut builder = axum::http::Request::post("/api/auth/login")
            .header(header::CONTENT_TYPE, "application/json");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let mut req = builder
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(
            "198.51.100.20:5555".parse::<SocketAddr>().unwrap(),
        ));
        req
    }

    fn lockout_rows(state: &AppState, username: &str) -> i64 {
        state
            .db_pool
            .get()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM account_lockout WHERE username = ?1",
                [username],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn session_rows(state: &AppState) -> i64 {
        state
            .db_pool
            .get()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
            .unwrap()
    }

    fn sets_session_cookie(resp: &Response) -> bool {
        cookies_of(resp)
            .iter()
            .any(|c| c.starts_with("session_token=") && !c.starts_with("session_token=;"))
    }

    fn session_owner(state: &AppState, token: &str) -> Option<String> {
        let conn = state.db_pool.get().unwrap();
        sessions::validate_session(&conn, token, &SessionConfig::default())
            .unwrap()
            .map(|s| s.username)
    }

    /// A wrong password and an unknown user get the same 401 (no username
    /// enumeration), no session, and both count toward that account's lockout.
    #[tokio::test]
    async fn failed_logins_are_refused_uniformly_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        insert_login_user(&state, "alice");

        let wrong = login(
            State(Arc::clone(&state)),
            login_as("alice", "Wrong-passw0rd", &[]),
        )
        .await;
        let unknown = login(
            State(Arc::clone(&state)),
            login_as("nobody", LOGIN_PASSWORD, &[]),
        )
        .await;
        for resp in [&wrong, &unknown] {
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            assert!(!sets_session_cookie(resp));
        }
        let (wrong, unknown) = (into_json(wrong).await, into_json(unknown).await);
        assert_eq!(
            wrong, unknown,
            "same refusal for unknown user and bad password"
        );
        assert_eq!(wrong["detail"], "Invalid username or password");
        assert_eq!(session_rows(&state), 0);
        assert_eq!(lockout_rows(&state, "alice"), 1);
        assert_eq!(lockout_rows(&state, "nobody"), 1);
        assert_eq!(test_support::audit_count(&state, "auth_failure"), 2);
    }

    /// Once an account reaches the failure limit even the right password is
    /// refused (429, Retry-After) and no session is issued; other accounts
    /// are not affected.
    #[tokio::test]
    async fn locked_account_refuses_even_the_correct_password() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        insert_login_user(&state, "alice");
        insert_login_user(&state, "bob");
        set_limits(&state, 100, 2).await;

        for _ in 0..2 {
            let resp = login(
                State(Arc::clone(&state)),
                login_as("alice", "Wrong-passw0rd", &[]),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
        let locked = login(
            State(Arc::clone(&state)),
            login_as("alice", LOGIN_PASSWORD, &[]),
        )
        .await;
        assert_eq!(locked.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(locked.headers()["retry-after"], "1800");
        assert!(!sets_session_cookie(&locked));
        assert_eq!(session_rows(&state), 0, "no session for a locked account");
        assert_eq!(test_support::audit_count(&state, "user_login"), 0);

        let bob = login(
            State(Arc::clone(&state)),
            login_as("bob", LOGIN_PASSWORD, &[]),
        )
        .await;
        assert_eq!(bob.status(), StatusCode::OK, "lockout is per account");
    }

    #[tokio::test]
    async fn successful_login_clears_the_failure_count() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        insert_login_user(&state, "alice");
        let resp = login(
            State(Arc::clone(&state)),
            login_as("alice", "Wrong-passw0rd", &[]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(lockout_rows(&state, "alice"), 1);

        let resp = login(
            State(Arc::clone(&state)),
            login_as("alice", LOGIN_PASSWORD, &[]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(lockout_rows(&state, "alice"), 0);
    }

    /// A rate-limited client is refused before its password is checked: the
    /// right password does not get it a session.
    #[tokio::test]
    async fn rate_limited_client_gets_no_session_with_the_right_password() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        insert_login_user(&state, "alice");
        set_limits(&state, 1, 100).await;

        let first = login(
            State(Arc::clone(&state)),
            login_as("alice", "Wrong-passw0rd", &[]),
        )
        .await;
        assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
        let limited = login(
            State(Arc::clone(&state)),
            login_as("alice", LOGIN_PASSWORD, &[]),
        )
        .await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(limited.headers()["retry-after"], "60");
        assert!(!sets_session_cookie(&limited));
        assert_eq!(session_rows(&state), 0);
        assert_eq!(
            lockout_rows(&state, "alice"),
            1,
            "a refused attempt is not checked, so not counted as a failure"
        );
    }

    fn rate_limit_rows(state: &AppState) -> i64 {
        state
            .db_pool
            .get()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM rate_limit_login", [], |r| r.get(0))
            .unwrap()
    }

    /// Record `count` login attempts, `age_secs` old, from the client of
    /// [`login_as`] (198.51.100.20).
    fn record_old_attempts(state: &AppState, count: usize, age_secs: f64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let conn = state.db_pool.get().unwrap();
        for _ in 0..count {
            conn.execute(
                "INSERT INTO rate_limit_login (client_ip, attempt_at, tenant_id) \
                 VALUES ('198.51.100.20', ?1, 'default')",
                [now - age_secs],
            )
            .unwrap();
        }
    }

    /// Regression: the per-IP limit recorded each attempt before counting
    /// it and refused at `count >= rate_limit_max`, so it allowed one
    /// attempt fewer than its maximum (4 a minute with the default 5). It
    /// allows exactly `rate_limit_max` attempts per window, as the bridge's
    /// `_check_login_rate` does (`test_rate_limit_at_exact_threshold`),
    /// and records each of them.
    #[tokio::test]
    async fn rate_limit_allows_exactly_rate_limit_max_attempts() {
        let default_max = security_state::SecurityLimits::default().rate_limit_max;
        for max in [1, 2, default_max] {
            let dir = tempfile::tempdir().unwrap();
            let state = test_support::app_state(&dir);
            security_tables(&state);
            rate_limit_only(&state, max).await;

            for n in 1..=max {
                let resp = login(
                    State(Arc::clone(&state)),
                    login_as("nobody", LOGIN_PASSWORD, &[]),
                )
                .await;
                assert_eq!(
                    refused_by(&resp),
                    "lockout",
                    "max {max}: attempt {n} is within the rate limit"
                );
            }
            let limited = login(
                State(Arc::clone(&state)),
                login_as("nobody", LOGIN_PASSWORD, &[]),
            )
            .await;
            assert_eq!(
                refused_by(&limited),
                "rate limit",
                "max {max}: attempt {} is over the limit",
                max + 1
            );
            assert_eq!(rate_limit_rows(&state), i64::from(max), "max {max}");
        }
    }

    /// The rate limit counts the attempts of its own window
    /// (`UC_RATE_LIMIT_WINDOW`), not those of the lockout's
    /// (`UC_LOCKOUT_WINDOW`): with the defaults, 5 attempts a minute per
    /// IP, not 5 per 30 minutes. Two attempts five minutes old use up a
    /// limit of two with a 10-minute rate-limit window and a 1-minute
    /// lockout window, and do not count with the windows the other way
    /// round.
    #[tokio::test]
    async fn rate_limit_counts_the_attempts_of_its_own_window_not_the_lockouts() {
        for (rate_limit_window_secs, lockout_window_secs, refused, rows) in
            [(600.0, 60.0, "rate limit", 2), (60.0, 600.0, "lockout", 3)]
        {
            let dir = tempfile::tempdir().unwrap();
            let state = test_support::app_state(&dir);
            security_tables(&state);
            // A zero lockout, as in rate_limit_only.
            state.auth_config.write().await.security_limits = security_state::SecurityLimits {
                rate_limit_max: 2,
                rate_limit_window_secs,
                lockout_max: 0,
                lockout_window_secs,
            };
            record_old_attempts(&state, 2, 300.0);

            let resp = login(
                State(Arc::clone(&state)),
                login_as("nobody", LOGIN_PASSWORD, &[]),
            )
            .await;
            let windows =
                format!("rate limit {rate_limit_window_secs} s, lockout {lockout_window_secs} s");
            assert_eq!(refused_by(&resp), refused, "{windows}");
            assert_eq!(rate_limit_rows(&state), rows, "{windows}");
        }
    }

    /// Regression: a refused attempt was recorded too, so a client that
    /// kept trying stayed limited for as long as it kept trying, however
    /// long ago its allowed attempts were. As in the bridge, only an
    /// allowed attempt is recorded: the client is limited until its
    /// allowed attempts leave the window, and not beyond.
    #[tokio::test]
    async fn refused_attempts_are_not_recorded_and_do_not_extend_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        insert_login_user(&state, "alice");
        set_limits(&state, 2, 100).await; // 3600 s window

        // The client used up its two attempts 50 min ago.
        record_old_attempts(&state, 2, 3000.0);

        for n in 1..=3 {
            let resp = login(
                State(Arc::clone(&state)),
                login_as("alice", LOGIN_PASSWORD, &[]),
            )
            .await;
            assert_eq!(
                resp.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "refused attempt {n}"
            );
        }
        assert_eq!(
            rate_limit_rows(&state),
            2,
            "a refused attempt is not recorded"
        );

        // Twelve minutes on, the allowed attempts have left the window
        // (the refused ones would still be in it, had they been recorded).
        state
            .db_pool
            .get()
            .unwrap()
            .execute(
                "UPDATE rate_limit_login SET attempt_at = attempt_at - 700",
                [],
            )
            .unwrap();
        let resp = login(
            State(Arc::clone(&state)),
            login_as("alice", LOGIN_PASSWORD, &[]),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the limit ends a window after the last allowed attempt"
        );
        assert_eq!(rate_limit_rows(&state), 3);
    }

    /// Parallel logins from one client cannot get more attempts than the
    /// rate limit allows. The worst case is forced, not hoped for: three
    /// attempts (`rate_limit_max = 2`) start while another connection holds
    /// the write lock. The count and the record are one statement that
    /// waits whole for the lock, so exactly two get past the rate limit and
    /// the third is refused without being recorded. A count run before the
    /// record would not wait: all three would count 0 and get through.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_logins_cannot_exceed_the_rate_limit() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        rate_limit_only(&state, 2).await;

        // One connection of the test pool (4) holds the write lock, the
        // other three take the attempts.
        let gate = test_support::WriteLockGate::<1>::close(&state.db_pool);
        let attempts: Vec<_> = (0..3)
            .map(|i| {
                tokio::spawn(login(
                    State(Arc::clone(&state)),
                    login_as("nobody", &format!("Wrong-passw0rd-{i}"), &[]),
                ))
            })
            .collect();
        gate.open_when_queued(3);
        let mut refusals = Vec::new();
        for attempt in attempts {
            let resp = attempt.await.unwrap();
            assert!(!sets_session_cookie(&resp));
            refusals.push(refused_by(&resp));
        }
        refusals.sort_unstable();
        assert_eq!(refusals, ["lockout", "lockout", "rate limit"]);
        assert_eq!(rate_limit_rows(&state), 2);
    }

    /// Concurrent guesses must not slip past the lockout limit: an attempt
    /// has to count against the account *before* its (slow, off-thread)
    /// password check, as the bridge does (`_reserve_login_attempt`), so a
    /// parallel attempt already sees it. Observed deterministically through
    /// the legacy-hash upgrade, a write made right after the password check.
    #[tokio::test]
    async fn login_attempt_counts_toward_lockout_before_the_password_check() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        let user = insert_login_user(&state, "alice");
        let conn = state.db_pool.get().unwrap();
        // Legacy SHA-256 golden vector from password::tests ("legacy_pass").
        conn.execute(
            "UPDATE users SET password_hash = ?1, salt = ?2 WHERE id = ?3",
            rusqlite::params![
                "226a301654835f8b229491de1c4bcdfb5c6f0fc3372d49550247adf47e909230",
                vec![0xbbu8; 32],
                user
            ],
        )
        .unwrap();
        conn.execute_batch(
            "CREATE TABLE probe (failures INTEGER NOT NULL);
             CREATE TRIGGER observe_check AFTER UPDATE OF password_hash ON users
             BEGIN INSERT INTO probe SELECT COUNT(*) FROM account_lockout
                   WHERE username = NEW.username; END;",
        )
        .unwrap();

        let resp = login(
            State(Arc::clone(&state)),
            login_as("alice", "legacy_pass", &[]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let seen: i64 = conn
            .query_row("SELECT failures FROM probe", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            seen, 1,
            "while the password was being checked the attempt was not yet counted"
        );
        assert_eq!(lockout_rows(&state, "alice"), 0, "cleared on success");
    }

    /// A disabled account is refused at the password check exactly like a
    /// wrong password: same 401 body (no account-state oracle telling
    /// "disabled, right password" apart from "wrong password"), the attempt
    /// counts toward the lockout instead of clearing it, and it is audited
    /// as an authentication failure.
    #[tokio::test]
    async fn disabled_account_cannot_log_in_with_the_right_password() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        let user = insert_login_user(&state, "alice");
        state
            .db_pool
            .get()
            .unwrap()
            .execute("UPDATE users SET enabled = 0 WHERE id = ?1", [user])
            .unwrap();

        let resp = login(
            State(Arc::clone(&state)),
            login_as("alice", LOGIN_PASSWORD, &[]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(!sets_session_cookie(&resp));
        let right = into_json(resp).await;
        assert_eq!(right["detail"], "Invalid username or password");
        assert_eq!(session_rows(&state), 0);
        assert_eq!(
            lockout_rows(&state, "alice"),
            1,
            "the refused attempt counts toward the lockout"
        );
        assert_eq!(test_support::audit_count(&state, "auth_failure"), 1);
        assert_eq!(test_support::audit_count(&state, "user_login"), 0);

        let wrong = login(
            State(Arc::clone(&state)),
            login_as("alice", "Wrong-passw0rd", &[]),
        )
        .await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            into_json(wrong).await,
            right,
            "the right password on a disabled account looks like a wrong one"
        );
        assert_eq!(lockout_rows(&state, "alice"), 2);
    }

    /// A refused login must not issue a session. Shared by the fail-closed
    /// tests below.
    fn assert_refused_without_session(state: &AppState, resp: &Response) {
        assert!(
            matches!(
                resp.status(),
                StatusCode::TOO_MANY_REQUESTS
                    | StatusCode::SERVICE_UNAVAILABLE
                    | StatusCode::INTERNAL_SERVER_ERROR
            ),
            "login allowed while the limiter could not be consulted: {}",
            resp.status()
        );
        assert!(!sets_session_cookie(resp));
        assert_eq!(session_rows(state), 0, "no session issued");
        assert_eq!(test_support::audit_count(state, "user_login"), 0);
    }

    /// The lockout must fail closed: if the failure count cannot be read,
    /// the login is refused rather than treated as "no failures" — else a
    /// storage fault (or a missing bridge-owned table) lifts every lockout.
    #[tokio::test]
    async fn lockout_fails_closed_when_its_state_cannot_be_read() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        insert_login_user(&state, "alice");
        set_limits(&state, 100, 2).await;
        for _ in 0..2 {
            let resp = login(
                State(Arc::clone(&state)),
                login_as("alice", "Wrong-passw0rd", &[]),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
        // alice is now locked out; then the lockout state becomes unreadable.
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch("ALTER TABLE account_lockout RENAME TO account_lockout_unavailable")
            .unwrap();

        let resp = login(
            State(Arc::clone(&state)),
            login_as("alice", LOGIN_PASSWORD, &[]),
        )
        .await;
        assert_refused_without_session(&state, &resp);
    }

    /// The per-IP rate limit must fail closed the same way.
    #[tokio::test]
    async fn rate_limit_fails_closed_when_its_state_cannot_be_read() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        insert_login_user(&state, "alice");
        set_limits(&state, 1, 100).await;
        let first = login(
            State(Arc::clone(&state)),
            login_as("alice", "Wrong-passw0rd", &[]),
        )
        .await;
        assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
        // The client is now at the limit; then the limiter state becomes
        // unreadable.
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch("ALTER TABLE rate_limit_login RENAME TO rate_limit_login_unavailable")
            .unwrap();

        // The second attempt would hit the limit; it must not get through.
        let resp = login(
            State(Arc::clone(&state)),
            login_as("alice", LOGIN_PASSWORD, &[]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_refused_without_session(&state, &resp);
    }

    /// Legacy SHA-256 golden vector from `password::tests` ("legacy_pass"):
    /// a successful check upgrades it, so a hash still equal to it shows
    /// that the password was never checked.
    const LEGACY_HASH: &str = "226a301654835f8b229491de1c4bcdfb5c6f0fc3372d49550247adf47e909230";
    const LEGACY_PASSWORD: &str = "legacy_pass";

    fn use_legacy_password(state: &AppState, user: i64) {
        state
            .db_pool
            .get()
            .unwrap()
            .execute(
                "UPDATE users SET password_hash = ?1, salt = ?2 WHERE id = ?3",
                rusqlite::params![LEGACY_HASH, vec![0xbbu8; 32], user],
            )
            .unwrap();
    }

    fn stored_hash(state: &AppState, user: i64) -> String {
        state
            .db_pool
            .get()
            .unwrap()
            .query_row(
                "SELECT password_hash FROM users WHERE id = ?1",
                [user],
                |r| r.get(0),
            )
            .unwrap()
    }

    /// Any limiter storage fault fails closed, not only a missing table:
    /// here each table is readable but refuses writes. The login is refused
    /// (503) before its password is checked — no PBKDF2, no session — and a
    /// failing rate limiter takes no lockout slot.
    #[tokio::test]
    async fn limiter_write_failures_refuse_before_the_password_check() {
        for table in ["rate_limit_login", "account_lockout"] {
            let dir = tempfile::tempdir().unwrap();
            let state = test_support::app_state(&dir);
            security_tables(&state);
            set_limits(&state, 100, 100).await;
            let user = insert_login_user(&state, "alice");
            use_legacy_password(&state, user);
            let first = login(
                State(Arc::clone(&state)),
                login_as("alice", "Wrong-passw0rd", &[]),
            )
            .await;
            assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
            state
                .db_pool
                .get()
                .unwrap()
                .execute_batch(&format!(
                    "CREATE TRIGGER refuse_write BEFORE INSERT ON {table} \
                     BEGIN SELECT RAISE(ABORT, 'injected failure'); END;"
                ))
                .unwrap();

            let resp = login(
                State(Arc::clone(&state)),
                login_as("alice", LEGACY_PASSWORD, &[]),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{table}");
            assert_refused_without_session(&state, &resp);
            assert_eq!(
                stored_hash(&state, user),
                LEGACY_HASH,
                "{table}: the password was never checked"
            );
            assert_eq!(
                lockout_rows(&state, "alice"),
                1,
                "{table}: only the earlier failure is counted"
            );
        }
    }

    /// Parallel wrong guesses cannot get more password checks than the
    /// lockout allows: each one reserves its slot atomically before its
    /// check, so with `lockout_max = 2` exactly two are checked (401) and
    /// the rest are refused as locked (429) without recording anything.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_wrong_guesses_cannot_exceed_the_lockout_limit() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        insert_login_user(&state, "alice");
        set_limits(&state, 100, 2).await;

        // As many guesses as the test pool has connections (4), all at once.
        let guesses: Vec<_> = (0..4)
            .map(|i| {
                tokio::spawn(login(
                    State(Arc::clone(&state)),
                    login_as("alice", &format!("Wrong-passw0rd-{i}"), &[]),
                ))
            })
            .collect();
        let mut statuses = Vec::new();
        for guess in guesses {
            let resp = guess.await.unwrap();
            assert!(!sets_session_cookie(&resp));
            statuses.push(resp.status());
        }
        statuses.sort();
        assert_eq!(
            statuses,
            [
                StatusCode::UNAUTHORIZED,
                StatusCode::UNAUTHORIZED,
                StatusCode::TOO_MANY_REQUESTS,
                StatusCode::TOO_MANY_REQUESTS
            ]
        );
        assert_eq!(lockout_rows(&state, "alice"), 2);
        assert_eq!(test_support::audit_count(&state, "auth_failure"), 2);

        let right = login(
            State(Arc::clone(&state)),
            login_as("alice", LOGIN_PASSWORD, &[]),
        )
        .await;
        assert_eq!(right.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(session_rows(&state), 0);
    }

    /// A password check that errors leaves its attempt counted (only a
    /// successful check clears it), so storage faults cannot be used to
    /// make guesses for free.
    #[tokio::test]
    async fn failed_password_check_leaves_the_attempt_counted() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        insert_login_user(&state, "alice");
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch("ALTER TABLE users RENAME TO users_unavailable")
            .unwrap();

        let resp = login(
            State(Arc::clone(&state)),
            login_as("alice", LOGIN_PASSWORD, &[]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!sets_session_cookie(&resp));
        assert_eq!(session_rows(&state), 0);
        assert_eq!(lockout_rows(&state, "alice"), 1);
    }

    /// A client that goes away during the password check stays counted,
    /// even with the right password: only a login that gets past a
    /// successful check clears the reservation.
    #[tokio::test]
    async fn abandoned_login_stays_counted() {
        for _ in 0..5 {
            let dir = tempfile::tempdir().unwrap();
            let state = test_support::app_state(&dir);
            security_tables(&state);
            insert_login_user(&state, "alice");

            // The first poll runs up to the PBKDF2 await; the cut-off drops
            // the request there, as a client disconnect does.
            let cut_off = tokio::time::timeout(
                Duration::from_millis(1),
                login(
                    State(Arc::clone(&state)),
                    login_as("alice", LOGIN_PASSWORD, &[]),
                ),
            )
            .await;
            if cut_off.is_ok() {
                continue; // The check beat the cut-off (a stalled runner): retry.
            }
            assert_eq!(lockout_rows(&state, "alice"), 1);
            assert_eq!(session_rows(&state), 0);
            return;
        }
        panic!("the login was never cut off during its password check");
    }

    /// With MFA on, the password alone yields only a short-lived MFA token:
    /// no session row and no session cookie.
    #[tokio::test]
    async fn mfa_user_gets_no_session_from_the_password_alone() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        let user = insert_login_user(&state, "alice");
        state
            .db_pool
            .get()
            .unwrap()
            .execute("UPDATE users SET mfa_enabled = 1 WHERE id = ?1", [user])
            .unwrap();

        let resp = login(
            State(Arc::clone(&state)),
            login_as("alice", LOGIN_PASSWORD, &[]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            cookies_of(&resp).is_empty(),
            "no cookies before the 2nd factor"
        );
        let body = into_json(resp).await;
        assert_eq!(body["mfa_required"], true);
        assert_eq!(body["session_token"], "");
        assert!(!body["mfa_token"].as_str().unwrap().is_empty());
        assert_eq!(session_rows(&state), 0);
    }

    /// The MFA decision fails closed: a user lookup that errors after the
    /// password check (here an unreadable display_name, standing in for
    /// SQLITE_BUSY) used to read as "MFA off" and issue a full session
    /// on the password alone.
    #[tokio::test]
    async fn mfa_user_gets_no_session_when_the_mfa_state_cannot_be_read() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        let user = insert_login_user(&state, "alice");
        state
            .db_pool
            .get()
            .unwrap()
            .execute(
                "UPDATE users SET mfa_enabled = 1, display_name = X'00ff' WHERE id = ?1",
                [user],
            )
            .unwrap();

        let resp = login(
            State(Arc::clone(&state)),
            login_as("alice", LOGIN_PASSWORD, &[]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(cookies_of(&resp).is_empty(), "no session cookie");
        assert_eq!(session_rows(&state), 0);
        assert_eq!(test_support::audit_count(&state, "user_login"), 0);
    }

    /// A user deleted between the password check and the MFA lookup gets
    /// no session either.
    #[tokio::test]
    async fn a_user_deleted_after_the_password_check_gets_no_session() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        insert_login_user(&state, "alice");
        // Delete the row as soon as the successful check clears the lockout.
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER vanish AFTER DELETE ON account_lockout \
                 BEGIN DELETE FROM users WHERE username = 'alice'; END;",
            )
            .unwrap();

        let resp = login(
            State(Arc::clone(&state)),
            login_as("alice", LOGIN_PASSWORD, &[]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(cookies_of(&resp).is_empty(), "no session cookie");
        assert_eq!(session_rows(&state), 0);
    }

    #[tokio::test]
    async fn malformed_login_body_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        insert_login_user(&state, "alice");
        for body in ["not json", r#"{"username":"alice"}"#] {
            let req = axum::http::Request::post("/api/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body))
                .unwrap();
            let resp = login(State(Arc::clone(&state)), req).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{body}");
            assert!(!sets_session_cookie(&resp));
        }
        assert_eq!(session_rows(&state), 0);
    }

    /// The `Content-Type` values a cross-site page can send without a CORS
    /// preflight (an HTML form's three encodings, a `no-cors` fetch with a
    /// parameter that names JSON), a missing one, and near misses. None is
    /// `application/json`, so none may sign the browser in.
    pub(crate) const NOT_JSON_CONTENT_TYPES: &[Option<&str>] = &[
        None,
        Some(""),
        Some("text/plain"),
        Some("text/plain;charset=UTF-8"),
        Some("text/plain;charset=application/json"),
        Some("text/plain; application/json"),
        Some("application/x-www-form-urlencoded"),
        Some("multipart/form-data; boundary=x"),
        Some("application/jsonx"),
        Some("application/json-seq"),
        Some("application/merge-patch+json"),
        Some("json"),
    ];

    /// `application/json` in any letter case, with parameters and spaces.
    pub(crate) const JSON_CONTENT_TYPES: &[&str] = &[
        "application/json",
        "Application/JSON",
        "application/json; charset=utf-8",
        " application/json ;charset=UTF-8",
    ];

    /// Login CSRF: login is CSRF-exempt and read the body as JSON whatever
    /// its `Content-Type`, so a cross-site `text/plain` form whose field
    /// spells a JSON object signed the victim's browser into the
    /// attacker's account. A body that is not declared `application/json`
    /// is now refused with 415 before anything is checked or recorded: no
    /// session, no cookie, no rate-limit attempt and no lockout failure.
    #[tokio::test]
    async fn login_refuses_a_body_not_declared_json() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        insert_login_user(&state, "alice");
        // What a form field named `{"username":"alice","password":"…","x":"`
        // with the value `"}` posts as text/plain: still a JSON object.
        let form_shaped =
            format!(r#"{{"username":"alice","password":"{LOGIN_PASSWORD}","x":"="}}"#);
        for content_type in NOT_JSON_CONTENT_TYPES {
            let mut builder = axum::http::Request::post("/api/auth/login")
                .header("origin", "https://evil.example")
                .header("sec-fetch-site", "cross-site");
            if let Some(content_type) = content_type {
                builder = builder.header(header::CONTENT_TYPE, *content_type);
            }
            let mut req = builder
                .body(axum::body::Body::from(form_shaped.clone()))
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(
                "198.51.100.20:5555".parse::<SocketAddr>().unwrap(),
            ));
            let resp = login(State(Arc::clone(&state)), req).await;
            assert_eq!(
                resp.status(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "{content_type:?}"
            );
            assert!(cookies_of(&resp).is_empty(), "{content_type:?}");
            assert_eq!(
                into_json(resp).await["detail"],
                "Content-Type must be application/json"
            );
        }
        // Two Content-Type fields are not one JSON declaration either.
        let mut req = axum::http::Request::post("/api/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(axum::body::Body::from(form_shaped.clone()))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(
            "198.51.100.20:5555".parse::<SocketAddr>().unwrap(),
        ));
        let resp = login(State(Arc::clone(&state)), req).await;
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(session_rows(&state), 0);
        assert_eq!(rate_limit_rows(&state), 0, "a refused body is no attempt");
        assert_eq!(lockout_rows(&state, "alice"), 0);

        // The same body declared as JSON signs in.
        for content_type in JSON_CONTENT_TYPES {
            let mut req = axum::http::Request::post("/api/auth/login")
                .header(header::CONTENT_TYPE, *content_type)
                .body(axum::body::Body::from(form_shaped.clone()))
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(
                "198.51.100.20:5555".parse::<SocketAddr>().unwrap(),
            ));
            let resp = login(State(Arc::clone(&state)), req).await;
            assert_eq!(resp.status(), StatusCode::OK, "{content_type}");
            assert!(sets_session_cookie(&resp), "{content_type}");
        }
    }

    /// Session fixation: a login never adopts a token the client brought
    /// along (an attacker-planted cookie, valid or not) — it always issues
    /// a fresh one, and the planted session is not upgraded to the victim.
    #[tokio::test]
    async fn login_never_adopts_a_client_supplied_session_token() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        insert_login_user(&state, "alice");
        let mallory = insert_login_user(&state, "mallory");
        let planted = {
            let conn = state.db_pool.get().unwrap();
            sessions::create_session(&conn, mallory, "", "", &SessionConfig::default())
                .unwrap()
                .0
        };
        let chosen = "attacker-chosen-session-token";
        let cookie = format!("session_token={planted}");
        let bearer = format!("Bearer {planted}");

        let mut issued = Vec::new();
        for _ in 0..2 {
            let resp = login(
                State(Arc::clone(&state)),
                login_as(
                    "alice",
                    LOGIN_PASSWORD,
                    &[
                        ("cookie", &cookie),
                        ("authorization", &bearer),
                        ("x-session-token", chosen),
                    ],
                ),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
            let cookies = cookies_of(&resp);
            let token = into_json(resp).await["session_token"]
                .as_str()
                .unwrap()
                .to_string();
            assert_ne!(token, planted);
            assert_ne!(token, chosen);
            assert!(cookies
                .iter()
                .any(|c| c.starts_with(&format!("session_token={token};"))));
            assert_eq!(session_owner(&state, &token).as_deref(), Some("alice"));
            issued.push(token);
        }
        assert_ne!(issued[0], issued[1], "every login gets a fresh token");
        assert_eq!(
            session_owner(&state, &planted).as_deref(),
            Some("mallory"),
            "the planted session still belongs to its owner"
        );
        assert_eq!(session_owner(&state, chosen), None);
    }

    // ── logout / me ────────────────────────────────────────────────────

    #[tokio::test]
    async fn logout_revokes_the_presented_session_and_expires_its_cookies() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user = insert_login_user(&state, "alice");
        let (gone, kept) = {
            let conn = state.db_pool.get().unwrap();
            let config = SessionConfig::default();
            (
                sessions::create_session(&conn, user, "", "", &config)
                    .unwrap()
                    .0,
                sessions::create_session(&conn, user, "", "", &config)
                    .unwrap()
                    .0,
            )
        };
        let mut headers = HeaderMap::new();
        headers.insert("cookie", format!("session_token={gone}").parse().unwrap());

        let resp = logout(State(Arc::clone(&state)), headers.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let cookies = cookies_of(&resp);
        for name in ["session_token", "csrf_token", LEGACY_TOKEN_COOKIE] {
            assert!(
                cookies
                    .iter()
                    .any(|c| c.starts_with(&format!("{name}=;")) && c.contains("Max-Age=0")),
                "{name} expired: {cookies:?}"
            );
        }
        assert_eq!(session_owner(&state, &gone), None);
        assert_eq!(session_owner(&state, &kept).as_deref(), Some("alice"));
        assert_eq!(test_support::audit_count(&state, "user_logout"), 1);

        let again = logout(State(Arc::clone(&state)), headers).await;
        assert_eq!(again.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(test_support::audit_count(&state, "user_logout"), 1);
    }

    /// Logout reads the `Bearer` scheme in any letter case, as the auth
    /// middleware does.
    #[tokio::test]
    async fn logout_reads_the_bearer_scheme_in_any_letter_case() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user = insert_login_user(&state, "alice");
        for scheme in ["bearer", "BEARER", "BeArEr"] {
            let token = {
                let conn = state.db_pool.get().unwrap();
                sessions::create_session(&conn, user, "", "", &SessionConfig::default())
                    .unwrap()
                    .0
            };
            let mut headers = HeaderMap::new();
            headers.insert(
                "authorization",
                format!("{scheme}  {token}").parse().unwrap(),
            );
            let resp = logout(State(Arc::clone(&state)), headers).await;
            assert_eq!(resp.status(), StatusCode::OK, "{scheme}");
            assert_eq!(session_owner(&state, &token), None, "{scheme}");
            // A session ended expires the cookies, whatever carried it.
            assert!(
                expires_session_cookies(&resp),
                "{scheme}: {:?}",
                cookies_of(&resp)
            );
        }
    }

    /// The three cookies logout expires, each with `Max-Age=0`.
    fn expires_session_cookies(resp: &Response) -> bool {
        let cookies = cookies_of(resp);
        ["session_token", "csrf_token", LEGACY_TOKEN_COOKIE]
            .iter()
            .all(|name| {
                cookies
                    .iter()
                    .any(|c| c.starts_with(&format!("{name}=;")) && c.contains("Max-Age=0"))
            })
            && cookies.len() == 3
    }

    #[tokio::test]
    async fn logout_without_a_known_token_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let resp = logout(State(Arc::clone(&state)), HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(cookies_of(&resp).is_empty(), "{:?}", cookies_of(&resp));
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer not-a-session".parse().unwrap());
        let resp = logout(State(Arc::clone(&state)), headers.clone()).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(cookies_of(&resp).is_empty(), "{:?}", cookies_of(&resp));
        headers.insert("cookie", "csrf_token=c".parse().unwrap());
        let resp = logout(State(Arc::clone(&state)), headers).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(expires_session_cookies(&resp), "{:?}", cookies_of(&resp));
        assert_eq!(test_support::audit_count(&state, "user_logout"), 0);
    }

    /// Forced sign-out (logout CSRF). Logout is CSRF-exempt, and a
    /// cross-site form post carries none of the gateway's cookies (they
    /// are `SameSite=Lax`), so it gets the "no token" 401. Browsers apply
    /// the `Set-Cookie` fields of a top-level navigation's response
    /// whatever their `SameSite`, so when that 401 expired the cookies,
    /// any page an operator visited could sign their dashboard out, on
    /// every visit, while the session itself lived on. A 401 now expires
    /// them only when the request carried one of them, as a request from
    /// the dashboard's own site with a stale cookie always does. A request
    /// that carried none, a `Bearer` or `X-Session-Token` that names no
    /// session included, gets no `Set-Cookie` (as on 0.1.0).
    #[tokio::test]
    async fn logout_expires_no_cookie_for_a_request_that_carried_none() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let headers = |fields: &[(&'static str, &[u8])]| {
            let mut headers = HeaderMap::new();
            for (name, value) in fields {
                headers.append(*name, HeaderValue::from_bytes(value).unwrap());
            }
            headers
        };
        let cross_site: &[(&str, &[u8])] = &[
            ("origin", b"https://evil.example"),
            ("sec-fetch-site", b"cross-site"),
            ("content-type", b"application/x-www-form-urlencoded"),
        ];
        let opaque: &[(&str, &[u8])] = &[("origin", b"null"), ("sec-fetch-site", b"cross-site")];
        for (case, fields) in [
            ("cross-site form", cross_site),
            ("opaque origin", opaque),
            (
                "unknown bearer",
                &[("authorization", b"Bearer not-a-session")],
            ),
            (
                "unknown header token",
                &[("x-session-token", b"not-a-session")],
            ),
            (
                "look-alike cookies",
                &[(
                    "cookie",
                    b"theme=dark; session_token_hint=1; Csrf_Token=x; xbridge_token=1; csrf_token",
                )],
            ),
        ] {
            let resp = logout(State(Arc::clone(&state)), headers(fields)).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{case}");
            assert!(
                cookies_of(&resp).is_empty(),
                "{case}: {:?}",
                cookies_of(&resp)
            );
        }
        // One of the three, however the browser sent it, is enough.
        for (case, fields) in [
            ("csrf cookie only", &[("cookie", &b"csrf_token=c"[..])][..]),
            ("legacy cookie only", &[("cookie", b"bridge_token=old")]),
            (
                "stale session cookie",
                &[("cookie", b"theme=dark; session_token=stale")],
            ),
            (
                "spaces around the name",
                &[("cookie", b"theme=dark;  csrf_token =c")],
            ),
            (
                "second cookie field",
                &[("cookie", b"theme=dark"), ("cookie", b"csrf_token=c")],
            ),
            (
                "beside a cookie that is not ASCII",
                &[("cookie", "name=caf\u{e9}; csrf_token=c".as_bytes())],
            ),
            (
                "unknown bearer with a cookie",
                &[
                    ("authorization", b"Bearer not-a-session"),
                    ("cookie", b"csrf_token=c"),
                ],
            ),
        ] {
            let resp = logout(State(Arc::clone(&state)), headers(fields)).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{case}");
            assert!(
                expires_session_cookies(&resp),
                "{case}: {:?}",
                cookies_of(&resp)
            );
        }
    }

    /// A stale HttpOnly cookie (its session expired, evicted or revoked
    /// elsewhere) outlived a logout: the 401 set no cookie, and the page's
    /// JavaScript cannot clear an HttpOnly one. Every outcome that leaves
    /// the caller signed out now expires `session_token`, `csrf_token` and
    /// `bridge_token`: the session ended (200), and a 401 (no session
    /// token, or one that names no session) for a request that carried one
    /// of them. The status codes are unchanged.
    #[tokio::test]
    async fn logout_expires_the_cookies_whenever_the_caller_is_signed_out() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user = insert_login_user(&state, "alice");
        let valid = {
            let conn = state.db_pool.get().unwrap();
            sessions::create_session(&conn, user, "", "", &SessionConfig::default())
                .unwrap()
                .0
        };
        let cookie = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(
                "cookie",
                format!("session_token={value}; csrf_token=c")
                    .parse()
                    .unwrap(),
            );
            headers
        };
        let csrf_only = {
            let mut headers = HeaderMap::new();
            headers.insert("cookie", "csrf_token=c".parse().unwrap());
            headers
        };
        for (case, headers, status) in [
            ("no session token", csrf_only, StatusCode::UNAUTHORIZED),
            ("unknown", cookie("stale-token"), StatusCode::UNAUTHORIZED),
            ("valid", cookie(&valid), StatusCode::OK),
            ("already ended", cookie(&valid), StatusCode::UNAUTHORIZED),
        ] {
            let resp = logout(State(Arc::clone(&state)), headers).await;
            assert_eq!(resp.status(), status, "{case}");
            assert!(
                expires_session_cookies(&resp),
                "{case}: {:?}",
                cookies_of(&resp)
            );
        }
        assert_eq!(session_owner(&state, &valid), None);
    }

    /// A logout the database could not complete keeps the cookies: the
    /// session may still exist, and the retry the dashboard offers ("Could
    /// not sign out. Please try again.") needs the cookie to end it. Had
    /// the cookies been expired here, that retry would find no token, get
    /// 401 and report "signed out" while the session lived on.
    #[tokio::test]
    async fn logout_keeps_the_cookies_when_the_session_could_not_be_ended() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user = insert_login_user(&state, "alice");
        let token = {
            let conn = state.db_pool.get().unwrap();
            let token = sessions::create_session(&conn, user, "", "", &SessionConfig::default())
                .unwrap()
                .0;
            conn.execute_batch(
                "CREATE TRIGGER refuse_logout BEFORE DELETE ON sessions \
                 BEGIN SELECT RAISE(ABORT, 'injected'); END",
            )
            .unwrap();
            token
        };
        let mut headers = HeaderMap::new();
        headers.insert("cookie", format!("session_token={token}").parse().unwrap());
        let resp = logout(State(Arc::clone(&state)), headers).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(cookies_of(&resp).is_empty(), "{:?}", cookies_of(&resp));
        assert_eq!(session_owner(&state, &token).as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn me_requires_authentication() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let req = axum::http::Request::get("/api/auth/me")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            me(State(Arc::clone(&state)), req).await.status(),
            StatusCode::UNAUTHORIZED
        );
        let mut req = axum::http::Request::get("/api/auth/me")
            .body(axum::body::Body::empty())
            .unwrap();
        req.extensions_mut().insert(AuthInfo::Unauthenticated);
        assert_eq!(
            me(State(state), req).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }

    /// `/api/auth/me` describes the caller only, and never echoes the
    /// session token or any stored credential.
    #[tokio::test]
    async fn me_describes_the_caller_without_credential_material() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user = insert_login_user(&state, "alice");
        let token = {
            let conn = state.db_pool.get().unwrap();
            conn.execute(
                "UPDATE users SET email = 'alice@example.test', totp_secret = 'JBSWY3DPEHPK3PXP' \
                 WHERE id = ?1",
                [user],
            )
            .unwrap();
            sessions::create_session(&conn, user, "", "", &SessionConfig::default())
                .unwrap()
                .0
        };
        let mut req = axum::http::Request::get("/api/auth/me")
            .body(axum::body::Body::empty())
            .unwrap();
        req.extensions_mut().insert(AuthInfo::Session {
            username: "alice".into(),
            user_id: user,
            role: crate::auth::rbac::Role::Admin,
            session_token: token.clone(),
            expires_at: String::new(),
            tenant_id: "default".into(),
            scope: String::new(),
        });
        let resp = me(State(Arc::clone(&state)), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = into_json(resp).await;
        assert_eq!(body["auth_type"], "session");
        assert_eq!(body["username"], "alice");
        assert_eq!(body["role"], "admin");
        assert_eq!(body["email"], "alice@example.test");
        let text = body.to_string();
        for secret in [
            token.as_str(),
            &crate::auth::password::hash_session_token(&token),
            LOGIN_HASH,
            "JBSWY3DPEHPK3PXP",
        ] {
            assert!(!text.contains(secret), "leaked {secret}");
        }

        let mut req = axum::http::Request::get("/api/auth/me")
            .body(axum::body::Body::empty())
            .unwrap();
        req.extensions_mut().insert(AuthInfo::ApiKey {
            key_id: "ops-key".into(),
            role: crate::auth::rbac::Role::Viewer,
        });
        let body = into_json(me(State(state), req).await).await;
        assert_eq!(
            body,
            serde_json::json!({"auth_type": "api_key", "key_id": "ops-key", "role": "viewer"})
        );
    }

    // ── change_password: refusals change nothing ───────────────────────

    fn assert_unchanged(f: &Fixture) {
        assert_eq!(password_hash(&f.state), f.old_hash, "password unchanged");
        assert_eq!(history_len(&f.state), 0, "no history written");
        assert!(session_alive(&f.state, &f.current_session));
        assert!(
            session_alive(&f.state, &f.other_session),
            "nobody logged out"
        );
        assert_eq!(test_support::audit_count(&f.state, "password_change"), 0);
    }

    fn with_body(
        mut req: axum::http::Request<axum::body::Body>,
        current: &str,
        new: &str,
    ) -> axum::http::Request<axum::body::Body> {
        *req.body_mut() = axum::body::Body::from(
            serde_json::json!({"current_password": current, "new_password": new}).to_string(),
        );
        req
    }

    #[tokio::test]
    async fn change_password_requires_a_session_principal() {
        let f = fixture();
        for auth in [
            None,
            Some(AuthInfo::Unauthenticated),
            Some(AuthInfo::ApiKey {
                key_id: "admin-key".into(),
                role: crate::auth::rbac::Role::Admin,
            }),
        ] {
            let mut req = change_request(&f);
            req.extensions_mut().remove::<AuthInfo>();
            if let Some(auth) = auth {
                req.extensions_mut().insert(auth);
            }
            let resp = change_password_with(Arc::clone(&f.state), req, fake_hasher).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        }
        assert_unchanged(&f);
    }

    #[tokio::test]
    async fn wrong_current_password_changes_nothing() {
        let f = fixture();
        let req = with_body(change_request(&f), "Not-the-passw0rd", NEW_PASSWORD);
        let resp = change_password_with(Arc::clone(&f.state), req, fake_hasher).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_unchanged(&f);
    }

    // ── change_password: current-password guesses are limited ─────────

    /// The 429 of a locked account, as the login sends it.
    async fn assert_locked(resp: Response) {
        assert_eq!(refused_by(&resp), "lockout");
        assert_eq!(
            into_json(resp).await["detail"],
            "Account temporarily locked due to too many failed attempts."
        );
    }

    /// Regression: the current password of a change was checked with no
    /// attempt limit, so a stolen session could guess it without end and,
    /// once right, set a password of its choosing and log the owner's
    /// other sessions out. Each check now counts toward the account's
    /// lockout, the one the login counts toward, and is audited when it
    /// fails; once `lockout_max` failures are counted even the right
    /// current password is refused, here and at the login.
    #[tokio::test]
    async fn wrong_current_passwords_count_toward_the_account_lockout() {
        let f = fixture();
        set_limits(&f.state, 100, 3).await;
        for guess in 0..3 {
            let wrong = format!("Wrong-passw0rd-{guess}");
            let req = with_body(change_request(&f), &wrong, NEW_PASSWORD);
            let resp = change_password_with(Arc::clone(&f.state), req, fake_hasher).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{wrong}");
        }
        assert_eq!(lockout_rows(&f.state, "alice"), 3, "every guess counted");
        assert_eq!(test_support::audit_count(&f.state, "auth_failure"), 3);

        let right =
            change_password_with(Arc::clone(&f.state), change_request(&f), fake_hasher).await;
        assert_locked(right).await;
        assert_unchanged(&f);
        assert_eq!(
            lockout_rows(&f.state, "alice"),
            3,
            "a refusal records nothing"
        );
        assert_eq!(test_support::audit_count(&f.state, "auth_failure"), 3);

        let login_resp = login(
            State(Arc::clone(&f.state)),
            login_as("alice", OLD_PASSWORD, &[]),
        )
        .await;
        assert_locked(login_resp).await;
    }

    /// The other way round: an account the logins locked cannot change its
    /// password either, even with the right current password, until the
    /// failures age out of the window. Nothing is checked or recorded.
    #[tokio::test]
    async fn a_locked_account_cannot_change_its_password() {
        let f = fixture();
        set_limits(&f.state, 100, 2).await;
        for _ in 0..2 {
            let resp = login(
                State(Arc::clone(&f.state)),
                login_as("alice", "Wrong-passw0rd", &[]),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }

        let resp =
            change_password_with(Arc::clone(&f.state), change_request(&f), fake_hasher).await;
        assert_locked(resp).await;
        assert_unchanged(&f);
        assert_eq!(lockout_rows(&f.state, "alice"), 2);
    }

    /// A wrong current password is audited with who tried it: the session's
    /// user as the target and the operator, and the client IP (the one an
    /// incident response needs to find a stolen session's holder). The
    /// login's failures carry the IP the same way.
    #[tokio::test]
    async fn a_wrong_current_password_is_audited_with_the_user_and_client_ip() {
        let f = fixture();
        let mut req = with_body(change_request(&f), "Wrong-passw0rd", NEW_PASSWORD);
        req.extensions_mut()
            .insert(crate::middleware::client_ip::ClientIp("203.0.113.9".into()));
        let resp = change_password_with(Arc::clone(&f.state), req, fake_hasher).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let entries: Vec<(String, String, String)> = {
            let conn = f.state.db_pool.get().unwrap();
            let mut stmt = conn
                .prepare(
                    "SELECT target_id, operator, note FROM audit_log \
                     WHERE action = 'auth_failure' ORDER BY id",
                )
                .unwrap();
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        assert_eq!(
            entries,
            [(
                "alice".to_string(),
                "alice".to_string(),
                "From 203.0.113.9".to_string()
            )]
        );
    }

    /// A change whose current password is right clears the failures, as a
    /// successful login does. A request refused before the current password
    /// is checked (a weak new password, a malformed body) is not counted.
    #[tokio::test]
    async fn a_password_change_clears_the_failure_count() {
        let f = fixture();
        let req = with_body(change_request(&f), OLD_PASSWORD, "Sh0rt");
        let resp = change_password_with(Arc::clone(&f.state), req, fake_hasher).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(lockout_rows(&f.state, "alice"), 0, "nothing was checked");

        let req = with_body(change_request(&f), "Wrong-passw0rd", NEW_PASSWORD);
        let resp = change_password_with(Arc::clone(&f.state), req, fake_hasher).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(lockout_rows(&f.state, "alice"), 1);

        let resp =
            change_password_with(Arc::clone(&f.state), change_request(&f), fake_hasher).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(password_hash(&f.state), NEW_HASH);
        assert_eq!(lockout_rows(&f.state, "alice"), 0, "cleared on success");
    }

    /// Parallel guesses cannot get more checks than the lockout allows:
    /// each one is counted, atomically with the lockout check, before its
    /// PBKDF2, so with `lockout_max = 2` exactly two are checked (401) and
    /// the others refused as locked (429).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_wrong_current_passwords_cannot_exceed_the_lockout_limit() {
        let f = fixture();
        set_limits(&f.state, 100, 2).await;
        // As many guesses as the test pool has connections (4), all at once.
        let guesses: Vec<_> = (0..4)
            .map(|i| {
                let req = with_body(
                    change_request(&f),
                    &format!("Wrong-passw0rd-{i}"),
                    NEW_PASSWORD,
                );
                tokio::spawn(change_password_with(Arc::clone(&f.state), req, fake_hasher))
            })
            .collect();
        let mut statuses = Vec::new();
        for guess in guesses {
            statuses.push(guess.await.unwrap().status());
        }
        statuses.sort();
        assert_eq!(
            statuses,
            [
                StatusCode::UNAUTHORIZED,
                StatusCode::UNAUTHORIZED,
                StatusCode::TOO_MANY_REQUESTS,
                StatusCode::TOO_MANY_REQUESTS
            ]
        );
        assert_eq!(lockout_rows(&f.state, "alice"), 2);
        assert_unchanged(&f);
    }

    /// The lockout fails closed for a change as for a login: when its state
    /// cannot be written, the change is refused (503) before the current
    /// password is checked.
    #[tokio::test]
    async fn change_password_lockout_fails_closed() {
        let f = fixture();
        f.state
            .db_pool
            .get()
            .unwrap()
            .execute_batch("ALTER TABLE account_lockout RENAME TO account_lockout_unavailable")
            .unwrap();
        let resp =
            change_password_with(Arc::clone(&f.state), change_request(&f), fake_hasher).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_unchanged(&f);
    }

    #[tokio::test]
    async fn weak_new_password_is_refused() {
        let f = fixture();
        for weak in ["Sh0rt", "alllowercase1", "ALLUPPERCASE1", "NoDigitsHere"] {
            let req = with_body(change_request(&f), OLD_PASSWORD, weak);
            let resp = change_password_with(Arc::clone(&f.state), req, fake_hasher).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{weak}");
        }
        for malformed in ["not json", r#"{"new_password":"New-passw0rd"}"#] {
            let mut req = change_request(&f);
            *req.body_mut() = axum::body::Body::from(malformed);
            let resp = change_password_with(Arc::clone(&f.state), req, fake_hasher).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{malformed}");
        }
        assert_unchanged(&f);
    }

    /// A password from the user's history is refused, and the refusal
    /// changes nothing (no new hash, no logout, no history row, no audit).
    #[tokio::test]
    async fn recently_used_password_is_refused() {
        let f = fixture();
        {
            // Legacy salted SHA-256 of NEW_PASSWORD: cheap to build, and
            // `verify_credential` accepts it like any stored hash.
            use sha2::{Digest, Sha256};
            let salt = [0x42u8; 32];
            let mut hasher = Sha256::new();
            hasher.update(salt);
            hasher.update(NEW_PASSWORD.as_bytes());
            let conn = f.state.db_pool.get().unwrap();
            password_history::ensure_password_history_table(&conn).unwrap();
            password_history::add_password_history(
                &conn,
                f.user_id,
                &hex::encode(hasher.finalize()),
                &salt,
            )
            .unwrap();
        }

        let resp =
            change_password_with(Arc::clone(&f.state), change_request(&f), fake_hasher).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            into_json(resp).await["detail"],
            "Password has been used recently. Choose a different password."
        );
        assert_eq!(password_hash(&f.state), f.old_hash);
        assert_eq!(history_len(&f.state), 1, "only the seeded entry");
        assert!(session_alive(&f.state, &f.other_session));
        assert_eq!(test_support::audit_count(&f.state, "password_change"), 0);
    }

    /// The current password is the most recently used one: "changing" to it
    /// must be refused like any password in the history.
    #[tokio::test]
    async fn current_password_is_refused_as_the_new_password() {
        let f = fixture();
        let req = with_body(change_request(&f), OLD_PASSWORD, OLD_PASSWORD);
        let resp = change_password_with(Arc::clone(&f.state), req, |_: &str| {
            (NEW_HASH.to_string(), vec![7u8; 32])
        })
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            into_json(resp).await["detail"],
            "Password has been used recently. Choose a different password."
        );
        assert_unchanged(&f);
    }

    /// `OLD_PASSWORD` (26 bytes) followed by `nuls` NUL characters, 64
    /// bytes at most in all. PBKDF2 keys HMAC with the password, and HMAC
    /// zero-pads a key shorter than its 64-byte block, so under any salt
    /// this hashes exactly like `OLD_PASSWORD`: to the stored hash it *is*
    /// the current password.
    fn current_with_nuls(nuls: usize) -> String {
        format!("{OLD_PASSWORD}{}", "\0".repeat(nuls))
    }

    /// Turn off the reuse policy (`UC_PASSWORD_HISTORY_COUNT=0`).
    fn disable_reuse_checks(f: &mut Fixture) {
        Arc::get_mut(&mut f.state)
            .unwrap()
            .config
            .password_history_count = 0;
    }

    /// Flag alice for a forced password change (K3, as for the bootstrap
    /// admin) and give her the `password_change_only` session a login then
    /// gets, or — `restricted: false` — a full one (a session from before
    /// the flag was set). Returns the session token.
    fn force_password_change(f: &Fixture, flag: bool, restricted: bool) -> String {
        let conn = f.state.db_pool.get().unwrap();
        conn.execute_batch(
            "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0",
        )
        .unwrap();
        conn.execute(
            "UPDATE users SET must_change_password = ?1 WHERE id = ?2",
            rusqlite::params![flag, f.user_id],
        )
        .unwrap();
        let scope = if restricted {
            SCOPE_PASSWORD_CHANGE_ONLY
        } else {
            ""
        };
        sessions::create_session_scoped(&conn, f.user_id, "", "", scope, &SessionConfig::default())
            .unwrap()
            .0
    }

    /// A change of alice's password from the session `token` (of the scope
    /// [`force_password_change`] gave it) to `new`.
    fn change_request_from(
        f: &Fixture,
        token: &str,
        restricted: bool,
        new: &str,
    ) -> axum::http::Request<axum::body::Body> {
        let mut req = with_body(change_request(f), OLD_PASSWORD, new);
        let scope = if restricted {
            SCOPE_PASSWORD_CHANGE_ONLY
        } else {
            ""
        };
        req.extensions_mut().insert(AuthInfo::Session {
            username: "alice".into(),
            user_id: f.user_id,
            role: crate::auth::rbac::Role::Viewer,
            session_token: token.into(),
            expires_at: String::new(),
            tenant_id: "default".into(),
            scope: scope.into(),
        });
        req
    }

    /// Run the change; it must be refused as reuse without hashing the new
    /// password or changing anything: the password, history, sessions and
    /// audit trail are untouched, and so are the forced-change flag (when
    /// `flagged`) and the session's scope.
    async fn assert_reuse_refused(
        f: &Fixture,
        req: axum::http::Request<axum::body::Body>,
        token: &str,
        flagged: bool,
        expected_scope: &str,
    ) {
        let resp = change_password_with(Arc::clone(&f.state), req, |_: &str| {
            panic!("the refused password is never hashed")
        })
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            into_json(resp).await["detail"],
            "Password has been used recently. Choose a different password."
        );
        let conn = f.state.db_pool.get().unwrap();
        assert_eq!(
            users::must_change_password(&conn, f.user_id).unwrap(),
            flagged,
            "the forced-change flag is untouched"
        );
        drop(conn);
        assert_eq!(
            session_scope(&f.state, token),
            expected_scope,
            "the session keeps its scope"
        );
        assert!(session_alive(&f.state, token));
        assert_unchanged(f);
    }

    /// The current password with trailing NULs hashes like the current
    /// password, so it is the current password and is refused too (the
    /// check compares against the stored hash, not the submitted string).
    #[tokio::test]
    async fn current_password_with_trailing_nuls_is_refused() {
        let f = fixture();
        for nuls in [1, 64 - OLD_PASSWORD.len()] {
            let new = current_with_nuls(nuls);
            assert!(crate::auth::password::validate_password_strength(&new).is_ok());
            let req = with_body(change_request(&f), OLD_PASSWORD, &new);
            assert_reuse_refused(&f, req, &f.current_session, false, "").await;
        }
    }

    /// K3: a forced password change (the auto-generated bootstrap password)
    /// cannot be satisfied by "changing" to the same password — the flag
    /// stays set and the session stays restricted.
    #[tokio::test]
    async fn forced_change_cannot_keep_the_current_password() {
        let f = fixture();
        let restricted = force_password_change(&f, true, true);
        // OLD_PASSWORD meets the strength policy: only reuse can refuse it.
        assert!(crate::auth::password::validate_password_strength(OLD_PASSWORD).is_ok());
        let req = change_request_from(&f, &restricted, true, OLD_PASSWORD);
        assert_reuse_refused(&f, req, &restricted, true, SCOPE_PASSWORD_CHANGE_ONLY).await;
    }

    /// K3: nor by "changing" to the current password plus a NUL, which
    /// serde_json accepts ("\u0000") and the strength policy allows, and
    /// which the stored hash cannot tell from the current password.
    #[tokio::test]
    async fn forced_change_cannot_keep_the_current_password_with_a_trailing_nul() {
        let f = fixture();
        let restricted = force_password_change(&f, true, true);
        let req = change_request_from(&f, &restricted, true, &current_with_nuls(1));
        assert_reuse_refused(&f, req, &restricted, true, SCOPE_PASSWORD_CHANGE_ONLY).await;
    }

    /// K3 does not depend on the reuse policy: with
    /// `UC_PASSWORD_HISTORY_COUNT=0` a forced change still refuses the
    /// current password (and its NUL-padded equivalents).
    #[tokio::test]
    async fn forced_change_refuses_the_current_password_without_reuse_checks() {
        let mut f = fixture();
        disable_reuse_checks(&mut f);
        let restricted = force_password_change(&f, true, true);
        for new in [OLD_PASSWORD.to_string(), current_with_nuls(1)] {
            let req = change_request_from(&f, &restricted, true, &new);
            assert_reuse_refused(&f, req, &restricted, true, SCOPE_PASSWORD_CHANGE_ONLY).await;
        }
    }

    /// Either sign of a forced change is enough, without reuse checks: the
    /// `must_change_password` flag (here on a full session, e.g. one from
    /// before the flag was set) or a `password_change_only` session (here
    /// with the flag already cleared).
    #[tokio::test]
    async fn either_sign_of_a_forced_change_refuses_the_current_password() {
        let mut f = fixture();
        disable_reuse_checks(&mut f);
        let full = force_password_change(&f, true, false);
        let req = change_request_from(&f, &full, false, OLD_PASSWORD);
        assert_reuse_refused(&f, req, &full, true, "").await;

        let mut f = fixture();
        disable_reuse_checks(&mut f);
        let restricted = force_password_change(&f, false, true);
        let req = change_request_from(&f, &restricted, true, OLD_PASSWORD);
        assert_reuse_refused(&f, req, &restricted, false, SCOPE_PASSWORD_CHANGE_ONLY).await;
    }

    /// `UC_PASSWORD_HISTORY_COUNT=0` turns the reuse checks of a voluntary
    /// change off, the current-password one included (policy: 0 means no
    /// reuse checks; only a forced change still refuses the current one).
    #[tokio::test]
    async fn disabled_reuse_checks_accept_the_current_password() {
        let mut f = fixture();
        disable_reuse_checks(&mut f);
        let req = with_body(change_request(&f), OLD_PASSWORD, OLD_PASSWORD);
        let resp = change_password_with(Arc::clone(&f.state), req, |new: &str| {
            assert_eq!(new, OLD_PASSWORD);
            (NEW_HASH.to_string(), vec![7u8; 32])
        })
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(password_hash(&f.state), NEW_HASH);
    }

    /// The new-password length limits count characters, not bytes, at the
    /// endpoint too: 7 two-byte characters are refused (with nothing
    /// changed), 103 (203 bytes, over 128) are accepted.
    #[tokio::test]
    async fn new_password_length_is_counted_in_characters() {
        let f = fixture();
        let of_chars = |n: usize| format!("Aa1{}", "\u{e9}".repeat(n - 3));
        let req = with_body(change_request(&f), OLD_PASSWORD, &of_chars(7));
        let resp = change_password_with(Arc::clone(&f.state), req, fake_hasher).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            into_json(resp).await["detail"],
            "Password must be at least 8 characters"
        );
        assert_unchanged(&f);

        let long = of_chars(103);
        assert!(long.len() > 128);
        let req = with_body(change_request(&f), OLD_PASSWORD, &long);
        let resp = change_password_with(Arc::clone(&f.state), req, move |new: &str| {
            assert_eq!(new, of_chars(103));
            (NEW_HASH.to_string(), vec![7u8; 32])
        })
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(password_hash(&f.state), NEW_HASH);
    }

    /// Without a session to keep, a password change logs the user out
    /// everywhere — and touches no other user's sessions.
    #[test]
    fn password_change_without_a_kept_session_revokes_all_of_them() {
        let f = fixture();
        let conn = f.state.db_pool.get().unwrap();
        password_history::ensure_password_history_table(&conn).unwrap();
        let bob = crate::storage::users::tests::insert_user(&conn, "bob", "viewer", true);
        let (bobs, _) =
            sessions::create_session(&conn, bob, "", "", &SessionConfig::default()).unwrap();

        let revoked = commit_password_change(
            &conn,
            &f.credential(),
            "alice",
            "default",
            NEW_HASH,
            &[7u8; 32],
            None,
        )
        .unwrap();
        assert_eq!(revoked, PasswordCommit::Changed(2));
        drop(conn);
        assert!(!session_alive(&f.state, &f.current_session));
        assert!(!session_alive(&f.state, &f.other_session));
        assert!(session_alive(&f.state, &bobs));
        assert_eq!(password_hash(&f.state), NEW_HASH);
    }

    // ── the route itself, failure paths and cookie flags ───────────────

    /// The route handler (not the injectable `change_password_with`) stores
    /// a real credential for the new password: the new password then
    /// verifies, the old one no longer does, the old hash enters the
    /// history and the user's other sessions end.
    #[tokio::test]
    async fn the_change_password_route_stores_a_credential_for_the_new_password() {
        let f = fixture();
        let resp = change_password(State(Arc::clone(&f.state)), change_request(&f)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let conn = f.state.db_pool.get().unwrap();
        assert_eq!(
            users::verify_password(&conn, "alice", NEW_PASSWORD, "default").unwrap(),
            Some(f.user_id),
            "the new password logs in"
        );
        assert_eq!(
            users::verify_password(&conn, "alice", OLD_PASSWORD, "default").unwrap(),
            None,
            "the old password no longer does"
        );
        drop(conn);
        assert_eq!(history_len(&f.state), 1);
        assert!(session_alive(&f.state, &f.current_session));
        assert!(!session_alive(&f.state, &f.other_session));
    }

    /// A hashing step that fails (its blocking task panics) refuses the
    /// change with 500, and nothing is changed.
    #[tokio::test]
    async fn a_password_change_whose_hashing_fails_changes_nothing() {
        let f = fixture();
        let resp = change_password_with(Arc::clone(&f.state), change_request(&f), |_: &str| {
            panic!("injected hashing failure")
        })
        .await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_unchanged(&f);
    }

    /// A commit that fails part-way (here: the password-history write) is
    /// refused with 500 and leaves nothing behind — the change never lands
    /// without the history entry the reuse policy relies on.
    #[tokio::test]
    async fn a_password_change_whose_commit_fails_changes_nothing() {
        let f = fixture();
        {
            let conn = f.state.db_pool.get().unwrap();
            password_history::ensure_password_history_table(&conn).unwrap();
            conn.execute_batch(
                "CREATE TRIGGER fail_history BEFORE INSERT ON password_history \
                 BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
            )
            .unwrap();
        }
        let resp =
            change_password_with(Arc::clone(&f.state), change_request(&f), fake_hasher).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_unchanged(&f);
    }

    /// A change whose account was disabled while it ran (its sessions
    /// left in place) changes nothing: the request was authorised for an
    /// enabled account, and a disabled one keeps the password it has.
    #[tokio::test]
    async fn a_password_change_of_an_account_disabled_meanwhile_changes_nothing() {
        let f = fixture();
        let resp = change_password_around(&f, || {
            f.state
                .db_pool
                .get()
                .unwrap()
                .execute("UPDATE users SET enabled = 0 WHERE id = ?1", [f.user_id])
                .unwrap();
        })
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(into_json(resp).await["detail"], "Not authenticated");
        assert_eq!(password_hash(&f.state), f.old_hash);
        assert_eq!(history_len(&f.state), 0);
        assert_eq!(test_support::audit_count(&f.state, "password_change"), 0);
        let conn = f.state.db_pool.get().unwrap();
        assert_eq!(
            sessions::count_user_sessions(&conn, f.user_id).unwrap(),
            2,
            "no session was revoked"
        );
    }

    /// K3 under a tenant MFA policy: completing a forced change lifts the
    /// `password_change_only` restriction only as far as the policy allows.
    /// A user without MFA keeps an `mfa_setup_only` session — never a full
    /// one — and a user with MFA gets full access.
    #[tokio::test]
    async fn a_forced_change_under_a_tenant_mfa_policy_still_requires_mfa_setup() {
        for (mfa_enabled, expected_scope) in [(false, SCOPE_MFA_SETUP_ONLY), (true, "")] {
            let f = fixture();
            tenant_requires_mfa_fixture(&f.state);
            f.state
                .db_pool
                .get()
                .unwrap()
                .execute(
                    "UPDATE users SET mfa_enabled = ?1 WHERE id = ?2",
                    rusqlite::params![mfa_enabled, f.user_id],
                )
                .unwrap();
            let restricted = force_password_change(&f, true, true);
            let req = change_request_from(&f, &restricted, true, NEW_PASSWORD);
            let resp = change_password_with(Arc::clone(&f.state), req, fake_hasher).await;
            assert_eq!(resp.status(), StatusCode::OK, "mfa_enabled={mfa_enabled}");
            assert_eq!(
                session_scope(&f.state, &restricted),
                expected_scope,
                "mfa_enabled={mfa_enabled}"
            );
            assert_eq!(password_hash(&f.state), NEW_HASH);
            let conn = f.state.db_pool.get().unwrap();
            assert!(!users::must_change_password(&conn, f.user_id).unwrap());
        }
    }

    /// A login or password-change body over 4 KiB is refused with 400
    /// before any credential is checked or any attempt counted, even when
    /// the request it carries is otherwise valid (the excess is an
    /// unknown field the JSON parser would ignore).
    #[tokio::test]
    async fn oversized_auth_bodies_are_refused_before_any_check() {
        let f = fixture();
        let padding = "x".repeat(5_000);

        let body = serde_json::json!({
            "username": "alice",
            "password": OLD_PASSWORD,
            "padding": padding,
        });
        let mut req = axum::http::Request::post("/api/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(
            "198.51.100.20:5555".parse::<SocketAddr>().unwrap(),
        ));
        let resp = login(State(Arc::clone(&f.state)), req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(!sets_session_cookie(&resp));
        assert_eq!(rate_limit_rows(&f.state), 0, "no attempt recorded");
        assert_eq!(lockout_rows(&f.state, "alice"), 0, "no guess counted");

        let mut req = change_request(&f);
        *req.body_mut() = axum::body::Body::from(
            serde_json::json!({
                "current_password": OLD_PASSWORD,
                "new_password": NEW_PASSWORD,
                "padding": padding,
            })
            .to_string(),
        );
        let resp = change_password_with(Arc::clone(&f.state), req, fake_hasher).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(lockout_rows(&f.state, "alice"), 0, "no guess counted");
        assert_unchanged(&f);
    }

    /// Refuse every delete from `account_lockout`: clearing an account's
    /// counted failures then fails with a storage error.
    fn make_lockout_unclearable(state: &AppState) {
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER keep_failures BEFORE DELETE ON account_lockout \
                 BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
            )
            .unwrap();
    }

    /// A successful login whose clear of the account's counted failures
    /// fails (a storage error) still goes on and issues its session: the
    /// attempt then merely stays counted, which errs towards the lockout,
    /// never away from it. (That a successful login does clear them is
    /// `successful_login_clears_the_failure_count`.)
    #[tokio::test]
    async fn a_lockout_that_cannot_be_cleared_stays_counted() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        insert_login_user(&state, "alice");
        make_lockout_unclearable(&state);

        let resp = login(
            State(Arc::clone(&state)),
            login_as("alice", LOGIN_PASSWORD, &[]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(sets_session_cookie(&resp));
        assert_eq!(session_rows(&state), 1);
        // Not a property of the login (the trigger guarantees it): proof
        // that the injected failure took hold, so the path above is the
        // failed-clear path and not the ordinary one.
        assert_eq!(lockout_rows(&state, "alice"), 1, "the clear failed");
    }

    /// An MFA user whose challenge cannot be stored gets a 500 — never a
    /// session, a session cookie or a challenge on the password alone.
    #[tokio::test]
    async fn mfa_user_gets_no_session_when_the_challenge_cannot_be_stored() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        security_tables(&state);
        let user = insert_login_user(&state, "alice");
        let conn = state.db_pool.get().unwrap();
        conn.execute("UPDATE users SET mfa_enabled = 1 WHERE id = ?1", [user])
            .unwrap();
        conn.execute_batch(
            "CREATE TRIGGER no_challenge BEFORE INSERT ON mfa_tokens \
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .unwrap();
        drop(conn);

        let resp = login(
            State(Arc::clone(&state)),
            login_as("alice", LOGIN_PASSWORD, &[]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(cookies_of(&resp).is_empty(), "no cookie");
        assert_eq!(session_rows(&state), 0);
        assert_eq!(mfa_token_rows(&state, user), 0);
        assert_eq!(test_support::audit_count(&state, "user_login"), 0);
        assert_eq!(
            test_support::audit_count(&state, "user_login_mfa_pending"),
            0
        );
    }

    /// A logout whose session cannot be deleted says so (500) and expires
    /// no cookie: the browser is never told it logged out while its
    /// session still works.
    #[tokio::test]
    async fn a_logout_that_cannot_revoke_the_session_does_not_report_success() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user = insert_login_user(&state, "alice");
        let token = {
            let conn = state.db_pool.get().unwrap();
            conn.execute_batch(
                "CREATE TRIGGER keep_sessions BEFORE DELETE ON sessions \
                 BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
            )
            .unwrap();
            sessions::create_session(&conn, user, "", "", &SessionConfig::default())
                .unwrap()
                .0
        };
        let mut headers = HeaderMap::new();
        headers.insert("cookie", format!("session_token={token}").parse().unwrap());

        let resp = logout(State(Arc::clone(&state)), headers).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(cookies_of(&resp).is_empty(), "no cookie expired");
        assert_eq!(session_owner(&state, &token).as_deref(), Some("alice"));
        assert_eq!(test_support::audit_count(&state, "user_logout"), 0);
    }

    /// `state` with the gateway's own TLS listener configured, in
    /// `bridge_env` (`tls_enabled()` only asks whether both files are set).
    fn tls_state(dir: &tempfile::TempDir, bridge_env: &str) -> Arc<AppState> {
        let Ok(mut state) = Arc::try_unwrap(test_support::app_state(dir)) else {
            unreachable!("fresh state has one owner")
        };
        state.config.bridge_env = bridge_env.into();
        state.config.tls_cert = Some(dir.path().join("tls.crt"));
        state.config.tls_key = Some(dir.path().join("tls.key"));
        assert!(state.config.tls_enabled());
        Arc::new(state)
    }

    /// A Set-Cookie value's attributes (everything after its `name=value`
    /// pair), trimmed and lower-cased, as a browser reads them: in any
    /// order and case, e.g. `["path=/", "samesite=lax", "httponly"]`.
    fn cookie_attributes(cookie: &str) -> Vec<String> {
        cookie
            .split(';')
            .skip(1)
            .map(|attribute| attribute.trim().to_ascii_lowercase())
            .collect()
    }

    /// In production over TLS every cookie the login sets and the logout
    /// expires is `Secure` (the session cookie stays HttpOnly, the CSRF
    /// cookie script-readable). Outside production — a self-signed
    /// development listener, whose Secure cookies browsers reject — none
    /// is. The attributes are read as a browser reads them, wherever they
    /// stand in the header.
    #[tokio::test]
    async fn auth_cookies_are_secure_in_production_over_tls_only() {
        for (bridge_env, secure) in [("production", true), ("development", false)] {
            let dir = tempfile::tempdir().unwrap();
            let state = tls_state(&dir, bridge_env);
            security_tables(&state);
            insert_login_user(&state, "alice");

            let resp = login(
                State(Arc::clone(&state)),
                login_as("alice", LOGIN_PASSWORD, &[]),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK, "{bridge_env}");
            let set = cookies_of(&resp);
            let token = into_json(resp).await["session_token"]
                .as_str()
                .unwrap()
                .to_string();
            assert_eq!(set.len(), 3, "{set:?}");
            for cookie in &set {
                assert_eq!(
                    cookie_attributes(cookie).contains(&"secure".to_string()),
                    secure,
                    "{bridge_env}: {cookie}"
                );
            }
            let session = set
                .iter()
                .find(|c| c.starts_with(&format!("session_token={token};")))
                .unwrap();
            assert!(
                cookie_attributes(session).contains(&"httponly".to_string()),
                "{session}"
            );
            let csrf = set.iter().find(|c| c.starts_with("csrf_token=")).unwrap();
            assert!(
                !cookie_attributes(csrf).contains(&"httponly".to_string()),
                "{csrf}"
            );

            let mut headers = HeaderMap::new();
            headers.insert("cookie", format!("session_token={token}").parse().unwrap());
            let resp = logout(State(Arc::clone(&state)), headers).await;
            assert_eq!(resp.status(), StatusCode::OK, "{bridge_env}");
            let expired = cookies_of(&resp);
            assert_eq!(expired.len(), 3, "{expired:?}");
            for cookie in &expired {
                let attributes = cookie_attributes(cookie);
                assert!(attributes.contains(&"max-age=0".to_string()), "{cookie}");
                assert_eq!(
                    attributes.contains(&"secure".to_string()),
                    secure,
                    "{bridge_env}: {cookie}"
                );
            }
        }
    }

    /// A change whose account was deleted while it ran is 404 and writes
    /// nothing: no history row for the gone user, no audit event, and the
    /// account is not brought back.
    #[tokio::test]
    async fn a_password_change_of_an_account_deleted_meanwhile_writes_nothing() {
        let f = fixture();
        let resp = change_password_around(&f, || {
            let conn = f.state.db_pool.get().unwrap();
            conn.execute("DELETE FROM sessions WHERE user_id = ?1", [f.user_id])
                .unwrap();
            conn.execute("DELETE FROM users WHERE id = ?1", [f.user_id])
                .unwrap();
        })
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(into_json(resp).await["detail"], "User not found");
        assert_eq!(history_len(&f.state), 0, "no history written");
        assert_eq!(test_support::audit_count(&f.state, "password_change"), 0);
        let conn = f.state.db_pool.get().unwrap();
        assert!(users::get_user_full(&conn, "alice", "default")
            .unwrap()
            .is_none());
    }

    /// A reuse check that cannot run (a history entry cannot be read: its
    /// hash is stored as a blob) refuses the change with 500: an unknown
    /// answer is never taken for "not reused", although the change itself
    /// could be committed. Nothing is changed.
    #[tokio::test]
    async fn a_password_change_whose_reuse_check_fails_changes_nothing() {
        let f = fixture();
        assert!(f.state.config.password_history_count > 0);
        {
            let conn = f.state.db_pool.get().unwrap();
            password_history::ensure_password_history_table(&conn).unwrap();
            conn.execute(
                "INSERT INTO password_history (user_id, password_hash, salt, changed_at) \
                 VALUES (?1, X'00', X'00', '2026-01-01T00:00:00+00:00')",
                [f.user_id],
            )
            .unwrap();
        }
        let resp =
            change_password_with(Arc::clone(&f.state), change_request(&f), fake_hasher).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(password_hash(&f.state), f.old_hash, "password unchanged");
        assert_eq!(history_len(&f.state), 1, "only the unreadable entry");
        assert!(session_alive(&f.state, &f.current_session));
        assert!(
            session_alive(&f.state, &f.other_session),
            "nobody logged out"
        );
        assert_eq!(test_support::audit_count(&f.state, "password_change"), 0);
    }

    /// As for a login: when a right current password cannot clear the
    /// account's counted failures (a storage error), the change still
    /// lands, history and session revocation included, and the attempt
    /// merely stays counted. (That a right current password does clear
    /// them is `a_password_change_clears_the_failure_count`.)
    #[tokio::test]
    async fn a_password_change_whose_lockout_cannot_be_cleared_stays_counted() {
        let f = fixture();
        make_lockout_unclearable(&f.state);
        let resp =
            change_password_with(Arc::clone(&f.state), change_request(&f), fake_hasher).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(password_hash(&f.state), NEW_HASH);
        assert_eq!(history_len(&f.state), 1);
        assert!(session_alive(&f.state, &f.current_session));
        assert!(!session_alive(&f.state, &f.other_session));
        // Not a property of the change (the trigger guarantees it): proof
        // that the injected failure took hold, so the path above is the
        // failed-clear path and not the ordinary one.
        assert_eq!(lockout_rows(&f.state, "alice"), 1, "the clear failed");
    }
}

#[cfg(test)]
mod coverage_tests {
    //! Fail-closed and all-or-nothing paths of login, logout and password
    //! change that the main suite leaves untaken.

    use super::*;
    use crate::db::pool::DbPool;
    use crate::middleware::auth::AuthInfo;
    use crate::storage::sessions::SessionConfig;
    use crate::test_support;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use std::net::SocketAddr;
    use std::time::Duration;

    /// Golden PBKDF2 vector (see `password::tests`): the hash of
    /// `"test_password"` under a salt of 32 × 0xaa.
    const PASSWORD: &str = "test_password";
    const PASSWORD_HASH: &str = "c23370bdfca8944baf8868776098f74c72a43de350d49fc65c0d3000ab9d7669";
    const NEW_PASSWORD: &str = "New-passw0rd-battery-staple";
    /// What a test commits as the hash of the new password.
    const NEW_HASH: &str = "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface";

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

    /// An app state with the bridge's login-limiter tables.
    fn login_state(dir: &tempfile::TempDir) -> Arc<AppState> {
        let state = test_support::app_state(dir);
        sql(
            &state,
            "CREATE TABLE rate_limit_login (id INTEGER PRIMARY KEY AUTOINCREMENT, \
             client_ip TEXT NOT NULL, attempt_at REAL NOT NULL, \
             tenant_id TEXT NOT NULL DEFAULT 'default'); \
             CREATE TABLE account_lockout (id INTEGER PRIMARY KEY AUTOINCREMENT, \
             username TEXT NOT NULL, failure_at REAL NOT NULL, \
             tenant_id TEXT NOT NULL DEFAULT 'default');",
        );
        state
    }

    /// An enabled account whose password is [`PASSWORD`].
    fn insert_user(state: &AppState, username: &str) -> i64 {
        let conn = state.db_pool.get().unwrap();
        conn.execute(
            "INSERT INTO users (username, password_hash, salt, role, enabled, created_at, tenant_id) \
             VALUES (?1, ?2, ?3, 'viewer', 1, '2026-01-01T00:00:00+00:00', 'default')",
            rusqlite::params![username, PASSWORD_HASH, vec![0xaau8; 32]],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    fn new_session(pool: &DbPool, user_id: i64, scope: &str) -> String {
        sessions::create_session_scoped(
            &pool.get().unwrap(),
            user_id,
            "",
            "",
            scope,
            &SessionConfig::default(),
        )
        .unwrap()
        .0
    }

    fn session_alive(pool: &DbPool, token: &str) -> bool {
        sessions::validate_session(&pool.get().unwrap(), token, &SessionConfig::default())
            .unwrap()
            .is_some()
    }

    fn scope_of(pool: &DbPool, token: &str) -> String {
        pool.get()
            .unwrap()
            .query_row(
                "SELECT COALESCE(scope, '') FROM sessions WHERE session_token = ?1",
                [crate::auth::password::hash_session_token(token)],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn stored_hash(pool: &DbPool) -> String {
        pool.get()
            .unwrap()
            .query_row(
                "SELECT password_hash FROM users WHERE username = 'alice'",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn login_request(username: &str) -> Request<Body> {
        let body = serde_json::json!({"username": username, "password": PASSWORD});
        let mut req = Request::post("/api/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(
            "198.51.100.20:5555".parse::<SocketAddr>().unwrap(),
        ));
        req
    }

    fn signed_in(user_id: i64, token: &str) -> AuthInfo {
        AuthInfo::Session {
            username: "alice".into(),
            user_id,
            role: crate::auth::rbac::Role::Viewer,
            session_token: token.into(),
            expires_at: String::new(),
            tenant_id: "default".into(),
            scope: String::new(),
        }
    }

    fn change_request(user_id: i64, token: &str) -> Request<Body> {
        let body = serde_json::json!({
            "current_password": PASSWORD,
            "new_password": NEW_PASSWORD,
        });
        let mut req = Request::post("/api/auth/change-password")
            .body(Body::from(body.to_string()))
            .unwrap();
        req.extensions_mut().insert(signed_in(user_id, token));
        req
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        headers
    }

    async fn json_of(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
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

    /// A tenant MFA policy that cannot be read (a stored value no boolean
    /// reads; only a missing table means "no policy") refuses the login
    /// after its password check: no session, no cookie — a full-scope
    /// session must not be issued on a policy nobody could check. Once the
    /// policy reads, it applies.
    #[tokio::test]
    async fn login_fails_closed_when_the_tenant_mfa_policy_cannot_be_read() {
        let dir = tempfile::tempdir().unwrap();
        let state = login_state(&dir);
        insert_user(&state, "alice");
        // BOOLEAN has NUMERIC affinity: 'yes' is stored as TEXT.
        sql(
            &state,
            "CREATE TABLE tenant_settings (tenant_id TEXT PRIMARY KEY, \
             mfa_required BOOLEAN NOT NULL DEFAULT 0, updated_at TEXT NOT NULL DEFAULT ''); \
             INSERT INTO tenant_settings VALUES ('default', 'yes', '');",
        );

        let resp = login(State(Arc::clone(&state)), login_request("alice")).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!resp.headers().contains_key(header::SET_COOKIE));
        assert_eq!(count(&state.db_pool, "SELECT COUNT(*) FROM sessions"), 0);
        assert_eq!(test_support::audit_count(&state, "user_login"), 0);

        sql(&state, "UPDATE tenant_settings SET mfa_required = 1");
        let resp = login(State(Arc::clone(&state)), login_request("alice")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_of(resp).await;
        assert_eq!(body["mfa_setup_required"], true);
        let token = body["session_token"].as_str().unwrap();
        assert_eq!(scope_of(&state.db_pool, token), SCOPE_MFA_SETUP_ONLY);
    }

    /// `UC_MAX_SESSIONS_PER_USER=0` means no cap, not "keep none": a login
    /// then evicts no session, its own and the earlier ones all work.
    #[tokio::test]
    async fn a_session_cap_of_zero_evicts_no_session() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = Arc::into_inner(login_state(&dir)).expect("a fresh state has one owner");
        state.config.max_sessions_per_user = 0;
        let state = Arc::new(state);
        let user_id = insert_user(&state, "alice");
        let mut tokens: Vec<String> = (0..3)
            .map(|_| new_session(&state.db_pool, user_id, ""))
            .collect();

        let resp = login(State(Arc::clone(&state)), login_request("alice")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        tokens.push(
            json_of(resp).await["session_token"]
                .as_str()
                .unwrap()
                .to_string(),
        );
        let conn = state.db_pool.get().unwrap();
        assert_eq!(sessions::count_user_sessions(&conn, user_id).unwrap(), 4);
        drop(conn);
        assert!(tokens.iter().all(|t| session_alive(&state.db_pool, t)));
    }

    /// Logout of `alice`'s new session on `state`: it ends the session and
    /// expires its cookie, and leaves `records` audit records.
    async fn assert_logout_with_audit_records(state: &Arc<AppState>, records: i64) {
        let user_id = insert_user(state, "alice");
        let token = new_session(&state.db_pool, user_id, "");
        let resp = logout(State(Arc::clone(state)), bearer(&token)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let expired = expire_cookie(crate::middleware::auth::SESSION_COOKIE, false);
        assert!(resp
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|cookie| cookie == expired.as_str()));
        assert!(!session_alive(&state.db_pool, &token), "the session ended");
        assert_eq!(test_support::audit_count(state, "user_logout"), records);
    }

    /// Audit logging is best effort: a logout whose record cannot be
    /// signed (production without an audit key) or cannot be written still
    /// ends the session and clears its cookies.
    #[tokio::test]
    async fn logout_ends_the_session_when_its_audit_record_cannot_be_kept() {
        // Without a configured key, production signs with a legacy
        // fallback from the environment if one is set (CI sets none).
        let signed_without_key = i64::from(audit_chain::get_audit_secret("", "production").is_ok());
        let dir = tempfile::tempdir().unwrap();
        let mut unsigned =
            Arc::into_inner(test_support::app_state(&dir)).expect("a fresh state has one owner");
        unsigned.config.bridge_env = "production".into();
        unsigned.config.audit_key = String::new();
        assert_logout_with_audit_records(&Arc::new(unsigned), signed_without_key).await;

        let dir = tempfile::tempdir().unwrap();
        let unwritable = test_support::app_state(&dir);
        sql(
            &unwritable,
            "CREATE TRIGGER no_audit BEFORE INSERT ON audit_log \
             BEGIN SELECT RAISE(ABORT, 'audit log unavailable'); END;",
        );
        assert_logout_with_audit_records(&unwritable, 0).await;
    }

    /// Without a database connection every auth endpoint answers 503 and
    /// records, ends or changes nothing: no login attempt is counted, the
    /// logout keeps the cookies its retry needs and the session lives on,
    /// the password stays.
    #[tokio::test]
    async fn auth_endpoints_answer_503_when_the_database_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let state = login_state(&dir);
        let user_id = insert_user(&state, "alice");
        let token = new_session(&state.db_pool, user_id, "");
        let (state, database) = without_database(state);
        let unavailable = StatusCode::SERVICE_UNAVAILABLE;

        let resp = login(State(Arc::clone(&state)), login_request("alice")).await;
        assert_eq!(resp.status(), unavailable, "login");
        assert!(!resp.headers().contains_key(header::SET_COOKIE));

        let mut headers = bearer(&token);
        headers.insert(
            header::COOKIE,
            format!("session_token={token}; csrf_token=c")
                .parse()
                .unwrap(),
        );
        let resp = logout(State(Arc::clone(&state)), headers).await;
        assert_eq!(resp.status(), unavailable, "logout");
        assert!(!resp.headers().contains_key(header::SET_COOKIE));

        let mut req = Request::get("/api/auth/me").body(Body::empty()).unwrap();
        req.extensions_mut().insert(signed_in(user_id, &token));
        assert_eq!(
            me(State(Arc::clone(&state)), req).await.status(),
            unavailable
        );

        let resp =
            change_password(State(Arc::clone(&state)), change_request(user_id, &token)).await;
        assert_eq!(resp.status(), unavailable, "change-password");

        assert!(session_alive(&database, &token));
        assert_eq!(count(&database, "SELECT COUNT(*) FROM rate_limit_login"), 0);
        assert_eq!(count(&database, "SELECT COUNT(*) FROM account_lockout"), 0);
        assert_eq!(stored_hash(&database), PASSWORD_HASH);
    }

    /// A current-password check that cannot run (its account table is
    /// unreadable) refuses the change with 500, changes nothing, and the
    /// attempt reserved before it stays counted toward the lockout.
    #[tokio::test]
    async fn a_current_password_check_that_cannot_run_refuses_the_change() {
        let dir = tempfile::tempdir().unwrap();
        let state = login_state(&dir);
        let user_id = insert_user(&state, "alice");
        let token = new_session(&state.db_pool, user_id, "");
        sql(&state, "ALTER TABLE users RENAME TO users_unavailable");

        let resp =
            change_password(State(Arc::clone(&state)), change_request(user_id, &token)).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            count(
                &state.db_pool,
                "SELECT COUNT(*) FROM account_lockout WHERE username = 'alice'"
            ),
            1,
            "the attempt stays counted"
        );
        let unchanged = format!(
            "SELECT COUNT(*) FROM users_unavailable WHERE password_hash = '{PASSWORD_HASH}'"
        );
        assert_eq!(count(&state.db_pool, &unchanged), 1);
        assert_eq!(test_support::audit_count(&state, "password_change"), 0);
    }

    /// `alice` (password [`PASSWORD`]) with the session making the change
    /// (in `scope`) and another one, and the password history table.
    struct Account {
        user_id: i64,
        current: String,
        other: String,
    }

    fn account(state: &AppState, scope: &str) -> Account {
        let user_id = insert_user(state, "alice");
        password_history::ensure_password_history_table(&state.db_pool.get().unwrap()).unwrap();
        Account {
            user_id,
            current: new_session(&state.db_pool, user_id, scope),
            other: new_session(&state.db_pool, user_id, ""),
        }
    }

    /// What verifying [`PASSWORD`] for account `user_id` yields.
    fn credential(user_id: i64) -> users::VerifiedCredential {
        users::VerifiedCredential {
            user_id,
            password_hash: PASSWORD_HASH.into(),
        }
    }

    fn commit(
        state: &AppState,
        credential: &users::VerifiedCredential,
        keep_session: &str,
    ) -> Result<PasswordCommit, rusqlite::Error> {
        commit_password_change(
            &state.db_pool.get().unwrap(),
            credential,
            "alice",
            "default",
            NEW_HASH,
            &[7u8; 32],
            Some(keep_session),
        )
    }

    /// The password, the history and both sessions are as `account` left them.
    #[track_caller]
    fn assert_unchanged(state: &AppState, account: &Account) {
        assert_eq!(stored_hash(&state.db_pool), PASSWORD_HASH);
        assert_eq!(
            count(&state.db_pool, "SELECT COUNT(*) FROM password_history"),
            0
        );
        assert!(session_alive(&state.db_pool, &account.current));
        assert!(session_alive(&state.db_pool, &account.other));
    }

    /// The account the request verified was deleted and another created
    /// under its name — with the very same password hash, so only the
    /// account id tells them apart. The change must not land on the new
    /// account.
    #[test]
    fn a_password_change_never_lands_on_an_account_recreated_under_its_name() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let deleted = insert_user(&state, "alice");
        sql(&state, &format!("DELETE FROM users WHERE id = {deleted}"));
        let recreated = account(&state, "");
        assert_ne!(recreated.user_id, deleted);

        assert_eq!(
            commit(&state, &credential(deleted), &recreated.current).unwrap(),
            PasswordCommit::CredentialChanged
        );
        assert_unchanged(&state, &recreated);
    }

    /// Every way the commit can stop after it began writes nothing: the
    /// password write landing on no row (the account went away under the
    /// lock, emulated by a trigger that skips the row) is "no such user"
    /// with the history entry rolled back; a failure lifting a forced
    /// change's restriction, and a session check that cannot be made, are
    /// errors that leave the password, the history, the restriction and
    /// the other sessions as they were.
    #[test]
    fn a_password_change_whose_commit_cannot_finish_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let lost = account(&state, "");
        sql(
            &state,
            "CREATE TRIGGER password_write_lost BEFORE UPDATE OF password_hash ON users \
             BEGIN SELECT RAISE(IGNORE); END;",
        );
        assert_eq!(
            commit(&state, &credential(lost.user_id), &lost.current).unwrap(),
            PasswordCommit::NoSuchUser
        );
        assert_unchanged(&state, &lost);

        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let forced = account(&state, SCOPE_PASSWORD_CHANGE_ONLY);
        sql(
            &state,
            "CREATE TRIGGER scope_locked BEFORE UPDATE OF scope ON sessions \
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        );
        assert!(commit(&state, &credential(forced.user_id), &forced.current).is_err());
        assert_unchanged(&state, &forced);
        assert_eq!(
            scope_of(&state.db_pool, &forced.current),
            SCOPE_PASSWORD_CHANGE_ONLY
        );

        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let unchecked = account(&state, "");
        sql(
            &state,
            "ALTER TABLE sessions RENAME TO sessions_unavailable",
        );
        assert!(commit(&state, &credential(unchecked.user_id), &unchecked.current).is_err());
        sql(
            &state,
            "ALTER TABLE sessions_unavailable RENAME TO sessions",
        );
        assert_unchanged(&state, &unchecked);
    }

    /// The reuse check of an account deleted since its password was
    /// verified matches nothing (no stored credential to compare with),
    /// and the commit then finds no such user and writes nothing.
    #[test]
    fn the_reuse_check_of_an_account_deleted_since_its_verification_matches_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let user_id = insert_user(&state, "alice");
        let conn = state.db_pool.get().unwrap();
        let forced = ReuseCheck {
            user_id,
            username: "alice".into(),
            tenant_id: "default".into(),
            history_count: 0,
            restricted_session: true,
        };
        assert!(forced.refuses(&conn, PASSWORD).unwrap(), "control");

        conn.execute("DELETE FROM users WHERE id = ?1", [user_id])
            .unwrap();
        assert!(!forced.refuses(&conn, PASSWORD).unwrap());
        assert_eq!(
            commit_password_change(
                &conn,
                &credential(user_id),
                "alice",
                "default",
                NEW_HASH,
                &[7u8; 32],
                None,
            )
            .unwrap(),
            PasswordCommit::NoSuchUser
        );
        assert_eq!(
            count(&state.db_pool, "SELECT COUNT(*) FROM password_history"),
            0
        );
    }
}
