//! Auth middleware — session + API key validation, session binding, response headers.
//!
//! Replicates Python's `require_api_key()` and `_try_session_auth()` from dependencies.py.
//! Injects `AuthInfo` into request extensions for downstream handlers.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tracing::{debug, warn};

use crate::auth::api_key;
use crate::auth::rbac::Role;
use crate::storage::security_state::SecurityLimits;
use crate::storage::sessions::{self, SessionConfig, ValidatedSession};
use crate::AppState;

use super::client_ip::{client_ip_of, extract_client_ip, ClientIp, TrustedProxies};

// ── Session scopes ────────────────────────────────────────────────────

/// Session scope of a user the tenant requires to set up MFA: only the MFA
/// endpoints and logout are allowed.
pub const SCOPE_MFA_SETUP_ONLY: &str = "mfa_setup_only";
/// Session scope of a user who must change their password (K3): only
/// change-password, logout and "who am I" are allowed.
pub const SCOPE_PASSWORD_CHANGE_ONLY: &str = "password_change_only";

/// Paths served without credentials, which ignore any the request carries:
/// the health/version probes and both login steps (password, then MFA
/// code). A browser can still hold an earlier restricted session cookie
/// (`password_change_only`, `mfa_setup_only`, an unknown scope) when a user
/// logs in; resolving it here would let that session's scope refuse the
/// login with 403 before the handler runs. Neither login handler reads
/// [`AuthInfo`]; they get the client IP from the [`ClientIp`] extension.
const UNAUTHENTICATED_PATHS: &[&str] = &[
    "/health",
    "/api/version",
    "/api/auth/login",
    "/api/auth/mfa/verify",
];

/// True for what a browser loads as a page or asset — a `GET`/`HEAD`
/// outside `/api` and `/ws` (`/`, `/login`, `/static/…`, `/favicon.ico`).
/// With a restricted session these are served as anonymous requests rather
/// than refused: the bridge serves its login page and static files to
/// anyone, and its pages send a visitor without a full session to
/// `/login`, so a user who must change their password (or set up MFA) can
/// always get back to the form. The restricted session is not passed on.
fn is_page_request(method: &axum::http::Method, path: &str) -> bool {
    if !(method == axum::http::Method::GET || method == axum::http::Method::HEAD) {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    !["/api", "/ws"]
        .iter()
        .any(|prefix| lower == *prefix || lower.starts_with(&format!("{prefix}/")))
}

/// Paths a [`SCOPE_PASSWORD_CHANGE_ONLY`] session may use (same list as the
/// bridge's `require_api_key`).
const PASSWORD_CHANGE_ALLOWED: &[&str] = &[
    "/api/auth/change-password",
    "/api/auth/logout",
    "/api/auth/me",
];

/// The 403 for a request outside its session's scope, or `None` when the
/// scope allows `path`. An unknown non-empty scope is treated as the most
/// restrictive one (fail closed): only logout and "who am I".
fn scope_violation(scope: &str, path: &str) -> Option<Response> {
    let detail = match scope {
        "" => return None,
        SCOPE_MFA_SETUP_ONLY => {
            if path.starts_with("/api/auth/mfa/") || path == "/api/auth/logout" {
                return None;
            }
            "MFA setup required before accessing other endpoints"
        }
        SCOPE_PASSWORD_CHANGE_ONLY => {
            if PASSWORD_CHANGE_ALLOWED.contains(&path) {
                return None;
            }
            "password change required"
        }
        other => {
            if path == "/api/auth/logout" || path == "/api/auth/me" {
                return None;
            }
            warn!(scope = other, "Session has an unknown scope — refusing");
            "session scope does not allow this request"
        }
    };
    Some(
        (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({ "detail": detail })),
        )
            .into_response(),
    )
}

// ── Client-supplied trust headers ─────────────────────────────────────

/// True for headers only the gateway may set: `x-rust-proxy` (the proxy
/// secret), `x-auth-*` (the identity it verified) and `x-license-*` (the
/// licence its resolver decided). The bridge trusts them because they come
/// from the gateway.
fn is_gateway_owned_header(name: &str) -> bool {
    name == "x-rust-proxy" || name.starts_with("x-auth-") || name.starts_with("x-license-")
}

/// Remove every client-supplied gateway-owned header at ingress, before
/// any handler, proxy or WebSocket upgrade can see or forward it. (The
/// proxy also skips its own trust headers; this covers every route and
/// the `x-license-*` family, which the proxy only overwrites when the
/// resolver produces a value — e.g. `X-License-Node-Limit` passed through
/// when the resolver returned none.)
fn strip_gateway_owned_headers(headers: &mut HeaderMap) {
    let forged: Vec<_> = headers
        .keys()
        .filter(|name| is_gateway_owned_header(name.as_str()))
        .cloned()
        .collect();
    for name in forged {
        debug!(header = %name, "Dropping client-supplied gateway-owned header");
        headers.remove(&name);
    }
}

// ── Types ─────────────────────────────────────────────────────────────

/// Authentication info injected into request extensions.
#[derive(Debug, Clone)]
pub enum AuthInfo {
    Session {
        username: String,
        user_id: i64,
        role: Role,
        session_token: String,
        expires_at: String,
        tenant_id: String,
        scope: String,
    },
    ApiKey {
        key_id: String,
        role: Role,
    },
    Unauthenticated,
}

impl AuthInfo {
    pub fn role(&self) -> Option<Role> {
        match self {
            AuthInfo::Session { role, .. } => Some(*role),
            AuthInfo::ApiKey { role, .. } => Some(*role),
            AuthInfo::Unauthenticated => None,
        }
    }
}

/// Session binding enforcement mode.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionBindingMode {
    /// Reject if IP or User-Agent changes.
    Strict,
    /// Reject on IP mismatch only (default).
    Ip,
    /// Log warning but allow.
    Warn,
    /// No binding check.
    None,
}

impl From<&str> for SessionBindingMode {
    /// Parse a `BRIDGE_SESSION_BINDING` value; unknown values mean `Ip`.
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "strict" => Self::Strict,
            "warn" => Self::Warn,
            "none" => Self::None,
            _ => Self::Ip,
        }
    }
}

/// Auth configuration built from Config at startup.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub session_config: SessionConfig,
    pub security_limits: SecurityLimits,
    pub binding_mode: SessionBindingMode,
    pub csrf_enabled: bool,
    pub trusted_proxies: TrustedProxies,
}

// ── Middleware ─────────────────────────────────────────────────────────

/// Auth middleware: validates session tokens and API keys, injects AuthInfo.
///
/// Also, for every request: drops client-supplied gateway-owned headers
/// (`x-rust-proxy`, `x-auth-*`, `x-license-*`), resolves the client IP once
/// through the trusted proxies and records it as a [`ClientIp`] extension,
/// and enforces restricted session scopes ([`SCOPE_MFA_SETUP_ONLY`],
/// [`SCOPE_PASSWORD_CHANGE_ONLY`]) on every route, native or proxied.
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    strip_gateway_owned_headers(req.headers_mut());

    // Read auth config once, clone what we need, drop lock before calling next
    let (session_config, binding_mode, trusted_proxies) = {
        let cfg = state.auth_config.read().await;
        (
            cfg.session_config.clone(),
            cfg.binding_mode.clone(),
            cfg.trusted_proxies.clone(),
        )
    };
    let client_ip = extract_client_ip(&req, &trusted_proxies);
    req.extensions_mut().insert(ClientIp(client_ip));

    // Health/version probes and the login steps: no credential resolution,
    // so no session scope applies (see UNAUTHENTICATED_PATHS).
    if UNAUTHENTICATED_PATHS.contains(&path.as_str()) {
        req.extensions_mut().insert(AuthInfo::Unauthenticated);
        let mut resp = next.run(req).await;
        mark_no_store(&path, &mut resp);
        return resp;
    }

    // Synchronous part first (session, client cert). Bound to a local so
    // no borrow of `req` is held across the API-key validation await.
    let pre_auth = resolve_auth(
        &state.db_pool,
        state.auth_enabled,
        state.cert_registry.as_deref(),
        &session_config,
        &binding_mode,
        &trusted_proxies,
        &req,
    );
    let mut auth_info = match pre_auth {
        PreAuth::Resolved(info) => info,
        PreAuth::ApiKey(key) => match validate_api_key(state.key_store.as_ref(), &key).await {
            Ok(info) => info,
            Err(status) => return status.into_response(),
        },
        PreAuth::Refused(status) => return status.into_response(),
    };

    // Scope enforcement for restricted sessions (MFA setup, forced
    // password change) — before any handler or the proxy runs. Browser
    // pages and assets are served without the session instead (see
    // `is_page_request`).
    let restricted = matches!(&auth_info, AuthInfo::Session { scope, .. } if !scope.is_empty());
    if restricted && is_page_request(req.method(), &path) {
        debug!(path = %path, "Restricted session: page served anonymously");
        auth_info = AuthInfo::Unauthenticated;
    } else if let AuthInfo::Session { ref scope, .. } = auth_info {
        if let Some(forbidden) = scope_violation(scope, &path) {
            return forbidden;
        }
    }
    let is_session = matches!(&auth_info, AuthInfo::Session { .. });
    let expires_at = if let AuthInfo::Session { ref expires_at, .. } = auth_info {
        Some(expires_at.clone())
    } else {
        None
    };

    req.extensions_mut().insert(auth_info);

    let mut resp = next.run(req).await;
    mark_no_store(&path, &mut resp);

    // Add session expiry headers
    if is_session {
        if let Some(ref exp_str) = expires_at {
            if let Some(remaining) = compute_remaining_seconds(exp_str) {
                if let Ok(val) = HeaderValue::from_str(&remaining.to_string()) {
                    resp.headers_mut().insert("x-session-expires-in", val);
                }
                if remaining < 300 {
                    resp.headers_mut().insert(
                        "x-session-warning",
                        HeaderValue::from_static("expiring-soon"),
                    );
                }
            }
        }
    }

    resp
}

/// Cache-Control on auth responses (they carry session tokens and cookies).
fn mark_no_store(path: &str, resp: &mut Response) {
    if path.starts_with("/api/auth/") {
        resp.headers_mut().insert(
            "cache-control",
            HeaderValue::from_static("no-store, no-cache, must-revalidate"),
        );
        resp.headers_mut()
            .insert("pragma", HeaderValue::from_static("no-cache"));
    }
}

/// Outcome of the synchronous part of auth resolution.
enum PreAuth {
    Resolved(AuthInfo),
    Refused(StatusCode),
    /// No session or client cert matched; this API key still needs
    /// validating (async — PBKDF2 runs on the blocking pool).
    ApiKey(String),
}

// Auth inputs are unpacked from AppState + the auth-config lock at the
// call site; threading them individually keeps resolve_auth a pure
// function.
fn resolve_auth(
    db_pool: &crate::db::pool::DbPool,
    auth_enabled: bool,
    cert_registry: Option<&crate::auth::client_cert::CertRegistry>,
    session_config: &SessionConfig,
    binding_mode: &SessionBindingMode,
    trusted_proxies: &TrustedProxies,
    req: &Request<Body>,
) -> PreAuth {
    // Try session auth first
    if let Some(token) = extract_session_token(req) {
        match try_session_auth(
            db_pool,
            session_config,
            binding_mode,
            trusted_proxies,
            req,
            &token,
        ) {
            Ok(Some(info)) => return PreAuth::Resolved(info),
            Err(status) => return PreAuth::Refused(status),
            Ok(None) => {}
        }
    }

    // Client-certificate auth (PKI mTLS) — additive. `resolve_client_cert`
    // returns None whenever an API key is present, so the API-key path
    // below keeps working unchanged: API keys and client certs coexist.
    if auth_enabled {
        if let Some(info) = resolve_client_cert(req, cert_registry) {
            return PreAuth::Resolved(info);
        }
    }

    // Fall back to API key
    if auth_enabled {
        if let Some(key_str) = api_key::extract_api_key(req) {
            return PreAuth::ApiKey(key_str);
        }
    }

    PreAuth::Resolved(AuthInfo::Unauthenticated)
}

async fn validate_api_key(
    key_store: Option<&api_key::KeyStore>,
    key: &str,
) -> Result<AuthInfo, StatusCode> {
    let Some(ks) = key_store else {
        return Ok(AuthInfo::Unauthenticated);
    };
    match ks.validate_for_instance(key).await {
        Ok(Some((key_id, role))) => Ok(AuthInfo::ApiKey { key_id, role }),
        Ok(None) => Ok(AuthInfo::Unauthenticated),
        Err(_) => Err(StatusCode::FORBIDDEN),
    }
}

/// Resolve a verified client certificate to an [`AuthInfo`].
///
/// rustls has already proven any presented certificate chains to the
/// configured CA; this maps the cert identity to a role via the bridge
/// CA registry.
///
/// Returns `None` — deferring to the API-key path — when:
/// - the request carries an `X-API-Key` header (API-key auth takes
///   precedence, so enabling PKI never breaks an API-key client, even
///   one connecting over an mTLS-capable listener);
/// - no client certificate was presented;
/// - the cert identity is unknown, revoked, or expired.
fn resolve_client_cert(
    req: &Request<Body>,
    cert_registry: Option<&crate::auth::client_cert::CertRegistry>,
) -> Option<AuthInfo> {
    if api_key::extract_api_key(req).is_some() {
        return None;
    }
    let cert = req
        .extensions()
        .get::<crate::auth::client_cert::ClientCertInfo>()?;
    match cert_registry.and_then(|reg| reg.lookup(cert)) {
        Some(role) => Some(AuthInfo::ApiKey {
            key_id: cert.identity.clone(),
            role,
        }),
        None => {
            warn!(
                identity = %cert.identity,
                serial = %cert.serial,
                "Client cert presented but unknown, mismatched, revoked, or expired"
            );
            None
        }
    }
}

/// The verified client certificate that authenticated `req`, if one did:
/// the middleware resolved an [`AuthInfo::ApiKey`] and the request carries
/// no API key, so [`resolve_client_cert`] decided (it defers to any API key
/// on the request). A browser presents a certificate it holds on any TLS
/// handshake to this host, so this is an ambient credential, as the session
/// cookie is.
pub(crate) fn authenticating_client_cert(
    req: &Request<Body>,
) -> Option<&crate::auth::client_cert::ClientCertInfo> {
    if !matches!(
        req.extensions().get::<AuthInfo>(),
        Some(AuthInfo::ApiKey { .. })
    ) || api_key::extract_api_key(req).is_some()
    {
        return None;
    }
    req.extensions()
        .get::<crate::auth::client_cert::ClientCertInfo>()
}

fn try_session_auth(
    db_pool: &crate::db::pool::DbPool,
    session_config: &SessionConfig,
    binding_mode: &SessionBindingMode,
    trusted_proxies: &TrustedProxies,
    req: &Request<Body>,
    token: &str,
) -> Result<Option<AuthInfo>, StatusCode> {
    let conn = db_pool.get().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if !sessions::session_belongs_to_instance(&conn, token)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let Some(session) = sessions::validate_session(&conn, token, session_config)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    else {
        return Ok(None);
    };

    // Session binding check
    if !check_session_binding(binding_mode, trusted_proxies, req, &session) {
        return Ok(None);
    }

    let role = session.role.parse::<Role>().unwrap_or(Role::Viewer);

    Ok(Some(AuthInfo::Session {
        username: session.username,
        user_id: session.user_id,
        role,
        session_token: token.to_string(),
        expires_at: session.expires_at,
        tenant_id: session.tenant_id,
        scope: session.scope,
    }))
}

fn check_session_binding(
    mode: &SessionBindingMode,
    trusted_proxies: &TrustedProxies,
    req: &Request<Body>,
    session: &ValidatedSession,
) -> bool {
    if *mode == SessionBindingMode::None {
        return true;
    }

    let current_ip = client_ip_of(req, trusted_proxies);
    let current_ua = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let ip_mismatch = !session.ip_address.is_empty() && current_ip != session.ip_address;
    let ua_mismatch = !session.user_agent.is_empty() && current_ua != session.user_agent;

    match mode {
        SessionBindingMode::Strict => {
            if ip_mismatch || ua_mismatch {
                warn!(
                    username = session.username,
                    stored_ip = session.ip_address,
                    current_ip = current_ip,
                    "Session binding rejected (strict): IP or UA mismatch"
                );
                return false;
            }
        }
        SessionBindingMode::Ip => {
            if ip_mismatch {
                warn!(
                    username = session.username,
                    stored_ip = session.ip_address,
                    current_ip = current_ip,
                    "Session binding rejected (ip): IP mismatch"
                );
                return false;
            }
        }
        SessionBindingMode::Warn => {
            if ip_mismatch || ua_mismatch {
                debug!(
                    username = session.username,
                    ip_mismatch, ua_mismatch, "Session binding mismatch (warn mode, allowed)"
                );
            }
        }
        SessionBindingMode::None => {}
    }

    true
}

// ── Token extraction ──────────────────────────────────────────────────

/// `Authorization: Bearer `: the scheme and the one space after it.
const BEARER_PREFIX: &str = "Bearer ";

/// The credential of an `Authorization: Bearer <credential>` header: what
/// follows the scheme and its space, without the whitespace around it
/// (empty when nothing else follows). `None` without an `Authorization`
/// header, for another scheme, or when no space follows the scheme.
///
/// The scheme is matched in any letter case (`bearer`, `BEARER`; RFC 9110
/// §11.1), as the bridge's `_extract_session_token` matches it. The shared
/// table `testdata/session_token_parity.json` pins both sides. Every
/// reader of a bearer credential goes through this: the session lookup
/// ([`extract_session_token`]), API keys, logout and the WebSocket origin
/// rule. When only the bridge read `bearer <token>`, the gateway took such
/// a request for an anonymous one and proxied it without its own session
/// checks.
pub fn bearer_credential(headers: &HeaderMap) -> Option<&str> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, credential) = value.split_at_checked(BEARER_PREFIX.len())?;
    if !scheme.eq_ignore_ascii_case(BEARER_PREFIX) {
        return None;
    }
    Some(credential.trim())
}

/// Extract a session token from the request (see
/// [`session_token_from_headers`]).
pub fn extract_session_token(req: &Request<Body>) -> Option<String> {
    session_token_from_headers(req.headers())
}

/// The name of the session cookie.
pub const SESSION_COOKIE: &str = "session_token";

/// One `name=value` pair of a `Cookie` field (the text between two `;`),
/// read as the bridge reads it (Starlette's `cookie_parser`): the name is
/// what precedes the first `=`, the value what follows it, each without
/// the whitespace around it. `None` for a pair without `=`, which names
/// no cookie the gateway or the bridge looks up.
///
/// So `session_token =<token>` and `session_token\t=<token>` are the
/// session cookie, as `session_token=<token>` is: the gateway resolves
/// them ([`session_token_from_headers`]) and the proxy forwards none of
/// them. When the gateway matched the cookie as `session_token=` exactly,
/// it neither resolved nor dropped `session_token =<token>`, and the
/// bridge, which trims the name, accepted the token without the
/// gateway's IP binding check.
///
/// Only a field that is visible ASCII (`HeaderValue::to_str`) is read, so
/// space and tab are the only whitespace here, which Rust's `trim` and
/// Python's `strip` both remove. The gateway forwards no other field.
pub fn cookie_pair(pair: &str) -> Option<(&str, &str)> {
    let (name, value) = pair.split_once('=')?;
    Some((name.trim(), value.trim()))
}

/// The session token in these headers, checking (in order):
/// 1. `Authorization: Bearer <token>` (the scheme in any letter case, see
///    [`bearer_credential`])
/// 2. `X-Session-Token` header
/// 3. `session_token` cookie (its name read as the bridge reads it, see
///    [`cookie_pair`]); the first one with a value, in every `Cookie`
///    field in order
///
/// An empty value is skipped. The shared table
/// `testdata/session_token_parity.json` pins the bridge's
/// `_extract_session_token` to the same reading.
pub fn session_token_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(token) = bearer_credential(headers).filter(|token| !token.is_empty()) {
        return Some(token.to_string());
    }

    // X-Session-Token header
    if let Some(val) = headers.get("x-session-token") {
        if let Ok(s) = val.to_str() {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }

    // session_token cookie
    // HTTP/2 may split cookies across multiple Cookie fields.
    for cookie_header in headers.get_all("cookie").iter() {
        if let Ok(cookies) = cookie_header.to_str() {
            for (name, value) in cookies.split(';').filter_map(cookie_pair) {
                if name == SESSION_COOKIE && !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }

    None
}

// ── Auth requirement helper ───────────────────────────────────────────

/// Check that the request has valid auth with at least the given role.
/// Read `AuthInfo` from request extensions (set by auth_middleware).
pub fn require_auth(req: &Request<Body>, min_role: Role) -> Result<AuthInfo, StatusCode> {
    let info = req
        .extensions()
        .get::<AuthInfo>()
        .cloned()
        .unwrap_or(AuthInfo::Unauthenticated);

    match &info {
        AuthInfo::Unauthenticated => Err(StatusCode::UNAUTHORIZED),
        AuthInfo::Session { role, .. } | AuthInfo::ApiKey { role, .. } => {
            if role.has_at_least(min_role) {
                Ok(info)
            } else {
                Err(StatusCode::FORBIDDEN)
            }
        }
    }
}

// ── Role ceilings (contract K5) ───────────────────────────────────────

fn ceiling_forbidden(detail: String) -> Response {
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({ "detail": detail })),
    )
        .into_response()
}

/// K5: refuse (403) unless the caller may give a `what` ("key", "user")
/// the role `target` — never above its own role, KEYMASTER only by a
/// KEYMASTER.
#[allow(clippy::result_large_err)] // the Err is the ready-made response
pub fn require_may_grant(auth: &AuthInfo, target: Role, what: &str) -> Result<(), Response> {
    let caller = auth.role().unwrap_or(Role::Sensor);
    if caller.may_grant(target) {
        return Ok(());
    }
    warn!(%caller, %target, what, "Role ceiling: assignment refused");
    Err(ceiling_forbidden(if target == Role::Keymaster {
        "Only KEYMASTER can assign the keymaster role".to_string()
    } else {
        format!("Cannot give a {what} a role above your own")
    }))
}

/// K5: refuse (403) unless the caller may change a `what` that currently
/// holds role `existing` (no managing — resetting, rotating, disabling,
/// re-roling — a principal above the caller's own role).
#[allow(clippy::result_large_err)] // the Err is the ready-made response
pub fn require_may_manage(auth: &AuthInfo, existing: Role, what: &str) -> Result<(), Response> {
    let caller = auth.role().unwrap_or(Role::Sensor);
    if caller.may_manage(existing) {
        return Ok(());
    }
    warn!(%caller, %existing, what, "Role ceiling: change refused");
    Err(ceiling_forbidden(format!(
        "Cannot modify a {what} with a role above your own"
    )))
}

// ── Helpers ───────────────────────────────────────────────────────────

/// Seconds until `expires_at`, read with the parser `validate_session`
/// enforces the expiry with, so every expiry it accepts gets the header.
/// It is computed after the handler, so a session that expired while the
/// request was served reports 0, as the bridge does, never a negative.
fn compute_remaining_seconds(expires_at: &str) -> Option<i64> {
    let exp = sessions::parse_iso_datetime(expires_at)?;
    Some((exp - chrono::Utc::now()).num_seconds().max(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    fn make_req() -> Request<Body> {
        Request::builder().uri("/test").body(Body::empty()).unwrap()
    }

    #[test]
    fn test_extract_bearer_token() {
        let req = Request::builder()
            .uri("/test")
            .header("authorization", "Bearer my-session-token")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_session_token(&req), Some("my-session-token".into()));
    }

    #[test]
    fn test_extract_x_session_token() {
        let req = Request::builder()
            .uri("/test")
            .header("x-session-token", "tok123")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_session_token(&req), Some("tok123".into()));
    }

    #[test]
    fn test_extract_cookie_token() {
        let req = Request::builder()
            .uri("/test")
            .header("cookie", "other=abc; session_token=fromcookie; foo=bar")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_session_token(&req), Some("fromcookie".into()));
    }

    #[test]
    fn test_extract_session_from_split_cookie_fields() {
        let req = Request::builder()
            .uri("/test")
            .version(axum::http::Version::HTTP_2)
            .header("cookie", "csrf_token=csrf; theme=dark")
            .header("cookie", "session_token=fromcookie")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_session_token(&req), Some("fromcookie".into()));
    }

    #[test]
    fn test_bearer_takes_priority_over_cookie() {
        let req = Request::builder()
            .uri("/test")
            .header("authorization", "Bearer bearer-tok")
            .header("cookie", "session_token=cookie-tok")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_session_token(&req), Some("bearer-tok".into()));
    }

    #[test]
    fn test_no_token_returns_none() {
        assert_eq!(extract_session_token(&make_req()), None);
    }

    #[test]
    fn test_empty_bearer_returns_none() {
        let req = Request::builder()
            .uri("/test")
            .header("authorization", "Bearer ")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_session_token(&req), None);
    }

    /// The table of requests the bridge is pinned to as well
    /// (`tests/bridge/test_session_token_parity.py`): each must carry the
    /// same session token on both sides, or none on both.
    const SESSION_PARITY_TABLE: &str = include_str!("../../testdata/session_token_parity.json");

    /// The table's size when last extended; the bridge's test has the
    /// same floor.
    const SESSION_PARITY_CASES: usize = 59;

    /// Regression: the gateway matched the scheme as `Bearer ` exactly, so
    /// `bearer <token>` was no credential to it while the bridge, which
    /// matches it case-insensitively (RFC 9110 §11.1), authenticated it:
    /// the proxy forwarded such a request as anonymous, without the
    /// gateway's own session checks. Likewise the cookie, matched as
    /// `session_token=` exactly while the bridge trims the name, so
    /// `session_token =<token>` reached the bridge unchecked.
    #[test]
    fn session_tokens_are_read_as_on_the_bridge() {
        let table: serde_json::Value = serde_json::from_str(SESSION_PARITY_TABLE).unwrap();
        let cases = table["cases"].as_array().unwrap();
        assert!(
            cases.len() >= SESSION_PARITY_CASES,
            "the shared table lost cases: {} < {SESSION_PARITY_CASES}",
            cases.len()
        );
        let mismatches: Vec<String> = cases
            .iter()
            .filter_map(|case| {
                let mut headers = HeaderMap::new();
                let fields = case["headers"].as_array().unwrap();
                for field in fields {
                    let name = field[0].as_str().unwrap();
                    let value = field[1].as_str().unwrap();
                    headers.append(
                        axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                        HeaderValue::from_str(value).unwrap(),
                    );
                }
                let expected = case["token"].as_str();
                let got = session_token_from_headers(&headers);
                (got.as_deref() != expected)
                    .then(|| format!("{fields:?}: gateway {got:?}, bridge {expected:?}"))
            })
            .collect();
        assert!(mismatches.is_empty(), "{mismatches:#?}");
    }

    /// [`extract_session_token`] is [`session_token_from_headers`] on the
    /// request's headers.
    #[test]
    fn extract_session_token_reads_the_request_headers() {
        let req = Request::get("/test")
            .header("cookie", "theme=dark; session_token\t=from-cookie")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_session_token(&req).as_deref(), Some("from-cookie"));
    }

    #[test]
    fn test_binding_mode_from_str() {
        assert_eq!(
            SessionBindingMode::from("strict"),
            SessionBindingMode::Strict
        );
        assert_eq!(SessionBindingMode::from("ip"), SessionBindingMode::Ip);
        assert_eq!(SessionBindingMode::from("IP"), SessionBindingMode::Ip);
        assert_eq!(SessionBindingMode::from("warn"), SessionBindingMode::Warn);
        assert_eq!(SessionBindingMode::from("none"), SessionBindingMode::None);
        assert_eq!(SessionBindingMode::from("anything"), SessionBindingMode::Ip);
    }

    #[test]
    fn test_require_auth_unauthenticated() {
        let req = make_req();
        assert!(require_auth(&req, Role::Viewer).is_err());
        assert_eq!(
            require_auth(&req, Role::Viewer).unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn test_require_auth_insufficient_role() {
        let mut req = make_req();
        req.extensions_mut().insert(AuthInfo::ApiKey {
            key_id: "k1".into(),
            role: Role::Sensor,
        });
        assert_eq!(
            require_auth(&req, Role::Admin).unwrap_err(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn test_require_auth_sufficient_role() {
        let mut req = make_req();
        req.extensions_mut().insert(AuthInfo::Session {
            username: "alice".into(),
            user_id: 1,
            role: Role::Admin,
            session_token: "tok".into(),
            expires_at: "2099-01-01T00:00:00+00:00".into(),
            tenant_id: "default".into(),
            scope: String::new(),
        });
        assert!(require_auth(&req, Role::Viewer).is_ok());
    }

    // -- Client-cert / API-key coexistence ------------------------------
    //
    // PKI is additive: enabling client-cert auth must never break
    // API-key auth. These exercise resolve_client_cert directly.

    /// The certificate registered under serial 1 (the registry entry
    /// records no fingerprint, so serial + identity decide).
    fn cert_info(identity: &str) -> crate::auth::client_cert::ClientCertInfo {
        crate::auth::client_cert::ClientCertInfo {
            identity: identity.into(),
            serial: "1".into(),
            fingerprint_sha256: "ab".repeat(32),
        }
    }

    fn cert_registry(identity: &str, role: &str) -> tempfile::NamedTempFile {
        use std::io::Write as _;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(
            f,
            concat!(
                r#"{{"issued": {{"1": {{"identity": "{}", "role": "{}", "#,
                r#""revoked": false, "not_after": "2099-01-01T00:00:00+00:00"}}}}}}"#,
            ),
            identity, role,
        )
        .unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn test_client_cert_resolves_to_role() {
        let f = cert_registry("local-edge", "node");
        let reg = crate::auth::client_cert::CertRegistry::load(f.path());
        let mut req = make_req();
        req.extensions_mut().insert(cert_info("local-edge"));
        match resolve_client_cert(&req, Some(&reg)) {
            Some(AuthInfo::ApiKey { key_id, role }) => {
                assert_eq!(key_id, "local-edge");
                assert_eq!(role, Role::Node);
            }
            other => panic!("expected ApiKey from cert, got {other:?}"),
        }
    }

    #[test]
    fn test_api_key_takes_precedence_over_client_cert() {
        // A request carrying BOTH an API key and a client cert must
        // defer to the API-key path — enabling PKI never hijacks an
        // API-key request.
        let f = cert_registry("local-edge", "node");
        let reg = crate::auth::client_cert::CertRegistry::load(f.path());
        let mut req = Request::builder()
            .uri("/test")
            .header("x-api-key", "some-api-key")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(cert_info("local-edge"));
        assert!(resolve_client_cert(&req, Some(&reg)).is_none());
    }

    #[test]
    fn test_no_client_cert_returns_none() {
        let f = cert_registry("local-edge", "node");
        let reg = crate::auth::client_cert::CertRegistry::load(f.path());
        // No cert on the request → defer to the API-key path.
        assert!(resolve_client_cert(&make_req(), Some(&reg)).is_none());
    }

    // -- Full middleware: scopes, gateway-owned headers, client IP -------

    use crate::storage::users::tests::insert_user;
    use crate::test_support;
    use axum::routing::{get, post};
    use tower::ServiceExt as _;

    async fn ok() -> &'static str {
        "ok"
    }

    /// Echo what the middleware left on the request.
    async fn echo(req: Request<Body>) -> axum::Json<serde_json::Value> {
        let owned: Vec<String> = req
            .headers()
            .keys()
            .map(|k| k.as_str().to_string())
            .filter(|k| is_gateway_owned_header(k))
            .collect();
        let ip = req.extensions().get::<ClientIp>().map(|c| c.0.clone());
        axum::Json(serde_json::json!({"owned": owned, "client_ip": ip}))
    }

    fn app(state: &Arc<AppState>) -> axum::Router {
        axum::Router::new()
            .route("/api/auth/me", get(ok))
            .route("/api/auth/logout", post(ok))
            .route("/api/auth/change-password", post(ok))
            .route("/api/auth/mfa/setup", post(ok))
            .route("/api/detections/recent", get(ok))
            .route("/api/admin/users", post(ok))
            .route("/echo", get(echo))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(state),
                auth_middleware,
            ))
            .with_state(Arc::clone(state))
    }

    fn session_with_scope(state: &AppState, scope: &str) -> String {
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, &format!("u-{scope}"), "admin", true);
        let (token, _) =
            sessions::create_session_scoped(&conn, user, "", "", scope, &SessionConfig::default())
                .unwrap();
        token
    }

    async fn call(
        state: &Arc<AppState>,
        method: &str,
        path: &str,
        token: &str,
    ) -> (StatusCode, String) {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app(state).oneshot(req).await.unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    /// K3 (contract): a `password_change_only` session may only change the
    /// password, log out and ask who it is — on every route, gateway-native
    /// or proxied — and is refused with {"detail":"password change required"}.
    #[tokio::test]
    async fn password_change_only_session_is_confined() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let token = session_with_scope(&state, SCOPE_PASSWORD_CHANGE_ONLY);

        for (method, path) in [
            ("GET", "/api/auth/me"),
            ("POST", "/api/auth/change-password"),
            ("POST", "/api/auth/logout"),
        ] {
            assert_eq!(
                call(&state, method, path, &token).await.0,
                StatusCode::OK,
                "{path}"
            );
        }
        for (method, path) in [
            ("GET", "/api/detections/recent"),
            ("POST", "/api/admin/users"),
            ("POST", "/api/auth/mfa/setup"),
            ("GET", "/api/some/proxied/route"),
        ] {
            let (status, body) = call(&state, method, path, &token).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
            let body: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(
                body,
                serde_json::json!({"detail": "password change required"})
            );
        }
    }

    /// Regression (Q25): a browser holding the HttpOnly
    /// `password_change_only` cookie got 403 JSON for `/login`, `/` and
    /// `/static/*` too, so after a reload it could not reach the login or
    /// change form until the cookie expired. Pages and assets are served
    /// as anonymous requests (the session is not passed on); the API stays
    /// confined.
    #[tokio::test]
    async fn a_restricted_session_cookie_does_not_lock_the_browser_out_of_the_pages() {
        async fn who(req: Request<Body>) -> &'static str {
            match req.extensions().get::<AuthInfo>() {
                Some(AuthInfo::Session { .. }) => "session",
                Some(AuthInfo::ApiKey { .. }) => "key",
                Some(AuthInfo::Unauthenticated) | None => "anonymous",
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let app = axum::Router::new()
            .route("/", get(who))
            .route("/login", get(who).post(who))
            .route("/static/{*file}", get(who))
            .route("/api/detections/recent", get(who))
            .route("/api/auth/me", get(who))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                auth_middleware,
            ))
            .with_state(Arc::clone(&state));
        for scope in [SCOPE_PASSWORD_CHANGE_ONLY, SCOPE_MFA_SETUP_ONLY] {
            let token = session_with_scope(&state, scope);
            let request = |method: &str, path: &str| {
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("cookie", format!("session_token={token}"))
                    .body(Body::empty())
                    .unwrap()
            };
            for (method, path) in [
                ("GET", "/login"),
                ("GET", "/static/login.js"),
                ("GET", "/"),
                ("HEAD", "/login"),
            ] {
                let resp = app.clone().oneshot(request(method, path)).await.unwrap();
                assert_eq!(resp.status(), StatusCode::OK, "{scope} {method} {path}");
                let body = axum::body::to_bytes(resp.into_body(), 1 << 10)
                    .await
                    .unwrap();
                if method == "GET" {
                    assert_eq!(&body[..], b"anonymous", "{scope} {path}");
                }
            }
            // The API, and anything but a page load, stay confined.
            for (method, path) in [("GET", "/api/detections/recent"), ("POST", "/login")] {
                let resp = app.clone().oneshot(request(method, path)).await.unwrap();
                assert_eq!(
                    resp.status(),
                    StatusCode::FORBIDDEN,
                    "{scope} {method} {path}"
                );
            }
            if scope == SCOPE_PASSWORD_CHANGE_ONLY {
                // "Who am I" still sees the restricted session.
                let resp = app
                    .clone()
                    .oneshot(request("GET", "/api/auth/me"))
                    .await
                    .unwrap();
                let body = axum::body::to_bytes(resp.into_body(), 1 << 10)
                    .await
                    .unwrap();
                assert_eq!(&body[..], b"session");
            }
        }
        // A full session is passed on to pages as before.
        let full = session_with_scope(&state, "");
        let req = Request::get("/login")
            .header("cookie", format!("session_token={full}"))
            .body(Body::empty())
            .unwrap();
        let body = axum::body::to_bytes(app.oneshot(req).await.unwrap().into_body(), 1 << 10)
            .await
            .unwrap();
        assert_eq!(&body[..], b"session");
    }

    #[test]
    fn page_requests_are_get_or_head_outside_api_and_ws() {
        use axum::http::Method;
        for path in [
            "/",
            "/login",
            "/static/app.js",
            "/favicon.ico",
            "/dashboard",
            "/apiary",
        ] {
            assert!(is_page_request(&Method::GET, path), "{path}");
        }
        for path in ["/api", "/api/x", "/API/x", "/ws", "/ws/feed", "/Ws/status"] {
            assert!(!is_page_request(&Method::GET, path), "{path}");
        }
        assert!(is_page_request(&Method::HEAD, "/login"));
        assert!(!is_page_request(&Method::POST, "/login"));
    }

    /// Regression (K3 / G13): `/api/auth/mfa/verify` resolved the request's
    /// credentials like any other route, so a browser still holding an
    /// earlier restricted session cookie — e.g. of a user who never
    /// finished a forced password change — could not complete anyone's MFA
    /// login: the scope check answered 403 "password change required"
    /// before the handler ran. Both login steps ignore whatever session the
    /// request carries, whatever its scope.
    #[tokio::test]
    async fn stale_restricted_cookie_does_not_block_the_login_steps() {
        use crate::auth::mfa_handler::{self, tests::current_code, tests::mfa_user};
        use crate::auth::session_handler;
        use crate::storage::mfa;

        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let login_app = || {
            axum::Router::new()
                .route("/api/auth/login", post(session_handler::login))
                .route("/api/auth/mfa/verify", post(mfa_handler::mfa_verify_login))
                .layer(axum::middleware::from_fn_with_state(
                    Arc::clone(&state),
                    auth_middleware,
                ))
                .with_state(Arc::clone(&state))
        };
        let post_with_cookie = |path: &str, cookie: &str, body: serde_json::Value| {
            Request::post(path)
                .header("cookie", format!("session_token={cookie}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        };

        for scope in [
            SCOPE_PASSWORD_CHANGE_ONLY,
            SCOPE_MFA_SETUP_ONLY,
            "something_new",
        ] {
            let stale = session_with_scope(&state, scope);
            let user_id = mfa_user(&state, &format!("mfa-{scope}"));
            let mfa_token =
                mfa::create_mfa_token_unchecked(&state.db_pool.get().unwrap(), user_id, 5).unwrap();

            let req = post_with_cookie(
                "/api/auth/mfa/verify",
                &stale,
                serde_json::json!({"mfa_token": mfa_token, "totp_code": current_code()}),
            );
            let resp = login_app().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "stale {scope} cookie");
            assert_eq!(
                resp.headers()["cache-control"],
                "no-store, no-cache, must-revalidate"
            );
            let body = axum::body::to_bytes(resp.into_body(), 1 << 16)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let fresh = body["session_token"].as_str().unwrap();
            assert_ne!(fresh, stale);
            let conn = state.db_pool.get().unwrap();
            let session = sessions::validate_session(&conn, fresh, &SessionConfig::default())
                .unwrap()
                .unwrap();
            assert_eq!(session.user_id, user_id, "the MFA user's own session");
            assert_eq!(session.scope, "", "a full-scope session");

            // The password step reaches its handler too (which rejects the
            // empty body) rather than the stale session's scope check.
            let req = post_with_cookie("/api/auth/login", &stale, serde_json::json!({}));
            let resp = login_app().oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "stale {scope} cookie"
            );
        }
    }

    #[tokio::test]
    async fn mfa_setup_only_and_unknown_scopes_are_confined() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let mfa = session_with_scope(&state, SCOPE_MFA_SETUP_ONLY);
        assert_eq!(
            call(&state, "POST", "/api/auth/mfa/setup", &mfa).await.0,
            StatusCode::OK
        );
        assert_eq!(
            call(&state, "POST", "/api/auth/logout", &mfa).await.0,
            StatusCode::OK
        );
        assert_eq!(
            call(&state, "GET", "/api/detections/recent", &mfa).await.0,
            StatusCode::FORBIDDEN
        );

        // A scope the gateway does not know fails closed.
        let odd = session_with_scope(&state, "something_new");
        assert_eq!(
            call(&state, "GET", "/api/auth/me", &odd).await.0,
            StatusCode::OK
        );
        assert_eq!(
            call(&state, "GET", "/api/detections/recent", &odd).await.0,
            StatusCode::FORBIDDEN
        );

        let full = session_with_scope(&state, "");
        assert_eq!(
            call(&state, "GET", "/api/detections/recent", &full).await.0,
            StatusCode::OK
        );
    }

    /// Regression (G13): client-supplied `x-license-*` headers were not
    /// stripped (e.g. `X-License-Node-Limit` reached the bridge whenever
    /// the resolver had no limit). Every gateway-owned header is dropped
    /// at ingress, on every route.
    #[tokio::test]
    async fn gateway_owned_headers_are_dropped_at_ingress() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let req = Request::get("/echo")
            .header("x-license-node-limit", "9999")
            .header("x-license-tier", "enterprise")
            .header("X-License-Features", "everything")
            .header("x-auth-role", "keymaster")
            .header("x-auth-user", "root")
            .header("x-auth-method", "client-cert")
            .header("x-rust-proxy", "guess")
            .header("x-request-id", "kept")
            .body(Body::empty())
            .unwrap();
        let resp = app(&state).oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["owned"], serde_json::json!([]), "{body}");
        assert!(is_gateway_owned_header("x-license-anything"));
        assert!(!is_gateway_owned_header("x-request-id"));
        assert!(!is_gateway_owned_header("x-api-key"));
    }

    #[tokio::test]
    async fn client_ip_is_resolved_once_through_trusted_proxies() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        state.auth_config.write().await.trusted_proxies = TrustedProxies::parse("10.0.0.0/8").0;
        let mut req = Request::get("/echo")
            .header("x-forwarded-for", "6.6.6.6, 198.51.100.4, 10.1.2.3")
            .body(Body::empty())
            .unwrap();
        let peer: std::net::SocketAddr = "10.0.0.1:1234".parse().unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(peer));
        let resp = app(&state).oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["client_ip"], "198.51.100.4");
    }

    /// G3: IP binding compares against the resolved client, so a stolen
    /// token replayed with the victim's address in X-Forwarded-For is
    /// refused when it does not come through the trusted proxy.
    #[test]
    fn ip_binding_ignores_forged_forwarded_for() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let conn = state.db_pool.get().unwrap();
        let user = insert_user(&conn, "victim", "admin", true);
        let (token, session) =
            sessions::create_session(&conn, user, "198.51.100.4", "ua", &SessionConfig::default())
                .unwrap();
        let trusted = TrustedProxies::parse("127.0.0.1").0;
        let attempt = |peer: &str, xff: &str| {
            let mut req = Request::get("/x")
                .header("authorization", format!("Bearer {token}"))
                .header("x-forwarded-for", xff)
                .body(Body::empty())
                .unwrap();
            let peer: std::net::SocketAddr = peer.parse().unwrap();
            req.extensions_mut()
                .insert(axum::extract::ConnectInfo(peer));
            check_session_binding(&SessionBindingMode::Ip, &trusted, &req, &session)
        };
        // Attacker connects directly, claiming the victim's address.
        assert!(!attempt("203.0.113.66:1", "198.51.100.4"));
        // Through the proxy, the forged entry is left of the real one.
        assert!(!attempt("127.0.0.1:1", "198.51.100.4, 203.0.113.66"));
        // The victim through the proxy is accepted.
        assert!(attempt("127.0.0.1:1", "198.51.100.4"));
    }

    #[test]
    fn test_unknown_cert_identity_returns_none() {
        let f = cert_registry("local-edge", "node");
        let reg = crate::auth::client_cert::CertRegistry::load(f.path());
        let mut req = make_req();
        req.extensions_mut().insert(cert_info("intruder"));
        assert!(resolve_client_cert(&req, Some(&reg)).is_none());
    }

    fn tenant_test_state(
        dir: &tempfile::TempDir,
        tenant: Option<serde_json::Value>,
    ) -> Arc<AppState> {
        use crate::ws::test_harness as h;
        let mut keys: serde_json::Value = serde_json::from_str(&h::keys_file(&[h::key_entry(
            "tenant-viewer",
            "tenant-test-key",
            "viewer",
            false,
        )]))
        .unwrap();
        if let Some(tenant) = tenant {
            keys["keys"]["tenant-viewer"]["tenant_id"] = tenant;
        }
        let state = h::state(dir, "http://127.0.0.1:1", &keys.to_string(), None);
        state.db_pool.get().unwrap().execute_batch(
            "CREATE TABLE detections (detection_id TEXT,node_id TEXT,timestamp TEXT,signal_class TEXT,
             confidence REAL,family TEXT,freq_hz REAL,snr_db REAL,power_dbm REAL,inference_ms REAL,
             backend TEXT,anomaly_score REAL,baseline_status TEXT,has_iq_capture INTEGER,
             gain_db REAL,lna_state TEXT,bandwidth_hz REAL,tenant_id TEXT);
             INSERT INTO detections(detection_id,node_id,timestamp,signal_class,confidence,freq_hz,
                 anomaly_score,has_iq_capture,tenant_id)
             VALUES('local-evidence','local-node',strftime('%Y-%m-%dT%H:%M:%S','now'),
                 'bpsk',0.9,400000000,0.8,0,'default');"
        ).unwrap();
        state
    }

    async fn tenant_read(
        state: &Arc<AppState>,
        headers: &[(&str, &str)],
    ) -> (StatusCode, serde_json::Value) {
        let router = axum::Router::new()
            .route(
                "/api/detections/recent",
                get(crate::query::handler::get_recent),
            )
            .fallback(crate::proxy::handler::proxy_fallback)
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(state),
                auth_middleware,
            ))
            .with_state(Arc::clone(state));
        let mut request = Request::get("/api/detections/recent");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = router
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, body)
    }

    #[tokio::test]
    async fn tenant_boundary_native_query_refuses_foreign_session_before_fallback_or_touch() {
        use crate::ws::test_harness as h;
        let dir = tempfile::tempdir().unwrap();
        let state = tenant_test_state(&dir, None);
        let local = h::session_for(&state, "local-viewer", "viewer");
        let local_header = format!("Bearer {local}");
        let (status, body) = tenant_read(&state, &[("authorization", &local_header)]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["detections"][0]["detection_id"], "local-evidence");
        let foreign = h::session_for(&state, "foreign-admin", "admin");
        let conn = state.db_pool.get().unwrap();
        conn.execute(
            "UPDATE users SET tenant_id='other' WHERE username='foreign-admin'",
            [],
        )
        .unwrap();
        let foreign_header = format!("Bearer {foreign}");
        assert_eq!(
            tenant_read(&state, &[("authorization", &foreign_header)])
                .await
                .0,
            StatusCode::FORBIDDEN,
            "foreign session alone"
        );
        conn.execute("UPDATE sessions SET last_active='2020-01-01T00:00:00+00:00' WHERE user_id=(SELECT id FROM users WHERE username='foreign-admin')",[]).unwrap();
        // A valid foreign principal is refused even when a local secondary key is present.
        // The foreign expired/idle record remains untouched by this instance.
        for name in ["authorization", "cookie"] {
            let value = if name == "cookie" {
                format!("session_token={foreign}")
            } else {
                format!("Bearer {foreign}")
            };
            let (status, _) =
                tenant_read(&state, &[(name, &value), ("x-api-key", "tenant-test-key")]).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{name}");
        }
        let last:String = conn.query_row("SELECT last_active FROM sessions WHERE user_id=(SELECT id FROM users WHERE username='foreign-admin')",[],|r|r.get(0)).unwrap();
        assert_eq!(last, "2020-01-01T00:00:00+00:00");
    }

    #[tokio::test]
    async fn tenant_boundary_native_query_refuses_explicit_foreign_or_malformed_key_metadata() {
        for tenant in [
            serde_json::json!("other"),
            serde_json::Value::Null,
            serde_json::json!(""),
            serde_json::json!(17),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let state = tenant_test_state(&dir, Some(tenant.clone()));
            for _ in 0..2 {
                // The same verdict applies to cached validations.
                let (status, _) = tenant_read(&state, &[("x-api-key", "tenant-test-key")]).await;
                assert_eq!(status, StatusCode::FORBIDDEN, "explicit tenant {tenant}");
            }
        }
        for tenant in [None, Some(serde_json::json!("default"))] {
            let dir = tempfile::tempdir().unwrap();
            let state = tenant_test_state(&dir, tenant);
            let (status, body) = tenant_read(&state, &[("x-api-key", "tenant-test-key")]).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["detections"][0]["detection_id"], "local-evidence");
        }
    }

    #[tokio::test]
    async fn tenant_boundary_refusal_precedes_real_proxy_and_unknown_session_still_falls_back() {
        use crate::ws::test_harness as h;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let backend = axum::Router::new().fallback(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            async { axum::Json(serde_json::json!({"instance":"default"})) }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, backend).await.unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        let mut state = tenant_test_state(&dir, None);
        Arc::get_mut(&mut state).unwrap().config.python_url = format!("http://{address}");
        let local = h::session_for(&state, "local-proxy", "viewer");
        let foreign = h::session_for(&state, "foreign-proxy", "admin");
        state
            .db_pool
            .get()
            .unwrap()
            .execute(
                "UPDATE users SET tenant_id='other' WHERE username='foreign-proxy'",
                [],
            )
            .unwrap();
        let router = axum::Router::new()
            .fallback(crate::proxy::handler::proxy_fallback)
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                auth_middleware,
            ))
            .with_state(Arc::clone(&state));
        let request = |token: &str| {
            Request::get("/api/system/detection-config")
                .header("authorization", format!("Bearer {token}"))
                .header("x-api-key", "tenant-test-key")
                .body(Body::empty())
                .unwrap()
        };
        assert_eq!(
            router
                .clone()
                .oneshot(request(&foreign))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            router
                .clone()
                .oneshot(request(&local))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            router
                .oneshot(request("unknown-session"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn tenant_boundary_database_failure_does_not_fall_through_to_an_api_key() {
        let dir = tempfile::tempdir().unwrap();
        let state = tenant_test_state(&dir, None);
        state
            .db_pool
            .get()
            .unwrap()
            .execute("DROP TABLE users", [])
            .unwrap();
        let (status, _) = tenant_read(
            &state,
            &[
                ("authorization", "Bearer unknown"),
                ("x-api-key", "tenant-test-key"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn tenant_boundary_native_logout_preserves_foreign_session_and_audit() {
        use crate::ws::test_harness as h;
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, "http://127.0.0.1:1", &h::keys_file(&[]), None);
        let foreign = h::session_for(&state, "foreign-viewer", "viewer");
        let local = h::session_for(&state, "local-viewer", "viewer");
        let conn = state.db_pool.get().unwrap();
        conn.execute(
            "UPDATE users SET tenant_id='other' WHERE username='foreign-viewer'",
            [],
        )
        .unwrap();
        let foreign_hash = crate::auth::password::hash_session_token(&foreign);
        let unchanged: (String, String) = conn
            .query_row(
                "SELECT expires_at,last_active FROM sessions WHERE session_token=?1",
                [&foreign_hash],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let router = axum::Router::new()
            .route(
                "/api/auth/logout",
                post(crate::auth::session_handler::logout),
            )
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                auth_middleware,
            ))
            .with_state(Arc::clone(&state));
        for (header, value) in [
            ("authorization", format!("Bearer {foreign}")),
            ("x-session-token", foreign.clone()),
            ("cookie", format!("session_token={foreign}")),
        ] {
            let request = Request::post("/api/auth/logout")
                .header("cookie", "theme=dark")
                .header(header, value)
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                router.clone().oneshot(request).await.unwrap().status(),
                StatusCode::FORBIDDEN
            );
            let current: (String, String) = conn
                .query_row(
                    "SELECT expires_at,last_active FROM sessions WHERE session_token=?1",
                    [&foreign_hash],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(current, unchanged);
            assert_eq!(crate::test_support::audit_count(&state, "user_logout"), 0);
        }
        let response = router
            .oneshot(
                Request::post("/api/auth/logout")
                    .header("cookie", format!("session_token={local}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sessions WHERE session_token=?1",
                [crate::auth::password::hash_session_token(&local)],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        assert_eq!(crate::test_support::audit_count(&state, "user_logout"), 1);
    }

    /// RBAC for sessions: the account's stored role decides access, read
    /// on every request. A stored role that names no role gets no more than
    /// VIEWER (the bridge's `_role_from_name` maps it to VIEWER too, so the
    /// VIEWER route still answers; that fallback is pinned here): every
    /// route above VIEWER refuses it with 403. Known roles, in any case,
    /// keep their own level.
    #[tokio::test]
    async fn unknown_session_role_gets_no_more_than_viewer() {
        use crate::ws::test_harness as h;
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let gate = |min: Role| {
            move |req: Request<Body>| async move {
                require_auth(&req, min).map(|auth| auth.role().unwrap().to_string())
            }
        };
        let app = axum::Router::new()
            .route("/viewer", get(gate(Role::Viewer)))
            .route("/analyst", get(gate(Role::Analyst)))
            .route("/admin", get(gate(Role::Admin)))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                auth_middleware,
            ))
            .with_state(Arc::clone(&state));

        let cases = [
            ("superuser", ["viewer", "403", "403"]),
            ("root", ["viewer", "403", "403"]),
            (" admin", ["viewer", "403", "403"]),
            ("", ["viewer", "403", "403"]),
            ("analyst", ["analyst", "analyst", "403"]),
            ("ADMIN", ["admin", "admin", "admin"]),
        ];
        for (i, (stored, expected)) in cases.into_iter().enumerate() {
            let token = h::session_for(&state, &format!("user-{i}"), stored);
            for (path, want) in ["/viewer", "/analyst", "/admin"].into_iter().zip(expected) {
                let req = Request::get(path)
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap();
                let resp = app.clone().oneshot(req).await.unwrap();
                let status = resp.status();
                let body = axum::body::to_bytes(resp.into_body(), 1 << 10)
                    .await
                    .unwrap();
                let got = if status == StatusCode::OK {
                    String::from_utf8_lossy(&body).into_owned()
                } else {
                    status.as_u16().to_string()
                };
                assert_eq!(got, want, "stored role {stored:?} on {path}");
            }
        }
    }

    // -- Credentials, role gates and the public-path allowlist ----------

    /// What the middleware decided, as a handler sees it.
    fn principal(req: &Request<Body>) -> String {
        match req.extensions().get::<AuthInfo>() {
            Some(AuthInfo::Session { role, scope, .. }) => format!("session:{role}:{scope}"),
            Some(AuthInfo::ApiKey { role, .. }) => format!("key:{role}"),
            Some(AuthInfo::Unauthenticated) | None => "anonymous".into(),
        }
    }

    /// A handler gated with `require_auth(min)`: 200 and the caller's role,
    /// or the refusal.
    fn gate(req: &Request<Body>, min: Role) -> Response {
        match require_auth(req, min) {
            Ok(info) => info.role().unwrap().to_string().into_response(),
            Err(status) => status.into_response(),
        }
    }

    /// A viewer-gated and an admin-gated route; everything else answers
    /// with [`principal`].
    fn gated_app(state: &Arc<AppState>) -> axum::Router {
        axum::Router::new()
            .route(
                "/api/viewer",
                get(|req: Request<Body>| async move { gate(&req, Role::Viewer) }),
            )
            .route(
                "/api/admin",
                get(|req: Request<Body>| async move { gate(&req, Role::Admin) }),
            )
            .fallback(|req: Request<Body>| async move { principal(&req) })
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(state),
                auth_middleware,
            ))
            .with_state(Arc::clone(state))
    }

    async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, HeaderMap, String) {
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        (status, headers, String::from_utf8_lossy(&body).into_owned())
    }

    fn bearer(path: &str, token: &str) -> Request<Body> {
        Request::get(path)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    fn with_cookie(method: &str, path: &str, cookie: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header("cookie", cookie)
            .body(Body::empty())
            .unwrap()
    }

    fn session_rows(state: &AppState, token: &str) -> i64 {
        state
            .db_pool
            .get()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM sessions WHERE session_token = ?1",
                [crate::auth::password::hash_session_token(token)],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn set_session_column(state: &AppState, token: &str, column: &str, value: &str) {
        state
            .db_pool
            .get()
            .unwrap()
            .execute(
                &format!("UPDATE sessions SET {column} = ?1 WHERE session_token = ?2"),
                [value, &crate::auth::password::hash_session_token(token)],
            )
            .unwrap();
    }

    /// Also with auth on and API keys loaded, as in production: there a
    /// bearer token that is no session is tried as an API key next, and
    /// an unknown one is still no credential.
    #[tokio::test]
    async fn missing_malformed_or_unknown_credentials_get_401_from_role_gates() {
        let dev_dir = tempfile::tempdir().unwrap();
        let keys_dir = tempfile::tempdir().unwrap();
        let unknown = "f".repeat(64);
        let header = |name: &str, value: &str| {
            Request::get("/api/viewer")
                .header(name, value)
                .body(Body::empty())
                .unwrap()
        };
        for state in [
            test_support::app_state(&dev_dir),
            tenant_test_state(&keys_dir, None),
        ] {
            let app = gated_app(&state);
            let mode = if state.auth_enabled {
                "auth on, keys loaded"
            } else {
                "development"
            };
            let requests = [
                Request::get("/api/viewer").body(Body::empty()).unwrap(),
                bearer("/api/viewer", &unknown),
                header("x-session-token", &unknown),
                header("cookie", &format!("session_token={unknown}")),
                header("authorization", "Basic YWRtaW46YWRtaW4="),
                header("authorization", "Bearer    "),
                header("cookie", "session_token="),
                header("x-api-key", &unknown),
            ];
            for req in requests {
                let what = format!("{:?}", req.headers());
                let (status, _, _) = send(&app, req).await;
                assert_eq!(status, StatusCode::UNAUTHORIZED, "{mode}: {what}");
            }
        }
    }

    /// A valid token under a cookie whose name merely contains
    /// `session_token` is not a credential.
    #[tokio::test]
    async fn only_the_session_token_cookie_carries_a_session() {
        use crate::ws::test_harness as h;
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let app = gated_app(&state);
        let token = h::session_for(&state, "cookie-admin", "admin");
        for cookie in [
            format!("xsession_token={token}"),
            format!("my_session_token={token}"),
            format!("session_token_old={token}"),
            format!("theme=dark; Session_Token={token}"),
        ] {
            let (status, _, _) = send(&app, with_cookie("GET", "/api/viewer", &cookie)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{cookie}");
        }
        // Empty earlier credentials do not hide a real one after them.
        let req = Request::get("/api/admin")
            .header("authorization", "Bearer   ")
            .header("x-session-token", "  ")
            .header(
                "cookie",
                format!("theme=dark; session_token=; session_token={token}"),
            )
            .body(Body::empty())
            .unwrap();
        let (status, _, body) = send(&app, req).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "admin"));
    }

    /// The `Bearer` scheme in any letter case carries the session, with the
    /// session's role and scope: a restricted session sent as
    /// `bearer <token>` is confined like one sent as `Bearer <token>`.
    #[tokio::test]
    async fn a_bearer_session_is_resolved_in_any_letter_case() {
        use crate::ws::test_harness as h;
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let token = h::session_for(&state, "case-admin", "admin");
        let restricted = session_with_scope(&state, SCOPE_PASSWORD_CHANGE_ONLY);
        let with_auth = |path: &str, value: String| {
            Request::get(path)
                .header("authorization", value)
                .body(Body::empty())
                .unwrap()
        };
        for scheme in ["Bearer", "bearer", "BEARER", "BeArEr"] {
            let req = with_auth("/api/admin", format!("{scheme}  {token} "));
            let (status, _, body) = send(&gated_app(&state), req).await;
            assert_eq!(
                (status, body.as_str()),
                (StatusCode::OK, "admin"),
                "{scheme}"
            );

            let req = with_auth("/api/detections/recent", format!("{scheme} {restricted}"));
            let resp = app(&state).oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{scheme}: restricted");
        }
    }

    /// A stored role that names no role makes the session a viewer's (as
    /// the bridge's `_role_from_name` does), never more.
    #[tokio::test]
    async fn role_gates_follow_the_stored_role_and_unknown_roles_are_viewers() {
        use crate::ws::test_harness as h;
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let app = gated_app(&state);
        let ok = StatusCode::OK;
        let no = StatusCode::FORBIDDEN;
        for (stored, viewer, admin, seen_as) in [
            ("node", no, no, "node"),
            ("viewer", ok, no, "viewer"),
            ("analyst", ok, no, "analyst"),
            ("admin", ok, ok, "admin"),
            ("keymaster", ok, ok, "keymaster"),
            ("root", ok, no, "viewer"),
            ("", ok, no, "viewer"),
        ] {
            let token = h::session_for(&state, &format!("user-{stored}"), stored);
            let (status, _, body) = send(&app, bearer("/api/viewer", &token)).await;
            assert_eq!(status, viewer, "{stored:?} on a viewer route");
            if status == StatusCode::OK {
                assert_eq!(body, seen_as, "{stored:?}");
            }
            let (status, _, _) = send(&app, bearer("/api/admin", &token)).await;
            assert_eq!(status, admin, "{stored:?} on an admin route");
        }
    }

    #[tokio::test]
    async fn expired_idle_and_disabled_sessions_are_refused() {
        use crate::ws::test_harness as h;
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let app = gated_app(&state);

        let expired = h::session_for(&state, "expired", "admin");
        set_session_column(&state, &expired, "expires_at", "2020-01-01T00:00:00+00:00");
        let (status, _, _) = send(&app, bearer("/api/viewer", &expired)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "past its absolute expiry");
        assert_eq!(session_rows(&state, &expired), 0, "expired session deleted");

        let idle = h::session_for(&state, "idle", "admin");
        set_session_column(&state, &idle, "last_active", "2020-01-01T00:00:00+00:00");
        let (status, _, _) = send(&app, bearer("/api/viewer", &idle)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "idle too long");
        assert_eq!(session_rows(&state, &idle), 0, "idle session deleted");

        let disabled = h::session_for(&state, "disabled", "admin");
        state
            .db_pool
            .get()
            .unwrap()
            .execute(
                "UPDATE users SET enabled = 0 WHERE username = 'disabled'",
                [],
            )
            .unwrap();
        for _ in 0..2 {
            let (status, _, _) = send(&app, bearer("/api/viewer", &disabled)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "user disabled");
        }

        // A live session in the same table still works.
        let live = h::session_for(&state, "live", "admin");
        let (status, _, body) = send(&app, bearer("/api/admin", &live)).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "admin"));
    }

    /// `now + offset` as the bridge stores it (`isoformat()`, whole seconds).
    fn stored_time(offset: chrono::Duration) -> String {
        (chrono::Utc::now() + offset)
            .format("%Y-%m-%dT%H:%M:%S+00:00")
            .to_string()
    }

    /// The absolute expiry and the idle timeout (30 minutes by default, or
    /// as configured) take effect when they are reached — not a day or
    /// hours later — and a session just inside both still works.
    #[tokio::test]
    async fn sessions_expire_at_their_absolute_and_idle_limits() {
        use crate::ws::test_harness as h;
        use chrono::Duration;
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let app = gated_app(&state);
        let check = |name: &'static str, column: &'static str, value: String, alive: bool| {
            let (state, app) = (&state, &app);
            async move {
                let token = h::session_for(state, name, "viewer");
                set_session_column(state, &token, column, &value);
                let (status, _, _) = send(app, bearer("/api/viewer", &token)).await;
                if alive {
                    assert_eq!(status, StatusCode::OK, "{name}: {column} = {value}");
                    assert_eq!(session_rows(state, &token), 1, "{name}: kept");
                } else {
                    assert_eq!(
                        status,
                        StatusCode::UNAUTHORIZED,
                        "{name}: {column} = {value}"
                    );
                    assert_eq!(session_rows(state, &token), 0, "{name}: deleted");
                }
            }
        };
        let expired = stored_time(Duration::seconds(-60));
        check("expired-a-minute-ago", "expires_at", expired, false).await;
        let expiring = stored_time(Duration::seconds(120));
        check("expires-in-two-minutes", "expires_at", expiring, true).await;
        let idle = stored_time(Duration::minutes(-31));
        check("idle-31-minutes", "last_active", idle, false).await;
        let active = stored_time(Duration::minutes(-25));
        check("idle-25-minutes", "last_active", active, true).await;

        // A configured idle timeout is the one applied.
        state
            .auth_config
            .write()
            .await
            .session_config
            .idle_timeout_minutes = 10;
        let idle = stored_time(Duration::minutes(-11));
        check("idle-11-of-10-minutes", "last_active", idle, false).await;
        let active = stored_time(Duration::minutes(-9));
        check("idle-9-of-10-minutes", "last_active", active, true).await;
    }

    /// A session whose expiry or last activity cannot be read is no
    /// session: it is refused and deleted, never kept without a limit.
    #[tokio::test]
    async fn unparseable_session_times_fail_closed() {
        use crate::ws::test_harness as h;
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let app = gated_app(&state);
        for (i, (column, value)) in [
            ("expires_at", "garbage"),
            // SQLite's datetime() spelling: read, and long past.
            ("expires_at", "2020-01-01 00:00:00"),
            ("last_active", "garbage"),
            // No writer stores '': it is not "never active" (only NULL is).
            ("last_active", ""),
            ("last_active", "2020-01-01 00:00:00"),
        ]
        .into_iter()
        .enumerate()
        {
            let token = h::session_for(&state, &format!("unreadable-{i}"), "admin");
            set_session_column(&state, &token, column, value);
            let (status, _, _) = send(&app, bearer("/api/viewer", &token)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{column} = {value:?}");
            assert_eq!(session_rows(&state, &token), 0, "{column} = {value:?}");
        }
    }

    /// A live session works whichever format the gateway, the bridge or
    /// SQLite stored its times in, and its response reports the remaining
    /// lifetime read from that same expiry. A NULL `last_active` (no idle
    /// information) is accepted too.
    #[tokio::test]
    async fn every_stored_time_format_is_read_and_reported() {
        use crate::ws::test_harness as h;
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let app = gated_app(&state);
        let expires = chrono::Utc::now() + chrono::Duration::seconds(1000);
        let active = chrono::Utc::now() - chrono::Duration::minutes(5);
        for (i, format) in [
            "%Y-%m-%dT%H:%M:%S+00:00",
            "%Y-%m-%dT%H:%M:%S%.6f+00:00",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S%.6f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S%.6f",
        ]
        .into_iter()
        .enumerate()
        {
            let token = h::session_for(&state, &format!("format-{i}"), "viewer");
            let expiry = expires.format(format).to_string();
            set_session_column(&state, &token, "expires_at", &expiry);
            let last = active.format(format).to_string();
            set_session_column(&state, &token, "last_active", &last);
            let (status, headers, _) = send(&app, bearer("/api/viewer", &token)).await;
            assert_eq!(status, StatusCode::OK, "{expiry:?} / {last:?}");
            let left: i64 = headers["x-session-expires-in"]
                .to_str()
                .unwrap()
                .parse()
                .unwrap();
            assert!((980..=1000).contains(&left), "{expiry:?}: {left}");
        }

        let token = h::session_for(&state, "never-active", "viewer");
        state
            .db_pool
            .get()
            .unwrap()
            .execute(
                "UPDATE sessions SET last_active = NULL WHERE session_token = ?1",
                [crate::auth::password::hash_session_token(&token)],
            )
            .unwrap();
        let (status, _, _) = send(&app, bearer("/api/viewer", &token)).await;
        assert_eq!(status, StatusCode::OK, "NULL last_active");
    }

    /// `future`'s output, and what it logged at DEBUG and above (on this
    /// thread, where a `#[tokio::test]` runs it and the middleware with it).
    async fn with_debug_logs<T>(future: impl std::future::Future<Output = T>) -> (T, String) {
        #[derive(Clone, Default)]
        struct Buffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Buffer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        let output = {
            crate::test_support::keep_log_capture_reliable();
            let _guard = tracing::subscriber::set_default(subscriber);
            future.await
        };
        let logged = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        (output, logged)
    }

    /// Strict refuses an IP or User-Agent change, Ip only an IP change,
    /// Warn and None neither; Warn logs each change it lets through, None
    /// does not look. A request without a known peer address is treated
    /// as coming from elsewhere (fail closed).
    #[tokio::test]
    async fn session_binding_modes_refuse_a_session_used_from_elsewhere() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let app = gated_app(&state);
        let (token, unbound) = {
            let conn = state.db_pool.get().unwrap();
            let user = insert_user(&conn, "bound", "admin", true);
            let config = SessionConfig::default();
            let bound =
                sessions::create_session(&conn, user, "203.0.113.10", "agent/1", &config).unwrap();
            let unbound = sessions::create_session(&conn, user, "", "", &config).unwrap();
            (bound.0, unbound.0)
        };
        let request = |token: &str, peer: Option<&str>, ua: &str| {
            let mut req = Request::get("/api/viewer")
                .header("authorization", format!("Bearer {token}"))
                .header("user-agent", ua)
                .body(Body::empty())
                .unwrap();
            if let Some(peer) = peer {
                let peer: std::net::SocketAddr = peer.parse().unwrap();
                req.extensions_mut()
                    .insert(axum::extract::ConnectInfo(peer));
            }
            req
        };
        let home = Some("203.0.113.10:5000");
        let away = Some("198.51.100.99:5000");
        let ok = StatusCode::OK;
        let refused = StatusCode::UNAUTHORIZED;
        // Warn mode lets every request through and records each mismatch
        // in the log: (IP mismatch, User-Agent mismatch) when it logs one.
        let quiet = None;
        let (ip_logged, ua_logged, both_logged) =
            (Some((true, false)), Some((false, true)), Some((true, true)));
        let cases = [
            (SessionBindingMode::Ip, home, "agent/1", ok, quiet),
            (SessionBindingMode::Ip, home, "agent/2", ok, quiet),
            (SessionBindingMode::Ip, away, "agent/1", refused, quiet),
            (SessionBindingMode::Ip, None, "agent/1", refused, quiet),
            (SessionBindingMode::Strict, home, "agent/1", ok, quiet),
            (SessionBindingMode::Strict, home, "agent/2", refused, quiet),
            (SessionBindingMode::Strict, away, "agent/1", refused, quiet),
            (SessionBindingMode::Strict, None, "agent/1", refused, quiet),
            (SessionBindingMode::Warn, away, "agent/2", ok, both_logged),
            (SessionBindingMode::Warn, away, "agent/1", ok, ip_logged),
            (SessionBindingMode::Warn, home, "agent/2", ok, ua_logged),
            (SessionBindingMode::Warn, home, "agent/1", ok, quiet),
            (SessionBindingMode::None, away, "agent/2", ok, quiet),
            // The owner keeps the session after refused attempts.
            (SessionBindingMode::Strict, home, "agent/1", ok, quiet),
        ];
        for (mode, peer, ua, expected, mismatch) in cases {
            state.auth_config.write().await.binding_mode = mode.clone();
            let ((status, _, _), logged) =
                with_debug_logs(send(&app, request(&token, peer, ua))).await;
            let case = format!("{mode:?} from {peer:?} as {ua}");
            assert_eq!(status, expected, "{case}");
            let warned = logged.contains("Session binding mismatch (warn mode, allowed)");
            assert_eq!(warned, mismatch.is_some(), "{case}: {logged}");
            if let Some((ip, ua)) = mismatch {
                for field in [format!("ip_mismatch={ip}"), format!("ua_mismatch={ua}")] {
                    assert!(logged.contains(&field), "{case}: {field} in {logged}");
                }
            }
        }
        // A session that recorded no address or agent is not bound.
        state.auth_config.write().await.binding_mode = SessionBindingMode::Strict;
        let (status, _, _) = send(&app, request(&unbound, away, "other")).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// The health/version probes and login steps never resolve the
    /// request's credentials, but only on an exact match: any other
    /// spelling resolves them, so a restricted session stays confined.
    #[tokio::test]
    async fn public_paths_ignore_credentials_on_an_exact_match_only() {
        use crate::ws::test_harness as h;
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let app = gated_app(&state);
        let full = format!("session_token={}", h::session_for(&state, "full", "admin"));
        let restricted = format!(
            "session_token={}",
            session_with_scope(&state, SCOPE_PASSWORD_CHANGE_ONLY)
        );
        for path in UNAUTHENTICATED_PATHS {
            for cookie in [&full, &restricted] {
                let (status, _, body) = send(&app, with_cookie("POST", path, cookie)).await;
                assert_eq!(
                    (status, body.as_str()),
                    (StatusCode::OK, "anonymous"),
                    "{path}"
                );
            }
        }
        for near in [
            "/health/",
            "/healthz",
            "/HEALTH",
            "/api/version/",
            "/api/versions",
            "/api/auth/login/",
            "/api/auth/loginx",
            "/api/auth/login/x",
            "/API/AUTH/LOGIN",
            "/api/auth/mfa/verify/",
            "/api/auth/mfa/verify2",
        ] {
            let (status, _, body) = send(&app, with_cookie("POST", near, &full)).await;
            assert_eq!(
                (status, body.as_str()),
                (StatusCode::OK, "session:admin:"),
                "{near}: credentials are resolved"
            );
            let (status, _, body) = send(&app, with_cookie("POST", near, &restricted)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{near}: scope applies");
            assert_eq!(body, r#"{"detail":"password change required"}"#, "{near}");
        }
    }

    /// Restricted scopes allow their paths exactly, in their exact case;
    /// WebSocket routes are not pages, so they stay confined.
    #[tokio::test]
    async fn restricted_scopes_allow_exact_paths_only() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let app = gated_app(&state);
        let mfa = format!(
            "session_token={}",
            session_with_scope(&state, SCOPE_MFA_SETUP_ONLY)
        );
        let pw = format!(
            "session_token={}",
            session_with_scope(&state, SCOPE_PASSWORD_CHANGE_ONLY)
        );
        for (cookie, method, path) in [
            (&mfa, "POST", "/api/auth/mfa"),
            (&mfa, "POST", "/api/auth/mfa-disable"),
            (&mfa, "POST", "/api/auth/mfax/setup"),
            (&mfa, "POST", "/API/AUTH/MFA/setup"),
            (&mfa, "POST", "/api/auth/logout/"),
            (&mfa, "GET", "/api/auth/me"),
            (&pw, "POST", "/api/auth/change-password/"),
            (&pw, "POST", "/api/auth/change-password-now"),
            (&pw, "POST", "/API/AUTH/CHANGE-PASSWORD"),
            (&pw, "GET", "/API/AUTH/ME"),
            (&pw, "GET", "/api/auth/me/sessions"),
            (&pw, "POST", "/api/auth/logout/all"),
            (&pw, "GET", "/ws/feed"),
            (&pw, "GET", "/WS/feed"),
            (&mfa, "GET", "/ws/audit"),
            (&mfa, "GET", "/api/detections/ws/feed"),
        ] {
            let (status, _, _) = send(&app, with_cookie(method, path, cookie)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}");
        }
        for (cookie, method, path) in [
            (&mfa, "POST", "/api/auth/mfa/setup"),
            (&mfa, "POST", "/api/auth/logout"),
            (&pw, "POST", "/api/auth/change-password"),
            (&pw, "GET", "/api/auth/me"),
        ] {
            let (status, _, body) = send(&app, with_cookie(method, path, cookie)).await;
            assert_eq!(status, StatusCode::OK, "{method} {path}");
            assert!(
                body.starts_with("session:admin:"),
                "{method} {path}: {body}"
            );
        }
    }

    /// Gateway-owned headers are dropped on the public paths too, every
    /// value of a repeated one, and the client IP is still recorded. The
    /// handler reports every header it got, so the forged names are
    /// checked by name, not by the predicate that strips them.
    #[tokio::test]
    async fn forged_gateway_headers_are_dropped_on_public_paths() {
        async fn seen(req: Request<Body>) -> axum::Json<serde_json::Value> {
            let names: Vec<String> = req
                .headers()
                .keys()
                .map(|k| k.as_str().to_string())
                .collect();
            let ip = req.extensions().get::<ClientIp>().map(|c| c.0.clone());
            axum::Json(serde_json::json!({"headers": names, "client_ip": ip}))
        }
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let app = axum::Router::new()
            .route("/health", get(seen))
            .route("/api/auth/login", post(seen))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                auth_middleware,
            ))
            .with_state(Arc::clone(&state));
        for (method, path) in [("GET", "/health"), ("POST", "/api/auth/login")] {
            let mut req = Request::builder()
                .method(method)
                .uri(path)
                .header("x-auth-role", "keymaster")
                .header("x-auth-role", "admin")
                .header("X-Auth-User", "root")
                .header("X-Rust-Proxy", "guess")
                .header("x-license-tier", "enterprise")
                .header("x-license-tier", "unlimited")
                .header("X-License-Node-Limit", "9999")
                .header("x-request-id", "kept")
                .body(Body::empty())
                .unwrap();
            let peer: std::net::SocketAddr = "198.51.100.7:4000".parse().unwrap();
            req.extensions_mut()
                .insert(axum::extract::ConnectInfo(peer));
            let (status, _, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            let body: serde_json::Value = serde_json::from_str(&body).unwrap();
            let headers: Vec<&str> = body["headers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|name| name.as_str().unwrap())
                .collect();
            for forged in [
                "x-auth-role",
                "x-auth-user",
                "x-rust-proxy",
                "x-license-tier",
                "x-license-node-limit",
            ] {
                assert!(!headers.contains(&forged), "{path}: {forged} reached it");
            }
            assert!(headers.contains(&"x-request-id"), "{path}: {headers:?}");
            assert_eq!(body["client_ip"], "198.51.100.7", "{path}");
        }
    }

    #[tokio::test]
    async fn session_responses_carry_the_remaining_lifetime_and_warn_near_expiry() {
        use crate::ws::test_harness as h;
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let app = gated_app(&state);
        let remaining = |headers: &HeaderMap| -> i64 {
            headers["x-session-expires-in"]
                .to_str()
                .unwrap()
                .parse()
                .unwrap()
        };

        let seconds = chrono::Duration::seconds;

        let normal = h::session_for(&state, "normal", "viewer");
        let (status, headers, _) = send(&app, bearer("/api/viewer", &normal)).await;
        assert_eq!(status, StatusCode::OK);
        let left = remaining(&headers);
        assert!((23 * 3600..=24 * 3600).contains(&left), "{left}");
        assert!(headers.get("x-session-warning").is_none());

        let soon = h::session_for(&state, "soon", "viewer");
        let expires = (chrono::Utc::now() + chrono::Duration::seconds(200))
            .format("%Y-%m-%dT%H:%M:%S+00:00")
            .to_string();
        set_session_column(&state, &soon, "expires_at", &expires);
        let (status, headers, _) = send(&app, bearer("/api/viewer", &soon)).await;
        assert_eq!(status, StatusCode::OK);
        let left = remaining(&headers);
        assert!((0..=200).contains(&left), "{left}");
        assert_eq!(headers["x-session-warning"], "expiring-soon");

        // 400 s left is more than five minutes: no warning yet.
        let later = h::session_for(&state, "later", "viewer");
        set_session_column(&state, &later, "expires_at", &stored_time(seconds(400)));
        let (status, headers, _) = send(&app, bearer("/api/viewer", &later)).await;
        assert_eq!(status, StatusCode::OK);
        let left = remaining(&headers);
        assert!((390..=400).contains(&left), "{left}");
        assert!(headers.get("x-session-warning").is_none(), "{left} s left");

        // The warning starts below five minutes: exactly 300 s left is not
        // warned. The expiry carries milliseconds (as the bridge's
        // isoformat() may carry microseconds), so a request served within
        // 0.9 s sees 300 s left; a slower one sees 299 and is retried.
        for attempt in 0..3 {
            let edge = h::session_for(&state, &format!("edge-{attempt}"), "viewer");
            let expires = (chrono::Utc::now() + chrono::Duration::milliseconds(300_900))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, false);
            set_session_column(&state, &edge, "expires_at", &expires);
            let (status, headers, _) = send(&app, bearer("/api/viewer", &edge)).await;
            assert_eq!(status, StatusCode::OK);
            let left = remaining(&headers);
            let warned = headers.get("x-session-warning").is_some();
            match left {
                300 => {
                    assert!(!warned, "exactly 300 s left is not warned");
                    break;
                }
                ..=299 => assert!(warned, "{left} s left is warned"),
                _ => panic!("{left} s left of 300.9"),
            }
        }

        // Without a session there is nothing to report.
        let (status, headers, _) = send(
            &app,
            Request::get("/api/viewer").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(headers.get("x-session-expires-in").is_none());
        assert!(headers.get("x-session-warning").is_none());
    }

    /// The header is computed after the handler, so a session can expire
    /// while its request is served: that reports 0 (the bridge clamps the
    /// same way), never a negative count.
    #[test]
    fn remaining_seconds_never_go_below_zero() {
        let at = |seconds: i64| {
            (chrono::Utc::now() + chrono::Duration::seconds(seconds))
                .format("%Y-%m-%dT%H:%M:%S+00:00")
                .to_string()
        };
        for expired in [at(-1), at(-5), "2000-01-01 00:00:00".to_string()] {
            assert_eq!(compute_remaining_seconds(&expired), Some(0), "{expired}");
        }
        let left = compute_remaining_seconds(&at(100)).unwrap();
        assert!((98..=100).contains(&left), "{left}");
        assert_eq!(compute_remaining_seconds("garbage"), None);
    }

    /// Responses under `/api/auth/` (they carry tokens and cookies) are
    /// never cached, the public login step included.
    #[tokio::test]
    async fn auth_responses_are_marked_no_store() {
        use crate::ws::test_harness as h;
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let app = gated_app(&state);
        let token = h::session_for(&state, "cache", "viewer");
        for path in ["/api/auth/me", "/api/auth/login", "/api/auth/sessions"] {
            let (status, headers, _) = send(&app, bearer(path, &token)).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert_eq!(
                headers["cache-control"], "no-store, no-cache, must-revalidate",
                "{path}"
            );
            assert_eq!(headers["pragma"], "no-cache", "{path}");
        }
        let (_, headers, _) = send(&app, bearer("/api/viewer", &token)).await;
        assert!(headers.get("cache-control").is_none());
    }

    /// K5: nobody gives or manages a role above their own, and KEYMASTER
    /// only by a KEYMASTER, refused with a 403 naming why. (Which role
    /// may grant which is `rbac::tests::role_ceilings`.) A caller without
    /// a principal is ranked as the lowest role, SENSOR.
    #[tokio::test]
    async fn role_ceilings_refuse_grants_and_changes_above_the_caller() {
        async fn refusal(resp: Response) -> (StatusCode, String) {
            let status = resp.status();
            let body = axum::body::to_bytes(resp.into_body(), 1 << 10)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            (status, body["detail"].as_str().unwrap().to_string())
        }
        let as_role = |role| AuthInfo::ApiKey {
            key_id: "caller".into(),
            role,
        };
        assert!(require_may_grant(&as_role(Role::Admin), Role::Admin, "key").is_ok());
        assert!(require_may_manage(&as_role(Role::Keymaster), Role::Keymaster, "user").is_ok());

        let forbidden = StatusCode::FORBIDDEN;
        let err = require_may_grant(&as_role(Role::Admin), Role::Keymaster, "key").unwrap_err();
        assert_eq!(
            refusal(err).await,
            (
                forbidden,
                "Only KEYMASTER can assign the keymaster role".into()
            )
        );
        let err = require_may_grant(&as_role(Role::Analyst), Role::Admin, "user").unwrap_err();
        assert_eq!(
            refusal(err).await,
            (forbidden, "Cannot give a user a role above your own".into())
        );
        let err = require_may_manage(&as_role(Role::Admin), Role::Keymaster, "user").unwrap_err();
        assert_eq!(
            refusal(err).await,
            (
                forbidden,
                "Cannot modify a user with a role above your own".into()
            )
        );
        let nobody = AuthInfo::Unauthenticated;
        assert_eq!(nobody.role(), None);
        assert!(require_may_grant(&nobody, Role::Node, "key").is_err());
        assert!(require_may_manage(&nobody, Role::Viewer, "user").is_err());
        // The ceilings alone do not refuse an anonymous caller: it is
        // ranked SENSOR, so SENSOR is within its ceiling. The admin user
        // routes, the callers, gate on `require_auth(.., Role::Admin)`
        // first, which refuses it with 401.
        assert!(require_may_grant(&nobody, Role::Sensor, "key").is_ok());
        assert!(require_may_manage(&nobody, Role::Sensor, "key").is_ok());
    }

    /// API keys are gated by their role; a wrong key, an empty one or a
    /// revoked one grants nothing, and a valid session wins over a key.
    #[tokio::test]
    async fn api_keys_are_gated_by_their_role_and_bad_keys_grant_nothing() {
        use crate::ws::test_harness as h;
        let dir = tempfile::tempdir().unwrap();
        let state = tenant_test_state(&dir, None);
        let app = gated_app(&state);
        let key = |path: &str, name: &str, value: &str| {
            Request::get(path)
                .header(name, value)
                .body(Body::empty())
                .unwrap()
        };
        let (status, _, body) =
            send(&app, key("/api/viewer", "x-api-key", "tenant-test-key")).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "viewer"));
        let (status, _, body) = send(&app, bearer("/api/viewer", "tenant-test-key")).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "viewer"));
        let (status, _, _) = send(&app, key("/api/admin", "x-api-key", "tenant-test-key")).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a viewer key on an admin route"
        );
        for wrong in ["tenant-test-kez", "", "TENANT-TEST-KEY"] {
            let (status, _, _) = send(&app, key("/api/viewer", "x-api-key", wrong)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{wrong:?}");
        }

        let admin = h::session_for(&state, "boss", "admin");
        let req = Request::get("/api/admin")
            .header("authorization", format!("Bearer {admin}"))
            .header("x-api-key", "tenant-test-key")
            .body(Body::empty())
            .unwrap();
        let (status, _, body) = send(&app, req).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "admin"));

        let revoked_dir = tempfile::tempdir().unwrap();
        let revoked = h::state(
            &revoked_dir,
            "http://127.0.0.1:1",
            &h::keys_file(&[h::key_entry(
                "tenant-viewer",
                "tenant-test-key",
                "viewer",
                true,
            )]),
            None,
        );
        let (status, _, _) = send(
            &gated_app(&revoked),
            key("/api/viewer", "x-api-key", "tenant-test-key"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "a revoked key");
    }

    /// With auth on but no key store loaded, an API key grants nothing.
    #[tokio::test]
    async fn api_key_without_a_key_store_grants_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = test_support::app_state(&dir);
        Arc::get_mut(&mut state).unwrap().auth_enabled = true;
        let req = Request::get("/api/viewer")
            .header("x-api-key", "any-key")
            .body(Body::empty())
            .unwrap();
        let (status, _, _) = send(&gated_app(&state), req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// A verified client certificate is gated by its registered role; an
    /// unknown or revoked one grants nothing.
    #[tokio::test]
    async fn client_certificates_are_gated_by_their_registered_role() {
        use crate::ws::test_harness as h;
        let dir = tempfile::tempdir().unwrap();
        let registry = dir.path().join("ca_registry.json");
        h::write_cert_registry(&registry, "edge-1", "analyst", false);
        let state = h::with_cert_registry(
            h::state(&dir, "http://127.0.0.1:1", &h::keys_file(&[]), None),
            &registry,
        );
        let app = gated_app(&state);
        let with_cert = |path: &str, identity: &str| {
            let mut req = Request::get(path).body(Body::empty()).unwrap();
            req.extensions_mut().insert(h::client_cert(identity));
            req
        };
        let (status, _, body) = send(&app, with_cert("/api/viewer", "edge-1")).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "analyst"));
        let (status, _, _) = send(&app, with_cert("/api/admin", "edge-1")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = send(&app, with_cert("/api/viewer", "intruder")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "unknown identity");

        h::write_cert_registry(&registry, "edge-1", "analyst", true);
        let (status, _, _) = send(&app, with_cert("/api/viewer", "edge-1")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "revoked certificate");
    }

    /// A session in a scope this build does not know is confined to the
    /// most restrictive set, which still lets its user log out (and ask
    /// who they are) — it is never stuck with a session it cannot end.
    #[tokio::test]
    async fn an_unknown_scope_can_still_log_out() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let odd = session_with_scope(&state, "scope_from_a_newer_bridge");
        for (method, path, expected) in [
            ("POST", "/api/auth/logout", StatusCode::OK),
            ("GET", "/api/auth/me", StatusCode::OK),
            ("POST", "/api/auth/change-password", StatusCode::FORBIDDEN),
            ("POST", "/api/auth/mfa/setup", StatusCode::FORBIDDEN),
        ] {
            let (status, body) = call(&state, method, path, &odd).await;
            assert_eq!(status, expected, "{method} {path}");
            if expected == StatusCode::FORBIDDEN {
                assert_eq!(
                    body, r#"{"detail":"session scope does not allow this request"}"#,
                    "{path}"
                );
            }
        }
    }

    /// A session whose row cannot be read (a storage error, here a stored
    /// value of the wrong type) refuses the request with 503: it is never
    /// taken for "no session" and passed on as anonymous — nor tried as
    /// an API key.
    #[tokio::test]
    async fn an_unreadable_session_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_support::app_state(&dir);
        let app = gated_app(&state);
        let token = crate::ws::test_harness::session_for(&state, "alice", "admin");
        let (status, _, body) = send(&app, bearer("/api/echo", &token)).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "session:admin:"));

        state
            .db_pool
            .get()
            .unwrap()
            .execute(
                "UPDATE sessions SET created_at = X'00' WHERE session_token = ?1",
                [crate::auth::password::hash_session_token(&token)],
            )
            .unwrap();
        for path in ["/api/echo", "/api/viewer"] {
            let (status, _, body) = send(&app, bearer(path, &token)).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{path}: {body}");
        }
        assert_eq!(session_rows(&state, &token), 1, "the row is left alone");
    }

    /// A session-token header or cookie field that is not visible ASCII is
    /// no credential: it is skipped — never decoded lossily into a token —
    /// and the next source is read.
    #[test]
    fn opaque_header_bytes_are_never_a_session_token() {
        let opaque = |bytes: &[u8]| HeaderValue::from_bytes(bytes).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", opaque(b"Bearer tok\xffen"));
        headers.insert("x-session-token", opaque(b"tok\xffen"));
        assert_eq!(session_token_from_headers(&headers), None);

        headers.append("cookie", opaque(b"session_token=caf\xe9"));
        assert_eq!(session_token_from_headers(&headers), None);

        headers.append("cookie", HeaderValue::from_static("session_token=readable"));
        assert_eq!(
            session_token_from_headers(&headers).as_deref(),
            Some("readable")
        );
    }

    /// Only a request the middleware resolved to a certificate principal
    /// (an `ApiKey` identity, with no API key on the request) counts as
    /// authenticated by its client certificate — the one the CSRF
    /// middleware then holds to the `Origin` rule. A session, an anonymous
    /// request or a real API key presented next to the certificate does
    /// not.
    #[test]
    fn only_a_certificate_principal_is_authenticated_by_its_certificate() {
        let request = |info: Option<AuthInfo>, api_key: bool| {
            let mut req = Request::post("/api/x");
            if api_key {
                req = req.header("x-api-key", "sk-1");
            }
            let mut req = req.body(Body::empty()).unwrap();
            req.extensions_mut().insert(cert_info("edge-7"));
            if let Some(info) = info {
                req.extensions_mut().insert(info);
            }
            req
        };
        let identity =
            |req: &Request<Body>| authenticating_client_cert(req).map(|c| c.identity.clone());
        let cert_principal = || AuthInfo::ApiKey {
            key_id: "edge-7".into(),
            role: Role::Analyst,
        };
        let session = AuthInfo::Session {
            username: "alice".into(),
            user_id: 1,
            role: Role::Admin,
            session_token: "tok".into(),
            expires_at: String::new(),
            tenant_id: "default".into(),
            scope: String::new(),
        };
        assert_eq!(
            identity(&request(Some(cert_principal()), false)).as_deref(),
            Some("edge-7")
        );
        assert_eq!(identity(&request(Some(cert_principal()), true)), None);
        assert_eq!(identity(&request(Some(session), false)), None);
        assert_eq!(
            identity(&request(Some(AuthInfo::Unauthenticated), false)),
            None
        );
        assert_eq!(identity(&request(None, false)), None);
    }
}
