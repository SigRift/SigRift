//! WebSocket authentication, shared by the gateway's own feeds and the
//! WebSocket proxy to the bridge.
//!
//! * **Before the upgrade** ([`authenticate`]) a WebSocket is checked with
//!   the credentials HTTP accepts — whatever the auth middleware resolved
//!   (session cookie / `Authorization` / `X-Session-Token`, `X-API-Key`,
//!   `?api_key=`, client certificate) — plus a credential in the
//!   subprotocol list, `Sec-WebSocket-Protocol: bridge-v1, <credential>`,
//!   which is an API key or a session token (the dashboard sends whichever
//!   it has; browsers cannot set headers on a WebSocket). A session token
//!   there gets the checks the auth middleware applies to a session
//!   (expiry, idle timeout, disabled user, session binding). An
//!   unauthenticated upgrade gets 401 and an authenticated one below the
//!   required role 403, without upgrading. A session in a restricted scope
//!   (`mfa_setup_only`, `password_change_only`, …) is refused. A session
//!   taken from the cookie, and a client certificate, are refused when the
//!   browser's `Origin` is neither this origin (scheme, host and port) nor
//!   listed in `UC_CORS_ORIGINS` (cross-site WebSocket hijacking: browsers
//!   attach cookies to cross-origin WebSocket handshakes from the same
//!   site, and present a client certificate on any TLS handshake to this
//!   host). A credential in the subprotocol list, or an API key, is not
//!   subject to the `Origin` check: a browser never adds it on its own,
//!   only a script that already holds it.
//! * **While the socket is open** ([`Revalidator`]) the credential is
//!   checked again before every data payload, every `UC_WS_REVALIDATE_SECS`
//!   while idle (default 30 s), and when keys.json is reloaded. It closes with
//!   [`CLOSE_CREDENTIAL_REVOKED`] (4001) when the API key was revoked,
//!   disabled, expired or lost its role, or the session was logged out,
//!   expired (absolute or idle) or its user disabled or demoted. The
//!   session check only reads: it does not extend the session. A
//!   client-certificate socket is looked up in the CA registry again
//!   (which reloads when the bridge changes it), and closed when the
//!   certificate was revoked, expired, removed or its role dropped below
//!   the route's: revocation is recorded in the registry, not in the TLS
//!   connection, which stays open.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, HeaderMap, Request, StatusCode, Uri},
    response::{IntoResponse, Response},
    Json,
};
use rusqlite::{params, OptionalExtension};
use tracing::{debug, warn};

use crate::auth::api_key::extract_api_key;
use crate::auth::client_cert::ClientCertInfo;
use crate::auth::rbac::Role;
use crate::middleware::auth::{AuthInfo, SessionBindingMode};
use crate::middleware::client_ip::extract_client_ip;
use crate::storage::sessions::{self, ValidatedSession};
use crate::AppState;

/// The subprotocol the bridge and the dashboard use (`bridge.WS_PROTOCOL`).
pub const WS_SUBPROTOCOL: &str = "bridge-v1";
/// Close code sent when the credential a socket was opened with is no
/// longer valid.
pub const CLOSE_CREDENTIAL_REVOKED: u16 = 4001;

/// Who opened a WebSocket.
#[derive(Debug, Clone)]
pub enum WsPrincipal {
    /// Authentication is disabled (`UC_ALLOW_NO_AUTH`).
    Anonymous,
    ApiKey {
        key: String,
        key_id: String,
        role: Role,
    },
    Session {
        token: String,
        username: String,
        role: Role,
    },
    ClientCert {
        identity: String,
        role: Role,
        /// The verified certificate, re-checked against the CA registry
        /// while the socket is open.
        cert: ClientCertInfo,
    },
}

impl WsPrincipal {
    pub fn role(&self) -> Option<Role> {
        match self {
            WsPrincipal::Anonymous => None,
            WsPrincipal::ApiKey { role, .. }
            | WsPrincipal::Session { role, .. }
            | WsPrincipal::ClientCert { role, .. } => Some(*role),
        }
    }

    /// For logs: key id, username or cert identity.
    pub fn name(&self) -> &str {
        match self {
            WsPrincipal::Anonymous => "anonymous",
            WsPrincipal::ApiKey { key_id, .. } => key_id,
            WsPrincipal::Session { username, .. } => username,
            WsPrincipal::ClientCert { identity, .. } => identity,
        }
    }
}

fn refuse(status: StatusCode, detail: &str) -> Response {
    (status, Json(serde_json::json!({ "detail": detail }))).into_response()
}

/// The credential in `Sec-WebSocket-Protocol: bridge-v1, <credential>` (an
/// API key or a session token): the entry after `bridge-v1` in the
/// (comma-separated, possibly repeated) header.
pub fn subprotocol_key(headers: &HeaderMap) -> Option<String> {
    let protocols: Vec<&str> = headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .collect();
    let at = protocols.iter().position(|p| *p == WS_SUBPROTOCOL)?;
    protocols
        .get(at + 1)
        .filter(|key| !key.is_empty())
        .map(|key| key.to_string())
}

/// True when the middleware's session came from the `session_token`
/// cookie (the credential a cross-site page can make the browser send),
/// not from a header only a script on this origin could set.
fn session_from_cookie(headers: &HeaderMap) -> bool {
    let bearer =
        crate::middleware::auth::bearer_credential(headers).is_some_and(|token| !token.is_empty());
    let x_session = headers
        .get("x-session-token")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| !v.trim().is_empty());
    !bearer && !x_session
}

/// `host[:port]`, lower-cased, without the default port of `scheme`
/// (`http` or `https`).
fn normalize_authority(authority: &str, scheme: &str) -> String {
    let authority = authority.trim().to_ascii_lowercase();
    let default_port = match scheme {
        "https" => ":443",
        "http" => ":80",
        _ => "",
    };
    match authority.strip_suffix(default_port) {
        Some(stripped) if !default_port.is_empty() => stripped.to_string(),
        _ => authority,
    }
}

/// `http` or `https` for a web scheme (any case; `ws` and `wss` are their
/// WebSocket forms), `None` for anything else.
fn web_scheme(scheme: &str) -> Option<&'static str> {
    if scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("wss") {
        Some("https")
    } else if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("ws") {
        Some("http")
    } else {
        None
    }
}

/// The entry of a forwarding header (`X-Forwarded-Proto`,
/// `X-Forwarded-Host`) that the direct peer, a trusted proxy, set: the
/// last entry of the last line. A proxy that appends puts its own entry
/// last; what is to its left came from further away, possibly from the
/// client. `None` without the header; `Some("")` when it holds no readable
/// entry.
fn forwarded_entry<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let line = headers.get_all(name).iter().next_back()?;
    Some(
        line.to_str()
            .ok()
            .and_then(|line| line.rsplit(',').next())
            .map_or("", str::trim),
    )
}

/// How a WebSocket handshake reached the gateway, as far as the gateway
/// can tell: what decides which origin is this origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listener {
    /// The gateway terminated TLS for this connection itself
    /// (`UC_TLS_CERT` / `UC_TLS_KEY`): the scheme is `https`, otherwise
    /// `http`.
    pub tls: bool,
    /// The direct peer is a trusted proxy (`UC_TRUSTED_PROXIES`), so its
    /// `X-Forwarded-Proto` and `X-Forwarded-Host` say how the browser
    /// reached that proxy. From any other peer both are ignored.
    pub trusted_proxy: bool,
}

impl Listener {
    /// How a request reached the gateway: over its own TLS listener when
    /// `tls` (the gateway serves TLS, or the request carries a verified
    /// client certificate, which only arrives over that listener), from a
    /// trusted proxy when `peer` is in `trusted_proxies`. Without a known
    /// peer it is not.
    pub(crate) fn of(
        tls: bool,
        peer: Option<SocketAddr>,
        trusted_proxies: &crate::middleware::client_ip::TrustedProxies,
    ) -> Self {
        Self {
            tls,
            trusted_proxy: peer.is_some_and(|peer| trusted_proxies.contains(peer.ip())),
        }
    }
}

/// Whether a browser `Origin` may use an ambient credential of this host
/// (the session cookie, a client certificate) on a WebSocket, or a client
/// certificate on a mutating HTTP request (`middleware::csrf`): no `Origin`
/// (not a browser), an origin listed in `cors_origins` (exactly), or this
/// origin. This origin is the request's scheme (see [`Listener`]) with its
/// `Host`, its URI authority (HTTP/2) or, from a trusted proxy, its
/// `X-Forwarded-Host`; the scheme's default port is implied. An opaque
/// (`null`), unreadable or non-web origin is never this origin, and
/// neither is any origin when a trusted proxy's `X-Forwarded-Proto` is not
/// a web scheme.
pub fn origin_allowed(
    headers: &HeaderMap,
    uri: &Uri,
    cors_origins: &str,
    listener: Listener,
) -> bool {
    let Some(origin) = headers.get(header::ORIGIN) else {
        return true;
    };
    let Ok(origin) = origin.to_str().map(str::trim) else {
        return false;
    };
    if cors_origins
        .split(',')
        .map(str::trim)
        .any(|allowed| !allowed.is_empty() && allowed.eq_ignore_ascii_case(origin))
    {
        return true;
    }
    let Ok(url) = reqwest::Url::parse(origin) else {
        return false; // "null" and other opaque origins
    };
    let (Some(origin_scheme), Some(host)) = (web_scheme(url.scheme()), url.host_str()) else {
        return false;
    };
    let Some(scheme) = this_scheme(headers, listener) else {
        return false;
    };
    if origin_scheme != scheme {
        return false;
    }
    let origin_authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let origin_authority = normalize_authority(&origin_authority, scheme);
    this_authorities(headers, uri, listener)
        .any(|authority| normalize_authority(authority, scheme) == origin_authority)
}

/// [`forwarded_entry`] when the direct peer is a trusted proxy, `None`
/// from any other peer.
fn trusted_forwarded<'a>(
    headers: &'a HeaderMap,
    listener: Listener,
    name: &str,
) -> Option<&'a str> {
    listener
        .trusted_proxy
        .then(|| forwarded_entry(headers, name))
        .flatten()
}

/// The scheme of this origin (see [`Listener`]): a trusted proxy's
/// `X-Forwarded-Proto`, otherwise `https` on the gateway's own TLS
/// listener and `http` on a plain one. `None` when that
/// `X-Forwarded-Proto` is no web scheme.
fn this_scheme(headers: &HeaderMap, listener: Listener) -> Option<&'static str> {
    match trusted_forwarded(headers, listener, "x-forwarded-proto") {
        Some(proto) => web_scheme(proto),
        None if listener.tls => Some("https"),
        None => Some("http"),
    }
}

/// The authorities that name this host: the `Host` header, the URI
/// authority (HTTP/2) and a trusted proxy's `X-Forwarded-Host`, those
/// the request has.
fn this_authorities<'a>(
    headers: &'a HeaderMap,
    uri: &'a Uri,
    listener: Listener,
) -> impl Iterator<Item = &'a str> {
    [
        headers.get(header::HOST).and_then(|v| v.to_str().ok()),
        uri.authority().map(|a| a.as_str()),
        trusted_forwarded(headers, listener, "x-forwarded-host"),
    ]
    .into_iter()
    .flatten()
}

/// What [`authenticate`] needs from an upgrade request. Owned, so the
/// request (whose body is not `Sync`) is not held across an await.
pub struct WsRequest {
    info: AuthInfo,
    api_key: Option<String>,
    /// The verified client certificate of the connection, if any.
    cert: Option<ClientCertInfo>,
    /// URI, headers and peer address of the upgrade (no body), for the
    /// `Origin` check and the session-binding check.
    head: Request<()>,
}

impl WsRequest {
    pub fn of(req: &Request<Body>) -> Self {
        let mut head = Request::new(());
        *head.uri_mut() = req.uri().clone();
        *head.headers_mut() = req.headers().clone();
        if let Some(peer) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
            head.extensions_mut().insert(*peer);
        }
        Self {
            info: req
                .extensions()
                .get::<AuthInfo>()
                .cloned()
                .unwrap_or(AuthInfo::Unauthenticated),
            api_key: extract_api_key(req),
            cert: req.extensions().get::<ClientCertInfo>().cloned(),
            head,
        }
    }

    fn headers(&self) -> &HeaderMap {
        self.head.headers()
    }

    fn uri(&self) -> &Uri {
        self.head.uri()
    }

    /// How this handshake reached the gateway: over its own TLS listener
    /// (a verified client certificate only arrives over one), and whether
    /// the direct peer is a trusted proxy. Without a known peer it is not.
    async fn listener(&self, state: &AppState) -> Listener {
        let peer = self
            .head
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(peer)| *peer);
        Listener::of(
            state.config.tls_enabled() || self.cert.is_some(),
            peer,
            &state.auth_config.read().await.trusted_proxies,
        )
    }

    /// Whether the browser `Origin`, if any, may use this handshake's
    /// ambient credential (see [`origin_allowed`]).
    fn origin_allowed(&self, state: &AppState, listener: Listener) -> bool {
        origin_allowed(
            self.headers(),
            self.uri(),
            &state.config.cors_origins,
            listener,
        )
    }
}

/// The refusal of a handshake whose ambient credential (`what`: the
/// session cookie, a client certificate) came from another origin. The
/// warning names the origin the gateway expected (scheme and host names,
/// see [`origin_allowed`]) and whether the peer is a trusted proxy, so a
/// reverse proxy that is not trusted, or does not send
/// `X-Forwarded-Proto` / `X-Forwarded-Host`, shows in the log.
fn refuse_cross_origin(
    principal: &str,
    what: &str,
    req: &WsRequest,
    listener: Listener,
) -> Response {
    warn_cross_origin(
        "WebSocket refused",
        principal,
        what,
        req.headers(),
        req.uri(),
        listener,
    );
    refuse(StatusCode::FORBIDDEN, "Cross-origin WebSocket refused")
}

/// Log `refused` (what the gateway did) for a request whose ambient
/// credential (`what`) came from another origin than this one: the origin
/// the gateway expected and whether the peer is a trusted proxy.
pub(crate) fn warn_cross_origin(
    refused: &str,
    principal: &str,
    what: &str,
    headers: &HeaderMap,
    uri: &Uri,
    listener: Listener,
) {
    let expected_hosts: Vec<&str> = this_authorities(headers, uri, listener).collect();
    warn!(
        principal,
        origin = ?headers.get(header::ORIGIN),
        expected_scheme = this_scheme(headers, listener)
            .unwrap_or("none (X-Forwarded-Proto is no web scheme)"),
        expected_hosts = ?expected_hosts,
        trusted_proxy = listener.trusted_proxy,
        "{refused}: cross-origin request with {what}"
    );
}

/// Whether a session passes the binding check: the same rule the auth
/// middleware applies to every HTTP request (`BRIDGE_SESSION_BINDING`):
/// `strict` = same client IP and User-Agent as at login, `ip` = same IP,
/// `warn` / `none` = not enforced. A session stored without an IP or
/// User-Agent is not bound to it.
fn session_binding_ok(
    mode: &SessionBindingMode,
    session: &ValidatedSession,
    client_ip: &str,
    user_agent: &str,
) -> bool {
    let ip_mismatch = !session.ip_address.is_empty() && client_ip != session.ip_address;
    let ua_mismatch = !session.user_agent.is_empty() && user_agent != session.user_agent;
    let refused = match mode {
        SessionBindingMode::Strict => ip_mismatch || ua_mismatch,
        SessionBindingMode::Ip => ip_mismatch,
        SessionBindingMode::Warn | SessionBindingMode::None => false,
    };
    if refused {
        warn!(
            username = session.username,
            stored_ip = session.ip_address,
            current_ip = client_ip,
            mode = ?mode,
            "WebSocket session binding rejected"
        );
    } else if (ip_mismatch || ua_mismatch) && *mode == SessionBindingMode::Warn {
        debug!(
            username = session.username,
            ip_mismatch, ua_mismatch, "WebSocket session binding mismatch (warn mode, allowed)"
        );
    }
    !refused
}

/// A session token from the subprotocol list, checked like the auth
/// middleware checks one from a cookie or header: it exists, is within its
/// absolute and idle timeouts, its user is enabled (all
/// `sessions::validate_session`, which also records the activity, as an
/// HTTP request does) and it passes the session-binding check. `None` when
/// it is not a valid session; a 503 refusal when that cannot be read.
#[allow(clippy::result_large_err)] // the Err is the ready-made response
async fn subprotocol_session(
    state: &AppState,
    req: &WsRequest,
    token: &str,
) -> Result<Option<ValidatedSession>, Response> {
    let (session_config, binding_mode, trusted_proxies) = {
        let cfg = state.auth_config.read().await;
        (
            cfg.session_config.clone(),
            cfg.binding_mode.clone(),
            cfg.trusted_proxies.clone(),
        )
    };
    let client_ip = extract_client_ip(&req.head, &trusted_proxies);
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let unavailable = || {
        refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "Authentication unavailable",
        )
    };
    let conn = state.db_pool.get().map_err(|_| unavailable())?;
    if !sessions::session_belongs_to_instance(&conn, token).map_err(|_| unavailable())? {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "Credential belongs to another tenant",
        ));
    }
    let token = token.to_string();
    // A storage error is not "no session": like the HTTP session path it
    // fails closed with 503, so an unreadable row never falls through to
    // the API-key check and a 401.
    let (_conn, session) = crate::db::pool::with_conn_blocking(conn, move |conn| {
        sessions::validate_session(conn, &token, &session_config)
    })
    .await
    .ok_or_else(unavailable)?;
    let Some(session) = session.map_err(|_| unavailable())? else {
        return Ok(None);
    };
    Ok(session_binding_ok(&binding_mode, &session, &client_ip, &user_agent).then_some(session))
}

/// A session in a restricted scope may not open WebSockets.
fn refuse_restricted_scope(username: &str, scope: &str) -> Response {
    warn!(
        username,
        scope, "WebSocket refused: restricted session scope"
    );
    refuse(
        StatusCode::FORBIDDEN,
        "This session cannot open WebSockets until it is fully authenticated",
    )
}

/// The principal for the credential in the subprotocol list: a session
/// token (checked first: a database lookup, no PBKDF2) or an API key.
#[allow(clippy::result_large_err)]
async fn subprotocol_principal(
    state: &AppState,
    req: &WsRequest,
    credential: String,
) -> Result<WsPrincipal, Response> {
    if let Some(session) = subprotocol_session(state, req, &credential).await? {
        if !session.scope.is_empty() {
            return Err(refuse_restricted_scope(&session.username, &session.scope));
        }
        // Same fallback as the auth middleware for an unknown role name.
        let role = session.role.parse::<Role>().unwrap_or(Role::Viewer);
        return Ok(WsPrincipal::Session {
            token: credential,
            username: session.username,
            role,
        });
    }
    if let Some(store) = state.key_store.as_ref() {
        if let Some((key_id, role)) =
            store
                .validate_for_instance(&credential)
                .await
                .map_err(|_| {
                    refuse(
                        StatusCode::FORBIDDEN,
                        "Credential belongs to another tenant",
                    )
                })?
        {
            return Ok(WsPrincipal::ApiKey {
                key: credential,
                key_id,
                role,
            });
        }
    }
    warn!("WebSocket refused: the subprotocol credential is neither a valid session nor API key");
    Err(refuse(StatusCode::UNAUTHORIZED, "Invalid credentials"))
}

/// Authenticate a WebSocket upgrade request before upgrading it. The `Err`
/// is the ready-made rejection: 401 without a valid credential, 403 for a
/// valid one that may not open this socket (role below `min_role`,
/// restricted session scope, cross-origin cookie or client certificate);
/// nothing is upgraded.
#[allow(clippy::result_large_err)]
pub async fn authenticate(
    state: &AppState,
    mut req: WsRequest,
    min_role: Role,
) -> Result<WsPrincipal, Response> {
    if !state.auth_enabled {
        return Ok(WsPrincipal::Anonymous);
    }
    let listener = req.listener(state).await;
    let info = std::mem::replace(&mut req.info, AuthInfo::Unauthenticated);
    let principal = match info {
        AuthInfo::Session {
            username,
            role,
            session_token,
            scope,
            tenant_id,
            ..
        } => {
            if tenant_id != crate::auth::api_key::INSTANCE_TENANT {
                return Err(refuse(
                    StatusCode::FORBIDDEN,
                    "Credential belongs to another tenant",
                ));
            }
            if !scope.is_empty() {
                return Err(refuse_restricted_scope(&username, &scope));
            }
            if session_from_cookie(req.headers()) && !req.origin_allowed(state, listener) {
                return Err(refuse_cross_origin(
                    &username,
                    "a session cookie",
                    &req,
                    listener,
                ));
            }
            WsPrincipal::Session {
                token: session_token,
                username,
                role,
            }
        }
        AuthInfo::ApiKey { key_id, role } => match (req.api_key.take(), req.cert.take()) {
            // An API key (header or query) is no ambient credential: no
            // Origin check.
            (Some(key), _) => WsPrincipal::ApiKey { key, key_id, role },
            // No API key on the request: the middleware resolved a
            // verified client certificate. The browser presents it on any
            // TLS handshake to this host, so it gets the cookie's check.
            (None, Some(cert)) => {
                if !req.origin_allowed(state, listener) {
                    return Err(refuse_cross_origin(
                        &key_id,
                        "a client certificate",
                        &req,
                        listener,
                    ));
                }
                WsPrincipal::ClientCert {
                    identity: key_id,
                    role,
                    cert,
                }
            }
            (None, None) => {
                warn!(
                    key_id,
                    "WebSocket refused: neither an API key nor a certificate"
                );
                return Err(refuse(StatusCode::UNAUTHORIZED, "Not authenticated"));
            }
        },
        AuthInfo::Unauthenticated => {
            // Nothing the middleware accepts (or a stale cookie): the
            // credential in the subprotocol list, if any.
            let Some(credential) = subprotocol_key(req.headers()) else {
                debug!("WebSocket refused: no credentials");
                return Err(refuse(StatusCode::UNAUTHORIZED, "Not authenticated"));
            };
            subprotocol_principal(state, &req, credential).await?
        }
    };
    if principal
        .role()
        .is_some_and(|role| !role.has_at_least(min_role))
    {
        warn!(
            principal = principal.name(),
            role = ?principal.role(),
            min_role = ?min_role,
            "WebSocket refused: insufficient role"
        );
        return Err(refuse(StatusCode::FORBIDDEN, "Insufficient role"));
    }
    Ok(principal)
}

// ── Re-validation of open sockets ─────────────────────────────────────

/// How often an open socket's credential is re-checked.
#[derive(Debug, Clone, Copy)]
pub struct RevalidateTiming {
    /// How often the cheap checks run (has keys.json been reloaded?).
    pub tick: Duration,
    /// Full re-check interval (`UC_WS_REVALIDATE_SECS`).
    pub period: Duration,
}

/// Default for `UC_WS_REVALIDATE_SECS`.
pub const DEFAULT_REVALIDATE_SECS: u64 = 30;
const REVALIDATE_TICK: Duration = Duration::from_secs(5);

impl RevalidateTiming {
    /// From `UC_WS_REVALIDATE_SECS` (seconds, at least 1; default 30).
    pub fn from_env() -> Self {
        static TIMING: OnceLock<RevalidateTiming> = OnceLock::new();
        *TIMING
            .get_or_init(|| Self::from_secs(std::env::var("UC_WS_REVALIDATE_SECS").ok().as_deref()))
    }

    fn from_secs(raw: Option<&str>) -> Self {
        let secs = match raw.map(str::trim).filter(|s| !s.is_empty()) {
            None => DEFAULT_REVALIDATE_SECS,
            Some(s) => match s.parse::<u64>() {
                Ok(n) => n.max(1),
                Err(_) => {
                    warn!(
                        value = s,
                        "UC_WS_REVALIDATE_SECS is not a number of seconds — using the default"
                    );
                    DEFAULT_REVALIDATE_SECS
                }
            },
        };
        let period = Duration::from_secs(secs);
        Self {
            tick: REVALIDATE_TICK.min(period),
            period,
        }
    }
}

/// Re-checks the credential of one open socket.
pub struct Revalidator {
    principal: WsPrincipal,
    min_role: Role,
    timing: RevalidateTiming,
    last_check: Instant,
    key_generation: Option<u64>,
}

impl Revalidator {
    pub fn new(
        state: &AppState,
        principal: WsPrincipal,
        min_role: Role,
        timing: RevalidateTiming,
    ) -> Self {
        let key_generation = match &principal {
            WsPrincipal::ApiKey { .. } => state.key_store.as_ref().map(|ks| ks.generation()),
            _ => None,
        };
        Self {
            principal,
            min_role,
            timing,
            last_check: Instant::now(),
            key_generation,
        }
    }

    /// How often [`still_valid`](Self::still_valid) should be called.
    pub fn tick(&self) -> Duration {
        self.timing.tick
    }

    pub fn principal(&self) -> &WsPrincipal {
        &self.principal
    }

    /// False once the socket's credential is no longer good enough.
    pub async fn still_valid(&mut self, state: &Arc<AppState>) -> bool {
        self.check(state, false).await
    }

    /// Check the winning credential immediately before forwarding a data
    /// payload. A cached periodic decision must not leak a payload after
    /// revocation, tenant reassignment, expiry or loss of the required role.
    /// API-key verification still uses the current snapshot-bound key cache.
    pub async fn valid_for_payload(&mut self, state: &Arc<AppState>) -> bool {
        self.check(state, true).await
    }

    async fn check(&mut self, state: &Arc<AppState>, force: bool) -> bool {
        let due = force || self.last_check.elapsed() >= self.timing.period;
        let ok = match &self.principal {
            WsPrincipal::Anonymous => true,
            WsPrincipal::ClientCert { cert, .. } => {
                if !due {
                    return true;
                }
                // The registry reloads when the bridge rewrites it; no
                // registry (any more) means no certificate is valid.
                state
                    .cert_registry
                    .as_ref()
                    .and_then(|registry| registry.lookup(cert))
                    .is_some_and(|role| role.has_at_least(self.min_role))
            }
            WsPrincipal::ApiKey { key, key_id, .. } => {
                let Some(store) = state.key_store.as_ref() else {
                    return false;
                };
                let generation = store.generation();
                if !due && Some(generation) == self.key_generation {
                    return true;
                }
                self.key_generation = Some(generation);
                matches!(
                    store.validate(key).await,
                    Some((id, role)) if id == *key_id && role.has_at_least(self.min_role)
                )
            }
            WsPrincipal::Session { token, .. } => {
                if !due {
                    return true;
                }
                session_still_valid(state, token, self.min_role).await
            }
        };
        self.last_check = Instant::now();
        if !ok {
            warn!(
                principal = self.principal.name(),
                "Closing WebSocket: its credential is no longer valid"
            );
        }
        ok
    }
}

/// Read-only session check: the session still exists, is within its
/// absolute and idle timeouts (by the same rule as `validate_session`, so
/// unreadable times refuse it), has full scope, and its user is enabled
/// with at least `min_role`. Unlike `validate_session`, it neither touches
/// `last_active`, so an open socket does not keep an idle session alive,
/// nor deletes a session it refuses.
async fn session_still_valid(state: &Arc<AppState>, token: &str, min_role: Role) -> bool {
    let idle_minutes = state
        .auth_config
        .read()
        .await
        .session_config
        .idle_timeout_minutes;
    let hashed = crate::auth::password::hash_session_token(token);
    let state = Arc::clone(state);
    let row = tokio::task::spawn_blocking(move || {
        let conn = state.db_pool.get().ok()?;
        conn.query_row(
            "SELECT s.expires_at, s.last_active, COALESCE(s.scope, ''), u.enabled, u.role \
             FROM sessions s JOIN users u ON s.user_id = u.id \
             WHERE s.session_token = ?1 AND u.tenant_id = ?2",
            params![hashed, crate::auth::api_key::INSTANCE_TENANT],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, bool>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()
        .ok()
        .flatten()
    })
    .await
    .ok()
    .flatten();
    let Some((expires_at, last_active, scope, enabled, role)) = row else {
        return false;
    };
    // A NULL expiry (the schema forbids it) is no expiry to check: refuse.
    let within_limits = expires_at.as_deref().is_some_and(|expires_at| {
        sessions::session_time_limit(
            expires_at,
            last_active.as_deref(),
            idle_minutes,
            chrono::Utc::now(),
        )
        .is_none()
    });
    let role_ok = role
        .parse::<Role>()
        .is_ok_and(|role| role.has_at_least(min_role));
    within_limits && scope.is_empty() && enabled && role_ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn subprotocol_key_is_the_entry_after_bridge_v1() {
        let h = headers(&[("sec-websocket-protocol", "bridge-v1, sk-123")]);
        assert_eq!(subprotocol_key(&h).as_deref(), Some("sk-123"));
        let h = headers(&[("sec-websocket-protocol", "bridge-v1,sk-123")]);
        assert_eq!(subprotocol_key(&h).as_deref(), Some("sk-123"));
        let h = headers(&[
            ("sec-websocket-protocol", "chat"),
            ("sec-websocket-protocol", "bridge-v1, sk-9"),
        ]);
        assert_eq!(subprotocol_key(&h).as_deref(), Some("sk-9"));
        for none in ["bridge-v1", "sk-123", "chat, sk-123", "bridge-v1, "] {
            let h = headers(&[("sec-websocket-protocol", none)]);
            assert_eq!(subprotocol_key(&h), None, "{none}");
        }
        assert_eq!(subprotocol_key(&HeaderMap::new()), None);
    }

    /// The gateway's own TLS listener, a direct client.
    const TLS: Listener = Listener {
        tls: true,
        trusted_proxy: false,
    };
    /// A plaintext listener, a direct client.
    const PLAIN: Listener = Listener {
        tls: false,
        trusted_proxy: false,
    };
    /// A plaintext listener behind a trusted proxy.
    const PLAIN_BEHIND_PROXY: Listener = Listener {
        tls: false,
        trusted_proxy: true,
    };

    #[test]
    fn origin_must_match_the_host_or_the_cors_list() {
        let uri: Uri = "/ws/status".parse().unwrap();
        let ok =
            |pairs: &[(&str, &str)], cors: &str| origin_allowed(&headers(pairs), &uri, cors, TLS);
        // Not a browser.
        assert!(ok(&[("host", "gw:8444")], ""));
        // Same origin, with and without default ports.
        assert!(ok(
            &[
                ("host", "gw.example:8444"),
                ("origin", "https://gw.example:8444")
            ],
            ""
        ));
        assert!(ok(
            &[("host", "GW.example"), ("origin", "https://gw.example")],
            ""
        ));
        assert!(ok(
            &[("host", "gw.example:443"), ("origin", "https://gw.example")],
            ""
        ));
        assert!(ok(
            &[("host", "gw.example"), ("origin", "https://gw.example:443")],
            ""
        ));
        assert!(ok(
            &[("host", "[::1]:8444"), ("origin", "https://[::1]:8444")],
            ""
        ));
        // Behind a trusted proxy that sets X-Forwarded-Host.
        assert!(origin_allowed(
            &headers(&[
                ("host", "gateway:8444"),
                ("x-forwarded-host", "sigrift.example"),
                ("origin", "http://sigrift.example")
            ]),
            &uri,
            "",
            PLAIN_BEHIND_PROXY
        ));
        // Another port or host on the same site is another origin.
        assert!(!ok(
            &[
                ("host", "gw.example:8444"),
                ("origin", "http://gw.example:8080")
            ],
            ""
        ));
        assert!(!ok(
            &[
                ("host", "gw.example:8444"),
                ("origin", "https://evil.example")
            ],
            ""
        ));
        assert!(!ok(&[("host", "gw.example:8444"), ("origin", "null")], ""));
        // Unless listed (exactly: the scheme is part of the entry).
        assert!(ok(
            &[("host", "gateway:8444"), ("origin", "https://ops.example")],
            "https://other.example, https://ops.example"
        ));
        assert!(!ok(
            &[("host", "gateway:8444"), ("origin", "http://ops.example")],
            "https://ops.example"
        ));
        assert!(origin_allowed(
            &headers(&[("host", "gateway:8444"), ("origin", "http://ops.example")]),
            &uri,
            "http://ops.example",
            TLS
        ));
    }

    /// An origin is a scheme as well as a host and port (RFC 6454): the
    /// scheme is the listener's (`https` on the gateway's TLS listener,
    /// `http` otherwise), and the default port is the one of that scheme.
    #[test]
    fn the_origin_scheme_must_be_the_listener_scheme() {
        let uri: Uri = "/ws/feed".parse().unwrap();
        let ok = |listener: Listener, host: &str, origin: &str| {
            origin_allowed(
                &headers(&[("host", host), ("origin", origin)]),
                &uri,
                "",
                listener,
            )
        };
        for (host, origin) in [
            ("gw.example:8444", "https://gw.example:8444"),
            ("gw.example", "https://gw.example"),
            ("gw.example:443", "https://gw.example"),
            ("gw.example:8444", "wss://gw.example:8444"),
            ("GW.EXAMPLE:8444", "HTTPS://gw.example:8444"),
        ] {
            assert!(ok(TLS, host, origin), "TLS: {host} {origin}");
            assert!(!ok(PLAIN, host, origin), "plain: {host} {origin}");
        }
        for (host, origin) in [
            ("gw.example:8080", "http://gw.example:8080"),
            ("gw.example", "http://gw.example"),
            ("gw.example:80", "http://gw.example"),
            ("gw.example", "http://gw.example:80"),
            ("gw.example:8080", "ws://gw.example:8080"),
        ] {
            assert!(ok(PLAIN, host, origin), "plain: {host} {origin}");
            assert!(!ok(TLS, host, origin), "TLS: {host} {origin}");
        }
        // The default port is the listener scheme's: the port-80 page is
        // not the port-443 gateway, nor the other way round.
        assert!(!ok(TLS, "gw.example", "http://gw.example"));
        assert!(!ok(TLS, "gw.example:443", "http://gw.example:443"));
        assert!(!ok(PLAIN, "gw.example", "https://gw.example"));
        assert!(!ok(TLS, "gw.example:80", "https://gw.example"));
        // Not a web scheme at all.
        for origin in ["ftp://gw.example:8444", "gopher://gw.example:8444"] {
            assert!(!ok(TLS, "gw.example:8444", origin), "{origin}");
            assert!(!ok(PLAIN, "gw.example:8444", origin), "{origin}");
        }
    }

    /// `X-Forwarded-Proto` and `X-Forwarded-Host` count only from a trusted
    /// proxy, and then only the entry that proxy set (the last one): what a
    /// client sends in them never makes its origin this origin.
    #[test]
    fn forwarded_headers_count_only_from_a_trusted_proxy() {
        let uri: Uri = "/ws/feed".parse().unwrap();
        let ok = |listener: Listener, pairs: &[(&str, &str)]| {
            origin_allowed(&headers(pairs), &uri, "", listener)
        };
        let host = ("host", "gw.example:8444");

        // From any other peer both are ignored.
        let forged_host = [
            host,
            ("x-forwarded-host", "evil.example"),
            ("origin", "https://evil.example"),
        ];
        assert!(!ok(TLS, &forged_host));
        let forged_list = [
            host,
            ("x-forwarded-host", "gw.example:8444, evil.example"),
            ("origin", "https://evil.example"),
        ];
        assert!(!ok(TLS, &forged_list));
        let forged_proto = [
            ("host", "gw.example:8080"),
            ("x-forwarded-proto", "https"),
            ("origin", "https://gw.example:8080"),
        ];
        assert!(!ok(PLAIN, &forged_proto));
        assert!(ok(
            PLAIN,
            &[
                ("host", "gw.example:8080"),
                ("x-forwarded-proto", "https"),
                ("origin", "http://gw.example:8080"),
            ]
        ));

        // From a trusted proxy: its scheme and host.
        let via = |proto: &'static str, forwarded_host: &'static str, origin: &'static str| {
            vec![
                ("host", "gateway:8444"),
                ("x-forwarded-proto", proto),
                ("x-forwarded-host", forwarded_host),
                ("origin", origin),
            ]
        };
        assert!(ok(
            PLAIN_BEHIND_PROXY,
            &via("https", "sigrift.example", "https://sigrift.example")
        ));
        assert!(ok(
            PLAIN_BEHIND_PROXY,
            &via("HTTPS", "sigrift.example:443", "https://sigrift.example")
        ));
        assert!(ok(
            PLAIN_BEHIND_PROXY,
            &via("wss", "sigrift.example", "https://sigrift.example")
        ));
        assert!(!ok(
            PLAIN_BEHIND_PROXY,
            &via("https", "sigrift.example", "http://sigrift.example")
        ));
        // A trusted proxy that says the browser used http overrides the
        // gateway's own TLS (TLS from the proxy to the gateway).
        let tls_behind_proxy = Listener {
            tls: true,
            trusted_proxy: true,
        };
        assert!(ok(
            tls_behind_proxy,
            &via("http", "sigrift.example", "http://sigrift.example")
        ));
        assert!(!ok(
            tls_behind_proxy,
            &via("http", "sigrift.example", "https://sigrift.example")
        ));
        // Without X-Forwarded-Proto the listener's scheme applies.
        let no_proto = [
            ("host", "gateway:8444"),
            ("x-forwarded-host", "sigrift.example"),
            ("origin", "http://sigrift.example"),
        ];
        assert!(ok(PLAIN_BEHIND_PROXY, &no_proto));
        assert!(!ok(tls_behind_proxy, &no_proto));
        // An X-Forwarded-Proto that is no web scheme (or empty) fails
        // closed: nothing is this origin.
        for proto in ["ftp", "", " , "] {
            for origin in ["https://sigrift.example", "http://sigrift.example"] {
                assert!(
                    !ok(PLAIN_BEHIND_PROXY, &via(proto, "sigrift.example", origin)),
                    "{proto:?} {origin}"
                );
            }
        }

        // Of several entries only the last counts: the one the trusted
        // proxy added (a client may have sent the others).
        let listed = |forwarded_host: &'static str, origin: &'static str| {
            via("https", forwarded_host, origin)
        };
        assert!(ok(
            PLAIN_BEHIND_PROXY,
            &listed("evil.example, sigrift.example", "https://sigrift.example")
        ));
        assert!(!ok(
            PLAIN_BEHIND_PROXY,
            &listed("evil.example, sigrift.example", "https://evil.example")
        ));
        assert!(!ok(
            PLAIN_BEHIND_PROXY,
            &via("http, https", "sigrift.example", "http://sigrift.example")
        ));
        assert!(ok(
            PLAIN_BEHIND_PROXY,
            &via("http, https", "sigrift.example", "https://sigrift.example")
        ));
        let two_lines = [
            ("host", "gateway:8444"),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "evil.example"),
            ("x-forwarded-host", "sigrift.example"),
        ];
        let with_origin = |origin: &'static str| {
            let mut pairs = two_lines.to_vec();
            pairs.push(("origin", origin));
            pairs
        };
        assert!(ok(
            PLAIN_BEHIND_PROXY,
            &with_origin("https://sigrift.example")
        ));
        assert!(!ok(
            PLAIN_BEHIND_PROXY,
            &with_origin("https://evil.example")
        ));
        // The Host header still names this origin behind the proxy.
        assert!(ok(PLAIN_BEHIND_PROXY, &with_origin("https://gateway:8444")));
    }

    #[test]
    fn session_from_cookie_unless_a_header_carried_it() {
        assert!(session_from_cookie(&headers(&[(
            "cookie",
            "session_token=a"
        )])));
        assert!(!session_from_cookie(&headers(&[(
            "authorization",
            "Bearer a"
        )])));
        assert!(!session_from_cookie(&headers(&[("x-session-token", "a")])));
    }

    /// The middleware reads the `Bearer` scheme in any letter case, so a
    /// session it resolved from `bearer a` came from a header, not from the
    /// cookie. A scheme that carries no session leaves the cookie as its
    /// source.
    #[test]
    fn a_bearer_header_in_any_letter_case_is_no_cookie_session() {
        for value in ["bearer a", "BEARER a", "BeArEr  a "] {
            let carried = headers(&[("authorization", value), ("cookie", "session_token=b")]);
            assert!(!session_from_cookie(&carried), "{value}");
        }
        for value in ["bearer ", "Bearer\ta", "Basic a", "Bearera"] {
            let carried = headers(&[("authorization", value), ("cookie", "session_token=b")]);
            assert!(session_from_cookie(&carried), "{value}");
        }
    }

    #[test]
    fn session_binding_matches_the_middleware_rules() {
        let session = |ip: &str, ua: &str| ValidatedSession {
            session_id: 1,
            user_id: 1,
            username: "alice".into(),
            role: "viewer".into(),
            display_name: String::new(),
            email: String::new(),
            enabled: true,
            tenant_id: "default".into(),
            ip_address: ip.into(),
            user_agent: ua.into(),
            created_at: String::new(),
            expires_at: String::new(),
            last_active: None,
            mfa_enabled: false,
            scope: String::new(),
        };
        let bound = session("10.0.0.1", "Firefox");
        let ok = |mode: SessionBindingMode, ip: &str, ua: &str| {
            session_binding_ok(&mode, &bound, ip, ua)
        };
        assert!(ok(SessionBindingMode::Strict, "10.0.0.1", "Firefox"));
        assert!(!ok(SessionBindingMode::Strict, "10.0.0.1", "curl"));
        assert!(!ok(SessionBindingMode::Strict, "10.0.0.2", "Firefox"));
        assert!(ok(SessionBindingMode::Ip, "10.0.0.1", "curl"));
        assert!(!ok(SessionBindingMode::Ip, "10.0.0.2", "Firefox"));
        assert!(ok(SessionBindingMode::Warn, "10.0.0.2", "curl"));
        assert!(ok(SessionBindingMode::None, "10.0.0.2", "curl"));
        // A session stored without IP / User-Agent is not bound to them.
        assert!(session_binding_ok(
            &SessionBindingMode::Strict,
            &session("", ""),
            "10.0.0.2",
            "curl"
        ));
    }

    #[test]
    fn revalidate_timing_parsing() {
        let t = RevalidateTiming::from_secs(None);
        assert_eq!((t.period.as_secs(), t.tick.as_secs()), (30, 5));
        let t = RevalidateTiming::from_secs(Some("2"));
        assert_eq!((t.period.as_secs(), t.tick.as_secs()), (2, 2));
        assert_eq!(RevalidateTiming::from_secs(Some("0")).period.as_secs(), 1);
        assert_eq!(
            RevalidateTiming::from_secs(Some("soon")).period.as_secs(),
            30
        );
    }

    // ── authenticate() and Revalidator against a real state ──────────

    use crate::auth::api_key::INSTANCE_TENANT;
    use crate::middleware::client_ip::TrustedProxies;
    use crate::ws::test_harness as h;

    /// An upgrade request as the auth middleware hands it to a WebSocket
    /// handler: these headers, from peer 127.0.0.1, with the `AuthInfo` the
    /// middleware resolved (`None`: it resolved nothing).
    fn upgrade(pairs: &[(&str, &str)], info: Option<AuthInfo>) -> Request<Body> {
        let mut req = Request::builder()
            .uri("/ws/feed")
            .body(Body::empty())
            .unwrap();
        *req.headers_mut() = headers(pairs);
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
        if let Some(info) = info {
            req.extensions_mut().insert(info);
        }
        req
    }

    /// A session the middleware resolved (from a cookie or a header).
    fn resolved_session(role: Role, tenant: &str, scope: &str) -> AuthInfo {
        AuthInfo::Session {
            username: "alice".into(),
            user_id: 1,
            role,
            session_token: "tok".into(),
            expires_at: String::new(),
            tenant_id: tenant.into(),
            scope: scope.into(),
        }
    }

    /// `authenticate`'s decision; a refusal as its status.
    async fn decide(
        state: &AppState,
        req: Request<Body>,
        min_role: Role,
    ) -> Result<WsPrincipal, StatusCode> {
        authenticate(state, WsRequest::of(&req), min_role)
            .await
            .map_err(|refusal| refusal.status())
    }

    fn test_state(dir: &tempfile::TempDir) -> Arc<AppState> {
        h::state(dir, "http://127.0.0.1:1", &h::keys_file(&[]), None)
    }

    /// Configure the gateway's own TLS listener (`tls_enabled()` only asks
    /// whether both files are configured).
    fn with_tls(state: &mut AppState, dir: &tempfile::TempDir) {
        state.config.tls_cert = Some(dir.path().join("tls.crt"));
        state.config.tls_key = Some(dir.path().join("tls.key"));
        assert!(state.config.tls_enabled());
    }

    /// A fresh `state` (its only owner) changed by `edit`.
    fn edited(state: Arc<AppState>, edit: impl FnOnce(&mut AppState)) -> Arc<AppState> {
        let Ok(mut state) = Arc::try_unwrap(state) else {
            unreachable!("fresh state has one owner")
        };
        edit(&mut state);
        Arc::new(state)
    }

    fn sql(state: &AppState, statement: &str) {
        state.db_pool.get().unwrap().execute(statement, []).unwrap();
    }

    /// A periodic check that never comes due within a test.
    fn slow() -> RevalidateTiming {
        RevalidateTiming {
            tick: Duration::from_secs(600),
            period: Duration::from_secs(600),
        }
    }

    fn session_principal(token: String) -> WsPrincipal {
        WsPrincipal::Session {
            token,
            username: "alice".into(),
            role: Role::Viewer,
        }
    }

    /// Defence in depth: a session the middleware passed on is still not
    /// enough for a WebSocket when it belongs to another tenant or is in a
    /// restricted scope (MFA setup, forced password change, or one this
    /// build does not know).
    #[tokio::test]
    async fn a_resolved_session_of_another_tenant_or_in_a_restricted_scope_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);
        let bearer = [("authorization", "Bearer tok")];

        let foreign = resolved_session(Role::Admin, "other", "");
        assert_eq!(
            decide(&state, upgrade(&bearer, Some(foreign)), Role::Viewer)
                .await
                .err(),
            Some(StatusCode::FORBIDDEN)
        );
        for scope in ["mfa_setup_only", "password_change_only", "not-yet-invented"] {
            let restricted = resolved_session(Role::Admin, INSTANCE_TENANT, scope);
            assert_eq!(
                decide(&state, upgrade(&bearer, Some(restricted)), Role::Viewer)
                    .await
                    .err(),
                Some(StatusCode::FORBIDDEN),
                "scope {scope}"
            );
        }

        let full = resolved_session(Role::Admin, INSTANCE_TENANT, "");
        match decide(&state, upgrade(&bearer, Some(full)), Role::Viewer).await {
            Ok(WsPrincipal::Session {
                token,
                username,
                role,
            }) => assert_eq!(
                (token.as_str(), username.as_str(), role),
                ("tok", "alice", Role::Admin)
            ),
            other => panic!("expected the session, got {other:?}"),
        }
    }

    /// Cross-site WebSocket hijacking: a page on another origin can make the
    /// browser send the session cookie with the handshake, but cannot add a
    /// header to it.
    #[tokio::test]
    async fn a_cookie_session_needs_this_origin_or_a_listed_one() {
        let dir = tempfile::tempdir().unwrap();
        // `*` is no wildcard here: only the origins listed are trusted. On
        // the gateway's own TLS listener, so this origin is https.
        let state = edited(test_state(&dir), |s| {
            s.config.cors_origins = "https://ops.example, *".into();
            with_tls(s, &dir);
        });
        let session = || Some(resolved_session(Role::Viewer, INSTANCE_TENANT, ""));
        let cookie = ("cookie", "session_token=tok");
        let host = ("host", "gw.example:8444");

        for origin in [
            "https://evil.example",
            "null",
            "",
            "https://gw.example:8445",
            "http://gw.example:8444",
            "https://gw.example.evil.example:8444",
            "https://ops.example.evil.example",
            "http://ops.example",
        ] {
            let req = upgrade(&[cookie, host, ("origin", origin)], session());
            assert_eq!(
                decide(&state, req, Role::Viewer).await.err(),
                Some(StatusCode::FORBIDDEN),
                "origin {origin:?}"
            );
        }
        for origin in ["https://gw.example:8444", "https://OPS.example"] {
            let req = upgrade(&[cookie, host, ("origin", origin)], session());
            assert!(
                decide(&state, req, Role::Viewer).await.is_ok(),
                "origin {origin:?}"
            );
        }
        // Not a browser (no Origin at all).
        assert!(
            decide(&state, upgrade(&[cookie, host], session()), Role::Viewer)
                .await
                .is_ok()
        );

        // A session in a header came from a script that holds the token.
        for credential in [("authorization", "Bearer tok"), ("x-session-token", "tok")] {
            let req = upgrade(
                &[cookie, host, ("origin", "https://evil.example"), credential],
                session(),
            );
            assert!(
                decide(&state, req, Role::Viewer).await.is_ok(),
                "{credential:?}"
            );
        }
        // An empty bearer is no header credential: the cookie decided.
        for empty in [("authorization", "Bearer   "), ("x-session-token", " ")] {
            let req = upgrade(
                &[cookie, host, ("origin", "https://evil.example"), empty],
                session(),
            );
            assert_eq!(
                decide(&state, req, Role::Viewer).await.err(),
                Some(StatusCode::FORBIDDEN),
                "{empty:?}"
            );
        }
    }

    /// An origin is a scheme as well as a host and port (RFC 6454): behind
    /// a TLS-terminating proxy that says the request came over https, a
    /// page served over plain http on the same host (which an active
    /// network attacker can forge) is another origin, and must not open a
    /// WebSocket with the session cookie.
    ///
    /// The same holds on the gateway's own TLS listener (`UC_TLS_CERT` /
    /// `UC_TLS_KEY`), and an `X-Forwarded-Proto` from a peer that is no
    /// trusted proxy says nothing about the scheme. (What must keep working
    /// whichever way the scheme is decided is pinned by
    /// `a_plain_listener_keeps_its_http_origin_whatever_an_untrusted_peer_claims`.)
    #[tokio::test]
    async fn a_plain_http_origin_is_not_the_https_gateway_origin() {
        let session = || Some(resolved_session(Role::Viewer, INSTANCE_TENANT, ""));
        let cookie = ("cookie", "session_token=tok");

        // Behind a TLS-terminating proxy the gateway trusts.
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);
        state.auth_config.write().await.trusted_proxies = TrustedProxies::parse("127.0.0.1").0;
        let via_tls_proxy = [
            cookie,
            ("host", "gateway:8444"),
            ("x-forwarded-host", "sigrift.example"),
            ("x-forwarded-proto", "https"),
        ];
        let with_origin = |origin: &'static str| {
            let mut pairs = via_tls_proxy.to_vec();
            pairs.push(("origin", origin));
            upgrade(&pairs, session())
        };
        assert!(
            decide(&state, with_origin("https://sigrift.example"), Role::Viewer)
                .await
                .is_ok(),
            "the https origin is this origin"
        );
        assert_eq!(
            decide(&state, with_origin("http://sigrift.example"), Role::Viewer)
                .await
                .err(),
            Some(StatusCode::FORBIDDEN),
            "a plain-http page on the same host is another origin"
        );

        // On the gateway's own TLS listener.
        let dir = tempfile::tempdir().unwrap();
        let state = edited(test_state(&dir), |s| {
            s.config.tls_cert = Some(dir.path().join("tls.crt"));
            s.config.tls_key = Some(dir.path().join("tls.key"));
        });
        assert!(state.config.tls_enabled());
        let direct = |origin: &'static str| {
            upgrade(
                &[cookie, ("host", "gw.example:8444"), ("origin", origin)],
                session(),
            )
        };
        assert!(
            decide(&state, direct("https://gw.example:8444"), Role::Viewer)
                .await
                .is_ok(),
            "direct TLS: the https origin is this origin"
        );
        assert_eq!(
            decide(&state, direct("http://gw.example:8444"), Role::Viewer)
                .await
                .err(),
            Some(StatusCode::FORBIDDEN),
            "direct TLS: a plain-http page on the same host and port is another origin"
        );

        // A plain listener stays plain whatever an untrusted peer claims:
        // its forged X-Forwarded-Proto does not make an https page this
        // origin.
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);
        let forged = upgrade(
            &[
                cookie,
                ("host", "127.0.0.1:8080"),
                ("x-forwarded-proto", "https"),
                ("origin", "https://127.0.0.1:8080"),
            ],
            session(),
        );
        assert_eq!(
            decide(&state, forged, Role::Viewer).await.err(),
            Some(StatusCode::FORBIDDEN),
            "untrusted X-Forwarded-Proto changed the scheme"
        );
    }

    /// The half of the scheme rule that holds today and must keep holding
    /// once the scheme is part of the comparison: on a plain listener (no
    /// TLS configured, no trusted proxy) the page's `http://` origin is
    /// this origin, also when an untrusted peer adds
    /// `X-Forwarded-Proto: https`. A fix that simply assumed https would
    /// lock every plain-listener dashboard out.
    #[tokio::test]
    async fn a_plain_listener_keeps_its_http_origin_whatever_an_untrusted_peer_claims() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);
        assert!(!state.config.tls_enabled());
        let session = || Some(resolved_session(Role::Viewer, INSTANCE_TENANT, ""));
        let plain = [
            ("cookie", "session_token=tok"),
            ("host", "127.0.0.1:8080"),
            ("origin", "http://127.0.0.1:8080"),
        ];
        assert!(
            decide(&state, upgrade(&plain, session()), Role::Viewer)
                .await
                .is_ok(),
            "plain listener, http origin"
        );
        let mut forged = plain.to_vec();
        forged.push(("x-forwarded-proto", "https"));
        assert!(
            decide(&state, upgrade(&forged, session()), Role::Viewer)
                .await
                .is_ok(),
            "an untrusted X-Forwarded-Proto does not make the listener https"
        );
    }

    /// `future`'s output, and what it logged at WARN and above (on this
    /// thread, where a `#[tokio::test]` runs it).
    async fn with_warnings<T>(future: impl std::future::Future<Output = T>) -> (T, String) {
        #[derive(Clone, Default)]
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
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish();
        let output = {
            crate::test_support::keep_log_capture_reliable();
            let _guard = tracing::subscriber::set_default(subscriber);
            future.await
        };
        let logged = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        (output, logged)
    }

    /// A refused cross-origin handshake logs the origin the gateway
    /// expected (scheme and host names) and whether the peer is a trusted
    /// proxy, so a reverse proxy that is not in `UC_TRUSTED_PROXIES`, or
    /// that sends no or a bad `X-Forwarded-Proto`, shows in the log.
    #[tokio::test]
    async fn a_cross_origin_refusal_logs_the_origin_the_gateway_expected() {
        let session = || Some(resolved_session(Role::Viewer, INSTANCE_TENANT, ""));
        let via_proxy = |proto: Option<&'static str>| {
            let mut pairs = vec![
                ("cookie", "session_token=tok"),
                ("host", "gateway:8444"),
                ("x-forwarded-host", "sigrift.example"),
                ("origin", "https://sigrift.example"),
            ];
            pairs.extend(proto.map(|proto| ("x-forwarded-proto", proto)));
            upgrade(&pairs, session())
        };
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);
        let refused = |logged: &str, expected: &[&str]| {
            assert!(logged.contains("WebSocket refused"), "{logged}");
            assert!(logged.contains("\"https://sigrift.example\""), "{logged}");
            for part in expected {
                assert!(logged.contains(part), "{part} in {logged}");
            }
        };

        // A proxy the gateway does not trust: its headers count for nothing.
        let (decided, logged) =
            with_warnings(decide(&state, via_proxy(Some("https")), Role::Viewer)).await;
        assert_eq!(decided.err(), Some(StatusCode::FORBIDDEN));
        refused(
            &logged,
            &[
                "expected_scheme=\"http\"",
                "expected_hosts=[\"gateway:8444\"]",
                "trusted_proxy=false",
            ],
        );

        // A trusted proxy that sends no X-Forwarded-Proto.
        state.auth_config.write().await.trusted_proxies = TrustedProxies::parse("127.0.0.1").0;
        let (decided, logged) = with_warnings(decide(&state, via_proxy(None), Role::Viewer)).await;
        assert_eq!(decided.err(), Some(StatusCode::FORBIDDEN));
        refused(
            &logged,
            &[
                "expected_scheme=\"http\"",
                "expected_hosts=[\"gateway:8444\", \"sigrift.example\"]",
                "trusted_proxy=true",
            ],
        );

        // One whose X-Forwarded-Proto is no web scheme.
        let (decided, logged) =
            with_warnings(decide(&state, via_proxy(Some("ftp")), Role::Viewer)).await;
        assert_eq!(decided.err(), Some(StatusCode::FORBIDDEN));
        refused(
            &logged,
            &["expected_scheme=\"none (X-Forwarded-Proto is no web scheme)\""],
        );

        // Control: with X-Forwarded-Proto: https, this is this origin.
        assert!(decide(&state, via_proxy(Some("https")), Role::Viewer)
            .await
            .is_ok());
    }

    #[test]
    fn opaque_unreadable_or_hostless_origins_are_never_this_origin() {
        let uri: Uri = "/ws/feed".parse().unwrap();
        let mut unreadable = headers(&[("host", "gw.example")]);
        unreadable.insert(
            header::ORIGIN,
            HeaderValue::from_bytes(b"https://gw.example\xff").unwrap(),
        );
        for listener in [TLS, PLAIN, PLAIN_BEHIND_PROXY] {
            assert!(!origin_allowed(&unreadable, &uri, "", listener));
            for origin in [
                "file:///etc/passwd",
                "data:text/html,hi",
                "about:blank",
                "gw.example",
                "//gw.example",
                "null",
            ] {
                let h = headers(&[("host", "gw.example"), ("origin", origin)]);
                assert!(!origin_allowed(&h, &uri, "", listener), "{origin}");
            }
            // Empty entries in UC_CORS_ORIGINS do not list the empty origin.
            let empty = headers(&[("host", "gw.example"), ("origin", "")]);
            assert!(!origin_allowed(&empty, &uri, " , ,", listener));
        }
        // An empty Host or X-Forwarded-Host names nothing.
        let tls_behind_proxy = Listener {
            tls: true,
            trusted_proxy: true,
        };
        for pairs in [
            &[("host", ""), ("origin", "https://gw.example")][..],
            &[("x-forwarded-host", ""), ("origin", "https://gw.example")][..],
            &[("x-forwarded-host", "a, "), ("origin", "https://a")][..],
        ] {
            let h = headers(pairs);
            assert!(!origin_allowed(&h, &uri, "", tls_behind_proxy), "{pairs:?}");
        }
        // HTTP/2 carries the authority in the URI, not in Host.
        let h2: Uri = "https://gw.example/ws/feed".parse().unwrap();
        assert!(origin_allowed(
            &headers(&[("origin", "https://gw.example")]),
            &h2,
            "",
            TLS
        ));
        assert!(!origin_allowed(
            &headers(&[("origin", "http://gw.example")]),
            &h2,
            "",
            TLS
        ));
        assert!(!origin_allowed(
            &headers(&[("origin", "https://evil.example")]),
            &h2,
            "",
            TLS
        ));
    }

    /// The middleware's API-key decision is only taken over with the key
    /// (or the verified certificate) actually on the request; the socket is
    /// then re-validated with exactly that credential.
    #[tokio::test]
    async fn a_resolved_api_key_needs_the_key_or_a_certificate_on_the_request() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);
        let resolved = || {
            Some(AuthInfo::ApiKey {
                key_id: "k1".into(),
                role: Role::Analyst,
            })
        };

        assert_eq!(
            decide(&state, upgrade(&[], resolved()), Role::Viewer)
                .await
                .err(),
            Some(StatusCode::UNAUTHORIZED)
        );
        match decide(
            &state,
            upgrade(&[("x-api-key", "sk-1")], resolved()),
            Role::Viewer,
        )
        .await
        {
            Ok(WsPrincipal::ApiKey { key, key_id, role }) => assert_eq!(
                (key.as_str(), key_id.as_str(), role),
                ("sk-1", "k1", Role::Analyst)
            ),
            other => panic!("expected the API key, got {other:?}"),
        }
        let mut req = upgrade(&[], resolved());
        req.extensions_mut().insert(h::client_cert("k1"));
        match decide(&state, req, Role::Viewer).await {
            Ok(WsPrincipal::ClientCert {
                identity,
                role,
                cert,
            }) => {
                assert_eq!((identity.as_str(), role), ("k1", Role::Analyst));
                assert_eq!(cert.serial, "1");
            }
            other => panic!("expected the certificate, got {other:?}"),
        }
    }

    /// A client certificate is an ambient credential, like the session
    /// cookie: a browser that holds one presents it on every TLS handshake
    /// to this host, including a WebSocket handshake a page on another
    /// origin starts (SameSite does not apply to it), and the CA issues
    /// certificates with viewer, analyst and admin roles. So a certificate
    /// handshake from a foreign `Origin` is refused, as a cookie one is.
    #[tokio::test]
    async fn a_certificate_handshake_from_another_origin_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);
        for origin in ["https://evil.example", "null"] {
            let mut req = upgrade(
                &[("host", "gw.example:8444"), ("origin", origin)],
                Some(AuthInfo::ApiKey {
                    key_id: "edge-7".into(),
                    role: Role::Viewer,
                }),
            );
            req.extensions_mut().insert(h::client_cert("edge-7"));
            assert_eq!(
                decide(&state, req, Role::Viewer).await.err(),
                Some(StatusCode::FORBIDDEN),
                "origin {origin}"
            );
        }
    }

    /// What the Origin rule for certificates must leave alone: an agent
    /// (no `Origin`) and a page on this origin keep their certificate
    /// socket.
    #[tokio::test]
    async fn a_certificate_handshake_without_an_origin_or_from_this_origin_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);
        let agent: &[(&str, &str)] = &[("host", "gw.example:8444")];
        let same_origin: &[(&str, &str)] = &[
            ("host", "gw.example:8444"),
            ("origin", "https://gw.example:8444"),
        ];
        for pairs in [agent, same_origin] {
            let mut req = upgrade(
                pairs,
                Some(AuthInfo::ApiKey {
                    key_id: "edge-7".into(),
                    role: Role::Viewer,
                }),
            );
            req.extensions_mut().insert(h::client_cert("edge-7"));
            match decide(&state, req, Role::Viewer).await {
                Ok(WsPrincipal::ClientCert { identity, .. }) => {
                    assert_eq!(identity, "edge-7", "{pairs:?}")
                }
                other => panic!("{pairs:?}: expected the certificate, got {other:?}"),
            }
        }
    }

    /// The certificate gets the whole Origin rule of the cookie: a
    /// certificate only arrives over the gateway's TLS listener, so a
    /// plain-http page on the same host and port is another origin; an
    /// origin listed in `UC_CORS_ORIGINS` is allowed; a client's own
    /// `X-Forwarded-Host` makes no origin this one.
    #[tokio::test]
    async fn the_certificate_origin_rule_is_the_cookie_rule() {
        let dir = tempfile::tempdir().unwrap();
        let state = edited(test_state(&dir), |s| {
            s.config.cors_origins = "https://ops.example".into()
        });
        let cert_upgrade = |pairs: &[(&str, &str)]| {
            let mut req = upgrade(
                pairs,
                Some(AuthInfo::ApiKey {
                    key_id: "edge-7".into(),
                    role: Role::Viewer,
                }),
            );
            req.extensions_mut().insert(h::client_cert("edge-7"));
            req
        };
        let host = ("host", "gw.example:8444");
        for refused in [
            &[host, ("origin", "http://gw.example:8444")][..],
            &[host, ("origin", "http://ops.example")][..],
            &[
                host,
                ("x-forwarded-host", "evil.example"),
                ("origin", "https://evil.example"),
            ][..],
        ] {
            assert_eq!(
                decide(&state, cert_upgrade(refused), Role::Viewer)
                    .await
                    .err(),
                Some(StatusCode::FORBIDDEN),
                "{refused:?}"
            );
        }
        assert!(matches!(
            decide(
                &state,
                cert_upgrade(&[host, ("origin", "https://ops.example")]),
                Role::Viewer
            )
            .await,
            Ok(WsPrincipal::ClientCert { .. })
        ));
    }

    /// An API key is no ambient credential (a page can only send it when
    /// its script holds it): from any origin it is accepted, also when the
    /// connection presents a certificate too (the key then decided).
    #[tokio::test]
    async fn an_api_key_handshake_is_not_subject_to_the_origin_check() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);
        let resolved = || {
            Some(AuthInfo::ApiKey {
                key_id: "k1".into(),
                role: Role::Viewer,
            })
        };
        for with_cert in [false, true] {
            let mut req = upgrade(
                &[
                    ("host", "gw.example:8444"),
                    ("x-api-key", "sk-1"),
                    ("origin", "https://evil.example"),
                ],
                resolved(),
            );
            if with_cert {
                req.extensions_mut().insert(h::client_cert("edge-7"));
            }
            match decide(&state, req, Role::Viewer).await {
                Ok(WsPrincipal::ApiKey { key, .. }) => assert_eq!(key, "sk-1"),
                other => panic!("with_cert={with_cert}: expected the API key, got {other:?}"),
            }
        }
    }

    /// Both callers of [`authenticate`] refuse a certificate handshake from
    /// another origin before upgrading: the native feed, and the proxy
    /// before it opens any connection to the bridge. Without an `Origin`
    /// (an agent) both still open.
    #[tokio::test]
    async fn native_feeds_and_the_proxy_refuse_a_foreign_certificate_handshake() {
        use axum::{extract::State, routing::get, Router};
        let bridge = h::fake_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let registry = dir.path().join("registry.json");
        h::write_cert_registry(&registry, "edge-7", "viewer", false);
        let state = h::with_cert_registry(
            h::state(&dir, &bridge.url, &h::keys_file(&[]), None),
            &registry,
        );
        let routes: Router<Arc<AppState>> = Router::new()
            .route("/ws/feed", get(crate::ws::feed::ws_detection_feed))
            .route(
                "/ws/status",
                get(
                    |State(state): State<Arc<AppState>>, req: Request<Body>| async move {
                        crate::proxy::ws_proxy::ws_proxy(state, req, "/api/nodes/ws/status").await
                    },
                ),
            );
        let addr = h::serve_with_cert(Arc::clone(&state), routes, h::client_cert("edge-7")).await;
        for path in ["/ws/feed", "/ws/status"] {
            for origin in ["https://evil.example", "null", "http://elsewhere.example"] {
                assert_eq!(
                    h::connect(addr, path, &[("origin", origin)]).await.err(),
                    Some(403),
                    "{path} {origin}"
                );
            }
        }
        assert!(bridge.seen.lock().unwrap().is_empty());
        for path in ["/ws/feed", "/ws/status"] {
            let (mut ws, _) = h::connect(addr, path, &[])
                .await
                .unwrap_or_else(|status| panic!("{path}: {status}"));
            ws.close(None).await.unwrap();
        }
        assert_eq!(bridge.seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn every_kind_of_principal_below_the_route_role_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);
        let resolved_key = |role| {
            Some(AuthInfo::ApiKey {
                key_id: "k1".into(),
                role,
            })
        };
        // A sensor key on a viewer feed.
        let req = upgrade(&[("x-api-key", "sk-1")], resolved_key(Role::Sensor));
        assert_eq!(
            decide(&state, req, Role::Viewer).await.err(),
            Some(StatusCode::FORBIDDEN)
        );
        // A node certificate on a viewer feed.
        let mut req = upgrade(&[], resolved_key(Role::Node));
        req.extensions_mut().insert(h::client_cert("k1"));
        assert_eq!(
            decide(&state, req, Role::Viewer).await.err(),
            Some(StatusCode::FORBIDDEN)
        );
        // An analyst session on the admin-only audit feed ...
        let bearer = [("authorization", "Bearer tok")];
        let analyst = resolved_session(Role::Analyst, INSTANCE_TENANT, "");
        assert_eq!(
            decide(&state, upgrade(&bearer, Some(analyst)), Role::Admin)
                .await
                .err(),
            Some(StatusCode::FORBIDDEN)
        );
        // ... where an admin is enough.
        let admin = resolved_session(Role::Admin, INSTANCE_TENANT, "");
        assert!(decide(&state, upgrade(&bearer, Some(admin)), Role::Admin)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn with_authentication_off_the_socket_is_anonymous() {
        let dir = tempfile::tempdir().unwrap();
        let state = edited(test_state(&dir), |s| s.auth_enabled = false);
        let principal = decide(&state, upgrade(&[], None), Role::Admin)
            .await
            .unwrap();
        assert!(matches!(principal, WsPrincipal::Anonymous));
        assert_eq!((principal.role(), principal.name()), (None, "anonymous"));
    }

    /// A session token offered in the subprotocol list gets the checks the
    /// middleware applies to one in a cookie: an expired, idle, logged-out
    /// session or one of a disabled user is no credential.
    #[tokio::test]
    async fn a_subprotocol_session_must_be_live() {
        for (what, change) in [
            (
                "expired",
                "UPDATE sessions SET expires_at='2000-01-01T00:00:00+00:00'",
            ),
            (
                "idle",
                "UPDATE sessions SET last_active='2000-01-01T00:00:00+00:00'",
            ),
            ("disabled user", "UPDATE users SET enabled=0"),
            ("logged out", "DELETE FROM sessions"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state(&dir);
            let token = h::session_for(&state, "alice", "viewer");
            let offer = format!("bridge-v1, {token}");
            let req = || upgrade(&[("sec-websocket-protocol", &offer)], None);
            match decide(&state, req(), Role::Viewer).await {
                Ok(WsPrincipal::Session { token: t, .. }) => assert_eq!(t, token),
                other => panic!("{what}: the live session was refused: {other:?}"),
            }
            sql(&state, change);
            assert_eq!(
                decide(&state, req(), Role::Viewer).await.err(),
                Some(StatusCode::UNAUTHORIZED),
                "{what}"
            );
        }
    }

    /// Session binding for a subprotocol session uses the client address the
    /// middleware would: `X-Forwarded-For` from a peer that is no trusted
    /// proxy does not move the client to the address the session is bound
    /// to, and `strict` binding compares the User-Agent too.
    #[tokio::test]
    async fn a_subprotocol_session_binding_cannot_be_met_with_forged_headers() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);
        state.auth_config.write().await.binding_mode = SessionBindingMode::Ip;
        let roamer = h::session_with(&state, "roamer", "viewer", "203.0.113.7", "");
        let offer = format!("bridge-v1, {roamer}");
        let forged = [
            ("sec-websocket-protocol", offer.as_str()),
            ("x-forwarded-for", "203.0.113.7"),
            ("x-real-ip", "203.0.113.7"),
        ];
        assert_eq!(
            decide(&state, upgrade(&forged, None), Role::Viewer)
                .await
                .err(),
            Some(StatusCode::UNAUTHORIZED)
        );
        // The same header from a trusted proxy does name the client.
        state.auth_config.write().await.trusted_proxies = TrustedProxies::parse("127.0.0.1").0;
        assert!(decide(&state, upgrade(&forged, None), Role::Viewer)
            .await
            .is_ok());
        state.auth_config.write().await.trusted_proxies = TrustedProxies::default();

        state.auth_config.write().await.binding_mode = SessionBindingMode::Strict;
        let local = h::session_with(&state, "local", "viewer", "127.0.0.1", "");
        state
            .db_pool
            .get()
            .unwrap()
            .execute(
                "UPDATE sessions SET user_agent = 'Firefox/140.0' WHERE session_token = ?1",
                [crate::auth::password::hash_session_token(&local)],
            )
            .unwrap();
        let offer = format!("bridge-v1, {local}");
        for user_agent in [Some("curl/8"), None] {
            let mut pairs = vec![("sec-websocket-protocol", offer.as_str())];
            pairs.extend(user_agent.map(|ua| ("user-agent", ua)));
            assert_eq!(
                decide(&state, upgrade(&pairs, None), Role::Viewer)
                    .await
                    .err(),
                Some(StatusCode::UNAUTHORIZED),
                "{user_agent:?}"
            );
        }
        let pairs = [
            ("sec-websocket-protocol", offer.as_str()),
            ("user-agent", "Firefox/140.0"),
        ];
        assert!(decide(&state, upgrade(&pairs, None), Role::Viewer)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn without_a_usable_credential_the_upgrade_is_unauthorized() {
        let dir = tempfile::tempdir().unwrap();
        // No key store: a subprotocol credential that is no session is
        // nothing.
        let state = edited(test_state(&dir), |s| s.key_store = None);
        for protocols in [
            None,
            Some("bridge-v1, sk-anything"),
            Some("bridge-v1"),
            Some("chat, sk-anything"),
        ] {
            let pairs: Vec<_> = protocols
                .map(|p| ("sec-websocket-protocol", p))
                .into_iter()
                .collect();
            assert_eq!(
                decide(&state, upgrade(&pairs, None), Role::Viewer)
                    .await
                    .err(),
                Some(StatusCode::UNAUTHORIZED),
                "{protocols:?}"
            );
        }
    }

    /// Every way a session stops being good enough refuses the next payload,
    /// however far away the periodic check is.
    #[tokio::test]
    async fn the_payload_check_follows_every_session_change() {
        for change in [
            "DELETE FROM sessions",
            "UPDATE sessions SET expires_at='2000-01-01T00:00:00+00:00'",
            // Naive timestamps are UTC.
            "UPDATE sessions SET expires_at='2000-01-01T00:00:00.5'",
            // SQLite's datetime() spelling is read.
            "UPDATE sessions SET expires_at='2000-01-01 00:00:00'",
            "UPDATE sessions SET last_active='2000-01-01T00:00:00+00:00'",
            "UPDATE sessions SET last_active='2000-01-01 00:00:00'",
            // Unreadable times fail closed, as in validate_session.
            "UPDATE sessions SET expires_at='garbage'",
            "UPDATE sessions SET expires_at=''",
            "UPDATE sessions SET last_active='garbage'",
            "UPDATE sessions SET last_active=''",
            "UPDATE sessions SET scope='password_change_only'",
            "UPDATE sessions SET scope='mfa_setup_only'",
            "UPDATE users SET enabled=0",
            "UPDATE users SET role='sensor'",
            "UPDATE users SET role='no-such-role'",
            "UPDATE users SET tenant_id='other'",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state(&dir);
            let token = h::session_for(&state, "alice", "viewer");
            let mut auth = Revalidator::new(&state, session_principal(token), Role::Viewer, slow());
            assert!(auth.valid_for_payload(&state).await, "before: {change}");
            sql(&state, change);
            assert!(!auth.valid_for_payload(&state).await, "{change}");
        }
    }

    /// The re-check reads every stored time format the way
    /// `validate_session` does, so a live session in any of them keeps its
    /// socket (a NULL `last_active` has no idle limit). Refusing one with
    /// unreadable times only reads: the row is neither deleted nor touched.
    #[tokio::test]
    async fn the_payload_check_reads_stored_times_like_validate_session() {
        for change in [
            "UPDATE sessions SET expires_at='2099-01-01T00:00:00+00:00'",
            "UPDATE sessions SET expires_at='2099-01-01T00:00:00.123456+00:00'",
            "UPDATE sessions SET expires_at='2099-01-01T00:00:00Z'",
            "UPDATE sessions SET expires_at='2099-01-01T00:00:00'",
            "UPDATE sessions SET expires_at='2099-01-01T00:00:00.123456'",
            "UPDATE sessions SET expires_at='2099-01-01 00:00:00'",
            "UPDATE sessions SET expires_at='2099-01-01 00:00:00.123456'",
            "UPDATE sessions SET last_active=strftime('%Y-%m-%d %H:%M:%S', 'now')",
            "UPDATE sessions SET last_active=strftime('%Y-%m-%dT%H:%M:%f', 'now')",
            "UPDATE sessions SET last_active=NULL",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state(&dir);
            let token = h::session_for(&state, "alice", "viewer");
            let mut auth = Revalidator::new(&state, session_principal(token), Role::Viewer, slow());
            sql(&state, change);
            assert!(auth.valid_for_payload(&state).await, "{change}");
        }

        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);
        let token = h::session_for(&state, "alice", "viewer");
        let mut auth = Revalidator::new(&state, session_principal(token), Role::Viewer, slow());
        sql(&state, "UPDATE sessions SET last_active='garbage'");
        assert!(!auth.valid_for_payload(&state).await);
        let stored: String = state
            .db_pool
            .get()
            .unwrap()
            .query_row("SELECT last_active FROM sessions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(stored, "garbage", "kept, and not touched");
    }

    /// A NULL `expires_at` is no expiry the re-check can enforce, so the
    /// session is refused (read-only: the row stays), as the bridge's
    /// `get_session` refuses it. The bridge's schema and this crate's test
    /// schema forbid NULL there, so the table is rebuilt without its
    /// constraints first (`CREATE TABLE … AS SELECT` copies none), as a
    /// database written by other tooling might have it.
    #[tokio::test]
    async fn the_payload_check_refuses_a_session_without_an_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);
        let token = h::session_for(&state, "alice", "viewer");
        let mut auth = Revalidator::new(&state, session_principal(token), Role::Viewer, slow());
        let conn = state.db_pool.get().unwrap();
        conn.execute_batch(
            "ALTER TABLE sessions RENAME TO constrained_sessions;
             CREATE TABLE sessions AS SELECT * FROM constrained_sessions;
             DROP TABLE constrained_sessions;",
        )
        .unwrap();
        assert!(auth.valid_for_payload(&state).await, "the rebuilt table");

        sql(&state, "UPDATE sessions SET expires_at = NULL");
        assert!(!auth.valid_for_payload(&state).await);
        let stored: (Option<String>, i64) = conn
            .query_row("SELECT expires_at, COUNT(*) FROM sessions", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(stored, (None, 1), "kept as it was");
    }

    /// The re-check is against the route's role, not merely "still a
    /// user": an admin demoted to analyst (still above viewer) loses the
    /// admin-only socket (`/ws/audit`) at the next payload.
    #[tokio::test]
    async fn an_admin_only_session_socket_closes_when_the_user_drops_below_admin() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);
        let token = h::session_for(&state, "root", "admin");
        let principal = WsPrincipal::Session {
            token,
            username: "root".into(),
            role: Role::Admin,
        };
        let mut auth = Revalidator::new(&state, principal, Role::Admin, slow());
        assert!(auth.valid_for_payload(&state).await, "an admin");
        sql(&state, "UPDATE users SET role='analyst'");
        assert!(!auth.valid_for_payload(&state).await, "demoted to analyst");
    }

    /// The same for an admin API key whose keys.json role drops to analyst.
    #[tokio::test]
    async fn an_admin_only_api_key_socket_closes_when_the_key_drops_below_admin() {
        let dir = tempfile::tempdir().unwrap();
        let keys = |role| h::keys_file(&[h::key_entry("admin-key", "sk-admin", role, false)]);
        let state = h::state(&dir, "http://127.0.0.1:1", &keys("admin"), None);
        let principal = WsPrincipal::ApiKey {
            key: "sk-admin".into(),
            key_id: "admin-key".into(),
            role: Role::Admin,
        };
        let mut auth = Revalidator::new(&state, principal, Role::Admin, slow());
        assert!(auth.valid_for_payload(&state).await, "an admin key");
        h::write_keys(&dir, &keys("analyst"));
        assert!(!auth.valid_for_payload(&state).await, "demoted to analyst");
    }

    /// The same for an admin certificate whose CA registry role drops to
    /// analyst.
    #[tokio::test]
    async fn an_admin_only_certificate_socket_closes_when_the_certificate_drops_below_admin() {
        let dir = tempfile::tempdir().unwrap();
        let registry = dir.path().join("registry.json");
        h::write_cert_registry(&registry, "ops-console", "admin", false);
        let state = h::with_cert_registry(test_state(&dir), &registry);
        let principal = WsPrincipal::ClientCert {
            identity: "ops-console".into(),
            role: Role::Admin,
            cert: h::client_cert("ops-console"),
        };
        let mut auth = Revalidator::new(&state, principal, Role::Admin, slow());
        assert!(auth.valid_for_payload(&state).await, "an admin certificate");
        h::write_cert_registry(&registry, "ops-console", "analyst", false);
        assert!(!auth.valid_for_payload(&state).await, "demoted to analyst");
    }

    /// "The session check only reads": an open socket does not keep its
    /// session alive, so an idle session still idles out.
    #[tokio::test]
    async fn revalidating_a_session_does_not_extend_it() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);
        let token = h::session_for(&state, "alice", "viewer");
        let idle_since = (chrono::Utc::now() - chrono::Duration::minutes(10))
            .format("%Y-%m-%dT%H:%M:%S+00:00")
            .to_string();
        state
            .db_pool
            .get()
            .unwrap()
            .execute("UPDATE sessions SET last_active = ?1", [&idle_since])
            .unwrap();
        // Due at every call.
        let timing = RevalidateTiming {
            tick: Duration::from_millis(1),
            period: Duration::ZERO,
        };
        let mut auth = Revalidator::new(&state, session_principal(token), Role::Viewer, timing);
        for _ in 0..3 {
            assert!(auth.valid_for_payload(&state).await);
            assert!(auth.still_valid(&state).await);
        }
        let stored: String = state
            .db_pool
            .get()
            .unwrap()
            .query_row("SELECT last_active FROM sessions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(stored, idle_since, "last_active untouched");

        // A due periodic check sees a logout too.
        h::delete_sessions(&state);
        assert!(!auth.still_valid(&state).await);
    }

    /// keys.json changing triggers the check of an API-key socket at the next
    /// tick, without waiting for the period (the key is re-checked when the
    /// file is reloaded).
    #[tokio::test]
    async fn an_api_key_socket_is_rechecked_as_soon_as_keys_json_changes() {
        /// A change to the key's keys.json entry.
        type Edit = fn(&mut serde_json::Value);
        let keys_json = |edit: Edit| {
            let mut keys: serde_json::Value = serde_json::from_str(&h::keys_file(&[h::key_entry(
                "viewer-key",
                "sk-viewer",
                "viewer",
                false,
            )]))
            .unwrap();
            edit(&mut keys["keys"]["viewer-key"]);
            keys.to_string()
        };
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, "http://127.0.0.1:1", &keys_json(|_| {}), None);
        let principal = || WsPrincipal::ApiKey {
            key: "sk-viewer".into(),
            key_id: "viewer-key".into(),
            role: Role::Viewer,
        };
        let mut auth = Revalidator::new(&state, principal(), Role::Viewer, slow());
        assert!(auth.valid_for_payload(&state).await, "the key is valid");

        let changes: [(&str, Edit); 5] = [
            ("revoked", |k| k["revoked"] = serde_json::json!(true)),
            ("disabled", |k| k["enabled"] = serde_json::json!(false)),
            ("expired", |k| {
                k["expires_at"] = serde_json::json!("2000-01-01T00:00:00+00:00")
            }),
            ("demoted", |k| k["role"] = serde_json::json!("sensor")),
            ("moved to another tenant", |k| {
                k["tenant_id"] = serde_json::json!("other")
            }),
        ];
        for (what, change) in changes {
            // Back to the key set the key was valid in, then the change.
            h::write_keys(&dir, &keys_json(|_| {}));
            let mut auth = Revalidator::new(&state, principal(), Role::Viewer, slow());
            h::write_keys(&dir, &keys_json(change));
            assert!(!auth.still_valid(&state).await, "{what}");
        }

        // The same secret under another key id is not the socket's key.
        h::write_keys(&dir, &keys_json(|_| {}));
        let mut auth = Revalidator::new(&state, principal(), Role::Viewer, slow());
        h::write_keys(
            &dir,
            &h::keys_file(&[h::key_entry("renamed-key", "sk-viewer", "viewer", false)]),
        );
        assert!(!auth.still_valid(&state).await);
    }

    /// A key also expires with keys.json unchanged, when its `expires_at`
    /// passes. The key-set generation does not move and the period is far
    /// away, so only the payload check's own re-check can refuse the key
    /// before the next payload. A key of the same file that expires
    /// tomorrow passes the same check, so the refusal is the expiry.
    #[tokio::test]
    async fn the_payload_check_refuses_a_key_that_expired_while_keys_json_was_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let mut keys: serde_json::Value = serde_json::from_str(&h::keys_file(&[
            h::key_entry("expiring-key", "sk-1", "viewer", false),
            h::key_entry("valid-key", "sk-viewer", "viewer", false),
        ]))
        .unwrap();
        let expires = chrono::Utc::now() + chrono::Duration::milliseconds(200);
        keys["keys"]["expiring-key"]["expires_at"] = serde_json::json!(expires.to_rfc3339());
        keys["keys"]["valid-key"]["expires_at"] =
            serde_json::json!((chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339());
        let state = h::state(&dir, "http://127.0.0.1:1", &keys.to_string(), None);
        let principal = |key_id: &str, key: &str| WsPrincipal::ApiKey {
            key: key.into(),
            key_id: key_id.into(),
            role: Role::Viewer,
        };

        let mut auth = Revalidator::new(
            &state,
            principal("expiring-key", "sk-1"),
            Role::Viewer,
            slow(),
        );
        while chrono::Utc::now() <= expires {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(!auth.valid_for_payload(&state).await, "expired");

        let mut auth = Revalidator::new(
            &state,
            principal("valid-key", "sk-viewer"),
            Role::Viewer,
            slow(),
        );
        assert!(auth.valid_for_payload(&state).await, "expires tomorrow");
    }

    #[tokio::test]
    async fn sockets_whose_credential_store_is_gone_are_closed() {
        let dir = tempfile::tempdir().unwrap();
        let state = edited(test_state(&dir), |s| s.key_store = None);
        let key = WsPrincipal::ApiKey {
            key: "sk-1".into(),
            key_id: "k1".into(),
            role: Role::Viewer,
        };
        let mut auth = Revalidator::new(&state, key, Role::Viewer, slow());
        assert!(!auth.still_valid(&state).await, "no keys.json");

        // No CA registry: no certificate is valid.
        let cert = || WsPrincipal::ClientCert {
            identity: "edge-7".into(),
            role: Role::Viewer,
            cert: h::client_cert("edge-7"),
        };
        let mut auth = Revalidator::new(&state, cert(), Role::Viewer, slow());
        assert!(!auth.valid_for_payload(&state).await, "no CA registry");

        // A registry that no longer lists the certificate.
        let dir = tempfile::tempdir().unwrap();
        let registry = dir.path().join("registry.json");
        h::write_cert_registry(&registry, "edge-8", "viewer", false);
        let state = h::with_cert_registry(test_state(&dir), &registry);
        let mut auth = Revalidator::new(&state, cert(), Role::Viewer, slow());
        assert!(!auth.valid_for_payload(&state).await, "certificate removed");

        // Authentication off: nothing to re-check.
        let mut auth = Revalidator::new(&state, WsPrincipal::Anonymous, Role::Viewer, slow());
        assert!(auth.valid_for_payload(&state).await);
    }

    /// A subprotocol session token whose session store cannot be read at
    /// all (its table is gone, so the tenant check already fails) is
    /// refused with 503 ("authentication unavailable"), not 401. For a
    /// single unreadable session row see
    /// `a_subprotocol_session_whose_row_cannot_be_read_is_503`.
    #[tokio::test]
    async fn a_subprotocol_session_fails_closed_when_the_session_store_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);
        let token = h::session_for(&state, "alice", "viewer");
        let offer = format!("bridge-v1, {token}");
        let req = || upgrade(&[("sec-websocket-protocol", &offer)], None);
        assert!(decide(&state, req(), Role::Viewer).await.is_ok());

        sql(&state, "ALTER TABLE sessions RENAME TO sessions_moved");
        assert_eq!(
            decide(&state, req(), Role::Viewer).await.err(),
            Some(StatusCode::SERVICE_UNAVAILABLE)
        );
    }

    /// A subprotocol session token whose session row cannot be read (a
    /// stored value of the wrong type, standing in for a storage error) is
    /// refused with 503, as the auth middleware refuses the same token in
    /// a header or cookie (`an_unreadable_session_fails_closed`): an
    /// unknown answer is not "no session", to be tried as an API key and
    /// refused with 401 as a bad credential.
    #[tokio::test]
    async fn a_subprotocol_session_whose_row_cannot_be_read_is_503() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(&dir);
        let token = h::session_for(&state, "alice", "viewer");
        let offer = format!("bridge-v1, {token}");
        let req = || upgrade(&[("sec-websocket-protocol", &offer)], None);
        assert!(decide(&state, req(), Role::Viewer).await.is_ok());

        sql(&state, "UPDATE sessions SET created_at = X'00'");
        assert_eq!(
            decide(&state, req(), Role::Viewer).await.err(),
            Some(StatusCode::SERVICE_UNAVAILABLE)
        );
    }

    /// The same for any column of the session or its user that cannot be
    /// read, not only the session's creation time.
    #[tokio::test]
    async fn a_subprotocol_session_with_any_unreadable_field_is_503() {
        for change in [
            "UPDATE users SET role = X'00'",
            "UPDATE users SET enabled = 'yes'",
            "UPDATE sessions SET scope = X'00'",
            "UPDATE users SET username = X'00'",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state(&dir);
            let token = h::session_for(&state, "alice", "viewer");
            let offer = format!("bridge-v1, {token}");
            let req = || upgrade(&[("sec-websocket-protocol", &offer)], None);
            assert!(
                decide(&state, req(), Role::Viewer).await.is_ok(),
                "before: {change}"
            );
            sql(&state, change);
            assert_eq!(
                decide(&state, req(), Role::Viewer).await.err(),
                Some(StatusCode::SERVICE_UNAVAILABLE),
                "{change}"
            );
        }
    }

    /// The same for a storage error inside `validate_session` that is not a
    /// column of the wrong type, after the tenant check has read the row:
    /// the `last_active` update fails (as on a busy or read-only database),
    /// or a column the session query reads is gone.
    #[tokio::test]
    async fn a_subprotocol_session_whose_validation_fails_in_storage_is_503() {
        for change in [
            "CREATE TRIGGER refuse_touch BEFORE UPDATE OF last_active ON sessions \
             BEGIN SELECT RAISE(ABORT, 'attempt to write a readonly database'); END",
            "ALTER TABLE users DROP COLUMN display_name",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state(&dir);
            let token = h::session_for(&state, "alice", "viewer");
            let offer = format!("bridge-v1, {token}");
            let req = || upgrade(&[("sec-websocket-protocol", &offer)], None);
            assert!(
                decide(&state, req(), Role::Viewer).await.is_ok(),
                "before: {change}"
            );
            sql(&state, change);
            assert_eq!(
                decide(&state, req(), Role::Viewer).await.err(),
                Some(StatusCode::SERVICE_UNAVAILABLE),
                "{change}"
            );
        }
    }

    /// An open session socket whose session row can no longer be read (a
    /// value of the wrong type, standing in for a storage error) fails the
    /// re-check: the socket is closed, not kept on the last good answer.
    #[tokio::test]
    async fn a_session_socket_closes_when_its_session_cannot_be_read() {
        for change in [
            "UPDATE users SET role = X'00'",
            "UPDATE users SET enabled = 'yes'",
            "UPDATE sessions SET scope = X'00'",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state(&dir);
            let token = h::session_for(&state, "alice", "viewer");
            let mut auth = Revalidator::new(
                &state,
                session_principal(token.clone()),
                Role::Viewer,
                slow(),
            );
            assert!(
                matches!(auth.principal(), WsPrincipal::Session { token: t, .. } if *t == token)
            );
            assert!(auth.valid_for_payload(&state).await, "before: {change}");
            sql(&state, change);
            assert!(!auth.valid_for_payload(&state).await, "{change}");
        }
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    /// The name a WebSocket principal is logged under never carries its
    /// credential: an API-key socket is named by its key id (not the key),
    /// a session socket by its username (not the token), a certificate
    /// socket by the certificate's identity.
    #[test]
    fn a_principal_is_logged_by_name_never_by_its_credential() {
        let principals = [
            WsPrincipal::Anonymous,
            WsPrincipal::ApiKey {
                key: "raw-credential-text".into(),
                key_id: "ops-key".into(),
                role: Role::Analyst,
            },
            WsPrincipal::Session {
                token: "raw-session-token".into(),
                username: "alice".into(),
                role: Role::Viewer,
            },
            WsPrincipal::ClientCert {
                identity: "edge-7".into(),
                role: Role::Node,
                cert: ClientCertInfo {
                    identity: "edge-7".into(),
                    serial: "66".into(),
                    fingerprint_sha256: "ab".repeat(32),
                },
            },
        ];
        let names: Vec<&str> = principals.iter().map(WsPrincipal::name).collect();
        assert_eq!(names, ["anonymous", "ops-key", "alice", "edge-7"]);
        for secret in ["raw-credential-text", "raw-session-token"] {
            assert!(!names.iter().any(|name| name.contains(secret)), "{secret}");
        }
    }

    /// Only a web scheme's default port is implied: for any other scheme
    /// nothing is stripped (an empty default port must not "strip" every
    /// authority), and the other web scheme's default port is kept.
    #[test]
    fn only_a_web_schemes_own_default_port_is_dropped() {
        assert_eq!(
            normalize_authority(" Gateway.Example:443 ", "https"),
            "gateway.example"
        );
        assert_eq!(
            normalize_authority("gateway.example:80", "http"),
            "gateway.example"
        );
        assert_eq!(
            normalize_authority("gateway.example:443", "http"),
            "gateway.example:443"
        );
        assert_eq!(
            normalize_authority("Gateway.Example:80", "ftp"),
            "gateway.example:80"
        );
    }
}
