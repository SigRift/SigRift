//! WebSocket proxy — forwards WS connections from the external gateway
//! to the internal Python backend (contract K1, gateway side).
//!
//! * The upgrade is authenticated **before** anything else (see
//!   [`crate::ws::auth::authenticate`]; VIEWER or above): an
//!   unauthenticated client gets 401 and never causes an upstream
//!   connection.
//! * Concurrent proxied sockets are capped per client IP
//!   (`UC_WS_PROXY_MAX_PER_IP`, default 32) and in total
//!   (`UC_WS_PROXY_MAX_TOTAL`, default 1024); `0` disables a cap. Over a
//!   cap the upgrade gets 429 (per IP) or 503 (total).
//! * The upstream request carries the client's query string, its
//!   `Sec-WebSocket-Protocol` verbatim, the credential the gateway verified
//!   in a form the bridge accepts (see [`upstream_credentials`]: a session
//!   as `Cookie: session_token=…`, an API key as `X-API-Key`, whichever
//!   header, query parameter or subprotocol entry it came from),
//!   `X-Rust-Proxy` and `X-Forwarded-For` exactly as the HTTP proxy sets
//!   them, the client's `User-Agent` (the bridge's `strict` session
//!   binding compares it), and the identity headers of the verified
//!   principal; no other client header is forwarded, so client-supplied
//!   trust headers (and credentials the gateway did not accept) never
//!   reach the bridge.
//!   `http://` becomes `ws://`, `https://` `wss://` (certificate verified
//!   unless the backend is loopback, as for HTTP).
//! * The upstream handshake completes before the client is upgraded, so
//!   the subprotocol the bridge selected is echoed to the client, and an
//!   upstream refusal (401/403/429…) is passed on instead of an upgrade.
//! * Data frames are relayed both ways; when either side closes (or goes
//!   away), the other is closed too, with the close code passed on. The
//!   credential is re-validated while the socket is open; the socket is
//!   closed with 4001 when it is no longer valid.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::{
    body::Body,
    extract::{
        ws::{self, CloseFrame, Message, WebSocket},
        FromRequestParts, WebSocketUpgrade,
    },
    http::{header, HeaderMap, HeaderName, HeaderValue, Request, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::{
    self, client::IntoClientRequest, protocol::frame::coding::CloseCode, Message as TMsg,
};
use tracing::{debug, warn};

use crate::auth::rbac::Role;
use crate::middleware::client_ip::{extract_client_ip, TrustedProxies};
use crate::proxy::handler::{
    external_authority, forwarded_for, forwarded_proto, identity_headers, is_loopback_url,
    proxy_secret_header,
};
use crate::ws::auth::{
    authenticate, RevalidateTiming, Revalidator, WsPrincipal, WsRequest, CLOSE_CREDENTIAL_REVOKED,
};
use crate::AppState;

/// How long the upstream handshake may take.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long closing both sides may take once the relay has ended.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

// ── Connection caps ───────────────────────────────────────────────────

/// Default for `UC_WS_PROXY_MAX_PER_IP`.
pub const DEFAULT_MAX_PER_IP: usize = 32;
/// Default for `UC_WS_PROXY_MAX_TOTAL`.
pub const DEFAULT_MAX_TOTAL: usize = 1024;

/// Caps on concurrent proxied WebSockets, per client IP and in total.
#[derive(Debug)]
pub struct WsConnLimits {
    /// 0 = no limit.
    max_per_ip: usize,
    /// 0 = no limit.
    max_total: usize,
    open: Mutex<OpenConns>,
}

#[derive(Debug, Default)]
struct OpenConns {
    total: usize,
    per_ip: HashMap<String, usize>,
}

/// Which cap a connection hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitHit {
    PerIp,
    Total,
}

/// One open proxied socket; releases its slot when dropped.
#[derive(Debug)]
pub struct ConnPermit {
    limits: Arc<WsConnLimits>,
    ip: String,
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        let mut open = self.limits.open.lock().unwrap_or_else(|e| e.into_inner());
        open.total = open.total.saturating_sub(1);
        if let Some(n) = open.per_ip.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                open.per_ip.remove(&self.ip);
            }
        }
    }
}

impl WsConnLimits {
    pub fn new(max_per_ip: usize, max_total: usize) -> Arc<Self> {
        Arc::new(Self {
            max_per_ip,
            max_total,
            open: Mutex::new(OpenConns::default()),
        })
    }

    /// From `UC_WS_PROXY_MAX_PER_IP` / `UC_WS_PROXY_MAX_TOTAL`.
    fn from_env() -> Arc<Self> {
        let read = |name: &str, default: usize| match std::env::var(name) {
            Ok(v) if !v.trim().is_empty() => v.trim().parse().unwrap_or_else(|_| {
                warn!(name, value = %v, default, "Not a number — using the default");
                default
            }),
            _ => default,
        };
        Self::new(
            read("UC_WS_PROXY_MAX_PER_IP", DEFAULT_MAX_PER_IP),
            read("UC_WS_PROXY_MAX_TOTAL", DEFAULT_MAX_TOTAL),
        )
    }

    pub fn try_acquire(self: &Arc<Self>, ip: &str) -> Result<ConnPermit, LimitHit> {
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        if self.max_total > 0 && open.total >= self.max_total {
            return Err(LimitHit::Total);
        }
        let mine = open.per_ip.get(ip).copied().unwrap_or(0);
        if self.max_per_ip > 0 && mine >= self.max_per_ip {
            return Err(LimitHit::PerIp);
        }
        open.total += 1;
        *open.per_ip.entry(ip.to_string()).or_insert(0) += 1;
        Ok(ConnPermit {
            limits: Arc::clone(self),
            ip: ip.to_string(),
        })
    }

    /// Open sockets from `ip`, and in total.
    pub fn open(&self, ip: &str) -> (usize, usize) {
        let open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        (open.per_ip.get(ip).copied().unwrap_or(0), open.total)
    }
}

/// The process-wide caps (configured from the environment once).
pub fn proxy_limits() -> &'static Arc<WsConnLimits> {
    static LIMITS: OnceLock<Arc<WsConnLimits>> = OnceLock::new();
    LIMITS.get_or_init(WsConnLimits::from_env)
}

// ── Handler ───────────────────────────────────────────────────────────

/// Settings of one proxy route (overridable in tests).
#[derive(Clone)]
pub struct WsProxyOptions {
    pub limits: Arc<WsConnLimits>,
    pub timing: RevalidateTiming,
}

impl WsProxyOptions {
    fn from_env() -> Self {
        Self {
            limits: Arc::clone(proxy_limits()),
            timing: RevalidateTiming::from_env(),
        }
    }
}

fn refuse(status: StatusCode, detail: &str) -> Response {
    (status, Json(serde_json::json!({ "detail": detail }))).into_response()
}

/// WebSocket proxy handler — authenticates, then bridges the client to
/// `upstream_path` on the Python backend.
pub async fn ws_proxy(state: Arc<AppState>, req: Request<Body>, upstream_path: &str) -> Response {
    ws_proxy_with(state, req, upstream_path, WsProxyOptions::from_env()).await
}

pub async fn ws_proxy_with(
    state: Arc<AppState>,
    req: Request<Body>,
    upstream_path: &str,
    options: WsProxyOptions,
) -> Response {
    // 1. Authenticate before anything touches the upstream.
    let principal = match authenticate(&state, WsRequest::of(&req), Role::Viewer).await {
        Ok(p) => p,
        Err(rejection) => return rejection,
    };

    // 2. Connection caps.
    let trusted = state.auth_config.read().await.trusted_proxies.clone();
    let client_ip = extract_client_ip(&req, &trusted);
    let permit = match options.limits.try_acquire(&client_ip) {
        Ok(p) => p,
        Err(hit) => {
            warn!(
                client_ip,
                ?hit,
                path = upstream_path,
                "WebSocket proxy connection cap reached"
            );
            return match hit {
                LimitHit::PerIp => refuse(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many WebSocket connections from this address",
                ),
                LimitHit::Total => refuse(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Too many WebSocket connections",
                ),
            };
        }
    };

    // 3. A real upgrade request? Build the upstream request from it.
    let upstream_req = match upstream_request(&state, &req, upstream_path, &principal, &trusted) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "Cannot build the upstream WebSocket request");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    let (mut parts, _body) = req.into_parts();
    let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(ws) => ws,
        Err(rejection) => return rejection.into_response(),
    };

    // 4. Upstream handshake first, so its answer can be relayed.
    let (upstream, selected) = match connect_upstream(&state, upstream_req).await {
        Ok(ok) => ok,
        Err(resp) => return resp,
    };
    let ws = match selected {
        Some(protocol) => ws.protocols([protocol]),
        None => ws,
    };

    let revalidator = Revalidator::new(&state, principal, Role::Viewer, options.timing);
    let path = upstream_path.to_string();
    ws.on_upgrade(move |client| async move {
        relay(client, upstream, revalidator, state, &path).await;
        drop(permit);
    })
}

// ── Upstream request ──────────────────────────────────────────────────

/// `python_url` as a WebSocket base URL: `http` → `ws`, `https` → `wss`.
pub fn ws_base_url(python_url: &str) -> Result<String, String> {
    let url = python_url.trim_end_matches('/');
    if let Some(rest) = url.strip_prefix("http://") {
        Ok(format!("ws://{rest}"))
    } else if let Some(rest) = url.strip_prefix("https://") {
        Ok(format!("wss://{rest}"))
    } else if url.starts_with("ws://") || url.starts_with("wss://") {
        Ok(url.to_string())
    } else {
        Err(format!("unsupported backend URL scheme: {python_url}"))
    }
}

/// The client's `Cookie` header(s) reduced to `session_token` (its name
/// read as the bridge reads it, see [`cookie_pair`]).
///
/// [`cookie_pair`]: crate::middleware::auth::cookie_pair
fn session_cookie(headers: &HeaderMap) -> Option<HeaderValue> {
    use crate::middleware::auth::{cookie_pair, SESSION_COOKIE};
    let kept: Vec<&str> = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .map(str::trim)
        .filter(|c| matches!(cookie_pair(c), Some((name, _)) if name == SESSION_COOKIE))
        .collect();
    if kept.is_empty() {
        return None;
    }
    HeaderValue::from_str(&kept.join("; ")).ok()
}

/// The credential headers for the bridge: exactly the credential the
/// gateway verified, in a form the bridge's `require_ws_auth` reads, and no
/// other. The bridge checks a subprotocol credential first, then a session
/// token (`Authorization: Bearer`, `X-Session-Token`, `session_token`
/// cookie) — refusing outright when that token is not a valid session —
/// then a client certificate, then `X-API-Key`; `?api_key=` only when
/// `BRIDGE_WS_QUERY_AUTH=enabled`. So:
///
/// * a session (from the cookie, `Authorization`, `X-Session-Token` or the
///   subprotocol list) goes as `Cookie: session_token=<token>`;
/// * an API key (from `X-API-Key`, `Authorization: Bearer`, `?api_key=` or
///   the subprotocol list) goes as `X-API-Key`;
/// * a client certificate goes as the identity headers only;
/// * any other credential the client sent (a stale cookie next to a valid
///   key, say) is dropped: the bridge would refuse the socket on it.
///
/// With authentication off (`UC_ALLOW_NO_AUTH`) the client's own
/// credentials are passed on unchanged (the cookie reduced to
/// `session_token`).
fn upstream_credentials(
    principal: &WsPrincipal,
    client: &HeaderMap,
) -> Vec<(HeaderName, HeaderValue)> {
    let mut out = Vec::new();
    match principal {
        WsPrincipal::Session { token, .. } => {
            if let Ok(cookie) = HeaderValue::from_str(&format!("session_token={token}")) {
                out.push((header::COOKIE, cookie));
            }
        }
        WsPrincipal::ApiKey { key, .. } => {
            if let Ok(key) = HeaderValue::from_str(key) {
                out.push((HeaderName::from_static("x-api-key"), key));
            }
        }
        WsPrincipal::ClientCert { .. } => {}
        WsPrincipal::Anonymous => {
            if let Some(cookie) = session_cookie(client) {
                out.push((header::COOKIE, cookie));
            }
            for name in [
                HeaderName::from_static("x-api-key"),
                HeaderName::from_static("x-session-token"),
                header::AUTHORIZATION,
            ] {
                if let Some(value) = client.get(&name) {
                    out.push((name, value.clone()));
                }
            }
        }
    }
    out
}

/// The identity the gateway verified, as the trust headers the HTTP proxy
/// sends (`x-auth-user` / `x-auth-key-id`, `x-auth-role`, and
/// `x-auth-method: client-cert` for a certificate) — taken from the
/// socket's principal, so a credential from the subprotocol list is
/// described too.
fn principal_identity_headers(principal: &WsPrincipal) -> Vec<(HeaderName, HeaderValue)> {
    let mut out = Vec::new();
    let (id_header, id, role) = match principal {
        WsPrincipal::Anonymous => return out,
        WsPrincipal::Session { username, role, .. } => ("x-auth-user", username, role),
        WsPrincipal::ApiKey { key_id, role, .. } => ("x-auth-key-id", key_id, role),
        WsPrincipal::ClientCert { identity, role, .. } => ("x-auth-key-id", identity, role),
    };
    if let Ok(value) = HeaderValue::from_str(id) {
        out.push((HeaderName::from_static(id_header), value));
    }
    out.push((
        HeaderName::from_static("x-auth-role"),
        HeaderValue::from_static(role.as_str()),
    ));
    if matches!(principal, WsPrincipal::ClientCert { .. }) {
        out.push((
            HeaderName::from_static("x-auth-method"),
            HeaderValue::from_static("client-cert"),
        ));
    }
    out
}

fn upstream_request(
    state: &AppState,
    req: &Request<Body>,
    upstream_path: &str,
    principal: &WsPrincipal,
    trusted: &TrustedProxies,
) -> Result<tungstenite::handshake::client::Request, String> {
    let mut url = format!(
        "{}{}",
        ws_base_url(&state.config.python_url)?,
        upstream_path
    );
    if let Some(query) = req.uri().query() {
        url.push('?');
        url.push_str(query);
    }
    let mut upstream = url.into_client_request().map_err(|e| e.to_string())?;
    let out = upstream.headers_mut();
    let client = req.headers();

    // The client's subprotocol list, verbatim (the bridge reads the key
    // from it and selects `bridge-v1`).
    let protocols: Vec<&str> = client
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    if !protocols.is_empty() {
        let joined = HeaderValue::from_str(&protocols.join(", ")).map_err(|e| e.to_string())?;
        out.insert(header::SEC_WEBSOCKET_PROTOCOL, joined);
    }
    for (name, value) in upstream_credentials(principal, client) {
        out.insert(name, value);
    }
    out.insert(
        HeaderName::from_static("x-rust-proxy"),
        proxy_secret_header(&state.config.proxy_secret),
    );
    if let Some(xff) = forwarded_for(req.extensions()) {
        out.insert(HeaderName::from_static("x-forwarded-for"), xff);
    }
    // The browser's User-Agent, as the HTTP proxy forwards it: the bridge's
    // session binding (`BRIDGE_SESSION_BINDING=strict`) compares it with
    // the one stored at login.
    if let Some(ua) = client.get(header::USER_AGENT) {
        out.insert(header::USER_AGENT, ua.clone());
    }
    let identity = match principal {
        // Authentication off: whatever the middleware resolved, as before.
        WsPrincipal::Anonymous => identity_headers(req),
        _ => principal_identity_headers(principal),
    };
    for (name, value) in identity {
        out.insert(name, value);
    }
    // The same rules as the HTTP proxy: the authority the client
    // addressed, and the scheme of the gateway's listener (or of a trusted
    // front proxy), whether or not a Host header came.
    if let Some(authority) = external_authority(req.uri(), client) {
        out.insert(HeaderName::from_static("x-forwarded-host"), authority);
    }
    out.insert(
        HeaderName::from_static("x-forwarded-proto"),
        forwarded_proto(
            state.config.tls_enabled(),
            req.extensions(),
            client,
            trusted,
        ),
    );
    if let Ok(id) = HeaderValue::from_str(&uuid::Uuid::new_v4().to_string()) {
        out.insert(HeaderName::from_static("x-request-id"), id);
    }
    Ok(upstream)
}

// ── Upstream connection ───────────────────────────────────────────────

type Upstream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Connect to the backend. `Ok` carries the subprotocol it selected; `Err`
/// the response for the client (the backend's 4xx is passed on, anything
/// else is 502, a timeout 504).
#[allow(clippy::result_large_err)] // the Err is the ready-made response
async fn connect_upstream(
    state: &AppState,
    request: tungstenite::handshake::client::Request,
) -> Result<(Upstream, Option<String>), Response> {
    let connector =
        if request.uri().scheme_str() == Some("wss") && is_loopback_url(&state.config.python_url) {
            // Loopback backend: skip certificate verification, as the HTTP
            // proxy does.
            Some(tokio_tungstenite::Connector::Rustls(insecure_loopback_tls()))
        } else {
            None
        };
    let target = request.uri().to_string();
    let connect = tokio_tungstenite::connect_async_tls_with_config(request, None, false, connector);
    match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, connect).await {
        Err(_) => {
            warn!(target, "WebSocket proxy: backend handshake timed out");
            Err(StatusCode::GATEWAY_TIMEOUT.into_response())
        }
        Ok(Err(tungstenite::Error::Http(resp))) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            debug!(target, %status, "WebSocket proxy: backend refused the upgrade");
            Err(if status.is_client_error() {
                status.into_response()
            } else {
                StatusCode::BAD_GATEWAY.into_response()
            })
        }
        Ok(Err(e)) => {
            warn!(target, error = %e, "WebSocket proxy: backend unreachable");
            Err(StatusCode::BAD_GATEWAY.into_response())
        }
        Ok(Ok((upstream, resp))) => {
            let selected = resp
                .headers()
                .get(header::SEC_WEBSOCKET_PROTOCOL)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.trim().to_string());
            debug!(target, "WS proxy connected to Python");
            Ok((upstream, selected))
        }
    }
}

/// A rustls client config that accepts any server certificate — used
/// only for a loopback backend.
fn insecure_loopback_tls() -> Arc<rustls::ClientConfig> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    #[derive(Debug)]
    struct AcceptAny(Arc<CryptoProvider>);

    impl ServerCertVerifier for AcceptAny {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let provider = CryptoProvider::get_default()
                .cloned()
                .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
            let config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
                .with_safe_default_protocol_versions()
                .expect("default TLS versions")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
                .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

// ── Relay ─────────────────────────────────────────────────────────────

/// Close frames to send once the relay ends: `None` = send none (that side
/// initiated or is gone), `Some(frame)` = send this one.
struct Closing {
    to_client: Option<Option<CloseFrame>>,
    to_upstream: Option<Option<tungstenite::protocol::CloseFrame>>,
}

fn going_away(reason: &'static str) -> CloseFrame {
    CloseFrame {
        code: ws::close_code::AWAY,
        reason: reason.into(),
    }
}

/// Close codes 1005/1006/1015 (and invalid ones) cannot be sent on the
/// wire; such a close is passed on without a code.
fn close_to_upstream(frame: Option<CloseFrame>) -> Option<tungstenite::protocol::CloseFrame> {
    let frame = frame?;
    let code = CloseCode::from(frame.code);
    code.is_allowed()
        .then(|| tungstenite::protocol::CloseFrame {
            code,
            reason: frame.reason.as_str().into(),
        })
}

fn close_to_client(frame: Option<tungstenite::protocol::CloseFrame>) -> Option<CloseFrame> {
    let frame = frame?;
    frame.code.is_allowed().then(|| CloseFrame {
        code: frame.code.into(),
        reason: frame.reason.as_str().into(),
    })
}

fn credential_revoked() -> Closing {
    Closing {
        to_client: Some(Some(CloseFrame {
            code: CLOSE_CREDENTIAL_REVOKED,
            reason: "credential revoked or expired".into(),
        })),
        to_upstream: Some(Some(tungstenite::protocol::CloseFrame {
            code: CloseCode::Away,
            reason: "client credential revoked".into(),
        })),
    }
}

/// Relay frames until either side closes or the credential stops being
/// valid, then close both sides.
async fn relay(
    client: WebSocket,
    upstream: Upstream,
    mut auth: Revalidator,
    state: Arc<AppState>,
    path: &str,
) {
    let (mut client_tx, mut client_rx) = client.split();
    let (mut up_tx, mut up_rx) = upstream.split();
    let tick = auth.tick();
    let mut check = tokio::time::interval_at(tokio::time::Instant::now() + tick, tick);

    let closing = loop {
        tokio::select! {
            msg = client_rx.next() => match msg {
                Some(Ok(Message::Close(frame))) => break Closing {
                    to_client: None,
                    to_upstream: Some(close_to_upstream(frame)),
                },
                // Pings are answered hop by hop.
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(msg)) => {
                    if !auth.valid_for_payload(&state).await {
                        break credential_revoked();
                    }
                    if let Some(m) = axum_to_tungstenite(msg) {
                        if up_tx.send(m).await.is_err() {
                            break Closing {
                                to_client: Some(Some(going_away("backend closed"))),
                                to_upstream: None,
                            };
                        }
                    }
                }
                Some(Err(_)) | None => break Closing {
                    to_client: None,
                    to_upstream: Some(Some(tungstenite::protocol::CloseFrame {
                        code: CloseCode::Away,
                        reason: "client went away".into(),
                    })),
                },
            },
            msg = up_rx.next() => match msg {
                Some(Ok(TMsg::Close(frame))) => break Closing {
                    to_client: Some(close_to_client(frame)),
                    to_upstream: None,
                },
                Some(Ok(TMsg::Ping(_) | TMsg::Pong(_) | TMsg::Frame(_))) => {}
                Some(Ok(msg)) => {
                    if !auth.valid_for_payload(&state).await {
                        break credential_revoked();
                    }
                    if let Some(m) = tungstenite_to_axum(msg) {
                        if client_tx.send(m).await.is_err() {
                            break Closing {
                                to_client: None,
                                to_upstream: Some(Some(tungstenite::protocol::CloseFrame {
                                    code: CloseCode::Away,
                                    reason: "client went away".into(),
                                })),
                            };
                        }
                    }
                }
                Some(Err(_)) | None => break Closing {
                    to_client: Some(Some(going_away("backend went away"))),
                    to_upstream: None,
                },
            },
            _ = check.tick() => {
                if !auth.still_valid(&state).await {
                    break credential_revoked();
                }
            }
        }
    };

    let close_client = async {
        if let Some(frame) = closing.to_client {
            let _ = client_tx.send(Message::Close(frame)).await;
        }
        let _ = client_tx.close().await;
    };
    let close_upstream = async {
        if let Some(frame) = closing.to_upstream {
            let _ = up_tx.send(TMsg::Close(frame)).await;
        }
        let _ = up_tx.close().await;
    };
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, async {
        tokio::join!(close_client, close_upstream)
    })
    .await;
    debug!(path, "WS proxy closed");
}

fn axum_to_tungstenite(msg: Message) -> Option<TMsg> {
    match msg {
        Message::Text(t) => Some(TMsg::Text(t.as_str().into())),
        Message::Binary(b) => Some(TMsg::Binary(b)),
        Message::Ping(p) => Some(TMsg::Ping(p)),
        Message::Pong(p) => Some(TMsg::Pong(p)),
        Message::Close(frame) => Some(TMsg::Close(close_to_upstream(frame))),
    }
}

fn tungstenite_to_axum(msg: TMsg) -> Option<Message> {
    match msg {
        TMsg::Text(t) => Some(Message::Text(t.as_str().into())),
        TMsg::Binary(b) => Some(Message::Binary(b)),
        TMsg::Ping(p) => Some(Message::Ping(p)),
        TMsg::Pong(p) => Some(Message::Pong(p)),
        TMsg::Close(frame) => Some(Message::Close(close_to_client(frame))),
        TMsg::Frame(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_axum_text_to_tungstenite() {
        let msg = axum_to_tungstenite(Message::Text("hello".into())).unwrap();
        assert_eq!(msg, TMsg::Text("hello".into()));
    }

    #[test]
    fn test_axum_binary_to_tungstenite() {
        let msg = axum_to_tungstenite(Message::Binary(vec![1, 2, 3].into())).unwrap();
        assert_eq!(msg, TMsg::Binary(vec![1, 2, 3].into()));
    }

    #[test]
    fn test_axum_ping_to_tungstenite() {
        let msg = axum_to_tungstenite(Message::Ping(vec![42].into())).unwrap();
        assert_eq!(msg, TMsg::Ping(vec![42].into()));
    }

    #[test]
    fn test_axum_pong_to_tungstenite() {
        let msg = axum_to_tungstenite(Message::Pong(vec![99].into())).unwrap();
        assert_eq!(msg, TMsg::Pong(vec![99].into()));
    }

    #[test]
    fn test_axum_close_to_tungstenite() {
        let msg = axum_to_tungstenite(Message::Close(None)).unwrap();
        assert_eq!(msg, TMsg::Close(None));
    }

    #[test]
    fn test_close_codes_are_passed_on() {
        let msg = axum_to_tungstenite(Message::Close(Some(CloseFrame {
            code: 4003,
            reason: "bye".into(),
        })))
        .unwrap();
        assert_eq!(
            msg,
            TMsg::Close(Some(tungstenite::protocol::CloseFrame {
                code: CloseCode::from(4003),
                reason: "bye".into(),
            }))
        );
        let back = close_to_client(Some(tungstenite::protocol::CloseFrame {
            code: CloseCode::from(4001),
            reason: "revoked".into(),
        }))
        .unwrap();
        assert_eq!((back.code, back.reason.as_str()), (4001, "revoked"));
        // Codes that may not appear on the wire are dropped.
        assert!(close_to_upstream(Some(CloseFrame {
            code: 1006,
            reason: "".into()
        }))
        .is_none());
    }

    #[test]
    fn test_tungstenite_text_to_axum() {
        let msg = tungstenite_to_axum(TMsg::Text("world".into())).unwrap();
        assert!(matches!(msg, Message::Text(_)));
    }

    #[test]
    fn test_tungstenite_binary_to_axum() {
        let msg = tungstenite_to_axum(TMsg::Binary(vec![4, 5, 6].into())).unwrap();
        assert!(matches!(msg, Message::Binary(_)));
    }

    #[test]
    fn test_tungstenite_ping_to_axum() {
        let msg = tungstenite_to_axum(TMsg::Ping(vec![1].into())).unwrap();
        assert!(matches!(msg, Message::Ping(_)));
    }

    #[test]
    fn test_tungstenite_pong_to_axum() {
        let msg = tungstenite_to_axum(TMsg::Pong(vec![2].into())).unwrap();
        assert!(matches!(msg, Message::Pong(_)));
    }

    #[test]
    fn test_tungstenite_close_to_axum() {
        let msg = tungstenite_to_axum(TMsg::Close(None)).unwrap();
        assert!(matches!(msg, Message::Close(_)));
    }

    #[test]
    fn test_tungstenite_frame_filtered() {
        let msg = tungstenite_to_axum(TMsg::Frame(
            tokio_tungstenite::tungstenite::protocol::frame::Frame::ping(vec![]),
        ));
        assert!(msg.is_none(), "Frame variant should be filtered out");
    }

    #[test]
    fn test_ws_base_url_rewrites_both_schemes() {
        assert_eq!(
            ws_base_url("http://bridge:8001").unwrap(),
            "ws://bridge:8001"
        );
        assert_eq!(
            ws_base_url("https://bridge:8001/").unwrap(),
            "wss://bridge:8001"
        );
        assert!(ws_base_url("ftp://bridge").is_err());
    }

    /// A backend URL already given as a WebSocket URL keeps its scheme: a
    /// `wss://` backend is never downgraded to plaintext `ws://`.
    #[test]
    fn test_ws_base_url_keeps_websocket_schemes() {
        assert_eq!(
            ws_base_url("wss://bridge:8001/").unwrap(),
            "wss://bridge:8001"
        );
        assert_eq!(ws_base_url("ws://bridge:8001").unwrap(), "ws://bridge:8001");
        for unusable in ["", "bridge:8001", "httpx://bridge", "WSS:/bridge"] {
            assert!(ws_base_url(unusable).is_err(), "{unusable:?}");
        }
    }

    #[test]
    fn test_session_cookie_keeps_only_the_session_token() {
        let mut h = HeaderMap::new();
        h.append(
            header::COOKIE,
            HeaderValue::from_static("theme=dark; session_token=abc; bridge_token=abc"),
        );
        h.append(header::COOKIE, HeaderValue::from_static("csrf_token=x"));
        assert_eq!(session_cookie(&h).unwrap(), "session_token=abc");
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("theme=dark"));
        assert!(session_cookie(&h).is_none());
        // The name as the bridge reads it, without the whitespace around it.
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("session_tokens=x; session_token\t=abc; Session_Token=y"),
        );
        assert_eq!(session_cookie(&h).unwrap(), "session_token\t=abc");
    }

    #[test]
    fn test_upstream_credentials_follow_the_principal() {
        let mut client = HeaderMap::new();
        client.insert(
            header::COOKIE,
            HeaderValue::from_static("theme=dark; session_token=stale"),
        );
        client.insert("x-api-key", HeaderValue::from_static("sk-other"));
        client.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer x"));
        let names = |out: Vec<(HeaderName, HeaderValue)>| -> Vec<(String, String)> {
            out.into_iter()
                .map(|(n, v)| (n.to_string(), v.to_str().unwrap().to_string()))
                .collect()
        };

        let cert = WsPrincipal::ClientCert {
            identity: "edge-7".into(),
            role: Role::Viewer,
            cert: crate::auth::client_cert::ClientCertInfo {
                identity: "edge-7".into(),
                serial: "1".into(),
                fingerprint_sha256: String::new(),
            },
        };
        // A certificate: nothing from the client (the bridge would try the
        // stale cookie before the certificate and refuse).
        assert!(upstream_credentials(&cert, &client).is_empty());
        assert_eq!(
            names(principal_identity_headers(&cert)),
            vec![
                ("x-auth-key-id".into(), "edge-7".into()),
                ("x-auth-role".into(), "viewer".into()),
                ("x-auth-method".into(), "client-cert".into()),
            ]
        );

        let session = WsPrincipal::Session {
            token: "tok".into(),
            username: "alice".into(),
            role: Role::Analyst,
        };
        assert_eq!(
            names(upstream_credentials(&session, &client)),
            vec![("cookie".into(), "session_token=tok".into())]
        );
        assert_eq!(
            names(principal_identity_headers(&session)),
            vec![
                ("x-auth-user".into(), "alice".into()),
                ("x-auth-role".into(), "analyst".into()),
            ]
        );

        let key = WsPrincipal::ApiKey {
            key: "sk-1".into(),
            key_id: "k1".into(),
            role: Role::Viewer,
        };
        assert_eq!(
            names(upstream_credentials(&key, &client)),
            vec![("x-api-key".into(), "sk-1".into())]
        );

        // Authentication off: the client's credentials, cookie reduced.
        assert_eq!(
            names(upstream_credentials(&WsPrincipal::Anonymous, &client)),
            vec![
                ("cookie".into(), "session_token=stale".into()),
                ("x-api-key".into(), "sk-other".into()),
                ("authorization".into(), "Bearer x".into()),
            ]
        );
        assert!(principal_identity_headers(&WsPrincipal::Anonymous).is_empty());
    }

    /// A verified identity or credential that is no valid header value (a
    /// CR/LF in a username, say) is dropped, never written into another
    /// header: the role header still says what the gateway verified.
    #[test]
    fn test_identity_values_that_are_no_header_values_are_dropped_not_injected() {
        let names = |out: Vec<(HeaderName, HeaderValue)>| -> Vec<(String, String)> {
            out.into_iter()
                .map(|(n, v)| (n.to_string(), v.to_str().unwrap().to_string()))
                .collect()
        };
        let injected = "x\r\nx-auth-role: keymaster";
        let session = WsPrincipal::Session {
            token: injected.into(),
            username: injected.into(),
            role: Role::Viewer,
        };
        assert!(upstream_credentials(&session, &HeaderMap::new()).is_empty());
        assert_eq!(
            names(principal_identity_headers(&session)),
            vec![("x-auth-role".into(), "viewer".into())]
        );
        let key = WsPrincipal::ApiKey {
            key: injected.into(),
            key_id: injected.into(),
            role: Role::Viewer,
        };
        assert!(upstream_credentials(&key, &HeaderMap::new()).is_empty());
        assert_eq!(
            names(principal_identity_headers(&key)),
            vec![("x-auth-role".into(), "viewer".into())]
        );
    }

    #[test]
    fn test_limits_per_ip_and_total() {
        let limits = WsConnLimits::new(2, 3);
        let a1 = limits.try_acquire("a").unwrap();
        let _a2 = limits.try_acquire("a").unwrap();
        assert_eq!(limits.try_acquire("a").unwrap_err(), LimitHit::PerIp);
        let _b1 = limits.try_acquire("b").unwrap();
        assert_eq!(limits.try_acquire("c").unwrap_err(), LimitHit::Total);
        drop(a1);
        assert_eq!(limits.open("a"), (1, 2));
        let _c1 = limits.try_acquire("c").unwrap();
        // 0 disables a cap.
        let unlimited = WsConnLimits::new(0, 0);
        let permits: Vec<_> = (0..100)
            .map(|_| unlimited.try_acquire("a").unwrap())
            .collect();
        assert_eq!(unlimited.open("a"), (100, 100));
        drop(permits);
        assert_eq!(unlimited.open("a"), (0, 0));
    }
}

#[cfg(test)]
mod relay_tests {
    use super::*;
    use crate::middleware::auth::SessionBindingMode;
    use crate::ws::test_harness::{self as h, BridgeEvent};
    use axum::{extract::State, routing::get, Router};
    use std::net::SocketAddr;

    fn fast() -> RevalidateTiming {
        RevalidateTiming {
            tick: Duration::from_millis(50),
            period: Duration::from_millis(100),
        }
    }

    async fn gateway(state: Arc<AppState>, limits: Arc<WsConnLimits>) -> SocketAddr {
        let options = WsProxyOptions {
            limits,
            timing: fast(),
        };
        let routes: Router<Arc<AppState>> = Router::new().route(
            "/ws/status",
            get(
                move |State(state): State<Arc<AppState>>, req: axum::extract::Request| {
                    let options = options.clone();
                    async move { ws_proxy_with(state, req, "/api/nodes/ws/status", options).await }
                },
            ),
        );
        h::serve(state, routes).await
    }

    #[tokio::test]
    async fn unauthenticated_upgrade_is_refused_before_contacting_the_backend() {
        let bridge = h::fake_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, &bridge.url, &h::keys_file(&[]), None);
        let addr = gateway(state, WsConnLimits::new(0, 0)).await;

        let refused = h::connect(addr, "/ws/status", &[]).await.err();
        assert_eq!(refused, Some(401));
        let refused = h::connect(
            addr,
            "/ws/status",
            &[("sec-websocket-protocol", "bridge-v1, not-a-key")],
        )
        .await
        .err();
        assert_eq!(refused, Some(401));
        assert!(bridge.seen.lock().unwrap().is_empty(), "no upstream socket");
    }

    #[tokio::test]
    async fn the_backend_gets_the_client_credentials_and_the_subprotocol_is_echoed() {
        let mut bridge = h::fake_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, &bridge.url, &h::keys_file(&[]), None);
        let token = h::session_for(&state, "alice", "viewer");
        let limits = WsConnLimits::new(0, 0);
        let addr = gateway(state, Arc::clone(&limits)).await;

        let cookie = format!("theme=dark; session_token={token}; bridge_token={token}");
        let (mut ws, protocol) = h::connect(
            addr,
            "/ws/status?since=10&limit=5",
            &[
                ("cookie", &cookie),
                ("sec-websocket-protocol", "bridge-v1, not-a-key"),
                ("x-auth-role", "admin"),
                ("x-rust-proxy", "forged"),
                ("x-forwarded-for", "203.0.113.9"),
            ],
        )
        .await
        .expect("upgraded");
        assert_eq!(protocol.as_deref(), Some("bridge-v1"));

        let seen = bridge.seen.lock().unwrap()[0].clone();
        let header = |name: &str| {
            seen.headers
                .get(name)
                .map(|v| v.to_str().unwrap().to_string())
        };
        assert_eq!(seen.path_and_query, "/api/nodes/ws/status?since=10&limit=5");
        assert_eq!(
            header("sec-websocket-protocol").as_deref(),
            Some("bridge-v1, not-a-key")
        );
        assert_eq!(header("cookie"), Some(format!("session_token={token}")));
        assert_eq!(header("x-rust-proxy").as_deref(), Some(h::PROXY_SECRET));
        assert_eq!(header("x-forwarded-for").as_deref(), Some("127.0.0.1"));
        assert_eq!(header("x-auth-role").as_deref(), Some("viewer"));
        assert_eq!(header("x-auth-user").as_deref(), Some("alice"));

        // Frames are relayed both ways.
        ws.send(TMsg::Text("hi".into())).await.unwrap();
        assert_eq!(
            h::next_msg(&mut ws, 5).await,
            Some(TMsg::Text("echo:hi".into()))
        );
        assert_eq!(limits.open("127.0.0.1"), (1, 1));

        // The backend's close (and its code) reaches the client.
        ws.send(TMsg::Text("close-4003".into())).await.unwrap();
        assert_eq!(h::close_code(&mut ws, 5).await, Some(4003));
        drop(ws);
        // ... and the slot is released.
        for _ in 0..50 {
            if limits.open("127.0.0.1") == (0, 0) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(limits.open("127.0.0.1"), (0, 0));
        let _ = bridge.events.try_recv();
    }

    #[tokio::test]
    async fn closing_the_client_closes_the_backend_socket() {
        let mut bridge = h::fake_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, &bridge.url, &h::keys_file(&[]), None);
        let token = h::session_for(&state, "alice", "viewer");
        let addr = gateway(state, WsConnLimits::new(0, 0)).await;

        let cookie = format!("session_token={token}");
        let (mut ws, _) = h::connect(addr, "/ws/status", &[("cookie", &cookie)])
            .await
            .unwrap();
        ws.close(Some(tungstenite::protocol::CloseFrame {
            code: CloseCode::Normal,
            reason: "done".into(),
        }))
        .await
        .unwrap();
        let event = tokio::time::timeout(Duration::from_secs(5), bridge.events.recv())
            .await
            .expect("backend socket closed");
        assert_eq!(event, Some(BridgeEvent::Closed(Some(1000))));
    }

    #[tokio::test]
    async fn a_cookie_session_from_another_origin_is_refused() {
        let bridge = h::fake_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, &bridge.url, &h::keys_file(&[]), None);
        let token = h::session_for(&state, "alice", "viewer");
        let addr = gateway(state, WsConnLimits::new(0, 0)).await;

        let cookie = format!("session_token={token}");
        let refused = h::connect(
            addr,
            "/ws/status",
            &[("cookie", &cookie), ("origin", "http://127.0.0.1:1")],
        )
        .await
        .err();
        assert_eq!(refused, Some(403));
        // The same session from this origin is fine.
        let origin = format!("http://{addr}");
        assert!(h::connect(
            addr,
            "/ws/status",
            &[("cookie", &cookie), ("origin", &origin)]
        )
        .await
        .is_ok());
        assert_eq!(bridge.seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_viewer_role_is_required() {
        let bridge = h::fake_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, &bridge.url, &h::keys_file(&[]), None);
        let token = h::session_for(&state, "probe", "sensor");
        let addr = gateway(state, WsConnLimits::new(0, 0)).await;
        let cookie = format!("session_token={token}");
        let refused = h::connect(addr, "/ws/status", &[("cookie", &cookie)])
            .await
            .err();
        assert_eq!(refused, Some(403));
        assert!(bridge.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn connections_per_client_ip_are_capped() {
        let bridge = h::fake_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, &bridge.url, &h::keys_file(&[]), None);
        let token = h::session_for(&state, "alice", "viewer");
        let limits = WsConnLimits::new(1, 10);
        let addr = gateway(state, Arc::clone(&limits)).await;
        let cookie = format!("session_token={token}");

        let (first, _) = h::connect(addr, "/ws/status", &[("cookie", &cookie)])
            .await
            .unwrap();
        let refused = h::connect(addr, "/ws/status", &[("cookie", &cookie)])
            .await
            .err();
        assert_eq!(refused, Some(429));
        drop(first);
        for _ in 0..50 {
            if limits.open("127.0.0.1").0 == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(h::connect(addr, "/ws/status", &[("cookie", &cookie)])
            .await
            .is_ok());
    }

    fn header_of(seen: &h::Seen, name: &str) -> Option<String> {
        seen.headers
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
    }

    /// What the dashboard sends: `new WebSocket(url, ["bridge-v1",
    /// apiKey || sessionToken])`, and after an MFA login (or with a stale
    /// cookie) no usable `session_token` cookie.
    #[tokio::test]
    async fn a_session_token_in_the_subprotocol_list_is_enough() {
        let mut bridge = h::fake_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, &bridge.url, &h::keys_file(&[]), None);
        let token = h::session_for(&state, "root", "admin");
        let addr = gateway(Arc::clone(&state), WsConnLimits::new(0, 0)).await;
        let protocols = format!("bridge-v1, {token}");

        // No cookie at all, and a script on another origin (it holds the
        // token, so the Origin check does not apply to it).
        let (mut ws, protocol) = h::connect(
            addr,
            "/ws/status",
            &[
                ("sec-websocket-protocol", &protocols),
                ("origin", "https://elsewhere.example"),
            ],
        )
        .await
        .expect("upgraded");
        assert_eq!(protocol.as_deref(), Some("bridge-v1"));
        let seen = bridge.seen.lock().unwrap()[0].clone();
        assert_eq!(
            header_of(&seen, "sec-websocket-protocol"),
            Some(protocols.clone())
        );
        assert_eq!(
            header_of(&seen, "cookie"),
            Some(format!("session_token={token}"))
        );
        assert_eq!(header_of(&seen, "x-auth-user").as_deref(), Some("root"));
        assert_eq!(header_of(&seen, "x-auth-role").as_deref(), Some("admin"));
        ws.send(TMsg::Text("hi".into())).await.unwrap();
        assert_eq!(
            h::next_msg(&mut ws, 5).await,
            Some(TMsg::Text("echo:hi".into()))
        );

        // A stale cookie next to it does not get in the way, and is not
        // passed on.
        let (_ws2, _) = h::connect(
            addr,
            "/ws/status",
            &[
                ("sec-websocket-protocol", &protocols),
                ("cookie", "session_token=logged-out-long-ago"),
            ],
        )
        .await
        .expect("upgraded");
        let seen = bridge.seen.lock().unwrap()[1].clone();
        assert_eq!(
            header_of(&seen, "cookie"),
            Some(format!("session_token={token}"))
        );

        // It is re-checked like any session: logging out closes the socket.
        h::delete_sessions(&state);
        assert_eq!(
            h::close_code(&mut ws, 5).await,
            Some(CLOSE_CREDENTIAL_REVOKED)
        );
        let event = tokio::time::timeout(Duration::from_secs(5), bridge.events.recv())
            .await
            .expect("backend socket closed too");
        assert!(matches!(event, Some(BridgeEvent::Closed(_))));
    }

    #[tokio::test]
    async fn a_session_token_in_the_subprotocol_list_gets_the_session_checks() {
        let bridge = h::fake_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, &bridge.url, &h::keys_file(&[]), None);
        state.auth_config.write().await.binding_mode = SessionBindingMode::Ip;
        let mfa_pending = h::session_with(&state, "new", "admin", "", "mfa_setup_only");
        let elsewhere = h::session_with(&state, "roamer", "admin", "10.9.9.9", "");
        let here = h::session_with(&state, "local", "viewer", "127.0.0.1", "");
        let sensor = h::session_for(&state, "probe", "sensor");
        let addr = gateway(Arc::clone(&state), WsConnLimits::new(0, 0)).await;
        let offer = |token: &str| format!("bridge-v1, {token}");

        let status = |token: String| async move {
            h::connect(addr, "/ws/status", &[("sec-websocket-protocol", &token)])
                .await
                .err()
        };
        // Restricted scope: refused.
        assert_eq!(status(offer(&mfa_pending)).await, Some(403));
        // Bound to another client IP (BRIDGE_SESSION_BINDING=ip): not a
        // valid session here, as for HTTP.
        assert_eq!(status(offer(&elsewhere)).await, Some(401));
        // Below VIEWER.
        assert_eq!(status(offer(&sensor)).await, Some(403));
        // Neither a session nor a key.
        assert_eq!(status(offer("nonsense")).await, Some(401));
        assert!(bridge.seen.lock().unwrap().is_empty(), "no upstream socket");
        // Bound to this client: fine.
        assert_eq!(status(offer(&here)).await, None);
        assert_eq!(bridge.seen.lock().unwrap().len(), 1);
    }

    /// Every credential the gateway accepts reaches the bridge in a form
    /// the bridge's `require_ws_auth` accepts, and nothing it would refuse
    /// the socket on.
    #[tokio::test]
    async fn the_backend_gets_the_verified_credential_in_a_form_it_accepts() {
        let bridge = h::fake_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let keys = h::keys_file(&[h::key_entry("viewer-key", "sk-viewer", "viewer", false)]);
        let state = h::state(&dir, &bridge.url, &keys, None);
        let token = h::session_for(&state, "alice", "viewer");
        let addr = gateway(Arc::clone(&state), WsConnLimits::new(0, 0)).await;
        let credentials = |i: usize| {
            let seen = bridge.seen.lock().unwrap()[i].clone();
            (
                header_of(&seen, "cookie"),
                header_of(&seen, "x-api-key"),
                header_of(&seen, "authorization"),
                header_of(&seen, "x-session-token"),
                seen.path_and_query,
            )
        };
        let connect = |path: &'static str, headers: Vec<(&'static str, String)>| async move {
            let headers: Vec<(&str, &str)> =
                headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
            h::connect(addr, path, &headers).await.expect("upgraded").0
        };

        // A session in X-Session-Token goes as the session cookie.
        let _a = connect("/ws/status", vec![("x-session-token", token.clone())]).await;
        assert_eq!(
            credentials(0),
            (
                Some(format!("session_token={token}")),
                None,
                None,
                None,
                "/api/nodes/ws/status".into()
            )
        );
        // ... and so does one in Authorization.
        let _b = connect(
            "/ws/status",
            vec![("authorization", format!("Bearer {token}"))],
        )
        .await;
        assert_eq!(credentials(1).0, Some(format!("session_token={token}")));
        assert_eq!(credentials(1).2, None);

        // A key in ?api_key= goes as X-API-Key (the bridge refuses query
        // keys unless BRIDGE_WS_QUERY_AUTH=enabled); the query is unchanged.
        let _c = connect("/ws/status?api_key=sk-viewer&since=5", vec![]).await;
        assert_eq!(
            credentials(2),
            (
                None,
                Some("sk-viewer".into()),
                None,
                None,
                "/api/nodes/ws/status?api_key=sk-viewer&since=5".into()
            )
        );
        // A key in Authorization: Bearer (the bridge would read it as a
        // session token) goes as X-API-Key too.
        let _d = connect(
            "/ws/status",
            vec![("authorization", "Bearer sk-viewer".into())],
        )
        .await;
        assert_eq!(
            credentials(3),
            (
                None,
                Some("sk-viewer".into()),
                None,
                None,
                "/api/nodes/ws/status".into()
            )
        );
        // A valid key next to a stale session cookie: the cookie (on which
        // the bridge would refuse the socket) is not passed on.
        let _e = connect(
            "/ws/status",
            vec![
                ("x-api-key", "sk-viewer".into()),
                ("cookie", "session_token=stale; theme=dark".into()),
            ],
        )
        .await;
        assert_eq!(
            credentials(4),
            (
                None,
                Some("sk-viewer".into()),
                None,
                None,
                "/api/nodes/ws/status".into()
            )
        );
        // A key in the subprotocol list: the list as sent, and the key.
        let _f = connect(
            "/ws/status",
            vec![("sec-websocket-protocol", "bridge-v1, sk-viewer".into())],
        )
        .await;
        assert_eq!(credentials(5).1, Some("sk-viewer".into()));
        let seen = bridge.seen.lock().unwrap()[5].clone();
        assert_eq!(
            header_of(&seen, "x-auth-key-id").as_deref(),
            Some("viewer-key")
        );
        assert_eq!(
            header_of(&seen, "sec-websocket-protocol").as_deref(),
            Some("bridge-v1, sk-viewer")
        );
    }

    /// Regression (Q1): the upstream handshake carried no User-Agent, so
    /// under `BRIDGE_SESSION_BINDING=strict` the bridge (which compares it
    /// with the one stored at login) refused every proxied session socket.
    /// The forwarded address is the one the session is bound to (Q2).
    #[tokio::test]
    async fn the_user_agent_reaches_the_bridge_for_strict_session_binding() {
        let bridge = h::fake_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, &bridge.url, &h::keys_file(&[]), None);
        state.auth_config.write().await.binding_mode = SessionBindingMode::Strict;
        let token = h::session_with(&state, "alice", "viewer", "127.0.0.1", "");
        state
            .db_pool
            .get()
            .unwrap()
            .execute(
                "UPDATE sessions SET user_agent = 'Firefox/140.0' WHERE session_token = ?1",
                [crate::auth::password::hash_session_token(&token)],
            )
            .unwrap();
        let addr = gateway(Arc::clone(&state), WsConnLimits::new(0, 0)).await;
        let cookie = format!("session_token={token}");

        let (_ws, _) = h::connect(
            addr,
            "/ws/status",
            &[("cookie", &cookie), ("user-agent", "Firefox/140.0")],
        )
        .await
        .expect("upgraded");
        let seen = bridge.seen.lock().unwrap()[0].clone();
        assert_eq!(
            header_of(&seen, "user-agent").as_deref(),
            Some("Firefox/140.0")
        );
        assert_eq!(
            header_of(&seen, "x-forwarded-for").as_deref(),
            Some("127.0.0.1")
        );

        // Another User-Agent is not this session (strict binding).
        let refused = h::connect(
            addr,
            "/ws/status",
            &[("cookie", &cookie), ("user-agent", "curl/8")],
        )
        .await
        .err();
        assert_eq!(refused, Some(401));
        assert_eq!(bridge.seen.lock().unwrap().len(), 1);
    }

    /// Regression (Q4): a proxied socket opened with a client certificate
    /// stayed open after the certificate was revoked.
    #[tokio::test]
    async fn a_revoked_client_certificate_closes_the_proxied_socket() {
        let mut bridge = h::fake_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let registry = dir.path().join("registry.json");
        h::write_cert_registry(&registry, "edge-7", "viewer", false);
        let state = h::with_cert_registry(
            h::state(&dir, &bridge.url, &h::keys_file(&[]), None),
            &registry,
        );
        let options = WsProxyOptions {
            limits: WsConnLimits::new(0, 0),
            timing: fast(),
        };
        let routes: Router<Arc<AppState>> = Router::new().route(
            "/ws/status",
            get(
                move |State(state): State<Arc<AppState>>, req: axum::extract::Request| {
                    let options = options.clone();
                    async move { ws_proxy_with(state, req, "/api/nodes/ws/status", options).await }
                },
            ),
        );
        let addr = h::serve_with_cert(Arc::clone(&state), routes, h::client_cert("edge-7")).await;

        let (mut ws, _) = h::connect(addr, "/ws/status", &[]).await.expect("upgraded");
        let seen = bridge.seen.lock().unwrap()[0].clone();
        assert_eq!(
            header_of(&seen, "x-auth-method").as_deref(),
            Some("client-cert")
        );
        assert_eq!(header_of(&seen, "x-auth-key-id").as_deref(), Some("edge-7"));
        ws.send(TMsg::Text("hi".into())).await.unwrap();
        assert_eq!(
            h::next_msg(&mut ws, 5).await,
            Some(TMsg::Text("echo:hi".into()))
        );

        h::write_cert_registry(&registry, "edge-7", "viewer", true);
        assert_eq!(
            h::close_code(&mut ws, 10).await,
            Some(CLOSE_CREDENTIAL_REVOKED)
        );
        let event = tokio::time::timeout(Duration::from_secs(5), bridge.events.recv())
            .await
            .expect("backend socket closed too");
        assert!(matches!(event, Some(BridgeEvent::Closed(_))));
    }

    #[tokio::test]
    async fn a_logged_out_session_closes_the_proxied_socket() {
        let mut bridge = h::fake_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, &bridge.url, &h::keys_file(&[]), None);
        let token = h::session_for(&state, "alice", "viewer");
        let addr = gateway(Arc::clone(&state), WsConnLimits::new(0, 0)).await;
        let cookie = format!("session_token={token}");

        let (mut ws, _) = h::connect(addr, "/ws/status", &[("cookie", &cookie)])
            .await
            .unwrap();
        ws.send(TMsg::Text("still here".into())).await.unwrap();
        assert!(h::next_msg(&mut ws, 5).await.is_some());

        h::delete_sessions(&state);
        assert_eq!(
            h::close_code(&mut ws, 5).await,
            Some(CLOSE_CREDENTIAL_REVOKED)
        );
        let event = tokio::time::timeout(Duration::from_secs(5), bridge.events.recv())
            .await
            .expect("backend socket closed too");
        assert!(matches!(event, Some(BridgeEvent::Closed(_))));
    }

    async fn tenant_boundary_slow_gateway(state: Arc<AppState>) -> SocketAddr {
        let options = WsProxyOptions {
            limits: WsConnLimits::new(0, 0),
            timing: RevalidateTiming {
                tick: Duration::from_secs(600),
                period: Duration::from_secs(600),
            },
        };
        let routes = Router::new().route(
            "/ws/status",
            get(
                move |State(state): State<Arc<AppState>>, req: axum::extract::Request| {
                    let options = options.clone();
                    async move { ws_proxy_with(state, req, "/api/nodes/ws/status", options).await }
                },
            ),
        );
        h::serve(state, routes).await
    }

    #[tokio::test]
    async fn tenant_boundary_payload_proxy_checks_before_backend_data() {
        let release = Arc::new(tokio::sync::Notify::new());
        let waiting = Arc::clone(&release);
        let backend = Router::new().route(
            "/api/nodes/ws/status",
            get(move |ws: ws::WebSocketUpgrade| {
                let waiting = Arc::clone(&waiting);
                async move {
                    ws.on_upgrade(move |mut socket| async move {
                        socket
                            .send(Message::Text("before-change".into()))
                            .await
                            .unwrap();
                        waiting.notified().await;
                        socket
                            .send(Message::Text("must-not-leak".into()))
                            .await
                            .unwrap();
                        while let Some(Ok(msg)) = socket.next().await {
                            if matches!(msg, Message::Close(_)) {
                                break;
                            }
                        }
                    })
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, backend).await.unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, &url, &h::keys_file(&[]), None);
        let token = h::session_for(&state, "moving-viewer", "viewer");
        let addr = tenant_boundary_slow_gateway(Arc::clone(&state)).await;
        let bearer = format!("Bearer {token}");
        let (mut ws, _) = h::connect(addr, "/ws/status", &[("authorization", &bearer)])
            .await
            .unwrap();
        assert_eq!(
            h::next_msg(&mut ws, 10).await,
            Some(TMsg::Text("before-change".into()))
        );
        state
            .db_pool
            .get()
            .unwrap()
            .execute("UPDATE users SET tenant_id='other'", [])
            .unwrap();
        release.notify_one();
        let next = h::next_msg(&mut ws, 10).await;
        server.abort();
        assert!(
            matches!(next, Some(TMsg::Close(Some(frame))) if u16::from(frame.code) == CLOSE_CREDENTIAL_REVOKED)
        );
    }

    #[tokio::test]
    async fn tenant_boundary_payload_proxy_checks_before_client_data() {
        let (seen_tx, mut seen_rx) = tokio::sync::mpsc::unbounded_channel();
        let backend = Router::new().route(
            "/api/nodes/ws/status",
            get(move |ws: ws::WebSocketUpgrade| {
                let seen_tx = seen_tx.clone();
                async move {
                    ws.on_upgrade(move |mut socket| async move {
                        while let Some(Ok(msg)) = socket.next().await {
                            match msg {
                                Message::Text(text) => {
                                    seen_tx.send(text.to_string()).unwrap();
                                    socket.send(Message::Text(text)).await.unwrap();
                                }
                                Message::Close(_) => break,
                                _ => {}
                            }
                        }
                    })
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, backend).await.unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, &url, &h::keys_file(&[]), None);
        let token = h::session_for(&state, "moving-viewer", "viewer");
        let addr = tenant_boundary_slow_gateway(Arc::clone(&state)).await;
        let bearer = format!("Bearer {token}");
        let (mut ws, _) = h::connect(addr, "/ws/status", &[("authorization", &bearer)])
            .await
            .unwrap();
        ws.send(TMsg::Text("before-change".into())).await.unwrap();
        assert_eq!(
            h::next_msg(&mut ws, 10).await,
            Some(TMsg::Text("before-change".into()))
        );
        assert_eq!(seen_rx.recv().await.as_deref(), Some("before-change"));
        state
            .db_pool
            .get()
            .unwrap()
            .execute("UPDATE users SET tenant_id='other'", [])
            .unwrap();
        ws.send(TMsg::Text("must-not-reach-backend".into()))
            .await
            .unwrap();
        let next = h::next_msg(&mut ws, 10).await;
        server.abort();
        assert!(
            matches!(next, Some(TMsg::Close(Some(frame))) if u16::from(frame.code) == CLOSE_CREDENTIAL_REVOKED)
        );
        assert!(
            seen_rx.try_recv().is_err(),
            "revoked client data reached backend"
        );
    }

    // ── Header forwarding, refusals, caps and frames ──────────────────

    async fn serve_backend(backend: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, backend).await.unwrap();
        });
        url
    }

    /// What a recording backend got on a socket.
    #[derive(Debug, PartialEq, Eq)]
    enum Got {
        Text(String),
        Closed(Option<u16>),
    }

    /// A backend at `/api/nodes/ws/status` that echoes text as
    /// `echo:<text>` and reports every text frame and the close it gets.
    async fn recording_backend() -> (String, tokio::sync::mpsc::UnboundedReceiver<Got>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let backend = Router::new().route(
            "/api/nodes/ws/status",
            get(move |ws: ws::WebSocketUpgrade| {
                let tx = tx.clone();
                async move {
                    ws.on_upgrade(move |mut socket| async move {
                        while let Some(Ok(msg)) = socket.next().await {
                            match msg {
                                Message::Text(t) => {
                                    let _ = tx.send(Got::Text(t.to_string()));
                                    let echo = Message::Text(format!("echo:{t}").into());
                                    let _ = socket.send(echo).await;
                                }
                                Message::Close(frame) => {
                                    let _ = tx.send(Got::Closed(frame.map(|f| f.code)));
                                    return;
                                }
                                _ => {}
                            }
                        }
                        let _ = tx.send(Got::Closed(None));
                    })
                }
            }),
        );
        (serve_backend(backend).await, rx)
    }

    async fn next_got(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Got>) -> Option<Got> {
        tokio::time::timeout(Duration::from_secs(15), rx.recv())
            .await
            .ok()
            .flatten()
    }

    fn expect_close(msg: Option<TMsg>, code: u16, what: &str) {
        match msg {
            Some(TMsg::Close(Some(frame))) => assert_eq!(u16::from(frame.code), code, "{what}"),
            other => panic!("{what}: expected close {code} first, got {other:?}"),
        }
    }

    /// Only headers the gateway sets itself reach the bridge: no
    /// client-supplied identity, licence, proxy-secret, forwarding, hop-by-hop
    /// or second credential header, whatever the client sends.
    #[tokio::test]
    async fn only_the_gateways_own_headers_reach_the_backend() {
        let bridge = h::fake_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, &bridge.url, &h::keys_file(&[]), None);
        let token = h::session_for(&state, "alice", "viewer");
        let addr = gateway(state, WsConnLimits::new(0, 0)).await;
        let bearer = format!("Bearer {token}");

        let (_ws, _) = h::connect(
            addr,
            "/ws/status",
            &[
                ("authorization", &bearer),
                ("x-api-key", "sk-forged"),
                ("x-session-token", "another-session"),
                ("cookie", "session_token=another-session; theme=dark"),
                ("x-auth-user", "root"),
                ("x-auth-key-id", "admin-key"),
                ("x-auth-role", "keymaster"),
                ("x-auth-method", "client-cert"),
                ("x-license-tier", "enterprise"),
                ("x-rust-proxy", "forged"),
                ("x-forwarded-for", "203.0.113.9"),
                ("x-forwarded-host", "evil.example"),
                ("x-forwarded-proto", "http"),
                ("x-real-ip", "203.0.113.9"),
                ("forwarded", "for=203.0.113.9;host=evil.example"),
                ("x-request-id", "client-chosen"),
                ("proxy-authorization", "Basic Zm9vOmJhcg=="),
                ("keep-alive", "timeout=5"),
                ("origin", "https://elsewhere.example"),
                ("user-agent", "Firefox/140.0"),
                ("sec-websocket-protocol", "bridge-v1, sk-forged"),
            ],
        )
        .await
        .expect("upgraded");
        let seen = bridge.seen.lock().unwrap()[0].clone();

        const HANDSHAKE: &[&str] = &[
            "host",
            "connection",
            "upgrade",
            "sec-websocket-key",
            "sec-websocket-version",
        ];
        const SET_BY_THE_GATEWAY: &[&str] = &[
            "cookie",
            "x-auth-user",
            "x-auth-role",
            "x-rust-proxy",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-request-id",
            "user-agent",
        ];
        // The client's subprotocol list goes verbatim (the bridge selects
        // `bridge-v1` from it).
        const FROM_THE_CLIENT: &[&str] = &["sec-websocket-protocol"];
        for name in seen.headers.keys() {
            assert!(
                HANDSHAKE.contains(&name.as_str())
                    || SET_BY_THE_GATEWAY.contains(&name.as_str())
                    || FROM_THE_CLIENT.contains(&name.as_str()),
                "{name} reached the backend"
            );
        }
        for name in SET_BY_THE_GATEWAY {
            assert_eq!(seen.headers.get_all(*name).iter().count(), 1, "one {name}");
        }
        let header = |name: &str| header_of(&seen, name);
        assert_eq!(header("cookie"), Some(format!("session_token={token}")));
        assert_eq!(header("x-auth-user").as_deref(), Some("alice"));
        assert_eq!(header("x-auth-role").as_deref(), Some("viewer"));
        assert_eq!(header("x-rust-proxy").as_deref(), Some(h::PROXY_SECRET));
        assert_eq!(header("x-forwarded-for").as_deref(), Some("127.0.0.1"));
        assert_eq!(header("x-forwarded-host"), Some(addr.to_string()));
        // The listener's scheme, here a plain ws:// one.
        assert_eq!(header("x-forwarded-proto").as_deref(), Some("http"));
        assert_eq!(header("user-agent").as_deref(), Some("Firefox/140.0"));
        // A second credential in the subprotocol list reaches the bridge
        // next to the verified session cookie, as sent. The bridge
        // (`_authenticate_ws`) consults the subprotocol credential only
        // when the request's own credentials (the cookie, X-API-Key or
        // the certificate assertion the gateway sends) find none, so it
        // never decides a proxied socket the gateway authenticated.
        assert_eq!(
            header("sec-websocket-protocol").as_deref(),
            Some("bridge-v1, sk-forged")
        );
        let request_id = header("x-request-id").unwrap();
        assert!(
            uuid::Uuid::parse_str(&request_id).is_ok(),
            "a gateway request id, not the client's: {request_id}"
        );
    }

    /// X-Forwarded-Proto follows the HTTP proxy's rule
    /// (`proxy::handler::forwarded_proto`): a peer that is no trusted
    /// proxy cannot change the listener's scheme (`http` on a plain
    /// listener, `https` on the TLS one); a trusted one says which scheme
    /// its client used, on either listener.
    #[tokio::test]
    async fn the_forwarded_proto_is_the_listeners_or_a_trusted_proxys() {
        async fn proto_seen(trusted: &str, tls: bool, claimed: &str) -> Option<String> {
            let bridge = h::fake_bridge().await;
            let dir = tempfile::tempdir().unwrap();
            let mut state = h::state(&dir, &bridge.url, &h::keys_file(&[]), None);
            if tls {
                // `tls_enabled()` only asks whether both are configured.
                let s = Arc::get_mut(&mut state).unwrap();
                s.config.tls_cert = Some(dir.path().join("tls.crt"));
                s.config.tls_key = Some(dir.path().join("tls.key"));
            }
            state.auth_config.write().await.trusted_proxies = TrustedProxies::parse(trusted).0;
            let token = h::session_for(&state, "alice", "viewer");
            let addr = gateway(state, WsConnLimits::new(0, 0)).await;
            let cookie = format!("session_token={token}");
            let (_ws, _) = h::connect(
                addr,
                "/ws/status",
                &[("cookie", &cookie), ("x-forwarded-proto", claimed)],
            )
            .await
            .expect("upgraded");
            let seen = bridge.seen.lock().unwrap()[0].clone();
            assert_eq!(seen.headers.get_all("x-forwarded-proto").iter().count(), 1);
            header_of(&seen, "x-forwarded-proto")
        }
        // The peer is 127.0.0.1.
        assert_eq!(
            proto_seen("", false, "https").await.as_deref(),
            Some("http")
        );
        assert_eq!(
            proto_seen("127.0.0.1", false, "https").await.as_deref(),
            Some("https")
        );
        assert_eq!(
            proto_seen("127.0.0.1", false, "http").await.as_deref(),
            Some("http")
        );
        assert_eq!(proto_seen("", true, "http").await.as_deref(), Some("https"));
        assert_eq!(
            proto_seen("127.0.0.1", true, "http").await.as_deref(),
            Some("http")
        );
    }

    /// With authentication off the client's own credentials are passed on,
    /// but the trust headers the bridge relies on still come only from the
    /// gateway.
    #[tokio::test]
    async fn with_authentication_off_forged_trust_headers_do_not_reach_the_backend() {
        let bridge = h::fake_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let Ok(mut state) = Arc::try_unwrap(h::state(&dir, &bridge.url, &h::keys_file(&[]), None))
        else {
            unreachable!("fresh state has one owner")
        };
        state.auth_enabled = false;
        let addr = gateway(Arc::new(state), WsConnLimits::new(0, 0)).await;

        let (_ws, _) = h::connect(
            addr,
            "/ws/status",
            &[
                ("x-auth-user", "root"),
                ("x-auth-key-id", "admin-key"),
                ("x-auth-role", "admin"),
                ("x-auth-method", "client-cert"),
                ("x-license-tier", "enterprise"),
                ("x-rust-proxy", "forged"),
                ("cookie", "theme=dark; session_token=abc"),
                ("cookie", "csrf_token=x"),
                ("x-api-key", "sk-1"),
                // Not stripped by the auth middleware: only ws_proxy's own
                // header choice keeps these from the bridge.
                ("x-real-ip", "203.0.113.9"),
                ("forwarded", "for=203.0.113.9;host=evil.example"),
                ("x-forwarded-host", "evil.example"),
                ("x-forwarded-for", "203.0.113.9"),
                ("proxy-authorization", "Basic Zm9vOmJhcg=="),
                ("x-request-id", "client-chosen"),
            ],
        )
        .await
        .expect("upgraded");
        let seen = bridge.seen.lock().unwrap()[0].clone();

        const HANDSHAKE: &[&str] = &[
            "host",
            "connection",
            "upgrade",
            "sec-websocket-key",
            "sec-websocket-version",
        ];
        const ALLOWED: &[&str] = &[
            // The client's own credentials (authentication is off).
            "cookie",
            "x-api-key",
            // Set by the gateway.
            "x-rust-proxy",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-request-id",
        ];
        for name in seen.headers.keys() {
            assert!(
                HANDSHAKE.contains(&name.as_str()) || ALLOWED.contains(&name.as_str()),
                "{name} reached the backend"
            );
        }
        for name in ALLOWED {
            assert!(
                seen.headers.get_all(*name).iter().count() <= 1,
                "one {name} at most"
            );
        }
        let values = |name: &str| -> Vec<String> {
            seen.headers
                .get_all(name)
                .iter()
                .map(|v| v.to_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(values("x-rust-proxy"), vec![h::PROXY_SECRET.to_string()]);
        assert_eq!(values("cookie"), vec!["session_token=abc".to_string()]);
        assert_eq!(values("x-api-key"), vec!["sk-1".to_string()]);
        assert_eq!(values("x-forwarded-for"), vec!["127.0.0.1".to_string()]);
        assert_eq!(values("x-forwarded-host"), vec![addr.to_string()]);
        let request_id = values("x-request-id").concat();
        assert!(
            uuid::Uuid::parse_str(&request_id).is_ok(),
            "a gateway request id, not the client's: {request_id}"
        );
    }

    /// A backend at `/api/nodes/ws/status` that refuses every upgrade with
    /// the status in `?status=`; counts the attempts.
    async fn refusing_backend() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        let backend = Router::new().route(
            "/api/nodes/ws/status",
            get(
                move |axum::extract::RawQuery(query): axum::extract::RawQuery| {
                    let counter = Arc::clone(&counter);
                    async move {
                        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let status = query
                            .as_deref()
                            .and_then(|q| q.strip_prefix("status="))
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(500);
                        StatusCode::from_u16(status).unwrap()
                    }
                },
            ),
        );
        (serve_backend(backend).await, hits)
    }

    /// The backend's refusal reaches the client instead of an upgrade (a
    /// 4xx as it is, anything else as 502), and the refused socket does not
    /// keep its connection slot.
    #[tokio::test]
    async fn a_backend_refusal_is_passed_on_instead_of_an_upgrade_and_frees_the_slot() {
        let (url, hits) = refusing_backend().await;
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, &url, &h::keys_file(&[]), None);
        let token = h::session_for(&state, "alice", "viewer");
        // One socket per address: a leaked slot would turn the next try into a 429.
        let limits = WsConnLimits::new(1, 1);
        let addr = gateway(state, Arc::clone(&limits)).await;
        let bearer = format!("Bearer {token}");

        let cases = [
            (401, 401),
            (403, 403),
            (404, 404),
            (429, 429),
            (500, 502),
            (503, 502),
        ];
        for (backend, client) in cases {
            let path = format!("/ws/status?status={backend}");
            assert_eq!(
                h::connect(addr, &path, &[("authorization", &bearer)])
                    .await
                    .err(),
                Some(client),
                "backend {backend}"
            );
            assert_eq!(
                limits.open("127.0.0.1"),
                (0, 0),
                "slot freed after {backend}"
            );
        }
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), cases.len());
    }

    /// An `https://` backend is spoken to over TLS only — a plain WebSocket
    /// server there never sees the handshake (or the credentials in it) —
    /// and a backend that cannot be reached or whose URL is unusable is a
    /// 502 that does not keep the slot.
    #[tokio::test]
    async fn an_unreachable_or_misconfigured_backend_is_a_502_without_a_plaintext_fallback() {
        let plain = h::fake_bridge().await;
        let tls_url = plain.url.replace("http://", "https://");
        for python_url in [
            tls_url.as_str(),
            "http://127.0.0.1:1",
            "ftp://bridge.invalid",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let state = h::state(&dir, python_url, &h::keys_file(&[]), None);
            let token = h::session_for(&state, "alice", "viewer");
            let limits = WsConnLimits::new(1, 1);
            let addr = gateway(state, Arc::clone(&limits)).await;
            let bearer = format!("Bearer {token}");
            assert_eq!(
                h::connect(addr, "/ws/status", &[("authorization", &bearer)])
                    .await
                    .err(),
                Some(502),
                "{python_url}"
            );
            assert_eq!(limits.open("127.0.0.1"), (0, 0), "{python_url}");
        }
        assert!(
            plain.seen.lock().unwrap().is_empty(),
            "no plaintext handshake with the https backend"
        );
    }

    /// A WebSocket server (at any path) behind TLS with a
    /// self-signed certificate (for `bridge.example` and 127.0.0.1) that no
    /// public CA vouches for, on a loopback port. Reports the outcome of
    /// every TLS handshake it sees.
    async fn self_signed_tls_backend() -> (
        u16,
        tokio::sync::mpsc::UnboundedReceiver<Result<(), String>>,
    ) {
        // The gateway binary installs the process-wide provider at
        // startup; the default (verifying) upstream connector needs one.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let issued = rcgen::generate_simple_self_signed(vec![
            "bridge.example".to_string(),
            "127.0.0.1".to_string(),
        ])
        .unwrap();
        let cert = rustls::pki_types::CertificateDer::from(issued.cert.der().to_vec());
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(issued.signing_key.serialize_der().into());
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    match acceptor.accept(tcp).await {
                        Err(e) => {
                            let _ = tx.send(Err(e.to_string()));
                        }
                        Ok(tls) => {
                            let _ = tx.send(Ok(()));
                            if let Ok(mut ws) = tokio_tungstenite::accept_async(tls).await {
                                while let Some(Ok(_)) = ws.next().await {}
                            }
                        }
                    }
                });
            }
        });
        (port, rx)
    }

    /// An `https://` backend that is not loopback has its certificate
    /// verified (as for HTTP): one no trusted CA issued fails the TLS
    /// handshake, so the client's credentials (session cookie, API key,
    /// `X-Rust-Proxy`) are never sent to whoever answers there, and the
    /// client gets 502. Only a loopback backend skips verification.
    ///
    /// The non-loopback URL names the same loopback server through its
    /// IPv4-mapped IPv6 address (`[::ffff:127.0.0.1]`), which is not a
    /// loopback address to the gateway; the backend reports the TCP
    /// connection, so the test cannot pass by never reaching it.
    #[tokio::test]
    async fn a_non_loopback_wss_backend_must_present_a_trusted_certificate() {
        let (port, mut handshakes) = self_signed_tls_backend().await;
        async fn next_handshake(
            rx: &mut tokio::sync::mpsc::UnboundedReceiver<Result<(), String>>,
        ) -> Option<Result<(), String>> {
            tokio::time::timeout(Duration::from_secs(15), rx.recv())
                .await
                .ok()
                .flatten()
        }

        // Loopback: verification skipped, the socket is relayed.
        let dir = tempfile::tempdir().unwrap();
        let loopback = format!("https://127.0.0.1:{port}");
        let state = h::state(&dir, &loopback, &h::keys_file(&[]), None);
        let token = h::session_for(&state, "alice", "viewer");
        let addr = gateway(state, WsConnLimits::new(0, 0)).await;
        let bearer = format!("Bearer {token}");
        let opened = h::connect(addr, "/ws/status", &[("authorization", &bearer)]).await;
        assert!(opened.is_ok(), "loopback wss backend: {:?}", opened.err());
        assert_eq!(next_handshake(&mut handshakes).await, Some(Ok(())));

        // Not loopback: the self-signed certificate is refused.
        let dir = tempfile::tempdir().unwrap();
        let remote = format!("https://[::ffff:127.0.0.1]:{port}");
        assert!(!is_loopback_url(&remote), "{remote} counts as loopback");
        let state = h::state(&dir, &remote, &h::keys_file(&[]), None);
        let token = h::session_for(&state, "alice", "viewer");
        let limits = WsConnLimits::new(1, 1);
        let addr = gateway(state, Arc::clone(&limits)).await;
        let bearer = format!("Bearer {token}");
        assert_eq!(
            h::connect(addr, "/ws/status", &[("authorization", &bearer)])
                .await
                .err(),
            Some(502),
            "an untrusted certificate on a non-loopback backend"
        );
        match next_handshake(&mut handshakes).await {
            Some(Err(_)) => {}
            other => panic!("expected a refused TLS handshake at the backend, got {other:?}"),
        }
        assert_eq!(limits.open("127.0.0.1"), (0, 0));
    }

    /// The total cap is a 503; an unauthenticated upgrade is refused before
    /// any cap is consulted, and `X-Forwarded-For` from a peer that is no
    /// trusted proxy does not buy a fresh per-address budget.
    #[tokio::test]
    async fn the_caps_cannot_be_dodged_and_refused_upgrades_never_reach_the_backend() {
        let bridge = h::fake_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, &bridge.url, &h::keys_file(&[]), None);
        let token = h::session_for(&state, "alice", "viewer");
        let per_ip = WsConnLimits::new(1, 10);
        let total = WsConnLimits::new(0, 1);
        let by_ip = gateway(Arc::clone(&state), Arc::clone(&per_ip)).await;
        let in_total = gateway(Arc::clone(&state), Arc::clone(&total)).await;
        let bearer = format!("Bearer {token}");
        let auth = [("authorization", bearer.as_str())];

        let (_first, _) = h::connect(by_ip, "/ws/status", &auth).await.unwrap();
        assert_eq!(h::connect(by_ip, "/ws/status", &[]).await.err(), Some(401));
        let spoofed = [
            ("authorization", bearer.as_str()),
            ("x-forwarded-for", "203.0.113.7"),
        ];
        assert_eq!(
            h::connect(by_ip, "/ws/status", &spoofed).await.err(),
            Some(429)
        );
        assert_eq!(per_ip.open("127.0.0.1"), (1, 1));
        assert_eq!(per_ip.open("203.0.113.7"), (0, 1));

        let (_second, _) = h::connect(in_total, "/ws/status", &auth).await.unwrap();
        assert_eq!(
            h::connect(in_total, "/ws/status", &[]).await.err(),
            Some(401)
        );
        assert_eq!(
            h::connect(in_total, "/ws/status", &auth).await.err(),
            Some(503)
        );
        assert_eq!(total.open("127.0.0.1"), (1, 1));
        assert_eq!(
            bridge.seen.lock().unwrap().len(),
            2,
            "refused upgrades never reached the backend"
        );
    }

    /// A plain GET is authenticated first; an authenticated one that is no
    /// WebSocket upgrade is refused without contacting the backend and
    /// without keeping a slot.
    #[tokio::test]
    async fn a_request_that_is_no_upgrade_never_reaches_the_backend() {
        let bridge = h::fake_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, &bridge.url, &h::keys_file(&[]), None);
        let token = h::session_for(&state, "alice", "viewer");
        let limits = WsConnLimits::new(1, 1);
        let addr = gateway(state, Arc::clone(&limits)).await;
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/ws/status");

        let anonymous = client.get(&url).send().await.unwrap().status();
        assert_eq!(anonymous.as_u16(), 401);
        let authenticated = client
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status();
        // Authenticated, then refused as no upgrade (axum: no
        // `Connection: upgrade`) — not refused by authentication.
        assert_eq!(
            authenticated.as_u16(),
            400,
            "authenticated, refused as no upgrade: {authenticated}"
        );
        assert_eq!(limits.open("127.0.0.1"), (0, 0));
        assert!(bridge.seen.lock().unwrap().is_empty());
    }

    /// A masked client frame (mask 0: the payload as given), `payload` < 126 bytes.
    fn client_frame(first_byte: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![first_byte, 0x80 | payload.len() as u8, 0, 0, 0, 0];
        frame.extend_from_slice(payload);
        frame
    }

    /// The frame and message size caps the relay enforces on both sides
    /// (tungstenite's, which neither the client upgrade nor the upstream
    /// connection overrides).
    const MAX_FRAME: usize = 16 << 20;
    const MAX_MESSAGE: usize = 64 << 20;

    /// Frames a client may not send — unmasked, one byte over the 16 MiB
    /// frame limit (only the header is sent: a frame is refused on its
    /// declared length), invalid UTF-8 text, a reserved opcode, reserved
    /// bits, a fragmented control frame — end the relay with nothing of
    /// them passed on, and the backend socket is closed as "going away".
    #[tokio::test]
    async fn malformed_or_oversized_client_frames_are_not_relayed() {
        use tokio::io::AsyncWriteExt;

        let (url, mut got) = recording_backend().await;
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, &url, &h::keys_file(&[]), None);
        let token = h::session_for(&state, "alice", "viewer");
        let addr = gateway(state, WsConnLimits::new(0, 0)).await;
        let bearer = format!("Bearer {token}");

        let mut oversized = vec![0x82, 0x80 | 127];
        oversized.extend_from_slice(&(MAX_FRAME as u64 + 1).to_be_bytes());
        oversized.extend_from_slice(&[0; 4]);
        let frames = [
            ("unmasked", vec![0x81, 0x02, b'h', b'i']),
            ("over the frame size limit", oversized),
            ("invalid UTF-8 text", client_frame(0x81, &[0xff, 0xfe])),
            ("reserved opcode", client_frame(0x83, b"hi")),
            ("reserved bits", client_frame(0xc1, b"hi")),
            ("fragmented ping", client_frame(0x09, b"")),
        ];
        for (what, frame) in frames {
            let (mut ws, _) = h::connect(addr, "/ws/status", &[("authorization", &bearer)])
                .await
                .unwrap();
            ws.send(TMsg::Text("ok".into())).await.unwrap();
            assert_eq!(
                h::next_msg(&mut ws, 15).await,
                Some(TMsg::Text("echo:ok".into())),
                "{what}"
            );
            assert_eq!(
                next_got(&mut got).await,
                Some(Got::Text("ok".into())),
                "{what}"
            );
            let tokio_tungstenite::MaybeTlsStream::Plain(tcp) = ws.get_mut() else {
                unreachable!("a ws:// connection")
            };
            tcp.write_all(&frame).await.unwrap();
            assert_eq!(
                next_got(&mut got).await,
                Some(Got::Closed(Some(1001))),
                "{what}"
            );
        }
    }

    /// A text message fragmented into frames that are each within the
    /// frame cap but together one byte over the 64 MiB message cap is not
    /// relayed (nor buffered without bound): the relay ends and the backend
    /// socket is closed as "going away", with no text of it passed on.
    #[tokio::test]
    async fn a_fragmented_client_message_over_the_message_cap_is_not_relayed() {
        use tokio::io::AsyncWriteExt;

        let (url, mut got) = recording_backend().await;
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, &url, &h::keys_file(&[]), None);
        let token = h::session_for(&state, "alice", "viewer");
        let addr = gateway(state, WsConnLimits::new(0, 0)).await;
        let bearer = format!("Bearer {token}");
        let (mut ws, _) = h::connect(addr, "/ws/status", &[("authorization", &bearer)])
            .await
            .unwrap();
        ws.send(TMsg::Text("ok".into())).await.unwrap();
        assert_eq!(
            h::next_msg(&mut ws, 15).await,
            Some(TMsg::Text("echo:ok".into()))
        );
        assert_eq!(next_got(&mut got).await, Some(Got::Text("ok".into())));

        /// A masked (mask 0) frame header with a 64-bit length.
        fn header(first_byte: u8, len: usize) -> Vec<u8> {
            let mut h = vec![first_byte, 0x80 | 127];
            h.extend_from_slice(&(len as u64).to_be_bytes());
            h.extend_from_slice(&[0; 4]);
            h
        }
        const CHUNK: usize = 4 << 20;
        const _: () = assert!(CHUNK <= MAX_FRAME && MAX_MESSAGE % CHUNK == 0);
        let payload = vec![b'a'; CHUNK];
        let tokio_tungstenite::MaybeTlsStream::Plain(tcp) = ws.get_mut() else {
            unreachable!("a ws:// connection")
        };
        // Text (FIN unset), then continuations, MAX_MESSAGE bytes in all...
        for i in 0..MAX_MESSAGE / CHUNK {
            let opcode = if i == 0 { 0x01 } else { 0x00 };
            tcp.write_all(&header(opcode, CHUNK)).await.unwrap();
            tcp.write_all(&payload).await.unwrap();
        }
        // ... and a final continuation one byte over the cap.
        let mut last = header(0x80, 1);
        last.push(b'a');
        tcp.write_all(&last).await.unwrap();

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(60), got.recv())
                .await
                .ok()
                .flatten(),
            Some(Got::Closed(Some(1001))),
            "the backend got none of the message, and a going-away close"
        );
    }

    /// A raw backend at any path: completes the handshake, then writes the
    /// frame named by `?frame=` byte for byte.
    async fn raw_backend() -> String {
        use tokio::io::AsyncWriteExt;
        use tungstenite::handshake::server;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut frame = Vec::new();
                    // The handshake callback's error type is tungstenite's.
                    #[allow(clippy::result_large_err)]
                    let callback = |req: &server::Request, resp: server::Response| {
                        frame = match req.uri().query() {
                            // Servers must not mask.
                            Some("frame=masked") => {
                                vec![0x81, 0x82, 1, 2, 3, 4, b'h' ^ 1, b'i' ^ 2]
                            }
                            // One byte over the frame cap, header only.
                            Some("frame=oversized") => {
                                let mut f = vec![0x82, 127];
                                f.extend_from_slice(&(MAX_FRAME as u64 + 1).to_be_bytes());
                                f
                            }
                            Some("frame=invalid-utf8") => vec![0x81, 0x02, 0xff, 0xfe],
                            Some("frame=reserved-bits") => vec![0xc1, 0x02, b'h', b'i'],
                            _ => vec![0x81, 0x02, b'h', b'i'],
                        };
                        Ok(resp)
                    };
                    let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(stream, callback).await
                    else {
                        return;
                    };
                    let _ = ws.get_mut().write_all(&frame).await;
                    while let Some(Ok(_)) = ws.next().await {}
                });
            }
        });
        url
    }

    /// Frames a backend may not send end the relay too: the client gets
    /// "going away" and none of the frame.
    #[tokio::test]
    async fn malformed_or_oversized_backend_frames_are_not_relayed() {
        let url = raw_backend().await;
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, &url, &h::keys_file(&[]), None);
        let token = h::session_for(&state, "alice", "viewer");
        let addr = gateway(state, WsConnLimits::new(0, 0)).await;
        let bearer = format!("Bearer {token}");

        // The well-formed frame is relayed: the backend is reachable.
        let (mut ws, _) = h::connect(addr, "/ws/status?frame=ok", &[("authorization", &bearer)])
            .await
            .unwrap();
        assert_eq!(
            h::next_msg(&mut ws, 15).await,
            Some(TMsg::Text("hi".into()))
        );
        for frame in ["masked", "oversized", "invalid-utf8", "reserved-bits"] {
            let path = format!("/ws/status?frame={frame}");
            let (mut ws, _) = h::connect(addr, &path, &[("authorization", &bearer)])
                .await
                .unwrap();
            expect_close(h::next_msg(&mut ws, 15).await, 1001, frame);
        }
    }

    /// Regression guard for the payload check on the proxy with an API key:
    /// once keys.json revokes the key, the client's next frame is not
    /// relayed and both sides are closed.
    #[tokio::test]
    async fn a_revoked_api_key_closes_the_proxied_socket_before_the_next_payload() {
        // Each payload check after a keys.json reload runs PBKDF2 (600k
        // iterations, slow in a debug build): wait generously, so a loaded
        // machine does not fail the test. The waits only end early on a
        // frame, never pass on a timeout.
        const PBKDF2_SECS: u64 = 60;
        let (url, mut got) = recording_backend().await;
        let dir = tempfile::tempdir().unwrap();
        let keys =
            |revoked| h::keys_file(&[h::key_entry("viewer-key", "sk-viewer", "viewer", revoked)]);
        let state = h::state(&dir, &url, &keys(false), None);
        let addr = tenant_boundary_slow_gateway(Arc::clone(&state)).await;
        let (mut ws, _) = h::connect(addr, "/ws/status", &[("x-api-key", "sk-viewer")])
            .await
            .unwrap();
        ws.send(TMsg::Text("before".into())).await.unwrap();
        assert_eq!(
            h::next_msg(&mut ws, PBKDF2_SECS).await,
            Some(TMsg::Text("echo:before".into()))
        );
        assert_eq!(next_got(&mut got).await, Some(Got::Text("before".into())));

        h::write_keys(&dir, &keys(true));
        ws.send(TMsg::Text("must-not-reach-backend".into()))
            .await
            .unwrap();
        expect_close(
            h::next_msg(&mut ws, PBKDF2_SECS).await,
            CLOSE_CREDENTIAL_REVOKED,
            "revoked key",
        );
        assert_eq!(next_got(&mut got).await, Some(Got::Closed(Some(1001))));
    }

    /// Every way a session stops being good enough (not only a tenant move)
    /// stops the proxy before the client's next frame reaches the backend.
    #[tokio::test]
    async fn every_session_change_closes_the_proxied_socket_before_the_next_payload() {
        for change in [
            "DELETE FROM sessions",
            "UPDATE sessions SET expires_at='2000-01-01T00:00:00+00:00'",
            "UPDATE sessions SET last_active='2000-01-01T00:00:00+00:00'",
            "UPDATE sessions SET scope='password_change_only'",
            "UPDATE users SET enabled=0",
            "UPDATE users SET role='sensor'",
        ] {
            let (url, mut got) = recording_backend().await;
            let dir = tempfile::tempdir().unwrap();
            let state = h::state(&dir, &url, &h::keys_file(&[]), None);
            let token = h::session_for(&state, "alice", "viewer");
            let addr = tenant_boundary_slow_gateway(Arc::clone(&state)).await;
            let bearer = format!("Bearer {token}");
            let (mut ws, _) = h::connect(addr, "/ws/status", &[("authorization", &bearer)])
                .await
                .unwrap();
            ws.send(TMsg::Text("before".into())).await.unwrap();
            assert_eq!(
                h::next_msg(&mut ws, 15).await,
                Some(TMsg::Text("echo:before".into())),
                "{change}"
            );
            assert_eq!(
                next_got(&mut got).await,
                Some(Got::Text("before".into())),
                "{change}"
            );

            state.db_pool.get().unwrap().execute(change, []).unwrap();
            ws.send(TMsg::Text("must-not-reach-backend".into()))
                .await
                .unwrap();
            expect_close(
                h::next_msg(&mut ws, 15).await,
                CLOSE_CREDENTIAL_REVOKED,
                change,
            );
            assert_eq!(
                next_got(&mut got).await,
                Some(Got::Closed(Some(1001))),
                "{change}"
            );
        }
    }

    /// A backend that accepts the connection but never answers the
    /// handshake holds the client for the upstream connect timeout, 10 s,
    /// and no longer: the upgrade is then refused with 504 and its slot
    /// given back, so the next upgrade (on a one-slot limit) is not refused
    /// for it. On a paused clock over an in-memory gateway, so the timeout
    /// passes in virtual time; the only timer pending meanwhile is that
    /// timeout. The bound is absolute, not the constant: a longer timeout
    /// fails it.
    #[tokio::test(start_paused = true)]
    async fn a_backend_that_never_answers_the_handshake_is_a_504_that_frees_the_slot() {
        const CLIENT_HELD_FOR: Duration = Duration::from_secs(10);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (held_tx, _held) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            // Keep every connection open, and never answer on it.
            while let Ok((stream, _)) = listener.accept().await {
                let _ = held_tx.send(stream);
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, &url, &h::keys_file(&[]), None);
        let token = h::session_for(&state, "alice", "viewer");
        let limits = WsConnLimits::new(1, 1);
        let options = WsProxyOptions {
            limits: Arc::clone(&limits),
            timing: fast(),
        };
        let routes = Router::new().route(
            "/ws/status",
            get(
                move |State(state): State<Arc<AppState>>, req: axum::extract::Request| {
                    let options = options.clone();
                    async move { ws_proxy_with(state, req, "/api/nodes/ws/status", options).await }
                },
            ),
        );
        let gw = h::serve_in_memory(Arc::clone(&state), routes);
        let bearer = format!("Bearer {token}");

        for attempt in ["first", "next"] {
            let started = tokio::time::Instant::now();
            // Bounded, so a longer or missing timeout fails the test
            // instead of hanging it.
            let outcome = tokio::time::timeout(
                CLIENT_HELD_FOR + Duration::from_secs(1),
                gw.connect("/ws/status", &[("authorization", &bearer)]),
            )
            .await
            .unwrap_or_else(|_| panic!("{attempt}: answered within {CLIENT_HELD_FOR:?}"));
            assert_eq!(outcome.err(), Some(504), "{attempt}");
            let held = started.elapsed();
            assert!(
                (CLIENT_HELD_FOR..CLIENT_HELD_FOR + Duration::from_secs(1)).contains(&held),
                "{attempt}: held for {held:?}"
            );
            assert_eq!(limits.open("127.0.0.1"), (0, 0), "{attempt}: slot freed");
        }
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use crate::ws::test_harness as h;
    use axum::{extract::State, routing::get, Router};
    use std::net::SocketAddr;

    /// A gateway serving `/ws/status` through the proxy (no caps, no
    /// revalidation within a test).
    async fn gateway(state: Arc<AppState>) -> SocketAddr {
        let options = WsProxyOptions {
            limits: WsConnLimits::new(0, 0),
            timing: RevalidateTiming {
                tick: Duration::from_secs(60),
                period: Duration::from_secs(60),
            },
        };
        let routes: Router<Arc<AppState>> = Router::new().route(
            "/ws/status",
            get(
                move |State(state): State<Arc<AppState>>, req: axum::extract::Request| {
                    let options = options.clone();
                    async move { ws_proxy_with(state, req, "/api/nodes/ws/status", options).await }
                },
            ),
        );
        h::serve(state, routes).await
    }

    /// A bridge that, once a socket is open, sends a ping and then
    /// `after-ping`, and reports every frame it receives.
    async fn pinging_bridge() -> (String, tokio::sync::mpsc::UnboundedReceiver<TMsg>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            ws.send(TMsg::Ping(b"from-bridge".to_vec().into()))
                .await
                .unwrap();
            ws.send(TMsg::Text("after-ping".into())).await.unwrap();
            while let Some(Ok(msg)) = ws.next().await {
                let _ = tx.send(msg);
            }
        });
        (url, rx)
    }

    /// Pings are answered hop by hop and never relayed: the bridge's ping
    /// does not reach the client (its first frame is the bridge's text),
    /// and the client's ping does not reach the bridge (nothing but the
    /// pong to its own ping comes before the client's text).
    #[tokio::test]
    async fn pings_are_answered_hop_by_hop_and_never_relayed() {
        let (url, mut bridge_frames) = pinging_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, &url, &h::keys_file(&[]), None);
        let token = h::session_for(&state, "alice", "viewer");
        let addr = gateway(state).await;
        let cookie = format!("session_token={token}");
        let (mut ws, _) = h::connect(addr, "/ws/status", &[("cookie", &cookie)])
            .await
            .expect("upgraded");
        assert_eq!(
            h::next_msg(&mut ws, 10).await,
            Some(TMsg::Text("after-ping".into()))
        );

        ws.send(TMsg::Ping(b"from-client".to_vec().into()))
            .await
            .unwrap();
        ws.send(TMsg::Text("hello".into())).await.unwrap();
        let mut before_text = Vec::new();
        let hello = TMsg::Text("hello".into());
        let mut frame = tokio::time::timeout(Duration::from_secs(10), bridge_frames.recv())
            .await
            .expect("a frame reaches the bridge")
            .expect("the bridge socket is open");
        while frame != hello {
            before_text.push(frame);
            frame = tokio::time::timeout(Duration::from_secs(10), bridge_frames.recv())
                .await
                .expect("a frame reaches the bridge")
                .expect("the bridge socket is open");
        }
        assert!(
            before_text
                .iter()
                .all(|f| *f == TMsg::Pong(b"from-bridge".to_vec().into())),
            "{before_text:?}"
        );
    }

    /// The upstream request invents no forwarding header the gateway
    /// cannot vouch for, and passes none of the client's on: without a
    /// known client address no X-Forwarded-For, without an authority no
    /// X-Forwarded-Host, and the scheme is the listener's. With
    /// authentication off, of the client's cookies only `session_token`
    /// would go (here there is none), while its API key is passed on.
    #[test]
    fn the_upstream_request_carries_no_forwarding_header_it_cannot_vouch_for() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::test_support::app_state(&dir);
        let req = Request::get("/ws/status?since=10")
            .header("x-forwarded-for", "203.0.113.9")
            .header("x-forwarded-host", "attacker.example")
            .header("x-forwarded-proto", "https")
            .header(header::COOKIE, "theme=dark; csrf_token=c")
            .header("x-api-key", "sk-client")
            .body(Body::empty())
            .unwrap();
        let upstream = upstream_request(
            &state,
            &req,
            "/api/nodes/ws/status",
            &WsPrincipal::Anonymous,
            &TrustedProxies::default(),
        )
        .unwrap();
        assert_eq!(upstream.uri().scheme_str(), Some("ws"));
        assert_eq!(
            upstream.uri().path_and_query().unwrap().as_str(),
            "/api/nodes/ws/status?since=10"
        );
        let headers = upstream.headers();
        assert!(headers.get("x-forwarded-for").is_none(), "{headers:?}");
        assert!(headers.get("x-forwarded-host").is_none(), "{headers:?}");
        assert_eq!(headers.get("x-forwarded-proto").unwrap(), "http");
        assert!(headers.get(header::COOKIE).is_none(), "{headers:?}");
        assert_eq!(headers.get("x-api-key").unwrap(), "sk-client");
    }

    /// A loopback `wss://` backend that only speaks TLS 1.2 is reached
    /// through the loopback connector (whose TLS 1.2 handshake signature
    /// check runs), and frames are relayed through it.
    #[tokio::test]
    async fn a_loopback_wss_backend_speaking_only_tls12_is_relayed() {
        let issued = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert = rustls::pki_types::CertificateDer::from(issued.cert.der().to_vec());
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(issued.signing_key.serialize_der().into());
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (version_tx, mut version_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let _ = version_tx.send(tls.get_ref().1.protocol_version());
            let mut ws = tokio_tungstenite::accept_async(tls).await.unwrap();
            while let Some(Ok(TMsg::Text(text))) = ws.next().await {
                ws.send(TMsg::Text(format!("tls12:{text}").into()))
                    .await
                    .unwrap();
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let state = h::state(
            &dir,
            &format!("https://127.0.0.1:{port}"),
            &h::keys_file(&[]),
            None,
        );
        let token = h::session_for(&state, "alice", "viewer");
        let addr = gateway(state).await;
        let bearer = format!("Bearer {token}");
        let (mut ws, _) = h::connect(addr, "/ws/status", &[("authorization", &bearer)])
            .await
            .expect("upgraded through the TLS 1.2 backend");
        assert_eq!(
            version_rx.recv().await,
            Some(Some(rustls::ProtocolVersion::TLSv1_2))
        );
        ws.send(TMsg::Text("hi".into())).await.unwrap();
        assert_eq!(
            h::next_msg(&mut ws, 10).await,
            Some(TMsg::Text("tls12:hi".into()))
        );
    }

    /// A socket over a connection cap is refused before the upgrade and
    /// before anything reaches the bridge (here none listens), takes no
    /// slot, and the refusal is logged with the client address, the cap it
    /// hit and the route: 429 for the client's own cap, 503 for the
    /// gateway's total.
    #[test]
    fn a_socket_over_a_cap_is_refused_and_logged_with_the_client() {
        const CLIENT: &str = "198.51.100.7";
        let dir = tempfile::tempdir().unwrap();
        let state = crate::test_support::app_state(&dir);
        for (limits, status, detail, hit) in [
            (
                WsConnLimits::new(1, 0),
                StatusCode::TOO_MANY_REQUESTS,
                "Too many WebSocket connections from this address",
                "hit=PerIp",
            ),
            (
                WsConnLimits::new(0, 1),
                StatusCode::SERVICE_UNAVAILABLE,
                "Too many WebSocket connections",
                "hit=Total",
            ),
        ] {
            let _held = limits.try_acquire(CLIENT).unwrap();
            let mut req = Request::get("/ws/status").body(Body::empty()).unwrap();
            req.extensions_mut()
                .insert(axum::extract::ConnectInfo(SocketAddr::from((
                    [198, 51, 100, 7],
                    40_000,
                ))));
            let options = WsProxyOptions {
                limits: Arc::clone(&limits),
                timing: RevalidateTiming {
                    tick: Duration::from_secs(60),
                    period: Duration::from_secs(60),
                },
            };
            let state = Arc::clone(&state);
            let ((refused, body), logs) = crate::test_support::logs_of(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async move {
                        let resp = ws_proxy_with(state, req, "/api/nodes/ws/status", options).await;
                        let status = resp.status();
                        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
                        (
                            status,
                            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                        )
                    })
            });
            assert_eq!(refused, status, "{hit}");
            assert_eq!(body["detail"], detail, "{hit}");
            assert_eq!(
                limits.open(CLIENT),
                (1, 1),
                "{hit}: the refusal took a slot"
            );
            let warned: Vec<&str> = logs
                .lines()
                .filter(|l| l.contains("WebSocket proxy connection cap reached"))
                .collect();
            assert_eq!(warned.len(), 1, "{hit}: {logs}");
            for named in [
                " WARN ",
                "client_ip=\"198.51.100.7\"",
                hit,
                "path=\"/api/nodes/ws/status\"",
            ] {
                assert!(warned[0].contains(named), "{named:?} missing: {logs}");
            }
        }
    }
}
