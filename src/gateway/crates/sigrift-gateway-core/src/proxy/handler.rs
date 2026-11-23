//! Catch-all reverse proxy handler.
//!
//! Forwards any request not matched by a Rust-native route to the Python
//! backend. Streams request and response bodies to avoid buffering large
//! payloads in memory.

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, error, warn};

use crate::middleware::client_ip::{ClientIp, TrustedProxies, UNKNOWN_CLIENT};
use crate::middleware::framing::{ambiguous_framing_response, has_ambiguous_framing};
use crate::middleware::path::{
    forwarded_unchanged, has_control_character, is_ambiguous_path, is_internal_path,
};
use crate::AppState;

// The feature-route table is injected into `AppState` at startup by the
// binary. The community binary uses `FeatureRoutes::EMPTY`, so no path
// prefix is gated; HS256 and hybrid-PQC binaries ship their own tables.
// Core carries no enterprise feature names.

/// How long a connection to the backend may sit idle in the proxy's pool
/// before a request may no longer reuse it.
///
/// Well under the bridge's keep-alive timeout: uvicorn closes a connection
/// that has been idle for `--timeout-keep-alive` seconds (5, set in
/// `src/sigrift/bridge/Dockerfile`). A request the pool sends on a
/// connection the backend is closing at that moment fails (reset or
/// closed before the response), and the proxy can only answer it with
/// 502 "Proxy error". With reqwest's default (90 s), a page loaded about
/// five seconds after the previous one could lose one of its scripts that
/// way. `tests/bridge/test_gateway_backend_keepalive.py` pins the margin
/// against the Dockerfile.
pub const BACKEND_POOL_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Build a shared `reqwest::Client` for proxying. Called once at startup.
///
/// TLS certificate verification is only skipped when the backend is a
/// loopback address — the normal same-host/container deployment where
/// Python listens on plaintext http. For a non-loopback backend we verify
/// certificates: silently accepting any cert over a remote hop is a MITM
/// risk. Idle connections are retired before the backend's keep-alive
/// timeout closes them ([`BACKEND_POOL_IDLE_TIMEOUT`]).
pub fn build_proxy_client(timeout_secs: u64, python_url: &str) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .connect_timeout(std::time::Duration::from_secs(5))
        .pool_max_idle_per_host(16)
        .pool_idle_timeout(BACKEND_POOL_IDLE_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none());
    if is_loopback_url(python_url) {
        // Python backend is local — no TLS, cert verification is moot.
        builder = builder.danger_accept_invalid_certs(true);
    } else if python_url.starts_with("https") {
        warn!(
            python_url,
            "UC_PYTHON_URL is a non-loopback HTTPS backend — verifying its TLS \
             certificate (verification is only skipped for loopback backends)"
        );
    }
    builder.build().expect("Failed to build proxy HTTP client")
}

/// Returns true when `url`'s host is a loopback address (127.0.0.0/8, ::1)
/// or `localhost`. Used to decide whether skipping TLS verification to the
/// Python backend is safe.
pub(crate) fn is_loopback_url(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Catch-all handler that proxies the request to the Python backend.
///
/// This is mounted as a fallback on the axum router so any route not
/// explicitly handled by Rust is forwarded transparently.
pub async fn proxy_fallback(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    // Refused before anything else (the framing guard around the whole
    // app refuses it first — this guards the handler itself).
    if has_ambiguous_framing(req.headers()) {
        return ambiguous_framing_response();
    }
    let method = req.method().clone();
    // A method the bridge serves no route for (TRACE, CONNECT, extension
    // methods) is refused, before the body is read: it was forwarded as
    // GET, so the bridge ran another method than the one auth and CSRF
    // decided on.
    let Some(backend_method) = to_reqwest_method(&method) else {
        debug!(
            method = %method,
            path = %req.uri().path(),
            "Refused a method the proxy does not forward"
        );
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, FORWARDED_METHODS)],
            "Method Not Allowed",
        )
            .into_response();
    };
    let uri = req.uri().clone();
    let path = uri.path();
    let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();

    // The bridge's gateway-only API is never proxied (K9; the router's
    // canonicalization refuses it first — this guards the handler itself).
    if is_internal_path(path) {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }
    // A control character (`%0A`…) would let the bridge serve another
    // route than the one routed here (V1; the canonicalization refuses it
    // first).
    if has_control_character(path) {
        return (StatusCode::BAD_REQUEST, "Invalid path").into_response();
    }

    // Path traversal protection: `..`, `//`, and anything else the URL
    // parser below would rewrite (`\`, `.` segments; K9 — the router's
    // canonicalization refuses these first).
    if path.contains("..") || path.contains("//") || is_ambiguous_path(path) {
        return (StatusCode::BAD_REQUEST, "Invalid path").into_response();
    }
    // Check URL-encoded traversal
    let decoded = path
        .replace("%2e", ".")
        .replace("%2E", ".")
        .replace("%2f", "/")
        .replace("%2F", "/");
    if decoded.contains("..") || (decoded.contains("//") && decoded != path) {
        return (StatusCode::BAD_REQUEST, "Invalid path").into_response();
    }

    // --- License feature gate ---------------------------------------------------
    // If the path matches a feature-gated route, ask the injected resolver
    // whether the current licence grants it before spending resources
    // proxying the request to Python.
    if let Some(required) = state.feature_routes.required_feature(path) {
        let allowed = state.license_resolver.has_feature(required);
        if !allowed {
            warn!(
                path = %path,
                feature = %required,
                "License feature gate denied request"
            );
            return (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({
                    "detail": format!(
                        "License does not include the '{}' feature required for {}",
                        required, path
                    )
                })),
            )
                .into_response();
        }
    }

    let target_url = format!("{}{}{}", state.config.python_url, path, query);
    // What reqwest sends is the path of the parsed URL, not the string
    // above: the WHATWG URL parser it uses reads `\` as `/` and removes
    // dot segments. Forward only when that is still the path that was
    // routed and checked here, and never when it is the internal API (K9).
    let target = match reqwest::Url::parse(&target_url) {
        Ok(target) => target,
        Err(e) => {
            warn!(path = %path, error = %e, "Refused a path that is not a valid backend URL");
            return (StatusCode::BAD_REQUEST, "Invalid path").into_response();
        }
    };
    if is_internal_path(target.path()) {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }
    if !forwarded_unchanged(target.path(), path) {
        warn!(
            path = %path,
            sent = %target.path(),
            "Refused a path the backend URL would change"
        );
        return (StatusCode::BAD_REQUEST, "Invalid path").into_response();
    }

    // WebSocket upgrade requests cannot be proxied as regular HTTP.
    // Return 426 so the client knows to retry — or, if the path matches
    // a known Python WS endpoint, redirect to Python's WS handler.
    let is_ws_upgrade = req
        .headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    if is_ws_upgrade {
        // For WebSocket connections, we can't proxy through reqwest.
        // Return 502 with a hint — the client will retry or fall back to polling.
        debug!(path = %path, "WebSocket upgrade request — not proxied (use Rust-native WS routes)");
        return (
            StatusCode::BAD_GATEWAY,
            "WebSocket proxy not supported — use /ws/feed or /ws/anomalies",
        )
            .into_response();
    }

    debug!(method = %method, path = %path, target = %target_url, "Proxying to Python");

    // Build the outbound request
    let mut proxy_req = state.proxy_client.request(backend_method, target);

    // Forward headers (filter hop-by-hop + host, which reqwest sets from target URL)
    let headers = req.headers();
    // For the response: the validators a revalidating client holds.
    let if_none_match: Vec<HeaderValue> = headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .cloned()
        .collect();
    let mut forwarded_headers = HeaderMap::new();
    for (name, value) in headers.iter() {
        if is_hop_by_hop(name.as_str()) || name.as_str() == "host" {
            continue;
        }
        // The body is forwarded as the bytes read below, and framed by
        // their length; the client's Content-Length need not describe
        // them (RFC 9112 §6.3: Transfer-Encoding overrides it).
        if name == header::CONTENT_LENGTH {
            continue;
        }
        // Strip client-supplied trust headers. The gateway is the sole
        // authority for x-rust-proxy / x-auth-*; a value forged by the
        // client must never reach Python (it would be an auth bypass
        // once Python honours the cert trust header).
        if is_trust_header(name.as_str()) {
            continue;
        }
        // The forwarding headers the bridge believes are the gateway's
        // (below): a client copy never reaches it — with or without a
        // Host header (HTTP/2 has none), or a known client address.
        if is_forwarding_header(name.as_str()) {
            continue;
        }
        // Cookie fields are joined and filtered together below, into the
        // one Cookie field an HTTP/1 request may carry (RFC 9113 §8.2.3).
        if name.as_str() == "cookie" {
            continue;
        }
        // The client's session credentials: the bridge gets the session
        // the gateway verified (below), and no other.
        if is_session_credential_header(name.as_str()) {
            continue;
        }
        // Every value, in order: a repeated field is a list, and the
        // bridge, like the gateway's own checks, reads the first one. The
        // gateway's own headers below replace any client copy (`insert`).
        forwarded_headers.append(name.clone(), value.clone());
    }
    if let Some(cookies) = backend_cookies(headers) {
        forwarded_headers.insert(header::COOKIE, cookies);
    }
    // Headers the client names in Connection are hop-by-hop too (RFC 9110
    // §7.6.1). Only the client's own copies are dropped (a nominated
    // Cookie drops the joined one): what the gateway sets below is added
    // after this.
    remove_connection_nominated(headers, &mut forwarded_headers);

    // Set X-Forwarded-For to the resolved client IP (see `forwarded_for`).
    if let Some(val) = forwarded_for(req.extensions()) {
        forwarded_headers.insert(header::HeaderName::from_static("x-forwarded-for"), val);
    }

    // Inject trust header so Python knows this came through Rust.
    forwarded_headers.insert(
        header::HeaderName::from_static("x-rust-proxy"),
        proxy_secret_header(&state.config.proxy_secret),
    );

    // Forward authenticated user info to Python.
    for (name, value) in identity_headers(&req) {
        forwarded_headers.insert(name, value);
    }
    if let Some(crate::middleware::auth::AuthInfo::Session { session_token, .. }) =
        req.extensions().get::<crate::middleware::auth::AuthInfo>()
    {
        // Forward the verified session token so Python can validate it
        // (the bridge resolves the session itself).
        let bearer = format!("Bearer {}", session_token);
        if let Ok(val) = HeaderValue::from_str(&bearer) {
            forwarded_headers.insert(header::AUTHORIZATION, val);
        }
    }

    // Forward the authority the client addressed, as Host and
    // X-Forwarded-Host, so Starlette generates correct URLs. Without it
    // (an HTTP/2 request has no Host header), url_for() and the bridge's
    // redirects name http://127.0.0.1:8001/..., which the browser can't
    // reach and CSP blocks.
    if let Some(authority) = external_authority(req.uri(), headers) {
        forwarded_headers.insert(header::HOST, authority.clone());
        forwarded_headers.insert(
            header::HeaderName::from_static("x-forwarded-host"),
            authority,
        );
    }
    // The scheme the client used, always (see `forwarded_proto`).
    let proto = {
        let auth_config = state.auth_config.read().await;
        forwarded_proto(
            state.config.tls_enabled(),
            req.extensions(),
            headers,
            &auth_config.trusted_proxies,
        )
    };
    forwarded_headers.insert(header::HeaderName::from_static("x-forwarded-proto"), proto);

    // Inject license info headers for Python backend
    {
        let tier = state.license_resolver.tier().as_str();
        if let Ok(val) = HeaderValue::from_str(tier) {
            forwarded_headers.insert(header::HeaderName::from_static("x-license-tier"), val);
        }
        let features = state.license_resolver.features().join(",");
        if let Ok(val) = HeaderValue::from_str(&features) {
            forwarded_headers.insert(header::HeaderName::from_static("x-license-features"), val);
        }
        if let Some(limit) = state.license_resolver.node_limit() {
            if let Ok(val) = HeaderValue::from_str(&limit.to_string()) {
                forwarded_headers
                    .insert(header::HeaderName::from_static("x-license-node-limit"), val);
            }
        }
    }

    // Inject correlation ID if not already present
    if !forwarded_headers.contains_key("x-request-id") {
        let req_id = uuid::Uuid::new_v4().to_string();
        if let Ok(val) = HeaderValue::from_str(&req_id) {
            forwarded_headers.insert(header::HeaderName::from_static("x-request-id"), val);
        }
    }

    proxy_req = proxy_req.headers(forwarded_headers);

    // Forward body
    let body_bytes = match axum::body::to_bytes(req.into_body(), state.config.max_body_size).await {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "Request body too large").into_response();
        }
    };
    if !body_bytes.is_empty() {
        // Framed by its own length (hyper sets the Content-Length).
        proxy_req = proxy_req.body(body_bytes);
    } else if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
        // An empty body sends no Content-Length; for a method that
        // defines content, say it is empty, as clients do.
        proxy_req = proxy_req.header(header::CONTENT_LENGTH, "0");
    }

    // Send to Python
    let response = match proxy_req.send().await {
        Ok(resp) => resp,
        Err(e) => {
            if e.is_connect() || e.is_timeout() {
                error!(error = %e, target = %target_url, "Python backend unreachable");
                return (StatusCode::BAD_GATEWAY, "Python backend unavailable").into_response();
            }
            warn!(error = %e, target = %target_url, "Proxy request failed");
            return (StatusCode::BAD_GATEWAY, "Proxy error").into_response();
        }
    };

    // Build the axum response from the reqwest response
    let status = StatusCode::from_u16(response.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    // Every value of a repeated header, in order: Set-Cookie above all,
    // which cannot be joined into one field. Hop-by-hop headers, and those
    // the backend names in Connection, stay on the backend hop.
    let backend_url = reqwest::Url::parse(&state.config.python_url).ok();
    let mut resp_headers = HeaderMap::new();
    for (name, value) in response.headers().iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        if name == header::SET_COOKIE && !relays_backend_cookie(path, value) {
            warn!(
                path = %path,
                "Dropped a Set-Cookie for a session cookie from the backend: \
                 only the gateway (and the SSO routes under /api/oidc) issue \
                 session cookies"
            );
            continue;
        }
        // A redirect to the backend's own origin (Starlette builds an
        // absolute one from the Host it got) goes out as the gateway path
        // it maps to, as the HTML rewrite below does for links, so the
        // internal address never reaches the client.
        let value = match &backend_url {
            Some(backend) if name == header::LOCATION || name == header::CONTENT_LOCATION => {
                gateway_relative(value, backend).unwrap_or_else(|| value.clone())
            }
            _ => value.clone(),
        };
        resp_headers.append(name.clone(), value);
    }
    remove_connection_nominated(response.headers(), &mut resp_headers);

    // HTML is rewritten only when the body is the page itself: not still
    // compressed (reqwest decodes gzip only), nor a byte range of it.
    let rewrite_html = resp_headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().contains("text/html"))
        && status != StatusCode::PARTIAL_CONTENT
        && !resp_headers
            .get_all(header::CONTENT_ENCODING)
            .iter()
            .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"));

    let resp_bytes: Bytes = match response.bytes().await {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "Failed to read Python response body");
            return (StatusCode::BAD_GATEWAY, "Failed to read backend response").into_response();
        }
    };

    // Rewrite Python internal URLs in HTML responses so the browser
    // loads assets from the external gateway, not the internal backend.
    let backend_origin = state.config.python_url.trim_end_matches('/');
    let final_body = match rewrite_html
        .then(|| strip_backend_origin(&resp_bytes, backend_origin.as_bytes()))
        .flatten()
    {
        Some(rewritten) => {
            // The backend's length and strong validator described the
            // body before the rewrite. hyper sets the length of this one.
            resp_headers.remove(header::CONTENT_LENGTH);
            weaken_etags(&mut resp_headers);
            Bytes::from(rewritten)
        }
        None => resp_bytes,
    };
    // A HEAD has no body to rewrite, but describes the page a GET gets,
    // which may be rewritten: its length is not known here, so it sends
    // none (RFC 9110 §8.6: none but the GET's), and its ETag is the weak
    // one of a rewritten page.
    let head_of_page = rewrite_html && method == Method::HEAD;
    if head_of_page {
        resp_headers.remove(header::CONTENT_LENGTH);
        weaken_etags(&mut resp_headers);
    }
    // A client revalidating a rewritten page holds its weak ETag, and the
    // backend answers 304 with its strong one, which would update no
    // stored response but one with that strong ETag (RFC 9111 §4.3.4):
    // send the weak one back. (The backend's 304 usually has no
    // Content-Type, so this goes by what the client holds.)
    if status == StatusCode::NOT_MODIFIED && holds_weakened_etag(&resp_headers, &if_none_match) {
        weaken_etags(&mut resp_headers);
    }

    let body = if head_of_page {
        // Of unknown length: for an empty body, of exact length 0, axum
        // would set `Content-Length: 0`.
        Body::from_stream(futures_util::stream::empty::<
            Result<Bytes, std::convert::Infallible>,
        >())
    } else {
        Body::from(final_body)
    };
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    *resp.headers_mut() = resp_headers;
    resp
}

/// `X-Forwarded-For` for a proxied request: the client IP the auth
/// middleware resolved ([`ClientIp`]: the peer, or the client named by a
/// trusted proxy in `UC_TRUSTED_PROXIES`, in canonical form — an
/// IPv4-mapped address as plain IPv4). It is the value the gateway binds
/// its sessions to, so the bridge's IP-binding check compares the same
/// string. Without a resolved value, the canonical peer address.
///
/// The gateway REPLACES rather than appends: an incoming XFF the gateway
/// did not vouch for would let a client spoof the bridge's per-IP rate
/// limiter / audit trail. Shared by the HTTP and WebSocket proxies.
pub(crate) fn forwarded_for(extensions: &axum::http::Extensions) -> Option<HeaderValue> {
    if let Some(ClientIp(ip)) = extensions.get::<ClientIp>() {
        if ip != UNKNOWN_CLIENT {
            return HeaderValue::from_str(ip).ok();
        }
    }
    let ConnectInfo(peer) = extensions.get::<ConnectInfo<SocketAddr>>()?;
    HeaderValue::from_str(&peer.ip().to_canonical().to_string()).ok()
}

/// `X-Forwarded-Proto` for a proxied request: the scheme the client used
/// to reach the gateway. The bridge builds its URLs with it, and hands out
/// a rotated API key only when it says `https`.
///
/// - When the direct peer (the connection's address, not a client named
///   in X-Forwarded-For) is a trusted proxy (`UC_TRUSTED_PROXIES`) and
///   its X-Forwarded-Proto is `http` or `https` (any letter case; of a
///   list, the rightmost entry, which the nearest proxy added): that, on
///   either listener. A TLS-terminating reverse proxy in front of the
///   plaintext listener says `https`; a load balancer that takes plain
///   http from its clients and re-encrypts to the TLS listener says
///   `http`, and the client's hop is then not encrypted.
/// - Otherwise the listener's scheme, whatever the request claims:
///   `https` on the gateway's TLS listener (`UC_TLS_CERT` /
///   `UC_TLS_KEY`), `http` on its plaintext one.
///
/// Shared by the HTTP and WebSocket proxies.
pub(crate) fn forwarded_proto(
    tls_listener: bool,
    extensions: &axum::http::Extensions,
    headers: &HeaderMap,
    trusted: &TrustedProxies,
) -> HeaderValue {
    let peer_is_trusted = extensions
        .get::<ConnectInfo<SocketAddr>>()
        .is_some_and(|ConnectInfo(peer)| trusted.contains(peer.ip()));
    let vouched = peer_is_trusted
        .then(|| {
            let proto = headers
                .get_all("x-forwarded-proto")
                .iter()
                .next_back()?
                .to_str()
                .ok()?
                .rsplit(',')
                .next()?
                .trim();
            if proto.eq_ignore_ascii_case("https") {
                Some(true)
            } else if proto.eq_ignore_ascii_case("http") {
                Some(false)
            } else {
                None
            }
        })
        .flatten();
    let https = vouched.unwrap_or(tls_listener);
    HeaderValue::from_static(if https { "https" } else { "http" })
}

/// The authority the client addressed, for the Host and X-Forwarded-Host
/// the bridge gets: the request target's authority — HTTP/2's
/// `:authority` (an HTTP/2 request has no Host header), or an
/// absolute-form HTTP/1.1 target, which takes precedence over Host (RFC
/// 9112 §3.2.2) — and otherwise the Host header. Any userinfo is left out.
/// Shared by the HTTP and WebSocket proxies.
pub(crate) fn external_authority(
    uri: &axum::http::Uri,
    headers: &HeaderMap,
) -> Option<HeaderValue> {
    if let Some(authority) = uri.authority() {
        let host_port = authority
            .as_str()
            .rsplit_once('@')
            .map_or(authority.as_str(), |(_, host_port)| host_port);
        if let Ok(value) = HeaderValue::from_str(host_port) {
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    headers.get(header::HOST).cloned()
}

/// `X-Rust-Proxy` for a proxied request: the shared proxy secret. If it is
/// empty or unparseable, an empty value — Python's trust check requires a
/// non-empty secret on both sides, so an empty header fails closed.
pub(crate) fn proxy_secret_header(secret: &str) -> HeaderValue {
    HeaderValue::from_str(secret).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// The identity the gateway verified, as trust headers for Python
/// (`x-auth-user` / `x-auth-key-id`, `x-auth-role`). A request
/// authenticated by a verified client cert carries a ClientCertInfo
/// extension and no API key — its identity cannot be re-validated by
/// Python (the cert terminated at the gateway's TLS layer), so it is
/// marked `x-auth-method: client-cert`. (The WebSocket proxy sends the same
/// headers, built from the socket's verified principal.)
pub(crate) fn identity_headers(req: &Request<Body>) -> Vec<(header::HeaderName, HeaderValue)> {
    use crate::middleware::auth::AuthInfo;
    let mut out = Vec::new();
    let is_cert_auth = req
        .extensions()
        .get::<crate::auth::client_cert::ClientCertInfo>()
        .is_some()
        && crate::auth::api_key::extract_api_key(req).is_none();
    match req.extensions().get::<AuthInfo>() {
        Some(AuthInfo::Session { username, role, .. }) => {
            if let Ok(val) = HeaderValue::from_str(username) {
                out.push((header::HeaderName::from_static("x-auth-user"), val));
            }
            out.push((
                header::HeaderName::from_static("x-auth-role"),
                HeaderValue::from_static(role.as_str()),
            ));
        }
        Some(AuthInfo::ApiKey { key_id, role }) => {
            if let Ok(val) = HeaderValue::from_str(key_id) {
                out.push((header::HeaderName::from_static("x-auth-key-id"), val));
            }
            out.push((
                header::HeaderName::from_static("x-auth-role"),
                HeaderValue::from_static(role.as_str()),
            ));
            if is_cert_auth {
                out.push((
                    header::HeaderName::from_static("x-auth-method"),
                    HeaderValue::from_static("client-cert"),
                ));
            }
        }
        _ => {}
    }
    out
}

/// The methods the proxy forwards: those the bridge serves (its routes use
/// GET, POST, PUT, PATCH and DELETE; its CORS middleware answers OPTIONS),
/// as the `Allow` header of a 405. (In the gateway an OPTIONS never gets
/// here: its own CORS layer answers every one.)
const FORWARDED_METHODS: &str = "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS";

/// The backend method for a method the proxy forwards ([`FORWARDED_METHODS`]);
/// `None` for any other — TRACE (which would echo the proxy secret and
/// bearer token back), CONNECT and extension methods are never forwarded.
fn to_reqwest_method(method: &Method) -> Option<reqwest::Method> {
    match *method {
        Method::GET => Some(reqwest::Method::GET),
        Method::POST => Some(reqwest::Method::POST),
        Method::PUT => Some(reqwest::Method::PUT),
        Method::DELETE => Some(reqwest::Method::DELETE),
        Method::PATCH => Some(reqwest::Method::PATCH),
        Method::HEAD => Some(reqwest::Method::HEAD),
        Method::OPTIONS => Some(reqwest::Method::OPTIONS),
        _ => None,
    }
}

/// Returns true for hop-by-hop headers that should not be forwarded.
/// (`trailer` announces trailer fields of a chunked body, which is never
/// forwarded as such; `trailers` is kept from an older list.)
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Remove from `headers` every field that the `Connection` fields of
/// `message` nominate as hop-by-hop (RFC 9110 §7.6.1): comma-separated,
/// trimmed, case-insensitive tokens. A token that is not a header name
/// (empty, holding a space…) names none, and an unreadable Connection
/// value names nothing. One map lookup per token: the cost grows with the
/// length of the Connection fields, not with that times the number of
/// headers (hyper admits ~400 KB of header, ~130k short tokens).
fn remove_connection_nominated(message: &HeaderMap, headers: &mut HeaderMap) {
    for token in message
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
    {
        // `remove` by `&str` matches in any letter case and finds nothing
        // for an invalid name.
        headers.remove(token.trim());
    }
}

/// `location` (a Location or Content-Location value) as the gateway path
/// it maps to, when it names the backend: the same origin as
/// `UC_PYTHON_URL` (scheme, host in any letter case, port with the
/// scheme's default) and a path at or below its path prefix, at a segment
/// boundary. Query and fragment are kept. `None` — send it as it is — for
/// anything else: a relative reference, another origin (another port of
/// the same host too), a path outside the prefix, a gateway path that
/// would start with `//` (a browser reads that as another host), or a
/// value that is not an ASCII URL.
fn gateway_relative(location: &HeaderValue, backend: &reqwest::Url) -> Option<HeaderValue> {
    let location = reqwest::Url::parse(location.to_str().ok()?.trim()).ok()?;
    if location.scheme() != backend.scheme()
        || location.host() != backend.host()
        || location.port_or_known_default() != backend.port_or_known_default()
    {
        return None;
    }
    let rest = location
        .path()
        .strip_prefix(backend.path().trim_end_matches('/'))?;
    // A path that starts with `//` (the parser also reads `/\` so) would
    // go out as a protocol-relative URL: another host, an open redirect.
    if (!rest.is_empty() && !rest.starts_with('/')) || rest.starts_with("//") {
        return None;
    }
    let mut relative = if rest.is_empty() {
        String::from("/")
    } else {
        rest.to_string()
    };
    if let Some(query) = location.query() {
        relative.push('?');
        relative.push_str(query);
    }
    if let Some(fragment) = location.fragment() {
        relative.push('#');
        relative.push_str(fragment);
    }
    HeaderValue::from_str(&relative).ok()
}

/// `body` without the backend URL `origin` (`UC_PYTHON_URL`, no trailing
/// slash), so the links it held are relative to the gateway: what followed
/// an occurrence is kept as the path, or `/` when it named the root
/// (`origin?x` becomes `/?x`). An occurrence that goes on with a character
/// that continues a host, port or path segment (`:8001` inside `:80010`)
/// is another URL, and is kept. Works on bytes, so HTML in another
/// encoding is never altered elsewhere. `None` when nothing changed.
fn strip_backend_origin(body: &[u8], origin: &[u8]) -> Option<Vec<u8>> {
    fn continues_url(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || b"-._~%:@".contains(&byte)
    }
    if origin.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(body.len());
    let mut rest = body;
    let mut changed = false;
    while let Some(at) = rest.windows(origin.len()).position(|w| w == origin) {
        out.extend_from_slice(&rest[..at]);
        let after = &rest[at + origin.len()..];
        match after.first() {
            Some(b'/') => changed = true,
            Some(&byte) if continues_url(byte) => out.extend_from_slice(origin),
            _ => {
                out.push(b'/');
                changed = true;
            }
        }
        rest = after;
    }
    if !changed {
        return None;
    }
    out.extend_from_slice(rest);
    Some(out)
}

/// Mark strong ETags weak (`W/"…"`, RFC 9110 §8.8.1): a rewritten body is
/// no longer the backend's bytes, but means the same. Revalidation keeps
/// working (Starlette compares If-None-Match weakly); a range request
/// with If-Range, which needs a strong validator, gets the whole body.
fn weaken_etags(headers: &mut HeaderMap) {
    let etags: Vec<HeaderValue> = headers
        .get_all(header::ETAG)
        .iter()
        .map(|etag| {
            if !etag.as_bytes().starts_with(b"\"") {
                return etag.clone();
            }
            let mut weak = b"W/".to_vec();
            weak.extend_from_slice(etag.as_bytes());
            HeaderValue::from_bytes(&weak).unwrap_or_else(|_| etag.clone())
        })
        .collect();
    headers.remove(header::ETAG);
    for etag in etags {
        headers.append(header::ETAG, etag);
    }
}

/// Whether a client's If-None-Match (`if_none_match`, its fields) holds
/// the weak form `W/"…"` of a strong ETag in `headers`: the validator
/// [`weaken_etags`] gave a rewritten page. (An entity tag holds no `"`,
/// so the quoted form found in a field is that tag.)
fn holds_weakened_etag(headers: &HeaderMap, if_none_match: &[HeaderValue]) -> bool {
    headers
        .get_all(header::ETAG)
        .iter()
        .filter(|etag| etag.as_bytes().starts_with(b"\""))
        .any(|etag| {
            let weak = [b"W/".as_slice(), etag.as_bytes()].concat();
            if_none_match.iter().any(|field| {
                field
                    .as_bytes()
                    .windows(weak.len())
                    .any(|window| window == weak.as_slice())
            })
        })
}

/// Join split Cookie fields for the HTTP/1 backend, retaining CSRF and
/// ordinary cookies. The verified session is forwarded as Authorization;
/// never pass a client's session_token or legacy bridge_token through.
/// A cookie is matched by its name as the bridge reads it ([`cookie_pair`]:
/// without the whitespace around it), so `session_token =<token>` is
/// dropped too: the bridge would take it for the session cookie and
/// accept a token the gateway never checked. A field that is not visible
/// ASCII is dropped whole.
///
/// [`cookie_pair`]: crate::middleware::auth::cookie_pair
fn backend_cookies(headers: &HeaderMap) -> Option<HeaderValue> {
    use crate::middleware::auth::{cookie_pair, SESSION_COOKIE};
    let kept: Vec<&str> = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .map(str::trim)
        .filter(|cookie| {
            !cookie.is_empty()
                && !matches!(
                    cookie_pair(cookie),
                    Some((name, _)) if name == SESSION_COOKIE || name == "bridge_token"
                )
        })
        .collect();
    if kept.is_empty() {
        return None;
    }
    HeaderValue::from_str(&kept.join("; ")).ok()
}

/// The path of the SSO routes: the bridge mounts the `sigrift-sentinel`
/// add-on's OIDC router (`sigrift_sentinel.routers.oidc`) under `/api`
/// when it is installed, and serves nothing there otherwise.
const SSO_PATH: &str = "/api/oidc";

/// True for [`SSO_PATH`] and the paths below it, as routed here
/// (case-sensitive, not percent-decoded).
fn is_sso_path(path: &str) -> bool {
    path.strip_prefix(SSO_PATH)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// The cookie only the gateway issues that a backend `Set-Cookie` value
/// sets or expires: the HttpOnly `session_token`, or the JS-readable
/// `bridge_token` older gateways set; `None` for any other cookie. Its
/// name is read as a browser and [`cookie_pair`] read it: before the first
/// `=` of the part before the first `;`, without the spaces around it,
/// case-sensitive. Read as bytes, so a value that is not visible ASCII is
/// judged by its name too.
///
/// [`cookie_pair`]: crate::middleware::auth::cookie_pair
fn gateway_session_cookie(value: &HeaderValue) -> Option<&'static str> {
    use crate::auth::session_handler::LEGACY_TOKEN_COOKIE;
    use crate::middleware::auth::SESSION_COOKIE;
    let pair = value
        .as_bytes()
        .split(|&b| b == b';')
        .next()
        .unwrap_or_default();
    let eq = pair.iter().position(|&b| b == b'=')?;
    let name = pair[..eq].trim_ascii();
    [SESSION_COOKIE, LEGACY_TOKEN_COOKIE]
        .into_iter()
        .find(|cookie| name == cookie.as_bytes())
}

/// Whether the proxy relays a backend `Set-Cookie` value in its answer to
/// a request for `path`.
///
/// Not when it sets or expires a cookie only the gateway issues
/// ([`gateway_session_cookie`]): no proxied route may plant a session in
/// the browser (session fixation) or end one behind the gateway's back.
/// The community bridge sets neither (every route of its own that issues
/// or ends a session is a native gateway route); this holds when it does.
///
/// The one exception is `session_token` from the SSO routes
/// ([`is_sso_path`]), the only bridge-side session issuer the gateway
/// does not shadow: the IdP redirects the browser to the add-on's
/// callback, which can hand the browser its session only as a cookie.
/// The legacy `bridge_token` is never relayed.
fn relays_backend_cookie(path: &str, value: &HeaderValue) -> bool {
    match gateway_session_cookie(value) {
        None => true,
        Some(cookie) => cookie == crate::middleware::auth::SESSION_COOKIE && is_sso_path(path),
    }
}

/// The client's session credentials: `Authorization` (the bridge reads a
/// `Bearer` session token there, in any letter case) and `X-Session-Token`.
/// The proxy never forwards them, nor the `session_token` cookie
/// ([`backend_cookies`]). The bridge resolves a session token it is
/// given itself, but not with every check the gateway made (the shipped
/// compose file leaves its IP binding off), so a token the gateway refused
/// — bound to another client IP, say — or did not take for a session must
/// not reach it. A session the gateway verified, from any of these headers
/// or the `session_token` cookie, is sent as `Authorization: Bearer`.
fn is_session_credential_header(name: &str) -> bool {
    matches!(name, "authorization" | "x-session-token")
}

/// Forwarding headers: who the client is and how it reached the gateway.
/// The bridge believes only the gateway's (`X-Forwarded-For`, `-Host`,
/// `-Proto`, set by the proxy itself), so any client copy is stripped —
/// with the variants it does not read today, so that no future reader
/// picks up a client's.
fn is_forwarding_header(name: &str) -> bool {
    matches!(
        name,
        "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-proto"
            | "x-forwarded-port"
            | "x-forwarded-prefix"
            | "forwarded"
            | "x-real-ip"
    )
}

/// Trust headers the gateway sets itself from verified auth state and
/// from the licence resolver (`x-license-*`). Any client-supplied copy is
/// stripped before proxying so it cannot be forged — Python trusts these
/// only because the gateway owns them (a client `X-License-Node-Limit`
/// would otherwise pass through whenever the resolver sets none).
fn is_trust_header(name: &str) -> bool {
    matches!(
        name,
        "x-rust-proxy" | "x-auth-user" | "x-auth-role" | "x-auth-key-id" | "x-auth-method"
    ) || name.starts_with("x-license-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn proxy_joins_split_cookies_without_forwarding_unverified_sessions() {
        use crate::auth::rbac::Role;
        use crate::middleware::auth::AuthInfo;
        use axum::{routing::post, Json, Router};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let backend = Router::new().route(
            "/api/change",
            post(|headers: HeaderMap| async move {
                Json(serde_json::json!({
                    "cookie": headers.get(header::COOKIE).unwrap().to_str().unwrap(),
                    "cookie_fields": headers.get_all(header::COOKIE).iter().count(),
                    "authorization": headers.get(header::AUTHORIZATION).unwrap().to_str().unwrap(),
                }))
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, backend).await.unwrap() });
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::test_support::app_state(&dir);
        Arc::get_mut(&mut state).unwrap().config.python_url = format!("http://{address}");
        let mut req = Request::post("/api/change")
            .version(axum::http::Version::HTTP_2)
            .header(header::COOKIE, "csrf_token=csrf; session_token=unverified")
            .header(header::COOKIE, "theme=dark; bridge_token=legacy")
            .header(header::COOKIE, "locale=en")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(AuthInfo::Session {
            username: "u".into(),
            user_id: 1,
            role: Role::Admin,
            session_token: "verified".into(),
            expires_at: "".into(),
            tenant_id: "default".into(),
            scope: String::new(),
        });
        let response = proxy_fallback(State(state), req).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        server.abort();
        let received: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(received["cookie"], "csrf_token=csrf; theme=dark; locale=en");
        assert_eq!(received["cookie_fields"], 1);
        assert_eq!(received["authorization"], "Bearer verified");
    }

    #[test]
    fn proxy_omits_cookies_when_only_unverified_sessions_are_present() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("session_token=unverified"),
        );
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("bridge_token=legacy"),
        );
        assert!(backend_cookies(&headers).is_none());
    }

    /// Regression: a cookie was dropped when it started with
    /// `session_token=`, but the bridge (Starlette's `cookie_parser`) reads
    /// a cookie's name without the whitespace around it, so
    /// `session_token =<token>` reached it as the session cookie, with a
    /// token the gateway had neither resolved nor checked. Every cookie
    /// whose name is `session_token` or `bridge_token`, as the bridge reads
    /// the name, is dropped; any other cookie is kept as sent.
    #[test]
    fn session_cookies_are_dropped_by_the_name_the_bridge_reads() {
        let mut headers = HeaderMap::new();
        for field in [
            "session_token =a; theme=dark",
            "csrf_token=c;session_token\t=b",
            " session_token \t= c ;bridge_token =d",
            "Session_Token=kept; xsession_token=kept; session_tokens=kept",
            "nameless; theme=session_token=kept; session token=kept",
        ] {
            headers.append(header::COOKIE, HeaderValue::from_static(field));
        }
        assert_eq!(
            backend_cookies(&headers).unwrap(),
            "theme=dark; csrf_token=c; Session_Token=kept; xsession_token=kept; \
             session_tokens=kept; nameless; theme=session_token=kept; session token=kept"
        );
        assert!(
            crate::middleware::auth::session_token_from_headers(&headers).is_some(),
            "the gateway reads those names as the session cookie too"
        );

        let mut only_sessions = HeaderMap::new();
        only_sessions.append(
            header::COOKIE,
            HeaderValue::from_static("session_token =a;\tbridge_token\t= b"),
        );
        assert!(backend_cookies(&only_sessions).is_none());
    }

    /// A Cookie field that is not visible ASCII is dropped whole, with the
    /// session cookie in it: the gateway never reads a session from such a
    /// field, so forwarding it would hand the bridge (which decodes the
    /// field as Latin-1) a session token the gateway never checked. Empty
    /// pairs are dropped too.
    #[test]
    fn opaque_cookie_fields_are_dropped_whole() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::from_bytes(b"session_token=unchecked; theme=caf\xe9").unwrap(),
        );
        headers.append(header::COOKIE, HeaderValue::from_static("a=1;; ;b=2;"));
        assert_eq!(
            crate::middleware::auth::session_token_from_headers(&headers),
            None,
            "no session for the gateway"
        );
        assert_eq!(backend_cookies(&headers).unwrap(), "a=1; b=2");

        let mut opaque_only = HeaderMap::new();
        opaque_only.append(
            header::COOKIE,
            HeaderValue::from_bytes(b"session_token=unchecked\x80").unwrap(),
        );
        assert!(backend_cookies(&opaque_only).is_none());
    }

    /// Regression (Q2): XFF was the raw peer, while sessions are bound to
    /// the canonical resolved client — a dual-stack listener forwarded an
    /// IPv4 client as `::ffff:a.b.c.d`, and behind a trusted reverse proxy
    /// the proxy's address, so the bridge refused gateway sessions.
    #[test]
    fn forwarded_for_is_the_resolved_canonical_client() {
        use axum::http::Extensions;
        let peer = |addr: &str| ConnectInfo(addr.parse::<SocketAddr>().unwrap());

        let mut ext = Extensions::new();
        ext.insert(peer("[::ffff:198.51.100.7]:4000"));
        assert_eq!(forwarded_for(&ext).unwrap(), "198.51.100.7");

        // Behind a trusted proxy: the client the middleware resolved.
        let mut ext = Extensions::new();
        ext.insert(peer("10.0.0.2:4000"));
        ext.insert(ClientIp("203.0.113.5".into()));
        assert_eq!(forwarded_for(&ext).unwrap(), "203.0.113.5");

        // The middleware's resolution of a mapped peer, end to end.
        let trusted = crate::middleware::client_ip::TrustedProxies::default();
        let mut req = Request::get("/x").body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(peer("[::ffff:198.51.100.7]:4000"));
        let resolved = crate::middleware::client_ip::extract_client_ip(&req, &trusted);
        req.extensions_mut().insert(ClientIp(resolved));
        assert_eq!(forwarded_for(req.extensions()).unwrap(), "198.51.100.7");

        // No peer known: nothing to vouch for.
        let mut ext = Extensions::new();
        ext.insert(ClientIp(UNKNOWN_CLIENT.into()));
        assert!(forwarded_for(&ext).is_none());
    }

    #[test]
    fn test_hop_by_hop_headers() {
        assert!(is_hop_by_hop("connection"));
        assert!(is_hop_by_hop("keep-alive"));
        assert!(is_hop_by_hop("proxy-authenticate"));
        assert!(is_hop_by_hop("proxy-authorization"));
        assert!(is_hop_by_hop("te"));
        assert!(is_hop_by_hop("trailers"));
        assert!(is_hop_by_hop("transfer-encoding"));
        assert!(is_hop_by_hop("upgrade"));
        assert!(is_hop_by_hop("trailer"));
        assert!(is_hop_by_hop("proxy-connection"));
    }

    /// Connection tokens are trimmed and case-insensitive, read from every
    /// Connection field, and remove every value of the header they name;
    /// empty tokens, invalid names and unreadable values name nothing.
    #[test]
    fn connection_nominations_are_read_from_every_field() {
        let mut message = HeaderMap::new();
        message.append(
            header::CONNECTION,
            HeaderValue::from_static("close, X-Hop ,, bad name, x-absent"),
        );
        message.append(header::CONNECTION, HeaderValue::from_static("KEEP-ALIVE"));
        // Unreadable: names nothing, x-kept included.
        message.append(
            header::CONNECTION,
            HeaderValue::from_bytes(b"x-kept, x-\xffopaque").unwrap(),
        );
        let mut headers = HeaderMap::new();
        for name in ["x-hop", "keep-alive", "x-kept", "x-other", "x-hop"] {
            headers.append(name, HeaderValue::from_static("v"));
        }
        let unchanged = headers.clone();
        remove_connection_nominated(&HeaderMap::new(), &mut headers);
        assert_eq!(headers, unchanged);

        remove_connection_nominated(&message, &mut headers);
        let mut left: Vec<&str> = headers.keys().map(|name| name.as_str()).collect();
        left.sort_unstable();
        assert_eq!(left, ["x-kept", "x-other"]);
        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn test_non_hop_by_hop_headers() {
        assert!(!is_hop_by_hop("content-type"));
        assert!(!is_hop_by_hop("authorization"));
        assert!(!is_hop_by_hop("x-api-key"));
        assert!(!is_hop_by_hop("x-request-id"));
        assert!(!is_hop_by_hop("host"));
        assert!(!is_hop_by_hop("accept"));
        assert!(!is_hop_by_hop("content-length"));
    }

    #[test]
    fn test_trust_headers_are_stripped() {
        // Every gateway-owned trust header must be recognised so a
        // client-supplied copy is dropped before proxying to Python.
        assert!(is_trust_header("x-rust-proxy"));
        assert!(is_trust_header("x-auth-user"));
        assert!(is_trust_header("x-auth-role"));
        assert!(is_trust_header("x-auth-key-id"));
        assert!(is_trust_header("x-auth-method"));
    }

    #[test]
    fn test_client_license_headers_are_stripped() {
        assert!(is_trust_header("x-license-tier"));
        assert!(is_trust_header("x-license-features"));
        assert!(is_trust_header("x-license-node-limit"));
    }

    #[test]
    fn test_ordinary_headers_are_not_trust_headers() {
        assert!(!is_trust_header("x-api-key"));
        assert!(!is_trust_header("authorization"));
        assert!(!is_trust_header("content-type"));
        assert!(!is_trust_header("x-auth"));
    }

    #[test]
    fn test_method_conversion() {
        assert_eq!(to_reqwest_method(&Method::GET), Some(reqwest::Method::GET));
        assert_eq!(
            to_reqwest_method(&Method::POST),
            Some(reqwest::Method::POST)
        );
        assert_eq!(to_reqwest_method(&Method::PUT), Some(reqwest::Method::PUT));
        assert_eq!(
            to_reqwest_method(&Method::DELETE),
            Some(reqwest::Method::DELETE)
        );
        assert_eq!(
            to_reqwest_method(&Method::PATCH),
            Some(reqwest::Method::PATCH)
        );
        assert_eq!(
            to_reqwest_method(&Method::HEAD),
            Some(reqwest::Method::HEAD)
        );
        assert_eq!(
            to_reqwest_method(&Method::OPTIONS),
            Some(reqwest::Method::OPTIONS)
        );
        // Every method the 405's Allow header names is forwarded.
        for name in FORWARDED_METHODS.split(", ") {
            let method = Method::from_bytes(name.as_bytes()).unwrap();
            assert!(to_reqwest_method(&method).is_some(), "{name}");
        }
    }

    /// Methods the bridge serves no route for are never forwarded.
    #[test]
    fn unknown_methods_have_no_backend_method() {
        for method in [
            Method::TRACE,
            Method::CONNECT,
            Method::from_bytes(b"PURGE").unwrap(),
            Method::from_bytes(b"get").unwrap(),
        ] {
            assert_eq!(to_reqwest_method(&method), None, "{method}");
        }
    }

    // Unknown methods end to end:
    // `security_tests::unknown_methods_are_not_forwarded_as_get` and
    // `security_tests::unknown_methods_are_refused_before_the_backend`.

    // `build_proxy_client` is exercised by
    // `security_tests::tls_verification_is_only_skipped_for_a_loopback_backend`
    // (certificate checks), `backend_redirects_are_returned_not_followed`
    // (redirect policy), `backend_failures_do_not_leak_internals`
    // (timeout) and `idle_backend_connections_are_retired_before_keep_alive_closes_them`
    // (pool idle timeout); every security test proxies through it.

    /// TLS verification to the backend is only skipped for a loopback
    /// host; anything else (or anything unparseable) keeps it on.
    #[test]
    fn test_is_loopback_url() {
        assert!(is_loopback_url("http://127.0.0.1:8001"));
        assert!(is_loopback_url("http://127.5.5.5:8001"));
        assert!(is_loopback_url("https://localhost:8443"));
        assert!(is_loopback_url("http://LOCALHOST:8001"));
        assert!(is_loopback_url("http://[::1]:8001"));
        assert!(!is_loopback_url("http://bridge:8001"));
        assert!(!is_loopback_url("https://example.com"));
        assert!(!is_loopback_url("http://10.0.0.1:8001"));
        // Look-alike names are not loopback.
        assert!(!is_loopback_url("http://localhost.evil.com"));
        assert!(!is_loopback_url("http://127.0.0.1.evil.com"));
        // No host, or not a URL at all.
        assert!(!is_loopback_url("unix:/var/run/sock"));
        assert!(!is_loopback_url("not-a-url"));
    }

    // Per-path feature-gate tests previously lived here, coupled to the
    // hardcoded FEATURE_ROUTES constant. They now live alongside the
    // actual table in `sigrift_gateway_legacy::feature_routes` so the
    // core crate carries no enterprise path names.
}

#[cfg(test)]
mod security_tests {
    //! Security behaviour of the catch-all proxy: what it refuses before
    //! forwarding, which headers a client can never forge or smuggle
    //! through, how it frames what it forwards, and how it fails when the
    //! backend does. Every backend here is a loopback listener on an
    //! ephemeral port (or [`REFUSED_URL`], which nothing listens on), and
    //! "never forwarded" is asserted on what the backend actually received.
    //! Requests go through the production proxy client
    //! ([`build_proxy_client`]).
    use super::*;
    use crate::auth::rbac::Role;
    use crate::license::{LicenseResolver, LicenseTier};
    use crate::middleware::auth::AuthInfo;
    use crate::test_support::REFUSED_URL;
    use axum::Router;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tower::ServiceExt as _;

    /// A resolver that grants nothing, so feature-gated paths are denied.
    struct DenyAll;
    impl LicenseResolver for DenyAll {
        fn tier(&self) -> LicenseTier {
            LicenseTier::Professional
        }
        fn has_feature(&self, _feature: &str) -> bool {
            false
        }
        fn node_limit(&self) -> Option<u32> {
            Some(7)
        }
        fn issuer(&self) -> &str {
            "test"
        }
        fn features(&self) -> Vec<String> {
            vec!["alpha".into(), "beta".into()]
        }
    }

    static GATED: &[(&str, &str)] = &[("/api/gated", "gated_feature")];

    /// Hop-by-hop headers (RFC 9110 §7.6.1) a proxy must not forward.
    const HOP_BY_HOP: [&str; 7] = [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "transfer-encoding",
        "upgrade",
    ];

    /// The production proxy timeout default (`UC_PROXY_TIMEOUT`).
    const PROXY_TIMEOUT_SECS: u64 = 30;

    /// A state proxying through the production client for a loopback
    /// backend (every backend here is one); `f` may replace it.
    fn state_with(dir: &tempfile::TempDir, f: impl FnOnce(&mut AppState)) -> Arc<AppState> {
        let mut state = crate::test_support::app_state(dir);
        let s = Arc::get_mut(&mut state).unwrap();
        s.proxy_client = build_proxy_client(PROXY_TIMEOUT_SECS, REFUSED_URL);
        f(s);
        state
    }

    async fn body_string(resp: Response) -> String {
        let b = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        String::from_utf8(b.to_vec()).unwrap()
    }

    fn api_key(key_id: &str, role: Role) -> AuthInfo {
        AuthInfo::ApiKey {
            key_id: key_id.into(),
            role,
        }
    }

    fn session(username: &str, role: Role, token: &str) -> AuthInfo {
        AuthInfo::Session {
            username: username.into(),
            user_id: 1,
            role,
            session_token: token.into(),
            expires_at: String::new(),
            tenant_id: "default".into(),
            scope: String::new(),
        }
    }

    /// One request the fake backend received.
    #[derive(Debug, Clone)]
    struct Seen {
        path_and_query: String,
        method: Method,
        headers: HeaderMap,
        body: Bytes,
    }

    impl Seen {
        /// Every value the backend got for header `name`.
        fn values(&self, name: &str) -> Vec<&str> {
            self.headers
                .get_all(name)
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect()
        }
    }

    /// A fake bridge that records every request it gets. It answers
    /// `/page` with HTML naming its own origin, `/redirect?<url>` with a
    /// 302 to `<url>`, and anything else with 200 "from-backend".
    struct Backend {
        origin: String,
        seen: Arc<Mutex<Vec<Seen>>>,
        server: tokio::task::JoinHandle<()>,
    }

    impl Backend {
        async fn start() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
            let record = Arc::clone(&seen);
            let page_origin = origin.clone();
            let app = Router::new().fallback(move |req: Request<Body>| {
                let record = Arc::clone(&record);
                let page_origin = page_origin.clone();
                async move {
                    let (parts, body) = req.into_parts();
                    let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
                    record.lock().unwrap().push(Seen {
                        path_and_query: parts
                            .uri
                            .path_and_query()
                            .map(|p| p.to_string())
                            .unwrap_or_default(),
                        method: parts.method.clone(),
                        headers: parts.headers.clone(),
                        body,
                    });
                    match parts.uri.path() {
                        "/page" => (
                            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                            format!("<a href=\"{page_origin}/static/app.js\">x</a>"),
                        )
                            .into_response(),
                        "/redirect" => (
                            StatusCode::FOUND,
                            [(
                                header::LOCATION,
                                parts.uri.query().unwrap_or("/").to_string(),
                            )],
                        )
                            .into_response(),
                        _ => "from-backend".into_response(),
                    }
                }
            });
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            Self {
                origin,
                seen,
                server,
            }
        }

        fn requests(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }

        /// The one request the backend received.
        fn only(&self) -> Seen {
            let seen = self.requests();
            assert_eq!(seen.len(), 1, "backend requests: {seen:?}");
            seen.into_iter().next().unwrap()
        }
    }

    impl Drop for Backend {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    /// Once a request head has arrived on `stream`, answer it with
    /// `response` (raw bytes) and close the connection.
    async fn answer_raw<S>(mut stream: S, response: &[u8])
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut head = Vec::new();
        let mut buf = [0u8; 1024];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => head.extend_from_slice(&buf[..n]),
            }
        }
        let _ = stream.write_all(response).await;
        let _ = stream.shutdown().await;
    }

    /// A backend that, once it has read a request head, answers it with
    /// `response` (raw bytes) and closes the connection.
    async fn raw_backend(response: &'static [u8]) -> String {
        raw_backend_with(|_| response.to_vec()).await
    }

    /// [`raw_backend`], with the response built from the backend's own
    /// origin (`http://127.0.0.1:<port>`).
    async fn raw_backend_with(response: impl FnOnce(&str) -> Vec<u8>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let response: &'static [u8] = Vec::leak(response(&origin));
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(answer_raw(stream, response));
            }
        });
        origin
    }

    /// A backend that accepts connections and never answers (it reads
    /// until the client goes away).
    async fn silent_backend() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = tokio::io::copy(&mut stream, &mut tokio::io::sink()).await;
                });
            }
        });
        origin
    }

    /// What a [`tls_backend`] saw: TCP connections accepted, and TLS
    /// handshakes completed on them.
    #[derive(Default)]
    struct TlsSeen {
        accepted: std::sync::atomic::AtomicUsize,
        handshakes: std::sync::atomic::AtomicUsize,
    }

    /// An HTTPS backend on 127.0.0.1 with a self-signed certificate for
    /// `localhost` and `127.0.0.1` (no public CA vouches for it). It
    /// answers every request 200 "tls-backend". Returns its port.
    async fn tls_backend() -> (u16, Arc<TlsSeen>) {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::sync::atomic::Ordering;
        let cert = rcgen::generate_simple_self_signed(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        // An explicit provider: several are in the dependency tree, and
        // this sets no process-wide default.
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert.cert.der().to_vec())], key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen: Arc<TlsSeen> = Arc::default();
        let record = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                record.accepted.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let record = Arc::clone(&record);
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    record.handshakes.fetch_add(1, Ordering::SeqCst);
                    answer_raw(
                        tls,
                        b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\n\
                          tls-backend",
                    )
                    .await;
                });
            }
        });
        (port, seen)
    }

    /// Serve `proxy_fallback` over `state` on a loopback port, as the
    /// gateway does (real hyper HTTP/1 parsing, connection info).
    async fn serve_gateway(state: Arc<AppState>) -> SocketAddr {
        serve_app(Router::new().fallback(proxy_fallback).with_state(state)).await
    }

    /// [`serve_gateway`] behind the layers the gateway puts around every
    /// route: the framing guard and the path canonicalization.
    async fn serve_guarded_gateway(state: Arc<AppState>) -> SocketAddr {
        serve_app(crate::middleware::path::with_canonical_paths(
            Router::new().fallback(proxy_fallback).with_state(state),
        ))
        .await
    }

    async fn serve_app(app: Router) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap()
        });
        addr
    }

    /// Write `request` (raw bytes) to the gateway at `addr` and read the
    /// response until the gateway closes the connection.
    async fn raw_exchange(addr: SocketAddr, request: &[u8]) -> String {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(request).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
            .await
            .expect("the gateway answers and closes the connection")
            .unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    /// The proxy refuses every path a backend could read differently from
    /// the one routed here — and none of them reaches the backend.
    ///
    /// The handler's guards overlap on purpose (defence in depth behind
    /// the router's canonicalization): a literal `.` segment or `\` is
    /// refused both by `is_ambiguous_path` and by `forwarded_unchanged`
    /// (for any backend URL that does not itself end in an encoded `/.`),
    /// and an internal path is checked before and after URL parsing (the
    /// second check matters with a backend URL prefix; see
    /// `internal_api_is_not_reached_through_a_backend_url_prefix`). So
    /// this test checks that some guard refuses each path, not which one;
    /// the guards' own unit tests are in `middleware::path`.
    #[tokio::test]
    async fn refused_paths_never_reach_the_backend() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = backend.origin.clone());
        let cases: &[(&str, StatusCode)] = &[
            // The bridge's gateway-only API, however spelled.
            ("/api/internal/node-keys", StatusCode::NOT_FOUND),
            ("/API/Internal", StatusCode::NOT_FOUND),
            ("/api/%69nternal/hooks", StatusCode::NOT_FOUND),
            ("/x/../api/internal", StatusCode::NOT_FOUND),
            // Control characters, encoded.
            ("/api/detections/batch%0A", StatusCode::BAD_REQUEST),
            ("/api/a%00b", StatusCode::BAD_REQUEST),
            ("/api/a%7f", StatusCode::BAD_REQUEST),
            // Traversal and doubled slashes, plain or encoded.
            ("/api/../etc/passwd", StatusCode::BAD_REQUEST),
            ("/api//double", StatusCode::BAD_REQUEST),
            ("/api/./x", StatusCode::BAD_REQUEST),
            ("/api/%2e%2e/secret", StatusCode::BAD_REQUEST),
            ("/api/%2E%2E/secret", StatusCode::BAD_REQUEST),
            ("/api/a%2f%2fb", StatusCode::BAD_REQUEST),
            ("/api/a%2F%2Fb", StatusCode::BAD_REQUEST),
            // An encoded `.` segment: the URL parser would drop it and
            // send `/api/x`, a different path than the one checked.
            ("/api/%2e/x", StatusCode::BAD_REQUEST),
            ("/api/%2E/x", StatusCode::BAD_REQUEST),
            // An encoded `..` joined to an encoded separator in one
            // segment: not a dot segment to the URL parser, so it would
            // be sent unchanged, and the bridge decodes it to `../`
            // (`..\` on a host that reads `\` as a separator).
            ("/api/%2e%2e%2fsecret", StatusCode::BAD_REQUEST),
            ("/api/%2E%2E%2F%2E%2E%2Fetc/passwd", StatusCode::BAD_REQUEST),
            ("/api/%2e%2e%5csecret", StatusCode::BAD_REQUEST),
            ("/api/x/.%2e%5c.%2e%5cetc", StatusCode::BAD_REQUEST),
        ];
        for (path, expected) in cases {
            let req = Request::get(*path).body(Body::empty()).unwrap();
            let resp = proxy_fallback(State(state.clone()), req).await;
            assert_eq!(resp.status(), *expected, "{path}");
        }
        assert!(backend.requests().is_empty(), "{:?}", backend.requests());
    }

    /// `UC_PYTHON_URL` may carry a path prefix (the sent path only has to
    /// end with the routed one). Then a path that is not the internal API
    /// here — nor to the router's canonicalization — becomes it on the
    /// backend; the gateway must check the URL it would send as well.
    #[tokio::test]
    async fn internal_api_is_not_reached_through_a_backend_url_prefix() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| {
            s.config.python_url = format!("{}/api", backend.origin);
        });
        for path in [
            "/internal/bind-node-key",
            "/Internal/ingest-hook",
            "/%69nternal",
        ] {
            assert!(!crate::middleware::path::is_internal_path(path), "{path}");
            let req = Request::post(path).body(Body::empty()).unwrap();
            let resp = proxy_fallback(State(state.clone()), req).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
        }
        assert!(backend.requests().is_empty(), "{:?}", backend.requests());

        // Anything else is forwarded below the prefix.
        let req = Request::get("/nodes").body(Body::empty()).unwrap();
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(backend.only().path_and_query, "/api/nodes");
    }

    /// A gated path the licence lacks is refused with 403 and a detail
    /// naming the feature, before reaching the backend; an ungated path
    /// is forwarded.
    #[tokio::test]
    async fn license_gate_denies_unlicensed_feature_before_the_backend() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| {
            s.config.python_url = backend.origin.clone();
            s.license_resolver = Arc::new(DenyAll);
            s.feature_routes = crate::FeatureRoutes(GATED);
        });
        let req = Request::get("/api/gated/report")
            .body(Body::empty())
            .unwrap();
        let resp = proxy_fallback(State(state.clone()), req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        let detail = body["detail"].as_str().unwrap();
        assert!(detail.contains("'gated_feature'"), "{detail}");
        assert!(detail.contains("/api/gated/report"), "{detail}");
        assert!(backend.requests().is_empty());

        let req = Request::get("/api/open").body(Body::empty()).unwrap();
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(backend.only().path_and_query, "/api/open");
    }

    /// A licensed feature passes the gate and is forwarded.
    #[tokio::test]
    async fn license_gate_allows_licensed_feature() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| {
            s.config.python_url = backend.origin.clone();
            s.feature_routes = crate::FeatureRoutes(GATED);
        });
        let req = Request::get("/api/gated").body(Body::empty()).unwrap();
        let resp = proxy_fallback(State(state), req).await;
        // The null resolver grants everything.
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "from-backend");
        assert_eq!(backend.only().path_and_query, "/api/gated");
    }

    /// In the production composition the path is canonicalized before the
    /// proxy runs (K9), so percent-encoding a character of a gated prefix —
    /// which the bridge would decode — does not get past the gate.
    #[tokio::test]
    async fn license_gate_holds_for_percent_encoded_gated_paths() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| {
            s.config.python_url = backend.origin.clone();
            s.license_resolver = Arc::new(DenyAll);
            s.feature_routes = crate::FeatureRoutes(GATED);
        });
        let app = crate::middleware::path::with_canonical_paths(
            Router::new().fallback(proxy_fallback).with_state(state),
        );
        for path in ["/api/%67ated/report", "/api/gat%65d", "/%61pi/gated/x"] {
            let req = Request::get(path).body(Body::empty()).unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path}");
        }
        assert!(backend.requests().is_empty(), "{:?}", backend.requests());
    }

    /// A WebSocket upgrade (in any letter case) is answered by the gateway
    /// and never forwarded as plain HTTP.
    #[tokio::test]
    async fn websocket_upgrade_is_never_proxied() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = backend.origin.clone());
        for upgrade in ["websocket", "WebSocket"] {
            let req = Request::get("/api/stream")
                .header("connection", "upgrade")
                .header("upgrade", upgrade)
                .body(Body::empty())
                .unwrap();
            let resp = proxy_fallback(State(state.clone()), req).await;
            assert_eq!(resp.status(), StatusCode::BAD_GATEWAY, "{upgrade}");
            assert!(body_string(resp)
                .await
                .contains("WebSocket proxy not supported"));
        }
        assert!(backend.requests().is_empty());
    }

    /// The body limit holds at its boundary and for a streamed body that
    /// declares no length; an oversized body never reaches the backend.
    #[tokio::test]
    async fn body_size_limit_is_enforced_before_forwarding() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| {
            s.config.python_url = backend.origin.clone();
            s.config.max_body_size = 8;
        });

        // Exactly at the limit: forwarded whole.
        let req = Request::post("/api/upload")
            .body(Body::from(vec![b'x'; 8]))
            .unwrap();
        let resp = proxy_fallback(State(state.clone()), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(backend.only().body, vec![b'x'; 8]);

        // One byte over.
        let req = Request::post("/api/upload")
            .body(Body::from(vec![b'x'; 9]))
            .unwrap();
        let resp = proxy_fallback(State(state.clone()), req).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // Streamed, with no length declared up front.
        let chunks = futures_util::stream::iter([
            Ok::<_, std::io::Error>(Bytes::from_static(b"xxxxx")),
            Ok(Bytes::from_static(b"xxxxx")),
        ]);
        let req = Request::post("/api/upload")
            .body(Body::from_stream(chunks))
            .unwrap();
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // Only the first request was forwarded.
        assert_eq!(backend.requests().len(), 1);
    }

    /// Client-forged trust headers — repeated, or beside the real ones —
    /// never reach the backend: the gateway's own values replace them, one
    /// value each. (Header names are lowercased by `http::HeaderName`
    /// before the proxy sees them, so letter case is not a way around
    /// this.)
    #[tokio::test]
    async fn forged_trust_headers_are_replaced_by_gateway_values() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| {
            s.config.python_url = backend.origin.clone();
            s.config.proxy_secret = "gateway-secret".into();
            s.license_resolver = Arc::new(DenyAll);
        });
        let mut req = Request::post("/api/echo?x=1")
            .header("host", "gw.example")
            .header("x-rust-proxy", "forged")
            .header("x-rust-proxy", "forged-again")
            .header("x-auth-user", "admin")
            .header("x-auth-role", "keymaster")
            .header("x-auth-role", "admin")
            .header("x-auth-method", "client-cert")
            .header("x-license-tier", "enterprise")
            .header("x-license-node-limit", "99999")
            .header("x-forwarded-for", "1.2.3.4")
            .header("x-forwarded-host", "attacker.example")
            .header("x-forwarded-proto", "ftp")
            .header("x-request-id", "req-123")
            .header("x-custom", "kept")
            .body(Body::from("payload"))
            .unwrap();
        req.extensions_mut().insert(ClientIp("203.0.113.9".into()));
        req.extensions_mut().insert(api_key("key-1", Role::Viewer));
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let seen = backend.only();
        assert_eq!(seen.method, Method::POST);
        assert_eq!(seen.path_and_query, "/api/echo?x=1");
        assert_eq!(seen.body, "payload");
        assert_eq!(seen.values("x-rust-proxy"), ["gateway-secret"]);
        assert!(seen.values("x-auth-user").is_empty(), "forged user");
        assert_eq!(seen.values("x-auth-key-id"), ["key-1"]);
        assert_eq!(seen.values("x-auth-role"), ["viewer"]);
        assert!(seen.values("x-auth-method").is_empty(), "forged method");
        assert_eq!(seen.values("x-license-tier"), ["professional"]);
        assert_eq!(seen.values("x-license-features"), ["alpha,beta"]);
        assert_eq!(seen.values("x-license-node-limit"), ["7"]);
        assert_eq!(seen.values("x-forwarded-for"), ["203.0.113.9"]);
        assert_eq!(seen.values("host"), ["gw.example"]);
        assert_eq!(seen.values("x-forwarded-host"), ["gw.example"]);
        // The gateway's own scheme, not the client's: this listener is
        // plaintext (see `forwarded_proto_is_https_on_a_tls_listener` for
        // the TLS value).
        assert_eq!(seen.values("x-forwarded-proto"), ["http"]);
        assert_eq!(seen.values("x-request-id"), ["req-123"]);
        assert_eq!(seen.values("x-custom"), ["kept"]);
    }

    /// Unauthenticated: no identity headers at all, and a client-supplied
    /// node limit cannot appear even though the resolver sets none.
    #[tokio::test]
    async fn unauthenticated_request_carries_no_identity_or_forged_limit() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = backend.origin.clone());
        let mut req = Request::get("/api/echo")
            .header("x-license-node-limit", "99999")
            .header("x-auth-key-id", "forged")
            .header("x-auth-role", "admin")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(AuthInfo::Unauthenticated);
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let seen = backend.only();
        for name in [
            "x-auth-user",
            "x-auth-key-id",
            "x-auth-role",
            "x-auth-method",
        ] {
            assert!(seen.values(name).is_empty(), "{name}");
        }
        assert!(seen.values("authorization").is_empty());
        assert!(seen.values("x-license-node-limit").is_empty());
        assert_eq!(seen.values("x-license-tier"), ["community"]);
        // A request id is generated when the client sent none.
        let ids = seen.values("x-request-id");
        assert_eq!(ids.len(), 1);
        assert!(uuid::Uuid::parse_str(ids[0]).is_ok(), "{ids:?}");
    }

    /// A verified session is forwarded as its own bearer token and
    /// identity: the client's Authorization header and identity claims
    /// never replace them.
    #[tokio::test]
    async fn session_identity_replaces_client_credentials() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = backend.origin.clone());
        let mut req = Request::get("/api/echo")
            .header("authorization", "Bearer attacker-token")
            .header("x-auth-user", "root")
            .header("x-auth-key-id", "admin-key")
            .header(header::COOKIE, "session_token=attacker-token")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(session("alice", Role::Analyst, "verified-token"));
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let seen = backend.only();
        assert_eq!(seen.values("authorization"), ["Bearer verified-token"]);
        assert_eq!(seen.values("x-auth-user"), ["alice"]);
        assert_eq!(seen.values("x-auth-role"), ["analyst"]);
        assert!(seen.values("x-auth-key-id").is_empty());
        assert!(seen.values("x-auth-method").is_empty());
        assert!(
            seen.values("cookie").is_empty(),
            "unverified session cookie"
        );
    }

    /// Regression: the client's `Authorization` and `X-Session-Token` were
    /// forwarded whenever the gateway had not verified a session, and the
    /// bridge authenticates a session token it gets there itself. A token
    /// the gateway refused (bound to another IP, say) or did not recognise
    /// (`bearer <token>`) therefore reached the bridge, which accepted it
    /// without the gateway's IP binding check. Now the bridge gets
    /// a session credential only when it is the session the gateway
    /// verified, as `Authorization: Bearer`.
    #[tokio::test]
    async fn unverified_session_credentials_never_reach_the_bridge() {
        let cases = [
            ("anonymous", AuthInfo::Unauthenticated, None),
            ("api key", api_key("key-1", Role::Viewer), None),
            (
                "session",
                session("alice", Role::Analyst, "verified-token"),
                Some("Bearer verified-token"),
            ),
        ];
        for (what, auth, authorization) in cases {
            let backend = Backend::start().await;
            let dir = tempfile::tempdir().unwrap();
            let state = state_with(&dir, |s| s.config.python_url = backend.origin.clone());
            let mut req = Request::get("/api/echo")
                .header("authorization", "bearer stolen-token")
                .header("authorization", "Bearer second-copy")
                .header("x-session-token", "stolen-token")
                .header("x-api-key", "sk-client")
                .body(Body::empty())
                .unwrap();
            req.extensions_mut().insert(auth);
            let resp = proxy_fallback(State(state), req).await;
            assert_eq!(resp.status(), StatusCode::OK, "{what}");

            let seen = backend.only();
            assert_eq!(
                seen.values("authorization"),
                authorization.into_iter().collect::<Vec<_>>(),
                "{what}"
            );
            assert!(seen.values("x-session-token").is_empty(), "{what}");
            // An API key is not a session credential: the bridge checks it
            // against the same keys.json.
            assert_eq!(seen.values("x-api-key"), ["sk-client"], "{what}");
        }
    }

    /// Hop-by-hop request headers — among them credentials meant for a
    /// proxy hop — are not forwarded, and the forwarded body is framed by
    /// the gateway from what it read, not by the client's
    /// Transfer-Encoding.
    #[tokio::test]
    async fn hop_by_hop_request_headers_are_not_forwarded() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = backend.origin.clone());
        let req = Request::post("/api/echo")
            .header("connection", "keep-alive")
            .header("keep-alive", "timeout=5")
            .header("proxy-authorization", "Basic dXNlcjpwYXNz")
            .header("proxy-authenticate", "Basic")
            .header("te", "trailers")
            .header("transfer-encoding", "chunked")
            .header("upgrade", "h2c")
            .body(Body::from("payload"))
            .unwrap();
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let seen = backend.only();
        for name in HOP_BY_HOP {
            assert!(
                seen.values(name).is_empty(),
                "{name}: {:?}",
                seen.values(name)
            );
        }
        assert_eq!(seen.body, "payload");
        assert_eq!(seen.values("content-length"), ["7"]);
    }

    /// RFC 9110 §7.6.1: a header the client names in `Connection` is
    /// hop-by-hop for that message, and a proxy must not forward it. The
    /// gateway's own headers, which it adds after the client's are
    /// filtered, must still reach the backend even when the client names
    /// them too.
    #[tokio::test]
    async fn connection_nominated_headers_are_not_forwarded() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| {
            s.config.python_url = backend.origin.clone();
            s.config.proxy_secret = "gateway-secret".into();
        });
        let mut req = Request::get("/api/echo")
            .header(
                "connection",
                "close, x-hop, x-rust-proxy, x-forwarded-for, x-auth-key-id, x-auth-role",
            )
            .header("x-hop", "should-not-pass")
            .header("x-kept", "yes")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ClientIp("203.0.113.9".into()));
        req.extensions_mut().insert(api_key("key-1", Role::Admin));
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let seen = backend.only();
        assert!(
            seen.values("x-hop").is_empty(),
            "{:?}",
            seen.values("x-hop")
        );
        assert_eq!(seen.values("x-kept"), ["yes"]);
        assert_eq!(seen.values("x-rust-proxy"), ["gateway-secret"]);
        assert_eq!(seen.values("x-forwarded-for"), ["203.0.113.9"]);
        assert_eq!(seen.values("x-auth-key-id"), ["key-1"]);
        assert_eq!(seen.values("x-auth-role"), ["admin"]);
    }

    /// The other headers the gateway owns survive a nomination too: the
    /// verified session's bearer, the Host it forwards, the licence
    /// headers and a request id (generated, as the client's own is
    /// dropped). A nominated Cookie drops the joined cookie, so no Cookie
    /// field at all reaches the backend — never more than one.
    #[tokio::test]
    async fn connection_nominations_never_suppress_gateway_headers() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = backend.origin.clone());
        let mut req = Request::get("/api/echo")
            .header("host", "gw.example")
            .header(
                "connection",
                "Authorization, HOST,x-request-id , cookie, x-license-tier",
            )
            .header("connection", "x-second-field")
            .header("authorization", "Bearer client-token")
            .header("x-request-id", "client-id")
            .header(header::COOKIE, "csrf_token=c")
            .header(header::COOKIE, "theme=dark")
            .header("x-second-field", "dropped")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(session("alice", Role::Analyst, "verified-token"));
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let seen = backend.only();
        assert_eq!(seen.values("authorization"), ["Bearer verified-token"]);
        assert_eq!(seen.values("host"), ["gw.example"]);
        assert_eq!(seen.values("x-license-tier"), ["community"]);
        let ids = seen.values("x-request-id");
        assert_eq!(ids.len(), 1);
        assert!(uuid::Uuid::parse_str(ids[0]).is_ok(), "{ids:?}");
        assert!(
            seen.values("cookie").is_empty(),
            "{:?}",
            seen.values("cookie")
        );
        assert!(seen.values("x-second-field").is_empty());
        assert!(seen.values("connection").is_empty());
    }

    /// A response header the backend names in its Connection field stays
    /// on the backend hop as well.
    #[tokio::test]
    async fn backend_connection_nominated_headers_are_not_returned() {
        let origin = raw_backend(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: X-Secret, close\r\n\
              X-Secret: internal\r\nX-Kept: yes\r\n\r\nok",
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = origin);
        let req = Request::get("/api/x").body(Body::empty()).unwrap();
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get("x-secret").is_none());
        assert!(resp.headers().get("connection").is_none());
        assert_eq!(resp.headers()["x-kept"], "yes");
        assert_eq!(body_string(resp).await, "ok");
    }

    /// Without a resolved client or peer address the gateway sends no
    /// X-Forwarded-For — and none of the client's values either.
    #[tokio::test]
    async fn client_forwarded_for_is_dropped_without_a_known_client() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = backend.origin.clone());
        let mut req = Request::get("/api/echo")
            .header("x-forwarded-for", "1.2.3.4")
            .header("x-forwarded-for", "5.6.7.8")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ClientIp(UNKNOWN_CLIENT.into()));
        assert!(forwarded_for(req.extensions()).is_none());
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let seen = backend.only();
        assert!(
            seen.values("x-forwarded-for").is_empty(),
            "{:?}",
            seen.values("x-forwarded-for")
        );
    }

    /// With only the peer known, X-Forwarded-For is the peer's canonical
    /// address: a client-supplied chain is replaced, never appended to.
    #[tokio::test]
    async fn forwarded_for_replaces_the_client_chain_with_the_peer() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = backend.origin.clone());
        let mut req = Request::get("/api/echo")
            .header("x-forwarded-for", "1.2.3.4, 10.0.0.1")
            .header("x-forwarded-for", "5.6.7.8")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(
            "[::ffff:192.0.2.10]:4000".parse::<SocketAddr>().unwrap(),
        ));
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(backend.only().values("x-forwarded-for"), ["192.0.2.10"]);
    }

    /// What the backend got as X-Forwarded-Proto for a request with a
    /// Host header, from `peer` (as the auth middleware resolves it)
    /// carrying `client_proto` as its own X-Forwarded-Proto.
    async fn forwarded_proto(
        tls: bool,
        trusted_proxies: &str,
        peer: &str,
        client_proto: Option<&str>,
    ) -> Vec<String> {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let (trusted, invalid) =
            crate::middleware::client_ip::TrustedProxies::parse(trusted_proxies);
        assert!(invalid.is_empty(), "{invalid:?}");
        let state = state_with(&dir, |s| {
            s.config.python_url = backend.origin.clone();
            if tls {
                // `tls_enabled()` only asks whether both are configured.
                s.config.tls_cert = Some("gateway.crt".into());
                s.config.tls_key = Some("gateway.key".into());
            }
        });
        assert_eq!(state.config.tls_enabled(), tls);
        state.auth_config.write().await.trusted_proxies = trusted.clone();
        let mut req = Request::get("/api/echo").header("host", "gw.example");
        if let Some(proto) = client_proto {
            req = req.header("x-forwarded-proto", proto);
        }
        let mut req = req.body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        let client = crate::middleware::client_ip::extract_client_ip(&req, &trusted);
        req.extensions_mut().insert(ClientIp(client));
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let seen = backend.only();
        seen.values("x-forwarded-proto")
            .into_iter()
            .map(str::to_string)
            .collect()
    }

    /// A gateway serving TLS itself tells the bridge the client used
    /// `https`, whatever the client claims.
    #[tokio::test]
    async fn forwarded_proto_is_https_on_a_tls_listener() {
        let peer = "198.51.100.7:4000";
        assert_eq!(forwarded_proto(true, "", peer, None).await, ["https"]);
        assert_eq!(
            forwarded_proto(true, "", peer, Some("http")).await,
            ["https"]
        );
    }

    /// Behind a TLS-terminating reverse proxy listed in
    /// `UC_TRUSTED_PROXIES` (the deployment PRODUCTION_READINESS.md
    /// recommends), the gateway listens in plaintext, and that proxy
    /// vouches for the client's `https`: the bridge must still get it.
    #[tokio::test]
    async fn a_trusted_front_proxy_vouches_for_https() {
        assert_eq!(
            forwarded_proto(false, "10.0.0.2", "10.0.0.2:4000", Some("https")).await,
            ["https"]
        );
    }

    /// A trusted load balancer that takes plain http from its clients and
    /// re-encrypts to the gateway's TLS listener says `http`: the bridge
    /// must not believe the client's hop is encrypted (it hands a rotated
    /// raw API key only to `https`).
    #[tokio::test]
    async fn a_trusted_proxy_before_the_tls_listener_can_say_http() {
        assert_eq!(
            forwarded_proto(true, "10.0.0.2", "10.0.0.2:4000", Some("http")).await,
            ["http"]
        );
        assert_eq!(
            forwarded_proto(true, "10.0.0.2", "10.0.0.2:4000", None).await,
            ["https"]
        );
    }

    /// X-Forwarded-Proto tells the bridge which scheme the client used;
    /// its key-rotation endpoint hands out a new raw API key only when it
    /// says `https`. A gateway listening without TLS must not claim it,
    /// nor pass on the claim of a client that is not a trusted proxy.
    #[tokio::test]
    async fn forwarded_proto_is_http_on_a_plaintext_listener() {
        let peer = "198.51.100.7:4000";
        assert_eq!(forwarded_proto(false, "", peer, None).await, ["http"]);
        assert_eq!(
            forwarded_proto(false, "", peer, Some("https")).await,
            ["http"]
        );
        // A trusted proxy elsewhere does not make this peer one.
        assert_eq!(
            forwarded_proto(false, "10.0.0.2", peer, Some("https")).await,
            ["http"]
        );
    }

    /// An HTTP/2 request carries its authority in the URI and no Host
    /// header. The client's own X-Forwarded-Host / X-Forwarded-Proto —
    /// which the bridge trusts for its URLs and its TLS check — must not
    /// reach the backend then either.
    #[tokio::test]
    async fn client_forwarded_host_and_proto_are_dropped_without_a_host_header() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = backend.origin.clone());
        let req = Request::get("https://gw.example/api/echo")
            .version(axum::http::Version::HTTP_2)
            .header("x-forwarded-host", "attacker.example")
            .header("x-forwarded-proto", "ftp")
            .body(Body::empty())
            .unwrap();
        assert!(req.headers().get(header::HOST).is_none());
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let seen = backend.only();
        assert!(
            !seen
                .values("x-forwarded-host")
                .contains(&"attacker.example"),
            "{:?}",
            seen.values("x-forwarded-host")
        );
        assert!(
            !seen.values("x-forwarded-proto").contains(&"ftp"),
            "{:?}",
            seen.values("x-forwarded-proto")
        );
    }

    /// Every client copy of a forwarding header is dropped on an HTTP/2
    /// request (and its X-Forwarded-For also when no client address is
    /// known); the bridge gets the gateway's values: the `:authority` as
    /// Host and X-Forwarded-Host — so its URLs and redirects name the
    /// gateway, not the backend — and the listener's scheme.
    #[tokio::test]
    async fn http2_requests_forward_their_authority_and_no_client_forwarding_headers() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = backend.origin.clone());
        let req = Request::get("https://gw.example:8444/api/echo?x=1")
            .version(axum::http::Version::HTTP_2)
            .header("x-forwarded-host", "attacker.example")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-for", "1.2.3.4")
            .header("x-forwarded-port", "443")
            .header("x-forwarded-prefix", "/evil")
            .header("forwarded", "for=1.2.3.4;host=attacker.example;proto=https")
            .header("x-real-ip", "1.2.3.4")
            .header("x-custom", "kept")
            .body(Body::empty())
            .unwrap();
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let seen = backend.only();
        assert_eq!(seen.path_and_query, "/api/echo?x=1");
        assert_eq!(seen.values("host"), ["gw.example:8444"]);
        assert_eq!(seen.values("x-forwarded-host"), ["gw.example:8444"]);
        assert_eq!(seen.values("x-forwarded-proto"), ["http"]);
        for name in [
            "x-forwarded-for",
            "x-forwarded-port",
            "x-forwarded-prefix",
            "forwarded",
            "x-real-ip",
        ] {
            assert!(
                seen.values(name).is_empty(),
                "{name}: {:?}",
                seen.values(name)
            );
        }
        assert_eq!(seen.values("x-custom"), ["kept"]);
    }

    /// The authority of the request target wins over a Host header (RFC
    /// 9112 §3.2.2, for an absolute-form HTTP/1.1 target; for HTTP/2 the
    /// two must agree), and userinfo in it is never forwarded.
    #[tokio::test]
    async fn the_request_target_authority_wins_over_host() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = backend.origin.clone());
        for (target, expected) in [
            ("http://gw.example/api/echo", "gw.example"),
            ("http://user:pw@gw.example:8080/api/echo", "gw.example:8080"),
            ("http://[2001:db8::1]:8444/api/echo", "[2001:db8::1]:8444"),
        ] {
            let req = Request::get(target)
                .header("host", "other.example")
                .body(Body::empty())
                .unwrap();
            let resp = proxy_fallback(State(state.clone()), req).await;
            assert_eq!(resp.status(), StatusCode::OK, "{target}");
            let seen = backend.requests().pop().unwrap();
            assert_eq!(seen.values("host"), [expected], "{target}");
            assert_eq!(seen.values("x-forwarded-host"), [expected], "{target}");
        }
    }

    /// The scheme rule itself: only the direct peer — never the client a
    /// trusted proxy names in X-Forwarded-For — can say which scheme its
    /// client used, with its rightmost X-Forwarded-Proto entry, in any
    /// letter case, on either listener. Anything else leaves the
    /// listener's scheme.
    #[test]
    fn forwarded_proto_trusts_only_the_direct_peer() {
        use axum::http::Extensions;
        let (trusted, _) = TrustedProxies::parse("10.0.0.0/8");
        let proto = |tls: bool, peer: Option<&str>, client: Option<&str>, xfp: &[&str]| {
            let mut ext = Extensions::new();
            if let Some(peer) = peer {
                ext.insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
            }
            if let Some(client) = client {
                ext.insert(ClientIp(client.into()));
            }
            let mut headers = HeaderMap::new();
            for value in xfp {
                headers.append("x-forwarded-proto", HeaderValue::from_str(value).unwrap());
            }
            super::forwarded_proto(tls, &ext, &headers, &trusted)
        };
        let proxy = Some("10.0.0.2:4000");
        let client = Some("198.51.100.7:4000");

        // TLS listener, an untrusted or unknown peer: whatever it claims.
        assert_eq!(proto(true, client, None, &["http"]), "https");
        assert_eq!(proto(true, None, None, &["http"]), "https");
        assert_eq!(proto(true, None, None, &[]), "https");
        assert_eq!(proto(true, client, Some("10.0.0.2"), &["http"]), "https");

        // TLS listener, a trusted peer: a load balancer that took plain
        // http from its client and re-encrypts says so.
        assert_eq!(proto(true, proxy, None, &["http"]), "http");
        assert_eq!(proto(true, proxy, None, &["HTTP"]), "http");
        assert_eq!(proto(true, proxy, None, &["https, http"]), "http");
        assert_eq!(proto(true, proxy, None, &["https"]), "https");
        assert_eq!(proto(true, proxy, None, &["http, https"]), "https");
        assert_eq!(proto(true, proxy, None, &["ftp"]), "https");
        assert_eq!(proto(true, proxy, None, &[]), "https");

        // Plaintext, a trusted peer.
        assert_eq!(proto(false, proxy, None, &["https"]), "https");
        assert_eq!(proto(false, proxy, None, &["HTTPS"]), "https");
        assert_eq!(proto(false, proxy, None, &["http"]), "http");
        assert_eq!(proto(false, proxy, None, &["http, https"]), "https");
        assert_eq!(proto(false, proxy, None, &["https, http"]), "http");
        assert_eq!(proto(false, proxy, None, &["https", "http"]), "http");
        assert_eq!(proto(false, proxy, None, &["ftp"]), "http");
        assert_eq!(proto(false, proxy, None, &[]), "http");
        // An IPv4-mapped peer is the IPv4 proxy.
        assert_eq!(
            proto(false, Some("[::ffff:10.0.0.2]:4000"), None, &["https"]),
            "https"
        );

        // Plaintext, an untrusted or unknown peer.
        assert_eq!(proto(false, client, None, &["https"]), "http");
        assert_eq!(proto(false, None, None, &["https"]), "http");
        // A resolved client address that is a trusted one does not
        // make an untrusted peer a proxy.
        assert_eq!(proto(false, client, Some("10.0.0.2"), &["https"]), "http");
    }

    /// Request smuggling: for `Content-Length` followed by
    /// `Transfer-Encoding: chunked`, hyper decodes the body as chunked but
    /// keeps the Content-Length header, which then no longer describes the
    /// body (forwarded, it truncated the body the backend got). A front
    /// proxy that framed the request by its Content-Length would also
    /// have sent the rest as part of it. Such a request is refused before
    /// the backend, and the connection is closed (RFC 9112 §6.1), so a
    /// request pipelined behind it is never answered.
    #[tokio::test]
    async fn content_length_with_transfer_encoding_is_refused_and_the_connection_closed() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = backend.origin.clone());
        let gateway = serve_gateway(state).await;
        // No `Connection: close` from the client: the gateway closes.
        let response = raw_exchange(
            gateway,
            b"POST /api/echo HTTP/1.1\r\nHost: gw.example\r\nContent-Length: 3\r\n\
              Transfer-Encoding: chunked\r\n\r\n7\r\npayload\r\n0\r\n\r\n\
              GET /api/smuggled HTTP/1.1\r\nHost: gw.example\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        assert!(
            response
                .to_ascii_lowercase()
                .contains("\r\nconnection: close\r\n"),
            "{response}"
        );
        assert_eq!(response.matches("HTTP/1.1 ").count(), 1, "{response}");
        assert!(backend.requests().is_empty(), "{:?}", backend.requests());
    }

    /// The client's Content-Length is never forwarded: the backend gets
    /// the body the gateway read, framed by its real length — not cut
    /// short by a smaller value, nor left waiting (until the proxy
    /// timeout) for the bytes a larger one promises. An empty body of a
    /// method that defines content is sent as `Content-Length: 0`.
    #[tokio::test]
    async fn client_content_length_is_never_forwarded() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| {
            s.config.python_url = backend.origin.clone();
            s.proxy_client = build_proxy_client(5, &backend.origin);
        });
        for declared in ["3", "20", "7"] {
            let req = Request::post("/api/echo")
                .header(header::CONTENT_LENGTH, declared)
                .body(Body::from("payload"))
                .unwrap();
            let resp = proxy_fallback(State(state.clone()), req).await;
            assert_eq!(resp.status(), StatusCode::OK, "{declared}");
        }
        for seen in backend.requests() {
            assert_eq!(seen.body, "payload");
            assert_eq!(seen.values("content-length"), ["7"]);
        }

        let req = Request::post("/api/empty")
            .header(header::CONTENT_LENGTH, "5")
            .body(Body::empty())
            .unwrap();
        let resp = proxy_fallback(State(state.clone()), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let req = Request::get("/api/get")
            .header(header::CONTENT_LENGTH, "5")
            .body(Body::empty())
            .unwrap();
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let seen = backend.requests();
        assert_eq!(seen.len(), 5, "{seen:?}");
        assert_eq!(seen[3].values("content-length"), ["0"]);
        assert!(seen[3].body.is_empty());
        assert!(seen[4].values("content-length").is_empty(), "{seen:?}");
    }

    /// hyper itself drops a Content-Length that follows
    /// `Transfer-Encoding: chunked` (the handler never sees it, so cannot
    /// refuse it) and would keep the connection open: the body is the
    /// chunked one, forwarded whole with its own length, and the framing
    /// guard closes the connection after the response (RFC 9112 §6.1), so
    /// a front proxy that framed the request by its Content-Length cannot
    /// have the rest read as another request.
    #[tokio::test]
    async fn transfer_encoding_before_content_length_is_framed_by_the_chunks() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = backend.origin.clone());
        let gateway = serve_guarded_gateway(state).await;
        // No `Connection: close` from the client: the gateway closes.
        let response = raw_exchange(
            gateway,
            b"POST /api/echo HTTP/1.1\r\nHost: gw.example\r\nTransfer-Encoding: chunked\r\n\
              Content-Length: 3\r\n\r\n7\r\npayload\r\n0\r\n\r\n\
              GET /api/smuggled HTTP/1.1\r\nHost: gw.example\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            response
                .to_ascii_lowercase()
                .contains("\r\nconnection: close\r\n"),
            "{response}"
        );
        assert_eq!(response.matches("HTTP/1.1 ").count(), 1, "{response}");
        let seen = backend.only();
        assert_eq!(seen.body, "payload");
        assert_eq!(seen.values("content-length"), ["7"]);
    }

    /// Conflicting Content-Length values are refused by hyper before the
    /// gateway sees the request.
    #[tokio::test]
    async fn conflicting_content_lengths_never_reach_the_backend() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = backend.origin.clone());
        let gateway = serve_gateway(state).await;
        let response = raw_exchange(
            gateway,
            b"POST /api/echo HTTP/1.1\r\nHost: gw.example\r\nContent-Length: 3\r\n\
              Content-Length: 7\r\n\r\npayload",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        assert!(backend.requests().is_empty(), "{:?}", backend.requests());
    }

    /// Hop-by-hop response headers — the backend's own Transfer-Encoding
    /// framing among them — are not passed back to the client; other
    /// headers and the decoded body are.
    #[tokio::test]
    async fn hop_by_hop_response_headers_are_not_returned() {
        let origin = raw_backend(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\
              Connection: keep-alive\r\nKeep-Alive: timeout=5\r\nProxy-Authenticate: Basic\r\n\
              Upgrade: h2c\r\nX-Kept: yes\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = origin);
        let req = Request::get("/api/x").body(Body::empty()).unwrap();
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        for name in HOP_BY_HOP {
            assert!(resp.headers().get(name).is_none(), "{name}");
        }
        assert_eq!(resp.headers()["x-kept"], "yes");
        assert_eq!(body_string(resp).await, "hello");
    }

    /// A header the backend sends more than once — Set-Cookie above all,
    /// which cannot be joined into one line — reaches the client with
    /// every value, in order. Losing one drops a cookie the bridge set
    /// (a CSRF token, a cleared session) without any error.
    #[tokio::test]
    async fn repeated_backend_response_headers_are_all_returned() {
        let origin = raw_backend(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: a=1\r\n\
              Set-Cookie: b=2\r\nVary: Origin\r\nVary: Cookie\r\nConnection: close\r\n\r\nok",
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = origin);
        let req = Request::get("/api/x").body(Body::empty()).unwrap();
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let values = |name: &str| -> Vec<String> {
            resp.headers()
                .get_all(name)
                .iter()
                .map(|v| v.to_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(values("set-cookie"), ["a=1", "b=2"]);
        assert_eq!(values("vary"), ["Origin", "Cookie"]);
    }

    /// Set-Cookie values hold commas of their own (`Expires`), so they are
    /// never joined: three cookies, attributes and all, arrive as three
    /// fields.
    #[tokio::test]
    async fn set_cookie_fields_are_never_merged() {
        let origin = raw_backend(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\
              Set-Cookie: csrf_token=c; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT\r\n\
              Set-Cookie: layout=; Max-Age=0; HttpOnly\r\n\
              Set-Cookie: theme=dark\r\nConnection: close\r\n\r\nok",
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = origin);
        let req = Request::get("/api/x").body(Body::empty()).unwrap();
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let cookies: Vec<&str> = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            cookies,
            [
                "csrf_token=c; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT",
                "layout=; Max-Age=0; HttpOnly",
                "theme=dark",
            ]
        );
    }

    /// The gateway is the only issuer of session cookies. A backend
    /// response that sets (or expires) `session_token` or the legacy
    /// `bridge_token` is relayed without that field, whatever the spaces
    /// around the name, as a browser and `cookie_pair` read it, so a
    /// proxied bridge route can never plant or end a gateway session.
    /// Other cookies, `csrf_token` among them, and a name that only looks
    /// alike pass unchanged and in order.
    #[tokio::test]
    async fn backend_session_cookies_are_not_relayed() {
        let origin = raw_backend(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\
              Set-Cookie: session_token=planted; Path=/; HttpOnly\r\n\
              Set-Cookie: csrf_token=c; Path=/\r\n\
              Set-Cookie: bridge_token=planted\r\n\
              Set-Cookie:  session_token =spaced; Path=/\r\n\
              Set-Cookie: session_token=; Max-Age=0\r\n\
              Set-Cookie: session_token_hint=1\r\n\
              Set-Cookie: Session_Token=other\r\n\
              Set-Cookie: theme=dark\r\nConnection: close\r\n\r\nok",
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = origin);
        let req = Request::get("/api/x").body(Body::empty()).unwrap();
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let cookies: Vec<&str> = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            cookies,
            [
                "csrf_token=c; Path=/",
                "session_token_hint=1",
                "Session_Token=other",
                "theme=dark",
            ]
        );
    }

    /// The one bridge-side session issuer the gateway does not shadow: the
    /// SSO routes of the `sigrift-sentinel` add-on, which the bridge mounts
    /// under `/api/oidc` when it is installed. The IdP redirects the
    /// browser to its callback, and the callback can only hand the browser
    /// its session as `Set-Cookie: session_token=…`; dropping it signed
    /// every SSO login in to nothing. On exactly that path and below it
    /// the backend's `session_token` is relayed; the legacy `bridge_token`
    /// is not, and neither is anywhere else, a look-alike path or a
    /// percent-encoded spelling the bridge would decode to it included
    /// (that fails closed: the cookie is dropped).
    #[tokio::test]
    async fn the_sso_routes_alone_may_set_the_session_cookie() {
        let origin = raw_backend(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\
              Set-Cookie: session_token=sso; Path=/; HttpOnly; SameSite=Lax\r\n\
              Set-Cookie: bridge_token=planted\r\n\
              Set-Cookie: csrf_token=c; Path=/\r\nConnection: close\r\n\r\nok",
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = origin);
        let set_cookies = |resp: &Response| -> Vec<String> {
            resp.headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .map(|v| v.to_str().unwrap().to_string())
                .collect()
        };
        for path in [
            "/api/oidc",
            "/api/oidc/",
            "/api/oidc/callback?code=x&state=y",
            "/api/oidc/acme/callback",
        ] {
            let req = Request::get(path).body(Body::empty()).unwrap();
            let resp = proxy_fallback(State(Arc::clone(&state)), req).await;
            assert_eq!(resp.status(), StatusCode::OK, "{path}");
            assert_eq!(
                set_cookies(&resp),
                [
                    "session_token=sso; Path=/; HttpOnly; SameSite=Lax",
                    "csrf_token=c; Path=/",
                ],
                "{path}"
            );
        }
        for path in [
            "/api/oidcx/callback",
            "/api/oidc-callback",
            "/api/auth/oidc/callback",
            "/api/x/oidc/callback",
            "/oidc/callback",
            "/API/oidc/callback",
            "/api/OIDC/callback",
            "/api/%6fidc/callback",
            "/api/x?next=/api/oidc/callback",
        ] {
            let req = Request::get(path).body(Body::empty()).unwrap();
            let resp = proxy_fallback(State(Arc::clone(&state)), req).await;
            assert_eq!(resp.status(), StatusCode::OK, "{path}");
            assert_eq!(set_cookies(&resp), ["csrf_token=c; Path=/"], "{path}");
        }
    }

    /// The same for a request header the client sends more than once:
    /// every value is forwarded, in order.
    #[tokio::test]
    async fn repeated_request_headers_are_all_forwarded() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = backend.origin.clone());
        let req = Request::get("/api/echo")
            .header("accept", "text/html")
            .header("accept", "application/json")
            .header("x-multi", "one")
            .header("x-multi", "two")
            .body(Body::empty())
            .unwrap();
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let seen = backend.only();
        assert_eq!(seen.values("accept"), ["text/html", "application/json"]);
        assert_eq!(seen.values("x-multi"), ["one", "two"]);
    }

    /// HTML from the backend has its internal origin stripped, so the
    /// internal address never reaches the browser.
    #[tokio::test]
    async fn html_response_hides_internal_origin() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = backend.origin.clone());
        let req = Request::get("/page").body(Body::empty()).unwrap();
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert_eq!(body, "<a href=\"/static/app.js\">x</a>");
        assert!(!body.contains(&backend.origin));
    }

    /// The rewrite changes the body's length, so the Content-Length sent
    /// to the client must be the rewritten body's: hyper writes the header
    /// as given, and a stale, larger value leaves the client waiting for
    /// bytes that never come (a debug build's hyper panics on it).
    #[tokio::test]
    async fn rewritten_html_keeps_response_framing_consistent() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = backend.origin.clone());
        let req = Request::get("/page").body(Body::empty()).unwrap();
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let declared = resp
            .headers()
            .get(header::CONTENT_LENGTH)
            .map(|v| v.to_str().unwrap().to_string());
        let body = body_string(resp).await;
        if let Some(declared) = declared {
            assert_eq!(declared, body.len().to_string(), "body: {body}");
        }
    }

    /// The same through hyper, as the client sees it: the length on the
    /// wire is the rewritten body's (a stale one made a debug build's
    /// hyper panic, and a release build send fewer bytes than declared).
    /// A HEAD has no length: the backend's is that of the page before the
    /// rewrite, and hyper adds none.
    #[tokio::test]
    async fn rewritten_html_is_framed_by_its_new_length_on_the_wire() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = backend.origin.clone());
        let gateway = serve_gateway(state).await;
        let page = "<a href=\"/static/app.js\">x</a>";

        let response = raw_exchange(
            gateway,
            b"GET /page HTTP/1.1\r\nHost: gw.example\r\nConnection: close\r\n\r\n",
        )
        .await;
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            head.to_ascii_lowercase()
                .contains(&format!("\r\ncontent-length: {}", page.len())),
            "{head}"
        );
        assert_eq!(body, page);

        // The connection stays usable after the HEAD: a GET behind it is
        // answered, and the HEAD's response ends at its head.
        let response = raw_exchange(
            gateway,
            b"HEAD /page HTTP/1.1\r\nHost: gw.example\r\n\r\n\
              GET /page HTTP/1.1\r\nHost: gw.example\r\nConnection: close\r\n\r\n",
        )
        .await;
        let (head, rest) = response.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("HTTP/1.1 200"), "{response}");
        for framing in ["\r\ncontent-length:", "\r\ntransfer-encoding:"] {
            assert!(!head.to_ascii_lowercase().contains(framing), "{head}");
        }
        assert!(rest.starts_with("HTTP/1.1 200"), "{response}");
        assert!(rest.ends_with(&format!("\r\n\r\n{page}")), "{response}");
    }

    /// A HEAD for an HTML page the rewrite applies to describes the GET,
    /// whose body may be rewritten: no Content-Length (the backend's is
    /// the length before the rewrite) and the weak ETag the GET gets. A
    /// 304 to a client that revalidates with that weak ETag carries it
    /// again, not the backend's strong one, which would update no stored
    /// response (RFC 9111 §4.3.4). Everything else keeps its headers.
    #[tokio::test]
    async fn head_and_not_modified_agree_with_the_rewritten_page() {
        let send = |origin: String, req: Request<Body>| async move {
            let dir = tempfile::tempdir().unwrap();
            let state = state_with(&dir, |s| s.config.python_url = origin);
            let resp = proxy_fallback(State(state), req).await;
            (resp.status(), resp.headers().clone())
        };
        let head = || Request::head("/page").body(Body::empty()).unwrap();
        let etags = |headers: &HeaderMap| -> Vec<String> {
            headers
                .get_all(header::ETAG)
                .iter()
                .map(|v| v.to_str().unwrap().to_string())
                .collect()
        };

        let html = raw_backend(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
              Content-Length: 60\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
        )
        .await;
        let (status, headers) = send(html, head()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(headers.get(header::CONTENT_LENGTH).is_none(), "{headers:?}");
        assert_eq!(etags(&headers), ["W/\"v1\""]);

        // Not rewritten as a GET, so the HEAD keeps the backend's headers.
        for (context, response) in [
            (
                "compressed",
                &b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: br\r\n\
                   Content-Length: 60\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n"[..],
            ),
            (
                "not HTML",
                &b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                   Content-Length: 60\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n"[..],
            ),
        ] {
            let origin = raw_backend(response).await;
            let (_, headers) = send(origin, head()).await;
            assert_eq!(headers[header::CONTENT_LENGTH], "60", "{context}");
            assert_eq!(etags(&headers), ["\"v1\""], "{context}");
        }

        let revalidate = |etag: &'static str, if_none_match: &'static [&'static str]| async move {
            let origin = raw_backend_with(|_| {
                format!("HTTP/1.1 304 Not Modified\r\nETag: {etag}\r\nConnection: close\r\n\r\n")
                    .into_bytes()
            })
            .await;
            let mut req = Request::get("/page");
            for value in if_none_match {
                req = req.header(header::IF_NONE_MATCH, *value);
            }
            let (status, headers) = send(origin, req.body(Body::empty()).unwrap()).await;
            assert_eq!(status, StatusCode::NOT_MODIFIED);
            etags(&headers)
        };
        // The client holds the rewritten page's weak ETag.
        assert_eq!(revalidate("\"v1\"", &["W/\"v1\""]).await, ["W/\"v1\""]);
        assert_eq!(
            revalidate("\"v1\"", &["\"v0\", W/\"v1\""]).await,
            ["W/\"v1\""]
        );
        assert_eq!(
            revalidate("\"v1\"", &["W/\"v0\"", "W/\"v1\""]).await,
            ["W/\"v1\""]
        );
        // It holds the strong one, another, or none: the backend's is kept.
        assert_eq!(revalidate("\"v1\"", &["\"v1\""]).await, ["\"v1\""]);
        assert_eq!(revalidate("\"v1\"", &["W/\"v10\""]).await, ["\"v1\""]);
        assert_eq!(revalidate("\"v1\"", &[]).await, ["\"v1\""]);
        // A weak ETag from the backend stays as it is.
        assert_eq!(revalidate("W/\"v1\"", &["W/\"v1\""]).await, ["W/\"v1\""]);
    }

    /// What the rewrite keeps as it was: a body still compressed (reqwest
    /// decodes only gzip), a byte range (206), and HTML that names the
    /// backend only as part of a longer port. A rewritten body loses the
    /// backend's Content-Length and gets its strong ETag as a weak one.
    #[tokio::test]
    async fn the_html_rewrite_leaves_encoded_partial_and_other_origins_alone() {
        let send = |origin: String| async move {
            let dir = tempfile::tempdir().unwrap();
            let state = state_with(&dir, |s| s.config.python_url = origin);
            let req = Request::get("/page").body(Body::empty()).unwrap();
            let resp = proxy_fallback(State(state), req).await;
            let headers = resp.headers().clone();
            (headers, body_string(resp).await)
        };
        let html = |status: &str, extra: &str, body: &str| {
            format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\n{extra}\
                 Connection: close\r\n\r\n{body}",
                body.len()
            )
            .into_bytes()
        };

        let origin = raw_backend_with(|o| html("200 OK", "Content-Encoding: br\r\n", o)).await;
        let (headers, body) = send(origin.clone()).await;
        assert_eq!(body, origin, "a compressed body is not rewritten");
        assert_eq!(headers[header::CONTENT_LENGTH], origin.len().to_string());

        let origin = raw_backend_with(|o| {
            html(
                "206 Partial Content",
                "Content-Range: bytes 0-20/100\r\n",
                o,
            )
        })
        .await;
        let (headers, body) = send(origin.clone()).await;
        assert_eq!(body, origin, "a byte range is not rewritten");
        assert_eq!(headers[header::CONTENT_LENGTH], origin.len().to_string());

        let origin =
            raw_backend_with(|o| html("200 OK", "ETag: \"v1\"\r\n", &format!("{o}0/x"))).await;
        let (headers, body) = send(origin.clone()).await;
        assert_eq!(body, format!("{origin}0/x"), "a longer port is another URL");
        assert_eq!(headers[header::ETAG], "\"v1\"");

        let origin = raw_backend_with(|o| {
            html(
                "200 OK",
                "ETag: \"v1\"\r\n",
                &format!("<a href=\"{o}/x\"><a href='{o}'>"),
            )
        })
        .await;
        let (headers, body) = send(origin.clone()).await;
        assert_eq!(body, "<a href=\"/x\"><a href='/'>");
        assert!(headers.get(header::CONTENT_LENGTH).is_none(), "{headers:?}");
        assert_eq!(headers[header::ETAG], "W/\"v1\"");
    }

    /// The rewrite on bytes: every occurrence, a root reference becomes
    /// `/`, an occurrence that continues the authority or the last path
    /// segment is kept, and bytes that are not UTF-8 pass unchanged.
    #[test]
    fn backend_origin_is_stripped_only_where_it_ends() {
        let strip = |body: &[u8], origin: &str| strip_backend_origin(body, origin.as_bytes());
        let origin = "http://127.0.0.1:8001";
        assert_eq!(
            strip(
                b"a http://127.0.0.1:8001/x b http://127.0.0.1:8001/y",
                origin
            )
            .unwrap(),
            b"a /x b /y"
        );
        assert_eq!(
            strip(
                b"[http://127.0.0.1:8001?q] (http://127.0.0.1:8001#f) http://127.0.0.1:8001",
                origin
            )
            .unwrap(),
            b"[/?q] (/#f) /"
        );
        assert_eq!(
            strip(b"\xff\xfe http://127.0.0.1:8001/x \xc3", origin).unwrap(),
            b"\xff\xfe /x \xc3"
        );
        assert!(strip(b"http://127.0.0.1:80010/x", origin).is_none());
        assert!(strip(b"http://127.0.0.1:8001.evil/x", origin).is_none());
        assert!(strip(b"nothing here", origin).is_none());
        assert!(strip(b"", origin).is_none());
        // A backend URL with a path prefix ends at a segment boundary.
        let origin = "http://bridge:8001/api";
        assert_eq!(
            strip(
                b"http://bridge:8001/api/nodes http://bridge:8001/apix",
                origin
            )
            .unwrap(),
            b"/nodes http://bridge:8001/apix"
        );
    }

    /// Backend failures answer 502 with a fixed message: no backend
    /// address, error text or backend header reaches the client. A
    /// backend that never answers is given up on after the proxy timeout.
    #[tokio::test]
    async fn backend_failures_do_not_leak_internals() {
        let refused = REFUSED_URL.to_string();
        let garbage = raw_backend(b"NOT-HTTP garbage\r\n\r\n").await;
        let truncated = raw_backend(
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nX-Backend-Secret: s3cr3t\r\n\r\nshort",
        )
        .await;
        let silent = silent_backend().await;
        let cases = [
            (refused, PROXY_TIMEOUT_SECS, "Python backend unavailable"),
            (garbage, PROXY_TIMEOUT_SECS, "Proxy error"),
            (
                truncated,
                PROXY_TIMEOUT_SECS,
                "Failed to read backend response",
            ),
            (silent, 1, "Python backend unavailable"),
        ];
        for (origin, timeout_secs, expected) in cases {
            let dir = tempfile::tempdir().unwrap();
            let state = state_with(&dir, |s| {
                s.proxy_client = build_proxy_client(timeout_secs, &origin);
                s.config.python_url = origin.clone();
            });
            let req = Request::get("/api/x").body(Body::empty()).unwrap();
            let resp = tokio::time::timeout(
                Duration::from_secs(PROXY_TIMEOUT_SECS),
                proxy_fallback(State(state), req),
            )
            .await
            .expect("the proxy gives up on its own timeout");
            assert_eq!(resp.status(), StatusCode::BAD_GATEWAY, "{expected}");
            assert!(resp.headers().get("x-backend-secret").is_none());
            let body = body_string(resp).await;
            assert_eq!(body, expected);
            assert!(!body.contains(&origin), "{body}");
        }
    }

    /// The bridge (uvicorn) closes a keep-alive connection idle for its
    /// timeout, and a request sent on it as it closes fails with 502
    /// "Proxy error". The pool reuses a connection only while it has been
    /// idle for less than [`BACKEND_POOL_IDLE_TIMEOUT`], well under that
    /// timeout; after that the next request opens a new one. This backend
    /// keeps every connection open, so a reuse would show.
    #[tokio::test]
    async fn idle_backend_connections_are_retired_before_keep_alive_closes_them() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    // Answer each request head on the connection, keeping
                    // it open, until the client closes it.
                    let mut pending = Vec::new();
                    let mut buf = [0u8; 1024];
                    loop {
                        while let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                            pending.drain(..end + 4);
                            let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                            if stream.write_all(reply).await.is_err() {
                                return;
                            }
                        }
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => pending.extend_from_slice(&buf[..n]),
                        }
                    }
                });
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| {
            s.proxy_client = build_proxy_client(PROXY_TIMEOUT_SECS, &origin);
            s.config.python_url = origin.clone();
        });
        let get = |state: &Arc<AppState>| {
            let req = Request::get("/static/app.js").body(Body::empty()).unwrap();
            proxy_fallback(State(Arc::clone(state)), req)
        };
        // Let the connection go back to the pool after each response.
        let settle = || tokio::time::sleep(Duration::from_millis(100));

        assert_eq!(body_string(get(&state).await).await, "ok");
        settle().await;
        assert_eq!(body_string(get(&state).await).await, "ok");
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "a connection idle for less than the pool timeout is reused"
        );

        settle().await;
        tokio::time::sleep(BACKEND_POOL_IDLE_TIMEOUT + Duration::from_millis(300)).await;
        assert_eq!(body_string(get(&state).await).await, "ok");
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            2,
            "a connection idle for longer than the pool timeout is not reused"
        );
    }

    /// A redirect the backend points at its own internal origin (Starlette
    /// builds one for a trailing-slash redirect from the Host it got) must
    /// not hand the client the internal address.
    #[tokio::test]
    async fn backend_redirect_to_its_own_origin_hides_it() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = backend.origin.clone());
        let req = Request::get(format!("/redirect?{}/api/x/", backend.origin))
            .body(Body::empty())
            .unwrap();
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers()[header::LOCATION].to_str().unwrap();
        assert!(!location.contains(&backend.origin), "{location}");
    }

    /// The redirect goes out as the gateway path the backend URL maps to,
    /// with its query; Content-Location the same. A relative Location is
    /// passed on as it is.
    #[tokio::test]
    async fn backend_redirects_to_its_own_origin_become_gateway_paths() {
        let origin = raw_backend_with(|o| {
            format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: {o}/api/nodes/?limit=5\r\n\
                 Content-Location: {o}/api/nodes\r\nContent-Length: 0\r\n\
                 Connection: close\r\n\r\n"
            )
            .into_bytes()
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = origin);
        let req = Request::get("/api/nodes").body(Body::empty()).unwrap();
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(resp.headers()[header::LOCATION], "/api/nodes/?limit=5");
        assert_eq!(resp.headers()[header::CONTENT_LOCATION], "/api/nodes");

        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = backend.origin.clone());
        let req = Request::get("/redirect?/dashboard?tab=1")
            .body(Body::empty())
            .unwrap();
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.headers()[header::LOCATION], "/dashboard?tab=1");
    }

    /// Which Locations name the backend: its exact origin (scheme, host in
    /// any case, port with the scheme's default) and a path under its
    /// prefix. Everything else is sent as it is.
    #[test]
    fn only_locations_naming_the_backend_are_rewritten() {
        let check = |backend: &str, location: &[u8]| {
            let backend = reqwest::Url::parse(backend).unwrap();
            let location = HeaderValue::from_bytes(location).unwrap();
            gateway_relative(&location, &backend).map(|v| v.to_str().unwrap().to_string())
        };
        let local = "http://127.0.0.1:8001";
        assert_eq!(
            check(local, b"http://127.0.0.1:8001/api/x/?a=1#top").as_deref(),
            Some("/api/x/?a=1#top")
        );
        assert_eq!(
            check(local, b"HTTP://127.0.0.1:8001/x").as_deref(),
            Some("/x")
        );
        assert_eq!(check(local, b"http://127.0.0.1:8001").as_deref(), Some("/"));
        assert_eq!(check(local, b"http://127.0.0.1:8002/x"), None);
        assert_eq!(check(local, b"https://127.0.0.1:8001/x"), None);
        assert_eq!(check(local, b"http://localhost:8001/x"), None);
        assert_eq!(check(local, b"https://gw.example/x"), None);
        assert_eq!(check(local, b"/relative?x=1"), None);
        assert_eq!(check(local, b"relative"), None);
        assert_eq!(check(local, b"http://[::1"), None);
        assert_eq!(check(local, b"http://127.0.0.1:8001/\xff"), None);

        // A default port, written or not, and a host in another case.
        let bridge = "http://Bridge:80/api";
        assert_eq!(
            check(bridge, b"http://bridge/api/nodes/").as_deref(),
            Some("/nodes/")
        );
        assert_eq!(check(bridge, b"http://BRIDGE:80/api").as_deref(), Some("/"));
        assert_eq!(check(bridge, b"http://bridge/api/").as_deref(), Some("/"));
        // Outside the prefix, or past it without a segment boundary.
        assert_eq!(check(bridge, b"http://bridge/apix"), None);
        assert_eq!(check(bridge, b"http://bridge/other"), None);
        assert_eq!(
            check("https://10.0.0.5/", b"https://10.0.0.5:443/x").as_deref(),
            Some("/x")
        );

        // A gateway path starting with `//` is a protocol-relative URL,
        // which the browser follows to another host: never produced.
        assert_eq!(check(local, b"http://127.0.0.1:8001//evil.example/x"), None);
        assert_eq!(
            check(local, b"http://127.0.0.1:8001/\\evil.example/x"),
            None
        );
        assert_eq!(check(local, b"http://127.0.0.1:8001//"), None);
        assert_eq!(check(bridge, b"http://bridge/api//evil.example"), None);
        assert_eq!(check(bridge, b"http://bridge/api/\\evil.example"), None);
        // One later in the path is still a path.
        assert_eq!(
            check(local, b"http://127.0.0.1:8001/x//y").as_deref(),
            Some("/x//y")
        );
    }

    /// TLS certificate verification to the backend is skipped only for a
    /// loopback backend (the same host's own bridge). For any other one a
    /// certificate no CA vouches for is refused, and the request never
    /// reaches it. `[::ffff:127.0.0.1]` reaches the same listener but is
    /// not a loopback address to the gateway, so it stands in for a
    /// remote backend.
    #[tokio::test]
    async fn tls_verification_is_only_skipped_for_a_loopback_backend() {
        use std::sync::atomic::Ordering;
        let (port, seen) = tls_backend().await;
        let send = |python_url: String| async move {
            let dir = tempfile::tempdir().unwrap();
            let state = state_with(&dir, |s| {
                s.proxy_client = build_proxy_client(PROXY_TIMEOUT_SECS, &python_url);
                s.config.python_url = python_url.clone();
            });
            let req = Request::get("/api/x").body(Body::empty()).unwrap();
            let resp = proxy_fallback(State(state), req).await;
            (resp.status(), body_string(resp).await)
        };

        let loopback = format!("https://127.0.0.1:{port}");
        assert!(is_loopback_url(&loopback));
        assert_eq!(
            send(loopback).await,
            (StatusCode::OK, "tls-backend".to_string())
        );
        assert_eq!(seen.handshakes.load(Ordering::SeqCst), 1);

        let remote = format!("https://[::ffff:127.0.0.1]:{port}");
        assert!(!is_loopback_url(&remote));
        let accepted = seen.accepted.load(Ordering::SeqCst);
        let (status, body) = send(remote).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
        assert_eq!(body, "Python backend unavailable");
        // The connection reached the backend; its certificate was refused.
        assert!(seen.accepted.load(Ordering::SeqCst) > accepted);
        assert_eq!(seen.handshakes.load(Ordering::SeqCst), 1);
    }

    /// A method the proxy does not know (TRACE, an extension method) is
    /// refused or forwarded as it is: never rewritten to GET. Auth and
    /// CSRF decided on the original method (CSRF is enforced for every
    /// method but GET/HEAD/OPTIONS), so the bridge must not execute
    /// another one.
    #[tokio::test]
    async fn unknown_methods_are_not_forwarded_as_get() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| s.config.python_url = backend.origin.clone());
        let methods = [Method::TRACE, Method::from_bytes(b"PURGE").unwrap()];
        for method in &methods {
            let req = Request::builder()
                .method(method.clone())
                .uri("/api/x")
                .body(Body::empty())
                .unwrap();
            let resp = proxy_fallback(State(state.clone()), req).await;
            if resp.status() != StatusCode::METHOD_NOT_ALLOWED {
                assert_eq!(resp.status(), StatusCode::OK, "{method}");
            }
        }
        // Whatever was forwarded went with the client's own method.
        for seen in backend.requests() {
            assert!(methods.contains(&seen.method), "{seen:?}");
        }
    }

    /// The bridge serves none of these methods, so the gateway refuses
    /// them itself — 405 naming the methods it forwards — before reading
    /// the body or contacting the backend. TRACE in particular would echo
    /// the proxy secret and the session's bearer token back.
    #[tokio::test]
    async fn unknown_methods_are_refused_before_the_backend() {
        let backend = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| {
            s.config.python_url = backend.origin.clone();
            s.config.max_body_size = 4;
        });
        for method in [
            Method::TRACE,
            Method::CONNECT,
            Method::from_bytes(b"PURGE").unwrap(),
            Method::from_bytes(b"PROPFIND").unwrap(),
        ] {
            // A body over the limit: refused for its method, not its size.
            let mut req = Request::builder()
                .method(method.clone())
                .uri("/api/x")
                .body(Body::from("larger than the limit"))
                .unwrap();
            req.extensions_mut()
                .insert(session("alice", Role::Admin, "verified-token"));
            let resp = proxy_fallback(State(state.clone()), req).await;
            assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED, "{method}");
            assert_eq!(
                resp.headers()[header::ALLOW],
                "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS",
                "{method}"
            );
        }
        assert!(backend.requests().is_empty(), "{:?}", backend.requests());

        // The methods it does forward still reach the backend as sent.
        for method in [Method::OPTIONS, Method::DELETE, Method::PATCH] {
            let req = Request::builder()
                .method(method.clone())
                .uri("/api/x")
                .body(Body::empty())
                .unwrap();
            let resp = proxy_fallback(State(state.clone()), req).await;
            assert_eq!(resp.status(), StatusCode::OK, "{method}");
        }
        let methods: Vec<Method> = backend.requests().into_iter().map(|s| s.method).collect();
        assert_eq!(methods, [Method::OPTIONS, Method::DELETE, Method::PATCH]);
    }

    /// The production proxy client returns a backend redirect to the
    /// client instead of following it, so the proxy secret and identity
    /// headers are never sent wherever the backend points.
    #[tokio::test]
    async fn backend_redirects_are_returned_not_followed() {
        let backend = Backend::start().await;
        let elsewhere = Backend::start().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, |s| {
            s.config.python_url = backend.origin.clone();
            s.config.proxy_secret = "gateway-secret".into();
            s.proxy_client = build_proxy_client(5, &backend.origin);
        });
        let target = format!("{}/collect", elsewhere.origin);
        let mut req = Request::get(format!("/redirect?{target}"))
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(api_key("key-1", Role::Admin));
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(resp.headers()[header::LOCATION], target.as_str());
        assert_eq!(backend.only().values("x-rust-proxy"), ["gateway-secret"]);
        assert!(elsewhere.requests().is_empty(), "redirect was followed");
    }

    #[test]
    fn identity_headers_for_session_and_cert_authenticated_key() {
        use crate::auth::client_cert::ClientCertInfo;
        // Session: user + role.
        let mut req = Request::get("/x").body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(session("alice", Role::Analyst, "t"));
        let h = identity_headers(&req);
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].0, "x-auth-user");
        assert_eq!(h[0].1, "alice");
        assert_eq!(h[1].0, "x-auth-role");
        assert_eq!(h[1].1, "analyst");

        // A key identity that came from a verified client cert (no API
        // key on the request) is marked client-cert.
        let cert = ClientCertInfo {
            identity: "node-1".into(),
            serial: "1".into(),
            fingerprint_sha256: "ab".into(),
        };
        let mut req = Request::get("/x").body(Body::empty()).unwrap();
        req.extensions_mut().insert(cert.clone());
        req.extensions_mut()
            .insert(api_key("cert:node-1", Role::Node));
        let h = identity_headers(&req);
        assert!(h
            .iter()
            .any(|(n, v)| n == "x-auth-method" && v == "client-cert"));

        // Same cert, but the request also carries an API key: the key is
        // the identity, so it is not marked client-cert.
        let mut req = Request::get("/x")
            .header("x-api-key", "k")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(cert);
        req.extensions_mut().insert(api_key("key", Role::Node));
        let h = identity_headers(&req);
        assert!(!h.iter().any(|(n, _)| n == "x-auth-method"));

        // A key without any client cert is not marked client-cert either.
        let mut req = Request::get("/x").body(Body::empty()).unwrap();
        req.extensions_mut().insert(api_key("key", Role::Node));
        assert!(!identity_headers(&req)
            .iter()
            .any(|(n, _)| n == "x-auth-method"));

        // No auth info: nothing.
        let req = Request::get("/x").body(Body::empty()).unwrap();
        assert!(identity_headers(&req).is_empty());
    }

    /// An unencodable secret yields an empty header, which the bridge's
    /// trust check treats as untrusted (fail closed).
    #[test]
    fn proxy_secret_header_fails_closed_on_invalid_secret() {
        assert_eq!(proxy_secret_header("s3cret"), "s3cret");
        assert_eq!(proxy_secret_header("bad\nsecret"), "");
        assert_eq!(proxy_secret_header(""), "");
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use crate::auth::rbac::Role;
    use crate::license::{LicenseResolver, LicenseTier};
    use crate::middleware::auth::AuthInfo;
    use crate::test_support::logs_of;
    use std::sync::Mutex;

    /// A backend that records the headers of every request and answers 200.
    async fn recording_backend() -> (String, Arc<Mutex<Vec<HeaderMap>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen: Arc<Mutex<Vec<HeaderMap>>> = Arc::default();
        let record = Arc::clone(&seen);
        let app = axum::Router::new().fallback(move |headers: HeaderMap| {
            let record = Arc::clone(&record);
            async move {
                record.lock().unwrap().push(headers);
                "from-backend"
            }
        });
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, seen)
    }

    /// The headers of the one request the backend received.
    fn only(seen: &Mutex<Vec<HeaderMap>>) -> HeaderMap {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "backend requests: {seen:?}");
        seen[0].clone()
    }

    /// A licence whose extra features cannot be sent as a header value,
    /// with no node limit.
    struct UnsendableFeatures;

    impl LicenseResolver for UnsendableFeatures {
        fn tier(&self) -> LicenseTier {
            LicenseTier::Professional
        }
        fn has_feature(&self, _feature: &str) -> bool {
            true
        }
        fn node_limit(&self) -> Option<u32> {
            None
        }
        fn issuer(&self) -> &str {
            "test"
        }
        fn features(&self) -> Vec<String> {
            vec!["alpha\nbeta".into()]
        }
    }

    /// The bridge gets the session the gateway verified as `Authorization:
    /// Bearer`, and no other credential: when that token cannot be sent as
    /// a header value, no Authorization goes at all, never the client's
    /// own Authorization or X-Session-Token in its place.
    #[tokio::test]
    async fn an_unsendable_verified_session_token_forwards_no_credential() {
        let (url, seen) = recording_backend().await;
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::test_support::app_state(&dir);
        Arc::get_mut(&mut state).unwrap().config.python_url = url;
        let mut req = Request::get("/api/things")
            .header(header::AUTHORIZATION, "Bearer client-supplied")
            .header("x-session-token", "client-supplied")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(AuthInfo::Session {
            username: "alice".into(),
            user_id: 1,
            role: Role::Viewer,
            session_token: "verified\ntoken".into(),
            expires_at: String::new(),
            tenant_id: "default".into(),
            scope: String::new(),
        });
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let headers = only(&seen);
        assert!(headers.get(header::AUTHORIZATION).is_none(), "{headers:?}");
        assert!(headers.get("x-session-token").is_none(), "{headers:?}");
        assert_eq!(headers.get("x-auth-user").unwrap(), "alice");
        assert_eq!(headers.get("x-auth-role").unwrap(), "viewer");
    }

    /// The licence headers the bridge reads are the gateway's alone: when
    /// it has none to send (features it cannot encode, no node limit), the
    /// client's copies are not forwarded in their place, and the tier is
    /// the resolver's.
    #[tokio::test]
    async fn client_licence_headers_never_stand_in_for_the_gateways() {
        let (url, seen) = recording_backend().await;
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::test_support::app_state(&dir);
        let s = Arc::get_mut(&mut state).unwrap();
        s.config.python_url = url;
        s.license_resolver = Arc::new(UnsendableFeatures);
        let req = Request::get("/api/things")
            .header("x-license-features", "everything")
            .header("x-license-node-limit", "9999")
            .header("x-license-tier", "government")
            .body(Body::empty())
            .unwrap();
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let headers = only(&seen);
        assert!(headers.get("x-license-features").is_none(), "{headers:?}");
        assert!(headers.get("x-license-node-limit").is_none(), "{headers:?}");
        let tiers: Vec<_> = headers.get_all("x-license-tier").iter().collect();
        assert_eq!(tiers, ["professional"]);
    }

    /// A backend URL that does not parse with the path appended (a
    /// misconfigured `UC_PYTHON_URL`) refuses the request instead of
    /// forwarding it anywhere.
    #[tokio::test]
    async fn a_backend_url_that_does_not_parse_refuses_the_request() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::test_support::app_state(&dir);
        Arc::get_mut(&mut state).unwrap().config.python_url = "http://[bridge".into();
        let req = Request::get("/api/things").body(Body::empty()).unwrap();
        let resp = proxy_fallback(State(state), req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], b"Invalid path");
    }

    /// A trusted front proxy's X-Forwarded-Proto that is not readable text
    /// is not believed: the listener's own scheme is sent.
    #[test]
    fn an_unreadable_forwarded_proto_from_a_trusted_proxy_is_not_believed() {
        let trusted = crate::middleware::client_ip::parse_trusted_proxies("127.0.0.1");
        let mut extensions = axum::http::Extensions::new();
        extensions.insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-proto",
            HeaderValue::from_bytes(b"https\xff").unwrap(),
        );
        assert_eq!(
            forwarded_proto(false, &extensions, &headers, &trusted),
            "http"
        );
        assert_eq!(
            forwarded_proto(true, &extensions, &headers, &trusted),
            "https"
        );
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert_eq!(
            forwarded_proto(false, &extensions, &headers, &trusted),
            "https"
        );
    }

    /// An empty backend origin rewrites nothing (and an empty pattern
    /// never matches everywhere).
    #[test]
    fn an_empty_backend_origin_rewrites_nothing() {
        assert_eq!(
            strip_backend_origin(b"<a href=\"/static/app.js\">", b""),
            None
        );
    }

    /// Only strong ETags are weakened: one that is already weak (or not a
    /// quoted tag) is kept as it is, never turned into `W/W/"…"`, and the
    /// order of the fields is kept.
    #[test]
    fn already_weak_etags_are_kept_as_they_are() {
        let mut headers = HeaderMap::new();
        headers.append(header::ETAG, HeaderValue::from_static("W/\"v1\""));
        headers.append(header::ETAG, HeaderValue::from_static("\"v2\""));
        headers.append(header::ETAG, HeaderValue::from_static("*"));
        weaken_etags(&mut headers);
        let etags: Vec<_> = headers.get_all(header::ETAG).iter().collect();
        assert_eq!(etags, ["W/\"v1\"", "W/\"v2\"", "*"]);
    }

    /// The proxy client says that it verifies the certificate of a
    /// non-loopback HTTPS backend; for a plaintext or loopback backend it
    /// says nothing.
    #[test]
    fn only_a_remote_https_backend_gets_the_certificate_verification_warning() {
        let warning = "verifying its TLS certificate";
        let (_, logs) = logs_of(|| build_proxy_client(30, "https://bridge.internal:8443"));
        assert!(logs.contains(warning), "{logs}");
        for url in ["http://bridge.internal:8001", "https://127.0.0.1:8443"] {
            let (_, logs) = logs_of(|| build_proxy_client(30, url));
            assert!(!logs.contains(warning), "{url}: {logs}");
        }
    }

    /// The identity headers are the gateway's alone. A verified identity
    /// whose name cannot be sent as a header value (here it holds a line
    /// break) reaches the bridge with its role and without a name: never
    /// with the name, role or method the client put in its own trust
    /// headers in its place.
    #[tokio::test]
    async fn an_identity_name_that_cannot_be_sent_is_left_out_never_replaced() {
        let session = AuthInfo::Session {
            username: "ali\nce".into(),
            user_id: 1,
            role: Role::Viewer,
            session_token: "verified-token".into(),
            expires_at: String::new(),
            tenant_id: "default".into(),
            scope: String::new(),
        };
        let key = AuthInfo::ApiKey {
            key_id: "key\nid".into(),
            role: Role::Viewer,
        };
        for auth in [session, key] {
            let (url, seen) = recording_backend().await;
            let dir = tempfile::tempdir().unwrap();
            let mut state = crate::test_support::app_state(&dir);
            Arc::get_mut(&mut state).unwrap().config.python_url = url;
            let mut req = Request::get("/api/things")
                .header("x-auth-user", "admin")
                .header("x-auth-key-id", "master")
                .header("x-auth-role", "admin")
                .header("x-auth-method", "client-cert")
                .body(Body::empty())
                .unwrap();
            req.extensions_mut().insert(auth.clone());
            let resp = proxy_fallback(State(state), req).await;
            assert_eq!(resp.status(), StatusCode::OK, "{auth:?}");
            let headers = only(&seen);
            for forged in ["x-auth-user", "x-auth-key-id", "x-auth-method"] {
                assert!(headers.get(forged).is_none(), "{auth:?}: {headers:?}");
            }
            let roles: Vec<_> = headers.get_all("x-auth-role").iter().collect();
            assert_eq!(roles, ["viewer"], "{auth:?}");
        }
    }

    /// A licence that grants no feature.
    struct NoFeatures;

    impl LicenseResolver for NoFeatures {
        fn tier(&self) -> LicenseTier {
            LicenseTier::Community
        }
        fn has_feature(&self, _feature: &str) -> bool {
            false
        }
        fn node_limit(&self) -> Option<u32> {
            None
        }
        fn issuer(&self) -> &str {
            "test"
        }
    }

    /// The proxy's refusals reach no backend and are logged with what was
    /// refused: a gated path the licence lacks (403) with the path and the
    /// feature, and a path the backend URL would rewrite (400; here a
    /// percent-encoded dot segment, which the URL parser removes) with the
    /// path routed and the path that would have been sent.
    #[test]
    fn refused_paths_reach_no_backend_and_are_logged_with_what_was_refused() {
        static GATED: &[(&str, &str)] = &[("/api/gated", "gated_feature")];
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (url, seen) = runtime.block_on(recording_backend());
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::test_support::app_state(&dir);
        let s = Arc::get_mut(&mut state).unwrap();
        s.config.python_url = url;
        s.license_resolver = Arc::new(NoFeatures);
        s.feature_routes = crate::FeatureRoutes(GATED);

        let refused = |path: &str| {
            let req = Request::get(path).body(Body::empty()).unwrap();
            logs_of(|| {
                runtime
                    .block_on(proxy_fallback(State(Arc::clone(&state)), req))
                    .status()
            })
        };
        let (status, logs) = refused("/api/gated/report");
        assert_eq!(status, StatusCode::FORBIDDEN);
        let denied: Vec<&str> = logs
            .lines()
            .filter(|l| l.contains("License feature gate denied request"))
            .collect();
        assert_eq!(denied.len(), 1, "{logs}");
        for named in [" WARN ", "path=/api/gated/report", "feature=gated_feature"] {
            assert!(denied[0].contains(named), "{named:?} missing: {logs}");
        }

        let (status, logs) = refused("/api/%2e/secret");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let rewritten: Vec<&str> = logs
            .lines()
            .filter(|l| l.contains("Refused a path the backend URL would change"))
            .collect();
        assert_eq!(rewritten.len(), 1, "{logs}");
        for named in [" WARN ", "path=/api/%2e/secret", "sent=/api/secret"] {
            assert!(rewritten[0].contains(named), "{named:?} missing: {logs}");
        }
        assert!(seen.lock().unwrap().is_empty(), "a refused path was sent");
    }
}
