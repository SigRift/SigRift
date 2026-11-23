//! Request-path canonicalization (contract K9).
//!
//! axum routes on the raw, still percent-encoded path, while the bridge's
//! server (uvicorn) percent-decodes the path before Starlette routes it. A
//! path that spelled one character of a gateway-native route as an escape
//! — `/api/auth/mfa/%64isable` — therefore missed the native route, went to
//! the proxy and reached the bridge's handler for the decoded path,
//! without the gateway's protections (MFA attempt limits, node binding,
//! role ceilings, session scopes).
//!
//! So before routing, and so before every path-based decision (native
//! route match, auth exemptions, session scopes, CSRF exemptions, the
//! proxy's filters), the gateway:
//!
//! * answers 404 — and never proxies — `/api/internal` and everything
//!   below it, in any letter case and however it is encoded (escapes,
//!   `%2F`, doubled slashes, `.` segments): that is the bridge's
//!   gateway-only API (node-key binding, post-ingest hooks; K7, K8), which
//!   trusts the proxy secret the gateway adds to every proxied request;
//! * refuses (400) a path holding an encoded slash (`%2F`): the bridge
//!   would read it as a `/`, so the gateway would route a different path
//!   than the bridge serves. A client can always send the `/` itself;
//! * refuses (400) a path holding a control character (a byte below
//!   0x20, or 0x7F), encoded or not ([`has_control_character`]). The
//!   bridge decodes `%0A` to a line feed, and its routes' patterns end in
//!   `$`, which in Python also matches just before a final line feed: so
//!   `/api/detections/batch%0A` missed the gateway's native route, was
//!   proxied, and the bridge served its own copy of
//!   `/api/detections/batch` — without the gateway's node binding, audit
//!   and scoring. No client sends control characters in a path;
//! * decodes percent-encoded *unreserved* characters (RFC 3986 §2.3:
//!   `A-Z a-z 0-9 - . _ ~`; decoding them never changes what a URI means)
//!   and routes and forwards the result. Every other escape stays as it
//!   is;
//! * refuses (400) a path that, once decoded, the proxy's URL parser would
//!   rewrite before it reaches the bridge ([`is_ambiguous_path`]): one
//!   holding a `\` (the WHATWG URL rules the `url` crate follows read it
//!   as `/` in http(s) URLs), a `.` or `..` segment (removed or resolved
//!   — `%2E` is decoded first, so it counts too) or an empty segment
//!   other than a trailing slash (`//`). For any of those the gateway
//!   would route one path and the bridge serve another (the bridge's copy
//!   of a gateway-native route, without the gateway's protections, or its
//!   gateway-only API). Clients — browsers, the edge agents — never send
//!   such paths: they normalize them first.
//!
//! Middleware added with `Router::layer` runs after routing, so this one
//! wraps the whole router ([`with_canonical_paths`]), inside only the
//! framing guard ([`crate::middleware::framing`]).

use std::borrow::Cow;

use axum::{
    body::Body,
    extract::Request,
    http::{uri::PathAndQuery, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
    Json, Router,
};
use tower::Layer as _;
use tracing::{debug, warn};

/// The first two segments of the bridge's gateway-only API (K7, K8).
const INTERNAL_SEGMENTS: [&str; 2] = ["api", "internal"];

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// RFC 3986 §2.3 unreserved characters.
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// `path` with the escapes for which `decode` holds decoded; every other
/// byte, and every malformed escape, is kept as it is.
fn decode_where(path: &str, decode: impl Fn(u8) -> bool) -> Cow<'_, [u8]> {
    if !path.contains('%') {
        return Cow::Borrowed(path.as_bytes());
    }
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = bytes.get(i + 1).copied().and_then(hex_value);
            let lo = bytes.get(i + 2).copied().and_then(hex_value);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                let c = (hi << 4) | lo;
                if decode(c) {
                    out.push(c);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    Cow::Owned(out)
}

/// `path` with its percent-encoded unreserved characters decoded.
pub fn decode_unreserved(path: &str) -> Cow<'_, str> {
    match decode_where(path, is_unreserved) {
        Cow::Borrowed(_) => Cow::Borrowed(path),
        // Only ASCII bytes were decoded, so this stays valid UTF-8.
        Cow::Owned(bytes) if bytes.as_slice() == path.as_bytes() => Cow::Borrowed(path),
        Cow::Owned(bytes) => Cow::Owned(String::from_utf8_lossy(&bytes).into_owned()),
    }
}

/// True when `path` holds an encoded `/` (`%2F`, either case).
pub fn has_encoded_slash(path: &str) -> bool {
    path.as_bytes()
        .windows(3)
        .any(|w| w[0] == b'%' && w[1] == b'2' && (w[2] == b'f' || w[2] == b'F'))
}

/// True when `path`, fully percent-decoded, holds a control character: a
/// byte below 0x20 (`%00`, `%09`, `%0A`, `%0D`…) or 0x7F (`%7F`).
pub fn has_control_character(path: &str) -> bool {
    decode_where(path, |_| true)
        .iter()
        .any(|&b| b < 0x20 || b == 0x7f)
}

/// True when `path` is `/api/internal` or below it however the proxy's URL
/// parser or the bridge could read it: fully percent-decoded, in any case,
/// with `\` read as `/`, `.` segments dropped, `..` segments resolved and
/// empty segments ignored.
pub fn is_internal_path(path: &str) -> bool {
    let decoded = decode_where(path, |_| true);
    let decoded = String::from_utf8_lossy(&decoded).to_ascii_lowercase();
    let mut segments: Vec<&str> = Vec::new();
    for segment in decoded.split(['/', '\\']) {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            segment => segments.push(segment),
        }
    }
    segments.len() >= INTERNAL_SEGMENTS.len()
        && INTERNAL_SEGMENTS
            .iter()
            .zip(&segments)
            .all(|(expected, got)| expected == got)
}

/// True when the proxy's URL parser would not send `path` as it is: it
/// holds a `\`, a `.` or `..` segment, or an empty segment other than a
/// trailing slash. `path` is a canonical path (escaped unreserved
/// characters decoded, so `%2E` is a `.` here).
///
/// The `url` crate behind `reqwest` follows the WHATWG URL rules: in an
/// http(s) URL it reads `\` as `/` and removes `.` segments and resolves
/// `..` ones (also spelled `%2E`), so the bridge would get — and serve —
/// a different path than the one the gateway routed and checked.
pub fn is_ambiguous_path(path: &str) -> bool {
    if path.contains('\\') {
        return true;
    }
    let mut segments = path.split('/').skip(1).peekable();
    while let Some(segment) = segments.next() {
        let last = segments.peek().is_none();
        if segment == "." || segment == ".." || (segment.is_empty() && !last) {
            return true;
        }
    }
    false
}

/// True when sending `routed` to the bridge as the URL whose parsed path
/// is `sent` keeps it as it is: `sent`, fully percent-decoded, ends with
/// `routed`, fully percent-decoded. The URL parser only adds escapes (for
/// `"`, `{`, non-ASCII bytes…), which the bridge decodes again; anything
/// else it changed (a `\` read as `/`, a removed dot segment) shows here.
pub fn forwarded_unchanged(sent: &str, routed: &str) -> bool {
    decode_where(sent, |_| true).ends_with(&decode_where(routed, |_| true))
}

fn refuse(status: StatusCode, detail: &str) -> Response {
    (status, Json(serde_json::json!({ "detail": detail }))).into_response()
}

/// `uri` with its path replaced by `path` (query, scheme and authority kept).
fn with_path(uri: &Uri, path: &str) -> Option<Uri> {
    let path_and_query = match uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_string(),
    };
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(path_and_query.parse::<PathAndQuery>().ok()?);
    Uri::from_parts(parts).ok()
}

/// The canonicalization middleware (see the module documentation).
pub async fn canonicalize_path(mut req: Request<Body>, next: Next) -> Response {
    let raw = req.uri().path();
    if is_internal_path(raw) {
        warn!(path = %raw, "Refused a request for the bridge's internal API");
        return refuse(StatusCode::NOT_FOUND, "Not Found");
    }
    if has_encoded_slash(raw) {
        warn!(path = %raw, "Refused a path holding an encoded slash");
        return refuse(StatusCode::BAD_REQUEST, "Invalid path");
    }
    if has_control_character(raw) {
        warn!(path = %raw, "Refused a path holding a control character");
        return refuse(StatusCode::BAD_REQUEST, "Invalid path");
    }
    let path = decode_unreserved(raw);
    if is_ambiguous_path(&path) {
        warn!(path = %raw, "Refused a path the proxy would not forward as routed");
        return refuse(StatusCode::BAD_REQUEST, "Invalid path");
    }
    if let Cow::Owned(path) = path {
        let Some(uri) = with_path(req.uri(), &path) else {
            return refuse(StatusCode::BAD_REQUEST, "Invalid path");
        };
        debug!(from = %req.uri().path(), to = %path, "Canonicalized the request path");
        *req.uri_mut() = uri;
    }
    next.run(req).await
}

/// `app` behind [`canonicalize_path`]: every request is canonicalized
/// first and routed by `app` afterwards. Outside both is the framing
/// guard ([`guard_framing`](crate::middleware::framing::guard_framing)),
/// so that no layer that answers a request itself — this one, or the
/// CORS, body-limit and auth layers in `app` — keeps open a connection
/// whose framing a front proxy may read otherwise.
pub fn with_canonical_paths(app: Router) -> Router {
    Router::new().fallback_service(
        axum::middleware::from_fn(crate::middleware::framing::guard_framing)
            .layer(axum::middleware::from_fn(canonicalize_path).layer(app)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use tower::ServiceExt as _;

    #[test]
    fn unreserved_escapes_are_decoded_and_others_kept() {
        assert_eq!(
            decode_unreserved("/api/auth/mfa/%64isable"),
            "/api/auth/mfa/disable"
        );
        assert_eq!(decode_unreserved("/%41%7a%30%2D%2e%5F%7E"), "/Az0-._~");
        for kept in [
            "/a%2Fb",
            "/a%20b",
            "/a%3Fb",
            "/a%25",
            "/a%zz",
            "/a%4",
            "/a%",
            "/caf%C3%A9",
        ] {
            assert_eq!(decode_unreserved(kept), kept, "{kept}");
            assert!(
                matches!(decode_unreserved(kept), Cow::Borrowed(_)),
                "{kept}"
            );
        }
        assert!(matches!(decode_unreserved("/plain"), Cow::Borrowed(_)));
        // %25 is not unreserved, so nothing is decoded twice.
        assert_eq!(decode_unreserved("/%2564isable"), "/%2564isable");
    }

    #[test]
    fn internal_paths_are_recognised_however_spelled() {
        for internal in [
            "/api/internal",
            "/api/internal/",
            "/api/internal/bind-node-key",
            "/api/internal/ingest-hook",
            "/API/Internal/ingest-hook",
            "/Api/iNtErNaL/bind-node-key",
            "/api/%69nternal/bind-node-key",
            "/%61pi/internal/x",
            // Escaped letters in either case, decoding to either case.
            "/%41%50%49/%49nternal",
            "/api/%49%4E%54ERNAL/x",
            "/api/%49%6e%74ernal/x",
            "/api/internal%2Fbind-node-key",
            "/api%2Finternal/x",
            "/api//internal/x",
            "/api/./internal/x",
            "//api/internal",
            // The URL parser behind the proxy reads `\` as `/` and
            // resolves dot segments (K9 regression: these were proxied).
            "/api\\internal\\bind-node-key",
            "/api\\internal/ingest-hook",
            "/api/internal\\ingest-hook",
            "\\api\\internal",
            "/api/x/../internal/ingest-hook",
            "/x/../api/internal",
            "/api/%2E/internal/x",
        ] {
            assert!(is_internal_path(internal), "{internal}");
        }
        for other in [
            "/api/internals",
            "/api/internalx/y",
            "/api/inter",
            "/internal/x",
            "/api/nodes/internal",
            "/api/%2569nternal/x",
            "/api/internal/../x",
            "/api/../internal",
            "/",
        ] {
            assert!(!is_internal_path(other), "{other}");
        }
    }

    #[test]
    fn paths_the_url_parser_would_rewrite_are_ambiguous() {
        for ambiguous in [
            "/api\\auth\\mfa\\disable",
            "/api/detections\\batch",
            "/api/auth/./mfa/disable",
            "/api/auth/mfa/disable/.",
            "/api/auth/mfa/../mfa/disable",
            "/api/detections/..",
            "/.",
            "/api//detections/batch",
            "//api/detections/batch",
            "/api/x//",
        ] {
            assert!(is_ambiguous_path(ambiguous), "{ambiguous}");
        }
        for plain in [
            "/",
            "/api/nodes/",
            "/api/nodes/x",
            "/static/app.js",
            "/.well-known/security.txt",
            "/a/.../b",
            "/a/..b/.c",
            "/a/%5Cb",
            "*",
        ] {
            assert!(!is_ambiguous_path(plain), "{plain}");
        }
    }

    /// The check the proxy makes on the URL it sends: the parser may add
    /// escapes, but any other change to the routed path shows.
    #[test]
    fn forwarded_unchanged_detects_what_the_url_parser_rewrote() {
        let sent = |path: &str| {
            reqwest::Url::parse(&format!("http://127.0.0.1:8001{path}"))
                .unwrap()
                .path()
                .to_string()
        };
        for kept in [
            "/api/nodes/x",
            "/api/nodes/",
            "/api/nodes/caf\u{e9}",
            "/api/nodes/a\"b{c}",
            "/api/nodes/x%20y",
            "/api/nodes/%5C",
        ] {
            assert!(forwarded_unchanged(&sent(kept), kept), "{kept}");
        }
        for rewritten in [
            "/api\\internal\\bind-node-key",
            "/api/auth/./mfa/disable",
            "/api/auth/mfa/%2E/disable",
            "/api/auth/mfa/disable/.",
            "/api/x/../y",
        ] {
            assert_ne!(sent(rewritten), rewritten, "{rewritten}");
            assert!(
                !forwarded_unchanged(&sent(rewritten), rewritten),
                "{rewritten}"
            );
        }
    }

    #[test]
    fn control_characters_are_found_encoded_or_not() {
        for control in [
            "/api/detections/batch%0A",
            "/api/detections/batch%0a",
            "/api/detections/batch%0D",
            "/api/detections/batch%0d%0a",
            "/api/detections/batch%00",
            "/api/detections/batch%7F",
            "/api/detections/batch%7f",
            "/api/detections/batch%09",
            "/api/detections/batch%1F",
            "/api/%0A/detections/batch",
            "/api/detec%0Ations/batch",
            "%0A/api",
            "/api/x\n",
            "/api/x\u{7f}",
        ] {
            assert!(has_control_character(control), "{control:?}");
        }
        for plain in [
            "/api/detections/batch",
            "/api/nodes/x%20y",
            "/api/nodes/%20",
            "/api/nodes/%250A",
            "/api/nodes/%0",
            "/api/nodes/%0G",
            "/api/nodes/%7E",
            "/api/nodes/%80",
            "/api/nodes/caf%C3%A9",
            "/api/nodes/caf\u{e9}",
        ] {
            assert!(!has_control_character(plain), "{plain:?}");
        }
    }

    #[test]
    fn encoded_slashes_are_found() {
        assert!(has_encoded_slash("/a%2fb"));
        assert!(has_encoded_slash("/a%2Fb"));
        assert!(has_encoded_slash("/api/nodes%2F"), "at the end");
        assert!(has_encoded_slash("/%2Fapi/nodes"), "at the start");
        assert!(!has_encoded_slash("/a%252Fb"), "an encoded percent sign");
        assert!(!has_encoded_slash("/a/b%2"));
    }

    async fn path_of(req: Request<Body>) -> String {
        req.uri().to_string()
    }

    fn app() -> Router {
        with_canonical_paths(
            Router::new()
                .route("/api/auth/mfa/disable", get(|| async { "native" }))
                .fallback(path_of),
        )
    }

    async fn get_path(path: &str) -> (StatusCode, String) {
        let req = Request::get(path).body(Body::empty()).unwrap();
        let resp = app().oneshot(req).await.unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn routing_sees_the_canonical_path() {
        assert_eq!(
            get_path("/api/auth/mfa/%64isable").await,
            (StatusCode::OK, "native".into())
        );
        assert_eq!(
            get_path("/api/auth/mfa/%64%69%73able").await,
            (StatusCode::OK, "native".into())
        );
        // The fallback (the proxy) gets the canonical path and the query
        // unchanged; other escapes stay encoded.
        assert_eq!(
            get_path("/api/%6eodes/x%20y?q=%64").await,
            (StatusCode::OK, "/api/nodes/x%20y?q=%64".into())
        );
    }

    #[tokio::test]
    async fn internal_paths_and_encoded_slashes_are_refused() {
        for path in [
            "/api/internal/bind-node-key",
            "/api/Internal/ingest-hook",
            "/api/%69nternal/ingest-hook",
            "/api/internal",
            "/API/INTERNAL",
            "/%41%50%49/%49nternal",
            "/api/%49%4E%54ERNAL/x",
            "/api/internal%2Fingest-hook",
            "/api\\internal\\bind-node-key",
            "/api\\internal/ingest-hook",
            "/api/internal\\ingest-hook",
        ] {
            assert_eq!(get_path(path).await.0, StatusCode::NOT_FOUND, "{path}");
        }
        for path in [
            "/api/auth%2Fmfa%2Fdisable",
            "/api/auth%2fmfa%2fdisable",
            "/api/nodes%2F",
            "/%2Fapi/nodes",
            "/api/nodes/a%2fb",
        ] {
            let (status, body) = get_path(path).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
            assert_eq!(body, r#"{"detail":"Invalid path"}"#, "{path}");
        }
    }

    /// P1/K9 regression: a `.` segment (literal or `%2E`) or a `\` made
    /// the gateway route one path while the proxy's URL parser sent the
    /// bridge another — here the native route's path.
    #[tokio::test]
    async fn dot_segments_and_backslashes_are_refused() {
        for path in [
            "/api/auth/./mfa/disable",
            "/api/auth/mfa/%2E/disable",
            "/api/auth/mfa/%2e%2E/mfa/disable",
            "/api/auth/mfa/disable/.",
            "/api\\auth\\mfa\\disable",
            "/api/auth/mfa\\disable",
            "/api//auth/mfa/disable",
        ] {
            let (status, body) = get_path(path).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
            assert_eq!(body, r#"{"detail":"Invalid path"}"#, "{path}");
        }
        // A trailing slash and dots inside a segment are ordinary.
        assert_eq!(
            get_path("/api/nodes/a..b/.c/").await,
            (StatusCode::OK, "/api/nodes/a..b/.c/".into())
        );
    }

    /// V1 regression: the bridge decodes `%0A` to a line feed, and its
    /// route patterns end in `$`, which matches before a final line feed —
    /// so a native route's path with an encoded control character missed
    /// the native route and reached the bridge's copy of it.
    #[tokio::test]
    async fn encoded_control_characters_are_refused() {
        for path in [
            "/api/auth/mfa/disable%0A",
            "/api/auth/mfa/disable%0a",
            "/api/auth/mfa/disable%0D",
            "/api/auth/mfa/disable%00",
            "/api/auth/mfa/disable%7F",
            "/api/auth/mfa/disable%0D%0A",
            "/api/auth/mfa%0A/disable",
            "/api/nodes/x%09y",
        ] {
            let (status, body) = get_path(path).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
            assert_eq!(body, r#"{"detail":"Invalid path"}"#, "{path}");
        }
        // The internal API stays a 404, however it is spelled.
        assert_eq!(
            get_path("/api/internal/ingest-hook%0A").await.0,
            StatusCode::NOT_FOUND
        );
        // Other escapes (and a literal space escape) still pass.
        assert_eq!(
            get_path("/api/nodes/x%20y%250A").await,
            (StatusCode::OK, "/api/nodes/x%20y%250A".into())
        );
    }

    /// On a real server the wrapper keeps what the connection adds to each
    /// request: the peer address (`ConnectInfo`, which `serve` installs
    /// around the wrapper) and the upgrade handle WebSockets need.
    #[tokio::test]
    async fn connection_info_and_upgrades_pass_through_the_wrapper() {
        use axum::extract::{
            ws::{Message, WebSocketUpgrade},
            ConnectInfo,
        };
        use futures_util::StreamExt as _;
        use std::net::SocketAddr;

        let app = with_canonical_paths(Router::new().route(
            "/ws/echo",
            get(
                |ConnectInfo(peer): ConnectInfo<SocketAddr>, ws: WebSocketUpgrade| async move {
                    ws.on_upgrade(move |mut socket| async move {
                        let _ = socket
                            .send(Message::Text(peer.ip().to_string().into()))
                            .await;
                    })
                },
            ),
        ));
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
        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws/%65cho"))
            .await
            .expect("upgraded through the wrapper");
        let msg = ws.next().await.unwrap().unwrap();
        assert_eq!(msg.into_text().unwrap().as_str(), "127.0.0.1");
    }

    async fn send_path(app: &Router, method: &str, path: &str) -> (StatusCode, String) {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    /// `%5C` is a `\` once the bridge decodes it, so it cannot spell the
    /// way into the internal API either.
    #[tokio::test]
    async fn encoded_backslashes_cannot_reach_the_internal_api() {
        assert!(is_internal_path("%5Capi%5Cinternal"));
        for path in [
            "/api%5Cinternal",
            "/api%5cinternal%5cbind-node-key",
            "/api/internal%5Cingest-hook",
            "/%5Capi%5Cinternal",
            "/api%5C%69nternal/x",
        ] {
            assert!(is_internal_path(path), "{path}");
            assert_eq!(get_path(path).await.0, StatusCode::NOT_FOUND, "{path}");
        }
    }

    /// Encoded (and half-encoded) dot segments are resolved before the
    /// internal-API check, and refused anywhere else.
    #[tokio::test]
    async fn encoded_dot_segments_are_resolved_or_refused() {
        for path in [
            "/api/x/%2E%2E/internal/y",
            "/api/x/%2e%2e/internal",
            "/x/%2E%2E/api/internal/bind-node-key",
            "/api/x/.%2E/internal",
            "/api/x/%2E./internal",
            "/api/%2e/internal",
        ] {
            assert_eq!(get_path(path).await.0, StatusCode::NOT_FOUND, "{path}");
        }
        for path in [
            "/api/auth/mfa/.%2E/mfa/disable",
            "/api/auth/mfa/%2E./mfa/disable",
            "/api/detections/%2E%2E",
            "/api/detections/%2e",
            "/%2E%2E/api/auth/mfa/disable",
        ] {
            let (status, body) = get_path(path).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
            assert_eq!(body, r#"{"detail":"Invalid path"}"#, "{path}");
        }
    }

    /// The bridge decodes a path once, so the gateway decodes it once
    /// too: a doubly encoded name is not the native route, and a doubly
    /// encoded slash, dot or control character stays as it is.
    #[tokio::test]
    async fn double_encoding_is_never_decoded_twice() {
        for path in [
            "/api/auth/mfa/%2564isable",
            "/api/%2569nternal/x",
            "/api%252Finternal/x",
            "/api/auth/mfa/%252E%252E/disable",
            "/api/nodes/%255C",
            "/api/nodes/%2500",
        ] {
            assert_eq!(
                get_path(path).await,
                (StatusCode::OK, path.to_string()),
                "{path}"
            );
        }
    }

    /// An overlong UTF-8 spelling of `.` (`%C0%AE`) is not a dot to the
    /// gateway, the URL parser or the bridge: it passes unchanged and
    /// never matches a native route or the internal API.
    #[tokio::test]
    async fn overlong_utf8_dots_are_not_dots() {
        for path in [
            "/api/x/%C0%AE%C0%AE/internal",
            "/api/auth/mfa/%C0%AE/disable",
        ] {
            assert!(!is_internal_path(path), "{path}");
            assert!(!is_ambiguous_path(&decode_unreserved(path)), "{path}");
            assert_eq!(
                get_path(path).await,
                (StatusCode::OK, path.to_string()),
                "{path}"
            );
            let sent = reqwest::Url::parse(&format!("http://127.0.0.1:8001{path}"))
                .unwrap()
                .path()
                .to_string();
            assert!(forwarded_unchanged(&sent, path), "{path} -> {sent}");
        }
    }

    /// Canonicalization does not depend on the method, and keeps the
    /// authority of an absolute-form request target.
    #[tokio::test]
    async fn every_method_and_request_form_is_canonicalized() {
        let app = app();
        for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"] {
            let (status, _) = send_path(&app, method, "/api/internal/bind-node-key").await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method}");
            let (status, _) = send_path(&app, method, "/api/auth/./mfa/disable").await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{method}");
            assert_eq!(
                send_path(&app, method, "/api/%6Eodes/x").await,
                (StatusCode::OK, "/api/nodes/x".into()),
                "{method}"
            );
        }
        assert_eq!(
            send_path(&app, "GET", "http://gw.example/api/%6Eodes/x?q=%64").await,
            (StatusCode::OK, "http://gw.example/api/nodes/x?q=%64".into())
        );
        assert_eq!(
            send_path(&app, "GET", "http://gw.example/api/%69nternal/x")
                .await
                .0,
            StatusCode::NOT_FOUND
        );
    }

    // -- The gateway's stack: canonical paths, then auth, then CSRF ------

    /// Canonicalization in front of the auth and CSRF middleware, as the
    /// gateway layers them, over an admin-only route, two auth routes and
    /// a fallback standing in for the proxy.
    fn protected_gateway(state: &std::sync::Arc<crate::AppState>) -> Router {
        use crate::auth::rbac::Role;
        use crate::middleware::auth::{auth_middleware, require_auth};
        use crate::middleware::csrf::csrf_middleware;
        use axum::routing::post;
        use std::sync::Arc;

        with_canonical_paths(
            Router::new()
                .route(
                    "/api/admin/users",
                    post(|req: Request<Body>| async move {
                        match require_auth(&req, Role::Admin) {
                            Ok(_) => "admin-handler".into_response(),
                            Err(status) => status.into_response(),
                        }
                    }),
                )
                .route(
                    "/api/auth/change-password",
                    post(|| async { "change-password" }),
                )
                .route("/api/auth/logout", post(|| async { "logout" }))
                .route("/api/auth/mfa/setup", post(|| async { "mfa-setup" }))
                .fallback(
                    |req: Request<Body>| async move { format!("proxied:{}", req.uri().path()) },
                )
                .layer(axum::middleware::from_fn_with_state(
                    Arc::clone(state),
                    csrf_middleware,
                ))
                .layer(axum::middleware::from_fn_with_state(
                    Arc::clone(state),
                    auth_middleware,
                ))
                .with_state(Arc::clone(state)),
        )
    }

    async fn post_with(
        app: &Router,
        path: &str,
        cookie: &str,
        csrf: Option<&str>,
    ) -> (StatusCode, String) {
        let mut req = Request::post(path).header("cookie", cookie);
        if let Some(token) = csrf {
            req = req.header("x-csrf-token", token);
        }
        let resp = app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    /// K3/K9: a restricted session cannot leave its scope, a session
    /// cannot skip the CSRF check and nobody reaches the internal API by
    /// spelling a path so that a scope, exemption or public-path check
    /// sees one path while the handler (or the bridge) gets another.
    /// Escapes that are harmless are decoded first, so every check sees
    /// the path the handler serves.
    #[tokio::test]
    async fn protected_routes_cannot_be_reached_through_path_tricks() {
        use crate::middleware::auth::{SCOPE_MFA_SETUP_ONLY, SCOPE_PASSWORD_CHANGE_ONLY};
        use crate::ws::test_harness as h;

        let dir = tempfile::tempdir().unwrap();
        let state = crate::test_support::app_state(&dir);
        state.auth_config.write().await.csrf_enabled = true;
        let app = protected_gateway(&state);
        let csrf = "csrf_token=t1";
        let restricted = format!(
            "session_token={}; {csrf}",
            h::session_with(&state, "pw", "admin", "", SCOPE_PASSWORD_CHANGE_ONLY)
        );
        let full = format!("session_token={}", h::session_for(&state, "full", "admin"));

        // A password_change_only session: the allowed route, however its
        // harmless escapes are spelled, and nothing beyond it.
        for path in ["/api/auth/change-password", "/api/auth/%63hange-password"] {
            assert_eq!(
                post_with(&app, path, &restricted, Some("t1")).await,
                (StatusCode::OK, "change-password".into()),
                "{path}"
            );
        }
        for path in [
            "/api/auth/change-password/../../admin/users",
            "/api/auth/change-password/%2E%2E/%2E%2E/admin/users",
            "/api/auth/change-password/.%2e/.%2e/admin/users",
            "/api/auth/change-password%2F..%2F..%2Fadmin%2Fusers",
            "/api/auth/change-password\\..\\..\\admin\\users",
            "/api/auth//change-password",
            "/health/../api/admin/users",
            "/api/auth/login/%2E%2E/%2E%2E/admin/users",
        ] {
            let (status, body) = post_with(&app, path, &restricted, Some("t1")).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
        }
        let (status, body) = post_with(&app, "/api/admin/%75sers", &restricted, Some("t1")).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body, r#"{"detail":"password change required"}"#);

        // An mfa_setup_only session is allowed a whole prefix
        // (`/api/auth/mfa/`), so dot segments under it are the way out it
        // would take: refused before any scope check sees them.
        let mfa = format!(
            "session_token={}; {csrf}",
            h::session_with(&state, "mfa", "admin", "", SCOPE_MFA_SETUP_ONLY)
        );
        assert_eq!(
            post_with(&app, "/api/auth/mfa/%73etup", &mfa, Some("t1")).await,
            (StatusCode::OK, "mfa-setup".into())
        );
        for path in [
            "/api/auth/mfa/../../admin/users",
            "/api/auth/mfa/%2E%2E/%2E%2E/admin/users",
            "/api/auth/mfa/.%2e/.%2e/admin/users",
        ] {
            let (status, body) = post_with(&app, path, &mfa, Some("t1")).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
            assert_eq!(body, r#"{"detail":"Invalid path"}"#, "{path}");
        }
        let (status, body) = post_with(&app, "/api/admin/%75sers", &mfa, Some("t1")).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(
            body,
            r#"{"detail":"MFA setup required before accessing other endpoints"}"#
        );

        // A full session without the CSRF token: an exempt path is exempt
        // only when it is the path served.
        let (status, body) = post_with(&app, "/api/admin/users", &full, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, r#"{"detail":"CSRF token missing or mismatch"}"#);
        assert_eq!(
            post_with(&app, "/api/auth/%6Cogout", &full, None).await,
            (StatusCode::OK, "logout".into())
        );
        for path in [
            "/api/auth/logout/../../admin/users",
            "/api/auth/logout/%2e%2e/%2e%2e/admin/users",
            "/api/auth/logout%2F..%2F..%2Fadmin%2Fusers",
            "/api/auth/logout\\..\\..\\admin\\users",
            "/api/auth/login/../../admin/users",
            "/api/detections/batch/../../admin/users",
        ] {
            let (status, body) = post_with(&app, path, &full, None).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
        }
        let (status, _) =
            post_with(&app, "/api/admin/users?next=/api/auth/logout", &full, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // With the token the admin route is reached (the control case).
        let both = format!("{full}; {csrf}");
        assert_eq!(
            post_with(&app, "/api/admin/%75sers", &both, Some("t1")).await,
            (StatusCode::OK, "admin-handler".into())
        );

        // The internal API is never served, whatever the credentials.
        for path in [
            "/api/internal/bind-node-key",
            "/api/%69nternal/bind-node-key",
            "/API/Internal/ingest-hook",
            "/api/x/%2E%2E/internal/ingest-hook",
            "/api%5Cinternal%5Cbind-node-key",
        ] {
            let (status, body) = post_with(&app, path, &both, Some("t1")).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {body}");
            assert!(!body.starts_with("proxied:"), "{path}: {body}");
        }
    }
}
