//! Security headers middleware.
//!
//! Applies standard security headers to every response:
//! - Content-Security-Policy
//! - X-Frame-Options
//! - X-Content-Type-Options
//! - Referrer-Policy
//! - Permissions-Policy
//! - Strict-Transport-Security (HTTPS only)
//!
//! Also injects a correlation ID (`X-Request-ID`) into every request/response
//! for distributed tracing.

use axum::{
    body::Body,
    http::{header::HeaderName, HeaderValue, Request, Response},
};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tower::{Layer, Service};

/// Configuration for security headers.
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub csp_mode: CspMode,
    pub hsts_enabled: bool,
    pub tls_active: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CspMode {
    Strict,
    ReportOnly,
    Disabled,
}

impl From<&str> for CspMode {
    /// Parse a `UC_CSP_MODE` value; unknown values mean `Strict`.
    fn from(s: &str) -> Self {
        match s {
            "report-only" => Self::ReportOnly,
            "disabled" => Self::Disabled,
            _ => Self::Strict,
        }
    }
}

// The reviewed policy. The bridge sends the same one when it runs without a
// gateway (`_CSP_VALUE` in src/sigrift/bridge/app.py); the shared table
// testdata/security_headers_parity.json pins both. Scripts load only from
// this origin: the pages have no inline script, event-handler attribute or
// `javascript:` URL, so markup injected into a page cannot run script.
// Styles keep 'unsafe-inline' for the templates' style attributes.
const CSP_DIRECTIVES: &str = "\
default-src 'self'; \
script-src 'self'; \
object-src 'none'; \
style-src 'self' 'unsafe-inline'; \
img-src 'self' data: https://*.tile.openstreetmap.org; \
connect-src 'self' wss: ws:; \
font-src 'self'; \
frame-ancestors 'none'; \
base-uri 'self'; \
form-action 'self'";

// ---------------------------------------------------------------------------
// Layer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SecurityHeadersLayer {
    config: SecurityConfig,
}

impl SecurityHeadersLayer {
    pub fn new(config: SecurityConfig) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for SecurityHeadersLayer {
    type Service = SecurityHeadersMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityHeadersMiddleware {
            inner,
            config: self.config.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Middleware service
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SecurityHeadersMiddleware<S> {
    inner: S,
    config: SecurityConfig,
}

impl<S> Service<Request<Body>> for SecurityHeadersMiddleware<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Send + Clone + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        // Inject X-Request-ID if not present
        let req_id = if let Some(existing) = req.headers().get("x-request-id") {
            existing.clone()
        } else {
            let id = uuid::Uuid::new_v4().to_string();
            let val =
                HeaderValue::from_str(&id).unwrap_or_else(|_| HeaderValue::from_static("unknown"));
            req.headers_mut()
                .insert(HeaderName::from_static("x-request-id"), val.clone());
            val
        };

        let config = self.config.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let mut resp = inner.call(req).await?;
            let headers = resp.headers_mut();

            // X-Request-ID (echo back)
            headers.insert(HeaderName::from_static("x-request-id"), req_id);

            // X-Content-Type-Options
            headers.insert(
                HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static("nosniff"),
            );

            // X-Frame-Options
            headers.insert(
                HeaderName::from_static("x-frame-options"),
                HeaderValue::from_static("DENY"),
            );

            // Referrer-Policy
            headers.insert(
                HeaderName::from_static("referrer-policy"),
                HeaderValue::from_static("strict-origin-when-cross-origin"),
            );

            // Permissions-Policy (restrictive)
            headers.insert(
                HeaderName::from_static("permissions-policy"),
                HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
            );

            // X-DNS-Prefetch-Control
            headers.insert(
                HeaderName::from_static("x-dns-prefetch-control"),
                HeaderValue::from_static("off"),
            );

            // Prevent browser from caching HTML pages (forces fresh JS loads)
            if !headers.contains_key("cache-control") {
                headers.insert(
                    HeaderName::from_static("cache-control"),
                    HeaderValue::from_static("no-cache, no-store, must-revalidate"),
                );
                headers.insert(
                    HeaderName::from_static("pragma"),
                    HeaderValue::from_static("no-cache"),
                );
            }

            // Content-Security-Policy: always the gateway's. A backend's policy
            // (or report-only policy) is replaced, never merged, so a backend
            // cannot weaken it; UC_CSP_MODE=report-only or disabled is the
            // operator's escape hatch.
            {
                // Remove the backend's CSP if present
                headers.remove("content-security-policy");
                headers.remove("content-security-policy-report-only");
                match config.csp_mode {
                    CspMode::Strict => {
                        headers.insert(
                            HeaderName::from_static("content-security-policy"),
                            HeaderValue::from_static(CSP_DIRECTIVES),
                        );
                    }
                    CspMode::ReportOnly => {
                        headers.insert(
                            HeaderName::from_static("content-security-policy-report-only"),
                            HeaderValue::from_static(CSP_DIRECTIVES),
                        );
                    }
                    CspMode::Disabled => {}
                }
            }

            // HSTS (only when TLS is active)
            if config.hsts_enabled && config.tls_active {
                headers.insert(
                    HeaderName::from_static("strict-transport-security"),
                    HeaderValue::from_static("max-age=31536000; includeSubDomains"),
                );
            }

            Ok(resp)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppState;
    use axum::{
        http::{HeaderMap, Method, StatusCode},
        response::AppendHeaders,
        routing::get,
        Router,
    };
    use std::sync::Arc;
    use tower::ServiceExt as _;

    /// The reviewed policy, written out by hand rather than taken from
    /// [`CSP_DIRECTIVES`]: a test that compares the header with the
    /// production constant passes whatever the constant says. A change to
    /// the policy has to be made here too, on purpose, and in the table
    /// the bridge is pinned to ([`SECURITY_HEADERS_TABLE`]).
    const EXPECTED_CSP: &str = "default-src 'self'; \
        script-src 'self'; \
        object-src 'none'; \
        style-src 'self' 'unsafe-inline'; \
        img-src 'self' data: https://*.tile.openstreetmap.org; \
        connect-src 'self' wss: ws:; \
        font-src 'self'; \
        frame-ancestors 'none'; \
        base-uri 'self'; \
        form-action 'self'";

    /// The reviewed Content-Security-Policy and Permissions-Policy, shared
    /// with the bridge (`tests/bridge/test_security_headers_parity.py`),
    /// which sends them itself when no gateway is in front of it.
    const SECURITY_HEADERS_TABLE: &str =
        include_str!("../../testdata/security_headers_parity.json");

    /// `policy` as (directive, sources) pairs, in order.
    fn csp_directives(policy: &str) -> Vec<(&str, Vec<&str>)> {
        policy
            .split(';')
            .map(str::trim)
            .filter(|d| !d.is_empty())
            .map(|d| {
                let mut tokens = d.split_ascii_whitespace();
                let name = tokens.next().unwrap();
                (name, tokens.collect())
            })
            .collect()
    }

    /// The headers every response carries whatever the CSP/HSTS settings,
    /// with the gateway's value.
    const PROTECTIVE: [(&str, &str); 5] = [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "strict-origin-when-cross-origin"),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=(), payment=()",
        ),
        ("x-dns-prefetch-control", "off"),
    ];
    const HSTS: &str = "max-age=31536000; includeSubDomains";

    fn app(config: SecurityConfig) -> Router {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .route(
                "/cached",
                get(|| async {
                    (
                        [
                            ("cache-control", "max-age=60"),
                            ("content-security-policy", "default-src *"),
                            ("content-security-policy-report-only", "default-src *"),
                        ],
                        "ok",
                    )
                }),
            )
            // A backend trying to weaken every protective header, some
            // of them twice.
            .route(
                "/weak",
                get(|| async {
                    (
                        AppendHeaders([
                            ("x-content-type-options", "sniff"),
                            ("x-frame-options", "ALLOWALL"),
                            ("x-frame-options", "SAMEORIGIN"),
                            ("referrer-policy", "unsafe-url"),
                            ("permissions-policy", "camera=*"),
                            ("x-dns-prefetch-control", "on"),
                            ("strict-transport-security", "max-age=0"),
                            ("content-security-policy", "default-src *"),
                            ("content-security-policy", "script-src *"),
                            ("x-request-id", "chosen-by-backend"),
                        ]),
                        "ok",
                    )
                }),
            )
            .route(
                "/fail",
                get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "boom") }),
            )
            .layer(SecurityHeadersLayer::new(config))
    }

    fn config(csp_mode: CspMode, hsts_enabled: bool, tls_active: bool) -> SecurityConfig {
        SecurityConfig {
            csp_mode,
            hsts_enabled,
            tls_active,
        }
    }

    async fn send(app: Router, req: Request<Body>) -> (StatusCode, HeaderMap) {
        let resp = app.oneshot(req).await.unwrap();
        (resp.status(), resp.headers().clone())
    }

    async fn get_headers(app: Router, uri: &str, req_id: Option<&str>) -> HeaderMap {
        let mut builder = Request::get(uri);
        if let Some(id) = req_id {
            builder = builder.header("x-request-id", id);
        }
        let (status, headers) = send(app, builder.body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::OK);
        headers
    }

    /// Every value of header `name`.
    fn values<'a>(h: &'a HeaderMap, name: &str) -> Vec<&'a str> {
        h.get_all(name)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect()
    }

    /// The protective headers and the strict CSP, each exactly once with
    /// the gateway's value.
    fn assert_protected(h: &HeaderMap, context: &str) {
        for (name, value) in PROTECTIVE {
            assert_eq!(values(h, name), [value], "{context}: {name}");
        }
        assert_eq!(
            values(h, "content-security-policy"),
            [EXPECTED_CSP],
            "{context}"
        );
        assert!(
            h.get("content-security-policy-report-only").is_none(),
            "{context}"
        );
    }

    #[test]
    fn unknown_csp_mode_fails_closed_to_strict() {
        assert_eq!(CspMode::from("report-only"), CspMode::ReportOnly);
        assert_eq!(CspMode::from("disabled"), CspMode::Disabled);
        assert_eq!(CspMode::from("strict"), CspMode::Strict);
        // Typos and case variants must not disable the policy.
        assert_eq!(CspMode::from("Disabled"), CspMode::Strict);
        assert_eq!(CspMode::from("off"), CspMode::Strict);
        assert_eq!(CspMode::from(""), CspMode::Strict);
    }

    /// The policy is the reviewed one, and no directive of it allows any
    /// origin (`*`) or `eval`. Scripts and the fallback load only from
    /// the gateway's own origin, with no inline script, event-handler
    /// attribute or `javascript:` URL; plugins and framing are refused
    /// outright.
    #[test]
    fn strict_csp_is_the_reviewed_policy() {
        assert_eq!(CSP_DIRECTIVES, EXPECTED_CSP);

        let directives = csp_directives(CSP_DIRECTIVES);
        // Exactly these directives, written out here: a new one added to
        // the constant, EXPECTED_CSP and the shared table alike fails. The
        // CSP3 script-src-elem and script-src-attr in particular take
        // precedence over script-src for <script> elements and handler
        // attributes, so either could re-allow inline script.
        let names: Vec<&str> = directives.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            [
                "default-src",
                "script-src",
                "object-src",
                "style-src",
                "img-src",
                "connect-src",
                "font-src",
                "frame-ancestors",
                "base-uri",
                "form-action",
            ]
        );
        for (name, sources) in &directives {
            for forbidden in [
                "*",
                "'unsafe-eval'",
                "'wasm-unsafe-eval'",
                "'unsafe-hashes'",
                "'strict-dynamic'",
            ] {
                assert!(!sources.contains(&forbidden), "{name} allows {forbidden}");
            }
            for source in sources {
                assert!(
                    !source.starts_with("'nonce-") && !source.starts_with("'sha"),
                    "{name} allows {source}"
                );
            }
            // Inline styles only, until the templates' style attributes move
            // to stylesheets.
            if *name != "style-src" {
                assert!(
                    !sources.contains(&"'unsafe-inline'"),
                    "{name} allows 'unsafe-inline'"
                );
            }
        }
        let sources = |wanted: &str| {
            directives
                .iter()
                .find(|(name, _)| *name == wanted)
                .map(|(_, sources)| sources.clone())
                .unwrap_or_else(|| panic!("no {wanted} directive"))
        };
        assert_eq!(sources("default-src"), ["'self'"]);
        assert_eq!(sources("frame-ancestors"), ["'none'"]);
        assert_eq!(sources("base-uri"), ["'self'"]);
        assert_eq!(sources("form-action"), ["'self'"]);
        // Scripts only from the origin: no host or scheme source, and none
        // of 'unsafe-inline', 'unsafe-hashes' or a nonce/hash that would
        // let injected markup run.
        assert_eq!(sources("script-src"), ["'self'"]);
        // No plugin content (<object>, <embed>), which default-src would
        // otherwise allow from the origin.
        assert_eq!(sources("object-src"), ["'none'"]);
    }

    /// The gateway's policy is the one the bridge sends when it runs
    /// without a gateway: the shared table holds both values, and the
    /// bridge's test reads the same file.
    #[test]
    fn headers_match_the_shared_table() {
        let table: serde_json::Value = serde_json::from_str(SECURITY_HEADERS_TABLE).unwrap();
        let csp = table["content-security-policy"].as_str().unwrap();
        assert_eq!(csp, EXPECTED_CSP);
        assert_eq!(CSP_DIRECTIVES, csp);
        let permissions = PROTECTIVE
            .iter()
            .find(|(name, _)| *name == "permissions-policy")
            .map(|(_, value)| *value)
            .unwrap();
        assert_eq!(table["permissions-policy"].as_str().unwrap(), permissions);
    }

    #[tokio::test]
    async fn strict_mode_sets_all_protective_headers() {
        let h = get_headers(app(config(CspMode::Strict, true, false)), "/", None).await;
        assert_protected(&h, "/");
        assert_eq!(h["cache-control"], "no-cache, no-store, must-revalidate");
        assert_eq!(h["pragma"], "no-cache");
        // A request id is generated (UUID v4).
        let id = h["x-request-id"].to_str().unwrap();
        assert!(uuid::Uuid::parse_str(id).is_ok(), "{id}");
    }

    #[tokio::test]
    async fn backend_csp_is_replaced_and_cache_control_kept() {
        let h = get_headers(app(config(CspMode::Strict, false, true)), "/cached", None).await;
        // A weaker backend CSP (or report-only policy) never survives.
        assert_protected(&h, "/cached");
        // A backend's own cache policy is left alone.
        assert_eq!(h["cache-control"], "max-age=60");
        assert!(h.get("pragma").is_none());
    }

    #[tokio::test]
    async fn report_only_and_disabled_modes() {
        let h = get_headers(
            app(config(CspMode::ReportOnly, false, false)),
            "/cached",
            None,
        )
        .await;
        assert!(h.get("content-security-policy").is_none());
        assert_eq!(
            values(&h, "content-security-policy-report-only"),
            [EXPECTED_CSP]
        );

        let h = get_headers(
            app(config(CspMode::Disabled, false, false)),
            "/cached",
            None,
        )
        .await;
        // Disabled removes the backend's CSP too, but the other headers stay.
        assert!(h.get("content-security-policy").is_none());
        assert!(h.get("content-security-policy-report-only").is_none());
        for (name, value) in PROTECTIVE {
            assert_eq!(values(&h, name), [value], "{name}");
        }
    }

    /// HSTS is sent only when it is enabled and the connection is TLS:
    /// never over plaintext, never when the operator turned it off.
    #[tokio::test]
    async fn hsts_only_when_enabled_and_tls_active() {
        for (hsts_enabled, tls_active) in
            [(true, true), (true, false), (false, true), (false, false)]
        {
            let h = get_headers(
                app(config(CspMode::Strict, hsts_enabled, tls_active)),
                "/",
                None,
            )
            .await;
            let expected: &[&str] = if hsts_enabled && tls_active {
                &[HSTS]
            } else {
                &[]
            };
            assert_eq!(
                values(&h, "strict-transport-security"),
                expected,
                "hsts_enabled={hsts_enabled} tls_active={tls_active}"
            );
        }
    }

    /// A backend cannot weaken a protective header: every one is replaced
    /// by the gateway's single value, HSTS included.
    #[tokio::test]
    async fn weaker_backend_headers_are_overridden() {
        let h = get_headers(
            app(config(CspMode::Strict, true, true)),
            "/weak",
            Some("trace-7"),
        )
        .await;
        assert_protected(&h, "/weak");
        assert_eq!(values(&h, "strict-transport-security"), [HSTS]);
        // The correlation id is the request's, not the backend's.
        assert_eq!(values(&h, "x-request-id"), ["trace-7"]);
    }

    /// Error responses made inside the layer — no route, wrong method, a
    /// failing handler — carry the same protective headers. (In the served
    /// app the layer wraps every other layer, so the refusals of the auth
    /// and CSRF middlewares, the body limit and the path canonicalization
    /// carry them too: `builder::security_header_tests`.)
    #[tokio::test]
    async fn error_responses_carry_security_headers() {
        let cases = [
            (Method::GET, "/missing", StatusCode::NOT_FOUND),
            (Method::POST, "/", StatusCode::METHOD_NOT_ALLOWED),
            (Method::GET, "/fail", StatusCode::INTERNAL_SERVER_ERROR),
        ];
        for (method, uri, expected) in cases {
            let req = Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap();
            let (status, h) = send(app(config(CspMode::Strict, true, true)), req).await;
            assert_eq!(status, expected, "{uri}");
            assert_protected(&h, uri);
            assert_eq!(values(&h, "strict-transport-security"), [HSTS], "{uri}");
            assert_eq!(
                h["cache-control"], "no-cache, no-store, must-revalidate",
                "{uri}"
            );
            assert!(h.get("x-request-id").is_some(), "{uri}");
        }
    }

    /// The layer wraps the proxy fallback: proxied responses (whatever
    /// headers the backend sent) and the responses the proxy handler makes
    /// itself — its path refusals, a 413 for a body it reads past the
    /// limit, 502 — carry the protective headers.
    ///
    /// In the production router most of these refusals are made before the
    /// handler (but still inside this layer): `canonicalize_path` answers
    /// the `..` and `/api/internal` requests, and `RequestBodyLimitLayer` a
    /// body whose declared Content-Length is over the limit (see
    /// `builder::security_header_tests`). There, the handler's own 400/404
    /// are defence in depth, and its 413 is for a body sent without a
    /// declared length.
    #[tokio::test]
    async fn proxied_and_proxy_error_responses_carry_security_headers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_url = format!("http://{}", listener.local_addr().unwrap());
        let backend = Router::new().fallback(|| async {
            (
                [
                    ("x-frame-options", "ALLOWALL"),
                    ("content-security-policy", "default-src *"),
                ],
                "from-backend",
            )
        });
        let server = tokio::spawn(async move { axum::serve(listener, backend).await.unwrap() });

        let gateway = |dir: &tempfile::TempDir, python_url: &str| {
            let mut state = crate::test_support::app_state(dir);
            let s: &mut AppState = Arc::get_mut(&mut state).unwrap();
            s.config.python_url = python_url.to_string();
            s.config.max_body_size = 4;
            Router::new()
                .fallback(crate::proxy::handler::proxy_fallback)
                .layer(SecurityHeadersLayer::new(config(
                    CspMode::Strict,
                    true,
                    true,
                )))
                .with_state(state)
        };
        let dir = tempfile::tempdir().unwrap();
        let up = gateway(&dir, &backend_url);
        let down_dir = tempfile::tempdir().unwrap();
        let down = gateway(&down_dir, crate::test_support::REFUSED_URL);

        let get = |uri: &str| Request::get(uri).body(Body::empty()).unwrap();
        let cases = [
            (&up, get("/api/x"), StatusCode::OK),
            (&up, get("/api/../x"), StatusCode::BAD_REQUEST),
            (&up, get("/api/internal/keys"), StatusCode::NOT_FOUND),
            (
                &up,
                Request::post("/api/x").body(Body::from("12345")).unwrap(),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                &up,
                Request::get("/api/x")
                    .header("upgrade", "websocket")
                    .body(Body::empty())
                    .unwrap(),
                StatusCode::BAD_GATEWAY,
            ),
            (&down, get("/api/x"), StatusCode::BAD_GATEWAY),
        ];
        for (app, req, expected) in cases {
            let context = format!("{} {}", req.method(), req.uri());
            let (status, h) = send(app.clone(), req).await;
            assert_eq!(status, expected, "{context}");
            assert_protected(&h, &context);
            assert_eq!(values(&h, "strict-transport-security"), [HSTS], "{context}");
        }
        server.abort();
    }
}
