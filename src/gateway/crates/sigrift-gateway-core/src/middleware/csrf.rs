//! CSRF protection for mutating requests, by the credential that
//! authenticated them.
//!
//! * **A session** needs the double-submit token while CSRF protection is
//!   on: an `X-CSRF-Token` header equal to the `csrf_token` cookie.
//!   Replicates Python's CSRF enforcement from app.py:443-486. Unlike the
//!   bridge, the gateway exempts neither the batch ingest paths nor a
//!   mutating request that carries `Upgrade: websocket` (see
//!   `CSRF_EXEMPT_PATHS` and `required_check`).
//! * **A client certificate** is refused when the browser's `Origin` is
//!   another origin than this one and is not listed in `UC_CORS_ORIGINS`
//!   (`ws::auth::origin_allowed`, the rule a WebSocket handshake gets). A
//!   browser that holds a certificate presents it on any TLS handshake to
//!   this host, whichever page started the request, and SameSite does not
//!   apply to it, so the `Origin` check holds whether CSRF protection is on
//!   or off. An agent sends no `Origin` and needs no token.
//! * **An API key** is never checked: a browser does not add one by itself.

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::warn;

use super::auth::{authenticating_client_cert, AuthInfo};
use crate::auth::client_cert::ClientCertInfo;
use crate::ws::auth::{origin_allowed, warn_cross_origin, Listener};
use crate::AppState;

/// Paths exempt from CSRF validation.
///
/// The bridge's list (app.py) also exempts the batch ingest paths,
/// `/api/detections/batch` and `/batch`. The gateway does not: it serves
/// them itself and accepts an ANALYST-or-above session there (for any
/// node), so a session batch needs the token like any other session
/// mutation. Edge ingest is unaffected: API keys and client certificates
/// never need the token, and an agent's certificate batch carries no
/// `Origin` for the certificate's `Origin` check to refuse.
const CSRF_EXEMPT_PATHS: &[&str] = &[
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/mfa/verify",
    "/api/version",
    "/api/health",
    "/health",
];

/// CSRF middleware: the double-submit token for a session's mutating
/// request, the `Origin` check for a client certificate's (see the module
/// documentation).
pub async fn csrf_middleware(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let csrf_enabled = {
        let cfg = state.auth_config.read().await;
        cfg.csrf_enabled
    };
    match required_check(csrf_enabled, &req) {
        Check::Nothing => {}
        Check::Token => {
            let csrf_cookie = extract_csrf_cookie(&req);
            let csrf_header = req
                .headers()
                .get("x-csrf-token")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            if !csrf_tokens_match(&csrf_cookie, &csrf_header) {
                warn!("CSRF validation failed: cookie/header missing or mismatch");
                return (
                    StatusCode::FORBIDDEN,
                    axum::Json(serde_json::json!({"detail": "CSRF token missing or mismatch"})),
                )
                    .into_response();
            }
        }
        Check::Origin(cert) => {
            let peer = req
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(peer)| *peer);
            // A verified certificate only arrives over the gateway's own
            // TLS listener, so this origin's scheme is https (or what a
            // trusted proxy's X-Forwarded-Proto says), as on a WebSocket.
            let listener =
                Listener::of(true, peer, &state.auth_config.read().await.trusted_proxies);
            if !origin_allowed(
                req.headers(),
                req.uri(),
                &state.config.cors_origins,
                listener,
            ) {
                warn_cross_origin(
                    "Request refused",
                    &cert.identity,
                    "a client certificate",
                    req.headers(),
                    req.uri(),
                    listener,
                );
                return (
                    StatusCode::FORBIDDEN,
                    axum::Json(serde_json::json!({"detail": "Cross-origin request refused"})),
                )
                    .into_response();
            }
        }
    }

    next.run(req).await
}

/// The double-submit check: both tokens present and equal, compared in
/// constant time so the time a refusal takes says nothing about how much
/// of a guessed token matched.
fn csrf_tokens_match(cookie: &str, header: &str) -> bool {
    !cookie.is_empty()
        && !header.is_empty()
        && constant_time_eq::constant_time_eq(cookie.as_bytes(), header.as_bytes())
}

/// What a request must pass before it goes on.
#[derive(Debug)]
enum Check<'a> {
    /// Nothing: a safe method, an exempt path, an API key, no credential,
    /// or a session while CSRF protection is off.
    Nothing,
    /// The double-submit token: a session's mutating request while CSRF
    /// protection is on.
    Token,
    /// The browser `Origin`: a mutating request that this verified client
    /// certificate authenticated, whether CSRF protection is on or off.
    Origin(&'a ClientCertInfo),
}

fn required_check(csrf_enabled: bool, req: &Request<Body>) -> Check<'_> {
    // Only mutating methods. A WebSocket handshake is a GET (RFC 6455),
    // so it is exempt here; the Origin check in `ws::auth` is its CSRF
    // defence. An `Upgrade` header exempts nothing else: on a POST, PUT,
    // PATCH or DELETE it is no handshake. (The bridge still skips any
    // request with `Upgrade: websocket`, but the gateway never forwards
    // one to it: the HTTP proxy answers those with 502.)
    let method = req.method();
    if *method == Method::GET || *method == Method::HEAD || *method == Method::OPTIONS {
        return Check::Nothing;
    }

    // Check exempt paths
    if CSRF_EXEMPT_PATHS.contains(&req.uri().path()) {
        return Check::Nothing;
    }

    // By the credential. A client certificate also resolves to `ApiKey`,
    // when the request carries no API key.
    match req.extensions().get::<AuthInfo>() {
        Some(AuthInfo::Session { .. }) if csrf_enabled => Check::Token,
        Some(AuthInfo::ApiKey { .. }) => {
            authenticating_client_cert(req).map_or(Check::Nothing, Check::Origin)
        }
        _ => Check::Nothing,
    }
}

/// Whether `req` needs the double-submit token.
#[cfg(test)]
fn should_enforce_csrf(csrf_enabled: bool, req: &Request<Body>) -> bool {
    matches!(required_check(csrf_enabled, req), Check::Token)
}

fn extract_csrf_cookie(req: &Request<Body>) -> String {
    // HTTP/2 permits each cookie to arrive in its own Cookie field.
    for cookie_header in req.headers().get_all("cookie").iter() {
        if let Ok(cookies) = cookie_header.to_str() {
            for part in cookies.split(';') {
                let part = part.trim();
                if let Some(val) = part.strip_prefix("csrf_token=") {
                    return val.trim().to_string();
                }
            }
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    /// A timing test would be flaky, so the property is checked in the
    /// source: the double-submit check compares the cookie and the header
    /// only with `constant_time_eq` (it compared them with `!=`, whose
    /// early exit leaks how much of a guess matched), and the middleware
    /// leaves the comparison to it.
    #[test]
    fn csrf_tokens_are_compared_in_constant_time() {
        use crate::auth::totp::tests::{assert_constant_time_compares, fn_body};
        let src = include_str!("csrf.rs");
        assert_constant_time_compares("csrf_tokens_match", fn_body(src, "csrf_tokens_match"), 1);
        let middleware = fn_body(src, "csrf_middleware");
        assert!(middleware.contains("csrf_tokens_match(&csrf_cookie, &csrf_header)"));
        assert!(!middleware.contains("csrf_cookie != csrf_header"));
    }

    #[test]
    fn test_extract_csrf_cookie_present() {
        let req = Request::builder()
            .uri("/test")
            .header(
                "cookie",
                "session_token=abc; csrf_token=mytoken123; other=val",
            )
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_csrf_cookie(&req), "mytoken123");
    }

    #[test]
    fn test_extract_csrf_cookie_absent() {
        let req = Request::builder()
            .uri("/test")
            .header("cookie", "session_token=abc")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_csrf_cookie(&req), "");
    }

    #[test]
    fn test_extract_csrf_cookie_no_header() {
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        assert_eq!(extract_csrf_cookie(&req), "");
    }

    #[tokio::test]
    async fn csrf_validates_all_cookie_fields_without_weakening_mismatch_checks() {
        use axum::{http::header, middleware, routing::post, Router};
        use tower::ServiceExt;

        let dir = tempfile::tempdir().unwrap();
        let state = crate::test_support::app_state(&dir);
        state.auth_config.write().await.csrf_enabled = true;
        let app = Router::new()
            .route("/api/change", post(|| async { StatusCode::NO_CONTENT }))
            .layer(middleware::from_fn_with_state(state, csrf_middleware));
        let cases: &[(&[&str], &str, StatusCode)] = &[
            (
                &["session_token=session; csrf_token=csrf"],
                "csrf",
                StatusCode::NO_CONTENT,
            ),
            (
                &["session_token=session", "csrf_token=csrf"],
                "csrf",
                StatusCode::NO_CONTENT,
            ),
            (
                &["csrf_token=csrf", "session_token=session"],
                "csrf",
                StatusCode::NO_CONTENT,
            ),
            (
                &["session_token=session", "theme=dark", "csrf_token=csrf"],
                "csrf",
                StatusCode::NO_CONTENT,
            ),
            (
                &["session_token=session", "csrf_token=csrf"],
                "wrong",
                StatusCode::FORBIDDEN,
            ),
            (
                &["session_token=session", "csrf_token=csrf"],
                "",
                StatusCode::FORBIDDEN,
            ),
            (
                &["session_token=session", "theme=dark"],
                "csrf",
                StatusCode::FORBIDDEN,
            ),
        ];
        for &(cookies, csrf_header, expected) in cases {
            let mut req = req_with_auth_info(
                "POST",
                "/api/change",
                AuthInfo::Session {
                    username: "u".into(),
                    user_id: 1,
                    role: crate::auth::rbac::Role::Admin,
                    session_token: "session".into(),
                    expires_at: "".into(),
                    tenant_id: "default".into(),
                    scope: String::new(),
                },
            );
            *req.version_mut() = axum::http::Version::HTTP_2;
            for cookie in cookies {
                req.headers_mut()
                    .append(header::COOKIE, (*cookie).parse().unwrap());
            }
            req.headers_mut()
                .insert("x-csrf-token", csrf_header.parse().unwrap());
            assert_eq!(app.clone().oneshot(req).await.unwrap().status(), expected);
        }
    }

    // ── should_enforce_csrf tests ─────────────────────────────────────

    fn req_with_auth_info(
        method: &str,
        path: &str,
        auth: super::super::auth::AuthInfo,
    ) -> Request<Body> {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(auth);
        req
    }

    #[test]
    fn test_csrf_skips_get_requests() {
        let req = req_with_auth_info(
            "GET",
            "/api/test",
            super::super::auth::AuthInfo::Session {
                username: "u".into(),
                user_id: 1,
                role: crate::auth::rbac::Role::Admin,
                session_token: "t".into(),
                expires_at: "".into(),
                tenant_id: "default".into(),
                scope: String::new(),
            },
        );
        assert!(!should_enforce_csrf(true, &req));
    }

    #[test]
    fn test_csrf_enforced_for_session_post() {
        let req = req_with_auth_info(
            "POST",
            "/api/some/endpoint",
            super::super::auth::AuthInfo::Session {
                username: "u".into(),
                user_id: 1,
                role: crate::auth::rbac::Role::Admin,
                session_token: "t".into(),
                expires_at: "".into(),
                tenant_id: "default".into(),
                scope: String::new(),
            },
        );
        assert!(should_enforce_csrf(true, &req));
    }

    #[test]
    fn test_csrf_skips_api_key_auth() {
        let req = req_with_auth_info(
            "POST",
            "/api/test",
            super::super::auth::AuthInfo::ApiKey {
                key_id: "k1".into(),
                role: crate::auth::rbac::Role::Admin,
            },
        );
        assert!(!should_enforce_csrf(true, &req));
    }

    #[test]
    fn test_csrf_skips_exempt_paths() {
        for path in CSRF_EXEMPT_PATHS {
            let req = req_with_auth_info(
                "POST",
                path,
                super::super::auth::AuthInfo::Session {
                    username: "u".into(),
                    user_id: 1,
                    role: crate::auth::rbac::Role::Admin,
                    session_token: "t".into(),
                    expires_at: "".into(),
                    tenant_id: "default".into(),
                    scope: String::new(),
                },
            );
            assert!(
                !should_enforce_csrf(true, &req),
                "Path {} should be exempt",
                path
            );
        }
    }

    #[test]
    fn test_csrf_skips_when_disabled() {
        let req = req_with_auth_info(
            "POST",
            "/api/test",
            super::super::auth::AuthInfo::Session {
                username: "u".into(),
                user_id: 1,
                role: crate::auth::rbac::Role::Admin,
                session_token: "t".into(),
                expires_at: "".into(),
                tenant_id: "default".into(),
                scope: String::new(),
            },
        );
        assert!(!should_enforce_csrf(false, &req));
    }

    #[test]
    fn test_csrf_skips_unauthenticated() {
        let req = req_with_auth_info(
            "POST",
            "/api/test",
            super::super::auth::AuthInfo::Unauthenticated,
        );
        assert!(!should_enforce_csrf(true, &req));
    }

    /// A WebSocket handshake is a GET (RFC 6455), exempt as a safe
    /// method. An `Upgrade` header, `websocket` included, exempts no
    /// mutating request, on any path.
    #[test]
    fn test_csrf_upgrade_header_exempts_no_other_mutation() {
        let with_upgrade = |method: &str, path: &str, upgrade: &str| {
            let mut req = req_with_auth_info("POST", path, admin_session());
            *req.method_mut() = method.parse().unwrap();
            req.headers_mut()
                .insert("upgrade", upgrade.parse().unwrap());
            req
        };
        for path in ["/ws/feed", "/api/admin/settings/security"] {
            for upgrade in ["websocket", "WebSocket"] {
                assert!(
                    !should_enforce_csrf(true, &with_upgrade("GET", path, upgrade)),
                    "GET {path} with Upgrade: {upgrade}"
                );
            }
            for method in ["POST", "PUT", "PATCH", "DELETE"] {
                for upgrade in [
                    "websocket",
                    "WebSocket",
                    "WEBSOCKET",
                    "h2c",
                    "websocket2",
                    "TLS/1.0",
                    "web socket",
                    "",
                ] {
                    assert!(
                        should_enforce_csrf(true, &with_upgrade(method, path, upgrade)),
                        "{method} {path} with Upgrade: {upgrade:?}"
                    );
                }
            }
        }
    }

    /// The batch ingest paths are not exempt: a session batch needs the
    /// token, while API keys and client certificates (both `ApiKey` to
    /// this middleware), the edge ingest path, still do not.
    #[test]
    fn batch_ingest_needs_the_token_for_a_session_only() {
        for path in ["/batch", "/api/detections/batch"] {
            assert!(!CSRF_EXEMPT_PATHS.contains(&path), "{path}");
            for role in [
                crate::auth::rbac::Role::Analyst,
                crate::auth::rbac::Role::Admin,
            ] {
                let session = AuthInfo::Session {
                    username: "u".into(),
                    user_id: 1,
                    role,
                    session_token: "t".into(),
                    expires_at: "".into(),
                    tenant_id: "default".into(),
                    scope: String::new(),
                };
                let req = req_with_auth_info("POST", path, session);
                assert!(should_enforce_csrf(true, &req), "{path} {role:?} session");
            }
            for role in [
                crate::auth::rbac::Role::Sensor,
                crate::auth::rbac::Role::Admin,
            ] {
                let key_or_cert = AuthInfo::ApiKey {
                    key_id: "edge-7".into(),
                    role,
                };
                let req = req_with_auth_info("POST", path, key_or_cert);
                assert!(!should_enforce_csrf(true, &req), "{path} {role:?} key");
            }
        }
    }

    /// A `method path` request the middleware resolved to an ADMIN
    /// `ApiKey`, carrying a verified certificate when `cert` and these
    /// headers.
    fn key_or_cert(
        method: &str,
        path: &str,
        cert: bool,
        headers: &[(&str, &str)],
    ) -> Request<Body> {
        let mut req = req_with_auth_info(
            method,
            path,
            AuthInfo::ApiKey {
                key_id: "ops-laptop".into(),
                role: crate::auth::rbac::Role::Admin,
            },
        );
        if cert {
            req.extensions_mut()
                .insert(crate::ws::test_harness::client_cert("ops-laptop"));
        }
        for (name, value) in headers {
            req.headers_mut().append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        req
    }

    /// A client certificate's mutating request gets the `Origin` check,
    /// whether CSRF protection is on or off, and never the token; its
    /// safe methods and the exempt paths get nothing. A request that
    /// carries an API key is the key's (the certificate did not decide),
    /// and so is an `ApiKey` without a certificate.
    #[test]
    fn a_client_certificate_mutation_gets_the_origin_check() {
        for csrf_enabled in [true, false] {
            for method in ["POST", "PUT", "PATCH", "DELETE"] {
                for path in ["/api/admin/users", "/batch", "/api/maps/upload"] {
                    let req = key_or_cert(method, path, true, &[]);
                    let check = required_check(csrf_enabled, &req);
                    assert!(
                        matches!(check, Check::Origin(cert) if cert.identity == "ops-laptop"),
                        "{csrf_enabled} {method} {path}: {check:?}"
                    );
                }
                for headers in [
                    &[("x-api-key", "sk-x")][..],
                    &[("authorization", "Bearer sk-x")],
                ] {
                    let req = key_or_cert(method, "/api/admin/users", true, headers);
                    let check = required_check(csrf_enabled, &req);
                    assert!(matches!(check, Check::Nothing), "{headers:?}: {check:?}");
                }
                let req = key_or_cert(method, "/api/admin/users?api_key=sk-x", true, &[]);
                let check = required_check(csrf_enabled, &req);
                assert!(matches!(check, Check::Nothing), "?api_key=: {check:?}");
                let req = key_or_cert(method, "/api/admin/users", false, &[]);
                let check = required_check(csrf_enabled, &req);
                assert!(matches!(check, Check::Nothing), "no certificate: {check:?}");
            }
            for method in ["GET", "HEAD", "OPTIONS"] {
                let req = key_or_cert(method, "/api/admin/users", true, &[]);
                let check = required_check(csrf_enabled, &req);
                assert!(matches!(check, Check::Nothing), "{method}: {check:?}");
            }
            for path in CSRF_EXEMPT_PATHS {
                let req = key_or_cert("POST", path, true, &[]);
                let check = required_check(csrf_enabled, &req);
                assert!(matches!(check, Check::Nothing), "{path}: {check:?}");
            }
        }
        // A session and a certificate on one request: the session decided
        // (the auth middleware tries it first), so the token applies.
        let mut req = req_with_auth_info("POST", "/api/admin/users", admin_session());
        req.extensions_mut()
            .insert(crate::ws::test_harness::client_cert("ops-laptop"));
        assert!(matches!(required_check(true, &req), Check::Token));
        assert!(matches!(required_check(false, &req), Check::Nothing));
    }

    /// The certificate's `Origin` check behind the auth middleware: this
    /// origin is https (a certificate only arrives over TLS) at the `Host`,
    /// or what a trusted proxy's `X-Forwarded-Proto` / `X-Forwarded-Host`
    /// say; from any other peer those headers are ignored.
    #[tokio::test]
    async fn the_certificate_origin_check_takes_forwarding_headers_from_a_trusted_proxy_only() {
        use crate::ws::test_harness as h;
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(
            &dir,
            crate::test_support::REFUSED_URL,
            &h::keys_file(&[]),
            None,
        );
        let registry = dir.path().join("registry.json");
        h::write_cert_registry(&registry, "ops-laptop", "admin", false);
        let state = h::with_cert_registry(state, &registry);
        state.auth_config.write().await.trusted_proxies =
            super::super::client_ip::TrustedProxies::parse("10.0.0.1").0;
        let app = behind_auth(&state);
        let proxy: SocketAddr = "10.0.0.1:40000".parse().unwrap();
        let other: SocketAddr = "10.0.0.2:40000".parse().unwrap();
        type Headers = &'static [(&'static str, &'static str)];
        const NONE: Headers = &[];
        const HTTPS: Headers = &[
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "ops.example"),
        ];
        const HTTP: Headers = &[
            ("x-forwarded-proto", "http"),
            ("x-forwarded-host", "ops.example"),
        ];
        let (allowed, refused) = (StatusCode::NO_CONTENT, StatusCode::FORBIDDEN);
        let cases: [(SocketAddr, &str, Headers, StatusCode); 7] = [
            (other, "https://gw.internal:8444", NONE, allowed),
            (other, "http://gw.internal:8444", NONE, refused),
            (other, "https://ops.example", HTTPS, refused),
            (proxy, "https://ops.example", HTTPS, allowed),
            (proxy, "https://ops.example", HTTP, refused),
            (proxy, "http://ops.example", HTTP, allowed),
            (proxy, "https://evil.example", HTTPS, refused),
        ];
        for (peer, origin, headers, expected) in cases {
            let mut req = Request::post("/api/change")
                .header("host", "gw.internal:8444")
                .header("origin", origin)
                .body(Body::empty())
                .unwrap();
            for (name, value) in headers {
                req.headers_mut().insert(*name, value.parse().unwrap());
            }
            req.extensions_mut().insert(h::client_cert("ops-laptop"));
            req.extensions_mut().insert(ConnectInfo(peer));
            assert_eq!(
                status_of(&app, req).await,
                expected,
                "{peer} {origin} {headers:?}"
            );
        }
    }

    // ── Middleware decisions ──────────────────────────────────────────

    fn admin_session() -> AuthInfo {
        AuthInfo::Session {
            username: "u".into(),
            user_id: 1,
            role: crate::auth::rbac::Role::Admin,
            session_token: "session".into(),
            expires_at: "".into(),
            tenant_id: "default".into(),
            scope: String::new(),
        }
    }

    /// The CSRF layer alone over a 204 fallback, CSRF on (the directory
    /// holds the state's database).
    async fn csrf_only_app() -> (tempfile::TempDir, axum::Router) {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::test_support::app_state(&dir);
        state.auth_config.write().await.csrf_enabled = true;
        let app = axum::Router::new()
            .fallback(|| async { StatusCode::NO_CONTENT })
            .layer(axum::middleware::from_fn_with_state(state, csrf_middleware));
        (dir, app)
    }

    /// A session POST to `path` with these Cookie fields and CSRF header.
    fn session_post(path: &str, cookies: &[&[u8]], csrf_header: Option<&str>) -> Request<Body> {
        let mut req = req_with_auth_info("POST", path, admin_session());
        *req.version_mut() = axum::http::Version::HTTP_2;
        for cookie in cookies {
            req.headers_mut().append(
                axum::http::header::COOKIE,
                axum::http::HeaderValue::from_bytes(cookie).unwrap(),
            );
        }
        if let Some(value) = csrf_header {
            req.headers_mut()
                .insert("x-csrf-token", value.parse().unwrap());
        }
        req
    }

    async fn status_of(app: &axum::Router, req: Request<Body>) -> StatusCode {
        use tower::ServiceExt as _;
        app.clone().oneshot(req).await.unwrap().status()
    }

    /// Only the exempt paths themselves skip the check: a trailing slash,
    /// another case, a longer name or a sub-path is checked, and a query
    /// string is not part of the path.
    #[tokio::test]
    async fn only_exact_exempt_paths_skip_the_check() {
        let (_dir, app) = csrf_only_app().await;
        for path in CSRF_EXEMPT_PATHS {
            let req = session_post(path, &[b"session_token=s"], None);
            assert_eq!(status_of(&app, req).await, StatusCode::NO_CONTENT, "{path}");
        }
        for near in [
            "/api/auth/login/",
            "/api/auth/loginx",
            "/API/AUTH/LOGIN",
            "/api/auth/Logout",
            "/api/auth/logout/all",
            "/api/auth/mfa/verify/",
            "/api/auth/mfa/verify/x",
            // Not exempt at all (the bridge's list has them).
            "/api/detections/batch",
            "/batch",
            "/api/detections/batch/",
            "/api/detections/batchx",
            "/api/detections/batch/../../admin/users",
            "/batch/",
            "/health/",
            "/api/health/x",
            "/api/version2",
            "/api/admin/users?next=/api/auth/login",
        ] {
            let req = session_post(near, &[b"session_token=s"], None);
            assert_eq!(status_of(&app, req).await, StatusCode::FORBIDDEN, "{near}");
        }
    }

    /// A cookie whose name merely contains `csrf_token` is not the CSRF
    /// cookie, so a header matching it does not pass.
    #[tokio::test]
    async fn only_the_csrf_token_cookie_counts() {
        let (_dir, app) = csrf_only_app().await;
        for cookie in [
            &b"xcsrf_token=abc"[..],
            b"my_csrf_token=abc; theme=dark",
            b"csrf_token_old=abc",
            b"CSRF_TOKEN=abc",
        ] {
            let req = session_post("/api/change", &[cookie], Some("abc"));
            assert_eq!(
                status_of(&app, req).await,
                StatusCode::FORBIDDEN,
                "{}",
                String::from_utf8_lossy(cookie)
            );
        }
        let req = session_post("/api/change", &[b"theme=dark; csrf_token=abc"], Some("abc"));
        assert_eq!(status_of(&app, req).await, StatusCode::NO_CONTENT);
    }

    /// An empty cookie never matches an empty (or missing) header.
    #[tokio::test]
    async fn empty_tokens_never_match() {
        let (_dir, app) = csrf_only_app().await;
        for (cookie, header) in [
            (&b"csrf_token="[..], Some("")),
            (b"csrf_token=", None),
            (b"csrf_token=   ; theme=dark", Some("")),
            (b"session_token=s", Some("")),
            (b"session_token=s", None),
        ] {
            let req = session_post("/api/change", &[cookie], header);
            assert_eq!(
                status_of(&app, req).await,
                StatusCode::FORBIDDEN,
                "{} / {header:?}",
                String::from_utf8_lossy(cookie)
            );
        }
    }

    /// PRE-09: a Cookie field that is not visible ASCII is skipped as a
    /// whole — the token is still found in another field, and a token
    /// only inside the unreadable field is no token (fail closed).
    #[tokio::test]
    async fn an_unreadable_cookie_field_never_yields_a_token() {
        let (_dir, app) = csrf_only_app().await;
        let req = session_post(
            "/api/change",
            &[b"theme=caf\xc3\xa9", b"csrf_token=c1"],
            Some("c1"),
        );
        assert_eq!(status_of(&app, req).await, StatusCode::NO_CONTENT);
        let req = session_post(
            "/api/change",
            &[b"csrf_token=c1; theme=caf\xc3\xa9"],
            Some("c1"),
        );
        assert_eq!(status_of(&app, req).await, StatusCode::FORBIDDEN);
    }

    /// `/api/change` (every method) behind the auth middleware and this
    /// one, as the gateway layers them.
    fn behind_auth(state: &Arc<AppState>) -> axum::Router {
        axum::Router::new()
            .route(
                "/api/change",
                axum::routing::get(|| async { "read" })
                    .options(|| async { "options" })
                    .post(|| async { StatusCode::NO_CONTENT })
                    .put(|| async { StatusCode::NO_CONTENT })
                    .patch(|| async { StatusCode::NO_CONTENT })
                    .delete(|| async { StatusCode::NO_CONTENT }),
            )
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(state),
                csrf_middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(state),
                super::super::auth::auth_middleware,
            ))
    }

    /// A real WebSocket handshake is a GET (RFC 6455; RFC 8441 uses
    /// CONNECT without an Upgrade header), so `Upgrade: websocket` on a
    /// mutating request is no handshake and exempts nothing. The GET
    /// handshake itself still needs no token.
    #[tokio::test]
    async fn a_websocket_upgrade_header_does_not_exempt_a_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::test_support::app_state(&dir);
        state.auth_config.write().await.csrf_enabled = true;
        let token = crate::ws::test_harness::session_for(&state, "csrf-ws", "admin");
        let app = behind_auth(&state);
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            for upgrade in ["websocket", "WebSocket"] {
                let req = Request::builder()
                    .method(method)
                    .uri("/api/change")
                    .header("cookie", format!("session_token={token}"))
                    .header("connection", "upgrade")
                    .header("upgrade", upgrade)
                    .body(Body::empty())
                    .unwrap();
                assert_eq!(
                    status_of(&app, req).await,
                    StatusCode::FORBIDDEN,
                    "{method} with Upgrade: {upgrade}"
                );
            }
            // With the token it passes, as without the header.
            let req = Request::builder()
                .method(method)
                .uri("/api/change")
                .header("cookie", format!("session_token={token}; csrf_token=t1"))
                .header("x-csrf-token", "t1")
                .header("connection", "upgrade")
                .header("upgrade", "websocket")
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                status_of(&app, req).await,
                StatusCode::NO_CONTENT,
                "{method} with Upgrade: websocket and the token"
            );
        }
        let handshake = Request::get("/api/change")
            .header("cookie", format!("session_token={token}"))
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status_of(&app, handshake).await, StatusCode::OK);
    }

    /// The gateway's order: the auth middleware resolves the session, then
    /// this one checks it. Every mutating method needs the double-submit
    /// token, however the session arrived (and whatever other protocol an
    /// Upgrade header names); safe methods do not; and the check is off
    /// when CSRF is disabled.
    #[tokio::test]
    async fn session_mutations_need_the_token_behind_the_auth_middleware() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::test_support::app_state(&dir);
        let token = crate::ws::test_harness::session_for(&state, "csrf-user", "admin");
        let app = behind_auth(&state);
        let request = |method: &str, cookies: &[&str], header: Option<&str>| {
            let mut builder = Request::builder()
                .method(method)
                .uri("/api/change")
                .version(axum::http::Version::HTTP_2);
            for cookie in cookies {
                builder = builder.header("cookie", *cookie);
            }
            if let Some(value) = header {
                builder = builder.header("x-csrf-token", value);
            }
            builder.body(Body::empty()).unwrap()
        };
        let session = format!("session_token={token}");

        // CSRF off (the default here): no token needed.
        let req = request("POST", &[&session], None);
        assert_eq!(status_of(&app, req).await, StatusCode::NO_CONTENT);

        state.auth_config.write().await.csrf_enabled = true;
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            // An Upgrade header for another protocol changes nothing.
            let with_upgrade = |upgrade: &str| {
                let mut req = request(method, &[&session], None);
                req.headers_mut()
                    .insert("upgrade", upgrade.parse().unwrap());
                req
            };
            for req in [
                request(method, &[&session], None),
                with_upgrade("h2c"),
                with_upgrade("websocket2"),
            ] {
                let what = format!("{method} {:?}", req.headers().get("upgrade"));
                let resp = {
                    use tower::ServiceExt as _;
                    app.clone().oneshot(req).await.unwrap()
                };
                assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{what} without");
                let body = axum::body::to_bytes(resp.into_body(), 1 << 10)
                    .await
                    .unwrap();
                assert_eq!(
                    &body[..],
                    br#"{"detail":"CSRF token missing or mismatch"}"#,
                    "{what}"
                );
            }
            let both = format!("{session}; csrf_token=t1");
            let req = request(method, &[&both], Some("t1"));
            assert_eq!(
                status_of(&app, req).await,
                StatusCode::NO_CONTENT,
                "{method} with"
            );
            let req = request(method, &[&both], Some("t2"));
            assert_eq!(
                status_of(&app, req).await,
                StatusCode::FORBIDDEN,
                "{method} mismatched"
            );
        }
        for method in ["GET", "HEAD", "OPTIONS"] {
            let req = request(method, &[&session], None);
            assert_eq!(status_of(&app, req).await, StatusCode::OK, "{method}");
        }

        // A session sent as a bearer token is a session too.
        let req = Request::post("/api/change")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(status_of(&app, req).await, StatusCode::FORBIDDEN);

        // PRE-09: session and CSRF cookies in separate Cookie fields.
        let split = [session.as_str(), "csrf_token=t3"];
        let req = request("POST", &split, Some("t3"));
        assert_eq!(status_of(&app, req).await, StatusCode::NO_CONTENT);
        let req = request("POST", &split, Some("t4"));
        assert_eq!(status_of(&app, req).await, StatusCode::FORBIDDEN);
    }
}
