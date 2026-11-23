//! Request framing (RFC 9112 §6.1): the guard that runs before any other
//! layer can answer a request.
//!
//! A request with both `Content-Length` and `Transfer-Encoding` can be
//! framed one way by a front proxy and another way by the gateway, so
//! bytes one of them reads as body the other reads as the next request
//! (request smuggling). RFC 9112 §6.1 lets a server refuse such a request
//! or frame it by its Transfer-Encoding, and requires it to close the
//! connection after responding either way. hyper frames the body by its
//! chunked encoding and, when Content-Length came first, keeps that
//! header: the gateway refuses that request (400) and closes the
//! connection. A Content-Length that comes after Transfer-Encoding hyper
//! drops without a trace (and keeps the connection open), so the gateway
//! cannot tell that request from a plain chunked one. It therefore closes
//! the connection after every HTTP/1 request that carries
//! Transfer-Encoding, whatever the response. Browsers and the edge agents
//! frame their bodies by Content-Length, so this costs them nothing.
//!
//! The guard must be outside every layer that answers requests itself —
//! CORS (every `OPTIONS`), the body limit (a declared length above it),
//! the path canonicalization (`/api/internal`, refused paths),
//! authentication: after such an answer hyper keeps the connection open,
//! reads the rest of the chunked body, and parses what follows it as
//! another request. [`with_canonical_paths`] puts it around the whole app.
//!
//! [`with_canonical_paths`]: crate::middleware::path::with_canonical_paths

use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderMap, HeaderValue, StatusCode, Version},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tracing::warn;

/// Whether a request carries both `Transfer-Encoding` and
/// `Content-Length`. hyper itself refuses conflicting Content-Length
/// values, and a Content-Length an HTTP/2 body does not match; one that
/// follows Transfer-Encoding it drops, so this sees only one that came
/// before it.
pub(crate) fn has_ambiguous_framing(headers: &HeaderMap) -> bool {
    headers.contains_key(header::TRANSFER_ENCODING) && headers.contains_key(header::CONTENT_LENGTH)
}

/// 400 for [`has_ambiguous_framing`], closing the connection. (hyper
/// closes it after a response that says `Connection: close`, without
/// reading anything more from it.)
pub(crate) fn ambiguous_framing_response() -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CONNECTION, "close")],
        "Request has both Content-Length and Transfer-Encoding",
    )
        .into_response()
}

/// Whether the connection must close after the response to a request
/// with these `version` and `headers`: an HTTP/1 request that carries
/// Transfer-Encoding (see the module documentation). HTTP/2 has no
/// Transfer-Encoding (hyper refuses one) and frames every body itself.
fn closes_connection(version: Version, headers: &HeaderMap) -> bool {
    matches!(
        version,
        Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11
    ) && headers.contains_key(header::TRANSFER_ENCODING)
}

/// The framing guard (see the module documentation): refuses a request
/// with [`has_ambiguous_framing`], and closes the connection after every
/// other HTTP/1 request that carries Transfer-Encoding.
pub async fn guard_framing(req: Request<Body>, next: Next) -> Response {
    if has_ambiguous_framing(req.headers()) {
        warn!(
            path = %req.uri().path(),
            "Refused a request with both Content-Length and Transfer-Encoding"
        );
        return ambiguous_framing_response();
    }
    let close = closes_connection(req.version(), req.headers());
    let mut response = next.run(req).await;
    if close {
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tower::ServiceExt as _;

    #[test]
    fn only_both_framings_together_are_ambiguous() {
        let headers = |pairs: &[(&'static str, &'static str)]| {
            let mut map = HeaderMap::new();
            for (name, value) in pairs {
                map.append(*name, HeaderValue::from_static(value));
            }
            map
        };
        assert!(has_ambiguous_framing(&headers(&[
            ("content-length", "5"),
            ("transfer-encoding", "chunked"),
        ])));
        assert!(!has_ambiguous_framing(&headers(&[("content-length", "5")])));
        assert!(!has_ambiguous_framing(&headers(&[(
            "transfer-encoding",
            "chunked"
        )])));
        assert!(!has_ambiguous_framing(&HeaderMap::new()));
    }

    /// An app behind the guard that answers 200 (with `Connection:
    /// keep-alive`, which the guard must replace) and counts its calls.
    fn guarded() -> (Router, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let app = Router::new()
            .fallback(move || {
                counter.fetch_add(1, Ordering::SeqCst);
                async { ([(header::CONNECTION, "keep-alive")], "inner") }
            })
            .layer(axum::middleware::from_fn(guard_framing));
        (app, calls)
    }

    fn request(version: Version, pairs: &[(&str, &str)]) -> Request<Body> {
        let mut req = Request::post("/api/x").version(version);
        for (name, value) in pairs {
            req = req.header(*name, *value);
        }
        req.body(Body::empty()).unwrap()
    }

    /// Both framings: 400 and `Connection: close`, and nothing inside the
    /// guard runs.
    #[tokio::test]
    async fn both_framings_are_refused_before_the_app() {
        let (app, calls) = guarded();
        let resp = app
            .oneshot(request(
                Version::HTTP_11,
                &[("content-length", "5"), ("transfer-encoding", "chunked")],
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(resp.headers()[header::CONNECTION], "close");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    /// An HTTP/1 request that carries Transfer-Encoding is answered by the
    /// app, and the connection then closed; a request framed by its
    /// Content-Length alone, or an HTTP/2 one, keeps the app's
    /// Connection header.
    #[tokio::test]
    async fn every_http1_request_with_transfer_encoding_closes_the_connection() {
        for version in [Version::HTTP_10, Version::HTTP_11] {
            let (app, calls) = guarded();
            let resp = app
                .oneshot(request(version, &[("transfer-encoding", "chunked")]))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{version:?}");
            assert_eq!(
                resp.headers()
                    .get_all(header::CONNECTION)
                    .iter()
                    .collect::<Vec<_>>(),
                ["close"],
                "{version:?}"
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
        for (version, pairs) in [
            (Version::HTTP_11, &[("content-length", "5")][..]),
            (Version::HTTP_11, &[][..]),
            (Version::HTTP_2, &[("transfer-encoding", "chunked")][..]),
        ] {
            let (app, _) = guarded();
            let resp = app.oneshot(request(version, pairs)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{version:?} {pairs:?}");
            assert_eq!(
                resp.headers()[header::CONNECTION],
                "keep-alive",
                "{version:?} {pairs:?}"
            );
        }
    }
}
