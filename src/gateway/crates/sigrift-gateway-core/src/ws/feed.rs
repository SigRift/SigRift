//! WebSocket detection feed — broadcasts new detections to connected
//! clients — and the runner shared by every broadcast feed
//! (`/ws/feed`, `/ws/anomalies`, `/ws/audit`).
//!
//! A feed is authenticated before the upgrade and re-validated while open
//! (see [`crate::ws::auth`]). A subscriber that falls behind the broadcast
//! buffer is told how many messages it missed (`{"type": "lagged",
//! "dropped": N}`) and keeps receiving; it is never silently cut off. When
//! the feed ends for any reason the socket is closed.

use axum::{
    body::Body,
    extract::{
        ws::{close_code, CloseFrame, Message, WebSocket},
        FromRequestParts, State, WebSocketUpgrade,
    },
    http::Request,
    response::{IntoResponse, Response},
};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::broadcast::{self, error::RecvError};
use tracing::{debug, warn};

use crate::auth::rbac::Role;
use crate::ws::auth::{
    authenticate, RevalidateTiming, Revalidator, WsRequest, CLOSE_CREDENTIAL_REVOKED,
    WS_SUBPROTOCOL,
};
use crate::AppState;

/// Selects the broadcast channel a feed serves.
pub(crate) type Subscribe = fn(&AppState) -> broadcast::Receiver<String>;

pub async fn ws_detection_feed(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    serve_feed(state, req, Role::Viewer, "detections", |s| {
        s.detection_tx.subscribe()
    })
    .await
}

/// Authenticate, upgrade and run a broadcast feed.
pub(crate) async fn serve_feed(
    state: Arc<AppState>,
    req: Request<Body>,
    min_role: Role,
    feed: &'static str,
    subscribe: Subscribe,
) -> Response {
    serve_feed_with(
        state,
        req,
        min_role,
        feed,
        subscribe,
        RevalidateTiming::from_env(),
    )
    .await
}

pub(crate) async fn serve_feed_with(
    state: Arc<AppState>,
    req: Request<Body>,
    min_role: Role,
    feed: &'static str,
    subscribe: Subscribe,
    timing: RevalidateTiming,
) -> Response {
    let principal = match authenticate(&state, WsRequest::of(&req), min_role).await {
        Ok(p) => p,
        Err(rejection) => return rejection,
    };
    let (mut parts, _body) = req.into_parts();
    let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(ws) => ws,
        Err(rejection) => return rejection.into_response(),
    };
    let rx = subscribe(&state);
    let revalidator = Revalidator::new(&state, principal, min_role, timing);
    ws.protocols([WS_SUBPROTOCOL])
        .on_upgrade(move |socket| run_broadcast_feed(socket, rx, revalidator, state, feed))
}

/// Pump `rx` to the socket until the client leaves, the channel closes or
/// the credential stops being valid; then close the socket.
pub(crate) async fn run_broadcast_feed(
    socket: WebSocket,
    mut rx: broadcast::Receiver<String>,
    mut auth: Revalidator,
    state: Arc<AppState>,
    feed: &'static str,
) {
    let (mut sender, mut receiver) = socket.split();
    let tick = auth.tick();
    let mut check = tokio::time::interval_at(tokio::time::Instant::now() + tick, tick);
    debug!(
        feed,
        principal = auth.principal().name(),
        "WebSocket feed client connected"
    );

    let close: Option<CloseFrame> = loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Ok(text) => {
                    if !auth.valid_for_payload(&state).await {
                        break Some(CloseFrame {
                            code: CLOSE_CREDENTIAL_REVOKED,
                            reason: "credential revoked or expired".into(),
                        });
                    }
                    if sender.send(Message::Text(text.into())).await.is_err() {
                        break None;
                    }
                }
                Err(RecvError::Lagged(dropped)) => {
                    if !auth.valid_for_payload(&state).await {
                        break Some(CloseFrame {
                            code: CLOSE_CREDENTIAL_REVOKED,
                            reason: "credential revoked or expired".into(),
                        });
                    }
                    warn!(feed, dropped, "WebSocket feed subscriber lagged — messages dropped");
                    let notice = serde_json::json!({"type": "lagged", "dropped": dropped});
                    if sender.send(Message::Text(notice.to_string().into())).await.is_err() {
                        break None;
                    }
                }
                Err(RecvError::Closed) => break Some(CloseFrame {
                    code: close_code::AWAY,
                    reason: "feed closed".into(),
                }),
            },
            incoming = receiver.next() => match incoming {
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break None,
                Some(Ok(_)) => {}
            },
            _ = check.tick() => {
                if !auth.still_valid(&state).await {
                    break Some(CloseFrame {
                        code: CLOSE_CREDENTIAL_REVOKED,
                        reason: "credential revoked or expired".into(),
                    });
                }
            }
        }
    };

    if let Some(frame) = close {
        let _ = sender.send(Message::Close(Some(frame))).await;
    }
    let _ = sender.close().await;
    debug!(feed, "WebSocket feed client disconnected");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ws::test_harness as h;
    use axum::{routing::get, Router};
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio_tungstenite::tungstenite::Message as TMsg;

    /// Failure bound, in seconds, for a frame that follows an API-key
    /// re-check after keys.json changed. A passing test ends at the frame.
    ///
    /// Re-checking a key that is still listed runs PBKDF2 (600k
    /// iterations): seconds in a debug build, a minute or more on a loaded
    /// machine. The tests that wait for one therefore run on a paused clock
    /// (`start_paused`) over an `h::MemGateway`. Tokio does not advance a
    /// paused clock while a blocking task (PBKDF2) runs, so this bounds the
    /// gateway's own waiting, never PBKDF2's CPU time. A revoked key is
    /// refused without PBKDF2, so `a_revoked_api_key_closes_the_feed` waits
    /// on the real clock.
    const KEY_RECHECK_SECS: u64 = 60;

    /// A re-check interval that cannot come due during a test, for a tick
    /// (on the tokio clock) or a period (on `std::time::Instant`).
    ///
    /// A period keeps running in real time on a paused tokio clock, so a
    /// short one, like [`fast`]'s, can elapse while virtual time steps
    /// towards a deadline, the more easily the more loaded the machine is.
    /// A test that must see a check come from one source (the key-set
    /// generation, or a payload) sets the other sources to `NEVER_DUE`.
    const NEVER_DUE: Duration = Duration::from_secs(600);
    // A `NEVER_DUE` tick cannot fire before the failure bound, and a
    // `NEVER_DUE` period is far beyond the real time a test takes.
    const _: () = assert!(KEY_RECHECK_SECS < NEVER_DUE.as_secs());

    fn fast() -> RevalidateTiming {
        RevalidateTiming {
            tick: Duration::from_millis(50),
            period: Duration::from_millis(100),
        }
    }

    async fn gateway(state: Arc<AppState>) -> SocketAddr {
        h::serve(state, routes()).await
    }

    fn routes() -> Router<Arc<AppState>> {
        routes_with(fast())
    }

    /// [`routes`], with the detection feed re-checked on `timing`.
    fn routes_with(timing: RevalidateTiming) -> Router<Arc<AppState>> {
        Router::new()
            .route(
                "/ws/feed",
                get(
                    move |State(state): State<Arc<AppState>>, req: Request<Body>| async move {
                        serve_feed_with(
                            state,
                            req,
                            Role::Viewer,
                            "detections",
                            |s| s.detection_tx.subscribe(),
                            timing,
                        )
                        .await
                    },
                ),
            )
            .route("/ws/audit", get(crate::audit::ws_feed::ws_audit_feed))
    }

    fn text(msg: Option<TMsg>) -> String {
        match msg {
            Some(TMsg::Text(t)) => t.as_str().to_string(),
            other => panic!("expected a text message, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_feed_requires_credentials_and_accepts_a_key_in_the_subprotocol() {
        let dir = tempfile::tempdir().unwrap();
        let keys = h::keys_file(&[
            h::key_entry("viewer-key", "sk-viewer", "viewer", false),
            h::key_entry("sensor-key", "sk-sensor", "sensor", false),
        ]);
        let state = h::state(&dir, "http://127.0.0.1:1", &keys, None);
        let addr = gateway(Arc::clone(&state)).await;

        assert_eq!(h::connect(addr, "/ws/feed", &[]).await.err(), Some(401));
        let sensor = [("sec-websocket-protocol", "bridge-v1, sk-sensor")];
        assert_eq!(h::connect(addr, "/ws/feed", &sensor).await.err(), Some(403));

        let viewer = [("sec-websocket-protocol", "bridge-v1, sk-viewer")];
        let (mut ws, protocol) = h::connect(addr, "/ws/feed", &viewer).await.unwrap();
        assert_eq!(protocol.as_deref(), Some("bridge-v1"), "subprotocol echoed");
        // Give the server task time to subscribe.
        tokio::time::sleep(Duration::from_millis(100)).await;
        state.detection_tx.send("{\"n\":1}".into()).unwrap();
        assert_eq!(text(h::next_msg(&mut ws, 5).await), "{\"n\":1}");
    }

    /// The dashboard offers `["bridge-v1", apiKey || sessionToken]`; after
    /// an MFA login (or with a stale cookie) there is no usable cookie.
    #[tokio::test]
    async fn the_feed_accepts_a_session_token_in_the_subprotocol() {
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, "http://127.0.0.1:1", &h::keys_file(&[]), None);
        let viewer = h::session_for(&state, "alice", "viewer");
        let sensor = h::session_for(&state, "probe", "sensor");
        let restricted = h::session_with(&state, "new", "admin", "", "password_change_only");
        let addr = gateway(Arc::clone(&state)).await;
        let offer = |token: &str| format!("bridge-v1, {token}");

        for (token, refused) in [(&sensor, 403), (&restricted, 403)] {
            let protocols = offer(token);
            assert_eq!(
                h::connect(addr, "/ws/feed", &[("sec-websocket-protocol", &protocols)])
                    .await
                    .err(),
                Some(refused)
            );
        }

        let protocols = offer(&viewer);
        let (mut ws, protocol) = h::connect(
            addr,
            "/ws/feed",
            &[
                ("sec-websocket-protocol", &protocols),
                ("cookie", "session_token=stale"),
            ],
        )
        .await
        .expect("upgraded");
        assert_eq!(protocol.as_deref(), Some("bridge-v1"));
        tokio::time::sleep(Duration::from_millis(100)).await;
        state.detection_tx.send("{\"n\":1}".into()).unwrap();
        assert_eq!(text(h::next_msg(&mut ws, 5).await), "{\"n\":1}");

        // Re-checked as a session: logging out closes the feed.
        h::delete_sessions(&state);
        assert_eq!(
            h::close_code(&mut ws, 5).await,
            Some(crate::ws::auth::CLOSE_CREDENTIAL_REVOKED)
        );
    }

    #[tokio::test]
    async fn a_revoked_api_key_closes_the_feed() {
        let dir = tempfile::tempdir().unwrap();
        let keys = h::keys_file(&[h::key_entry("viewer-key", "sk-viewer", "viewer", false)]);
        let state = h::state(&dir, "http://127.0.0.1:1", &keys, None);
        let addr = gateway(Arc::clone(&state)).await;

        let viewer = [("sec-websocket-protocol", "bridge-v1, sk-viewer")];
        let (mut ws, _) = h::connect(addr, "/ws/feed", &viewer).await.unwrap();
        // Still open after several re-checks.
        assert!(h::next_msg(&mut ws, 1).await.is_none());

        h::write_keys(
            &dir,
            &h::keys_file(&[h::key_entry("viewer-key", "sk-viewer", "viewer", true)]),
        );
        assert_eq!(
            h::close_code(&mut ws, KEY_RECHECK_SECS).await,
            Some(crate::ws::auth::CLOSE_CREDENTIAL_REVOKED)
        );
    }

    /// Regression (Q4): a client-certificate socket was never checked
    /// again, so a revoked certificate kept streaming until the client
    /// disconnected. Revocation (or a role drop) in the CA registry now
    /// closes it with 4001.
    #[tokio::test]
    async fn a_revoked_client_certificate_closes_the_feed() {
        let dir = tempfile::tempdir().unwrap();
        let registry = dir.path().join("registry.json");
        h::write_cert_registry(&registry, "edge-7", "viewer", false);
        let state = h::with_cert_registry(
            h::state(&dir, "http://127.0.0.1:1", &h::keys_file(&[]), None),
            &registry,
        );
        let addr = h::serve_with_cert(Arc::clone(&state), routes(), h::client_cert("edge-7")).await;

        let (mut ws, _) = h::connect(addr, "/ws/feed", &[]).await.expect("upgraded");
        tokio::time::sleep(Duration::from_millis(100)).await;
        state.detection_tx.send("{\"n\":1}".into()).unwrap();
        assert_eq!(text(h::next_msg(&mut ws, 5).await), "{\"n\":1}");
        // Still open after several re-checks.
        assert!(h::next_msg(&mut ws, 1).await.is_none());

        h::write_cert_registry(&registry, "edge-7", "viewer", true);
        assert_eq!(
            h::close_code(&mut ws, 10).await,
            Some(crate::ws::auth::CLOSE_CREDENTIAL_REVOKED)
        );

        // A role below the feed's closes it too.
        h::write_cert_registry(&registry, "edge-7", "viewer", false);
        let (mut ws, _) = h::connect(addr, "/ws/feed", &[]).await.expect("upgraded");
        h::write_cert_registry(&registry, "edge-7", "sensor", false);
        assert_eq!(
            h::close_code(&mut ws, 10).await,
            Some(crate::ws::auth::CLOSE_CREDENTIAL_REVOKED)
        );

        // So does a role the bridge never writes: KEYMASTER is never
        // delegated to a certificate, so the entry authorises nothing
        // rather than raising the socket's role.
        h::write_cert_registry(&registry, "edge-7", "viewer", false);
        let (mut ws, _) = h::connect(addr, "/ws/feed", &[]).await.expect("upgraded");
        h::write_cert_registry(&registry, "edge-7", "keymaster", false);
        assert_eq!(
            h::close_code(&mut ws, 10).await,
            Some(crate::ws::auth::CLOSE_CREDENTIAL_REVOKED)
        );
    }

    #[tokio::test]
    async fn a_lagging_subscriber_is_told_and_keeps_receiving() {
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, "http://127.0.0.1:1", &h::keys_file(&[]), None);
        let token = h::session_for(&state, "alice", "viewer");
        let addr = gateway(Arc::clone(&state)).await;
        let cookie = format!("session_token={token}");
        let (mut ws, _) = h::connect(addr, "/ws/feed", &[("cookie", &cookie)])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // One burst bigger than the channel (16 in tests): the subscriber
        // lags. Before the fix its send task ended here, leaving the
        // socket open but silent.
        for i in 0..200 {
            state.detection_tx.send(format!("{{\"n\":{i}}}")).unwrap();
        }
        let mut lagged = false;
        let mut last = String::new();
        while let Some(msg) = h::next_msg(&mut ws, 2).await {
            let t = text(Some(msg));
            if t.contains("\"lagged\"") {
                let v: serde_json::Value = serde_json::from_str(&t).unwrap();
                assert!(v["dropped"].as_u64().unwrap() > 0);
                lagged = true;
            } else {
                last = t;
            }
            if last == "{\"n\":199}" {
                break;
            }
        }
        assert!(lagged, "the client is told it missed messages");
        assert_eq!(last, "{\"n\":199}", "the newest messages still arrive");

        // And the feed keeps working afterwards.
        state.detection_tx.send("{\"after\":true}".into()).unwrap();
        assert_eq!(text(h::next_msg(&mut ws, 5).await), "{\"after\":true}");
    }

    #[tokio::test]
    async fn the_audit_feed_delivers_entries_to_admins_only() {
        let sink = crate::audit::store::tests::test_sink();
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, "http://127.0.0.1:1", &h::keys_file(&[]), Some(sink));
        let admin = h::session_for(&state, "root", "admin");
        let viewer = h::session_for(&state, "alice", "viewer");
        let addr = gateway(Arc::clone(&state)).await;

        let cookie = format!("session_token={viewer}");
        assert_eq!(
            h::connect(addr, "/ws/audit", &[("cookie", &cookie)])
                .await
                .err(),
            Some(403)
        );

        let cookie = format!("session_token={admin}");
        let (mut ws, _) = h::connect(addr, "/ws/audit", &[("cookie", &cookie)])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let action = format!("feed_probe_{}", uuid::Uuid::new_v4().simple());
        let conn = state.db_pool.get().unwrap();
        crate::audit::store::log_audit(
            &conn, b"secret", &action, "t", "root", "", "", "", 0.0, "", "default",
        )
        .unwrap();
        // Other tests may publish to the shared sink too: find ours.
        let mut found = false;
        while let Some(msg) = h::next_msg(&mut ws, 5).await {
            if text(Some(msg)).contains(&action) {
                found = true;
                break;
            }
        }
        assert!(found, "the new audit entry is delivered");
    }

    #[tokio::test]
    async fn a_closed_feed_channel_closes_the_socket() {
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, "http://127.0.0.1:1", &h::keys_file(&[]), None);
        let token = h::session_for(&state, "alice", "viewer");
        // The route holds the only sender, so taking it out closes the channel.
        let sender = Arc::new(std::sync::Mutex::new(Some(
            broadcast::channel::<String>(4).0,
        )));
        let feed_tx = Arc::clone(&sender);
        let routes: Router<Arc<AppState>> = Router::new().route(
            "/ws/once",
            get(
                move |State(state): State<Arc<AppState>>, req: Request<Body>| {
                    let rx = feed_tx.lock().unwrap().as_ref().unwrap().subscribe();
                    async move {
                        let principal = authenticate(&state, WsRequest::of(&req), Role::Viewer)
                            .await
                            .unwrap();
                        let (mut parts, _) = req.into_parts();
                        let ws = WebSocketUpgrade::from_request_parts(&mut parts, &())
                            .await
                            .unwrap();
                        let auth = Revalidator::new(&state, principal, Role::Viewer, fast());
                        ws.on_upgrade(move |s| run_broadcast_feed(s, rx, auth, state, "once"))
                    }
                },
            ),
        );
        let addr = h::serve(Arc::clone(&state), routes).await;
        let cookie = format!("session_token={token}");
        let (mut ws, _) = h::connect(addr, "/ws/once", &[("cookie", &cookie)])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(sender.lock().unwrap().take());
        assert_eq!(h::close_code(&mut ws, 5).await, Some(close_code::AWAY));
    }

    #[tokio::test]
    async fn tenant_boundary_foreign_session_cannot_open_header_or_subprotocol_feed() {
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, "http://127.0.0.1:1", &h::keys_file(&[]), None);
        let token = h::session_for(&state, "foreign-viewer", "viewer");
        state
            .db_pool
            .get()
            .unwrap()
            .execute(
                "UPDATE users SET tenant_id='other' WHERE username='foreign-viewer'",
                [],
            )
            .unwrap();
        let addr = gateway(Arc::clone(&state)).await;
        for (name, value) in [
            ("authorization", format!("Bearer {token}")),
            ("sec-websocket-protocol", format!("bridge-v1, {token}")),
        ] {
            assert_eq!(
                h::connect(addr, "/ws/feed", &[(name, &value)]).await.err(),
                Some(403),
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn tenant_boundary_foreign_api_key_cannot_open_subprotocol_feed() {
        let dir = tempfile::tempdir().unwrap();
        let mut keys: serde_json::Value = serde_json::from_str(&h::keys_file(&[h::key_entry(
            "foreign-viewer",
            "tenant-test-key",
            "viewer",
            false,
        )]))
        .unwrap();
        keys["keys"]["foreign-viewer"]["tenant_id"] = serde_json::json!("other");
        let state = h::state(&dir, "http://127.0.0.1:1", &keys.to_string(), None);
        let addr = gateway(state).await;
        assert_eq!(
            h::connect(
                addr,
                "/ws/feed",
                &[("sec-websocket-protocol", "bridge-v1, tenant-test-key")]
            )
            .await
            .err(),
            Some(403)
        );
    }

    #[tokio::test]
    async fn tenant_boundary_open_session_feed_closes_after_user_moves_tenant() {
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, "http://127.0.0.1:1", &h::keys_file(&[]), None);
        let token = h::session_for(&state, "moving-viewer", "viewer");
        let addr = gateway(Arc::clone(&state)).await;
        let offer = format!("bridge-v1, {token}");
        let (mut ws, _) = h::connect(addr, "/ws/feed", &[("sec-websocket-protocol", &offer)])
            .await
            .unwrap();
        state
            .db_pool
            .get()
            .unwrap()
            .execute(
                "UPDATE users SET tenant_id='other' WHERE username='moving-viewer'",
                [],
            )
            .unwrap();
        assert_eq!(
            h::close_code(&mut ws, 15).await,
            Some(CLOSE_CREDENTIAL_REVOKED)
        );
    }

    /// On a paused clock (see `KEY_RECHECK_SECS`). The 50 ms tick must find
    /// the reload through the key-set generation: with the period
    /// `NEVER_DUE` and no payload sent, nothing else re-checks the key
    /// within the deadline.
    #[tokio::test(start_paused = true)]
    async fn tenant_boundary_open_key_feed_closes_after_key_moves_tenant() {
        let dir = tempfile::tempdir().unwrap();
        let mut keys: serde_json::Value = serde_json::from_str(&h::keys_file(&[h::key_entry(
            "moving-viewer",
            "tenant-test-key",
            "viewer",
            false,
        )]))
        .unwrap();
        let state = h::state(&dir, "http://127.0.0.1:1", &keys.to_string(), None);
        let timing = RevalidateTiming {
            tick: Duration::from_millis(50),
            period: NEVER_DUE,
        };
        let gw = h::serve_in_memory(Arc::clone(&state), routes_with(timing));
        let (mut ws, _) = gw
            .connect(
                "/ws/feed",
                &[("sec-websocket-protocol", "bridge-v1, tenant-test-key")],
            )
            .await
            .unwrap();
        keys["keys"]["moving-viewer"]["tenant_id"] = serde_json::json!("other");
        h::write_keys(&dir, &keys.to_string());
        assert_eq!(
            h::close_code(&mut ws, KEY_RECHECK_SECS).await,
            Some(CLOSE_CREDENTIAL_REVOKED)
        );
    }

    /// The control for the paused-clock key tests: with keys.json unchanged
    /// the feed stays open through every periodic check until the deadline,
    /// which then expires in virtual time (the test fails fast, not hangs,
    /// if a check stops closing the socket), and the feed still delivers.
    #[tokio::test(start_paused = true)]
    async fn an_unchanged_key_keeps_the_feed_open_past_the_paused_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let keys = h::keys_file(&[h::key_entry(
            "steady-viewer",
            "tenant-test-key",
            "viewer",
            false,
        )]);
        let state = h::state(&dir, "http://127.0.0.1:1", &keys, None);
        let gw = h::serve_in_memory(Arc::clone(&state), routes());
        let (mut ws, _) = gw
            .connect(
                "/ws/feed",
                &[("sec-websocket-protocol", "bridge-v1, tenant-test-key")],
            )
            .await
            .unwrap();
        let opened = tokio::time::Instant::now();
        assert_eq!(h::close_code(&mut ws, KEY_RECHECK_SECS).await, None);
        assert!(opened.elapsed() >= Duration::from_secs(KEY_RECHECK_SECS));
        state.detection_tx.send("still-open".into()).unwrap();
        assert_eq!(
            h::next_msg(&mut ws, KEY_RECHECK_SECS).await,
            Some(TMsg::Text("still-open".into()))
        );
    }

    #[tokio::test]
    async fn tenant_boundary_payload_checks_session_before_periodic_deadline() {
        for change in [
            "UPDATE users SET tenant_id='other'",
            "UPDATE users SET role='sensor'",
            "UPDATE users SET enabled=0",
            "DELETE FROM sessions",
            "UPDATE sessions SET expires_at='2000-01-01T00:00:00+00:00'",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let state = h::state(&dir, "http://127.0.0.1:1", &h::keys_file(&[]), None);
            let token = h::session_for(&state, "moving-viewer", "viewer");
            let routes = Router::new().route(
                "/ws/feed",
                get(
                    |State(state): State<Arc<AppState>>, req: Request<Body>| async move {
                        serve_feed_with(
                            state,
                            req,
                            Role::Viewer,
                            "detections",
                            |s| s.detection_tx.subscribe(),
                            RevalidateTiming {
                                tick: Duration::from_secs(600),
                                period: Duration::from_secs(600),
                            },
                        )
                        .await
                    },
                ),
            );
            let addr = h::serve(Arc::clone(&state), routes).await;
            let bearer = format!("Bearer {token}");
            let (mut ws, _) = h::connect(addr, "/ws/feed", &[("authorization", &bearer)])
                .await
                .unwrap();
            state.detection_tx.send("before-change".into()).unwrap();
            assert_eq!(
                h::next_msg(&mut ws, 10).await,
                Some(TMsg::Text("before-change".into()))
            );
            state.db_pool.get().unwrap().execute(change, []).unwrap();
            state.detection_tx.send("must-not-leak".into()).unwrap();
            // Do not skip data frames: the very next frame must be the refusal.
            assert!(
                matches!(h::next_msg(&mut ws, 10).await,
                Some(TMsg::Close(Some(frame))) if u16::from(frame.code) == CLOSE_CREDENTIAL_REVOKED),
                "change {change} allowed a data frame or failed to close"
            );
        }
    }

    /// On a paused clock (see `KEY_RECHECK_SECS`). The tick and period are
    /// `NEVER_DUE`, so a periodic check cannot close the socket in place of
    /// a broken payload check.
    #[tokio::test(start_paused = true)]
    async fn tenant_boundary_payload_checks_key_before_periodic_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let mut keys: serde_json::Value = serde_json::from_str(&h::keys_file(&[h::key_entry(
            "moving-viewer",
            "tenant-test-key",
            "viewer",
            false,
        )]))
        .unwrap();
        let state = h::state(&dir, "http://127.0.0.1:1", &keys.to_string(), None);
        let timing = RevalidateTiming {
            tick: NEVER_DUE,
            period: NEVER_DUE,
        };
        let gw = h::serve_in_memory(Arc::clone(&state), routes_with(timing));
        let (mut ws, _) = gw
            .connect("/ws/feed", &[("x-api-key", "tenant-test-key")])
            .await
            .unwrap();
        state.detection_tx.send("before-change".into()).unwrap();
        assert_eq!(
            h::next_msg(&mut ws, KEY_RECHECK_SECS).await,
            Some(TMsg::Text("before-change".into()))
        );
        keys["keys"]["moving-viewer"]["tenant_id"] = serde_json::json!("other");
        h::write_keys(&dir, &keys.to_string());
        state.detection_tx.send("must-not-leak".into()).unwrap();
        // Do not skip data frames: the very next frame must be the refusal.
        assert!(matches!(h::next_msg(&mut ws, KEY_RECHECK_SECS).await,
            Some(TMsg::Close(Some(frame))) if u16::from(frame.code) == CLOSE_CREDENTIAL_REVOKED));
    }

    #[tokio::test]
    async fn tenant_boundary_payload_preserves_winning_session_key_and_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let registry = dir.path().join("registry.json");
        h::write_cert_registry(&registry, "local-certificate", "viewer", false);
        let mut keys: serde_json::Value = serde_json::from_str(&h::keys_file(&[
            h::key_entry("local-key", "local-tenant-test-key", "viewer", false),
            h::key_entry("foreign-key", "foreign-tenant-test-key", "viewer", false),
        ]))
        .unwrap();
        keys["keys"]["foreign-key"]["tenant_id"] = serde_json::json!("other");
        let state = h::with_cert_registry(
            h::state(&dir, "http://127.0.0.1:1", &keys.to_string(), None),
            &registry,
        );
        let token = h::session_for(&state, "local-viewer", "viewer");
        let routes = Router::new().route(
            "/ws/feed",
            get(
                |State(state): State<Arc<AppState>>, req: Request<Body>| async move {
                    serve_feed_with(
                        state,
                        req,
                        Role::Viewer,
                        "detections",
                        |s| s.detection_tx.subscribe(),
                        RevalidateTiming {
                            tick: Duration::from_secs(600),
                            period: Duration::from_secs(600),
                        },
                    )
                    .await
                },
            ),
        );
        // The existing harness supplies the verified TLS identity extension;
        // the real certificate registry and authentication middleware decide.
        let addr = h::serve_with_cert(
            Arc::clone(&state),
            routes,
            h::client_cert("local-certificate"),
        )
        .await;
        for headers in [vec![], vec![("x-api-key", "local-tenant-test-key")]] {
            let (mut ws, _) = h::connect(addr, "/ws/feed", &headers).await.unwrap();
            ws.close(None).await.unwrap();
        }
        for (key, expected) in [("foreign-tenant-test-key", 403), ("invalid-key", 401)] {
            assert_eq!(
                h::connect(addr, "/ws/feed", &[("x-api-key", key)])
                    .await
                    .err(),
                Some(expected)
            );
        }
        let bearer = format!("Bearer {token}");
        let (mut ws, _) = h::connect(
            addr,
            "/ws/feed",
            &[
                ("authorization", &bearer),
                ("x-api-key", "foreign-tenant-test-key"),
            ],
        )
        .await
        .unwrap();
        state.detection_tx.send("winning-session".into()).unwrap();
        assert_eq!(
            h::next_msg(&mut ws, 10).await,
            Some(TMsg::Text("winning-session".into()))
        );
        h::delete_sessions(&state);
        state
            .detection_tx
            .send("must-not-fall-back-to-certificate".into())
            .unwrap();
        assert!(matches!(h::next_msg(&mut ws, 10).await,
            Some(TMsg::Close(Some(frame))) if u16::from(frame.code) == CLOSE_CREDENTIAL_REVOKED));
    }

    /// `/ws/feed` whose periodic re-check never comes due within a test.
    fn slow_routes() -> Router<Arc<AppState>> {
        Router::new().route(
            "/ws/feed",
            get(
                |State(state): State<Arc<AppState>>, req: Request<Body>| async move {
                    serve_feed_with(
                        state,
                        req,
                        Role::Viewer,
                        "detections",
                        |s| s.detection_tx.subscribe(),
                        RevalidateTiming {
                            tick: Duration::from_secs(600),
                            period: Duration::from_secs(600),
                        },
                    )
                    .await
                },
            ),
        )
    }

    /// Cross-site WebSocket hijacking, through the real middleware: a page
    /// on another (or an opaque) origin cannot open the feed with the
    /// browser's session cookie; the cookie from this origin, or the token
    /// in a header (which only a script holding it can set), can. (The
    /// case matrix, and restricted scopes, are `ws::auth`'s unit tests.)
    #[tokio::test]
    async fn a_cross_site_page_cannot_open_the_feed_with_the_session_cookie() {
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, "http://127.0.0.1:1", &h::keys_file(&[]), None);
        let token = h::session_for(&state, "alice", "viewer");
        let addr = gateway(Arc::clone(&state)).await;
        let cookie = format!("session_token={token}");
        let this_origin = format!("http://{addr}");

        for origin in ["https://evil.example", "null"] {
            assert_eq!(
                h::connect(addr, "/ws/feed", &[("cookie", &cookie), ("origin", origin)])
                    .await
                    .err(),
                Some(403),
                "{origin}"
            );
        }

        let (mut same_origin, _) = h::connect(
            addr,
            "/ws/feed",
            &[("cookie", &cookie), ("origin", &this_origin)],
        )
        .await
        .expect("the cookie from this origin");
        let bearer = format!("Bearer {token}");
        let (mut header, _) = h::connect(
            addr,
            "/ws/feed",
            &[
                ("authorization", &bearer),
                ("origin", "https://evil.example"),
            ],
        )
        .await
        .expect("the token in a header");
        state.detection_tx.send("{\"n\":1}".into()).unwrap();
        assert_eq!(text(h::next_msg(&mut same_origin, 5).await), "{\"n\":1}");
        assert_eq!(text(h::next_msg(&mut header, 5).await), "{\"n\":1}");
    }

    /// A subscriber that fell behind is told what it missed only while its
    /// credential is good: after a logout it gets 4001, not the backlog
    /// notice (and none of the backlog).
    ///
    /// The runtime is single-threaded on purpose: the feed task cannot run
    /// while the burst is sent, so its receiver lags (`RecvError::Lagged`)
    /// rather than taking the first message (which would end in 4001 too,
    /// without the lag branch ever running).
    #[tokio::test(flavor = "current_thread")]
    async fn a_lagging_subscriber_whose_session_ended_gets_4001_not_the_backlog() {
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, "http://127.0.0.1:1", &h::keys_file(&[]), None);
        let token = h::session_for(&state, "alice", "viewer");
        let addr = h::serve(Arc::clone(&state), slow_routes()).await;
        let bearer = format!("Bearer {token}");
        // The feed subscribes before it answers the upgrade.
        let (mut ws, _) = h::connect(addr, "/ws/feed", &[("authorization", &bearer)])
            .await
            .unwrap();
        // Subscribed after the feed and read no sooner: when it lags, the
        // feed's receiver (at least as far behind) lags too.
        let mut probe = state.detection_tx.subscribe();

        h::delete_sessions(&state);
        // More than the channel holds (16 in tests), all sent before the
        // feed task runs again: it lags.
        for i in 0..64 {
            state.detection_tx.send(format!("{{\"n\":{i}}}")).unwrap();
        }
        assert!(
            matches!(
                probe.try_recv(),
                Err(broadcast::error::TryRecvError::Lagged(_))
            ),
            "the burst overflowed the channel"
        );
        match h::next_msg(&mut ws, 10).await {
            Some(TMsg::Close(Some(frame))) => {
                assert_eq!(u16::from(frame.code), CLOSE_CREDENTIAL_REVOKED)
            }
            other => panic!("expected the 4001 close first, got {other:?}"),
        }
    }

    /// The production route: authenticated (VIEWER or above) before the
    /// upgrade.
    #[tokio::test]
    async fn the_detection_feed_route_authenticates_before_upgrading() {
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, "http://127.0.0.1:1", &h::keys_file(&[]), None);
        let viewer = h::session_for(&state, "alice", "viewer");
        let sensor = h::session_for(&state, "probe", "sensor");
        let routes = Router::new().route("/ws/feed", get(ws_detection_feed));
        let addr = h::serve(Arc::clone(&state), routes).await;
        let bearer = |token: &str| format!("Bearer {token}");

        assert_eq!(h::connect(addr, "/ws/feed", &[]).await.err(), Some(401));
        assert_eq!(
            h::connect(addr, "/ws/feed", &[("authorization", &bearer(&sensor))])
                .await
                .err(),
            Some(403)
        );
        let (mut ws, _) = h::connect(addr, "/ws/feed", &[("authorization", &bearer(&viewer))])
            .await
            .expect("upgraded");
        state.detection_tx.send("{\"n\":1}".into()).unwrap();
        assert_eq!(text(h::next_msg(&mut ws, 5).await), "{\"n\":1}");
    }

    /// A plain GET is authenticated first, and an authenticated one that is
    /// no WebSocket upgrade is refused rather than served.
    #[tokio::test]
    async fn a_plain_http_request_to_the_feed_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, "http://127.0.0.1:1", &h::keys_file(&[]), None);
        let token = h::session_for(&state, "alice", "viewer");
        let addr = gateway(Arc::clone(&state)).await;
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/ws/feed");

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
    }

    /// The admin-only audit feed re-checks its socket against the admin
    /// role, not merely "still a user": an admin demoted to analyst while
    /// the feed is open gets 4001 instead of the next audit entry.
    #[tokio::test]
    async fn an_admin_demoted_while_the_audit_feed_is_open_gets_4001_not_the_next_entry() {
        // A channel of this test's own (not the process-wide audit sink).
        let audit_tx = broadcast::channel::<String>(16).0;
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(
            &dir,
            "http://127.0.0.1:1",
            &h::keys_file(&[]),
            Some(audit_tx),
        );
        let admin = h::session_for(&state, "root", "admin");
        let addr = gateway(Arc::clone(&state)).await;
        let bearer = format!("Bearer {admin}");
        // The feed subscribes before it answers the upgrade.
        let (mut ws, _) = h::connect(addr, "/ws/audit", &[("authorization", &bearer)])
            .await
            .expect("an admin opens the audit feed");
        state.audit_tx.send("entry-for-the-admin".into()).unwrap();
        assert_eq!(
            h::next_msg(&mut ws, 10).await,
            Some(TMsg::Text("entry-for-the-admin".into()))
        );

        state
            .db_pool
            .get()
            .unwrap()
            .execute("UPDATE users SET role='analyst' WHERE username='root'", [])
            .unwrap();
        state.audit_tx.send("entry-after-demotion".into()).unwrap();
        // Do not skip data frames: the very next frame must be the refusal.
        match h::next_msg(&mut ws, 10).await {
            Some(TMsg::Close(Some(frame))) => {
                assert_eq!(u16::from(frame.code), CLOSE_CREDENTIAL_REVOKED)
            }
            other => panic!("the demoted admin got {other:?} instead of the 4001 close"),
        }
    }
}
