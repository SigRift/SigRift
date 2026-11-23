//! Test harness for WebSocket routes: a real gateway router (with the auth
//! middleware) on a loopback port or over in-memory pipes, a fake bridge
//! WebSocket server, users, sessions and API keys.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::serve::ListenerExt;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::{
    self, client::IntoClientRequest, handshake::server, protocol::CloseFrame, Message,
};
use tokio_tungstenite::WebSocketStream;

use crate::auth::client_cert::{CertRegistry, ClientCertInfo};
use crate::middleware::auth::auth_middleware;
use crate::storage::sessions::{self, SessionConfig};
use crate::AppState;

pub(crate) const PROXY_SECRET: &str = "test-proxy-secret";

/// An auth-enabled state backed by `dir`, with a keys.json (initially
/// `keys_json`) and the backend at `python_url`.
pub(crate) fn state(
    dir: &tempfile::TempDir,
    python_url: &str,
    keys_json: &str,
    audit_tx: Option<tokio::sync::broadcast::Sender<String>>,
) -> Arc<AppState> {
    let keys = keys_path(dir);
    std::fs::write(&keys, keys_json).unwrap();
    let Ok(mut state) = Arc::try_unwrap(crate::test_support::app_state(dir)) else {
        unreachable!("fresh state has one owner")
    };
    state.key_store = crate::auth::api_key::KeyStore::try_new(&keys);
    assert!(state.key_store.is_some(), "keys.json must parse");
    state.auth_enabled = true;
    state.config.python_url = python_url.to_string();
    state.config.proxy_secret = PROXY_SECRET.to_string();
    if let Some(tx) = audit_tx {
        state.audit_tx = tx;
    }
    Arc::new(state)
}

pub(crate) fn keys_path(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("keys.json")
}

/// Replace keys.json atomically, as the bridge does.
pub(crate) fn write_keys(dir: &tempfile::TempDir, keys_json: &str) {
    let tmp = dir.path().join("keys.json.tmp");
    std::fs::write(&tmp, keys_json).unwrap();
    std::fs::rename(&tmp, keys_path(dir)).unwrap();
}

/// A keys.json entry for `raw` (PBKDF2 hash + lookup hash, like Python).
pub(crate) fn key_entry(key_id: &str, raw: &str, role: &str, revoked: bool) -> String {
    // PBKDF2 at 600k iterations is slow in debug builds: hash each key once.
    static HASHES: Mutex<Vec<(String, [u8; 32])>> = Mutex::new(Vec::new());
    let salt = [7u8; 32];
    let cached = HASHES
        .lock()
        .unwrap()
        .iter()
        .find(|(r, _)| r == raw)
        .map(|(_, h)| *h);
    let hash = cached.unwrap_or_else(|| {
        let mut hash = [0u8; 32];
        pbkdf2_hmac::<Sha256>(raw.as_bytes(), &salt, 600_000, &mut hash);
        HASHES.lock().unwrap().push((raw.to_string(), hash));
        hash
    });
    format!(
        r#""{key_id}": {{"hash": "{}", "salt": "{}", "lookup_hash": "{}", "role": "{role}",
             "revoked": {revoked}}}"#,
        hex::encode(hash),
        hex::encode(salt),
        hex::encode(Sha256::digest(raw.as_bytes())),
    )
}

pub(crate) fn keys_file(entries: &[String]) -> String {
    format!(r#"{{"keys": {{{}}}}}"#, entries.join(","))
}

/// A user with `role` and a full-scope session for it; returns the token.
pub(crate) fn session_for(state: &AppState, username: &str, role: &str) -> String {
    let conn = state.db_pool.get().unwrap();
    conn.execute(
        "INSERT INTO users (username, password_hash, salt, role, created_at) \
         VALUES (?1, 'x', 'x', ?2, '2026-01-01T00:00:00+00:00')",
        [username, role],
    )
    .unwrap();
    let user_id = conn.last_insert_rowid();
    sessions::create_session(&conn, user_id, "", "", &SessionConfig::default())
        .unwrap()
        .0
}

/// Like [`session_for`], with the session's stored client IP and scope.
pub(crate) fn session_with(
    state: &AppState,
    username: &str,
    role: &str,
    ip_address: &str,
    scope: &str,
) -> String {
    let token = session_for(state, username, role);
    state
        .db_pool
        .get()
        .unwrap()
        .execute(
            "UPDATE sessions SET ip_address = ?1, scope = ?2 WHERE session_token = ?3",
            [
                ip_address,
                scope,
                &crate::auth::password::hash_session_token(&token),
            ],
        )
        .unwrap();
    token
}

pub(crate) fn delete_sessions(state: &AppState) {
    state
        .db_pool
        .get()
        .unwrap()
        .execute("DELETE FROM sessions", [])
        .unwrap();
}

/// `state` with client-certificate auth backed by the CA registry at
/// `path` (see [`write_cert_registry`]).
pub(crate) fn with_cert_registry(state: Arc<AppState>, path: &std::path::Path) -> Arc<AppState> {
    let Ok(mut state) = Arc::try_unwrap(state) else {
        unreachable!("fresh state has one owner")
    };
    state.cert_registry = Some(Arc::new(CertRegistry::load(path)));
    Arc::new(state)
}

/// Replace the CA registry at `path` (atomically, as the bridge does) with
/// one certificate: serial 1, `identity`, `role`, `revoked`. Each write
/// gets a later mtime, so the registry sees every change.
pub(crate) fn write_cert_registry(
    path: &std::path::Path,
    identity: &str,
    role: &str,
    revoked: bool,
) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static WRITES: AtomicU64 = AtomicU64::new(1);
    let registry = serde_json::json!({"issued": {"1": {
        "identity": identity, "role": role, "revoked": revoked,
        "not_after": "2099-01-01T00:00:00+00:00",
    }}});
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, registry.to_string()).unwrap();
    std::fs::rename(&tmp, path).unwrap();
    let mtime =
        std::time::SystemTime::now() + Duration::from_secs(WRITES.fetch_add(1, Ordering::SeqCst));
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
}

/// The certificate [`write_cert_registry`] registers (no fingerprint is
/// recorded, so serial and identity decide).
pub(crate) fn client_cert(identity: &str) -> ClientCertInfo {
    ClientCertInfo {
        identity: identity.into(),
        serial: "1".into(),
        fingerprint_sha256: "ab".repeat(32),
    }
}

/// Serve `routes` (behind the auth middleware) on a loopback port.
pub(crate) async fn serve(state: Arc<AppState>, routes: Router<Arc<AppState>>) -> SocketAddr {
    let app = routes
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state);
    listen(app).await
}

/// [`serve`] where every connection presents `cert`, as the TLS acceptor
/// reports a verified client certificate.
pub(crate) async fn serve_with_cert(
    state: Arc<AppState>,
    routes: Router<Arc<AppState>>,
    cert: ClientCertInfo,
) -> SocketAddr {
    let app = routes
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(axum::middleware::from_fn(
            move |mut req: axum::extract::Request, next: axum::middleware::Next| {
                req.extensions_mut().insert(cert.clone());
                next.run(req)
            },
        ))
        .with_state(state);
    listen(app).await
}

async fn listen(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    addr
}

/// One handshake the fake bridge received.
#[derive(Debug, Clone)]
pub(crate) struct Seen {
    pub path_and_query: String,
    pub headers: axum::http::HeaderMap,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BridgeEvent {
    /// The gateway closed the upstream socket (close code, if any).
    Closed(Option<u16>),
}

/// A fake bridge: records handshakes, selects `bridge-v1` when offered,
/// echoes text as `echo:<text>`, and closes with 4003 on `close-4003`.
pub(crate) struct FakeBridge {
    pub url: String,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    pub events: mpsc::UnboundedReceiver<BridgeEvent>,
}

pub(crate) async fn fake_bridge() -> FakeBridge {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let (tx, events) = mpsc::unbounded_channel();
    let record = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let record = Arc::clone(&record);
            let tx = tx.clone();
            tokio::spawn(async move {
                // The handshake callback's error type is tungstenite's.
                #[allow(clippy::result_large_err)]
                let callback = |req: &server::Request, mut resp: server::Response| {
                    record.lock().unwrap().push(Seen {
                        path_and_query: req
                            .uri()
                            .path_and_query()
                            .map(|p| p.to_string())
                            .unwrap_or_default(),
                        headers: req.headers().clone(),
                    });
                    let offered = req
                        .headers()
                        .get("sec-websocket-protocol")
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|v| v.split(',').any(|p| p.trim() == "bridge-v1"));
                    if offered {
                        resp.headers_mut()
                            .insert("sec-websocket-protocol", "bridge-v1".parse().unwrap());
                    }
                    Ok(resp)
                };
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(stream, callback).await else {
                    return;
                };
                while let Some(msg) = ws.next().await {
                    match msg {
                        Ok(Message::Text(t)) if t.as_str() == "close-4003" => {
                            let _ = ws
                                .send(Message::Close(Some(CloseFrame {
                                    code: 4003.into(),
                                    reason: "bye".into(),
                                })))
                                .await;
                        }
                        Ok(Message::Text(t)) => {
                            let _ = ws.send(Message::Text(format!("echo:{t}").into())).await;
                        }
                        Ok(Message::Close(frame)) => {
                            let _ = tx.send(BridgeEvent::Closed(frame.map(|f| f.code.into())));
                            break;
                        }
                        Ok(_) => {}
                        Err(_) => {
                            let _ = tx.send(BridgeEvent::Closed(None));
                            break;
                        }
                    }
                }
            });
        }
    });
    FakeBridge { url, seen, events }
}

pub(crate) type Client =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Open a client WebSocket to `addr` + `path` with extra headers. `Err` is
/// the HTTP status of a refused upgrade.
pub(crate) async fn connect(
    addr: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<(Client, Option<String>), u16> {
    upgraded(tokio_tungstenite::connect_async(client_request(addr, path, headers)).await)
}

fn client_request(
    addr: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
) -> tungstenite::handshake::client::Request {
    let mut req = format!("ws://{addr}{path}").into_client_request().unwrap();
    for (name, value) in headers {
        req.headers_mut().append(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    req
}

/// The socket and selected subprotocol of a client handshake, or the HTTP
/// status of a refused upgrade.
fn upgraded<S>(
    handshake: Result<
        (WebSocketStream<S>, tungstenite::handshake::client::Response),
        tungstenite::Error,
    >,
) -> Result<(WebSocketStream<S>, Option<String>), u16> {
    match handshake {
        Ok((ws, resp)) => Ok((
            ws,
            resp.headers()
                .get("sec-websocket-protocol")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
        )),
        Err(tungstenite::Error::Http(resp)) => Err(resp.status().as_u16()),
        Err(e) => panic!("unexpected handshake error: {e}"),
    }
}

/// The address an in-memory gateway answers on, and the loopback peer
/// address its connections report (`ConnectInfo`).
const MEM_GATEWAY: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443);
const MEM_PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000);

/// A gateway like [`serve`]'s, reached over in-memory pipes instead of
/// loopback TCP. For tests on a paused tokio clock (`start_paused`).
///
/// A paused clock jumps to the next timer whenever the runtime is idle. Over
/// loopback TCP the runtime can be idle while a frame is still on its way
/// through the kernel (macOS delivers loopback packets on a kernel thread,
/// after the sender's write has returned), so the clock can jump to the
/// test's deadline and time out with the frame in flight. Over these pipes
/// every byte moves inside the runtime: the clock only advances when no
/// frame is left to deliver.
pub(crate) struct MemGateway {
    accept: mpsc::UnboundedSender<DuplexStream>,
}

pub(crate) type MemClient = WebSocketStream<DuplexStream>;

/// [`serve`] `routes` on a [`MemGateway`].
pub(crate) fn serve_in_memory(state: Arc<AppState>, routes: Router<Arc<AppState>>) -> MemGateway {
    let app = routes
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state);
    let (accept, incoming) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        // `tap_io` does nothing to the pipe; axum installs `ConnectInfo`
        // for a tapped listener of any kind, but untapped only for TCP.
        axum::serve(
            MemListener(incoming).tap_io(|_| {}),
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    MemGateway { accept }
}

impl MemGateway {
    /// [`connect`] to this gateway over a new in-memory pipe.
    pub(crate) async fn connect(
        &self,
        path: &str,
        headers: &[(&str, &str)],
    ) -> Result<(MemClient, Option<String>), u16> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        self.accept
            .send(server)
            .expect("the in-memory gateway is serving");
        upgraded(
            tokio_tungstenite::client_async(client_request(MEM_GATEWAY, path, headers), client)
                .await,
        )
    }
}

/// Hands [`MemGateway::connect`]'s pipes to `axum::serve`.
struct MemListener(mpsc::UnboundedReceiver<DuplexStream>);

impl axum::serve::Listener for MemListener {
    type Io = DuplexStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (DuplexStream, SocketAddr) {
        match self.0.recv().await {
            Some(pipe) => (pipe, MEM_PEER),
            // The MemGateway is gone: no connection can come any more.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(MEM_GATEWAY)
    }
}

/// Next message within `secs` seconds (`None` on timeout or end).
pub(crate) async fn next_msg<S>(ws: &mut WebSocketStream<S>, secs: u64) -> Option<Message>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::time::timeout(Duration::from_secs(secs), ws.next()).await {
        Ok(Some(Ok(msg))) => Some(msg),
        _ => None,
    }
}

/// The close code the client eventually receives (skipping data frames).
pub(crate) async fn close_code<S>(ws: &mut WebSocketStream<S>, secs: u64) -> Option<u16>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, ws.next()).await {
            Ok(Some(Ok(Message::Close(frame)))) => return frame.map(|f| f.code.into()),
            Ok(Some(Ok(_))) => continue,
            _ => return None,
        }
    }
}
