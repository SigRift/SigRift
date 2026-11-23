//! Test helpers: an [`AppState`] over a temporary SQLite database holding
//! the bridge's auth tables (the bridge owns the real schema; this is the
//! subset the auth handlers touch).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use clap::Parser;
use tokio::sync::broadcast;

use crate::analysis::correlator::NodeCorrelator;
use crate::config::Config;
use crate::db::pool::{DbPool, PooledConn};
use crate::middleware::auth::{AuthConfig, SessionBindingMode};
use crate::scoring::baseline::BaselineManager;
use crate::scoring::weights::ScoringWeights;
use crate::storage::security_state::SecurityLimits;
use crate::storage::sessions::SessionConfig;
use crate::{AppState, FeatureRoutes, NullLicenseResolver};

/// A bridge URL that refuses connections at once: nothing listens on
/// (privileged) port 1 — the crate's usual unreachable bridge. No test
/// binds it.
pub(crate) const REFUSED_URL: &str = "http://127.0.0.1:1";

const AUTH_SCHEMA: &str = "
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    display_name TEXT DEFAULT '',
    email TEXT DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_login TEXT,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    totp_secret TEXT DEFAULT NULL,
    mfa_enabled BOOLEAN NOT NULL DEFAULT 0
);
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip_address TEXT DEFAULT '',
    user_agent TEXT DEFAULT '',
    last_active TEXT,
    scope TEXT DEFAULT ''
);
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    target_id TEXT NOT NULL,
    target_ids TEXT DEFAULT '',
    signal_class TEXT DEFAULT '',
    freq_hz REAL DEFAULT 0.0,
    node_id TEXT DEFAULT '',
    operator TEXT DEFAULT '',
    note TEXT DEFAULT '',
    details TEXT DEFAULT '',
    tenant_id TEXT NOT NULL DEFAULT 'default',
    hmac_chain TEXT DEFAULT ''
);
CREATE TABLE mfa_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE mfa_backup_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    code_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    used BOOLEAN NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE totp_replay_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    totp_code TEXT NOT NULL,
    used_at REAL NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'default'
);
";

/// An [`AppState`] (development mode, audit key set) whose database lives
/// in `dir`.
pub(crate) fn app_state(dir: &tempfile::TempDir) -> Arc<AppState> {
    let mut config = Config::try_parse_from(["sigrift-gateway"]).unwrap();
    config.bridge_env = "development".to_string();
    config.audit_key = "test-audit-key".to_string();
    config.mfa_key = String::new();
    config.password_history_count = 5;
    config.db_path = dir.path().join("auth.db");

    // The pool opens its connections at once, and each puts the file in WAL
    // mode: on a new file all but one then wait out SQLite's busy backoff
    // (about 0.4 s per test). Switching it first makes theirs a no-op.
    rusqlite::Connection::open(&config.db_path)
        .unwrap()
        .execute_batch("PRAGMA journal_mode = WAL")
        .unwrap();
    let db_pool = crate::db::pool::create_pool(&config.db_path, 4, 5_000).unwrap();
    db_pool.get().unwrap().execute_batch(AUTH_SCHEMA).unwrap();

    let auth_config = AuthConfig {
        session_config: SessionConfig::default(),
        security_limits: SecurityLimits {
            rate_limit_max: 100,
            rate_limit_window_secs: 60.0,
            lockout_max: 100,
            lockout_window_secs: 60.0,
        },
        binding_mode: SessionBindingMode::None,
        csrf_enabled: false,
        trusted_proxies: Default::default(),
    };
    Arc::new(AppState {
        db_pool,
        baseline_manager: RwLock::new(BaselineManager::new(config.baseline_alpha)),
        scoring_weights: ScoringWeights::default(),
        correlator: RwLock::new(NodeCorrelator::new(config.active_nodes)),
        detection_tx: broadcast::channel(16).0,
        anomaly_tx: broadcast::channel(16).0,
        key_store: None,
        auth_enabled: false,
        cert_registry: None,
        proxy_client: reqwest::Client::new(),
        auth_config: Arc::new(tokio::sync::RwLock::new(auth_config)),
        audit_tx: broadcast::channel(16).0,
        license_resolver: Arc::new(NullLicenseResolver),
        feature_routes: FeatureRoutes::EMPTY,
        ingest_hooks: Arc::default(),
        config,
    })
}

/// Count audit-log rows with this action.
pub(crate) fn audit_count(state: &AppState, action: &str) -> i64 {
    state
        .db_pool
        .get()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM audit_log WHERE action = ?1",
            [action],
            |row| row.get(0),
        )
        .unwrap()
}

/// Per slot, how many connections have queued behind a [`WriteLockGate`].
/// A SQLite busy handler is a plain `fn` that cannot capture any state, so
/// each test that uses a gate takes a slot of its own (the gate's `SLOT`):
/// 0 for the storage test of `reserve_login_attempt`, 1 for the login
/// handler's. A new user adds a slot.
static GATE_QUEUED: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];

/// The busy handler of the connections behind a [`WriteLockGate`]: counts
/// the connection in `SLOT` when it starts waiting for a lock, then retries
/// every millisecond, for about ten seconds at most (so a test that never
/// opens its gate fails instead of hanging).
fn queue_behind_gate<const SLOT: usize>(retries: i32) -> bool {
    if retries == 0 {
        GATE_QUEUED[SLOT].fetch_add(1, Ordering::SeqCst);
    }
    std::thread::sleep(Duration::from_millis(1));
    retries < 10_000
}

/// Holds the database's write lock, so a test can force the interleaving a
/// race needs instead of hoping for it.
///
/// [`close`](Self::close) takes the write lock (`BEGIN IMMEDIATE` on one of
/// the pool's connections) and has the pool's other connections report
/// when they start waiting for a lock. A statement that writes then waits
/// whole, since SQLite takes the write lock before the statement reads
/// anything; a read run before it as a statement of its own does not wait
/// (in WAL mode readers never wait for the writer). Once the given number
/// of writers are queued, [`open_when_queued`](Self::open_when_queued)
/// commits, and they go on one at a time. The other connections keep the
/// gate's busy handler, which then waits as `busy_timeout` would.
pub(crate) struct WriteLockGate<const SLOT: usize> {
    holder: PooledConn,
}

impl<const SLOT: usize> WriteLockGate<SLOT> {
    /// Take the write lock of `pool`'s database. Every connection of the
    /// pool must be free.
    pub(crate) fn close(pool: &DbPool) -> Self {
        let mut conns: Vec<PooledConn> =
            (0..pool.max_size()).map(|_| pool.get().unwrap()).collect();
        let holder = conns.pop().unwrap();
        for conn in &mut conns {
            conn.busy_handler(Some(queue_behind_gate::<SLOT>)).unwrap();
        }
        drop(conns);
        GATE_QUEUED[SLOT].store(0, Ordering::SeqCst);
        holder.execute_batch("BEGIN IMMEDIATE").unwrap();
        Self { holder }
    }

    /// Wait (ten seconds at most) until `writers` connections are queued
    /// behind the gate, then release the write lock. Panics, after
    /// releasing it, if fewer than that ever queued.
    pub(crate) fn open_when_queued(self, writers: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        let queued = loop {
            let queued = GATE_QUEUED[SLOT].load(Ordering::SeqCst);
            if queued >= writers || Instant::now() >= deadline {
                break queued;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        self.holder.execute_batch("COMMIT").unwrap();
        assert!(
            queued >= writers,
            "only {queued} of {writers} writers queued behind the write lock"
        );
    }
}

/// Call before a test captures its thread's logs with a subscriber of
/// its own (`tracing::subscriber::set_default` or `with_default`), so
/// that it sees every event it logs while other tests run in parallel.
///
/// tracing caches, per callsite and for every thread, whether any
/// subscriber wants its events. While a single dispatcher is registered
/// (the capturing test's alone), a callsite hit for the first time is
/// asked of the subscriber of the thread that hits it: a parallel test's
/// thread, which has none, caches "never", and the capturing test then
/// never sees that event. This keeps a second dispatcher registered for
/// the whole run, so the interest is always asked of every registered
/// dispatcher, the capturing one included. It takes no event and sets
/// the max level to OFF, so it changes nothing else.
pub(crate) fn keep_log_capture_reliable() {
    use tracing_subscriber::layer::SubscriberExt as _;
    static SECOND_DISPATCHER: std::sync::OnceLock<tracing::Dispatch> = std::sync::OnceLock::new();
    SECOND_DISPATCHER.get_or_init(|| {
        tracing::Dispatch::new(
            tracing_subscriber::registry().with(tracing_subscriber::filter::LevelFilter::OFF),
        )
    });
}

/// Everything logged at INFO and above on this thread while `f` runs, as
/// text.
pub(crate) fn logs_of<R>(f: impl FnOnce() -> R) -> (R, String) {
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
        .with_max_level(tracing::Level::INFO)
        .finish();
    keep_log_capture_reliable();
    let result = tracing::subscriber::with_default(subscriber, f);
    let text = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
    (result, text)
}
