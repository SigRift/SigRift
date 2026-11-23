//! Gateway builder — the async-runtime body shared by every SigRift gateway
//! binary.
//!
//! The community binary (`sigrift-gateway`) owns its own pre-runtime
//! setup (CLI parsing, tracing init, TLS crypto provider, licence
//! loading) and then hands a configured [`GatewayBuilder`] off to its
//! `run()` method. Enterprise binaries (shipped in a separate
//! repository) follow the same contract with their own resolvers.
//!
//! The builder injects a [`SharedLicenseResolver`] so the runtime never
//! touches licensing keys or crypto directly. Community binaries inject
//! [`crate::NullLicenseResolver`]; enterprise binaries inject a real
//! resolver.

use std::sync::{Arc, RwLock};

use axum::{
    extract::State,
    http::{header, HeaderName, HeaderValue, Method},
    routing::{get, post, put},
    Router,
};
use tokio::sync::broadcast;
use tower_http::{cors::CorsLayer, limit::RequestBodyLimitLayer};
use tracing::{error, info, warn};

use crate::analysis::correlator::NodeCorrelator;
use crate::auth;
use crate::config::Config;
use crate::db;
use crate::feature_routes::FeatureRoutes;
use crate::ingest;
use crate::middleware::auth::{auth_middleware, AuthConfig, SessionBindingMode};
use crate::middleware::client_ip::parse_trusted_proxies;
use crate::middleware::csrf::csrf_middleware;
use crate::middleware::security::{CspMode, SecurityConfig, SecurityHeadersLayer};
use crate::proxy::handler::{
    build_proxy_client, is_loopback_url, proxy_fallback, proxy_secret_header,
};
use crate::proxy::ws_proxy;
use crate::query;
use crate::scoring::baseline::BaselineManager;
use crate::scoring::weights::ScoringWeights;
use crate::storage;
use crate::storage::security_state::SecurityLimits;
use crate::ws;
use crate::{audit, AppState, SharedLicenseResolver};

/// Error returned from [`GatewayBuilder::run`]. Binaries typically convert
/// this into a non-zero exit code.
#[derive(Debug)]
pub enum BuilderError {
    /// Production config rejected at startup (missing secret, weak default).
    Config(String),
    /// Failed to initialise the SQLite connection pool.
    DbPool(String),
    /// The database was migrated by a newer bridge than this build knows,
    /// or its schema version could not be read
    /// ([`db::schema::refuse_newer_schema`]).
    Schema(String),
    /// Failed to bind the listening socket.
    Bind(String),
    /// Failed to load TLS material.
    Tls(String),
    /// The serve loop terminated with an error.
    Serve(String),
}

impl std::fmt::Display for BuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuilderError::Config(m) => write!(f, "config: {m}"),
            BuilderError::DbPool(m) => write!(f, "db pool: {m}"),
            BuilderError::Schema(m) => write!(f, "schema: {m}"),
            BuilderError::Bind(m) => write!(f, "bind: {m}"),
            BuilderError::Tls(m) => write!(f, "tls: {m}"),
            BuilderError::Serve(m) => write!(f, "serve: {m}"),
        }
    }
}

impl std::error::Error for BuilderError {}

/// Gateway runtime assembly. Wraps the configured [`Config`] and an
/// injected [`SharedLicenseResolver`]. Community binaries inject a
/// [`crate::NullLicenseResolver`]; the legacy monorepo binary injects an
/// HS256-backed resolver; sentinel (in a separate repository) injects a
/// hybrid Ed25519 + ML-DSA-65 resolver.
pub struct GatewayBuilder {
    config: Config,
    license_resolver: SharedLicenseResolver,
    feature_routes: FeatureRoutes,
}

impl GatewayBuilder {
    /// Construct a builder with the required inputs. The resolver decides
    /// what `X-License-Tier`, `X-License-Features`, `X-License-Node-Limit`,
    /// and feature-gate answers the gateway returns. Core never constructs
    /// a concrete resolver itself.
    ///
    /// The feature-route table defaults to [`FeatureRoutes::EMPTY`] —
    /// community builds never gate any path prefix. Call
    /// [`GatewayBuilder::with_feature_routes`] to inject a real table.
    pub fn new(config: Config, license_resolver: SharedLicenseResolver) -> Self {
        Self {
            config,
            license_resolver,
            feature_routes: FeatureRoutes::EMPTY,
        }
    }

    /// Inject the path-prefix → required-feature table the proxy handler
    /// consults before forwarding to Python. HS256 and hybrid-PQC binaries
    /// use this to enforce tier-gated routes; community omits it.
    pub fn with_feature_routes(mut self, routes: FeatureRoutes) -> Self {
        self.feature_routes = routes;
        self
    }

    /// Runs the gateway until shutdown. Intended to be called from a tokio
    /// runtime (e.g. `#[tokio::main]`) owned by the binary crate.
    pub async fn run(self) -> Result<(), BuilderError> {
        let Self {
            config,
            license_resolver,
            feature_routes,
        } = self;

        // Production security guards — fail closed on missing secrets.
        check_startup_secrets(&config, |name| std::env::var(name).ok())?;
        // Refuse a session timeout the bridge may read as another value.
        let session_config = config.session_config().map_err(BuilderError::Config)?;

        // SIGTERM (docker stop) or Ctrl-C: stop listening, then deliver or
        // save the queued post-ingest hooks (K8b). Listened for from here
        // on, so a stop during the wait for the bridge is not ignored.
        let shutdown = ShutdownSignal::listen();

        info!(
            host = %config.host,
            port = config.port,
            python_url = %config.python_url,
            db_path = %config.db_path.display(),
            pool_size = config.pool_size,
            tls = config.tls_enabled(),
            env = %config.bridge_env,
            tier = %license_resolver.tier().as_str(),
            issuer = %license_resolver.issuer(),
            "Starting SigRift gateway"
        );

        // Database connection pool
        let db_pool = db::pool::create_pool(
            &config.db_path,
            config.pool_size,
            config.sqlite_busy_timeout,
        )
        .map_err(|e| BuilderError::DbPool(e.to_string()))?;

        // Refuse a database from a newer bridge, then verify the schema and
        // ensure the Rust-managed tables exist.
        prepare_database(&db_pool)?;

        // Baseline manager
        let mut baseline_manager = BaselineManager::new(config.baseline_alpha);
        if config.baseline_path.exists() {
            if let Err(e) = baseline_manager.load(&config.baseline_path) {
                warn!(error = %e, "Failed to load baselines");
            }
        }

        // Key store — fail CLOSED on missing/unreadable keys file.
        //
        // A missing or unreadable keys file means no API keys can be
        // loaded. Silently disabling auth in that case is fail-OPEN: every
        // route that gates on `auth_enabled` would then serve
        // unauthenticated requests. Instead we refuse to start unless the
        // operator has explicitly opted into a no-auth dev/test mode via
        // UC_ALLOW_NO_AUTH.
        let key_store = if config.keys_path.exists() {
            auth::api_key::KeyStore::try_new(&config.keys_path)
        } else {
            None
        };
        let auth_enabled = match (&key_store, config.allow_no_auth) {
            // Keys loaded — enforce auth (the normal path).
            (Some(_), _) => true,
            // No key store, but the operator explicitly allowed no-auth.
            (None, true) => {
                warn!(
                    path = %config.keys_path.display(),
                    "UC_ALLOW_NO_AUTH is set and the keys file is missing or \
                     unreadable — API-key authentication is DISABLED and every \
                     request is served unauthenticated. Never use this in \
                     production."
                );
                false
            }
            // No key store and no explicit opt-in — fail CLOSED by refusing
            // to start rather than silently serving unauthenticated traffic.
            (None, false) => {
                return Err(BuilderError::Config(format!(
                    "keys file {} is missing or unreadable and UC_ALLOW_NO_AUTH \
                     is not set — refusing to start with authentication disabled",
                    config.keys_path.display()
                )));
            }
        };

        // Client-cert (PKI) identity registry — Phase A mTLS auth. Loaded
        // when UC_CA_REGISTRY_PATH is set; resolves verified client-cert
        // identities to roles. Absent = client-cert auth disabled.
        let cert_registry = config.ca_registry_path.as_ref().map(|p| {
            info!(path = %p.display(), "Client-cert registry configured");
            Arc::new(auth::client_cert::CertRegistry::load(p))
        });

        // Proxy HTTP client
        let proxy_client = build_proxy_client(config.proxy_timeout, &config.python_url);

        // Auth config
        let trusted_proxies = parse_trusted_proxies(&config.trusted_proxies);
        let csrf_enabled = csrf_enabled(&config);
        let auth_config = AuthConfig {
            session_config,
            security_limits: SecurityLimits {
                rate_limit_max: config.rate_limit_max,
                rate_limit_window_secs: config.rate_limit_window_secs as f64,
                lockout_max: config.lockout_max,
                lockout_window_secs: config.lockout_window_secs as f64,
            },
            binding_mode: SessionBindingMode::from(config.session_binding.as_str()),
            csrf_enabled,
            trusted_proxies,
        };

        // Broadcast channels
        let (detection_tx, _) = broadcast::channel::<String>(1024);
        let (anomaly_tx, _) = broadcast::channel::<String>(1024);
        let (audit_tx, _) = broadcast::channel::<String>(256);

        let state = Arc::new(AppState {
            config: config.clone(),
            db_pool,
            baseline_manager: RwLock::new(baseline_manager),
            scoring_weights: ScoringWeights::default(),
            correlator: RwLock::new(NodeCorrelator::new(config.active_nodes)),
            detection_tx,
            anomaly_tx,
            key_store,
            auth_enabled,
            cert_registry,
            proxy_client,
            auth_config: Arc::new(tokio::sync::RwLock::new(auth_config)),
            audit_tx,
            license_resolver,
            feature_routes,
            ingest_hooks: Arc::new(ingest::hooks::IngestHooks::default()),
        });

        if config.unbound_node_keys_allowed() {
            warn!(
                "BRIDGE_ALLOW_UNBOUND_NODE_KEYS is set — unbound node API keys \
                 (SENSOR/NODE) stay unbound and may submit detection batches for ANY \
                 node; unbound VIEWER keys are still refused"
            );
        }

        // Wait for Python backend, then check the schema it migrated
        if wait_for_bridge(&config, &state.db_pool, shutdown.clone()).await? == BridgeWait::Stop {
            return Ok(());
        }

        // Every audit entry the gateway writes is published to /ws/audit.
        // Set only once nothing refuses the start any more: the sink is
        // process-wide, and no one subscribes to /ws/audit before serving.
        audit::store::set_event_sink(state.audit_tx.clone());

        // Deliver the bridge's post-ingest work for ingested batches (K8),
        // starting with what the last run saved at shutdown (K8b).
        let hook_target = ingest::hooks::HookTarget::new(
            state.proxy_client.clone(),
            &config.python_url,
            &config.proxy_secret,
        );
        let spool_path = config.hook_spool_file();
        let (stop_hook_worker, hook_worker_stop) = tokio::sync::watch::channel(false);
        let hook_worker = if config.proxy_secret_usable() {
            restore_hook_spool(&state.ingest_hooks, &spool_path).await;
            Some(ingest::hooks::spawn_worker_until(
                Arc::clone(&state.ingest_hooks),
                hook_target.clone(),
                hook_worker_stop,
            ))
        } else {
            // K10: hooks are disabled (the startup error says why). Keep a
            // spool from an earlier run for when the secret is set.
            if spool_path.exists() {
                warn!(
                    path = %spool_path.display(),
                    "Saved post-ingest hooks are kept, not sent: UC_PROXY_SECRET is not \
                     usable. They are sent at the first start with it set."
                );
            }
            None
        };

        // Periodic baseline save + WAL checkpoint + session/security cleanup
        let state_clone = Arc::clone(&state);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                // Serialising and writing the baselines is blocking work:
                // keep it off the async workers.
                let saver = Arc::clone(&state_clone);
                let saved = tokio::task::spawn_blocking(move || {
                    let mgr = saver
                        .baseline_manager
                        .read()
                        .unwrap_or_else(|e| e.into_inner());
                    mgr.save(&saver.config.baseline_path)
                        .map_err(|e| e.to_string())
                })
                .await;
                match saved {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => warn!(error = %e, "Failed to save baselines"),
                    Err(e) => warn!(error = %e, "Baseline save task failed"),
                }
                let security_limits = {
                    let cfg = state_clone.auth_config.read().await;
                    cfg.security_limits.clone()
                };
                if let Ok(conn) = state_clone.db_pool.get() {
                    match storage::sessions::cleanup_expired_sessions(&conn) {
                        Ok(n) if n > 0 => info!(deleted = n, "Expired sessions cleaned"),
                        Err(e) => warn!(error = %e, "Session cleanup failed"),
                        _ => {}
                    }
                    let _ =
                        storage::security_state::cleanup_all(&conn, "default", &security_limits);
                    let _ = storage::mfa::cleanup_expired_mfa_tokens(&conn);
                    let _ = storage::mfa::cleanup_totp_replay(&conn, "default");
                    let _ = storage::nodes::reap_expired_commands(&conn);
                    match conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE)") {
                        Ok(_) => info!("WAL checkpoint completed"),
                        Err(e) => warn!(error = %e, "WAL checkpoint failed"),
                    }
                }
            }
        });

        // Bind and serve until a shutdown signal (then for at most
        // SERVER_SHUTDOWN_GRACE more, to finish the requests in progress).
        let served = serve_gateway(Arc::clone(&state), shutdown).await;

        // Nothing new is ingested now: deliver what is still queued, and
        // save the rest for the next start (K8b) — also when serving
        // failed, so hooks restored from the spool are not lost.
        if let Some(worker) = hook_worker {
            let _ = stop_hook_worker.send(true);
            if let Err(e) = worker.await {
                warn!(error = %e, "The post-ingest hook task ended abnormally");
            }
            state
                .ingest_hooks
                .shutdown(&hook_target, &spool_path, ingest::hooks::SHUTDOWN_DRAIN)
                .await;
        }
        info!("Gateway stopped");
        served
    }
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

/// How long requests in progress get to finish once a shutdown signal
/// arrived, before the listener stops anyway. With the hook drain
/// ([`ingest::hooks::SHUTDOWN_DRAIN`]) this stays under Docker's 10 s stop
/// timeout.
pub const SERVER_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

/// Becomes ready once the process is asked to stop (SIGTERM or Ctrl-C).
/// Before this, the gateway ignored SIGTERM: as PID 1 in its container it
/// was killed 10 s after `docker stop`, losing its queued post-ingest
/// hooks.
#[derive(Debug, Clone)]
pub struct ShutdownSignal(tokio::sync::watch::Receiver<bool>);

impl ShutdownSignal {
    /// Listen for SIGTERM and Ctrl-C (SIGINT) from now on: SIGTERM is
    /// caught from the moment this returns.
    pub fn listen() -> Self {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let signals = StopSignals::register();
        tokio::spawn(async move {
            let signal = signals.wait().await;
            info!(
                signal,
                "Shutdown requested — finishing requests in progress, then delivering or \
                 saving the queued post-ingest hooks"
            );
            let _ = tx.send(true);
        });
        Self(rx)
    }

    /// A signal that becomes ready when `rx` becomes true (tests).
    pub fn from_receiver(rx: tokio::sync::watch::Receiver<bool>) -> Self {
        Self(rx)
    }

    /// Resolves once shutdown was requested. Never, if the sender is gone
    /// without requesting it.
    pub async fn wait(mut self) {
        if self.0.wait_for(|&stop| stop).await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// The signals that stop the gateway: SIGTERM (caught from registration
/// on) and SIGINT (Ctrl-C). One that cannot be listened for is logged, and
/// only the other counts — a failure to listen never stops the gateway.
struct StopSignals {
    #[cfg(unix)]
    term: Option<tokio::signal::unix::Signal>,
}

impl StopSignals {
    fn register() -> Self {
        #[cfg(unix)]
        let term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(term) => Some(term),
            Err(e) => {
                warn!(error = %e, "Cannot listen for SIGTERM; only Ctrl-C stops the gateway cleanly");
                None
            }
        };
        Self {
            #[cfg(unix)]
            term,
        }
    }

    /// The name of the first of them to arrive.
    async fn wait(self) -> &'static str {
        #[cfg(unix)]
        if let Some(mut term) = self.term {
            return tokio::select! {
                _ = term.recv() => "SIGTERM",
                ctrl_c = tokio::signal::ctrl_c() => match ctrl_c {
                    Ok(()) => "SIGINT",
                    Err(e) => {
                        warn!(error = %e, "Cannot listen for Ctrl-C");
                        term.recv().await;
                        "SIGTERM"
                    }
                },
            };
        }
        match tokio::signal::ctrl_c().await {
            Ok(()) => "SIGINT",
            Err(e) => {
                warn!(error = %e, "Cannot listen for Ctrl-C");
                std::future::pending().await
            }
        }
    }
}

/// Serve the gateway's app ([`served_app`], with the security headers
/// `state.config` asks for) on the configured listener, TLS when a
/// certificate and key are configured, until `shutdown`; then for at most
/// [`SERVER_SHUTDOWN_GRACE`] more, to finish the requests in progress.
///
/// The end of [`GatewayBuilder::run`], kept apart so that tests serve
/// exactly this on a real port (`security_header_tests`): what they check
/// is what `run` serves.
async fn serve_gateway(state: Arc<AppState>, shutdown: ShutdownSignal) -> Result<(), BuilderError> {
    let config = &state.config;
    let security_config = SecurityConfig {
        csp_mode: CspMode::from(config.csp_mode.as_str()),
        hsts_enabled: config.hsts_enabled,
        tls_active: config.tls_enabled(),
    };
    let app = served_app(Arc::clone(&state), security_config);
    let bind_addr = config.bind_addr();
    if config.tls_enabled() {
        serve_tls(app, &bind_addr, config, shutdown).await
    } else {
        match tokio::net::TcpListener::bind(&bind_addr).await {
            Ok(listener) => {
                info!(addr = %bind_addr, tls = false, "Listening (plaintext)");
                serve_plain(listener, app, shutdown).await
            }
            Err(e) => Err(BuilderError::Bind(format!("{bind_addr}: {e}"))),
        }
    }
}

/// Serve `app` on `listener` until `shutdown`; then stop accepting
/// connections and let requests in progress finish, for at most
/// [`SERVER_SHUTDOWN_GRACE`].
async fn serve_plain(
    listener: tokio::net::TcpListener,
    app: Router,
    shutdown: ShutdownSignal,
) -> Result<(), BuilderError> {
    use std::future::IntoFuture as _;
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown.clone().wait())
    .into_future();
    tokio::select! {
        served = server => served.map_err(|e| BuilderError::Serve(e.to_string())),
        () = async {
            shutdown.wait().await;
            tokio::time::sleep(SERVER_SHUTDOWN_GRACE).await;
        } => {
            warn!(
                grace_secs = SERVER_SHUTDOWN_GRACE.as_secs(),
                "Requests still in progress after the shutdown grace period — stopping anyway"
            );
            Ok(())
        }
    }
}

/// Queue again the post-ingest hooks the last run saved at shutdown.
async fn restore_hook_spool(hooks: &Arc<ingest::hooks::IngestHooks>, path: &std::path::Path) {
    let restoring = Arc::clone(hooks);
    let file = path.to_path_buf();
    match tokio::task::spawn_blocking(move || restoring.restore(&file)).await {
        Ok(Ok(report)) if report.batches > 0 || report.skipped_lines > 0 => {
            info!(
                path = %path.display(),
                batches = report.batches,
                detections = report.detections,
                skipped_lines = report.skipped_lines,
                "Queued the post-ingest hooks saved at the last shutdown"
            );
            if report.truncated {
                warn!(
                    path = %path.display(),
                    max_bytes = ingest::hooks::SPOOL_MAX_BYTES,
                    "The post-ingest hook spool was larger than allowed; the rest was discarded"
                );
            }
        }
        Ok(Ok(_)) => {}
        Ok(Err(e)) => error!(
            path = %path.display(),
            error = %e,
            "Cannot replay the post-ingest hooks saved at the last shutdown"
        ),
        Err(e) => error!(error = %e, "The post-ingest hook spool task failed"),
    }
}

/// Refuse a database that a newer bridge has migrated (PRE-68): see
/// [`db::schema::refuse_newer_schema`].
fn refuse_newer_schema(db_pool: &db::pool::DbPool) -> Result<(), BuilderError> {
    let conn = db_pool
        .get()
        .map_err(|e| BuilderError::DbPool(e.to_string()))?;
    db::schema::refuse_newer_schema(&conn).map_err(|e| BuilderError::Schema(e.to_string()))
}

/// The database steps of startup. First refuse a database that a newer
/// bridge has migrated, before anything here changes its schema. Then check
/// which of the bridge's tables exist (a fresh database, which the bridge
/// has not migrated yet, only gets a warning) and add what the gateway
/// manages itself: the `sessions.scope` column and the `password_history`,
/// `nodes` and `pending_commands` tables.
fn prepare_database(db_pool: &db::pool::DbPool) -> Result<(), BuilderError> {
    refuse_newer_schema(db_pool)?;
    let conn = db_pool
        .get()
        .map_err(|e| BuilderError::DbPool(e.to_string()))?;
    let missing = db::schema::verify_schema(&conn);
    if !missing.is_empty() {
        warn!(
            tables = ?missing,
            "Missing database tables — the Python app must create them first"
        );
    }
    let _ = conn.execute_batch("ALTER TABLE sessions ADD COLUMN scope TEXT DEFAULT ''");
    warn_about_legacy_gateway_keys(&conn);
    let _ = storage::password_history::ensure_password_history_table(&conn);
    let _ = storage::nodes::ensure_node_tables(&conn);
    Ok(())
}

/// Tell the operator about keys an older gateway stored in its own
/// `api_keys` table (see [`storage::api_keys`]): they never authenticated,
/// and they are not the keys the dashboard now manages.
fn warn_about_legacy_gateway_keys(conn: &rusqlite::Connection) {
    match storage::api_keys::legacy_gateway_key_ids(conn) {
        Ok(ids) if !ids.is_empty() => warn!(
            count = ids.len(),
            key_ids = ?ids.iter().take(50).collect::<Vec<_>>(),
            "Found API keys created through an older gateway's /api/admin/keys. They \
             were stored in a table nothing authenticates against, so they never \
             worked. Key management now goes to the bridge (keys.json): re-create \
             any of these you still need from the dashboard, and check the key list \
             there (GET /api/admin/keys) for keys you meant to revoke, rotate or \
             re-role — the old gateway API could not change them. The old table is \
             left untouched."
        ),
        Ok(_) => {}
        Err(e) => warn!(error = %e, "Could not check for legacy gateway API keys"),
    }
}

// ---------------------------------------------------------------------------
// Startup secret checks
// ---------------------------------------------------------------------------

const GENERATE_SECRET_HINT: &str = "python3 -c 'import secrets; print(secrets.token_urlsafe(32))'";

/// The startup error for a development gateway without a usable
/// `UC_PROXY_SECRET` (empty, or the old public default): contract K10.
fn proxy_secret_unusable_message() -> String {
    format!(
        "UC_PROXY_SECRET is not set (or is the old public default \
         'uppercrust-internal'). Node-key binding and post-ingest hooks are DISABLED: \
         both use the bridge's gateway-only API (/api/internal/*), which refuses every \
         request without the proxy secret. So unbound node API keys stay unbound and may \
         submit detection batches for ANY node (as with BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1), \
         and no alert rules, watch-band alerts, webhooks, edge-decoded message storage or \
         protocol-decode jobs run for ingested batches (GET /health counts them in \
         post_ingest_hooks.hooks_disabled). The bridge also ignores the licence headers \
         the gateway sends, and with BRIDGE_REQUIRE_PROXY=true it refuses every proxied \
         request. To fix it, set UC_PROXY_SECRET to the same strong value for the gateway \
         and the bridge (generate one with: {GENERATE_SECRET_HINT}; scripts/quickstart.sh \
         does it) and restart both. BRIDGE_ENV=production refuses to start without it."
    )
}

/// Whether the gateway enforces the CSRF double-submit token on session
/// mutations: `BRIDGE_CSRF=enabled` or `disabled` exactly; otherwise on,
/// unless `BRIDGE_ENV` is `development`, `dev` or `test`.
fn csrf_enabled(config: &Config) -> bool {
    match config.csrf_mode.as_str() {
        "enabled" => true,
        "disabled" => false,
        _ => !matches!(config.bridge_env.as_str(), "development" | "dev" | "test"),
    }
}

/// Why a `BRIDGE_CSRF` value is refused in production, or `None` when it
/// is unset, empty or `enabled`.
///
/// The value is read as the bridge reads it, trimmed and in any letter
/// case. The bridge turns CSRF protection off for every other non-empty
/// value (`disabled`, but also `off`, `true` or `0`), so production
/// refuses all of them, and one `BRIDGE_CSRF` gets the same verdict from
/// both services. (This gateway reads only an exact `disabled` as off.)
fn csrf_setting_problem(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() || normalized == "enabled" {
        return None;
    }
    Some(format!(
        "BRIDGE_CSRF={value:?} turns CSRF protection off (the bridge reads any value \
         other than enabled that way), which production refuses: unset BRIDGE_CSRF \
         or set it to enabled"
    ))
}

/// Check the secrets the gateway needs. In production
/// (`BRIDGE_ENV=production|prod`) every problem is collected and startup
/// is refused; in development each is logged as a warning. That covers
/// a `BRIDGE_CSRF` that turns CSRF protection off ([`csrf_setting_problem`]).
///
/// `env` looks up the secondary audit-key variables (`BRIDGE_AUDIT_SECRET`,
/// `BRIDGE_MASTER_KEY`); injectable for tests.
fn check_startup_secrets(
    config: &Config,
    env: impl Fn(&str) -> Option<String>,
) -> Result<(), BuilderError> {
    let production = config.is_production();
    let mut problems: Vec<String> = Vec::new();

    // The "uppercrust-internal" literal was a hardcoded default on both
    // sides for a long time, so we still reject it explicitly to catch
    // users copying stale docs.
    if !config.proxy_secret_usable() {
        if production {
            problems.push(format!(
                "production mode requires a strong UC_PROXY_SECRET (same value as the \
                 bridge; generate one with: {GENERATE_SECRET_HINT})"
            ));
        } else {
            // K10: say what actually stops working, once.
            error!("{}", proxy_secret_unusable_message());
        }
    }

    // Audit HMAC key: without it every audit event would be dropped (the
    // handlers skip logging when the secret cannot be resolved).
    if production {
        match audit::chain::resolve_audit_secret(&config.audit_key, &config.bridge_env, &env) {
            Err(e) => problems.push(format!(
                "{e} Use the same value as the bridge (generate one with: {GENERATE_SECRET_HINT})"
            )),
            Ok(_) if config.audit_key.trim().is_empty() => warn!(
                "BRIDGE_AUDIT_KEY is not set — the audit HMAC key is derived from the \
                 deprecated BRIDGE_AUDIT_SECRET / BRIDGE_MASTER_KEY fallback. Set \
                 BRIDGE_AUDIT_KEY to the bridge's value; the gateway does not need \
                 BRIDGE_MASTER_KEY."
            ),
            Ok(_) => {}
        }
    }

    // MFA key: must satisfy the Fernet key rule shared with the bridge, or
    // TOTP secrets would be stored unencrypted. The message says how to
    // repair a 43-character legacy key without losing existing secrets.
    if let Some(problem) = auth::fernet_enc::mfa_key_problem(&config.mfa_key) {
        if production {
            problems.push(problem);
        } else {
            warn!(
                "{problem}. Allowed in development: new TOTP secrets are stored \
                 base64-encoded only (NOT encrypted) until the key is fixed; \
                 production refuses to start."
            );
        }
    }

    // CSRF protection: production refuses to run with it off (owner
    // decision, 2026-11-10); elsewhere turning it off is allowed, loudly.
    if let Some(problem) = csrf_setting_problem(&config.csrf_mode) {
        if production {
            problems.push(problem);
        } else if csrf_enabled(config) {
            warn!(
                "{problem}. This gateway reads it as unset and keeps CSRF \
                 protection on (BRIDGE_ENV={}).",
                config.bridge_env
            );
        } else {
            warn!(
                "{problem}. Allowed outside production: CSRF protection is OFF, \
                 and only SameSite=Lax protects session requests; production \
                 refuses to start."
            );
        }
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(BuilderError::Config(format!(
            "BRIDGE_ENV={} — refusing to start: {}",
            config.bridge_env,
            problems.join("; ")
        )))
    }
}

// ---------------------------------------------------------------------------
// Router construction
// ---------------------------------------------------------------------------

/// The app [`GatewayBuilder::run`] serves, from the inside out: the
/// routes behind the CSRF and auth middlewares ([`build_router`]), the
/// body limit, CORS, path canonicalization (K9), the framing guard
/// (RFC 9112 §6.1) and, outermost, the security headers.
///
/// The security headers wrap everything, so every response carries them
/// once: the refusals of the framing guard, of the auth and CSRF
/// middlewares, of the body limit and of the path canonicalization too,
/// not only what the routes answer. The layer only adds response headers
/// (and an `X-Request-ID` on the request) and answers nothing itself, so
/// the framing guard still sees every request before any layer that
/// answers some requests itself (CORS every `OPTIONS`, the body limit,
/// the canonicalization, auth). What a layer inside sets on purpose
/// stays: an inner `Cache-Control` (the auth middleware's `no-store` on
/// `/api/auth/*`, a proxied asset's caching) and the framing guard's
/// `Connection: close` are kept, while a weaker CSP, `X-Frame-Options`
/// and the like are replaced. Every layer and handler inside sees the
/// `X-Request-ID` the security layer puts on the request.
fn served_app(state: Arc<AppState>, security_config: SecurityConfig) -> Router {
    let app = build_router(Arc::clone(&state), &state.config)
        .layer(RequestBodyLimitLayer::new(state.config.max_body_size))
        .layer(build_cors_layer(&state.config.cors_origins))
        .with_state(Arc::clone(&state));
    // K9: canonicalize the request path before routing (and so before
    // every path-based decision); refuse the bridge's internal API.
    // `with_canonical_paths` also puts the framing guard outside that, and
    // so outside CORS and the body limit, which answer some requests
    // themselves: it refuses Content-Length with Transfer-Encoding and
    // closes the connection after any request with Transfer-Encoding.
    crate::middleware::path::with_canonical_paths(app)
        .layer(SecurityHeadersLayer::new(security_config))
}

/// The routes, behind the auth middleware and, inside it, the CSRF
/// middleware (which needs the `AuthInfo` the auth middleware resolves).
fn build_router(state: Arc<AppState>, config: &Config) -> Router<Arc<AppState>> {
    let _ = config;
    Router::new()
        // Detections ingest + queries
        .route("/batch", post(ingest::handler::ingest_batch))
        .route("/api/detections/batch", post(ingest::handler::ingest_batch))
        .route("/api/detections/recent", get(query::handler::get_recent))
        .route(
            "/api/detections/timeline",
            get(query::handler::get_timeline),
        )
        .route(
            "/api/detections/distribution",
            get(query::handler::get_distribution),
        )
        .route("/api/detections/heatmap", get(query::handler::get_heatmap))
        .route("/api/detections/summary", get(query::handler::get_summary))
        .route("/api/detections/stats", get(query::handler::get_summary))
        .route(
            "/api/detections/anomalies/summary",
            get(query::handler::get_anomaly_summary),
        )
        // Auth endpoints
        .route("/api/auth/login", post(auth::session_handler::login))
        .route("/api/auth/logout", post(auth::session_handler::logout))
        .route("/api/auth/me", get(auth::session_handler::me))
        .route(
            "/api/auth/change-password",
            post(auth::session_handler::change_password),
        )
        .route("/api/auth/mfa/setup", post(auth::mfa_handler::mfa_setup))
        .route(
            "/api/auth/mfa/verify-setup",
            post(auth::mfa_handler::mfa_verify_setup),
        )
        .route(
            "/api/auth/mfa/verify",
            post(auth::mfa_handler::mfa_verify_login),
        )
        .route(
            "/api/auth/mfa/disable",
            post(auth::mfa_handler::mfa_disable),
        )
        .route(
            "/api/auth/mfa/regenerate-backup-codes",
            post(auth::mfa_handler::mfa_regenerate_backup_codes),
        )
        .route(
            "/api/admin/settings/mfa",
            put(auth::mfa_handler::set_tenant_mfa).get(auth::mfa_handler::get_tenant_mfa),
        )
        .route(
            "/api/admin/users/{username}/disable-mfa",
            post(auth::mfa_handler::admin_disable_user_mfa),
        )
        // Admin key management (`/api/admin/keys*`) is deliberately NOT a
        // native route: it is proxied to the bridge, the only writer of
        // keys.json — which is what both the gateway and the bridge
        // authenticate against. See storage::api_keys.
        // Admin user management
        .route(
            "/api/admin/users",
            post(auth::admin_user_handler::create_user_handler)
                .get(auth::admin_user_handler::list_users_handler),
        )
        .route(
            "/api/admin/users/{username}",
            put(auth::admin_user_handler::update_user_handler)
                .delete(auth::admin_user_handler::disable_user_handler),
        )
        .route(
            "/api/admin/users/{username}/reset-password",
            post(auth::admin_user_handler::reset_password_handler),
        )
        // Admin session management
        .route(
            "/api/admin/sessions",
            get(auth::admin_session_handler::list_sessions_handler),
        )
        .route(
            "/api/admin/sessions/{token_prefix}",
            axum::routing::delete(auth::admin_session_handler::kill_session_handler),
        )
        // Audit endpoints
        .route(
            "/api/admin/audit",
            get(audit::handler::get_audit_log).delete(audit::handler::purge_archived),
        )
        .route("/api/admin/audit/verify", get(audit::handler::verify_chain))
        .route(
            "/api/admin/audit/filters",
            get(audit::handler::get_audit_filters),
        )
        .route(
            "/api/admin/audit/actions",
            get(audit::handler::get_audit_actions),
        )
        .route(
            "/api/admin/audit/archive",
            post(audit::handler::archive_audit),
        )
        .route(
            "/api/admin/audit/export",
            post(audit::handler::export_audit),
        )
        .route(
            "/api/admin/settings/security",
            get(audit::handler::get_security_settings).put(audit::handler::set_security_settings),
        )
        // WiFi networks/stats use the Python fallback, which owns the
        // dashboard aggregation contract (including hourly data and filters).
        // Raw observations are not interchangeable with network summaries.
        // Other native protocol query endpoints:
        .route(
            "/api/bluetooth/stats",
            get(query::protocol_handler::get_bt_stats_handler),
        )
        .route(
            "/api/bluetooth/devices",
            get(query::protocol_handler::get_bt_devices_handler),
        )
        .route(
            "/api/alerts",
            get(query::protocol_handler::get_alerts_handler),
        )
        // WebSocket native feeds
        .route("/ws/feed", get(ws::feed::ws_detection_feed))
        .route("/ws/anomalies", get(ws::anomaly_feed::ws_anomaly_feed))
        .route("/ws/audit", get(audit::ws_feed::ws_audit_feed))
        // WebSocket proxies to Python
        .route("/ws/status", get(ws_proxy_status))
        .route("/ws/wifi", get(ws_proxy_wifi))
        .route("/ws/bluetooth", get(ws_proxy_bluetooth))
        .route("/ws/zigbee", get(ws_proxy_zigbee))
        .route("/ws/spectrum", get(ws_proxy_spectrum))
        .route("/ws/spectrum-monitor", get(ws_proxy_spectrum_monitor))
        .route("/ws/alerts", get(ws_proxy_alerts))
        // WebSocket aliases (Python-style paths used by dashboard.js)
        .route("/api/nodes/ws/status", get(ws_proxy_status))
        .route("/api/alerts/ws/alerts", get(ws_proxy_alerts))
        .route("/api/detections/ws/feed", get(ws::feed::ws_detection_feed))
        .route("/api/wifi/ws/wifi", get(ws_proxy_wifi))
        .route("/api/bluetooth/ws/bluetooth", get(ws_proxy_bluetooth))
        .route("/api/zigbee/ws/zigbee", get(ws_proxy_zigbee))
        .route("/api/spectrum/ws/spectrum", get(ws_proxy_spectrum))
        .route(
            "/api/spectrum/ws/spectrum-monitor",
            get(ws_proxy_spectrum_monitor),
        )
        .route("/health", get(health_check))
        // Proxy fallback for everything else
        .fallback(proxy_fallback)
        // Middleware. In axum the layer added last is the outermost, so
        // the auth middleware runs first, then CSRF. The security headers
        // go around the whole app, in `served_app`.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            csrf_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
    // The framing guard (RFC 9112 §6.1) is not here but outside every
    // layer: `middleware::path::with_canonical_paths` adds it.
}

// ---------------------------------------------------------------------------
// Python-backend wait + TLS serving
// ---------------------------------------------------------------------------

/// Outcome of the startup readiness probe.
#[derive(Debug, PartialEq, Eq)]
enum Readiness {
    Ready {
        attempt: u32,
    },
    /// The bridge answered 403: it does not accept our proxy secret.
    SecretRefused,
    NotReady,
}

/// How [`wait_for_bridge`] ended.
#[derive(Debug, PartialEq, Eq)]
enum BridgeWait {
    /// Go on starting: the bridge answered, or the wait gave up.
    Start,
    /// A shutdown was requested meanwhile.
    Stop,
}

/// Wait for the bridge (see [`wait_for_python`]) unless a shutdown is
/// requested first, then check the schema again before the gateway listens.
/// The bridge migrates the database before it answers, so a gateway started
/// on a fresh database (or one the bridge had not migrated yet) next to a
/// newer bridge refuses here instead of serving that bridge's schema.
///
/// This is the last check: it runs once, when the wait ends, also when the
/// wait gave up after 60 s. A migration the bridge commits after that (a
/// bridge slower than the wait to answer, or one upgraded on its own while
/// the gateway runs) is refused only at the gateway's next start.
async fn wait_for_bridge(
    config: &Config,
    db_pool: &db::pool::DbPool,
    shutdown: ShutdownSignal,
) -> Result<BridgeWait, BuilderError> {
    tokio::select! {
        () = wait_for_python(&config.python_url, &config.proxy_secret) => {}
        () = shutdown.wait() => {
            info!("Shutdown requested while waiting for the bridge — exiting");
            return Ok(BridgeWait::Stop);
        }
    }
    refuse_newer_schema(db_pool)?;
    Ok(BridgeWait::Start)
}

/// Wait (up to 60 s) until the bridge answers `GET /api/version`.
///
/// The probe carries `X-Rust-Proxy` like every proxied request (contract
/// K2b): a bridge with `BRIDGE_REQUIRE_PROXY=true` refuses anything else
/// from a non-loopback peer, so without it every probe got 403 and each
/// start waited the full 60 s.
async fn wait_for_python(python_url: &str, proxy_secret: &str) {
    let mut client_builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(5));
    // Only skip TLS verification for a loopback backend — mirrors the proxy
    // client so a remote HTTPS backend's certificate is verified here too.
    if is_loopback_url(python_url) {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }
    let client = client_builder.build().unwrap();
    let delay = std::time::Duration::from_secs(2);
    if probe_python(&client, python_url, proxy_secret, 30, delay).await == Readiness::NotReady {
        error!(
            "Python backend not ready after 60s — starting anyway (proxy will return 502). \
             The database schema is checked once more now: a migration the bridge commits \
             later is refused only at the gateway's next start"
        );
    }
}

async fn probe_python(
    client: &reqwest::Client,
    python_url: &str,
    proxy_secret: &str,
    attempts: u32,
    delay: std::time::Duration,
) -> Readiness {
    let version_url = format!("{}/api/version", python_url.trim_end_matches('/'));
    for attempt in 1..=attempts {
        let probe = client
            .get(&version_url)
            .header("x-rust-proxy", proxy_secret_header(proxy_secret))
            .send()
            .await;
        match probe {
            Ok(resp) if resp.status().is_success() => {
                info!(attempt, "Python backend ready");
                return Readiness::Ready { attempt };
            }
            Ok(resp) if resp.status() == reqwest::StatusCode::FORBIDDEN => {
                // Not "still starting": a proxy-only bridge refuses this
                // gateway's secret. Every proxied request would get 403.
                error!(
                    url = %version_url,
                    "The bridge refused the gateway's proxy secret (403): UC_PROXY_SECRET \
                     is empty or differs from the bridge's — set the same value on both. \
                     Starting anyway; proxied requests will be refused."
                );
                return Readiness::SecretRefused;
            }
            Ok(resp) => {
                warn!(attempt, status = %resp.status(), "Python responded but not ready");
            }
            Err(e) => {
                if attempt % 5 == 0 {
                    warn!(attempt, error = %e, "Waiting for Python backend...");
                }
            }
        }
        if attempt < attempts {
            tokio::time::sleep(delay).await;
        }
    }
    Readiness::NotReady
}

async fn serve_tls(
    app: Router,
    bind_addr: &str,
    config: &Config,
    shutdown: ShutdownSignal,
) -> Result<(), BuilderError> {
    let cert_path = config
        .tls_cert
        .as_ref()
        .ok_or_else(|| BuilderError::Tls("TLS cert path required".to_string()))?;
    let key_path = config
        .tls_key
        .as_ref()
        .ok_or_else(|| BuilderError::Tls("TLS key path required".to_string()))?;

    // Build the rustls ServerConfig ourselves so we can attach a client
    // certificate verifier when UC_TLS_CLIENT_CA is set. With a verifier
    // in allow-unauthenticated mode, a client that presents a cert must
    // chain to the CA, while a client with no cert still completes the
    // handshake and falls through to API-key auth — Phase A is additive.
    let server_config = build_server_config(cert_path, key_path, config.tls_client_ca.as_deref())
        .map_err(|e| BuilderError::Tls(format!("load TLS config: {e}")))?;

    let addr: std::net::SocketAddr = bind_addr
        .parse()
        .map_err(|e| BuilderError::Bind(format!("invalid bind address {bind_addr}: {e}")))?;

    let mtls = config.tls_client_ca.is_some();
    info!(addr = %bind_addr, tls = true, mtls, "Listening (TLS)");

    let rustls_config =
        axum_server::tls_rustls::RustlsConfig::from_config(std::sync::Arc::new(server_config));
    let acceptor = client_cert_tls::ClientCertAcceptor::new(
        axum_server::tls_rustls::RustlsAcceptor::new(rustls_config),
    );

    // On shutdown: stop accepting, let requests in progress finish for at
    // most SERVER_SHUTDOWN_GRACE, then close what is left.
    let handle = axum_server::Handle::new();
    let stopping = handle.clone();
    tokio::spawn(async move {
        shutdown.wait().await;
        stopping.graceful_shutdown(Some(SERVER_SHUTDOWN_GRACE));
    });

    axum_server::bind(addr)
        .handle(handle)
        .acceptor(acceptor)
        .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await
        .map_err(|e| BuilderError::Serve(e.to_string()))
}

/// Assemble a rustls [`ServerConfig`](rustls::ServerConfig), optionally
/// with a client-certificate verifier loaded from *client_ca*.
fn build_server_config(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    client_ca: Option<&std::path::Path>,
) -> std::io::Result<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let cert_pem = std::fs::read(cert_path)?;
    let cert_chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_slice()).collect::<Result<_, _>>()?;
    if cert_chain.is_empty() {
        return Err(std::io::Error::other(format!(
            "no certificates in {}",
            cert_path.display()
        )));
    }

    let key_pem = std::fs::read(key_path)?;
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_slice())?
        .ok_or_else(|| {
            std::io::Error::other(format!("no private key in {}", key_path.display()))
        })?;

    let builder = rustls::ServerConfig::builder();
    let mut server_config = match client_ca {
        Some(ca) => {
            let verifier = auth::client_cert::load_client_verifier(ca)?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    }
    .with_single_cert(cert_chain, key)
    .map_err(|e| std::io::Error::other(e.to_string()))?;

    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(server_config)
}

/// TLS acceptor that surfaces the verified client-cert identity.
///
/// rustls has already proven any presented certificate chains to the
/// configured CA by the time the handshake completes; this acceptor
/// extracts the leaf cert's identity and injects it into per-request
/// extensions so the auth middleware can resolve it to a role.
mod client_cert_tls {
    use std::future::Future;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use axum_server::accept::Accept;
    use axum_server::tls_rustls::RustlsAcceptor;
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio_rustls::server::TlsStream;

    use crate::auth::client_cert::ClientCertInfo;

    #[derive(Clone)]
    pub struct ClientCertAcceptor {
        inner: RustlsAcceptor,
    }

    impl ClientCertAcceptor {
        pub fn new(inner: RustlsAcceptor) -> Self {
            Self { inner }
        }
    }

    impl<I, S> Accept<I, S> for ClientCertAcceptor
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        S: Send + 'static,
    {
        type Stream = TlsStream<I>;
        type Service = CertExtService<S>;
        type Future =
            Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

        fn accept(&self, stream: I, service: S) -> Self::Future {
            let inner = self.inner.clone();
            Box::pin(async move {
                let (tls_stream, service) = inner.accept(stream, service).await?;
                let (peer_count, cert) = {
                    let (_io, conn) = tls_stream.get_ref();
                    let chain = conn.peer_certificates();
                    let count = chain.map(<[_]>::len).unwrap_or(0);
                    let cert = chain
                        .and_then(|chain| chain.first())
                        .and_then(|leaf| ClientCertInfo::from_der(leaf.as_ref()));
                    (count, cert)
                };
                tracing::debug!(
                    peer_certs = peer_count,
                    identity = ?cert.as_ref().map(|c| c.identity.as_str()),
                    "mTLS acceptor: client cert extraction"
                );
                Ok((
                    tls_stream,
                    CertExtService {
                        inner: service,
                        cert,
                    },
                ))
            })
        }
    }

    /// Service wrapper that injects the connection's client-cert identity
    /// (when present) into every request handled on that connection.
    #[derive(Clone)]
    pub struct CertExtService<S> {
        inner: S,
        cert: Option<ClientCertInfo>,
    }

    impl<S, B> tower::Service<axum::http::Request<B>> for CertExtService<S>
    where
        S: tower::Service<axum::http::Request<B>>,
    {
        type Response = S::Response;
        type Error = S::Error;
        type Future = S::Future;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.inner.poll_ready(cx)
        }

        fn call(&mut self, mut req: axum::http::Request<B>) -> Self::Future {
            if let Some(cert) = &self.cert {
                req.extensions_mut().insert(cert.clone());
            }
            self.inner.call(req)
        }
    }
}

/// The mTLS acceptor `serve_tls` installs, driven over an in-memory stream
/// (no sockets): the client identity it hands the auth middleware is that
/// of the leaf certificate the handshake verified.
#[cfg(test)]
mod client_cert_tls_tests {
    use std::convert::Infallible;
    use std::sync::Arc;

    use axum_server::accept::Accept as _;
    use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
    use rustls::pki_types::{CertificateDer, ServerName};
    use tower::ServiceExt as _;

    use super::client_cert_tls::ClientCertAcceptor;
    use crate::auth::client_cert::tests::{self as cc, Leaf, TestCa};
    use crate::auth::client_cert::{CertRegistry, ClientCertInfo};
    use crate::auth::rbac::Role;

    /// The acceptor as `serve_tls` builds it (`build_server_config`), with a
    /// server certificate from `server_ca` and client certificates verified
    /// against `client_ca`.
    fn gateway_acceptor(
        dir: &tempfile::TempDir,
        client_ca: &TestCa,
        server_ca: &TestCa,
    ) -> ClientCertAcceptor {
        let server = cc::issue_leaf(server_ca, "localhost", |p| {
            p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth]
        });
        let cert = dir.path().join("server.pem");
        let key = dir.path().join("server.key");
        let ca = dir.path().join("client-ca.pem");
        std::fs::write(&cert, cc::to_pem("CERTIFICATE", &server.der)).unwrap();
        std::fs::write(&key, server.key.serialize_pem()).unwrap();
        std::fs::write(&ca, client_ca.pem()).unwrap();
        let config = super::build_server_config(&cert, &key, Some(&ca)).unwrap();
        ClientCertAcceptor::new(RustlsAcceptor::new(RustlsConfig::from_config(Arc::new(
            config,
        ))))
    }

    /// One connection through `acceptor` from a client that presents
    /// `Some((chain, key))` — the certificates it sends, in order, proving
    /// possession with `key`'s private key — or no certificate. Returns the
    /// client certificate a request on that connection carries.
    async fn cert_seen_by_requests(
        acceptor: &ClientCertAcceptor,
        server_ca: &TestCa,
        client: Option<(Vec<CertificateDer<'static>>, &Leaf)>,
    ) -> Option<ClientCertInfo> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(server_ca.der().clone()).unwrap();
        let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
        let config = match client {
            Some((chain, key)) => builder.with_client_auth_cert(chain, key.key_der()).unwrap(),
            None => builder.with_no_client_auth(),
        };
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let app = tower::service_fn(|req: axum::http::Request<()>| async move {
            Ok::<_, Infallible>(req.extensions().get::<ClientCertInfo>().cloned())
        });
        let (accepted, connected) = tokio::join!(
            acceptor.accept(server_io, app),
            connector.connect(ServerName::try_from("localhost").unwrap(), client_io),
        );
        connected.expect("client handshake");
        let (_tls, service) = accepted.expect("server handshake");
        service.oneshot(axum::http::Request::new(())).await.unwrap()
    }

    /// Certificates are public, so a client holding any registered
    /// certificate can append the admin's certificate after its own leaf;
    /// the handshake still succeeds (only the leaf is authenticated). The
    /// identity must come from that leaf, never from the extra certificate.
    #[tokio::test]
    async fn acceptor_takes_the_identity_from_the_verified_leaf_not_extra_chain_certs() {
        cc::ensure_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let client_ca = cc::test_ca("SigRift Test CA");
        let server_ca = cc::test_ca("Server CA");
        let acceptor = gateway_acceptor(&dir, &client_ca, &server_ca);

        let attacker = cc::issue_leaf(&client_ca, "edge-low", |_| {});
        let admin = cc::issue_leaf(&client_ca, "edge-admin", |_| {});
        let attacker_info = ClientCertInfo::from_der(&attacker.der).unwrap();
        let admin_info = ClientCertInfo::from_der(&admin.der).unwrap();
        let registry_file = cc::write_registry(&format!(
            "{}, {}",
            cc::entry(&attacker_info, "sensor", false, cc::FAR_FUTURE),
            cc::entry(&admin_info, "admin", false, cc::FAR_FUTURE)
        ));
        let registry = CertRegistry::load(registry_file.path());

        // Control: the admin, with its own key, is the admin.
        let seen = cert_seen_by_requests(
            &acceptor,
            &server_ca,
            Some((vec![admin.der.clone()], &admin)),
        )
        .await;
        assert_eq!(seen.as_ref(), Some(&admin_info), "control");
        assert_eq!(registry.lookup(&admin_info), Some(Role::Admin), "control");

        let chain = vec![attacker.der.clone(), admin.der.clone()];
        let seen = cert_seen_by_requests(&acceptor, &server_ca, Some((chain, &attacker)))
            .await
            .expect("the verified leaf is injected");
        assert_eq!(seen, attacker_info);
        assert_eq!(seen.identity, "edge-low");
        assert_eq!(registry.lookup(&seen), Some(Role::Sensor));

        // No certificate: nothing is injected and API-key auth follows.
        assert_eq!(
            cert_seen_by_requests(&acceptor, &server_ca, None).await,
            None
        );
    }
}

// ---------------------------------------------------------------------------
// WebSocket proxy handlers (one per Python WS path). Each authenticates the
// upgrade itself before contacting Python (see `proxy::ws_proxy`).
// ---------------------------------------------------------------------------

async fn ws_proxy_status(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
) -> axum::response::Response {
    ws_proxy::ws_proxy(state, req, "/api/nodes/ws/status").await
}
async fn ws_proxy_alerts(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
) -> axum::response::Response {
    ws_proxy::ws_proxy(state, req, "/api/alerts/ws/alerts").await
}
async fn ws_proxy_spectrum(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
) -> axum::response::Response {
    ws_proxy::ws_proxy(state, req, "/api/spectrum/ws/spectrum").await
}
async fn ws_proxy_spectrum_monitor(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
) -> axum::response::Response {
    ws_proxy::ws_proxy(state, req, "/api/spectrum/ws/spectrum-monitor").await
}
async fn ws_proxy_wifi(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
) -> axum::response::Response {
    ws_proxy::ws_proxy(state, req, "/api/wifi/ws/wifi").await
}
async fn ws_proxy_bluetooth(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
) -> axum::response::Response {
    ws_proxy::ws_proxy(state, req, "/api/bluetooth/ws/bluetooth").await
}
async fn ws_proxy_zigbee(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
) -> axum::response::Response {
    ws_proxy::ws_proxy(state, req, "/api/zigbee/ws/zigbee").await
}

fn build_cors_layer(cors_origins: &str) -> CorsLayer {
    let methods = vec![
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::PATCH,
    ];
    let headers = vec![
        header::CONTENT_TYPE,
        header::AUTHORIZATION,
        header::COOKIE,
        HeaderName::from_static("x-api-key"),
        HeaderName::from_static("x-session-token"),
        HeaderName::from_static("x-csrf-token"),
    ];

    if cors_origins.is_empty() {
        CorsLayer::new()
            .allow_methods(methods)
            .allow_headers(headers)
    } else {
        let origins: Vec<HeaderValue> = cors_origins
            .split(',')
            .filter_map(|s| {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    trimmed.parse().ok()
                }
            })
            .collect();
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods(methods)
            .allow_headers(headers)
    }
}

/// `GET /health`: `{"status": "ok", "post_ingest_hooks": {"enabled": …,
/// …counters…}}`. `enabled` is false without a usable `UC_PROXY_SECRET`
/// (K10).
async fn health_check(State(state): State<Arc<AppState>>) -> axum::Json<serde_json::Value> {
    let mut hooks = serde_json::to_value(state.ingest_hooks.stats()).unwrap_or_default();
    if let Some(fields) = hooks.as_object_mut() {
        fields.insert("enabled".into(), state.config.proxy_secret_usable().into());
    }
    axum::Json(serde_json::json!({
        "status": "ok",
        "post_ingest_hooks": hooks,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    // `Fernet.generate_key()` output.
    const FERNET_KEY: &str = "gbhtBUbPkbiIqPMsYEdh1YUZAxWFy-1pp3gVY24zhzM=";

    /// A config with every secret set; tests then knock one out. Fields
    /// under test are assigned explicitly so the process env cannot leak in.
    fn config(env: &str) -> Config {
        let mut c = Config::try_parse_from(["sigrift-gateway"]).unwrap();
        c.bridge_env = env.to_string();
        c.proxy_secret = "a-strong-proxy-secret".to_string();
        c.audit_key = "an-audit-key".to_string();
        c.mfa_key = FERNET_KEY.to_string();
        c.csrf_mode = String::new();
        c
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn refusal(c: &Config) -> String {
        match check_startup_secrets(c, no_env) {
            Err(BuilderError::Config(msg)) => msg,
            other => panic!("expected a config refusal, got {other:?}"),
        }
    }

    #[test]
    fn production_with_all_secrets_starts() {
        assert!(check_startup_secrets(&config("production"), no_env).is_ok());
    }

    /// A session timeout written with digits other than 0-9, which the
    /// bridge may read and the gateway cannot (`Config::session_config`),
    /// stops the gateway before it opens anything. Everything it could
    /// open lives in a temporary directory, and the missing keys file
    /// stops a gateway that went on regardless.
    #[tokio::test]
    async fn a_session_timeout_the_bridge_may_read_otherwise_stops_the_gateway() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = config("development");
        c.host = "127.0.0.1".to_string();
        c.port = 0;
        c.db_path = dir.path().join("auth.db");
        c.keys_path = dir.path().join("keys.json");
        c.baseline_path = dir.path().join("baselines.json");
        c.hook_spool_path = Some(dir.path().join("hooks.spool"));
        c.allow_no_auth = false;
        c.session_idle_timeout_minutes = Some("\u{ff11}\u{ff15}".to_string());
        let run = GatewayBuilder::new(c, Arc::new(crate::NullLicenseResolver)).run();
        match tokio::time::timeout(std::time::Duration::from_secs(10), run).await {
            Ok(Err(BuilderError::Config(msg))) => {
                assert!(msg.contains("BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES"), "{msg}");
            }
            other => panic!("expected a config refusal, got {other:?}"),
        }
        assert!(!dir.path().join("auth.db").exists(), "opened the database");
    }

    #[test]
    fn production_refuses_missing_audit_key() {
        let mut c = config("production");
        c.audit_key = String::new();
        let msg = refusal(&c);
        assert!(msg.contains("BRIDGE_AUDIT_KEY"), "{msg}");
        assert!(
            msg.contains("token_urlsafe"),
            "names how to generate: {msg}"
        );

        // "prod" is production too.
        c.bridge_env = "prod".to_string();
        assert!(refusal(&c).contains("BRIDGE_AUDIT_KEY"));
    }

    #[test]
    fn production_accepts_audit_key_from_master_key() {
        let mut c = config("production");
        c.audit_key = String::new();
        let env = |name: &str| (name == "BRIDGE_MASTER_KEY").then(|| "mk".to_string());
        assert!(check_startup_secrets(&c, env).is_ok());
    }

    #[test]
    fn production_refuses_missing_mfa_key() {
        let mut c = config("production");
        c.mfa_key = String::new();
        let msg = refusal(&c);
        assert!(msg.contains("BRIDGE_MFA_KEY is not set"), "{msg}");
        assert!(msg.contains("Fernet.generate_key()"), "{msg}");
    }

    #[test]
    fn production_refuses_invalid_mfa_key() {
        let mut c = config("production");
        // `secrets.token_urlsafe(32)` — the wrong generator; not a Fernet key.
        c.mfa_key = "gbhtBUbPkbiIqPMsYEdh1YUZAxWFy-1pp3gVY24zhzM".to_string();
        let msg = refusal(&c);
        assert!(
            msg.contains("BRIDGE_MFA_KEY is not a valid Fernet key"),
            "{msg}"
        );
        // The lossless repair is spelled out, not just "generate a new key".
        assert!(msg.contains("it is 43 characters long"), "{msg}");
        assert!(
            msg.contains(auth::fernet_enc::FERNET_KEY_REPAIR_HINT),
            "{msg}"
        );

        c.mfa_key = "not-a-fernet-key".to_string();
        let msg = refusal(&c);
        assert!(
            msg.contains(auth::fernet_enc::FERNET_KEY_REPAIR_HINT),
            "{msg}"
        );
    }

    #[test]
    fn production_accepts_standard_alphabet_mfa_key() {
        // `openssl rand -base64 32` style: Python's Fernet accepts it, so
        // the gateway must start with it too.
        let mut c = config("production");
        c.mfa_key = "+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/s=".to_string();
        assert!(check_startup_secrets(&c, no_env).is_ok());
    }

    /// Owner decision (2026-11-10): production refuses to start with CSRF
    /// protection turned off. `BRIDGE_CSRF=disabled` was honoured in every
    /// environment. The value is read as the bridge reads it (trimmed, any
    /// letter case), and any value other than `enabled` is refused, since
    /// the bridge turns CSRF off for every one of them: the same setting
    /// gets the same verdict on both services. The message names the
    /// variable and what to do.
    #[test]
    fn production_refuses_csrf_protection_turned_off() {
        for env in ["production", "prod", " Production "] {
            for value in [
                "disabled",
                "Disabled",
                " disabled ",
                "off",
                "false",
                "0",
                "true",
                "on",
                "disable",
            ] {
                let mut c = config(env);
                c.csrf_mode = value.to_string();
                let msg = refusal(&c);
                assert!(msg.contains("BRIDGE_CSRF"), "{env} {value:?}: {msg}");
                assert!(
                    msg.contains("unset BRIDGE_CSRF or set it to enabled"),
                    "{env} {value:?}: {msg}"
                );
                assert!(msg.contains(&format!("{:?}", value)), "{msg}");
            }
            for value in ["", "  ", "enabled", "Enabled", " enabled "] {
                let mut c = config(env);
                c.csrf_mode = value.to_string();
                assert!(check_startup_secrets(&c, no_env).is_ok(), "{env} {value:?}");
            }
        }
        // Elsewhere it is allowed, with a warning.
        for env in ["development", "dev", "test", "staging"] {
            let mut c = config(env);
            c.csrf_mode = "disabled".to_string();
            assert!(check_startup_secrets(&c, no_env).is_ok(), "{env}");
        }
    }

    /// How the gateway reads `BRIDGE_CSRF` is unchanged: `enabled` and
    /// `disabled` exactly, anything else is the default for `BRIDGE_ENV`
    /// (off in development, dev and test only).
    #[test]
    fn csrf_setting_resolution_is_unchanged() {
        for (env, value, enabled) in [
            ("production", "", true),
            ("production", "enabled", true),
            ("staging", "", true),
            ("staging", "disabled", false),
            ("development", "", false),
            ("development", "enabled", true),
            ("dev", "Disabled", false),
            ("test", "", false),
        ] {
            let mut c = config(env);
            c.csrf_mode = value.to_string();
            assert_eq!(csrf_enabled(&c), enabled, "{env} {value:?}");
        }
    }

    #[test]
    fn production_reports_every_problem_at_once() {
        let mut c = config("production");
        c.proxy_secret = "uppercrust-internal".to_string();
        c.audit_key = String::new();
        c.mfa_key = "nope".to_string();
        let msg = refusal(&c);
        assert!(msg.contains("UC_PROXY_SECRET"), "{msg}");
        assert!(msg.contains("BRIDGE_AUDIT_KEY"), "{msg}");
        assert!(msg.contains("BRIDGE_MFA_KEY"), "{msg}");
    }

    /// A stub of a proxy-only bridge (`BRIDGE_REQUIRE_PROXY=true`):
    /// `GET /api/version` answers 200 with the right `X-Rust-Proxy`, 403
    /// without it. Returns its URL and a hit counter.
    async fn proxy_only_bridge(
        secret: &'static str,
    ) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        let app = Router::new().route(
            "/api/version",
            get(move |headers: axum::http::HeaderMap| {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    if headers.get("x-rust-proxy").and_then(|v| v.to_str().ok()) == Some(secret) {
                        axum::http::StatusCode::OK
                    } else {
                        axum::http::StatusCode::FORBIDDEN
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, hits)
    }

    /// Regression (Q5 / K2b): the readiness probe sent no `X-Rust-Proxy`,
    /// so a proxy-only bridge answered 403 to all 30 probes and every
    /// gateway start waited 60 s (long enough for compose to mark the
    /// gateway unhealthy).
    #[tokio::test]
    async fn the_readiness_probe_passes_a_proxy_only_bridge() {
        use std::sync::atomic::Ordering;
        use std::time::{Duration, Instant};
        let (url, hits) = proxy_only_bridge("probe-secret").await;
        let client = reqwest::Client::new();
        let slow = Duration::from_secs(2);

        assert_eq!(
            probe_python(&client, &url, "probe-secret", 30, slow).await,
            Readiness::Ready { attempt: 1 }
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        // A wrong (or empty) secret is reported at once, not retried for 60 s.
        let started = Instant::now();
        assert_eq!(
            probe_python(&client, &url, "wrong", 30, slow).await,
            Readiness::SecretRefused
        );
        assert_eq!(
            probe_python(&client, &url, "", 30, slow).await,
            Readiness::SecretRefused
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(hits.load(Ordering::SeqCst), 3);

        // Nothing listening: retried, then given up.
        assert_eq!(
            probe_python(
                &client,
                "http://127.0.0.1:9",
                "s",
                2,
                Duration::from_millis(10)
            )
            .await,
            Readiness::NotReady
        );
    }

    #[test]
    fn development_is_lenient() {
        let mut c = config("development");
        c.proxy_secret = String::new();
        c.audit_key = String::new();
        c.mfa_key = "nope".to_string();
        assert!(check_startup_secrets(&c, no_env).is_ok());
        c.mfa_key = String::new();
        assert!(check_startup_secrets(&c, no_env).is_ok());
    }

    use crate::test_support::logs_of;

    /// The WARN lines of `logs`.
    fn warnings(logs: &str) -> Vec<&str> {
        logs.lines().filter(|l| l.contains("WARN")).collect()
    }

    /// Production may still take the audit HMAC key from the deprecated
    /// `BRIDGE_AUDIT_SECRET` or `BRIDGE_MASTER_KEY`, but says to set
    /// `BRIDGE_AUDIT_KEY` (the gateway must not need the master key). A
    /// `BRIDGE_AUDIT_KEY` of whitespace is no key, as on the bridge: with a
    /// fallback set it is warned about like an unset one, and without one
    /// it is refused.
    #[test]
    fn production_warns_about_a_fallback_audit_key_and_refuses_a_blank_one() {
        let mut c = config("production");
        for unset in ["", " \t "] {
            c.audit_key = unset.to_string();
            for fallback in ["BRIDGE_AUDIT_SECRET", "BRIDGE_MASTER_KEY"] {
                let env = |name: &str| (name == fallback).then(|| "legacy-secret".to_string());
                let (checked, logs) = logs_of(|| check_startup_secrets(&c, env));
                assert!(checked.is_ok(), "{unset:?} {fallback}: {checked:?}");
                let warned = warnings(&logs);
                assert_eq!(warned.len(), 1, "{unset:?} {fallback}: {logs}");
                for named in [
                    "BRIDGE_AUDIT_KEY is not set",
                    "deprecated",
                    "BRIDGE_MASTER_KEY",
                ] {
                    assert!(
                        warned[0].contains(named),
                        "{unset:?} {fallback}: {named:?} missing: {logs}"
                    );
                }
            }
        }

        // BRIDGE_AUDIT_KEY set: it is the key, and nothing is said about
        // the fallbacks the environment also holds.
        let master = |name: &str| (name == "BRIDGE_MASTER_KEY").then(|| "mk".to_string());
        let (checked, logs) = logs_of(|| check_startup_secrets(&config("production"), master));
        assert!(checked.is_ok());
        assert!(warnings(&logs).is_empty(), "{logs}");

        c.audit_key = " \t ".to_string();
        assert!(refusal(&c).contains("BRIDGE_AUDIT_KEY"));
    }

    /// Development starts with an MFA key production refuses, and says
    /// what that costs: new TOTP secrets are stored unencrypted.
    #[test]
    fn development_warns_that_totp_secrets_are_not_encrypted_without_a_valid_mfa_key() {
        for key in ["", "not-a-fernet-key"] {
            let mut c = config("development");
            c.mfa_key = key.to_string();
            let (checked, logs) = logs_of(|| check_startup_secrets(&c, no_env));
            assert!(checked.is_ok(), "{key:?}");
            let warned: Vec<&str> = warnings(&logs)
                .into_iter()
                .filter(|l| l.contains("BRIDGE_MFA_KEY"))
                .collect();
            assert_eq!(warned.len(), 1, "{key:?}: {logs}");
            for named in ["NOT encrypted", "production refuses to start"] {
                assert!(
                    warned[0].contains(named),
                    "{key:?}: {named:?} missing: {logs}"
                );
            }
        }
        let (_, logs) = logs_of(|| check_startup_secrets(&config("development"), no_env));
        assert!(!logs.contains("BRIDGE_MFA_KEY"), "{logs}");
    }

    /// V12 / K10 regression: without a usable UC_PROXY_SECRET a development
    /// gateway only warned that "license tier trust" was disabled, while
    /// node-key binding (503 for every new node key) and every post-ingest
    /// hook (no alerts, watch bands, webhooks, decode jobs) were broken.
    /// It now logs one error that says so, and how to fix it.
    #[test]
    fn development_without_a_proxy_secret_logs_one_error_naming_what_is_disabled() {
        for secret in ["", "uppercrust-internal"] {
            let mut c = config("development");
            c.proxy_secret = secret.to_string();
            let (checked, logs) = logs_of(|| check_startup_secrets(&c, no_env));
            assert!(checked.is_ok());
            let errors: Vec<&str> = logs.lines().filter(|l| l.contains("ERROR")).collect();
            assert_eq!(errors.len(), 1, "{logs}");
            for named in [
                "Node-key binding and post-ingest hooks are DISABLED",
                "/api/internal/",
                "ANY node",
                "BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1",
                "alert rules",
                "watch-band alerts",
                "webhooks",
                "protocol-decode jobs",
                "hooks_disabled",
                "set UC_PROXY_SECRET to the same strong value",
                "token_urlsafe",
            ] {
                assert!(
                    errors[0].contains(named),
                    "{named:?} missing: {}",
                    errors[0]
                );
            }
            assert!(!logs.contains("license tier trust is DISABLED"), "{logs}");
        }
        // With a usable secret: no error.
        let (checked, logs) = logs_of(|| check_startup_secrets(&config("development"), no_env));
        assert!(checked.is_ok());
        assert!(!logs.contains("ERROR"), "{logs}");
    }

    /// A router whose `/slow` answers after `delay`.
    fn slow_app(delay: std::time::Duration) -> Router {
        Router::new().route(
            "/slow",
            get(move || async move {
                tokio::time::sleep(delay).await;
                "done"
            }),
        )
    }

    /// V2 regression (first half): the gateway had no shutdown path at all.
    /// On a shutdown signal the listener stops accepting, the request in
    /// progress still gets its answer, and serving returns so the hooks can
    /// be drained and spooled.
    #[tokio::test]
    async fn serving_stops_on_shutdown_after_the_requests_in_progress() {
        use std::time::{Duration, Instant};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(serve_plain(
            listener,
            slow_app(Duration::from_millis(500)),
            ShutdownSignal::from_receiver(stopped),
        ));
        let request = tokio::spawn(async move {
            reqwest::get(format!("http://{addr}/slow"))
                .await
                .unwrap()
                .text()
                .await
                .unwrap()
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let started = Instant::now();
        stop.send(true).unwrap();
        let served = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("serving returns")
            .unwrap();
        assert!(served.is_ok());
        assert!(started.elapsed() < SERVER_SHUTDOWN_GRACE);
        assert_eq!(request.await.unwrap(), "done");
        // No longer listening.
        assert!(tokio::net::TcpStream::connect(addr).await.is_err());
    }

    /// A request that does not finish does not hold the shutdown up for
    /// more than the grace period.
    #[tokio::test]
    async fn a_stuck_request_does_not_hold_up_the_shutdown() {
        use std::time::{Duration, Instant};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(serve_plain(
            listener,
            slow_app(Duration::from_secs(60)),
            ShutdownSignal::from_receiver(stopped),
        ));
        let _stuck = tokio::spawn(reqwest::get(format!("http://{addr}/slow")));
        tokio::time::sleep(Duration::from_millis(100)).await;
        let started = Instant::now();
        stop.send(true).unwrap();
        let served = tokio::time::timeout(SERVER_SHUTDOWN_GRACE + Duration::from_secs(2), server)
            .await
            .expect("serving returns after the grace period")
            .unwrap();
        assert!(served.is_ok());
        assert!(started.elapsed() >= SERVER_SHUTDOWN_GRACE);
    }

    /// K8b end to end, as `run` sequences it: hooks queued when the bridge
    /// is down are spooled at shutdown, and at the next start they are
    /// replayed — before anything new — once the bridge is back.
    #[tokio::test]
    async fn hooks_spooled_at_shutdown_are_delivered_after_the_restart() {
        use ingest::hooks::{HookItem, HookTarget, IngestHooks, SHUTDOWN_DRAIN};
        use std::sync::Mutex;
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("gateway-post-ingest-hooks.spool");
        let body = |node: &str| {
            serde_json::to_vec(&serde_json::json!({
                "node_id": node, "detections": [{"detection_id": format!("{node}-1")}],
                "decoded_messages": [], "received_at": "2026-11-06T00:00:00+00:00",
            }))
            .unwrap()
        };
        let item = |node: &str| HookItem {
            node_id: node.into(),
            detections: 1,
            body: body(node).into(),
        };

        // First run: the bridge is down.
        let down = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let first = Arc::new(IngestHooks::default());
        first.push(item("edge-1"));
        first.push(item("edge-2"));
        let target = HookTarget::new(reqwest::Client::new(), &format!("http://{down}"), "s");
        first.shutdown(&target, &spool, SHUTDOWN_DRAIN).await;
        assert!(spool.exists());

        // Second run: the bridge is back.
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let record = Arc::clone(&seen);
        let bridge = Router::new().route(
            ingest::hooks::HOOK_PATH,
            post(move |payload: axum::Json<serde_json::Value>| {
                let record = Arc::clone(&record);
                async move {
                    let node = payload["node_id"].as_str().unwrap_or_default().to_string();
                    record.lock().unwrap().push(node);
                    axum::http::StatusCode::OK
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, bridge).await.unwrap() });
        let second = Arc::new(IngestHooks::default());
        restore_hook_spool(&second, &spool).await;
        assert!(!spool.exists(), "the spool is deleted once replayed");
        second.push(item("edge-3"));
        let (_stop, stopped) = tokio::sync::watch::channel(false);
        let worker = ingest::hooks::spawn_worker_until(
            Arc::clone(&second),
            HookTarget::new(reqwest::Client::new(), &url, "s"),
            stopped,
        );
        for _ in 0..200 {
            if second.stats().delivered_batches == 3 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        worker.abort();
        assert_eq!(seen.lock().unwrap().clone(), ["edge-1", "edge-2", "edge-3"]);
        assert_eq!(second.stats().restored_batches, 2);
    }

    #[tokio::test]
    async fn a_shutdown_signal_without_a_sender_never_fires() {
        let (stop, stopped) = tokio::sync::watch::channel(false);
        drop(stop);
        let waited = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            ShutdownSignal::from_receiver(stopped).wait(),
        )
        .await;
        assert!(waited.is_err());
    }

    /// Set in the child process [`sigterm_requests_the_shutdown`] runs
    /// [`sigterm_in_a_process_of_its_own`] in.
    #[cfg(unix)]
    const SIGTERM_CHILD_ENV: &str = "SIGRIFT_GATEWAY_SIGTERM_TEST_CHILD";

    /// `docker stop` sends SIGTERM: it is caught (the gateway is PID 1 in
    /// its container, where an unhandled SIGTERM is ignored until SIGKILL).
    ///
    /// A signal goes to the whole process, and so to every
    /// [`ShutdownSignal::listen`] in it: a test running
    /// [`GatewayBuilder::run`] at the same time would take it as its own
    /// shutdown request and stop. So the signal is sent to a child process
    /// that runs only [`sigterm_in_a_process_of_its_own`], never to the
    /// test process.
    #[cfg(unix)]
    #[test]
    fn sigterm_requests_the_shutdown() {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "builder::tests::sigterm_in_a_process_of_its_own",
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(SIGTERM_CHILD_ENV, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&child.stdout);
        assert!(
            child.status.success(),
            "{}\n{stdout}\n{}",
            child.status,
            String::from_utf8_lossy(&child.stderr)
        );
        // Neither filtered out nor skipped: the child ran the test.
        assert!(stdout.contains("1 passed"), "{stdout}");
        assert!(stdout.contains("SIGTERM caught"), "{stdout}");
    }

    /// The SIGTERM test proper, run only by [`sigterm_requests_the_shutdown`]
    /// in a process of its own (anywhere else it does nothing, so that
    /// `--ignored` / `--include-ignored` runs signal no other test).
    #[cfg(unix)]
    #[ignore = "sigterm_requests_the_shutdown runs it in a child process"]
    #[tokio::test]
    async fn sigterm_in_a_process_of_its_own() {
        if std::env::var_os(SIGTERM_CHILD_ENV).is_none() {
            return;
        }
        let signal = ShutdownSignal::listen();
        // The shell's own `kill`: no procps needed.
        let killed = std::process::Command::new("sh")
            .args(["-c", &format!("kill -TERM {}", std::process::id())])
            .status()
            .unwrap();
        assert!(killed.success());
        tokio::time::timeout(std::time::Duration::from_secs(5), signal.wait())
            .await
            .expect("SIGTERM requests the shutdown");
        println!("SIGTERM caught");
    }
}

/// Every WebSocket path the dashboard opens must reach a WebSocket handler:
/// the HTTP fallback proxy cannot upgrade a connection.
#[cfg(test)]
mod ws_route_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    /// The WebSocket URLs in src/sigrift/bridge/static/*.js.
    const DASHBOARD_WS_PATHS: &[&str] = &[
        "/api/nodes/ws/status",
        "/api/alerts/ws/alerts",
        "/api/detections/ws/feed",
        "/api/wifi/ws/wifi",
        "/api/bluetooth/ws/bluetooth",
        "/api/zigbee/ws/zigbee",
        "/api/spectrum/ws/spectrum",
        "/api/spectrum/ws/spectrum-monitor",
    ];

    #[tokio::test]
    async fn every_dashboard_websocket_path_has_a_websocket_route() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::ws::test_harness::state(
            &dir,
            "http://127.0.0.1:1",
            &crate::ws::test_harness::keys_file(&[]),
            None,
        );
        let app = build_router(Arc::clone(&state), &state.config).with_state(state);
        for path in DASHBOARD_WS_PATHS {
            let req = Request::builder()
                .uri(*path)
                .header("connection", "upgrade")
                .header("upgrade", "websocket")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            // A WebSocket route authenticates the upgrade (401 here); the
            // HTTP fallback would answer 502 "WebSocket proxy not supported".
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{path}");
        }
    }
}

/// Contract K9 through the real router: percent-encoded paths are routed
/// natively, and the bridge's internal API is never proxied.
#[cfg(test)]
mod path_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Mutex;
    use tower::ServiceExt as _;

    /// A fake bridge that records every request it gets (method, path and
    /// query) and answers 200 "from-bridge".
    async fn recording_bridge() -> (String, Arc<Mutex<Vec<String>>>) {
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let record = Arc::clone(&seen);
        let app = Router::new().fallback(move |req: Request<Body>| {
            let record = Arc::clone(&record);
            async move {
                record.lock().unwrap().push(format!(
                    "{} {}",
                    req.method(),
                    req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("")
                ));
                "from-bridge"
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, seen)
    }

    fn gateway(state: &Arc<AppState>) -> Router {
        crate::middleware::path::with_canonical_paths(
            build_router(Arc::clone(state), &state.config).with_state(Arc::clone(state)),
        )
    }

    async fn send(app: &Router, method: &str, path: &str) -> (StatusCode, String) {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    /// The dashboard consumes Python's network aggregates, not raw WiFi
    /// observations. Shadowing these paths lost signal/client/time fields,
    /// filters, and hourly data even though the request returned HTTP 200.
    #[tokio::test]
    async fn wifi_dashboard_queries_reach_the_aggregation_backend() {
        let (url, seen) = recording_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = crate::ws::test_harness::state(
            &dir,
            &url,
            &crate::ws::test_harness::keys_file(&[]),
            None,
        );
        let app = gateway(&state);
        let paths = [
            "/api/wifi/stats",
            "/api/wifi/networks?band=5GHz&node_id=node%20one&limit=17",
            "/api/%77ifi/networks?band=2.4GHz",
        ];
        for path in paths {
            let (status, body) = send(&app, "GET", path).await;
            assert_eq!((status, body.as_str()), (StatusCode::OK, "from-bridge"));
        }
        assert_eq!(
            seen.lock().unwrap().clone(),
            [
                "GET /api/wifi/stats",
                "GET /api/wifi/networks?band=5GHz&node_id=node%20one&limit=17",
                "GET /api/wifi/networks?band=2.4GHz",
            ]
        );
    }

    /// Regression (P1): `/api/auth/mfa/%64isable` missed the native route
    /// (axum routes on the encoded path) and was proxied to the bridge,
    /// which decodes it — skipping the gateway's MFA attempt limits.
    #[tokio::test]
    async fn encoded_native_paths_are_served_natively() {
        let (url, seen) = recording_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = crate::ws::test_harness::state(
            &dir,
            &url,
            &crate::ws::test_harness::keys_file(&[]),
            None,
        );
        let app = gateway(&state);
        for path in [
            "/api/auth/mfa/%64isable",
            "/api/auth/mfa/%72egenerate-backup-codes",
            "/api/auth/mfa/%76erify",
            "/api/%61uth/mfa/disable",
            "/api/detections/%62atch",
        ] {
            let (status, body) = send(&app, "POST", path).await;
            assert_ne!(body, "from-bridge", "{path} was proxied");
            assert!(status.is_client_error(), "{path}: {status}");
        }
        assert!(
            seen.lock().unwrap().is_empty(),
            "{:?}",
            seen.lock().unwrap()
        );

        // Anything else is proxied with the canonical path.
        let (status, body) = send(&app, "GET", "/api/%6Eodes/%7Ex?q=%64").await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "from-bridge"));
        assert_eq!(seen.lock().unwrap().clone(), ["GET /api/nodes/~x?q=%64"]);
    }

    #[tokio::test]
    async fn the_bridge_internal_api_is_never_proxied() {
        let (url, seen) = recording_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = crate::ws::test_harness::state(
            &dir,
            &url,
            &crate::ws::test_harness::keys_file(&[]),
            None,
        );
        let app = gateway(&state);
        for (method, path) in [
            ("POST", "/api/internal/bind-node-key"),
            ("POST", "/api/internal/ingest-hook"),
            ("GET", "/api/internal"),
            ("POST", "/API/Internal/ingest-hook"),
            ("POST", "/api/%69nternal/bind-node-key"),
            ("POST", "/api/%49NTERNAL/bind-node-key"),
            ("POST", "/%61pi/internal/ingest-hook"),
            ("POST", "/api/internal%2Fbind-node-key"),
            ("POST", "/api%2Finternal/ingest-hook"),
            ("POST", "/api/./internal/ingest-hook"),
            // The proxy's URL parser reads `\` as `/` and resolves dot
            // segments, so these reached the bridge's internal API.
            ("POST", "/api\\internal\\bind-node-key"),
            ("POST", "/api\\internal/ingest-hook"),
            ("POST", "/api/internal\\ingest-hook"),
            ("POST", "/api/nodes/../internal/bind-node-key"),
            ("POST", "/api/%2E%2E/api/internal/ingest-hook"),
        ] {
            let (status, body) = send(&app, method, path).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {body}");
        }
        assert!(
            seen.lock().unwrap().is_empty(),
            "{:?}",
            seen.lock().unwrap()
        );
    }

    /// Regression: the gateway served `/api/admin/keys*` itself and wrote
    /// keys to an `api_keys` table nothing authenticates against, so keys
    /// created from the dashboard never worked and the real keys (keys.json,
    /// written by the bridge) could not be listed, revoked, rotated or
    /// re-roled there. Key management must reach the bridge.
    #[tokio::test]
    async fn admin_key_management_is_proxied_to_the_bridge() {
        use crate::ws::test_harness as h;

        let (url, seen) = recording_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let raw = "sk_admin_route_test_key_0123456789abcdef";
        let state = h::state(
            &dir,
            &url,
            &h::keys_file(&[h::key_entry("ops-admin", raw, "admin", false)]),
            None,
        );
        let app = gateway(&state);
        let routes = [
            ("GET", "/api/admin/keys"),
            ("POST", "/api/admin/keys"),
            ("DELETE", "/api/admin/keys/key_abc"),
            ("PUT", "/api/admin/keys/key_abc/permissions"),
            ("POST", "/api/admin/keys/key_abc/rotate"),
        ];
        for (method, path) in routes {
            let req = Request::builder()
                .method(method)
                .uri(path)
                .header("x-api-key", raw)
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            let status = resp.status();
            let body = axum::body::to_bytes(resp.into_body(), 1 << 16)
                .await
                .unwrap();
            assert_eq!(
                (status, String::from_utf8_lossy(&body).as_ref()),
                (StatusCode::OK, "from-bridge"),
                "{method} {path}"
            );
        }
        assert_eq!(
            seen.lock().unwrap().clone(),
            routes.map(|(m, p)| format!("{m} {p}"))
        );
        // ... and the gateway keeps no key table of its own.
        let conn = state.db_pool.get().unwrap();
        assert!(storage::api_keys::legacy_gateway_key_ids(&conn)
            .unwrap()
            .is_empty());
    }

    /// The same over a real connection: hyper accepts a `\` in the
    /// request target, and the gateway must still refuse it.
    #[tokio::test]
    async fn backslash_internal_paths_are_refused_over_a_real_connection() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (url, seen) = recording_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = crate::ws::test_harness::state(
            &dir,
            &url,
            &crate::ws::test_harness::keys_file(&[]),
            None,
        );
        let app = gateway(&state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap()
        });
        for target in [
            "/api\\internal\\bind-node-key",
            "/api/internal\\ingest-hook",
            "/api\\auth\\mfa\\disable",
        ] {
            let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
            let request = format!(
                "POST {target} HTTP/1.1\r\nHost: gw\r\nContent-Type: application/json\r\n\
                 Content-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            );
            conn.write_all(request.as_bytes()).await.unwrap();
            let mut response = String::new();
            conn.read_to_string(&mut response).await.unwrap();
            let status_line = response.lines().next().unwrap_or_default().to_string();
            assert!(
                status_line.starts_with("HTTP/1.1 404") || status_line.starts_with("HTTP/1.1 400"),
                "{target}: {status_line}"
            );
        }
        assert!(
            seen.lock().unwrap().is_empty(),
            "{:?}",
            seen.lock().unwrap()
        );
    }

    /// A request framed by both Content-Length and Transfer-Encoding is
    /// refused on native routes as well as proxied ones, before
    /// authentication, and the gateway closes the connection after it
    /// (RFC 9112 §6.1): what follows the chunked body is never read as
    /// another request.
    #[tokio::test]
    async fn ambiguous_framing_is_refused_on_every_route_and_closes_the_connection() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (url, seen) = recording_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = crate::ws::test_harness::state(
            &dir,
            &url,
            &crate::ws::test_harness::keys_file(&[]),
            None,
        );
        let app = gateway(&state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap()
        });
        // A native route, a proxied one, and one authentication refuses.
        for target in ["/api/auth/login", "/api/bridge-only", "/api/admin/users"] {
            let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
            let request = format!(
                "POST {target} HTTP/1.1\r\nHost: gw\r\nContent-Type: application/json\r\n\
                 Content-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{{}}\r\n0\r\n\r\n\
                 GET /health HTTP/1.1\r\nHost: gw\r\n\r\n"
            );
            conn.write_all(request.as_bytes()).await.unwrap();
            let mut response = String::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                conn.read_to_string(&mut response),
            )
            .await
            .expect("the gateway closes the connection")
            .unwrap();
            assert!(response.starts_with("HTTP/1.1 400"), "{target}: {response}");
            assert!(
                response
                    .to_ascii_lowercase()
                    .contains("\r\nconnection: close\r\n"),
                "{target}: {response}"
            );
            assert_eq!(
                response.matches("HTTP/1.1 ").count(),
                1,
                "{target}: {response}"
            );
        }
        assert!(
            seen.lock().unwrap().is_empty(),
            "{:?}",
            seen.lock().unwrap()
        );
    }

    /// P1 regression: a `.` segment (literal, or `%2E` decoded by the
    /// canonicalization) or a `\` in a gateway-native route's path missed
    /// the native route, and the proxy's URL parser then sent the bridge
    /// the native path — its copy of the route, without the gateway's
    /// protections (MFA attempt limits, ingest node binding, audit).
    #[tokio::test]
    async fn dot_segment_and_backslash_spellings_never_reach_the_bridge() {
        let (url, seen) = recording_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = crate::ws::test_harness::state(
            &dir,
            &url,
            &crate::ws::test_harness::keys_file(&[]),
            None,
        );
        let app = gateway(&state);
        for path in [
            "/api/auth/./mfa/disable",
            "/api/auth/mfa/%2E/disable",
            "/api/auth/mfa/disable/.",
            "/api/detections/./batch",
            "/api/detections/%2e/batch",
            "/api\\auth\\mfa\\disable",
            "/api\\detections\\batch",
            "/api/auth/mfa\\regenerate-backup-codes",
            "/api/nodes/./x",
        ] {
            let (status, body) = send(&app, "POST", path).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
        }
        assert!(
            seen.lock().unwrap().is_empty(),
            "{:?}",
            seen.lock().unwrap()
        );
    }

    /// V1 regression: a native route's path with an encoded control
    /// character at the end (`%0A`) missed the native route and was
    /// proxied; the bridge decodes it to `<route>\n`, which its route
    /// patterns (ending in `$`) still match, so it served its copy of the
    /// route — without the gateway's node binding, audit or MFA limits.
    #[tokio::test]
    async fn encoded_control_characters_never_reach_the_bridge() {
        let (url, seen) = recording_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = crate::ws::test_harness::state(
            &dir,
            &url,
            &crate::ws::test_harness::keys_file(&[]),
            None,
        );
        let app = gateway(&state);
        for (method, path) in [
            ("POST", "/api/detections/batch%0A"),
            ("POST", "/api/detections/batch%0a"),
            ("POST", "/batch%0A"),
            ("POST", "/api/admin/keys%0A"),
            ("GET", "/api/admin/keys%0D%0A"),
            ("POST", "/api/admin/users%0A"),
            ("POST", "/api/auth/login%0A"),
            ("POST", "/api/auth/mfa/disable%00"),
            ("POST", "/api/auth/mfa/disable%7F"),
            ("POST", "/api/auth/mfa/disable%0D"),
            ("POST", "/api/detections%0A/batch"),
            ("GET", "/api/nodes/x%09"),
        ] {
            let (status, body) = send(&app, method, path).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {path}: {body}");
            assert_eq!(body, r#"{"detail":"Invalid path"}"#, "{method} {path}");
        }
        assert!(
            seen.lock().unwrap().is_empty(),
            "{:?}",
            seen.lock().unwrap()
        );
        // The proxy handler refuses them too, reached directly.
        for path in ["/api/detections/batch%0A", "/api/admin/keys%00"] {
            let req = Request::post(path).body(Body::empty()).unwrap();
            let resp = crate::proxy::handler::proxy_fallback(
                axum::extract::State(Arc::clone(&state)),
                req,
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{path}");
        }
        assert!(seen.lock().unwrap().is_empty());
    }

    /// Defence in depth: the proxy handler itself, reached without the
    /// router's canonicalization, refuses a path its URL parser would
    /// rewrite and never sends the internal API.
    #[tokio::test]
    async fn the_proxy_handler_refuses_paths_its_url_parser_would_rewrite() {
        let (url, seen) = recording_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = crate::ws::test_harness::state(
            &dir,
            &url,
            &crate::ws::test_harness::keys_file(&[]),
            None,
        );
        for (path, expected) in [
            ("/api\\internal\\bind-node-key", StatusCode::NOT_FOUND),
            ("/api/internal\\ingest-hook", StatusCode::NOT_FOUND),
            ("/api\\auth\\mfa\\disable", StatusCode::BAD_REQUEST),
            ("/api/auth/./mfa/disable", StatusCode::BAD_REQUEST),
            ("/api/auth/mfa/disable/.", StatusCode::BAD_REQUEST),
        ] {
            let req = Request::post(path).body(Body::empty()).unwrap();
            let resp = crate::proxy::handler::proxy_fallback(
                axum::extract::State(Arc::clone(&state)),
                req,
            )
            .await;
            assert_eq!(resp.status(), expected, "{path}");
        }
        assert!(
            seen.lock().unwrap().is_empty(),
            "{:?}",
            seen.lock().unwrap()
        );
        // An ordinary path is still proxied, escapes added by the URL
        // parser included.
        let req = Request::get("/api/nodes/a\"b").body(Body::empty()).unwrap();
        let resp =
            crate::proxy::handler::proxy_fallback(axum::extract::State(Arc::clone(&state)), req)
                .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(seen.lock().unwrap().clone(), ["GET /api/nodes/a%22b"]);
    }

    #[tokio::test]
    async fn encoded_websocket_paths_reach_the_websocket_routes() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::ws::test_harness::state(
            &dir,
            "http://127.0.0.1:1",
            &crate::ws::test_harness::keys_file(&[]),
            None,
        );
        let req = Request::builder()
            .uri("/ws/%73tatus")
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(Body::empty())
            .unwrap();
        let resp = gateway(&state).oneshot(req).await.unwrap();
        // Authenticated by the WebSocket route (the HTTP fallback would
        // answer 502).
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn health_reports_the_post_ingest_hook_counters() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::ws::test_harness::state(
            &dir,
            "http://127.0.0.1:1",
            &crate::ws::test_harness::keys_file(&[]),
            None,
        );
        let (status, body) = send(&gateway(&state), "GET", "/health").await;
        assert_eq!(status, StatusCode::OK);
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["status"], "ok");
        for counter in [
            "dropped_batches",
            "dropped_detections",
            "failed_batches",
            "queued_detections",
            "hooks_disabled",
            "restored_batches",
            "restored_detections",
        ] {
            assert_eq!(body["post_ingest_hooks"][counter], 0, "{counter}");
        }
        assert_eq!(body["post_ingest_hooks"]["enabled"], true);

        // K10: without a usable proxy secret the hooks are disabled.
        let Ok(mut no_secret) = Arc::try_unwrap(state) else {
            unreachable!()
        };
        no_secret.config.proxy_secret = String::new();
        let (_, body) = send(&gateway(&Arc::new(no_secret)), "GET", "/health").await;
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["post_ingest_hooks"]["enabled"], false);
    }

    /// Every username the admin create accepts can be managed through the
    /// `{username}` routes behind the path guard — demoted, MFA-disabled,
    /// password-reset and disabled, natively, whether the client sends its
    /// dots as they are or as `%2E`. The guard refuses "." and ".." as path
    /// segments (400 on every route, so an account with such a name could
    /// never be disabled or demoted through the API), and so the create
    /// refuses those two names, even with the admin role.
    #[tokio::test]
    async fn every_creatable_username_is_reachable_by_the_user_routes() {
        use crate::ws::test_harness as h;
        use serde_json::json;

        let (url, seen) = recording_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let raw = "sk_admin_route_test_key_0123456789abcdef";
        let state = h::state(
            &dir,
            &url,
            &h::keys_file(&[h::key_entry("ops-admin", raw, "admin", false)]),
            None,
        );
        let app = gateway(&state);
        let call = |method: &str, path: &str, body: serde_json::Value| {
            let req = Request::builder()
                .method(method)
                .uri(path)
                .header("x-api-key", raw)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap();
            let app = app.clone();
            async move {
                let resp = app.oneshot(req).await.unwrap();
                let status = resp.status();
                let body = axum::body::to_bytes(resp.into_body(), 1 << 16)
                    .await
                    .unwrap();
                (status, String::from_utf8_lossy(&body).into_owned())
            }
        };
        // (role, enabled, password_hash) of the account, if it exists.
        let account = |name: &str| -> Option<(String, bool, String)> {
            let conn = state.db_pool.get().unwrap();
            let mut stmt = conn
                .prepare("SELECT role, enabled, password_hash FROM users WHERE username = ?1")
                .unwrap();
            let mut rows = stmt
                .query_map([name], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .unwrap();
            rows.next().map(Result::unwrap)
        };
        // An enabled admin account (as stored by an earlier create, or by
        // a path that does not validate the name).
        let reset_to_admin = |name: &str| {
            let conn = state.db_pool.get().unwrap();
            if account(name).is_none() {
                storage::users::tests::insert_user(&conn, name, "admin", true);
            }
            conn.execute(
                "UPDATE users SET role = 'admin', enabled = 1 WHERE username = ?1",
                [name],
            )
            .unwrap();
        };
        let create =
            |name: &str| json!({"username": name, "password": "Str0ng-Passw0rd", "role": "admin"});
        // The routes that take no new password, then the password reset.
        let routes = |name: &str| {
            [
                (
                    "PUT",
                    format!("/api/admin/users/{name}"),
                    json!({"role": "analyst"}),
                ),
                (
                    "POST",
                    format!("/api/admin/users/{name}/disable-mfa"),
                    json!({}),
                ),
                ("DELETE", format!("/api/admin/users/{name}"), json!({})),
            ]
        };
        let reset = |name: &str| {
            (
                "POST",
                format!("/api/admin/users/{name}/reset-password"),
                json!({"new_password": "Replacement-Str0ng-Passw0rd"}),
            )
        };
        let spellings = |name: &str| [name.to_string(), name.replace('.', "%2E")];

        // Why the create refuses them: the guard answers 400 for such an
        // account on every route, in either spelling, and changes nothing.
        for name in [".", ".."] {
            reset_to_admin(name);
            let before = account(name);
            for spelling in spellings(name) {
                for (method, path, body) in routes(&spelling).into_iter().chain([reset(&spelling)])
                {
                    let (status, resp) = call(method, &path, body).await;
                    assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {path}: {resp}");
                    assert_eq!(resp, r#"{"detail":"Invalid path"}"#, "{method} {path}");
                }
            }
            assert_eq!(account(name), before, "{name:?}");
        }
        state
            .db_pool
            .get()
            .unwrap()
            .execute("DELETE FROM users", [])
            .unwrap();
        for name in [".", ".."] {
            let (status, body) = call("POST", "/api/admin/users", create(name)).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{name:?}: {body}");
            assert!(body.contains("Invalid username"), "{name:?}: {body}");
            assert!(account(name).is_none(), "{name:?}");
        }

        // Every other dotted name is an ordinary segment. "..." goes through
        // the real create; the others are stored directly (the create's own
        // tests cover accepting them). PBKDF2 is slow in debug builds, so
        // each password is reset once, in the escaped spelling, which the
        // guard decodes before it looks at the segments.
        let (status, body) = call("POST", "/api/admin/users", create("...")).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        for name in ["...", "..x", "x..", "a.b"] {
            for spelling in spellings(name) {
                reset_to_admin(name);
                for (method, path, body) in routes(&spelling) {
                    let (status, resp) = call(method, &path, body).await;
                    assert_eq!(status, StatusCode::OK, "{method} {path}: {resp}");
                }
                let (role, enabled, _) = account(name).unwrap();
                assert_eq!((role.as_str(), enabled), ("analyst", false), "{spelling}");
            }
            let (_, _, old_hash) = account(name).unwrap();
            let (method, path, body) = reset(&name.replace('.', "%2E"));
            let (status, resp) = call(method, &path, body).await;
            assert_eq!(status, StatusCode::OK, "{method} {path}: {resp}");
            assert_ne!(account(name).unwrap().2, old_hash, "{path}");
        }
        assert!(
            seen.lock().unwrap().is_empty(),
            "{:?}",
            seen.lock().unwrap()
        );
    }
}

/// The security headers through the app [`GatewayBuilder::run`] serves
/// ([`served_app`]): [`SecurityHeadersLayer`] wraps the framing guard,
/// `with_canonical_paths`, the body limit and CORS layers, and the auth
/// and CSRF middlewares, so their refusals carry the headers as the
/// routes' answers do.
#[cfg(test)]
mod security_header_tests {
    use super::*;
    use crate::ws::test_harness as h;
    use axum::body::Body;
    use axum::http::{HeaderMap, Request, StatusCode};
    use std::sync::Mutex;
    use tower::ServiceExt as _;

    pub(super) const MAX_BODY: usize = 16;
    const HSTS: &str = "max-age=31536000; includeSubDomains";

    /// An auth-enabled state over an unreachable bridge, CSRF on, with
    /// a small body limit.
    pub(super) async fn state(dir: &tempfile::TempDir) -> Arc<AppState> {
        state_with(dir, crate::test_support::REFUSED_URL, |_| {}).await
    }

    /// [`state`] over the bridge at `python_url`, changed by `edit`.
    async fn state_with(
        dir: &tempfile::TempDir,
        python_url: &str,
        edit: impl FnOnce(&mut AppState),
    ) -> Arc<AppState> {
        let state = h::state(dir, python_url, &h::keys_file(&[]), None);
        let Ok(mut state) = Arc::try_unwrap(state) else {
            unreachable!("fresh state has one owner")
        };
        state.config.max_body_size = MAX_BODY;
        edit(&mut state);
        state.auth_config.write().await.csrf_enabled = true;
        Arc::new(state)
    }

    /// The app `GatewayBuilder::run` serves (strict CSP, HSTS on a TLS
    /// listener).
    pub(super) fn production_app(state: &Arc<AppState>) -> Router {
        let security = SecurityConfig {
            csp_mode: CspMode::Strict,
            hsts_enabled: true,
            tls_active: true,
        };
        served_app(Arc::clone(state), security)
    }

    /// A fake bridge that records the headers of every request and answers
    /// like a static asset trying to weaken the protective headers: its
    /// own caching, a permissive CSP and `X-Frame-Options`.
    async fn asset_bridge() -> (String, Arc<Mutex<Vec<HeaderMap>>>) {
        let seen: Arc<Mutex<Vec<HeaderMap>>> = Arc::default();
        let record = Arc::clone(&seen);
        let app = Router::new().fallback(move |req: Request<Body>| {
            let record = Arc::clone(&record);
            async move {
                record.lock().unwrap().push(req.headers().clone());
                (
                    [
                        ("cache-control", "public, max-age=3600"),
                        ("content-security-policy", "default-src *"),
                        ("x-frame-options", "ALLOWALL"),
                    ],
                    "asset",
                )
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, seen)
    }

    /// Every value of header `name`.
    fn values<'a>(headers: &'a HeaderMap, name: &str) -> Vec<&'a str> {
        headers
            .get_all(name)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect()
    }

    /// The protective headers, each exactly once with the gateway's value
    /// (the exact CSP is pinned in `middleware::security`), and one
    /// request id.
    pub(super) fn assert_protective_headers(headers: &HeaderMap, context: &str) {
        assert_protective_headers_with_hsts(headers, context, Some(HSTS));
    }

    /// [`assert_protective_headers`] with `Strict-Transport-Security`
    /// exactly `hsts`, or absent for `None`.
    fn assert_protective_headers_with_hsts(headers: &HeaderMap, context: &str, hsts: Option<&str>) {
        for (name, value) in [
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
            ("referrer-policy", "strict-origin-when-cross-origin"),
            (
                "permissions-policy",
                "camera=(), microphone=(), geolocation=(), payment=()",
            ),
            ("x-dns-prefetch-control", "off"),
        ] {
            assert_eq!(values(headers, name), [value], "{context}: {name}");
        }
        assert_eq!(
            values(headers, "strict-transport-security"),
            hsts.into_iter().collect::<Vec<_>>(),
            "{context}: HSTS"
        );
        let csp = values(headers, "content-security-policy");
        assert!(
            csp.len() == 1 && csp[0].contains("frame-ancestors 'none'"),
            "{context}: CSP {csp:?}"
        );
        assert!(
            headers.get("content-security-policy-report-only").is_none(),
            "{context}"
        );
        let ids = values(headers, "x-request-id");
        assert!(
            ids.len() == 1 && !ids[0].is_empty(),
            "{context}: X-Request-ID {ids:?}"
        );
    }

    async fn check(app: &Router, cases: Vec<(&str, Request<Body>, StatusCode)>) {
        for (context, req, expected) in cases {
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), expected, "{context}");
            assert_protective_headers(resp.headers(), context);
        }
    }

    /// Responses made by the handlers and the proxy — inside the layer —
    /// carry the headers in the production composition.
    #[tokio::test]
    async fn handler_and_proxy_responses_carry_security_headers() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir).await;
        let app = production_app(&state);
        let get = |uri: &str| Request::get(uri).body(Body::empty()).unwrap();
        let undeclared_length =
            futures_util::stream::iter([Ok::<_, std::io::Error>(bytes::Bytes::from(vec![
                b'x';
                MAX_BODY
                    + 1
            ]))]);
        check(
            &app,
            vec![
                ("health", get("/health"), StatusCode::OK),
                (
                    "native route without credentials",
                    get("/api/detections/recent"),
                    StatusCode::UNAUTHORIZED,
                ),
                (
                    "wrong method on an ingest route",
                    get("/batch"),
                    StatusCode::METHOD_NOT_ALLOWED,
                ),
                (
                    "wrong method on /health",
                    Request::post("/health").body(Body::empty()).unwrap(),
                    StatusCode::METHOD_NOT_ALLOWED,
                ),
                ("bridge unreachable", get("/api/x"), StatusCode::BAD_GATEWAY),
                (
                    "streamed body over the limit",
                    Request::post("/api/x")
                        .body(Body::from_stream(undeclared_length))
                        .unwrap(),
                    StatusCode::PAYLOAD_TOO_LARGE,
                ),
            ],
        )
        .await;
    }

    /// Refusals by the layers outside the handlers — the framing guard, the
    /// auth and CSRF middlewares, the path canonicalization, the body limit
    /// for a declared length — must carry the same headers: a refusal page
    /// is still a page a browser renders, frames and sniffs. (Over TCP, for
    /// the framing guard: `framing_tests`.)
    #[tokio::test]
    async fn refusals_by_outer_layers_carry_security_headers() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir).await;
        let app = production_app(&state);
        let session = h::session_for(&state, "alice", "admin");
        let restricted = h::session_with(&state, "bob", "admin", "", "password_change_only");
        let bearer = |token: &str| format!("Bearer {token}");
        check(
            &app,
            vec![
                (
                    "session scope (auth middleware)",
                    Request::get("/api/x")
                        .header("authorization", bearer(&restricted))
                        .body(Body::empty())
                        .unwrap(),
                    StatusCode::FORBIDDEN,
                ),
                (
                    "missing CSRF token",
                    Request::post("/api/x")
                        .header("authorization", bearer(&session))
                        .body(Body::empty())
                        .unwrap(),
                    StatusCode::FORBIDDEN,
                ),
                (
                    "internal API (canonicalization)",
                    Request::get("/api/internal/x").body(Body::empty()).unwrap(),
                    StatusCode::NOT_FOUND,
                ),
                (
                    "encoded slash (canonicalization)",
                    Request::get("/api/a%2Fb").body(Body::empty()).unwrap(),
                    StatusCode::BAD_REQUEST,
                ),
                (
                    "declared length over the limit",
                    Request::post("/api/x")
                        .header("content-length", (MAX_BODY + 1).to_string())
                        .body(Body::from(vec![b'x'; MAX_BODY + 1]))
                        .unwrap(),
                    StatusCode::PAYLOAD_TOO_LARGE,
                ),
                (
                    "Content-Length and Transfer-Encoding (framing guard)",
                    Request::post("/api/x")
                        .header("content-length", "5")
                        .header("transfer-encoding", "chunked")
                        .body(Body::from("0\r\n\r\n"))
                        .unwrap(),
                    StatusCode::BAD_REQUEST,
                ),
            ],
        )
        .await;
    }

    /// The CORS layer's answers (a preflight it makes itself, and a
    /// response it adds `Access-Control-*` to) get the protective headers
    /// and keep their own.
    #[tokio::test]
    async fn cors_answers_keep_their_headers_and_get_the_protective_ones() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, crate::test_support::REFUSED_URL, |s| {
            s.config.cors_origins = "https://ops.example".into()
        })
        .await;
        let app = production_app(&state);
        let preflight = Request::options("/api/x")
            .header("origin", "https://ops.example")
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "x-csrf-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(preflight).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_protective_headers(resp.headers(), "preflight");
        assert_eq!(
            values(resp.headers(), "access-control-allow-origin"),
            ["https://ops.example"]
        );
        let allowed = values(resp.headers(), "access-control-allow-methods").join(",");
        assert!(allowed.contains("POST"), "{allowed}");

        let cross_origin = Request::get("/api/x")
            .header("origin", "https://ops.example")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(cross_origin).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        assert_protective_headers(resp.headers(), "cross-origin GET");
        assert_eq!(
            values(resp.headers(), "access-control-allow-origin"),
            ["https://ops.example"]
        );
    }

    /// The cache policy a layer inside sets on purpose stays: the auth
    /// middleware's `no-store` on `/api/auth/*` (on the handler's refusal
    /// too) and a proxied asset's own caching. The asset's weaker CSP and
    /// `X-Frame-Options` are still replaced. Everything else gets the
    /// gateway's default.
    #[tokio::test]
    async fn an_inner_cache_policy_is_kept() {
        let (bridge, seen) = asset_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, &bridge, |_| {}).await;
        let app = production_app(&state);
        let session = h::session_for(&state, "carol", "viewer");
        let get = |uri: &str| Request::get(uri).body(Body::empty()).unwrap();
        let me_with_session = Request::get("/api/auth/me")
            .header("authorization", format!("Bearer {session}"))
            .body(Body::empty())
            .unwrap();
        for (context, req, expected) in [
            (
                "/api/auth/me with a session",
                me_with_session,
                StatusCode::OK,
            ),
            (
                "/api/auth/me without one",
                get("/api/auth/me"),
                StatusCode::UNAUTHORIZED,
            ),
        ] {
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), expected, "{context}");
            assert_protective_headers(resp.headers(), context);
            assert_eq!(
                values(resp.headers(), "cache-control"),
                ["no-store, no-cache, must-revalidate"],
                "{context}"
            );
            assert_eq!(values(resp.headers(), "pragma"), ["no-cache"], "{context}");
        }

        let resp = app.clone().oneshot(get("/static/app.js")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(seen.lock().unwrap().len(), 1, "proxied");
        assert_protective_headers(resp.headers(), "proxied asset");
        assert_eq!(
            values(resp.headers(), "cache-control"),
            ["public, max-age=3600"]
        );
        assert!(resp.headers().get("pragma").is_none());

        let resp = app.oneshot(get("/health")).await.unwrap();
        assert_eq!(
            values(resp.headers(), "cache-control"),
            ["no-cache, no-store, must-revalidate"]
        );
        assert_eq!(values(resp.headers(), "pragma"), ["no-cache"]);
    }

    /// The `X-Request-ID` a client sends comes back, also on an outer
    /// layer's refusal; and the one the layer adds when there is none is
    /// the one the layers and handlers inside see: the bridge gets the id
    /// the client is told.
    #[tokio::test]
    async fn the_request_id_is_the_one_every_layer_sees() {
        let (bridge, seen) = asset_bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(&dir, &bridge, |_| {}).await;
        let app = production_app(&state);
        let session = h::session_for(&state, "dave", "admin");

        let csrf_refusal = Request::post("/api/x")
            .header("authorization", format!("Bearer {session}"))
            .header("x-request-id", "trace-7")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(csrf_refusal).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(values(resp.headers(), "x-request-id"), ["trace-7"]);
        assert!(seen.lock().unwrap().is_empty());

        let traced = Request::get("/static/app.js")
            .header("x-request-id", "trace-8")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(traced).await.unwrap();
        assert_eq!(values(resp.headers(), "x-request-id"), ["trace-8"]);
        assert_eq!(
            values(&seen.lock().unwrap()[0], "x-request-id"),
            ["trace-8"]
        );

        let untraced = Request::get("/static/app.js").body(Body::empty()).unwrap();
        let resp = app.oneshot(untraced).await.unwrap();
        let ids = values(resp.headers(), "x-request-id");
        assert!(uuid::Uuid::parse_str(ids[0]).is_ok(), "{ids:?}");
        assert_eq!(values(&seen.lock().unwrap()[1], "x-request-id"), ids);
    }

    /// A WebSocket handshake through the served app: the 101 carries the
    /// protective headers once, and the socket works.
    #[tokio::test]
    async fn a_websocket_upgrade_carries_the_headers_and_works() {
        use tokio_tungstenite::tungstenite::{client::IntoClientRequest as _, Message};
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir).await;
        let token = h::session_for(&state, "erin", "viewer");
        let app = production_app(&state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap()
        });
        let mut req = format!("ws://{addr}/ws/feed")
            .into_client_request()
            .unwrap();
        let headers = req.headers_mut();
        headers.insert("cookie", format!("session_token={token}").parse().unwrap());
        headers.insert("origin", format!("http://{addr}").parse().unwrap());
        let (mut ws, resp) = tokio_tungstenite::connect_async(req)
            .await
            .expect("upgraded");
        assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert_protective_headers(resp.headers(), "101");
        state.detection_tx.send("{\"n\":1}".into()).unwrap();
        match h::next_msg(&mut ws, 5).await {
            Some(Message::Text(text)) => assert_eq!(text.as_str(), "{\"n\":1}"),
            other => panic!("expected the detection, got {other:?}"),
        }
    }

    /// A gateway that [`serve_gateway`] (the end of `GatewayBuilder::run`)
    /// serves on a loopback port.
    struct Served {
        addr: std::net::SocketAddr,
        stop: tokio::sync::watch::Sender<bool>,
        server: tokio::task::JoinHandle<Result<(), BuilderError>>,
    }

    impl Served {
        /// Serve `state` (see [`listening_state`]); returns once the
        /// listener accepts connections.
        async fn start(state: Arc<AppState>) -> Self {
            use std::time::{Duration, Instant};
            let addr = state.config.bind_addr().parse().unwrap();
            let (stop, stopped) = tokio::sync::watch::channel(false);
            let server = tokio::spawn(serve_gateway(state, ShutdownSignal::from_receiver(stopped)));
            let deadline = Instant::now() + Duration::from_secs(10);
            while tokio::net::TcpStream::connect(addr).await.is_err() {
                if server.is_finished() {
                    panic!("serving ended before listening: {:?}", server.await);
                }
                assert!(Instant::now() < deadline, "nothing listens on {addr}");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Self { addr, stop, server }
        }

        /// Ask for the shutdown; serving ends without an error.
        async fn stop(self) {
            self.stop.send(true).unwrap();
            let served = tokio::time::timeout(
                SERVER_SHUTDOWN_GRACE + std::time::Duration::from_secs(5),
                self.server,
            )
            .await
            .expect("serving stops")
            .unwrap();
            assert!(served.is_ok(), "{served:?}");
        }
    }

    /// [`state`] for a gateway listening on a free loopback port with a
    /// production configuration's security settings (strict CSP, HSTS
    /// on), changed by `edit`.
    async fn listening_state(
        dir: &tempfile::TempDir,
        edit: impl FnOnce(&mut AppState),
    ) -> Arc<AppState> {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .unwrap()
            .port();
        state_with(dir, crate::test_support::REFUSED_URL, |s| {
            s.config.host = "127.0.0.1".into();
            s.config.port = port;
            s.config.csp_mode = "strict".into();
            s.config.hsts_enabled = true;
            edit(s);
        })
        .await
    }

    /// The paths the served-gateway tests request, with the status each
    /// gets: an answer, a refusal by the auth middleware, and one by the
    /// path canonicalization outside everything else.
    const SERVED_CASES: [(&str, u16); 3] = [
        ("/health", 200),
        ("/api/detections/recent", 401),
        ("/api/internal/x", 404),
    ];

    /// What `GatewayBuilder::run` serves on a plaintext listener carries
    /// the security headers (the tests above build the same app, this one
    /// the same server), but no HSTS: the connection is not TLS.
    #[tokio::test]
    async fn the_served_gateway_sends_the_headers_on_a_plaintext_listener() {
        let dir = tempfile::tempdir().unwrap();
        let state = listening_state(&dir, |_| {}).await;
        assert!(!state.config.tls_enabled());
        let served = Served::start(state).await;
        let client = reqwest::Client::new();
        for (path, status) in SERVED_CASES {
            let resp = client
                .get(format!("http://{}{path}", served.addr))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status().as_u16(), status, "{path}");
            assert_protective_headers_with_hsts(resp.headers(), path, None);
        }
        drop(client);
        served.stop().await;
    }

    /// On the gateway's own TLS listener, what `GatewayBuilder::run`
    /// serves carries the security headers and HSTS.
    #[tokio::test]
    async fn the_served_gateway_sends_the_headers_and_hsts_on_a_tls_listener() {
        use crate::auth::client_cert::tests as cc;
        cc::ensure_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let ca = cc::test_ca("Server CA");
        let server = cc::issue_leaf(&ca, "localhost", |p| {
            p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth]
        });
        let cert = dir.path().join("server.pem");
        let key = dir.path().join("server.key");
        std::fs::write(&cert, cc::to_pem("CERTIFICATE", &server.der)).unwrap();
        std::fs::write(&key, server.key.serialize_pem()).unwrap();
        let state = listening_state(&dir, |s| {
            s.config.tls_cert = Some(cert);
            s.config.tls_key = Some(key);
        })
        .await;
        let served = Served::start(state).await;
        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(ca.pem().as_bytes()).unwrap())
            .resolve("localhost", served.addr)
            .build()
            .unwrap();
        for (path, status) in SERVED_CASES {
            let resp = client
                .get(format!("https://localhost:{}{path}", served.addr.port()))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status().as_u16(), status, "{path}");
            assert_protective_headers(resp.headers(), path);
        }
        drop(client);
        served.stop().await;
    }
}

/// CSRF on the batch ingest routes, through the served app: an ANALYST
/// session may submit a batch (for any node), but only with the
/// double-submit token, as for every other session mutation; API keys and
/// client certificates (the edge ingest path) need none.
#[cfg(test)]
mod batch_csrf_tests {
    use super::*;
    use crate::ws::test_harness as h;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    /// The tables a batch writes to.
    pub(super) const INGEST_SCHEMA: &str = "
        CREATE TABLE detections (
            detection_id TEXT PRIMARY KEY, node_id TEXT, timestamp TEXT, signal_class TEXT,
            confidence REAL, family TEXT, freq_hz REAL, snr_db REAL, power_dbm REAL,
            inference_ms REAL, backend TEXT, anomaly_score REAL, baseline_status TEXT,
            has_iq_capture INTEGER, gain_db REAL, lna_state TEXT, bandwidth_hz REAL,
            tenant_id TEXT);
        CREATE TABLE rf_anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT, detection_id TEXT, signal_class TEXT,
            family TEXT, freq_hz REAL, dedup_key TEXT, node_id TEXT, timestamp TEXT,
            confidence REAL, snr_db REAL, power_dbm REAL, anomaly_score REAL, priority TEXT,
            dimensions TEXT, reasons TEXT, baseline_status TEXT, has_iq_capture INTEGER,
            seen_count INTEGER, first_seen TEXT, tenant_id TEXT, dismissed INTEGER DEFAULT 0);
        CREATE TABLE fhss_events (
            fhss_id TEXT PRIMARY KEY, node_id TEXT, timestamp TEXT, hop_rate_hz REAL,
            hop_set TEXT, bandwidth_hz REAL, dwell_time_ms REAL, duration_sec REAL,
            signal_class TEXT, detection_count INTEGER, confidence REAL, tenant_id TEXT);";

    const EDGE_KEY: &str = "sk-edge-admin";

    /// CSRF on, an unbound ADMIN key, a SENSOR certificate for `edge-7`.
    async fn state(dir: &tempfile::TempDir) -> Arc<AppState> {
        let keys = h::keys_file(&[h::key_entry("edge-admin", EDGE_KEY, "admin", false)]);
        let state = h::state(dir, crate::test_support::REFUSED_URL, &keys, None);
        let registry = dir.path().join("registry.json");
        h::write_cert_registry(&registry, "edge-7", "sensor", false);
        let state = h::with_cert_registry(state, &registry);
        state.auth_config.write().await.csrf_enabled = true;
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch(INGEST_SCHEMA)
            .unwrap();
        state
    }

    fn app(state: &Arc<AppState>) -> Router {
        let security = SecurityConfig {
            csp_mode: CspMode::Strict,
            hsts_enabled: false,
            tls_active: false,
        };
        served_app(Arc::clone(state), security)
    }

    /// A batch for node `edge-7`, sent as a CORS-simple `text/plain` body,
    /// with these extra headers.
    fn batch(path: &str, id: &str, headers: &[(&str, &str)]) -> Request<Body> {
        let body = serde_json::json!({"node_id": "edge-7", "detections": [{
            "detection_id": id, "signal_class": "qpsk", "confidence": 0.9,
            "freq_hz": 433_920_000.0, "timestamp": "2026-11-05T10:00:00+00:00",
        }]});
        let mut req = Request::post(path).header("content-type", "text/plain");
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        req.body(Body::from(body.to_string())).unwrap()
    }

    async fn send(app: &Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap_or_default())
    }

    fn stored(state: &AppState) -> Vec<String> {
        let conn = state.db_pool.get().unwrap();
        let mut stmt = conn
            .prepare("SELECT detection_id FROM detections ORDER BY rowid")
            .unwrap();
        stmt.query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    #[tokio::test]
    async fn a_session_batch_needs_the_csrf_token_and_edge_credentials_do_not() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir).await;
        let app = app(&state);
        let session = h::session_for(&state, "analyst", "analyst");
        let cookie = format!("session_token={session}");
        let with_token = format!("{cookie}; csrf_token=t1");
        let bearer = format!("Bearer {session}");
        let mut expected = Vec::new();

        for path in ["/batch", "/api/detections/batch"] {
            for (what, headers) in [
                ("session cookie", vec![("cookie", cookie.as_str())]),
                (
                    "session cookie, mismatched token",
                    vec![("cookie", with_token.as_str()), ("x-csrf-token", "t2")],
                ),
                ("bearer session", vec![("authorization", bearer.as_str())]),
            ] {
                let (status, body) = send(&app, batch(path, "refused", &headers)).await;
                assert_eq!(status, StatusCode::FORBIDDEN, "{path} {what}: {body}");
                assert_eq!(body["detail"], "CSRF token missing or mismatch", "{path}");
            }
            assert_eq!(stored(&state), expected, "{path}: nothing stored");

            let id = format!("session{}", path.len());
            let headers = [("cookie", with_token.as_str()), ("x-csrf-token", "t1")];
            let (status, body) = send(&app, batch(path, &id, &headers)).await;
            assert_eq!(status, StatusCode::OK, "{path} session with token: {body}");
            assert_eq!(body["accepted"], true, "{path}");
            expected.push(id);

            let id = format!("key{}", path.len());
            let (status, body) = send(&app, batch(path, &id, &[("x-api-key", EDGE_KEY)])).await;
            assert_eq!(status, StatusCode::OK, "{path} API key: {body}");
            expected.push(id);

            let id = format!("cert{}", path.len());
            let mut req = batch(path, &id, &[]);
            req.extensions_mut().insert(h::client_cert("edge-7"));
            let (status, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK, "{path} certificate: {body}");
            expected.push(id);

            assert_eq!(stored(&state), expected, "{path}");
        }
    }
}

/// A client certificate is an ambient credential: a browser that holds one
/// presents it on any TLS handshake to the gateway, whichever page started
/// the request, and SameSite does not apply to it. A mutating request that
/// a certificate authenticates is refused when the browser's `Origin` is
/// another origin, on native and proxied routes alike and whether CSRF
/// protection is on or off, as its WebSocket handshake is (`ws::auth`). An
/// agent (no `Origin`), this origin, an origin listed in `UC_CORS_ORIGINS`,
/// a safe method and an API key are not affected.
#[cfg(test)]
mod cert_origin_tests {
    use super::*;
    use crate::ws::test_harness as h;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Mutex;
    use tower::ServiceExt as _;

    /// The `Host` the requests name: the gateway's TLS listener, so this
    /// origin is `https://gw.example:8444`.
    const HOST: &str = "gw.example:8444";
    const THIS_ORIGIN: &str = "https://gw.example:8444";
    const OPS_KEY: &str = "sk-ops-admin";
    const CREATE_ADMIN: &str =
        r#"{"username":"csrfadmin","password":"Forged-Pass1","role":"admin","x":"="}"#;

    /// A fake bridge that records the path of every request and answers 200.
    async fn bridge() -> (String, Arc<Mutex<Vec<String>>>) {
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let record = Arc::clone(&seen);
        let app = Router::new().fallback(move |req: Request<Body>| {
            let record = Arc::clone(&record);
            async move {
                record.lock().unwrap().push(req.uri().path().to_string());
                "{}"
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, seen)
    }

    /// Auth on over the bridge at `python_url`, an ADMIN certificate for
    /// `ops-laptop`, an ADMIN API key, a user `victim` with MFA on,
    /// `UC_CORS_ORIGINS` = `cors` and CSRF protection `csrf`.
    async fn state(
        dir: &tempfile::TempDir,
        python_url: &str,
        cors: &str,
        csrf: bool,
    ) -> Arc<AppState> {
        let keys = h::keys_file(&[h::key_entry("ops-admin", OPS_KEY, "admin", false)]);
        let state = h::state(dir, python_url, &keys, None);
        let registry = dir.path().join("registry.json");
        h::write_cert_registry(&registry, "ops-laptop", "admin", false);
        let Ok(mut state) = Arc::try_unwrap(h::with_cert_registry(state, &registry)) else {
            unreachable!("fresh state has one owner")
        };
        state.config.cors_origins = cors.into();
        let state = Arc::new(state);
        state.auth_config.write().await.csrf_enabled = csrf;
        state
            .db_pool
            .get()
            .unwrap()
            .execute(
                "INSERT INTO users (username, password_hash, salt, role, created_at, mfa_enabled) \
                 VALUES ('victim', 'x', 'x', 'viewer', '2026-01-01T00:00:00+00:00', 1)",
                [],
            )
            .unwrap();
        state
    }

    fn app(state: &Arc<AppState>) -> Router {
        let security = SecurityConfig {
            csp_mode: CspMode::Strict,
            hsts_enabled: true,
            tls_active: true,
        };
        served_app(Arc::clone(state), security)
    }

    /// What a cross-site form makes the browser send: `method path` with a
    /// CORS-simple body, `Host`, this `Origin` (if any), and the
    /// `ops-laptop` certificate, as the TLS acceptor reports it.
    fn cert_request(method: &str, path: &str, origin: Option<&str>) -> Request<Body> {
        let body = if path == "/api/admin/users" {
            CREATE_ADMIN
        } else {
            "a=b"
        };
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("host", HOST)
            .header("content-type", "text/plain");
        if let Some(origin) = origin {
            req = req.header("origin", origin);
        }
        let mut req = req.body(Body::from(body)).unwrap();
        req.extensions_mut().insert(h::client_cert("ops-laptop"));
        req
    }

    async fn send(app: &Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap_or_default())
    }

    fn user_count(state: &AppState, username: &str) -> i64 {
        state
            .db_pool
            .get()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM users WHERE username = ?1",
                [username],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn victim_column(state: &AppState, column: &str) -> bool {
        state
            .db_pool
            .get()
            .unwrap()
            .query_row(
                &format!("SELECT {column} FROM users WHERE username = 'victim'"),
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn victim_mfa(state: &AppState) -> bool {
        victim_column(state, "mfa_enabled")
    }

    fn victim_enabled(state: &AppState) -> bool {
        victim_column(state, "enabled")
    }

    fn set_victim_mfa(state: &AppState) {
        state
            .db_pool
            .get()
            .unwrap()
            .execute(
                "UPDATE users SET mfa_enabled = 1 WHERE username = 'victim'",
                [],
            )
            .unwrap();
    }

    #[tokio::test]
    async fn a_cross_origin_certificate_mutation_is_refused_on_every_route() {
        let (bridge_url, seen) = bridge().await;
        for csrf in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let state = state(&dir, &bridge_url, "https://ops.example", csrf).await;
            let app = app(&state);
            for origin in [
                "https://evil.example",
                "null",
                // Another scheme, port or host than this origin.
                "http://gw.example:8444",
                "https://gw.example",
                "https://gw.example:8445",
                "https://gw.example:8444.evil.example",
                "https://evil.example:8444",
                // UC_CORS_ORIGINS lists only the exact origin.
                "https://ops.example:8444",
                "http://ops.example",
            ] {
                for (method, path) in [
                    ("POST", "/api/admin/users"),
                    ("POST", "/api/admin/users/victim/disable-mfa"),
                    ("PUT", "/api/admin/settings/security"),
                    ("DELETE", "/api/admin/users/victim"),
                    ("POST", "/batch"),
                    // Proxied to the bridge.
                    ("POST", "/api/maps/upload"),
                    ("PATCH", "/api/nodes/edge-7"),
                ] {
                    let what = format!("csrf={csrf} {method} {path} from {origin}");
                    let (status, body) = send(&app, cert_request(method, path, Some(origin))).await;
                    assert_eq!(status, StatusCode::FORBIDDEN, "{what}: {body}");
                    assert_eq!(body["detail"], "Cross-origin request refused", "{what}");
                }
            }
            assert_eq!(user_count(&state, "csrfadmin"), 0, "csrf={csrf}");
            assert!(victim_mfa(&state), "csrf={csrf}");
            assert!(victim_enabled(&state), "csrf={csrf}");
        }
        let seen = seen.lock().unwrap();
        assert!(seen.is_empty(), "the bridge got {seen:?}");
    }

    #[tokio::test]
    async fn a_certificate_mutation_from_an_agent_this_origin_or_a_listed_one_passes() {
        let (bridge_url, seen) = bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir, &bridge_url, "https://ops.example", true).await;
        let app = app(&state);
        for origin in [
            None,
            Some(THIS_ORIGIN),
            Some("https://GW.example:8444"),
            Some("wss://gw.example:8444"),
            Some("https://ops.example"),
        ] {
            set_victim_mfa(&state);
            let req = cert_request("POST", "/api/admin/users/victim/disable-mfa", origin);
            let (status, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK, "{origin:?}: {body}");
            assert!(!victim_mfa(&state), "{origin:?}");

            let req = cert_request("POST", "/api/maps/upload", origin);
            let (status, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK, "{origin:?} proxied: {body}");
        }
        assert_eq!(seen.lock().unwrap().len(), 5);

        let (status, body) = send(&app, cert_request("POST", "/api/admin/users", None)).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(user_count(&state, "csrfadmin"), 1);
    }

    /// An API key is no ambient credential, and a safe method changes
    /// nothing: neither is checked, whatever the `Origin`.
    #[tokio::test]
    async fn an_api_key_or_a_safe_method_is_not_origin_checked() {
        let (bridge_url, seen) = bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir, &bridge_url, "", true).await;
        let app = app(&state);

        let mut req = cert_request(
            "POST",
            "/api/admin/users/victim/disable-mfa",
            Some("https://evil.example"),
        );
        req.headers_mut()
            .insert("x-api-key", OPS_KEY.parse().unwrap());
        let (status, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK, "API key: {body}");
        assert!(!victim_mfa(&state));

        for path in ["/api/admin/users", "/api/maps/list"] {
            let req = cert_request("GET", path, Some("https://evil.example"));
            let (status, body) = send(&app, req).await;
            assert_eq!(status, StatusCode::OK, "GET {path}: {body}");
        }
        assert_eq!(*seen.lock().unwrap(), ["/api/maps/list"]);
    }
}

/// Role default parity, end to end through the app `GatewayBuilder::run`
/// serves and a real keys.json: a key stored without a role or with one
/// that names no role is a VIEWER key, as on the bridge, and the bridge's
/// master key (written without a role) is ADMIN, as on the bridge.
#[cfg(test)]
mod role_default_tests {
    use super::*;
    use crate::ws::test_harness as h;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    /// A keys.json entry for `raw` whose `role` field is `role_field`
    /// (`""` for none).
    fn entry(key_id: &str, raw: &str, role_field: &str) -> String {
        let with_role = h::key_entry(key_id, raw, "viewer", false);
        let entry = with_role.replace(r#""role": "viewer","#, role_field);
        assert_ne!(entry, with_role, "the role field is replaced");
        entry
    }

    async fn send(app: &Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap_or_default())
    }

    fn get(path: &str, key: &str) -> Request<Body> {
        Request::get(path)
            .header("x-api-key", key)
            .body(Body::empty())
            .unwrap()
    }

    fn batch(key: &str) -> Request<Body> {
        batch_for(key, "edge-01")
    }

    fn batch_for(key: &str, node: &str) -> Request<Body> {
        let body = serde_json::json!({"node_id": node, "detections": [{
            "detection_id": format!("d-{key}-{node}"), "signal_class": "qpsk", "confidence": 0.9,
            "freq_hz": 433_920_000.0, "timestamp": "2026-11-05T10:00:00+00:00",
        }]});
        Request::post("/api/detections/batch")
            .header("x-api-key", key)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    /// The app over `state`, with the tables a batch writes to.
    fn app(state: &Arc<AppState>) -> Router {
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch(super::batch_csrf_tests::INGEST_SCHEMA)
            .unwrap();
        served_app(
            Arc::clone(state),
            SecurityConfig {
                csp_mode: CspMode::Strict,
                hsts_enabled: false,
                tls_active: false,
            },
        )
    }

    /// With `BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1` and the bridge unreachable:
    /// a key without a role read nothing the gateway serves (403 on its
    /// viewer routes) and submitted batches for any node, and the master
    /// key, as the bridge writes it on first run, was refused on the
    /// gateway's admin routes. (Null, non-string and unknown roles read
    /// like a missing one: `auth::api_key` tests, through the parser.)
    #[tokio::test]
    async fn a_key_without_a_role_is_a_viewer_key_and_the_master_key_is_admin() {
        const LEGACY: &str = "sk-legacy-without-a-role-000";
        const MASTER: &str = "sk-master-without-a-role-000";
        let keys = h::keys_file(&[entry("legacy", LEGACY, ""), entry("master", MASTER, "")]);
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(&dir, crate::test_support::REFUSED_URL, &keys, None);
        let Ok(mut state) = Arc::try_unwrap(state) else {
            unreachable!("fresh state has one owner")
        };
        state.config.allow_unbound_node_keys = "1".into();
        let app = app(&Arc::new(state));

        let (status, body) = send(&app, get("/api/detections/recent", LEGACY)).await;
        assert_eq!(status, StatusCode::OK, "a viewer reads: {body}");
        let (status, body) = send(&app, batch(LEGACY)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(
            body["detail"], "Node endpoints require a node API key",
            "a viewer key is no node credential"
        );
        let (status, _) = send(&app, get("/api/admin/audit/verify", LEGACY)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "not an admin");

        let (status, body) = send(&app, get("/api/admin/audit/verify", MASTER)).await;
        assert_eq!(status, StatusCode::OK, "master is ADMIN: {body}");
        let (status, body) = send(&app, batch(MASTER)).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "an ADMIN key acts for any node: {body}"
        );
    }

    /// A key without a role named after a registered node keeps the
    /// bridge's legacy rule (that node's key), but as a VIEWER key it is
    /// decided from the gateway's copy of nodes.json alone, with node-key
    /// binding on and no binding request (the bridge here is unreachable,
    /// which would be a 503). A node registered since the bridge last
    /// saved nodes.json is not listed: refused as for any VIEWER key.
    #[tokio::test]
    async fn a_key_without_a_role_named_after_a_node_keeps_the_legacy_rule() {
        const LISTED: &str = "sk-edge-01-without-a-role-00";
        const UNLISTED: &str = "sk-edge-02-without-a-role-00";
        let keys = h::keys_file(&[entry("edge-01", LISTED, ""), entry("edge-02", UNLISTED, "")]);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("nodes.json"),
            r#"{"nodes": {"edge-01": {"status": "online"}}}"#,
        )
        .unwrap();
        let state = h::state(&dir, crate::test_support::REFUSED_URL, &keys, None);
        assert!(!state.config.unbound_node_keys_allowed());
        assert!(state.config.proxy_secret_usable(), "node-key binding is on");
        let app = app(&state);

        let (status, body) = send(&app, batch_for(LISTED, "edge-01")).await;
        assert_eq!(status, StatusCode::OK, "its own node: {body}");
        let (status, body) = send(&app, batch_for(LISTED, "edge-03")).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["detail"], "API key is bound to node 'edge-01'");
        let (status, body) = send(&app, batch_for(UNLISTED, "edge-02")).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["detail"], "Node endpoints require a node API key");
    }
}

/// The framing guard (`middleware::framing`) in the composition
/// `GatewayBuilder::run` serves (`served_app`, through
/// `security_header_tests::production_app`), over TCP, so that hyper
/// parses the requests and decides whether a connection stays open. Each
/// layer of that composition answers some requests itself (CORS every
/// `OPTIONS`, the body limit a declared length above it, the path
/// canonicalization `/api/internal` and refused paths, authentication):
/// none may answer a request whose framing a front proxy may read
/// otherwise and keep the connection open, or what follows the chunked
/// body is read as the next request.
#[cfg(test)]
mod framing_tests {
    use super::security_header_tests::{
        assert_protective_headers, production_app, state, MAX_BODY,
    };
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// What a smuggling client sends behind its chunked body: it must
    /// never be answered.
    const SMUGGLED: &str = "GET /api/internal/smuggled HTTP/1.1\r\nHost: gw\r\n\r\n";

    /// The empty chunked body every request here carries (5 bytes, the
    /// Content-Length the requests declare unless they say otherwise).
    const EMPTY_CHUNKED: &str = "0\r\n\r\n";

    async fn serve(app: axum::Router) -> SocketAddr {
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

    /// Write `request` to the gateway at `addr` and read what it sends:
    /// the bytes, and whether it closed the connection (within 5 s).
    async fn exchange(addr: SocketAddr, request: &str) -> (String, bool) {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut received = Vec::new();
        let mut buf = [0u8; 4096];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let closed = loop {
            match tokio::time::timeout_at(deadline, stream.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => break true,
                Ok(Ok(n)) => received.extend_from_slice(&buf[..n]),
                Err(_) => break false,
            }
        };
        (String::from_utf8_lossy(&received).into_owned(), closed)
    }

    /// The gateway sent one response, with `status` and `Connection:
    /// close`, and closed the connection: nothing behind the request was
    /// answered.
    fn assert_one_response_then_closed(context: &str, exchanged: &(String, bool), status: u16) {
        let (response, closed) = exchanged;
        assert!(closed, "{context}: the connection stayed open: {response}");
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status} ")),
            "{context}: {response}"
        );
        assert!(
            response
                .to_ascii_lowercase()
                .contains("\r\nconnection: close\r\n"),
            "{context}: {response}"
        );
        assert_eq!(
            response.matches("HTTP/1.1 ").count(),
            1,
            "{context}: {response}"
        );
    }

    /// Content-Length before `Transfer-Encoding: chunked` (hyper keeps
    /// both) is refused with 400 and the connection closed, whichever
    /// layer would have answered the request: the CORS preflight (with or
    /// without an Origin), the canonicalization, the body limit,
    /// authentication, a native route or the proxy.
    #[tokio::test]
    async fn ambiguous_framing_is_refused_before_any_layer_answers() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir).await;
        let addr = serve(production_app(&state)).await;
        let declared = EMPTY_CHUNKED.len().to_string();
        let over_limit = (MAX_BODY * 10).to_string();
        let cases = [
            (
                "CORS preflight without Origin",
                "OPTIONS /api/x HTTP/1.1\r\n",
                &declared,
            ),
            (
                "CORS preflight",
                "OPTIONS /api/x HTTP/1.1\r\nOrigin: https://app.example\r\n\
                 Access-Control-Request-Method: POST\r\n",
                &declared,
            ),
            (
                "internal API",
                "POST /api/internal/x HTTP/1.1\r\n",
                &declared,
            ),
            ("dot segment", "POST /api/%2e%2e/x HTTP/1.1\r\n", &declared),
            ("encoded slash", "POST /api/a%2Fb HTTP/1.1\r\n", &declared),
            (
                "control character",
                "POST /api/x%0A HTTP/1.1\r\n",
                &declared,
            ),
            (
                "declared length over the limit",
                "POST /api/x HTTP/1.1\r\n",
                &over_limit,
            ),
            (
                "authentication refuses",
                "GET /api/detections/recent HTTP/1.1\r\n",
                &declared,
            ),
            (
                "native route",
                "POST /api/auth/login HTTP/1.1\r\nContent-Type: application/json\r\n",
                &declared,
            ),
            ("proxied", "POST /api/x HTTP/1.1\r\n", &declared),
        ];
        for (context, head, length) in cases {
            let request = format!(
                "{head}Host: gw\r\nContent-Length: {length}\r\nTransfer-Encoding: chunked\r\n\r\n\
                 {EMPTY_CHUNKED}{SMUGGLED}"
            );
            assert_one_response_then_closed(context, &exchange(addr, &request).await, 400);
        }
    }

    /// A Content-Length after `Transfer-Encoding: chunked` hyper drops
    /// unseen, so the gateway frames that request by its chunks and
    /// answers it, as one with Transfer-Encoding alone, and then closes
    /// the connection (RFC 9112 §6.1) — whichever layer answers.
    #[tokio::test]
    async fn every_request_with_transfer_encoding_closes_the_connection() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir).await;
        let addr = serve(production_app(&state)).await;
        let te_then_cl = "Transfer-Encoding: chunked\r\nContent-Length: 5\r\n";
        let te = "Transfer-Encoding: chunked\r\n";
        let cases = [
            ("native route", "GET /health", te_then_cl, 200),
            ("proxied", "POST /api/x", te_then_cl, 502),
            ("CORS preflight", "OPTIONS /api/x", te_then_cl, 200),
            ("canonicalization", "POST /api/internal/x", te_then_cl, 404),
            (
                "authentication refuses",
                "GET /api/detections/recent",
                te_then_cl,
                401,
            ),
            ("chunked alone, native route", "GET /health", te, 200),
            ("chunked alone, proxied", "POST /api/x", te, 502),
        ];
        for (context, line, framing, status) in cases {
            let request =
                format!("{line} HTTP/1.1\r\nHost: gw\r\n{framing}\r\n{EMPTY_CHUNKED}{SMUGGLED}");
            assert_one_response_then_closed(context, &exchange(addr, &request).await, status);
        }
    }

    /// Requests framed by Content-Length alone keep their connection:
    /// a pipelined request is answered too.
    #[tokio::test]
    async fn requests_framed_by_content_length_keep_the_connection() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir).await;
        let addr = serve(production_app(&state)).await;
        let (response, closed) = exchange(
            addr,
            "POST /api/x HTTP/1.1\r\nHost: gw\r\nContent-Length: 2\r\n\r\n{}\
             GET /health HTTP/1.1\r\nHost: gw\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(closed, "{response}");
        assert!(response.starts_with("HTTP/1.1 502 "), "{response}");
        assert_eq!(response.matches("HTTP/1.1 ").count(), 2, "{response}");
        assert!(
            response.contains("\r\n\r\nPython backend unavailable"),
            "{response}"
        );
    }

    /// The header fields of the one response in `response`.
    fn response_headers(response: &str) -> axum::http::HeaderMap {
        let (head, _) = response.split_once("\r\n\r\n").expect("a response head");
        let mut headers = axum::http::HeaderMap::new();
        for line in head.split("\r\n").skip(1) {
            let (name, value) = line.split_once(':').expect("a header field");
            headers.append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_str(value.trim()).unwrap(),
            );
        }
        headers
    }

    /// The security headers wrap the framing guard: its 400 carries them
    /// on the wire, next to its `Connection: close`, with the request id
    /// the client sent.
    #[tokio::test]
    async fn the_framing_refusal_carries_the_security_headers() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir).await;
        let addr = serve(production_app(&state)).await;
        let request = format!(
            "POST /api/x HTTP/1.1\r\nHost: gw\r\nX-Request-ID: trace-framing\r\n\
             Content-Length: {}\r\nTransfer-Encoding: chunked\r\n\r\n{EMPTY_CHUNKED}{SMUGGLED}",
            EMPTY_CHUNKED.len()
        );
        let exchanged = exchange(addr, &request).await;
        assert_one_response_then_closed("framing refusal", &exchanged, 400);
        let headers = response_headers(&exchanged.0);
        assert_protective_headers(&headers, "framing refusal");
        assert_eq!(
            headers.get("x-request-id").unwrap(),
            "trace-framing",
            "{}",
            exchanged.0
        );
    }
}

/// PRE-68 follow-up: the gateway opens the bridge's database, so it must
/// refuse one that a newer bridge has migrated, as the bridge does, before
/// it changes anything in it.
#[cfg(test)]
mod schema_guard_tests {
    use super::*;
    use clap::Parser;
    use std::path::Path;

    /// A development gateway on `dir/detections.db`, with no keys file
    /// (allowed) and a bridge at `python_url`.
    fn config(dir: &Path, python_url: &str) -> Config {
        let mut c = Config::try_parse_from(["sigrift-gateway"]).unwrap();
        c.bridge_env = "development".to_string();
        c.allow_no_auth = true;
        c.db_path = dir.join("detections.db");
        c.keys_path = dir.join("no-keys.json");
        c.baseline_path = dir.join("baselines.json");
        c.hook_spool_path = Some(dir.join("hooks.spool"));
        c.python_url = python_url.to_string();
        c.proxy_secret = "a-strong-proxy-secret".to_string();
        c.host = "127.0.0.1".to_string();
        c.port = 0;
        c
    }

    /// What a bridge leaves behind: its `schema_version` rows (the
    /// historical gaps 39 and 44 left out) and a `sessions` table from
    /// before the gateway's `scope` column.
    fn bridge_database(path: &Path, versions: impl IntoIterator<Item = i64>) {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_version (
                 version INTEGER PRIMARY KEY,
                 description TEXT NOT NULL,
                 applied_at TEXT NOT NULL
             );
             CREATE TABLE sessions (id INTEGER PRIMARY KEY, token TEXT);",
        )
        .unwrap();
        for v in versions {
            conn.execute(
                "INSERT INTO schema_version VALUES (?1, 'migration', datetime('now'))",
                [v],
            )
            .unwrap();
        }
    }

    fn sqlite_master(path: &Path) -> Vec<(String, String, Option<String>)> {
        let conn = rusqlite::Connection::open(path).unwrap();
        let mut stmt = conn
            .prepare("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")
            .unwrap();
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        rows
    }

    /// Run the gateway with `config` until it ends, for at most 10 s, and
    /// return the error it refused to start with.
    async fn run_refusal(config: &Config) -> BuilderError {
        let resolver: SharedLicenseResolver = Arc::new(crate::NullLicenseResolver);
        let ran = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            GatewayBuilder::new(config.clone(), resolver).run(),
        )
        .await;
        match ran {
            Ok(Err(e)) => e,
            Ok(Ok(())) => panic!("the gateway exited cleanly instead of refusing"),
            Err(_) => panic!("the gateway kept running on a newer schema"),
        }
    }

    /// Started on a database holding a migration newer than any this build
    /// knows, the gateway stops with an error naming it, at once and
    /// without waiting for the bridge (none answers here), and leaves the
    /// schema as it was.
    #[tokio::test]
    async fn run_refuses_a_database_from_a_newer_bridge_without_changing_it() {
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path(), "http://127.0.0.1:9");
        let newer = db::schema::NEWEST_KNOWN_BRIDGE_MIGRATION + 1;
        bridge_database(
            &config.db_path,
            (1..=newer).filter(|v| ![39, 44].contains(v)),
        );
        let before = sqlite_master(&config.db_path);

        let err = run_refusal(&config).await;
        assert!(matches!(err, BuilderError::Schema(_)), "{err:?}");
        let err = err.to_string();
        assert!(err.contains(&format!("[{newer}]")), "{err}");
        assert!(err.contains("newer than this gateway build"), "{err}");
        assert_eq!(
            sqlite_master(&config.db_path),
            before,
            "the refused database was changed"
        );
    }

    /// The gateway started first, on a fresh database; a newer bridge then
    /// migrates it before it answers. `run` stops with the refusal of the
    /// check made once the bridge answered, instead of going on to listen.
    #[tokio::test]
    async fn run_refuses_a_newer_bridge_that_migrates_while_the_gateway_waits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.db");
        let newer = db::schema::NEWEST_KNOWN_BRIDGE_MIGRATION + 1;
        let url = bridge(&path, Some(vec![1, newer])).await;
        let config = config(dir.path(), &url);

        let err = run_refusal(&config).await;
        match &err {
            BuilderError::Schema(msg) => assert!(msg.contains(&format!("[{newer}]")), "{msg}"),
            other => panic!("expected a schema refusal, got {other:?}"),
        }
        // It got past the first check: the fresh database got the
        // gateway's own tables before the bridge migrated it.
        assert!(
            tables(&path).contains(&"nodes".to_string()),
            "{:?}",
            tables(&path)
        );
    }

    fn pool(path: &Path) -> db::pool::DbPool {
        db::pool::create_pool(path, 2, 5000).unwrap()
    }

    fn tables(path: &Path) -> Vec<String> {
        sqlite_master(path)
            .into_iter()
            .filter(|(kind, name, _)| kind == "table" && !name.starts_with("sqlite_"))
            .map(|(_, name, _)| name)
            .collect()
    }

    /// The gateway may start before the bridge has created anything: it
    /// still starts (the missing tables only get a warning) and adds only
    /// its own tables, never a `schema_version`.
    #[test]
    fn a_fresh_database_is_prepared_as_before() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.db");
        prepare_database(&pool(&path)).unwrap();
        assert_eq!(
            tables(&path),
            ["nodes", "password_history", "pending_commands"]
        );
    }

    /// A database the bridge of this release migrated (gaps 39 and 44
    /// included) is accepted, and gets the gateway's own column and tables.
    #[test]
    fn the_current_bridge_schema_is_prepared() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.db");
        bridge_database(
            &path,
            (1..=db::schema::NEWEST_KNOWN_BRIDGE_MIGRATION).filter(|v| ![39, 44].contains(v)),
        );
        prepare_database(&pool(&path)).unwrap();
        assert_eq!(
            tables(&path),
            [
                "nodes",
                "password_history",
                "pending_commands",
                "schema_version",
                "sessions"
            ]
        );
        let sessions = sqlite_master(&path)
            .into_iter()
            .find(|(_, name, _)| name == "sessions")
            .and_then(|(_, _, sql)| sql)
            .unwrap();
        assert!(sessions.contains("scope"), "{sessions}");
    }

    /// Refused before any of the gateway's own schema changes, and the
    /// refusal is the startup error, not a warning.
    #[test]
    fn a_newer_bridge_schema_is_refused_before_any_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.db");
        let newest = db::schema::NEWEST_KNOWN_BRIDGE_MIGRATION;
        bridge_database(&path, [newest, newest + 1]);
        let before = sqlite_master(&path);
        match prepare_database(&pool(&path)) {
            Err(BuilderError::Schema(msg)) => {
                assert!(msg.contains(&format!("[{}]", newest + 1)), "{msg}")
            }
            other => panic!("expected a schema refusal, got {other:?}"),
        }
        assert_eq!(sqlite_master(&path), before);
    }

    /// A `schema_version` the gateway cannot read refuses too (fail
    /// closed), as on the bridge.
    #[test]
    fn an_unreadable_schema_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.db");
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE schema_version (applied_at TEXT);")
            .unwrap();
        let before = sqlite_master(&path);
        assert!(matches!(
            prepare_database(&pool(&path)),
            Err(BuilderError::Schema(_))
        ));
        assert_eq!(sqlite_master(&path), before);
    }

    /// Keys an older gateway stored in its own `api_keys` table never
    /// authenticated, and are not the keys the dashboard manages: startup
    /// names them (the first 50) so the operator re-creates or revokes the
    /// real ones, and leaves the table as it is. A table it cannot read
    /// only gets a warning; the start goes on.
    #[test]
    fn legacy_gateway_keys_are_reported_at_startup_and_left_alone() {
        use crate::test_support::logs_of;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 key_id TEXT UNIQUE NOT NULL, hash TEXT NOT NULL);",
        )
        .unwrap();
        for n in 0..60 {
            conn.execute(
                "INSERT INTO api_keys (key_id, hash) VALUES (?1, 'h')",
                [format!("legacy-{n:02}")],
            )
            .unwrap();
        }
        let (prepared, logs) = logs_of(|| prepare_database(&pool(&path)));
        prepared.unwrap();
        let warned: Vec<&str> = logs
            .lines()
            .filter(|l| l.contains("WARN") && l.contains("older gateway's /api/admin/keys"))
            .collect();
        assert_eq!(warned.len(), 1, "{logs}");
        for named in ["count=60", "\"legacy-00\"", "\"legacy-49\"", "re-create"] {
            assert!(warned[0].contains(named), "{named:?} missing: {logs}");
        }
        assert!(!warned[0].contains("\"legacy-50\""), "{logs}");
        let kept: i64 = conn
            .query_row("SELECT COUNT(*) FROM api_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(kept, 60, "the legacy table was changed");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.db");
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE api_keys (id INTEGER PRIMARY KEY, name TEXT);")
            .unwrap();
        let (prepared, logs) = logs_of(|| prepare_database(&pool(&path)));
        prepared.unwrap();
        assert!(
            logs.contains("Could not check for legacy gateway API keys"),
            "{logs}"
        );

        // No legacy table: nothing to say.
        let dir = tempfile::tempdir().unwrap();
        let (prepared, logs) =
            logs_of(|| prepare_database(&pool(&dir.path().join("detections.db"))));
        prepared.unwrap();
        assert!(
            !logs.contains("api_keys") && !logs.contains("API keys"),
            "{logs}"
        );
    }

    /// A stand-in bridge answering `GET /api/version`. With `migrate_to`,
    /// it first migrates `db_path` to those versions, as a bridge does
    /// before it serves.
    async fn bridge(db_path: &Path, migrate_to: Option<Vec<i64>>) -> String {
        let db_path = db_path.to_path_buf();
        let app = Router::new().route(
            "/api/version",
            get(move || {
                let db_path = db_path.clone();
                let migrate_to = migrate_to.clone();
                async move {
                    if let Some(versions) = migrate_to {
                        let conn = rusqlite::Connection::open(&db_path).unwrap();
                        conn.execute_batch(
                            "CREATE TABLE IF NOT EXISTS schema_version (
                                 version INTEGER PRIMARY KEY,
                                 description TEXT NOT NULL,
                                 applied_at TEXT NOT NULL
                             );",
                        )
                        .unwrap();
                        for v in versions {
                            conn.execute(
                                "INSERT OR IGNORE INTO schema_version
                                 VALUES (?1, 'migration', datetime('now'))",
                                [v],
                            )
                            .unwrap();
                        }
                    }
                    r#"{"api_version": "1"}"#
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        url
    }

    /// A shutdown signal that never fires (its sender is kept).
    fn no_shutdown() -> (tokio::sync::watch::Sender<bool>, ShutdownSignal) {
        let (tx, rx) = tokio::sync::watch::channel(false);
        (tx, ShutdownSignal::from_receiver(rx))
    }

    /// The gateway started on a fresh database, before the bridge; a newer
    /// bridge then migrates it before it answers. The gateway refuses once
    /// the bridge answers, before it listens.
    #[tokio::test]
    async fn a_newer_bridge_that_migrates_while_the_gateway_waits_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.db");
        let pool = pool(&path);
        prepare_database(&pool).unwrap();
        let newest = db::schema::NEWEST_KNOWN_BRIDGE_MIGRATION;
        let url = bridge(&path, Some(vec![newest, newest + 1])).await;
        let config = config(dir.path(), &url);
        let (_keep, shutdown) = no_shutdown();
        let waited = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            wait_for_bridge(&config, &pool, shutdown),
        )
        .await
        .expect("the bridge answered at once");
        match waited {
            Err(BuilderError::Schema(msg)) => {
                assert!(msg.contains(&format!("[{}]", newest + 1)), "{msg}")
            }
            other => panic!("expected a schema refusal, got {other:?}"),
        }
    }

    /// A bridge of this release (or none migrating yet) lets the gateway
    /// go on starting.
    #[tokio::test]
    async fn a_known_schema_after_the_bridge_wait_starts() {
        for migrate_to in [
            None,
            Some(vec![1, db::schema::NEWEST_KNOWN_BRIDGE_MIGRATION]),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("detections.db");
            let pool = pool(&path);
            prepare_database(&pool).unwrap();
            let url = bridge(&path, migrate_to.clone()).await;
            let config = config(dir.path(), &url);
            let (_keep, shutdown) = no_shutdown();
            let waited = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                wait_for_bridge(&config, &pool, shutdown),
            )
            .await
            .expect("the bridge answered at once");
            assert_eq!(waited.unwrap(), BridgeWait::Start, "{migrate_to:?}");
        }
    }

    /// A shutdown while waiting still just stops, without a schema check.
    #[tokio::test]
    async fn a_shutdown_while_waiting_for_the_bridge_stops() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.db");
        let pool = pool(&path);
        let config = config(dir.path(), "http://127.0.0.1:9");
        let (stop, stopped) = tokio::sync::watch::channel(false);
        stop.send(true).unwrap();
        let waited = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            wait_for_bridge(&config, &pool, ShutdownSignal::from_receiver(stopped)),
        )
        .await
        .expect("the shutdown ends the wait");
        assert_eq!(waited.unwrap(), BridgeWait::Stop);
    }
}

/// Session credentials through the served app: the bridge gets a session
/// token only as the session the gateway verified, sent as
/// `Authorization: Bearer`. The bridge resolves any session token it is
/// given itself, but the shipped compose file leaves its own IP binding off
/// (`BRIDGE_SESSION_BINDING=none`), so the gateway's checks hold only if no
/// token the gateway refused or did not recognise reaches it.
#[cfg(test)]
mod session_credential_tests {
    use super::*;
    use crate::middleware::auth::SCOPE_PASSWORD_CHANGE_ONLY;
    use crate::ws::test_harness as h;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{HeaderMap, Request, StatusCode};
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use tower::ServiceExt as _;

    const OPS_KEY: &str = "sk-ops-viewer";
    /// The client IP the sessions are bound to, and another one.
    const HOME: &str = "198.51.100.7:5000";
    const AWAY: &str = "203.0.113.9:5000";

    /// A fake bridge that records the headers of every request it gets.
    async fn bridge() -> (String, Arc<Mutex<Vec<HeaderMap>>>) {
        let seen: Arc<Mutex<Vec<HeaderMap>>> = Arc::default();
        let record = Arc::clone(&seen);
        let app = Router::new().fallback(move |req: Request<Body>| {
            let record = Arc::clone(&record);
            async move {
                record.lock().unwrap().push(req.headers().clone());
                "{}"
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, seen)
    }

    /// Auth on over the bridge at `url`, a VIEWER API key, IP binding.
    async fn state(dir: &tempfile::TempDir, url: &str) -> Arc<AppState> {
        let keys = h::keys_file(&[h::key_entry("ops", OPS_KEY, "viewer", false)]);
        let state = h::state(dir, url, &keys, None);
        {
            let mut auth = state.auth_config.write().await;
            auth.binding_mode = SessionBindingMode::Ip;
            auth.csrf_enabled = true;
        }
        state
    }

    fn app(state: &Arc<AppState>) -> Router {
        let security = SecurityConfig {
            csp_mode: CspMode::Strict,
            hsts_enabled: false,
            tls_active: false,
        };
        served_app(Arc::clone(state), security)
    }

    fn get(path: &str, peer: &str, headers: &[(&str, String)]) -> Request<Body> {
        let mut req = Request::get(path);
        for (name, value) in headers {
            req = req.header(*name, value);
        }
        let mut req = req.body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        req
    }

    fn values(headers: &HeaderMap, name: &str) -> Vec<String> {
        headers
            .get_all(name)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    /// The headers of the one request the bridge got since the last call.
    fn forwarded(seen: &Mutex<Vec<HeaderMap>>) -> HeaderMap {
        let mut seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "bridge requests: {seen:?}");
        seen.pop().unwrap()
    }

    /// Regression: a session token the gateway did not accept was proxied
    /// as an anonymous request with the token still in it, and the bridge
    /// authenticated it. That was so for a session bound to another IP
    /// (the gateway's binding check refused it) and for any session sent
    /// as `bearer <token>` (the gateway read only `Bearer`).
    #[tokio::test]
    async fn only_the_session_the_gateway_verified_reaches_the_bridge() {
        let (url, seen) = bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir, &url).await;
        let token = h::session_with(&state, "okuser", "analyst", "198.51.100.7", "");
        let app = app(&state);

        let bearer = |scheme: &str| vec![("authorization", format!("{scheme} {token}"))];
        let x_session = vec![("x-session-token", token.clone())];
        let verified = vec![format!("Bearer {token}")];
        let cases = [
            ("Bearer, own IP", HOME, bearer("Bearer"), Some("okuser")),
            ("bearer, own IP", HOME, bearer("bearer"), Some("okuser")),
            ("BEARER, own IP", HOME, bearer("BEARER"), Some("okuser")),
            (
                "X-Session-Token, own IP",
                HOME,
                x_session.clone(),
                Some("okuser"),
            ),
            ("Bearer, another IP", AWAY, bearer("Bearer"), None),
            ("bearer, another IP", AWAY, bearer("bearer"), None),
            ("X-Session-Token, another IP", AWAY, x_session, None),
        ];
        for (what, peer, headers, user) in cases {
            let resp = app
                .clone()
                .oneshot(get("/api/echo", peer, &headers))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{what}");
            let got = forwarded(&seen);
            let (users, authorization) = match user {
                Some(user) => (vec![user.to_string()], verified.clone()),
                None => (vec![], vec![]),
            };
            assert_eq!(values(&got, "x-auth-user"), users, "{what}");
            assert_eq!(values(&got, "authorization"), authorization, "{what}");
            assert!(values(&got, "x-session-token").is_empty(), "{what}");
        }
    }

    /// Regression: the gateway read the session cookie as `session_token=`
    /// exactly, and the proxy dropped only cookies that started so, while
    /// the bridge (Starlette's `cookie_parser`) trims a cookie's name. So
    /// `session_token =<token>` was no session to the gateway, reached the
    /// bridge unchanged and was accepted there, from any IP. Now the
    /// gateway reads the name as the bridge does: such a cookie is the
    /// session, with the gateway's checks, and the proxy never forwards it.
    #[tokio::test]
    async fn a_session_cookie_is_read_by_the_name_the_bridge_reads() {
        let (url, seen) = bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir, &url).await;
        let token = h::session_with(&state, "okuser", "analyst", "198.51.100.7", "");
        let app = app(&state);

        let verified = vec![format!("Bearer {token}")];
        let cookies = [
            (format!("session_token ={token}"), vec![]),
            (
                format!("theme=dark; session_token\t={token}"),
                vec!["theme=dark".to_string()],
            ),
            (format!(" session_token \t= {token}"), vec![]),
        ];
        for (cookie, kept) in cookies {
            for (peer, user) in [(HOME, Some("okuser")), (AWAY, None)] {
                let what = format!("{cookie:?} from {peer}");
                let headers = [("cookie", cookie.clone())];
                let resp = app
                    .clone()
                    .oneshot(get("/api/echo", peer, &headers))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK, "{what}");
                let got = forwarded(&seen);
                let (users, authorization) = match user {
                    Some(user) => (vec![user.to_string()], verified.clone()),
                    None => (vec![], vec![]),
                };
                assert_eq!(values(&got, "x-auth-user"), users, "{what}");
                assert_eq!(values(&got, "authorization"), authorization, "{what}");
                assert_eq!(values(&got, "cookie"), kept, "{what}");
            }
        }

        // Next to an API key the gateway accepts, from another IP: the key
        // authenticates, and the session it refused stays behind.
        let headers = [
            ("x-api-key", OPS_KEY.to_string()),
            ("cookie", format!("session_token ={token}")),
        ];
        let resp = app.oneshot(get("/api/echo", AWAY, &headers)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let got = forwarded(&seen);
        assert_eq!(values(&got, "x-auth-key-id"), ["ops"]);
        assert!(values(&got, "x-auth-user").is_empty());
        assert!(values(&got, "authorization").is_empty());
        assert!(values(&got, "cookie").is_empty());
    }

    /// A request the gateway authenticates by its API key does not carry a
    /// session token it also holds to the bridge, which would try that
    /// session before the key.
    #[tokio::test]
    async fn an_api_key_request_carries_no_unverified_session_to_the_bridge() {
        let (url, seen) = bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir, &url).await;
        let token = h::session_with(&state, "okuser", "admin", "198.51.100.7", "");
        let headers = [
            ("x-api-key", OPS_KEY.to_string()),
            ("authorization", format!("Bearer {token}")),
            ("x-session-token", token.clone()),
        ];
        let resp = app(&state)
            .oneshot(get("/api/echo", AWAY, &headers))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let got = forwarded(&seen);
        assert_eq!(values(&got, "x-auth-key-id"), ["ops"]);
        assert_eq!(values(&got, "x-api-key"), [OPS_KEY]);
        assert!(values(&got, "x-auth-user").is_empty());
        assert!(values(&got, "authorization").is_empty());
        assert!(values(&got, "x-session-token").is_empty());
    }

    /// `bearer <token>` gets the gateway's own checks: it authenticates the
    /// gateway's native routes, and a restricted session sent that way is
    /// confined to its scope before anything is proxied.
    #[tokio::test]
    async fn a_lowercase_bearer_session_gets_the_gateway_checks() {
        let (url, seen) = bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir, &url).await;
        let token = h::session_with(&state, "okuser", "analyst", "198.51.100.7", "");
        let restricted = h::session_with(
            &state,
            "pwuser",
            "analyst",
            "198.51.100.7",
            SCOPE_PASSWORD_CHANGE_ONLY,
        );
        let app = app(&state);

        let me = get(
            "/api/auth/me",
            HOME,
            &[("authorization", format!("bearer {token}"))],
        );
        let resp = app.clone().oneshot(me).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["username"], "okuser");

        let echo = get(
            "/api/echo",
            HOME,
            &[("authorization", format!("bearer {restricted}"))],
        );
        let resp = app.oneshot(echo).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(seen.lock().unwrap().is_empty(), "nothing was proxied");
    }

    /// A Cookie field that is not visible ASCII is no credential to the
    /// gateway, and the proxy drops it whole: the session token in it
    /// never reaches the bridge (which decodes such a field as Latin-1 and
    /// would take the token the gateway never checked). The client's
    /// readable cookies still go through, and the same token in a readable
    /// field is the session.
    #[tokio::test]
    async fn an_opaque_cookie_field_carries_no_session_to_the_bridge() {
        let (url, seen) = bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir, &url).await;
        let token = h::session_with(&state, "okuser", "analyst", "198.51.100.7", "");
        let app = app(&state);
        let echo = |fields: Vec<Vec<u8>>| {
            let mut req = get("/api/echo", HOME, &[]);
            for field in fields {
                req.headers_mut().append(
                    axum::http::header::COOKIE,
                    axum::http::HeaderValue::from_bytes(&field).unwrap(),
                );
            }
            req
        };

        let readable = format!("session_token={token}").into_bytes();
        let resp = app.clone().oneshot(echo(vec![readable])).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let got = forwarded(&seen);
        assert_eq!(values(&got, "x-auth-user"), ["okuser"], "a readable field");

        let mut opaque = format!("session_token={token}; theme=caf").into_bytes();
        opaque.push(0xe9);
        let resp = app
            .oneshot(echo(vec![opaque, b"lang=en".to_vec()]))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let got = forwarded(&seen);
        assert!(values(&got, "x-auth-user").is_empty(), "no session");
        assert!(values(&got, "authorization").is_empty());
        // Read lossily: a forwarded opaque field is no `str`.
        let cookies: Vec<String> = got
            .get_all("cookie")
            .iter()
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .collect();
        assert_eq!(cookies, ["lang=en"], "the field is dropped whole");
    }

    /// A session token whose row cannot be read (a storage error, here a
    /// stored value of the wrong type) is refused with 503 by the served
    /// app before anything is proxied: it is never passed on as an
    /// anonymous request with the token still in it.
    #[tokio::test]
    async fn an_unreadable_session_is_refused_before_anything_is_proxied() {
        let (url, seen) = bridge().await;
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir, &url).await;
        let token = h::session_with(&state, "okuser", "analyst", "198.51.100.7", "");
        let app = app(&state);
        let echo = || {
            get(
                "/api/echo",
                HOME,
                &[("authorization", format!("Bearer {token}"))],
            )
        };

        let resp = app.clone().oneshot(echo()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(values(&forwarded(&seen), "x-auth-user"), ["okuser"]);

        state
            .db_pool
            .get()
            .unwrap()
            .execute(
                "UPDATE sessions SET created_at = X'00' WHERE session_token = ?1",
                [crate::auth::password::hash_session_token(&token)],
            )
            .unwrap();
        let resp = app.oneshot(echo()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(seen.lock().unwrap().is_empty(), "nothing was proxied");
    }
}

/// What [`GatewayBuilder::run`] refuses to start with, before it opens
/// anything a refusal could leave changed: production without the secrets
/// it needs, and no key store without `UC_ALLOW_NO_AUTH` (fail closed, not
/// a gateway that serves every request unauthenticated). Both come before
/// the wait for the bridge: none answers here, so a gateway that went on
/// would still be waiting when these tests give up on it.
#[cfg(test)]
mod startup_refusal_tests {
    use super::*;
    use clap::Parser;
    use std::path::Path;

    // `Fernet.generate_key()` output.
    const FERNET_KEY: &str = "gbhtBUbPkbiIqPMsYEdh1YUZAxWFy-1pp3gVY24zhzM=";

    /// A `bridge_env` gateway with every secret production needs, writing
    /// only in `dir`, with no keys file and no bridge answering.
    fn config(dir: &Path, bridge_env: &str) -> Config {
        let mut c = Config::try_parse_from(["sigrift-gateway"]).unwrap();
        c.bridge_env = bridge_env.to_string();
        c.proxy_secret = "a-strong-proxy-secret".to_string();
        c.audit_key = "an-audit-key".to_string();
        c.mfa_key = FERNET_KEY.to_string();
        c.db_path = dir.join("detections.db");
        c.keys_path = dir.join("keys.json");
        c.baseline_path = dir.join("baselines.json");
        c.hook_spool_path = Some(dir.join("hooks.spool"));
        c.python_url = crate::test_support::REFUSED_URL.to_string();
        c.host = "127.0.0.1".to_string();
        c.port = 0;
        c.allow_no_auth = false;
        c.session_absolute_timeout_hours = None;
        c.session_idle_timeout_minutes = None;
        c
    }

    /// The configuration error `run` stops with, within 10 s.
    async fn refusal(config: Config) -> String {
        let resolver: SharedLicenseResolver = Arc::new(crate::NullLicenseResolver);
        let ran = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            GatewayBuilder::new(config, resolver).run(),
        )
        .await;
        match ran {
            Ok(Err(BuilderError::Config(msg))) => msg,
            Ok(other) => panic!("expected a configuration refusal, got {other:?}"),
            Err(_) => panic!("the gateway went on starting instead of refusing"),
        }
    }

    /// The startup secret checks are what `run` does first: production
    /// with a weak or missing secret stops before the database is even
    /// created, with the error naming the setting.
    #[tokio::test]
    async fn production_without_its_secrets_stops_before_opening_the_database() {
        /// The setting named in the refusal, and how the config lacks it.
        type Case = (&'static str, fn(&mut Config));
        let cases: [Case; 3] = [
            ("UC_PROXY_SECRET", |c| {
                c.proxy_secret = "uppercrust-internal".to_string()
            }),
            ("BRIDGE_AUDIT_KEY", |c| c.audit_key = String::new()),
            ("BRIDGE_MFA_KEY", |c| c.mfa_key = String::new()),
        ];
        // `run` takes the deprecated audit-key fallbacks from the process
        // environment: with one set there, an empty BRIDGE_AUDIT_KEY is
        // not refused (`tests::production_accepts_audit_key_from_master_key`).
        let audit_fallback_set = ["BRIDGE_AUDIT_SECRET", "BRIDGE_MASTER_KEY"]
            .iter()
            .any(|name| std::env::var_os(name).is_some());
        for (named, weaken) in cases {
            if named == "BRIDGE_AUDIT_KEY" && audit_fallback_set {
                continue;
            }
            let dir = tempfile::tempdir().unwrap();
            let mut c = config(dir.path(), "production");
            weaken(&mut c);
            let db_path = c.db_path.clone();
            let msg = refusal(c).await;
            assert!(
                msg.contains("BRIDGE_ENV=production — refusing to start"),
                "{named}: {msg}"
            );
            assert!(msg.contains(named), "{named}: {msg}");
            assert!(!db_path.exists(), "{named}: the database was created");
        }
    }

    /// No key store — the keys file missing, unreadable or not a keys
    /// file — and no `UC_ALLOW_NO_AUTH`: the gateway refuses to start
    /// rather than serve with API-key authentication off, and says which
    /// file and which setting. (With `UC_ALLOW_NO_AUTH` it goes on to wait
    /// for the bridge: `schema_guard_tests`.)
    #[tokio::test]
    async fn no_key_store_without_uc_allow_no_auth_stops_the_gateway() {
        for what in ["missing", "not JSON", "a directory"] {
            let dir = tempfile::tempdir().unwrap();
            let c = config(dir.path(), "development");
            match what {
                "not JSON" => std::fs::write(&c.keys_path, "{not json").unwrap(),
                "a directory" => std::fs::create_dir(&c.keys_path).unwrap(),
                _ => {}
            }
            let keys = c.keys_path.display().to_string();
            let msg = refusal(c).await;
            for named in [
                keys.as_str(),
                "missing or unreadable",
                "UC_ALLOW_NO_AUTH",
                "refusing to start with authentication disabled",
            ] {
                assert!(
                    msg.contains(named),
                    "keys file {what}: {named:?} missing: {msg}"
                );
            }
            assert!(
                BuilderError::Config(msg)
                    .to_string()
                    .starts_with("config: keys file "),
                "{what}"
            );
        }
    }
}

/// The listeners [`serve_gateway`] (the end of `GatewayBuilder::run`)
/// opens. TLS material it cannot load stops it: it never falls back to
/// plaintext, nor a client-certificate CA it cannot load to a listener
/// without client-certificate verification. A bind address it cannot use
/// stops it too. On the mTLS listener a client certificate is an identity
/// only when it chains to `UC_TLS_CLIENT_CA` and the CA registry names it.
#[cfg(test)]
mod listener_tests {
    use super::*;
    use crate::auth::client_cert::tests::{self as cc, Leaf, TestCa};
    use crate::auth::client_cert::ClientCertInfo;
    use crate::ws::test_harness as h;
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .unwrap()
            .port()
    }

    /// A state for a gateway on a free loopback port, changed by `edit`,
    /// and the directory of its database.
    fn state(edit: impl FnOnce(&mut Config)) -> (tempfile::TempDir, Arc<AppState>) {
        let dir = tempfile::tempdir().unwrap();
        let state = h::state(
            &dir,
            crate::test_support::REFUSED_URL,
            &h::keys_file(&[]),
            None,
        );
        let Ok(mut state) = Arc::try_unwrap(state) else {
            unreachable!("fresh state has one owner")
        };
        state.config.host = "127.0.0.1".to_string();
        state.config.port = free_port();
        edit(&mut state.config);
        (dir, Arc::new(state))
    }

    /// The error `serve_gateway` stops with for `state` (within 10 s).
    async fn refused(state: Arc<AppState>) -> BuilderError {
        let addr = state.config.bind_addr();
        let (_keep, stopped) = tokio::sync::watch::channel(false);
        let served = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            serve_gateway(state, ShutdownSignal::from_receiver(stopped)),
        )
        .await;
        match served {
            Ok(Err(e)) => e,
            Ok(Ok(())) => panic!("{addr}: serving ended without an error"),
            Err(_) => panic!("{addr}: listening instead of refusing"),
        }
    }

    /// The CAs and the PEM files in `dir`: a server certificate for
    /// `localhost` and its key, the client CA, and files holding only a
    /// key (so no certificate), another key than the certificate's, and a
    /// `PRIVATE KEY` block that is no key.
    struct Pems {
        server_ca: TestCa,
        client_ca: TestCa,
        cert: PathBuf,
        key: PathBuf,
        client_ca_file: PathBuf,
        key_only: PathBuf,
        other_key: PathBuf,
        not_a_key: PathBuf,
    }

    fn pems(dir: &Path) -> Pems {
        cc::ensure_crypto_provider();
        let server_ca = cc::test_ca("Server CA");
        let server_leaf = |ca: &TestCa| {
            cc::issue_leaf(ca, "localhost", |p| {
                p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth]
            })
        };
        let server = server_leaf(&server_ca);
        let pems = Pems {
            client_ca: cc::test_ca("Client CA"),
            cert: dir.join("server.pem"),
            key: dir.join("server.key"),
            client_ca_file: dir.join("client-ca.pem"),
            key_only: dir.join("key-only.pem"),
            other_key: dir.join("other.key"),
            not_a_key: dir.join("not-a-key.pem"),
            server_ca,
        };
        std::fs::write(&pems.cert, cc::to_pem("CERTIFICATE", &server.der)).unwrap();
        std::fs::write(&pems.key, server.key.serialize_pem()).unwrap();
        std::fs::write(&pems.client_ca_file, pems.client_ca.pem()).unwrap();
        std::fs::write(&pems.key_only, server.key.serialize_pem()).unwrap();
        let other = server_leaf(&pems.server_ca);
        std::fs::write(&pems.other_key, other.key.serialize_pem()).unwrap();
        std::fs::write(&pems.not_a_key, cc::to_pem("PRIVATE KEY", b"no key")).unwrap();
        pems
    }

    #[tokio::test]
    async fn tls_material_that_does_not_load_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = pems(dir.path());
        let missing = dir.path().join("missing.pem");
        let no_certificate = format!("no certificates in {}", p.key_only.display());
        let no_key = format!("no private key in {}", p.cert.display());
        let no_ca = format!(
            "no certificates found in client CA file {}",
            p.key_only.display()
        );
        // (what, certificate, key, client CA, named in the error)
        type Case<'a> = (&'a str, &'a Path, &'a Path, Option<&'a Path>, &'a str);
        let cases: [Case; 8] = [
            (
                "a certificate file without a certificate",
                &p.key_only,
                &p.key,
                None,
                &no_certificate,
            ),
            (
                "a key file without a private key",
                &p.cert,
                &p.cert,
                None,
                &no_key,
            ),
            ("a missing certificate file", &missing, &p.key, None, ""),
            ("a missing key file", &p.cert, &missing, None, ""),
            (
                "another key than the certificate's",
                &p.cert,
                &p.other_key,
                None,
                "",
            ),
            (
                "a key block that is no key",
                &p.cert,
                &p.not_a_key,
                None,
                "",
            ),
            (
                "a client CA file without a certificate",
                &p.cert,
                &p.key,
                Some(&p.key_only),
                &no_ca,
            ),
            (
                "a missing client CA file",
                &p.cert,
                &p.key,
                Some(&missing),
                "",
            ),
        ];
        for (what, cert, key, client_ca, named) in cases {
            let (_db, state) = state(|c| {
                c.tls_cert = Some(cert.to_path_buf());
                c.tls_key = Some(key.to_path_buf());
                c.tls_client_ca = client_ca.map(Path::to_path_buf);
            });
            let err = refused(state).await;
            let BuilderError::Tls(msg) = &err else {
                panic!("{what}: expected a TLS refusal, got {err:?}");
            };
            assert!(msg.starts_with("load TLS config: "), "{what}: {msg}");
            assert!(msg.contains(named), "{what}: {named:?} missing: {msg}");
            assert!(
                err.to_string().starts_with("tls: load TLS config: "),
                "{what}"
            );
        }
    }

    /// A `UC_HOST` holding a port of its own (so the bind address has two)
    /// stops a TLS listener, with the address it could not use.
    #[tokio::test]
    async fn a_tls_listener_on_a_bind_address_with_two_ports_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = pems(dir.path());
        let (_db, state) = state(|c| {
            c.host = "127.0.0.1:8443".to_string();
            c.tls_cert = Some(p.cert.clone());
            c.tls_key = Some(p.key.clone());
        });
        let port = state.config.port;
        match refused(state).await {
            BuilderError::Bind(msg) => {
                assert!(msg.contains(&format!("127.0.0.1:8443:{port}")), "{msg}")
            }
            other => panic!("expected a bind refusal, got {other:?}"),
        }
    }

    /// A listener whose port is taken stops the gateway rather than run
    /// without it: the plaintext one with the address, the TLS one too.
    #[tokio::test]
    async fn a_port_in_use_is_refused() {
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = taken.local_addr().unwrap().port();
        let (_db, plain) = state(|c| c.port = port);
        let err = refused(plain).await;
        assert!(matches!(&err, BuilderError::Bind(_)), "{err:?}");
        assert!(
            err.to_string()
                .starts_with(&format!("bind: 127.0.0.1:{port}: ")),
            "{err}"
        );

        let dir = tempfile::tempdir().unwrap();
        let p = pems(dir.path());
        let (_db, tls) = state(|c| {
            c.port = port;
            c.tls_cert = Some(p.cert.clone());
            c.tls_key = Some(p.key.clone());
        });
        let err = refused(tls).await;
        assert!(
            matches!(&err, BuilderError::Bind(_) | BuilderError::Serve(_)),
            "TLS: {err:?}"
        );
    }

    /// `serve_gateway` serving `state` until the shutdown is asked for.
    struct Serving {
        addr: SocketAddr,
        stop: tokio::sync::watch::Sender<bool>,
        server: tokio::task::JoinHandle<Result<(), BuilderError>>,
    }

    impl Serving {
        /// Returns once the listener accepts connections. It tries to
        /// connect until it can, yielding to the server task between
        /// attempts: no sleeping.
        async fn start(state: Arc<AppState>) -> Self {
            let addr: SocketAddr = state.config.bind_addr().parse().unwrap();
            let (stop, stopped) = tokio::sync::watch::channel(false);
            let mut server =
                tokio::spawn(serve_gateway(state, ShutdownSignal::from_receiver(stopped)));
            let listening = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while tokio::net::TcpStream::connect(addr).await.is_err() {
                    if server.is_finished() {
                        return false;
                    }
                    tokio::task::yield_now().await;
                }
                true
            })
            .await;
            match listening {
                Ok(true) => {}
                Ok(false) => panic!("serving ended before listening: {:?}", (&mut server).await),
                Err(_) => panic!("nothing listens on {addr}"),
            }
            Self { addr, stop, server }
        }

        /// Ask for the shutdown; serving ends without an error.
        async fn stop(self) {
            self.stop.send(true).unwrap();
            let served = tokio::time::timeout(SERVER_SHUTDOWN_GRACE * 2, self.server)
                .await
                .expect("serving stops")
                .unwrap();
            assert!(served.is_ok(), "{served:?}");
        }
    }

    /// A TLS connection to `addr`, with the server certificate checked
    /// against `server_ca`, presenting the certificate of `client` (or
    /// none) and offering the ALPN protocols `alpn`.
    async fn tls_connect(
        addr: SocketAddr,
        server_ca: &TestCa,
        client: Option<&Leaf>,
        alpn: &[&[u8]],
    ) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, String> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(server_ca.der().clone()).unwrap();
        let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
        let mut config = match client {
            Some(leaf) => builder
                .with_client_auth_cert(vec![leaf.der.clone()], leaf.key_der())
                .unwrap(),
            None => builder.with_no_client_auth(),
        };
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| format!("connect: {e}"))?;
        tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                tcp,
            )
            .await
            .map_err(|e| format!("handshake: {e}"))
    }

    /// The status of `GET path` over TLS to `addr`, with the server
    /// certificate checked against `server_ca`, presenting the certificate
    /// of `client` (or none); `Err` when no answer comes.
    async fn tls_get(
        addr: SocketAddr,
        server_ca: &TestCa,
        client: Option<&Leaf>,
        path: &str,
    ) -> Result<u16, String> {
        let mut tls = tls_connect(addr, server_ca, client, &[]).await?;
        let request =
            format!("GET {path} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n");
        tls.write_all(request.as_bytes())
            .await
            .map_err(|e| format!("write: {e}"))?;
        let mut answer = Vec::new();
        let mut chunk = [0u8; 4096];
        while !answer.windows(4).any(|w| w == b"\r\n\r\n") {
            match tls.read(&mut chunk).await {
                Ok(0) => return Err(format!("closed: {}", String::from_utf8_lossy(&answer))),
                Ok(n) => answer.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(format!("read: {e}")),
            }
        }
        let head = String::from_utf8_lossy(&answer);
        head.split(' ')
            .nth(1)
            .and_then(|status| status.parse().ok())
            .ok_or_else(|| head.to_string())
    }

    /// On the gateway's own mTLS listener (`UC_TLS_CLIENT_CA` and
    /// `UC_CA_REGISTRY_PATH`), the identity a request has is that of the
    /// client certificate it was sent with: the role the registry gives
    /// it, none for a certificate the registry does not name (API-key
    /// auth follows). A certificate of another CA, even naming a
    /// registered identity, gets no answer at all.
    #[tokio::test]
    async fn the_mtls_listener_takes_the_registered_certificates_of_its_ca() {
        let dir = tempfile::tempdir().unwrap();
        let p = pems(dir.path());
        let admin = cc::issue_leaf(&p.client_ca, "ops-laptop", |_| {});
        let sensor = cc::issue_leaf(&p.client_ca, "edge-7", |_| {});
        let unregistered = cc::issue_leaf(&p.client_ca, "stray-laptop", |_| {});
        let other_ca = cc::issue_leaf(&cc::test_ca("Client CA"), "ops-laptop", |_| {});
        let info = |leaf: &Leaf| ClientCertInfo::from_der(&leaf.der).unwrap();
        let registry = dir.path().join("registry.json");
        std::fs::write(
            &registry,
            format!(
                r#"{{"issued": {{{}, {}}}}}"#,
                cc::entry(&info(&admin), "admin", false, cc::FAR_FUTURE),
                cc::entry(&info(&sensor), "sensor", false, cc::FAR_FUTURE)
            ),
        )
        .unwrap();
        let (_db, state) = state(|c| {
            c.tls_cert = Some(p.cert.clone());
            c.tls_key = Some(p.key.clone());
            c.tls_client_ca = Some(p.client_ca_file.clone());
        });
        let served = Serving::start(h::with_cert_registry(state, &registry)).await;
        let get = |client| tls_get(served.addr, &p.server_ca, client, "/api/admin/users");

        assert_eq!(get(Some(&admin)).await, Ok(200), "the registered admin");
        assert_eq!(get(Some(&sensor)).await, Ok(403), "a registered sensor");
        assert_eq!(
            get(Some(&unregistered)).await,
            Ok(401),
            "a certificate the registry does not name"
        );
        assert_eq!(get(None).await, Ok(401), "no certificate");
        let answered = get(Some(&other_ca)).await;
        assert!(
            answered.is_err(),
            "a certificate of another CA got an answer: {answered:?}"
        );
        served.stop().await;
    }

    /// The TLS listener negotiates (ALPN) HTTP/2 with a client that offers
    /// it, as browsers do, and speaks it; HTTP/1.1 with one that offers
    /// only that.
    #[tokio::test]
    async fn the_tls_listener_serves_http2_to_a_client_that_offers_it() {
        let dir = tempfile::tempdir().unwrap();
        let p = pems(dir.path());
        let (_db, state) = state(|c| {
            c.tls_cert = Some(p.cert.clone());
            c.tls_key = Some(p.key.clone());
        });
        let served = Serving::start(state).await;

        let http1 = tls_connect(served.addr, &p.server_ca, None, &[b"http/1.1"])
            .await
            .unwrap();
        assert_eq!(http1.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
        drop(http1);

        let mut h2 = tls_connect(served.addr, &p.server_ca, None, &[b"h2", b"http/1.1"])
            .await
            .unwrap();
        assert_eq!(h2.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        // The client connection preface (RFC 9113 §3.4): the magic, then
        // an empty SETTINGS frame. An HTTP/2 server's first frame is its
        // own SETTINGS (type 0x4) on stream 0.
        h2.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0")
            .await
            .unwrap();
        let mut frame_header = [0u8; 9];
        h2.read_exact(&mut frame_header).await.unwrap();
        assert_eq!(
            (frame_header[3], &frame_header[5..]),
            (0x4, &[0u8; 4][..]),
            "no HTTP/2 SETTINGS frame: {:?}",
            String::from_utf8_lossy(&frame_header)
        );
        drop(h2);
        served.stop().await;
    }
}

/// The CORS policy of the app [`GatewayBuilder::run`] serves
/// ([`served_app`]): an origin gets `Access-Control-Allow-Origin` only when
/// `UC_CORS_ORIGINS` lists it exactly (empty entries are skipped), none
/// with the default (same origin only), and never credentials.
#[cfg(test)]
mod cors_tests {
    use super::*;
    use crate::ws::test_harness as h;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    fn app(dir: &tempfile::TempDir, cors_origins: &str) -> Router {
        let state = h::state(
            dir,
            crate::test_support::REFUSED_URL,
            &h::keys_file(&[]),
            None,
        );
        let Ok(mut state) = Arc::try_unwrap(state) else {
            unreachable!("fresh state has one owner")
        };
        state.config.cors_origins = cors_origins.to_string();
        let security = SecurityConfig {
            csp_mode: CspMode::Strict,
            hsts_enabled: false,
            tls_active: false,
        };
        served_app(Arc::new(state), security)
    }

    /// The `Access-Control-Allow-Origin` the app answers a preflight from
    /// `origin` and a cross-origin `GET /health` with (`None`: none); and
    /// neither allows credentials.
    async fn allowed(app: &Router, origin: &str) -> [Option<String>; 2] {
        let preflight = Request::options("/api/x")
            .header("origin", origin)
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "x-csrf-token")
            .body(Body::empty())
            .unwrap();
        let get = Request::get("/health")
            .header("origin", origin)
            .body(Body::empty())
            .unwrap();
        let mut answers = [None, None];
        for (answer, req) in answers.iter_mut().zip([preflight, get]) {
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{origin}");
            assert!(
                resp.headers()
                    .get("access-control-allow-credentials")
                    .is_none(),
                "{origin}: credentials allowed"
            );
            *answer = resp
                .headers()
                .get("access-control-allow-origin")
                .map(|v| v.to_str().unwrap().to_string());
        }
        answers
    }

    #[tokio::test]
    async fn only_the_listed_origins_are_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(&dir, " https://ops.example, ,https://noc.example:8443,");
        for origin in ["https://ops.example", "https://noc.example:8443"] {
            let expected = Some(origin.to_string());
            assert_eq!(
                allowed(&app, origin).await,
                [expected.clone(), expected],
                "{origin}"
            );
        }
        for origin in [
            "https://evil.example",
            "null",
            "http://ops.example",
            "https://noc.example",
            "https://ops.example.evil.example",
            "https://OPS.example",
        ] {
            assert_eq!(allowed(&app, origin).await, [None, None], "{origin}");
        }
    }

    #[tokio::test]
    async fn the_default_allows_no_other_origin() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(&dir, "");
        for origin in ["https://ops.example", "null", "http://127.0.0.1:8444"] {
            assert_eq!(allowed(&app, origin).await, [None, None], "{origin}");
        }
    }
}

/// [`GatewayBuilder::run`] from its start to its stop, as the gateway
/// binary runs it: what it serves is what its configuration asks for —
/// authentication on, with the API keys of the keys file it loaded,
/// sessions bound to their address and ended by the configured idle
/// timeout, CSRF protection as `BRIDGE_ENV` and `BRIDGE_CSRF` set it, the
/// injected licence resolver and feature-route table, the security
/// headers, the audit feed — and on SIGTERM it stops serving and returns,
/// having delivered the post-ingest hooks: those the last run saved, and
/// the one still queued when the signal came.
///
/// In child processes of their own, as `tests::sigterm_requests_the_shutdown`
/// does it: the signal goes to the whole process, and `run` sets the
/// process-wide audit sink, which `audit::store`'s tests set in the test
/// process.
#[cfg(all(test, unix))]
mod run_tests {
    use super::*;
    use crate::ingest::hooks::{HookItem, HookTarget, IngestHooks};
    use crate::ws::test_harness as h;
    use axum::body::Body;
    use axum::http::{HeaderMap, Request, StatusCode};
    use std::path::Path;
    use std::sync::Mutex;
    use std::time::Duration;

    /// Set in the child processes the tests below run their checks in.
    const CHILD_ENV: &str = "SIGRIFT_GATEWAY_RUN_TEST_CHILD";
    /// What a child prints once every check passed.
    const ALL_CHECKED: &str = "run test: every check passed";
    // `Fernet.generate_key()` output.
    const FERNET_KEY: &str = "gbhtBUbPkbiIqPMsYEdh1YUZAxWFy-1pp3gVY24zhzM=";
    /// The key of the keys file: an ANALYST key (operator tooling), which
    /// may submit a batch for any node.
    const ANALYST_KEY: &str = "sk-run-test-analyst";
    /// The node whose first post-ingest hook the stand-in bridge holds.
    const HELD_NODE: &str = "edge-3";
    static FEATURE_ROUTES: &[(&str, &str)] = &[
        ("/api/gated", "gated_feature"),
        ("/api/licensed", "licensed_feature"),
    ];

    /// A licence with `licensed_feature` and no other.
    struct LicensedFeatureOnly;

    impl crate::LicenseResolver for LicensedFeatureOnly {
        fn tier(&self) -> crate::LicenseTier {
            crate::LicenseTier::Professional
        }
        fn has_feature(&self, feature: &str) -> bool {
            feature == "licensed_feature"
        }
        fn node_limit(&self) -> Option<u32> {
            None
        }
        fn issuer(&self) -> &str {
            "run-test-issuer"
        }
    }

    /// Runs `child`, one of the ignored tests below, in a process of its
    /// own, and checks that it ran and passed.
    fn in_a_child_process(child: &str) {
        let ran = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("builder::run_tests::{child}"),
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&ran.stdout);
        assert!(
            ran.status.success(),
            "{}\n{stdout}\n{}",
            ran.status,
            String::from_utf8_lossy(&ran.stderr)
        );
        // Neither filtered out nor skipped: the child ran the test.
        assert!(stdout.contains("1 passed"), "{stdout}");
        assert!(stdout.contains(ALL_CHECKED), "{stdout}");
    }

    #[test]
    fn run_serves_its_configuration_and_stops_on_sigterm() {
        in_a_child_process("run_in_a_process_of_its_own");
    }

    #[test]
    fn run_turns_csrf_protection_on_as_bridge_env_and_bridge_csrf_say() {
        in_a_child_process("csrf_in_a_process_of_its_own");
    }

    /// What reached the bridge: `METHOD path` of every proxied request,
    /// and the node and `X-Rust-Proxy` of every post-ingest hook it took.
    #[derive(Default)]
    struct Seen {
        proxied: Vec<String>,
        hooks: Vec<(String, String)>,
        /// The first hook for [`HELD_NODE`] came, and was never answered.
        held: bool,
    }

    /// A stand-in bridge: `GET /api/version` answers (so `run` stops
    /// waiting at once), proxied requests are recorded and get 200, and so
    /// do hooks, except the first for [`HELD_NODE`]: that one gets no
    /// answer, and wakes `held`.
    struct Bridge {
        url: String,
        seen: Arc<Mutex<Seen>>,
        held: Arc<tokio::sync::Notify>,
    }

    async fn bridge() -> Bridge {
        let seen: Arc<Mutex<Seen>> = Arc::default();
        let held = Arc::new(tokio::sync::Notify::new());
        let (hooks, holding, proxied) = (Arc::clone(&seen), Arc::clone(&held), Arc::clone(&seen));
        let app = Router::new()
            .route("/api/version", get(|| async { r#"{"api_version": "1"}"# }))
            .route(
                ingest::hooks::HOOK_PATH,
                post(
                    move |headers: HeaderMap, payload: axum::Json<serde_json::Value>| {
                        let (hooks, holding) = (Arc::clone(&hooks), Arc::clone(&holding));
                        async move {
                            let node = payload["node_id"].as_str().unwrap_or_default();
                            let secret = headers
                                .get("x-rust-proxy")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or_default();
                            let hold = {
                                let mut seen = hooks.lock().unwrap();
                                let hold = node == HELD_NODE && !seen.held;
                                if hold {
                                    seen.held = true;
                                } else {
                                    seen.hooks.push((node.to_string(), secret.to_string()));
                                }
                                hold
                            };
                            if hold {
                                holding.notify_one();
                                std::future::pending::<()>().await;
                            }
                            StatusCode::OK
                        }
                    },
                ),
            )
            .fallback(move |req: Request<Body>| {
                let proxied = Arc::clone(&proxied);
                async move {
                    let request = format!("{} {}", req.method(), req.uri().path());
                    proxied.lock().unwrap().proxied.push(request);
                    "{}"
                }
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Bridge { url, seen, held }
    }

    /// The child's logs (INFO and up), and a wake-up on every write.
    #[derive(Clone)]
    struct Logs {
        text: Arc<Mutex<Vec<u8>>>,
        written: Arc<tokio::sync::watch::Sender<()>>,
    }

    impl Logs {
        /// The logs of this process from now on.
        fn capture() -> Self {
            let logs = Self {
                text: Arc::default(),
                written: Arc::new(tokio::sync::watch::channel(()).0),
            };
            let writer = logs.clone();
            tracing::subscriber::set_global_default(
                tracing_subscriber::fmt()
                    .with_writer(move || writer.clone())
                    .with_ansi(false)
                    .with_max_level(tracing::Level::INFO)
                    .finish(),
            )
            .unwrap();
            logs
        }

        fn text(&self) -> String {
            String::from_utf8_lossy(&self.text.lock().unwrap()).into_owned()
        }

        /// Returns once `gateways` plaintext listeners are bound.
        async fn listening(&self, gateways: usize) {
            let mut written = self.written.subscribe();
            let bound = |_: &()| self.text().matches("Listening (plaintext)").count() >= gateways;
            written.wait_for(bound).await.unwrap();
        }
    }

    impl std::io::Write for Logs {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.text.lock().unwrap().extend_from_slice(bytes);
            self.written.send_replace(());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Prints the gateway's logs when a check fails.
    struct ShowLogsOnPanic(Logs);

    impl Drop for ShowLogsOnPanic {
        fn drop(&mut self) {
            if std::thread::panicking() {
                eprintln!("--- gateway logs ---\n{}", self.0.text());
            }
        }
    }

    /// `n` distinct free loopback ports: each is held until all are found.
    fn free_ports(n: usize) -> Vec<u16> {
        let held: Vec<std::net::TcpListener> = (0..n)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        held.iter()
            .map(|listener| listener.local_addr().unwrap().port())
            .collect()
    }

    /// The state of a gateway writing in `dir` whose keys file holds
    /// `keys` (its database: the bridge's auth tables), and the
    /// configuration `run` starts it with: production, with every secret
    /// production needs, plaintext on loopback port `port`, `bridge` as
    /// its bridge, and no client-certificate auth.
    fn gateway(
        dir: &tempfile::TempDir,
        bridge: &Bridge,
        keys: &[String],
        port: u16,
    ) -> (Arc<AppState>, Config) {
        let state = h::state(dir, &bridge.url, &h::keys_file(keys), None);
        let mut config = state.config.clone();
        config.bridge_env = "production".to_string();
        config.keys_path = h::keys_path(dir);
        config.baseline_path = dir.path().join("baselines.json");
        config.hook_spool_path = Some(dir.path().join("hooks.spool"));
        config.mfa_key = FERNET_KEY.to_string();
        config.host = "127.0.0.1".to_string();
        config.port = port;
        config.tls_cert = None;
        config.tls_key = None;
        config.tls_client_ca = None;
        config.ca_registry_path = None;
        config.allow_no_auth = false;
        config.csrf_mode = String::new();
        config.session_binding = "ip".to_string();
        config.session_absolute_timeout_hours = None;
        config.session_idle_timeout_minutes = None;
        config.csp_mode = "strict".to_string();
        config.cors_origins = String::new();
        config.trusted_proxies = String::new();
        (state, config)
    }

    /// SIGTERM to this process, as `docker stop` sends it.
    fn sigterm() {
        let killed = std::process::Command::new("sh")
            .args(["-c", &format!("kill -TERM {}", std::process::id())])
            .status()
            .unwrap();
        assert!(killed.success());
    }

    /// What a last run saved at its shutdown, the bridge being down: a
    /// hook per node in `nodes`, in that order.
    async fn spool_of_a_last_run(path: &Path, nodes: &[&str]) {
        let hooks = IngestHooks::default();
        for node in nodes {
            let body = serde_json::json!({
                "node_id": node, "detections": [{"detection_id": format!("{node}-1")}],
                "decoded_messages": [], "received_at": "2026-11-06T00:00:00+00:00",
            });
            hooks.push(HookItem {
                node_id: node.to_string(),
                detections: 1,
                body: serde_json::to_vec(&body).unwrap().into(),
            });
        }
        let down = HookTarget::new(
            reqwest::Client::new(),
            crate::test_support::REFUSED_URL,
            h::PROXY_SECRET,
        );
        hooks.shutdown(&down, path, Duration::ZERO).await;
        assert!(path.exists(), "nothing was spooled");
    }

    /// The test proper of [`run_serves_its_configuration_and_stops_on_sigterm`],
    /// run only by it, in a process of its own (anywhere else it does
    /// nothing).
    #[ignore = "run_serves_its_configuration_and_stops_on_sigterm runs it in a child process"]
    #[tokio::test]
    async fn run_in_a_process_of_its_own() {
        use reqwest::Method;
        use tokio_tungstenite::tungstenite::{client::IntoClientRequest as _, Message};
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        let logs = Logs::capture();
        let _show = ShowLogsOnPanic(logs.clone());

        // The bridge's auth and detection tables, a keys file with an
        // ANALYST key, and sessions: two bound to the address the checks
        // connect from, one bound to another, and one idle for 10 minutes.
        let dir = tempfile::tempdir().unwrap();
        let bridge = bridge().await;
        let analyst = h::key_entry("ops-tool", ANALYST_KEY, "analyst", false);
        let (state, mut config) = gateway(&dir, &bridge, &[analyst], free_ports(1)[0]);
        let conn = state.db_pool.get().unwrap();
        conn.execute_batch(super::batch_csrf_tests::INGEST_SCHEMA)
            .unwrap();
        let alice = h::session_with(&state, "alice", "admin", "127.0.0.1", "");
        let dave = h::session_with(&state, "dave", "admin", "127.0.0.1", "");
        let roaming = h::session_with(&state, "bob", "admin", "10.9.9.9", "");
        let idle = h::session_with(&state, "carol", "admin", "127.0.0.1", "");
        let ten_minutes_ago = (chrono::Utc::now() - chrono::Duration::minutes(10))
            .format("%Y-%m-%dT%H:%M:%S+00:00")
            .to_string();
        conn.execute(
            "UPDATE sessions SET last_active = ?1 WHERE session_token = ?2",
            [
                ten_minutes_ago,
                crate::auth::password::hash_session_token(&idle),
            ],
        )
        .unwrap();
        drop((conn, state));
        config.session_idle_timeout_minutes = Some("5".to_string());
        let port = config.port;
        let spool = config.hook_spool_file();
        spool_of_a_last_run(&spool, &["edge-1", "edge-2"]).await;

        let mut gateway = tokio::spawn(
            GatewayBuilder::new(config, Arc::new(LicensedFeatureOnly))
                .with_feature_routes(FeatureRoutes(FEATURE_ROUTES))
                .run(),
        );
        tokio::time::timeout(Duration::from_secs(20), async {
            tokio::select! {
                () = logs.listening(1) => {}
                ended = &mut gateway => panic!("run ended before listening: {ended:?}"),
            }
        })
        .await
        .expect("the gateway listens");

        let base = format!("http://127.0.0.1:{port}");
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let send = |method: Method, path: &str, session: Option<&str>, csrf: Option<&str>| {
            let mut req = client.request(method, format!("{base}{path}"));
            if let Some(token) = session {
                req = req.bearer_auth(token);
            }
            if let Some(token) = csrf {
                req = req
                    .header("cookie", format!("csrf_token={token}"))
                    .header("x-csrf-token", token);
            }
            async move {
                let resp = req.send().await.unwrap();
                let status = resp.status().as_u16();
                let headers = resp.headers().clone();
                (status, headers, resp.text().await.unwrap())
            }
        };

        // Authentication is on (the keys file was loaded), and the
        // response carries the security headers (no HSTS without TLS).
        let (status, headers, body) = send(Method::GET, "/api/detections/recent", None, None).await;
        assert_eq!(status, 401, "a native route without credentials: {body}");
        assert_eq!(headers["x-frame-options"], "DENY");
        let csp = headers["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert!(headers.get("strict-transport-security").is_none());

        // The key of the keys file authenticates: the ANALYST key submits
        // a batch for a node, then reads it back.
        let batch = serde_json::json!({"node_id": HELD_NODE, "detections": [{
            "detection_id": "edge-3-1", "signal_class": "qpsk", "confidence": 0.9,
            "freq_hz": 433_920_000.0, "timestamp": chrono::Utc::now().to_rfc3339(),
        }]});
        let resp = client
            .post(format!("{base}/api/detections/batch"))
            .header("x-api-key", ANALYST_KEY)
            .json(&batch)
            .send()
            .await
            .unwrap();
        let (status, body) = (resp.status().as_u16(), resp.text().await.unwrap());
        assert_eq!(status, 200, "a batch sent with the ANALYST key: {body}");
        assert!(body.contains(r#""inserted":1"#), "{body}");
        let resp = client
            .get(format!("{base}/api/detections/recent?minutes=60"))
            .header("x-api-key", ANALYST_KEY)
            .send()
            .await
            .unwrap();
        let (status, body) = (resp.status().as_u16(), resp.text().await.unwrap());
        assert_eq!(status, 200, "{body}");
        assert!(body.contains(r#""detection_id":"edge-3-1""#), "{body}");

        // A session from the address it is bound to is accepted; from
        // another address (BRIDGE_SESSION_BINDING=ip) or idle for longer
        // than BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES (5, not the default
        // 30), it is not.
        let (status, _, body) = send(Method::GET, "/api/auth/me", Some(&alice), None).await;
        assert_eq!(status, 200, "{body}");
        assert!(body.contains(r#""username":"alice""#), "{body}");
        let (status, _, body) = send(Method::GET, "/api/auth/me", Some(&roaming), None).await;
        assert_eq!(status, 401, "a session bound to another address: {body}");
        let (status, _, body) = send(Method::GET, "/api/auth/me", Some(&idle), None).await;
        assert_eq!(status, 401, "a session idle for 10 minutes: {body}");

        // CSRF protection (production, BRIDGE_CSRF unset): a session's
        // POST needs the double-submit token.
        let (status, _, body) = send(Method::POST, "/api/reports", Some(&alice), None).await;
        assert_eq!(status, 403, "{body}");
        assert!(body.contains("CSRF token missing or mismatch"), "{body}");
        let (status, _, body) = send(Method::POST, "/api/reports", Some(&alice), Some("t-1")).await;
        assert_eq!(status, 200, "with the token: {body}");

        // The injected feature routes and licence: a gated path whose
        // feature the licence lacks is refused, one it has is proxied.
        let (status, _, body) = send(Method::GET, "/api/gated/report", Some(&alice), None).await;
        assert_eq!(status, 403, "{body}");
        assert!(body.contains("'gated_feature'"), "{body}");
        let (status, _, body) = send(Method::GET, "/api/licensed/report", Some(&alice), None).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            bridge.seen.lock().unwrap().proxied,
            ["POST /api/reports", "GET /api/licensed/report"]
        );

        // What the gateway audits reaches the audit feed.
        let mut feed = format!("ws://127.0.0.1:{port}/ws/audit")
            .into_client_request()
            .unwrap();
        let headers = feed.headers_mut();
        headers.insert("cookie", format!("session_token={alice}").parse().unwrap());
        headers.insert("origin", base.parse().unwrap());
        let (mut feed, _) = tokio_tungstenite::connect_async(feed)
            .await
            .expect("the audit feed opens");
        let (status, _, body) =
            send(Method::POST, "/api/auth/logout", Some(&dave), Some("t-2")).await;
        assert_eq!(status, 200, "{body}");
        loop {
            match h::next_msg(&mut feed, 5).await {
                Some(Message::Text(entry)) if entry.contains(r#""action":"user_logout""#) => break,
                Some(_) => continue,
                None => panic!("the logout's audit entry did not reach /ws/audit"),
            }
        }
        drop(feed);
        drop(client);

        // The batch's post-ingest hook is being delivered: the bridge has
        // it, and does not answer.
        tokio::time::timeout(Duration::from_secs(10), bridge.held.notified())
            .await
            .expect("the batch's post-ingest hook reaches the bridge");

        // SIGTERM (`docker stop`): serving stops and `run` returns.
        sigterm();
        let ran = tokio::time::timeout(Duration::from_secs(20), gateway)
            .await
            .expect("run returns after SIGTERM")
            .expect("run did not panic");
        assert!(ran.is_ok(), "{ran:?}");

        // The hooks the last run saved were delivered, and the batch's,
        // interrupted by the shutdown, was delivered once serving stopped;
        // all with the proxy secret, and nothing is left to replay.
        let secret = h::PROXY_SECRET.to_string();
        assert_eq!(
            bridge.seen.lock().unwrap().hooks,
            [
                ("edge-1".to_string(), secret.clone()),
                ("edge-2".to_string(), secret.clone()),
                (HELD_NODE.to_string(), secret),
            ]
        );
        assert!(!spool.exists(), "the spool is still there");
        let logged = logs.text();
        for line in [
            "issuer=run-test-issuer",
            "Queued the post-ingest hooks saved at the last shutdown",
            "Shutdown requested",
            "Gateway stopped",
        ] {
            assert!(logged.contains(line), "{line:?} was not logged");
        }
        assert!(
            !logged.contains("UC_ALLOW_NO_AUTH"),
            "authentication was off"
        );
        println!("{ALL_CHECKED}");
    }

    /// The test proper of [`run_turns_csrf_protection_on_as_bridge_env_and_bridge_csrf_say`],
    /// run only by it, in a process of its own (anywhere else it does
    /// nothing): a gateway per case, all stopped by one SIGTERM. Without
    /// `BRIDGE_CSRF`, only `BRIDGE_ENV=development`, `dev` and `test` leave
    /// CSRF protection off; `BRIDGE_CSRF=enabled` turns it on in any
    /// environment, and `disabled` turns it off outside production
    /// (production refuses to start with it:
    /// `production_refuses_csrf_protection_turned_off`).
    #[ignore = "run_turns_csrf_protection_on_as_bridge_env_and_bridge_csrf_say runs it in a child process"]
    #[tokio::test]
    async fn csrf_in_a_process_of_its_own() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        let logs = Logs::capture();
        let _show = ShowLogsOnPanic(logs.clone());
        let bridge = bridge().await;
        // (BRIDGE_ENV, BRIDGE_CSRF, whether a session's POST needs the token)
        let cases = [
            ("production", "", true),
            ("development", "", false),
            ("dev", "", false),
            ("test", "", false),
            ("development", "enabled", true),
            ("production", "enabled", true),
            ("staging", "disabled", false),
        ];
        let mut gateways = Vec::new();
        for ((bridge_env, csrf, _), port) in cases.into_iter().zip(free_ports(cases.len())) {
            let dir = tempfile::tempdir().unwrap();
            let (state, mut config) = gateway(&dir, &bridge, &[], port);
            let session = h::session_with(&state, "alice", "admin", "127.0.0.1", "");
            drop(state);
            config.bridge_env = bridge_env.to_string();
            config.csrf_mode = csrf.to_string();
            let url = format!("http://127.0.0.1:{}/api/reports", config.port);
            let resolver: SharedLicenseResolver = Arc::new(crate::NullLicenseResolver);
            let run = tokio::spawn(GatewayBuilder::new(config, resolver).run());
            gateways.push((dir, url, session, run));
        }
        tokio::time::timeout(Duration::from_secs(20), async {
            let runs = gateways.iter_mut().map(|(_, _, _, run)| run);
            tokio::select! {
                () = logs.listening(cases.len()) => {}
                (ended, i, _) = futures_util::future::select_all(runs) => {
                    panic!("{}: run ended before listening: {ended:?}", gateways[i].1)
                }
            }
        })
        .await
        .expect("every gateway listens");

        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        for ((bridge_env, csrf, protected), (_, url, session, _)) in cases.iter().zip(&gateways) {
            let resp = client.post(url).bearer_auth(session).send().await.unwrap();
            let (status, body) = (resp.status().as_u16(), resp.text().await.unwrap());
            let case = format!("BRIDGE_ENV={bridge_env} BRIDGE_CSRF={csrf:?}");
            if *protected {
                assert_eq!(status, 403, "{case}: {body}");
                assert!(
                    body.contains("CSRF token missing or mismatch"),
                    "{case}: {body}"
                );
            } else {
                assert_eq!(status, 200, "{case}: {body}");
            }
        }
        drop(client);

        sigterm();
        for (_, url, _, run) in gateways {
            let ran = tokio::time::timeout(Duration::from_secs(20), run)
                .await
                .expect("run returns after SIGTERM")
                .expect("run did not panic");
            assert!(ran.is_ok(), "{url}: {ran:?}");
        }
        println!("{ALL_CHECKED}");
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use crate::ingest::hooks::IngestHooks;
    use crate::test_support::{logs_of, REFUSED_URL};
    use axum::http::{HeaderMap, StatusCode};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    /// Run `future` to completion on a runtime of this thread, so that
    /// [`logs_of`] sees everything it logs.
    fn on_this_thread<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    /// A pool that never hands out a connection.
    fn unavailable_pool(dir: &tempfile::TempDir) -> db::pool::DbPool {
        let manager =
            db::manager::SqliteConnectionManager::file(dir.path().join("missing").join("x.db"))
                .with_flags(rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE);
        r2d2::Pool::builder()
            .max_size(1)
            .min_idle(Some(0))
            .connection_timeout(Duration::from_millis(50))
            .build_unchecked(manager)
    }

    /// A bridge that answers its first readiness probe 503 (still
    /// starting) is probed again, and is ready once it answers 2xx; every
    /// probe carries the proxy secret, and the not-ready answer is logged
    /// with its status.
    #[test]
    fn a_bridge_that_answers_but_is_not_ready_is_probed_again() {
        let secrets: Arc<Mutex<Vec<String>>> = Arc::default();
        let record = Arc::clone(&secrets);
        let (ready, logs) = logs_of(|| {
            on_this_thread(async move {
                let probes = Arc::new(AtomicUsize::new(0));
                let bridge = Router::new().route(
                    "/api/version",
                    get(move |headers: HeaderMap| {
                        let (probes, record) = (Arc::clone(&probes), Arc::clone(&record));
                        async move {
                            record
                                .lock()
                                .unwrap()
                                .push(headers["x-rust-proxy"].to_str().unwrap().to_string());
                            if probes.fetch_add(1, Ordering::SeqCst) == 0 {
                                StatusCode::SERVICE_UNAVAILABLE
                            } else {
                                StatusCode::OK
                            }
                        }
                    }),
                );
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let url = format!("http://{}", listener.local_addr().unwrap());
                tokio::spawn(async move { axum::serve(listener, bridge).await.unwrap() });
                probe_python(
                    &reqwest::Client::new(),
                    &url,
                    "probe-secret",
                    5,
                    Duration::ZERO,
                )
                .await
            })
        });
        assert_eq!(ready, Readiness::Ready { attempt: 2 });
        assert_eq!(*secrets.lock().unwrap(), ["probe-secret", "probe-secret"]);
        assert!(logs.contains("Python responded but not ready"), "{logs}");
        assert!(logs.contains("503"), "{logs}");
    }

    /// A bridge that cannot be reached is not ready after the given number
    /// of probes, and the wait is logged every fifth probe, not at each.
    #[test]
    fn an_unreachable_bridge_is_not_ready_and_the_wait_is_logged_every_fifth_probe() {
        let (ready, logs) = logs_of(|| {
            on_this_thread(probe_python(
                &reqwest::Client::new(),
                REFUSED_URL,
                "probe-secret",
                5,
                Duration::ZERO,
            ))
        });
        assert_eq!(ready, Readiness::NotReady);
        assert_eq!(
            logs.matches("Waiting for Python backend").count(),
            1,
            "{logs}"
        );
        assert!(logs.contains("attempt=5"), "{logs}");
    }

    /// A TLS listener whose certificate or key path is missing is refused
    /// (it never falls back to plaintext), with the setting it lacks.
    #[tokio::test]
    async fn a_tls_listener_without_its_certificate_or_key_path_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::test_support::app_state(&dir);
        let (_stop, stopped) = tokio::sync::watch::channel(false);
        let pem = dir.path().join("server.pem");
        for (cert, key, missing) in [
            (None, Some(pem.clone()), "TLS cert path required"),
            (Some(pem.clone()), None, "TLS key path required"),
        ] {
            let mut config = state.config.clone();
            config.tls_cert = cert;
            config.tls_key = key;
            let refused = serve_tls(
                Router::new(),
                "127.0.0.1:0",
                &config,
                ShutdownSignal::from_receiver(stopped.clone()),
            )
            .await
            .unwrap_err();
            assert!(
                matches!(&refused, BuilderError::Tls(m) if m == missing),
                "{refused:?}"
            );
            assert_eq!(refused.to_string(), format!("tls: {missing}"));
        }
    }

    /// Without a database connection the startup database steps stop the
    /// gateway with a connection-pool error, before checking anything.
    #[test]
    fn startup_stops_when_the_database_cannot_be_reached() {
        let dir = tempfile::tempdir().unwrap();
        let pool = unavailable_pool(&dir);
        for refused in [
            refuse_newer_schema(&pool).unwrap_err(),
            prepare_database(&pool).unwrap_err(),
        ] {
            assert!(matches!(refused, BuilderError::DbPool(_)), "{refused:?}");
            assert!(refused.to_string().starts_with("db pool: "), "{refused}");
        }
        assert!(!dir.path().join("missing").exists());
    }

    /// Startup names exactly the bridge tables that are missing, and says
    /// nothing about tables once the bridge has created them all; the
    /// tables the gateway manages itself are there either way.
    #[test]
    fn startup_warns_about_exactly_the_missing_bridge_tables() {
        let dir = tempfile::tempdir().unwrap();
        let pool = db::pool::create_pool(&dir.path().join("detections.db"), 2, 5_000).unwrap();
        let bridge_tables = [
            "detections",
            "rf_anomalies",
            "fhss_events",
            "users",
            "sessions",
            "audit_log",
            "rate_limit_login",
            "account_lockout",
            "mfa_tokens",
            "mfa_backup_codes",
            "totp_replay_cache",
            "tenant_settings",
        ];
        let conn = pool.get().unwrap();
        for table in bridge_tables {
            conn.execute_batch(&format!("CREATE TABLE {table} (id INTEGER PRIMARY KEY)"))
                .unwrap();
        }
        drop(conn);
        let ((), logs) = logs_of(|| prepare_database(&pool).unwrap());
        assert!(logs.contains("Missing database tables"), "{logs}");
        assert!(logs.contains("tables=[\"oidc_states\"]"), "{logs}");

        pool.get()
            .unwrap()
            .execute_batch("CREATE TABLE oidc_states (id INTEGER PRIMARY KEY)")
            .unwrap();
        let ((), logs) = logs_of(|| prepare_database(&pool).unwrap());
        assert!(!logs.contains("Missing database tables"), "{logs}");
        let conn = pool.get().unwrap();
        for table in ["password_history", "nodes", "pending_commands"] {
            let exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "{table}");
        }
        let scope: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name = 'scope'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(scope, 1);
    }

    /// What startup replays from the hook spool is reported: lines that
    /// are not hook payloads are skipped and counted (and the file is
    /// deleted all the same), a spool longer than allowed is cut with a
    /// warning after the hooks that fit, and a spool that cannot be read
    /// is an error that queues nothing and leaves it in place.
    #[test]
    fn startup_reports_what_it_replays_from_the_hook_spool() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("hooks.spool");

        std::fs::write(&spool, b"not a payload\n{\"node_id\": 7}\n").unwrap();
        let hooks = Arc::new(IngestHooks::default());
        let ((), logs) = logs_of(|| on_this_thread(restore_hook_spool(&hooks, &spool)));
        for expected in [
            "Queued the post-ingest hooks saved at the last shutdown",
            "batches=0",
            "skipped_lines=2",
        ] {
            assert!(logs.contains(expected), "{expected:?} missing: {logs}");
        }
        assert!(!spool.exists());
        assert_eq!(hooks.stats().queued_batches, 0);

        let line = |node: &str| {
            format!("{{\"node_id\":\"{node}\",\"detections\":[{{\"detection_id\":\"d\"}}]}}\n")
        };
        let first = line("edge-1");
        std::fs::write(&spool, format!("{first}{}", line("edge-2"))).unwrap();
        let hooks = Arc::new(IngestHooks::default().with_spool_limit(first.len()));
        let ((), logs) = logs_of(|| on_this_thread(restore_hook_spool(&hooks, &spool)));
        assert!(logs.contains("batches=1"), "{logs}");
        assert!(
            logs.contains("spool was larger than allowed; the rest was discarded"),
            "{logs}"
        );
        assert_eq!(hooks.stats().queued_batches, 1);

        let unreadable = dir.path().join("spool-directory");
        std::fs::create_dir(&unreadable).unwrap();
        let hooks = Arc::new(IngestHooks::default());
        let ((), logs) = logs_of(|| on_this_thread(restore_hook_spool(&hooks, &unreadable)));
        assert!(
            logs.contains("Cannot replay the post-ingest hooks saved at the last shutdown"),
            "{logs}"
        );
        assert_eq!(hooks.stats().queued_batches, 0);
        assert!(unreadable.is_dir());
    }

    use clap::Parser as _;

    // `Fernet.generate_key()` output.
    const FERNET_KEY: &str = "gbhtBUbPkbiIqPMsYEdh1YUZAxWFy-1pp3gVY24zhzM=";

    /// Outside production a `BRIDGE_CSRF` the bridge reads as "off" is
    /// allowed, with one warning that says what this gateway makes of it,
    /// which is not always what the bridge does: where CSRF protection is
    /// on by default (`staging`), any value but an exact `disabled` keeps
    /// the gateway's protection on while the bridge's is off; `disabled`,
    /// or any such value where protection is off by default (development),
    /// turns the gateway's off too, and the warning says production refuses
    /// that. `enabled` says nothing.
    #[test]
    fn outside_production_a_csrf_setting_read_as_off_is_warned_about_as_applied() {
        let kept_on = "This gateway reads it as unset and keeps CSRF protection on \
                       (BRIDGE_ENV=staging)";
        let off = "Allowed outside production: CSRF protection is OFF";
        for (env, value, protected, said) in [
            ("staging", "off", true, kept_on),
            ("staging", "disabled", false, off),
            ("development", "off", false, off),
        ] {
            let mut c = Config::try_parse_from(["sigrift-gateway"]).unwrap();
            c.bridge_env = env.into();
            c.csrf_mode = value.into();
            c.proxy_secret = "a-strong-proxy-secret".into();
            c.mfa_key = FERNET_KEY.into();
            let (checked, logs) = logs_of(|| check_startup_secrets(&c, |_: &str| None));
            assert!(checked.is_ok(), "{env} {value}: {checked:?}");
            assert_eq!(csrf_enabled(&c), protected, "{env} {value}");
            let warned: Vec<&str> = logs
                .lines()
                .filter(|l| l.contains(" WARN ") && l.contains("BRIDGE_CSRF"))
                .collect();
            assert_eq!(warned.len(), 1, "{env} {value}: {logs}");
            let quoted = format!("BRIDGE_CSRF={value:?}");
            for named in [said, quoted.as_str()] {
                assert!(
                    warned[0].contains(named),
                    "{env} {value}: {named:?} missing: {logs}"
                );
            }
            assert_eq!(
                warned[0].contains("production refuses to start"),
                !protected,
                "{env} {value}: {logs}"
            );
        }

        let mut c = Config::try_parse_from(["sigrift-gateway"]).unwrap();
        c.bridge_env = "staging".into();
        c.csrf_mode = "enabled".into();
        c.proxy_secret = "a-strong-proxy-secret".into();
        c.mfa_key = FERNET_KEY.into();
        let (checked, logs) = logs_of(|| check_startup_secrets(&c, |_: &str| None));
        assert!(checked.is_ok(), "{checked:?}");
        assert!(csrf_enabled(&c));
        assert!(!logs.contains("BRIDGE_CSRF"), "{logs}");
    }

    /// `run` says, before it waits for the bridge, which settings leave the
    /// gateway less protected than its defaults: API-key authentication off
    /// (`UC_ALLOW_NO_AUTH` without a keys file), unbound node keys allowed
    /// to submit for any node, and a client-cert registry it cannot read
    /// (which then authorises no certificate). A baselines file it cannot
    /// load is warned about and left as it is. The startup line names the
    /// bridge, the environment and the licence. The bridge's answer to the
    /// readiness probe (which carries the proxy secret) is followed by the
    /// schema check: this bridge migrated the database past this build, so
    /// `run` refuses before it listens.
    #[test]
    fn run_warns_about_each_weakened_setting_before_it_waits_for_the_bridge() {
        use crate::LicenseResolver as _;
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::try_parse_from(["sigrift-gateway"]).unwrap();
        config.bridge_env = "development".into();
        config.allow_no_auth = true;
        config.keys_path = dir.path().join("no-keys.json");
        config.db_path = dir.path().join("detections.db");
        config.baseline_path = dir.path().join("baselines.json");
        config.hook_spool_path = Some(dir.path().join("hooks.spool"));
        let registry = dir.path().join("ca-registry.json");
        config.ca_registry_path = Some(registry.clone());
        config.allow_unbound_node_keys = "1".into();
        config.proxy_secret = "a-strong-proxy-secret".into();
        config.mfa_key = FERNET_KEY.into();
        config.host = "127.0.0.1".into();
        config.port = 0;
        std::fs::write(&config.baseline_path, b"not a baselines file").unwrap();
        std::fs::write(&registry, b"{not json").unwrap();
        let keys_path = config.keys_path.display().to_string();
        let baseline_path = config.baseline_path.clone();
        let newer = db::schema::NEWEST_KNOWN_BRIDGE_MIGRATION + 1;

        let probes: Arc<Mutex<Vec<String>>> = Arc::default();
        let record = Arc::clone(&probes);
        let db_path = config.db_path.clone();
        let (ran, logs) = logs_of(|| {
            on_this_thread(async move {
                // A bridge that migrates the database past this build
                // before it answers, as a newer bridge does.
                let bridge = Router::new().route(
                    "/api/version",
                    get(move |headers: HeaderMap| {
                        let (record, db_path) = (Arc::clone(&record), db_path.clone());
                        async move {
                            record
                                .lock()
                                .unwrap()
                                .push(headers["x-rust-proxy"].to_str().unwrap().to_string());
                            rusqlite::Connection::open(&db_path)
                                .unwrap()
                                .execute_batch(&format!(
                                    "CREATE TABLE IF NOT EXISTS schema_version (
                                         version INTEGER PRIMARY KEY,
                                         description TEXT NOT NULL,
                                         applied_at TEXT NOT NULL);
                                     INSERT OR IGNORE INTO schema_version
                                         VALUES ({newer}, 'newer', datetime('now'));"
                                ))
                                .unwrap();
                            r#"{"api_version": "1"}"#
                        }
                    }),
                );
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                config.python_url = format!("http://{}", listener.local_addr().unwrap());
                tokio::spawn(async move { axum::serve(listener, bridge).await.unwrap() });
                let resolver: SharedLicenseResolver = Arc::new(crate::NullLicenseResolver);
                // Only bounds a hang: the bridge answers the first probe.
                tokio::time::timeout(
                    Duration::from_secs(60),
                    GatewayBuilder::new(config, resolver).run(),
                )
                .await
            })
        });
        let refused = ran
            .expect("the gateway refused instead of hanging")
            .expect_err("a newer schema is refused");
        assert!(
            matches!(&refused, BuilderError::Schema(m) if m.contains(&format!("[{newer}]"))),
            "{refused:?}"
        );
        // Every probe carried the proxy secret (a machine slow enough for
        // the first one to time out sends it again).
        let probes = probes.lock().unwrap();
        assert!(!probes.is_empty());
        assert!(
            probes.iter().all(|p| p == "a-strong-proxy-secret"),
            "{probes:?}"
        );
        assert!(!logs.contains("Listening"), "{logs}");
        assert_eq!(
            std::fs::read(&baseline_path).unwrap(),
            b"not a baselines file"
        );

        /// The line of `logs` holding `needle`, which must come before the
        /// bridge answered the probe.
        fn line_of<'a>(logs: &'a str, needle: &str) -> &'a str {
            let ready = logs
                .find("Python backend ready")
                .unwrap_or_else(|| panic!("the probe was not answered: {logs}"));
            let line = logs
                .lines()
                .find(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("{needle:?} missing: {logs}"));
            assert!(
                logs.find(line).unwrap() < ready,
                "{needle:?} after the wait: {logs}"
            );
            line
        }
        let null = crate::NullLicenseResolver;
        let tier = format!("tier={}", null.tier().as_str());
        let issuer = format!("issuer={}", null.issuer());
        let started = line_of(&logs, "Starting SigRift gateway");
        for named in [
            "python_url=http://127.0.0.1:",
            "env=development",
            "tls=false",
            tier.as_str(),
            issuer.as_str(),
        ] {
            assert!(started.contains(named), "{named:?} missing: {started}");
        }
        assert!(line_of(&logs, "Failed to load baselines").contains(" WARN "));
        let no_auth = line_of(&logs, "API-key authentication is DISABLED");
        assert!(no_auth.contains(" WARN "), "{no_auth}");
        assert!(no_auth.contains(&keys_path), "{no_auth}");
        let configured = line_of(&logs, "Client-cert registry configured");
        assert!(
            configured.contains(&registry.display().to_string()),
            "{configured}"
        );
        let unreadable = line_of(
            &logs,
            "CA registry is unreadable; it authorises no certificate",
        );
        assert!(unreadable.contains(" WARN "), "{unreadable}");
        assert!(line_of(&logs, "Loaded CA cert registry").contains("count=0"));
        let unbound = line_of(&logs, "BRIDGE_ALLOW_UNBOUND_NODE_KEYS is set");
        assert!(unbound.contains(" WARN "), "{unbound}");
        assert!(unbound.contains("ANY node"), "{unbound}");
    }
}
