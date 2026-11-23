//! SigRift gateway core library.
//!
//! Shared logic between the community binary (`sigrift-gateway`) and the
//! enterprise binary (`sigrift-gateway-sentinel`, maintained in a separate
//! repository). This crate contains no licence verification, no crypto keys,
//! and no tier-enforcement code — licensing decisions are delegated to an
//! injected [`LicenseResolver`].

pub mod analysis;
pub mod audit;
pub mod auth;
pub mod builder;
pub mod cache;
pub mod class_map;
pub mod config;
pub mod db;
pub mod feature_routes;
pub mod ingest;
pub mod license;
pub mod middleware;
pub mod models;
pub mod proxy;
pub mod query;
pub mod scoring;
pub mod storage;
#[cfg(test)]
pub(crate) mod test_support;
pub mod ws;

pub use builder::{BuilderError, GatewayBuilder};
pub use feature_routes::FeatureRoutes;
pub use license::{LicenseResolver, LicenseTier, NullLicenseResolver, SharedLicenseResolver};

use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;

use analysis::correlator::NodeCorrelator;
use config::Config;
use db::pool::DbPool;
use scoring::baseline::BaselineManager;
use scoring::weights::ScoringWeights;

/// Shared application state.
pub struct AppState {
    pub config: Config,
    pub db_pool: DbPool,
    pub baseline_manager: RwLock<BaselineManager>,
    pub scoring_weights: ScoringWeights,
    pub correlator: RwLock<NodeCorrelator>,
    pub detection_tx: broadcast::Sender<String>,
    pub anomaly_tx: broadcast::Sender<String>,
    pub key_store: Option<auth::api_key::KeyStore>,
    /// True if auth is configured (keys file path exists). When true but key_store
    /// is None (unreadable file), all requests are denied (fail-closed).
    pub auth_enabled: bool,
    /// Client-certificate identity registry (PKI mTLS auth). `Some` when
    /// `UC_CA_REGISTRY_PATH` is configured; resolves verified client
    /// certs to roles. `None` disables client-cert auth.
    pub cert_registry: Option<Arc<auth::client_cert::CertRegistry>>,
    /// HTTP client for proxying requests to the Python backend.
    pub proxy_client: reqwest::Client,
    /// Auth configuration (session binding, CSRF, rate limits, trusted proxies).
    /// Wrapped in `tokio::sync::RwLock` for hot-reload via admin API.
    pub auth_config: Arc<tokio::sync::RwLock<middleware::auth::AuthConfig>>,
    /// Broadcast channel for real-time audit events.
    pub audit_tx: broadcast::Sender<String>,
    /// Injected licensing decisions. Community builds inject
    /// [`NullLicenseResolver`]; legacy/enterprise builds inject a resolver
    /// backed by HS256 or hybrid-PQC verification. Core never constructs a
    /// real resolver itself.
    pub license_resolver: SharedLicenseResolver,
    /// Path prefixes that require licensed features before the proxy
    /// forwards to Python. Community builds inject
    /// [`FeatureRoutes::EMPTY`]; legacy/enterprise builds inject a
    /// populated table.
    pub feature_routes: FeatureRoutes,
    /// Queue of the bridge's post-ingest work for ingested batches
    /// (contract K8); a background task delivers it.
    pub ingest_hooks: Arc<ingest::hooks::IngestHooks>,
}
