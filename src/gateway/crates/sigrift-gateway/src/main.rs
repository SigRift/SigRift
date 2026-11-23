//! sigrift-gateway — SigRift community gateway binary.
//!
//! Thin wrapper around `sigrift-gateway-core`. Injects
//! [`sigrift_gateway_core::NullLicenseResolver`] so the core runs at
//! community tier with every feature available. This binary contains no
//! licence-verification code, no signing keys, and no tier-enforcement
//! logic; those live in the enterprise edition shipped separately.

use std::sync::Arc;

use clap::Parser;
use tracing::error;

use sigrift_gateway_core::{
    config::Config, GatewayBuilder, NullLicenseResolver, SharedLicenseResolver,
};

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let config = Config::parse();

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.log_level));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .init();

    let resolver: SharedLicenseResolver = Arc::new(NullLicenseResolver);

    if let Err(e) = GatewayBuilder::new(config, resolver).run().await {
        error!(error = %e, "Gateway terminated with error");
        std::process::exit(1);
    }
}
