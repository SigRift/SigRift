//! Licence-resolution trait and the no-op resolver used by the community
//! binary.
//!
//! The core library never verifies a signature, loads a key, or enforces a
//! tier. All of that lives in the binary that wires a concrete resolver
//! into [`crate::builder::GatewayBuilder`]. The community binary injects
//! [`NullLicenseResolver`]; the sentinel binary injects a resolver backed by
//! hybrid Ed25519 + ML-DSA-65 signature verification.

use std::sync::Arc;

/// Licence tier. Schema enum shared across editions so headers
/// (`X-License-Tier`), logs, and telemetry use the same vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LicenseTier {
    Community,
    Professional,
    Enterprise,
    Government,
}

impl LicenseTier {
    /// Lowercase string form used in HTTP headers and logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            LicenseTier::Community => "community",
            LicenseTier::Professional => "professional",
            LicenseTier::Enterprise => "enterprise",
            LicenseTier::Government => "government",
        }
    }

    /// Parse the tier string as emitted by upstream licence files. Accepts
    /// the canonical lowercase names and numeric tiers (`0`..`3`). Unknown
    /// strings fall back to [`LicenseTier::Community`] — fail-closed rather
    /// than fail-open for unrecognised enterprise tiers.
    pub fn from_str_lenient(s: &str) -> LicenseTier {
        match s.to_lowercase().as_str() {
            "community" | "0" => LicenseTier::Community,
            "professional" | "1" => LicenseTier::Professional,
            "enterprise" | "2" => LicenseTier::Enterprise,
            "government" | "3" => LicenseTier::Government,
            _ => LicenseTier::Community,
        }
    }
}

/// Answers licensing questions for the running gateway.
///
/// Implementations must be cheap to call — the auth middleware consults the
/// resolver on every request. Cache any expensive state at construction
/// time.
pub trait LicenseResolver: Send + Sync {
    /// The tier the current licence grants.
    fn tier(&self) -> LicenseTier;

    /// Whether a named feature is available. Feature names match the schema
    /// in `FEATURE_TIER` on the Python side.
    fn has_feature(&self, feature: &str) -> bool;

    /// Hard ceiling on the number of registered edge nodes, if any.
    fn node_limit(&self) -> Option<u32>;

    /// Human-readable issuer string for logs and support bundles.
    fn issuer(&self) -> &str;

    /// Ad-hoc features granted beyond the tier defaults. Used by the proxy
    /// handler to populate the `X-License-Features` header for the Python
    /// backend. Default is empty — community (NullLicenseResolver) has no
    /// ad-hoc extras.
    fn features(&self) -> Vec<String> {
        Vec::new()
    }
}

/// A resolver that grants every feature, reports `Community` tier, and
/// imposes no node limit. The community binary injects this; it has no
/// dependency on a licence file, signing key, or HSM.
pub struct NullLicenseResolver;

impl LicenseResolver for NullLicenseResolver {
    fn tier(&self) -> LicenseTier {
        LicenseTier::Community
    }

    fn has_feature(&self, _feature: &str) -> bool {
        true
    }

    fn node_limit(&self) -> Option<u32> {
        None
    }

    fn issuer(&self) -> &str {
        "sigrift-open (unlicensed community build)"
    }
}

/// Convenience alias — resolvers are usually shared via `Arc` so they can
/// be cloned into middleware, background tasks, and long-lived state.
pub type SharedLicenseResolver = Arc<dyn LicenseResolver>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_resolver_grants_everything() {
        let r = NullLicenseResolver;
        assert_eq!(r.tier(), LicenseTier::Community);
        assert!(r.has_feature("tdoa"));
        assert!(r.has_feature("fingerprint"));
        assert!(r.has_feature("arbitrary-feature-name"));
        assert!(r.node_limit().is_none());
    }

    #[test]
    fn tier_as_str_is_lowercase_header_form() {
        assert_eq!(LicenseTier::Community.as_str(), "community");
        assert_eq!(LicenseTier::Professional.as_str(), "professional");
        assert_eq!(LicenseTier::Enterprise.as_str(), "enterprise");
        assert_eq!(LicenseTier::Government.as_str(), "government");
    }

    #[test]
    fn resolver_is_object_safe() {
        let _boxed: Box<dyn LicenseResolver> = Box::new(NullLicenseResolver);
        let _shared: SharedLicenseResolver = Arc::new(NullLicenseResolver);
    }
}
