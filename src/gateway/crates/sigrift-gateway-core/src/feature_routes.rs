//! Path-prefix → required-feature mapping used by the proxy fallback.
//!
//! The table is intentionally **not defined in core**. Community builds
//! inject [`FeatureRoutes::EMPTY`], so the public source contains no
//! list of paywalled path prefixes. HS256-era monorepo binaries and
//! enterprise (sentinel) binaries inject their own table via
//! [`crate::builder::GatewayBuilder::with_feature_routes`].

/// A list of `(path_prefix, required_feature)` pairs. Lookup uses
/// longest-prefix semantics via [`FeatureRoutes::required_feature`].
#[derive(Debug, Clone, Copy)]
pub struct FeatureRoutes(pub &'static [(&'static str, &'static str)]);

impl FeatureRoutes {
    /// No path prefixes are gated. Community builds use this.
    pub const EMPTY: FeatureRoutes = FeatureRoutes(&[]);

    /// If `path` matches any of the configured prefixes, return the
    /// required feature name. First-match wins; callers typically order
    /// the table from most specific prefix to least specific, but the
    /// tables shipped today are disjoint so ordering is irrelevant.
    pub fn required_feature(&self, path: &str) -> Option<&'static str> {
        self.0
            .iter()
            .find(|(prefix, _)| path.starts_with(prefix))
            .map(|(_, feature)| *feature)
    }

    /// Number of configured path prefixes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if no path prefixes are gated.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for FeatureRoutes {
    fn default() -> Self {
        FeatureRoutes::EMPTY
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_table_gates_nothing() {
        assert!(FeatureRoutes::EMPTY.is_empty());
        assert_eq!(FeatureRoutes::EMPTY.required_feature("/api/anything"), None);
    }

    #[test]
    fn prefix_match_returns_feature() {
        static ROUTES: &[(&str, &str)] = &[("/api/demo", "demo_feature")];
        let t = FeatureRoutes(ROUTES);
        assert_eq!(t.required_feature("/api/demo"), Some("demo_feature"));
        assert_eq!(t.required_feature("/api/demo/sub"), Some("demo_feature"));
        assert_eq!(t.required_feature("/api/other"), None);
    }

    #[test]
    fn default_is_empty() {
        let t: FeatureRoutes = Default::default();
        assert!(t.is_empty());
    }
}
