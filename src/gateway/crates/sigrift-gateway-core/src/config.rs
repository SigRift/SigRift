//! Configuration via CLI args and environment variables.

use clap::Parser;
use std::path::PathBuf;

use tracing::warn;

use crate::storage::security_state::MAX_LOCKOUT_WINDOW_SECS;
use crate::storage::sessions::{SessionConfig, MAX_ABSOLUTE_TIMEOUT_HOURS};

/// Proxy secrets the bridge never accepts (its `INSECURE_PROXY_SECRETS`):
/// none, and the old public default.
pub const INSECURE_PROXY_SECRETS: [&str; 2] = ["", "uppercrust-internal"];

/// File name of the post-ingest hook spool in the gateway's data directory.
pub const HOOK_SPOOL_FILE_NAME: &str = "gateway-post-ingest-hooks.spool";

#[derive(Parser, Debug, Clone)]
#[command(
    name = "sigrift-gateway",
    about = "Security gateway + detection ingest for The Bridge"
)]
pub struct Config {
    // -----------------------------------------------------------------------
    // Network
    // -----------------------------------------------------------------------
    /// Host to bind the external (public) listener
    #[arg(long, env = "UC_HOST", default_value = "0.0.0.0")]
    pub host: String,

    /// Port for the external (public) listener
    #[arg(long, env = "UC_PORT", default_value_t = 8444)]
    pub port: u16,

    /// TLS certificate file (PEM). If set, enables TLS on the external port.
    #[arg(long, env = "UC_TLS_CERT")]
    pub tls_cert: Option<PathBuf>,

    /// TLS private key file (PEM)
    #[arg(long, env = "UC_TLS_KEY")]
    pub tls_key: Option<PathBuf>,

    /// CA certificate (PEM) used to verify client certificates (mTLS).
    /// When set, a client presenting a cert must have it chain to this
    /// CA; clients with no cert still fall through to API-key auth.
    #[arg(long, env = "UC_TLS_CLIENT_CA")]
    pub tls_client_ca: Option<PathBuf>,

    /// Path to the bridge CA's `registry.json`, mapping verified
    /// client-cert identities to roles. Required for client-cert auth
    /// to resolve to anything; without it, presented certs are ignored.
    #[arg(long, env = "UC_CA_REGISTRY_PATH")]
    pub ca_registry_path: Option<PathBuf>,

    // -----------------------------------------------------------------------
    // Python backend proxy
    // -----------------------------------------------------------------------
    /// URL of the Python (SigRift bridge) backend. Rust proxies non-native routes here.
    #[arg(long, env = "UC_PYTHON_URL", default_value = "http://127.0.0.1:8001")]
    pub python_url: String,

    /// Timeout (seconds) for proxy requests to Python
    #[arg(long, env = "UC_PROXY_TIMEOUT", default_value_t = 30)]
    pub proxy_timeout: u64,

    /// Header injected into proxied requests so Python can verify the request
    /// came through Rust. Python rejects requests without this header when
    /// BRIDGE_REQUIRE_PROXY=true. The bridge's gateway-only API (node-key
    /// binding, post-ingest hooks) refuses every call without a usable one
    /// (see [`Config::proxy_secret_usable`]).
    #[arg(long, env = "UC_PROXY_SECRET", default_value = "")]
    pub proxy_secret: String,

    // -----------------------------------------------------------------------
    // Database
    // -----------------------------------------------------------------------
    /// Path to the shared SQLite database
    #[arg(
        long,
        env = "UC_DB_PATH",
        default_value = "../src/sigrift/bridge/data/detections.db"
    )]
    pub db_path: PathBuf,

    /// Path to the API keys JSON file
    #[arg(
        long,
        env = "UC_KEYS_PATH",
        default_value = "../src/sigrift/bridge/data/keys.json"
    )]
    pub keys_path: PathBuf,

    /// Path to baseline persistence file
    #[arg(long, env = "UC_BASELINE_PATH", default_value = "data/baselines.json")]
    pub baseline_path: PathBuf,

    /// Where post-ingest hooks still queued at shutdown are saved, and
    /// replayed from at the next start (contract K8b). Default:
    /// `gateway-post-ingest-hooks.spool` next to the baselines file
    /// (`UC_BASELINE_PATH`). See [`Config::hook_spool_file`].
    #[arg(long, env = "UC_HOOK_SPOOL_PATH")]
    pub hook_spool_path: Option<PathBuf>,

    /// SQLite connection pool size
    #[arg(long, env = "UC_POOL_SIZE", default_value_t = 8)]
    pub pool_size: u32,

    /// SQLite busy timeout in milliseconds (shared with Python's WAL)
    #[arg(long, env = "UC_SQLITE_BUSY_TIMEOUT", default_value_t = 30_000)]
    pub sqlite_busy_timeout: u32,

    // -----------------------------------------------------------------------
    // Request limits
    // -----------------------------------------------------------------------
    /// Maximum request body size in bytes (before decompression)
    #[arg(long, env = "UC_MAX_BODY_SIZE", default_value_t = 10_485_760)]
    pub max_body_size: usize,

    /// Maximum decompressed body size (gzip bomb protection)
    #[arg(long, env = "UC_MAX_DECOMPRESSED_SIZE", default_value_t = 52_428_800)]
    pub max_decompressed_size: usize,

    // -----------------------------------------------------------------------
    // Scoring
    // -----------------------------------------------------------------------
    /// EWMA alpha for baselines
    #[arg(long, env = "UC_BASELINE_ALPHA", default_value_t = 0.01)]
    pub baseline_alpha: f64,

    /// Number of active edge nodes (for correlation scoring)
    #[arg(long, env = "UC_ACTIVE_NODES", default_value_t = 5)]
    pub active_nodes: usize,

    // -----------------------------------------------------------------------
    // Security headers
    // -----------------------------------------------------------------------
    /// Bridge environment (production, development, test). Controls HSTS and CSP strictness.
    #[arg(long, env = "BRIDGE_ENV", default_value = "production")]
    pub bridge_env: String,

    /// Content-Security-Policy mode: "strict" (default), "report-only", "disabled"
    #[arg(long, env = "UC_CSP_MODE", default_value = "strict")]
    pub csp_mode: String,

    /// Enable HSTS header (only when TLS is active)
    #[arg(long, env = "UC_HSTS", default_value_t = true)]
    pub hsts_enabled: bool,

    /// Trusted proxy IPs and CIDR networks, IPv4 or IPv6 (comma-separated).
    /// `X-Forwarded-For` is honoured only when the direct peer is one of
    /// them; the client IP is then the rightmost entry that is not a
    /// trusted proxy. Invalid entries are logged and ignored.
    #[arg(long, env = "UC_TRUSTED_PROXIES", default_value = "127.0.0.1,::1")]
    pub trusted_proxies: String,

    // -----------------------------------------------------------------------
    // Session & Auth
    // -----------------------------------------------------------------------
    /// Absolute session timeout in hours (default 24, at most 10000000).
    /// Read as the bridge reads it: an empty value, one below 1 or one
    /// that is not an integer gives the default, a larger one 10000000,
    /// with a warning (none for an empty value). One written with digits
    /// other than 0-9 stops the gateway from starting
    #[arg(long, env = "BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS")]
    pub session_absolute_timeout_hours: Option<String>,

    /// Session idle timeout in minutes (default 30, per NIST 800-63B).
    /// Read as the bridge reads it: an empty value, one below 1 or one
    /// that is not an integer gives the default, with a warning (none for
    /// an empty value). One written with digits other than 0-9 stops the
    /// gateway from starting
    #[arg(long, env = "BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES")]
    pub session_idle_timeout_minutes: Option<String>,

    /// Login rate limit: max attempts per IP within the window, at least 1.
    /// 0 stops the gateway from starting: it would refuse every login,
    /// administrators' included
    #[arg(
        long,
        env = "UC_RATE_LIMIT_MAX",
        default_value_t = 5,
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    pub rate_limit_max: u32,

    /// Login rate limit: sliding window in seconds, at least 1. 0 stops the
    /// gateway from starting: it would count no attempt, so no limit
    #[arg(
        long,
        env = "UC_RATE_LIMIT_WINDOW",
        default_value_t = 60,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub rate_limit_window_secs: u64,

    /// Account lockout: max failed attempts per account within the window,
    /// at least 1. 0 stops the gateway from starting: it would lock every
    /// account, administrators' included
    #[arg(
        long,
        env = "UC_LOCKOUT_MAX",
        default_value_t = 10,
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    pub lockout_max: u32,

    /// Account lockout: window in seconds, 1 to 86400 (24 h). A longer
    /// window stops the gateway from starting: the bridge prunes the shared
    /// `account_lockout` table after 24 h, so it would not hold
    /// ([`MAX_LOCKOUT_WINDOW_SECS`]). So does 0, which would count no
    /// failure, so no lockout
    #[arg(
        long,
        env = "UC_LOCKOUT_WINDOW",
        default_value_t = 1800,
        value_parser = clap::value_parser!(u64).range(1..=MAX_LOCKOUT_WINDOW_SECS)
    )]
    pub lockout_window_secs: u64,

    /// Session binding mode: strict (IP+UA), ip (IP only), warn (log), none
    #[arg(long, env = "BRIDGE_SESSION_BINDING", default_value = "ip")]
    pub session_binding: String,

    /// `1` / `true` / `yes` / `on`: leave unbound node API keys unbound —
    /// they may then submit batches for any node — instead of binding each
    /// to the first node it submits for (the bridge's setting of the same
    /// name; set it on both). See [`Config::unbound_node_keys_allowed`].
    #[arg(long, env = "BRIDGE_ALLOW_UNBOUND_NODE_KEYS", default_value = "")]
    pub allow_unbound_node_keys: String,

    /// Allow the gateway to start with NO API-key store loaded, disabling
    /// API-key authentication entirely. DANGEROUS: every auth-gated route
    /// is served unauthenticated. Intended only for local development and
    /// tests — in production a missing or unreadable keys file is a fatal
    /// startup error unless this is explicitly set.
    #[arg(long, env = "UC_ALLOW_NO_AUTH", default_value_t = false)]
    pub allow_no_auth: bool,

    /// Maximum concurrent sessions per user; a login beyond it evicts the
    /// user's oldest sessions. 0 = unlimited.
    #[arg(long, env = "UC_MAX_SESSIONS_PER_USER", default_value_t = 50)]
    pub max_sessions_per_user: u32,

    /// Number of previous passwords to check for reuse (0 = disabled; the
    /// current password is checked too, and a forced change refuses it
    /// even at 0)
    #[arg(long, env = "UC_PASSWORD_HISTORY_COUNT", default_value_t = 5)]
    pub password_history_count: usize,

    /// CSRF mode override: enabled, disabled (empty = auto based on
    /// bridge_env). Production (`BRIDGE_ENV` production or prod) refuses to
    /// start with any value but empty or `enabled`.
    #[arg(long, env = "BRIDGE_CSRF", default_value = "")]
    pub csrf_mode: String,

    /// Fernet key for MFA TOTP secret encryption (32-byte URL-safe base64)
    #[arg(long, env = "BRIDGE_MFA_KEY", default_value = "")]
    pub mfa_key: String,

    /// HMAC key for audit chain (SHA-256 of this value used as HMAC secret)
    #[arg(long, env = "BRIDGE_AUDIT_KEY", default_value = "")]
    pub audit_key: String,

    /// Path to the license JWT file
    #[arg(long, env = "UC_LICENSE_PATH", default_value = "data/license.jwt")]
    pub license_path: PathBuf,

    /// HMAC secret for license JWT verification (raw string, not hex)
    #[arg(long, env = "UC_LICENSE_SECRET", default_value = "")]
    pub license_secret: String,

    /// Days before audit entries are eligible for archiving
    #[arg(long, env = "UC_AUDIT_ARCHIVE_DAYS", default_value_t = 90)]
    pub audit_archive_days: u32,

    // -----------------------------------------------------------------------
    // Operational
    // -----------------------------------------------------------------------
    /// Log level
    #[arg(long, env = "UC_LOG_LEVEL", default_value = "info")]
    pub log_level: String,

    /// Allowed CORS origins (comma-separated). Empty = same-origin only.
    #[arg(long, env = "UC_CORS_ORIGINS", default_value = "")]
    pub cors_origins: String,
}

impl Config {
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// True when `BRIDGE_ENV` is `production` or `prod`. See
    /// [`is_production_env`].
    pub fn is_production(&self) -> bool {
        is_production_env(&self.bridge_env)
    }

    /// The session timeouts, from `BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS`
    /// and `BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES` (or their options), read
    /// as the bridge reads them (see [`read_session_timeout`]). Logs a
    /// warning for every value it does not use as given. The `Err` says
    /// why the gateway must not start: a value the bridge may read as a
    /// timeout that the gateway cannot read.
    pub fn session_config(&self) -> Result<SessionConfig, String> {
        let defaults = SessionConfig::default();
        Ok(SessionConfig {
            absolute_timeout_hours: read_session_timeout(
                "BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS",
                "--session-absolute-timeout-hours",
                self.session_absolute_timeout_hours.as_deref(),
                defaults.absolute_timeout_hours,
                MAX_ABSOLUTE_TIMEOUT_HOURS,
            )?,
            idle_timeout_minutes: read_session_timeout(
                "BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES",
                "--session-idle-timeout-minutes",
                self.session_idle_timeout_minutes.as_deref(),
                defaults.idle_timeout_minutes,
                i64::MAX,
            )?,
        })
    }

    pub fn tls_enabled(&self) -> bool {
        self.tls_cert.is_some() && self.tls_key.is_some()
    }

    /// True when `UC_PROXY_SECRET` is a secret the bridge accepts: not
    /// empty and not the old public default `uppercrust-internal` (the
    /// bridge's `INSECURE_PROXY_SECRETS`). Without one, the bridge refuses
    /// its gateway-only API, so the gateway neither asks it to bind node
    /// keys (K7) nor sends it post-ingest hooks (K8) — contract K10.
    pub fn proxy_secret_usable(&self) -> bool {
        !INSECURE_PROXY_SECRETS.contains(&self.proxy_secret.as_str())
    }

    /// The post-ingest hook spool file: `UC_HOOK_SPOOL_PATH`, or
    /// `gateway-post-ingest-hooks.spool` in the directory of the baselines
    /// file (the gateway's data directory).
    pub fn hook_spool_file(&self) -> PathBuf {
        match &self.hook_spool_path {
            Some(path) => path.clone(),
            None => self
                .baseline_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new(""))
                .join(HOOK_SPOOL_FILE_NAME),
        }
    }

    /// True when `BRIDGE_ALLOW_UNBOUND_NODE_KEYS` restores unbound node
    /// keys: `1`, `true`, `yes` or `on`, case-insensitive (the values the
    /// bridge's `allow_unbound_node_keys()` accepts).
    pub fn unbound_node_keys_allowed(&self) -> bool {
        matches!(
            self.allow_unbound_node_keys
                .trim()
                .to_ascii_lowercase()
                .as_str(),
            "1" | "true" | "yes" | "on"
        )
    }
}

/// True when a `BRIDGE_ENV` value means production: `production` or
/// `prod`, case-insensitive and trimmed — matching Python's
/// `_is_production()` in `bridge/storage/users.py`.
pub fn is_production_env(bridge_env: &str) -> bool {
    matches!(
        bridge_env.trim().to_ascii_lowercase().as_str(),
        "production" | "prod"
    )
}

/// Read a session timeout setting (`variable`, or its command-line
/// `option`) as the bridge's `UserStore._get_absolute_timeout_hours` and
/// `_get_idle_timeout_minutes` (bridge/storage/users.py) read theirs:
///
/// - Unset, or empty once trimmed: `default`, silently.
/// - Otherwise it is trimmed as `str.strip()` trims and read as `int()`
///   reads a string: an optional `+` or `-`, then digits, with single
///   underscores allowed between them (`" +1_000 "` is 1000). A value of
///   at least 1 is used.
/// - Below 1, not an integer, or with more digits than `int()` reads
///   ([`PYTHON_INT_MAX_STR_DIGITS`]): `default`. The bridge warns only
///   for the last two; the gateway warns for all three, since a value
///   below 1 that it used would end every session at once.
/// - Above `max`: `max`, with a warning. The bridge has no ceiling: a
///   huge absolute timeout makes its `create_session` raise
///   `OverflowError` (from about 7e7 hours, an expiry past year 9999),
///   so its logins fail with 500. The gateway's ceiling is the one
///   `PUT /api/admin/settings/security` enforces.
///
/// One deliberate difference: only ASCII digits are read. `int()` also
/// reads other decimal digits (`"١٢"`, `"１２"`), so the bridge may use
/// such a value while the gateway cannot. Its default could then keep a
/// session the bridge has ended (`"１５"` idle minutes against the
/// default 30), so the gateway refuses to start instead: the `Err` says
/// why. A value with any non-ASCII number character where a digit goes
/// is refused this way, also one `int()` does not read (`"²"`, which the
/// bridge reads as its default), since telling those apart needs the
/// Unicode tables of the bridge's Python version.
fn read_session_timeout(
    variable: &str,
    option: &str,
    raw: Option<&str>,
    default: i64,
    max: i64,
) -> Result<i64, String> {
    let Some(raw) = raw else {
        return Ok(default);
    };
    let value = raw.trim_matches(is_python_whitespace);
    if value.is_empty() {
        return Ok(default);
    }
    match parse_python_int(value) {
        Err(NotAPythonInt::NotAnInteger) => {
            warn!(
                "{variable} ({option}) is {raw:?}, which is not an integer: \
                 using the default {default}"
            );
            Ok(default)
        }
        Err(NotAPythonInt::TooManyDigits(digits)) => {
            warn!(
                "{variable} ({option}) has {digits} digits, more than the \
                 {PYTHON_INT_MAX_STR_DIGITS} the bridge's int() reads: using the default {default}"
            );
            Ok(default)
        }
        Err(NotAPythonInt::NonAsciiDigits) => Err(format!(
            "{variable} ({option}) is {raw:?}, which is written with digits other than \
             0-9. The bridge may read it as a timeout (Python's int() reads other \
             decimal digits) and the gateway does not, so it cannot apply the same \
             timeout as the bridge: write the value with the digits 0-9"
        )),
        Ok(v) if v < 1 => {
            warn!(
                "{variable} ({option}) is {raw:?}, which is below 1 and would end \
                 every session at once: using the default {default}"
            );
            Ok(default)
        }
        // As the bridge does (UserStore._absolute_timeout_hours): a value
        // above the maximum is ignored, not capped.
        Ok(v) if v > max => {
            warn!(
                "{variable} ({option}) is {raw:?}, which is above the maximum {max}: \
                 using the default {default}"
            );
            Ok(default)
        }
        Ok(v) => Ok(v),
    }
}

/// The whitespace Python's `str.strip()` removes (`str.isspace()`):
/// Unicode `White_Space`, which is [`char::is_whitespace`], and the
/// separators U+001C to U+001F.
fn is_python_whitespace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// The most digits Python's `int()` reads from a string: the default of
/// `sys.get_int_max_str_digits()` in Python 3.11 and later (the bridge's
/// `requires-python`). It raises `ValueError` for a longer one, so the
/// bridge then uses its default. Every digit counts, leading zeros too;
/// the sign and underscores do not. The gateway does not follow a limit
/// changed with `PYTHONINTMAXSTRDIGITS` or `-X int_max_str_digits` on the
/// bridge.
const PYTHON_INT_MAX_STR_DIGITS: usize = 4300;

/// Why [`parse_python_int`] did not read a string.
#[derive(Debug, PartialEq, Eq)]
enum NotAPythonInt {
    /// `int()` refuses it, and would even if its non-ASCII number
    /// characters were digits.
    NotAnInteger,
    /// An integer of more than [`PYTHON_INT_MAX_STR_DIGITS`] digits (this
    /// many), which `int()` refuses.
    TooManyDigits(usize),
    /// An integer if its non-ASCII number characters are decimal digits,
    /// which `int()` reads and the gateway does not.
    NonAsciiDigits,
}

/// Read `s` as Python's `int(s)` reads an already trimmed string: an
/// optional `+` or `-`, then ASCII digits with single underscores allowed
/// between them, at most [`PYTHON_INT_MAX_STR_DIGITS`] of them. Python's
/// integers are unbounded, so a value outside the i64 range saturates.
fn parse_python_int(s: &str) -> Result<i64, NotAPythonInt> {
    let (negative, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    if digits.split('_').any(|group| group.is_empty()) {
        return Err(NotAPythonInt::NotAnInteger);
    }
    let mut value: i64 = 0;
    let mut count = 0;
    let mut non_ascii = false;
    for c in digits.chars().filter(|&c| c != '_') {
        count += 1;
        let digit = match c.to_digit(10) {
            Some(digit) => i64::from(digit),
            None if c.is_numeric() => {
                non_ascii = true;
                continue;
            }
            None => return Err(NotAPythonInt::NotAnInteger),
        };
        value = if negative {
            value.saturating_mul(10).saturating_sub(digit)
        } else {
            value.saturating_mul(10).saturating_add(digit)
        };
    }
    // `int()` refuses this many digits whichever they are, so the bridge
    // uses its default for certain.
    if count > PYTHON_INT_MAX_STR_DIGITS {
        return Err(NotAPythonInt::TooManyDigits(count));
    }
    if non_ascii {
        return Err(NotAPythonInt::NonAsciiDigits);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unbound_node_keys_setting_matches_the_bridge() {
        let mut c = Config::try_parse_from(["sigrift-gateway"]).unwrap();
        for (raw, allowed) in [
            ("", false),
            ("0", false),
            ("false", false),
            ("off", false),
            ("1", true),
            ("TRUE", true),
            (" yes ", true),
            ("on", true),
        ] {
            c.allow_unbound_node_keys = raw.to_string();
            assert_eq!(c.unbound_node_keys_allowed(), allowed, "{raw:?}");
        }
    }

    /// Regression: any `UC_LOCKOUT_WINDOW` was accepted, but the bridge's
    /// periodic cleanup deleted the `account_lockout` rows older than its
    /// own 1800-second window, so a longer window unlocked accounts at the
    /// bridge's next cleanup. The bridge now keeps them for
    /// [`MAX_LOCKOUT_WINDOW_SECS`], and the gateway refuses to start with a
    /// longer window.
    #[test]
    fn a_lockout_window_longer_than_the_bridge_keeps_failures_is_refused() {
        let parse = |window: u64| {
            Config::try_parse_from([
                "sigrift-gateway".to_string(),
                format!("--lockout-window-secs={window}"),
            ])
        };
        for window in [1, 1800, 86_400] {
            let c = parse(window).unwrap_or_else(|e| panic!("{window}: {e}"));
            assert_eq!(c.lockout_window_secs, window);
        }
        assert_eq!(MAX_LOCKOUT_WINDOW_SECS, 86_400);
        for window in [MAX_LOCKOUT_WINDOW_SECS + 1, 604_800, u64::MAX] {
            let err = parse(window).expect_err(&window.to_string()).to_string();
            assert!(err.contains("lockout-window-secs"), "{window}: {err}");
        }
        let c = Config::try_parse_from(["sigrift-gateway"]).unwrap();
        assert_eq!(c.lockout_window_secs, 1800);
    }

    /// Regression: a login limit of 0 was accepted. A count of 0
    /// (`UC_RATE_LIMIT_MAX`, `UC_LOCKOUT_MAX`) refuses every login,
    /// administrators' included, since an attempt is allowed only below
    /// the count; a window of 0 (`UC_RATE_LIMIT_WINDOW`,
    /// `UC_LOCKOUT_WINDOW`) counts no attempt, so it turns the rate limit
    /// or the lockout off. Each stops the gateway from starting with a
    /// message naming the option, as `PUT /api/admin/settings/security`
    /// refuses the same values; 1 is applied.
    #[test]
    fn a_login_limit_of_zero_is_refused() {
        let options = [
            ("rate-limit-max", "UC_RATE_LIMIT_MAX"),
            ("rate-limit-window-secs", "UC_RATE_LIMIT_WINDOW"),
            ("lockout-max", "UC_LOCKOUT_MAX"),
            ("lockout-window-secs", "UC_LOCKOUT_WINDOW"),
        ];
        let parse = |option: &str, value: &str| {
            Config::try_parse_from(["sigrift-gateway".to_string(), format!("--{option}={value}")])
        };
        for (option, env) in options {
            for value in ["0", "-1"] {
                let err = parse(option, value)
                    .expect_err(&format!("{env}={value}"))
                    .to_string();
                assert!(err.contains(option), "{env}={value}: {err}");
            }
            let c = parse(option, "1").unwrap_or_else(|e| panic!("{env}=1: {e}"));
            let applied = (
                c.rate_limit_max,
                c.rate_limit_window_secs,
                c.lockout_max,
                c.lockout_window_secs,
            );
            let expected = match option {
                "rate-limit-max" => (1, 60, 10, 1800),
                "rate-limit-window-secs" => (5, 1, 10, 1800),
                "lockout-max" => (5, 60, 1, 1800),
                _ => (5, 60, 10, 1),
            };
            assert_eq!(applied, expected, "{env}=1");
        }
        let c = Config::try_parse_from(["sigrift-gateway".to_string()]).unwrap();
        assert_eq!(
            (
                c.rate_limit_max,
                c.rate_limit_window_secs,
                c.lockout_max,
                c.lockout_window_secs
            ),
            (5, 60, 10, 1800)
        );
        let c = Config::try_parse_from([
            "sigrift-gateway",
            "--rate-limit-max=4294967295",
            "--lockout-max=4294967295",
        ])
        .unwrap();
        assert_eq!((c.rate_limit_max, c.lockout_max), (u32::MAX, u32::MAX));
    }

    #[test]
    fn proxy_secret_usable_matches_the_bridge() {
        let mut c = Config::try_parse_from(["sigrift-gateway"]).unwrap();
        for (secret, usable) in [
            ("", false),
            ("uppercrust-internal", false),
            ("a-strong-secret", true),
            (" ", true),
        ] {
            c.proxy_secret = secret.to_string();
            assert_eq!(c.proxy_secret_usable(), usable, "{secret:?}");
        }
    }

    #[test]
    fn the_hook_spool_lives_next_to_the_baselines_by_default() {
        let mut c = Config::try_parse_from(["sigrift-gateway"]).unwrap();
        c.baseline_path = PathBuf::from("/app/data/baselines.json");
        c.hook_spool_path = None;
        assert_eq!(
            c.hook_spool_file(),
            PathBuf::from("/app/data/gateway-post-ingest-hooks.spool")
        );
        c.baseline_path = PathBuf::from("baselines.json");
        assert_eq!(
            c.hook_spool_file(),
            PathBuf::from("gateway-post-ingest-hooks.spool")
        );
        c.hook_spool_path = Some(PathBuf::from("/var/lib/gw/hooks.spool"));
        assert_eq!(
            c.hook_spool_file(),
            PathBuf::from("/var/lib/gw/hooks.spool")
        );
    }

    /// The session timeouts the gateway runs with for these command-line
    /// arguments, or why it refuses to start. The `BRIDGE_SESSION_*`
    /// variables reach the same fields through clap
    /// (`session_timeouts_are_read_from_the_bridge_variables`), so this is
    /// also what each variable value gives.
    fn session_config_result(args: &[String]) -> Result<SessionConfig, String> {
        let argv = std::iter::once("sigrift-gateway".to_string()).chain(args.iter().cloned());
        Config::try_parse_from(argv)
            .unwrap_or_else(|e| panic!("clap refused {args:?}: {e}"))
            .session_config()
    }

    /// The session timeouts the gateway runs with for these command-line
    /// arguments (see [`session_config_result`]).
    fn session_config_of(args: &[String]) -> SessionConfig {
        session_config_result(args)
            .unwrap_or_else(|e| panic!("the gateway refused to start with {args:?}: {e}"))
    }

    /// Both session timeout options set to `raw`.
    fn both_timeouts(raw: &str) -> [String; 2] {
        [
            format!("--session-absolute-timeout-hours={raw}"),
            format!("--session-idle-timeout-minutes={raw}"),
        ]
    }

    /// Regression: `BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS` and
    /// `BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES` (and their options) were
    /// plain i64s. A value below 1 was used as it was, so every session
    /// expired as it was created, or was idle at its next request. A value
    /// Python's `int()` reads but Rust's i64 parser does not (`" 5 "`,
    /// `"+3"`, `"1_000"`), or one nobody reads (`"abc"`, `""`), stopped
    /// the gateway from starting. The bridge's `_get_absolute_timeout_hours`
    /// and `_get_idle_timeout_minutes` (bridge/storage/users.py) use the
    /// first and fall back to their defaults (24 hours, 30 minutes) for
    /// the rest, and so does the gateway now.
    #[test]
    fn session_timeouts_are_read_as_the_bridge_reads_them() {
        // `None`: the bridge uses its default.
        let cases: &[(&str, Option<i64>)] = &[
            ("", None),
            (" \t ", None),
            ("1", Some(1)),
            ("24", Some(24)),
            ("90", Some(90)),
            // str.strip() whitespace, which includes U+001C..U+001F.
            (" 5 ", Some(5)),
            ("\t7\n", Some(7)),
            ("\u{a0}8\u{3000}", Some(8)),
            ("\u{1c}9\u{1f}", Some(9)),
            // int() syntax.
            ("+3", Some(3)),
            ("007", Some(7)),
            ("1_000", Some(1000)),
            ("1_0_0", Some(100)),
            // Not above 0.
            ("0", None),
            ("-0", None),
            ("+0", None),
            ("0_0", None),
            ("-1", None),
            ("-24", None),
            ("-99999999999999999999999", None),
            // Not an int() literal.
            ("abc", None),
            ("1.5", None),
            ("1e3", None),
            ("0x10", None),
            ("1__0", None),
            ("_1", None),
            ("1_", None),
            ("+_1", None),
            ("+", None),
            ("-", None),
            ("++1", None),
            ("+-1", None),
            ("- 5", None),
            ("1 2", None),
            ("\u{200b}5", None),
            // Other decimal digits in a value that is not an integer
            // anyway (a non-ASCII digit alone is refused, see
            // a_timeout_written_with_other_digits_stops_the_gateway).
            ("\u{ff11}a", None),
            ("\u{ff11}.5", None),
            ("\u{ff11}__5", None),
            ("\u{200b}\u{ff11}", None),
        ];
        for &(raw, read) in cases {
            let c = session_config_of(&both_timeouts(raw));
            assert_eq!(c.absolute_timeout_hours, read.unwrap_or(24), "{raw:?}");
            assert_eq!(c.idle_timeout_minutes, read.unwrap_or(30), "{raw:?}");
        }
        let c = session_config_of(&[]);
        assert_eq!((c.absolute_timeout_hours, c.idle_timeout_minutes), (24, 30));
    }

    /// Regression: Python's `int()` refuses a string of more than 4300
    /// digits (`sys.get_int_max_str_digits()`), so the bridge uses its
    /// default for one, while the gateway read it, saturated. An idle
    /// timeout of 4301 ones was then no idle limit on the gateway and 30
    /// minutes on the bridge, an absolute one 10000000 hours against 24.
    /// Every digit counts, leading zeros too; the sign, underscores and
    /// surrounding whitespace do not.
    #[test]
    fn a_timeout_with_more_digits_than_int_reads_gives_the_default() {
        assert_eq!(PYTHON_INT_MAX_STR_DIGITS, 4300);
        let ones = |n: usize| "1".repeat(n);
        let underscored = |n: usize| vec!["1"; n].join("_");
        let zeros = |n: usize| "0".repeat(n);
        // Saturated past i64: above the absolute maximum, so the default
        // (as on the bridge), and no idle limit.
        let huge = Some((SessionConfig::default().absolute_timeout_hours, i64::MAX));
        // `None`: the bridge uses its default.
        let cases: Vec<(String, Option<(i64, i64)>)> = vec![
            (ones(4300), huge),
            (format!("+{}", ones(4300)), huge),
            (format!(" {} ", ones(4300)), huge),
            (underscored(4300), huge),
            (format!("{}5", zeros(4299)), Some((5, 5))),
            (ones(4301), None),
            (format!("+{}", ones(4301)), None),
            (format!("-{}", ones(4301)), None),
            (underscored(4301), None),
            (format!("{}5", zeros(4300)), None),
            (zeros(4301), None),
            (format!("{}x", ones(4301)), None),
            // int() refuses so many digits whichever they are, so this is
            // the bridge's default too, not a value to refuse.
            ("\u{ff11}".repeat(4301), None),
        ];
        for (raw, read) in cases {
            let c = session_config_of(&both_timeouts(&raw));
            let read = read.unwrap_or((24, 30));
            assert_eq!(
                (c.absolute_timeout_hours, c.idle_timeout_minutes),
                read,
                "{} characters: {:?}...",
                raw.chars().count(),
                raw.chars().take(8).collect::<String>()
            );
        }
    }

    /// The one difference from the bridge: Python's `int()` also reads
    /// other decimal digits (`"１５"` is 15), and the gateway reads only
    /// 0-9. It used its default for such a value, which could keep a
    /// session the bridge has ended (an idle timeout of `"１５"` was 15
    /// minutes on the bridge and 30 on the gateway). Now it refuses to
    /// start and says why, as it did before it read the values as the
    /// bridge does. That includes number characters that `int()` does not
    /// read (`"²"`, `"⅕"`, `"Ⅰ"`; the bridge's default): telling them
    /// apart from decimal digits needs the Unicode tables of the bridge's
    /// Python version.
    #[test]
    fn a_timeout_written_with_other_digits_stops_the_gateway() {
        for raw in [
            "\u{ff11}\u{ff15}",
            " \u{661}\u{662} ",
            "+1\u{ff15}",
            "-\u{ff11}",
            "1_\u{ff15}",
            "\u{1d7d7}",
            "\u{b2}",
            "\u{2155}",
            "\u{2160}",
        ] {
            for (option, variable) in [
                (
                    "--session-absolute-timeout-hours",
                    "BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS",
                ),
                (
                    "--session-idle-timeout-minutes",
                    "BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES",
                ),
            ] {
                let refused = session_config_result(&[format!("{option}={raw}")])
                    .expect_err(&format!("{option}={raw:?} is refused"));
                for named in [variable, option, &format!("{raw:?}"), "0-9"] {
                    assert!(refused.contains(named), "{named:?} missing: {refused}");
                }
            }
        }
    }

    /// Regression: a huge absolute timeout was used as it was, and every
    /// login then panicked or got a session whose expiry no request could
    /// read. Like the bridge (`UserStore._absolute_timeout_hours`), a value
    /// above `MAX_ABSOLUTE_TIMEOUT_HOURS`, the ceiling the settings API
    /// enforces too, is ignored and the default used; the maximum itself is
    /// used as given. A huge idle timeout means no idle limit, as on the
    /// bridge, and saturates.
    #[test]
    fn a_session_timeout_above_the_maximum_gives_the_default() {
        use crate::storage::sessions::MAX_ABSOLUTE_TIMEOUT_HOURS;
        let default = SessionConfig::default().absolute_timeout_hours;
        for (raw, idle) in [
            ("10000001", 10_000_001),
            ("9223372036854775807", i64::MAX),
            ("9223372036854775808", i64::MAX),
            ("99999999999999999999999", i64::MAX),
        ] {
            let c = session_config_of(&both_timeouts(raw));
            assert_eq!(c.absolute_timeout_hours, default, "{raw}");
            assert_eq!(c.idle_timeout_minutes, idle, "{raw}");
        }
        let c = session_config_of(&both_timeouts("10000000"));
        assert_eq!(c.absolute_timeout_hours, MAX_ABSOLUTE_TIMEOUT_HOURS);
    }

    /// The characters for which Python 3.12's `str.isspace()` is true, the
    /// ones `str.strip()` removes.
    #[test]
    fn python_whitespace_is_what_str_strip_removes() {
        let python: Vec<u32> = [
            0x9..=0xd,
            0x1c..=0x20,
            0x85..=0x85,
            0xa0..=0xa0,
            0x1680..=0x1680,
            0x2000..=0x200a,
            0x2028..=0x2029,
            0x202f..=0x202f,
            0x205f..=0x205f,
            0x3000..=0x3000,
        ]
        .into_iter()
        .flatten()
        .collect();
        let gateway: Vec<u32> = (0..=char::MAX as u32)
            .filter_map(char::from_u32)
            .filter(|&c| is_python_whitespace(c))
            .map(u32::from)
            .collect();
        assert_eq!(gateway, python);
    }

    /// Every timeout value the gateway does not use as given is logged
    /// with what it uses instead. The bridge logs only an unreadable one.
    #[test]
    fn session_timeouts_not_used_as_given_are_logged() {
        let warnings = |args: &[String]| {
            let (_, logs) = crate::test_support::logs_of(|| session_config_of(args));
            logs.lines()
                .filter(|line| line.contains("WARN"))
                .map(str::to_string)
                .collect::<Vec<_>>()
        };

        let logged = warnings(&[
            "--session-absolute-timeout-hours=abc".to_string(),
            "--session-idle-timeout-minutes=0".to_string(),
        ]);
        assert_eq!(logged.len(), 2, "{logged:?}");
        for named in [
            "BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS",
            "\"abc\"",
            "not an integer",
            "default 24",
        ] {
            assert!(logged[0].contains(named), "{named:?} missing: {logged:?}");
        }
        for named in [
            "BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES",
            "\"0\"",
            "below 1",
            "default 30",
        ] {
            assert!(logged[1].contains(named), "{named:?} missing: {logged:?}");
        }

        let logged = warnings(&["--session-absolute-timeout-hours=99999999999999999999999".into()]);
        assert_eq!(logged.len(), 1, "{logged:?}");
        assert!(logged[0].contains("10000000"), "{logged:?}");

        // Too many digits for int(): the count, not the value itself.
        let logged = warnings(&[format!(
            "--session-idle-timeout-minutes={}",
            "1".repeat(4301)
        )]);
        assert_eq!(logged.len(), 1, "{logged:?}");
        for named in [
            "BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES",
            "4301 digits",
            "4300",
            "default 30",
        ] {
            assert!(logged[0].contains(named), "{named:?} missing: {logged:?}");
        }
        assert!(logged[0].len() < 300, "{logged:?}");

        // Values used as given, and empty ones (the bridge's default,
        // without a warning), log nothing.
        assert_eq!(warnings(&both_timeouts(" 48 ")), Vec::<String>::new());
        assert_eq!(warnings(&both_timeouts("")), Vec::<String>::new());
        assert_eq!(warnings(&[]), Vec::<String>::new());
    }

    /// The contract with the bridge is the variable names: both services
    /// read `BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS` and
    /// `BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES`. The other tests give the
    /// timeouts as command-line options, which they would pass if clap no
    /// longer read a variable, or read it under another name; the gateway
    /// would then keep its default while the bridge used the value. The
    /// variables are set for a child process (this test binary, running
    /// only this test), since every test in this process would see them.
    #[test]
    fn session_timeouts_are_read_from_the_bridge_variables() {
        const CHILD: &str = "SIGRIFT_GATEWAY_TEST_SESSION_VARIABLES_CHILD";
        const MARKER: &str = "session timeouts read: ";
        const ABSOLUTE: &str = "BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS";
        const IDLE: &str = "BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES";
        if std::env::var_os(CHILD).is_some() {
            let c = session_config_of(&[]);
            println!(
                "{MARKER}{} {}",
                c.absolute_timeout_hours, c.idle_timeout_minutes
            );
            return;
        }

        let path = concat!(
            module_path!(),
            "::session_timeouts_are_read_from_the_bridge_variables"
        );
        // libtest names a test by its path without the crate.
        let (_, test) = path.split_once("::").unwrap();
        for (absolute, idle, read) in [
            (Some(" 48 "), Some("+1_0"), (48, 10)),
            (Some("7"), None, (7, 30)),
            (None, Some("45"), (24, 45)),
            (Some("0"), Some("abc"), (24, 30)),
            (Some(""), Some(""), (24, 30)),
            (None, None, (24, 30)),
            (
                Some("99999999999999999999"),
                Some("99999999999999999999"),
                (24, i64::MAX),
            ),
        ] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args([test, "--exact", "--nocapture", "--test-threads=1"])
                .env(CHILD, "1")
                .env_remove(ABSOLUTE)
                .env_remove(IDLE);
            for (variable, value) in [(ABSOLUTE, absolute), (IDLE, idle)] {
                if let Some(value) = value {
                    child.env(variable, value);
                }
            }
            let output = child.output().unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            let context = format!(
                "{ABSOLUTE}={absolute:?} {IDLE}={idle:?}\n{stdout}{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.status.success(), "{context}");
            let line = stdout
                .split_once(MARKER)
                .and_then(|(_, rest)| rest.lines().next())
                .unwrap_or_else(|| panic!("the child did not run {test}: {context}"));
            assert_eq!(line, format!("{} {}", read.0, read.1), "{context}");
        }
    }

    #[test]
    fn production_env_values() {
        for v in ["production", "prod", "PRODUCTION", " Prod\n"] {
            assert!(is_production_env(v), "{v:?}");
        }
        for v in ["", "dev", "development", "test", "staging", "production2"] {
            assert!(!is_production_env(v), "{v:?}");
        }
    }
}
