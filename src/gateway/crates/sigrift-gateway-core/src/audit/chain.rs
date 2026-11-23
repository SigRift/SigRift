//! HMAC chain computation, secret derivation, and `python_float_str()`.
//!
//! Implements the tamper-evident audit chain matching Python's
//! `sigrift/bridge/storage/audit.py`. Each entry's HMAC covers the previous
//! entry's HMAC, forming a linked chain.
//!
//! Record versions (none is stored; verifiers try v3, then v2, then v1):
//! * v1 and v2 join their fields with a bare `|`, so text containing `|`
//!   can move between adjacent fields without changing the HMAC, and v2
//!   does not cover `target_ids` or `tenant_id`. Rows already written keep
//!   that weakness (stored rows are never rewritten).
//! * v3, written for new entries by both the gateway and the bridge, covers
//!   the v2 fields plus `target_ids` and `tenant_id`, each prefixed with
//!   its length in UTF-8 bytes ([`compute_hmac_v3`]).

use std::fmt::Write as _;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::path::Path;
use tracing::warn;

type HmacSha256 = Hmac<Sha256>;

/// Sentinel value for entries that predate HMAC chain (legacy rows).
pub const LEGACY_NO_HMAC_SENTINEL: &str = "LEGACY_NO_HMAC";

// ── python_float_str ──────────────────────────────────────────────────

/// Format an f64 to match Python's `str(float)` output exactly.
///
/// Critical for HMAC parity — the `freq_hz` field in audit payloads
/// must produce identical strings in Rust and Python.
pub fn python_float_str(f: f64) -> String {
    if f.is_nan() {
        return "nan".to_string();
    }
    if f.is_infinite() {
        return if f > 0.0 {
            "inf".to_string()
        } else {
            "-inf".to_string()
        };
    }

    // Handle negative zero
    if f == 0.0 && f.is_sign_negative() {
        return "-0.0".to_string();
    }

    // Python 3.1+ uses shortest round-trip repr (David Gay's dtoa).
    // It switches to scientific notation when:
    //   - magnitude >= 1e16 (large)
    //   - magnitude < 1e-4 and != 0 (small)
    // Use Rust's {:e} for scientific, {:.prec} for decimal, matching Python.

    // For zero
    if f == 0.0 {
        return "0.0".to_string();
    }

    let abs = f.abs();

    // Python uses repr() which gives shortest round-trip string.
    // We replicate by checking if Python would use scientific notation.
    if abs >= 1e16 || (abs != 0.0 && abs < 1e-4) {
        // Scientific notation path
        // Use Python-compatible formatting via format!("{:e}")
        // but we need the shortest representation
        let repr = format!("{}", f); // Rust may or may not use sci notation

        // If Rust already gave us scientific notation, reformat it
        if repr.contains('e') || repr.contains('E') {
            return format_sci(&repr);
        }

        // Rust didn't use scientific but Python would — use {:e} and clean up
        // Actually, use a different approach: format with enough precision
        // and use Python's algorithm
        let s = format!("{:e}", f);
        return format_sci(&s);
    }

    // Decimal notation path
    let s = format!("{}", f);

    // Rust omits .0 for integer-valued floats
    if !s.contains('.') && !s.contains('e') {
        return format!("{}.0", s);
    }

    s
}

/// Reformat Rust scientific notation to match Python's format.
fn format_sci(s: &str) -> String {
    if let Some(e_pos) = s.find('e').or_else(|| s.find('E')) {
        let (mantissa, exp_part) = s.split_at(e_pos);
        let exp_str = &exp_part[1..];

        let (sign, digits) = if let Some(d) = exp_str.strip_prefix('-') {
            ("-", d)
        } else if let Some(d) = exp_str.strip_prefix('+') {
            ("+", d)
        } else {
            ("+", exp_str)
        };

        let exp_num: i32 = digits.parse().unwrap_or(0);

        // Clean up mantissa: remove trailing zeros after decimal, but keep at least one digit
        let mantissa_clean = if mantissa.contains('.') {
            let trimmed = mantissa.trim_end_matches('0');
            let trimmed = trimmed.trim_end_matches('.');
            trimmed
        } else {
            mantissa
        };

        if exp_num.abs() < 10 {
            format!("{}e{}{:02}", mantissa_clean, sign, exp_num.abs())
        } else {
            format!("{}e{}{}", mantissa_clean, sign, exp_num.abs())
        }
    } else {
        s.to_string()
    }
}

// ── Secret derivation ─────────────────────────────────────────────────

/// Derive the audit HMAC secret from configuration.
///
/// Resolution order (matching Python):
/// 1. `BRIDGE_AUDIT_KEY` → SHA-256
/// 2. `BRIDGE_AUDIT_SECRET` → SHA-256 (legacy)
/// 3. `BRIDGE_MASTER_KEY` → SHA-256("bridge-audit-hmac:" + key)
/// 4. File `data/audit.key` (dev mode only)
/// 5. Production: fail-closed
pub fn get_audit_secret(audit_key: &str, bridge_env: &str) -> Result<Vec<u8>, String> {
    resolve_audit_secret(audit_key, bridge_env, |name| std::env::var(name).ok())
}

/// [`get_audit_secret`] with an injectable environment lookup, so the
/// resolution (and the production startup check) is testable without
/// depending on the test process's environment.
pub fn resolve_audit_secret(
    audit_key: &str,
    bridge_env: &str,
    env: impl Fn(&str) -> Option<String>,
) -> Result<Vec<u8>, String> {
    // 1. BRIDGE_AUDIT_KEY (trimmed, like Python)
    let audit_key = audit_key.trim();
    if !audit_key.is_empty() {
        return Ok(sha256_bytes(audit_key.as_bytes()));
    }

    // 2. BRIDGE_AUDIT_SECRET (legacy, from env)
    if let Some(secret) = env("BRIDGE_AUDIT_SECRET") {
        let secret = secret.trim();
        if !secret.is_empty() {
            return Ok(sha256_bytes(secret.as_bytes()));
        }
    }

    // 3. BRIDGE_MASTER_KEY (domain-separated)
    if let Some(master) = env("BRIDGE_MASTER_KEY") {
        let master = master.trim();
        if !master.is_empty() {
            let mut input = b"bridge-audit-hmac:".to_vec();
            input.extend_from_slice(master.as_bytes());
            return Ok(sha256_bytes(&input));
        }
    }

    // 4. Production fail-closed
    if crate::config::is_production_env(bridge_env) {
        return Err(
            "No audit key configured in production mode. Set BRIDGE_AUDIT_KEY \
                    (BRIDGE_AUDIT_SECRET and BRIDGE_MASTER_KEY are deprecated fallbacks)."
                .into(),
        );
    }

    // 5. Dev mode: try file, or generate ephemeral
    let key_path = Path::new("data/audit.key");
    if key_path.exists() {
        if let Ok(contents) = std::fs::read_to_string(key_path) {
            let key = contents.trim();
            if !key.is_empty() {
                return Ok(sha256_bytes(key.as_bytes()));
            }
        }
    }

    // Generate ephemeral key (won't survive restart)
    warn!("No audit key configured — using ephemeral key (dev mode only)");
    let mut buf = [0u8; 32];
    use rand::RngExt;
    rand::rng().fill(&mut buf[..]);
    Ok(buf.to_vec())
}

fn sha256_bytes(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}

// ── HMAC computation ──────────────────────────────────────────────────

/// Compute v1 HMAC-SHA256 (legacy format).
///
/// Payload: `{prev_hmac}|{action}|{target_id}|{operator}|{timestamp}`
pub fn compute_hmac_v1(
    secret: &[u8],
    previous_hmac: &str,
    action: &str,
    target_id: &str,
    operator: &str,
    timestamp: &str,
) -> String {
    let payload = format!(
        "{}|{}|{}|{}|{}",
        previous_hmac, action, target_id, operator, timestamp
    );
    hmac_sha256(secret, &payload)
}

/// Compute v2 HMAC-SHA256 (current format, covers all mutable fields).
///
/// Payload: `v2|{prev}|{action}|{target_id}|{operator}|{timestamp}|{details}|{note}|{signal_class}|{freq_hz}|{node_id}`
// One parameter per HMAC payload field, in payload order — mirrors Python.
#[allow(clippy::too_many_arguments)]
pub fn compute_hmac_v2(
    secret: &[u8],
    previous_hmac: &str,
    action: &str,
    target_id: &str,
    operator: &str,
    timestamp: &str,
    details: &str,
    note: &str,
    signal_class: &str,
    freq_hz: &str,
    node_id: &str,
) -> String {
    let payload = format!(
        "v2|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        previous_hmac,
        action,
        target_id,
        operator,
        timestamp,
        details,
        note,
        signal_class,
        freq_hz,
        node_id
    );
    hmac_sha256(secret, &payload)
}

/// The v3 HMAC input: `v3`, then `|{len}:{field}` for each field, where
/// `len` is the field's length in UTF-8 bytes (`str::len`, as Python's
/// `len(field.encode("utf-8"))`). The length prefixes make the encoding
/// injective, and no v2 (`v2|…`) or v1 payload (which starts with the
/// previous HMAC: `""`, 64 hex digits or the legacy sentinel) starts with
/// `v3|`.
pub(crate) fn hmac_v3_payload(fields: &[&str]) -> String {
    let mut payload = String::from("v3");
    for field in fields {
        let _ = write!(payload, "|{}:{}", field.len(), field);
    }
    payload
}

/// Compute v3 HMAC-SHA256, the version written for new entries.
///
/// Covers the v2 fields plus the stored `target_ids` text and `tenant_id`,
/// each length-prefixed (see `hmac_v3_payload`); identical to Python's
/// `_compute_hmac_v3`.
// One parameter per HMAC payload field, in payload order — mirrors Python.
#[allow(clippy::too_many_arguments)]
pub fn compute_hmac_v3(
    secret: &[u8],
    previous_hmac: &str,
    action: &str,
    target_id: &str,
    operator: &str,
    timestamp: &str,
    details: &str,
    note: &str,
    signal_class: &str,
    freq_hz: &str,
    node_id: &str,
    target_ids: &str,
    tenant_id: &str,
) -> String {
    let payload = hmac_v3_payload(&[
        previous_hmac,
        action,
        target_id,
        operator,
        timestamp,
        details,
        note,
        signal_class,
        freq_hz,
        node_id,
        target_ids,
        tenant_id,
    ]);
    hmac_sha256(secret, &payload)
}

/// Hex HMAC-SHA256 of an arbitrary payload under the audit secret (used
/// for records outside the row chain, such as the archive anchor).
pub(crate) fn hmac_hex(secret: &[u8], payload: &str) -> String {
    hmac_sha256(secret, payload)
}

fn hmac_sha256(secret: &[u8], payload: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key length");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Key: SHA-256("test_audit_key")
    fn test_secret() -> Vec<u8> {
        sha256_bytes(b"test_audit_key")
    }

    // ── python_float_str tests ────────────────────────────────────────

    #[test]
    fn test_python_float_str_zero() {
        assert_eq!(python_float_str(0.0), "0.0");
    }

    #[test]
    fn test_python_float_str_negative_zero() {
        assert_eq!(python_float_str(-0.0), "-0.0");
    }

    #[test]
    fn test_python_float_str_integers() {
        assert_eq!(python_float_str(1.0), "1.0");
        assert_eq!(python_float_str(-1.0), "-1.0");
        assert_eq!(python_float_str(2.0), "2.0");
        assert_eq!(python_float_str(10.0), "10.0");
        assert_eq!(python_float_str(100.0), "100.0");
        assert_eq!(python_float_str(1000.0), "1000.0");
        assert_eq!(python_float_str(1000000.0), "1000000.0");
        assert_eq!(python_float_str(2400000000.0), "2400000000.0");
    }

    #[test]
    #[allow(clippy::approx_constant)]
    fn test_python_float_str_decimals() {
        assert_eq!(python_float_str(0.5), "0.5");
        assert_eq!(python_float_str(0.1), "0.1");
        assert_eq!(python_float_str(0.01), "0.01");
        assert_eq!(python_float_str(0.001), "0.001");
        assert_eq!(python_float_str(0.0001), "0.0001");
        assert_eq!(python_float_str(-3.14), "-3.14");
    }

    #[test]
    fn test_python_float_str_sci_notation_large() {
        assert_eq!(python_float_str(1e15), "1000000000000000.0");
        assert_eq!(python_float_str(1e16), "1e+16");
        assert_eq!(python_float_str(1e17), "1e+17");
        assert_eq!(python_float_str(1e100), "1e+100");
        assert_eq!(python_float_str(1e308), "1e+308");
        assert_eq!(python_float_str(-1e16), "-1e+16");
    }

    #[test]
    fn test_python_float_str_sci_notation_small() {
        assert_eq!(python_float_str(1e-5), "1e-05");
        assert_eq!(python_float_str(1e-7), "1e-07");
        assert_eq!(python_float_str(-1e-7), "-1e-07");
        assert_eq!(python_float_str(5e-324), "5e-324");
    }

    /// A `freq_hz` in scientific notation with a fractional mantissa must
    /// give the HMAC input Python gives, or every entry holding one fails
    /// verification on the other service. Expected: Python 3's `repr()`.
    #[test]
    fn test_python_float_str_sci_notation_fractional_mantissa() {
        for (value, python) in [
            (1.5e-7, "1.5e-07"),
            (9.87654321e-5, "9.87654321e-05"),
            (1.2345e-10, "1.2345e-10"),
            (2.5e16, "2.5e+16"),
            (-6.02e23, "-6.02e+23"),
            (1.0000000000000002e16, "1.0000000000000002e+16"),
            (f64::MAX, "1.7976931348623157e+308"),
            (f64::MIN_POSITIVE, "2.2250738585072014e-308"),
        ] {
            assert_eq!(python_float_str(value), python, "{value:e}");
        }
    }

    #[test]
    #[allow(clippy::approx_constant)]
    fn test_python_float_str_precision() {
        assert_eq!(python_float_str(0.1 + 0.2), "0.30000000000000004");
        assert_eq!(python_float_str(1.0 / 3.0), "0.3333333333333333");
        // Literal is a formatting test case, not an approximation of π.
        assert_eq!(python_float_str(3.14159265358979), "3.14159265358979");
    }

    #[test]
    fn test_python_float_str_special() {
        assert_eq!(python_float_str(f64::INFINITY), "inf");
        assert_eq!(python_float_str(f64::NEG_INFINITY), "-inf");
        assert_eq!(python_float_str(f64::NAN), "nan");
    }

    #[test]
    fn test_python_float_str_mixed() {
        assert_eq!(python_float_str(123456789.12345679), "123456789.12345679");
        assert_eq!(python_float_str(433000000.0), "433000000.0");
        assert_eq!(python_float_str(5800000000.0), "5800000000.0");
        assert_eq!(python_float_str(-2400000000.0), "-2400000000.0");
    }

    // ── HMAC v1 tests ─────────────────────────────────────────────────

    #[test]
    fn test_hmac_v1_empty_predecessor() {
        let secret = test_secret();
        let hmac = compute_hmac_v1(
            &secret,
            "",
            "user_login",
            "testuser",
            "testuser",
            "2024-01-01T00:00:00+00:00",
        );
        assert_eq!(
            hmac,
            "4d91d30c89610fa01495bb63373af64748f0cc2fa92eae9d1829c5dc0077072c"
        );
    }

    #[test]
    fn test_hmac_v1_golden_vector() {
        let secret = test_secret();
        let hmac = compute_hmac_v1(
            &secret,
            "",
            "user_login",
            "testuser",
            "testuser",
            "2024-01-01T00:00:00+00:00",
        );
        assert_eq!(hmac.len(), 64);
        assert!(hex::decode(&hmac).is_ok());
    }

    // ── HMAC v2 tests ─────────────────────────────────────────────────

    #[test]
    fn test_hmac_v2_empty_predecessor() {
        let secret = test_secret();
        let hmac = compute_hmac_v2(
            &secret,
            "",
            "user_login",
            "testuser",
            "testuser",
            "2024-01-01T00:00:00+00:00",
            "",
            "",
            "",
            "0.0",
            "",
        );
        assert_eq!(
            hmac,
            "b091ad4c6e113e653c51eb3064bac1e899eff07f8fc0f30cf5ecfcb4bf070e9a"
        );
    }

    #[test]
    fn test_hmac_v2_chained() {
        let secret = test_secret();
        let first = compute_hmac_v2(
            &secret,
            "",
            "user_login",
            "testuser",
            "testuser",
            "2024-01-01T00:00:00+00:00",
            "",
            "",
            "",
            "0.0",
            "",
        );
        let second = compute_hmac_v2(
            &secret,
            &first,
            "user_logout",
            "testuser",
            "testuser",
            "2024-01-01T00:01:00+00:00",
            "",
            "",
            "",
            "0.0",
            "",
        );
        assert_eq!(
            second,
            "ff8d284bd3e181266f1fe064c0c22b74aa8cd8844676eb46d6a59c6964650cfe"
        );
    }

    #[test]
    fn test_hmac_v2_with_details() {
        let secret = test_secret();
        let hmac = compute_hmac_v2(
            &secret,
            "",
            "auth_failure",
            "baduser",
            "",
            "2024-01-01T00:00:00+00:00",
            "{\"ip\":\"10.0.0.1\"}",
            "Login failed",
            "qpsk",
            "2400000000.0",
            "node1",
        );
        assert_eq!(
            hmac,
            "9c4d351280d586a55c6f4efdac3a0a915af40d5836ab4f9cc39464cfbe26f0cb"
        );
    }

    // ── HMAC v3 tests ─────────────────────────────────────────────────
    //
    // Golden vectors shared with Python
    // (tests/bridge/test_audit_storage_security.py).

    const V3_EMPTY: &str = "dd117c1f04cef5294841277d1f9ca81eb8ca2c4fe056d8b7ccd22691924d81ad";

    #[test]
    fn test_hmac_v3_golden_vectors() {
        let secret = test_secret();
        let first = compute_hmac_v3(
            &secret,
            "",
            "user_login",
            "testuser",
            "testuser",
            "2024-01-01T00:00:00+00:00",
            "",
            "",
            "",
            "0.0",
            "",
            "",
            "default",
        );
        assert_eq!(first, V3_EMPTY);
        let second = compute_hmac_v3(
            &secret,
            &first,
            "user_logout",
            "testuser",
            "testuser",
            "2024-01-01T00:01:00+00:00",
            "",
            "",
            "",
            "0.0",
            "",
            "",
            "default",
        );
        assert_eq!(
            second,
            "e8cc81b36b1321c4b843aecfa270d730efa616f802092fc8eed4680a6473ce8a"
        );
        let full = compute_hmac_v3(
            &secret,
            &first,
            "bulk_dismiss_rf",
            "1",
            "alice",
            "2024-01-01T00:02:00+00:00",
            "{\"ip\":\"10.0.0.1\",\"who\":\"名前|Ω\"}",
            "approved|signed-off\0ok",
            "wifi",
            "2400000000.0",
            "node1",
            "[\"1\",\"2\",\"3\"]",
            "tenant-b",
        );
        assert_eq!(
            full,
            "95fbc262b9f5c8ec7b7965cea3c5b41b36b544227cb35792b157a9c5f662a0ec"
        );
    }

    #[test]
    fn test_hmac_v3_payload_counts_utf8_bytes() {
        assert_eq!(hmac_v3_payload(&["", "é|x", "a"]), "v3|0:|4:é|x|1:a");
        assert_eq!(hmac_v3_payload(&["nul\0"]), "v3|4:nul\0");
        assert_ne!(hmac_v3_payload(&["a|1:b"]), hmac_v3_payload(&["a", "b"]));
    }

    #[test]
    fn test_hmac_v3_text_cannot_move_between_fields() {
        let secret = test_secret();
        let v3 = |note: &str, signal_class: &str| {
            compute_hmac_v3(
                &secret,
                "",
                "dismiss",
                "det-1",
                "",
                "ts",
                "",
                note,
                signal_class,
                "0.0",
                "",
                "",
                "default",
            )
        };
        let v2 = |note: &str, signal_class: &str| {
            compute_hmac_v2(
                &secret,
                "",
                "dismiss",
                "det-1",
                "",
                "ts",
                "",
                note,
                signal_class,
                "0.0",
                "",
            )
        };
        // v2 cannot tell these apart; v3 can.
        assert_eq!(
            v2("approved|signed-off", "wifi"),
            v2("approved", "signed-off|wifi")
        );
        assert_ne!(
            v3("approved|signed-off", "wifi"),
            v3("approved", "signed-off|wifi")
        );
    }

    #[test]
    fn test_hmac_v3_covers_target_ids_and_tenant() {
        let secret = test_secret();
        let v3 = |target_ids: &str, tenant_id: &str| {
            compute_hmac_v3(
                &secret, "", "a", "t", "o", "ts", "", "", "", "0.0", "", target_ids, tenant_id,
            )
        };
        assert_ne!(v3("[\"1\"]", "default"), v3("[\"2\"]", "default"));
        assert_ne!(v3("", "default"), v3("", "tenant-b"));
    }

    #[test]
    fn test_hmac_deterministic() {
        let secret = test_secret();
        let h1 = compute_hmac_v2(&secret, "", "test", "t", "o", "ts", "", "", "", "0.0", "");
        let h2 = compute_hmac_v2(&secret, "", "test", "t", "o", "ts", "", "", "", "0.0", "");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hmac_different_key() {
        let k1 = sha256_bytes(b"key1");
        let k2 = sha256_bytes(b"key2");
        let h1 = compute_hmac_v1(&k1, "", "a", "b", "c", "d");
        let h2 = compute_hmac_v1(&k2, "", "a", "b", "c", "d");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_legacy_sentinel_value() {
        assert_eq!(LEGACY_NO_HMAC_SENTINEL, "LEGACY_NO_HMAC");
    }

    // ── Secret derivation tests ───────────────────────────────────────

    #[test]
    fn test_secret_from_audit_key() {
        let secret = get_audit_secret("my_audit_key", "test").unwrap();
        let expected = sha256_bytes(b"my_audit_key");
        assert_eq!(secret, expected);
    }

    #[test]
    fn test_secret_domain_separation() {
        // BRIDGE_AUDIT_KEY = "mykey" → SHA-256("mykey")
        let direct = sha256_bytes(b"mykey");
        // BRIDGE_MASTER_KEY = "mykey" → SHA-256("bridge-audit-hmac:mykey")
        let domain_sep = sha256_bytes(b"bridge-audit-hmac:mykey");
        assert_ne!(
            direct, domain_sep,
            "Domain separation should produce different keys"
        );
    }

    #[test]
    fn test_secret_empty_key_dev_mode() {
        // In dev mode with no keys set, should succeed with ephemeral key
        let result = get_audit_secret("", "test");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_secret_empty_key_production_fails() {
        let no_env = |_: &str| None;
        assert!(resolve_audit_secret("", "production", no_env).is_err());
        assert!(resolve_audit_secret("  ", "prod", no_env).is_err());
        assert!(resolve_audit_secret("", "PRODUCTION", no_env).is_err());
    }

    #[test]
    fn test_secret_from_env_fallbacks() {
        let env = |name: &str| (name == "BRIDGE_MASTER_KEY").then(|| " mk ".to_string());
        assert_eq!(
            resolve_audit_secret("", "production", env).unwrap(),
            sha256_bytes(b"bridge-audit-hmac:mk")
        );
        let env = |name: &str| (name == "BRIDGE_AUDIT_SECRET").then(|| "legacy".to_string());
        assert_eq!(
            resolve_audit_secret("", "production", env).unwrap(),
            sha256_bytes(b"legacy")
        );
        // BRIDGE_AUDIT_KEY is trimmed, like Python.
        assert_eq!(
            resolve_audit_secret(" k\n", "production", |_: &str| None).unwrap(),
            sha256_bytes(b"k")
        );
    }

    /// Environment variables: (name, value).
    type Vars<'a> = [(&'a str, &'a str)];

    /// An environment holding exactly `vars`. Every call returns the same
    /// closure type, so the cases below all run through one instantiation
    /// of [`resolve_audit_secret`].
    fn env_of<'a>(vars: &'a Vars<'a>) -> impl Fn(&str) -> Option<String> + 'a {
        move |name: &str| {
            vars.iter()
                .find(|(var, _)| *var == name)
                .map(|(_, value)| value.to_string())
        }
    }

    /// The key resolution order, as on the bridge: `BRIDGE_AUDIT_KEY`, then
    /// `BRIDGE_AUDIT_SECRET`, then `BRIDGE_MASTER_KEY` (domain-separated),
    /// each trimmed. A blank value is no key and falls through: the HMAC
    /// key must never be derived from an empty value (anyone can compute
    /// SHA-256("") or SHA-256("bridge-audit-hmac:") and forge the chain).
    /// With no key, production refuses to start.
    #[test]
    fn test_secret_resolution_order_skips_blank_values() {
        const SECRET: &str = "BRIDGE_AUDIT_SECRET";
        const MASTER: &str = "BRIDGE_MASTER_KEY";
        let both = [(SECRET, "legacy"), (MASTER, "mk")];
        let cases: [(&str, &Vars, Option<Vec<u8>>); 7] = [
            ("audit-key", &both, Some(sha256_bytes(b"audit-key"))),
            (" \t", &both, Some(sha256_bytes(b"legacy"))),
            (
                "",
                &[(SECRET, " \t "), (MASTER, " mk ")],
                Some(sha256_bytes(b"bridge-audit-hmac:mk")),
            ),
            (
                "",
                &[(MASTER, "mk")],
                Some(sha256_bytes(b"bridge-audit-hmac:mk")),
            ),
            ("", &[(SECRET, " legacy\n")], Some(sha256_bytes(b"legacy"))),
            ("", &[(SECRET, " "), (MASTER, "\n")], None),
            ("", &[], None),
        ];
        for (audit_key, vars, expected) in cases {
            let resolved = resolve_audit_secret(audit_key, "production", env_of(vars));
            match expected {
                Some(key) => assert_eq!(resolved.as_ref().ok(), Some(&key), "{vars:?}"),
                None => {
                    let err = resolved.unwrap_err();
                    assert!(err.contains("No audit key configured"), "{vars:?}: {err}");
                }
            }
        }

        // In development a blank value is no key either: a fresh random key
        // is used instead (or the one in data/audit.key, if the working
        // directory holds one).
        let blank = [(SECRET, " "), (MASTER, " \n")];
        let dev = resolve_audit_secret(" ", "development", env_of(&blank)).unwrap();
        let again = resolve_audit_secret(" ", "development", env_of(&blank)).unwrap();
        assert_eq!(dev.len(), 32);
        for derived_from_blank in [
            sha256_bytes(b""),
            sha256_bytes(b" "),
            sha256_bytes(b"bridge-audit-hmac:"),
            sha256_bytes(b"bridge-audit-hmac: \n"),
        ] {
            assert_ne!(dev, derived_from_blank);
        }
        match std::fs::read_to_string("data/audit.key") {
            Ok(file_key) if !file_key.trim().is_empty() => {
                assert_eq!(dev, sha256_bytes(file_key.trim().as_bytes()));
                assert_eq!(again, dev);
            }
            _ => assert_ne!(again, dev, "the ephemeral key must be random"),
        }
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    /// `format_sci` rewrites any exponent spelling the formatter may hand
    /// it into Python's (`e`, sign, at least two digits) and keeps the
    /// shortest mantissa, so the `freq_hz` text inside an HMAC input is
    /// the bridge's whatever the spelling: an explicit `+`, an upper-case
    /// `E` and trailing mantissa zeros included. Text without an exponent
    /// is returned unchanged.
    #[test]
    fn scientific_notation_is_normalised_to_pythons_spelling() {
        for (rust, python) in [
            ("1.5e+7", "1.5e+07"),
            ("2.50e+16", "2.5e+16"),
            ("1.000e+100", "1e+100"),
            ("4E-5", "4e-05"),
            ("-6.020E+23", "-6.02e+23"),
            ("7e12", "7e+12"),
        ] {
            assert_eq!(format_sci(rust), python, "{rust}");
        }
        assert_eq!(format_sci("433920000.0"), "433920000.0");
        assert_eq!(format_sci(""), "");
    }

    /// The HMAC of an entry depends on the `freq_hz` text exactly: two
    /// spellings of one value that are not normalised alike would give
    /// different HMACs, and an entry signed on one service would fail
    /// verification on the other.
    #[test]
    fn the_hmac_input_holds_the_normalised_frequency() {
        let secret = sha256_bytes(b"coverage-key");
        let v3 = |freq: &str| {
            compute_hmac_v3(
                &secret, "", "dismiss", "det-1", "op", "ts", "", "", "", freq, "", "", "default",
            )
        };
        assert_eq!(v3(&python_float_str(1.5e7)), v3("15000000.0"));
        assert_eq!(v3(&format_sci("1.5e+16")), v3(&python_float_str(1.5e16)));
        assert_ne!(v3("1.5e+16"), v3("1.5e16"));
    }
}
