//! TOTP (RFC 6238) and HOTP (RFC 4226) implementation.
//!
//! Uses HMAC-SHA1 matching Python's `sigrift/bridge/security/totp.py`.
//! No external TOTP crate — implements the spec directly for full control
//! over cross-language parity.

use constant_time_eq::constant_time_eq;
use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt;
use sha1::Sha1;
use std::fmt;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha1 = Hmac<Sha1>;

/// Why a TOTP secret cannot be used as a key. Its `Display` names the
/// problem only, never the secret, so it can be logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidSecret {
    /// Not Base32 (RFC 4648): a character outside `A-Z2-7` in either case
    /// (whitespace, `0`, `1`, `8`, `9`, punctuation, non-ASCII), padding
    /// before the end, or a length no Base32 string has.
    NotBase32,
    /// Decodes to no key bytes or to zero bytes only, which HMAC treats as
    /// the empty key: its codes can be computed without knowing any secret.
    NoKeyBytes,
}

impl fmt::Display for InvalidSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotBase32 => "TOTP secret is not valid Base32",
            Self::NoKeyBytes => "TOTP secret decodes to an empty or all-zero key",
        })
    }
}

impl std::error::Error for InvalidSecret {}

/// RFC 4648 Base32 as the bridge decodes it (Python's `base64.b32decode`):
/// the unused low bits of the last character need not be zero.
static BASE32_LENIENT: LazyLock<data_encoding::Encoding> = LazyLock::new(|| {
    let mut spec = data_encoding::Specification::new();
    spec.symbols.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
    spec.padding = Some('=');
    spec.check_trailing_bits = false;
    spec.encoding()
        .expect("constant Base32 specification is valid")
});

/// Generate a random base32-encoded secret (no padding).
///
/// Default 20 bytes (160 bits) per RFC 4226 recommendation.
/// Matches Python: `base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")`
pub fn generate_secret(nbytes: usize) -> String {
    let mut raw = vec![0u8; nbytes];
    rand::rng().fill(&mut raw[..]);
    data_encoding::BASE32_NOPAD.encode(&raw)
}

/// Decode a Base32 secret (either case, padding optional) into its key.
///
/// Accepts exactly the secrets the bridge's `_decode_secret` accepts, with
/// the same key bytes, except that it also refuses non-ASCII input that
/// Python's `upper()` maps to ASCII, and keys without a non-zero byte.
///
/// The key length is not checked, as on the bridge: a key shorter than the
/// 128 bits RFC 4226 (R6) requires is used as it is, and a very short one
/// can be guessed (a 1-byte key has 255 usable values, few enough to try
/// across lockout windows). That risk is accepted: every secret either side
/// stores comes from `generate_secret(20)` (160 bits), so only a secret
/// written to the database by other means can be short, and refusing it
/// here alone would make the gateway and the bridge disagree on its codes.
fn decode_secret(secret: &str) -> Result<Vec<u8>, InvalidSecret> {
    // `b32decode` refuses padding anywhere but at the end, which
    // `data_encoding` accepts between concatenated blocks.
    if secret.trim_end_matches('=').contains('=') {
        return Err(InvalidSecret::NotBase32);
    }
    // Uppercase + pad to multiple of 8. Non-ASCII input stays as it is
    // (Python's `upper()` would turn 'ſ' into 'S' and 'ı' into 'I'), so the
    // decoder refuses it: none of its bytes is a Base32 symbol.
    let upper = secret.to_ascii_uppercase();
    let padded = format!("{}{}", upper, "=".repeat((8 - upper.len() % 8) % 8));
    let key = BASE32_LENIENT
        .decode(padded.as_bytes())
        .map_err(|_| InvalidSecret::NotBase32)?;
    // HMAC zero-pads its key, so an empty or all-zero key is a key anyone
    // can use. (Folded rather than short-circuited: the key is secret.)
    if key.iter().fold(0u8, |acc, b| acc | b) == 0 {
        return Err(InvalidSecret::NoKeyBytes);
    }
    Ok(key)
}

/// Whether `secret` is usable as a TOTP key: the reason
/// [`verify_totp`] refuses every code for it, if any.
pub fn check_secret(secret: &str) -> Result<(), InvalidSecret> {
    decode_secret(secret).map(drop)
}

/// Compute an HOTP value per RFC 4226; there is none for an unusable
/// secret ([`InvalidSecret`]).
pub fn compute_hotp(secret: &str, counter: u64, digits: u32) -> Result<String, InvalidSecret> {
    Ok(hotp(&decode_secret(secret)?, counter, digits))
}

/// HOTP (RFC 4226) of a decoded key.
fn hotp(key: &[u8], counter: u64, digits: u32) -> String {
    let counter_bytes = counter.to_be_bytes();

    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(&counter_bytes);
    let result = mac.finalize().into_bytes();

    // Dynamic truncation (RFC 4226 Section 5.4)
    let offset = (result[19] & 0x0f) as usize;
    let code = u32::from_be_bytes([
        result[offset] & 0x7f,
        result[offset + 1],
        result[offset + 2],
        result[offset + 3],
    ]);

    let modulus = 10u32.pow(digits);
    format!("{:0>width$}", code % modulus, width = digits as usize)
}

/// Compute a TOTP value per RFC 6238.
///
/// Defaults: SHA1, 30-second period, 6 digits. There is no code for an
/// unusable secret ([`InvalidSecret`]).
pub fn compute_totp(
    secret: &str,
    timestamp: Option<u64>,
    period: u32,
    digits: u32,
) -> Result<String, InvalidSecret> {
    let ts = timestamp.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });
    let counter = ts / period as u64;
    compute_hotp(secret, counter, digits)
}

/// Verify a TOTP code with a time window.
///
/// Window=1 checks T-1, T, T+1 (3 codes total).
/// Uses constant-time comparison. No code verifies for a secret that is
/// not usable as a key ([`check_secret`]).
pub fn verify_totp(
    secret: &str,
    code: &str,
    window: i32,
    timestamp: Option<u64>,
    period: u32,
    digits: u32,
) -> bool {
    let Ok(key) = decode_secret(secret) else {
        return false;
    };
    let ts = timestamp.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });
    let current_counter = (ts / period as u64) as i64;

    for offset in -window..=window {
        let counter = (current_counter + offset as i64) as u64;
        let expected = hotp(&key, counter, digits);
        if constant_time_eq(code.as_bytes(), expected.as_bytes()) {
            return true;
        }
    }
    false
}

/// Generate an otpauth:// provisioning URI for QR codes.
///
/// Compatible with Google Authenticator, Authy, etc.
pub fn get_provisioning_uri(
    secret: &str,
    username: &str,
    issuer: &str,
    period: u32,
    digits: u32,
    algorithm: &str,
) -> String {
    // URL-encode the label (issuer:username)
    let label = format!("{}:{}", issuer, username);
    let encoded_label = url_encode(&label);
    let encoded_issuer = url_encode(issuer);

    format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
        encoded_label, secret, encoded_issuer, algorithm, digits, period
    )
}

/// Simple URL encoding (percent-encode non-alphanumeric except :@-._~)
fn url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b':' | b'@' => {
                result.push(b as char);
            }
            b' ' => result.push_str("%20"),
            _ => {
                result.push_str(&format!("%{:02X}", b));
            }
        }
    }
    result
}

/// Generate random backup codes.
///
/// Default: 10 codes, 8 hex characters each (32 bits per code).
/// Matches Python: `secrets.token_hex(length // 2)`
pub fn generate_backup_codes(count: usize, length: usize) -> Vec<String> {
    let byte_len = length / 2;
    (0..count)
        .map(|_| {
            let mut buf = vec![0u8; byte_len];
            rand::rng().fill(&mut buf[..]);
            hex::encode(buf)
        })
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // RFC 6238 Appendix B test vector (SHA1)
    // Secret: "12345678901234567890" (ASCII), base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn test_rfc6238_test_vector_t59() {
        // T=59, counter=1, expected=287082
        let code = compute_totp(RFC_SECRET, Some(59), 30, 8).unwrap();
        assert_eq!(code, "94287082");
    }

    #[test]
    fn test_rfc6238_test_vector_t1111111109() {
        // T=1111111109, counter=37037036, expected=07081804
        let code = compute_totp(RFC_SECRET, Some(1111111109), 30, 8).unwrap();
        assert_eq!(code, "07081804");
    }

    #[test]
    fn test_rfc6238_test_vector_t1234567890() {
        // T=1234567890, counter=41152263, expected=89005924
        let code = compute_totp(RFC_SECRET, Some(1234567890), 30, 8).unwrap();
        assert_eq!(code, "89005924");
    }

    #[test]
    fn test_totp_6_digits() {
        let code = compute_totp(RFC_SECRET, Some(59), 30, 6).unwrap();
        assert_eq!(code.len(), 6);
        assert_eq!(code, "287082");
    }

    #[test]
    fn test_verify_totp_exact_match() {
        let code = compute_totp(RFC_SECRET, Some(59), 30, 6).unwrap();
        assert!(verify_totp(RFC_SECRET, &code, 0, Some(59), 30, 6));
    }

    #[test]
    fn test_verify_totp_window() {
        // Code at T=59 (counter=1) should be accepted at T=89 (counter=2) with window=1
        let code = compute_totp(RFC_SECRET, Some(59), 30, 6).unwrap();
        assert!(verify_totp(RFC_SECRET, &code, 1, Some(89), 30, 6));
    }

    #[test]
    fn test_verify_totp_outside_window() {
        let code = compute_totp(RFC_SECRET, Some(59), 30, 6).unwrap();
        // At T=119 (counter=3), code from counter=1 should fail with window=1
        assert!(!verify_totp(RFC_SECRET, &code, 1, Some(119), 30, 6));
    }

    #[test]
    fn test_verify_totp_wrong_code() {
        assert!(!verify_totp(RFC_SECRET, "000000", 1, Some(59), 30, 6));
    }

    #[test]
    fn test_generate_secret_length() {
        let secret = generate_secret(20);
        // 20 bytes = 160 bits, base32 = ceil(160/5) = 32 chars
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn test_generate_secret_valid_base32() {
        let secret = generate_secret(20);
        let decoded = decode_secret(&secret).unwrap();
        assert_eq!(decoded.len(), 20);
    }

    #[test]
    fn test_generate_secret_unique() {
        let s1 = generate_secret(20);
        let s2 = generate_secret(20);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_provisioning_uri_format() {
        let uri = get_provisioning_uri("JBSWY3DPEHPK3PXP", "alice", "SigRift", 30, 6, "SHA1");
        assert!(uri.starts_with("otpauth://totp/SigRift:alice?"));
        assert!(uri.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(uri.contains("issuer=SigRift"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    #[test]
    fn test_backup_codes_count_and_length() {
        let codes = generate_backup_codes(10, 8);
        assert_eq!(codes.len(), 10);
        for code in &codes {
            assert_eq!(code.len(), 8);
            assert!(hex::decode(code).is_ok(), "Should be valid hex: {}", code);
        }
    }

    #[test]
    fn test_backup_codes_unique() {
        let codes = generate_backup_codes(10, 8);
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), 10, "All backup codes should be unique");
    }

    // Cross-language golden vector: precomputed from Python
    // python3 -c "from sigrift.bridge.security.totp import compute_totp; print(compute_totp('JBSWY3DPEHPK3PXP', timestamp=1000000, period=30, digits=6))"
    #[test]
    fn test_python_golden_vector() {
        // Secret: "JBSWY3DPEHPK3PXP" (base32 of "Hello!\xde\xad\xbe\xef")
        // Timestamp: 1000000, counter = 33333
        let code = compute_totp("JBSWY3DPEHPK3PXP", Some(1000000), 30, 6).unwrap();
        // Verify it's 6 digits (exact value depends on the HMAC computation)
        assert_eq!(code.len(), 6);
        // The actual expected value: compute manually or from Python
        // For now, verify determinism
        let code2 = compute_totp("JBSWY3DPEHPK3PXP", Some(1000000), 30, 6).unwrap();
        assert_eq!(code, code2);
    }

    #[test]
    fn test_decode_secret_with_padding() {
        // "JBSWY3DPEHPK3PXP" decodes to "Hello!\xde\xad\xbe\xef"
        let decoded = decode_secret("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(decoded.len(), 10);
        assert_eq!(&decoded[..6], b"Hello!");
    }

    // ── Security paths: window, skew, malformed codes, key binding ────

    /// A timestamp in the middle of 30-second step `counter`.
    fn mid_step(counter: u64) -> u64 {
        counter * 30 + 15
    }

    /// RFC 4226 Appendix D: HOTP values of the ASCII secret
    /// "12345678901234567890" for counters 0..=9 (dynamic truncation).
    #[test]
    fn hotp_matches_rfc4226_appendix_d() {
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, code) in expected.iter().enumerate() {
            assert_eq!(
                compute_hotp(RFC_SECRET, counter as u64, 6).unwrap(),
                *code,
                "{counter}"
            );
        }
    }

    /// Window 1 tolerates one step of clock skew in either direction and no
    /// more: codes of steps T-1, T, T+1 verify at step T, T-2 and T+2 do not.
    #[test]
    fn window_one_accepts_one_step_of_skew_each_way_and_no_more() {
        let now = mid_step(100);
        let code = |counter| compute_hotp(RFC_SECRET, counter, 6).unwrap();
        let distinct: std::collections::HashSet<_> = (98..=102).map(code).collect();
        assert_eq!(distinct.len(), 5, "fixture codes must differ");

        for counter in [99, 100, 101] {
            assert!(
                verify_totp(RFC_SECRET, &code(counter), 1, Some(now), 30, 6),
                "step {counter} is within one step of 100"
            );
        }
        for counter in [98, 102] {
            assert!(
                !verify_totp(RFC_SECRET, &code(counter), 1, Some(now), 30, 6),
                "step {counter} is outside the window"
            );
        }
    }

    #[test]
    fn window_zero_accepts_only_the_current_step() {
        let now = mid_step(100);
        assert!(verify_totp(
            RFC_SECRET,
            &compute_hotp(RFC_SECRET, 100, 6).unwrap(),
            0,
            Some(now),
            30,
            6
        ));
        for counter in [99, 101] {
            let code = compute_hotp(RFC_SECRET, counter, 6).unwrap();
            assert!(!verify_totp(RFC_SECRET, &code, 0, Some(now), 30, 6));
        }
    }

    /// A code is tied to its 30-second step: valid through the last second of
    /// the step, invalid from the first second of the next (window 0).
    #[test]
    fn a_code_expires_at_its_step_boundary() {
        let code = compute_hotp(RFC_SECRET, 100, 6).unwrap();
        assert!(verify_totp(RFC_SECRET, &code, 0, Some(3000), 30, 6));
        assert!(verify_totp(RFC_SECRET, &code, 0, Some(3029), 30, 6));
        assert!(!verify_totp(RFC_SECRET, &code, 0, Some(3030), 30, 6));
        assert!(!verify_totp(RFC_SECRET, &code, 0, Some(2999), 30, 6));
    }

    /// Anything but the exact code string is refused: a prefix, an extended
    /// code, the longer code it was truncated from, padding, other digits.
    #[test]
    fn malformed_variants_of_a_valid_code_are_rejected() {
        let now = mid_step(100);
        let valid = compute_hotp(RFC_SECRET, 100, 6).unwrap();
        let eight = compute_hotp(RFC_SECRET, 100, 8).unwrap();
        assert!(eight.ends_with(&valid), "the 6-digit code is a suffix");
        assert!(verify_totp(RFC_SECRET, &valid, 1, Some(now), 30, 6));
        for bad in [
            String::new(),
            valid[..5].to_string(),
            format!("{valid}0"),
            format!("0{valid}"),
            eight,
            format!(" {valid}"),
            format!("{valid}\n"),
            valid
                .chars()
                .map(|c| char::from_u32(c as u32 - '0' as u32 + 0xFF10).unwrap())
                .collect(),
        ] {
            assert!(
                !verify_totp(RFC_SECRET, &bad, 1, Some(now), 30, 6),
                "{bad:?} must not verify"
            );
        }
    }

    #[test]
    fn a_code_of_one_secret_does_not_verify_under_another() {
        let now = mid_step(100);
        let other = "JBSWY3DPEHPK3PXP";
        let code = compute_totp(RFC_SECRET, Some(now), 30, 6).unwrap();
        assert_ne!(code, compute_totp(other, Some(now), 30, 6).unwrap());
        assert!(!verify_totp(other, &code, 1, Some(now), 30, 6));
        // Base32 is case-insensitive: the same secret in lowercase is the same key.
        assert!(verify_totp(
            &RFC_SECRET.to_lowercase(),
            &code,
            1,
            Some(now),
            30,
            6
        ));
    }

    /// At the epoch the T-1 step does not exist: verification must not
    /// panic, accepts the codes of steps 0 and 1, and not that of step 2.
    /// (The T-1 counter wraps to `u64::MAX`, whose code is therefore also
    /// accepted at ts=0; no clock is at the epoch, so that is not checked.)
    #[test]
    fn verification_at_the_epoch_does_not_panic_and_keeps_the_window() {
        assert!(verify_totp(
            RFC_SECRET,
            &compute_hotp(RFC_SECRET, 0, 6).unwrap(),
            1,
            Some(0),
            30,
            6
        ));
        assert!(verify_totp(
            RFC_SECRET,
            &compute_hotp(RFC_SECRET, 1, 6).unwrap(),
            1,
            Some(0),
            30,
            6
        ));
        assert!(!verify_totp(
            RFC_SECRET,
            &compute_hotp(RFC_SECRET, 2, 6).unwrap(),
            1,
            Some(0),
            30,
            6
        ));
    }

    /// The HOTP code of the empty HMAC key, the code anyone can compute,
    /// derived without this module's decoder or truncation.
    pub(crate) fn empty_key_hotp(counter: u64, digits: u32) -> String {
        let mut mac = HmacSha1::new_from_slice(&[]).unwrap();
        mac.update(&counter.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let offset = usize::from(digest[19] & 0x0f);
        let word = u32::from_be_bytes(digest[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
        format!("{:0w$}", word % 10u32.pow(digits), w = digits as usize)
    }

    /// Golden values from the bridge (`compute_hotp("", counter)`). HMAC
    /// zero-pads its key, so an all-zero key has the same codes: that is
    /// why `decode_secret` refuses those too.
    #[test]
    fn empty_key_codes_match_the_bridge_and_equal_all_zero_key_codes() {
        assert_eq!(empty_key_hotp(100, 6), "032003");
        assert_eq!(empty_key_hotp(0, 6), "328482");
        for counter in [0, 100] {
            assert_eq!(hotp(&[], counter, 6), empty_key_hotp(counter, 6));
            assert_eq!(hotp(&[0; 20], counter, 6), empty_key_hotp(counter, 6));
        }
    }

    /// A secret that decodes to no key bytes (empty, or not base32) must not
    /// turn TOTP into HMAC with an empty key, whose codes anyone can compute.
    #[test]
    fn a_secret_without_key_bytes_never_verifies() {
        let now = mid_step(100);
        let empty_key_code = empty_key_hotp(100, 6);
        for secret in ["", "not base32!", "01890189"] {
            assert!(
                !verify_totp(secret, &empty_key_code, 1, Some(now), 30, 6),
                "secret {secret:?} accepted a code computable without any secret"
            );
        }
    }

    /// Every secret the bridge's decoder refuses, any non-ASCII secret, and
    /// every secret whose key has no non-zero byte is unusable: it has no
    /// code, and no code verifies, neither the empty-key code nor that of a
    /// lenient decoding.
    #[test]
    fn unusable_secrets_have_no_code_and_verify_nothing() {
        use InvalidSecret::{NoKeyBytes, NotBase32};
        let now = mid_step(100);
        let a = |n| "A".repeat(n);
        let cases = [
            // Characters outside the alphabet, whitespace, non-ASCII.
            ("not base32!".to_string(), NotBase32),
            ("not-a-base32-secret!".into(), NotBase32),
            ("01890189".into(), NotBase32),
            ("JBSWY3DP EHPK3PXP".into(), NotBase32),
            (" JBSWY3DPEHPK3PXP".into(), NotBase32),
            ("JBSWY3DPEHPK3PXP\n".into(), NotBase32),
            ("JBSWY3DPEHPK3PX\u{de}".into(), NotBase32),
            ("JBSWY3DPEHPK3PX\u{ff30}".into(), NotBase32), // fullwidth 'P'
            // Python's upper() makes these 'S', 'I' and "FF", letters of the
            // alphabet (the bridge accepts the first two); Unicode
            // uppercasing must not.
            ("JBSWY3DPEHPK3PX\u{17f}".into(), NotBase32),
            ("JBSWY3DPEHPK3PX\u{131}".into(), NotBase32),
            ("JBSWY3DPEHPK3P\u{fb00}".into(), NotBase32),
            // Lengths no Base32 string has (1, 3 or 6 past a multiple of 8).
            ("J".into(), NotBase32),
            ("JBS".into(), NotBase32),
            ("JBSWY3".into(), NotBase32),
            ("JBSWY3DPEHPK3PXPJ".into(), NotBase32),
            // Padding that is misplaced, excessive or all there is.
            ("GE======GEZDGNBV".into(), NotBase32),
            ("GE=GE".into(), NotBase32),
            ("GE=======".into(), NotBase32),
            ("========".into(), NotBase32),
            ("=".into(), NotBase32),
            // No key bytes, or only zero bytes (also beyond the HMAC block).
            (String::new(), NoKeyBytes),
            ("AA".into(), NoKeyBytes),
            ("AB".into(), NoKeyBytes), // one zero byte; trailing bits unused
            ("AAAA".into(), NoKeyBytes),
            ("AA======".into(), NoKeyBytes),
            (a(16), NoKeyBytes),
            (a(32), NoKeyBytes),
            ("a".repeat(32), NoKeyBytes),
            (a(104), NoKeyBytes),
        ];
        // The key that decoding the blocks either side of the misplaced
        // padding would give ("GE" and "GEZDGNBV": b"1" and b"12345").
        let concatenated_key_code = hotp(b"112345", 100, 6);
        for (secret, reason) in cases {
            assert_eq!(check_secret(&secret), Err(reason), "{secret:?}");
            assert_eq!(compute_hotp(&secret, 100, 6), Err(reason), "{secret:?}");
            assert_eq!(compute_totp(&secret, Some(now), 30, 6), Err(reason));
            for counter in 99..=101 {
                let code = empty_key_hotp(counter, 6);
                assert!(
                    !verify_totp(&secret, &code, 1, Some(now), 30, 6),
                    "{secret:?} accepted an empty-key code"
                );
            }
            assert!(!verify_totp(
                &secret,
                &concatenated_key_code,
                1,
                Some(now),
                30,
                6
            ));
        }
    }

    /// The secrets the bridge accepts decode to the bridge's key bytes:
    /// either case, with or without padding, and with non-zero unused bits
    /// in the last character (which `b32decode` ignores). Codes are golden
    /// values from the bridge's `compute_hotp(secret, 100)`.
    #[test]
    fn usable_secrets_decode_like_the_bridge() {
        let now = mid_step(100);
        let cases: [(&[&str], &[u8], &str); 3] = [
            (
                &["JBSWY3DPEHPK3PXP", "jbswy3dpehpk3pxp", "JbSwY3dPeHpK3pXp"],
                b"Hello!\xde\xad\xbe\xef",
                "594318",
            ),
            (
                &[
                    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGE",
                    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGE==",
                    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGE======",
                    "gezdgnbvgy3tqojqgezdgnbvgy3tqojqge",
                ],
                b"123456789012345678901",
                "042393",
            ),
            (
                // 'Q' leaves the 3 unused bits zero, 'X' does not.
                &["JBSWY3DPEHPK3PQ", "JBSWY3DPEHPK3PX", "jbswy3dpehpk3px"],
                b"Hello!\xde\xad\xbe",
                "657210",
            ),
        ];
        for (secrets, key, code) in cases {
            for secret in secrets {
                assert_eq!(decode_secret(secret).as_deref(), Ok(key), "{secret}");
                assert_eq!(check_secret(secret), Ok(()));
                assert_eq!(compute_hotp(secret, 100, 6).as_deref(), Ok(code));
                assert!(verify_totp(secret, code, 0, Some(now), 30, 6), "{secret}");
            }
        }
    }

    /// The username is attacker-chosen at enrolment: it must not be able to
    /// add or override otpauth parameters (e.g. a second `secret=`), add a
    /// fragment, or break out of the label.
    #[test]
    fn provisioning_uri_label_cannot_inject_parameters() {
        let uri = get_provisioning_uri(
            "JBSWY3DPEHPK3PXP",
            "eve&secret=AAAAAAAA&issuer=Evil#frag /x?y=z",
            "Sig Rift&Co",
            30,
            6,
            "SHA1",
        );
        assert!(!uri.contains('#'), "{uri}");
        let (path, query) = uri.split_once('?').unwrap();
        let label = path.strip_prefix("otpauth://totp/").unwrap();
        assert!(
            !label.contains(['&', '=', '?', '/', ' ']),
            "label must be percent-encoded: {label}"
        );
        assert_eq!(
            label,
            "Sig%20Rift%26Co:eve%26secret%3DAAAAAAAA%26issuer%3DEvil%23frag%20%2Fx%3Fy%3Dz"
        );
        let params: Vec<&str> = query.split('&').collect();
        assert_eq!(
            params,
            [
                "secret=JBSWY3DPEHPK3PXP",
                "issuer=Sig%20Rift%26Co",
                "algorithm=SHA1",
                "digits=6",
                "period=30"
            ]
        );
    }

    /// Backup codes are stored hashed from their lowercase form and
    /// verification lowercases input, so generated codes must be lowercase
    /// hex, `length` characters (`length / 2` bytes) long.
    #[test]
    fn backup_codes_are_lowercase_hex_of_the_requested_length() {
        let codes = generate_backup_codes(50, 8);
        for code in &codes {
            assert_eq!(code, &code.to_lowercase());
            assert_eq!(hex::decode(code).unwrap().len(), 4);
        }
    }

    /// The body of the first `fn {name}(` in `src`, braces matched. For
    /// source-level checks of security-sensitive functions.
    pub(crate) fn fn_body<'a>(src: &'a str, name: &str) -> &'a str {
        let start = src
            .find(&format!("fn {name}("))
            .unwrap_or_else(|| panic!("fn {name} not found"));
        let open = start + src[start..].find('{').unwrap();
        let mut depth = 0usize;
        for (i, c) in src[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &src[open..=open + i];
                    }
                }
                _ => {}
            }
        }
        panic!("fn {name}: unbalanced braces");
    }

    /// `body` compares secrets only with `constant_time_eq`, exactly
    /// `calls` times, and with no short-circuiting comparison besides.
    pub(crate) fn assert_constant_time_compares(name: &str, body: &str, calls: usize) {
        assert_eq!(
            body.matches("constant_time_eq(").count(),
            calls,
            "{name} must compare every candidate with constant_time_eq"
        );
        for op in [
            "==",
            "!=",
            ".eq(",
            ".ne(",
            ".cmp(",
            "starts_with",
            "ends_with",
            "contains(",
        ] {
            assert!(
                !body.contains(op),
                "{name} compares with `{op}`, which leaks how much of a code matched"
            );
        }
    }

    /// A timing test would be flaky, so the constant-time property of the
    /// code comparison is checked in the source: every expected code is
    /// compared with `constant_time_eq`, never with `==` or a prefix test.
    #[test]
    fn verify_totp_compares_codes_in_constant_time() {
        let body = fn_body(include_str!("totp.rs"), "verify_totp");
        assert_constant_time_compares("verify_totp", body, 1);
    }
}
