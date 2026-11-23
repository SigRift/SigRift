//! Password hashing and session token hashing — parity with Python credentials.py.
//!
//! PBKDF2-HMAC-SHA256 (600K iterations, 32-byte output) for passwords.
//! SHA-256 for session token storage hashing.
//! Legacy salted-SHA-256 fallback for pre-migration credentials.

use constant_time_eq::constant_time_eq;
use pbkdf2::pbkdf2_hmac;
use rand::RngExt;
use sha2::{Digest, Sha256};

const PBKDF2_ITERATIONS: u32 = 600_000;
const PBKDF2_DKLEN: usize = 32;
const SALT_LEN: usize = 32;

/// Hash a credential with PBKDF2-HMAC-SHA256.
///
/// Returns `(hex_hash, salt_bytes)`. If `salt` is `None`, generates 32
/// cryptographically random bytes.
///
/// Matches Python: `hashlib.pbkdf2_hmac("sha256", cred.encode("utf-8"), salt, 600_000, dklen=32)`
pub fn hash_credential(credential: &str, salt: Option<&[u8]>) -> (String, Vec<u8>) {
    let salt_bytes = match salt {
        Some(s) => s.to_vec(),
        None => {
            let mut buf = vec![0u8; SALT_LEN];
            rand::rng().fill(&mut buf);
            buf
        }
    };
    let mut dk = [0u8; PBKDF2_DKLEN];
    pbkdf2_hmac::<Sha256>(
        credential.as_bytes(),
        &salt_bytes,
        PBKDF2_ITERATIONS,
        &mut dk,
    );
    (hex::encode(dk), salt_bytes)
}

/// Verify a credential against a stored hash and salt.
///
/// Tries PBKDF2 first, then legacy SHA-256 fallback if the hash is 64 hex
/// chars and PBKDF2 didn't match.
///
/// Returns `(matches, is_legacy)` — the caller can use `is_legacy` to trigger
/// a transparent upgrade to PBKDF2.
pub fn verify_credential(credential: &str, expected_hash: &str, salt: &[u8]) -> (bool, bool) {
    // Try PBKDF2 first (current format)
    let (computed, _) = hash_credential(credential, Some(salt));
    if constant_time_eq(computed.as_bytes(), expected_hash.as_bytes()) {
        return (true, false);
    }

    // Legacy SHA-256 fallback: SHA256(salt || credential_bytes)
    if expected_hash.len() == 64 && verify_legacy_sha256(credential, expected_hash, salt) {
        return (true, true);
    }

    (false, false)
}

/// SHA-256 hex digest of a string (used for session token hashing).
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Legacy salted-SHA-256 verification: `SHA-256(salt_bytes || credential_bytes)`.
///
/// Matches Python:
/// ```python
/// h = hashlib.sha256()
/// h.update(salt)
/// h.update(credential.encode("utf-8"))
/// hmac.compare_digest(h.hexdigest(), expected_hash)
/// ```
fn verify_legacy_sha256(credential: &str, expected_hash: &str, salt: &[u8]) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(credential.as_bytes());
    let computed = hex::encode(hasher.finalize());
    constant_time_eq(computed.as_bytes(), expected_hash.as_bytes())
}

/// SHA-256 hash a session token for database storage.
///
/// Matches Python: `hashlib.sha256(token.encode("utf-8")).hexdigest()`
pub fn hash_session_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate a cryptographically random session token (64 hex chars).
///
/// Python uses `secrets.token_urlsafe(32)` (~43 chars URL-safe base64), but
/// the token format doesn't need to match — only its SHA-256 hash is stored
/// and compared cross-language.
pub fn generate_session_token() -> String {
    let mut buf = [0u8; 32];
    rand::rng().fill(&mut buf);
    hex::encode(buf)
}

/// Decode a salt value from SQLite that may be stored as BLOB or TEXT.
///
/// Python passes raw `bytes` to SQLite's `TEXT NOT NULL` column via parameter
/// binding — SQLite stores these as BLOB. Some rows may contain hex-encoded
/// strings from the Rust API key path.
///
/// Handles:
/// - `ValueRef::Blob` → raw bytes (Python-created rows)
/// - `ValueRef::Text` → try hex decode, fallback to raw UTF-8 bytes
pub fn decode_salt(value: &rusqlite::types::ValueRef<'_>) -> Option<Vec<u8>> {
    match value {
        rusqlite::types::ValueRef::Blob(b) => Some(b.to_vec()),
        rusqlite::types::ValueRef::Text(s) => {
            let text = std::str::from_utf8(s).ok()?;
            // Try hex decode first (Rust API key path stores hex)
            hex::decode(text)
                .ok()
                .or_else(|| Some(text.as_bytes().to_vec()))
        }
        _ => None,
    }
}

/// Validate password strength.
///
/// Requirements: 8-128 chars, at least one uppercase, one lowercase, one digit.
///
/// The length is counted in characters (Unicode scalar values, i.e.
/// Python's `len()`, as the bridge's `min_length=8` / `max_length=128`
/// count), not UTF-8 bytes, and without normalisation (which would change
/// the PBKDF2 input).
pub fn validate_password_strength(password: &str) -> Result<(), String> {
    let length = password.chars().count();
    if length < 8 {
        return Err("Password must be at least 8 characters".into());
    }
    if length > 128 {
        return Err("Password must not exceed 128 characters".into());
    }
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Err("Password must contain at least one uppercase letter".into());
    }
    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        return Err("Password must contain at least one lowercase letter".into());
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err("Password must contain at least one digit".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors precomputed from Python:
    //   from sigrift.lib.security.credentials import hash_credential
    //   import hashlib

    #[test]
    fn test_pbkdf2_golden_vector() {
        let salt = vec![0xaa; 32];
        let (hash, _) = hash_credential("test_password", Some(&salt));
        assert_eq!(
            hash,
            "c23370bdfca8944baf8868776098f74c72a43de350d49fc65c0d3000ab9d7669"
        );
    }

    #[test]
    fn test_pbkdf2_empty_password() {
        let salt = vec![0xaa; 32];
        let (hash, _) = hash_credential("", Some(&salt));
        assert_eq!(
            hash,
            "3fd018bf1a05270c2090838599e048434be4c771712c807de2ff3f8e357b3e16"
        );
    }

    #[test]
    fn test_pbkdf2_unicode_password() {
        let salt = vec![0xaa; 32];
        let (hash, _) = hash_credential("pässwörd", Some(&salt));
        assert_eq!(
            hash,
            "a4200d960ccc63a8cbefe155417954d53a14099f9bf1b904b71343720578078a"
        );
    }

    #[test]
    fn test_legacy_sha256_golden_vector() {
        let salt = vec![0xbb; 32];
        let expected = "226a301654835f8b229491de1c4bcdfb5c6f0fc3372d49550247adf47e909230";
        let (matches, is_legacy) = verify_credential("legacy_pass", expected, &salt);
        assert!(matches);
        assert!(is_legacy);
    }

    #[test]
    fn test_session_token_hash_golden_vector() {
        let hash = hash_session_token("test_token_abc");
        assert_eq!(
            hash,
            "4419a8f8e923f3a3252e8a8ef5828122c81f83c24213ac19e426e7cd0dd4369c"
        );
    }

    #[test]
    fn test_pbkdf2_roundtrip() {
        let (hash, salt) = hash_credential("my_password", None);
        assert_eq!(hash.len(), 64);
        assert_eq!(salt.len(), 32);
        let (matches, is_legacy) = verify_credential("my_password", &hash, &salt);
        assert!(matches);
        assert!(!is_legacy);
    }

    #[test]
    fn test_wrong_password_fails() {
        let (hash, salt) = hash_credential("correct", None);
        let (matches, _) = verify_credential("wrong", &hash, &salt);
        assert!(!matches);
    }

    #[test]
    fn test_pbkdf2_not_detected_as_legacy() {
        let (hash, salt) = hash_credential("test", None);
        // Both PBKDF2 and legacy produce 64-char hex, but the correct
        // password should match PBKDF2 first (is_legacy=false).
        let (matches, is_legacy) = verify_credential("test", &hash, &salt);
        assert!(matches);
        assert!(!is_legacy);
    }

    #[test]
    fn test_generate_session_token() {
        let token = generate_session_token();
        assert_eq!(token.len(), 64);
        // Should be valid hex
        assert!(hex::decode(&token).is_ok());
        // Two calls should produce different tokens
        let token2 = generate_session_token();
        assert_ne!(token, token2);
    }

    #[test]
    fn test_decode_salt_blob() {
        let raw = vec![1u8, 2, 3, 4];
        let value = rusqlite::types::Value::Blob(raw.clone());
        let vref = rusqlite::types::ValueRef::from(&value);
        assert_eq!(decode_salt(&vref), Some(raw));
    }

    #[test]
    fn test_decode_salt_hex_text() {
        let hex_str = "aabbccdd";
        let value = rusqlite::types::Value::Text(hex_str.to_string());
        let vref = rusqlite::types::ValueRef::from(&value);
        assert_eq!(decode_salt(&vref), Some(vec![0xaa, 0xbb, 0xcc, 0xdd]));
    }

    #[test]
    fn test_decode_salt_null() {
        let value = rusqlite::types::Value::Null;
        let vref = rusqlite::types::ValueRef::from(&value);
        assert_eq!(decode_salt(&vref), None);
    }

    // ── Password complexity ───────────────────────────────────────────

    #[test]
    fn test_password_complexity_accepts_valid() {
        assert!(validate_password_strength("MyPassw0rd").is_ok());
        assert!(validate_password_strength("Abcdefg1").is_ok());
        assert!(validate_password_strength("Complex1Password!").is_ok());
    }

    #[test]
    fn test_password_complexity_rejects_too_short() {
        assert!(validate_password_strength("Pa1").is_err());
        assert!(validate_password_strength("Abcdef1").is_err());
    }

    #[test]
    fn test_password_complexity_rejects_too_long() {
        let long = format!("A1{}", "a".repeat(127));
        assert!(validate_password_strength(&long).is_err());
    }

    #[test]
    fn test_password_complexity_rejects_no_uppercase() {
        assert!(validate_password_strength("password1").is_err());
    }

    #[test]
    fn test_password_complexity_rejects_no_lowercase() {
        assert!(validate_password_strength("PASSWORD1").is_err());
    }

    #[test]
    fn test_password_complexity_rejects_no_digit() {
        assert!(validate_password_strength("Password").is_err());
    }

    // ── Verification fails closed ─────────────────────────────────────

    const LEGACY_SALT: [u8; 32] = [0xbb; 32];
    const LEGACY_HASH: &str = "226a301654835f8b229491de1c4bcdfb5c6f0fc3372d49550247adf47e909230";

    /// The legacy SHA-256 fallback accepts only the exact password and salt
    /// it was made from, and never reports a legacy match on failure (which
    /// would trigger a re-hash).
    #[test]
    fn legacy_fallback_rejects_wrong_password_or_salt() {
        assert_eq!(
            verify_credential("legacy_pass ", LEGACY_HASH, &LEGACY_SALT),
            (false, false)
        );
        assert_eq!(
            verify_credential("Legacy_pass", LEGACY_HASH, &LEGACY_SALT),
            (false, false)
        );
        assert_eq!(
            verify_credential("legacy_pass", LEGACY_HASH, &[0xbc; 32]),
            (false, false)
        );
    }

    /// A blank, truncated or padded stored hash never verifies, even for an
    /// empty password with an empty salt.
    #[test]
    fn malformed_stored_hash_never_matches() {
        let salt = vec![0xaa; 32];
        let good = "c23370bdfca8944baf8868776098f74c72a43de350d49fc65c0d3000ab9d7669";
        assert_eq!(verify_credential("", "", &[]), (false, false));
        let padded = format!("{good}0");
        for stored in ["", &good[..63], padded.as_str()] {
            assert_eq!(
                verify_credential("test_password", stored, &salt),
                (false, false),
                "{stored:?}"
            );
        }
    }

    /// Each fresh hash gets its own random salt, so equal passwords do not
    /// produce equal stored hashes, and the salt really takes part in the
    /// hash (the right password with another account's salt fails).
    #[test]
    fn fresh_hashes_use_unique_salts() {
        let (h1, s1) = hash_credential("Same-Passw0rd", None);
        let (h2, s2) = hash_credential("Same-Passw0rd", None);
        assert_eq!(s1.len(), SALT_LEN);
        assert_ne!(s1, s2);
        assert_ne!(h1, h2);
        assert_eq!(verify_credential("Same-Passw0rd", &h1, &s2), (false, false));
    }

    #[test]
    fn sha256_hex_golden_vectors() {
        assert_eq!(
            sha256_hex("test_token_abc"),
            hash_session_token("test_token_abc")
        );
        assert_eq!(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// Text salts that are not hex are kept as their raw bytes (never
    /// collapsed to an empty salt); non-text, non-blob values give no salt.
    #[test]
    fn decode_salt_text_and_unsupported_values() {
        for text in ["not-hex!", "abc"] {
            let value = rusqlite::types::Value::Text(text.to_string());
            let vref = rusqlite::types::ValueRef::from(&value);
            assert_eq!(decode_salt(&vref), Some(text.as_bytes().to_vec()));
        }
        for value in [
            rusqlite::types::Value::Integer(7),
            rusqlite::types::Value::Real(1.5),
        ] {
            assert_eq!(decode_salt(&rusqlite::types::ValueRef::from(&value)), None);
        }
    }

    // ── Password policy ───────────────────────────────────────────────

    #[test]
    fn password_length_boundaries() {
        let of_len = |n: usize| format!("Aa1{}", "x".repeat(n - 3));
        assert!(validate_password_strength("").is_err());
        assert!(validate_password_strength(&of_len(7)).is_err());
        assert!(validate_password_strength(&of_len(8)).is_ok());
        assert!(validate_password_strength(&of_len(128)).is_ok());
        assert!(validate_password_strength(&of_len(129)).is_err());
    }

    /// The policy error is returned to API clients: it must not echo the
    /// rejected password.
    #[test]
    fn policy_errors_do_not_echo_the_password() {
        for weak in ["Sh0rt", "alllowercase1", "ALLUPPERCASE1", "NoDigitsHere"] {
            let err = validate_password_strength(weak).unwrap_err();
            assert!(!err.contains(weak), "{err}");
        }
    }

    /// The limits are 8 and 128 characters (the bridge's `min_length=8` /
    /// `max_length=128` count characters too), however many bytes the
    /// characters take: a 7-character multibyte password is refused, and a
    /// multibyte one of 8 to 128 characters (up to 253 bytes) is accepted,
    /// while 129 characters is refused.
    #[test]
    fn password_length_limits_count_characters_not_bytes() {
        let of_chars = |n: usize| format!("Aa1{}", "\u{e9}".repeat(n - 3));
        assert_eq!(of_chars(129).chars().count(), 129);
        assert!(validate_password_strength(&of_chars(7)).is_err());
        assert!(validate_password_strength(&of_chars(8)).is_ok());
        assert!(validate_password_strength(&of_chars(103)).is_ok());
        assert!(validate_password_strength(&of_chars(128)).is_ok());
        assert!(validate_password_strength(&of_chars(129)).is_err());
    }

    /// Characters are Unicode scalar values, like Python's `len()`: a
    /// 4-byte character outside the BMP (two UTF-16 units) counts once, and
    /// a combining mark counts on its own (code points, not graphemes). The
    /// errors keep their wording and name no part of the password.
    #[test]
    fn password_length_counts_unicode_scalar_values() {
        let astral = |n: usize| format!("Aa1{}", "\u{1f600}".repeat(n - 3));
        assert_eq!(astral(8).len(), 3 + 5 * 4);
        assert_eq!(
            validate_password_strength(&astral(7)).unwrap_err(),
            "Password must be at least 8 characters"
        );
        assert!(validate_password_strength(&astral(8)).is_ok());
        assert!(
            validate_password_strength(&astral(128)).is_ok(),
            "503 bytes"
        );
        assert_eq!(
            validate_password_strength(&astral(129)).unwrap_err(),
            "Password must not exceed 128 characters"
        );

        // "e" + COMBINING ACUTE ACCENT is one grapheme but two characters.
        let combining = format!("Aa1{}x", "e\u{301}".repeat(2));
        assert_eq!(combining.chars().count(), 8);
        assert!(validate_password_strength(&combining).is_ok());
        let combining = format!("Aa1{}", "e\u{301}".repeat(2));
        assert!(
            validate_password_strength(&combining).is_err(),
            "7 characters"
        );

        // The length check still comes first: a short multibyte password is
        // refused for its length even when it also lacks a digit.
        assert_eq!(
            validate_password_strength("Aa\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}").unwrap_err(),
            "Password must be at least 8 characters"
        );
    }

    /// Distinct strings can be the same credential: HMAC (the PBKDF2 PRF)
    /// zero-pads a key shorter than its 64-byte block, so trailing NULs up
    /// to 64 bytes give the same hash under any salt, and the strength
    /// policy accepts them. Whether a password is one already used must
    /// therefore be decided by [`verify_credential`] against the stored
    /// hash, never by comparing strings (change-password relies on this).
    #[test]
    fn trailing_nuls_are_the_same_credential() {
        let password = "Same-passw0rd";
        let padded = format!("{password}{}", "\0".repeat(64 - password.len()));
        assert!(validate_password_strength(&padded).is_ok());
        let (hash, salt) = hash_credential(password, None);
        assert_eq!(verify_credential(&padded, &hash, &salt), (true, false));
        // One byte past the block the key is hashed instead: different.
        let (matches, _) = verify_credential(&format!("{padded}\0"), &hash, &salt);
        assert!(!matches);
    }
}
