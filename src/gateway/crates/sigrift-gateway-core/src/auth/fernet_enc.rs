//! Fernet encryption for TOTP secrets at rest.
//!
//! Implements the Fernet token format (v0x80) for Python compatibility:
//! - AES-128-CBC encryption with PKCS7 padding
//! - HMAC-SHA256 authentication
//! - Key: 32 bytes, base64 (first 16 = signing, last 16 = encryption)
//!
//! # Key rule (shared with the bridge and the installers)
//!
//! After trimming surrounding whitespace, `BRIDGE_MFA_KEY` is valid iff it
//! is exactly 44 characters, the first 43 are from `[A-Za-z0-9-_+/]`, the
//! 44th is `=`, and it base64-decodes (mapping `-`→`+`, `_`→`/`) to 32
//! bytes. That is what Python's `Fernet(key)` (`urlsafe_b64decode`)
//! accepts, so the bridge and the gateway agree on every key and derive the
//! same 32 bytes from it: both alphabets are accepted, and non-zero
//! trailing bits in the 43rd character are ignored, as Python ignores them.
//!
//! A 43-character `[A-Za-z0-9-_]` key that decodes to 32 bytes (what
//! `secrets.token_urlsafe(32)` produces, and what older gateways accepted
//! and may have encrypted with) is **not** valid, but is repaired without
//! loss by appending `=` — see [`repair_legacy_fernet_key`]. The gateway
//! never encrypts with such a key; it still decrypts with it, so secrets
//! written by an older gateway stay readable until the key is repaired.
//!
//! Reference: https://github.com/fernet/spec/blob/master/Spec.md

use std::sync::OnceLock;

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt;
use sha2::Sha256;
use tracing::warn;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type HmacSha256 = Hmac<Sha256>;

const FERNET_VERSION: u8 = 0x80;

/// The command that generates a new Fernet key.
pub const GENERATE_FERNET_KEY_COMMAND: &str =
    "python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'";

/// What to do about an invalid `BRIDGE_MFA_KEY` (shared wording with the
/// bridge and the installers).
pub const FERNET_KEY_REPAIR_HINT: &str = "if the key is 43 characters long, append '=' to keep \
     existing encrypted TOTP secrets readable; otherwise generate a new key with python3 -c \
     'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'";

/// Standard-alphabet, padded base64 that, like Python's decoder, ignores
/// non-zero trailing bits.
fn base64_python_compatible() -> &'static data_encoding::Encoding {
    static ENCODING: OnceLock<data_encoding::Encoding> = OnceLock::new();
    ENCODING.get_or_init(|| {
        let mut spec = data_encoding::BASE64.specification();
        spec.check_trailing_bits = false;
        spec.encoding()
            .expect("BASE64 with relaxed trailing bits is a valid specification")
    })
}

fn is_key_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'+' | b'/')
}

/// The 32 key bytes of a key that satisfies the key rule (module docs), or
/// `None` if it does not.
fn canonical_key_bytes(key: &str) -> Option<[u8; 32]> {
    let key = key.trim().as_bytes();
    if key.len() != 44 || key[43] != b'=' || !key[..43].iter().copied().all(is_key_char) {
        return None;
    }
    let standard: Vec<u8> = key
        .iter()
        .map(|&c| match c {
            b'-' => b'+',
            b'_' => b'/',
            c => c,
        })
        .collect();
    base64_python_compatible()
        .decode(&standard)
        .ok()?
        .try_into()
        .ok()
}

fn split_key(bytes: [u8; 32]) -> ([u8; 16], [u8; 16]) {
    let mut signing = [0u8; 16];
    let mut encryption = [0u8; 16];
    signing.copy_from_slice(&bytes[..16]);
    encryption.copy_from_slice(&bytes[16..]);
    (signing, encryption)
}

/// Key halves (signing, encryption) for **encrypting**: only a key that
/// satisfies the key rule.
fn encryption_key(key: &str) -> Option<([u8; 16], [u8; 16])> {
    canonical_key_bytes(key).map(split_key)
}

/// Key halves for **decrypting**: a valid key, or a repairable legacy
/// 43-character key (the same 32 bytes as its repaired form), so secrets an
/// older gateway encrypted with it stay readable.
fn decryption_key(key: &str) -> Option<([u8; 16], [u8; 16])> {
    canonical_key_bytes(key)
        .or_else(|| repair_legacy_fernet_key(key).and_then(|k| canonical_key_bytes(&k)))
        .map(split_key)
}

/// Generate a Fernet key (for testing).
#[cfg(test)]
fn generate_key() -> String {
    let mut key = [0u8; 32];
    rand::rng().fill(&mut key);
    let mut encoded = data_encoding::BASE64URL_NOPAD.encode(&key);
    encoded.push('=');
    encoded
}

/// Encrypt data using Fernet token format.
fn fernet_encrypt(plaintext: &[u8], signing_key: &[u8; 16], encryption_key: &[u8; 16]) -> String {
    let mut iv = [0u8; 16];
    rand::rng().fill(&mut iv);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Encrypt with AES-128-CBC + PKCS7 padding
    let ciphertext = Aes128CbcEnc::new(encryption_key.into(), &iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    // Build token: version(1) || timestamp(8) || iv(16) || ciphertext(N)
    let mut token_data = Vec::with_capacity(1 + 8 + 16 + ciphertext.len());
    token_data.push(FERNET_VERSION);
    token_data.extend_from_slice(&timestamp.to_be_bytes());
    token_data.extend_from_slice(&iv);
    token_data.extend_from_slice(&ciphertext);

    // HMAC-SHA256 over the token data
    let mut mac = HmacSha256::new_from_slice(signing_key).unwrap();
    mac.update(&token_data);
    let hmac_result = mac.finalize().into_bytes();

    // Final token: token_data || hmac(32)
    token_data.extend_from_slice(&hmac_result);

    // URL-safe base64 encode
    data_encoding::BASE64URL_NOPAD.encode(&token_data)
}

/// Decrypt a Fernet token.
fn fernet_decrypt(
    token: &str,
    signing_key: &[u8; 16],
    encryption_key: &[u8; 16],
) -> Result<Vec<u8>, String> {
    // Add padding for base64 decode
    let token_clean = token.trim_end_matches('=');
    let token_bytes = data_encoding::BASE64URL_NOPAD
        .decode(token_clean.as_bytes())
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    // Minimum: version(1) + timestamp(8) + iv(16) + padding(16) + hmac(32) = 73
    if token_bytes.len() < 73 {
        return Err("Token too short".into());
    }

    // Verify version
    if token_bytes[0] != FERNET_VERSION {
        return Err(format!("Invalid version: {:#x}", token_bytes[0]));
    }

    // Split: data || hmac(32)
    let (data, expected_hmac) = token_bytes.split_at(token_bytes.len() - 32);

    // Verify HMAC
    let mut mac = HmacSha256::new_from_slice(signing_key).unwrap();
    mac.update(data);
    mac.verify_slice(expected_hmac)
        .map_err(|_| "HMAC verification failed".to_string())?;

    // Extract IV and ciphertext
    let iv: [u8; 16] = data[9..25].try_into().map_err(|_| "Invalid IV")?;
    let ciphertext = &data[25..];

    // Decrypt AES-128-CBC
    let plaintext = Aes128CbcDec::new(encryption_key.into(), &iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    Ok(plaintext)
}

// ── Public API ────────────────────────────────────────────────────────

/// True iff *key* satisfies the shared `BRIDGE_MFA_KEY` rule (module docs):
/// exactly what Python's `cryptography.fernet.Fernet` accepts, URL-safe or
/// standard base64 alphabet. Surrounding whitespace is ignored.
pub fn is_valid_fernet_key(key: &str) -> bool {
    canonical_key_bytes(key).is_some()
}

/// The lossless repair of a legacy key: for a 43-character
/// `[A-Za-z0-9-_]` key that decodes to 32 bytes (`secrets.token_urlsafe(32)`
/// output), the same key with `=` appended, which is valid and decodes to
/// the same 32 bytes. `None` for any other key, valid ones included.
pub fn repair_legacy_fernet_key(key: &str) -> Option<String> {
    let key = key.trim();
    let legacy_shape = key.len() == 43
        && key
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_');
    if !legacy_shape {
        return None;
    }
    let repaired = format!("{key}=");
    is_valid_fernet_key(&repaired).then_some(repaired)
}

/// Why *key* cannot be used as `BRIDGE_MFA_KEY`, with what to do about it,
/// or `None` if it is valid.
pub fn mfa_key_problem(key: &str) -> Option<String> {
    if key.trim().is_empty() {
        return Some(format!(
            "BRIDGE_MFA_KEY is not set — set it to the bridge's Fernet key (generate one \
             with {GENERATE_FERNET_KEY_COMMAND})"
        ));
    }
    if is_valid_fernet_key(key) {
        return None;
    }
    let detail = if repair_legacy_fernet_key(key).is_some() {
        "it is 43 characters long, the unpadded form of a valid key"
    } else {
        "expected 44 characters: 43 base64 characters encoding 32 bytes, then '='"
    };
    Some(format!(
        "BRIDGE_MFA_KEY is not a valid Fernet key ({detail}) — {FERNET_KEY_REPAIR_HINT}"
    ))
}

/// Encrypt a TOTP secret for storage.
///
/// Encrypts only with a key that satisfies the key rule — the same keys
/// Python accepts — and returns `fernet:<ciphertext>`. With a missing or
/// invalid key (a repairable 43-character key included): in development
/// returns `b64:<base64>` (NOT encrypted) with a warning, as the bridge
/// does; in production returns an error rather than storing the secret
/// unencrypted.
pub fn encrypt_totp_secret(
    plaintext: &str,
    mfa_key: &str,
    production: bool,
) -> Result<String, String> {
    if let Some((signing, encryption)) = encryption_key(mfa_key) {
        let token = fernet_encrypt(plaintext.as_bytes(), &signing, &encryption);
        return Ok(format!("fernet:{}", token));
    }
    let problem = mfa_key_problem(mfa_key).unwrap_or_default();
    if production {
        return Err(format!(
            "{problem} — refusing to store a TOTP secret unencrypted in production"
        ));
    }
    warn!("{problem} — storing TOTP secret base64-encoded only (NOT encrypted; development mode)");
    Ok(format!(
        "b64:{}",
        data_encoding::BASE64.encode(plaintext.as_bytes())
    ))
}

/// Decrypt a stored TOTP secret.
///
/// Handles three formats:
/// - `fernet:<token>` — Fernet decryption (with a valid key, or with a
///   repairable 43-character legacy key, see [`repair_legacy_fernet_key`])
/// - `b64:<encoded>` — base64 decoding
/// - legacy plaintext (no prefix)
pub fn decrypt_totp_secret(stored: &str, mfa_key: &str) -> Result<String, String> {
    if let Some(ciphertext) = stored.strip_prefix("fernet:") {
        if mfa_key.trim().is_empty() {
            return Err("Fernet-encrypted secret but no BRIDGE_MFA_KEY configured".into());
        }
        let (signing, encryption) =
            decryption_key(mfa_key).ok_or_else(|| "Invalid BRIDGE_MFA_KEY".to_string())?;
        let plaintext = fernet_decrypt(ciphertext, &signing, &encryption)?;
        return String::from_utf8(plaintext)
            .map_err(|e| format!("Decrypted secret is not valid UTF-8: {}", e));
    }

    if let Some(encoded) = stored.strip_prefix("b64:") {
        let decoded = data_encoding::BASE64
            .decode(encoded.as_bytes())
            .map_err(|e| format!("Base64 decode failed: {}", e))?;
        return String::from_utf8(decoded)
            .map_err(|e| format!("Decoded secret is not valid UTF-8: {}", e));
    }

    // Legacy: plaintext (pre-migration secrets)
    Ok(stored.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip_fernet() {
        let key = generate_key();
        let secret = "JBSWY3DPEHPK3PXP";
        let encrypted = encrypt_totp_secret(secret, &key, false).unwrap();
        assert!(encrypted.starts_with("fernet:"));
        let decrypted = decrypt_totp_secret(&encrypted, &key).unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_encrypt_no_key_uses_b64() {
        let secret = "JBSWY3DPEHPK3PXP";
        let encrypted = encrypt_totp_secret(secret, "", false).unwrap();
        assert!(encrypted.starts_with("b64:"));
        let decrypted = decrypt_totp_secret(&encrypted, "").unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_decrypt_legacy_plaintext() {
        let result = decrypt_totp_secret("JBSWY3DPEHPK3PXP", "").unwrap();
        assert_eq!(result, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn test_decrypt_fernet_without_key_fails() {
        let key = generate_key();
        let encrypted = encrypt_totp_secret("secret", &key, false).unwrap();
        let result = decrypt_totp_secret(&encrypted, "");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_fernet_wrong_key_fails() {
        let key1 = generate_key();
        let key2 = generate_key();
        let encrypted = encrypt_totp_secret("secret", &key1, false).unwrap();
        let result = decrypt_totp_secret(&encrypted, &key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_b64_roundtrip() {
        let secret = "SOME_SECRET_VALUE_123";
        let encrypted = encrypt_totp_secret(secret, "", false).unwrap();
        let decrypted = decrypt_totp_secret(&encrypted, "").unwrap();
        assert_eq!(decrypted, secret);
    }

    // Shared test vectors, computed with Python `cryptography`:
    //   base64.urlsafe_b64decode(key).hex(), and
    //   Fernet(key)._encrypt_from_parts(b"JBSWY3DPEHPK3PXP", 1700000000, bytes(range(16)))
    /// `Fernet.generate_key()` output (URL-safe alphabet).
    const URLSAFE_KEY: &str = "gbhtBUbPkbiIqPMsYEdh1YUZAxWFy-1pp3gVY24zhzM=";
    const URLSAFE_KEY_HEX: &str =
        "81b86d0546cf91b888a8f32c604761d58519031585cbed69a77815636e338733";
    const URLSAFE_TOKEN: &str = "fernet:gAAAAABlU_EAAAECAwQFBgcICQoLDA0OD3hrj0EybXZ_uqlhhD-\
                                 dLSQpOP9oZl2oyisR9kHusJYe_csoAJQW3vb2XeCyQUALyNHgqWsXDYYe1dOIVLlyqnc=";
    /// `secrets.token_urlsafe(32)`-style legacy key: URLSAFE_KEY minus '='.
    const LEGACY_43_KEY: &str = "gbhtBUbPkbiIqPMsYEdh1YUZAxWFy-1pp3gVY24zhzM";
    /// Standard alphabet (`openssl rand -base64 32` style), accepted by
    /// Python's `Fernet`.
    const STANDARD_KEY: &str = "+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/s=";
    const STANDARD_KEY_HEX: &str =
        "fbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfb";
    const STANDARD_TOKEN: &str = "fernet:gAAAAABlU_EAAAECAwQFBgcICQoLDA0OD0vT3b0q4cBgmJzf0wpZHIh\
                                  YY6xVgej7Qzi2-Pqe-xukbmfSmrakUybyEGSXnjNKWfZbtn1IF2dpGh2-T3GaJj4=";
    /// Both alphabets mixed in one key.
    const MIXED_KEY: &str = "-_+/-_+/-_+/-_+/-_+/-_+/-_+/-_+/-_+/-_+/-_s=";
    const MIXED_KEY_HEX: &str = "fbffbffbffbffbffbffbffbffbffbffbffbffbffbffbffbffbffbffbffbffbfb";
    const MIXED_TOKEN: &str = "fernet:gAAAAABlU_EAAAECAwQFBgcICQoLDA0OD_LzpAmaTMVrVqmEyV8lNyqFiFL\
                               rJ_nw0naZ6vmdTS7g_LivBgKX94BXOPWUotqX0z5rtNdLVv_Egz_g_Smj0MU=";
    /// URLSAFE_KEY with non-zero trailing bits in the 43rd character;
    /// Python ignores them and derives URLSAFE_KEY's bytes.
    const NONCANONICAL_KEY: &str = "gbhtBUbPkbiIqPMsYEdh1YUZAxWFy-1pp3gVY24zhzN=";

    #[test]
    fn test_key_bytes_match_python() {
        for (key, hex_bytes) in [
            (URLSAFE_KEY, URLSAFE_KEY_HEX),
            (STANDARD_KEY, STANDARD_KEY_HEX),
            (MIXED_KEY, MIXED_KEY_HEX),
            (NONCANONICAL_KEY, URLSAFE_KEY_HEX),
        ] {
            assert_eq!(
                canonical_key_bytes(key).map(hex::encode).as_deref(),
                Some(hex_bytes),
                "{key}"
            );
        }
        // The lossless repair: the 43-char legacy key decrypts with the
        // same bytes as its padded form.
        assert_eq!(decryption_key(LEGACY_43_KEY), encryption_key(URLSAFE_KEY));
        assert!(encryption_key(LEGACY_43_KEY).is_none());
    }

    #[test]
    fn test_decrypts_python_tokens_under_every_accepted_alphabet() {
        for (key, token) in [
            (URLSAFE_KEY, URLSAFE_TOKEN),
            (STANDARD_KEY, STANDARD_TOKEN),
            (MIXED_KEY, MIXED_TOKEN),
            (NONCANONICAL_KEY, URLSAFE_TOKEN),
            // A secret an older gateway encrypted under the unpadded key
            // stays readable both before and after the '=' repair.
            (LEGACY_43_KEY, URLSAFE_TOKEN),
        ] {
            assert_eq!(
                decrypt_totp_secret(token, key).as_deref(),
                Ok("JBSWY3DPEHPK3PXP"),
                "{key}"
            );
        }
    }

    #[test]
    fn test_fernet_key_invalid() {
        assert!(encryption_key("too_short").is_none());
        assert!(encryption_key("").is_none());
        assert!(decryption_key("too_short").is_none());
        assert!(decryption_key("").is_none());
        let (signing, encryption) = encryption_key(&generate_key()).unwrap();
        assert_eq!((signing.len(), encryption.len()), (16, 16));
    }

    #[test]
    fn test_is_valid_fernet_key() {
        assert!(is_valid_fernet_key(URLSAFE_KEY));
        assert!(is_valid_fernet_key(
            " AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n"
        ));
        assert!(is_valid_fernet_key(&generate_key()));
        // Python's Fernet accepts the standard alphabet, mixed alphabets
        // and non-canonical trailing bits, so the gateway does too.
        assert!(is_valid_fernet_key(STANDARD_KEY));
        assert!(is_valid_fernet_key(MIXED_KEY));
        assert!(is_valid_fernet_key(NONCANONICAL_KEY));
        // `secrets.token_urlsafe(32)` — 43 chars, no padding: Python's
        // Fernet rejects it, so must we.
        assert!(!is_valid_fernet_key(LEGACY_43_KEY));
        assert!(!is_valid_fernet_key(""));
        assert!(!is_valid_fernet_key("change-me"));
        assert!(!is_valid_fernet_key(&"!".repeat(44)));
        assert!(!is_valid_fernet_key(&format!("{}!=", &URLSAFE_KEY[..42])));
        // 44 characters but no '=' (33 bytes), '=' in the wrong place,
        // too long.
        assert!(!is_valid_fernet_key(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g"
        ));
        assert!(!is_valid_fernet_key(&format!("{}=A", &URLSAFE_KEY[..42])));
        assert!(!is_valid_fernet_key(&format!("{URLSAFE_KEY}=")));
        assert!(!is_valid_fernet_key(&format!("A{URLSAFE_KEY}")));
    }

    #[test]
    fn test_repair_legacy_fernet_key() {
        assert_eq!(
            repair_legacy_fernet_key(LEGACY_43_KEY).as_deref(),
            Some(URLSAFE_KEY)
        );
        assert_eq!(
            repair_legacy_fernet_key(&format!(" {LEGACY_43_KEY}\n")).as_deref(),
            Some(URLSAFE_KEY)
        );
        // Valid keys need no repair; other shapes are not repairable.
        assert_eq!(repair_legacy_fernet_key(URLSAFE_KEY), None);
        assert_eq!(repair_legacy_fernet_key(&STANDARD_KEY[..43]), None);
        assert_eq!(repair_legacy_fernet_key(&LEGACY_43_KEY[..42]), None);
        assert_eq!(repair_legacy_fernet_key(&"!".repeat(43)), None);
        assert_eq!(repair_legacy_fernet_key(""), None);
    }

    #[test]
    fn test_mfa_key_problem_messages() {
        assert_eq!(mfa_key_problem(URLSAFE_KEY), None);
        assert_eq!(mfa_key_problem(STANDARD_KEY), None);

        let unset = mfa_key_problem("  ").unwrap();
        assert!(unset.contains("BRIDGE_MFA_KEY is not set"), "{unset}");
        assert!(unset.contains(GENERATE_FERNET_KEY_COMMAND), "{unset}");

        for key in [LEGACY_43_KEY, "change-me"] {
            let msg = mfa_key_problem(key).unwrap();
            assert!(msg.contains("not a valid Fernet key"), "{msg}");
            assert!(
                msg.contains(
                    "if the key is 43 characters long, append '=' to keep existing \
                     encrypted TOTP secrets readable; otherwise generate a new key with \
                     python3 -c 'from cryptography.fernet import Fernet; \
                     print(Fernet.generate_key().decode())'"
                ),
                "{msg}"
            );
        }
        assert!(mfa_key_problem(LEGACY_43_KEY)
            .unwrap()
            .contains("it is 43 characters long"));
    }

    #[test]
    fn test_production_refuses_plaintext_fallback() {
        assert!(encrypt_totp_secret("JBSWY3DPEHPK3PXP", "", true).is_err());
        assert!(encrypt_totp_secret("JBSWY3DPEHPK3PXP", "not-a-key", true).is_err());
        let key = generate_key();
        let encrypted = encrypt_totp_secret("JBSWY3DPEHPK3PXP", &key, true).unwrap();
        assert!(encrypted.starts_with("fernet:"));
    }

    #[test]
    fn test_dev_invalid_key_falls_back_to_b64() {
        let encrypted = encrypt_totp_secret("JBSWY3DPEHPK3PXP", "not-a-key", false).unwrap();
        assert!(encrypted.starts_with("b64:"));
    }

    #[test]
    fn test_never_encrypts_with_unpadded_legacy_key() {
        // Python rejects the 43-char key, so a `fernet:` token written
        // under it would be unreadable by the bridge: development falls
        // back to b64 exactly as the bridge does, production refuses.
        let stored = encrypt_totp_secret("JBSWY3DPEHPK3PXP", LEGACY_43_KEY, false).unwrap();
        assert!(stored.starts_with("b64:"), "{stored}");
        assert_eq!(
            decrypt_totp_secret(&stored, LEGACY_43_KEY).as_deref(),
            Ok("JBSWY3DPEHPK3PXP")
        );
        let err = encrypt_totp_secret("JBSWY3DPEHPK3PXP", LEGACY_43_KEY, true).unwrap_err();
        assert!(err.contains("append '='"), "{err}");
    }

    #[test]
    fn test_encrypts_with_standard_alphabet_key() {
        let stored = encrypt_totp_secret("JBSWY3DPEHPK3PXP", STANDARD_KEY, true).unwrap();
        assert!(stored.starts_with("fernet:"));
        assert_eq!(
            decrypt_totp_secret(&stored, STANDARD_KEY).as_deref(),
            Ok("JBSWY3DPEHPK3PXP")
        );
        // The same 32 bytes in either alphabet: a key rewritten from
        // '+/' to '-_' still decrypts.
        let urlsafe = STANDARD_KEY.replace('+', "-").replace('/', "_");
        assert_eq!(
            decrypt_totp_secret(&stored, &urlsafe).as_deref(),
            Ok("JBSWY3DPEHPK3PXP")
        );
    }

    #[test]
    fn test_existing_b64_secret_readable_with_key_configured() {
        // Users upgrading from a keyless setup keep their b64: secrets.
        let stored = encrypt_totp_secret("JBSWY3DPEHPK3PXP", "", false).unwrap();
        let key = generate_key();
        assert_eq!(
            decrypt_totp_secret(&stored, &key).unwrap(),
            "JBSWY3DPEHPK3PXP"
        );
    }

    #[test]
    fn test_decrypt_python_fernet_token() {
        // cryptography.fernet.Fernet(KEY).encrypt(b"JBSWY3DPEHPK3PXP")
        let key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        let stored = "fernet:gAAAAABq7F2am_i14UCE6YXA9Z6AYdPS2O6G1hSho5UHjUJla4t_\
                      e3gUzqQ1ZpSstu-peKbRr06EJRSjbFn8kihMDBZwWSvl2Bc3vByVOa4NxK9SPCfjr-g=";
        assert_eq!(
            decrypt_totp_secret(stored, key).unwrap(),
            "JBSWY3DPEHPK3PXP"
        );
    }

    // ── Security paths ────────────────────────────────────────────────

    use aes::cipher::block_padding::NoPadding;

    const SECRET: &str = "JBSWY3DPEHPK3PXP";

    /// The raw bytes of a stored `fernet:` token.
    fn token_bytes(stored: &str) -> Vec<u8> {
        let token = stored.strip_prefix("fernet:").unwrap();
        data_encoding::BASE64URL_NOPAD
            .decode(token.trim_end_matches('=').as_bytes())
            .unwrap()
    }

    /// Raw token bytes stored the way Python writes them (padded URL-safe).
    fn stored(bytes: &[u8]) -> String {
        format!("fernet:{}", data_encoding::BASE64URL.encode(bytes))
    }

    /// A token built from chosen parts and MACed with `key`'s signing half:
    /// it passes authentication whatever is underneath, as only a holder of
    /// the key could produce.
    fn signed_token(key: &str, version: u8, timestamp: u64, iv: [u8; 16], ct: &[u8]) -> String {
        let (signing, _) = encryption_key(key).unwrap();
        let mut data = vec![version];
        data.extend_from_slice(&timestamp.to_be_bytes());
        data.extend_from_slice(&iv);
        data.extend_from_slice(ct);
        let mut mac = HmacSha256::new_from_slice(&signing).unwrap();
        mac.update(&data);
        data.extend_from_slice(&mac.finalize().into_bytes());
        stored(&data)
    }

    /// AES-128-CBC/PKCS7 of `plaintext` under `key`'s encryption half.
    fn cbc_encrypt(key: &str, iv: [u8; 16], plaintext: &[u8]) -> Vec<u8> {
        let (_, enc) = encryption_key(key).unwrap();
        Aes128CbcEnc::new(&enc.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext)
    }

    /// Every byte of the token is authenticated: flipping any bit of the
    /// version, timestamp, IV, ciphertext or MAC is refused — and, past the
    /// version byte, refused by the MAC before any decryption runs, so a
    /// tampered token cannot probe the padding (no padding oracle).
    #[test]
    fn test_tampering_with_any_token_byte_is_rejected() {
        let original = token_bytes(URLSAFE_TOKEN);
        assert_eq!(
            decrypt_totp_secret(&stored(&original), URLSAFE_KEY).as_deref(),
            Ok(SECRET)
        );
        for i in 0..original.len() {
            for bit in [0x01u8, 0x80] {
                let mut tampered = original.clone();
                tampered[i] ^= bit;
                let result = decrypt_totp_secret(&stored(&tampered), URLSAFE_KEY);
                let expected = if i == 0 {
                    "Invalid version"
                } else {
                    "HMAC verification failed"
                };
                assert!(
                    matches!(&result, Err(e) if e.starts_with(expected)),
                    "byte {i} bit {bit:#x}: {result:?}"
                );
            }
        }
    }

    #[test]
    fn test_truncated_or_extended_tokens_are_rejected() {
        let original = token_bytes(URLSAFE_TOKEN);
        // Byte-level truncation, down to nothing.
        for len in 0..original.len() {
            let result = decrypt_totp_secret(&stored(&original[..len]), URLSAFE_KEY);
            if len < 73 {
                assert_eq!(result, Err("Token too short".to_string()), "{len} bytes");
            } else {
                assert_eq!(
                    result,
                    Err("HMAC verification failed".to_string()),
                    "{len} bytes"
                );
            }
        }
        // The stored text cut short anywhere inside the token (the trailing
        // '=' padding is optional, as in Python).
        let unpadded = URLSAFE_TOKEN.trim_end_matches('=').len();
        for len in "fernet:".len()..unpadded {
            let result = decrypt_totp_secret(&URLSAFE_TOKEN[..len], URLSAFE_KEY);
            assert!(result.is_err(), "{len} chars: {result:?}");
        }
        // Bytes appended after the MAC.
        for extra in [&[0u8][..], &[0u8; 16], &original[original.len() - 32..]] {
            let mut longer = original.clone();
            longer.extend_from_slice(extra);
            assert_eq!(
                decrypt_totp_secret(&stored(&longer), URLSAFE_KEY),
                Err("HMAC verification failed".to_string()),
                "{} extra bytes",
                extra.len()
            );
        }
    }

    /// Only the exact key decrypts: a key that shares either half with the
    /// right key fails too, and none of them yields the secret.
    #[test]
    fn test_wrong_key_halves_are_rejected() {
        let right = canonical_key_bytes(URLSAFE_KEY).unwrap();
        let key_with = |flip: usize| {
            let mut bytes = right;
            bytes[flip] ^= 0x01;
            data_encoding::BASE64URL.encode(&bytes)
        };
        // Signing half differs (byte 0): the MAC refuses it.
        assert_eq!(
            decrypt_totp_secret(URLSAFE_TOKEN, &key_with(0)),
            Err("HMAC verification failed".to_string())
        );
        // Signing half right, encryption half wrong (byte 31): the MAC
        // passes and AES decrypts to garbage, which must not be the secret.
        // (For this vector the garbage also fails the padding check, but
        // that is luck — about 255 times in 256 — not a guarantee: only the
        // MAC, checked before decryption, protects against a wrong key.)
        let result = decrypt_totp_secret(URLSAFE_TOKEN, &key_with(31));
        assert_ne!(result.as_deref(), Ok(SECRET), "{result:?}");
        // An unrelated valid key.
        assert_eq!(
            decrypt_totp_secret(URLSAFE_TOKEN, STANDARD_KEY),
            Err("HMAC verification failed".to_string())
        );
    }

    /// Rotating `BRIDGE_MFA_KEY` (no multi-key support): a secret stored under
    /// the old key is refused under the new one — an error, not garbage — and
    /// stays readable with the old key until it is re-encrypted, after which
    /// only the new key reads it.
    #[test]
    fn test_key_rotation_requires_reencryption() {
        let old = generate_key();
        let new = generate_key();
        let under_old = encrypt_totp_secret(SECRET, &old, true).unwrap();
        assert_eq!(
            decrypt_totp_secret(&under_old, &new),
            Err("HMAC verification failed".to_string())
        );
        let plaintext = decrypt_totp_secret(&under_old, &old).unwrap();
        assert_eq!(plaintext, SECRET);

        let under_new = encrypt_totp_secret(&plaintext, &new, true).unwrap();
        assert_eq!(decrypt_totp_secret(&under_new, &new).as_deref(), Ok(SECRET));
        assert_eq!(
            decrypt_totp_secret(&under_new, &old),
            Err("HMAC verification failed".to_string())
        );
    }

    /// The timestamp is authenticated (see the tamper test) but does not
    /// expire a stored secret: as with Python's `Fernet.decrypt(token)`
    /// without a `ttl`, a token from any time decrypts. New tokens carry
    /// the version byte and the current time, so a Python reader that does
    /// pass a `ttl` accepts them.
    #[test]
    fn test_timestamps_do_not_expire_stored_secrets() {
        let iv = [7u8; 16];
        let ct = cbc_encrypt(URLSAFE_KEY, iv, SECRET.as_bytes());
        for timestamp in [0, 1_700_000_000, u64::MAX] {
            let token = signed_token(URLSAFE_KEY, FERNET_VERSION, timestamp, iv, &ct);
            assert_eq!(
                decrypt_totp_secret(&token, URLSAFE_KEY).as_deref(),
                Ok(SECRET),
                "{timestamp}"
            );
        }

        let unix_now = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        };
        let before = unix_now();
        let token = token_bytes(&encrypt_totp_secret(SECRET, URLSAFE_KEY, true).unwrap());
        let after = unix_now();
        assert_eq!(token[0], FERNET_VERSION);
        let stamped = u64::from_be_bytes(token[1..9].try_into().unwrap());
        // A few seconds of slack in case the wall clock steps in between.
        assert!(
            (before.saturating_sub(5)..=after + 5).contains(&stamped),
            "{stamped} not in {before}..={after}"
        );
    }

    /// The same secret encrypted twice gives unrelated tokens: a fresh
    /// random IV each time, so stored ciphertexts do not reveal that two
    /// users share a secret.
    #[test]
    fn test_each_encryption_uses_a_fresh_iv() {
        let key = generate_key();
        let tokens: Vec<Vec<u8>> = (0..8)
            .map(|_| token_bytes(&encrypt_totp_secret(SECRET, &key, true).unwrap()))
            .collect();
        let ivs: std::collections::HashSet<&[u8]> = tokens.iter().map(|t| &t[9..25]).collect();
        let cts: std::collections::HashSet<&[u8]> =
            tokens.iter().map(|t| &t[25..t.len() - 32]).collect();
        assert_eq!(ivs.len(), tokens.len(), "IVs repeat");
        assert_eq!(cts.len(), tokens.len(), "ciphertexts repeat");
        for token in &tokens {
            assert_eq!(
                decrypt_totp_secret(&stored(token), &key).as_deref(),
                Ok(SECRET)
            );
        }
    }

    /// A token that passes the MAC but is malformed underneath is refused
    /// with an error, never a panic or a partial secret.
    #[test]
    fn test_authenticated_but_malformed_tokens_are_refused() {
        let iv = [9u8; 16];
        let good = cbc_encrypt(URLSAFE_KEY, iv, SECRET.as_bytes());
        let token = |version: u8, ct: &[u8]| signed_token(URLSAFE_KEY, version, 1, iv, ct);
        assert_eq!(
            decrypt_totp_secret(&token(FERNET_VERSION, &good), URLSAFE_KEY).as_deref(),
            Ok(SECRET),
            "control"
        );

        // An unknown version, even with a valid MAC.
        assert_eq!(
            decrypt_totp_secret(&token(0x81, &good), URLSAFE_KEY),
            Err("Invalid version: 0x81".to_string())
        );

        // Ciphertext that is not a whole number of AES blocks.
        let mut ragged = good.clone();
        ragged.push(0);
        let result = decrypt_totp_secret(&token(FERNET_VERSION, &ragged), URLSAFE_KEY);
        assert!(
            matches!(&result, Err(e) if e.starts_with("Decryption failed")),
            "{result:?}"
        );

        // Invalid PKCS7 padding (a final plaintext byte of 0).
        let (_, enc) = encryption_key(URLSAFE_KEY).unwrap();
        let unpadded = Aes128CbcEnc::new(&enc.into(), &iv.into())
            .encrypt_padded_vec_mut::<NoPadding>(&[0u8; 16]);
        let result = decrypt_totp_secret(&token(FERNET_VERSION, &unpadded), URLSAFE_KEY);
        assert!(
            matches!(&result, Err(e) if e.starts_with("Decryption failed")),
            "{result:?}"
        );

        // A plaintext that is not UTF-8.
        let binary = cbc_encrypt(URLSAFE_KEY, iv, &[0xff, 0xfe, 0x00]);
        let result = decrypt_totp_secret(&token(FERNET_VERSION, &binary), URLSAFE_KEY);
        assert!(
            matches!(&result, Err(e) if e.starts_with("Decrypted secret is not valid UTF-8")),
            "{result:?}"
        );

        // The smallest well-formed token (an empty secret, 73 bytes) is
        // accepted: the length check does not cut off valid tokens.
        let empty = cbc_encrypt(URLSAFE_KEY, iv, b"");
        let min = token(FERNET_VERSION, &empty);
        assert_eq!(token_bytes(&min).len(), 73);
        assert_eq!(decrypt_totp_secret(&min, URLSAFE_KEY).as_deref(), Ok(""));
    }

    #[test]
    fn test_malformed_stored_values_are_refused() {
        for value in [
            "fernet:",
            "fernet:====",
            "fernet:not base64!",
            "fernet:gAAAAABlU_EA",
            "b64:not base64!",
        ] {
            let result = decrypt_totp_secret(value, URLSAFE_KEY);
            assert!(result.is_err(), "{value}: {result:?}");
        }
        // b64: wrapping bytes that are not UTF-8.
        let binary = format!("b64:{}", data_encoding::BASE64.encode(&[0xff, 0xfe]));
        assert!(decrypt_totp_secret(&binary, "").is_err());
    }

    /// Unusable keys — non-ASCII, NUL, padding only, whitespace only — are
    /// refused everywhere (and in production nothing is stored) without
    /// panicking on multi-byte input.
    #[test]
    fn test_hostile_keys_are_refused_without_panicking() {
        let keys = [
            "é".repeat(22),                      // 44 bytes, not ASCII
            format!("{}a=", "é".repeat(21)),     // 44 bytes ending in '='
            format!("{}a", "€".repeat(14)),      // 43 bytes: legacy length
            format!("{}\0", &URLSAFE_KEY[..43]), // NUL instead of '='
            URLSAFE_KEY.replacen('g', "\0", 1),  // NUL inside
            "=".repeat(44),
            format!("{}é", &URLSAFE_KEY[..42]), // 44 bytes, '=' missing
        ];
        for key in &keys {
            assert!(!is_valid_fernet_key(key), "{key:?}");
            assert_eq!(repair_legacy_fernet_key(key), None, "{key:?}");
            assert!(mfa_key_problem(key).is_some(), "{key:?}");
            assert!(encrypt_totp_secret(SECRET, key, true).is_err(), "{key:?}");
            assert_eq!(
                decrypt_totp_secret(URLSAFE_TOKEN, key),
                Err("Invalid BRIDGE_MFA_KEY".to_string()),
                "{key:?}"
            );
        }
        // Whitespace only is "no key": production refuses to store, and a
        // stored token is not readable.
        for blank in [" ", "\n\t "] {
            assert!(encrypt_totp_secret(SECRET, blank, true).is_err());
            assert_eq!(
                decrypt_totp_secret(URLSAFE_TOKEN, blank),
                Err("Fernet-encrypted secret but no BRIDGE_MFA_KEY configured".to_string())
            );
        }
    }

    /// Errors (returned to callers and logged) name the problem but never
    /// carry key material or the secret.
    #[test]
    fn test_errors_never_contain_key_material_or_the_secret() {
        let not_a_key = "prod-mfa-key-9f8e7d6c5b4a39281706f5e4d3c2b1a0";
        let iv = [3u8; 16];
        let mut tampered = token_bytes(URLSAFE_TOKEN);
        tampered[30] ^= 0x01;
        // A stored secret that is the real secret plus one invalid byte, so
        // the UTF-8 errors fire with the secret right there in the bytes.
        let almost_utf8 = [SECRET.as_bytes(), &[0xff]].concat();
        let fernet_binary = signed_token(
            URLSAFE_KEY,
            FERNET_VERSION,
            1,
            iv,
            &cbc_encrypt(URLSAFE_KEY, iv, &almost_utf8),
        );
        let b64_binary = format!("b64:{}", data_encoding::BASE64.encode(&almost_utf8));
        let fernet_utf8_error = decrypt_totp_secret(&fernet_binary, URLSAFE_KEY).unwrap_err();
        let b64_utf8_error = decrypt_totp_secret(&b64_binary, URLSAFE_KEY).unwrap_err();
        // Only the position of the bad byte, never the bytes themselves (in
        // any rendering: text, lossy text or a list of numbers).
        assert_eq!(
            fernet_utf8_error,
            "Decrypted secret is not valid UTF-8: invalid utf-8 sequence of 1 bytes from index 16"
        );
        assert_eq!(
            b64_utf8_error,
            "Decoded secret is not valid UTF-8: invalid utf-8 sequence of 1 bytes from index 16"
        );
        let errors = [
            decrypt_totp_secret(URLSAFE_TOKEN, STANDARD_KEY).unwrap_err(),
            decrypt_totp_secret(URLSAFE_TOKEN, not_a_key).unwrap_err(),
            decrypt_totp_secret(&stored(&tampered), URLSAFE_KEY).unwrap_err(),
            fernet_utf8_error,
            b64_utf8_error,
            decrypt_totp_secret(&format!("b64:{SECRET}!"), URLSAFE_KEY).unwrap_err(),
            encrypt_totp_secret(SECRET, not_a_key, true).unwrap_err(),
            encrypt_totp_secret(SECRET, LEGACY_43_KEY, true).unwrap_err(),
            encrypt_totp_secret(SECRET, "", true).unwrap_err(),
            mfa_key_problem(not_a_key).unwrap(),
            mfa_key_problem(LEGACY_43_KEY).unwrap(),
        ];
        let key_hex = hex::encode(canonical_key_bytes(URLSAFE_KEY).unwrap());
        let secret_b64 = data_encoding::BASE64.encode(SECRET.as_bytes());
        let needles = [
            URLSAFE_KEY,
            &URLSAFE_KEY[..16],
            &URLSAFE_KEY[22..38],
            STANDARD_KEY,
            not_a_key,
            &not_a_key[..16],
            &key_hex[..16],
            &key_hex[32..48],
            SECRET,
            &secret_b64,
        ];
        for err in &errors {
            for needle in needles {
                assert!(!err.contains(needle), "{err:?} contains {needle:?}");
            }
        }
    }
}
