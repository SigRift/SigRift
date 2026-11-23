//! Client-certificate (mTLS) identity resolution.
//!
//! Phase A of the PKI rollout. When the gateway is configured with a
//! client-CA (`UC_TLS_CLIENT_CA`), rustls verifies that any presented
//! client certificate chains to that CA. This module then maps the
//! verified certificate to an agent identity and role:
//!
//! 1. [`ClientCertInfo::from_der`] extracts the identity (DNS SAN, or CN
//!    as a fallback), the serial number and the SHA-256 fingerprint of the
//!    leaf certificate.
//! 2. [`CertRegistry`] looks that exact certificate up in the
//!    `registry.json` written by the bridge CA — by serial number, checking
//!    the recorded fingerprint and identity — and resolves it to a
//!    [`Role`], rejecting revoked, expired or unknown certificates.
//!
//! The verifier proves the certificate is *authentic* (chains to our
//! CA); the registry decides what it is *authorised* for. Both checks
//! must pass. Because the registry is keyed by serial, revoking one
//! certificate (the bridge marks its serial `revoked`) disables that
//! certificate even while the same identity holds a newer valid one —
//! the registry acts as the CRL.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};
use tracing::{info, warn};

use super::api_key::FileStamp;
use super::rbac::Role;

/// A verified client certificate, as the auth middleware needs it.
/// Injected into request extensions by the TLS acceptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCertInfo {
    /// DNS SAN (or CN) — the agent identity.
    pub identity: String,
    /// Serial number in decimal, as the bridge CA keys its registry
    /// (`str(serial)` in Python).
    pub serial: String,
    /// Lowercase hex SHA-256 of the certificate DER (the registry's
    /// `fingerprint_sha256`).
    pub fingerprint_sha256: String,
}

impl ClientCertInfo {
    /// Parse a leaf certificate (DER). `None` if it does not parse or has
    /// no usable identity.
    pub fn from_der(der: &[u8]) -> Option<Self> {
        use x509_parser::prelude::*;

        let identity = parse_cert_identity(der)?;
        let (_, cert) = X509Certificate::from_der(der).ok()?;
        Some(Self {
            identity,
            serial: serial_to_decimal(cert.raw_serial()),
            fingerprint_sha256: hex::encode(Sha256::digest(der)),
        })
    }
}

/// Big-endian serial bytes (DER INTEGER content, possibly with a leading
/// 0x00 sign byte) as a decimal string without leading zeros.
fn serial_to_decimal(bytes: &[u8]) -> String {
    // Repeated division by 10^9 of the base-256 number.
    let mut digits: Vec<u8> = bytes.iter().copied().skip_while(|&b| b == 0).collect();
    if digits.is_empty() {
        return "0".to_string();
    }
    let mut chunks: Vec<u32> = Vec::new();
    while !digits.is_empty() {
        let mut rem: u64 = 0;
        let mut quotient = Vec::with_capacity(digits.len());
        for &b in &digits {
            let cur = (rem << 8) | u64::from(b);
            let q = cur / 1_000_000_000;
            rem = cur % 1_000_000_000;
            if !(quotient.is_empty() && q == 0) {
                quotient.push(q as u8);
            }
        }
        chunks.push(rem as u32);
        digits = quotient;
    }
    let mut out = chunks.pop().unwrap_or(0).to_string();
    for chunk in chunks.iter().rev() {
        out.push_str(&format!("{chunk:09}"));
    }
    out
}

/// Canonical form of a registry serial key: decimal digits without leading
/// zeros. `None` if it is not a decimal number.
fn canonical_serial(key: &str) -> Option<String> {
    let key = key.trim();
    if key.is_empty() || !key.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let trimmed = key.trim_start_matches('0');
    Some(if trimmed.is_empty() { "0" } else { trimmed }.to_string())
}

/// Extract the agent identity from a leaf certificate (DER bytes).
///
/// Prefers the first `dNSName` SAN entry — the bridge CA always sets
/// one. Falls back to the subject CN. Returns `None` if the bytes do
/// not parse as a certificate or carry no usable name.
pub fn parse_cert_identity(der: &[u8]) -> Option<String> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(der).ok()?;

    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                if !dns.is_empty() {
                    return Some((*dns).to_string());
                }
            }
        }
    }

    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    cn
}

fn io_other<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

/// Build a rustls client-certificate verifier from a PEM CA bundle.
///
/// The verifier runs in **allow-unauthenticated** mode: clients that
/// present *no* certificate still complete the handshake (and fall
/// through to API-key auth), but a client that *does* present one must
/// have it chain to this CA or the handshake fails. This keeps Phase A
/// purely additive.
pub fn load_client_verifier(
    ca_path: &Path,
) -> io::Result<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
    let pem = std::fs::read(ca_path)?;
    let mut roots = rustls::RootCertStore::empty();
    let mut count = 0;
    for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
        roots.add(cert?).map_err(io_other)?;
        count += 1;
    }
    if count == 0 {
        return Err(io_other(format!(
            "no certificates found in client CA file {}",
            ca_path.display()
        )));
    }
    rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated()
        .build()
        .map_err(io_other)
}

// ── Registry ────────────────────────────────────────────────────────

/// One issued certificate in the registry.
#[derive(Debug, Clone)]
struct CertEntry {
    identity: String,
    role: Role,
    revoked: bool,
    not_after: Option<chrono::DateTime<chrono::Utc>>,
    /// Lowercase hex SHA-256 of the issued certificate, when recorded.
    fingerprint: Option<String>,
    /// The entry is not one the bridge could have written: it is not an
    /// object, its `identity` is missing or not a non-empty string, its
    /// `role` is missing or not exactly a certificate role (see
    /// [`parse_role`]), a field the bridge always writes in a fixed shape
    /// (`revoked`, `fingerprint_sha256`, `not_after`) is present but
    /// malformed, or another entry has the same serial. The entry is kept,
    /// so its serial stays taken, but it authorises no certificate.
    malformed: bool,
}

impl CertEntry {
    /// Usable = well-formed, not revoked and not past its expiry.
    fn is_valid(&self) -> bool {
        if self.malformed || self.revoked {
            return false;
        }
        match self.not_after {
            Some(exp) => exp > chrono::Utc::now(),
            None => true,
        }
    }
}

/// The JSON type of `v`, for log messages about malformed registry fields.
fn json_kind(v: &serde_json::Value) -> &'static str {
    use serde_json::Value;
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// A registry entry's `identity`: the bridge always writes it as a
/// non-empty string. Anything else (missing, empty, not a string) is
/// malformed.
fn parse_identity(v: Option<&serde_json::Value>) -> Result<String, String> {
    match v {
        Some(serde_json::Value::String(s)) if !s.is_empty() => Ok(s.clone()),
        Some(serde_json::Value::String(_)) => Err("empty".to_string()),
        Some(other) => Err(format!("a {}, not a string", json_kind(other))),
        None => Err("missing".to_string()),
    }
}

/// The roles a client certificate can carry, as the bridge CA writes them
/// (`ca.py` `VALID_CERT_ROLES`): every [`Role`] but KEYMASTER, which is
/// never delegated to a certificate.
const CERT_ROLES: [Role; 5] = [
    Role::Sensor,
    Role::Node,
    Role::Viewer,
    Role::Analyst,
    Role::Admin,
];

/// A registry entry's `role`. The bridge (`ca.py` `_issue`, the only
/// writer) always writes it, as one of [`CERT_ROLES`] spelt exactly as
/// [`Role::as_str`] spells it (`sensor`, `node`, `viewer`, `analyst`,
/// `admin`), and refuses to issue any other. Every other value is
/// malformed, never a fallback role: a missing role (as for `identity`,
/// which the bridge also always writes), `keymaster` in any spelling,
/// another spelling of a certificate role (`ADMIN`, `" admin"`, or a
/// Unicode case mapping such as `adm\u{131}n`, which `to_uppercase()`
/// turns into `ADMIN`), an unknown name, and a value that is not a string.
///
/// Unlike [`parse_fingerprint`], this does not normalise other notations:
/// any spelling of a fingerprint can only match the one certificate,
/// whereas a role grants access, so the gateway reads only what the bridge
/// writes. [`Role`]'s `FromStr` (case-insensitive, for `keys.json` and the
/// database) is not used to grant a role here.
fn parse_role(v: Option<&serde_json::Value>) -> Result<Role, String> {
    let name = match v {
        Some(serde_json::Value::String(s)) => s,
        Some(other) => return Err(format!("a {}, not a string", json_kind(other))),
        None => return Err("missing".to_string()),
    };
    if let Some(role) = CERT_ROLES.into_iter().find(|r| r.as_str() == name) {
        return Ok(role);
    }
    let expected = CERT_ROLES.map(|r| r.as_str()).join(", ");
    Err(match name.parse::<Role>() {
        Ok(Role::Keymaster) => "keymaster is never delegated to a certificate".to_string(),
        Ok(role) => format!("not spelt as the bridge writes \"{role}\" (one of {expected})"),
        Err(_) if name.is_empty() => "empty".to_string(),
        Err(_) => format!("not a certificate role (one of {expected})"),
    })
}

/// A registry entry's `revoked`. The bridge writes `false` at issue and
/// `true` on `revoke()`. A missing or `null` flag means live: both are
/// falsy to the bridge, whose `revoke()` replaces them with `true`. Any
/// other value is malformed. The bridge never writes one, and its readers
/// disagree on what it means (Python truthiness makes `"false"` revoked,
/// and Python and the admin UI's JS differ on `[]` and `{}`), so the
/// gateway does not guess.
fn parse_revoked(v: Option<&serde_json::Value>) -> Result<bool, String> {
    match v {
        None | Some(serde_json::Value::Null) => Ok(false),
        Some(serde_json::Value::Bool(b)) => Ok(*b),
        Some(other) => Err(format!("a {}, not a boolean", json_kind(other))),
    }
}

/// A registry entry's `fingerprint_sha256`. The bridge always records the
/// certificate's SHA-256 as 64 lowercase hex digits; other notations of it
/// (upper case, `AB:CD:…` separators, surrounding whitespace) are
/// normalised. Only a *missing* field is a legacy entry bound by serial and
/// identity alone (`Ok(None)`). A field that is present but is no SHA-256
/// in any notation (empty, separators or whitespace only, the wrong
/// length, not hex, `null`, not a string) is malformed, never "no
/// fingerprint".
fn parse_fingerprint(v: Option<&serde_json::Value>) -> Result<Option<String>, String> {
    let raw = match v {
        None => return Ok(None),
        Some(serde_json::Value::String(s)) => s,
        Some(other) => return Err(format!("a {}, not a string", json_kind(other))),
    };
    let fp = raw.trim().to_ascii_lowercase().replace(':', "");
    if fp.is_empty() {
        Err("empty".to_string())
    } else if fp.len() != 64 || !fp.bytes().all(|b| b.is_ascii_hexdigit()) {
        Err(format!(
            "not 64 hex digits ({} characters once normalised)",
            fp.chars().count()
        ))
    } else {
        Ok(Some(fp))
    }
}

/// A registry entry's `not_after`. The bridge writes `isoformat()` of an
/// aware UTC datetime (`2026-01-01T00:00:00.123456+00:00`); any RFC 3339
/// timestamp (`Z`, another offset, a space for the `T`) is read.
///
/// A missing field means no registry expiry (`Ok(None)`). The bridge
/// (`ca.py` `_issue`, the only writer) always writes `not_after`, so only
/// a hand-made or legacy entry lacks it, and the TLS verifier still
/// enforces the certificate's own notAfter at the handshake. A field that
/// is present but unreadable (a naive timestamp, a bare date, other text,
/// a number, `null`) leaves the expiry unknown and is malformed, never
/// "does not expire".
fn parse_not_after(
    v: Option<&serde_json::Value>,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, String> {
    match v {
        None => Ok(None),
        Some(serde_json::Value::String(s)) => chrono::DateTime::parse_from_rfc3339(s)
            .map(|dt| Some(dt.with_timezone(&chrono::Utc)))
            .map_err(|e| format!("not an RFC 3339 timestamp with an offset ({e})")),
        Some(other) => Err(format!("a {}, not a timestamp string", json_kind(other))),
    }
}

/// The `issued` object of `registry.json`: every entry in file order, a
/// repeated key included. A `serde_json::Value` object keeps only the last
/// of several equal keys (as Python's `json` does), so a later copy of a
/// serial would silently replace an earlier revoked or malformed one.
struct IssuedEntries(Vec<(String, serde_json::Value)>);

impl<'de> serde::Deserialize<'de> for IssuedEntries {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Entries;
        impl<'de> serde::de::Visitor<'de> for Entries {
            type Value = IssuedEntries;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object of registry entries")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<IssuedEntries, A::Error> {
                let mut entries = Vec::new();
                while let Some(entry) = map.next_entry()? {
                    entries.push(entry);
                }
                Ok(IssuedEntries(entries))
            }
        }
        deserializer.deserialize_map(Entries)
    }
}

/// `registry.json` as the gateway reads it: its `issued` object, `None`
/// when there is none. A file that is not a JSON object, an `issued` that
/// is not an object, or a second `issued` key is an error, so the file
/// authorises no certificate.
struct RegistryFile(Option<IssuedEntries>);

impl<'de> serde::Deserialize<'de> for RegistryFile {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct File;
        impl<'de> serde::de::Visitor<'de> for File {
            type Value = RegistryFile;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a registry object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<RegistryFile, A::Error> {
                let mut issued = None;
                while let Some(key) = map.next_key::<String>()? {
                    if key != "issued" {
                        map.next_value::<serde::de::IgnoredAny>()?;
                    } else if issued.is_some() {
                        return Err(serde::de::Error::duplicate_field("issued"));
                    } else {
                        issued = Some(map.next_value::<IssuedEntries>()?);
                    }
                }
                Ok(RegistryFile(issued))
            }
        }
        deserializer.deserialize_map(File)
    }
}

#[derive(Default)]
struct RegistryInner {
    /// Decimal serial → the certificate issued with it.
    by_serial: HashMap<String, CertEntry>,
    /// The file version `by_serial` was parsed from; `None` when the file
    /// was missing or unreadable (it is then tried again on every lookup).
    version: Option<RegistryVersion>,
}

/// One version of `registry.json`, as loaded.
struct RegistryVersion {
    /// Its mtime, size and inode when read.
    stamp: FileStamp,
    /// SHA-256 of its contents, so reading it again re-parses (and logs)
    /// only if they changed.
    digest: [u8; 32],
    /// It was read within [`RACY_WINDOW`] of its mtime, so a later write
    /// in the same timestamp tick may carry the same stamp: it is read
    /// again on every lookup until a read falls outside that window.
    racy: bool,
}

/// The coarsest file timestamp granularity this has to allow for: FAT
/// stores mtimes in 2-second steps, HFS+ and ext3 in seconds, and Linux
/// stamps ext4, XFS or Btrfs files from a clock that advances in ticks of
/// a few milliseconds.
const RACY_WINDOW: Duration = Duration::from_secs(2);

/// Whether a write after `read_at` could get `stamp`'s mtime. Such a write
/// is stamped no earlier than [`RACY_WINDOW`] before `read_at` (a coarse
/// clock lags by up to one step), so only an mtime that recent — or one
/// in the future, written by a clock ahead of ours — can recur.
fn is_racy(stamp: &FileStamp, read_at: SystemTime) -> bool {
    match stamp.modified {
        Some(modified) => read_at
            .duration_since(modified)
            .map_or(true, |age| age < RACY_WINDOW),
        // No mtime to go by: only the contents tell versions apart.
        None => true,
    }
}

/// Certificate → role map backed by the bridge CA's `registry.json`
/// (`{"issued": {"<decimal serial>": {identity, role, fingerprint_sha256,
/// not_after, revoked, ...}}}`). An entry whose `identity` is missing or
/// unusable, whose `role` is missing or not one the bridge issues
/// (`keymaster` included), or whose `revoked`, `fingerprint_sha256` or
/// `not_after` is present but malformed, authorises no certificate (see
/// [`parse_identity`], [`parse_role`], [`parse_revoked`],
/// [`parse_fingerprint`] and [`parse_not_after`]). Neither does a serial
/// with more than one entry (`"66"` and `"066"`, or the same key twice).
///
/// Reloads automatically when the file changes, so a revocation on the
/// bridge side takes effect on the gateway's next lookup without a
/// restart. A change is a new mtime, size or inode ([`FileStamp`]; the
/// bridge replaces the file atomically, so every write has a new inode).
/// Since the mtime is coarse, two versions written within one timestamp
/// tick can share it; and an in-place rewrite of the same size keeps the
/// inode too. So a version read within [`RACY_WINDOW`] of its mtime is
/// read again on each lookup until one is read clear of that window,
/// as git does for "racily clean" index entries.
pub struct CertRegistry {
    path: PathBuf,
    inner: RwLock<RegistryInner>,
    /// Serialises reloads, so a slow one cannot install an older version
    /// over a newer one another lookup already loaded.
    reload_lock: Mutex<()>,
}

impl CertRegistry {
    /// Load the registry from *path*. Returns the registry even if the
    /// file is missing or unreadable (it then resolves nothing) so a
    /// not-yet-created registry does not block startup.
    pub fn load(path: &Path) -> Self {
        let registry = Self {
            path: path.to_path_buf(),
            inner: RwLock::new(RegistryInner::default()),
            reload_lock: Mutex::new(()),
        };
        registry.reload_if_changed();
        registry
    }

    fn parse(raw: &str) -> HashMap<String, CertEntry> {
        let mut out: HashMap<String, CertEntry> = HashMap::new();
        let issued = match serde_json::from_str::<RegistryFile>(raw) {
            Ok(RegistryFile(Some(IssuedEntries(issued)))) => issued,
            Ok(RegistryFile(None)) => return out,
            Err(e) => {
                warn!(error = %e, "CA registry is unreadable; it authorises no certificate");
                return out;
            }
        };
        for (serial_key, entry) in issued {
            let Some(serial) = canonical_serial(&serial_key) else {
                warn!(serial = %serial_key, "CA registry entry key is not a decimal serial — ignored");
                continue;
            };
            let parsed = Self::parse_entry(&serial, &entry);
            // Each certificate is its own entry: a revoked serial stays
            // revoked even when the identity holds a newer valid cert.
            // Two entries for one serial (`"66"` and `"066"`, or the same
            // key twice) fail closed: the bridge never writes them, and
            // letting the last one win would let a live copy replace a
            // revoked or malformed one, so the serial authorises nothing.
            match out.entry(serial) {
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(parsed);
                }
                std::collections::hash_map::Entry::Occupied(mut slot) => {
                    warn!(
                        serial = %slot.key(),
                        key = %serial_key,
                        "CA registry has more than one entry for this serial; it authorises no certificate"
                    );
                    slot.get_mut().malformed = true;
                }
            }
        }
        out
    }

    /// One `issued` entry. A malformed entry fails closed: it is kept (a
    /// dropped entry would free its serial) but marked unusable, and each
    /// reason is logged (see [`CertEntry::malformed`]).
    fn parse_entry(serial: &str, entry: &serde_json::Value) -> CertEntry {
        let mut malformed = false;
        let mut refuse = |field: &str, reason: String| {
            warn!(
                serial = %serial,
                field,
                reason = %reason,
                "CA registry entry is malformed; it authorises no certificate"
            );
            malformed = true;
        };
        let Some(fields) = entry.as_object() else {
            refuse("entry", format!("a {}, not an object", json_kind(entry)));
            return CertEntry {
                identity: String::new(),
                role: Role::Sensor,
                revoked: true,
                not_after: None,
                fingerprint: None,
                malformed: true,
            };
        };
        let identity = parse_identity(fields.get("identity")).unwrap_or_else(|reason| {
            refuse("identity", reason);
            String::new()
        });
        // The fallback is a placeholder: the entry is malformed and
        // authorises no certificate.
        let role = parse_role(fields.get("role")).unwrap_or_else(|reason| {
            refuse("role", reason);
            Role::Sensor
        });
        let revoked = parse_revoked(fields.get("revoked")).unwrap_or_else(|reason| {
            refuse("revoked", reason);
            true
        });
        let not_after = parse_not_after(fields.get("not_after")).unwrap_or_else(|reason| {
            refuse("not_after", reason);
            None
        });
        let fingerprint =
            parse_fingerprint(fields.get("fingerprint_sha256")).unwrap_or_else(|reason| {
                refuse("fingerprint_sha256", reason);
                None
            });
        CertEntry {
            identity,
            role,
            revoked,
            not_after,
            fingerprint,
            malformed,
        }
    }

    /// Whether the version loaded is known to be the one on disk, whose
    /// stamp is `disk`.
    fn is_current(&self, disk: Option<&FileStamp>) -> bool {
        let inner = self.inner.read().unwrap();
        matches!((&inner.version, disk), (Some(loaded), Some(disk)) if !loaded.racy && loaded.stamp == *disk)
    }

    fn reload_if_changed(&self) {
        if self.is_current(FileStamp::of(&self.path).as_ref()) {
            return;
        }
        let _reloading = self.reload_lock.lock().unwrap();
        // Before the stat and the read: what they see is no older.
        let read_at = SystemTime::now();
        let disk = FileStamp::of(&self.path);
        // Another lookup may have reloaded while this one waited.
        if self.is_current(disk.as_ref()) {
            return;
        }
        // Stat before read: should the file be replaced in between, the
        // stamp kept is the older one, and the next lookup reads again.
        let raw = disk.and_then(|stamp| {
            let raw = std::fs::read(&self.path).ok()?;
            Some((stamp, String::from_utf8(raw).ok()?))
        });
        let Some((stamp, raw)) = raw else {
            // Missing or unreadable: authorise nothing, not the last copy.
            let mut inner = self.inner.write().unwrap();
            inner.by_serial.clear();
            inner.version = None;
            return;
        };
        let version = RegistryVersion {
            stamp,
            digest: Sha256::digest(raw.as_bytes()).into(),
            racy: is_racy(&stamp, read_at),
        };
        let unchanged = {
            let inner = self.inner.read().unwrap();
            inner
                .version
                .as_ref()
                .is_some_and(|loaded| loaded.digest == version.digest)
        };
        if unchanged {
            self.inner.write().unwrap().version = Some(version);
            return;
        }
        let by_serial = Self::parse(&raw);
        info!(
            count = by_serial.len(),
            path = %self.path.display(),
            "Loaded CA cert registry"
        );
        let mut inner = self.inner.write().unwrap();
        inner.by_serial = by_serial;
        inner.version = Some(version);
    }

    /// Resolve a verified client certificate to a role.
    ///
    /// The registry entry is found by the certificate's serial number and
    /// must describe exactly this certificate: same fingerprint (when the
    /// registry records one — the bridge CA always does) and same identity.
    /// Returns `None` when the certificate is unknown, its entry is
    /// malformed, it does not match its entry, is revoked, or has expired.
    pub fn lookup(&self, cert: &ClientCertInfo) -> Option<Role> {
        self.reload_if_changed();
        let inner = self.inner.read().unwrap();
        let Some(entry) = inner.by_serial.get(&cert.serial) else {
            warn!(serial = %cert.serial, identity = %cert.identity, "Client cert serial not in the CA registry");
            return None;
        };
        if entry.malformed {
            warn!(serial = %cert.serial, identity = %cert.identity, "Client cert's CA registry entry is malformed");
            return None;
        }
        if let Some(fp) = &entry.fingerprint {
            if !constant_time_eq::constant_time_eq(
                fp.as_bytes(),
                cert.fingerprint_sha256.to_ascii_lowercase().as_bytes(),
            ) {
                warn!(serial = %cert.serial, "Client cert fingerprint does not match the CA registry");
                return None;
            }
        }
        if entry.identity != cert.identity {
            warn!(
                serial = %cert.serial,
                presented = %cert.identity,
                registered = %entry.identity,
                "Client cert identity does not match the CA registry"
            );
            return None;
        }
        if entry.is_valid() {
            Some(entry.role)
        } else {
            None
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    fn leaf_der(dns_name: &str) -> Vec<u8> {
        let cert = rcgen::generate_simple_self_signed(vec![dns_name.to_string()]).unwrap();
        cert.cert.der().to_vec()
    }

    /// Install a rustls crypto provider for tests. The gateway binaries
    /// do this at startup; unit tests must do it themselves. Multiple
    /// providers are in the dep tree, so the choice must be explicit.
    pub(crate) fn ensure_crypto_provider() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    #[test]
    fn parse_identity_from_san() {
        let der = leaf_der("local-edge");
        assert_eq!(parse_cert_identity(&der).as_deref(), Some("local-edge"));
    }

    #[test]
    fn parse_identity_rejects_garbage() {
        assert_eq!(parse_cert_identity(b"not a certificate"), None);
    }

    pub(crate) fn write_registry(entries: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, r#"{{"issued": {{{entries}}}}}"#).unwrap();
        f.flush().unwrap();
        f
    }

    /// A certificate for `identity` with the given serial number.
    fn cert_with_serial(identity: &str, serial: &[u8]) -> ClientCertInfo {
        let mut params = rcgen::CertificateParams::new(vec![identity.to_string()]).unwrap();
        params.serial_number = Some(rcgen::SerialNumber::from_slice(serial));
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        ClientCertInfo::from_der(cert.der()).unwrap()
    }

    /// A registry entry the way the bridge CA (`ca.py`) writes it.
    pub(crate) fn entry(
        cert: &ClientCertInfo,
        role: &str,
        revoked: bool,
        not_after: &str,
    ) -> String {
        format!(
            r#""{}": {{"identity": "{}", "role": "{role}", "san": "DNS:{}",
                 "fingerprint_sha256": "{}", "revoked": {revoked},
                 "not_after": "{not_after}"}}"#,
            cert.serial, cert.identity, cert.identity, cert.fingerprint_sha256
        )
    }

    pub(crate) const FAR_FUTURE: &str = "2099-01-01T00:00:00+00:00";

    #[test]
    fn from_der_reads_serial_and_fingerprint() {
        let cert = cert_with_serial("local-edge", &[0x01, 0x00]);
        assert_eq!(cert.identity, "local-edge");
        assert_eq!(cert.serial, "256");
        assert_eq!(cert.fingerprint_sha256.len(), 64);
        assert!(ClientCertInfo::from_der(b"garbage").is_none());
    }

    #[test]
    fn serial_decimal_matches_python_str_int() {
        assert_eq!(serial_to_decimal(&[]), "0");
        assert_eq!(serial_to_decimal(&[0x00]), "0");
        assert_eq!(serial_to_decimal(&[0x00, 0xff]), "255");
        assert_eq!(serial_to_decimal(&[0x3b, 0x9a, 0xca, 0x00]), "1000000000");
        // A 159-bit serial as x509.random_serial_number() makes:
        // int("7f" + "ff"*19, 16) == 2**159 - 1
        let mut max159 = vec![0x7f];
        max159.extend([0xff; 19]);
        assert_eq!(
            serial_to_decimal(&max159),
            "730750818665451459101842416358141509827966271487"
        );
        assert_eq!(canonical_serial("00042").as_deref(), Some("42"));
        assert_eq!(canonical_serial("0").as_deref(), Some("0"));
        assert_eq!(canonical_serial("12ab"), None);
    }

    #[test]
    fn registry_resolves_the_registered_certificate() {
        let cert = cert_with_serial("local-edge", &[0x42]);
        let f = write_registry(&entry(&cert, "node", false, FAR_FUTURE));
        let reg = CertRegistry::load(f.path());
        assert_eq!(reg.lookup(&cert), Some(Role::Node));
        // Another certificate for the same identity is not registered.
        let other = cert_with_serial("local-edge", &[0x43]);
        assert_eq!(reg.lookup(&other), None);
    }

    #[test]
    fn registry_rejects_revoked() {
        let cert = cert_with_serial("gone", &[0x10]);
        let f = write_registry(&entry(&cert, "node", true, FAR_FUTURE));
        let reg = CertRegistry::load(f.path());
        assert_eq!(reg.lookup(&cert), None);
    }

    #[test]
    fn registry_rejects_expired() {
        let cert = cert_with_serial("stale", &[0x11]);
        let f = write_registry(&entry(&cert, "node", false, "2000-01-01T00:00:00+00:00"));
        let reg = CertRegistry::load(f.path());
        assert_eq!(reg.lookup(&cert), None);
    }

    /// Regression (G9): the registry was keyed by identity and preferred
    /// any valid entry, so a revoked certificate kept authenticating as
    /// its identity once a newer valid certificate existed for it.
    #[test]
    fn revoked_cert_stays_revoked_after_rotation() {
        let old = cert_with_serial("rotated", &[0x01]);
        let new = cert_with_serial("rotated", &[0x02]);
        let f = write_registry(&format!(
            "{}, {}",
            entry(&old, "node", true, FAR_FUTURE),
            entry(&new, "node", false, FAR_FUTURE)
        ));
        let reg = CertRegistry::load(f.path());
        assert_eq!(reg.lookup(&old), None, "revoked serial is refused");
        assert_eq!(reg.lookup(&new), Some(Role::Node));
    }

    #[test]
    fn registry_requires_matching_fingerprint_and_identity() {
        let cert = cert_with_serial("edge-a", &[0x21]);
        // Same serial, different certificate (fingerprint).
        let forged = cert_with_serial("edge-a", &[0x21]);
        assert_ne!(cert.fingerprint_sha256, forged.fingerprint_sha256);
        let f = write_registry(&entry(&cert, "node", false, FAR_FUTURE));
        let reg = CertRegistry::load(f.path());
        assert_eq!(reg.lookup(&cert), Some(Role::Node));
        assert_eq!(reg.lookup(&forged), None, "fingerprint mismatch");

        // Same serial and fingerprint field but a different identity.
        let mut renamed = cert.clone();
        renamed.identity = "edge-b".into();
        assert_eq!(reg.lookup(&renamed), None, "identity mismatch");

        // Identities are case-sensitive: the bridge's `_IDENTITY_RE` allows
        // upper case, so `EDGE-A` is another agent.
        let mut upper = cert.clone();
        upper.identity = "EDGE-A".into();
        assert_eq!(reg.lookup(&upper), None, "identity differs only in case");
    }

    #[test]
    fn entry_without_fingerprint_matches_by_serial_and_identity() {
        let cert = cert_with_serial("legacy", &[0x31]);
        let f = write_registry(&format!(
            r#""{}": {{"identity": "legacy", "role": "sensor", "revoked": false,
                      "not_after": "{FAR_FUTURE}"}}"#,
            cert.serial
        ));
        let reg = CertRegistry::load(f.path());
        assert_eq!(reg.lookup(&cert), Some(Role::Sensor));

        // Without a fingerprint, serial and identity are all that bind the
        // entry, so the identity must match exactly — case included.
        let mut upper = cert.clone();
        upper.identity = "LEGACY".into();
        assert_eq!(reg.lookup(&upper), None, "identity differs only in case");
        let mut other = cert.clone();
        other.identity = "legacy-2".into();
        assert_eq!(reg.lookup(&other), None, "another identity");
    }

    /// A `fingerprint_sha256` that is present but unusable (empty, only
    /// separators or whitespace, not a string) must not quietly turn the
    /// entry into a fingerprint-less legacy one: the bridge always records
    /// the fingerprint, so such an entry is corrupt and binds no certificate.
    /// Only a *missing* fingerprint means serial-and-identity matching.
    #[test]
    fn registry_unusable_fingerprint_does_not_disable_the_binding() {
        let cert = cert_with_serial("local-edge", &[0x32]);
        // Another certificate with the same serial and identity.
        let forged = cert_with_serial("local-edge", &[0x32]);
        assert_ne!(cert.fingerprint_sha256, forged.fingerprint_sha256);
        let with_fingerprint = |fp: &str| {
            write_registry(&format!(
                r#""{}": {{"identity": "local-edge", "role": "admin",
                     "fingerprint_sha256": {fp}, "revoked": false,
                     "not_after": "{FAR_FUTURE}"}}"#,
                cert.serial
            ))
        };
        // Control: with the real fingerprint the template binds `cert` only.
        let f = with_fingerprint(&format!(r#""{}""#, cert.fingerprint_sha256));
        let reg = CertRegistry::load(f.path());
        assert_eq!(reg.lookup(&cert), Some(Role::Admin), "control");
        assert_eq!(reg.lookup(&forged), None, "control");

        for fp in [r#""""#, r#"":""#, r#"" ""#, "null", "123"] {
            let f = with_fingerprint(fp);
            assert_eq!(CertRegistry::load(f.path()).lookup(&forged), None, "{fp}");
        }
    }

    #[test]
    fn registry_missing_file_resolves_nothing() {
        let reg = CertRegistry::load(Path::new("/nonexistent/registry.json"));
        assert_eq!(reg.lookup(&cert_with_serial("anyone", &[0x05])), None);
    }

    #[test]
    fn verifier_builds_from_valid_ca_pem() {
        ensure_crypto_provider();
        let ca = rcgen::generate_simple_self_signed(vec!["test-ca".to_string()]).unwrap();
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(ca.cert.pem().as_bytes()).unwrap();
        f.flush().unwrap();
        assert!(load_client_verifier(f.path()).is_ok());
    }

    #[test]
    fn verifier_rejects_empty_ca_file() {
        ensure_crypto_provider();
        let f = tempfile::NamedTempFile::new().unwrap();
        assert!(load_client_verifier(f.path()).is_err());
    }

    // ── Security paths: the TLS client verifier ────────────────────────
    //
    // `load_client_verifier` decides authenticity: a presented certificate
    // must chain to the configured CA, be inside its validity period and be
    // meant for client authentication. These drive the verifier the TLS
    // acceptor uses directly, at a fixed verification time.

    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
        ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
    use rustls::server::danger::ClientCertVerifier;
    use rustls::{CertificateError, Error as TlsError};

    pub(crate) type TestCa = CertifiedIssuer<'static, KeyPair>;

    /// 2026-01-01T00:00:00Z — the verification time of the verifier tests.
    const NOW_SECS: u64 = 1_767_225_600;

    fn at(secs: u64) -> UnixTime {
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(secs))
    }

    fn dn(cn: &str) -> DistinguishedName {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        dn
    }

    /// A CA with the bridge CA's profile: CA:TRUE, keyCertSign.
    pub(crate) fn test_ca(name: &str) -> TestCa {
        let mut params = CertificateParams::default();
        params.distinguished_name = dn(name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap()
    }

    /// The bridge CA's client leaf profile (`ca.py`): CN = DNS SAN =
    /// identity, CA:FALSE, digitalSignature, clientAuth.
    fn leaf_params(identity: &str) -> CertificateParams {
        let mut params = CertificateParams::new(vec![identity.to_string()]).unwrap();
        params.distinguished_name = dn(identity);
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params
    }

    pub(crate) struct Leaf {
        pub(crate) der: CertificateDer<'static>,
        pub(crate) key: KeyPair,
    }

    impl Leaf {
        pub(crate) fn key_der(&self) -> PrivateKeyDer<'static> {
            PrivatePkcs8KeyDer::from(self.key.serialize_der()).into()
        }
    }

    fn sign_leaf(params: &CertificateParams, issuer: &Issuer<'_, KeyPair>) -> Leaf {
        let key = KeyPair::generate().unwrap();
        let der = params.signed_by(&key, issuer).unwrap().der().clone();
        Leaf { der, key }
    }

    /// A client certificate for `identity` issued by `issuer`, with the
    /// leaf profile adjusted by `tweak`.
    pub(crate) fn issue_leaf(
        issuer: &Issuer<'_, KeyPair>,
        identity: &str,
        tweak: impl FnOnce(&mut CertificateParams),
    ) -> Leaf {
        let mut params = leaf_params(identity);
        tweak(&mut params);
        sign_leaf(&params, issuer)
    }

    /// `der` as a PEM block with `label`.
    pub(crate) fn to_pem(label: &str, der: &[u8]) -> String {
        let b64 = data_encoding::BASE64.encode(der);
        let body: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|line| std::str::from_utf8(line).unwrap())
            .collect();
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            body.join("\n")
        )
    }

    /// A PEM file holding `contents`.
    pub(crate) fn pem_file(contents: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    /// The gateway's verifier for a client-CA bundle made of `cas`.
    fn verifier_trusting(cas: &[&TestCa]) -> Arc<dyn ClientCertVerifier> {
        ensure_crypto_provider();
        let bundle: String = cas.iter().map(|ca| ca.pem()).collect();
        load_client_verifier(pem_file(&bundle).path()).unwrap()
    }

    fn verify_at(
        verifier: &dyn ClientCertVerifier,
        leaf: &[u8],
        intermediates: &[CertificateDer<'static>],
        secs: u64,
    ) -> Result<(), TlsError> {
        verifier
            .verify_client_cert(&CertificateDer::from(leaf), intermediates, at(secs))
            .map(|_| ())
    }

    fn verify(verifier: &dyn ClientCertVerifier, leaf: &[u8]) -> Result<(), TlsError> {
        verify_at(verifier, leaf, &[], NOW_SECS)
    }

    fn replace_all(haystack: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
        assert_eq!(
            from.len(),
            to.len(),
            "same-length replacement keeps the DER shape"
        );
        let mut out = haystack.to_vec();
        let mut found = false;
        let mut i = 0;
        while i + from.len() <= out.len() {
            if &out[i..i + from.len()] == from {
                out[i..i + from.len()].copy_from_slice(to);
                found = true;
                i += from.len();
            } else {
                i += 1;
            }
        }
        assert!(found, "pattern must occur");
        out
    }

    #[test]
    fn verifier_accepts_a_client_cert_issued_by_the_ca() {
        let ca = test_ca("SigRift Test CA");
        let verifier = verifier_trusting(&[&ca]);
        let leaf = issue_leaf(&ca, "local-edge", |_| {});
        assert_eq!(verify(&*verifier, &leaf.der), Ok(()));
        assert_eq!(
            ClientCertInfo::from_der(&leaf.der).map(|c| c.identity),
            Some("local-edge".to_string())
        );
    }

    #[test]
    fn verifier_rejects_a_cert_from_another_ca() {
        let trusted = test_ca("SigRift Test CA");
        let verifier = verifier_trusting(&[&trusted]);

        let rogue = test_ca("Rogue CA");
        let leaf = issue_leaf(&rogue, "local-edge", |_| {});
        assert!(matches!(
            verify(&*verifier, &leaf.der),
            Err(TlsError::InvalidCertificate(
                CertificateError::UnknownIssuer
            ))
        ));

        // A CA that copies the trusted CA's name but not its key.
        let impostor = test_ca("SigRift Test CA");
        let leaf = issue_leaf(&impostor, "local-edge", |_| {});
        assert!(
            matches!(
                verify(&*verifier, &leaf.der),
                Err(TlsError::InvalidCertificate(CertificateError::BadSignature))
            ),
            "same-name CA"
        );

        // A self-signed certificate claiming the identity.
        let key = KeyPair::generate().unwrap();
        let self_signed = leaf_params("local-edge").self_signed(&key).unwrap();
        assert!(matches!(
            verify(&*verifier, self_signed.der()),
            Err(TlsError::InvalidCertificate(
                CertificateError::UnknownIssuer
            ))
        ));
    }

    #[test]
    fn verifier_rejects_an_expired_cert() {
        let ca = test_ca("SigRift Test CA");
        let verifier = verifier_trusting(&[&ca]);
        let leaf = issue_leaf(&ca, "stale-edge", |p| {
            p.not_before = rcgen::date_time_ymd(2024, 1, 1);
            p.not_after = rcgen::date_time_ymd(2025, 1, 1);
        });
        assert!(matches!(
            verify(&*verifier, &leaf.der),
            Err(TlsError::InvalidCertificate(
                CertificateError::Expired | CertificateError::ExpiredContext { .. }
            ))
        ));
        // The same certificate inside its validity period is accepted: the
        // refusal is the expiry, nothing else.
        let mid_2024 = NOW_SECS - 570 * 86_400;
        assert_eq!(verify_at(&*verifier, &leaf.der, &[], mid_2024), Ok(()));
    }

    #[test]
    fn verifier_rejects_a_not_yet_valid_cert() {
        let ca = test_ca("SigRift Test CA");
        let verifier = verifier_trusting(&[&ca]);
        let leaf = issue_leaf(&ca, "future-edge", |p| {
            p.not_before = rcgen::date_time_ymd(2027, 1, 1);
            p.not_after = rcgen::date_time_ymd(2028, 1, 1);
        });
        assert!(matches!(
            verify(&*verifier, &leaf.der),
            Err(TlsError::InvalidCertificate(
                CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. }
            ))
        ));
        let mid_2027 = NOW_SECS + 545 * 86_400;
        assert_eq!(verify_at(&*verifier, &leaf.der, &[], mid_2027), Ok(()));
    }

    #[test]
    fn verifier_rejects_a_cert_not_meant_for_client_auth() {
        let ca = test_ca("SigRift Test CA");
        let verifier = verifier_trusting(&[&ca]);
        for eku in [
            vec![ExtendedKeyUsagePurpose::ServerAuth],
            vec![ExtendedKeyUsagePurpose::CodeSigning],
            vec![ExtendedKeyUsagePurpose::EmailProtection],
        ] {
            let leaf = issue_leaf(&ca, "local-edge", |p| p.extended_key_usages = eku.clone());
            assert!(
                matches!(
                    verify(&*verifier, &leaf.der),
                    Err(TlsError::InvalidCertificate(
                        CertificateError::InvalidPurpose
                            | CertificateError::InvalidPurposeContext { .. }
                    ))
                ),
                "{eku:?}"
            );
        }
        // clientAuth next to another purpose is fine.
        let leaf = issue_leaf(&ca, "local-edge", |p| {
            p.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ]
        });
        assert_eq!(verify(&*verifier, &leaf.der), Ok(()));
    }

    /// What the TLS layer does *not* refuse: a CA-signed leaf with no EKU
    /// at all (webpki requires clientAuth only when an EKU is present), a
    /// leaf whose KeyUsage is only a CA purpose (KeyUsage is not checked on
    /// end entities), and a leaf under a trust anchor that has itself
    /// expired (trust anchors are a name and a key, with no validity). The
    /// bridge CA never issues such certificates, so none of them has a
    /// registry entry, and the registry is what refuses them.
    #[test]
    fn verifier_accepts_leaves_without_eku_or_signing_key_usage() {
        let ca = test_ca("SigRift Test CA");
        let verifier = verifier_trusting(&[&ca]);
        let issued = issue_leaf(&ca, "local-edge", |_| {});
        let issued_info = ClientCertInfo::from_der(&issued.der).unwrap();
        let f = write_registry(&entry(&issued_info, "admin", false, FAR_FUTURE));
        let reg = CertRegistry::load(f.path());
        assert_eq!(reg.lookup(&issued_info), Some(Role::Admin), "control");

        let mut expired_root = CertificateParams::default();
        expired_root.distinguished_name = dn("SigRift Expired CA");
        expired_root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        expired_root.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        expired_root.not_before = rcgen::date_time_ymd(2019, 1, 1);
        expired_root.not_after = rcgen::date_time_ymd(2021, 1, 1);
        let expired_root =
            CertifiedIssuer::self_signed(expired_root, KeyPair::generate().unwrap()).unwrap();
        let expired_verifier = verifier_trusting(&[&expired_root]);

        for (label, verifier, leaf) in [
            (
                "no EKU",
                &verifier,
                issue_leaf(&ca, "local-edge", |p| p.extended_key_usages = vec![]),
            ),
            (
                "KeyUsage keyCertSign only",
                &verifier,
                issue_leaf(&ca, "local-edge", |p| {
                    p.key_usages = vec![KeyUsagePurpose::KeyCertSign]
                }),
            ),
            (
                "KeyUsage cRLSign only",
                &verifier,
                issue_leaf(&ca, "local-edge", |p| {
                    p.key_usages = vec![KeyUsagePurpose::CrlSign]
                }),
            ),
            (
                "trust anchor expired in 2021",
                &expired_verifier,
                issue_leaf(&expired_root, "local-edge", |_| {}),
            ),
        ] {
            assert_eq!(verify(&**verifier, &leaf.der), Ok(()), "{label}");
            let info = ClientCertInfo::from_der(&leaf.der).unwrap();
            assert_eq!(info.identity, "local-edge", "{label}");
            assert_eq!(reg.lookup(&info), None, "{label}: not registered");
        }
    }

    /// `err` is webpki's `kind` error, which rustls passes on as
    /// `CertificateError::Other`.
    fn is_webpki_error(err: &Result<(), TlsError>, kind: &str) -> bool {
        matches!(
            err,
            Err(TlsError::InvalidCertificate(CertificateError::Other(other)))
                if format!("{other:?}").contains(kind)
        )
    }

    #[test]
    fn verifier_rejects_the_ca_certificate_presented_as_a_client_cert() {
        let ca = test_ca("SigRift Test CA");
        let verifier = verifier_trusting(&[&ca]);
        let result = verify(&*verifier, ca.der());
        assert!(is_webpki_error(&result, "CaUsedAsEndEntity"), "{result:?}");
    }

    /// A client certificate is not a CA: a registered agent cannot mint
    /// certificates for other identities with its own key.
    #[test]
    fn verifier_rejects_a_cert_minted_by_another_client_cert() {
        let ca = test_ca("SigRift Test CA");
        let verifier = verifier_trusting(&[&ca]);

        let agent_params = leaf_params("edge-a");
        let agent = sign_leaf(&agent_params, &ca);
        let agent_der = agent.der.clone();
        let agent_issuer = Issuer::new(agent_params, agent.key);
        let minted = issue_leaf(&agent_issuer, "edge-b", |_| {});
        // Refused because the issuer is CA:FALSE.
        let result = verify_at(&*verifier, &minted.der, &[agent_der], NOW_SECS);
        assert!(is_webpki_error(&result, "EndEntityUsedAsCa"), "{result:?}");

        // The same chain through a real intermediate CA is accepted.
        let mut sub_params = CertificateParams::default();
        sub_params.distinguished_name = dn("SigRift Sub CA");
        sub_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        sub_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let sub =
            CertifiedIssuer::signed_by(sub_params, KeyPair::generate().unwrap(), &ca).unwrap();
        let leaf = issue_leaf(&sub, "edge-b", |_| {});
        assert_eq!(
            verify_at(&*verifier, &leaf.der, &[sub.der().clone()], NOW_SECS),
            Ok(())
        );
        // ...but only when the client sends the intermediate.
        assert!(matches!(
            verify(&*verifier, &leaf.der),
            Err(TlsError::InvalidCertificate(
                CertificateError::UnknownIssuer
            ))
        ));
    }

    /// Editing the identity of an issued certificate (to impersonate
    /// another agent) breaks the CA signature.
    #[test]
    fn verifier_rejects_a_cert_edited_after_issuance() {
        let ca = test_ca("SigRift Test CA");
        let verifier = verifier_trusting(&[&ca]);
        let leaf = issue_leaf(&ca, "edge-aaaa", |_| {});

        let renamed = replace_all(&leaf.der, b"edge-aaaa", b"edge-root");
        assert_eq!(
            parse_cert_identity(&renamed).as_deref(),
            Some("edge-root"),
            "the edit really changes the identity"
        );
        assert!(matches!(
            verify(&*verifier, &renamed),
            Err(TlsError::InvalidCertificate(CertificateError::BadSignature))
        ));

        let mut bad_sig = leaf.der.to_vec();
        *bad_sig.last_mut().unwrap() ^= 0x01;
        assert!(
            matches!(
                verify(&*verifier, &bad_sig),
                Err(TlsError::InvalidCertificate(CertificateError::BadSignature))
            ),
            "flipped signature bit"
        );
    }

    #[test]
    fn verifier_and_parser_reject_malformed_certificates() {
        let ca = test_ca("SigRift Test CA");
        let verifier = verifier_trusting(&[&ca]);
        let leaf = issue_leaf(&ca, "local-edge", |_| {});
        let pem = to_pem("CERTIFICATE", &leaf.der);
        let truncated = &leaf.der[..leaf.der.len() / 2];
        for (label, bytes) in [
            ("empty", &b""[..]),
            ("garbage", &b"not a certificate"[..]),
            ("truncated", truncated),
            ("PEM text instead of DER", pem.as_bytes()),
        ] {
            assert!(
                matches!(
                    verify(&*verifier, bytes),
                    Err(TlsError::InvalidCertificate(CertificateError::BadEncoding))
                ),
                "{label}"
            );
            assert_eq!(ClientCertInfo::from_der(bytes), None, "{label}");
        }
    }

    #[test]
    fn verifier_trusts_every_ca_in_the_bundle() {
        // CA rotation: during the overlap the bundle holds both CAs.
        let old = test_ca("SigRift CA 2025");
        let new = test_ca("SigRift CA 2026");
        let verifier = verifier_trusting(&[&old, &new]);
        assert_eq!(
            verify(&*verifier, &issue_leaf(&old, "edge-a", |_| {}).der),
            Ok(())
        );
        assert_eq!(
            verify(&*verifier, &issue_leaf(&new, "edge-b", |_| {}).der),
            Ok(())
        );
        // Once the old CA is dropped from the bundle, its certs are refused.
        let verifier = verifier_trusting(&[&new]);
        assert!(matches!(
            verify(&*verifier, &issue_leaf(&old, "edge-a", |_| {}).der),
            Err(TlsError::InvalidCertificate(
                CertificateError::UnknownIssuer
            ))
        ));
    }

    /// A bad client-CA file fails startup rather than silently disabling
    /// verification.
    #[test]
    fn verifier_refuses_unusable_ca_files() {
        ensure_crypto_provider();
        let missing = Path::new("/nonexistent/client-ca.pem");
        assert!(load_client_verifier(missing).is_err(), "missing file");

        let ca = test_ca("SigRift Test CA");
        let bad_base64 = format!(
            "{}-----BEGIN CERTIFICATE-----\n!!!!not-base64!!!!\n-----END CERTIFICATE-----\n",
            ca.pem()
        );
        assert!(
            load_client_verifier(pem_file(&bad_base64).path()).is_err(),
            "undecodable PEM block next to a good CA"
        );

        let not_der = to_pem("CERTIFICATE", b"not DER at all");
        assert!(
            load_client_verifier(pem_file(&not_der).path()).is_err(),
            "PEM block that is not a certificate"
        );

        // A key instead of a certificate: refused, and the error does not
        // echo the key.
        let key_pem = KeyPair::generate().unwrap().serialize_pem();
        let Err(err) = load_client_verifier(pem_file(&key_pem).path()) else {
            panic!("a key file is not a CA bundle");
        };
        let err = err.to_string();
        assert!(err.contains("no certificates found"), "{err}");
        for line in key_pem.lines().filter(|l| !l.starts_with("-----")) {
            assert!(!err.contains(line), "error leaks key material: {err}");
        }
    }

    // ── Security paths: the mTLS handshake ─────────────────────────────
    //
    // An in-memory TLS handshake (no sockets) between a server configured
    // as the gateway configures it and a client.

    fn pump(from: &mut rustls::Connection, to: &mut rustls::Connection) -> Result<(), TlsError> {
        let mut wire = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut wire).unwrap();
        }
        let mut rd = wire.as_slice();
        while !rd.is_empty() {
            to.read_tls(&mut rd).unwrap();
            to.process_new_packets()?;
        }
        Ok(())
    }

    /// Handshake with a server whose client verifier trusts `client_cas`.
    /// The client presents `Some((chain, key))` — the certificates it sends,
    /// in order, proving possession with `key`'s private key — or no
    /// certificate. Returns the client chain the server accepted, or the
    /// error that failed the handshake.
    fn mtls_handshake(
        client_cas: &[&TestCa],
        client: Option<(Vec<CertificateDer<'static>>, &Leaf)>,
    ) -> Result<Option<Vec<CertificateDer<'static>>>, TlsError> {
        let verifier = verifier_trusting(client_cas);
        let server_ca = test_ca("Server CA");
        let server_leaf = issue_leaf(&server_ca, "localhost", |p| {
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth]
        });
        let server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![server_leaf.der.clone()], server_leaf.key_der())
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(server_ca.der().clone()).unwrap();
        let client_builder = rustls::ClientConfig::builder().with_root_certificates(roots);
        let client_config = match client {
            Some((chain, key)) => client_builder
                .with_client_auth_cert(chain, key.key_der())
                .unwrap(),
            None => client_builder.with_no_client_auth(),
        };
        let mut client: rustls::Connection =
            rustls::ClientConnection::new(Arc::new(client_config), "localhost".try_into().unwrap())
                .unwrap()
                .into();
        let mut server: rustls::Connection = rustls::ServerConnection::new(Arc::new(server_config))
            .unwrap()
            .into();
        for _ in 0..10 {
            pump(&mut client, &mut server)?;
            pump(&mut server, &mut client)?;
            let idle = !client.wants_write() && !server.wants_write();
            if idle && !client.is_handshaking() && !server.is_handshaking() {
                return Ok(server.peer_certificates().map(<[_]>::to_vec));
            }
        }
        panic!("handshake did not settle");
    }

    /// A client may send more certificates after its leaf, and the
    /// handshake still succeeds: rustls authenticates the first certificate
    /// (key possession and chain to the CA) and treats the rest only as
    /// candidate intermediates. The server then sees the whole chain, leaf first.
    /// An appended certificate can be another agent's real, registered
    /// certificate (certificates are public), so only the first one may
    /// ever be resolved to a role — `builder.rs` checks that the TLS
    /// acceptor does exactly that.
    #[test]
    fn mtls_handshake_accepts_extra_chain_certs_behind_the_leaf() {
        let ca = test_ca("SigRift Test CA");
        let attacker = issue_leaf(&ca, "edge-low", |_| {});
        let admin = issue_leaf(&ca, "edge-admin", |_| {});
        let sent = vec![attacker.der.clone(), admin.der.clone()];
        let chain = mtls_handshake(&[&ca], Some((sent.clone(), &attacker)))
            .expect("the extra certificate does not fail the handshake")
            .expect("the server sees the client chain");
        assert_eq!(chain, sent, "the chain as sent, leaf first");
    }

    /// A client that sends its own same-name CA along with its leaf, to
    /// make the chain look complete, is refused at the handshake.
    #[test]
    fn mtls_handshake_fails_for_a_cert_from_a_same_name_ca() {
        let trusted = test_ca("SigRift Test CA");
        let impostor = test_ca("SigRift Test CA");
        let leaf = issue_leaf(&impostor, "local-edge", |_| {});
        let result = mtls_handshake(
            &[&trusted],
            Some((vec![leaf.der.clone(), impostor.der().clone()], &leaf)),
        );
        assert!(
            matches!(
                result,
                Err(TlsError::InvalidCertificate(CertificateError::BadSignature))
            ),
            "{result:?}"
        );
    }

    /// Phase A is additive: no certificate still completes the handshake
    /// (API-key auth follows), with no client identity.
    #[test]
    fn mtls_handshake_without_a_cert_completes_unauthenticated() {
        let ca = test_ca("SigRift Test CA");
        let verifier = verifier_trusting(&[&ca]);
        assert!(verifier.offer_client_auth());
        assert!(!verifier.client_auth_mandatory());
        assert_eq!(mtls_handshake(&[&ca], None), Ok(None));
    }

    // ── Security paths: certificate identity ───────────────────────────

    #[test]
    fn identity_is_the_dns_san_not_the_common_name() {
        // A CN naming a more privileged identity does not override the SAN.
        let mut params = CertificateParams::new(vec!["edge-1".to_string()]).unwrap();
        params.distinguished_name = dn("admin-console");
        let cert = params.self_signed(&KeyPair::generate().unwrap()).unwrap();
        assert_eq!(parse_cert_identity(cert.der()).as_deref(), Some("edge-1"));

        // The first DNS SAN is the identity.
        let params =
            CertificateParams::new(vec!["edge-1".to_string(), "edge-2".to_string()]).unwrap();
        let cert = params.self_signed(&KeyPair::generate().unwrap()).unwrap();
        assert_eq!(parse_cert_identity(cert.der()).as_deref(), Some("edge-1"));
    }

    #[test]
    fn identity_falls_back_to_cn_only_without_a_dns_san() {
        // An IP-address SAN is not an identity: the CN is used.
        let mut params = CertificateParams::new(vec!["192.0.2.7".to_string()]).unwrap();
        params.distinguished_name = dn("edge-ip");
        let cert = params.self_signed(&KeyPair::generate().unwrap()).unwrap();
        assert_eq!(parse_cert_identity(cert.der()).as_deref(), Some("edge-ip"));

        // An empty DNS SAN is never an (empty) identity.
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![rcgen::SanType::DnsName("".try_into().unwrap())];
        params.distinguished_name = dn("edge-cn");
        let cert = params.self_signed(&KeyPair::generate().unwrap()).unwrap();
        assert_eq!(parse_cert_identity(cert.der()).as_deref(), Some("edge-cn"));
        params.distinguished_name = DistinguishedName::new();
        let cert = params.self_signed(&KeyPair::generate().unwrap()).unwrap();
        assert_eq!(parse_cert_identity(cert.der()), None);

        // No DNS SAN and no CN: no identity, so no ClientCertInfo.
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = DistinguishedName::new();
        let cert = params.self_signed(&KeyPair::generate().unwrap()).unwrap();
        assert_eq!(parse_cert_identity(cert.der()), None);
        assert_eq!(ClientCertInfo::from_der(cert.der()), None);
    }

    // ── Security paths: the registry ───────────────────────────────────

    /// Replace the registry at `path` with `{"issued": {entries}}` and give
    /// it the mtime `epoch_secs`, so a reload is detected without waiting.
    fn rewrite_registry(path: &Path, entries: &str, epoch_secs: u64) {
        std::fs::write(path, format!(r#"{{"issued": {{{entries}}}}}"#)).unwrap();
        set_mtime(path, epoch_secs);
    }

    fn set_mtime(path: &Path, epoch_secs: u64) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(epoch_secs))
            .unwrap();
    }

    /// Everything logged (INFO and above) on this thread while `f` runs.
    fn logs_of<R>(f: impl FnOnce() -> R) -> (R, String) {
        #[derive(Clone, Default)]
        struct Buffer(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Buffer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .finish();
        // A parallel test parsing a registry on a thread with no
        // subscriber would otherwise cache the registry's warn! callsites
        // as "never", and this thread would capture nothing.
        crate::test_support::keep_log_capture_reliable();
        let result = tracing::subscriber::with_default(subscriber, f);
        let text = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        (result, text)
    }

    /// The entry `{"issued": {entries}}` parses to for `serial`, and what
    /// parsing logged.
    fn parse_logged(entries: &str, serial: &str) -> (Option<CertEntry>, String) {
        let (mut parsed, logs) =
            logs_of(|| CertRegistry::parse(&format!(r#"{{"issued": {{{entries}}}}}"#)));
        (parsed.remove(serial), logs)
    }

    /// `entries` leave a kept but malformed entry for `serial` that is not
    /// valid, and parsing logged `field` as the malformed one.
    #[track_caller]
    fn assert_malformed(entries: &str, serial: &str, field: &str, label: &str) {
        let (parsed, logs) = parse_logged(entries, serial);
        let parsed = parsed.unwrap_or_else(|| panic!("{label}: entry dropped"));
        assert!(parsed.malformed, "{label}: not marked malformed");
        assert!(!parsed.is_valid(), "{label}: still valid");
        let warning = logs
            .lines()
            .find(|l| l.contains("CA registry entry is malformed"))
            .unwrap_or_else(|| panic!("{label}: nothing logged: {logs}"));
        assert!(
            warning.contains("WARN") && warning.contains(&format!(r#"field="{field}""#)),
            "{label}: {warning}"
        );
    }

    /// A revocation written by the bridge takes effect on the next lookup,
    /// without a gateway restart.
    #[test]
    fn revocation_on_disk_takes_effect_without_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let cert = cert_with_serial("local-edge", &[0x51]);
        rewrite_registry(&path, &entry(&cert, "node", false, FAR_FUTURE), 1_000_000);
        let reg = CertRegistry::load(&path);
        assert_eq!(reg.lookup(&cert), Some(Role::Node));

        rewrite_registry(&path, &entry(&cert, "node", true, FAR_FUTURE), 2_000_000);
        assert_eq!(reg.lookup(&cert), None, "revoked after reload");

        // A role downgrade propagates the same way.
        rewrite_registry(&path, &entry(&cert, "sensor", false, FAR_FUTURE), 3_000_000);
        assert_eq!(reg.lookup(&cert), Some(Role::Sensor));
    }

    /// A registry that disappears or becomes unreadable after startup
    /// authorises nothing; the last good copy is not kept.
    #[test]
    fn registry_fails_closed_when_it_vanishes_or_is_corrupted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let cert = cert_with_serial("local-edge", &[0x52]);
        let good = entry(&cert, "admin", false, FAR_FUTURE);

        rewrite_registry(&path, &good, 1_000_000);
        let reg = CertRegistry::load(&path);
        assert_eq!(reg.lookup(&cert), Some(Role::Admin));
        std::fs::write(&path, r#"{"issued": {"#).unwrap();
        set_mtime(&path, 2_000_000);
        assert_eq!(reg.lookup(&cert), None, "truncated JSON");

        rewrite_registry(&path, &good, 3_000_000);
        assert_eq!(reg.lookup(&cert), Some(Role::Admin));
        std::fs::write(&path, r#"{"certs": {}}"#).unwrap();
        set_mtime(&path, 4_000_000);
        assert_eq!(reg.lookup(&cert), None, "no \"issued\" map");

        rewrite_registry(&path, &good, 5_000_000);
        assert_eq!(reg.lookup(&cert), Some(Role::Admin));
        std::fs::remove_file(&path).unwrap();
        assert_eq!(reg.lookup(&cert), None, "registry deleted");
    }

    /// `{"issued": {entries}}`, the registry file's contents.
    fn registry_json(entries: &str) -> String {
        format!(r#"{{"issued": {{{entries}}}}}"#)
    }

    /// Replace the registry the way the bridge CA does (`ca._atomic_write`):
    /// a new file beside it, renamed over the old one — a new inode.
    fn replace_registry(path: &Path, entries: &str) {
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, registry_json(entries)).unwrap();
        std::fs::rename(&tmp, path).unwrap();
    }

    fn set_modified(path: &Path, modified: SystemTime) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(modified)
            .unwrap();
    }

    /// Regression: the registry was reloaded only when its mtime changed.
    /// Filesystem timestamps are coarse (Linux takes them from a clock that
    /// advances in 1-4 ms ticks), so a revocation the bridge wrote within
    /// the tick of the version the gateway had loaded — revoking right
    /// after issuing, or a batch of revocations — kept the same mtime and
    /// was never applied: the revoked certificate went on authenticating
    /// until some later write.
    #[test]
    fn a_revocation_written_in_the_same_mtime_tick_takes_effect() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let cert = cert_with_serial("local-edge", &[0x53]);
        replace_registry(&path, &entry(&cert, "admin", false, FAR_FUTURE));
        set_mtime(&path, 1_000_000);
        let reg = CertRegistry::load(&path);
        assert_eq!(reg.lookup(&cert), Some(Role::Admin));

        replace_registry(&path, &entry(&cert, "admin", true, FAR_FUTURE));
        set_mtime(&path, 1_000_000);
        assert_eq!(reg.lookup(&cert), None, "revoked in the same tick");
    }

    /// A version rewritten in place within the tick of the one loaded —
    /// same inode, same size, same mtime, so nothing the metadata shows has
    /// changed — still takes effect: a version loaded that close to its
    /// mtime is checked again.
    #[test]
    fn an_in_place_rewrite_in_the_same_mtime_tick_takes_effect() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let cert = cert_with_serial("local-edge", &[0x54]);
        let live = registry_json(&entry(&cert, "admin", false, FAR_FUTURE));
        // `true ` is as long as `false`: the size does not change either.
        let revoked = registry_json(&entry(&cert, "admin", true, FAR_FUTURE))
            .replace(r#""revoked": true,"#, r#""revoked": true ,"#);
        assert_eq!(live.len(), revoked.len());
        std::fs::write(&path, &live).unwrap();
        let written = std::fs::metadata(&path).unwrap().modified().unwrap();
        let reg = CertRegistry::load(&path);
        assert_eq!(reg.lookup(&cert), Some(Role::Admin));

        std::fs::write(&path, &revoked).unwrap();
        set_modified(&path, written);
        assert_eq!(reg.lookup(&cert), None, "revoked in place in the same tick");
    }

    /// Checking a version again does not re-parse it when it is unchanged:
    /// the registry is parsed (and logged) once per version.
    #[test]
    fn an_unchanged_registry_is_parsed_once() {
        let dir = tempfile::tempdir().unwrap();
        let cert = cert_with_serial("local-edge", &[0x55]);
        for (label, modified) in [
            ("written just now", None),
            ("written long ago", Some(1_000_000)),
        ] {
            let path = dir.path().join(format!("{}.json", modified.unwrap_or(0)));
            std::fs::write(
                &path,
                registry_json(&entry(&cert, "node", false, FAR_FUTURE)),
            )
            .unwrap();
            if let Some(secs) = modified {
                set_mtime(&path, secs);
            }
            let (roles, logs) = logs_of(|| {
                let reg = CertRegistry::load(&path);
                (0..3).map(|_| reg.lookup(&cert)).collect::<Vec<_>>()
            });
            assert_eq!(roles, [Some(Role::Node); 3], "{label}");
            assert_eq!(
                logs.matches("Loaded CA cert registry").count(),
                1,
                "{label}: {logs}"
            );
        }
    }

    /// An entry whose key is not a decimal serial is ignored (it names no
    /// certificate). An entry whose identity is missing, empty or not a
    /// string is kept but refused, like any other malformed entry.
    #[test]
    fn registry_refuses_entries_with_malformed_keys_or_identity() {
        let cert = cert_with_serial("local-edge", &[0x42]); // serial 66
        assert_eq!(cert.serial, "66");
        let fp = &cert.fingerprint_sha256;
        let shaped = |key: &str, identity: &str| {
            format!(
                r#""{key}": {{"identity": "{identity}", "role": "admin",
                     "fingerprint_sha256": "{fp}", "revoked": false,
                     "not_after": "{FAR_FUTURE}"}}"#
            )
        };
        for (label, entries) in [
            ("hex key", shaped("0x42", "local-edge")),
            ("signed key", shaped("-66", "local-edge")),
            ("float key", shaped("66.0", "local-edge")),
            ("empty key", shaped("", "local-edge")),
        ] {
            let f = write_registry(&entries);
            assert_eq!(CertRegistry::load(f.path()).lookup(&cert), None, "{label}");
            let parsed = CertRegistry::parse(&format!(r#"{{"issued": {{{entries}}}}}"#));
            assert!(parsed.is_empty(), "{label}");
        }
        for (label, entries) in [
            ("empty identity", shaped("66", "")),
            (
                "missing identity",
                format!(
                    r#""66": {{"role": "admin", "fingerprint_sha256": "{fp}",
                         "revoked": false, "not_after": "{FAR_FUTURE}"}}"#
                ),
            ),
            (
                "non-string identity",
                r#""66": {"identity": 66, "role": "admin"}"#.to_string(),
            ),
            (
                "null identity",
                format!(r#""66": {{"identity": null, "fingerprint_sha256": "{fp}"}}"#),
            ),
        ] {
            let f = write_registry(&entries);
            assert_eq!(CertRegistry::load(f.path()).lookup(&cert), None, "{label}");
            assert_malformed(&entries, "66", "identity", label);
        }
        for not_an_object in ["null", r#""local-edge""#, "66", "[]", "true"] {
            let entries = format!(r#""66": {not_an_object}"#);
            assert_eq!(
                CertRegistry::load(write_registry(&entries).path()).lookup(&cert),
                None,
                "{not_an_object}"
            );
            assert_malformed(&entries, "66", "entry", not_an_object);
        }
        // Leading zeros are the same decimal serial.
        let f = write_registry(&shaped("00066", "local-edge"));
        assert_eq!(
            CertRegistry::load(f.path()).lookup(&cert),
            Some(Role::Admin)
        );
    }

    /// The bridge (`ca.py` `_issue`, the only writer) always writes `role`,
    /// spelt exactly as one of `VALID_CERT_ROLES`, and refuses to issue any
    /// other. Every other role makes the entry malformed, logged at WARN
    /// with `field="role"`, and never falls back to a role: `keymaster` in
    /// any spelling (never delegated to a certificate), another spelling of
    /// a certificate role (letter case, whitespace, a Unicode case mapping
    /// that `to_uppercase()` turns into the role), an unknown name, a value
    /// that is not a string, and a missing role.
    #[test]
    fn registry_refuses_roles_the_bridge_never_writes() {
        let cert = cert_with_serial("local-edge", &[0x53]);
        let shaped = |role_field: &str| {
            format!(
                r#""{}": {{"identity": "local-edge", {role_field}
                     "fingerprint_sha256": "{}", "revoked": false,
                     "not_after": "{FAR_FUTURE}"}}"#,
                cert.serial, cert.fingerprint_sha256
            )
        };
        let lookup =
            |entries: &str| CertRegistry::load(write_registry(entries).path()).lookup(&cert);
        for (name, role) in [
            ("sensor", Role::Sensor),
            ("node", Role::Node),
            ("viewer", Role::Viewer),
            ("analyst", Role::Analyst),
            ("admin", Role::Admin),
        ] {
            let entries = shaped(&format!(r#""role": "{name}","#));
            assert_eq!(lookup(&entries), Some(role), "control {name}");
            let (parsed, logs) = parse_logged(&entries, &cert.serial);
            assert!(parsed.is_some_and(|e| !e.malformed), "control {name}");
            assert!(!logs.contains("malformed"), "control {name}: {logs}");
        }

        // JSON string contents, so `\u…` and `\n` are JSON escapes.
        let keymaster = [
            "keymaster",
            "KEYMASTER",
            "KeyMaster",
            r"keyma\u017fter", // U+017F LATIN SMALL LETTER LONG S
        ];
        // Other spellings that `Role::from_str` would read as the role
        // (U+0131 is LATIN SMALL LETTER DOTLESS I).
        let case_variants = ["ADMIN", "Admin", "Node", r"adm\u0131n"];
        let unknown = [
            " admin",
            "admin ",
            r"admin\n",
            r"\u0430dmin", // U+0430 CYRILLIC SMALL LETTER A
            "superuser",
            "root",
            "sensor,admin",
        ];
        let mut role_fields: Vec<(String, &str)> = Vec::new();
        for name in keymaster {
            role_fields.push((
                format!(r#""role": "{name}","#),
                "keymaster is never delegated to a certificate",
            ));
        }
        for name in case_variants {
            role_fields.push((
                format!(r#""role": "{name}","#),
                "not spelt as the bridge writes",
            ));
        }
        for name in unknown {
            role_fields.push((format!(r#""role": "{name}","#), "not a certificate role"));
        }
        role_fields.push((r#""role": "","#.to_string(), "empty"));
        for value in ["4", "null", "true", r#"["admin"]"#, r#"{"name": "admin"}"#] {
            role_fields.push((format!(r#""role": {value},"#), "not a string"));
        }
        role_fields.push((String::new(), "missing"));

        for (role_field, reason) in &role_fields {
            let entries = shaped(role_field);
            assert_eq!(lookup(&entries), None, "{role_field}");
            assert_malformed(&entries, &cert.serial, "role", role_field);
            let (_, logs) = parse_logged(&entries, &cert.serial);
            assert!(logs.contains(reason), "{role_field}: {logs}");
        }
        // The same through the bridge-shaped fixture, the way the probe
        // found it: no spelling of keymaster resolves to KEYMASTER.
        for name in ["keymaster", "KeyMaster", "keyma\u{17f}ter"] {
            assert_eq!(
                lookup(&entry(&cert, name, false, FAR_FUTURE)),
                None,
                "{name}"
            );
        }
    }

    /// A refused role is logged by its field and a reason built from the
    /// certificate roles only, never with the value itself, in any
    /// notation: `registry.json` is not trusted, and a role holding a
    /// newline would otherwise write a forged line into the gateway log at
    /// every registry load.
    #[test]
    fn registry_refusal_never_echoes_the_raw_role() {
        let cert = cert_with_serial("local-edge", &[0x54]);
        // One value per refusal reason, each with a marker no reason
        // contains (as JSON: `\n` is a JSON escape).
        for (role_value, marker) in [
            (r#""kEyMaStEr""#, "kEyMaStEr"),
            (r#""aDmIn""#, "aDmIn"),
            (r#""forged-role-7f3c""#, "forged-role-7f3c"),
            (
                r#""x\n2026-11-09T00:00:00.000000Z  INFO forged line""#,
                "forged line",
            ),
            (r#"{"name": "forged-object-role"}"#, "forged-object-role"),
            (r#"["forged-array-role"]"#, "forged-array-role"),
        ] {
            let entries = format!(
                r#""{}": {{"identity": "local-edge", "role": {role_value},
                     "fingerprint_sha256": "{}", "revoked": false,
                     "not_after": "{FAR_FUTURE}"}}"#,
                cert.serial, cert.fingerprint_sha256
            );
            assert_malformed(&entries, &cert.serial, "role", role_value);
            let (_, logs) = parse_logged(&entries, &cert.serial);
            assert!(!logs.contains(marker), "{role_value}: {logs}");
            // The refusal is the only line: nothing in the value starts
            // another one.
            assert_eq!(logs.lines().count(), 1, "{role_value}: {logs}");
        }
    }

    /// The registry resolves exactly the roles the bridge CA issues
    /// (`VALID_CERT_ROLES` in `ca.py`), each to the role of that name, and
    /// no other [`Role`]: KEYMASTER is never delegated to a certificate.
    #[test]
    fn registry_resolves_exactly_the_roles_the_bridge_ca_issues() {
        let ca_py = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../sigrift/bridge/ca.py");
        let source =
            std::fs::read_to_string(&ca_py).unwrap_or_else(|e| panic!("{}: {e}", ca_py.display()));
        let line = source
            .lines()
            .find(|l| l.starts_with("VALID_CERT_ROLES = "))
            .expect("VALID_CERT_ROLES in ca.py");
        let issued: Vec<&str> = line.split('"').skip(1).step_by(2).collect();
        assert_eq!(issued.len(), 5, "{line}");

        let cert = cert_with_serial("local-edge", &[0x60]);
        let mut resolved = Vec::new();
        for role in [
            Role::Sensor,
            Role::Node,
            Role::Viewer,
            Role::Analyst,
            Role::Admin,
            Role::Keymaster,
        ] {
            let f = write_registry(&entry(&cert, role.as_str(), false, FAR_FUTURE));
            match CertRegistry::load(f.path()).lookup(&cert) {
                Some(got) => {
                    assert_eq!(got, role);
                    resolved.push(role.as_str());
                }
                None => assert!(!issued.contains(&role.as_str()), "{role} refused"),
            }
        }
        resolved.sort_unstable();
        let mut issued = issued;
        issued.sort_unstable();
        assert_eq!(resolved, issued);
    }

    /// The fingerprint is compared in any common notation, and still binds
    /// the entry to exactly one certificate.
    #[test]
    fn registry_fingerprint_notation_is_normalised_but_still_binding() {
        let cert = cert_with_serial("local-edge", &[0x54]);
        let openssl_style = cert
            .fingerprint_sha256
            .to_ascii_uppercase()
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        let mut registered = cert.clone();
        registered.fingerprint_sha256 = format!(" {openssl_style} ");
        let f = write_registry(&entry(&registered, "node", false, FAR_FUTURE));
        let reg = CertRegistry::load(f.path());
        assert_eq!(reg.lookup(&cert), Some(Role::Node));

        let mut other = cert.clone();
        other.fingerprint_sha256 = "00".repeat(32);
        assert_eq!(reg.lookup(&other), None, "different certificate");
        let mut prefix = cert.clone();
        prefix.fingerprint_sha256.truncate(32);
        assert_eq!(reg.lookup(&prefix), None, "fingerprint prefix");
    }

    /// Expiry is enforced for the timestamp formats the bridge writes
    /// (`datetime.isoformat()` of an aware UTC datetime, microseconds
    /// included) and for other UTC offsets.
    #[test]
    fn registry_enforces_expiry_in_the_bridge_timestamp_formats() {
        let cert = cert_with_serial("local-edge", &[0x55]);
        for expired in [
            "2001-02-03T04:05:06.789012+00:00",
            "2001-02-03T04:05:06Z",
            "2001-02-03T04:05:06-05:00",
        ] {
            let f = write_registry(&entry(&cert, "node", false, expired));
            assert_eq!(
                CertRegistry::load(f.path()).lookup(&cert),
                None,
                "{expired}"
            );
        }
        for valid in ["2099-02-03T04:05:06.789012+00:00", "2099-02-03T04:05:06Z"] {
            let f = write_registry(&entry(&cert, "node", false, valid));
            assert_eq!(
                CertRegistry::load(f.path()).lookup(&cert),
                Some(Role::Node),
                "{valid}"
            );
        }
    }

    /// A `not_after` that is present but cannot be read (a naive timestamp
    /// such as Python's `isoformat()` of a naive datetime, text, a number)
    /// must not mean "never expires": the expiry is unknown, so the entry
    /// is not usable.
    #[test]
    fn registry_unparseable_not_after_is_not_a_free_pass() {
        let cert = cert_with_serial("local-edge", &[0x57]);
        let with_not_after = |not_after: &str| {
            write_registry(&format!(
                r#""{}": {{"identity": "local-edge", "role": "admin",
                     "fingerprint_sha256": "{}", "revoked": false,
                     "not_after": {not_after}}}"#,
                cert.serial, cert.fingerprint_sha256
            ))
        };
        // Control: the same template with a readable future expiry.
        let f = with_not_after(&format!(r#""{FAR_FUTURE}""#));
        assert_eq!(
            CertRegistry::load(f.path()).lookup(&cert),
            Some(Role::Admin),
            "control"
        );

        for not_after in [r#""2001-02-03T04:05:06""#, r#""garbage""#, "978307200"] {
            let f = with_not_after(not_after);
            assert_eq!(
                CertRegistry::load(f.path()).lookup(&cert),
                None,
                "{not_after}"
            );
        }
    }

    /// The bridge (`ca.py`) treats any truthy `revoked` as revoked (`if not
    /// entry.get("revoked")`, e.g. when building the CRL). The gateway must
    /// not accept a certificate the bridge considers revoked, and must keep
    /// accepting one whose flag is `false`, `null` or missing. (Other
    /// non-booleans, Python-falsy ones included, are refused outright: see
    /// `registry_refuses_every_non_boolean_revoked_flag`.)
    #[test]
    fn registry_treats_a_truthy_non_boolean_revoked_flag_as_revoked() {
        let cert = cert_with_serial("local-edge", &[0x56]);
        let with_revoked = |revoked_field: &str| {
            write_registry(&format!(
                r#""{}": {{"identity": "local-edge", "role": "admin",
                     "fingerprint_sha256": "{}", {revoked_field}
                     "not_after": "{FAR_FUTURE}"}}"#,
                cert.serial, cert.fingerprint_sha256
            ))
        };
        // Falsy in Python: the certificate stays usable. `false` is also
        // the control that the template itself resolves.
        for live in [r#""revoked": false,"#, r#""revoked": null,"#, ""] {
            let f = with_revoked(live);
            assert_eq!(
                CertRegistry::load(f.path()).lookup(&cert),
                Some(Role::Admin),
                "{live:?}"
            );
        }
        // Truthy in Python — non-empty strings (even "false" and "0"),
        // non-zero numbers, non-empty lists: revoked.
        for flag in [r#""true""#, r#""false""#, r#""0""#, "1", r#""yes""#, "[1]"] {
            let f = with_revoked(&format!(r#""revoked": {flag},"#));
            assert_eq!(CertRegistry::load(f.path()).lookup(&cert), None, "{flag}");
        }
    }

    /// An entry exactly as `ca.py` `_issue` writes it (every field, the
    /// `isoformat()` timestamps with microseconds, `revoked_at: null`) still
    /// resolves, and the same entry as `revoke()` leaves it is refused as
    /// revoked, not as malformed.
    #[test]
    fn registry_accepts_entries_exactly_as_the_bridge_writes_them() {
        let cert = cert_with_serial("local-edge", &[0x58]);
        let bridge_entry = |revoked: &str, revoked_at: &str| {
            format!(
                r#""{}": {{"identity": "local-edge", "role": "analyst",
                     "san": "DNS:local-edge",
                     "fingerprint_sha256": "{}",
                     "issued_at": "2026-01-01T00:00:00.123456+00:00",
                     "not_before": "2025-12-31T23:55:00.123456+00:00",
                     "not_after": "2099-01-01T00:00:00.123456+00:00",
                     "revoked": {revoked}, "revoked_at": {revoked_at}}}"#,
                cert.serial, cert.fingerprint_sha256
            )
        };
        let f = write_registry(&bridge_entry("false", "null"));
        assert_eq!(
            CertRegistry::load(f.path()).lookup(&cert),
            Some(Role::Analyst)
        );
        let revoked = bridge_entry("true", r#""2026-02-01T00:00:00.654321+00:00""#);
        let f = write_registry(&revoked);
        assert_eq!(CertRegistry::load(f.path()).lookup(&cert), None, "revoked");
        for (label, raw) in [
            ("issued", bridge_entry("false", "null")),
            ("revoked", revoked),
        ] {
            let parsed = CertRegistry::parse(&format!(r#"{{"issued": {{{raw}}}}}"#));
            let parsed = parsed.get(&cert.serial).expect(label);
            assert!(!parsed.malformed, "{label}");
            assert_eq!(parsed.revoked, label == "revoked", "{label}");
            assert_eq!(parsed.fingerprint.as_ref(), Some(&cert.fingerprint_sha256));
            assert!(parsed.not_after.is_some(), "{label}");
        }
    }

    /// Any `revoked` other than `true`, `false`, `null` or missing is
    /// malformed and refused, including values that are falsy in Python
    /// (`0`, `""`, `[]`, `{}`): the bridge never writes them, and its
    /// readers do not agree on what they mean.
    #[test]
    fn registry_refuses_every_non_boolean_revoked_flag() {
        let cert = cert_with_serial("local-edge", &[0x59]);
        for flag in [
            "0",
            "0.0",
            "2",
            "-1",
            r#""""#,
            r#""True""#,
            r#""revoked""#,
            "[]",
            "[false]",
            "{}",
            r#"{"a": 1}"#,
        ] {
            let entries = format!(
                r#""{}": {{"identity": "local-edge", "role": "admin",
                     "fingerprint_sha256": "{}", "revoked": {flag},
                     "not_after": "{FAR_FUTURE}"}}"#,
                cert.serial, cert.fingerprint_sha256
            );
            let f = write_registry(&entries);
            assert_eq!(CertRegistry::load(f.path()).lookup(&cert), None, "{flag}");
            assert_malformed(&entries, &cert.serial, "revoked", flag);
        }
    }

    /// A present but unusable `fingerprint_sha256` binds *no* certificate,
    /// not even the one the entry was issued for, and whatever its JSON
    /// type. A string that is not 64 hex digits once normalised (a prefix,
    /// extra digits, a `sha256:` label, not hex) is unusable too. Such a
    /// string could never equal a real fingerprint anyway, so the entry is
    /// also checked directly: it is marked malformed, and the log names the
    /// field.
    #[test]
    fn registry_unusable_fingerprint_binds_no_certificate() {
        let cert = cert_with_serial("local-edge", &[0x5a]);
        let forged = cert_with_serial("local-edge", &[0x5a]);
        let fp = &cert.fingerprint_sha256;
        for bad in [
            r#""""#.to_string(),
            r#"":""#.to_string(),
            r#"" ""#.to_string(),
            r#""::  ""#.to_string(),
            "null".to_string(),
            "123".to_string(),
            "true".to_string(),
            "[]".to_string(),
            format!(r#"["{fp}"]"#),
            format!(r#"{{"sha256": "{fp}"}}"#),
            r#""abc""#.to_string(),
            format!(r#""{}""#, "zz".repeat(32)),
            format!(r#""{}""#, &fp[..32]),
            format!(r#""{}""#, &fp[..63]),
            format!(r#""{fp}00""#),
            format!(r#""sha256:{fp}""#),
            format!(r#""{} {}""#, &fp[..32], &fp[32..]),
        ] {
            let entries = format!(
                r#""{}": {{"identity": "local-edge", "role": "admin",
                     "fingerprint_sha256": {bad}, "revoked": false,
                     "not_after": "{FAR_FUTURE}"}}"#,
                cert.serial
            );
            let f = write_registry(&entries);
            let reg = CertRegistry::load(f.path());
            assert_eq!(reg.lookup(&cert), None, "issued cert, {bad}");
            assert_eq!(reg.lookup(&forged), None, "other cert, {bad}");
            assert_malformed(&entries, &cert.serial, "fingerprint_sha256", &bad);
        }
    }

    /// `not_after` in every shape the gateway does not read leaves the
    /// expiry unknown, so the entry is unusable, whether the value would
    /// have meant the past or the future. RFC 3339 with a space separator
    /// is read; a missing `not_after` means no registry expiry.
    #[test]
    fn registry_unreadable_not_after_makes_the_entry_unusable() {
        let cert = cert_with_serial("local-edge", &[0x5b]);
        let with_not_after = |field: &str| {
            format!(
                r#""{}": {{"identity": "local-edge", "role": "admin",
                     "fingerprint_sha256": "{}", {field} "revoked": false}}"#,
                cert.serial, cert.fingerprint_sha256
            )
        };
        let lookup = |field: &str| {
            CertRegistry::load(write_registry(&with_not_after(field)).path()).lookup(&cert)
        };
        for bad in [
            r#""2099-01-01T00:00:00""#,
            r#""2099-01-01T00:00:00.123456""#,
            r#""2001-02-03""#,
            r#""2099-01-01""#,
            r#""""#,
            r#""never""#,
            r#"" 2099-01-01T00:00:00+00:00""#,
            "null",
            "true",
            "4102444800",
            "[]",
            "{}",
        ] {
            let field = format!(r#""not_after": {bad},"#);
            assert_eq!(lookup(&field), None, "{bad}");
            assert_malformed(&with_not_after(&field), &cert.serial, "not_after", bad);
        }
        // A space for the `T` is still RFC 3339, and is enforced both ways.
        assert_eq!(
            lookup(r#""not_after": "2001-02-03 04:05:06+00:00","#),
            None,
            "past, space separator"
        );
        assert_eq!(
            lookup(r#""not_after": "2099-02-03 04:05:06+00:00","#),
            Some(Role::Admin),
            "future, space separator"
        );
        // Missing: no registry expiry (the bridge always writes the field;
        // the TLS verifier still enforces the certificate's own notAfter).
        assert_eq!(lookup(""), Some(Role::Admin), "missing not_after");
    }

    /// A malformed entry is kept (marked unusable), not dropped, and a
    /// serial with more than one entry authorises no certificate, in either
    /// order. Otherwise another spelling of the same serial (`"066"`, `"66 "`,
    /// or the same key repeated) could stand in for a malformed or revoked
    /// entry. The bridge writes each serial once, as `str(serial)`, and its
    /// CRL lists `int(key)` of each revoked entry, so `"66 "` is serial 66
    /// to it too.
    #[test]
    fn registry_keeps_malformed_entries_as_unusable() {
        let cert = cert_with_serial("local-edge", &[0x42]); // serial 66
        assert_eq!(cert.serial, "66");
        let fp = &cert.fingerprint_sha256;
        let live = |key: &str| {
            format!(
                r#""{key}": {{"identity": "local-edge", "role": "admin",
                     "fingerprint_sha256": "{fp}", "revoked": false,
                     "not_after": "{FAR_FUTURE}"}}"#
            )
        };
        // The live "66" entry with one field replaced.
        let with = |from: &str, to: &str| {
            let good = live("66");
            assert!(good.contains(from), "{from}");
            good.replace(from, to)
        };
        let lookup =
            |entries: &str| CertRegistry::load(write_registry(entries).path()).lookup(&cert);
        let spellings = ["66", "066", "66 ", r"66\n"];
        for key in spellings {
            assert_eq!(lookup(&live(key)), Some(Role::Admin), "control {key:?}");
        }

        let fingerprint = format!(r#""fingerprint_sha256": "{fp}""#);
        let not_after = format!(r#""not_after": "{FAR_FUTURE}""#);
        for (field, bad) in [
            (
                "revoked",
                with(r#""revoked": false"#, r#""revoked": "true""#),
            ),
            (
                "fingerprint_sha256",
                with(&fingerprint, r#""fingerprint_sha256": """#),
            ),
            ("not_after", with(&not_after, r#""not_after": "garbage""#)),
            (
                "identity",
                with(r#""identity": "local-edge""#, r#""identity": """#),
            ),
            ("identity", with(r#""identity": "local-edge","#, "")),
            ("role", with(r#""role": "admin""#, r#""role": "keymaster""#)),
            ("role", with(r#""role": "admin""#, r#""role": "superuser""#)),
            ("role", with(r#""role": "admin","#, "")),
            ("entry", r#""66": null"#.to_string()),
        ] {
            assert_malformed(&bad, "66", field, &bad);
            for key in spellings {
                for entries in [
                    format!("{}, {bad}", live(key)),
                    format!("{bad}, {}", live(key)),
                ] {
                    assert_eq!(lookup(&entries), None, "{field}, {key:?}: {entries}");
                }
            }
        }

        // A revoked entry and a live copy of its serial, in either order.
        let revoked = with(r#""revoked": false"#, r#""revoked": true"#);
        assert_eq!(lookup(&revoked), None, "revoked alone");
        for key in spellings {
            for entries in [
                format!("{}, {revoked}", live(key)),
                format!("{revoked}, {}", live(key)),
            ] {
                assert_eq!(lookup(&entries), None, "revoked, {key:?}: {entries}");
            }
        }

        // Even two well-formed copies: which one the bridge means is unknown.
        let (parsed, logs) = parse_logged(&format!("{}, {}", live("66"), live("066")), "66");
        assert!(parsed.is_some_and(|e| e.malformed && !e.is_valid()));
        assert!(
            logs.lines().any(|l| l.contains("WARN")
                && l.contains("more than one entry for this serial")
                && l.contains(r#"key=066"#)),
            "{logs}"
        );
        assert_eq!(lookup(&format!("{}, {}", live("66"), live("66"))), None);
        // Other serials in the same file are not affected.
        let other = cert_with_serial("local-edge", &[0x43]); // serial 67
        let f = write_registry(&format!(
            "{}, {}, {}",
            live("66"),
            live("066"),
            entry(&other, "node", false, FAR_FUTURE)
        ));
        assert_eq!(
            CertRegistry::load(f.path()).lookup(&other),
            Some(Role::Node)
        );
    }

    /// The lookup that turns a certificate away because its entry is
    /// malformed says so (the parse-time warning names the field; this one
    /// names the certificate). A revoked entry is refused, but not as
    /// malformed.
    #[test]
    fn registry_lookup_logs_a_malformed_entry_as_the_reason() {
        let cert = cert_with_serial("local-edge", &[0x5e]);
        let good = entry(&cert, "admin", false, FAR_FUTURE);
        let lookup_logged = |entries: &str| {
            let f = write_registry(entries);
            let reg = CertRegistry::load(f.path());
            logs_of(|| reg.lookup(&cert))
        };
        let (role, logs) = lookup_logged(&good);
        assert_eq!(role, Some(Role::Admin), "control");
        assert!(!logs.contains("malformed"), "control: {logs}");

        for (from, to) in [
            (
                format!(r#""fingerprint_sha256": "{}""#, cert.fingerprint_sha256),
                r#""fingerprint_sha256": """#,
            ),
            (
                format!(r#""not_after": "{FAR_FUTURE}""#),
                r#""not_after": "garbage""#,
            ),
            (
                r#""identity": "local-edge""#.to_string(),
                r#""identity": """#,
            ),
            (r#""revoked": false"#.to_string(), r#""revoked": "true""#),
            (r#""role": "admin""#.to_string(), r#""role": "keymaster""#),
            (r#""role": "admin""#.to_string(), r#""role": "superuser""#),
        ] {
            assert!(good.contains(from.as_str()), "{from}");
            let (role, logs) = lookup_logged(&good.replace(from.as_str(), to));
            assert_eq!(role, None, "{to}");
            assert!(
                logs.lines().any(|l| l.contains("WARN")
                    && l.contains("Client cert's CA registry entry is malformed")
                    && l.contains(&format!("serial={}", cert.serial))),
                "{to}: {logs}"
            );
        }

        let (role, logs) = lookup_logged(&entry(&cert, "admin", true, FAR_FUTURE));
        assert_eq!(role, None, "revoked");
        assert!(!logs.contains("malformed"), "revoked: {logs}");
    }

    /// Only a JSON object with one `issued` object is read as a registry;
    /// any other shape authorises nothing, including a second `issued` key
    /// (JSON readers keep only the last one, which would hide the first).
    /// Other top-level keys are ignored.
    #[test]
    fn registry_reads_a_single_issued_object() {
        let cert = cert_with_serial("local-edge", &[0x5f]);
        let good = entry(&cert, "node", false, FAR_FUTURE);
        let lookup = |raw: &str| CertRegistry::load(pem_file(raw).path()).lookup(&cert);
        assert_eq!(
            lookup(&format!(
                r#"{{"version": 1, "issued": {{{good}}}, "other": [1, {{"issued": null}}]}}"#
            )),
            Some(Role::Node),
            "control"
        );
        for raw in [
            format!(r#"[{{"issued": {{{good}}}}}]"#),
            format!(r#"[{{{good}}}]"#),
            format!(r#"{{"issued": [{{{good}}}]}}"#),
            r#"{"issued": null}"#.to_string(),
            r#""issued""#.to_string(),
            format!(r#"{{"issued": {{{good}}}, "issued": {{{good}}}}}"#),
            format!(r#"{{"issued": {{}}, "issued": {{{good}}}}}"#),
            format!(r#"{{"issued": {{{good}}}}} trailing"#),
        ] {
            assert_eq!(lookup(&raw), None, "{raw}");
            assert!(CertRegistry::parse(&raw).is_empty(), "{raw}");
        }
    }

    /// A registry rewritten with a malformed field takes effect on the next
    /// lookup, as a revocation does. This is the path the auth middleware
    /// and the WebSocket re-check use.
    #[test]
    fn malformed_entry_on_disk_takes_effect_without_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let cert = cert_with_serial("local-edge", &[0x5c]);
        let shaped = |revoked: &str, fingerprint: &str, not_after: &str| {
            format!(
                r#""{}": {{"identity": "local-edge", "role": "node",
                     "fingerprint_sha256": {fingerprint}, "revoked": {revoked},
                     "not_after": {not_after}}}"#,
                cert.serial
            )
        };
        let fp = format!(r#""{}""#, cert.fingerprint_sha256);
        let until = format!(r#""{FAR_FUTURE}""#);
        rewrite_registry(&path, &shaped("false", &fp, &until), 1_000_000);
        let reg = CertRegistry::load(&path);
        assert_eq!(reg.lookup(&cert), Some(Role::Node), "control");

        let mut mtime = 1_000_000;
        for (label, bad) in [
            ("revoked", shaped(r#""true""#, &fp, &until)),
            ("fingerprint_sha256", shaped("false", "null", &until)),
            (
                "not_after",
                shaped("false", &fp, r#""2099-01-01T00:00:00""#),
            ),
        ] {
            mtime += 1_000_000;
            rewrite_registry(&path, &bad, mtime);
            assert_eq!(reg.lookup(&cert), None, "{label}");
            mtime += 1_000_000;
            rewrite_registry(&path, &shaped("false", &fp, &until), mtime);
            assert_eq!(reg.lookup(&cert), Some(Role::Node), "{label}: repaired");
        }
    }

    /// Through the full auth middleware, a certificate whose registry entry
    /// is malformed is not authenticated (the request stays anonymous), while
    /// the same entry well-formed authenticates it.
    #[tokio::test]
    async fn malformed_registry_entry_does_not_authenticate_a_request() {
        use crate::middleware::auth::AuthInfo;
        use crate::ws::test_harness as h;
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt as _;

        async fn who(req: Request<Body>) -> String {
            match req.extensions().get::<AuthInfo>() {
                Some(AuthInfo::ApiKey { key_id, role }) => format!("{key_id}:{}", role.as_str()),
                Some(AuthInfo::Session { .. }) => "session".into(),
                Some(AuthInfo::Unauthenticated) | None => "anonymous".into(),
            }
        }

        let cert = cert_with_serial("local-edge", &[0x5d]);
        let dir = tempfile::tempdir().unwrap();
        let registry = dir.path().join("registry.json");
        let state = h::with_cert_registry(
            h::state(&dir, "http://127.0.0.1:1", &h::keys_file(&[]), None),
            &registry,
        );
        let app = axum::Router::new()
            .route("/api/whoami", axum::routing::get(who))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                crate::middleware::auth::auth_middleware,
            ))
            .with_state(Arc::clone(&state));
        let whoami = |app: axum::Router| {
            let cert = cert.clone();
            async move {
                let mut req = Request::builder()
                    .uri("/api/whoami")
                    .body(Body::empty())
                    .unwrap();
                req.extensions_mut().insert(cert);
                let resp = app.oneshot(req).await.unwrap();
                let bytes = axum::body::to_bytes(resp.into_body(), 1 << 10)
                    .await
                    .unwrap();
                String::from_utf8(bytes.to_vec()).unwrap()
            }
        };

        rewrite_registry(
            &registry,
            &entry(&cert, "admin", false, FAR_FUTURE),
            1_000_000,
        );
        assert_eq!(whoami(app.clone()).await, "local-edge:admin", "control");

        let good = entry(&cert, "admin", false, FAR_FUTURE);
        let malformed = [
            (r#""revoked": false"#.to_string(), r#""revoked": "true""#),
            (
                format!(r#""fingerprint_sha256": "{}""#, cert.fingerprint_sha256),
                r#""fingerprint_sha256": """#,
            ),
            (
                format!(r#""not_after": "{FAR_FUTURE}""#),
                r#""not_after": "2099-01-01T00:00:00""#,
            ),
            // Not `local-edge:keymaster`, nor a fallback role.
            (r#""role": "admin""#.to_string(), r#""role": "keymaster""#),
            (r#""role": "admin""#.to_string(), r#""role": "KeyMaster""#),
            (r#""role": "admin""#.to_string(), r#""role": "superuser""#),
            (r#""role": "admin", "#.to_string(), ""),
        ];
        for (n, (from, to)) in malformed.iter().enumerate() {
            assert!(good.contains(from.as_str()), "{from}");
            rewrite_registry(
                &registry,
                &good.replace(from.as_str(), to),
                2_000_000 + n as u64,
            );
            assert_eq!(whoami(app.clone()).await, "anonymous", "{to}");
        }
    }

    /// Client-certificate identity comes only from the TLS layer (the
    /// acceptor's request extension). Headers that describe a certificate —
    /// as a TLS-terminating proxy might send them — authenticate nothing.
    #[tokio::test]
    async fn cert_headers_cannot_stand_in_for_a_verified_client_cert() {
        use crate::middleware::auth::AuthInfo;
        use crate::ws::test_harness as h;
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt as _;

        async fn who(req: Request<Body>) -> String {
            match req.extensions().get::<AuthInfo>() {
                Some(AuthInfo::ApiKey { key_id, role }) => format!("{key_id}:{}", role.as_str()),
                Some(AuthInfo::Session { .. }) => "session".into(),
                Some(AuthInfo::Unauthenticated) | None => "anonymous".into(),
            }
        }

        let ca = test_ca("SigRift Test CA");
        let leaf = issue_leaf(&ca, "local-edge", |_| {});
        let cert = ClientCertInfo::from_der(&leaf.der).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let registry = dir.path().join("registry.json");
        rewrite_registry(
            &registry,
            &entry(&cert, "admin", false, FAR_FUTURE),
            1_000_000,
        );
        let state = h::with_cert_registry(
            h::state(&dir, "http://127.0.0.1:1", &h::keys_file(&[]), None),
            &registry,
        );
        let app = axum::Router::new()
            .route("/api/whoami", axum::routing::get(who))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                crate::middleware::auth::auth_middleware,
            ))
            .with_state(Arc::clone(&state));

        let der_b64 = data_encoding::BASE64.encode(&leaf.der);
        let pem_escaped = to_pem("CERTIFICATE", &leaf.der).replace('\n', "%0A");
        let xfcc = format!(
            "Hash={};Subject=\"CN=local-edge\";DNS=local-edge",
            cert.fingerprint_sha256
        );
        let request = |with_tls_cert: bool| {
            let mut req = Request::builder()
                .uri("/api/whoami")
                .header("x-client-cert", &der_b64)
                .header("x-ssl-client-cert", &pem_escaped)
                .header("ssl-client-cert", &pem_escaped)
                .header("x-forwarded-client-cert", &xfcc)
                .header("x-client-cert-serial", &cert.serial)
                .header("x-client-cert-fingerprint", &cert.fingerprint_sha256)
                .header("x-ssl-client-s-dn", "CN=local-edge")
                .header("x-ssl-client-verify", "SUCCESS")
                .header("x-auth-method", "client-cert")
                .header("x-auth-identity", "local-edge")
                .header("x-auth-role", "admin")
                .body(Body::empty())
                .unwrap();
            if with_tls_cert {
                req.extensions_mut().insert(cert.clone());
            }
            req
        };
        let body = |resp: axum::response::Response| async move {
            let bytes = axum::body::to_bytes(resp.into_body(), 1 << 10)
                .await
                .unwrap();
            String::from_utf8(bytes.to_vec()).unwrap()
        };

        let resp = app.clone().oneshot(request(false)).await.unwrap();
        assert_eq!(body(resp).await, "anonymous", "headers alone");
        // Control: the same request with the certificate from the TLS layer.
        let resp = app.oneshot(request(true)).await.unwrap();
        assert_eq!(body(resp).await, "local-edge:admin");
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    /// A registry version whose mtime cannot be read gives no stamp to
    /// trust, so it counts as racy and is read again on every lookup: a
    /// rewrite that keeps its size and inode (a revocation edited in place)
    /// is never missed. An mtime in the future (a clock ahead of ours) is
    /// racy too; one well in the past is not.
    #[test]
    fn a_registry_version_without_a_trustworthy_mtime_is_read_again() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut stamp = FileStamp::of(file.path()).unwrap();
        let read_at = SystemTime::now();

        stamp.modified = None;
        assert!(is_racy(&stamp, read_at), "no mtime");
        stamp.modified = Some(read_at + Duration::from_secs(3600));
        assert!(is_racy(&stamp, read_at), "an mtime in the future");
        stamp.modified = Some(read_at - Duration::from_secs(3600));
        assert!(!is_racy(&stamp, read_at), "an mtime an hour old");
    }
}
