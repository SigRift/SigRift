//! API key store and validation.
//!
//! Keys live in `keys.json`, written by the Python backend
//! (`sigrift.bridge.persistence`) with an atomic tmp + rename. The store:
//!
//! * reloads the file whenever its mtime, size or inode changes (the
//!   [`CertRegistry`](super::client_cert::CertRegistry) pattern), so a
//!   revocation (`persistence.remove_key`) or a new key takes effect on the
//!   next request without a restart. A reload that fails — unreadable,
//!   truncated or invalid JSON — keeps the previous good key set;
//! * enforces `expires_at` (Python `datetime.isoformat()`; a naive value
//!   is UTC, an unparseable one is treated as already expired);
//! * finds the candidate entry by `lookup_hash` (hex SHA-256 of the raw
//!   key, Python `compute_lookup_hash`) and runs PBKDF2 against that one
//!   entry only. A key with no lookup-hash match is rejected without any
//!   PBKDF2, unless the file still holds legacy entries written before
//!   `lookup_hash` existed: then, like the bridge, it is checked against
//!   every usable legacy entry (a "legacy scan");
//! * runs PBKDF2 on tokio's blocking pool, never on an async worker, and
//!   bounds it: at most [`PBKDF2_CONCURRENCY`] verifications at a time, of
//!   which at most [`LEGACY_SCAN_CONCURRENCY`] legacy scans, with at most
//!   [`LEGACY_SCAN_MAX_WAITING`] more scans waiting — any further scan is
//!   rejected at once without PBKDF2. The permits travel with the blocking
//!   task, which cannot be cancelled, so they are held until PBKDF2 has
//!   finished even if the request is dropped (client disconnect) first;
//! * caches results — successes for 60 s (`SUCCESS_CACHE_TTL`), failures
//!   until the next reload — from inside the blocking task, so a dropped
//!   request still leaves its result behind and a repeat costs no PBKDF2.
//!   Every reload clears the caches, so a cached key never outlives a
//!   revocation the store has seen;
//! * reads each key's role as the bridge does ([`effective_role`]): the
//!   master key is ADMIN, a missing or unknown role is VIEWER, and a key
//!   whose id starts with one of [`EDGE_KEY_PREFIXES`] and that is stored
//!   with a role of ANALYST or higher (in any letter case) acts as NODE.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use axum::{extract::Request, http::StatusCode};
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{info, warn};

pub use super::rbac::Role;

/// Native queries and login are bound to this one instance tenant. This is
/// not per-request routing; foreign credentials must never select local data.
pub const INSTANCE_TENANT: &str = "default";

#[derive(Debug)]
pub struct ForeignTenant;

type ScopedKey = (String, Role, bool);

/// Key-id prefixes of edge/sensor node keys (the bridge's
/// `persistence._EDGE_PREFIXES`). See [`effective_role`].
pub const EDGE_KEY_PREFIXES: [&str; 6] =
    ["node_", "rtlsdr_", "hackrf_", "sensor_", "edge_", "sdr_"];

/// The bridge's master API key: always ADMIN (`stored_key_role`), however
/// keys.json stores its role. See [`effective_role`].
pub const MASTER_KEY_ID: &str = "master";

/// The role of a key stored without a role, or with one that names none:
/// VIEWER, the bridge's least-privilege default (`_role_from_name`).
/// Never a node role: SENSOR and NODE keys are node credentials, bound to
/// the first node they report for (K7b). See [`effective_role`].
pub const DEFAULT_KEY_ROLE: Role = Role::Viewer;

/// PBKDF2-HMAC-SHA256 iterations — matches Python `credentials.py`.
const PBKDF2_ITERATIONS: u32 = 600_000;
/// How long a successful validation is served from cache.
const SUCCESS_CACHE_TTL: Duration = Duration::from_secs(60);
/// Entry caps for the success / failure caches (cleared when full).
const SUCCESS_CACHE_MAX: usize = 1024;
const FAILED_CACHE_MAX: usize = 1024;
/// API-key PBKDF2 verifications running at once (indexed lookups and
/// legacy scans together). Further ones wait for a slot.
pub const PBKDF2_CONCURRENCY: usize = 4;
/// Legacy scans running at once (each may run one PBKDF2 per legacy entry).
pub const LEGACY_SCAN_CONCURRENCY: usize = 2;
/// Legacy scans allowed to wait for a slot; a scan beyond that is rejected
/// at once, without PBKDF2, rather than queued without limit.
pub const LEGACY_SCAN_MAX_WAITING: usize = 8;
/// Above this many legacy entries a legacy scan gets slow; warn about it.
const LEGACY_SCAN_SLOW: usize = 16;
/// Most legacy key_ids named in one log line.
const LEGACY_IDS_LOGGED: usize = 64;

#[derive(Debug, Clone)]
pub struct ApiKey {
    pub key_id: String,
    pub hash: String,
    pub salt: String,
    pub role: Role,
    pub node_id: Option<String>,
    pub enabled: bool,
    /// Absent legacy metadata inherits the instance; explicit values must match.
    pub instance_tenant: bool,
    /// Lowercase hex SHA-256 of the raw key (Python `compute_lookup_hash`).
    /// `None` for legacy entries written before the field existed.
    pub lookup_hash: Option<String>,
    /// Expiry from `expires_at`. An unparseable value is stored as
    /// [`DateTime::<Utc>::MIN_UTC`] so the key is rejected (fail closed).
    pub expires_at: Option<DateTime<Utc>>,
}

impl ApiKey {
    /// Usable = enabled and not past `expires_at` (Python rejects when
    /// `now > expires_at`).
    fn is_usable(&self, now: DateTime<Utc>) -> bool {
        self.enabled
            && match self.expires_at {
                Some(exp) => now <= exp,
                None => true,
            }
    }
}

/// One parsed version of `keys.json`.
#[derive(Default)]
struct KeySet {
    keys: Vec<ApiKey>,
    /// lookup_hash → indexes into `keys`.
    by_lookup: HashMap<String, Vec<usize>>,
    /// Indexes of entries without a usable `lookup_hash`.
    legacy: Vec<usize>,
}

/// Identity of one on-disk version of the keys file (and of the CA
/// registry, [`CertRegistry`](super::client_cert::CertRegistry)). Python
/// replaces the file atomically, so the inode changes on every write;
/// mtime and size catch in-place edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FileStamp {
    pub(super) modified: Option<SystemTime>,
    len: u64,
    #[cfg(unix)]
    ino: u64,
}

impl FileStamp {
    pub(super) fn of(path: &Path) -> Option<Self> {
        let meta = std::fs::metadata(path).ok()?;
        Some(Self {
            modified: meta.modified().ok(),
            len: meta.len(),
            #[cfg(unix)]
            ino: std::os::unix::fs::MetadataExt::ino(&meta),
        })
    }
}

/// The bridge's node registry, `nodes.json` (`{"nodes": {"<node id>":
/// {...}}}`), which the bridge (`sigrift.bridge.persistence`) keeps in the
/// same data directory as keys.json. Read only for the bridge's legacy
/// rule that a key whose id is a registered node's id is that node's key
/// ([`KeyStore::is_registered_node`]). Reloaded when the file changes; a
/// missing file is an empty registry, and a version that cannot be read
/// or parsed keeps the previous one.
struct NodeRegistry {
    path: PathBuf,
    /// The stamp of the version last attempted, and the node ids loaded.
    loaded: Mutex<(Option<FileStamp>, Arc<HashSet<String>>)>,
}

impl NodeRegistry {
    /// The file name the bridge uses (`persistence._FILES["nodes"]`).
    const FILE_NAME: &'static str = "nodes.json";

    fn beside(keys_path: &Path) -> Self {
        Self {
            path: keys_path.with_file_name(Self::FILE_NAME),
            loaded: Mutex::new((None, Arc::default())),
        }
    }

    fn parse(raw: &[u8]) -> Result<HashSet<String>, String> {
        let value: serde_json::Value = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
        match value.get("nodes") {
            None | Some(serde_json::Value::Null) => Ok(HashSet::new()),
            Some(serde_json::Value::Object(nodes)) => Ok(nodes.keys().cloned().collect()),
            Some(_) => Err("\"nodes\" is not an object".into()),
        }
    }

    fn current(&self) -> Arc<HashSet<String>> {
        let disk = FileStamp::of(&self.path);
        let mut loaded = self.loaded.lock().unwrap();
        if loaded.0 == disk {
            return Arc::clone(&loaded.1);
        }
        let nodes = match std::fs::read(&self.path) {
            Ok(raw) => Self::parse(&raw).map_err(|e| format!("parse: {e}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HashSet::new()),
            Err(e) => Err(format!("read: {e}")),
        };
        match nodes {
            Ok(nodes) => loaded.1 = Arc::new(nodes),
            Err(e) => warn!(
                error = %e,
                path = %self.path.display(),
                "Bridge node registry unreadable — keeping the previous node list"
            ),
        }
        loaded.0 = disk;
        Arc::clone(&loaded.1)
    }
}

struct Loaded {
    set: Arc<KeySet>,
    /// Bumped on every successful load; ties cache entries to a key set.
    generation: u64,
    /// Stamp of the file version last attempted (successfully or not), so a
    /// broken version is not re-parsed on every request. `None` = the file
    /// could not be stat'ed.
    seen: Option<FileStamp>,
}

/// Validation caches, valid only for key set `generation`.
#[derive(Default)]
struct Caches {
    generation: u64,
    /// SHA-256(raw key) → (index into the key set, inserted at).
    ok: HashMap<[u8; 32], (usize, Instant)>,
    /// SHA-256(raw key) of keys that failed PBKDF2 verification.
    failed: HashSet<[u8; 32]>,
}

/// Checks a presented key against one stored entry (PBKDF2 in production;
/// replaceable in tests).
type Verifier = Box<dyn Fn(&ApiKey, &str) -> bool + Send + Sync>;

/// What a verification task needs after its request may be gone.
struct Shared {
    caches: Mutex<Caches>,
    /// PBKDF2 verifications run so far (observability and tests).
    pbkdf2_runs: AtomicU64,
    verify: Verifier,
}

/// Outcome of a cache lookup.
enum Cached {
    /// The key is known: `Some` = valid (with its identity), `None` =
    /// known to fail.
    Hit(Option<ScopedKey>),
    Miss,
}

impl Shared {
    fn verify_one(&self, stored: &ApiKey, presented: &str) -> bool {
        self.pbkdf2_runs.fetch_add(1, Ordering::Relaxed);
        (self.verify)(stored, presented)
    }

    fn lookup(
        &self,
        set: &KeySet,
        generation: u64,
        digest: &[u8; 32],
        now: DateTime<Utc>,
    ) -> Cached {
        let mut caches = self.caches.lock().unwrap();
        if caches.generation != generation {
            return Cached::Miss;
        }
        if caches.failed.contains(digest) {
            return Cached::Hit(None);
        }
        if let Some(&(idx, at)) = caches.ok.get(digest) {
            let key = &set.keys[idx];
            if at.elapsed() < SUCCESS_CACHE_TTL && key.is_usable(now) {
                return Cached::Hit(Some((key.key_id.clone(), key.role, key.instance_tenant)));
            }
            caches.ok.remove(digest);
        }
        Cached::Miss
    }

    /// Cache a verification result for key set `generation` (ignored if
    /// the set has been reloaded since).
    fn record(&self, generation: u64, digest: [u8; 32], matched: Option<usize>) {
        let mut caches = self.caches.lock().unwrap();
        if caches.generation != generation {
            return;
        }
        match matched {
            Some(idx) => {
                if caches.ok.len() >= SUCCESS_CACHE_MAX {
                    caches.ok.clear();
                }
                caches.ok.insert(digest, (idx, Instant::now()));
            }
            None => {
                if caches.failed.len() >= FAILED_CACHE_MAX {
                    caches.failed.clear();
                }
                caches.failed.insert(digest);
            }
        }
    }
}

/// Concurrency limits for API-key PBKDF2 work.
struct Limits {
    /// Every verification (indexed or legacy) holds one of these.
    pbkdf2: Arc<Semaphore>,
    /// Every running legacy scan holds one of these.
    legacy_running: Arc<Semaphore>,
    /// Every running or waiting legacy scan holds one of these; when none
    /// is left a new scan is rejected instead of queued.
    legacy_admitted: Arc<Semaphore>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            pbkdf2: Arc::new(Semaphore::new(PBKDF2_CONCURRENCY)),
            legacy_running: Arc::new(Semaphore::new(LEGACY_SCAN_CONCURRENCY)),
            legacy_admitted: Arc::new(Semaphore::new(
                LEGACY_SCAN_CONCURRENCY + LEGACY_SCAN_MAX_WAITING,
            )),
        }
    }
}

/// Permits held by one verification. They are moved into its blocking
/// task and released when that task ends, never earlier.
struct Permits {
    _pbkdf2: OwnedSemaphorePermit,
    _legacy: Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)>,
}

pub struct KeyStore {
    path: PathBuf,
    /// The bridge's node registry next to the keys file.
    nodes: NodeRegistry,
    loaded: RwLock<Loaded>,
    /// Serialises reloads so a slow reader cannot install a stale version.
    reload_lock: Mutex<()>,
    shared: Arc<Shared>,
    limits: Limits,
}

/// Outcome of picking which stored entries a presented key could match.
#[derive(Debug, PartialEq, Eq)]
enum Candidates {
    /// The lookup hash matched these usable entries.
    Indexed(Vec<usize>),
    /// The lookup hash matched only disabled or expired entries.
    Unusable(usize),
    /// No lookup-hash match; these usable legacy entries may still match.
    Legacy(Vec<usize>),
    /// Nothing can match — reject without PBKDF2.
    None,
}

impl KeyStore {
    fn with_verifier(path: &Path, verify: Verifier) -> Self {
        Self {
            path: path.to_path_buf(),
            nodes: NodeRegistry::beside(path),
            loaded: RwLock::new(Loaded {
                set: Arc::new(KeySet::default()),
                generation: 0,
                seen: None,
            }),
            reload_lock: Mutex::new(()),
            shared: Arc::new(Shared {
                caches: Mutex::new(Caches::default()),
                pbkdf2_runs: AtomicU64::new(0),
                verify,
            }),
            limits: Limits::default(),
        }
    }

    fn empty(path: &Path) -> Self {
        Self::with_verifier(
            path,
            Box::new(|stored, presented| verify_key(&stored.salt, presented, &stored.hash)),
        )
    }

    pub fn new(path: &Path) -> Self {
        let store = Self::empty(path);
        if let Err(e) = store.reload() {
            warn!(error = %e, "Failed to load API keys");
        }
        store
    }

    /// Try to create a KeyStore, returning None if the initial load fails.
    pub fn try_new(path: &Path) -> Option<Self> {
        let store = Self::empty(path);
        match store.reload() {
            Ok(_) => Some(store),
            Err(e) => {
                warn!(error = %e, "Failed to load API keys");
                None
            }
        }
    }

    /// Re-read the keys file now. On failure the previous key set stays
    /// in place and the error is returned.
    pub fn reload(&self) -> Result<(), Box<dyn std::error::Error>> {
        let _guard = self.reload_lock.lock().unwrap();
        self.load(FileStamp::of(&self.path))
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })
    }

    /// Reload if the file changed since the last attempt.
    fn reload_if_changed(&self) {
        if self.loaded.read().unwrap().seen == FileStamp::of(&self.path) {
            return;
        }
        let _guard = self.reload_lock.lock().unwrap();
        // Re-stat under the lock: another request may have reloaded already.
        let disk = FileStamp::of(&self.path);
        if self.loaded.read().unwrap().seen == disk {
            return;
        }
        if let Err(e) = self.load(disk) {
            warn!(
                error = %e,
                path = %self.path.display(),
                "API key file reload failed — keeping the previous key set"
            );
        }
    }

    /// Read + parse the file and install it. Caller holds `reload_lock`.
    fn load(&self, disk: Option<FileStamp>) -> Result<(), String> {
        let parsed = std::fs::read_to_string(&self.path)
            .map_err(|e| format!("read {}: {e}", self.path.display()))
            .and_then(|raw| parse_key_set(&raw));
        let mut loaded = self.loaded.write().unwrap();
        loaded.seen = disk;
        let set = parsed?;
        let count = set.keys.len();
        let legacy_ids: Vec<String> = set
            .legacy
            .iter()
            .map(|&i| set.keys[i].key_id.clone())
            .collect();
        loaded.set = Arc::new(set);
        loaded.generation += 1;
        let generation = loaded.generation;
        // Reset the caches while still holding the write lock, so no
        // validation can pair the new set with the old caches.
        let mut caches = self.shared.caches.lock().unwrap();
        caches.generation = generation;
        caches.ok.clear();
        caches.failed.clear();
        drop(caches);
        drop(loaded);
        info!(count, generation, "API keys loaded");
        warn_about_legacy_keys(&legacy_ids);
        Ok(())
    }

    fn snapshot(&self) -> (Arc<KeySet>, u64) {
        let loaded = self.loaded.read().unwrap();
        (Arc::clone(&loaded.set), loaded.generation)
    }

    /// Take the permits a verification needs, or `None` when the legacy
    /// scan queue is full (the key is then rejected without PBKDF2).
    ///
    /// Cancel-safe: a request dropped while waiting here holds nothing.
    async fn acquire_permits(&self, legacy: bool, digest: &[u8; 32]) -> Option<Permits> {
        let legacy_permits = if legacy {
            let Ok(admitted) = Arc::clone(&self.limits.legacy_admitted).try_acquire_owned() else {
                warn!(
                    key_fp = %key_fingerprint(digest),
                    "Legacy API-key scan queue is full — rejecting the key without PBKDF2"
                );
                return None;
            };
            let running = Arc::clone(&self.limits.legacy_running)
                .acquire_owned()
                .await
                .ok()?;
            Some((admitted, running))
        } else {
            None
        };
        let pbkdf2 = Arc::clone(&self.limits.pbkdf2).acquire_owned().await.ok()?;
        Some(Permits {
            _pbkdf2: pbkdf2,
            _legacy: legacy_permits,
        })
    }

    /// Validate an API key string. Returns (key_id, role) on success.
    ///
    /// PBKDF2 runs on tokio's blocking pool, so this must be called from
    /// within a tokio runtime. Cancel-safe: dropping the future never
    /// releases a concurrency permit before PBKDF2 has finished, and the
    /// result is cached even if nobody is left to read it.
    pub async fn validate(&self, api_key: &str) -> Option<(String, Role)> {
        self.validate_for_instance(api_key).await.ok().flatten()
    }

    /// Authenticate first, then refuse a valid credential scoped elsewhere.
    /// The tenant decision travels with the same immutable key snapshot/cache
    /// result as its role; a later metadata lookup cannot mix generations.
    pub async fn validate_for_instance(
        &self,
        api_key: &str,
    ) -> Result<Option<(String, Role)>, ForeignTenant> {
        match self.validate_scoped(api_key).await {
            Some((key_id, role, true)) => Ok(Some((key_id, role))),
            Some((_, _, false)) => Err(ForeignTenant),
            None => Ok(None),
        }
    }

    async fn validate_scoped(&self, api_key: &str) -> Option<ScopedKey> {
        self.reload_if_changed();
        let (set, generation) = self.snapshot();
        let digest: [u8; 32] = Sha256::digest(api_key.as_bytes()).into();
        let now = Utc::now();

        if let Cached::Hit(result) = self.shared.lookup(&set, generation, &digest, now) {
            return result;
        }

        let (candidates, legacy) = match select_candidates(&set, &hex::encode(digest), now) {
            Candidates::Indexed(c) => (c, false),
            Candidates::Legacy(c) => (c, true),
            Candidates::Unusable(idx) => {
                warn!(key_id = %set.keys[idx].key_id, "API key is disabled or expired");
                return None;
            }
            Candidates::None => {
                warn!(key_fp = %key_fingerprint(&digest), "No matching API key found");
                return None;
            }
        };

        let permits = self.acquire_permits(legacy, &digest).await?;

        // A validation of the same key may have finished while this one
        // waited for its permits. Bind the cached credential to fresh metadata
        // after that await; the file may have changed without another reader.
        if let Cached::Hit(result) = self.shared.lookup(&set, generation, &digest, now) {
            return result.and_then(|(key_id, _, _)| {
                set.keys
                    .iter()
                    .find(|key| key.key_id == key_id)
                    .and_then(|key| self.current_match(key))
            });
        }

        let matched = {
            let set = Arc::clone(&set);
            let shared = Arc::clone(&self.shared);
            let key = api_key.to_owned();
            tokio::task::spawn_blocking(move || {
                // Held until PBKDF2 is done, even if the request is gone.
                let _permits = permits;
                let matched = candidates
                    .into_iter()
                    .find(|&idx| shared.verify_one(&set.keys[idx], &key));
                // Cached here rather than by the request, so a dropped
                // request still leaves the result behind.
                shared.record(generation, digest, matched);
                matched
            })
            .await
        };
        let matched = match matched {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "API key verification task failed");
                return None;
            }
        };

        let Some(idx) = matched else {
            warn!(key_fp = %key_fingerprint(&digest), "No matching API key found");
            return None;
        };
        let key = &set.keys[idx];

        self.current_match(key)
    }

    /// After awaited verification, take one fresh snapshot of credential and
    /// metadata together. A disk-only edit must be observed even when no other
    /// request has reloaded the file, and a rotated credential cannot inherit
    /// the old credential's successful PBKDF2 result.
    fn current_match(&self, verified: &ApiKey) -> Option<ScopedKey> {
        self.reload_if_changed();
        let (current, _) = self.snapshot();
        match current.keys.iter().find(|key| {
            key.key_id == verified.key_id && key.hash == verified.hash && key.salt == verified.salt
        }) {
            Some(key) if key.is_usable(Utc::now()) => {
                Some((key.key_id.clone(), key.role, key.instance_tenant))
            }
            _ => {
                warn!(key_id = %verified.key_id, "API key revoked during validation");
                None
            }
        }
    }

    /// The node `key_id` is bound to (its `node_id` in keys.json) in the
    /// current key set, reloading the file first if it changed. `None` =
    /// unbound (absent, null, empty or whitespace-only `node_id`) or
    /// unknown key.
    pub fn node_binding(&self, key_id: &str) -> Option<String> {
        self.reload_if_changed();
        let (set, _) = self.snapshot();
        set.keys
            .iter()
            .find(|k| k.key_id == key_id)
            .and_then(|k| k.node_id.clone())
            .filter(|node| !node.trim().is_empty())
    }

    /// True when `node_id` is a node registered with the bridge: an entry
    /// of its `nodes.json`, next to keys.json (reloaded when it changes).
    /// The bridge's legacy rule makes a key whose id is a registered
    /// node's id that node's key (`existing_node_binding`); the bridge
    /// writes the binding to keys.json when it applies the rule, so this
    /// only matters for a key the bridge has not seen since. The bridge
    /// saves the registry periodically, so a node registered moments ago
    /// may not be listed yet.
    pub fn is_registered_node(&self, node_id: &str) -> bool {
        self.nodes.current().contains(node_id)
    }

    /// Alias of [`KeyStore::node_binding`].
    pub fn node_id_for(&self, key_id: &str) -> Option<String> {
        self.node_binding(key_id)
    }

    /// Generation of the current key set, reloading the file first if it
    /// changed. It changes on every successful reload, so a caller holding
    /// a long-lived credential (a WebSocket) can re-validate it then.
    pub fn generation(&self) -> u64 {
        self.reload_if_changed();
        self.snapshot().1
    }

    #[cfg(test)]
    fn pbkdf2_runs(&self) -> u64 {
        self.shared.pbkdf2_runs.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn key_ids(&self) -> Vec<String> {
        let (set, _) = self.snapshot();
        set.keys.iter().map(|k| k.key_id.clone()).collect()
    }
}

/// Tell the operator about entries without `lookup_hash`, by key_id: every
/// presented key the gateway cannot find by lookup hash costs one PBKDF2
/// per such entry.
fn warn_about_legacy_keys(legacy_ids: &[String]) {
    if legacy_ids.is_empty() {
        return;
    }
    let shown = &legacy_ids[..legacy_ids.len().min(LEGACY_IDS_LOGGED)];
    warn!(
        legacy = legacy_ids.len(),
        key_ids = ?shown,
        "API keys without lookup_hash found. Each presented key that matches no \
         lookup_hash is checked against all of them with PBKDF2 ({LEGACY_SCAN_CONCURRENCY} \
         such scans at a time; with {LEGACY_SCAN_MAX_WAITING} more waiting, further ones \
         are rejected). Use each of these keys once on a bridge route, which records its \
         lookup_hash, or rotate it."
    );
    if legacy_ids.len() > LEGACY_SCAN_SLOW {
        warn!(
            legacy = legacy_ids.len(),
            "More than {LEGACY_SCAN_SLOW} API keys without lookup_hash: every unknown key \
             costs {} PBKDF2 runs and legacy keys validate slowly until they are upgraded \
             or rotated",
            legacy_ids.len()
        );
    }
}

/// Pick the stored entries a key with this lookup hash could match.
fn select_candidates(set: &KeySet, lookup_hex: &str, now: DateTime<Utc>) -> Candidates {
    if let Some(indexes) = set.by_lookup.get(lookup_hex) {
        let usable: Vec<usize> = indexes
            .iter()
            .copied()
            .filter(|&i| set.keys[i].is_usable(now))
            .collect();
        return if usable.is_empty() {
            Candidates::Unusable(indexes[0])
        } else {
            Candidates::Indexed(usable)
        };
    }
    // Every usable legacy entry, as the bridge scans them all: a cap here
    // would permanently reject the keys beyond it. The cost is bounded by
    // the legacy-scan permits instead.
    let legacy: Vec<usize> = set
        .legacy
        .iter()
        .copied()
        .filter(|&i| set.keys[i].is_usable(now))
        .collect();
    if legacy.is_empty() {
        Candidates::None
    } else {
        Candidates::Legacy(legacy)
    }
}

// ── keys.json parsing ─────────────────────────────────────────────────

/// Replace every `\uXXXX` escape of a lone UTF-16 surrogate with `\uFFFD`.
///
/// Python's `json.dump` (ensure_ascii) writes a string holding a lone
/// surrogate — e.g. a key description `"\ud800"` — as that escape, which
/// is valid for Python but rejected by serde_json, so one such description
/// used to make the whole file unparseable: the gateway kept its previous
/// key set forever (revocations stopped applying) and a restart failed.
/// Proper surrogate pairs and every other escape are left untouched; a
/// `\\` is consumed as a unit so `\\ud800` (a backslash and text) is not
/// mistaken for an escape. Returns the text and the number of replacements.
fn replace_lone_surrogate_escapes(raw: &str) -> (std::borrow::Cow<'_, str>, usize) {
    fn hex4(b: &[u8]) -> Option<u16> {
        let s = std::str::from_utf8(b.get(..4)?).ok()?;
        u16::from_str_radix(s, 16).ok()
    }
    let bytes = raw.as_bytes();
    if !raw.contains("\\u") {
        return (std::borrow::Cow::Borrowed(raw), 0);
    }
    let mut out = String::with_capacity(raw.len());
    let mut replaced = 0;
    let mut copied = 0; // bytes of `raw` already in `out`
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            i += 1;
            continue;
        }
        if bytes.get(i + 1) != Some(&b'u') {
            i += 2; // `\\`, `\"`, `\n`, …: skip the escaped char too
            continue;
        }
        let Some(unit) = hex4(&bytes[i + 2..]) else {
            i += 2;
            continue;
        };
        let is_high = (0xD800..=0xDBFF).contains(&unit);
        let is_low = (0xDC00..=0xDFFF).contains(&unit);
        if is_high {
            let low = (bytes.get(i + 6) == Some(&b'\\') && bytes.get(i + 7) == Some(&b'u'))
                .then(|| hex4(&bytes[i + 8..]))
                .flatten();
            if low.is_some_and(|l| (0xDC00..=0xDFFF).contains(&l)) {
                i += 12; // a valid pair
                continue;
            }
        }
        if is_high || is_low {
            out.push_str(&raw[copied..i]);
            out.push_str("\\uFFFD");
            replaced += 1;
            copied = i + 6;
        }
        i += 6;
    }
    if replaced == 0 {
        return (std::borrow::Cow::Borrowed(raw), 0);
    }
    out.push_str(&raw[copied..]);
    (std::borrow::Cow::Owned(out), replaced)
}

/// True if any string in `value` (keys included) holds U+FFFD.
fn holds_replacement_char(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(s) => s.contains('\u{FFFD}'),
        serde_json::Value::Array(items) => items.iter().any(holds_replacement_char),
        serde_json::Value::Object(map) => map
            .iter()
            .any(|(k, v)| k.contains('\u{FFFD}') || holds_replacement_char(v)),
        _ => false,
    }
}

/// Parse `keys.json`. Supports both formats:
///   {"keys": {"key_id": {hash, salt, role, ...}, ...}}   (Python persistence)
///   {"keys": [{key_id, hash, salt, role, ...}, ...]}     (array format)
///
/// Lone UTF-16 surrogate escapes (valid for Python, not for serde_json) are
/// read as U+FFFD (see [`replace_lone_surrogate_escapes`]) and the entries
/// holding them are logged by key_id, so one odd description never blocks
/// the whole file.
fn parse_key_set(raw: &str) -> Result<KeySet, String> {
    let (text, replaced) = replace_lone_surrogate_escapes(raw);
    let parsed: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("invalid JSON: {e}"))?;
    let keys_val = parsed.get("keys").unwrap_or(&parsed);

    let entries: Vec<(String, &serde_json::Value)> = if let Some(obj) = keys_val.as_object() {
        obj.iter()
            .map(|(kid, entry)| (kid.clone(), entry))
            .collect()
    } else if let Some(arr) = keys_val.as_array() {
        arr.iter()
            .map(|entry| (str_field(entry, "key_id").unwrap_or_default(), entry))
            .collect()
    } else {
        return Err("no \"keys\" object or array".into());
    };

    let mut set = KeySet::default();
    for (key_id, entry) in entries {
        if replaced > 0 && (key_id.contains('\u{FFFD}') || holds_replacement_char(entry)) {
            warn!(
                key_id = %key_id,
                "keys.json entry holds an unpaired UTF-16 surrogate escape; \
                 read it as U+FFFD (the key itself still works)"
            );
        }
        if let Some(key) = parse_entry(key_id, entry) {
            let idx = set.keys.len();
            match &key.lookup_hash {
                Some(lh) => set.by_lookup.entry(lh.clone()).or_default().push(idx),
                None => set.legacy.push(idx),
            }
            set.keys.push(key);
        }
    }
    Ok(set)
}

fn json_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn str_field(entry: &serde_json::Value, name: &str) -> Option<String> {
    entry.get(name).and_then(|v| v.as_str()).map(String::from)
}

/// The role key `key_id` authenticates with, from its stored `role`
/// (`None` when the entry has no `role`, or one that is not a string).
///
/// The bridge's rule (`dependencies.stored_key_role`), which both layers
/// must apply alike — the shared table `testdata/key_role_parity.json`
/// pins them to it:
///
/// * the key [`MASTER_KEY_ID`] is ADMIN, whatever is stored. The bridge
///   writes it without a role on first run (and as `viewer` once another
///   key change rewrites the file);
/// * a missing or unknown role is [`DEFAULT_KEY_ROLE`], VIEWER. The
///   gateway used to read it as SENSOR, so it refused such a key on its
///   own viewer routes and took it for a node credential;
/// * a key whose id starts with one of [`EDGE_KEY_PREFIXES`] and whose
///   stored role reads as ANALYST or higher — case-insensitively, as
///   roles are parsed, so `ADMIN` and `keymaster` count — is a node key:
///   NODE (`persistence.edge_key_role`). The bridge applies this when it
///   loads keys.json and keeps the stored role in the file until its next
///   key change, so reading the stored role made the two layers disagree
///   — the gateway took such a key for operator tooling (never bound, any
///   node) while the bridge binds it on first use (K7b).
pub fn effective_role(key_id: &str, stored: Option<&str>) -> Role {
    if key_id == MASTER_KEY_ID {
        return Role::Admin;
    }
    let role = stored
        .and_then(|s| s.parse::<Role>().ok())
        .unwrap_or(DEFAULT_KEY_ROLE);
    let edge_key = EDGE_KEY_PREFIXES.iter().any(|p| key_id.starts_with(p));
    if edge_key && role >= Role::Analyst {
        warn!(
            key_id,
            stored_role = %role,
            "Edge key stored with an operator role acts as a NODE key (as on the bridge)"
        );
        return Role::Node;
    }
    role
}

fn parse_entry(key_id: String, entry: &serde_json::Value) -> Option<ApiKey> {
    if !entry.is_object() {
        return None;
    }
    let hash = str_field(entry, "hash").unwrap_or_default();
    if key_id.is_empty() || hash.is_empty() {
        warn!(key_id = %key_id, "Skipping API key entry without key_id or hash");
        return None;
    }
    let role = effective_role(&key_id, entry.get("role").and_then(|v| v.as_str()));
    let revoked = entry
        .get("revoked")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let enabled = !revoked
        && entry
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

    let lookup_hash = match str_field(entry, "lookup_hash") {
        Some(lh) => {
            let lh = lh.trim().to_ascii_lowercase();
            if lh.len() == 64 && lh.bytes().all(|b| b.is_ascii_hexdigit()) {
                Some(lh)
            } else {
                if !lh.is_empty() {
                    warn!(key_id = %key_id, "Ignoring malformed lookup_hash");
                }
                None
            }
        }
        None => None,
    };

    // Missing, null or empty = never expires (legacy policy, as on the
    // bridge). Any other value that is not a parseable string — including a
    // number, bool, array or object — fails closed, matching the bridge's
    // `key_expired` (sigrift/bridge/dependencies.py), instead of silently
    // granting a non-expiring key. The bridge parses with its own
    // `key_expiry` (Python `fromisoformat`), which accepts a different set
    // of hand-edited shapes than `parse_expiry` below.
    let expires_at = match entry.get("expires_at") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) if s.trim().is_empty() => None,
        Some(serde_json::Value::String(s)) => Some(parse_expiry(s).unwrap_or_else(|| {
            warn!(key_id = %key_id, expires_at = %s, "Unparseable expires_at — treating key as expired");
            DateTime::<Utc>::MIN_UTC
        })),
        Some(other) => {
            warn!(
                key_id = %key_id,
                kind = json_kind(other),
                "Non-string expires_at — treating key as expired"
            );
            Some(DateTime::<Utc>::MIN_UTC)
        }
    };

    Some(ApiKey {
        hash,
        salt: str_field(entry, "salt").unwrap_or_default(),
        role,
        node_id: str_field(entry, "node_id"),
        enabled,
        instance_tenant: entry
            .get("tenant_id")
            .map_or(true, |v| v.as_str() == Some(INSTANCE_TENANT)),
        lookup_hash,
        expires_at,
        key_id,
    })
}

/// Parse an `expires_at` value as written by Python `datetime.isoformat()`:
/// `2026-01-01T00:00:00[.ffffff]+00:00`, or a naive variant (treated as
/// UTC, matching `dependencies.py`), or a bare date.
fn parse_expiry(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(dt) = DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f%:z") {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(naive.and_utc());
        }
    }
    NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|naive| naive.and_utc())
}

/// Non-reversible fingerprint of an API key for logging: the first 8 hex
/// chars of SHA-256(key), revealing zero key entropy.
fn key_fingerprint(digest: &[u8; 32]) -> String {
    hex::encode(&digest[..4])
}

/// Try PBKDF2-HMAC-SHA256 first (current Python format), then legacy SHA256.
/// Returns true if either matches.
fn verify_key(salt_hex: &str, key: &str, expected_hash: &str) -> bool {
    // Decode salt from hex to raw bytes
    let salt_bytes = match hex::decode(salt_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };

    // PBKDF2-HMAC-SHA256 (600_000 iterations, 32-byte output — matches Python)
    let mut pbkdf2_out = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        key.as_bytes(),
        &salt_bytes,
        PBKDF2_ITERATIONS,
        &mut pbkdf2_out,
    );
    let pbkdf2_hex = hex::encode(pbkdf2_out);
    if constant_time_eq::constant_time_eq(pbkdf2_hex.as_bytes(), expected_hash.as_bytes()) {
        return true;
    }

    // Legacy: SHA256(raw_salt_bytes + key_bytes)
    let mut hasher = Sha256::new();
    hasher.update(&salt_bytes);
    hasher.update(key.as_bytes());
    let legacy_hex = hex::encode(hasher.finalize());
    if constant_time_eq::constant_time_eq(legacy_hex.as_bytes(), expected_hash.as_bytes()) {
        return true;
    }

    // Legacy variant: SHA256(salt_hex_string + key_string) — used by early upperCrust keys
    let mut hasher2 = Sha256::new();
    hasher2.update(salt_hex.as_bytes());
    hasher2.update(key.as_bytes());
    let legacy2_hex = hex::encode(hasher2.finalize());
    constant_time_eq::constant_time_eq(legacy2_hex.as_bytes(), expected_hash.as_bytes())
}

/// Extract API key from request headers.
pub fn extract_api_key(req: &Request) -> Option<String> {
    // Check X-API-Key header first
    if let Some(val) = req.headers().get("x-api-key") {
        return val.to_str().ok().map(String::from);
    }
    // Check Authorization: Bearer <key> (the scheme in any letter case)
    if let Some(key) = crate::middleware::auth::bearer_credential(req.headers()) {
        return Some(key.to_string());
    }
    // Check query parameter
    if let Some(query) = req.uri().query() {
        for pair in query.split('&') {
            if let Some(val) = pair.strip_prefix("api_key=") {
                return Some(val.to_string());
            }
        }
    }
    None
}

/// Middleware that requires a valid API key with at least the given role.
pub async fn require_auth(
    key_store: &KeyStore,
    req: &Request,
    min_role: &Role,
) -> Result<(String, Role), StatusCode> {
    let api_key = extract_api_key(req).ok_or(StatusCode::UNAUTHORIZED)?;
    let (key_id, role) = key_store
        .validate_for_instance(&api_key)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if role < *min_role {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok((key_id, role))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    // Golden vectors computed with Python `sigrift.lib.security.credentials`:
    //   hashlib.pbkdf2_hmac("sha256", raw.encode(), bytes.fromhex(salt), 600_000, 32).hex()
    //   compute_lookup_hash(raw) == hashlib.sha256(raw.encode()).hexdigest()
    const ALPHA_RAW: &str = "sk-test-alpha-0123456789";
    const ALPHA_SALT: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
    const ALPHA_HASH: &str = "7ea3c8e71f4dbfb4385ccf81a283b2c67e2ef78a394871d706a51cd3907248ef";
    const ALPHA_LOOKUP: &str = "f3cc30144572e7f426d929e72f3d912aafa9db08d78ca9b73621e4ec248b4287";
    const BRAVO_SALT: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    const BRAVO_HASH: &str = "5a7ace08e5276f27ece1e45c0c5e08d6098d01436b07fe93ae87d19fbb07f75f";
    const BRAVO_LOOKUP: &str = "3149c167899b761f91197cb056e918be0f3c18b0b176f59f32b94e1e123db121";
    // Legacy SHA-256(salt_bytes + raw), no lookup_hash.
    const LEGACY_RAW: &str = "sk-legacy-charlie";
    const LEGACY_SALT: &str = "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe";
    const LEGACY_HASH: &str = "e4e6e0b6a114542b46ebecd89db9152a684bbcbb0fa2a6577b724e433ba8aa69";

    fn alpha(expires_at: &str) -> String {
        format!(
            r#""alpha": {{"hash": "{ALPHA_HASH}", "salt": "{ALPHA_SALT}",
                "lookup_hash": "{ALPHA_LOOKUP}", "role": "analyst",
                "expires_at": {expires_at}}}"#
        )
    }

    fn bravo() -> String {
        format!(
            r#""bravo": {{"hash": "{BRAVO_HASH}", "salt": "{BRAVO_SALT}",
                "lookup_hash": "{BRAVO_LOOKUP}", "role": "viewer", "expires_at": null}}"#
        )
    }

    fn legacy() -> String {
        format!(r#""legacy": {{"hash": "{LEGACY_HASH}", "salt": "{LEGACY_SALT}", "role": "node"}}"#)
    }

    /// Write keys.json like Python does: tmp file + atomic rename.
    fn write_keys(dir: &tempfile::TempDir, entries: &[String]) -> PathBuf {
        write_raw(
            dir,
            &format!(
                r#"{{"keys": {{{}}}, "saved_at": "2026-01-01T00:00:00+00:00"}}"#,
                entries.join(",")
            ),
        )
    }

    fn write_raw(dir: &tempfile::TempDir, contents: &str) -> PathBuf {
        let path = dir.path().join("keys.json");
        let tmp = dir.path().join("keys.tmp");
        let mut f = std::fs::File::create(&tmp).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        f.sync_all().unwrap();
        std::fs::rename(&tmp, &path).unwrap();
        path
    }

    #[tokio::test]
    async fn valid_key_validates_once_then_hits_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_keys(&dir, &[alpha("null"), bravo()]);
        let store = KeyStore::try_new(&path).unwrap();

        assert_eq!(
            store.validate(ALPHA_RAW).await,
            Some(("alpha".to_string(), Role::Analyst))
        );
        assert_eq!(store.pbkdf2_runs(), 1, "only the indexed entry is checked");
        assert_eq!(
            store.validate(ALPHA_RAW).await,
            Some(("alpha".to_string(), Role::Analyst))
        );
        assert_eq!(
            store.pbkdf2_runs(),
            1,
            "second validation served from cache"
        );
    }

    #[tokio::test]
    async fn reload_picks_up_revoked_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_keys(&dir, &[alpha("null"), bravo()]);
        let store = KeyStore::try_new(&path).unwrap();
        assert!(store.validate(ALPHA_RAW).await.is_some());

        // Python `persistence.remove_key("alpha")` rewrites the file without it.
        write_keys(&dir, &[bravo()]);
        assert_eq!(store.validate(ALPHA_RAW).await, None);
        assert_eq!(store.key_ids(), vec!["bravo".to_string()]);
        assert_eq!(
            store.pbkdf2_runs(),
            1,
            "revoked key rejected without PBKDF2"
        );
    }

    #[test]
    fn reload_picks_up_new_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_keys(&dir, &[bravo()]);
        let store = KeyStore::try_new(&path).unwrap();
        assert_eq!(store.key_ids(), vec!["bravo".to_string()]);

        write_keys(&dir, &[alpha("null"), bravo()]);
        store.reload_if_changed();
        let mut ids = store.key_ids();
        ids.sort();
        assert_eq!(ids, vec!["alpha".to_string(), "bravo".to_string()]);
    }

    #[test]
    fn failed_reload_keeps_previous_key_set() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_keys(&dir, &[alpha("null"), bravo()]);
        let store = KeyStore::try_new(&path).unwrap();

        // Truncated / partial write.
        write_raw(&dir, r#"{"keys": {"alpha": {"hash": "7ea3"#);
        store.reload_if_changed();
        assert_eq!(store.key_ids().len(), 2);
        assert!(store.reload().is_err());
        assert_eq!(store.key_ids().len(), 2);

        // Empty file and wrong shape are failures too.
        write_raw(&dir, "");
        store.reload_if_changed();
        assert_eq!(store.key_ids().len(), 2);
        write_raw(&dir, r#"{"keys": 42}"#);
        store.reload_if_changed();
        assert_eq!(store.key_ids().len(), 2);

        // A missing file keeps the previous set as well.
        std::fs::remove_file(&path).unwrap();
        store.reload_if_changed();
        assert_eq!(store.key_ids().len(), 2);

        // A valid (empty) key set is applied: every key revoked.
        write_raw(&dir, r#"{"keys": {}}"#);
        store.reload_if_changed();
        assert!(store.key_ids().is_empty());
    }

    #[tokio::test]
    async fn expired_key_rejected_without_pbkdf2() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_keys(&dir, &[alpha(r#""2020-01-01T00:00:00.123456+00:00""#)]);
        let store = KeyStore::try_new(&path).unwrap();
        assert_eq!(store.validate(ALPHA_RAW).await, None);
        assert_eq!(store.pbkdf2_runs(), 0);
    }

    #[tokio::test]
    async fn future_expiry_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_keys(&dir, &[alpha(r#""2999-01-01T00:00:00+00:00""#)]);
        let store = KeyStore::try_new(&path).unwrap();
        assert!(store.validate(ALPHA_RAW).await.is_some());
    }

    #[tokio::test]
    async fn cached_key_rejected_once_expired() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_keys(
            &dir,
            &[format!(
                r#""bravo": {{"hash": "{BRAVO_HASH}", "salt": "{BRAVO_SALT}",
                    "lookup_hash": "{BRAVO_LOOKUP}", "expires_at": "2020-01-01T00:00:00"}}"#
            )],
        );
        let store = KeyStore::try_new(&path).unwrap();
        // Simulate a key that was cached while valid and has since expired
        // (same generation, so the cache entry is live).
        let (_, generation) = store.snapshot();
        let digest: [u8; 32] = Sha256::digest(b"whatever").into();
        store.shared.record(generation, digest, Some(0));
        assert_eq!(store.validate("whatever").await, None);
        assert!(store.shared.caches.lock().unwrap().ok.is_empty());
        assert_eq!(store.pbkdf2_runs(), 0);
    }

    #[tokio::test]
    async fn unknown_key_rejected_without_pbkdf2() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_keys(&dir, &[alpha("null"), bravo()]);
        let store = KeyStore::try_new(&path).unwrap();
        for i in 0..50 {
            assert_eq!(store.validate(&format!("attacker-{i}")).await, None);
        }
        assert_eq!(store.pbkdf2_runs(), 0, "no lookup-hash match → no PBKDF2");
    }

    #[tokio::test]
    async fn stale_cache_entry_from_old_generation_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_keys(&dir, &[bravo()]);
        let store = KeyStore::try_new(&path).unwrap();
        let (_, generation) = store.snapshot();
        write_keys(&dir, &[]);
        store.reload_if_changed();
        // A validation that started before the reload must not populate
        // the new generation's cache.
        let digest: [u8; 32] = Sha256::digest(b"late").into();
        store.shared.record(generation, digest, Some(0));
        assert!(store.shared.caches.lock().unwrap().ok.is_empty());
        assert_eq!(store.validate("late").await, None);
    }

    #[tokio::test]
    async fn legacy_entry_without_lookup_hash_still_validates() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_keys(&dir, &[legacy(), bravo()]);
        let store = KeyStore::try_new(&path).unwrap();
        assert_eq!(
            store.validate(LEGACY_RAW).await,
            Some(("legacy".to_string(), Role::Node))
        );
        // Only the legacy entry was scanned; bravo has a lookup_hash.
        assert_eq!(store.pbkdf2_runs(), 1);
        // A wrong key is checked against the legacy entry once, then cached.
        assert_eq!(store.validate("nope").await, None);
        assert_eq!(store.validate("nope").await, None);
        assert_eq!(store.pbkdf2_runs(), 2);
    }

    fn legacy_key(key_id: &str) -> ApiKey {
        ApiKey {
            key_id: key_id.into(),
            hash: "00".into(),
            salt: "00".into(),
            role: Role::Viewer,
            node_id: None,
            enabled: true,
            instance_tenant: true,
            lookup_hash: None,
            expires_at: None,
        }
    }

    #[test]
    fn legacy_scan_covers_every_usable_entry() {
        let mut set = KeySet::default();
        for i in 0..(LEGACY_SCAN_SLOW + 5) {
            set.legacy.push(set.keys.len());
            set.keys.push(legacy_key(&format!("k{i}")));
        }
        set.keys[3].enabled = false;
        set.keys[4].expires_at = Some(DateTime::<Utc>::MIN_UTC);
        match select_candidates(&set, &"0".repeat(64), Utc::now()) {
            Candidates::Legacy(c) => {
                assert_eq!(c.len(), LEGACY_SCAN_SLOW + 3);
                assert!(!c.contains(&3) && !c.contains(&4));
            }
            other => panic!("expected legacy candidates, got {other:?}"),
        }
        assert_eq!(
            select_candidates(&KeySet::default(), &"0".repeat(64), Utc::now()),
            Candidates::None
        );
    }

    #[test]
    fn parse_entry_fields() {
        let set = parse_key_set(&format!(
            r#"{{"keys": {{{}, "off": {{"hash": "ab", "salt": "cd", "enabled": false}},
                "gone": {{"hash": "ab", "salt": "cd", "revoked": true}},
                "nohash": {{"salt": "cd"}}, "junk": "x",
                "badexp": {{"hash": "ab", "salt": "cd", "expires_at": "soon"}}}}}}"#,
            alpha(r#""2030-06-01T12:00:00""#)
        ))
        .unwrap();
        let get = |id: &str| set.keys.iter().find(|k| k.key_id == id);
        let a = get("alpha").unwrap();
        assert_eq!(a.role, Role::Analyst);
        assert_eq!(a.lookup_hash.as_deref(), Some(ALPHA_LOOKUP));
        assert_eq!(
            a.expires_at,
            Some(
                NaiveDate::from_ymd_opt(2030, 6, 1)
                    .unwrap()
                    .and_hms_opt(12, 0, 0)
                    .unwrap()
                    .and_utc()
            )
        );
        assert!(!get("off").unwrap().enabled);
        assert!(!get("gone").unwrap().enabled);
        assert!(get("nohash").is_none());
        assert!(get("junk").is_none());
        assert!(!get("badexp").unwrap().is_usable(Utc::now()));
        assert_eq!(set.by_lookup.len(), 1);
        assert_eq!(set.legacy.len(), 3);
    }

    #[test]
    fn non_string_expires_at_fails_closed_like_the_bridge() {
        let set = parse_key_set(
            r#"{"keys": {
                "num": {"hash": "ab", "salt": "cd", "expires_at": 4102444800},
                "bool": {"hash": "ab", "salt": "cd", "expires_at": true},
                "obj": {"hash": "ab", "salt": "cd", "expires_at": {"at": "2099-01-01"}},
                "null": {"hash": "ab", "salt": "cd", "expires_at": null},
                "empty": {"hash": "ab", "salt": "cd", "expires_at": "  "},
                "none": {"hash": "ab", "salt": "cd"}}}"#,
        )
        .unwrap();
        let usable = |id: &str| {
            set.keys
                .iter()
                .find(|k| k.key_id == id)
                .unwrap()
                .is_usable(Utc::now())
        };
        for id in ["num", "bool", "obj"] {
            assert!(!usable(id), "{id} must be treated as expired");
        }
        for id in ["null", "empty", "none"] {
            assert!(usable(id), "{id} keeps the legacy non-expiring policy");
        }
    }

    #[test]
    fn parse_array_format() {
        let set = parse_key_set(&format!(
            r#"{{"keys": [{{"key_id": "a", "hash": "{ALPHA_HASH}", "salt": "{ALPHA_SALT}",
                "lookup_hash": "{}", "role": "ADMIN"}}]}}"#,
            ALPHA_LOOKUP.to_uppercase()
        ))
        .unwrap();
        assert_eq!(set.keys[0].key_id, "a");
        assert_eq!(set.keys[0].role, Role::Admin);
        assert!(set.by_lookup.contains_key(ALPHA_LOOKUP));
    }

    /// GW5-R4 regression: the bridge downgrades an edge-named key stored
    /// as ADMIN or ANALYST to NODE when it loads keys.json (without
    /// rewriting the file); the gateway used the stored role, so such a
    /// key was ANALYST operator tooling here and a node key there.
    #[test]
    fn edge_named_keys_with_an_operator_role_are_node_keys() {
        let entry = |id: &str, role: &str| {
            format!(r#""{id}": {{"hash": "ab", "salt": "cd", "role": "{role}"}}"#)
        };
        let set = parse_key_set(&format!(
            r#"{{"keys": {{{}}}}}"#,
            [
                entry("edge_x", "analyst"),
                entry("node_1", "admin"),
                entry("rtlsdr_a", "analyst"),
                entry("hackrf_b", "analyst"),
                entry("sensor_c", "analyst"),
                entry("sdr_d", "admin"),
                entry("edge_v", "viewer"),
                entry("edge_s", "sensor"),
                entry("edge_k", "keymaster"),
                entry("edge_u", "ANALYST"),
                entry("node_a", "Admin"),
                entry("edge_o", "node"),
                entry("edge_z", "bogus"),
                entry("edgex", "analyst"),
                entry("my_edge_x", "analyst"),
                entry("grafana", "analyst"),
            ]
            .join(",")
        ))
        .unwrap();
        let role = |id: &str| set.keys.iter().find(|k| k.key_id == id).unwrap().role;
        for id in [
            "edge_x", "node_1", "rtlsdr_a", "hackrf_b", "sensor_c", "sdr_d",
        ] {
            assert_eq!(role(id), Role::Node, "{id}");
        }
        // Any role of ANALYST or higher, in any letter case (as on the
        // bridge), and only for the edge prefixes at the start of the id.
        for id in ["edge_k", "edge_u", "node_a"] {
            assert_eq!(role(id), Role::Node, "{id}");
        }
        assert_eq!(role("edge_v"), Role::Viewer);
        assert_eq!(role("edge_s"), Role::Sensor);
        assert_eq!(role("edge_o"), Role::Node);
        // An unknown or missing role is VIEWER for an edge key too.
        assert_eq!(role("edge_z"), Role::Viewer);
        assert_eq!(role("edgex"), Role::Analyst);
        assert_eq!(role("my_edge_x"), Role::Analyst);
        assert_eq!(role("grafana"), Role::Analyst);
        assert_eq!(effective_role("edge_n", None), Role::Viewer);
    }

    /// Role default parity regression: a key stored without a role (legacy
    /// keys), or with one that names no role, authenticated as SENSOR here
    /// and as VIEWER on the bridge (`dependencies._role_from_name`,
    /// `stored_key_role`). So the gateway refused it on its own viewer
    /// routes (native queries, WebSocket feeds) that the bridge's routes
    /// let it read, and took it for a node credential: with
    /// `BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1`, or without a usable proxy
    /// secret, it accepted its batches for any node.
    #[test]
    fn a_missing_or_unknown_role_is_viewer() {
        for (key_id, stored) in [
            ("legacy", None),
            ("x", Some("")),
            ("x", Some("superuser")),
            ("x", Some(" admin")),
            ("x", Some("admin ")),
            ("edge_z", Some("bogus")),
            ("edge_n", None),
        ] {
            assert_eq!(
                effective_role(key_id, stored),
                Role::Viewer,
                "{key_id} {stored:?}"
            );
        }
        // Through the keys.json parser: a null, number, list or object is
        // no role name either.
        let set = parse_key_set(
            r#"{"keys": {
                "none": {"hash": "ab", "salt": "cd"},
                "null": {"hash": "ab", "salt": "cd", "role": null},
                "number": {"hash": "ab", "salt": "cd", "role": 4},
                "list": {"hash": "ab", "salt": "cd", "role": ["admin"]},
                "object": {"hash": "ab", "salt": "cd", "role": {"name": "admin"}},
                "edge_none": {"hash": "ab", "salt": "cd"}
            }}"#,
        )
        .unwrap();
        assert_eq!(set.keys.len(), 6);
        for key in &set.keys {
            assert_eq!(key.role, Role::Viewer, "{}", key.key_id);
        }
    }

    /// The bridge always reads its master key as ADMIN (`stored_key_role`)
    /// and writes it without a role on first run (as `viewer` after the
    /// next key change). The gateway read the stored role: SENSOR, then
    /// VIEWER — refused on the gateway's own admin routes — or KEYMASTER
    /// for a master key stored as such.
    #[test]
    fn the_master_key_is_admin_whatever_is_stored() {
        for stored in [
            None,
            Some("viewer"),
            Some("sensor"),
            Some("node"),
            Some("bogus"),
            Some("admin"),
            Some("keymaster"),
        ] {
            assert_eq!(effective_role("master", stored), Role::Admin, "{stored:?}");
        }
        // Only that exact key id.
        for key_id in ["Master", "master_2", " master", "masterkey"] {
            assert_eq!(effective_role(key_id, None), Role::Viewer, "{key_id}");
        }
        assert_eq!(effective_role("masterkey", Some("sensor")), Role::Sensor);
        let set = parse_key_set(r#"{"keys": {"master": {"hash": "ab", "salt": "cd"}}}"#).unwrap();
        assert_eq!(set.keys[0].role, Role::Admin);
    }

    /// The master key's ADMIN role is no exemption from the usability
    /// checks: revoked, disabled or expired, it is refused like any key,
    /// as by the bridge's `_key_usable`. (Through the whole validation
    /// path; the shared table checks the parsed flags.)
    #[tokio::test]
    async fn a_revoked_disabled_or_expired_master_key_is_refused() {
        let master = |extra: &str| {
            format!(
                r#""master": {{"hash": "{ALPHA_HASH}", "salt": "{ALPHA_SALT}",
                    "lookup_hash": "{ALPHA_LOOKUP}"{extra}}}"#
            )
        };
        let dir = tempfile::tempdir().unwrap();
        let store = KeyStore::try_new(&write_keys(&dir, &[master("")])).unwrap();
        assert_eq!(
            store.validate(ALPHA_RAW).await,
            Some(("master".to_string(), Role::Admin))
        );
        for extra in [
            r#", "revoked": true"#,
            r#", "enabled": false"#,
            r#", "role": "admin", "revoked": true, "enabled": true"#,
            r#", "expires_at": "2020-01-01T00:00:00+00:00""#,
            r#", "expires_at": "soon""#,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let store = KeyStore::try_new(&write_keys(&dir, &[master(extra)])).unwrap();
            assert_eq!(store.validate(ALPHA_RAW).await, None, "master{extra}");
        }
    }

    /// The table of stored roles the bridge is pinned to as well
    /// (`tests/bridge/test_key_role_parity.py`): each case, alone in a
    /// keys.json, must authenticate with the same role on both sides, or
    /// be refused on both (`usable: false`).
    const ROLE_PARITY_TABLE: &str = include_str!("../../testdata/key_role_parity.json");

    /// The table's size when last extended; the bridge's test has the
    /// same floor. Any lost case fails both sides, not only the bridge's
    /// rewrite check.
    const ROLE_PARITY_CASES: usize = 47;

    #[test]
    fn stored_roles_read_as_on_the_bridge() {
        let table: serde_json::Value = serde_json::from_str(ROLE_PARITY_TABLE).unwrap();
        let cases = table["cases"].as_array().unwrap();
        assert!(
            cases.len() >= ROLE_PARITY_CASES,
            "the shared table lost cases: {} < {ROLE_PARITY_CASES}",
            cases.len()
        );
        let now = Utc::now();
        let mut mismatches = Vec::new();
        for case in cases {
            let key_id = case["key_id"].as_str().unwrap();
            let mut entry = serde_json::json!({"hash": "ab", "salt": "cd"});
            for (field, value) in case["entry"].as_object().unwrap() {
                entry[field] = value.clone();
            }
            let raw = serde_json::json!({"keys": {key_id: entry}}).to_string();
            let set = parse_key_set(&raw).unwrap();
            assert_eq!(set.keys.len(), 1, "{key_id}");
            let expected: Role = case["role"].as_str().unwrap().parse().unwrap();
            let got = set.keys[0].role;
            if got != expected {
                mismatches.push(format!(
                    "{key_id} {}: {got}, the bridge reads {expected}",
                    case["entry"]
                ));
            }
            let usable = case.get("usable").map_or(true, |u| u.as_bool().unwrap());
            if set.keys[0].is_usable(now) != usable {
                mismatches.push(format!(
                    "{key_id} {}: usable is {}, on the bridge {usable}",
                    case["entry"], !usable
                ));
            }
        }
        assert!(
            mismatches.is_empty(),
            "{} mismatches:\n{}",
            mismatches.len(),
            mismatches.join("\n")
        );
    }

    /// Regression (Residual-B): Python writes a lone surrogate in a key
    /// description as `"\ud800"`; serde_json refused the whole file, so the
    /// gateway froze on its previous key set (and could not start).
    #[test]
    fn lone_surrogate_in_a_description_does_not_block_the_file() {
        // What `json.dumps({"description": "x\ud800y"})` produces.
        let raw = format!(
            r#"{{"keys": {{{}, "bad": {{"hash": "{BRAVO_HASH}", "salt": "{BRAVO_SALT}",
                "lookup_hash": "{BRAVO_LOOKUP}", "role": "viewer",
                "description": "x\ud800y \udc00 \ud83d\ude00 \\ud800 \u00e9"}}}}}}"#,
            alpha("null")
        );
        assert!(serde_json::from_str::<serde_json::Value>(&raw).is_err());
        let set = parse_key_set(&raw).unwrap();
        let mut ids: Vec<_> = set.keys.iter().map(|k| k.key_id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids, ["alpha", "bad"], "both keys load");
        assert!(set.by_lookup.contains_key(BRAVO_LOOKUP));

        let (fixed, replaced) = replace_lone_surrogate_escapes(&raw);
        assert_eq!(replaced, 2, "only the two unpaired surrogates");
        let parsed: serde_json::Value = serde_json::from_str(&fixed).unwrap();
        assert_eq!(
            parsed["keys"]["bad"]["description"], "x\u{FFFD}y \u{FFFD} \u{1F600} \\ud800 \u{e9}",
            "pairs, escaped backslashes and other escapes are untouched"
        );
    }

    #[test]
    fn surrogate_scan_edge_cases() {
        for clean in [
            r#"{"a": "\\u"}"#,
            r#"{"a": "\u12"}"#,
            "\\",
            r#"{"a":"\ud83d\ude00"}"#,
        ] {
            assert_eq!(replace_lone_surrogate_escapes(clean).1, 0, "{clean}");
        }
        let (s, n) = replace_lone_surrogate_escapes(r#"["\ud800\ud800", "\udfff"]"#);
        assert_eq!(n, 3);
        assert_eq!(s, r#"["\uFFFD\uFFFD", "\uFFFD"]"#);
        let (s, n) = replace_lone_surrogate_escapes(r#""\ud800""#);
        assert_eq!((s.as_ref(), n), (r#""\uFFFD""#, 1));
    }

    #[test]
    fn store_with_a_surrogate_description_loads_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_keys(&dir, &[alpha("null")]);
        let store = KeyStore::try_new(&path).expect("loads");
        write_raw(
            &dir,
            &format!(
                r#"{{"keys": {{{}, "c": {{"hash": "h", "salt": "00", "role": "node",
                    "node_id": "edge-7", "description": "\udead"}}}}}}"#,
                bravo()
            ),
        );
        store.reload().unwrap();
        let mut ids = store.key_ids();
        ids.sort_unstable();
        assert_eq!(ids, ["bravo", "c"], "the reload applied (alpha revoked)");
        assert_eq!(store.node_id_for("c").as_deref(), Some("edge-7"));
        assert_eq!(store.node_id_for("bravo"), None);
        assert_eq!(store.node_id_for("nope"), None);
    }

    /// Q23: the bridge's node registry (nodes.json next to keys.json) is
    /// read for its legacy key-named-after-a-node rule, and re-read when
    /// it changes; a missing file is empty, a broken one keeps the last.
    #[test]
    fn registered_nodes_come_from_the_bridge_registry_beside_keys_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_keys(&dir, &[alpha("null")]);
        let store = KeyStore::try_new(&path).expect("loads");
        let nodes = dir.path().join("nodes.json");
        assert!(!store.is_registered_node("edge-7"), "no registry yet");

        std::fs::write(&nodes, r#"{"nodes": {"edge-7": {"status": "online"}}}"#).unwrap();
        assert!(store.is_registered_node("edge-7"));
        assert!(!store.is_registered_node("edge-8"));
        assert!(!store.is_registered_node("alpha"));

        std::fs::write(&nodes, r#"{"nodes": {"edge-8": {}, "edge-9": {"x": 1}}}"#).unwrap();
        assert!(!store.is_registered_node("edge-7"), "reloaded");
        assert!(store.is_registered_node("edge-8"));

        std::fs::write(&nodes, r#"{"nodes": {"edge-8": "#).unwrap();
        assert!(
            store.is_registered_node("edge-8"),
            "a broken file keeps the last list"
        );
        std::fs::write(&nodes, r#"{"other": 1}"#).unwrap();
        assert!(!store.is_registered_node("edge-8"));
        std::fs::remove_file(&nodes).unwrap();
        assert!(!store.is_registered_node("edge-8"));
    }

    #[test]
    fn parse_expiry_python_isoformat_variants() {
        let utc = |y, mo, d, h, mi, s| {
            NaiveDate::from_ymd_opt(y, mo, d)
                .unwrap()
                .and_hms_opt(h, mi, s)
                .unwrap()
                .and_utc()
        };
        assert_eq!(
            parse_expiry("2026-11-05T10:20:30+00:00"),
            Some(utc(2026, 11, 5, 10, 20, 30))
        );
        assert_eq!(
            parse_expiry("2026-11-05T12:20:30.654321+02:00").map(|d| d.timestamp()),
            Some(utc(2026, 11, 5, 10, 20, 30).timestamp())
        );
        assert_eq!(
            parse_expiry("2026-11-05T10:20:30Z"),
            Some(utc(2026, 11, 5, 10, 20, 30))
        );
        assert_eq!(
            parse_expiry("2026-11-05 10:20:30+00:00"),
            Some(utc(2026, 11, 5, 10, 20, 30))
        );
        assert_eq!(
            parse_expiry("2026-11-05T10:20:30"),
            Some(utc(2026, 11, 5, 10, 20, 30))
        );
        assert_eq!(
            parse_expiry("2026-11-05T10:20:30.5").map(|d| d.timestamp()),
            Some(utc(2026, 11, 5, 10, 20, 30).timestamp())
        );
        assert_eq!(parse_expiry("2026-11-05"), Some(utc(2026, 11, 5, 0, 0, 0)));
        assert_eq!(parse_expiry("next tuesday"), None);
    }

    #[test]
    fn lookup_hash_matches_python() {
        let digest: [u8; 32] = Sha256::digest(ALPHA_RAW.as_bytes()).into();
        assert_eq!(hex::encode(digest), ALPHA_LOOKUP);
        assert_eq!(key_fingerprint(&digest), &ALPHA_LOOKUP[..8]);
    }

    // ── Concurrency and cancellation ──────────────────────────────────

    /// Stands in for PBKDF2: blocks every verification until released and
    /// accepts a presented key iff it equals the stored `hash`. Counts how
    /// many verifications entered and how many ran at once.
    #[derive(Default)]
    struct Gate {
        open: Mutex<bool>,
        cv: std::sync::Condvar,
        entered: AtomicUsize,
        active: AtomicUsize,
        max_active: AtomicUsize,
    }

    impl Gate {
        fn verifier(self: &Arc<Self>) -> Verifier {
            let gate = Arc::clone(self);
            Box::new(move |stored, presented| {
                gate.entered.fetch_add(1, SeqCst);
                let active = gate.active.fetch_add(1, SeqCst) + 1;
                gate.max_active.fetch_max(active, SeqCst);
                let mut open = gate.open.lock().unwrap();
                while !*open {
                    open = gate.cv.wait(open).unwrap();
                }
                drop(open);
                gate.active.fetch_sub(1, SeqCst);
                stored.hash == presented
            })
        }

        fn release(&self) {
            *self.open.lock().unwrap() = true;
            self.cv.notify_all();
        }

        fn entered(&self) -> usize {
            self.entered.load(SeqCst)
        }

        fn max_active(&self) -> usize {
            self.max_active.load(SeqCst)
        }
    }

    /// A keys.json entry that the [`Gate`] verifier accepts for `raw`.
    fn gated_entry(key_id: &str, raw: &str, indexed: bool) -> String {
        let lookup = if indexed {
            format!(
                r#", "lookup_hash": "{}""#,
                hex::encode(Sha256::digest(raw.as_bytes()))
            )
        } else {
            String::new()
        };
        format!(r#""{key_id}": {{"hash": "{raw}", "salt": "00", "role": "viewer"{lookup}}}"#)
    }

    /// The test's handle on a [`Gate`]; opens it when dropped, so a failing
    /// assertion unblocks the verifications instead of hanging the test
    /// (the runtime waits for blocking tasks when it shuts down).
    struct GateHandle(Arc<Gate>);

    impl std::ops::Deref for GateHandle {
        type Target = Gate;
        fn deref(&self) -> &Gate {
            &self.0
        }
    }

    impl Drop for GateHandle {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    fn gated_store(dir: &tempfile::TempDir, entries: &[String]) -> (Arc<KeyStore>, GateHandle) {
        let path = write_keys(dir, entries);
        let gate = Arc::new(Gate::default());
        let store = KeyStore::with_verifier(&path, gate.verifier());
        store.reload().unwrap();
        (Arc::new(store), GateHandle(gate))
    }

    type Validation = tokio::task::JoinHandle<Option<(String, Role)>>;

    fn spawn_validate(store: &Arc<KeyStore>, key: &str) -> Validation {
        let store = Arc::clone(store);
        let key = key.to_owned();
        tokio::spawn(async move { store.validate(&key).await })
    }

    /// Drop a validation mid-flight, as hyper drops the request future
    /// when the client closes the connection.
    async fn disconnect(task: Validation) {
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }

    async fn wait_until(what: &str, done: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting until {what}");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    fn all_permits_free(store: &KeyStore) -> bool {
        let l = &store.limits;
        l.pbkdf2.available_permits() == PBKDF2_CONCURRENCY
            && l.legacy_running.available_permits() == LEGACY_SCAN_CONCURRENCY
            && l.legacy_admitted.available_permits()
                == LEGACY_SCAN_CONCURRENCY + LEGACY_SCAN_MAX_WAITING
    }

    #[tokio::test]
    async fn disconnected_legacy_scan_keeps_its_permits_until_pbkdf2_finishes() {
        let dir = tempfile::tempdir().unwrap();
        let (store, gate) = gated_store(&dir, &[gated_entry("old", "sk-old", false)]);

        let task = spawn_validate(&store, "attacker-0");
        wait_until("the scan runs", || gate.entered() == 1).await;
        disconnect(task).await;

        // PBKDF2 is still running on the blocking pool, so it still counts.
        let l = &store.limits;
        assert_eq!(
            l.legacy_running.available_permits(),
            LEGACY_SCAN_CONCURRENCY - 1
        );
        assert_eq!(
            l.legacy_admitted.available_permits(),
            LEGACY_SCAN_CONCURRENCY + LEGACY_SCAN_MAX_WAITING - 1
        );
        assert_eq!(l.pbkdf2.available_permits(), PBKDF2_CONCURRENCY - 1);

        gate.release();
        wait_until("the scan ends", || all_permits_free(&store)).await;
        // The result was cached although nobody waited for it.
        assert_eq!(store.validate("attacker-0").await, None);
        assert_eq!(store.pbkdf2_runs(), 1);
    }

    #[tokio::test]
    async fn legacy_scans_are_bounded_and_the_excess_rejected_without_pbkdf2() {
        let dir = tempfile::tempdir().unwrap();
        let (store, gate) = gated_store(&dir, &[gated_entry("old", "sk-old", false)]);
        let admitted = LEGACY_SCAN_CONCURRENCY + LEGACY_SCAN_MAX_WAITING;

        let tasks: Vec<Validation> = (0..admitted)
            .map(|i| spawn_validate(&store, &format!("attacker-{i}")))
            .collect();
        wait_until("the scan queue is full", || {
            store.limits.legacy_admitted.available_permits() == 0
                && gate.entered() == LEGACY_SCAN_CONCURRENCY
        })
        .await;

        // Beyond the queue: rejected at once, no PBKDF2, no waiting — and
        // not cached as a failure, since it was never checked.
        let started = Instant::now();
        assert_eq!(store.validate("attacker-extra").await, None);
        assert_eq!(store.validate("sk-old").await, None);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(gate.entered(), LEGACY_SCAN_CONCURRENCY);

        // Every client disconnects. Waiting scans give their place back;
        // running ones hold their permits until PBKDF2 ends.
        for task in tasks {
            disconnect(task).await;
        }
        assert_eq!(store.limits.legacy_running.available_permits(), 0);
        assert_eq!(
            store.limits.legacy_admitted.available_permits(),
            LEGACY_SCAN_MAX_WAITING
        );
        assert_eq!(
            store.limits.pbkdf2.available_permits(),
            PBKDF2_CONCURRENCY - LEGACY_SCAN_CONCURRENCY
        );

        gate.release();
        wait_until("the scans end", || all_permits_free(&store)).await;
        assert_eq!(gate.max_active(), LEGACY_SCAN_CONCURRENCY);
        assert_eq!(store.pbkdf2_runs(), LEGACY_SCAN_CONCURRENCY as u64);

        // The legacy key rejected while the queue was full works now.
        assert_eq!(
            store.validate("sk-old").await,
            Some(("old".to_string(), Role::Viewer))
        );
    }

    #[tokio::test]
    async fn disconnected_indexed_validation_still_fills_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let (store, gate) = gated_store(&dir, &[gated_entry("node-1", "sk-node-1", true)]);

        let task = spawn_validate(&store, "sk-node-1");
        wait_until("PBKDF2 runs", || gate.entered() == 1).await;
        disconnect(task).await;
        assert_eq!(
            store.limits.pbkdf2.available_permits(),
            PBKDF2_CONCURRENCY - 1
        );

        gate.release();
        wait_until("PBKDF2 ends", || all_permits_free(&store)).await;
        // Served from the cache the disconnected request filled.
        assert_eq!(
            store.validate("sk-node-1").await,
            Some(("node-1".to_string(), Role::Viewer))
        );
        assert_eq!(store.pbkdf2_runs(), 1);
    }

    #[tokio::test]
    async fn pbkdf2_verifications_are_bounded_across_keys() {
        let dir = tempfile::tempdir().unwrap();
        let n = PBKDF2_CONCURRENCY + 3;
        let entries: Vec<String> = (0..n)
            .map(|i| gated_entry(&format!("node-{i}"), &format!("sk-{i}"), true))
            .collect();
        let (store, gate) = gated_store(&dir, &entries);

        let tasks: Vec<Validation> = (0..n)
            .map(|i| spawn_validate(&store, &format!("sk-{i}")))
            .collect();
        wait_until("every slot is busy", || {
            gate.entered() == PBKDF2_CONCURRENCY
        })
        .await;
        // The others wait for a slot instead of each taking a blocking
        // thread.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(gate.entered(), PBKDF2_CONCURRENCY);

        gate.release();
        for (i, task) in tasks.into_iter().enumerate() {
            assert_eq!(
                task.await.unwrap(),
                Some((format!("node-{i}"), Role::Viewer))
            );
        }
        assert_eq!(gate.max_active(), PBKDF2_CONCURRENCY);
        assert_eq!(store.pbkdf2_runs(), n as u64);
    }

    #[tokio::test]
    async fn legacy_key_beyond_the_first_sixteen_validates() {
        let dir = tempfile::tempdir().unwrap();
        let n = LEGACY_SCAN_SLOW + 4;
        let entries: Vec<String> = (0..n)
            .map(|i| gated_entry(&format!("legacy-{i:02}"), &format!("sk-{i:02}"), false))
            .collect();
        let (store, gate) = gated_store(&dir, &entries);
        gate.release();

        // key_id order puts it last: only a scan of every entry finds it.
        let last = n - 1;
        assert_eq!(
            store.validate(&format!("sk-{last:02}")).await,
            Some((format!("legacy-{last:02}"), Role::Viewer))
        );
        assert_eq!(store.pbkdf2_runs(), n as u64);
    }

    #[tokio::test]
    async fn tenant_boundary_inflight_verification_uses_current_snapshot_scope() {
        let dir = tempfile::tempdir().unwrap();
        let entry = gated_entry("moving", "moving-test-key", true);
        let (store, gate) = gated_store(&dir, &[entry]);
        let task = spawn_validate(&store, "moving-test-key");
        wait_until("credential verification started", || gate.entered() == 1).await;
        let entry = gated_entry("moving", "moving-test-key", true);
        let mut value: serde_json::Value = serde_json::from_str(&format!("{{{entry}}}")).unwrap();
        value["moving"]["tenant_id"] = serde_json::json!("other");
        let encoded = value.to_string();
        write_keys(&dir, &[encoded[1..encoded.len() - 1].to_string()]);
        gate.release();
        assert_eq!(task.await.unwrap(), None);
        assert!(store
            .validate_for_instance("moving-test-key")
            .await
            .is_err());
        assert!(store
            .validate_for_instance("wrong-credential")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn tenant_boundary_inflight_verification_rechecks_current_credential() {
        for mutation in ["delete", "rotate", "disable", "demote"] {
            let dir = tempfile::tempdir().unwrap();
            let entry = gated_entry("moving", "moving-test-key", true);
            let (store, gate) = gated_store(&dir, std::slice::from_ref(&entry));
            let task = spawn_validate(&store, "moving-test-key");
            wait_until("credential verification started", || gate.entered() == 1).await;
            let mut value: serde_json::Value =
                serde_json::from_str(&format!("{{{entry}}}")).unwrap();
            match mutation {
                "delete" => {
                    value.as_object_mut().unwrap().remove("moving");
                }
                "rotate" => value["moving"]["hash"] = serde_json::json!("replacement-key"),
                "disable" => value["moving"]["enabled"] = serde_json::json!(false),
                "demote" => value["moving"]["role"] = serde_json::json!("sensor"),
                _ => unreachable!(),
            }
            let encoded = value.to_string();
            write_keys(&dir, &[encoded[1..encoded.len() - 1].to_string()]);
            // Only edit the actual file: no explicit KeyStore.reload call.
            gate.release();
            let expected = (mutation == "demote").then(|| ("moving".to_string(), Role::Sensor));
            assert_eq!(task.await.unwrap(), expected, "{mutation}");
            assert_eq!(
                store.validate("moving-test-key").await,
                expected,
                "{mutation} cached"
            );
        }
    }

    // ── Security paths: request auth, hashing, revocation, queued checks ──

    /// Like [`gated_entry`] (indexed), with extra JSON fields appended.
    fn gated_entry_with(key_id: &str, raw: &str, fields: &str) -> String {
        format!(
            r#""{key_id}": {{"hash": "{raw}", "salt": "00", "lookup_hash": "{}"{fields}}}"#,
            hex::encode(Sha256::digest(raw.as_bytes()))
        )
    }

    fn request_with(headers: &[(&str, &str)], uri: &str) -> Request {
        let mut builder = axum::http::Request::builder().uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(axum::body::Body::empty()).unwrap()
    }

    /// The production decision for a request's API key: the auth middleware
    /// resolves the key (`middleware::auth::validate_api_key`) and handlers
    /// gate on `middleware::auth::require_auth`. No key, an empty or an
    /// unknown key is 401; a valid key scoped to another tenant is refused
    /// with 403 by the middleware itself; a valid local key below the
    /// route's role is 403; only a valid local key with enough role reaches
    /// the handler, as itself.
    #[tokio::test]
    async fn request_auth_maps_each_rejection_to_its_status() {
        use crate::middleware::auth::{self as mw, AuthInfo};
        use axum::response::IntoResponse as _;
        use tower::ServiceExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = write_keys(
            &dir,
            &[
                gated_entry_with("viewer-key", "sk-viewer", r#", "role": "viewer""#),
                gated_entry_with("admin-key", "sk-admin", r#", "role": "admin""#),
                gated_entry_with(
                    "foreign-admin",
                    "sk-foreign",
                    r#", "role": "keymaster", "tenant_id": "other""#,
                ),
            ],
        );
        // The stored "hash" is the raw key (see `gated_entry_with`): no PBKDF2.
        let store = KeyStore::with_verifier(
            &path,
            Box::new(|stored, presented| stored.hash == presented),
        );
        store.reload().unwrap();
        let Ok(mut state) = Arc::try_unwrap(crate::test_support::app_state(&dir)) else {
            unreachable!("fresh state has one owner")
        };
        state.key_store = Some(store);
        state.auth_enabled = true;
        let state = Arc::new(state);

        let gated = |min_role: Role| {
            axum::routing::get(move |req: Request| async move {
                match mw::require_auth(&req, min_role) {
                    Ok(AuthInfo::ApiKey { key_id, role }) => {
                        format!("{key_id} {role}").into_response()
                    }
                    Ok(other) => (StatusCode::IM_A_TEAPOT, format!("{other:?}")).into_response(),
                    Err(status) => status.into_response(),
                }
            })
        };
        let app = axum::Router::new()
            .route("/viewer", gated(Role::Viewer))
            .route("/analyst", gated(Role::Analyst))
            .route("/admin", gated(Role::Admin))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&state),
                mw::auth_middleware,
            ));

        let ok = |key_id: &str, role: Role| (StatusCode::OK, format!("{key_id} {role}"));
        let refused = |status: StatusCode| (status, String::new());
        let cases = [
            (None, "/viewer", refused(StatusCode::UNAUTHORIZED)),
            (
                Some("sk-unknown"),
                "/viewer",
                refused(StatusCode::UNAUTHORIZED),
            ),
            (Some(""), "/viewer", refused(StatusCode::UNAUTHORIZED)),
            (
                Some("sk-foreign"),
                "/viewer",
                refused(StatusCode::FORBIDDEN),
            ),
            (
                Some("sk-viewer"),
                "/analyst",
                refused(StatusCode::FORBIDDEN),
            ),
            (Some("sk-viewer"), "/viewer", ok("viewer-key", Role::Viewer)),
            (Some("sk-admin"), "/admin", ok("admin-key", Role::Admin)),
            (Some("sk-admin"), "/viewer", ok("admin-key", Role::Admin)),
        ];
        for (key, route, expected) in cases {
            let headers: &[(&str, &str)] = match key {
                Some(key) => &[("x-api-key", key)],
                None => &[],
            };
            let resp = app
                .clone()
                .oneshot(request_with(headers, route))
                .await
                .unwrap();
            let status = resp.status();
            let body = axum::body::to_bytes(resp.into_body(), 1 << 16)
                .await
                .unwrap();
            assert_eq!(
                (status, String::from_utf8_lossy(&body).into_owned()),
                expected,
                "{key:?} {route}"
            );
        }
    }

    /// One credential decides: `X-API-Key` beats `Authorization: Bearer`,
    /// which beats the `api_key` query parameter; other schemes and
    /// parameters that merely end in `api_key` are not credentials.
    #[test]
    fn extract_api_key_sources_and_precedence() {
        let all = request_with(
            &[
                ("x-api-key", "from-header"),
                ("authorization", "Bearer from-bearer"),
            ],
            "/x?api_key=from-query",
        );
        assert_eq!(extract_api_key(&all).as_deref(), Some("from-header"));
        let bearer = request_with(
            &[("authorization", "Bearer from-bearer")],
            "/x?api_key=from-query",
        );
        assert_eq!(extract_api_key(&bearer).as_deref(), Some("from-bearer"));
        let query = request_with(&[], "/x?a=1&api_key=first&api_key=second");
        assert_eq!(extract_api_key(&query).as_deref(), Some("first"));

        let none: [(&[(&str, &str)], &str); 4] = [
            (&[("authorization", "Basic dXNlcjpwdw==")], "/x"),
            (&[("authorization", "Bearerfrom-bearer")], "/x"),
            (&[], "/x?not_api_key=x&apikey=y"),
            (&[], "/x"),
        ];
        for (headers, uri) in none {
            assert_eq!(
                extract_api_key(&request_with(headers, uri)),
                None,
                "{headers:?} {uri}"
            );
        }
        // A non-text X-API-Key is no credential, and does not fall through to
        // a different credential carried by the same request.
        let mut opaque = request_with(&[("authorization", "Bearer from-bearer")], "/x");
        opaque.headers_mut().insert(
            "x-api-key",
            axum::http::HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
        );
        assert_eq!(extract_api_key(&opaque), None);
    }

    /// A bearer key is read as a bearer session is (the shared table
    /// `testdata/session_token_parity.json`): the scheme in any letter case,
    /// the key without the whitespace around it.
    #[test]
    fn extract_api_key_reads_the_bearer_scheme_in_any_letter_case() {
        for value in ["bearer sk-x", "BEARER sk-x", "BeArEr   sk-x  "] {
            let req = request_with(&[("authorization", value)], "/x");
            assert_eq!(extract_api_key(&req).as_deref(), Some("sk-x"), "{value}");
        }
        let tab = request_with(&[("authorization", "bearer\tsk-x")], "/x");
        assert_eq!(extract_api_key(&tab), None);
    }

    /// The real verifier: PBKDF2 (current), salted SHA-256 over the salt
    /// bytes and over the salt hex (legacy) all match their own key only; a
    /// salt that is not hex never matches.
    #[test]
    fn verify_key_accepts_each_stored_format_for_its_key_only() {
        assert!(verify_key(ALPHA_SALT, ALPHA_RAW, ALPHA_HASH));
        assert!(!verify_key(
            ALPHA_SALT,
            "sk-test-alpha-012345678",
            ALPHA_HASH
        ));
        assert!(verify_key(LEGACY_SALT, LEGACY_RAW, LEGACY_HASH));

        let mut hasher = Sha256::new();
        hasher.update(LEGACY_SALT.as_bytes());
        hasher.update(b"sk-early");
        let early_hash = hex::encode(hasher.finalize());
        assert!(verify_key(LEGACY_SALT, "sk-early", &early_hash));

        // A salt that is not hex is refused outright. Each stored hash below
        // is one a fall-through would match: SHA-256 over the salt text (the
        // early format), and SHA-256 over empty salt bytes (the key alone).
        let mut over_salt_text = Sha256::new();
        over_salt_text.update(b"not-hex");
        over_salt_text.update(b"sk-x");
        assert!(!verify_key(
            "not-hex",
            "sk-x",
            &hex::encode(over_salt_text.finalize())
        ));
        assert!(!verify_key(
            "not-hex",
            "sk-x",
            &hex::encode(Sha256::digest(b"sk-x"))
        ));
    }

    /// Every stored-hash comparison is constant time (checked in the source:
    /// a timing test would be flaky).
    #[test]
    fn verify_key_compares_hashes_in_constant_time() {
        use crate::auth::totp::tests::{assert_constant_time_compares, fn_body};
        let body = fn_body(include_str!("api_key.rs"), "verify_key");
        assert_constant_time_compares("verify_key", body, 3);
    }

    /// A lookup-hash match only picks the candidate: the stored hash must
    /// still verify, and the failure is remembered so a repeat costs no
    /// PBKDF2.
    #[tokio::test]
    async fn a_matching_lookup_hash_alone_does_not_authenticate() {
        let dir = tempfile::tempdir().unwrap();
        let mut stale: serde_json::Value =
            serde_json::from_str(&format!("{{{}}}", gated_entry("stale", "sk-stale", true)))
                .unwrap();
        stale["stale"]["hash"] = serde_json::json!("sk-rotated");
        let encoded = stale.to_string();
        let (store, gate) = gated_store(&dir, &[encoded[1..encoded.len() - 1].to_string()]);
        gate.release();

        assert_eq!(store.validate("sk-stale").await, None);
        assert_eq!(store.validate("sk-stale").await, None);
        assert_eq!(store.pbkdf2_runs(), 1);
    }

    /// Revocation, disabling and expiry written in place each reject a key
    /// that validated before, on the next request (the reload clears the
    /// success cache) and without PBKDF2.
    #[tokio::test]
    async fn in_place_revocation_disable_or_expiry_rejects_the_key_after_reload() {
        for field in [
            r#", "revoked": true"#,
            r#", "enabled": false"#,
            r#", "expires_at": "2020-01-01T00:00:00+00:00""#,
            r#", "expires_at": "not a date""#,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (store, gate) = gated_store(&dir, &[gated_entry_with("k", "sk-k", "")]);
            gate.release();
            assert!(store.validate("sk-k").await.is_some(), "{field}");
            write_keys(&dir, &[gated_entry_with("k", "sk-k", field)]);
            assert_eq!(store.validate("sk-k").await, None, "{field}");
            assert_eq!(store.pbkdf2_runs(), 1, "{field}");
        }
    }

    /// A reload clears the failure cache: a key first presented before the
    /// bridge wrote it is not stuck rejected once it exists.
    #[tokio::test]
    async fn a_remembered_failure_does_not_outlive_the_key_being_added() {
        let dir = tempfile::tempdir().unwrap();
        let (store, gate) = gated_store(&dir, &[gated_entry("old", "sk-old", false)]);
        gate.release();
        assert_eq!(store.validate("sk-new").await, None);
        assert_eq!(store.validate("sk-new").await, None);
        assert_eq!(store.pbkdf2_runs(), 1, "the failure was cached");

        write_keys(
            &dir,
            &[
                gated_entry("old", "sk-old", false),
                gated_entry("new", "sk-new", false),
            ],
        );
        assert_eq!(
            store.validate("sk-new").await,
            Some(("new".to_string(), Role::Viewer))
        );
    }

    /// A role change in keys.json applies on the next request after the
    /// key has validated with its old role.
    #[tokio::test]
    async fn a_role_change_applies_after_reload() {
        let dir = tempfile::tempdir().unwrap();
        let (store, gate) = gated_store(
            &dir,
            &[gated_entry_with("k", "sk-k", r#", "role": "admin""#)],
        );
        gate.release();
        assert_eq!(
            store.validate("sk-k").await,
            Some(("k".to_string(), Role::Admin))
        );
        write_keys(
            &dir,
            &[gated_entry_with("k", "sk-k", r#", "role": "viewer""#)],
        );
        assert_eq!(
            store.validate("sk-k").await,
            Some(("k".to_string(), Role::Viewer))
        );
    }

    /// Validations of one key queued behind a running PBKDF2 reuse its
    /// result: the expensive check runs once, every caller gets the key.
    #[tokio::test]
    async fn queued_validations_of_one_key_reuse_the_running_check() {
        let dir = tempfile::tempdir().unwrap();
        let (store, gate) = gated_store(&dir, &[gated_entry("node-1", "sk-node-1", true)]);
        let mut slots: Vec<_> = (0..PBKDF2_CONCURRENCY)
            .map(|_| {
                Arc::clone(&store.limits.pbkdf2)
                    .try_acquire_owned()
                    .unwrap()
            })
            .collect();
        let first = spawn_validate(&store, "sk-node-1");
        let second = spawn_validate(&store, "sk-node-1");
        // Current-thread runtime: yielding lets both reach the permit queue.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        slots.pop();
        wait_until("one check runs", || gate.entered() == 1).await;
        gate.release();
        let expected = Some(("node-1".to_string(), Role::Viewer));
        assert_eq!(first.await.unwrap(), expected);
        assert_eq!(second.await.unwrap(), expected);
        assert_eq!(store.pbkdf2_runs(), 1);
        drop(slots);
    }

    /// A validation queued for a PBKDF2 slot across a reload answers with
    /// the reloaded metadata (here: a demotion), never the old role.
    #[tokio::test]
    async fn a_validation_queued_across_a_reload_gets_the_reloaded_role() {
        let dir = tempfile::tempdir().unwrap();
        let (store, gate) = gated_store(
            &dir,
            &[gated_entry_with("k", "sk-k", r#", "role": "admin""#)],
        );
        let slots: Vec<_> = (0..PBKDF2_CONCURRENCY)
            .map(|_| {
                Arc::clone(&store.limits.pbkdf2)
                    .try_acquire_owned()
                    .unwrap()
            })
            .collect();
        let tasks = [
            spawn_validate(&store, "sk-k"),
            spawn_validate(&store, "sk-k"),
        ];
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        write_keys(
            &dir,
            &[gated_entry_with("k", "sk-k", r#", "role": "viewer""#)],
        );
        store.reload().unwrap();
        gate.release();
        drop(slots);
        for task in tasks {
            assert_eq!(task.await.unwrap(), Some(("k".to_string(), Role::Viewer)));
        }
    }

    /// The generation (what long-lived WebSocket credentials re-validate on)
    /// moves on every applied reload and only then.
    #[test]
    fn generation_moves_on_applied_reloads_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_keys(&dir, &[bravo()]);
        let store = KeyStore::try_new(&path).unwrap();
        let first = store.generation();
        assert_eq!(store.generation(), first, "unchanged file");
        write_raw(&dir, r#"{"keys": {"#);
        assert_eq!(store.generation(), first, "a broken file is not applied");
        write_keys(&dir, &[]);
        assert!(store.generation() > first);
    }

    /// A store that cannot read its file at start-up holds no keys:
    /// `try_new` refuses to build one and `new` builds an empty one.
    #[tokio::test]
    async fn an_unreadable_keys_file_authenticates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("keys.json");
        assert!(KeyStore::try_new(&missing).is_none());
        let empty = KeyStore::new(&missing);
        assert!(empty.key_ids().is_empty());
        assert_eq!(empty.validate(ALPHA_RAW).await, None);

        // Once the bridge writes the file, the empty store picks it up.
        write_keys(&dir, &[alpha("null")]);
        assert_eq!(empty.key_ids(), Vec::<String>::new());
        empty.reload_if_changed();
        assert_eq!(empty.key_ids(), vec!["alpha".to_string()]);
    }

    /// A malformed `lookup_hash` is not trusted as an index: the entry is
    /// treated as legacy (full PBKDF2 scan), and a whitespace-only
    /// `node_id` binds the key to no node.
    #[test]
    fn malformed_lookup_hash_and_blank_node_id_are_not_trusted() {
        let non_hex = format!("zz{}", "0".repeat(62));
        let set = parse_key_set(&format!(
            r#"{{"keys": {{
                "short": {{"hash": "ab", "salt": "cd", "lookup_hash": "abc123"}},
                "nonhex": {{"hash": "ab", "salt": "cd", "lookup_hash": "{non_hex}"}},
                "blank": {{"hash": "ab", "salt": "cd", "lookup_hash": "  "}}}}}}"#
        ))
        .unwrap();
        assert!(set.by_lookup.is_empty());
        assert_eq!(set.legacy.len(), 3);

        let dir = tempfile::tempdir().unwrap();
        let path = write_keys(
            &dir,
            &[r#""edge_a": {"hash": "ab", "salt": "cd", "node_id": "   "}"#.to_string()],
        );
        let store = KeyStore::try_new(&path).unwrap();
        assert_eq!(store.node_binding("edge_a"), None);
    }

    /// A node registry whose `nodes` is not an object, or that cannot be
    /// read, keeps the previous node list rather than inventing nodes.
    #[test]
    fn a_malformed_or_unreadable_node_registry_keeps_the_last_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_keys(&dir, &[alpha("null")]);
        let store = KeyStore::try_new(&path).unwrap();
        let nodes = dir.path().join("nodes.json");
        std::fs::write(&nodes, r#"{"nodes": {"edge-7": {}}}"#).unwrap();
        assert!(store.is_registered_node("edge-7"));

        std::fs::write(&nodes, r#"{"nodes": ["edge-8"]}"#).unwrap();
        assert!(store.is_registered_node("edge-7"));
        assert!(!store.is_registered_node("edge-8"));

        std::fs::remove_file(&nodes).unwrap();
        std::fs::create_dir(&nodes).unwrap();
        assert!(
            store.is_registered_node("edge-7"),
            "unreadable keeps the last"
        );
        assert!(!store.is_registered_node("edge-8"));
    }

    /// Expiry is inclusive, as on the bridge (`now > expires_at` rejects).
    #[test]
    fn expiry_boundary_is_inclusive() {
        let at = NaiveDate::from_ymd_opt(2030, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc();
        let key = ApiKey {
            expires_at: Some(at),
            ..legacy_key("k")
        };
        assert!(key.is_usable(at));
        assert!(!key.is_usable(at + chrono::Duration::seconds(1)));
        assert!(key.is_usable(at - chrono::Duration::seconds(1)));
        assert!(!ApiKey {
            enabled: false,
            ..legacy_key("k")
        }
        .is_usable(at));
    }

    /// [`require_auth`], the gate for a handler that reads the API key off
    /// the request itself: no key or an unknown one is 401, a valid key
    /// scoped to another tenant 403, a valid local key below the route's
    /// role 403; only a valid local key with enough role passes, as itself,
    /// from whichever source [`extract_api_key`] reads.
    #[tokio::test]
    async fn require_auth_gates_on_the_key_its_tenant_and_its_role() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_keys(
            &dir,
            &[
                gated_entry_with("viewer-key", "sk-viewer", r#", "role": "viewer""#),
                gated_entry_with("admin-key", "sk-admin", r#", "role": "admin""#),
                gated_entry_with(
                    "foreign-admin",
                    "sk-foreign",
                    r#", "role": "admin", "tenant_id": "other""#,
                ),
            ],
        );
        // The stored "hash" is the raw key (see `gated_entry_with`): no PBKDF2.
        let store = KeyStore::with_verifier(
            &path,
            Box::new(|stored, presented| stored.hash == presented),
        );
        store.reload().unwrap();

        /// Request headers, URI, the route's role, the decision.
        type Case = (
            &'static [(&'static str, &'static str)],
            &'static str,
            Role,
            Result<(String, Role), StatusCode>,
        );
        let viewer = Ok(("viewer-key".to_string(), Role::Viewer));
        let admin = Ok(("admin-key".to_string(), Role::Admin));
        let cases: [Case; 9] = [
            (&[], "/x", Role::Viewer, Err(StatusCode::UNAUTHORIZED)),
            (
                &[("x-api-key", "sk-unknown")],
                "/x",
                Role::Viewer,
                Err(StatusCode::UNAUTHORIZED),
            ),
            (
                &[("x-api-key", "sk-foreign")],
                "/x",
                Role::Viewer,
                Err(StatusCode::FORBIDDEN),
            ),
            (
                &[("x-api-key", "sk-viewer")],
                "/x",
                Role::Analyst,
                Err(StatusCode::FORBIDDEN),
            ),
            (
                &[("x-api-key", "sk-viewer")],
                "/x",
                Role::Admin,
                Err(StatusCode::FORBIDDEN),
            ),
            (&[("x-api-key", "sk-viewer")], "/x", Role::Viewer, viewer),
            (
                &[("authorization", "Bearer sk-admin")],
                "/x",
                Role::Admin,
                admin.clone(),
            ),
            (&[], "/x?api_key=sk-admin", Role::Viewer, admin.clone()),
            (&[("x-api-key", "sk-admin")], "/x", Role::Analyst, admin),
        ];
        for (headers, uri, min_role, expected) in cases {
            let req = request_with(headers, uri);
            assert_eq!(
                require_auth(&store, &req, &min_role).await,
                expected,
                "{headers:?} {uri} at {min_role:?}"
            );
        }
    }

    /// A verification that fails outright (its blocking task panics) is a
    /// rejection, never an acceptance: the key is refused, every PBKDF2
    /// permit is given back, and the next attempt is refused the same way.
    #[tokio::test]
    async fn a_verification_that_fails_rejects_the_key_and_frees_its_permits() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_keys(
            &dir,
            &[
                gated_entry("indexed", "sk-indexed", true),
                gated_entry("legacy", "sk-legacy", false),
            ],
        );
        let store = KeyStore::with_verifier(
            &path,
            Box::new(|_, _| panic!("injected verification failure")),
        );
        store.reload().unwrap();
        for _ in 0..2 {
            for key in ["sk-indexed", "sk-legacy"] {
                assert_eq!(store.validate(key).await, None, "{key}");
                assert!(all_permits_free(&store), "{key}: permits returned");
            }
        }
        assert!(store.shared.caches.lock().unwrap().ok.is_empty());
    }

    /// An entry without a `key_id` (array format, absent or empty) or
    /// without a `hash` is never loaded, so it can authenticate nothing —
    /// not even as a principal with an empty key id.
    #[tokio::test]
    async fn entries_without_a_key_id_or_hash_are_never_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let lookup = |raw: &str| hex::encode(Sha256::digest(raw.as_bytes()));
        let path = write_raw(
            &dir,
            &format!(
                r#"{{"keys": [
                    {{"hash": "sk-anon", "salt": "00", "lookup_hash": "{}", "role": "admin"}},
                    {{"key_id": "", "hash": "sk-blank", "salt": "00", "lookup_hash": "{}",
                      "role": "admin"}},
                    {{"key_id": "nohash", "hash": "", "salt": "00", "lookup_hash": "{}",
                      "role": "admin"}},
                    {{"key_id": "kept", "hash": "sk-kept", "salt": "00", "lookup_hash": "{}",
                      "role": "viewer"}}
                ]}}"#,
                lookup("sk-anon"),
                lookup("sk-blank"),
                lookup(""),
                lookup("sk-kept"),
            ),
        );
        // Accepts a presented key equal to the stored "hash" — the empty
        // one too, were its entry loaded.
        let store = KeyStore::with_verifier(
            &path,
            Box::new(|stored, presented| stored.hash == presented),
        );
        store.reload().unwrap();
        assert_eq!(store.key_ids(), vec!["kept".to_string()]);
        for raw in ["sk-anon", "sk-blank", ""] {
            assert_eq!(store.validate(raw).await, None, "{raw:?}");
        }
        assert_eq!(
            store.validate("sk-kept").await,
            Some(("kept".to_string(), Role::Viewer))
        );
    }

    /// A cached success never outlives the key's `expires_at`: once the
    /// key has expired the cache answers nothing for it (its entry is
    /// dropped) and the key goes back through the checks, which refuse
    /// it. The cache lookup takes the time it decides at, so the expiry
    /// is crossed without waiting for it.
    #[tokio::test]
    async fn a_cached_success_is_not_served_once_its_key_has_expired() {
        let dir = tempfile::tempdir().unwrap();
        let expires = Utc::now() + chrono::Duration::days(1);
        let path = write_keys(
            &dir,
            &[gated_entry_with(
                "expiring",
                "sk-expiring",
                &format!(
                    r#", "role": "admin", "expires_at": "{}""#,
                    expires.to_rfc3339()
                ),
            )],
        );
        let store = KeyStore::with_verifier(
            &path,
            Box::new(|stored, presented| stored.hash == presented),
        );
        store.reload().unwrap();
        assert_eq!(
            store.validate("sk-expiring").await,
            Some(("expiring".to_string(), Role::Admin))
        );

        let (set, generation) = store.snapshot();
        let digest: [u8; 32] = Sha256::digest(b"sk-expiring").into();
        let lookup = |at| store.shared.lookup(&set, generation, &digest, at);
        assert!(
            matches!(lookup(Utc::now()), Cached::Hit(Some((ref id, Role::Admin, true))) if id == "expiring"),
            "cached while the key is usable"
        );
        let after_expiry = expires + chrono::Duration::seconds(1);
        assert!(
            matches!(lookup(after_expiry), Cached::Miss),
            "not served once expired"
        );
        assert!(
            store.shared.caches.lock().unwrap().ok.is_empty(),
            "the stale entry is dropped"
        );
        assert_eq!(
            select_candidates(&set, &hex::encode(digest), after_expiry),
            Candidates::Unusable(0),
            "and the key is then refused"
        );
    }
}

#[cfg(test)]
mod coverage_tests {
    //! API-key store paths the main suite leaves untaken: the success
    //! cache's time limit, the caches' size bounds, `KeyStore::new`, the
    //! `str(datetime)`-style expiry and the surrogate warning's reach.

    use super::*;

    /// An indexed keys.json entry whose stored "hash" is the raw key, for a
    /// store from [`plain_store`] (no PBKDF2).
    fn entry(key_id: &str, raw: &str, fields: &str) -> String {
        format!(
            r#""{key_id}": {{"hash": "{raw}", "salt": "00", "lookup_hash": "{}"{fields}}}"#,
            hex::encode(Sha256::digest(raw.as_bytes()))
        )
    }

    fn keys_file(dir: &tempfile::TempDir, entries: &[String]) -> PathBuf {
        let path = dir.path().join("keys.json");
        std::fs::write(&path, format!(r#"{{"keys": {{{}}}}}"#, entries.join(", "))).unwrap();
        path
    }

    /// A loaded store whose verifier compares the stored hash with the key.
    fn plain_store(path: &Path) -> KeyStore {
        let store =
            KeyStore::with_verifier(path, Box::new(|stored, presented| stored.hash == presented));
        store.reload().unwrap();
        store
    }

    fn utc(rfc3339: &str) -> Option<DateTime<Utc>> {
        Some(
            DateTime::parse_from_rfc3339(rfc3339)
                .unwrap()
                .with_timezone(&Utc),
        )
    }

    /// A success is served from the cache for `SUCCESS_CACHE_TTL` only: an
    /// older entry is dropped and the key goes through verification again
    /// (then is cached afresh), so no key rides on a check older than that.
    #[tokio::test]
    async fn a_cached_success_older_than_its_ttl_is_verified_again() {
        let dir = tempfile::tempdir().unwrap();
        let store = plain_store(&keys_file(
            &dir,
            &[entry("ops", "sk-ops", r#", "role": "analyst""#)],
        ));
        let ops = Some(("ops".to_string(), Role::Analyst));
        assert_eq!(store.validate("sk-ops").await, ops);
        assert_eq!(store.validate("sk-ops").await, ops);
        assert_eq!(
            store.pbkdf2_runs(),
            1,
            "the repeat is served from the cache"
        );

        let aged = Instant::now()
            .checked_sub(SUCCESS_CACHE_TTL + Duration::from_secs(1))
            .expect("the monotonic clock has run longer than the TTL");
        for (_, at) in store.shared.caches.lock().unwrap().ok.values_mut() {
            *at = aged;
        }
        assert_eq!(store.validate("sk-ops").await, ops);
        assert_eq!(store.pbkdf2_runs(), 2, "an expired entry is not served");
        assert_eq!(store.validate("sk-ops").await, ops);
        assert_eq!(store.pbkdf2_runs(), 2, "and the new result is cached");
    }

    /// Both caches are bounded: once one holds its maximum, the next entry
    /// replaces all of them, so keys sprayed at the gateway cannot grow
    /// its memory without limit.
    #[test]
    fn the_validation_caches_are_cleared_when_full() {
        let dir = tempfile::tempdir().unwrap();
        let store = plain_store(&keys_file(&dir, &[entry("ops", "sk-ops", "")]));
        let (_, generation) = store.snapshot();
        let digest = |n: usize| -> [u8; 32] { Sha256::digest(n.to_le_bytes()).into() };
        for n in 0..FAILED_CACHE_MAX {
            store.shared.record(generation, digest(n), None);
        }
        for n in FAILED_CACHE_MAX..FAILED_CACHE_MAX + SUCCESS_CACHE_MAX {
            store.shared.record(generation, digest(n), Some(0));
        }
        let full = {
            let caches = store.shared.caches.lock().unwrap();
            (caches.failed.len(), caches.ok.len())
        };
        assert_eq!(full, (FAILED_CACHE_MAX, SUCCESS_CACHE_MAX));

        let newest = FAILED_CACHE_MAX + SUCCESS_CACHE_MAX;
        store.shared.record(generation, digest(newest), None);
        store.shared.record(generation, digest(newest + 1), Some(0));
        let caches = store.shared.caches.lock().unwrap();
        assert_eq!(
            caches.failed.iter().collect::<Vec<_>>(),
            vec![&digest(newest)]
        );
        assert_eq!(
            caches.ok.keys().collect::<Vec<_>>(),
            vec![&digest(newest + 1)]
        );
    }

    /// `KeyStore::new` loads a readable keys file at once: its keys are
    /// known before any request, and an unknown key is refused without
    /// PBKDF2.
    #[tokio::test]
    async fn a_store_from_new_loads_the_keys_file_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = keys_file(&dir, &[entry("ops", "sk-ops", r#", "role": "admin""#)]);
        let store = KeyStore::new(&path);
        assert_eq!(store.key_ids(), vec!["ops".to_string()]);
        assert_eq!(store.generation(), 1);
        assert_eq!(store.validate("sk-unknown").await, None);
        assert_eq!(store.pbkdf2_runs(), 0);
    }

    /// An expiry written with a space and a colon-less offset (Python
    /// `strftime("%Y-%m-%d %H:%M:%S%z")`, which RFC 3339 does not read) is
    /// the instant it names: such a key is refused once it has passed —
    /// without PBKDF2 — and accepted before.
    #[tokio::test]
    async fn an_expiry_with_a_space_and_a_colon_less_offset_is_enforced() {
        assert_eq!(
            parse_expiry("2026-03-01 12:30:00+0200"),
            utc("2026-03-01T10:30:00Z")
        );
        assert_eq!(
            parse_expiry("2026-03-01 12:30:00.250000-0100"),
            utc("2026-03-01T13:30:00.25Z")
        );

        let format = "%Y-%m-%d %H:%M:%S%z";
        let past = (Utc::now() - chrono::Duration::days(1)).format(format);
        let future = (Utc::now() + chrono::Duration::days(1)).format(format);
        let dir = tempfile::tempdir().unwrap();
        let store = plain_store(&keys_file(
            &dir,
            &[
                entry("old", "sk-old", &format!(r#", "expires_at": "{past}""#)),
                entry("new", "sk-new", &format!(r#", "expires_at": "{future}""#)),
            ],
        ));
        assert_eq!(store.validate("sk-old").await, None);
        assert_eq!(store.pbkdf2_runs(), 0, "refused without PBKDF2");
        assert_eq!(
            store.validate("sk-new").await,
            Some(("new".to_string(), Role::Viewer))
        );
    }

    /// The warning about a lone surrogate escape names every entry that
    /// holds one — in its key id, in a list or in a nested object's key —
    /// and no other; each such entry still loads.
    #[test]
    fn a_lone_surrogate_anywhere_in_an_entry_is_reported_by_key_id() {
        let raw = r#"{"keys": {
            "node_\ud800": {"hash": "h1"},
            "tagged": {"hash": "h2", "tags": ["ok", "\udc00"]},
            "nested": {"hash": "h3", "meta": {"\ud800": 1}},
            "plain": {"hash": "h4", "description": "ok"}
        }}"#;
        let (parsed, logs) = crate::test_support::logs_of(|| parse_key_set(raw));
        let mut ids: Vec<String> = parsed.unwrap().keys.into_iter().map(|k| k.key_id).collect();
        ids.sort();
        assert_eq!(ids, ["nested", "node_\u{FFFD}", "plain", "tagged"]);
        let reported: Vec<&str> = logs
            .lines()
            .filter(|line| line.contains("unpaired UTF-16 surrogate"))
            .collect();
        assert_eq!(reported.len(), 3, "{logs}");
        for id in ["node_\u{FFFD}", "tagged", "nested"] {
            let field = format!("key_id={id}");
            assert!(
                reported.iter().any(|line| line.contains(&field)),
                "{id}: {logs}"
            );
        }
        assert!(!logs.contains("key_id=plain"), "{logs}");
    }

    /// A non-string `expires_at` fails closed (the key reads as expired),
    /// and the warning names the key and the JSON kind found there, so the
    /// operator can find the hand edit.
    #[test]
    fn a_non_string_expiry_is_reported_with_its_json_kind() {
        let raw = r#"{"keys": {
            "k-number": {"hash": "h", "expires_at": 1767225600},
            "k-bool": {"hash": "h", "expires_at": true},
            "k-array": {"hash": "h", "expires_at": ["2999-01-01"]},
            "k-object": {"hash": "h", "expires_at": {"at": "2999-01-01"}}
        }}"#;
        let (parsed, logs) = crate::test_support::logs_of(|| parse_key_set(raw));
        let keys = parsed.unwrap().keys;
        assert_eq!(keys.len(), 4);
        assert!(keys.iter().all(|key| !key.is_usable(Utc::now())));
        for (key_id, kind) in [
            ("k-number", "number"),
            ("k-bool", "bool"),
            ("k-array", "array"),
            ("k-object", "object"),
        ] {
            let (id_field, kind_field) = (format!("key_id={key_id}"), format!("kind=\"{kind}\""));
            assert!(
                logs.lines()
                    .any(|line| line.contains("Non-string expires_at")
                        && line.contains(&id_field)
                        && line.contains(&kind_field)),
                "{key_id}: {logs}"
            );
        }
    }
}
