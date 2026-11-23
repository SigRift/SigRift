//! Simple TTL cache for query results.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct CacheEntry<V> {
    value: V,
    expires_at: Instant,
}

pub struct TtlCache<V> {
    entries: Mutex<HashMap<String, CacheEntry<V>>>,
    ttl: Duration,
}

impl<V: Clone> TtlCache<V> {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    pub fn get(&self, key: &str) -> Option<V> {
        let entries = self.entries.lock().unwrap();
        if let Some(entry) = entries.get(key) {
            if entry.expires_at > Instant::now() {
                return Some(entry.value.clone());
            }
        }
        None
    }

    pub fn set(&self, key: String, value: V) {
        let mut entries = self.entries.lock().unwrap();
        entries.insert(
            key,
            CacheEntry {
                value,
                expires_at: Instant::now() + self.ttl,
            },
        );
    }

    pub fn invalidate_prefix(&self, prefix: &str) {
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|k, _| !k.starts_with(prefix));
    }

    pub fn evict_expired(&self) {
        let mut entries = self.entries.lock().unwrap();
        let now = Instant::now();
        entries.retain(|_, v| v.expires_at > now);
    }
}
