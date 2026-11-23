//! Frequency baseline tracking with EWMA for anomaly detection.
//!
//! Ingest takes every value here from sensors, so memory is bounded no
//! matter what they send:
//!
//! * a class is tracked under [`baseline_class`]: its canonical name, or
//!   one shared `unknown` key for any name outside the canonical taxonomy.
//!   A sensor therefore cannot make the gateway track (and save) arbitrary
//!   class names; the detection itself keeps the class it was sent with;
//! * at most [`MAX_BINS`] frequency bins, at most [`MAX_CLASSES_PER_BIN`]
//!   classes per bin, and at most [`MAX_TRACKED_CLASSES`] (bin, class)
//!   entries in all are tracked. When a new bin, class or entry would
//!   exceed a cap, the least recently updated bin (or, within a bin, the
//!   least recently seen class) is evicted.
//!
//! A file saved by an older gateway is folded into this shape on load.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::io::Write as _;
use std::path::Path;
use tracing::{info, warn};

use crate::class_map::baseline_class;

const MIN_LEARNING_DETECTIONS: u64 = 100;
const FREQ_BIN_HZ: f64 = 100_000.0;

/// Most frequency bins tracked at once.
pub const MAX_BINS: usize = 8192;
/// Most signal classes tracked per frequency bin.
pub const MAX_CLASSES_PER_BIN: usize = 64;
/// Most (bin, class) entries tracked across all bins.
pub const MAX_TRACKED_CLASSES: usize = 32_768;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrequencyBaseline {
    pub alpha: f64,
    pub class_counts: HashMap<String, u64>,
    pub class_ewma: HashMap<String, f64>,
    pub hourly_counts: HashMap<u8, HashMap<String, u64>>,
    pub power_ewma: f64,
    pub power_var: f64,
    pub snr_ewma: f64,
    pub snr_var: f64,
    pub total_detections: u64,
    /// Manager clock value of the last update (LRU order of bins).
    #[serde(default)]
    pub last_update: u64,
    /// Manager clock value at which each class was last seen (LRU order
    /// of classes).
    #[serde(default)]
    pub class_last_seen: HashMap<String, u64>,
}

impl FrequencyBaseline {
    pub fn new(alpha: f64) -> Self {
        Self {
            alpha,
            class_counts: HashMap::new(),
            class_ewma: HashMap::new(),
            hourly_counts: HashMap::new(),
            power_ewma: 0.0,
            power_var: 0.0,
            snr_ewma: 0.0,
            snr_var: 0.0,
            total_detections: 0,
            last_update: 0,
            class_last_seen: HashMap::new(),
        }
    }

    pub fn update(
        &mut self,
        class_name: &str,
        confidence: f64,
        power_dbm: Option<f64>,
        hour: u8,
        snr_db: Option<f64>,
    ) {
        let tick = self.last_update + 1;
        self.update_bounded(
            class_name,
            confidence,
            power_dbm,
            hour,
            snr_db,
            MAX_CLASSES_PER_BIN,
            tick,
        );
    }

    /// [`update`](Self::update), keeping at most `max_classes` classes
    /// (evicting the least recently seen one for a new class) and stamping
    /// the class and the bin with `tick`.
    #[allow(clippy::too_many_arguments)]
    fn update_bounded(
        &mut self,
        class_name: &str,
        _confidence: f64,
        power_dbm: Option<f64>,
        hour: u8,
        snr_db: Option<f64>,
        max_classes: usize,
        tick: u64,
    ) {
        let class_name = baseline_class(class_name);
        if !self.class_counts.contains_key(class_name) {
            while self.class_counts.len() >= max_classes.max(1) {
                if !self.evict_least_recent_class() {
                    break;
                }
            }
        }
        self.last_update = tick;
        self.class_last_seen.insert(class_name.to_string(), tick);
        self.total_detections += 1;

        // Class counts
        *self.class_counts.entry(class_name.to_string()).or_insert(0) += 1;

        // Class EWMA — update all tracked classes
        let alpha = self.alpha;
        for (cls, ewma) in self.class_ewma.iter_mut() {
            let indicator = if cls == class_name { 1.0 } else { 0.0 };
            *ewma = alpha * indicator + (1.0 - alpha) * *ewma;
        }
        if !self.class_ewma.contains_key(class_name) {
            self.class_ewma.insert(class_name.to_string(), alpha);
        }

        // Hourly counts
        let hour = hour % 24;
        let hour_map = self.hourly_counts.entry(hour).or_default();
        *hour_map.entry(class_name.to_string()).or_insert(0) += 1;

        // Power EWMA (Welford-style variance)
        if let Some(p) = power_dbm {
            if self.total_detections == 1 {
                self.power_ewma = p;
                self.power_var = 0.0;
            } else {
                let delta = p - self.power_ewma;
                self.power_ewma = alpha * p + (1.0 - alpha) * self.power_ewma;
                self.power_var = (1.0 - alpha) * (self.power_var + alpha * delta * delta);
            }
        }

        // SNR EWMA
        if let Some(s) = snr_db {
            if self.total_detections == 1 {
                self.snr_ewma = s;
                self.snr_var = 0.0;
            } else {
                let delta = s - self.snr_ewma;
                self.snr_ewma = alpha * s + (1.0 - alpha) * self.snr_ewma;
                self.snr_var = (1.0 - alpha) * (self.snr_var + alpha * delta * delta);
            }
        }
    }

    pub fn is_learning(&self) -> bool {
        self.total_detections < MIN_LEARNING_DETECTIONS
    }

    pub fn class_probability(&self, class_name: &str) -> f64 {
        if self.total_detections == 0 {
            return 0.0;
        }
        let count = self
            .class_counts
            .get(baseline_class(class_name))
            .copied()
            .unwrap_or(0);
        count as f64 / self.total_detections as f64
    }

    pub fn hourly_probability(&self, class_name: &str, hour: u8) -> f64 {
        let hour = hour % 24;
        let hour_data = match self.hourly_counts.get(&hour) {
            Some(h) => h,
            None => return 0.0,
        };
        let total: u64 = hour_data.values().sum();
        if total == 0 {
            return 0.0;
        }
        let count = hour_data
            .get(baseline_class(class_name))
            .copied()
            .unwrap_or(0);
        count as f64 / total as f64
    }

    pub fn power_zscore(&self, power_dbm: f64) -> f64 {
        if self.total_detections < 2 || self.power_var <= 0.0 {
            return 0.0;
        }
        let std = self.power_var.sqrt();
        if std < 1e-9 {
            return 0.0;
        }
        (power_dbm - self.power_ewma) / std
    }

    pub fn snr_zscore(&self, snr_db: f64) -> f64 {
        if self.total_detections < 2 || self.snr_var <= 0.0 {
            return 0.0;
        }
        let std = self.snr_var.sqrt();
        if std < 1e-9 {
            return 0.0;
        }
        (snr_db - self.snr_ewma) / std
    }

    pub fn is_novel_class(&self, class_name: &str) -> bool {
        !self.class_counts.contains_key(baseline_class(class_name))
    }

    /// Re-key classes a file from an older gateway tracked under their own
    /// (non-canonical) names to [`baseline_class`], merging their counts.
    fn fold_into_baseline_classes(&mut self) {
        fold_keys(&mut self.class_counts, |a, b| a.saturating_add(b));
        fold_keys(&mut self.class_ewma, |a, b| (a + b).min(1.0));
        fold_keys(&mut self.class_last_seen, u64::max);
        for hour_map in self.hourly_counts.values_mut() {
            fold_keys(hour_map, |a, b| a.saturating_add(b));
        }
    }

    /// Forget the least recently seen class (classes from files written
    /// before `class_last_seen` existed count as oldest, then the rarest).
    fn evict_least_recent_class(&mut self) -> bool {
        let Some(victim) = self
            .class_counts
            .iter()
            .min_by(|(a, ca), (b, cb)| {
                let seen_a = self.class_last_seen.get(*a).copied().unwrap_or(0);
                let seen_b = self.class_last_seen.get(*b).copied().unwrap_or(0);
                (seen_a, **ca, *a).cmp(&(seen_b, **cb, *b))
            })
            .map(|(name, _)| name.clone())
        else {
            return false;
        };
        self.class_counts.remove(&victim);
        self.class_ewma.remove(&victim);
        self.class_last_seen.remove(&victim);
        for hour_map in self.hourly_counts.values_mut() {
            hour_map.remove(&victim);
        }
        self.hourly_counts
            .retain(|_, hour_map| !hour_map.is_empty());
        true
    }
}

/// Re-key `map` by [`baseline_class`], combining values that land on the
/// same key.
fn fold_keys<V: Copy>(map: &mut HashMap<String, V>, combine: impl Fn(V, V) -> V) {
    if map.keys().all(|k| baseline_class(k) == k.as_str()) {
        return;
    }
    for (name, value) in std::mem::take(map) {
        let key = baseline_class(&name);
        match map.get_mut(key) {
            Some(existing) => *existing = combine(*existing, value),
            None => {
                map.insert(key.to_string(), value);
            }
        }
    }
}

fn default_max_bins() -> usize {
    MAX_BINS
}

fn default_max_classes() -> usize {
    MAX_CLASSES_PER_BIN
}

fn default_max_tracked() -> usize {
    MAX_TRACKED_CLASSES
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineManager {
    pub alpha: f64,
    pub baselines: HashMap<i64, FrequencyBaseline>,
    /// Logical clock, advanced on every update (LRU order).
    #[serde(default)]
    clock: u64,
    /// (last_update, bin) of every bin, oldest first.
    #[serde(skip)]
    lru: BTreeSet<(u64, i64)>,
    #[serde(skip, default = "default_max_bins")]
    max_bins: usize,
    #[serde(skip, default = "default_max_classes")]
    max_classes: usize,
    #[serde(skip, default = "default_max_tracked")]
    max_tracked: usize,
    /// (bin, class) entries tracked across all bins.
    #[serde(skip)]
    tracked: usize,
}

impl BaselineManager {
    pub fn new(alpha: f64) -> Self {
        Self::with_limits(alpha, MAX_BINS, MAX_CLASSES_PER_BIN)
    }

    /// A manager tracking at most `max_bins` bins of at most
    /// `max_classes` classes each (and [`MAX_TRACKED_CLASSES`] in all).
    pub fn with_limits(alpha: f64, max_bins: usize, max_classes: usize) -> Self {
        Self::with_all_limits(alpha, max_bins, max_classes, MAX_TRACKED_CLASSES)
    }

    /// [`with_limits`](Self::with_limits), tracking at most `max_tracked`
    /// (bin, class) entries across all bins.
    pub fn with_all_limits(
        alpha: f64,
        max_bins: usize,
        max_classes: usize,
        max_tracked: usize,
    ) -> Self {
        Self {
            alpha,
            baselines: HashMap::new(),
            clock: 0,
            lru: BTreeSet::new(),
            max_bins: max_bins.max(1),
            max_classes: max_classes.max(1),
            max_tracked: max_tracked.max(1),
            tracked: 0,
        }
    }

    /// (bin, class) entries currently tracked across all bins.
    pub fn tracked_classes(&self) -> usize {
        self.tracked
    }

    /// Rebuild the LRU index from the bins' stamps, re-key classes by
    /// [`baseline_class`] and enforce the caps (a file saved by an older
    /// gateway may hold more, or arbitrary class names).
    fn reindex(&mut self) {
        let max_classes = self.max_classes;
        for baseline in self.baselines.values_mut() {
            baseline.fold_into_baseline_classes();
            while baseline.class_counts.len() > max_classes {
                if !baseline.evict_least_recent_class() {
                    break;
                }
            }
        }
        self.lru = self
            .baselines
            .iter()
            .map(|(bin, b)| (b.last_update, *bin))
            .collect();
        self.clock = self.clock.max(self.lru.last().map_or(0, |(t, _)| *t));
        self.tracked = self.baselines.values().map(|b| b.class_counts.len()).sum();
        while self.baselines.len() > self.max_bins
            || (self.tracked > self.max_tracked && self.baselines.len() > 1)
        {
            if !self.evict_least_recent_bin() {
                break;
            }
        }
    }

    fn evict_least_recent_bin(&mut self) -> bool {
        let Some((_, bin)) = self.lru.pop_first() else {
            return false;
        };
        if let Some(evicted) = self.baselines.remove(&bin) {
            self.tracked = self.tracked.saturating_sub(evicted.class_counts.len());
        }
        true
    }

    pub fn freq_bin(freq_hz: f64) -> i64 {
        (freq_hz / FREQ_BIN_HZ).round() as i64
    }

    pub fn update(
        &mut self,
        freq_hz: f64,
        class_name: &str,
        confidence: f64,
        power_dbm: Option<f64>,
        hour: Option<u8>,
        snr_db: Option<f64>,
    ) -> &FrequencyBaseline {
        let bin = Self::freq_bin(freq_hz);
        let alpha = self.alpha;
        if self.lru.len() != self.baselines.len() {
            // `baselines` is public and was changed directly: resync.
            self.reindex();
        }
        match self.baselines.get(&bin) {
            Some(existing) => {
                self.lru.remove(&(existing.last_update, bin));
            }
            None => {
                while self.baselines.len() >= self.max_bins {
                    if !self.evict_least_recent_bin() {
                        break;
                    }
                }
            }
        }
        self.clock += 1;
        let tick = self.clock;
        self.lru.insert((tick, bin));
        let max_classes = self.max_classes;
        let hour = hour.unwrap_or_else(|| {
            chrono::Utc::now()
                .format("%H")
                .to_string()
                .parse()
                .unwrap_or(0)
        });
        let baseline = self
            .baselines
            .entry(bin)
            .or_insert_with(|| FrequencyBaseline::new(alpha));
        let before = baseline.class_counts.len();
        baseline.update_bounded(
            class_name,
            confidence,
            power_dbm,
            hour,
            snr_db,
            max_classes,
            tick,
        );
        let after = baseline.class_counts.len();
        self.tracked = (self.tracked + after).saturating_sub(before);
        // Over the overall cap: evict the least recently updated other bins
        // (this bin was just stamped, so it is the most recent one).
        while self.tracked > self.max_tracked && self.baselines.len() > 1 {
            if !self.evict_least_recent_bin() {
                break;
            }
        }
        &self.baselines[&bin]
    }

    pub fn get_baseline(&self, freq_hz: f64) -> Option<&FrequencyBaseline> {
        let bin = Self::freq_bin(freq_hz);
        self.baselines.get(&bin)
    }

    pub fn save(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        // Streamed, compact JSON: no second in-memory copy of the
        // baselines while ingest waits for the lock.
        let mut out = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
        serde_json::to_writer(&mut out, self)?;
        out.flush()?;
        out.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        std::fs::rename(&tmp, path)?;
        info!(count = self.baselines.len(), path = %path.display(), "Baselines saved");
        Ok(())
    }

    pub fn load(&mut self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        if !path.exists() {
            warn!(path = %path.display(), "Baseline file not found");
            return Ok(());
        }
        let file = std::io::BufReader::new(std::fs::File::open(path)?);
        let loaded: BaselineManager = serde_json::from_reader(file)?;
        self.alpha = loaded.alpha;
        self.baselines = loaded.baselines;
        self.clock = loaded.clock;
        self.reindex();
        info!(count = self.baselines.len(), path = %path.display(), "Baselines loaded");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bins(m: &BaselineManager) -> Vec<i64> {
        let mut bins: Vec<i64> = m.baselines.keys().copied().collect();
        bins.sort_unstable();
        bins
    }

    #[test]
    fn bins_are_capped_and_the_least_recently_updated_is_evicted() {
        let mut m = BaselineManager::with_limits(0.01, 3, 8);
        for f in [1e6, 2e6, 3e6] {
            m.update(f, "qpsk", 0.9, None, Some(1), None);
        }
        m.update(1e6, "qpsk", 0.9, None, Some(1), None); // refresh bin 10
        m.update(4e6, "qpsk", 0.9, None, Some(1), None); // evicts bin 20
        assert_eq!(bins(&m), vec![10, 30, 40]);
    }

    #[test]
    fn classes_per_bin_are_capped_and_the_least_recently_seen_is_evicted() {
        let mut m = BaselineManager::with_limits(0.01, 8, 3);
        for class in ["bpsk", "qpsk", "8psk"] {
            m.update(1e6, class, 0.9, None, Some(5), None);
        }
        m.update(1e6, "bpsk", 0.9, None, Some(5), None); // refresh "bpsk"
        m.update(1e6, "16qam", 0.9, None, Some(6), None); // evicts "qpsk"
        let b = m.get_baseline(1e6).unwrap();
        let mut classes: Vec<&String> = b.class_counts.keys().collect();
        classes.sort();
        assert_eq!(classes, ["16qam", "8psk", "bpsk"]);
        assert!(!b.class_ewma.contains_key("qpsk"));
        assert!(!b.class_last_seen.contains_key("qpsk"));
        assert!(b.hourly_counts.values().all(|h| !h.contains_key("qpsk")));
        assert!(b.is_novel_class("qpsk"));
    }

    #[test]
    fn unique_frequencies_and_classes_cannot_grow_memory_without_bound() {
        let mut m = BaselineManager::with_limits(0.01, 16, 4);
        for i in 0..2_000u32 {
            let freq = f64::from(i) * 1e5 * 7.0;
            m.update(freq, &format!("class-{i}"), 0.5, None, Some(0), None);
            m.update(1e6, &format!("flood-{i}"), 0.5, None, Some(0), None);
        }
        assert!(m.baselines.len() <= 16);
        assert!(m
            .baselines
            .values()
            .all(|b| b.class_counts.len() <= 4 && b.class_ewma.len() <= 4));
        // The bin that keeps being updated survives.
        assert!(m.get_baseline(1e6).is_some());
    }

    #[test]
    fn loading_an_older_unbounded_file_applies_the_caps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baselines.json");
        // Format written before the caps existed (no clock / LRU fields).
        let mut baselines = serde_json::Map::new();
        for bin in 0..10 {
            baselines.insert(
                bin.to_string(),
                serde_json::json!({
                    "alpha": 0.01, "class_counts": {"bpsk": 1, "qpsk": 2, "8psk": 3},
                    "class_ewma": {"bpsk": 0.1, "qpsk": 0.2, "8psk": 0.3},
                    "hourly_counts": {"1": {"bpsk": 1, "qpsk": 2, "8psk": 3}},
                    "power_ewma": 0.0, "power_var": 0.0, "snr_ewma": 0.0,
                    "snr_var": 0.0, "total_detections": 6
                }),
            );
        }
        std::fs::write(
            &path,
            serde_json::json!({"alpha": 0.01, "baselines": baselines}).to_string(),
        )
        .unwrap();

        let mut m = BaselineManager::with_limits(0.01, 4, 2);
        m.load(&path).unwrap();
        assert_eq!(m.baselines.len(), 4);
        for b in m.baselines.values() {
            // The rarest classes go first when nothing says which is older.
            let mut classes: Vec<&String> = b.class_counts.keys().collect();
            classes.sort();
            assert_eq!(classes, ["8psk", "qpsk"]);
        }
        m.update(99e6, "fm", 0.9, None, Some(1), None);
        assert_eq!(m.baselines.len(), 4);

        // Round trip keeps the LRU order.
        m.save(&path).unwrap();
        let mut again = BaselineManager::with_limits(0.01, 4, 2);
        again.load(&path).unwrap();
        assert_eq!(bins(&again), bins(&m));
        again.update(98e6, "am", 0.9, None, Some(1), None);
        assert!(again.get_baseline(99e6).is_some(), "newest bin kept");
    }

    /// Every String key the baselines hold (class names in all maps).
    fn key_count(m: &BaselineManager) -> usize {
        m.baselines
            .values()
            .map(|b| {
                b.class_counts.len()
                    + b.class_ewma.len()
                    + b.class_last_seen.len()
                    + b.hourly_counts.values().map(HashMap::len).sum::<usize>()
            })
            .sum()
    }

    /// Regression (Q3): unknown class names were tracked as they came, so
    /// one sensor key could make the gateway hold up to 8192 bins x 64
    /// arbitrary 128-character names, copied into every per-class map and
    /// up to 24 hourly maps (GB of keys, and of baselines.json).
    #[test]
    fn a_flood_of_unique_class_names_is_tracked_under_one_key() {
        let mut m = BaselineManager::new(0.01);
        for i in 0..20_000u32 {
            let class = format!("{i:0>128}");
            let freq = f64::from(i % 4000) * 1e5;
            m.update(freq, &class, 0.5, Some(-60.0), Some((i % 24) as u8), None);
        }
        assert_eq!(m.baselines.len(), 4000);
        for b in m.baselines.values() {
            assert_eq!(b.class_counts.keys().collect::<Vec<_>>(), ["unknown"]);
            assert!(b.class_last_seen.keys().all(|k| k == "unknown"));
            assert!(b.hourly_counts.values().all(|h| h.len() <= 1));
        }
        // One key per map: at most 3 + 24 per bin, none of them long.
        assert!(key_count(&m) <= 4000 * 27, "{}", key_count(&m));
        assert_eq!(m.tracked_classes(), 4000);
    }

    #[test]
    fn tracked_entries_are_capped_across_all_bins() {
        let classes = crate::class_map::CANONICAL_CLASSES;
        let mut m = BaselineManager::with_all_limits(0.01, 8192, 64, 500);
        for bin in 0..200u32 {
            for class in classes {
                m.update(f64::from(bin) * 1e5, class, 0.5, None, Some(3), None);
            }
            assert!(m.tracked_classes() <= 500);
        }
        let total: usize = m.baselines.values().map(|b| b.class_counts.len()).sum();
        assert_eq!(total, m.tracked_classes());
        assert!(total <= 500 && total > 500 - classes.len(), "{total}");
        // The most recently updated bin survives whole.
        assert_eq!(
            m.get_baseline(199e5).unwrap().class_counts.len(),
            classes.len()
        );
        assert!(m.get_baseline(0.0).is_none(), "oldest bins evicted");
    }

    #[test]
    fn unknown_classes_share_one_baseline_for_scoring_too() {
        let mut m = BaselineManager::new(0.01);
        m.update(1e6, "vendor-thing-a", 0.9, None, Some(2), None);
        m.update(1e6, "qpsk", 0.9, None, Some(2), None);
        let b = m.get_baseline(1e6).unwrap();
        assert!(!b.is_novel_class("vendor-thing-b"));
        assert!(b.is_novel_class("bpsk"));
        assert_eq!(b.class_probability("vendor-thing-b"), 0.5);
        assert_eq!(b.hourly_probability("other-name", 2), 0.5);
    }

    #[test]
    fn loading_a_file_with_arbitrary_class_names_folds_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baselines.json");
        let baseline = serde_json::json!({
            "alpha": 0.01,
            "class_counts": {"qpsk": 4, "junk-1": 2, "junk-2": 3},
            "class_ewma": {"qpsk": 0.4, "junk-1": 0.2, "junk-2": 0.3},
            "class_last_seen": {"qpsk": 1, "junk-1": 7, "junk-2": 5},
            "hourly_counts": {"4": {"qpsk": 4, "junk-1": 2, "junk-2": 3}},
            "power_ewma": 0.0, "power_var": 0.0, "snr_ewma": 0.0,
            "snr_var": 0.0, "total_detections": 9, "last_update": 7
        });
        std::fs::write(
            &path,
            serde_json::json!({"alpha": 0.01, "clock": 7, "baselines": {"10": baseline}})
                .to_string(),
        )
        .unwrap();
        let mut m = BaselineManager::new(0.01);
        m.load(&path).unwrap();
        let b = m.get_baseline(1e6).unwrap();
        let mut classes: Vec<&String> = b.class_counts.keys().collect();
        classes.sort();
        assert_eq!(classes, ["qpsk", "unknown"]);
        assert_eq!(b.class_counts["unknown"], 5);
        assert!((b.class_ewma["unknown"] - 0.5).abs() < 1e-9);
        assert_eq!(b.class_last_seen["unknown"], 7);
        assert_eq!(b.hourly_counts[&4]["unknown"], 5);
        assert_eq!(m.tracked_classes(), 2);
    }

    #[test]
    fn baselines_are_saved_as_compact_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baselines.json");
        let mut m = BaselineManager::new(0.01);
        m.update(1e6, "qpsk", 0.9, Some(-50.0), Some(1), Some(10.0));
        m.save(&path).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains('\n'), "{raw}");
        assert!(!dir.path().join("baselines.tmp").exists());
        let mut again = BaselineManager::new(0.01);
        again.load(&path).unwrap();
        assert_eq!(again.get_baseline(1e6).unwrap().total_detections, 1);
    }
}
