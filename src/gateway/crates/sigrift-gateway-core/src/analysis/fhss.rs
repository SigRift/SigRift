//! FHSS (Frequency-Hopping Spread Spectrum) signal detector.

use crate::models::fhss::FHSSEvent;
use chrono::{DateTime, TimeZone, Utc};
use std::collections::HashMap;

const MIN_DISTINCT_FREQS: usize = 3;
const FREQ_BIN_HZ: f64 = 50_000.0;
const DEFAULT_WINDOW_SEC: f64 = 1.0;
const MIN_HOP_RATE: f64 = 2.0;
const MAX_GAP_SEC: f64 = 5.0;

pub struct FHSSDetector {
    window_sec: f64,
    min_distinct_freqs: usize,
    freq_bin_hz: f64,
    _min_hop_rate: f64,
    max_gap_sec: f64,
}

impl Default for FHSSDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl FHSSDetector {
    pub fn new() -> Self {
        Self {
            window_sec: DEFAULT_WINDOW_SEC,
            min_distinct_freqs: MIN_DISTINCT_FREQS,
            freq_bin_hz: FREQ_BIN_HZ,
            _min_hop_rate: MIN_HOP_RATE,
            max_gap_sec: MAX_GAP_SEC,
        }
    }

    /// Analyse a batch of detections for FHSS patterns.
    /// Each detection needs: node_id, timestamp (ISO string), freq_hz, signal_class, confidence.
    pub fn analyse(&self, detections: &[DetectionView]) -> Vec<FHSSEvent> {
        // Group by node_id
        let mut by_node: HashMap<&str, Vec<&DetectionView>> = HashMap::new();
        for det in detections {
            if !det.node_id.is_empty() {
                by_node.entry(&det.node_id).or_default().push(det);
            }
        }

        let mut events = Vec::new();
        for (node_id, node_dets) in &by_node {
            let node_events = self.analyse_node(node_id, node_dets);
            events.extend(node_events);
        }
        events
    }

    fn analyse_node(&self, node_id: &str, detections: &[&DetectionView]) -> Vec<FHSSEvent> {
        let mut parsed: Vec<(f64, &DetectionView)> = Vec::new();
        for det in detections {
            if let Some(ts) = parse_timestamp(&det.timestamp) {
                parsed.push((ts, det));
            }
        }

        if parsed.len() < self.min_distinct_freqs {
            return Vec::new();
        }

        parsed.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

        let segments = self.split_segments(&parsed);
        let mut events = Vec::new();
        for segment in segments {
            if let Some(evt) = self.analyse_segment(node_id, &segment) {
                events.push(evt);
            }
        }
        events
    }

    fn split_segments<'a>(
        &self,
        sorted_dets: &[(f64, &'a DetectionView)],
    ) -> Vec<Vec<(f64, &'a DetectionView)>> {
        if sorted_dets.is_empty() {
            return Vec::new();
        }

        let mut segments = Vec::new();
        let mut current = vec![sorted_dets[0]];

        for i in 1..sorted_dets.len() {
            let gap = sorted_dets[i].0 - sorted_dets[i - 1].0;
            if gap > self.max_gap_sec {
                segments.push(current);
                current = Vec::new();
            }
            current.push(sorted_dets[i]);
        }
        if !current.is_empty() {
            segments.push(current);
        }
        segments
    }

    fn analyse_segment(
        &self,
        node_id: &str,
        segment: &[(f64, &DetectionView)],
    ) -> Option<FHSSEvent> {
        if segment.len() < self.min_distinct_freqs {
            return None;
        }

        // Collect (timestamp, freq_bin) pairs
        let points: Vec<(f64, i64)> = segment
            .iter()
            .map(|(ts, det)| (*ts, self.bin_freq(det.freq_hz)))
            .collect();

        // Sliding window check
        let mut fhss_detected = false;
        for i in 0..points.len() {
            let window_start = points[i].0 - self.window_sec;
            let mut bins_in_window = std::collections::HashSet::new();
            for j in (0..=i).rev() {
                if points[j].0 < window_start {
                    break;
                }
                bins_in_window.insert(points[j].1);
            }
            if bins_in_window.len() >= self.min_distinct_freqs {
                fhss_detected = true;
                break;
            }
        }

        if !fhss_detected {
            return None;
        }

        Some(self.compute_event(node_id, segment))
    }

    fn compute_event(&self, node_id: &str, segment: &[(f64, &DetectionView)]) -> FHSSEvent {
        let timestamps: Vec<f64> = segment.iter().map(|(ts, _)| *ts).collect();
        let t_start = timestamps.iter().cloned().fold(f64::INFINITY, f64::min);
        let t_end = timestamps.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let duration = t_end - t_start;

        // Binned hop set
        let mut binned_freqs: HashMap<i64, f64> = HashMap::new();
        for (_, det) in segment {
            let b = self.bin_freq(det.freq_hz);
            binned_freqs.entry(b).or_insert(det.freq_hz);
        }
        let mut hop_set: Vec<f64> = binned_freqs.values().cloned().collect();
        hop_set.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let bandwidth = if hop_set.len() > 1 {
            hop_set.last().unwrap() - hop_set.first().unwrap()
        } else {
            0.0
        };

        // Count frequency transitions
        let mut transitions = 0u64;
        let mut prev_bin: Option<i64> = None;
        for (_, det) in segment {
            let cur_bin = self.bin_freq(det.freq_hz);
            if let Some(pb) = prev_bin {
                if cur_bin != pb {
                    transitions += 1;
                }
            }
            prev_bin = Some(cur_bin);
        }

        let hop_rate = if duration > 0.0 {
            transitions as f64 / duration
        } else {
            0.0
        };
        let dwell_time_ms = if transitions > 0 {
            duration * 1000.0 / transitions as f64
        } else {
            0.0
        };

        // Dominant signal class
        let mut class_counts: HashMap<&str, usize> = HashMap::new();
        let mut total_conf = 0.0;
        for (_, det) in segment {
            if !det.signal_class.is_empty() {
                *class_counts.entry(&det.signal_class).or_insert(0) += 1;
            }
            total_conf += det.confidence;
        }
        let dominant_class = class_counts
            .iter()
            .max_by_key(|(_, c)| *c)
            .map(|(k, _)| k.to_string())
            .unwrap_or_default();

        let avg_conf = if !segment.is_empty() {
            total_conf / segment.len() as f64
        } else {
            0.0
        };

        let ts_iso = Utc
            .timestamp_opt(t_start as i64, ((t_start.fract()) * 1e9) as u32)
            .single()
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();

        FHSSEvent {
            fhss_id: uuid::Uuid::new_v4().simple().to_string()[..16].to_string(),
            node_id: node_id.to_string(),
            timestamp: ts_iso,
            hop_rate_hz: hop_rate,
            hop_set,
            bandwidth_hz: bandwidth,
            dwell_time_ms,
            duration_sec: duration,
            signal_class: dominant_class,
            detection_count: segment.len(),
            confidence: avg_conf,
            tenant_id: "default".to_string(),
        }
    }

    fn bin_freq(&self, freq_hz: f64) -> i64 {
        (freq_hz / self.freq_bin_hz).round() as i64
    }
}

/// Lightweight view into detection fields needed for FHSS analysis.
pub struct DetectionView {
    pub node_id: String,
    pub timestamp: String,
    pub freq_hz: f64,
    pub signal_class: String,
    pub confidence: f64,
}

fn parse_timestamp(ts: &str) -> Option<f64> {
    if ts.is_empty() {
        return None;
    }
    // Try ISO 8601 parse
    if let Ok(dt) = DateTime::parse_from_rfc3339(ts) {
        return Some(dt.timestamp() as f64 + dt.timestamp_subsec_nanos() as f64 / 1e9);
    }
    // Try common ISO format without timezone
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(dt.and_utc().timestamp() as f64);
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S") {
        return Some(dt.and_utc().timestamp() as f64);
    }
    // Try epoch seconds
    if let Ok(epoch) = ts.parse::<f64>() {
        return Some(epoch);
    }
    None
}
