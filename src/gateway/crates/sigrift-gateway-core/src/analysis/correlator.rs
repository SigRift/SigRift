//! Multi-node cross-correlation for anomaly score adjustment.

use chrono::DateTime;
use serde::Serialize;
use std::collections::HashSet;

const DEFAULT_TIME_WINDOW_SEC: f64 = 5.0;
const DEFAULT_FREQ_TOLERANCE_HZ: f64 = 100_000.0;

fn freq_bin(freq_hz: f64, tolerance: f64) -> i64 {
    if tolerance <= 0.0 {
        return freq_hz as i64;
    }
    (freq_hz / tolerance) as i64
}

#[derive(Debug, Clone, Serialize)]
pub struct CorrelationResult {
    pub correlated: bool,
    pub node_count: usize,
    pub total_active_nodes: usize,
    pub node_ids: Vec<String>,
    pub confidence_boost: f64,
    pub correlation_score: f64,
    pub adjusted_anomaly_score: f64,
}

pub struct NodeCorrelator {
    time_window_sec: f64,
    freq_tolerance_hz: f64,
    single_node_factor: f64,
    total_active_nodes: usize,
}

impl NodeCorrelator {
    pub fn new(total_active_nodes: usize) -> Self {
        Self {
            time_window_sec: DEFAULT_TIME_WINDOW_SEC,
            freq_tolerance_hz: DEFAULT_FREQ_TOLERANCE_HZ,
            single_node_factor: 0.8,
            total_active_nodes: total_active_nodes.max(1),
        }
    }

    pub fn set_active_node_count(&mut self, count: usize) {
        self.total_active_nodes = count.max(1);
    }

    /// Check if a detection correlates with recent detections from other nodes.
    // One parameter per detection field; a struct would only wrap them.
    #[allow(clippy::too_many_arguments)]
    pub fn check_correlation(
        &self,
        det_node: &str,
        det_class: &str,
        det_family: &str,
        det_freq: f64,
        det_timestamp: &str,
        det_anomaly: f64,
        recent_detections: &[RecentDetection],
    ) -> CorrelationResult {
        let det_bin = freq_bin(det_freq, self.freq_tolerance_hz);
        let det_ts = parse_timestamp(det_timestamp);

        let mut correlated_nodes: HashSet<String> = HashSet::new();

        for other in recent_detections {
            if other.node_id == det_node {
                continue;
            }

            // Check class/family match
            let class_match = det_class == other.signal_class
                || (!det_family.is_empty() && det_family == other.family);
            if !class_match {
                continue;
            }

            // Check frequency match
            let other_bin = freq_bin(other.freq_hz, self.freq_tolerance_hz);
            if det_bin != other_bin {
                continue;
            }

            // Check time window
            if let (Some(dt), Some(ot)) = (det_ts, parse_timestamp(&other.timestamp)) {
                let delta = (dt - ot).abs();
                if delta > self.time_window_sec {
                    continue;
                }
            }

            correlated_nodes.insert(other.node_id.clone());
        }

        let total_active = self.total_active_nodes;

        if correlated_nodes.is_empty() {
            let adjusted = self.adjust_anomaly_score(det_anomaly, false, 0.0);
            let corr_score = if total_active > 1 {
                1.0 / total_active as f64
            } else {
                0.0
            };
            return CorrelationResult {
                correlated: false,
                node_count: 1,
                total_active_nodes: total_active,
                node_ids: if det_node.is_empty() {
                    vec![]
                } else {
                    vec![det_node.to_string()]
                },
                confidence_boost: 0.0,
                correlation_score: (corr_score * 10000.0).round() / 10000.0,
                adjusted_anomaly_score: (adjusted * 10000.0).round() / 10000.0,
            };
        }

        let mut all_nodes: Vec<String> = correlated_nodes.into_iter().collect();
        if !det_node.is_empty() {
            all_nodes.push(det_node.to_string());
        }
        all_nodes.sort();
        all_nodes.dedup();
        let node_count = all_nodes.len();

        let boost = compute_boost(node_count);
        let corr_score = (node_count as f64 / total_active as f64).min(1.0);
        let adjusted = self.adjust_anomaly_score(det_anomaly, true, boost);

        CorrelationResult {
            correlated: true,
            node_count,
            total_active_nodes: total_active,
            node_ids: all_nodes,
            confidence_boost: (boost * 10000.0).round() / 10000.0,
            correlation_score: (corr_score * 10000.0).round() / 10000.0,
            adjusted_anomaly_score: (adjusted * 10000.0).round() / 10000.0,
        }
    }

    fn adjust_anomaly_score(
        &self,
        anomaly_score: f64,
        correlated: bool,
        confidence_boost: f64,
    ) -> f64 {
        let adjusted = if correlated {
            anomaly_score * (1.0 + confidence_boost)
        } else if self.total_active_nodes > 1 {
            anomaly_score * self.single_node_factor
        } else {
            anomaly_score
        };
        adjusted.clamp(0.0, 1.0)
    }
}

fn compute_boost(node_count: usize) -> f64 {
    match node_count {
        0 | 1 => 0.0,
        2 => 0.1,
        3 => 0.15,
        _ => 0.2,
    }
}

/// Lightweight struct for recent detections used in correlation checks.
pub struct RecentDetection {
    pub node_id: String,
    pub signal_class: String,
    pub family: String,
    pub freq_hz: f64,
    pub timestamp: String,
}

fn parse_timestamp(ts: &str) -> Option<f64> {
    if ts.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(ts) {
        return Some(dt.timestamp() as f64 + dt.timestamp_subsec_nanos() as f64 / 1e9);
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(dt.and_utc().timestamp() as f64);
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S") {
        return Some(dt.and_utc().timestamp() as f64);
    }
    if let Ok(epoch) = ts.parse::<f64>() {
        return Some(epoch);
    }
    None
}
