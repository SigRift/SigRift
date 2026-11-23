//! Anomaly scoring result models.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyResult {
    pub score: f64,
    pub priority: String,
    pub dimensions: HashMap<String, f64>,
    pub reasons: Vec<String>,
    pub baseline_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RFAnomaly {
    pub detection_id: String,
    pub signal_class: String,
    pub family: String,
    pub freq_hz: f64,
    pub dedup_key: String,
    pub node_id: String,
    pub timestamp: String,
    pub confidence: f64,
    pub snr_db: Option<f64>,
    pub power_dbm: Option<f64>,
    pub anomaly_score: f64,
    pub priority: String,
    pub dimensions: String,
    pub reasons: String,
    pub baseline_status: String,
    pub has_iq_capture: bool,
    #[serde(default)]
    pub tenant_id: String,
}

impl RFAnomaly {
    pub fn make_dedup_key(signal_class: &str, freq_hz: f64) -> String {
        let bucket = (freq_hz / 100_000.0) as i64;
        format!("{}|{}", signal_class, bucket)
    }
}
