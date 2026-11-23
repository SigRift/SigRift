//! FHSS event model.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FHSSEvent {
    pub fhss_id: String,
    pub node_id: String,
    pub timestamp: String,
    pub hop_rate_hz: f64,
    pub hop_set: Vec<f64>,
    pub bandwidth_hz: f64,
    pub dwell_time_ms: f64,
    pub duration_sec: f64,
    pub signal_class: String,
    pub detection_count: usize,
    pub confidence: f64,
    #[serde(default = "default_tenant")]
    pub tenant_id: String,
}

fn default_tenant() -> String {
    "default".to_string()
}
