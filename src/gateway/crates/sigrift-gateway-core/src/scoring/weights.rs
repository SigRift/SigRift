//! Configurable scoring dimension weights.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringWeights {
    pub novel_class: f64,
    pub rare_class: f64,
    pub low_confidence: f64,
    pub power_zscore: f64,
    pub snr_zscore: f64,
    pub timing_anomaly: f64,
    pub quiet_frequency: f64,
    pub iq_quality: f64,
    pub spectral_anomaly: f64,
    pub modulation_anomaly: f64,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        // Aligned with Python scorer (src/sigrift/bridge/anomaly/scorer.py)
        Self {
            novel_class: 0.22,
            rare_class: 0.14,
            low_confidence: 0.14,
            power_zscore: 0.10,
            snr_zscore: 0.08,
            timing_anomaly: 0.07,
            quiet_frequency: 0.04,
            iq_quality: 0.08,
            spectral_anomaly: 0.07,
            modulation_anomaly: 0.06,
        }
    }
}
