//! 7-dimension anomaly scorer ported from Python.

use crate::models::anomaly::AnomalyResult;
use crate::scoring::baseline::{BaselineManager, FrequencyBaseline};
use crate::scoring::weights::ScoringWeights;
use std::collections::HashMap;

pub struct AnomalyScorer<'a> {
    baseline_manager: &'a BaselineManager,
    weights: &'a ScoringWeights,
}

impl<'a> AnomalyScorer<'a> {
    pub fn new(baseline_manager: &'a BaselineManager, weights: &'a ScoringWeights) -> Self {
        Self {
            baseline_manager,
            weights,
        }
    }

    // One parameter per detection field; a struct would only wrap them.
    #[allow(clippy::too_many_arguments)]
    pub fn score(
        &self,
        signal_class: &str,
        confidence: f64,
        freq_hz: f64,
        power_dbm: Option<f64>,
        snr_db: Option<f64>,
        timestamp: Option<&str>,
        gain_db: Option<f64>,
    ) -> AnomalyResult {
        // Normalize power by receiver gain
        let adjusted_power = match (power_dbm, gain_db) {
            (Some(p), Some(g)) => Some(p - g),
            (p, _) => p,
        };

        let hour = extract_hour(timestamp);
        let baseline = self.baseline_manager.get_baseline(freq_hz);
        let is_learning = baseline.map_or(true, |b| b.is_learning());
        let baseline_status = if is_learning { "learning" } else { "stable" };

        let mut dimensions: HashMap<String, f64> = HashMap::new();
        let mut reasons: Vec<String> = Vec::new();

        // Novel class
        let novel = novel_class_score(baseline, signal_class);
        dimensions.insert("novel_class".into(), novel);
        if novel > 0.5 {
            reasons.push(format!("Novel class '{}' at this frequency", signal_class));
        }

        // Rare class
        let rare = rare_class_score(baseline, signal_class);
        dimensions.insert("rare_class".into(), rare);
        if rare > 0.5 {
            reasons.push(format!(
                "Rare class '{}' (low historical probability)",
                signal_class
            ));
        }

        // Low confidence
        let low_conf = low_confidence_score(confidence);
        dimensions.insert("low_confidence".into(), low_conf);
        if low_conf > 0.5 {
            reasons.push(format!("Low confidence ({:.2})", confidence));
        }

        // Power z-score
        let power = power_zscore_score(baseline, adjusted_power);
        dimensions.insert("power_zscore".into(), power);
        if power > 0.5 {
            reasons.push(format!(
                "Unusual signal power (power_dbm={:?})",
                adjusted_power
            ));
        }

        // SNR z-score
        let snr = snr_zscore_score(baseline, snr_db);
        dimensions.insert("snr_zscore".into(), snr);
        if snr > 0.5 {
            reasons.push(format!("Unusual SNR (snr_db={:?})", snr_db));
        }

        // Timing anomaly
        let timing = timing_anomaly_score(baseline, signal_class, hour);
        dimensions.insert("timing_anomaly".into(), timing);
        if timing > 0.5 {
            reasons.push(format!(
                "Unusual timing for '{}' at hour {}",
                signal_class, hour
            ));
        }

        // Quiet frequency
        let quiet = quiet_frequency_score(baseline);
        dimensions.insert("quiet_frequency".into(), quiet);
        if quiet > 0.5 {
            reasons.push("Rarely-used frequency".into());
        }

        // IQ-dependent dimensions (not available in batch ingest path — score 0.0)
        let iq_quality = 0.0_f64;
        let spectral_anomaly = 0.0_f64;
        let modulation_anomaly = 0.0_f64;
        dimensions.insert("iq_quality".into(), iq_quality);
        dimensions.insert("spectral_anomaly".into(), spectral_anomaly);
        dimensions.insert("modulation_anomaly".into(), modulation_anomaly);

        // Composite score (10 dimensions, aligned with Python scorer)
        let mut composite = self.weights.novel_class * novel
            + self.weights.rare_class * rare
            + self.weights.low_confidence * low_conf
            + self.weights.power_zscore * power
            + self.weights.snr_zscore * snr
            + self.weights.timing_anomaly * timing
            + self.weights.quiet_frequency * quiet
            + self.weights.iq_quality * iq_quality
            + self.weights.spectral_anomaly * spectral_anomaly
            + self.weights.modulation_anomaly * modulation_anomaly;

        // Learning dampening — only baseline-dependent dimensions dampened by 25%.
        // Novel class is NEVER dampened — unknown signals must score at full weight.
        if is_learning {
            // Subtract novel_class contribution, dampen the rest, add novel back at full weight
            let novel_contribution = self.weights.novel_class * novel;
            let rest = composite - novel_contribution;
            composite = novel_contribution + (rest * 0.75);
        }

        // Boost score for unknown signal classes (Blind Spot #5)
        let family = crate::class_map::normalize_family(signal_class);
        if family == "UNKNOWN" {
            composite = (composite + 0.3).min(1.0);
            reasons.push("Unknown signal classification — elevated for review".into());
        }

        composite = composite.clamp(0.0, 1.0);
        let priority = priority_label(composite);

        // Round dimensions
        for v in dimensions.values_mut() {
            *v = (*v * 10000.0).round() / 10000.0;
        }

        AnomalyResult {
            score: (composite * 10000.0).round() / 10000.0,
            priority: priority.to_string(),
            dimensions,
            reasons,
            baseline_status: baseline_status.to_string(),
        }
    }
}

fn novel_class_score(baseline: Option<&FrequencyBaseline>, class_name: &str) -> f64 {
    match baseline {
        Some(b) if b.is_novel_class(class_name) => 1.0,
        _ => 0.0,
    }
}

fn rare_class_score(baseline: Option<&FrequencyBaseline>, class_name: &str) -> f64 {
    match baseline {
        None => 0.0,
        Some(b) if b.total_detections == 0 => 0.0,
        Some(b) => 1.0 - b.class_probability(class_name),
    }
}

fn low_confidence_score(confidence: f64) -> f64 {
    (1.0 - confidence).clamp(0.0, 1.0)
}

fn power_zscore_score(baseline: Option<&FrequencyBaseline>, power_dbm: Option<f64>) -> f64 {
    match (baseline, power_dbm) {
        (Some(b), Some(p)) => {
            let z = b.power_zscore(p);
            let abs_z = z.abs();
            (abs_z / (abs_z + 3.0)).min(1.0)
        }
        _ => 0.0,
    }
}

fn snr_zscore_score(baseline: Option<&FrequencyBaseline>, snr_db: Option<f64>) -> f64 {
    match (baseline, snr_db) {
        (Some(b), Some(s)) => {
            let z = b.snr_zscore(s);
            let abs_z = z.abs();
            (abs_z / (abs_z + 3.0)).min(1.0)
        }
        _ => 0.0,
    }
}

fn timing_anomaly_score(baseline: Option<&FrequencyBaseline>, class_name: &str, hour: u8) -> f64 {
    match baseline {
        None => 0.0,
        Some(b) if b.total_detections == 0 => 0.0,
        Some(b) => 1.0 - b.hourly_probability(class_name, hour),
    }
}

fn quiet_frequency_score(baseline: Option<&FrequencyBaseline>) -> f64 {
    match baseline {
        None => 1.0,
        Some(b) if b.total_detections < 10 => 1.0,
        Some(b) if b.total_detections < 50 => 0.5,
        _ => 0.0,
    }
}

pub fn priority_label(score: f64) -> &'static str {
    if score < 0.3 {
        "normal"
    } else if score < 0.5 {
        "interesting"
    } else if score < 0.7 {
        "anomalous"
    } else {
        "critical"
    }
}

fn extract_hour(timestamp: Option<&str>) -> u8 {
    if let Some(ts) = timestamp {
        // Try to parse ISO 8601: "2024-01-15T14:30:00Z" — extract hour from T
        if let Some(t_pos) = ts.find('T') {
            if let Some(hour_str) = ts.get(t_pos + 1..t_pos + 3) {
                if let Ok(h) = hour_str.parse::<u8>() {
                    return h % 24;
                }
            }
        }
    }
    chrono::Utc::now()
        .format("%H")
        .to_string()
        .parse()
        .unwrap_or(0)
}
