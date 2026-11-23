//! Detection record and batch models.

use serde::{Deserialize, Deserializer, Serialize};

/// Accept timestamp as either an ISO 8601 string or a Unix float.
fn deserialize_timestamp<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    struct TimestampVisitor;

    impl<'de> de::Visitor<'de> for TimestampVisitor {
        type Value = String;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a string or numeric timestamp")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<String, E> {
            Ok(v.to_string())
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<String, E> {
            Ok(v)
        }

        fn visit_f64<E: de::Error>(self, v: f64) -> Result<String, E> {
            let secs = v as i64;
            let nanos = ((v - secs as f64) * 1_000_000_000.0) as u32;
            match chrono::DateTime::from_timestamp(secs, nanos) {
                Some(dt) => Ok(dt.to_rfc3339()),
                None => Err(E::custom(format!("invalid unix timestamp: {v}"))),
            }
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<String, E> {
            match chrono::DateTime::from_timestamp(v, 0) {
                Some(dt) => Ok(dt.to_rfc3339()),
                None => Err(E::custom(format!("invalid unix timestamp: {v}"))),
            }
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<String, E> {
            self.visit_i64(v as i64)
        }
    }

    deserializer.deserialize_any(TimestampVisitor)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRecord {
    /// Empty when the sender gave none; then [`edge_id`](Self::edge_id) is
    /// used, or ingest generates one.
    #[serde(default)]
    pub detection_id: String,
    /// `id`: the edge agents' name for `detection_id` (the bridge model's
    /// alias), which they also use for the detection's later IQ upload.
    /// Used when `detection_id` is absent (see
    /// [`adopt_edge_id`](Self::adopt_edge_id)); a non-string value is
    /// ignored.
    #[serde(default, rename = "id", skip_serializing)]
    pub edge_id: Option<serde_json::Value>,
    #[serde(default)]
    pub node_id: String,
    #[serde(
        default = "default_timestamp",
        deserialize_with = "deserialize_timestamp"
    )]
    pub timestamp: String,
    pub signal_class: String,
    pub confidence: f64,
    #[serde(default)]
    pub family: String,
    #[serde(default)]
    pub freq_hz: f64,
    pub snr_db: Option<f64>,
    pub power_dbm: Option<f64>,
    pub inference_ms: Option<f64>,
    #[serde(default = "default_backend")]
    pub backend: Option<String>,
    #[serde(default)]
    pub anomaly_score: f64,
    #[serde(default = "default_baseline_status")]
    pub baseline_status: String,
    #[serde(default)]
    pub has_iq_capture: bool,
    pub gain_db: Option<f64>,
    pub lna_state: Option<String>,
    pub bandwidth_hz: Option<f64>,
    /// Messages the edge already decoded for this detection, as sent. The
    /// gateway does not store them; it hands them to the bridge with the
    /// detection (see `ingest::hooks`).
    #[serde(default, skip_serializing)]
    pub decoded_messages: Option<serde_json::Value>,
}

impl DetectionRecord {
    /// Take the edge's `id` as the detection id when no `detection_id`
    /// was sent, so the stored detection keeps the id the edge refers to
    /// it by (IQ uploads, decoded messages).
    pub fn adopt_edge_id(&mut self) {
        let edge_id = self.edge_id.take();
        if self.detection_id.is_empty() {
            if let Some(serde_json::Value::String(id)) = edge_id {
                self.detection_id = id;
            }
        }
    }
}

fn generate_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..16].to_string()
}

fn default_backend() -> Option<String> {
    Some("onnx".to_string())
}

fn default_baseline_status() -> String {
    "stable".to_string()
}

fn default_timestamp() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionBatch {
    pub node_id: String,
    #[serde(default = "generate_id")]
    pub batch_id: String,
    #[serde(
        default = "default_timestamp",
        deserialize_with = "deserialize_timestamp"
    )]
    pub period_start: String,
    #[serde(
        default = "default_timestamp",
        deserialize_with = "deserialize_timestamp"
    )]
    pub period_end: String,
    pub detections: Vec<DetectionRecord>,
    pub summary: Option<DetectionSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSummary {
    #[serde(default)]
    pub period_seconds: f64,
    #[serde(default)]
    pub total_frames: u64,
    #[serde(default)]
    pub total_detections: u64,
    #[serde(default)]
    pub class_counts: std::collections::HashMap<String, u64>,
    #[serde(default)]
    pub avg_confidence: f64,
    #[serde(default)]
    pub dominant_class: String,
    #[serde(default)]
    pub dominant_family: String,
}

#[derive(Debug, Serialize)]
pub struct BatchResponse {
    pub accepted: bool,
    pub batch_id: String,
    pub inserted: usize,
    /// Detections in the batch as sent.
    pub total: usize,
    /// Detections dropped by per-detection validation.
    pub rejected: usize,
    /// `rejected` by reason (omitted when nothing was rejected).
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub rejected_reasons: std::collections::BTreeMap<&'static str, usize>,
    pub alerts_created: usize,
    pub correlation_count: usize,
    pub fhss_events: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(extra: serde_json::Value) -> DetectionRecord {
        let mut d = serde_json::json!({"signal_class": "qpsk", "confidence": 0.5});
        d.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let mut det: DetectionRecord = serde_json::from_value(d).unwrap();
        det.adopt_edge_id();
        det
    }

    /// The edge agents send each detection's id as `id`; the gateway
    /// ignored it and stored a random id, so the edge's later IQ upload
    /// (`/api/detections/{id}/iq`) and its decoded messages named a
    /// detection that did not exist.
    #[test]
    fn the_edge_id_is_the_detection_id_when_none_is_given() {
        // What edge/detection_reporter.py sends.
        let det = record(serde_json::json!({"id": "0123456789abcdef"}));
        assert_eq!(det.detection_id, "0123456789abcdef");
        let det = record(serde_json::json!({"id": "edge", "detection_id": "explicit"}));
        assert_eq!(det.detection_id, "explicit");
        let det = record(serde_json::json!({"id": 42}));
        assert_eq!(det.detection_id, "", "ingest generates one");
        assert!(det.edge_id.is_none());
        // Neither the edge id nor decoded messages are re-serialised.
        let det = record(serde_json::json!({"id": "e1", "decoded_messages": [{"text": "hi"}]}));
        assert!(det.decoded_messages.is_some());
        let out = serde_json::to_value(&det).unwrap();
        assert_eq!(out["detection_id"], "e1");
        assert!(out.get("id").is_none() && out.get("decoded_messages").is_none());
    }
}
