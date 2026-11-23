//! Signal class and family normalization for detection batches.

use crate::class_map::{normalize_class, normalize_family};
use crate::models::detection::DetectionRecord;

/// Normalize signal class and family for a batch of detections in-place.
pub fn normalize_batch(detections: &mut [DetectionRecord], node_id: &str) {
    for det in detections.iter_mut() {
        // Normalize signal class
        let canonical = normalize_class(&det.signal_class).to_string();
        det.signal_class = canonical;

        // Set family from canonical class
        det.family = normalize_family(&det.signal_class).to_string();

        // Set node_id if empty
        if det.node_id.is_empty() {
            det.node_id = node_id.to_string();
        }

        // Generate detection_id if empty
        if det.detection_id.is_empty() {
            det.detection_id = uuid::Uuid::new_v4().simple().to_string()[..16].to_string();
        }
    }
}
