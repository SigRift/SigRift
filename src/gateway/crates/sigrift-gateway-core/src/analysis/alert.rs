//! Alert rule evaluation engine.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertCondition {
    pub field: String,
    pub operator: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    #[serde(alias = "alert_id")]
    pub rule_id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub conditions: Vec<AlertCondition>,
    #[serde(default = "default_logic")]
    pub logic: String,
    #[serde(default = "default_cooldown")]
    pub cooldown_seconds: f64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub severity: String,
}

fn default_true() -> bool {
    true
}
fn default_logic() -> String {
    "AND".to_string()
}
fn default_cooldown() -> f64 {
    300.0
}

const VALID_FIELDS: &[&str] = &[
    "signal_class",
    "freq_hz",
    "snr_db",
    "power_dbm",
    "anomaly_score",
    "node_id",
    "family",
    "bandwidth_hz",
    "confidence",
];

const VALID_OPERATORS: &[&str] = &[
    "eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "between",
];

pub struct AlertEngine {
    cooldowns: HashMap<String, Instant>,
}

impl Default for AlertEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertEngine {
    pub fn new() -> Self {
        Self {
            cooldowns: HashMap::new(),
        }
    }

    /// Evaluate a detection against all enabled rules. Returns triggered rules.
    pub fn evaluate(
        &mut self,
        detection: &HashMap<String, serde_json::Value>,
        rules: &[AlertRule],
    ) -> Vec<AlertRule> {
        let now = Instant::now();
        let mut triggered = Vec::new();

        for rule in rules {
            if !rule.enabled {
                continue;
            }
            if rule.rule_id.is_empty() {
                continue;
            }

            // Check cooldown
            if let Some(last) = self.cooldowns.get(&rule.rule_id) {
                if now.duration_since(*last).as_secs_f64() < rule.cooldown_seconds {
                    continue;
                }
            }

            if evaluate_rule(detection, rule) {
                self.cooldowns.insert(rule.rule_id.clone(), now);
                triggered.push(rule.clone());
            }
        }

        triggered
    }
}

fn evaluate_rule(detection: &HashMap<String, serde_json::Value>, rule: &AlertRule) -> bool {
    if rule.conditions.is_empty() {
        return false;
    }

    let logic = rule.logic.to_uppercase();
    if logic == "OR" {
        rule.conditions
            .iter()
            .any(|c| evaluate_condition(detection, c))
    } else {
        rule.conditions
            .iter()
            .all(|c| evaluate_condition(detection, c))
    }
}

fn evaluate_condition(
    detection: &HashMap<String, serde_json::Value>,
    condition: &AlertCondition,
) -> bool {
    if !VALID_FIELDS.contains(&condition.field.as_str()) {
        return false;
    }
    if !VALID_OPERATORS.contains(&condition.operator.as_str()) {
        return false;
    }

    let det_value = match detection.get(&condition.field) {
        Some(v) => v,
        None => return false,
    };

    match condition.operator.as_str() {
        "eq" => det_value == &condition.value,
        "ne" => det_value != &condition.value,
        "gt" => cmp_float(det_value, &condition.value, |a, b| a > b),
        "gte" => cmp_float(det_value, &condition.value, |a, b| a >= b),
        "lt" => cmp_float(det_value, &condition.value, |a, b| a < b),
        "lte" => cmp_float(det_value, &condition.value, |a, b| a <= b),
        "in" => {
            if let Some(arr) = condition.value.as_array() {
                arr.contains(det_value)
            } else {
                false
            }
        }
        "not_in" => {
            if let Some(arr) = condition.value.as_array() {
                !arr.contains(det_value)
            } else {
                true
            }
        }
        "between" => {
            if let Some(arr) = condition.value.as_array() {
                if arr.len() == 2 {
                    let lo = to_f64(&arr[0]);
                    let hi = to_f64(&arr[1]);
                    let v = to_f64(det_value);
                    match (lo, hi, v) {
                        (Some(l), Some(h), Some(val)) => l <= val && val <= h,
                        _ => false,
                    }
                } else {
                    false
                }
            } else {
                false
            }
        }
        _ => false,
    }
}

fn cmp_float(a: &serde_json::Value, b: &serde_json::Value, cmp: fn(f64, f64) -> bool) -> bool {
    match (to_f64(a), to_f64(b)) {
        (Some(va), Some(vb)) => cmp(va, vb),
        _ => false,
    }
}

fn to_f64(v: &serde_json::Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_i64().map(|i| i as f64))
}
