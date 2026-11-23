//! POST /batch ingest handler — full pipeline.
//!
//! Node binding (contracts K4, K7, K7b; see [`crate::ingest::binding`]):
//! the credential must be allowed to act for the batch's node — a bound
//! key only for its node, an unbound node (SENSOR/NODE) key is bound to it
//! on first use through the bridge, an unbound VIEWER key never, a client
//! certificate only for the node it names, a session or an unbound key
//! only from ANALYST up — and every detection must belong to the batch's
//! node (an absent `node_id` is filled in from the batch).
//! Detections that fail validation are dropped individually and counted in
//! the response (`rejected`, `rejected_reasons`).
//!
//! A detection keeps the id the edge sent as `id` when it has no
//! `detection_id`. After the batch is stored, its newly inserted
//! detections (with the messages the edge decoded for them) are queued for
//! the bridge's post-ingest work (contract K8, [`crate::ingest::hooks`]):
//! alert rules, watch bands and webhooks run there asynchronously, so
//! `alerts_created` in the response stays 0. Without a usable
//! `UC_PROXY_SECRET` (development only) the bridge refuses them, so they
//! are only counted (`hooks_disabled`; contract K10).

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;
use tracing::{info, warn};

use crate::analysis::correlator::RecentDetection;
use crate::analysis::fhss::{DetectionView, FHSSDetector};
use crate::auth::rbac::Role;
use crate::ingest::binding::{authorize_batch, Submitter};
use crate::ingest::normalize::normalize_batch;
use crate::ingest::validate::{
    decompress_gzip, is_gzip, partition_detections, validate_node_id, validate_record_id,
};
use crate::middleware::auth::{require_auth, AuthInfo};
use crate::models::anomaly::RFAnomaly;
use crate::models::detection::{BatchResponse, DetectionBatch, DetectionRecord};
use crate::scoring::scorer::AnomalyScorer;
use crate::AppState;

/// An ingest failure, sent as-is.
pub struct IngestError(Response);

impl From<StatusCode> for IngestError {
    fn from(status: StatusCode) -> Self {
        IngestError(status.into_response())
    }
}

impl IntoResponse for IngestError {
    fn into_response(self) -> Response {
        self.0
    }
}

fn reject(status: StatusCode, detail: String) -> IngestError {
    IngestError((status, Json(serde_json::json!({ "detail": detail }))).into_response())
}

#[allow(clippy::result_large_err)] // the Err is the ready-made response
pub async fn ingest_batch(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
) -> Result<Json<BatchResponse>, IngestError> {
    // Auth check via middleware-injected AuthInfo
    let auth: Option<AuthInfo> = if state.auth_enabled {
        Some(require_auth(&req, Role::Sensor)?)
    } else {
        None
    };
    let submitter = Submitter::of(
        auth.as_ref(),
        crate::auth::api_key::extract_api_key(&req).is_some(),
    );

    // Extract body from the request
    let (_parts, body) = req.into_parts();
    let body = axum::body::to_bytes(body, state.config.max_body_size)
        .await
        .map_err(|_| IngestError::from(StatusCode::PAYLOAD_TOO_LARGE))?;

    // Decompress if gzip
    let data = if is_gzip(&body) {
        match decompress_gzip(&body, state.config.max_decompressed_size) {
            Ok(d) => d,
            Err(e) => {
                warn!(error = %e, "Decompression failed");
                return Err(StatusCode::BAD_REQUEST.into());
            }
        }
    } else {
        body
    };

    // Parse batch
    let batch: DetectionBatch = serde_json::from_slice(&data).map_err(|e| {
        warn!(error = %e, "Invalid batch JSON");
        IngestError::from(StatusCode::BAD_REQUEST)
    })?;

    if !validate_node_id(&batch.node_id) {
        warn!(node_id = ?batch.node_id, "Invalid node_id");
        return Err(StatusCode::BAD_REQUEST.into());
    }
    if !validate_record_id(&batch.batch_id) {
        warn!(node_id = %batch.node_id, "Invalid batch_id");
        return Err(reject(
            StatusCode::BAD_REQUEST,
            "batch_id must match [A-Za-z0-9_.:-]{1,128}".into(),
        ));
    }

    if let Err(refused) = authorize_batch(&state, &submitter, &batch.node_id).await {
        return Err(reject(refused.status, refused.detail));
    }
    let received_at = crate::ingest::hooks::received_now();

    let total = batch.detections.len();
    let parts = partition_detections(batch.detections, &batch.node_id);
    let rejected = parts.rejected_total();
    if rejected > 0 {
        warn!(
            batch_id = %batch.batch_id,
            node_id = %batch.node_id,
            rejected,
            reasons = ?parts.rejected,
            "Detections rejected by validation"
        );
    }
    let rejected_reasons = parts.rejected;
    let mut detections = parts.accepted;
    if detections.is_empty() {
        return Ok(Json(BatchResponse {
            accepted: true,
            batch_id: batch.batch_id.clone(),
            inserted: 0,
            total,
            rejected,
            rejected_reasons,
            alerts_created: 0,
            correlation_count: 0,
            fhss_events: 0,
        }));
    }

    // Normalize
    normalize_batch(&mut detections, &batch.node_id);

    // Score anomalies
    {
        let mut bm = state.baseline_manager.write().unwrap();
        let scorer = AnomalyScorer::new(&bm, &state.scoring_weights);

        for det in detections.iter_mut() {
            let result = scorer.score(
                &det.signal_class,
                det.confidence,
                det.freq_hz,
                det.power_dbm,
                det.snr_db,
                Some(&det.timestamp),
                det.gain_db,
            );
            det.anomaly_score = result.score;
            det.baseline_status = result.baseline_status.clone();

            // Broadcast anomalies above threshold
            if result.score >= 0.3 {
                let anomaly = RFAnomaly {
                    detection_id: det.detection_id.clone(),
                    signal_class: det.signal_class.clone(),
                    family: det.family.clone(),
                    freq_hz: det.freq_hz,
                    dedup_key: RFAnomaly::make_dedup_key(&det.signal_class, det.freq_hz),
                    node_id: det.node_id.clone(),
                    timestamp: det.timestamp.clone(),
                    confidence: det.confidence,
                    snr_db: det.snr_db,
                    power_dbm: det.power_dbm,
                    anomaly_score: result.score,
                    priority: result.priority.clone(),
                    dimensions: serde_json::to_string(&result.dimensions).unwrap_or_default(),
                    reasons: serde_json::to_string(&result.reasons).unwrap_or_default(),
                    baseline_status: result.baseline_status,
                    has_iq_capture: det.has_iq_capture,
                    tenant_id: "default".to_string(),
                };

                // Store anomaly
                let conn = state
                    .db_pool
                    .get()
                    .map_err(|_| IngestError::from(StatusCode::INTERNAL_SERVER_ERROR))?;
                if let Err(e) = crate::db::rf_anomalies::upsert(&conn, &anomaly) {
                    warn!(error = %e, "Failed to upsert anomaly");
                }

                // Broadcast to WebSocket
                let _ = state
                    .anomaly_tx
                    .send(serde_json::to_string(&anomaly).unwrap_or_default());
            }
        }

        // Update baselines
        for det in &detections {
            let hour = extract_hour(&det.timestamp);
            bm.update(
                det.freq_hz,
                &det.signal_class,
                det.confidence,
                det.power_dbm,
                Some(hour),
                det.snr_db,
            );
        }
    }

    // FHSS detection
    let fhss_detector = FHSSDetector::new();
    let views: Vec<DetectionView> = detections
        .iter()
        .map(|d| DetectionView {
            node_id: d.node_id.clone(),
            timestamp: d.timestamp.clone(),
            freq_hz: d.freq_hz,
            signal_class: d.signal_class.clone(),
            confidence: d.confidence,
        })
        .collect();
    let fhss_events = fhss_detector.analyse(&views);
    let fhss_count = fhss_events.len();

    // Store FHSS events
    if !fhss_events.is_empty() {
        let conn = state
            .db_pool
            .get()
            .map_err(|_| IngestError::from(StatusCode::INTERNAL_SERVER_ERROR))?;
        for evt in &fhss_events {
            if let Err(e) = crate::db::fhss::insert_event(&conn, evt) {
                warn!(error = %e, "Failed to insert FHSS event");
            }
        }
    }

    // Cross-node correlation
    let correlation_count = {
        let conn = state
            .db_pool
            .get()
            .map_err(|_| IngestError::from(StatusCode::INTERNAL_SERVER_ERROR))?;
        let recent = crate::db::detections::get_recent(&conn, 10, 500).unwrap_or_default();
        let recent_views: Vec<RecentDetection> = recent
            .iter()
            .map(|d| RecentDetection {
                node_id: d.node_id.clone(),
                signal_class: d.signal_class.clone(),
                family: d.family.clone(),
                freq_hz: d.freq_hz,
                timestamp: d.timestamp.clone(),
            })
            .collect();

        let correlator = state.correlator.read().unwrap();
        let mut count = 0usize;
        for det in &detections {
            let result = correlator.check_correlation(
                &det.node_id,
                &det.signal_class,
                &det.family,
                det.freq_hz,
                &det.timestamp,
                det.anomaly_score,
                &recent_views,
            );
            if result.correlated {
                count += 1;
            }
        }
        count
    };

    // Store detections
    let conn = state
        .db_pool
        .get()
        .map_err(|_| IngestError::from(StatusCode::INTERNAL_SERVER_ERROR))?;
    let new_rows =
        crate::db::detections::insert_batch_marking(&conn, &detections).map_err(|e| {
            warn!(error = %e, "Failed to insert detections");
            IngestError::from(StatusCode::INTERNAL_SERVER_ERROR)
        })?;
    drop(conn);
    let inserted = new_rows.iter().filter(|&&new| new).count();

    // K8: the bridge's post-ingest work for what was newly stored (a
    // detection already stored — a batch sent again — is not hooked twice).
    let new_detections: Vec<&DetectionRecord> = detections
        .iter()
        .zip(&new_rows)
        .filter_map(|(det, &new)| new.then_some(det))
        .collect();
    // Without a usable proxy secret the bridge refuses every hook (K10):
    // count them instead of filling the queue with requests bound to fail.
    if !new_detections.is_empty() {
        if state.config.proxy_secret_usable() {
            state
                .ingest_hooks
                .enqueue_batch(&batch.node_id, &new_detections, &received_at);
        } else {
            state.ingest_hooks.count_disabled(new_detections.len());
        }
    }

    // Broadcast to WebSocket feed
    for det in &detections {
        let _ = state
            .detection_tx
            .send(serde_json::to_string(det).unwrap_or_default());
    }

    info!(
        batch_id = %batch.batch_id,
        node_id = %batch.node_id,
        inserted = inserted,
        total = total,
        fhss = fhss_count,
        correlations = correlation_count,
        "Batch ingested"
    );

    Ok(Json(BatchResponse {
        accepted: true,
        batch_id: batch.batch_id,
        inserted,
        total,
        rejected,
        rejected_reasons,
        alerts_created: 0,
        correlation_count,
        fhss_events: fhss_count,
    }))
}

fn extract_hour(timestamp: &str) -> u8 {
    if let Some(t_pos) = timestamp.find('T') {
        if let Some(hour_str) = timestamp.get(t_pos + 1..t_pos + 3) {
            if let Ok(h) = hour_str.parse::<u8>() {
                return h % 24;
            }
        }
    }
    chrono::Utc::now()
        .format("%H")
        .to_string()
        .parse()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_hour_iso8601() {
        assert_eq!(extract_hour("2026-01-15T14:30:00Z"), 14);
        assert_eq!(extract_hour("2026-01-15T00:00:00Z"), 0);
        assert_eq!(extract_hour("2026-01-15T23:59:59Z"), 23);
        assert_eq!(extract_hour("2026-01-15T09:15:00+00:00"), 9);
    }

    #[test]
    fn test_extract_hour_with_fractional_seconds() {
        assert_eq!(extract_hour("2026-01-15T14:30:00.123Z"), 14);
    }

    #[test]
    fn test_extract_hour_boundary() {
        assert_eq!(extract_hour("2026-01-15T00:00:00Z"), 0);
        assert_eq!(extract_hour("2026-01-15T23:59:59Z"), 23);
    }

    #[test]
    fn test_extract_hour_malformed_falls_back() {
        // No T separator — should fall back to current hour
        let hour = extract_hour("not-a-timestamp");
        assert!(hour < 24);
    }

    #[test]
    fn test_extract_hour_empty_string() {
        let hour = extract_hour("");
        assert!(hour < 24);
    }

    #[test]
    fn test_extract_hour_truncated_after_t() {
        // T exists but no hour digits after it
        let hour = extract_hour("2026-01-15T");
        assert!(hour < 24);
    }
}

#[cfg(test)]
mod ingest_tests {
    use super::*;
    use crate::test_support;
    use axum::body::Body;
    use axum::http::Request;

    const INGEST_SCHEMA: &str = "
        CREATE TABLE detections (
            detection_id TEXT PRIMARY KEY, node_id TEXT, timestamp TEXT, signal_class TEXT,
            confidence REAL, family TEXT, freq_hz REAL, snr_db REAL, power_dbm REAL,
            inference_ms REAL, backend TEXT, anomaly_score REAL, baseline_status TEXT,
            has_iq_capture INTEGER, gain_db REAL, lna_state TEXT, bandwidth_hz REAL,
            tenant_id TEXT);
        CREATE TABLE rf_anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT, detection_id TEXT, signal_class TEXT,
            family TEXT, freq_hz REAL, dedup_key TEXT, node_id TEXT, timestamp TEXT,
            confidence REAL, snr_db REAL, power_dbm REAL, anomaly_score REAL, priority TEXT,
            dimensions TEXT, reasons TEXT, baseline_status TEXT, has_iq_capture INTEGER,
            seen_count INTEGER, first_seen TEXT, tenant_id TEXT, dismissed INTEGER DEFAULT 0);
        CREATE TABLE fhss_events (
            fhss_id TEXT PRIMARY KEY, node_id TEXT, timestamp TEXT, hop_rate_hz REAL,
            hop_set TEXT, bandwidth_hz REAL, dwell_time_ms REAL, duration_sec REAL,
            signal_class TEXT, detection_count INTEGER, confidence REAL, tenant_id TEXT);";

    /// An auth-enabled state whose keys.json binds `bound-key` to node
    /// `node-a` and leaves `free-key` and `edge-7` (sensors) and
    /// `admin-key` unbound.
    /// The bridge is unreachable unless a test points `python_url` at one.
    fn state(dir: &tempfile::TempDir) -> Arc<AppState> {
        state_with_bridge(dir, "http://127.0.0.1:9")
    }

    fn state_with_bridge(dir: &tempfile::TempDir, python_url: &str) -> Arc<AppState> {
        let keys = dir.path().join("keys.json");
        std::fs::write(
            &keys,
            r#"{"keys": {
                "bound-key": {"hash": "00", "salt": "00", "role": "sensor", "node_id": "node-a"},
                "free-key": {"hash": "00", "salt": "00", "role": "sensor", "node_id": null},
                "edge-7": {"hash": "00", "salt": "00", "role": "sensor"},
                "admin-key": {"hash": "00", "salt": "00", "role": "admin"}
            }}"#,
        )
        .unwrap();
        let Ok(mut state) = Arc::try_unwrap(test_support::app_state(dir)) else {
            unreachable!("fresh state has one owner")
        };
        state.key_store = crate::auth::api_key::KeyStore::try_new(&keys);
        assert!(state.key_store.is_some());
        state.auth_enabled = true;
        state.config.python_url = python_url.to_string();
        state.config.proxy_secret = "ingest-secret".to_string();
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch(INGEST_SCHEMA)
            .unwrap();
        Arc::new(state)
    }

    fn batch_request(key_id: &str, body: serde_json::Value) -> Request<Body> {
        batch_request_as(key_id, Role::Sensor, body)
    }

    fn batch_request_as(key_id: &str, role: Role, body: serde_json::Value) -> Request<Body> {
        let mut req = Request::builder()
            .method("POST")
            .uri("/api/detections/batch")
            .header("content-type", "application/json")
            // The middleware validated it; the handler only sees AuthInfo.
            .header("x-api-key", "presented")
            .body(Body::from(body.to_string()))
            .unwrap();
        req.extensions_mut().insert(AuthInfo::ApiKey {
            key_id: key_id.into(),
            role,
        });
        req
    }

    /// A request authenticated by a verified client certificate.
    fn cert_request(identity: &str, role: Role, body: serde_json::Value) -> Request<Body> {
        let mut req = batch_request_as(identity, role, body);
        req.headers_mut().remove("x-api-key");
        req.extensions_mut()
            .insert(crate::auth::client_cert::ClientCertInfo {
                identity: identity.into(),
                serial: "7".into(),
                fingerprint_sha256: String::new(),
            });
        req
    }

    fn session_request(role: Role, body: serde_json::Value) -> Request<Body> {
        let mut req = Request::post("/api/detections/batch")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        req.extensions_mut().insert(AuthInfo::Session {
            username: "user".into(),
            user_id: 1,
            role,
            session_token: "tok".into(),
            expires_at: "2099-01-01T00:00:00+00:00".into(),
            tenant_id: "default".into(),
            scope: String::new(),
        });
        req
    }

    /// A fake bridge whose bind endpoint answers `status` with `body`
    /// after `delay`, recording each request body and its X-Rust-Proxy.
    async fn bind_bridge(
        status: u16,
        body: serde_json::Value,
        delay: std::time::Duration,
    ) -> (
        String,
        Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>>,
    ) {
        use axum::routing::post;
        let seen: Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>> = Arc::default();
        let record = Arc::clone(&seen);
        let app = axum::Router::new().route(
            crate::ingest::binding::BIND_PATH,
            post(
                move |headers: axum::http::HeaderMap, Json(req): Json<serde_json::Value>| {
                    let (record, body) = (Arc::clone(&record), body.clone());
                    async move {
                        let secret = headers
                            .get("x-rust-proxy")
                            .map(|v| v.to_str().unwrap().to_string())
                            .unwrap_or_default();
                        record.lock().unwrap().push((secret, req));
                        tokio::time::sleep(delay).await;
                        (StatusCode::from_u16(status).unwrap(), Json(body))
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, seen)
    }

    fn detection(id: &str, node: Option<&str>) -> serde_json::Value {
        let mut d = serde_json::json!({
            "detection_id": id, "signal_class": "qpsk", "confidence": 0.9,
            "freq_hz": 433_920_000.0, "snr_db": 12.0, "power_dbm": -60.0,
            "timestamp": "2026-11-05T10:00:00+00:00",
        });
        if let Some(node) = node {
            d["node_id"] = node.into();
        }
        d
    }

    async fn ingest(state: &Arc<AppState>, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let resp = ingest_batch(State(state.clone()), req)
            .await
            .into_response();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    fn stored(state: &AppState) -> Vec<(String, String)> {
        let conn = state.db_pool.get().unwrap();
        let mut stmt = conn
            .prepare("SELECT detection_id, node_id FROM detections ORDER BY detection_id")
            .unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    /// The IQ-upload race (W2, gateway side): when a detection's IQ upload
    /// reaches the bridge before its batch, the bridge has already stored a
    /// placeholder row (`iq_capture`, confidence 0) under the detection id.
    /// `INSERT OR IGNORE` then dropped the real detection — it was never
    /// stored and never hooked, so no alert rule saw it. It must upgrade
    /// the placeholder, like the bridge's own insert, and only that.
    #[tokio::test]
    async fn a_batch_upgrades_the_iq_placeholder_of_its_own_detection() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        {
            let conn = state.db_pool.get().unwrap();
            conn.execute_batch(
                "INSERT INTO detections (detection_id, node_id, timestamp, signal_class,
                     confidence, anomaly_score, has_iq_capture, tenant_id) VALUES
                 ('d-stub', 'node-a', '2026-11-05T09:59:59+00:00', 'iq_capture', 0, 0, 1, 'default'),
                 ('d-other', 'node-b', '2026-11-05T09:59:59+00:00', 'iq_capture', 0, 0, 1, 'default'),
                 ('d-real', 'node-a', '2026-11-05T09:00:00+00:00', 'fsk', 0.7, 0, 0, 'default');",
            )
            .unwrap();
        }
        let body = serde_json::json!({"node_id": "node-a", "detections": [
            detection("d-stub", None), detection("d-other", None), detection("d-real", None),
        ]});
        let (status, json) = ingest(&state, batch_request("bound-key", body)).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["inserted"], 1, "{json}");

        let conn = state.db_pool.get().unwrap();
        let row = |id: &str| -> (String, String, f64, i64) {
            conn.query_row(
                "SELECT node_id, signal_class, confidence, has_iq_capture FROM detections \
                 WHERE detection_id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap()
        };
        // Upgraded in place, keeping its IQ capture flag.
        assert_eq!(row("d-stub"), ("node-a".into(), "qpsk".into(), 0.9, 1));
        // Another node's placeholder and a real detection are untouched.
        assert_eq!(
            row("d-other"),
            ("node-b".into(), "iq_capture".into(), 0.0, 1)
        );
        assert_eq!(row("d-real"), ("node-a".into(), "fsk".into(), 0.7, 0));
        // Only the upgraded detection is handed to the post-ingest hooks.
        assert_eq!(state.ingest_hooks.stats().enqueued_detections, 1);
    }

    #[tokio::test]
    async fn a_bound_key_can_only_submit_for_its_node() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);

        let body = serde_json::json!({"node_id": "node-b", "detections": [detection("d1", None)]});
        let (status, json) = ingest(&state, batch_request("bound-key", body)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(json["detail"].as_str().unwrap().contains("node-a"));
        assert!(stored(&state).is_empty());

        let body = serde_json::json!({"node_id": "node-a", "detections": [detection("d1", None)]});
        let (status, json) = ingest(&state, batch_request("bound-key", body)).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(stored(&state), [("d1".into(), "node-a".into())]);
    }

    #[tokio::test]
    async fn detections_for_another_node_are_rejected_individually() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        let mut feed = state.detection_tx.subscribe();

        let body = serde_json::json!({
            "node_id": "node-a",
            "detections": [
                detection("own", Some("node-a")),
                detection("filled", None),
                detection("forged", Some("node-y")),
            ],
        });
        // A batch reports for one node only.
        let (status, json) = ingest(&state, batch_request("bound-key", body)).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["total"], 3);
        assert_eq!(json["inserted"], 2);
        assert_eq!(json["rejected"], 1);
        assert_eq!(json["rejected_reasons"]["node_mismatch"], 1);
        assert_eq!(
            stored(&state),
            [
                ("filled".into(), "node-a".into()),
                ("own".into(), "node-a".into())
            ]
        );
        let broadcast: Vec<String> = std::iter::from_fn(|| feed.try_recv().ok()).collect();
        assert_eq!(broadcast.len(), 2);
        assert!(broadcast.iter().all(|m| !m.contains("forged")));
    }

    #[tokio::test]
    async fn invalid_detection_fields_are_rejected_with_counts() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);

        let mut long_class = detection("long", None);
        long_class["signal_class"] = "x".repeat(129).into();
        let mut markup = detection("markup", None);
        markup["signal_class"] = "<img src=x onerror=alert(1)>".into();
        let mut bad_id = detection("../../etc", None);
        bad_id["detection_id"] = "../../etc".into();
        let mut bad_ts = detection("ts", None);
        bad_ts["timestamp"] = "yesterday".into();
        let mut bad_conf = detection("conf", None);
        bad_conf["confidence"] = 7.5.into();
        let mut bad_lna = detection("lna", None);
        bad_lna["lna_state"] = "a\nb".into();

        let body = serde_json::json!({
            "node_id": "node-a",
            "detections": [long_class, markup, bad_id, bad_ts, bad_conf, bad_lna,
                           detection("good", None)],
        });
        let (status, json) = ingest(&state, batch_request("bound-key", body)).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(
            (json["inserted"].as_u64(), json["rejected"].as_u64()),
            (Some(1), Some(6))
        );
        assert_eq!(json["rejected_reasons"]["invalid_signal_class"], 2);
        assert_eq!(json["rejected_reasons"]["invalid_detection_id"], 1);
        assert_eq!(json["rejected_reasons"]["invalid_timestamp"], 1);
        assert_eq!(json["rejected_reasons"]["invalid_confidence"], 1);
        assert_eq!(json["rejected_reasons"]["invalid_lna_state"], 1);
        assert_eq!(stored(&state), [("good".into(), "node-a".into())]);
        // Rejected classes never reach the baselines.
        let bm = state.baseline_manager.read().unwrap();
        let b = bm.get_baseline(433_920_000.0).unwrap();
        assert_eq!(b.class_counts.keys().collect::<Vec<_>>(), ["qpsk"]);
    }

    #[tokio::test]
    async fn a_batch_with_only_invalid_detections_inserts_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        let body = serde_json::json!({
            "node_id": "node-a", "detections": [detection("x", Some("node-b"))],
        });
        let (status, json) = ingest(&state, batch_request("bound-key", body)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            (json["inserted"].as_u64(), json["rejected"].as_u64()),
            (Some(0), Some(1))
        );
        assert!(stored(&state).is_empty());
    }

    /// K7: a node certificate's identity is its node id — it may submit
    /// for that node only (no trust on first use); an admin certificate
    /// for any node. A key's binding does not apply to a certificate whose
    /// identity happens to equal that key's id.
    #[tokio::test]
    async fn a_client_certificate_may_only_submit_for_its_own_node() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        let batch = |node: &str, id: &str| serde_json::json!({"node_id": node, "detections": [detection(id, None)]});
        let (status, json) = ingest(
            &state,
            cert_request("node-b", Role::Node, batch("node-b", "c1")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let (status, json) = ingest(
            &state,
            cert_request("node-b", Role::Node, batch("node-c", "c2")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{json}");
        // Before K7 any certificate could submit for any node.
        let (status, _) = ingest(
            &state,
            cert_request("bound-key", Role::Sensor, batch("node-b", "c3")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = ingest(
            &state,
            cert_request("ops", Role::Admin, batch("node-c", "c4")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            stored(&state),
            [
                ("c1".into(), "node-b".into()),
                ("c4".into(), "node-c".into())
            ]
        );
    }

    /// Regression (Q23 / P2, K7): an unbound node key could post batches
    /// for any node for good (the bridge's trust-on-first-use binding never
    /// ran for gateway-ingested batches). The gateway now has the bridge
    /// bind the key to the batch's node first, and refuses otherwise.
    #[tokio::test]
    async fn an_unbound_key_is_bound_by_the_bridge_on_first_use() {
        use std::time::Duration;
        let batch = |id: &str| serde_json::json!({"node_id": "node-x", "detections": [detection(id, None)]});

        // 200: bound to this node — accepted.
        let (url, seen) = bind_bridge(
            200,
            serde_json::json!({"node_id": "node-x", "bound": true}),
            Duration::ZERO,
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_bridge(&dir, &url);
        let (status, json) = ingest(&state, batch_request("free-key", batch("t1"))).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(stored(&state), [("t1".into(), "node-x".into())]);
        assert_eq!(
            seen.lock().unwrap().clone(),
            [(
                "ingest-secret".to_string(),
                serde_json::json!({"key_id": "free-key", "node_id": "node-x"})
            )]
        );

        // 409 (bound elsewhere) and 404 (unknown key): refused, nothing stored.
        for status in [409, 404] {
            let (url, _) = bind_bridge(
                status,
                serde_json::json!({"node_id": "node-q"}),
                Duration::ZERO,
            )
            .await;
            let dir = tempfile::tempdir().unwrap();
            let state = state_with_bridge(&dir, &url);
            let (got, json) = ingest(&state, batch_request("free-key", batch("t2"))).await;
            assert_eq!(got, StatusCode::FORBIDDEN, "{status}");
            assert_eq!(json["detail"], crate::ingest::binding::BOUND_ELSEWHERE);
            assert!(stored(&state).is_empty());
        }

        // A bridge that does not answer in time, or at all, or with an
        // error: 503, fail closed.
        let (url, _) = bind_bridge(
            200,
            serde_json::json!({"node_id": "node-x"}),
            Duration::from_secs(4),
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_bridge(&dir, &url);
        let started = std::time::Instant::now();
        let (status, _) = ingest(&state, batch_request("free-key", batch("t3"))).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(started.elapsed() < Duration::from_secs(4));
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_bridge(&dir, "http://127.0.0.1:9");
        let (status, _) = ingest(&state, batch_request("free-key", batch("t4"))).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let (url, _) = bind_bridge(500, serde_json::json!({}), Duration::ZERO).await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_bridge(&dir, &url);
        let (status, _) = ingest(&state, batch_request("free-key", batch("t5"))).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(stored(&state).is_empty());
    }

    #[tokio::test]
    async fn admin_keys_and_the_unbound_keys_setting_skip_the_binding() {
        let batch = |id: &str| serde_json::json!({"node_id": "node-x", "detections": [detection(id, None)]});
        // The bridge is unreachable: no binding request may be needed.
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        let (status, json) = ingest(
            &state,
            batch_request_as("admin-key", Role::Admin, batch("a1")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");

        let dir = tempfile::tempdir().unwrap();
        let Ok(mut unbound) = Arc::try_unwrap(state_with_bridge(&dir, "http://127.0.0.1:9")) else {
            unreachable!()
        };
        unbound.config.allow_unbound_node_keys = "1".into();
        let unbound = Arc::new(unbound);
        let (status, json) = ingest(&unbound, batch_request("free-key", batch("a2"))).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        // A bound key stays bound even then.
        let (status, _) = ingest(&unbound, batch_request("bound-key", batch("a3"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    /// Q23 regression: with BRIDGE_ALLOW_UNBOUND_NODE_KEYS set, a key named
    /// after a node registered with the bridge was accepted for any node
    /// at the gateway, while the bridge's legacy rule (applied before the
    /// setting) binds it to that node.
    #[tokio::test]
    async fn the_unbound_keys_setting_keeps_the_legacy_node_named_key_rule() {
        let batch = |node: &str, id: &str| serde_json::json!({"node_id": node, "detections": [detection(id, None)]});
        let dir = tempfile::tempdir().unwrap();
        // The bridge is unreachable: the rule is applied from the
        // registry, without a binding request.
        let Ok(mut unbound) = Arc::try_unwrap(state_with_bridge(&dir, "http://127.0.0.1:9")) else {
            unreachable!()
        };
        unbound.config.allow_unbound_node_keys = "1".into();
        let unbound = Arc::new(unbound);
        std::fs::write(
            dir.path().join("nodes.json"),
            r#"{"nodes": {"edge-7": {"status": "online"}, "node-x": {}}}"#,
        )
        .unwrap();

        let (status, json) = ingest(&unbound, batch_request("edge-7", batch("node-x", "l1"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{json}");
        assert_eq!(json["detail"], "API key is bound to node 'edge-7'");
        // Its own node is fine, and so is any node for a key that is not
        // named after a registered node.
        let (status, json) = ingest(&unbound, batch_request("edge-7", batch("edge-7", "l2"))).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let (status, json) =
            ingest(&unbound, batch_request("free-key", batch("edge-7", "l3"))).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        // An admin key named after a node still acts for any node.
        let (status, json) = ingest(
            &unbound,
            batch_request_as("edge-7", Role::Admin, batch("node-x", "l4")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(
            stored(&unbound),
            [
                ("l2".into(), "edge-7".into()),
                ("l3".into(), "edge-7".into()),
                ("l4".into(), "node-x".into())
            ]
        );
    }

    /// P2: a VIEWER session is not a node credential; ANALYST and above
    /// may still submit (unchanged).
    #[tokio::test]
    async fn sessions_below_analyst_cannot_submit_batches() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        let batch = |id: &str| serde_json::json!({"node_id": "victim-node", "detections": [detection(id, None)]});
        let (status, json) = ingest(&state, session_request(Role::Viewer, batch("s1"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(json["detail"], "Node endpoints require a node API key");
        let (status, _) = ingest(&state, session_request(Role::Analyst, batch("s2"))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(stored(&state), [("s2".into(), "victim-node".into())]);
    }

    /// K8: what was newly stored is queued for the bridge's post-ingest
    /// work, with the edge's ids and decoded messages; a batch sent again
    /// is not queued twice.
    #[tokio::test]
    async fn new_detections_are_queued_for_the_bridge_post_ingest_hook() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        // As edge/detection_reporter.py sends it: the id is `id`.
        let mut edge = detection("unused", None);
        edge.as_object_mut().unwrap().remove("detection_id");
        edge["id"] = "e0123456789abcde".into();
        edge["decoded_messages"] = serde_json::json!([{"protocol": "adsb", "icao": "a1b2c3"}]);
        let body = serde_json::json!({
            "node_id": "node-a",
            "detections": [edge, detection("plain", None), detection("bad", Some("node-z"))],
        });
        let (status, json) = ingest(&state, batch_request("bound-key", body.clone())).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(
            json["alerts_created"], 0,
            "alerts are created asynchronously"
        );
        assert_eq!(
            stored(&state),
            [
                ("e0123456789abcde".into(), "node-a".into()),
                ("plain".into(), "node-a".into())
            ]
        );
        let stats = state.ingest_hooks.stats();
        assert_eq!((stats.queued_batches, stats.queued_detections), (1, 2));
        let item = state.ingest_hooks.next().await;
        let payload: serde_json::Value = serde_json::from_slice(&item.body).unwrap();
        assert_eq!(payload["node_id"], "node-a");
        assert!(payload["received_at"].as_str().unwrap().ends_with("+00:00"));
        let ids: Vec<&str> = payload["detections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["detection_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["e0123456789abcde", "plain"]);
        assert_eq!(payload["detections"][0]["node_id"], "node-a");
        assert_eq!(payload["detections"][0]["signal_class"], "qpsk");
        assert_eq!(
            payload["decoded_messages"],
            serde_json::json!([{"protocol": "adsb", "icao": "a1b2c3",
                                "detection_id": "e0123456789abcde", "node_id": "node-a"}])
        );

        // The edge sends the batch again (its response was lost).
        let (status, json) = ingest(&state, batch_request("bound-key", body)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["inserted"], 0);
        assert_eq!(state.ingest_hooks.stats().queued_batches, 0);
    }

    #[tokio::test]
    async fn an_invalid_batch_id_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        let body = serde_json::json!({
            "node_id": "node-a", "batch_id": "x".repeat(500), "detections": [],
        });
        let (status, _) = ingest(&state, batch_request("bound-key", body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// W1 / K7b regression: an unbound VIEWER (dashboard) key was bound by
    /// the bridge to whatever node it first named — one already bound to
    /// another key included — and its forged batches were accepted. Only
    /// node keys (SENSOR/NODE) are bound on first use now: an unbound
    /// VIEWER key is refused, an unbound ANALYST key acts unbound, and
    /// neither makes a binding request.
    #[tokio::test]
    async fn only_node_keys_are_bound_on_first_use() {
        use std::time::Duration;
        let batch = |node: &str, id: &str| serde_json::json!({"node_id": node, "detections": [detection(id, None)]});
        let (url, seen) = bind_bridge(
            200,
            serde_json::json!({"node_id": "edge-01", "bound": true}),
            Duration::ZERO,
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_bridge(&dir, &url);

        let (status, json) = ingest(
            &state,
            batch_request_as("free-key", Role::Viewer, batch("edge-01", "v1")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{json}");
        assert_eq!(json["detail"], crate::ingest::binding::NOT_A_NODE_KEY);
        assert!(stored(&state).is_empty());
        assert!(state.ingest_hooks.stats().enqueued_batches == 0);

        // ANALYST: operator tooling — any node, never bound.
        let (status, json) = ingest(
            &state,
            batch_request_as("free-key", Role::Analyst, batch("edge-01", "a1")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let (status, _) = ingest(
            &state,
            batch_request_as("free-key", Role::Analyst, batch("edge-02", "a2")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(seen.lock().unwrap().is_empty(), "no binding request");

        // A VIEWER key an admin bound to a node acts for that node (K4).
        let (status, json) = ingest(
            &state,
            batch_request_as("bound-key", Role::Viewer, batch("node-a", "v2")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");

        // A node key is still bound on first use.
        let (status, json) = ingest(
            &state,
            batch_request_as("free-key", Role::Node, batch("edge-01", "n1")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert_eq!(
            stored(&state),
            [
                ("a1".into(), "edge-01".into()),
                ("a2".into(), "edge-02".into()),
                ("n1".into(), "edge-01".into()),
                ("v2".into(), "node-a".into()),
            ]
        );
    }

    /// K7b: a key named after a registered node is that node's key (the
    /// bridge's legacy rule) whatever its role, so the ANALYST and VIEWER
    /// shortcuts do not apply to it.
    #[tokio::test]
    async fn node_named_viewer_and_analyst_keys_keep_the_legacy_rule() {
        let batch = |node: &str, id: &str| serde_json::json!({"node_id": node, "detections": [detection(id, None)]});
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        std::fs::write(
            dir.path().join("nodes.json"),
            r#"{"nodes": {"edge-7": {"status": "online"}}}"#,
        )
        .unwrap();
        for role in [Role::Viewer, Role::Analyst] {
            let (status, json) = ingest(
                &state,
                batch_request_as("edge-7", role, batch("node-x", "x")),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{role}: {json}");
            assert_eq!(json["detail"], "API key is bound to node 'edge-7'");
        }
        let (status, json) = ingest(
            &state,
            batch_request_as("edge-7", Role::Viewer, batch("edge-7", "own")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(stored(&state), [("own".into(), "edge-7".into())]);
    }

    /// K7b: the first key to claim a node wins. The bridge's 409 naming the
    /// requested node itself (another key holds it) is refused with 403,
    /// and says what to do; a 403 "not a node key" from the bridge is a
    /// refusal too, not 503.
    #[tokio::test]
    async fn a_node_claimed_by_another_key_is_refused() {
        use std::time::Duration;
        let batch =
            serde_json::json!({"node_id": "edge-01", "detections": [detection("c1", None)]});
        let (url, _) = bind_bridge(
            409,
            serde_json::json!({"node_id": "edge-01", "detail": "node already has a bound key"}),
            Duration::ZERO,
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_bridge(&dir, &url);
        let (status, json) = ingest(&state, batch_request("free-key", batch.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{json}");
        let detail = json["detail"].as_str().unwrap();
        assert!(
            detail.contains("Node 'edge-01' already has a bound API key"),
            "{detail}"
        );
        assert!(stored(&state).is_empty());

        // GW5-R2 regression: the bridge's answer for a key it does not
        // consider a node key (its role changed since the gateway last
        // read keys.json) is a 409 naming the requested node. It read as
        // "another key holds the node".
        let bridge_answers = [
            (
                409,
                serde_json::json!({"node_id": "edge-01",
                                   "detail": crate::ingest::binding::NOT_A_NODE_KEY}),
            ),
            (
                403,
                serde_json::json!({"detail": crate::ingest::binding::NOT_A_NODE_KEY}),
            ),
        ];
        for (code, body) in bridge_answers {
            let (url, _) = bind_bridge(code, body, Duration::ZERO).await;
            let dir = tempfile::tempdir().unwrap();
            let state = state_with_bridge(&dir, &url);
            let (status, json) = ingest(&state, batch_request("free-key", batch.clone())).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{code}: {json}");
            assert_eq!(
                json,
                serde_json::json!({"detail": crate::ingest::binding::NOT_A_NODE_KEY}),
                "{code}"
            );
            assert!(stored(&state).is_empty());
        }
    }

    /// With BRIDGE_ALLOW_UNBOUND_NODE_KEYS set, unbound node keys act for
    /// any node without a binding request, but an unbound VIEWER key is
    /// still refused — the setting never makes a dashboard key a node
    /// credential, on the bridge (enforce_node_binding refuses it before
    /// looking at the setting) or here. The legacy node-named-key rule and
    /// existing bindings still apply.
    #[tokio::test]
    async fn the_unbound_keys_setting_covers_node_keys_but_never_viewer_keys() {
        let batch = |node: &str, id: &str| serde_json::json!({"node_id": node, "detections": [detection(id, None)]});
        let dir = tempfile::tempdir().unwrap();
        // The bridge is unreachable: no binding request may be needed.
        let Ok(mut unbound) = Arc::try_unwrap(state_with_bridge(&dir, "http://127.0.0.1:9")) else {
            unreachable!()
        };
        unbound.config.allow_unbound_node_keys = "1".into();
        let unbound = Arc::new(unbound);
        std::fs::write(
            dir.path().join("nodes.json"),
            r#"{"nodes": {"edge-7": {}}}"#,
        )
        .unwrap();
        for (node, id) in [("edge-01", "v1"), ("edge-02", "v2")] {
            let (status, json) = ingest(
                &unbound,
                batch_request_as("free-key", Role::Sensor, batch(node, id)),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{node}: {json}");
        }
        // An unbound VIEWER key is not a node credential, setting or not.
        let (status, json) = ingest(
            &unbound,
            batch_request_as("dashboard-key", Role::Viewer, batch("edge-01", "v5")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{json}");
        assert_eq!(json["detail"], "Node endpoints require a node API key");
        // Named after a registered node: that node's key only.
        let (status, json) = ingest(
            &unbound,
            batch_request_as("edge-7", Role::Sensor, batch("edge-01", "v3")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{json}");
        assert_eq!(json["detail"], "API key is bound to node 'edge-7'");
        // A key bound to a node stays bound.
        let (status, _) = ingest(
            &unbound,
            batch_request_as("bound-key", Role::Viewer, batch("edge-01", "v4")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            stored(&unbound),
            [
                ("v1".into(), "edge-01".into()),
                ("v2".into(), "edge-02".into())
            ]
        );
    }

    /// GW5-R4 regression: the bridge treats a key whose id starts with an
    /// edge prefix (`edge_`, `node_`, `sensor_`…) and that is stored as
    /// ANALYST or ADMIN as a NODE key (it downgrades it at load, without
    /// rewriting keys.json), so it binds it on first use. The gateway read
    /// the stored role, took the key for ANALYST operator tooling and
    /// accepted its batches for any node without asking the bridge: the
    /// forgery K7 closes. End to end through the auth middleware and the
    /// key store: the key is a node key, so the bridge is asked to bind it,
    /// and its refusal (another key holds the node) is a 403.
    #[tokio::test]
    async fn an_edge_named_key_stored_as_analyst_is_bound_like_a_node_key() {
        use crate::ws::test_harness as h;
        use std::time::Duration;
        let raw = "sk-edge-x-analyst-0123456789";
        let (url, seen) = bind_bridge(
            409,
            serde_json::json!({"node_id": "victim-node",
                               "detail": "node already has a bound key"}),
            Duration::ZERO,
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_bridge(&dir, &url);
        h::write_keys(
            &dir,
            &h::keys_file(&[h::key_entry("edge_x", raw, "analyst", false)]),
        );
        let routes =
            axum::Router::new().route("/api/detections/batch", axum::routing::post(ingest_batch));
        let addr = h::serve(Arc::clone(&state), routes).await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/api/detections/batch"))
            .header("x-api-key", raw)
            .json(&serde_json::json!({
                "node_id": "victim-node", "detections": [detection("forged", None)],
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            seen.lock().unwrap().clone(),
            [(
                "ingest-secret".to_string(),
                serde_json::json!({"key_id": "edge_x", "node_id": "victim-node"})
            )],
            "the bridge is asked to bind the key"
        );
        assert!(stored(&state).is_empty());
    }

    /// V12 / K10 regression: without a usable UC_PROXY_SECRET (allowed in
    /// development) the bridge refuses its internal API, so every first
    /// batch of an unbound node key got 503 and every hook was queued only
    /// to be refused. Now keys stay unbound (as with
    /// BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1) and hooks are only counted.
    #[tokio::test]
    async fn without_a_usable_proxy_secret_binding_and_hooks_are_skipped() {
        let batch = |node: &str, id: &str| serde_json::json!({"node_id": node, "detections": [detection(id, None)]});
        for secret in ["", "uppercrust-internal"] {
            let dir = tempfile::tempdir().unwrap();
            // The bridge is unreachable: no request may be needed.
            let Ok(mut no_secret) = Arc::try_unwrap(state(&dir)) else {
                unreachable!()
            };
            no_secret.config.proxy_secret = secret.into();
            let no_secret = Arc::new(no_secret);
            std::fs::write(
                dir.path().join("nodes.json"),
                r#"{"nodes": {"edge-7": {}}}"#,
            )
            .unwrap();

            let (status, json) =
                ingest(&no_secret, batch_request("free-key", batch("node-x", "k1"))).await;
            assert_eq!(status, StatusCode::OK, "{secret:?}: {json}");
            let (status, _) =
                ingest(&no_secret, batch_request("free-key", batch("node-y", "k2"))).await;
            assert_eq!(status, StatusCode::OK, "still unbound");
            // The legacy rule, bindings and the VIEWER refusal still apply.
            let (status, _) =
                ingest(&no_secret, batch_request("edge-7", batch("node-x", "k3"))).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            let (status, _) = ingest(
                &no_secret,
                batch_request("bound-key", batch("node-x", "k4")),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            let (status, _) = ingest(
                &no_secret,
                batch_request_as("free-key", Role::Viewer, batch("node-x", "k5")),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);

            let stats = no_secret.ingest_hooks.stats();
            assert_eq!(stats.enqueued_batches, 0, "{secret:?}");
            assert_eq!(stats.queued_batches, 0);
            assert_eq!(stats.hooks_disabled, 2);
            assert_eq!(
                stored(&no_secret),
                [
                    ("k1".into(), "node-x".into()),
                    ("k2".into(), "node-y".into())
                ]
            );
        }
    }

    /// K4: a key bound to a node acts for that node only, whatever its
    /// role — the binding is checked before the ADMIN and ANALYST
    /// shortcuts.
    #[tokio::test]
    async fn a_bound_key_is_held_to_its_node_whatever_its_role() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        let batch = |node: &str, id: &str| serde_json::json!({"node_id": node, "detections": [detection(id, None)]});
        for role in [Role::Analyst, Role::Admin, Role::Keymaster] {
            let (status, json) = ingest(
                &state,
                batch_request_as("bound-key", role, batch("node-b", "r")),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{role}: {json}");
            assert_eq!(
                json["detail"], "API key is bound to node 'node-a'",
                "{role}"
            );
            let id = format!("own-{role}");
            let (status, json) = ingest(
                &state,
                batch_request_as("bound-key", role, batch("node-a", &id)),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{role}: {json}");
        }
        assert!(stored(&state).iter().all(|(_, node)| node == "node-a"));
        assert_eq!(stored(&state).len(), 3);
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    /// [`batch_request`] with `body` sent as it is (gzip, garbage…).
    fn raw_request(key_id: &str, body: Vec<u8>) -> Request<Body> {
        let mut req = batch_request(key_id, serde_json::Value::Null);
        *req.body_mut() = Body::from(body);
        req
    }

    /// `state` with its config changed by `edit`.
    fn reconfigured(
        state: Arc<AppState>,
        edit: impl FnOnce(&mut crate::config::Config),
    ) -> Arc<AppState> {
        let Ok(mut state) = Arc::try_unwrap(state) else {
            unreachable!("fresh state has one owner")
        };
        edit(&mut state.config);
        Arc::new(state)
    }

    /// Gzip bomb protection: a gzip batch is inflated, but never past
    /// UC_MAX_DECOMPRESSED_SIZE, and a corrupt stream is refused — not
    /// half-parsed.
    #[tokio::test]
    async fn gzip_batches_are_inflated_within_the_decompressed_limit() {
        let dir = tempfile::tempdir().unwrap();
        let state = reconfigured(state(&dir), |c| c.max_decompressed_size = 4096);
        let batch = |id: &str| {
            serde_json::json!({"node_id": "node-a", "detections": [detection(id, None)]})
                .to_string()
                .into_bytes()
        };
        let (status, json) = ingest(&state, raw_request("bound-key", gzip(&batch("gz1")))).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["inserted"], 1, "{json}");

        // Valid JSON (trailing whitespace is allowed) that inflates past
        // the limit.
        let mut padded = batch("gz2");
        padded.resize(padded.len() + 8192, b' ');
        let (status, _) = ingest(&state, raw_request("bound-key", gzip(&padded))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // Truncated, and a gzip magic over garbage.
        let whole = gzip(&batch("gz3"));
        for corrupt in [
            whole[..whole.len() - 6].to_vec(),
            b"\x1f\x8b{\"node_id\"".to_vec(),
        ] {
            let (status, _) = ingest(&state, raw_request("bound-key", corrupt)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        assert_eq!(stored(&state), [("gz1".into(), "node-a".into())]);
    }

    /// UC_MAX_BODY_SIZE bounds the body the handler reads (before any
    /// inflation): 413, nothing stored.
    #[tokio::test]
    async fn an_oversized_body_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let state = reconfigured(state(&dir), |c| c.max_body_size = 512);
        let detections: Vec<_> = (0..8)
            .map(|i| detection(&format!("big{i}"), None))
            .collect();
        let body = serde_json::json!({"node_id": "node-a", "detections": detections});
        assert!(body.to_string().len() > 512);
        let (status, _) = ingest(&state, batch_request("bound-key", body)).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(stored(&state).is_empty());

        let small = serde_json::json!({"node_id": "node-a", "detections": [detection("s", None)]});
        assert!(small.to_string().len() <= 512);
        let (status, json) = ingest(&state, batch_request("bound-key", small)).await;
        assert_eq!(status, StatusCode::OK, "{json}");
    }

    /// A batch that is not JSON, or whose node_id is not
    /// `[A-Za-z0-9_-]{1,64}`, is refused before the credential is checked
    /// against the node: no binding request ever names such a node.
    #[tokio::test]
    async fn a_malformed_batch_or_node_id_is_refused_before_any_binding() {
        let (url, seen) = bind_bridge(
            200,
            serde_json::json!({"node_id": "node-x", "bound": true}),
            std::time::Duration::ZERO,
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let state = state_with_bridge(&dir, &url);
        for body in [&b"not json"[..], b"", b"[]", br#"{"detections": []}"#] {
            let (status, _) = ingest(&state, raw_request("free-key", body.to_vec())).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body:?}");
        }
        let long = "n".repeat(65);
        for node in [
            "",
            "../etc",
            "node-a/../x",
            "a b",
            "node\n",
            "nöde",
            "<b>",
            &long,
        ] {
            let body = serde_json::json!({"node_id": node, "detections": [detection("m", None)]});
            let (status, _) = ingest(&state, batch_request("free-key", body)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{node:?}");
        }
        assert!(seen.lock().unwrap().is_empty(), "no binding request");
        assert!(stored(&state).is_empty());

        // The same key, for a valid node id: bound through the bridge.
        let body = serde_json::json!({"node_id": "node-x", "detections": [detection("m", None)]});
        let (status, json) = ingest(&state, batch_request("free-key", body)).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    /// With authentication on, a request that resolves to no principal is
    /// refused (401) before its body is read: a gzip bomb from an
    /// anonymous client is never inflated (it would be a 400). Directly,
    /// and behind the auth middleware, which passes a request with no key
    /// or an unknown one on as unauthenticated.
    #[tokio::test]
    async fn an_unauthenticated_batch_is_refused_before_its_body_is_read() {
        use crate::ws::test_harness as h;
        let dir = tempfile::tempdir().unwrap();
        let state = reconfigured(state(&dir), |c| c.max_decompressed_size = 1024);
        // No legacy entries: an unknown key is looked up, not hashed.
        h::write_keys(&dir, &h::keys_file(&[]));
        let url = serve_ingest(&state).await;
        let client = reqwest::Client::new();
        let batch = serde_json::json!({"node_id": "node-a", "detections": [detection("u", None)]})
            .to_string()
            .into_bytes();
        let mut bomb = batch.clone();
        bomb.resize(1 << 20, b' ');
        for body in [batch, gzip(&bomb)] {
            let anonymous = Request::post("/api/detections/batch")
                .body(Body::from(body.clone()))
                .unwrap();
            let (status, _) = ingest(&state, anonymous).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            for key in [None, Some("sk-unknown")] {
                let mut req = client.post(&url).body(body.clone());
                if let Some(key) = key {
                    req = req.header("x-api-key", key);
                }
                let resp = req.send().await.unwrap();
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{key:?}");
            }
        }
        assert!(stored(&state).is_empty());
    }

    /// With authentication off (UC_ALLOW_NO_AUTH, development), batches
    /// are accepted for any node and no key is bound.
    #[tokio::test]
    async fn without_authentication_batches_are_accepted_unbound() {
        let (url, seen) = bind_bridge(
            200,
            serde_json::json!({"node_id": "node-x", "bound": true}),
            std::time::Duration::ZERO,
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let Ok(mut open) = Arc::try_unwrap(state_with_bridge(&dir, &url)) else {
            unreachable!()
        };
        open.auth_enabled = false;
        let open = Arc::new(open);
        for (node, id) in [("node-x", "o1"), ("node-y", "o2")] {
            let req = Request::post("/api/detections/batch")
                .body(Body::from(
                    serde_json::json!({"node_id": node, "detections": [detection(id, None)]})
                        .to_string(),
                ))
                .unwrap();
            let (status, json) = ingest(&open, req).await;
            assert_eq!(status, StatusCode::OK, "{json}");
        }
        assert!(seen.lock().unwrap().is_empty());
        assert_eq!(
            stored(&open),
            [
                ("o1".into(), "node-x".into()),
                ("o2".into(), "node-y".into())
            ]
        );
    }

    /// The IQ placeholder upgrade stays within the tenant: a placeholder
    /// another tenant stored under the same detection id is left alone,
    /// and nothing is hooked for it.
    #[tokio::test]
    async fn a_batch_never_upgrades_another_tenants_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch(
                "INSERT INTO detections (detection_id, node_id, timestamp, signal_class,
                     confidence, anomaly_score, has_iq_capture, tenant_id) VALUES
                 ('d-acme', 'node-a', '2026-11-05T09:59:59+00:00', 'iq_capture', 0, 0, 1, 'acme');",
            )
            .unwrap();
        let body =
            serde_json::json!({"node_id": "node-a", "detections": [detection("d-acme", None)]});
        let (status, json) = ingest(&state, batch_request("bound-key", body)).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["inserted"], 0, "{json}");
        let row: (String, f64, String) = state
            .db_pool
            .get()
            .unwrap()
            .query_row(
                "SELECT signal_class, confidence, tenant_id FROM detections \
                 WHERE detection_id = 'd-acme'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(row, ("iq_capture".into(), 0.0, "acme".into()));
        assert_eq!(state.ingest_hooks.stats().enqueued_detections, 0);
    }

    /// Numbers out of range (the baselines and the scorer take them as
    /// they are) and backend names that are not `[A-Za-z0-9_-]{1,32}`
    /// never reach storage.
    #[tokio::test]
    async fn out_of_range_numbers_and_bad_backends_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        let with = |id: &str, field: &str, value: serde_json::Value| {
            let mut d = detection(id, None);
            d[field] = value;
            d
        };
        let body = serde_json::json!({"node_id": "node-a", "detections": [
            with("f1", "freq_hz", (-1.0).into()),
            with("f2", "freq_hz", 2e12.into()),
            with("m1", "power_dbm", 1e300.into()),
            with("m2", "bandwidth_hz", (-2e12).into()),
            with("m3", "inference_ms", 1e13.into()),
            with("b1", "backend", "onnx; rm -rf".into()),
            with("b2", "backend", "x".repeat(33).into()),
            with("ok", "backend", "onnx".into()),
        ]});
        let (status, json) = ingest(&state, batch_request("bound-key", body)).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(
            json["rejected_reasons"],
            serde_json::json!({"invalid_frequency": 2, "invalid_measurement": 3,
                               "invalid_backend": 2})
        );
        assert_eq!(
            (json["total"].as_u64(), json["inserted"].as_u64()),
            (Some(8), Some(1))
        );
        assert_eq!(stored(&state), [("ok".into(), "node-a".into())]);
    }

    // ── Through the auth middleware ───────────────────────────────────

    /// The raw key ws::feed's tests use too: the harness hashes it once.
    const SENSOR_KEY: &str = "sk-sensor";

    /// keys.json with the SENSOR key `sensor-1` ([`SENSOR_KEY`]) bound to
    /// `node-a`, of `tenant` when given.
    fn sensor_keys(tenant: Option<&str>) -> String {
        use crate::ws::test_harness as h;
        let mut keys: serde_json::Value = serde_json::from_str(&h::keys_file(&[h::key_entry(
            "sensor-1", SENSOR_KEY, "sensor", false,
        )]))
        .unwrap();
        keys["keys"]["sensor-1"]["node_id"] = "node-a".into();
        if let Some(tenant) = tenant {
            keys["keys"]["sensor-1"]["tenant_id"] = tenant.into();
        }
        keys.to_string()
    }

    /// The ingest route behind the auth middleware, on a loopback port.
    async fn serve_ingest(state: &Arc<AppState>) -> String {
        let routes =
            axum::Router::new().route("/api/detections/batch", axum::routing::post(ingest_batch));
        let addr = crate::ws::test_harness::serve(Arc::clone(state), routes).await;
        format!("http://{addr}/api/detections/batch")
    }

    /// K4 end to end: a key's binding holds however the key is presented.
    /// A key that is not sent as X-API-Key (a Bearer token, `?api_key=`)
    /// is still a key, not taken for a client certificate, whose
    /// identity rule would decide instead.
    #[tokio::test]
    async fn a_bound_key_stays_bound_however_it_is_presented() {
        use crate::ws::test_harness as h;
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        h::write_keys(&dir, &sensor_keys(None));
        let url = serve_ingest(&state).await;
        let client = reqwest::Client::new();
        let send = |how: &str, node: &str, id: &str| {
            let body = serde_json::json!({"node_id": node, "detections": [detection(id, None)]});
            let req = match how {
                "header" => client.post(&url).header("x-api-key", SENSOR_KEY),
                "bearer" => client.post(&url).bearer_auth(SENSOR_KEY),
                _ => client.post(format!("{url}?api_key={SENSOR_KEY}")),
            };
            req.json(&body).send()
        };
        for how in ["header", "bearer", "query"] {
            let resp = send(how, "node-b", &format!("{how}-b")).await.unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{how}");
            let json: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(json["detail"], "API key is bound to node 'node-a'", "{how}");
            let resp = send(how, "node-a", &format!("{how}-a")).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{how}");
        }
        assert_eq!(
            stored(&state),
            [
                ("bearer-a".into(), "node-a".into()),
                ("header-a".into(), "node-a".into()),
                ("query-a".into(), "node-a".into()),
            ]
        );
    }

    /// The tenant boundary holds for ingest: a key of another tenant
    /// cannot submit, not even for the node it is bound to, nor can an
    /// ANALYST session of another tenant (one of this instance's tenant
    /// may submit for any node).
    #[tokio::test]
    async fn a_foreign_tenant_credential_cannot_submit_batches() {
        use crate::ws::test_harness as h;
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        h::write_keys(&dir, &sensor_keys(Some("other")));
        let url = serve_ingest(&state).await;
        let client = reqwest::Client::new();
        let batch = |node: &str, id: &str| serde_json::json!({"node_id": node, "detections": [detection(id, None)]});

        let resp = client
            .post(&url)
            .header("x-api-key", SENSOR_KEY)
            .json(&batch("node-a", "t-key"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let local = h::session_for(&state, "local-analyst", "analyst");
        let foreign = h::session_for(&state, "foreign-analyst", "analyst");
        state
            .db_pool
            .get()
            .unwrap()
            .execute(
                "UPDATE users SET tenant_id = 'other' WHERE username = 'foreign-analyst'",
                [],
            )
            .unwrap();
        for (token, id, expected) in [
            (&foreign, "t-foreign", StatusCode::FORBIDDEN),
            (&local, "t-local", StatusCode::OK),
        ] {
            let resp = client
                .post(&url)
                .bearer_auth(token)
                .json(&batch("node-x", id))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), expected, "{id}");
        }
        assert_eq!(stored(&state), [("t-local".into(), "node-x".into())]);
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use crate::ingest::validate::MAX_FUTURE_SKEW;
    use crate::test_support;
    use axum::body::Body;
    use axum::http::Request;

    /// The bridge tables ingest writes, as `ingest_tests` creates them.
    const INGEST_SCHEMA: &str = "
        CREATE TABLE detections (
            detection_id TEXT PRIMARY KEY, node_id TEXT, timestamp TEXT, signal_class TEXT,
            confidence REAL, family TEXT, freq_hz REAL, snr_db REAL, power_dbm REAL,
            inference_ms REAL, backend TEXT, anomaly_score REAL, baseline_status TEXT,
            has_iq_capture INTEGER, gain_db REAL, lna_state TEXT, bandwidth_hz REAL,
            tenant_id TEXT);
        CREATE TABLE rf_anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT, detection_id TEXT, signal_class TEXT,
            family TEXT, freq_hz REAL, dedup_key TEXT, node_id TEXT, timestamp TEXT,
            confidence REAL, snr_db REAL, power_dbm REAL, anomaly_score REAL, priority TEXT,
            dimensions TEXT, reasons TEXT, baseline_status TEXT, has_iq_capture INTEGER,
            seen_count INTEGER, first_seen TEXT, tenant_id TEXT, dismissed INTEGER DEFAULT 0);
        CREATE TABLE fhss_events (
            fhss_id TEXT PRIMARY KEY, node_id TEXT, timestamp TEXT, hop_rate_hz REAL,
            hop_set TEXT, bandwidth_hz REAL, dwell_time_ms REAL, duration_sec REAL,
            signal_class TEXT, detection_count INTEGER, confidence REAL, tenant_id TEXT);";

    /// The time of the detections here, taken once per test: half the
    /// clock skew ingest allows ahead of now, so the ones a test stores are
    /// accepted and stay among the recent detections the correlation looks
    /// at (those of the last 10 s) for minutes, however slow the machine.
    fn soon() -> String {
        (chrono::Utc::now() + MAX_FUTURE_SKEW / 2).to_rfc3339()
    }

    /// A state without authentication (every batch is accepted unbound)
    /// whose database holds the ingest tables.
    fn state(dir: &tempfile::TempDir) -> Arc<AppState> {
        let state = test_support::app_state(dir);
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch(INGEST_SCHEMA)
            .unwrap();
        state
    }

    fn detection(id: &str, class: &str, freq_hz: f64, timestamp: &str) -> serde_json::Value {
        serde_json::json!({
            "detection_id": id, "signal_class": class, "confidence": 0.9,
            "freq_hz": freq_hz, "snr_db": 12.0, "power_dbm": -60.0, "timestamp": timestamp,
        })
    }

    /// Three detections of `prefix` hopping over three channels within a
    /// second: a frequency-hopping signal.
    fn hops(prefix: &str) -> Vec<serde_json::Value> {
        [
            (433_920_000.0, "2026-11-05T10:00:00.000+00:00"),
            (434_120_000.0, "2026-11-05T10:00:00.300+00:00"),
            (434_320_000.0, "2026-11-05T10:00:00.600+00:00"),
        ]
        .iter()
        .enumerate()
        .map(|(i, (freq, ts))| detection(&format!("{prefix}{i}"), "qpsk", *freq, ts))
        .collect()
    }

    fn batch(node: &str, detections: Vec<serde_json::Value>) -> Request<Body> {
        let body = serde_json::json!({"node_id": node, "detections": detections});
        Request::post("/api/detections/batch")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn ingest(state: &Arc<AppState>, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let resp = ingest_batch(State(state.clone()), req)
            .await
            .into_response();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    /// The first column of every row `sql` selects, as text.
    fn column(state: &AppState, sql: &str) -> Vec<String> {
        let conn = state.db_pool.get().unwrap();
        let mut stmt = conn.prepare(sql).unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    /// A pool that never hands out a connection.
    fn unavailable_pool(dir: &tempfile::TempDir) -> crate::db::pool::DbPool {
        let manager = crate::db::manager::SqliteConnectionManager::file(
            dir.path().join("missing").join("detections.db"),
        )
        .with_flags(rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE);
        r2d2::Pool::builder()
            .max_size(1)
            .min_idle(Some(0))
            .connection_timeout(std::time::Duration::from_millis(50))
            .build_unchecked(manager)
    }

    /// A detection that scores at or above 0.3 (here a signal class the
    /// class map does not know, which is raised for review) is stored as
    /// an RF anomaly and broadcast on the anomaly feed; an ordinary
    /// detection of the same batch is neither. An anomaly that cannot be
    /// stored does not cost the batch its detections.
    #[tokio::test]
    async fn an_anomalous_detection_is_stored_and_broadcast_as_an_rf_anomaly() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        let t0 = soon();
        let mut feed = state.anomaly_tx.subscribe();
        let (status, json) = ingest(
            &state,
            batch(
                "node-a",
                vec![
                    detection("plain", "qpsk", 433_920_000.0, &t0),
                    detection("odd", "mystery_burst", 868_000_000.0, &t0),
                ],
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["inserted"], 2, "{json}");
        assert_eq!(
            column(&state, "SELECT detection_id FROM rf_anomalies"),
            ["odd"]
        );
        let announced: serde_json::Value = serde_json::from_str(&feed.try_recv().unwrap()).unwrap();
        assert_eq!(announced["detection_id"], "odd");
        assert_eq!(announced["node_id"], "node-a");
        assert!(
            announced["anomaly_score"].as_f64().unwrap() >= 0.3,
            "{announced}"
        );
        assert!(feed.try_recv().is_err(), "one anomaly only");

        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch("DROP TABLE rf_anomalies")
            .unwrap();
        let (status, json) = ingest(
            &state,
            batch(
                "node-a",
                vec![detection("odd-2", "mystery_burst", 868_000_000.0, &t0)],
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["inserted"], 1, "{json}");
        assert_eq!(
            column(
                &state,
                "SELECT detection_id FROM detections ORDER BY detection_id"
            ),
            ["odd", "odd-2", "plain"]
        );
    }

    /// Detections of one node hopping over three channels within a second
    /// are stored as one FHSS event of that node, and counted in the
    /// response. An event that cannot be stored does not cost the batch its
    /// detections.
    #[tokio::test]
    async fn a_hopping_signal_is_stored_as_an_fhss_event() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        let (status, json) = ingest(&state, batch("node-a", hops("h"))).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(
            (json["inserted"].as_u64(), json["fhss_events"].as_u64()),
            (Some(3), Some(1))
        );
        assert_eq!(
            column(&state, "SELECT node_id FROM fhss_events"),
            ["node-a"]
        );

        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch("DROP TABLE fhss_events")
            .unwrap();
        let (status, json) = ingest(&state, batch("node-a", hops("g"))).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["inserted"], 3, "{json}");
        assert_eq!(
            column(
                &state,
                "SELECT detection_id FROM detections WHERE detection_id LIKE 'g%' ORDER BY 1"
            ),
            ["g0", "g1", "g2"]
        );
    }

    /// The same signal (class and channel) reported by a second node while
    /// the first node's report is recent is counted as a correlation; the
    /// first report, and one on another channel, correlate with nothing.
    #[tokio::test]
    async fn the_same_signal_on_two_nodes_is_counted_as_correlated() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        let t0 = soon();
        let mut correlations = Vec::new();
        for (node, id, freq) in [
            ("node-a", "c-a", 433_920_000.0),
            ("node-b", "c-b", 433_920_000.0),
            ("node-c", "c-c", 915_000_000.0),
        ] {
            let (status, json) =
                ingest(&state, batch(node, vec![detection(id, "qpsk", freq, &t0)])).await;
            assert_eq!(status, StatusCode::OK, "{node}: {json}");
            correlations.push(json["correlation_count"].as_u64().unwrap());
        }
        assert_eq!(correlations, [0, 1, 0]);
    }

    /// A detection dated more than [`MAX_FUTURE_SKEW`] ahead is dropped on
    /// its own and counted, like any other invalid field; one dated within
    /// it, or in the past, is stored. Were they stored, 500 detections of
    /// one node dated in 2099 would stay the newest of the recent
    /// detections the correlation reads (at most 500) for good, and no
    /// other node's report would correlate again.
    #[tokio::test]
    async fn detections_dated_too_far_ahead_are_refused_and_cannot_crowd_out_correlation() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        let t0 = soon();
        let late = (chrono::Utc::now() + MAX_FUTURE_SKEW * 2).to_rfc3339();
        let mut detections: Vec<_> = (0..500)
            .map(|i| {
                let freq = 100_000_000.0 + f64::from(i) * 1e6;
                detection(&format!("f{i}"), "qpsk", freq, "2099-01-01T00:00:00+00:00")
            })
            .collect();
        detections.extend([
            detection("late", "qpsk", 99_000_000.0, &late),
            detection("past", "qpsk", 99_000_000.0, "2026-11-05T10:00:00+00:00"),
            detection("soon", "qpsk", 99_000_000.0, &t0),
        ]);
        let (status, json) = ingest(&state, batch("node-x", detections)).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(
            (json["inserted"].as_u64(), json["rejected"].as_u64()),
            (Some(2), Some(501)),
            "{json}"
        );
        assert_eq!(
            json["rejected_reasons"],
            serde_json::json!({"future_timestamp": 501})
        );
        assert_eq!(
            column(&state, "SELECT detection_id FROM detections ORDER BY 1"),
            ["past", "soon"]
        );

        let mut correlations = Vec::new();
        for (node, id) in [("node-a", "c-a"), ("node-b", "c-b")] {
            let req = batch(node, vec![detection(id, "qpsk", 433_920_000.0, &t0)]);
            let (status, json) = ingest(&state, req).await;
            assert_eq!(status, StatusCode::OK, "{node}: {json}");
            correlations.push(json["correlation_count"].as_u64().unwrap());
        }
        assert_eq!(correlations, [0, 1]);
    }

    /// A batch whose detections cannot be stored is refused with 500, and
    /// nothing is announced for it: no detection on the live feed, no
    /// post-ingest hook queued or counted.
    #[tokio::test]
    async fn a_batch_that_cannot_be_stored_is_a_500_and_announces_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        state
            .db_pool
            .get()
            .unwrap()
            .execute_batch("DROP TABLE detections")
            .unwrap();
        let mut feed = state.detection_tx.subscribe();
        let (status, json) = ingest(
            &state,
            batch(
                "node-a",
                vec![detection("lost", "qpsk", 433_920_000.0, &soon())],
            ),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{json}");
        assert!(
            feed.try_recv().is_err(),
            "a detection that was not stored was announced"
        );
        let hooks = state.ingest_hooks.stats();
        assert_eq!(
            (
                hooks.queued_batches,
                hooks.enqueued_batches,
                hooks.hooks_disabled
            ),
            (0, 0, 0)
        );
    }

    /// A timestamp whose hour is not a number is learned at the current
    /// UTC hour (read before and after, so an hour boundary in between
    /// cannot fail the test).
    #[test]
    fn a_timestamp_without_a_numeric_hour_counts_at_the_current_hour() {
        let now = || {
            chrono::Utc::now()
                .format("%H")
                .to_string()
                .parse::<u8>()
                .unwrap()
        };
        let before = now();
        let hour = extract_hour("2026-01-15Tab:30:00Z");
        let after = now();
        assert!(
            hour == before || hour == after,
            "{hour} is neither {before} nor {after}"
        );
    }

    /// Without a database connection a batch is refused with 500 at the
    /// first store it needs (anomaly, FHSS event or detections), and
    /// nothing is announced on the detection or anomaly feeds.
    #[tokio::test]
    async fn without_a_database_connection_batches_are_refused_with_500() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = test_support::app_state(&dir);
        Arc::get_mut(&mut state).unwrap().db_pool = unavailable_pool(&dir);
        let mut detections = state.detection_tx.subscribe();
        let mut anomalies = state.anomaly_tx.subscribe();
        let t0 = soon();
        for batch_detections in [
            vec![detection("plain", "qpsk", 433_920_000.0, &t0)],
            hops("h"),
            vec![detection("odd", "mystery_burst", 868_000_000.0, &t0)],
        ] {
            let (status, json) = ingest(&state, batch("node-a", batch_detections)).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{json}");
        }
        assert!(detections.try_recv().is_err());
        assert!(anomalies.try_recv().is_err());
    }

    /// Detections refused by validation are logged with the batch, the node
    /// and the reasons (counted), never with the refused values: a
    /// detection id carrying a line break and a forged log line does not
    /// reach the gateway's log. The rest of the batch is stored and logged
    /// as ingested, with its counts.
    #[test]
    fn a_partly_refused_batch_logs_reasons_not_the_refused_values() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(&dir);
        let forged = "x\n2026-11-18T00:00:00Z ERROR forged-log-line";
        let t0 = soon();
        let body = serde_json::json!({
            "node_id": "node-a",
            "batch_id": "batch-42",
            "detections": [
                detection(forged, "qpsk", 433_920_000.0, &t0),
                detection("kept", "qpsk", 433_920_000.0, &t0),
            ],
        });
        let req = Request::post("/api/detections/batch")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let ((status, json), logs) = test_support::logs_of(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(ingest(&state, req))
        });
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(
            (json["inserted"].as_u64(), json["rejected"].as_u64()),
            (Some(1), Some(1)),
            "{json}"
        );
        assert_eq!(json["rejected_reasons"]["invalid_detection_id"], 1);
        assert_eq!(
            column(&state, "SELECT detection_id FROM detections"),
            ["kept"]
        );

        let refused: Vec<&str> = logs
            .lines()
            .filter(|l| l.contains("Detections rejected by validation"))
            .collect();
        assert_eq!(refused.len(), 1, "{logs}");
        for named in [
            " WARN ",
            "batch_id=batch-42",
            "node_id=node-a",
            "rejected=1",
            "invalid_detection_id",
        ] {
            assert!(refused[0].contains(named), "{named:?} missing: {logs}");
        }
        assert!(!logs.contains("forged-log-line"), "{logs}");
        let ingested: Vec<&str> = logs
            .lines()
            .filter(|l| l.contains("Batch ingested"))
            .collect();
        assert_eq!(ingested.len(), 1, "{logs}");
        for named in ["batch_id=batch-42", "inserted=1", "total=2", "fhss=0"] {
            assert!(ingested[0].contains(named), "{named:?} missing: {logs}");
        }
    }
}
