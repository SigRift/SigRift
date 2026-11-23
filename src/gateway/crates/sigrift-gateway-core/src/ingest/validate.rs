//! Input validation and gzip decompression.
//!
//! Ingest validates every detection of a batch, not only the batch: field
//! values end up in the database, on the dashboard and on the WebSocket
//! feeds, and in the anomaly baselines. A detection that fails is dropped
//! on its own and counted (see [`partition_detections`]); the rest of the
//! batch is still ingested. The rules mirror the bridge's models
//! (`sigrift/bridge/models.py`, `_validate_id`), plus length bounds on the
//! free-text fields the bridge leaves unbounded and a bound on how far
//! ahead of the gateway's clock a detection may be dated
//! ([`MAX_FUTURE_SKEW`]), which the bridge does not check.

use bytes::Bytes;
use flate2::read::GzDecoder;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Read;

use crate::models::detection::DetectionRecord;

/// Check if data starts with gzip magic bytes.
pub fn is_gzip(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

/// Decompress gzip data with bomb protection.
pub fn decompress_gzip(
    data: &[u8],
    max_decompressed_size: usize,
) -> Result<Bytes, DecompressError> {
    let mut decoder = GzDecoder::new(data);
    let mut buf = Vec::with_capacity(data.len().min(65536));
    let mut total = 0usize;

    loop {
        let mut chunk = [0u8; 8192];
        match decoder.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if total > max_decompressed_size {
                    return Err(DecompressError::TooLarge(max_decompressed_size));
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(e) => return Err(DecompressError::Io(e.to_string())),
        }
    }

    Ok(Bytes::from(buf))
}

#[derive(Debug)]
pub enum DecompressError {
    TooLarge(usize),
    Io(String),
}

impl std::fmt::Display for DecompressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecompressError::TooLarge(max) => write!(f, "Decompressed data exceeds {} bytes", max),
            DecompressError::Io(e) => write!(f, "Decompression error: {}", e),
        }
    }
}

/// True if `s` is 1..=`max` bytes, all ASCII alphanumerics or one of `extra`.
fn ascii_token(s: &str, max: usize, extra: &[u8]) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}

/// Validate a node_id: `[A-Za-z0-9_-]{1,64}` (the bridge's `_validate_id`).
pub fn validate_node_id(node_id: &str) -> bool {
    ascii_token(node_id, 64, b"-_")
}

/// Validate a signal_class: `[A-Za-z0-9_/.-]{1,128}` (the bridge's
/// `_SIGNAL_CLASS_PATTERN`).
pub fn validate_signal_class(signal_class: &str) -> bool {
    ascii_token(signal_class, 128, b"-_/.")
}

/// Validate a detection or batch id: `[A-Za-z0-9_.:-]{1,128}`, no `..`
/// (ids appear in URL paths such as `/api/detections/{id}/iq`).
pub fn validate_record_id(id: &str) -> bool {
    ascii_token(id, 128, b"-_.:") && !id.contains("..")
}

/// Validate a `backend` name: `[A-Za-z0-9_-]{1,32}` (the bridge's
/// `_BACKEND_PATTERN`).
pub fn validate_backend(backend: &str) -> bool {
    ascii_token(backend, 32, b"-_")
}

/// Short free text (e.g. `lna_state`): at most 64 characters, no control
/// characters.
fn validate_short_text(s: &str) -> bool {
    s.chars().count() <= 64 && !s.chars().any(char::is_control)
}

/// How far ahead of the gateway's clock a detection may be dated. Edges
/// date a detection when they capture it, so a later time comes from a
/// clock ahead of the gateway's; this allows the 5 minutes of clock skew
/// between hosts that the bridge's CA allows for (`_BACKDATE` in
/// `sigrift/bridge/ca.py`). Unbounded, a detection dated in the future
/// stays among the recent detections the correlation reads (newest
/// first, at most 500; `db::detections::get_recent`) until it is purged,
/// and enough of them crowd out every real one.
pub const MAX_FUTURE_SKEW: chrono::Duration = chrono::Duration::minutes(5);

/// The instant of a timestamp [`validate_timestamp`] accepts.
fn parse_timestamp(ts: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    if ts.len() > 64 {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(ts)
        .or_else(|_| chrono::DateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S%.f%z"))
        .map(|t| t.to_utc())
        .ok()
        .or_else(|| {
            ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"]
                .iter()
                .find_map(|fmt| chrono::NaiveDateTime::parse_from_str(ts, fmt).ok())
                .map(|t| t.and_utc())
        })
}

/// A detection timestamp: RFC 3339, or ISO 8601 without an offset (UTC),
/// at most 64 bytes. Numeric timestamps were already converted to RFC 3339
/// when the batch was parsed.
pub fn validate_timestamp(ts: &str) -> bool {
    parse_timestamp(ts).is_some()
}

/// Check a detection timestamp as of `now`: it must parse, and be at most
/// [`MAX_FUTURE_SKEW`] ahead of `now`. Any time in the past is accepted.
pub fn check_timestamp(ts: &str, now: chrono::DateTime<chrono::Utc>) -> Result<(), Rejection> {
    match parse_timestamp(ts) {
        None => Err(Rejection::InvalidTimestamp),
        Some(t) if t - now > MAX_FUTURE_SKEW => Err(Rejection::FutureTimestamp),
        Some(_) => Ok(()),
    }
}

/// Largest magnitude accepted for a numeric detection field.
const MAX_ABS_NUMBER: f64 = 1e12;

fn sane_number(v: f64) -> bool {
    v.is_finite() && v.abs() <= MAX_ABS_NUMBER
}

/// Why one detection of a batch was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Rejection {
    /// `node_id` differs from the batch's `node_id`.
    NodeMismatch,
    InvalidSignalClass,
    InvalidDetectionId,
    InvalidTimestamp,
    /// `timestamp` more than [`MAX_FUTURE_SKEW`] ahead of the gateway's
    /// clock.
    FutureTimestamp,
    InvalidConfidence,
    InvalidFrequency,
    InvalidMeasurement,
    InvalidBackend,
    InvalidLnaState,
}

impl Rejection {
    pub fn as_str(self) -> &'static str {
        match self {
            Rejection::NodeMismatch => "node_mismatch",
            Rejection::InvalidSignalClass => "invalid_signal_class",
            Rejection::InvalidDetectionId => "invalid_detection_id",
            Rejection::InvalidTimestamp => "invalid_timestamp",
            Rejection::FutureTimestamp => "future_timestamp",
            Rejection::InvalidConfidence => "invalid_confidence",
            Rejection::InvalidFrequency => "invalid_frequency",
            Rejection::InvalidMeasurement => "invalid_measurement",
            Rejection::InvalidBackend => "invalid_backend",
            Rejection::InvalidLnaState => "invalid_lna_state",
        }
    }
}

/// Check one detection of a batch from `batch_node_id`. An empty `node_id`
/// is filled in from the batch; any other must equal it, so a sensor can
/// only report detections for the node the batch is for.
pub fn validate_detection(det: &mut DetectionRecord, batch_node_id: &str) -> Result<(), Rejection> {
    det.adopt_edge_id();
    if det.node_id.is_empty() {
        det.node_id = batch_node_id.to_string();
    } else if det.node_id != batch_node_id {
        return Err(Rejection::NodeMismatch);
    }
    if !validate_signal_class(&det.signal_class) {
        return Err(Rejection::InvalidSignalClass);
    }
    if !det.detection_id.is_empty() && !validate_record_id(&det.detection_id) {
        return Err(Rejection::InvalidDetectionId);
    }
    check_timestamp(&det.timestamp, chrono::Utc::now())?;
    if !(det.confidence.is_finite() && (0.0..=1.0).contains(&det.confidence)) {
        return Err(Rejection::InvalidConfidence);
    }
    if !(det.freq_hz.is_finite() && (0.0..=MAX_ABS_NUMBER).contains(&det.freq_hz)) {
        return Err(Rejection::InvalidFrequency);
    }
    let measurements = [
        det.snr_db,
        det.power_dbm,
        det.inference_ms,
        det.gain_db,
        det.bandwidth_hz,
    ];
    if measurements.iter().flatten().any(|v| !sane_number(*v)) {
        return Err(Rejection::InvalidMeasurement);
    }
    if det.backend.as_deref().is_some_and(|b| !validate_backend(b)) {
        return Err(Rejection::InvalidBackend);
    }
    if det
        .lna_state
        .as_deref()
        .is_some_and(|s| !validate_short_text(s))
    {
        return Err(Rejection::InvalidLnaState);
    }
    Ok(())
}

/// Detections that passed [`validate_detection`], and a count of the rest
/// by reason.
pub struct Partitioned {
    pub accepted: Vec<DetectionRecord>,
    pub rejected: BTreeMap<&'static str, usize>,
}

impl Partitioned {
    pub fn rejected_total(&self) -> usize {
        self.rejected.values().sum()
    }
}

/// Split a batch's detections into valid ones and per-reason reject counts.
pub fn partition_detections(detections: Vec<DetectionRecord>, batch_node_id: &str) -> Partitioned {
    let mut out = Partitioned {
        accepted: Vec::with_capacity(detections.len()),
        rejected: BTreeMap::new(),
    };
    for mut det in detections {
        match validate_detection(&mut det, batch_node_id) {
            Ok(()) => out.accepted.push(det),
            Err(reason) => *out.rejected.entry(reason.as_str()).or_insert(0) += 1,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det(node: &str) -> DetectionRecord {
        serde_json::from_value(serde_json::json!({
            "detection_id": "abc123", "node_id": node, "signal_class": "lora-css",
            "confidence": 0.5, "freq_hz": 868e6, "timestamp": 1_762_336_800.25,
        }))
        .unwrap()
    }

    #[test]
    fn ids_follow_the_bridge_patterns() {
        assert!(validate_node_id("edge-01_a"));
        assert!(!validate_node_id(""));
        assert!(!validate_node_id(&"n".repeat(65)));
        assert!(!validate_node_id("nöde"), "ASCII only, like the bridge");
        assert!(!validate_node_id("a b"));
        // The bridge's `$`-anchored patterns used to let a trailing newline
        // through; both sides now refuse it.
        for id in ["edge-01\n", "\nedge-01", "edge-01\r\n"] {
            assert!(!validate_node_id(id), "{id:?}");
        }
        assert!(!validate_signal_class("lora-css\n"));
        assert!(!validate_backend("onnx\n"));

        assert!(validate_signal_class("wifi/802.11ac"));
        assert!(validate_signal_class(&"c".repeat(128)));
        assert!(!validate_signal_class(&"c".repeat(129)));
        assert!(!validate_signal_class("<script>"));

        assert!(validate_record_id("0123456789abcdef"));
        assert!(validate_record_id("node-1:42.7"));
        assert!(!validate_record_id("../x"));
        assert!(!validate_record_id("a/b"));
        assert!(!validate_record_id(&"i".repeat(129)));

        assert!(validate_backend("onnx"));
        assert!(!validate_backend("on nx"));
    }

    #[test]
    fn timestamps_must_parse() {
        for ok in [
            "2026-11-05T10:00:00+00:00",
            "2026-11-05T10:00:00.123456Z",
            "2026-11-05T10:00:00.5+0000",
            "2026-11-05T10:00:00",
            "2026-11-05 10:00:00.25",
        ] {
            assert!(validate_timestamp(ok), "{ok}");
        }
        for bad in ["", "yesterday", "2026-13-45T99:00:00Z", &"9".repeat(65)] {
            assert!(!validate_timestamp(bad), "{bad}");
        }
    }

    /// A detection may be dated up to [`MAX_FUTURE_SKEW`] ahead of the
    /// gateway's clock and no further: the instant counts, whatever offset
    /// it is written with. Any time in the past is accepted.
    #[test]
    fn a_timestamp_may_be_at_most_max_future_skew_ahead() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-11-18T12:00:00Z")
            .unwrap()
            .to_utc();
        let bound = now + MAX_FUTURE_SKEW;
        assert_eq!(bound.to_rfc3339(), "2026-11-18T12:05:00+00:00");
        for ok in [
            bound.to_rfc3339(),
            "2026-11-18T12:05:00".into(),
            "2026-11-18T14:05:00+02:00".into(),
            now.to_rfc3339(),
            "2026-11-05T10:00:00+00:00".into(),
            "1970-01-01T00:00:00Z".into(),
        ] {
            assert_eq!(check_timestamp(&ok, now), Ok(()), "{ok}");
        }
        for ahead in [
            (bound + chrono::Duration::microseconds(1)).to_rfc3339(),
            "2026-11-18 12:05:01".into(),
            "2026-11-18T07:05:01-05:00".into(),
            "2099-01-01T00:00:00+00:00".into(),
        ] {
            assert_eq!(
                check_timestamp(&ahead, now),
                Err(Rejection::FutureTimestamp),
                "{ahead}"
            );
        }
        assert_eq!(
            check_timestamp("yesterday", now),
            Err(Rejection::InvalidTimestamp)
        );
    }

    #[test]
    fn a_valid_detection_passes_and_an_empty_node_is_filled() {
        let mut d = det("");
        assert_eq!(validate_detection(&mut d, "node-a"), Ok(()));
        assert_eq!(d.node_id, "node-a");
        let mut d = det("node-a");
        assert_eq!(validate_detection(&mut d, "node-a"), Ok(()));
    }

    #[test]
    fn each_rule_rejects() {
        type Mutation = fn(&mut DetectionRecord);
        let cases: Vec<(Mutation, Rejection)> = vec![
            (|d| d.node_id = "node-b".into(), Rejection::NodeMismatch),
            (
                |d| d.signal_class = String::new(),
                Rejection::InvalidSignalClass,
            ),
            (
                |d| d.detection_id = "a b".into(),
                Rejection::InvalidDetectionId,
            ),
            (|d| d.timestamp = "now".into(), Rejection::InvalidTimestamp),
            (
                |d| d.timestamp = "2099-01-01T00:00:00+00:00".into(),
                Rejection::FutureTimestamp,
            ),
            (|d| d.confidence = -0.1, Rejection::InvalidConfidence),
            (|d| d.confidence = f64::NAN, Rejection::InvalidConfidence),
            (|d| d.freq_hz = -1.0, Rejection::InvalidFrequency),
            (|d| d.freq_hz = f64::INFINITY, Rejection::InvalidFrequency),
            (|d| d.snr_db = Some(f64::NAN), Rejection::InvalidMeasurement),
            (|d| d.power_dbm = Some(1e300), Rejection::InvalidMeasurement),
            (
                |d| d.backend = Some("x;y".into()),
                Rejection::InvalidBackend,
            ),
            (
                |d| d.lna_state = Some("z".repeat(65)),
                Rejection::InvalidLnaState,
            ),
        ];
        for (mutate, expected) in cases {
            let mut d = det("node-a");
            mutate(&mut d);
            assert_eq!(validate_detection(&mut d, "node-a"), Err(expected));
        }
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn only_the_gzip_magic_is_taken_for_gzip() {
        assert!(is_gzip(&gzip(b"{}")));
        assert!(is_gzip(&[0x1f, 0x8b]));
        for not in [
            &b""[..],
            &[0x1f],
            &[0x1f, 0x00],
            &[0x8b, 0x1f],
            b"{\"node_id\"",
        ] {
            assert!(!is_gzip(not), "{not:?}");
        }
    }

    /// Gzip bomb protection: a body inflates to at most the limit; one
    /// byte more is refused, however small the compressed body is.
    #[test]
    fn gzip_is_inflated_up_to_the_limit_and_no_further() {
        let json = br#"{"node_id": "edge-1", "detections": []}"#;
        let ok = decompress_gzip(&gzip(json), json.len()).unwrap();
        assert_eq!(&ok[..], &json[..]);
        match decompress_gzip(&gzip(json), json.len() - 1) {
            Err(DecompressError::TooLarge(max)) => assert_eq!(max, json.len() - 1),
            other => panic!("{other:?}"),
        }

        // 8 MiB of zeros compress to some 8 KiB.
        let bomb = gzip(&vec![0u8; 8 << 20]);
        assert!(bomb.len() < 64 << 10, "{}", bomb.len());
        let err = decompress_gzip(&bomb, 1 << 20).unwrap_err();
        assert!(
            matches!(err, DecompressError::TooLarge(1_048_576)),
            "{err:?}"
        );
    }

    /// The limit bounds memory, not only the result: inflation stops as
    /// soon as the output passes the limit, and the rest of the stream is
    /// never read. A bomb that breaks off after several times the limit
    /// is refused as too large; inflating it all before checking the size
    /// would reach the break (an I/O error) holding the whole output.
    #[test]
    fn a_gzip_bomb_is_refused_before_the_rest_of_it_is_read() {
        let bomb = gzip(&vec![0u8; 8 << 20]);
        // The first half inflates to some 4 MiB, then the stream breaks.
        let cut = &bomb[..bomb.len() / 2];
        assert!(
            matches!(
                decompress_gzip(cut, usize::MAX),
                Err(DecompressError::Io(_))
            ),
            "a cut stream fails once it is read to the cut"
        );
        let err = decompress_gzip(cut, 1 << 20).unwrap_err();
        assert!(
            matches!(err, DecompressError::TooLarge(1_048_576)),
            "{err:?}"
        );
    }

    #[test]
    fn corrupt_gzip_is_an_error_not_a_partial_body() {
        let whole = gzip(&[b'x'; 4096]);
        // A truncated stream, a bad header after the magic, a bad CRC.
        let mut bad_crc = whole.clone();
        let n = bad_crc.len();
        bad_crc[n - 8] ^= 0xff;
        for broken in [
            whole[..whole.len() / 2].to_vec(),
            vec![0x1f, 0x8b, 0xff, 0xff, 0xff],
            bad_crc,
        ] {
            let err = decompress_gzip(&broken, 1 << 20).unwrap_err();
            assert!(matches!(err, DecompressError::Io(_)), "{err:?}");
        }
    }

    #[test]
    fn partition_counts_by_reason() {
        let mut bad = det("node-b");
        bad.detection_id = "x".into();
        let parts = partition_detections(vec![det("node-a"), bad, det("")], "node-a");
        assert_eq!(parts.accepted.len(), 2);
        assert_eq!(parts.rejected_total(), 1);
        assert_eq!(parts.rejected.get("node_mismatch"), Some(&1));
    }

    /// A detection dated too far ahead is dropped on its own and counted
    /// under its reason, like any other invalid field.
    #[test]
    fn a_detection_dated_too_far_ahead_is_counted_on_its_own() {
        let mut ahead = det("node-a");
        ahead.timestamp = (chrono::Utc::now() + MAX_FUTURE_SKEW * 2).to_rfc3339();
        let parts = partition_detections(vec![det("node-a"), ahead], "node-a");
        assert_eq!(parts.accepted.len(), 1);
        assert_eq!(parts.rejected_total(), 1);
        assert_eq!(parts.rejected.get("future_timestamp"), Some(&1));
    }
}
