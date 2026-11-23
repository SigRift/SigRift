"""Advanced cross-correlation tests — multi-node, cross-layer, signature matching.

Tests verify that the correlation and scoring systems correctly handle:
1. Multi-node RF agreement (boost)
2. Single-node dampening
3. Cross-layer SDR↔WiFi confirmation
4. Threat signature matching at scoring time
5. TDOA clustering eligibility
6. Correlation score computation
7. Coordinated multi-layer attack scenarios
"""

import sqlite3
import time
from datetime import datetime, timezone

import pytest
from unittest.mock import MagicMock

from sigrift.bridge.anomaly.correlator import NodeCorrelator
from sigrift.bridge.correlation_engine import CrossCorrelator, CrossCorrelation

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def correlator():
    return NodeCorrelator(
        time_window_sec=15,
        freq_tolerance_hz=100_000,
        single_node_factor=0.9,
        total_active_nodes=5,
    )


@pytest.fixture
def mock_ctx():
    """In-memory SQLite with all tables needed by CrossCorrelator."""
    conn = sqlite3.connect(":memory:")
    conn.executescript("""
        CREATE TABLE detections (
            detection_id TEXT PRIMARY KEY,
            node_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            signal_class TEXT NOT NULL DEFAULT '',
            confidence REAL NOT NULL DEFAULT 0.0,
            family TEXT NOT NULL DEFAULT '',
            freq_hz REAL NOT NULL DEFAULT 0.0,
            snr_db REAL,
            power_dbm REAL,
            anomaly_score REAL NOT NULL DEFAULT 0.0,
            tenant_id TEXT NOT NULL DEFAULT 'default'
        );
        CREATE TABLE wifi_metadata (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            detection_id TEXT NOT NULL DEFAULT '',
            bssid TEXT NOT NULL DEFAULT '',
            ssid TEXT NOT NULL DEFAULT '',
            channel INTEGER DEFAULT 0,
            timestamp TEXT NOT NULL,
            node_id TEXT NOT NULL DEFAULT '',
            tenant_id TEXT NOT NULL DEFAULT 'default'
        );
        CREATE TABLE bt_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_addr TEXT NOT NULL DEFAULT '',
            device_name TEXT NOT NULL DEFAULT '',
            channel INTEGER DEFAULT 0,
            timestamp TEXT NOT NULL,
            node_id TEXT NOT NULL DEFAULT '',
            tenant_id TEXT NOT NULL DEFAULT 'default'
        );
        CREATE TABLE zigbee_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ieee_addr TEXT NOT NULL DEFAULT '',
            channel INTEGER NOT NULL DEFAULT 0,
            timestamp TEXT NOT NULL,
            node_id TEXT NOT NULL DEFAULT '',
            tenant_id TEXT NOT NULL DEFAULT 'default'
        );
        CREATE TABLE cross_correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_a TEXT NOT NULL,
            source_a_id TEXT DEFAULT '',
            source_b TEXT NOT NULL DEFAULT '',
            source_b_id TEXT DEFAULT '',
            freq_hz REAL NOT NULL DEFAULT 0.0,
            time_delta_ms REAL NOT NULL DEFAULT 0.0,
            correlation_type TEXT NOT NULL DEFAULT '',
            node_id TEXT NOT NULL DEFAULT '',
            timestamp TEXT NOT NULL,
            tenant_id TEXT NOT NULL DEFAULT 'default'
        );
    """)
    ctx = MagicMock()
    ctx.get_conn.return_value = conn
    return ctx


@pytest.fixture
def cross_correlator(mock_ctx):
    return CrossCorrelator(mock_ctx, time_window_ms=500)


@pytest.fixture
def scorer(detection_store):
    from sigrift.bridge.anomaly.scorer import AnomalyScorer
    from sigrift.bridge.anomaly.baseline import BaselineManager
    return AnomalyScorer(BaselineManager())


# ---------------------------------------------------------------------------
# 1. Multi-Node RF Correlation
# ---------------------------------------------------------------------------

class TestMultiNodeCorrelation:
    """Verify multi-node detection boosts anomaly score."""

    def test_two_nodes_same_signal_boosts(self, correlator):
        """Two nodes detecting the same signal should boost the score."""
        now = time.time()
        det = {
            "node_id": "node1",
            "signal_class": "gps-jammer",
            "freq_hz": 1575420000.0,
            "timestamp": now,
            "anomaly_score": 0.6,
        }
        recent = [
            {
                "node_id": "node2",
                "signal_class": "gps-jammer",
                "freq_hz": 1575420000.0,
                "timestamp": now - 2,
            }
        ]
        result = correlator.check_correlation(det, recent)
        assert result.correlated, "Should correlate when 2 nodes see same signal"
        assert result.node_count >= 2
        assert result.adjusted_anomaly_score > 0.6, \
            f"Score should be boosted from 0.6, got {result.adjusted_anomaly_score}"

    def test_three_nodes_stronger_boost(self, correlator):
        """Three nodes should give a stronger boost than two."""
        now = time.time()
        det = {
            "node_id": "node1",
            "signal_class": "gps-jammer",
            "freq_hz": 1575420000.0,
            "timestamp": now,
            "anomaly_score": 0.5,
        }
        recent_2 = [
            {"node_id": "node2", "signal_class": "gps-jammer",
             "freq_hz": 1575420000.0, "timestamp": now - 1},
        ]
        recent_3 = [
            {"node_id": "node2", "signal_class": "gps-jammer",
             "freq_hz": 1575420000.0, "timestamp": now - 1},
            {"node_id": "node3", "signal_class": "gps-jammer",
             "freq_hz": 1575420000.0, "timestamp": now - 2},
        ]
        r2 = correlator.check_correlation(det, recent_2)
        r3 = correlator.check_correlation(det, recent_3)
        assert r3.adjusted_anomaly_score > r2.adjusted_anomaly_score, \
            f"3-node ({r3.adjusted_anomaly_score}) should beat 2-node ({r2.adjusted_anomaly_score})"

    def test_single_node_dampened(self, correlator):
        """Single-node detection should be dampened."""
        now = time.time()
        det = {
            "node_id": "node1",
            "signal_class": "qpsk",
            "freq_hz": 2400000000.0,
            "timestamp": now,
            "anomaly_score": 0.7,
        }
        result = correlator.check_correlation(det, [])
        assert not result.correlated
        assert result.adjusted_anomaly_score < 0.7, \
            f"Single-node should be dampened from 0.7, got {result.adjusted_anomaly_score}"
        assert result.adjusted_anomaly_score == pytest.approx(0.7 * 0.9, abs=0.01)

    def test_outside_time_window_no_correlation(self, correlator):
        """Detections outside the time window should not correlate."""
        now = time.time()
        det = {
            "node_id": "node1",
            "signal_class": "gps-jammer",
            "freq_hz": 1575420000.0,
            "timestamp": now,
            "anomaly_score": 0.5,
        }
        old_recent = [
            {"node_id": "node2", "signal_class": "gps-jammer",
             "freq_hz": 1575420000.0, "timestamp": now - 30},  # 30s ago, outside 15s window
        ]
        result = correlator.check_correlation(det, old_recent)
        assert not result.correlated

    def test_different_frequency_no_correlation(self, correlator):
        """Detections at different frequencies should not correlate."""
        now = time.time()
        det = {
            "node_id": "node1",
            "signal_class": "qpsk",
            "freq_hz": 2400000000.0,
            "timestamp": now,
            "anomaly_score": 0.5,
        }
        different_freq = [
            {"node_id": "node2", "signal_class": "qpsk",
             "freq_hz": 5800000000.0, "timestamp": now - 1},
        ]
        result = correlator.check_correlation(det, different_freq)
        assert not result.correlated


# ---------------------------------------------------------------------------
# 2. Correlation Score Computation
# ---------------------------------------------------------------------------

class TestCorrelationScore:
    """Verify correlation_score = node_count / total_active_nodes."""

    def test_score_2_of_5(self, correlator):
        now = time.time()
        det = {"node_id": "n1", "signal_class": "qpsk", "freq_hz": 2.4e9,
               "timestamp": now, "anomaly_score": 0.5}
        recent = [{"node_id": "n2", "signal_class": "qpsk",
                   "freq_hz": 2.4e9, "timestamp": now - 1}]
        r = correlator.check_correlation(det, recent)
        assert r.correlation_score == pytest.approx(2 / 5, abs=0.01)

    def test_score_5_of_5(self, correlator):
        now = time.time()
        det = {"node_id": "n1", "signal_class": "qpsk", "freq_hz": 2.4e9,
               "timestamp": now, "anomaly_score": 0.5}
        recent = [
            {"node_id": f"n{i}", "signal_class": "qpsk",
             "freq_hz": 2.4e9, "timestamp": now - 1}
            for i in range(2, 6)
        ]
        r = correlator.check_correlation(det, recent)
        assert r.correlation_score == pytest.approx(1.0, abs=0.01)


# ---------------------------------------------------------------------------
# 3. Cross-Layer (SDR ↔ WiFi) Correlation
# ---------------------------------------------------------------------------

class TestCrossLayerCorrelation:
    """Verify SDR↔WiFi/BT cross-correlation using DB-backed CrossCorrelator."""

    def test_sdr_wifi_confirmed(self, mock_ctx, cross_correlator):
        """SDR detection + WiFi at same freq/time → confirmed."""
        conn = mock_ctx.get_conn()
        now = datetime.now(timezone.utc)
        ts = now.isoformat()

        # Seed WiFi on channel 1 (2412 MHz)
        conn.execute(
            "INSERT INTO wifi_metadata (channel, timestamp, node_id) VALUES (?, ?, ?)",
            (1, ts, "node1"),
        )
        conn.commit()

        events = [{"freq_hz": 2412e6, "timestamp": ts, "id": "det1"}]
        results = cross_correlator.correlate("sdr", events, "node1")

        confirmed = [r for r in results if r.correlation_type == "confirmed"]
        assert len(confirmed) >= 1, \
            f"SDR+WiFi at same freq should correlate, got {[r.correlation_type for r in results]}"
        assert confirmed[0].source_a == "sdr"
        assert confirmed[0].source_b == "wifi"

    def test_sdr_unmatched(self, cross_correlator):
        """SDR detection with no WiFi/BT → unmatched_sdr."""
        now = datetime.now(timezone.utc)
        ts = now.isoformat()

        events = [{"freq_hz": 433920000, "timestamp": ts, "id": "det_lone"}]
        results = cross_correlator.correlate("sdr", events, "node1")

        assert len(results) == 1
        assert results[0].correlation_type == "unmatched_sdr"

    def test_sdr_bt_confirmed(self, mock_ctx, cross_correlator):
        """SDR detection + Bluetooth at overlapping freq → confirmed."""
        conn = mock_ctx.get_conn()
        now = datetime.now(timezone.utc)
        ts = now.isoformat()

        # BT channel 39 → 2441 MHz
        conn.execute(
            "INSERT INTO bt_devices (channel, timestamp, node_id) VALUES (?, ?, ?)",
            (39, ts, "node1"),
        )
        conn.commit()

        events = [{"freq_hz": 2441e6, "timestamp": ts, "id": "det_bt"}]
        results = cross_correlator.correlate("sdr", events, "node1")

        confirmed = [r for r in results if r.correlation_type == "confirmed"]
        assert len(confirmed) >= 1
        assert confirmed[0].source_b == "bt"

    def test_multi_source_sdr_wifi_bt(self, mock_ctx, cross_correlator):
        """SDR at 2.4 GHz with both WiFi and BT → multi_source."""
        conn = mock_ctx.get_conn()
        now = datetime.now(timezone.utc)
        ts = now.isoformat()

        # WiFi channel 6 (2437 MHz) and BT channel 35 (2437 MHz)
        conn.execute(
            "INSERT INTO wifi_metadata (channel, timestamp, node_id) VALUES (?, ?, ?)",
            (6, ts, "node1"),
        )
        conn.execute(
            "INSERT INTO bt_devices (channel, timestamp, node_id) VALUES (?, ?, ?)",
            (35, ts, "node1"),
        )
        conn.commit()

        events = [{"freq_hz": 2437e6, "timestamp": ts, "id": "det_multi"}]
        results = cross_correlator.correlate("sdr", events, "node1")

        multi = [r for r in results if r.correlation_type == "multi_source"]
        assert len(multi) >= 1, \
            f"SDR+WiFi+BT should be multi_source, got {[r.correlation_type for r in results]}"

    def test_cross_correlation_stored(self, mock_ctx, cross_correlator):
        """Correlation results should be persisted to cross_correlations table."""
        conn = mock_ctx.get_conn()
        now = datetime.now(timezone.utc)
        ts = now.isoformat()

        events = [{"freq_hz": 433920000, "timestamp": ts, "id": "det_store"}]
        cross_correlator.correlate("sdr", events, "node1")

        rows = conn.execute("SELECT COUNT(*) FROM cross_correlations").fetchone()
        assert rows[0] >= 1, "Correlations should be stored in DB"


# ---------------------------------------------------------------------------
# 4. Threat Signature Matching
# ---------------------------------------------------------------------------

class TestSignatureMatching:
    """Verify threat signatures are scored against detections."""

    def test_gps_jammer_signature_match(self, detection_store):
        """GPS jammer at 1575 MHz should match the GPS Jammer threat signature."""
        from sigrift.bridge.storage.signature_library import SignatureLibraryStore
        sig_store = SignatureLibraryStore(detection_store._ctx)

        if hasattr(sig_store, "seed_threat_signatures"):
            sig_store.seed_threat_signatures()

        matches = sig_store.match_by_parameters(
            freq_hz=1575420000.0,
            signal_class="gps-jammer",
        )
        assert len(matches) >= 1, "GPS jammer at L1 should match a threat signature"
        assert matches[0]["match_score"] > 0.3, \
            f"Match score should be significant, got {matches[0]['match_score']}"

    def test_no_match_for_normal_signal(self, detection_store):
        """Normal FM broadcast should not strongly match threat signatures."""
        from sigrift.bridge.storage.signature_library import SignatureLibraryStore
        sig_store = SignatureLibraryStore(detection_store._ctx)

        if hasattr(sig_store, "seed_threat_signatures"):
            sig_store.seed_threat_signatures()

        matches = sig_store.match_by_parameters(
            freq_hz=97500000.0,  # 97.5 FM broadcast
            signal_class="fm",
        )
        # FM broadcast shouldn't strongly match surveillance signatures
        if matches:
            assert matches[0]["match_score"] < 0.7, \
                f"FM broadcast shouldn't be high threat, got {matches[0]['match_score']}"

    def test_covert_mic_signature_match(self, detection_store):
        """Signal in VHF covert mic range should match."""
        from sigrift.bridge.storage.signature_library import SignatureLibraryStore
        sig_store = SignatureLibraryStore(detection_store._ctx)

        if hasattr(sig_store, "seed_threat_signatures"):
            sig_store.seed_threat_signatures()

        matches = sig_store.match_by_parameters(
            freq_hz=170000000.0,  # VHF bug range
            signal_class="fm",
            power_dbm=-30.0,
        )
        # Should match VHF audio bug signatures
        assert len(matches) >= 1, "VHF signal should match covert mic signatures"


# ---------------------------------------------------------------------------
# 5. Scorer Integration with Signatures
# ---------------------------------------------------------------------------

class TestScorerSignatureIntegration:
    """Verify the scorer uses signature library when available."""

    def test_scorer_without_sig_store(self):
        """Scorer without signature store should return 0.0 for SIGNATURE_MATCH."""
        from sigrift.bridge.anomaly.scorer import AnomalyScorer
        from sigrift.bridge.anomaly.baseline import BaselineManager
        scorer = AnomalyScorer(BaselineManager())

        det = {"signal_class": "gps-jammer", "confidence": 0.9,
               "freq_hz": 1575420000.0}
        result = scorer.score(det)
        assert result.dimensions.get("signature_match", 0.0) == 0.0

    def test_scorer_with_sig_store_matches(self, detection_store):
        """Scorer with signature store should score GPS jammer match."""
        from sigrift.bridge.anomaly.scorer import AnomalyScorer
        from sigrift.bridge.anomaly.baseline import BaselineManager
        from sigrift.bridge.storage.signature_library import SignatureLibraryStore

        sig_store = SignatureLibraryStore(detection_store._ctx)
        if hasattr(sig_store, "seed_threat_signatures"):
            sig_store.seed_threat_signatures()

        scorer = AnomalyScorer(BaselineManager())
        scorer._sig_store = sig_store

        det = {"signal_class": "gps-jammer", "confidence": 0.9,
               "freq_hz": 1575420000.0, "power_dbm": -20.0}
        result = scorer.score(det)
        sig_score = result.dimensions.get("signature_match", 0.0)
        assert sig_score > 0.0, f"GPS jammer should match signature, got {sig_score}"
        assert "threat signature" in " ".join(result.reasons).lower(), \
            f"Should mention threat signature in reasons: {result.reasons}"


# ---------------------------------------------------------------------------
# 6. TDOA Candidate Detection
# ---------------------------------------------------------------------------

class TestTDOACandidates:
    """Verify TDOA-eligible cluster detection (3+ nodes, <=100ms)."""

    def test_tdoa_3_nodes_tight_timing(self):
        """3 nodes within 50ms should yield a TDOA candidate."""
        correlator = NodeCorrelator(
            time_window_sec=15, freq_tolerance_hz=100_000, total_active_nodes=5,
        )
        now = time.time()
        dets = [
            {"node_id": "n1", "signal_class": "qpsk", "freq_hz": 2.4e9,
             "timestamp": now},
            {"node_id": "n2", "signal_class": "qpsk", "freq_hz": 2.4e9,
             "timestamp": now + 0.02},
            {"node_id": "n3", "signal_class": "qpsk", "freq_hz": 2.4e9,
             "timestamp": now + 0.04},
        ]
        candidates = correlator.find_tdoa_candidates(
            dets, min_nodes=3, max_time_spread_sec=0.100,
        )
        assert len(candidates) >= 1, "3 nodes within 50ms should be TDOA-eligible"
        assert len(candidates[0]) == 3

    def test_tdoa_too_spread(self):
        """3 nodes spread over 500ms should NOT yield TDOA candidate."""
        correlator = NodeCorrelator(
            time_window_sec=15, freq_tolerance_hz=100_000, total_active_nodes=5,
        )
        now = time.time()
        dets = [
            {"node_id": "n1", "signal_class": "qpsk", "freq_hz": 2.4e9,
             "timestamp": now},
            {"node_id": "n2", "signal_class": "qpsk", "freq_hz": 2.4e9,
             "timestamp": now + 0.3},
            {"node_id": "n3", "signal_class": "qpsk", "freq_hz": 2.4e9,
             "timestamp": now + 0.5},
        ]
        candidates = correlator.find_tdoa_candidates(
            dets, min_nodes=3, max_time_spread_sec=0.100,
        )
        assert len(candidates) == 0, "500ms spread should NOT qualify for TDOA"

    def test_tdoa_callback_fires(self):
        """TDOA callback should fire when 3+ node cluster found."""
        callback_calls = []
        correlator = NodeCorrelator(
            time_window_sec=15, freq_tolerance_hz=100_000, total_active_nodes=5,
        )
        correlator.set_tdoa_callback(lambda dets: callback_calls.append(dets))

        now = time.time()
        dets = [
            {"node_id": "n1", "signal_class": "noise", "freq_hz": 900e6,
             "timestamp": now},
            {"node_id": "n2", "signal_class": "noise", "freq_hz": 900e6,
             "timestamp": now + 0.01},
            {"node_id": "n3", "signal_class": "noise", "freq_hz": 900e6,
             "timestamp": now + 0.02},
        ]
        # find_correlation_groups triggers TDOA callback internally
        correlator.find_correlation_groups(dets, min_nodes=2)
        assert len(callback_calls) >= 1, "TDOA callback should fire for 3-node cluster"


# ---------------------------------------------------------------------------
# 7. Correlation Groups
# ---------------------------------------------------------------------------

class TestCorrelationGroups:
    """Verify find_correlation_groups grouping and scoring."""

    def test_two_groups_by_freq(self):
        """Two different frequencies should produce two groups."""
        correlator = NodeCorrelator(
            time_window_sec=15, freq_tolerance_hz=100_000, total_active_nodes=5,
        )
        now = time.time()
        dets = [
            {"node_id": "n1", "signal_class": "qpsk", "freq_hz": 2.4e9, "timestamp": now},
            {"node_id": "n2", "signal_class": "qpsk", "freq_hz": 2.4e9, "timestamp": now - 1},
            {"node_id": "n1", "signal_class": "ofdm", "freq_hz": 5.8e9, "timestamp": now},
            {"node_id": "n3", "signal_class": "ofdm", "freq_hz": 5.8e9, "timestamp": now - 2},
        ]
        groups = correlator.find_correlation_groups(dets, min_nodes=2)
        assert len(groups) == 2, f"Expected 2 groups, got {len(groups)}"
        classes = {g.signal_class for g in groups}
        assert "qpsk" in classes
        assert "ofdm" in classes

    def test_group_correlation_score(self):
        """Correlation score = distinct_nodes / total_active_nodes."""
        correlator = NodeCorrelator(
            time_window_sec=15, freq_tolerance_hz=100_000, total_active_nodes=4,
        )
        now = time.time()
        dets = [
            {"node_id": "n1", "signal_class": "qpsk", "freq_hz": 2.4e9, "timestamp": now},
            {"node_id": "n2", "signal_class": "qpsk", "freq_hz": 2.4e9, "timestamp": now - 1},
            {"node_id": "n3", "signal_class": "qpsk", "freq_hz": 2.4e9, "timestamp": now - 2},
        ]
        groups = correlator.find_correlation_groups(dets, min_nodes=2)
        assert len(groups) == 1
        assert groups[0].correlation_score == pytest.approx(3 / 4, abs=0.01)


# ---------------------------------------------------------------------------
# 8. Multi-Layer Attack Scenario
# ---------------------------------------------------------------------------

class TestCoordinatedAttack:
    """Simulate coordinated multi-layer attacks."""

    def test_jammer_plus_wifi_deauth(self, correlator, mock_ctx, cross_correlator):
        """Simultaneous RF jammer + WiFi deauth should both be detected."""
        now = time.time()

        # RF: GPS jammer detected by 2 nodes
        rf_det = {
            "node_id": "node1",
            "signal_class": "gps-jammer",
            "freq_hz": 1575420000.0,
            "timestamp": now,
            "anomaly_score": 0.7,
        }
        rf_recent = [
            {"node_id": "node2", "signal_class": "gps-jammer",
             "freq_hz": 1575420000.0, "timestamp": now - 1},
        ]

        # Check RF correlation
        rf_result = correlator.check_correlation(rf_det, rf_recent)
        assert rf_result.correlated
        assert rf_result.adjusted_anomaly_score > 0.7  # boosted

        # Cross-layer: SDR detection at 2.4 GHz should be unmatched
        # (no WiFi seeded in DB = unmatched_sdr)
        ts_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
        sdr_events = [{"freq_hz": 2412e6, "timestamp": ts_iso, "id": "attack_sdr"}]
        cross_results = cross_correlator.correlate("sdr", sdr_events, "node1")
        assert len(cross_results) >= 1
        # Without WiFi/BT data in DB, SDR at 2.4GHz is unmatched
        assert cross_results[0].correlation_type == "unmatched_sdr"

    def test_multi_node_correlation_score_formula(self, correlator):
        """Verify the exact correlation score formula."""
        now = time.time()
        det = {"node_id": "n1", "signal_class": "noise", "freq_hz": 2.4e9,
               "timestamp": now, "anomaly_score": 0.8}

        # 3 of 5 nodes
        recent = [
            {"node_id": "n2", "signal_class": "noise", "freq_hz": 2.4e9, "timestamp": now - 1},
            {"node_id": "n3", "signal_class": "noise", "freq_hz": 2.4e9, "timestamp": now - 2},
        ]
        r = correlator.check_correlation(det, recent)

        assert r.node_count == 3
        assert r.correlation_score == pytest.approx(3 / 5, abs=0.01)
        # 3-node boost = +15%
        assert r.adjusted_anomaly_score == pytest.approx(0.8 * 1.15, abs=0.05)
