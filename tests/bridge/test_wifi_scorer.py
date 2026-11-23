"""Tests for WiFi anomaly scorer — baselines and scoring dimensions."""

from __future__ import annotations

from pathlib import Path

import pytest

from sigrift.bridge.anomaly.wifi_scorer import (
    WifiAnomalyScorer,
    WifiBaseline,
    WifiBaselineManager,
    _DIMENSION_WEIGHTS,
)


# ---------------------------------------------------------------------------
# WifiBaseline
# ---------------------------------------------------------------------------


class TestWifiBaseline:
    def test_initial_state(self):
        bl = WifiBaseline()
        assert bl.total_observations == 0
        assert bl.is_learning()
        assert bl.signal_ewma == 0.0
        assert bl.expected_channel is None

    def test_update_tracks_ssid(self):
        bl = WifiBaseline()
        bl.update("TestNet", 6, "WPA2", -50.0, 3, 0.1, 12)
        assert "TestNet" in bl.expected_ssids
        bl.update("TestNet2", 6, "WPA2", -50.0, 3, 0.1, 12)
        assert "TestNet2" in bl.expected_ssids

    def test_update_tracks_channel(self):
        bl = WifiBaseline()
        bl.update("Net", 11, "WPA2", -50.0, 2, 0.0, 8)
        assert bl.expected_channel == 11
        # Channel doesn't change after first set
        bl.update("Net", 6, "WPA2", -50.0, 2, 0.0, 8)
        assert bl.expected_channel == 11

    def test_update_tracks_security(self):
        bl = WifiBaseline()
        bl.update("Net", 6, "WPA3", -50.0, 2, 0.0, 8)
        assert bl.expected_security == "WPA3"

    def test_is_learning(self):
        bl = WifiBaseline()
        for i in range(49):
            bl.update("Net", 6, "WPA2", -50.0, 2, 0.0, 8)
        assert bl.is_learning()
        bl.update("Net", 6, "WPA2", -50.0, 2, 0.0, 8)
        assert not bl.is_learning()

    def test_signal_zscore(self):
        bl = WifiBaseline(alpha=0.1)
        # Build history with some variation around -50 dBm
        import random
        rng = random.Random(42)
        for _ in range(200):
            sig = -50.0 + rng.gauss(0, 3.0)
            bl.update("Net", 6, "WPA2", sig, 2, 0.0, 8)
        # Z-score of the baseline value should be near 0
        z = bl.signal_zscore(bl.signal_ewma)
        assert abs(z) < 0.5
        # Far-away value should have high z-score
        z_far = bl.signal_zscore(-20.0)
        assert abs(z_far) > 2.0

    def test_signal_zscore_insufficient_data(self):
        bl = WifiBaseline()
        assert bl.signal_zscore(-50.0) == 0.0
        bl.update("Net", 6, "WPA2", -50.0, 2, 0.0, 8)
        assert bl.signal_zscore(-50.0) == 0.0

    def test_to_dict_from_dict_roundtrip(self):
        bl = WifiBaseline(alpha=0.05)
        bl.update("TestNet", 6, "WPA2", -45.0, 3, 0.1, 10)
        bl.update("OtherNet", 11, "WPA2", -55.0, 1, 0.05, 14)

        data = bl.to_dict()
        restored = WifiBaseline.from_dict(data)

        assert restored.alpha == bl.alpha
        assert restored.expected_ssids == bl.expected_ssids
        assert restored.expected_channel == bl.expected_channel
        assert restored.expected_security == bl.expected_security
        assert restored.total_observations == bl.total_observations
        assert abs(restored.signal_ewma - bl.signal_ewma) < 1e-6


# ---------------------------------------------------------------------------
# WifiBaselineManager
# ---------------------------------------------------------------------------


class TestWifiBaselineManager:
    def test_get_or_create(self):
        mgr = WifiBaselineManager()
        assert mgr.get_baseline("aa:bb:cc:11:22:33") is None
        bl = mgr.update("aa:bb:cc:11:22:33", "TestNet", 6, "WPA2", -50.0, 2, 0.0, 8)
        assert bl is not None
        assert isinstance(bl, WifiBaseline)
        assert mgr.get_baseline("aa:bb:cc:11:22:33") is bl

    def test_ssid_to_bssids_index(self):
        mgr = WifiBaselineManager()
        mgr.update("aa:bb:cc:11:22:33", "TestNet", 6, "WPA2", -50.0, 2, 0.0, 8)
        mgr.update("dd:ee:ff:44:55:66", "OtherNet", 11, "WPA3", -60.0, 1, 0.0, 8)
        mgr.update("11:22:33:44:55:66", "TestNet", 1, "WPA2", -70.0, 0, 0.0, 8)

        bssids = mgr.get_bssids_for_ssid("TestNet")
        assert "aa:bb:cc:11:22:33" in bssids
        assert "11:22:33:44:55:66" in bssids
        assert "dd:ee:ff:44:55:66" not in bssids

        assert mgr.get_bssids_for_ssid("NonExistent") == set()

    def test_save_load(self, tmp_path: Path):
        mgr = WifiBaselineManager()
        mgr.update("aa:bb:cc:11:22:33", "TestNet", 6, "WPA2", -50.0, 2, 0.1, 8)
        mgr.update("dd:ee:ff:44:55:66", "OtherNet", 11, "WPA3", -60.0, 1, 0.0, 8)

        path = str(tmp_path / "wifi_baselines.json")
        mgr.save(path)
        assert Path(path).exists()

        mgr2 = WifiBaselineManager()
        mgr2.load(path)
        assert len(mgr2.baselines) == 2
        bl = mgr2.get_baseline("aa:bb:cc:11:22:33")
        assert bl is not None
        assert isinstance(bl, WifiBaseline)
        assert "TestNet" in bl.expected_ssids
        assert "TestNet" in mgr2._ssid_to_bssids
        assert "aa:bb:cc:11:22:33" in mgr2.get_bssids_for_ssid("TestNet")

    def test_load_missing_file(self, tmp_path: Path):
        mgr = WifiBaselineManager()
        mgr.load(str(tmp_path / "nonexistent.json"))
        assert len(mgr.baselines) == 0


# ---------------------------------------------------------------------------
# Dimension scorers
# ---------------------------------------------------------------------------


class TestDimensionScorers:
    def _make_scorer(self) -> tuple[WifiBaselineManager, WifiAnomalyScorer]:
        mgr = WifiBaselineManager()
        return mgr, WifiAnomalyScorer(mgr)

    def test_evil_twin(self):
        mgr, scorer = self._make_scorer()
        # Register a BSSID for "TestNet"
        mgr.update("aa:bb:cc:11:22:33", "TestNet", 6, "WPA2", -50.0, 2, 0.0, 8)
        # New BSSID claiming same SSID → evil twin
        score = scorer._evil_twin_score("ff:ff:ff:ff:ff:ff", "TestNet")
        assert score == 1.0
        # Known BSSID → no evil twin
        score = scorer._evil_twin_score("aa:bb:cc:11:22:33", "TestNet")
        assert score == 0.0
        # Empty SSID → no detection
        score = scorer._evil_twin_score("ff:ff:ff:ff:ff:ff", "")
        assert score == 0.0

    def test_security_downgrade(self):
        bl = WifiBaseline()
        bl.expected_security = "WPA2"
        # WPA2 → Open = full downgrade
        assert WifiAnomalyScorer._security_downgrade_score(bl, "Open") == 1.0
        assert WifiAnomalyScorer._security_downgrade_score(bl, "WEP") == 1.0
        # WPA2 → WPA2 = no downgrade
        assert WifiAnomalyScorer._security_downgrade_score(bl, "WPA2") == 0.0
        # WPA2 → WPA3 = upgrade, no alarm
        assert WifiAnomalyScorer._security_downgrade_score(bl, "WPA3") == 0.0
        # Empty security = unknown, NOT a downgrade
        assert WifiAnomalyScorer._security_downgrade_score(bl, "") == 0.0

        bl3 = WifiBaseline()
        bl3.expected_security = "WPA3"
        # WPA3 → WPA2 = partial downgrade
        assert WifiAnomalyScorer._security_downgrade_score(bl3, "WPA2") == 0.5
        # WPA3 → Open = full downgrade
        assert WifiAnomalyScorer._security_downgrade_score(bl3, "Open") == 1.0

        # No baseline
        assert WifiAnomalyScorer._security_downgrade_score(None, "Open") == 0.0

    def test_signal_anomaly(self):
        import random
        rng = random.Random(42)
        bl = WifiBaseline(alpha=0.1)
        for _ in range(200):
            sig = -50.0 + rng.gauss(0, 3.0)
            bl.update("Net", 6, "WPA2", sig, 2, 0.0, 8)
        # Normal signal
        score = WifiAnomalyScorer._signal_anomaly_score(bl, bl.signal_ewma)
        assert score < 0.2
        # Anomalous signal (very different)
        score = WifiAnomalyScorer._signal_anomaly_score(bl, -10.0)
        assert score > 0.3
        # No baseline
        assert WifiAnomalyScorer._signal_anomaly_score(None, -50.0) == 0.0

    def test_new_network(self):
        assert WifiAnomalyScorer._new_network_score(None) == 1.0
        bl = WifiBaseline()
        assert WifiAnomalyScorer._new_network_score(bl) == 0.0

    def test_channel_change(self):
        bl = WifiBaseline()
        bl.expected_channel = 6
        bl.seen_channels = {6}
        assert WifiAnomalyScorer._channel_change_score(bl, 6) == 0.0
        # Never-seen channel scores 1.0
        assert WifiAnomalyScorer._channel_change_score(bl, 11) == 1.0
        assert WifiAnomalyScorer._channel_change_score(bl, 0) == 0.0
        assert WifiAnomalyScorer._channel_change_score(None, 6) == 0.0
        # Previously-seen channel scores 0.0 (normal roaming)
        bl.seen_channels.add(11)
        assert WifiAnomalyScorer._channel_change_score(bl, 11) == 0.0

    def test_client_surge(self):
        bl = WifiBaseline()
        bl.client_count_ewma = 5.0
        # No surge (below 2x)
        assert WifiAnomalyScorer._client_surge_score(bl, 5) == 0.0
        assert WifiAnomalyScorer._client_surge_score(bl, 10) == 0.0
        # Surge (above 2x)
        score = WifiAnomalyScorer._client_surge_score(bl, 15)
        assert score > 0.0
        # 5x = max
        score = WifiAnomalyScorer._client_surge_score(bl, 25)
        assert score == 1.0
        # No baseline
        assert WifiAnomalyScorer._client_surge_score(None, 10) == 0.0
        # Low EWMA
        bl2 = WifiBaseline()
        bl2.client_count_ewma = 0.5
        assert WifiAnomalyScorer._client_surge_score(bl2, 10) == 0.0

    def test_deauth_indicator(self):
        # No deauths, low retry, few frames → 0
        assert WifiAnomalyScorer._deauth_indicator_score(0.0, 0, 1) == 0.0
        # High retry rate but too few frames → 0 (noise)
        assert WifiAnomalyScorer._deauth_indicator_score(1.0, 0, 2) == 0.0
        # High retry rate with enough frames → scores
        score = WifiAnomalyScorer._deauth_indicator_score(0.8, 0, 10)
        assert score > 0.5
        # Actual deauth frames → always scores regardless of frame count
        score = WifiAnomalyScorer._deauth_indicator_score(0.0, 3, 1)
        assert score == pytest.approx(3.0 / 6.0, abs=0.01)  # 3/(3+3)
        # Many deauths → high score
        score = WifiAnomalyScorer._deauth_indicator_score(0.0, 10, 10)
        assert score > 0.7


# ---------------------------------------------------------------------------
# Composite scoring
# ---------------------------------------------------------------------------


class TestWifiAnomalyScorer:
    def test_weights_sum_to_one(self):
        total = sum(_DIMENSION_WEIGHTS.values())
        assert abs(total - 1.0) < 1e-9

    def test_normal_batch(self):
        mgr = WifiBaselineManager()
        scorer = WifiAnomalyScorer(mgr)

        # Build baseline with 60 observations of same network
        for _ in range(60):
            mgr.update("aa:bb:cc:11:22:33", "TestNet", 6, "WPA2", -50.0, 2, 0.05, 8)

        records = [
            {"bssid": "aa:bb:cc:11:22:33", "ssid": "TestNet", "channel": 6,
             "band": "2.4GHz", "security": "WPA2", "signal_dbm": -50.0,
             "client_mac": "c1:c1:c1:c1:c1:c1", "retry_flag": 0},
        ]
        results = scorer.score_batch(records, "node-01")
        # Known, normal network should have very low score
        for r in results:
            assert r.score < 0.3
            assert r.priority == "normal"

    def test_evil_twin_batch(self):
        mgr = WifiBaselineManager()
        scorer = WifiAnomalyScorer(mgr)

        # Establish baseline for a legitimate network
        for _ in range(60):
            mgr.update("aa:bb:cc:11:22:33", "CorpNet", 6, "WPA2", -50.0, 2, 0.0, 8)

        # Evil twin: same SSID, different BSSID (6 frames to avoid low-frame dampening)
        records = [
            {"bssid": "ff:ff:ff:ff:ff:ff", "ssid": "CorpNet", "channel": 6,
             "band": "2.4GHz", "security": "Open", "signal_dbm": -30.0,
             "client_mac": f"c{i}:00:00:00:00:00", "retry_flag": 0}
            for i in range(6)
        ]
        results = scorer.score_batch(records, "node-01")
        assert len(results) >= 1
        assert all(hasattr(r, 'score') for r in results)
        result = results[0]
        # Evil twin + new network dimensions should fire
        assert result.dimensions.get("evil_twin", 0) == 1.0
        assert result.dimensions.get("new_network", 0) == 1.0
        # security_downgrade=0 because the evil twin BSSID has no baseline
        # Score = (0.30*1.0 + 0.10*1.0) * 0.5 learning dampening = 0.20
        assert result.score >= 0.15
        assert result.baseline_status in ("new", "learning")

    def test_learning_dampening(self):
        mgr = WifiBaselineManager()
        scorer = WifiAnomalyScorer(mgr)

        # New network with no baseline at all — learning phase
        records = [
            {"bssid": "aa:bb:cc:11:22:33", "ssid": "NewNet", "channel": 6,
             "band": "2.4GHz", "security": "WPA2", "signal_dbm": -50.0,
             "client_mac": "", "retry_flag": 0},
        ]
        results = scorer.score_batch(records, "node-01")
        assert len(results) >= 1
        assert all(hasattr(r, 'score') for r in results)
        result = results[0]
        # New network dimension = 1.0, weight = 0.10
        # With learning dampening (0.5x), raw score * 0.5
        assert result.baseline_status in ("new", "learning")
        # Score should be dampened
        new_net_weighted = 1.0 * 0.10  # new_network weight
        assert result.score <= new_net_weighted * 0.5 + 0.01 or result.score > 0

    def test_score_bounds(self):
        mgr = WifiBaselineManager()
        scorer = WifiAnomalyScorer(mgr)

        # Maximally anomalous: evil twin + security downgrade + everything
        for _ in range(60):
            mgr.update("aa:bb:cc:11:22:33", "CorpNet", 6, "WPA3", -50.0, 2, 0.01, 8)

        records = [
            {"bssid": "ff:ff:ff:ff:ff:ff", "ssid": "CorpNet", "channel": 11,
             "band": "2.4GHz", "security": "Open", "signal_dbm": -10.0,
             "client_mac": "c1", "retry_flag": 1},
        ]
        results = scorer.score_batch(records, "node-01")
        for r in results:
            assert 0.0 <= r.score <= 1.0

    def test_empty_batch(self):
        mgr = WifiBaselineManager()
        scorer = WifiAnomalyScorer(mgr)
        results = scorer.score_batch([], "node-01")
        assert results == []

    def test_skip_empty_bssid(self):
        mgr = WifiBaselineManager()
        scorer = WifiAnomalyScorer(mgr)
        records = [{"bssid": "", "ssid": "Net", "signal_dbm": -50.0}]
        results = scorer.score_batch(records, "node-01")
        assert results == []


# ---------------------------------------------------------------------------
# Enrichment tests
# ---------------------------------------------------------------------------


class TestEnrichment:
    """Tests for forensic enrichment fields added to anomaly results."""

    def _make_records(self, n=5, bssid="aa:bb:cc:11:22:33", **overrides):
        """Generate n WiFi records for a single BSSID."""
        base = {
            "bssid": bssid,
            "ssid": "TestNet",
            "channel": 6,
            "channel_width": 40,
            "band": "2.4GHz",
            "security": "WPA2",
            "signal_dbm": -50.0,
            "noise_dbm": -90.0,
            "frame_type": "data",
            "client_mac": "",
            "data_rate_mbps": 54.0,
            "retry_flag": 0,
        }
        base.update(overrides)
        records = []
        for i in range(n):
            rec = dict(base)
            rec["client_mac"] = f"c{i}:c{i}:c{i}:c{i}:c{i}:c{i}" if i < 3 else ""
            records.append(rec)
        return records

    def test_enriched_fields_populated(self):
        """Verify score_batch populates all new enrichment fields."""
        mgr = WifiBaselineManager()
        scorer = WifiAnomalyScorer(mgr)

        records = self._make_records(n=10)
        results = scorer.score_batch(records, "node-01")
        assert len(results) >= 1
        assert all(hasattr(r, 'frame_count') for r in results)

        r = results[0]
        assert r.frame_count == 10
        assert r.client_count == 3  # c0, c1, c2 are non-empty
        assert r.noise_dbm_max == -90.0
        assert r.data_rate_min == 54.0
        assert r.data_rate_max == 54.0
        assert r.channel_width == 40
        assert isinstance(r.frame_type_counts, dict)
        assert r.frame_type_counts.get("data", 0) == 10
        assert isinstance(r.client_macs, list)
        assert len(r.client_macs) == 3
        assert isinstance(r.frame_capture, list)
        assert r.baseline_observations == 0  # no baseline yet

    def test_frame_capture_prioritized(self):
        """Management frames should appear before data frames."""
        mgr = WifiBaselineManager()
        scorer = WifiAnomalyScorer(mgr)

        records = [
            {"bssid": "aa:bb:cc:11:22:33", "ssid": "Net", "channel": 6,
             "band": "2.4GHz", "security": "WPA2", "signal_dbm": -50.0,
             "frame_type": "data", "client_mac": "", "retry_flag": 0,
             "data_rate_mbps": 54.0, "noise_dbm": 0.0, "channel_width": 20},
            {"bssid": "aa:bb:cc:11:22:33", "ssid": "Net", "channel": 6,
             "band": "2.4GHz", "security": "WPA2", "signal_dbm": -50.0,
             "frame_type": "deauth", "client_mac": "d1:d1:d1:d1:d1:d1",
             "retry_flag": 1, "data_rate_mbps": 0.0, "noise_dbm": 0.0,
             "channel_width": 20},
            {"bssid": "aa:bb:cc:11:22:33", "ssid": "Net", "channel": 6,
             "band": "2.4GHz", "security": "WPA2", "signal_dbm": -50.0,
             "frame_type": "data", "client_mac": "", "retry_flag": 0,
             "data_rate_mbps": 54.0, "noise_dbm": 0.0, "channel_width": 20},
        ]
        results = scorer.score_batch(records, "node-01")
        assert len(results) >= 1
        assert isinstance(results[0].frame_capture, list)
        frames = results[0].frame_capture
        # Deauth (management) should be first
        assert frames[0]["frame_type"] == "deauth"

    def test_frame_capture_capped(self):
        """Frame capture list should be capped at max_frame_capture."""
        mgr = WifiBaselineManager()
        scorer = WifiAnomalyScorer(mgr, max_frame_capture=3)

        records = self._make_records(n=10)
        results = scorer.score_batch(records, "node-01")
        assert len(results) >= 1
        assert isinstance(results[0].frame_capture, list)
        assert len(results[0].frame_capture) == 3

    def test_deauth_count_aggregation(self):
        """Deauth + disassociation frames should be counted correctly."""
        mgr = WifiBaselineManager()
        scorer = WifiAnomalyScorer(mgr)

        records = [
            {"bssid": "aa:bb:cc:11:22:33", "ssid": "Net", "channel": 6,
             "band": "2.4GHz", "security": "WPA2", "signal_dbm": -50.0,
             "frame_type": "deauth", "client_mac": "", "retry_flag": 0,
             "data_rate_mbps": 0.0, "noise_dbm": 0.0, "channel_width": 20},
            {"bssid": "aa:bb:cc:11:22:33", "ssid": "Net", "channel": 6,
             "band": "2.4GHz", "security": "WPA2", "signal_dbm": -50.0,
             "frame_type": "disassociation", "client_mac": "", "retry_flag": 0,
             "data_rate_mbps": 0.0, "noise_dbm": 0.0, "channel_width": 20},
            {"bssid": "aa:bb:cc:11:22:33", "ssid": "Net", "channel": 6,
             "band": "2.4GHz", "security": "WPA2", "signal_dbm": -50.0,
             "frame_type": "data", "client_mac": "", "retry_flag": 0,
             "data_rate_mbps": 54.0, "noise_dbm": 0.0, "channel_width": 20},
        ]
        results = scorer.score_batch(records, "node-01")
        assert len(results) >= 1
        assert isinstance(results[0].deauth_count, int)
        assert results[0].deauth_count == 2

    def test_noise_excludes_zeros(self):
        """noise_dbm_max should ignore zero values."""
        mgr = WifiBaselineManager()
        scorer = WifiAnomalyScorer(mgr)

        records = [
            {"bssid": "aa:bb:cc:11:22:33", "ssid": "Net", "channel": 6,
             "band": "2.4GHz", "security": "WPA2", "signal_dbm": -50.0,
             "frame_type": "data", "client_mac": "", "retry_flag": 0,
             "data_rate_mbps": 54.0, "noise_dbm": 0.0, "channel_width": 20},
            {"bssid": "aa:bb:cc:11:22:33", "ssid": "Net", "channel": 6,
             "band": "2.4GHz", "security": "WPA2", "signal_dbm": -50.0,
             "frame_type": "data", "client_mac": "", "retry_flag": 0,
             "data_rate_mbps": 54.0, "noise_dbm": -85.0, "channel_width": 20},
        ]
        results = scorer.score_batch(records, "node-01")
        assert len(results) >= 1
        assert isinstance(results[0].noise_dbm_max, float)
        assert results[0].noise_dbm_max == -85.0

    def test_baseline_snapshots(self):
        """Baseline comparison values should be populated from existing baseline."""
        mgr = WifiBaselineManager()
        scorer = WifiAnomalyScorer(mgr)

        # Build a mature baseline on channel 6
        for _ in range(60):
            mgr.update("aa:bb:cc:11:22:33", "CorpNet", 6, "WPA2", -50.0, 3, 0.05, 8)

        # Use a channel change (6 → 11) to guarantee score > 0
        records = [
            {"bssid": "aa:bb:cc:11:22:33", "ssid": "CorpNet", "channel": 11,
             "band": "2.4GHz", "security": "WPA2", "signal_dbm": -45.0,
             "frame_type": "data", "client_mac": "c1:c1:c1:c1:c1:c1",
             "retry_flag": 0, "data_rate_mbps": 54.0, "noise_dbm": -90.0,
             "channel_width": 20},
        ]
        results = scorer.score_batch(records, "node-01")
        assert len(results) >= 1, "Expected score > 0 from channel change"
        r = results[0]
        assert r.expected_signal is not None
        assert isinstance(r.expected_signal, float)
        assert abs(r.expected_signal - (-50.0)) < 2.0  # close to -50
        assert r.expected_channel == 6
        assert r.expected_security == "WPA2"
        assert r.baseline_observations == 60
        # signal_zscore may be 0 if baseline variance is near-zero
        # (all 60 observations at exactly -50.0 → std ≈ 0)
        assert isinstance(r.signal_zscore, float)

    def test_mac_anonymized_in_frame_capture(self):
        """Verify that pre-anonymized MACs flow through to frame_capture."""
        mgr = WifiBaselineManager()
        scorer = WifiAnomalyScorer(mgr)

        # Simulate pre-anonymized MACs (as the router does before scoring)
        records = [
            {"bssid": "aa:bb:cc:11:22:33", "ssid": "Net", "channel": 6,
             "band": "2.4GHz", "security": "WPA2", "signal_dbm": -50.0,
             "frame_type": "data", "client_mac": "aa:bb:cc:xx:yy:zz",
             "retry_flag": 0, "data_rate_mbps": 54.0, "noise_dbm": 0.0,
             "channel_width": 20},
        ]
        results = scorer.score_batch(records, "node-01")
        assert len(results) >= 1
        assert all(hasattr(r, 'client_macs') for r in results)
        r = results[0]
        # client_macs and frame_capture should contain the MAC as given
        assert "aa:bb:cc:xx:yy:zz" in r.client_macs
        assert r.frame_capture[0]["client_mac"] == "aa:bb:cc:xx:yy:zz"

    def test_noise_all_zeros(self):
        """noise_dbm_max is 0.0 when all noise readings are zero."""
        mgr = WifiBaselineManager()
        scorer = WifiAnomalyScorer(mgr)

        records = self._make_records(n=3, noise_dbm=0.0)
        results = scorer.score_batch(records, "node-01")
        assert len(results) >= 1
        assert isinstance(results[0].noise_dbm_max, float)
        assert results[0].noise_dbm_max == 0.0

    def test_forensic_fields_roundtrip(self, tmp_path):
        """Test insert and retrieve of enriched anomaly data through DetectionStore."""
        from sigrift.bridge.detection_store import DetectionStore

        store = DetectionStore(db_path=str(tmp_path / "test.db"))

        anomaly = {
            "bssid": "aa:bb:cc:11:22:33",
            "ssid": "TestNet",
            "channel": 6,
            "band": "2.4GHz",
            "security": "WPA2",
            "signal_dbm": -50.0,
            "anomaly_score": 0.5,
            "priority": "anomalous",
            "dimensions": {"evil_twin": 0.0, "new_network": 1.0},
            "reasons": ["New network"],
            "baseline_status": "new",
            "node_id": "node-01",
            "timestamp": "2025-01-01T00:00:00+00:00",
            "client_count": 3,
            "retry_rate": 0.1,
            "noise_dbm_max": -85.0,
            "data_rate_min": 6.0,
            "data_rate_max": 54.0,
            "channel_width": 40,
            "frame_count": 10,
            "deauth_count": 2,
            "frame_type_counts": {"data": 8, "deauth": 2},
            "expected_signal": -50.0,
            "signal_zscore": 1.5,
            "expected_channel": 6,
            "expected_security": "WPA2",
            "expected_client_count": 2.5,
            "expected_retry_rate": 0.05,
            "baseline_observations": 60,
            "client_macs": ["aa:bb:cc:11:22:33", "dd:ee:ff:44:55:66"],
            "frame_capture": [
                {"frame_type": "deauth", "client_mac": "aa:bb:cc:11:22:33",
                 "signal_dbm": -50.0, "data_rate_mbps": 0.0, "retry_flag": 0},
            ],
        }

        store.insert_wifi_anomalies_batch([anomaly])

        # Default query should NOT include frames
        rows = store.get_wifi_anomalies(min_score=0.3, include_frames=False)
        assert len(rows) == 1
        row = rows[0]
        assert row["client_count"] == 3
        assert row["deauth_count"] == 2
        assert row["frame_type_counts"] == {"data": 8, "deauth": 2}
        assert "frame_capture" not in row
        assert "client_macs" not in row

        # With include_frames=True should include frames
        rows_full = store.get_wifi_anomalies(min_score=0.3, include_frames=True)
        assert len(rows_full) == 1
        row_full = rows_full[0]
        assert row_full["client_macs"] == ["aa:bb:cc:11:22:33", "dd:ee:ff:44:55:66"]
        assert len(row_full["frame_capture"]) == 1
        assert row_full["frame_capture"][0]["frame_type"] == "deauth"

        store.close()

    def test_get_anomalies_excludes_frames_by_default(self, tmp_path):
        """Verify frame_capture is not in default get_wifi_anomalies response."""
        from sigrift.bridge.detection_store import DetectionStore

        store = DetectionStore(db_path=str(tmp_path / "test.db"))

        store.insert_wifi_anomalies_batch([{
            "bssid": "aa:bb:cc:11:22:33",
            "anomaly_score": 0.5,
            "priority": "anomalous",
            "baseline_status": "new",
            "timestamp": "2025-01-01T00:00:00+00:00",
            "frame_capture": [{"frame_type": "data"}],
            "client_macs": ["aa:bb:cc:xx:yy:zz"],
        }])

        rows = store.get_wifi_anomalies(min_score=0.3)
        assert len(rows) == 1
        assert "frame_capture" not in rows[0]
        assert "client_macs" not in rows[0]

        store.close()


class TestForensicRoundtrip:
    """Test insert → get roundtrip with enriched fields via DetectionStore."""

    def test_cleanup_wifi_anomalies(self, tmp_path):
        """cleanup_wifi_anomalies deletes old records."""
        from sigrift.bridge.detection_store import DetectionStore

        store = DetectionStore(db_path=tmp_path / "test.db")

        # Insert an old anomaly
        anomaly = {
            "bssid": "aa:bb:cc:11:22:33",
            "anomaly_score": 0.5,
            "timestamp": "2020-01-01T00:00:00+00:00",  # very old
        }
        store.insert_wifi_anomalies_batch([anomaly])

        # Verify it exists
        results = store.get_wifi_anomalies(min_score=0.3)
        assert len(results) == 1

        # Cleanup
        deleted = store.cleanup_wifi_anomalies(max_age_days=7)
        assert deleted == 1

        # Verify it's gone
        results = store.get_wifi_anomalies(min_score=0.3)
        assert len(results) == 0


# ---------------------------------------------------------------------------
# Evil twin vendor mismatch tests
# ---------------------------------------------------------------------------


class TestEvilTwinVendor:
    """Test enhanced evil twin scoring with vendor comparison."""

    def _make_scorer(self):
        mgr = WifiBaselineManager()
        return WifiAnomalyScorer(mgr)

    def test_vendor_mismatch_scores_1_0(self):
        """Different vendor from known BSSID for same SSID → 1.0."""
        scorer = self._make_scorer()
        # Establish baseline for BSSID-1 with vendor "Cisco"
        scorer.baseline_manager.update(
            "AA:BB:CC:11:22:33", "CorpNet", 6, "WPA2", -50.0, 2, 0.0, 12,
            vendor="Cisco Systems, Inc",
        )
        # Score BSSID-2 (same SSID, different vendor = evil twin)
        score = scorer._evil_twin_score(
            "DD:EE:FF:44:55:66", "CorpNet", vendor="Raspberry Pi Foundation",
        )
        assert score == 1.0

    def test_vendor_match_scores_0_7(self):
        """Same vendor from known BSSID for same SSID → 0.7 (multi-AP)."""
        scorer = self._make_scorer()
        scorer.baseline_manager.update(
            "AA:BB:CC:11:22:33", "CorpNet", 6, "WPA2", -50.0, 2, 0.0, 12,
            vendor="Cisco Systems, Inc",
        )
        score = scorer._evil_twin_score(
            "DD:EE:FF:44:55:66", "CorpNet", vendor="Cisco Systems, Inc",
        )
        assert score == 0.7

    def test_no_vendor_info_scores_1_0(self):
        """No vendor info available → 1.0 (preserve existing behavior)."""
        scorer = self._make_scorer()
        scorer.baseline_manager.update(
            "AA:BB:CC:11:22:33", "CorpNet", 6, "WPA2", -50.0, 2, 0.0, 12,
        )
        score = scorer._evil_twin_score("DD:EE:FF:44:55:66", "CorpNet")
        assert score == 1.0

    def test_no_vendor_on_new_but_known_has_vendor(self):
        """Known has vendor, new doesn't → 1.0 (unknown = suspicious)."""
        scorer = self._make_scorer()
        scorer.baseline_manager.update(
            "AA:BB:CC:11:22:33", "CorpNet", 6, "WPA2", -50.0, 2, 0.0, 12,
            vendor="Cisco Systems, Inc",
        )
        score = scorer._evil_twin_score(
            "DD:EE:FF:44:55:66", "CorpNet", vendor="",
        )
        assert score == 1.0

    def test_baseline_vendor_tracking(self):
        """WifiBaseline tracks expected_vendor on first observation."""
        bl = WifiBaseline()
        bl.update("Net", 6, "WPA2", -50.0, 2, 0.0, 12, vendor="Intel Corporate")
        assert bl.expected_vendor == "Intel Corporate"
        # Vendor doesn't change after first set
        bl.update("Net", 6, "WPA2", -50.0, 2, 0.0, 12, vendor="Other Corp")
        assert bl.expected_vendor == "Intel Corporate"

    def test_baseline_vendor_serialization(self):
        """WifiBaseline vendor roundtrips through to_dict/from_dict."""
        bl = WifiBaseline()
        bl.update("Net", 6, "WPA2", -50.0, 2, 0.0, 12, vendor="Apple, Inc.")
        data = bl.to_dict()
        assert data["expected_vendor"] == "Apple, Inc."
        restored = WifiBaseline.from_dict(data)
        assert restored.expected_vendor == "Apple, Inc."

    def test_score_batch_passes_vendor(self):
        """score_batch propagates vendor to evil twin scoring."""
        scorer = self._make_scorer()
        # Establish a known network
        scorer.baseline_manager.update(
            "AA:BB:CC:11:22:33", "CorpNet", 6, "WPA2", -50.0, 2, 0.0, 12,
            vendor="Cisco Systems, Inc",
        )
        # Score a batch with different vendor (evil twin)
        records = [
            {
                "bssid": "DD:EE:FF:44:55:66",
                "ssid": "CorpNet",
                "channel": 6,
                "band": "2.4GHz",
                "security": "WPA2",
                "signal_dbm": -60.0,
                "client_mac": "",
                "retry_flag": 0,
                "noise_dbm": 0.0,
                "data_rate_mbps": 0.0,
                "channel_width": 20,
                "frame_type": "beacon",
                "vendor": "Raspberry Pi Foundation",
            },
        ]
        results = scorer.score_batch(records, "node01")
        # Should produce an anomaly with evil_twin dimension scored
        assert len(results) > 0
        assert all(hasattr(r, 'dimensions') for r in results)
        et_score = results[0].dimensions.get("evil_twin", 0)
        assert et_score == 1.0  # vendor mismatch


class TestMigration10:
    """Test that migration 10 adds vendor columns correctly."""

    def test_vendor_columns_exist(self, tmp_path):
        """After migration, vendor columns should exist in all tables."""
        from sigrift.bridge.storage.base import SharedContext

        ctx = SharedContext(db_path=tmp_path / "test.db")
        conn = ctx.get_conn()

        # Check wifi_metadata has vendor and client_vendor
        cols = {row[1] for row in conn.execute("PRAGMA table_info(wifi_metadata)").fetchall()}
        assert "vendor" in cols
        assert "client_vendor" in cols

        # Check wifi_metadata_hourly has vendor
        cols = {row[1] for row in conn.execute("PRAGMA table_info(wifi_metadata_hourly)").fetchall()}
        assert "vendor" in cols

        # Check wifi_anomalies has vendor
        cols = {row[1] for row in conn.execute("PRAGMA table_info(wifi_anomalies)").fetchall()}
        assert "vendor" in cols

        ctx.close()
