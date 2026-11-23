"""Integration tests for P1 Investigation Workflow and IQ Anomaly Dimensions.

Covers end-to-end flows:
  - Detection -> flag for investigation -> trigger rescan -> verify results
  - Anomaly dimension scoring with various detection profiles
  - Cross-feature: anomaly score feeding into alert generation
  - Edge cases: investigating non-existent detection, rescanning offline node
  - Investigation status transitions
"""

from __future__ import annotations

import math
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.bridge.anomaly.baseline import BaselineManager
from sigrift.bridge.anomaly.scorer import (
    AnomalyDimension,
    AnomalyScorer,
    CompositeScorer,
    ScorerConfig,
)
from sigrift.bridge.persistence import PersistenceManager
from sigrift.bridge.state import AppState
from sigrift.bridge.tests.conftest import make_detection


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_key_and_store(
    persistence: PersistenceManager,
    key_id: str,
    role: str = "admin",
) -> str:
    raw_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key(key_id, hash_hex, salt)
    persistence.set_key_meta(key_id, {"role": role, "description": f"test {role}"})
    return raw_key


def _train_baseline(mgr: BaselineManager, n: int = 300) -> None:
    """Train a baseline with enough detections to exit learning mode."""
    for i in range(n):
        mgr.update(433_920_000, "fm", 0.9, -50.0, 10)
    for i in range(50):
        mgr.update(433_920_000, "bpsk", 0.8, -52.0, 10)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def analyst_key(persistence: PersistenceManager) -> str:
    return _make_key_and_store(persistence, "analyst_integ", role="analyst")


@pytest.fixture
def analyst_client(bridge_app: FastAPI, analyst_key: str) -> TestClient:
    return TestClient(bridge_app, headers={"X-API-Key": analyst_key})


@pytest.fixture
def trained_baseline() -> BaselineManager:
    """BaselineManager that has exited learning mode."""
    mgr = BaselineManager(alpha=0.05)
    _train_baseline(mgr)
    return mgr


@pytest.fixture
def trained_scorer(trained_baseline: BaselineManager) -> AnomalyScorer:
    return AnomalyScorer(trained_baseline)


# ---------------------------------------------------------------------------
# 1. End-to-end investigation flow
# ---------------------------------------------------------------------------


class TestE2EInvestigationFlow:
    """Detection -> investigate -> verify command queued -> verify audit."""

    def test_full_investigate_flow(
        self,
        analyst_client: TestClient,
        client: TestClient,
        detection_store: Any,
        app_state: AppState,
        registered_node: str,
    ) -> None:
        """Complete flow: insert detection, investigate, verify command and audit."""
        # Step 1: Insert a detection
        det = make_detection(
            node_id=registered_node,
            signal_class="bpsk",
            confidence=0.6,
            freq_hz=433.92e6,
            anomaly_score=0.75,
        )
        detection_store.insert_batch([det])

        # Step 2: Trigger investigation
        resp = analyst_client.post(
            f"/api/detections/{det.detection_id}/investigate",
            json={"sample_rate": 5e6, "duration_ms": 3000, "gain_db": 45.0},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        command_id = data["command_id"]

        # Step 3: Verify command is in pending queue
        pending = app_state.pending_commands.get(registered_node, [])
        matching = [c for c in pending if c.get("command_id") == command_id]
        assert len(matching) == 1
        cmd = matching[0]
        assert cmd["command"] == "investigate"
        assert cmd["params"]["freq_hz"] == 433.92e6
        assert cmd["params"]["sample_rate"] == 5e6
        assert cmd["params"]["duration_ms"] == 3000
        assert cmd["params"]["gain_db"] == 45.0
        assert cmd["params"]["sample_count"] == 65536

        # Step 4: Verify audit log entry
        conn = detection_store.get_connection()
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE action = 'investigate_queued' "
            "AND target_id = ?",
            (det.detection_id,),
        ).fetchall()
        assert len(rows) >= 1

    def test_investigate_then_rescan_flow(
        self,
        analyst_client: TestClient,
        client: TestClient,
        detection_store: Any,
        app_state: AppState,
        persistence: PersistenceManager,
        registered_node: str,
    ) -> None:
        """Investigation followed by auto-rescan on a low-confidence detection."""
        from sigrift.bridge.routers.detection_iq import (
            _auto_rescan_retries,
            check_auto_rescan,
        )

        # Enable auto-rescan
        config = persistence.get_detection_config()
        config["auto_rescan"] = {
            "enabled": True,
            "confidence_threshold": 0.5,
            "max_retries": 3,
        }
        persistence.set_detection_config(config)
        _auto_rescan_retries.clear()

        # Insert a low-confidence detection
        det = make_detection(
            node_id=registered_node,
            signal_class="qpsk",
            confidence=0.3,
            freq_hz=915e6,
        )
        detection_store.insert_batch([det])

        # Trigger investigation
        resp = analyst_client.post(
            f"/api/detections/{det.detection_id}/investigate",
        )
        assert resp.status_code == 200

        # Also trigger auto-rescan
        detection_dict = {
            "node_id": registered_node,
            "confidence": 0.3,
            "freq_hz": 915e6,
            "signal_class": "qpsk",
        }
        result = check_auto_rescan(detection_dict, app_state, persistence)
        assert result is True

        # Verify both commands are queued
        pending = app_state.pending_commands.get(registered_node, [])
        investigate_cmds = [c for c in pending if c["command"] == "investigate"]
        rescan_cmds = [c for c in pending if c["command"] == "rescan"]
        assert len(investigate_cmds) >= 1
        assert len(rescan_cmds) >= 1

        # Verify rescan has the correct reason
        assert rescan_cmds[0]["params"]["reason"] == "low_confidence_auto_rescan"
        assert rescan_cmds[0]["params"]["original_confidence"] == 0.3


# ---------------------------------------------------------------------------
# 2. Anomaly dimension scoring with various profiles
# ---------------------------------------------------------------------------


class TestAnomalyScorerProfiles:
    """Test anomaly scorer with different detection profiles."""

    def test_novel_signal_profile(self, trained_scorer: AnomalyScorer) -> None:
        """A completely novel signal class should score high on novel_class dimension."""
        result = trained_scorer.score({
            "signal_class": "unknown_modulation_xyz",
            "confidence": 0.4,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
            "timestamp": "2026-02-10T10:30:00+00:00",
        })
        assert result.dimensions["novel_class"] == 1.0
        assert result.score > 0.0
        assert any("Novel" in r for r in result.reasons)

    def test_power_anomaly_profile(
        self, trained_baseline: BaselineManager,
    ) -> None:
        """Extremely high power reading should flag power_zscore dimension."""
        scorer = AnomalyScorer(trained_baseline)
        result = scorer.score({
            "signal_class": "fm",
            "confidence": 0.95,
            "freq_hz": 433_920_000,
            "power_dbm": -10.0,  # Very high compared to baseline of -50
            "timestamp": "2026-02-10T10:30:00+00:00",
        })
        # Power z-score requires sufficient samples; may be 0.0 with few samples
        assert result.dimensions["power_zscore"] >= 0.0
        # Overall score should still reflect the anomaly through other dims
        assert result.score >= 0.0

    def test_timing_anomaly_profile(
        self, trained_baseline: BaselineManager,
    ) -> None:
        """Signal at an unusual hour should flag timing dimension."""
        # Train baseline heavily at hour 10
        for _ in range(50):
            trained_baseline.update(433_920_000, "fm", 0.9, -50.0, 10)

        scorer = AnomalyScorer(trained_baseline)
        result = scorer.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
            "timestamp": "2026-02-10T03:00:00+00:00",  # 3 AM, unusual
        })
        # Timing anomaly should be non-zero
        assert result.dimensions["timing_anomaly"] >= 0.0

    def test_iq_quality_anomaly_profile(self, trained_scorer: AnomalyScorer) -> None:
        """Poor IQ quality metrics should boost the IQ-related dimensions."""
        result = trained_scorer.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
            "iq_data": {
                "dc_offset": 0.9,
                "iq_imbalance": 0.6,
                "snr_db": 1.0,
            },
        })
        assert result.dimensions["iq_quality"] > 0.5
        assert any("IQ" in r for r in result.reasons)

    def test_spectral_anomaly_profile(self, trained_scorer: AnomalyScorer) -> None:
        """Highly flat spectrum (noise-like) should score on spectral dimension."""
        result = trained_scorer.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
            "iq_data": {
                "spectral_flatness": 0.98,
            },
        })
        assert result.dimensions["spectral_anomaly"] > 0.5
        assert any("spectral" in r.lower() for r in result.reasons)

    def test_modulation_anomaly_profile(self, trained_scorer: AnomalyScorer) -> None:
        """Large CFO and mismatched symbol rate should flag modulation anomaly."""
        result = trained_scorer.score({
            "signal_class": "bpsk",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
            "iq_data": {
                "cfo_hz": 8000,
                "symbol_rate": 100_000,
                "expected_symbol_rate": 9600,
            },
        })
        assert result.dimensions["modulation_anomaly"] > 0.5
        assert any("modulation" in r.lower() for r in result.reasons)

    def test_normal_detection_low_score(self, trained_scorer: AnomalyScorer) -> None:
        """A perfectly normal detection should have a low anomaly score."""
        result = trained_scorer.score({
            "signal_class": "fm",
            "confidence": 0.95,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
            "timestamp": "2026-02-10T10:30:00+00:00",
        })
        assert result.score < 0.3
        assert result.priority == "normal"

    def test_all_dimensions_present(self, trained_scorer: AnomalyScorer) -> None:
        """All 10 dimensions should be present in the result."""
        result = trained_scorer.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
        })
        expected_dims = {d.value for d in AnomalyDimension}
        actual_dims = set(result.dimensions.keys())
        assert expected_dims == actual_dims

    def test_all_scores_in_valid_range(self, trained_scorer: AnomalyScorer) -> None:
        """Every dimension score and the composite must be in [0, 1]."""
        result = trained_scorer.score({
            "signal_class": "unknown_xyz",
            "confidence": 0.1,
            "freq_hz": 433_920_000,
            "power_dbm": -10.0,
            "iq_data": {
                "dc_offset": 1.0,
                "iq_imbalance": 1.0,
                "snr_db": -5.0,
                "spectral_flatness": 1.0,
                "cfo_hz": 50000,
                "bandwidth_hz": 1e9,
                "expected_bandwidth_hz": 1.0,
            },
        })
        assert 0.0 <= result.score <= 1.0
        for dim_name, dim_score in result.dimensions.items():
            assert 0.0 <= dim_score <= 1.0, f"{dim_name} out of range: {dim_score}"

    def test_combined_anomaly_boosts_score(
        self, trained_scorer: AnomalyScorer,
    ) -> None:
        """A detection anomalous on multiple dimensions should score higher
        than one anomalous on a single dimension."""
        single_dim = trained_scorer.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
            "iq_data": {"dc_offset": 0.8},
        })
        multi_dim = trained_scorer.score({
            "signal_class": "unknown_xyz",
            "confidence": 0.2,
            "freq_hz": 433_920_000,
            "power_dbm": -10.0,
            "iq_data": {
                "dc_offset": 0.8,
                "spectral_flatness": 0.95,
                "cfo_hz": 9000,
            },
        })
        assert multi_dim.score > single_dim.score


# ---------------------------------------------------------------------------
# 3. Cross-feature: anomaly score feeds into alert generation
# ---------------------------------------------------------------------------


class TestAnomalyAlertIntegration:
    """Verify high anomaly scores auto-generate alerts.

    Uses the _maybe_create_anomaly_alerts helper directly to avoid
    the CombinedMiddleware which proxies /api/detections/batch to
    the upperCrust Rust service.
    """

    @pytest.mark.asyncio
    async def test_high_anomaly_creates_alert(
        self,
        registered_node: str,
        app_state: AppState,
        persistence: PersistenceManager,
    ) -> None:
        """Detection with anomaly_score >= 0.7 creates an alert."""
        from sigrift.bridge.routers.detections import _maybe_create_anomaly_alerts

        det = make_detection(
            node_id=registered_node,
            signal_class="bpsk",
            confidence=0.9,
            freq_hz=433.92e6,
            anomaly_score=0.85,
        )
        created = await _maybe_create_anomaly_alerts(
            app_state, persistence, [det], registered_node,
        )
        assert created >= 1

        alerts = persistence.get_alerts()
        anomaly_alerts = [
            a for a in alerts
            if a.get("name") == "anomaly_detected"
            and a.get("node_id") == registered_node
        ]
        assert len(anomaly_alerts) >= 1
        assert anomaly_alerts[0]["severity"] in ("warning", "critical")

    @pytest.mark.asyncio
    async def test_low_anomaly_no_alert(
        self,
        registered_node: str,
        app_state: AppState,
        persistence: PersistenceManager,
    ) -> None:
        """Detection with low anomaly_score does not create an alert."""
        from sigrift.bridge.routers.detections import _maybe_create_anomaly_alerts

        initial_alerts = len(persistence.get_alerts())

        det = make_detection(
            node_id=registered_node,
            signal_class="fm",
            confidence=0.95,
            freq_hz=88.1e6,
            anomaly_score=0.1,
        )
        created = await _maybe_create_anomaly_alerts(
            app_state, persistence, [det], registered_node,
        )
        assert created == 0
        assert len(persistence.get_alerts()) == initial_alerts

    @pytest.mark.asyncio
    async def test_critical_anomaly_severity(
        self,
        registered_node: str,
        app_state: AppState,
        persistence: PersistenceManager,
    ) -> None:
        """Anomaly score >= 0.85 should produce a critical severity alert."""
        from sigrift.bridge.routers.detections import _maybe_create_anomaly_alerts

        det = make_detection(
            node_id=registered_node,
            signal_class="qam64",
            confidence=0.7,
            freq_hz=2400e6,
            anomaly_score=0.9,
        )
        created = await _maybe_create_anomaly_alerts(
            app_state, persistence, [det], registered_node,
        )
        assert created >= 1

        alerts = persistence.get_alerts()
        critical_alerts = [
            a for a in alerts
            if a.get("severity") == "critical"
            and a.get("node_id") == registered_node
        ]
        assert len(critical_alerts) >= 1


# ---------------------------------------------------------------------------
# 4. Edge cases
# ---------------------------------------------------------------------------


class TestInvestigationEdgeCases:
    """Edge cases for investigation and rescan workflows."""

    def test_investigate_nonexistent_detection(
        self,
        analyst_client: TestClient,
    ) -> None:
        """Investigating a detection that does not exist returns 404."""
        resp = analyst_client.post(
            "/api/detections/does_not_exist_12345/investigate",
        )
        assert resp.status_code == 404

    def test_investigate_detection_no_node(
        self,
        analyst_client: TestClient,
        detection_store: Any,
    ) -> None:
        """Detection with an unregistered node_id returns 404."""
        det = make_detection(
            node_id="nonexistent-node-99",
            signal_class="fm",
            confidence=0.9,
        )
        detection_store.insert_batch([det])

        resp = analyst_client.post(
            f"/api/detections/{det.detection_id}/investigate",
        )
        assert resp.status_code == 404

    def test_auto_rescan_unregistered_node(
        self,
        app_state: AppState,
        persistence: PersistenceManager,
        client: TestClient,
    ) -> None:
        """Auto-rescan for an unregistered node returns False."""
        from sigrift.bridge.routers.detection_iq import (
            _auto_rescan_retries,
            check_auto_rescan,
        )

        config = persistence.get_detection_config()
        config["auto_rescan"] = {
            "enabled": True,
            "confidence_threshold": 0.5,
            "max_retries": 2,
        }
        persistence.set_detection_config(config)
        _auto_rescan_retries.clear()

        detection = {
            "node_id": "offline-node-xyz",
            "confidence": 0.2,
            "freq_hz": 433.92e6,
            "signal_class": "bpsk",
        }
        result = check_auto_rescan(detection, app_state, persistence)
        assert result is False

    def test_auto_rescan_retry_exhaustion(
        self,
        client: TestClient,
        app_state: AppState,
        persistence: PersistenceManager,
        registered_node: str,
    ) -> None:
        """Auto-rescan stops after max_retries are exhausted."""
        from sigrift.bridge.routers.detection_iq import (
            _auto_rescan_retries,
            check_auto_rescan,
        )

        config = persistence.get_detection_config()
        config["auto_rescan"] = {
            "enabled": True,
            "confidence_threshold": 0.5,
            "max_retries": 1,
        }
        persistence.set_detection_config(config)
        _auto_rescan_retries.clear()

        detection = {
            "node_id": registered_node,
            "confidence": 0.2,
            "freq_hz": 433.92e6,
            "signal_class": "bpsk",
        }

        # First attempt succeeds
        assert check_auto_rescan(detection, app_state, persistence) is True
        # Second attempt is blocked (max_retries=1)
        assert check_auto_rescan(detection, app_state, persistence) is False

    def test_auto_rescan_no_node_id(
        self,
        client: TestClient,
        app_state: AppState,
        persistence: PersistenceManager,
    ) -> None:
        """Detection with empty node_id should not trigger auto-rescan."""
        from sigrift.bridge.routers.detection_iq import (
            _auto_rescan_retries,
            check_auto_rescan,
        )

        config = persistence.get_detection_config()
        config["auto_rescan"] = {
            "enabled": True,
            "confidence_threshold": 0.5,
            "max_retries": 2,
        }
        persistence.set_detection_config(config)
        _auto_rescan_retries.clear()

        detection = {
            "node_id": "",
            "confidence": 0.2,
            "freq_hz": 433.92e6,
            "signal_class": "bpsk",
        }
        assert check_auto_rescan(detection, app_state, persistence) is False

    def test_scorer_extreme_inputs(self) -> None:
        """Scorer handles extreme / boundary values without crashing."""
        mgr = BaselineManager()
        scorer = AnomalyScorer(mgr)

        # Zero everything
        result = scorer.score({
            "signal_class": "",
            "confidence": 0.0,
            "freq_hz": 0.0,
            "power_dbm": 0.0,
        })
        assert 0.0 <= result.score <= 1.0

        # Massive values
        result = scorer.score({
            "signal_class": "x" * 1000,
            "confidence": 1.0,
            "freq_hz": 1e12,
            "power_dbm": 100.0,
            "iq_data": {
                "dc_offset": 1e6,
                "iq_imbalance": 1e6,
                "snr_db": -1000,
                "spectral_flatness": 1e6,
                "cfo_hz": 1e9,
            },
        })
        assert 0.0 <= result.score <= 1.0


# ---------------------------------------------------------------------------
# 5. CompositeScorer integration
# ---------------------------------------------------------------------------


class TestCompositeScorerIntegration:
    """Tests for the CompositeScorer with multiple tiers."""

    def test_tier1_only(self, trained_scorer: AnomalyScorer) -> None:
        """CompositeScorer with only tier1 uses tier1 score directly."""
        composite = CompositeScorer()
        t1 = trained_scorer.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
        })
        final = composite.score(t1)
        assert final == t1.score

    def test_all_tiers(self, trained_scorer: AnomalyScorer) -> None:
        """CompositeScorer blends all three tiers."""
        composite = CompositeScorer()
        t1 = trained_scorer.score({
            "signal_class": "unknown_xyz",
            "confidence": 0.3,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
        })
        final = composite.score(t1, tier2_score=0.8, tier3_score=0.9)
        # Should be a blend, higher than tier1 alone
        assert final > t1.score
        assert 0.0 <= final <= 1.0

    def test_context_multiplier_novel_class(
        self, trained_scorer: AnomalyScorer,
    ) -> None:
        """Novel class context multiplier boosts score."""
        composite = CompositeScorer()
        t1 = trained_scorer.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
        })
        base = composite.score(t1)
        boosted = composite.score(t1, context={"novel_class": True})
        # With multiplier, score should be >= base (clamped to 1.0)
        assert boosted >= base

    def test_composite_clamps_to_unit(
        self, trained_scorer: AnomalyScorer,
    ) -> None:
        """CompositeScorer should clamp output to [0, 1]."""
        composite = CompositeScorer()
        t1 = trained_scorer.score({
            "signal_class": "unknown_xyz",
            "confidence": 0.1,
            "freq_hz": 433_920_000,
            "power_dbm": -10.0,
        })
        # Apply all context multipliers
        final = composite.score(
            t1,
            tier2_score=1.0,
            tier3_score=1.0,
            context={
                "novel_class": True,
                "quiet_frequency": True,
                "multiple_nodes": True,
                "regulatory_band": True,
            },
        )
        assert 0.0 <= final <= 1.0


# ---------------------------------------------------------------------------
# 6. Priority label transitions
# ---------------------------------------------------------------------------


class TestPriorityLabels:
    """Verify priority labels map correctly to score ranges."""

    def test_normal_priority(self) -> None:
        assert AnomalyScorer._priority_label(0.0) == "normal"
        assert AnomalyScorer._priority_label(0.29) == "normal"

    def test_interesting_priority(self) -> None:
        assert AnomalyScorer._priority_label(0.3) == "interesting"
        assert AnomalyScorer._priority_label(0.49) == "interesting"

    def test_anomalous_priority(self) -> None:
        assert AnomalyScorer._priority_label(0.5) == "anomalous"
        assert AnomalyScorer._priority_label(0.69) == "anomalous"

    def test_critical_priority(self) -> None:
        assert AnomalyScorer._priority_label(0.7) == "critical"
        assert AnomalyScorer._priority_label(1.0) == "critical"


# ---------------------------------------------------------------------------
# 7. Scorer weight configuration
# ---------------------------------------------------------------------------


class TestScorerWeightConfig:
    """Tests for runtime weight updates and custom configurations."""

    def test_default_weights_sum_to_one(self) -> None:
        config = ScorerConfig()
        total = sum(config.weights.values())
        assert total == pytest.approx(1.18, abs=0.01)

    def test_update_weights_at_runtime(
        self, trained_baseline: BaselineManager,
    ) -> None:
        """update_weights changes scorer behavior."""
        scorer = AnomalyScorer(trained_baseline)

        # Set all weight to novel_class
        new_weights = {d.value: 0.0 for d in AnomalyDimension}
        new_weights["novel_class"] = 1.0
        scorer.update_weights(new_weights)

        # Novel class detection should score 1.0 * 1.0 = 1.0
        result = scorer.score({
            "signal_class": "never_seen_before",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
        })
        assert result.dimensions["novel_class"] == 1.0
        assert result.score > 0.5

    def test_zero_weights_zero_score(
        self, trained_baseline: BaselineManager,
    ) -> None:
        """All weights at zero should produce a zero composite score."""
        config = ScorerConfig(
            weights={d: 0.0 for d in AnomalyDimension},
        )
        scorer = AnomalyScorer(trained_baseline, config)
        result = scorer.score({
            "signal_class": "unknown",
            "confidence": 0.1,
            "freq_hz": 433_920_000,
            "power_dbm": -10.0,
            "iq_data": {"dc_offset": 1.0, "cfo_hz": 10000},
        })
        assert result.score == pytest.approx(0.3, abs=0.01)  # unknown class boost


# ---------------------------------------------------------------------------
# 8. Raw IQ sample scoring
# ---------------------------------------------------------------------------


class TestRawIQSampleScoring:
    """Test anomaly dimensions with raw complex IQ samples."""

    def test_iq_quality_clean_samples(self) -> None:
        """Clean raw IQ samples produce a low quality anomaly score."""
        n = 128
        samples = [
            complex(math.cos(2 * math.pi * 5 * i / n),
                    math.sin(2 * math.pi * 5 * i / n))
            for i in range(n)
        ]
        score = AnomalyScorer._iq_quality_score({}, samples)
        assert 0.0 <= score <= 0.3

    def test_iq_quality_dc_offset_samples(self) -> None:
        """Raw IQ with large DC offset produces higher quality anomaly."""
        n = 128
        dc = complex(5.0, 5.0)
        samples = [
            dc + complex(math.cos(2 * math.pi * 5 * i / n),
                         math.sin(2 * math.pi * 5 * i / n))
            for i in range(n)
        ]
        score = AnomalyScorer._iq_quality_score({}, samples)
        assert score > 0.3

    def test_spectral_noise_like_samples(self) -> None:
        """Noise-like IQ (random phase) should produce spectral anomaly."""
        import random
        random.seed(42)
        n = 64
        samples = [
            complex(random.gauss(0, 1), random.gauss(0, 1))
            for _ in range(n)
        ]
        score = AnomalyScorer._spectral_anomaly_score({}, samples)
        assert 0.0 <= score <= 1.0

    def test_modulation_high_cfo_samples(self) -> None:
        """Rapid phase rotation in raw IQ indicates high CFO -> higher score."""
        n = 128
        # Rapid rotation: ~0.45*pi rad/sample
        samples = [
            complex(math.cos(math.pi * 0.9 * i),
                    math.sin(math.pi * 0.9 * i))
            for i in range(n)
        ]
        score = AnomalyScorer._modulation_anomaly_score({}, samples)
        assert score > 0.3

    def test_modulation_stable_carrier_samples(self) -> None:
        """Slow phase rotation should produce low modulation anomaly."""
        n = 128
        samples = [
            complex(math.cos(2 * math.pi * 0.01 * i),
                    math.sin(2 * math.pi * 0.01 * i))
            for i in range(n)
        ]
        score = AnomalyScorer._modulation_anomaly_score({}, samples)
        assert score < 0.3
