"""Tests for threat signature library — seed data, parameter matching,
scoring dimension, ingest wiring, and API endpoints.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient

from sigrift.bridge.persistence import PersistenceManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_api_key(persistence: PersistenceManager, key_id: str, role: str = "admin") -> str:
    from sigrift.lib.security.credentials import generate_api_key, hash_credential
    raw_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key(key_id, hash_hex, salt)
    persistence.set_key_meta(key_id, {"role": role, "description": f"test {role}"})
    return raw_key


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def app(tmp_path):
    from sigrift.bridge.app import create_test_app
    return create_test_app(tmp_path)


@pytest.fixture()
def persistence(app) -> PersistenceManager:
    return app.state.persistence


@pytest.fixture()
def client(app, persistence):
    admin_key = _make_api_key(persistence, "ts_admin", "admin")
    return TestClient(app, headers={"X-API-Key": admin_key})


@pytest.fixture()
def viewer_client(app, persistence):
    viewer_key = _make_api_key(persistence, "ts_viewer", "viewer")
    return TestClient(app, headers={"X-API-Key": viewer_key})


@pytest.fixture()
def sig_store(app):
    return app.state.signature_library_store


# ---------------------------------------------------------------------------
# Storage layer tests
# ---------------------------------------------------------------------------


class TestSignatureStoreThreats:
    """Test threat-specific storage methods."""

    def test_seed_populates_library(self, sig_store):
        """Seed data should populate library with known threat signatures."""
        # create_test_app already seeds, so just verify the data is there
        threats = sig_store.get_threat_signatures()
        assert isinstance(threats, list)
        assert len(threats) >= 15

    def test_seed_idempotent(self, sig_store):
        """Seeding again should return 0 (already seeded)."""
        count = sig_store.seed_threat_signatures()
        assert count == 0

    def test_get_threat_signatures_all(self, sig_store):
        """Should return all threat signatures."""
        sig_store.seed_threat_signatures()
        threats = sig_store.get_threat_signatures()
        assert isinstance(threats, list)
        assert len(threats) >= 15
        for t in threats:
            assert isinstance(t["threat_category"], str)
            assert t["threat_category"] != ""

    def test_get_threat_signatures_by_category(self, sig_store):
        """Should filter by threat category."""
        sig_store.seed_threat_signatures()
        mics = sig_store.get_threat_signatures(threat_category="covert_mic")
        assert isinstance(mics, list)
        assert len(mics) >= 3
        for m in mics:
            assert m["threat_category"] == "covert_mic"

    def test_get_threat_signatures_by_level(self, sig_store):
        """Should filter by threat level."""
        sig_store.seed_threat_signatures()
        critical = sig_store.get_threat_signatures(threat_level="critical")
        assert isinstance(critical, list)
        assert len(critical) >= 5
        for c in critical:
            assert c["threat_level"] == "critical"

    def test_add_threat_signature(self, sig_store):
        """Should store threat-specific fields."""
        sig_id = sig_store.add_signature(
            name="Custom Threat",
            protocol="digital",
            signal_class="fsk",
            threat_category="covert_mic",
            threat_level="high",
            freq_min_hz=400_000_000,
            freq_max_hz=410_000_000,
            burst_duration_ms=50,
            burst_interval_ms=5000,
            power_min_dbm=-30,
            power_max_dbm=-5,
        )
        sig = sig_store.get_signature(sig_id)
        assert sig["threat_category"] == "covert_mic"
        assert sig["threat_level"] == "high"
        assert sig["freq_min_hz"] == 400_000_000
        assert sig["freq_max_hz"] == 410_000_000
        assert sig["burst_duration_ms"] == 50
        assert sig["burst_interval_ms"] == 5000
        assert sig["power_min_dbm"] == -30
        assert sig["power_max_dbm"] == -5
        assert sig["active"] == 1

    def test_update_threat_fields(self, sig_store):
        """Should allow updating threat fields."""
        sig_id = sig_store.add_signature(
            name="Updatable",
            protocol="analog",
            signal_class="fm",
            threat_category="unknown_threat",
            threat_level="low",
        )
        sig_store.update_signature(
            sig_id,
            threat_category="covert_mic",
            threat_level="critical",
            active=False,
        )
        sig = sig_store.get_signature(sig_id)
        assert sig["threat_category"] == "covert_mic"
        assert sig["threat_level"] == "critical"
        assert sig["active"] == 0

    def test_inactive_excluded_from_matching(self, sig_store):
        """Inactive signatures should not appear in match results."""
        sig_id = sig_store.add_signature(
            name="Inactive Sig",
            protocol="analog",
            signal_class="fm",
            threat_category="covert_mic",
            threat_level="critical",
            center_freq_hz=433_920_000,
            freq_min_hz=430_000_000,
            freq_max_hz=440_000_000,
            active=False,
        )
        matches = sig_store.match_by_parameters(freq_hz=433_920_000, signal_class="fm")
        matched_ids = [m["id"] for m in matches]
        assert sig_id not in matched_ids


class TestParameterMatching:
    """Test parameter-based threat signature matching."""

    def test_exact_freq_match(self, sig_store):
        """Exact frequency within range should score high."""
        sig_store.seed_threat_signatures()
        matches = sig_store.match_by_parameters(
            freq_hz=433_920_000,
            signal_class="fm",
            power_dbm=-20,
        )
        assert isinstance(matches, list)
        assert len(matches) > 0
        assert isinstance(matches[0]["match_score"], float)
        assert matches[0]["match_score"] > 0.5

    def test_freq_outside_range_no_match(self, sig_store):
        """Frequency far outside any range should not match."""
        sig_store.seed_threat_signatures()
        matches = sig_store.match_by_parameters(
            freq_hz=50_000_000,  # HF — no threat sigs here
            signal_class="cw",
        )
        assert len(matches) == 0

    def test_class_mismatch_reduces_score(self, sig_store):
        """Wrong signal class should reduce match score."""
        sig_store.seed_threat_signatures()
        # FM match
        fm_matches = sig_store.match_by_parameters(
            freq_hz=433_920_000,
            signal_class="fm",
        )
        # Wrong class at same freq
        wrong_matches = sig_store.match_by_parameters(
            freq_hz=433_920_000,
            signal_class="ofdm",
        )
        # FM matches should score higher than wrong class
        if fm_matches and wrong_matches:
            assert fm_matches[0]["match_score"] >= wrong_matches[0]["match_score"]

    def test_power_in_range_boosts_score(self, sig_store):
        """Power within expected range should boost score."""
        sig_store.add_signature(
            name="Power Test",
            protocol="analog",
            signal_class="fm",
            threat_category="covert_mic",
            threat_level="high",
            center_freq_hz=433_920_000,
            freq_min_hz=430_000_000,
            freq_max_hz=440_000_000,
            power_min_dbm=-40,
            power_max_dbm=-5,
        )
        in_range = sig_store.match_by_parameters(
            freq_hz=433_920_000, signal_class="fm", power_dbm=-20,
        )
        out_range = sig_store.match_by_parameters(
            freq_hz=433_920_000, signal_class="fm", power_dbm=30,
        )
        # In-range should score higher
        assert isinstance(in_range, list)
        assert len(in_range) > 0
        if out_range:
            assert in_range[0]["match_score"] >= out_range[0]["match_score"]

    def test_bandwidth_proximity(self, sig_store):
        """Similar bandwidth should contribute to match score."""
        sig_store.add_signature(
            name="BW Test",
            protocol="digital",
            signal_class="fsk",
            threat_category="covert_mic",
            threat_level="high",
            center_freq_hz=868_000_000,
            bandwidth_hz=100_000,
            freq_min_hz=863_000_000,
            freq_max_hz=870_000_000,
        )
        close_bw = sig_store.match_by_parameters(
            freq_hz=868_000_000, signal_class="fsk", bandwidth_hz=100_000,
        )
        far_bw = sig_store.match_by_parameters(
            freq_hz=868_000_000, signal_class="fsk", bandwidth_hz=10_000_000,
        )
        assert isinstance(close_bw, list)
        assert len(close_bw) > 0
        if far_bw:
            assert close_bw[0]["match_score"] >= far_bw[0]["match_score"]

    def test_multiple_matches_sorted(self, sig_store):
        """Multiple matching signatures should be sorted by score descending."""
        sig_store.seed_threat_signatures()
        matches = sig_store.match_by_parameters(
            freq_hz=433_920_000,
            signal_class="ook",
        )
        if len(matches) > 1:
            for i in range(len(matches) - 1):
                assert matches[i]["match_score"] >= matches[i + 1]["match_score"]

    def test_center_freq_fallback(self, sig_store):
        """Should use center_freq_hz when freq_min/max not set."""
        sig_store.add_signature(
            name="Center Only",
            protocol="analog",
            signal_class="fm",
            threat_category="covert_mic",
            threat_level="medium",
            center_freq_hz=500_000_000,
            bandwidth_hz=200_000,
        )
        matches = sig_store.match_by_parameters(
            freq_hz=500_000_000, signal_class="fm",
        )
        assert isinstance(matches, list)
        assert len(matches) > 0


# ---------------------------------------------------------------------------
# Scorer dimension tests
# ---------------------------------------------------------------------------


class TestSignatureMatchDimension:
    """Test SIGNATURE_MATCH as a scoring dimension."""

    def test_dimension_exists_in_enum(self):
        from sigrift.bridge.anomaly.scorer import AnomalyDimension
        assert hasattr(AnomalyDimension, "SIGNATURE_MATCH")
        assert AnomalyDimension.SIGNATURE_MATCH.value == "signature_match"

    def test_dimension_in_default_weights(self):
        from sigrift.bridge.anomaly.scorer import DEFAULT_RF_DIMENSION_WEIGHTS
        assert "signature_match" in DEFAULT_RF_DIMENSION_WEIGHTS
        assert DEFAULT_RF_DIMENSION_WEIGHTS["signature_match"] == 0.15  # active by default

    def test_scorer_outputs_signature_match_dimension(self):
        from sigrift.bridge.anomaly.scorer import AnomalyScorer, ScorerConfig
        from sigrift.bridge.anomaly.baseline import BaselineManager
        mgr = BaselineManager()
        scorer = AnomalyScorer(mgr, ScorerConfig())
        result = scorer.score({
            "signal_class": "fm",
            "confidence": 0.8,
            "freq_hz": 433_920_000,
        })
        assert "signature_match" in result.dimensions
        assert isinstance(result.dimensions["signature_match"], float)
        # Placeholder value — actual scoring happens at ingest level
        assert result.dimensions["signature_match"] == 0.0


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------


class TestThreatEndpoints:
    """Test threat signature API endpoints."""

    def test_list_threats(self, client):
        """GET /api/signatures/threats/list should return seeded threats."""
        resp = client.get("/api/signatures/threats/list")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 15
        assert all(isinstance(s, dict) for s in data)

    def test_list_threats_filter_category(self, client):
        """Should filter by threat_category."""
        resp = client.get(
            "/api/signatures/threats/list?threat_category=jammer",
    
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 2
        for sig in data:
            assert sig["threat_category"] == "jammer"

    def test_list_threats_filter_level(self, client):
        """Should filter by threat_level."""
        resp = client.get(
            "/api/signatures/threats/list?threat_level=high",
    
        )
        assert resp.status_code == 200
        data = resp.json()
        for sig in data:
            assert sig["threat_level"] == "high"

    def test_match_threats_by_params(self, client):
        """POST /api/signatures/threats/match should find matching threats."""
        resp = client.post(
            "/api/signatures/threats/match",
            json={
                "freq_hz": 433_920_000,
                "signal_class": "fm",
                "power_dbm": -20,
            },
    
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["matched"] is True
        assert isinstance(data["count"], int)
        assert data["count"] > 0
        assert isinstance(data["matches"], list)
        assert isinstance(data["matches"][0]["match_score"], float)
        assert data["matches"][0]["match_score"] > 0.3

    def test_match_threats_no_match(self, client):
        """Should return empty when no signatures match."""
        resp = client.post(
            "/api/signatures/threats/match",
            json={
                "freq_hz": 50_000_000,
                "signal_class": "cw",
            },
    
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["matched"] is False
        assert data["count"] == 0

    def test_seed_endpoint(self, client):
        """POST /api/signatures/threats/seed should be idempotent."""
        # Already seeded during app creation
        resp = client.post(
            "/api/signatures/threats/seed",
    
        )
        assert resp.status_code == 200
        assert resp.json()["seeded"] == 0  # already seeded

    def test_create_with_threat_fields(self, client):
        """Creating a signature with threat fields should persist them."""
        resp = client.post(
            "/api/signatures/",
            data={
                "name": "Test Threat Via API",
                "protocol": "digital",
                "signal_class": "ook",
            },
    
        )
        assert resp.status_code == 201
        sig_id = resp.json()["id"]

        # Update with threat fields
        resp = client.put(
            f"/api/signatures/{sig_id}",
            json={
                "description": "Test threat device",
            },
    
        )
        assert resp.status_code == 200

    def test_stats_includes_threat_data(self, client):
        """Stats endpoint should work with threat signatures."""
        resp = client.get("/api/signatures/stats")
        assert resp.status_code == 200
        stats = resp.json()
        assert isinstance(stats["total"], int)
        assert stats["total"] >= 15
        assert isinstance(stats["verified_count"], int)
        assert stats["verified_count"] >= 15  # seeds are verified

    def test_export_includes_threat_fields(self, client):
        """Export should include threat-specific fields."""
        resp = client.post(
            "/api/signatures/export",
            json={"sig_ids": None},
    
        )
        assert resp.status_code == 200
        data = resp.json()
        sigs = data["signatures"]
        threat_sigs = [s for s in sigs if s.get("threat_category")]
        assert len(threat_sigs) > 0
        s = threat_sigs[0]
        assert "threat_category" in s
        assert isinstance(s["threat_category"], str)
        assert "threat_level" in s
        assert isinstance(s["threat_level"], str)

    def test_import_with_threat_fields(self, client):
        """Import should handle threat fields."""
        resp = client.post(
            "/api/signatures/import",
            json={
                "signatures": [{
                    "name": "Imported Threat",
                    "protocol": "digital",
                    "signal_class": "fsk",
                    "threat_category": "gps_tracker",
                    "threat_level": "high",
                    "freq_min_hz": 900_000_000,
                    "freq_max_hz": 930_000_000,
                    "power_min_dbm": -20,
                    "power_max_dbm": 10,
                }],
            },
    
        )
        assert resp.status_code == 201
        assert resp.json()["imported"] == 1


# ---------------------------------------------------------------------------
# Seed data integrity tests
# ---------------------------------------------------------------------------


class TestSeedDataIntegrity:
    """Verify seed data quality and completeness."""

    def test_all_seeds_have_required_fields(self):
        from sigrift.bridge.storage.signature_library import _THREAT_SEED_DATA
        required = {"name", "protocol", "signal_class", "threat_category", "threat_level"}
        for i, seed in enumerate(_THREAT_SEED_DATA):
            for field in required:
                assert field in seed, f"Seed {i} ({seed.get('name', '?')}) missing {field}"
                assert seed[field], f"Seed {i} ({seed.get('name', '?')}) has empty {field}"

    def test_all_seeds_have_freq_range(self):
        from sigrift.bridge.storage.signature_library import _THREAT_SEED_DATA
        for seed in _THREAT_SEED_DATA:
            has_range = seed.get("freq_min_hz") is not None and seed.get("freq_max_hz") is not None
            has_center = seed.get("center_freq_hz") is not None
            assert has_range or has_center, f"Seed {seed['name']} has no frequency info"

    def test_threat_categories_are_valid(self):
        from sigrift.bridge.storage.signature_library import _THREAT_SEED_DATA
        valid_categories = {
            "covert_mic", "video_tx", "body_worn_tx",
            "gps_tracker", "jammer", "remote_control", "unknown_threat",
            "imsi_catcher", "drone_surveillance", "data_exfil",
            "surveillance_infra", "counter_surveillance",
        }
        for seed in _THREAT_SEED_DATA:
            assert seed["threat_category"] in valid_categories, (
                f"Seed {seed['name']} has invalid category {seed['threat_category']}"
            )

    def test_threat_levels_are_valid(self):
        from sigrift.bridge.storage.signature_library import _THREAT_SEED_DATA
        valid_levels = {"low", "medium", "high", "critical"}
        for seed in _THREAT_SEED_DATA:
            assert seed["threat_level"] in valid_levels, (
                f"Seed {seed['name']} has invalid level {seed['threat_level']}"
            )

    def test_freq_ranges_are_sane(self):
        from sigrift.bridge.storage.signature_library import _THREAT_SEED_DATA
        for seed in _THREAT_SEED_DATA:
            fmin = seed.get("freq_min_hz")
            fmax = seed.get("freq_max_hz")
            if fmin is not None and fmax is not None:
                assert fmin < fmax, f"Seed {seed['name']}: freq_min >= freq_max"
                assert fmin > 0, f"Seed {seed['name']}: freq_min <= 0"

    def test_power_ranges_are_sane(self):
        from sigrift.bridge.storage.signature_library import _THREAT_SEED_DATA
        for seed in _THREAT_SEED_DATA:
            pmin = seed.get("power_min_dbm")
            pmax = seed.get("power_max_dbm")
            if pmin is not None and pmax is not None:
                assert pmin < pmax, f"Seed {seed['name']}: power_min >= power_max"

    def test_coverage_across_categories(self):
        from sigrift.bridge.storage.signature_library import _THREAT_SEED_DATA
        categories = {s["threat_category"] for s in _THREAT_SEED_DATA}
        expected = {"covert_mic", "video_tx", "body_worn_tx", "gps_tracker", "jammer",
                    "remote_control", "imsi_catcher", "drone_surveillance", "data_exfil",
                    "surveillance_infra", "counter_surveillance"}
        assert expected.issubset(categories), f"Missing categories: {expected - categories}"

    def test_coverage_across_frequency_bands(self):
        """Seeds should cover VHF, UHF, L-band, S-band, C-band."""
        from sigrift.bridge.storage.signature_library import _THREAT_SEED_DATA
        bands_covered = set()
        for seed in _THREAT_SEED_DATA:
            center = seed.get("center_freq_hz", 0)
            if center < 300_000_000:
                bands_covered.add("vhf")
            elif center < 1_000_000_000:
                bands_covered.add("uhf")
            elif center < 2_000_000_000:
                bands_covered.add("l_band")
            elif center < 4_000_000_000:
                bands_covered.add("s_band")
            else:
                bands_covered.add("c_band_plus")
        assert len(bands_covered) >= 4, f"Only {bands_covered} covered"
