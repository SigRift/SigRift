"""Tests for geolocation providers, adapters, and registry integration."""

import time

import pytest

pytest.importorskip(
    "sigrift.providers.geo_tdoa",
    reason="TDOA provider is enterprise-only and not shipped in community",
)

from sigrift.providers.base import GeoEstimate, GeoProvider, SignalObservation
from sigrift.providers.adapters import (
    detections_to_observations,
    geo_estimate_to_tdoa_dict,
)
from sigrift.providers.geo_tdoa import TDOAGeoProvider
from sigrift.providers.geo_rss import RSSGeoProvider
from sigrift.providers.null import NullGeoProvider


# ---------------------------------------------------------------------------
# TDOAGeoProvider
# ---------------------------------------------------------------------------


class TestTDOAGeoProvider:
    def test_name(self):
        assert TDOAGeoProvider().name == "TDOAGeoProvider"

    def test_min_receivers(self):
        assert TDOAGeoProvider().min_receivers == 3

    def test_insufficient_observations(self):
        provider = TDOAGeoProvider()
        obs = [
            SignalObservation(frequency_hz=433e6, timestamp_ns=int(time.time() * 1e9), power_dbm=-50, node_id="n1"),
            SignalObservation(frequency_hz=433e6, timestamp_ns=int(time.time() * 1e9), power_dbm=-50, node_id="n2"),
        ]
        result = provider.estimate(obs)
        assert result.confidence == 0.0
        assert result.method == "tdoa"

    def test_configure_coordinate_mode(self):
        provider = TDOAGeoProvider()
        provider.configure({"coordinate_mode": "geo", "max_time_spread_sec": 0.05})
        assert provider._config["coordinate_mode"] == "geo"

    def test_estimate_returns_geo_estimate(self):
        provider = TDOAGeoProvider()
        provider.configure({"coordinate_mode": "2d"})
        now = time.time()
        obs = [
            SignalObservation(
                frequency_hz=433e6,
                timestamp_ns=int(now * 1e9),
                power_dbm=-50,
                node_id=f"n{i}",
                signal_class="fm",
                metadata={"node_position": {"x_m": float(i * 10), "y_m": 0.0}},
            )
            for i in range(4)
        ]
        # Stagger timestamps slightly for TDOA
        for i, o in enumerate(obs):
            o.timestamp_ns += i * 1_000_000  # 1ms apart
        result = provider.estimate(obs)
        assert isinstance(result, GeoEstimate)
        assert result.method == "tdoa"

    def test_metadata_preserved(self):
        provider = TDOAGeoProvider()
        provider.configure({"coordinate_mode": "2d"})
        now = time.time()
        obs = [
            SignalObservation(
                frequency_hz=433e6,
                timestamp_ns=int((now + i * 0.001) * 1e9),
                power_dbm=-50,
                node_id=f"n{i}",
                signal_class="fm",
                metadata={"node_position": {"x_m": float(i * 50), "y_m": float(i * 30)}},
            )
            for i in range(4)
        ]
        result = provider.estimate(obs)
        if result.confidence > 0:
            assert "coordinate_mode" in result.metadata
            assert "tdoa_pairs" in result.metadata
            assert result.metadata["coordinate_mode"] == "2d"


# ---------------------------------------------------------------------------
# RSSGeoProvider
# ---------------------------------------------------------------------------


class TestRSSGeoProvider:
    def test_name(self):
        assert RSSGeoProvider().name == "RSSGeoProvider"

    def test_min_receivers(self):
        assert RSSGeoProvider().min_receivers == 2

    def test_insufficient_observations(self):
        provider = RSSGeoProvider()
        obs = [SignalObservation(frequency_hz=433e6, timestamp_ns=0, power_dbm=-50, node_id="n1")]
        result = provider.estimate(obs)
        assert result.confidence == 0.0
        assert result.method == "rss"

    def test_configure_path_loss(self):
        provider = RSSGeoProvider()
        provider.configure({"path_loss_exponent": 3.0, "reference_rssi_dbm": -40.0})
        assert provider._path_loss_exponent == 3.0
        assert provider._reference_rssi_dbm == -40.0


# ---------------------------------------------------------------------------
# NullGeoProvider
# ---------------------------------------------------------------------------


class TestNullGeoProvider:
    def test_returns_zero_confidence(self):
        provider = NullGeoProvider()
        result = provider.estimate([])
        assert result.confidence == 0.0
        assert result.method == "none"

    def test_min_receivers_zero(self):
        assert NullGeoProvider().min_receivers == 0


# ---------------------------------------------------------------------------
# Adapters
# ---------------------------------------------------------------------------


class TestDetectionsToObservations:
    def test_basic_conversion(self):
        dets = [
            {"node_id": "n1", "timestamp": time.time(), "freq_hz": 433e6, "signal_class": "fm", "power_dbm": -50},
            {"node_id": "n2", "timestamp": time.time(), "freq_hz": 433e6, "signal_class": "fm", "power_dbm": -55},
        ]
        positions = {
            "n1": {"x_m": 0.0, "y_m": 0.0},
            "n2": {"x_m": 10.0, "y_m": 0.0},
        }
        obs = detections_to_observations(dets, positions)
        assert len(obs) == 2
        assert obs[0].node_id == "n1"
        assert obs[0].frequency_hz == 433e6
        assert obs[0].metadata["node_position"]["x_m"] == 0.0

    def test_skips_unknown_nodes(self):
        dets = [
            {"node_id": "n1", "timestamp": time.time(), "freq_hz": 433e6},
            {"node_id": "unknown", "timestamp": time.time(), "freq_hz": 433e6},
        ]
        positions = {"n1": {"x_m": 0.0, "y_m": 0.0}}
        obs = detections_to_observations(dets, positions)
        assert len(obs) == 1

    def test_iso_timestamp(self):
        dets = [{"node_id": "n1", "timestamp": "2026-04-10T12:00:00+00:00", "freq_hz": 433e6}]
        positions = {"n1": {"x_m": 0.0, "y_m": 0.0}}
        obs = detections_to_observations(dets, positions)
        assert len(obs) == 1
        assert obs[0].timestamp_ns > 0

    def test_missing_timestamp_skipped(self):
        dets = [{"node_id": "n1", "freq_hz": 433e6}]
        positions = {"n1": {"x_m": 0.0, "y_m": 0.0}}
        obs = detections_to_observations(dets, positions)
        assert len(obs) == 0


class TestGeoEstimateToTdoaDict:
    def test_roundtrip(self):
        estimate = GeoEstimate(
            latitude=40.7128,
            longitude=-74.0060,
            confidence=0.85,
            error_radius_m=15.0,
            method="tdoa",
            metadata={
                "estimate_id": "test-123",
                "signal_class": "fm",
                "freq_hz": 433e6,
                "gdop": 2.5,
                "cep_m": 15.0,
                "tdoa_pairs": [{"node_a": "n1", "node_b": "n2", "tdoa_ns": 100}],
                "coordinate_mode": "geo",
                "contributing_nodes": ["n1", "n2", "n3"],
                "time_spread_ms": 5.0,
                "node_count": 3,
                "location": {"lat": 40.7128, "lon": -74.0060},
            },
        )
        d = geo_estimate_to_tdoa_dict(estimate)
        assert d["estimate_id"] == "test-123"
        assert d["confidence"] == 0.85
        assert d["gdop"] == 2.5
        assert d["location"]["lat"] == 40.7128
        assert d["coordinate_mode"] == "geo"
        assert len(d["tdoa_pairs"]) == 1
        assert d["node_count"] == 3

    def test_generates_estimate_id_if_missing(self):
        estimate = GeoEstimate(confidence=0.5, method="tdoa")
        d = geo_estimate_to_tdoa_dict(estimate)
        assert d["estimate_id"]  # should be a UUID
        assert len(d["estimate_id"]) > 10


# ---------------------------------------------------------------------------
# GeoProvider interface compliance
# ---------------------------------------------------------------------------


class TestProviderInterface:
    @pytest.mark.parametrize("cls", [TDOAGeoProvider, RSSGeoProvider, NullGeoProvider])
    def test_is_geo_provider(self, cls):
        assert issubclass(cls, GeoProvider)

    @pytest.mark.parametrize("cls", [TDOAGeoProvider, RSSGeoProvider, NullGeoProvider])
    def test_has_configure(self, cls):
        provider = cls()
        provider.configure({})  # should not raise

    @pytest.mark.parametrize("cls", [TDOAGeoProvider, RSSGeoProvider, NullGeoProvider])
    def test_estimate_returns_geo_estimate(self, cls):
        provider = cls()
        result = provider.estimate([])
        assert isinstance(result, GeoEstimate)
