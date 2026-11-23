"""Tests for multi-tenant data isolation.

Verifies that data written by tenant A is invisible to tenant B
across all storage sub-stores: detections, RF anomalies, WiFi
anomalies, WiFi metadata, audit log, and feedback.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.models import DetectionRecord

def _make_detection(**kwargs) -> DetectionRecord:
    defaults = dict(
        node_id="node-01",
        signal_class="bpsk",
        confidence=0.95,
        family="psk",
        freq_hz=433.92e6,
        snr_db=15.0,
        anomaly_score=0.0,
    )
    defaults.update(kwargs)
    return DetectionRecord(**defaults)

@pytest.fixture
def store_a(tmp_path: Path) -> DetectionStore:
    """DetectionStore for tenant 'alpha'."""
    return DetectionStore(db_path=tmp_path / "multi.db", tenant_id="alpha")

@pytest.fixture
def store_b(tmp_path: Path) -> DetectionStore:
    """DetectionStore for tenant 'bravo', sharing the same DB file."""
    return DetectionStore(db_path=tmp_path / "multi.db", tenant_id="bravo")

@pytest.fixture
def store_default(tmp_path: Path) -> DetectionStore:
    """DetectionStore for the default tenant."""
    return DetectionStore(db_path=tmp_path / "multi.db", tenant_id="default")

# -----------------------------------------------------------------------
# Detection CRUD isolation
# -----------------------------------------------------------------------

class TestDetectionIsolation:
    def test_insert_and_query_isolated(self, store_a, store_b):
        """Tenant A inserts detections; tenant B sees nothing."""
        dets = [_make_detection(anomaly_score=0.1)]
        store_a.insert_batch(dets)

        assert store_a.row_count() == 1
        assert store_b.row_count() == 0

    def test_get_recent_isolated(self, store_a, store_b):
        store_a.insert_batch([_make_detection()])
        assert len(store_a.get_recent(minutes=60)) == 1
        assert len(store_b.get_recent(minutes=60)) == 0

    def test_get_detection_by_id_isolated(self, store_a, store_b):
        det = _make_detection(detection_id="det-iso-1")
        store_a.insert_batch([det])
        assert store_a.get_detection_by_id("det-iso-1") is not None
        assert store_b.get_detection_by_id("det-iso-1") is None

    def test_stats_isolated(self, store_a, store_b):
        store_a.insert_batch([_make_detection()])
        stats_a = store_a.get_stats(hours=24)
        stats_b = store_b.get_stats(hours=24)
        assert stats_a.total_detections == 1
        assert stats_b.total_detections == 0

# -----------------------------------------------------------------------
# RF anomaly isolation
# -----------------------------------------------------------------------

class TestRFAnomalyIsolation:
    def test_insert_and_query_isolated(self, store_a, store_b):
        anomalies = [{
            "detection_id": "rf-1",
            "signal_class": "bpsk",
            "family": "psk",
            "freq_hz": 433.92e6,
            "node_id": "node-01",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "confidence": 0.9,
            "anomaly_score": 0.8,
        }]
        store_a.insert_rf_anomalies_batch(anomalies)

        result_a = store_a.get_rf_anomalies(min_score=0.3)
        result_b = store_b.get_rf_anomalies(min_score=0.3)
        assert len(result_a) == 1
        assert len(result_b) == 0

    def test_count_isolated(self, store_a, store_b):
        anomalies = [{
            "signal_class": "qpsk",
            "freq_hz": 915e6,
            "node_id": "node-01",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "anomaly_score": 0.6,
        }]
        store_a.insert_rf_anomalies_batch(anomalies)
        assert store_a.count_rf_anomalies(min_score=0.3) == 1
        assert store_b.count_rf_anomalies(min_score=0.3) == 0

    def test_dismiss_isolated(self, store_a, store_b):
        """Dismissing in tenant B should not affect tenant A."""
        anomalies = [{
            "signal_class": "bpsk",
            "freq_hz": 433.92e6,
            "node_id": "node-01",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "anomaly_score": 0.8,
        }]
        ids = store_a.insert_rf_anomalies_batch(anomalies)
        # Tenant B tries to dismiss tenant A's anomaly — should not work
        store_b.dismiss_rf_anomaly(ids[0])
        result_a = store_a.get_rf_anomalies(min_score=0.3)
        assert len(result_a) == 1  # Still visible to A

    def test_get_by_ids_isolated(self, store_a, store_b):
        """Tenant B cannot fetch (and so escalate) tenant A's anomaly by ID."""
        ids = store_a.insert_rf_anomalies_batch([{
            "signal_class": "bpsk",
            "freq_hz": 433.92e6,
            "node_id": "node-01",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "anomaly_score": 0.8,
        }])
        assert [r["id"] for r in store_a.get_rf_anomalies_by_ids(ids)] == ids
        assert store_b.get_rf_anomalies_by_ids(ids) == []

# -----------------------------------------------------------------------
# WiFi anomaly isolation
# -----------------------------------------------------------------------

class TestWiFiAnomalyIsolation:
    def test_insert_and_query_isolated(self, store_a, store_b):
        anomaly = {
            "bssid": "AA:BB:CC:DD:EE:FF",
            "ssid": "TestNet",
            "channel": 6,
            "anomaly_score": 0.7,
            "priority": "anomalous",
            "node_id": "node-01",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        store_a.insert_wifi_anomaly(anomaly)

        result_a = store_a.get_wifi_anomalies(min_score=0.3)
        result_b = store_b.get_wifi_anomalies(min_score=0.3)
        assert len(result_a) == 1
        assert len(result_b) == 0

    def test_count_isolated(self, store_a, store_b):
        anomaly = {
            "bssid": "11:22:33:44:55:66",
            "anomaly_score": 0.5,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        store_a.insert_wifi_anomaly(anomaly)
        assert store_a.count_wifi_anomalies(min_score=0.3) == 1
        assert store_b.count_wifi_anomalies(min_score=0.3) == 0

    def test_get_by_ids_isolated(self, store_a, store_b):
        """Tenant B cannot fetch (and so escalate) tenant A's anomaly by ID."""
        anomaly_id = store_a.insert_wifi_anomaly({
            "bssid": "11:22:33:44:55:77",
            "anomaly_score": 0.5,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        assert [r["id"] for r in store_a.get_wifi_anomalies_by_ids([anomaly_id])] == [
            anomaly_id
        ]
        assert store_b.get_wifi_anomalies_by_ids([anomaly_id]) == []

# -----------------------------------------------------------------------
# Audit log isolation
# -----------------------------------------------------------------------

class TestAuditIsolation:
    def test_audit_log_isolated(self, store_a, store_b):
        store_a.log_audit(action="dismiss", target_id="det-1")
        log_a = store_a.get_audit_log()
        log_b = store_b.get_audit_log()
        assert len(log_a) == 1
        assert len(log_b) == 0

    def test_dismissed_ids_isolated(self, store_a, store_b):
        store_a.log_audit(action="dismiss", target_id="det-x")
        assert "det-x" in store_a.get_dismissed_ids()
        assert "det-x" not in store_b.get_dismissed_ids()

    def test_is_dismissed_isolated(self, store_a, store_b):
        store_a.log_audit(action="dismiss", target_id="det-y")
        assert store_a.is_dismissed("det-y") is True
        assert store_b.is_dismissed("det-y") is False

# -----------------------------------------------------------------------
# Feedback isolation
# -----------------------------------------------------------------------

class TestFeedbackIsolation:
    def test_feedback_isolated(self, store_a, store_b):
        # Insert a detection first so the FK works
        store_a.insert_batch([_make_detection(detection_id="fb-det-1")])
        store_a.add_feedback("fb-det-1", "true_positive", note="yes")

        fb_a = store_a.get_feedback("fb-det-1")
        fb_b = store_b.get_feedback("fb-det-1")
        assert len(fb_a) == 1
        assert len(fb_b) == 0

# -----------------------------------------------------------------------
# Default tenant backward compatibility
# -----------------------------------------------------------------------

class TestDefaultTenant:
    def test_default_tenant_works(self, store_default):
        """Default tenant can read its own data."""
        store_default.insert_batch([_make_detection(detection_id="def-1")])
        assert store_default.row_count() == 1
        assert store_default.get_detection_by_id("def-1") is not None

    def test_default_tenant_isolated_from_named(self, store_default, store_a):
        store_default.insert_batch([_make_detection(detection_id="def-2")])
        assert store_default.row_count() >= 1
        assert store_a.get_detection_by_id("def-2") is None
