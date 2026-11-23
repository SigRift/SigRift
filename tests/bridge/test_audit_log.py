"""Tests for the audit log feature in DetectionStore.

Covers:
  - log_audit() writes entries
  - get_audit_log() with filters
  - get_dismissed_ids() returns dismissed detection IDs
  - is_dismissed() checks individual IDs
  - Audit log persistence across DetectionStore instances
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sigrift.bridge.detection_store import DetectionStore

# ---------------------------------------------------------------------------
# log_audit tests
# ---------------------------------------------------------------------------

class TestLogAudit:
    """Tests for DetectionStore.log_audit."""

    def test_log_audit_basic(self, detection_store: DetectionStore) -> None:
        """Basic audit entry is written and returned."""
        entry = detection_store.log_audit(
            action="dismiss",
            target_id="det_001",
            signal_class="bpsk",
            freq_hz=433.92e6,
            node_id="node-01",
            operator="test-key",
        )
        assert entry["action"] == "dismiss"
        assert entry["target_id"] == "det_001"
        assert entry["signal_class"] == "bpsk"
        assert entry["freq_hz"] == 433.92e6
        assert entry["node_id"] == "node-01"
        assert entry["operator"] == "test-key"
        assert isinstance(entry["timestamp"], str) and len(entry["timestamp"]) > 0

    def test_log_audit_with_details(self, detection_store: DetectionStore) -> None:
        """Audit entry with details dict."""
        entry = detection_store.log_audit(
            action="feedback",
            target_id="det_002",
            details={"label": "true_positive", "extra": 42},
        )
        assert entry["details"] == {"label": "true_positive", "extra": 42}

    def test_log_audit_with_target_ids(self, detection_store: DetectionStore) -> None:
        """Audit entry with bulk target_ids."""
        ids = ["det_001", "det_002", "det_003"]
        entry = detection_store.log_audit(
            action="bulk_dismiss",
            target_id="det_001",
            target_ids=ids,
        )
        assert entry["target_ids"] == ids

    def test_log_audit_with_note(self, detection_store: DetectionStore) -> None:
        """Audit entry with a note."""
        entry = detection_store.log_audit(
            action="dismiss",
            target_id="det_001",
            note="False alarm confirmed",
        )
        assert entry["note"] == "False alarm confirmed"

    def test_log_audit_defaults(self, detection_store: DetectionStore) -> None:
        """Audit entry with only required fields uses defaults."""
        entry = detection_store.log_audit(
            action="dismiss",
            target_id="det_001",
        )
        assert entry["signal_class"] == ""
        assert entry["freq_hz"] == 0.0
        assert entry["node_id"] == ""
        assert entry["operator"] == ""
        assert entry["note"] == ""
        assert entry["details"] == {}
        assert entry["target_ids"] == []

# ---------------------------------------------------------------------------
# get_audit_log tests
# ---------------------------------------------------------------------------

class TestGetAuditLog:
    """Tests for DetectionStore.get_audit_log."""

    def test_get_audit_log_empty(self, detection_store: DetectionStore) -> None:
        """Empty audit log returns empty list."""
        assert detection_store.get_audit_log() == []

    def test_get_audit_log_returns_entries(self, detection_store: DetectionStore) -> None:
        """Written entries are returned."""
        detection_store.log_audit(action="dismiss", target_id="det_001")
        detection_store.log_audit(action="baseline", target_id="det_002")
        entries = detection_store.get_audit_log()
        assert len(entries) == 2
        assert all(isinstance(e, dict) for e in entries)

    def test_get_audit_log_order(self, detection_store: DetectionStore) -> None:
        """Entries are returned newest first."""
        detection_store.log_audit(action="dismiss", target_id="det_001")
        detection_store.log_audit(action="baseline", target_id="det_002")
        entries = detection_store.get_audit_log()
        assert entries[0]["target_id"] == "det_002"  # newer
        assert entries[1]["target_id"] == "det_001"  # older

    def test_get_audit_log_filter_action(self, detection_store: DetectionStore) -> None:
        """Filter by action type."""
        detection_store.log_audit(action="dismiss", target_id="det_001")
        detection_store.log_audit(action="baseline", target_id="det_002")
        detection_store.log_audit(action="dismiss", target_id="det_003")

        entries = detection_store.get_audit_log(action="dismiss")
        assert len(entries) == 2
        assert all(e["action"] == "dismiss" for e in entries)

    def test_get_audit_log_filter_target_id(self, detection_store: DetectionStore) -> None:
        """Filter by target_id."""
        detection_store.log_audit(action="dismiss", target_id="det_001")
        detection_store.log_audit(action="feedback", target_id="det_001")
        detection_store.log_audit(action="dismiss", target_id="det_002")

        entries = detection_store.get_audit_log(target_id="det_001")
        assert len(entries) == 2
        assert all(e["target_id"] == "det_001" for e in entries)

    def test_get_audit_log_limit(self, detection_store: DetectionStore) -> None:
        """Limit parameter works."""
        for i in range(10):
            detection_store.log_audit(action="dismiss", target_id=f"det_{i:03d}")
        entries = detection_store.get_audit_log(limit=3)
        assert len(entries) == 3
        assert all(isinstance(e, dict) for e in entries)

    def test_get_audit_log_json_parsing(self, detection_store: DetectionStore) -> None:
        """JSON fields (details, target_ids) are parsed correctly."""
        detection_store.log_audit(
            action="bulk_dismiss",
            target_id="det_001",
            target_ids=["det_001", "det_002"],
            details={"reason": "test"},
        )
        entries = detection_store.get_audit_log()
        assert len(entries) == 1
        assert isinstance(entries[0], dict)
        assert entries[0]["target_ids"] == ["det_001", "det_002"]
        assert entries[0]["details"] == {"reason": "test"}

# ---------------------------------------------------------------------------
# get_dismissed_ids tests
# ---------------------------------------------------------------------------

class TestGetDismissedIds:
    """Tests for DetectionStore.get_dismissed_ids."""

    def test_no_dismissed(self, detection_store: DetectionStore) -> None:
        """Empty audit log returns empty set."""
        assert detection_store.get_dismissed_ids() == set()

    def test_dismiss_actions(self, detection_store: DetectionStore) -> None:
        """dismiss actions are included."""
        detection_store.log_audit(action="dismiss", target_id="det_001")
        detection_store.log_audit(action="dismiss", target_id="det_002")
        assert detection_store.get_dismissed_ids() == {"det_001", "det_002"}

    def test_bulk_dismiss_actions(self, detection_store: DetectionStore) -> None:
        """bulk_dismiss actions are included."""
        detection_store.log_audit(action="bulk_dismiss", target_id="det_003")
        assert detection_store.get_dismissed_ids() == {"det_003"}

    def test_other_actions_excluded(self, detection_store: DetectionStore) -> None:
        """Non-dismiss actions are not included."""
        detection_store.log_audit(action="dismiss", target_id="det_001")
        detection_store.log_audit(action="baseline", target_id="det_002")
        detection_store.log_audit(action="feedback", target_id="det_003")
        assert detection_store.get_dismissed_ids() == {"det_001"}

    def test_deduplicated(self, detection_store: DetectionStore) -> None:
        """Same detection dismissed twice still returns once."""
        detection_store.log_audit(action="dismiss", target_id="det_001")
        detection_store.log_audit(action="dismiss", target_id="det_001")
        assert detection_store.get_dismissed_ids() == {"det_001"}

# ---------------------------------------------------------------------------
# is_dismissed tests
# ---------------------------------------------------------------------------

class TestIsDismissed:
    """Tests for DetectionStore.is_dismissed."""

    def test_not_dismissed(self, detection_store: DetectionStore) -> None:
        """Returns False for unknown ID."""
        assert detection_store.is_dismissed("det_999") is False

    def test_is_dismissed_after_dismiss(self, detection_store: DetectionStore) -> None:
        """Returns True after dismiss action."""
        detection_store.log_audit(action="dismiss", target_id="det_001")
        assert detection_store.is_dismissed("det_001") is True
        assert detection_store.is_dismissed("det_002") is False

    def test_is_dismissed_after_bulk_dismiss(self, detection_store: DetectionStore) -> None:
        """Returns True after bulk_dismiss action."""
        detection_store.log_audit(action="bulk_dismiss", target_id="det_001")
        assert detection_store.is_dismissed("det_001") is True

# ---------------------------------------------------------------------------
# Persistence across instances
# ---------------------------------------------------------------------------

class TestAuditPersistence:
    """Test audit data persists across DetectionStore instances."""

    def test_audit_survives_reopen(self, tmp_path: Path) -> None:
        """Audit entries survive closing and reopening the store."""
        db_path = tmp_path / "audit_persist.db"

        store1 = DetectionStore(db_path=db_path)
        store1.log_audit(action="dismiss", target_id="det_001")
        store1.log_audit(action="baseline", target_id="det_002")
        store1.close()

        store2 = DetectionStore(db_path=db_path)
        entries = store2.get_audit_log()
        assert len(entries) == 2
        assert all(isinstance(e, dict) for e in entries)
        assert store2.get_dismissed_ids() == {"det_001"}
        store2.close()

    def test_dismissed_ids_survive_reopen(self, tmp_path: Path) -> None:
        """Dismissed IDs are available after store restart."""
        db_path = tmp_path / "dismissed_persist.db"

        store1 = DetectionStore(db_path=db_path)
        store1.log_audit(action="dismiss", target_id="det_001")
        store1.log_audit(action="bulk_dismiss", target_id="det_002")
        store1.close()

        store2 = DetectionStore(db_path=db_path)
        dismissed = store2.get_dismissed_ids()
        assert isinstance(dismissed, set)
        assert "det_001" in dismissed
        assert "det_002" in dismissed
        store2.close()

# ---------------------------------------------------------------------------
# Extended filtering tests (offset, operator, node_id, search, date range)
# ---------------------------------------------------------------------------

class TestAuditLogExtendedFilters:
    """Tests for the expanded audit log filtering capabilities."""

    def _seed(self, store: DetectionStore) -> None:
        """Seed the store with varied audit entries."""
        store.log_audit(action="dismiss", target_id="det_001", operator="key_alice", node_id="node-01", note="false alarm")
        store.log_audit(action="baseline", target_id="det_002", operator="key_bob", node_id="node-02", note="baseline set")
        store.log_audit(action="feedback", target_id="det_003", operator="key_alice", node_id="node-01", note="confirmed threat")
        store.log_audit(action="dismiss", target_id="det_004", operator="key_bob", node_id="node-03")
        store.log_audit(action="bulk_dismiss", target_id="det_005", operator="key_charlie", node_id="node-01")

    def test_filter_by_operator(self, detection_store: DetectionStore) -> None:
        """Filter audit entries by operator."""
        self._seed(detection_store)
        entries = detection_store.get_audit_log(operator="key_alice")
        assert len(entries) == 2
        assert all(e["operator"] == "key_alice" for e in entries)

    def test_filter_by_node_id(self, detection_store: DetectionStore) -> None:
        """Filter audit entries by node_id."""
        self._seed(detection_store)
        entries = detection_store.get_audit_log(node_id="node-01")
        assert len(entries) == 3
        assert all(e["node_id"] == "node-01" for e in entries)

    def test_filter_by_search_note(self, detection_store: DetectionStore) -> None:
        """Search filter matches note content."""
        self._seed(detection_store)
        entries = detection_store.get_audit_log(search="alarm")
        assert len(entries) == 1
        assert entries[0]["note"] == "false alarm"

    def test_filter_by_search_target_id(self, detection_store: DetectionStore) -> None:
        """Search filter matches target_id."""
        self._seed(detection_store)
        entries = detection_store.get_audit_log(search="det_003")
        assert len(entries) == 1
        assert entries[0]["target_id"] == "det_003"

    def test_filter_by_search_action(self, detection_store: DetectionStore) -> None:
        """Search filter matches action names."""
        self._seed(detection_store)
        entries = detection_store.get_audit_log(search="baseline")
        assert len(entries) == 1
        assert entries[0]["action"] == "baseline"

    def test_filter_combined(self, detection_store: DetectionStore) -> None:
        """Multiple filters combine with AND logic."""
        self._seed(detection_store)
        entries = detection_store.get_audit_log(action="dismiss", operator="key_bob")
        assert len(entries) == 1
        assert entries[0]["target_id"] == "det_004"

    def test_offset_pagination(self, detection_store: DetectionStore) -> None:
        """Offset skips the first N entries."""
        self._seed(detection_store)
        all_entries = detection_store.get_audit_log(limit=100)
        offset_entries = detection_store.get_audit_log(limit=100, offset=2)
        assert len(offset_entries) == len(all_entries) - 2
        # offset entries should be the tail (older) entries
        assert offset_entries[0]["target_id"] == all_entries[2]["target_id"]

    def test_limit_and_offset(self, detection_store: DetectionStore) -> None:
        """Limit + offset produces correct page."""
        self._seed(detection_store)
        page = detection_store.get_audit_log(limit=2, offset=1)
        assert len(page) == 2

    def test_date_range_start(self, detection_store: DetectionStore) -> None:
        """Start date filter excludes older entries."""
        self._seed(detection_store)
        entries = detection_store.get_audit_log()
        # Use the timestamp of the 3rd newest entry as start
        mid_ts = entries[2]["timestamp"]
        filtered = detection_store.get_audit_log(start=mid_ts)
        assert len(filtered) >= 3  # entries at or after mid_ts
        assert all(isinstance(e, dict) for e in filtered)

    def test_date_range_end(self, detection_store: DetectionStore) -> None:
        """End date filter excludes newer entries."""
        self._seed(detection_store)
        entries = detection_store.get_audit_log()
        # Use the timestamp of the 3rd newest entry as end
        mid_ts = entries[2]["timestamp"]
        filtered = detection_store.get_audit_log(end=mid_ts)
        assert len(filtered) >= 1  # at least the entry at mid_ts
        assert all(isinstance(e, dict) for e in filtered)

    def test_no_results(self, detection_store: DetectionStore) -> None:
        """Filters that match nothing return empty list."""
        self._seed(detection_store)
        entries = detection_store.get_audit_log(operator="nonexistent")
        assert entries == []

# ---------------------------------------------------------------------------
# Distinct value helpers (for filter dropdowns)
# ---------------------------------------------------------------------------

class TestAuditDistinctHelpers:
    """Tests for get_audit_actions, get_audit_operators, get_audit_node_ids."""

    def test_get_audit_actions_empty(self, detection_store: DetectionStore) -> None:
        """Empty store returns no actions."""
        assert detection_store.get_audit_actions() == []

    def test_get_audit_actions(self, detection_store: DetectionStore) -> None:
        """Returns distinct sorted action types."""
        detection_store.log_audit(action="dismiss", target_id="d1")
        detection_store.log_audit(action="baseline", target_id="d2")
        detection_store.log_audit(action="dismiss", target_id="d3")
        actions = detection_store.get_audit_actions()
        assert actions == ["baseline", "dismiss"]

    def test_get_audit_operators_empty(self, detection_store: DetectionStore) -> None:
        """Empty store returns no operators."""
        assert detection_store.get_audit_operators() == []

    def test_get_audit_operators(self, detection_store: DetectionStore) -> None:
        """Returns distinct operators excluding empty strings."""
        detection_store.log_audit(action="dismiss", target_id="d1", operator="key_a")
        detection_store.log_audit(action="dismiss", target_id="d2", operator="key_b")
        detection_store.log_audit(action="dismiss", target_id="d3", operator="key_a")
        detection_store.log_audit(action="dismiss", target_id="d4")  # empty operator
        operators = detection_store.get_audit_operators()
        assert operators == ["key_a", "key_b"]

    def test_get_audit_node_ids_empty(self, detection_store: DetectionStore) -> None:
        """Empty store returns no node IDs."""
        assert detection_store.get_audit_node_ids() == []

    def test_get_audit_node_ids(self, detection_store: DetectionStore) -> None:
        """Returns distinct node IDs excluding empty strings."""
        detection_store.log_audit(action="dismiss", target_id="d1", node_id="node-01")
        detection_store.log_audit(action="dismiss", target_id="d2", node_id="node-02")
        detection_store.log_audit(action="dismiss", target_id="d3", node_id="node-01")
        detection_store.log_audit(action="dismiss", target_id="d4")  # empty node_id
        node_ids = detection_store.get_audit_node_ids()
        assert node_ids == ["node-01", "node-02"]

# ---------------------------------------------------------------------------
# API endpoint tests for audit log
# ---------------------------------------------------------------------------

class TestAuditEndpoints:
    """Tests for admin audit API endpoints."""

    def test_get_audit_log_endpoint(self, client) -> None:
        """GET /api/admin/audit returns paginated results."""
        # Seed some data
        resp = client.get("/api/admin/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)
        assert "entries" in data
        assert isinstance(data["entries"], list)

    def test_audit_filter_params(self, client, detection_store) -> None:
        """GET /api/admin/audit accepts filter query params."""
        detection_store.log_audit(action="dismiss", target_id="det_e2e", operator="key_test", node_id="node-99")
        resp = client.get("/api/admin/audit", params={
            "action": "dismiss",
            "operator": "key_test",
            "node_id": "node-99",
        })
        assert resp.status_code == 200
        entries = resp.json()["entries"]
        assert len(entries) >= 1
        assert isinstance(entries[0], dict)
        assert entries[0]["operator"] == "key_test"

    def test_audit_search_param(self, client, detection_store) -> None:
        """GET /api/admin/audit search param works."""
        detection_store.log_audit(action="dismiss", target_id="det_searchable", note="unique_needle")
        resp = client.get("/api/admin/audit", params={"search": "unique_needle"})
        assert resp.status_code == 200
        entries = resp.json()["entries"]
        assert len(entries) >= 1
        assert isinstance(entries[0], dict)

    def test_audit_pagination(self, client, detection_store) -> None:
        """GET /api/admin/audit supports limit and offset."""
        for i in range(5):
            detection_store.log_audit(action="dismiss", target_id=f"det_page_{i}")
        resp = client.get("/api/admin/audit", params={"limit": 2, "offset": 1})
        assert resp.status_code == 200
        entries = resp.json()["entries"]
        assert len(entries) == 2

    def test_audit_actions_endpoint(self, client, detection_store) -> None:
        """GET /api/admin/audit/actions returns distinct actions."""
        detection_store.log_audit(action="dismiss", target_id="d1")
        detection_store.log_audit(action="baseline", target_id="d2")
        resp = client.get("/api/admin/audit/actions")
        assert resp.status_code == 200
        actions = resp.json()
        assert isinstance(actions, list)
        assert "dismiss" in actions
        assert "baseline" in actions

    def test_audit_filters_endpoint(self, client, detection_store) -> None:
        """GET /api/admin/audit/filters returns all dropdown values."""
        detection_store.log_audit(action="dismiss", target_id="d1", operator="op1", node_id="n1")
        resp = client.get("/api/admin/audit/filters")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)
        assert "actions" in data
        assert isinstance(data["actions"], list)
        assert "operators" in data
        assert isinstance(data["operators"], list)
        assert "node_ids" in data
        assert isinstance(data["node_ids"], list)
        assert "dismiss" in data["actions"]
        assert "op1" in data["operators"]
        assert "n1" in data["node_ids"]
