"""Tests for FeedbackStore (sigrift.bridge.storage.feedback).

Covers add_feedback with valid/invalid labels, get_feedback,
and get_feedback_by_label.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sigrift.bridge.detection_store import DetectionStore


@pytest.fixture
def store(tmp_path: Path) -> DetectionStore:
    """DetectionStore backed by a temp SQLite file."""
    return DetectionStore(db_path=tmp_path / "feedback_test.db")


class TestAddFeedback:
    """add_feedback stores operator labels."""

    def test_add_valid_label(self, store: DetectionStore):
        row_id = store.add_feedback("det-001", "true_positive", note="confirmed")
        assert row_id > 0

    def test_add_all_valid_labels(self, store: DetectionStore):
        for label in ("true_positive", "false_positive", "expected", "interesting"):
            row_id = store.add_feedback(f"det-{label}", label)
            assert row_id > 0

    def test_add_invalid_label_raises(self, store: DetectionStore):
        with pytest.raises(ValueError, match="label must be one of"):
            store.add_feedback("det-001", "not_a_label")


class TestGetFeedback:
    """get_feedback returns all labels for a detection."""

    def test_get_empty(self, store: DetectionStore):
        assert store.get_feedback("nonexistent") == []

    def test_get_after_add(self, store: DetectionStore):
        store.add_feedback("det-001", "true_positive", note="yes")
        store.add_feedback("det-001", "false_positive", note="changed mind")
        entries = store.get_feedback("det-001")
        assert len(entries) == 2
        # Newest first
        assert entries[0]["label"] == "false_positive"
        assert entries[1]["label"] == "true_positive"


class TestGetFeedbackByLabel:
    """get_feedback_by_label filters across all detections."""

    def test_filter_by_label(self, store: DetectionStore):
        store.add_feedback("det-001", "true_positive")
        store.add_feedback("det-002", "false_positive")
        store.add_feedback("det-003", "true_positive")

        tp = store.get_feedback_by_label("true_positive")
        assert len(tp) == 2
        assert all(e["label"] == "true_positive" for e in tp)

        fp = store.get_feedback_by_label("false_positive")
        assert len(fp) == 1

    def test_limit_respected(self, store: DetectionStore):
        for i in range(10):
            store.add_feedback(f"det-{i:03d}", "expected")
        results = store.get_feedback_by_label("expected", limit=3)
        assert len(results) == 3

    def test_empty_for_unused_label(self, store: DetectionStore):
        store.add_feedback("det-001", "true_positive")
        assert store.get_feedback_by_label("interesting") == []
