"""Bulk re-evaluate-and-dismiss only dismisses rows it can name.

A queue row that the scorer resolves but that arrives without its row id
cannot be targeted, so it must stay in the queue rather than be guessed at
or take another row with it. Real SQLite store, real route and auth; only the
scorer and the id of one listed row are replaced.
"""

from __future__ import annotations

from types import SimpleNamespace


def test_resolved_row_without_an_id_is_left_in_the_queue(
    client, bridge_app, detection_store, monkeypatch
):
    detection_store.insert_rf_anomalies_batch(
        [
            {
                "detection_id": detection_id,
                "signal_class": "bpsk",
                "freq_hz": freq_hz,
                "node_id": "node-a",
                "timestamp": "2026-11-18T00:00:00+00:00",
                "anomaly_score": 0.8,
            }
            for detection_id, freq_hz in (
                ("det-named", 433.92e6),
                ("det-anon", 868.3e6),
            )
        ]
    )
    listed = detection_store.get_rf_anomalies

    def without_one_id(**options):
        rows = listed(**options)
        return [
            {k: v for k, v in row.items() if k != "id"}
            if row["detection_id"] == "det-anon"
            else row
            for row in rows
        ]

    dismissed_batches = []
    dismiss = detection_store.dismiss_rf_anomalies_bulk

    def recording_dismiss(ids):
        dismissed_batches.append(list(ids))
        return dismiss(ids)

    named_id = next(
        row["id"] for row in listed(limit=10) if row["detection_id"] == "det-named"
    )
    monkeypatch.setattr(detection_store, "get_rf_anomalies", without_one_id)
    monkeypatch.setattr(detection_store, "dismiss_rf_anomalies_bulk", recording_dismiss)
    # Both rows re-score as resolved.
    monkeypatch.setattr(
        bridge_app.state,
        "rf_scorer",
        SimpleNamespace(score=lambda anomaly: SimpleNamespace(score=0.05)),
    )
    response = client.post("/api/detections/anomalies/bulk/reeval-dismiss")
    assert response.status_code == 200
    assert response.json() == {
        "ok": True,
        "processed": 2,
        "still_anomalous": 0,
        "dismissed": 1,
        "errors": 0,
        "remaining_total": 1,
    }
    # Only the named row was sent for dismissal; the other one is still active.
    assert dismissed_batches == [[named_id]]
    monkeypatch.setattr(detection_store, "get_rf_anomalies", listed)
    remaining = client.get("/api/detections/anomalies").json()["anomalies"]
    assert [row["detection_id"] for row in remaining] == ["det-anon"]
