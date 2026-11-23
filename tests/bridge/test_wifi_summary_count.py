"""Summary counts use the real active Wi-Fi queue, not a cached/list-page proxy."""

from datetime import datetime, timedelta, timezone
import sqlite3
import time

import pytest

from sigrift.bridge.detection_store import DetectionStore


def add_anomaly(store, number=1, *, score=0.7, node="synthetic-wifi-a"):
    return store.insert_wifi_anomaly(
        {
            "bssid": f"02:53:49:00:{number // 256:02x}:{number % 256:02x}",
            "ssid": "Synthetic summary test",
            "node_id": node,
            "anomaly_score": score,
            # Queue age is deliberately independent of metadata's 24-hour window.
            "timestamp": (datetime.now(timezone.utc) - timedelta(days=3)).isoformat(),
        }
    )


def stats(client):
    response = client.get("/api/wifi/stats")
    assert response.status_code == 200
    return response.json()


def test_empty_authenticated_stats_exposes_numeric_zero(client):
    result = stats(client)
    assert result["anomaly_count"] == 0
    assert type(result["anomaly_count"]) is int
    assert result["total_networks"] == result["total_clients"] == 0


@pytest.mark.parametrize(
    ("score", "state", "expected"),
    [
        (0.299, "active", 0),
        (0.3, "active", 1),
        (0.9, "dismissed", 0),
        (0.9, "snoozed", 0),
        (0.9, "expired", 1),
    ],
)
def test_stats_matches_default_active_list(
    client, detection_store, score, state, expected
):
    row_id = add_anomaly(detection_store, score=score)
    if state == "dismissed":
        detection_store.dismiss_wifi_anomaly(row_id)
    elif state in {"snoozed", "expired"}:
        delta = timedelta(hours=1 if state == "snoozed" else -1)
        detection_store.snooze_wifi_anomaly(
            row_id, (datetime.now(timezone.utc) + delta).isoformat()
        )
    before = tuple(
        detection_store.get_connection()
        .execute("SELECT * FROM wifi_anomalies WHERE id = ?", (row_id,))
        .fetchone()
    )
    assert stats(client)["anomaly_count"] == expected
    response = client.get("/api/wifi/anomalies")
    assert response.status_code == 200
    assert response.json()["total"] == response.json()["count"] == expected
    after = tuple(
        detection_store.get_connection()
        .execute("SELECT * FROM wifi_anomalies WHERE id = ?", (row_id,))
        .fetchone()
    )
    assert after == before  # Observing stats does not resolve/re-score stored records.


def test_count_is_tenant_scoped_across_nodes_and_beyond_first_page(
    client, detection_store
):
    for i in range(53):
        add_anomaly(detection_store, i, node=f"synthetic-wifi-{i % 2}")
    foreign = DetectionStore(detection_store.db_path, tenant_id="other")
    try:
        add_anomaly(foreign, 100)
        response = client.get("/api/wifi/anomalies")
        assert response.status_code == 200
        assert response.json()["count"] == 50
        assert response.json()["total"] == stats(client)["anomaly_count"] == 53
        assert foreign.get_wifi_stats()["anomaly_count"] == 1
    finally:
        foreign.close()


def test_refresh_sees_other_worker_insert_dismiss_and_snooze(client, detection_store):
    assert stats(client)["anomaly_count"] == 0  # Warm the metadata cache.
    cached_metadata = detection_store._wifi_meta.get_wifi_stats()
    other = DetectionStore(detection_store.db_path)
    try:
        first = add_anomaly(other, 1)
        second = add_anomaly(other, 2)
        assert stats(client)["anomaly_count"] == 2
        other.dismiss_wifi_anomaly(first)
        assert stats(client)["anomaly_count"] == 1
        other.snooze_wifi_anomaly(
            second, (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        )
        assert stats(client)["anomaly_count"] == 0
        assert detection_store._wifi_meta.get_wifi_stats() is cached_metadata
        assert "anomaly_count" not in cached_metadata
    finally:
        other.close()


def test_snooze_expiry_refreshes_count_without_a_write_or_cache_reset(detection_store):
    row_id = add_anomaly(detection_store)
    detection_store.snooze_wifi_anomaly(
        row_id, (datetime.now(timezone.utc) + timedelta(seconds=1.5)).isoformat()
    )
    assert detection_store.get_wifi_stats()["anomaly_count"] == 0
    cached_metadata = detection_store._wifi_meta.get_wifi_stats()
    conn = detection_store.get_connection()
    writes = conn.total_changes
    deadline = time.monotonic() + 5
    while detection_store.get_wifi_stats()["anomaly_count"] == 0:
        assert time.monotonic() < deadline, "Expired snooze remained hidden"
        time.sleep(0.02)
    assert detection_store.get_wifi_stats()["anomaly_count"] == 1
    assert conn.total_changes == writes
    assert detection_store._wifi_meta.get_wifi_stats() is cached_metadata


def test_count_read_failure_is_not_reported_as_zero(detection_store):
    detection_store.get_wifi_stats()  # Previously cached metadata must not hide failure.
    conn = detection_store.get_connection()
    conn.execute("DROP TABLE wifi_anomalies")
    conn.commit()
    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        detection_store.get_wifi_stats()


def test_authenticated_count_endpoint_still_rejects_wrong_key(client, detection_store):
    add_anomaly(detection_store)
    response = client.get(
        "/api/wifi/stats", headers={"X-API-Key": "wrong-synthetic-key"}
    )
    assert response.status_code == 401
    assert "anomaly_count" not in response.json()


def test_stats_result_does_not_mutate_prior_response(detection_store):
    original = detection_store.get_wifi_stats()
    add_anomaly(detection_store)
    current = detection_store.get_wifi_stats()
    assert original["anomaly_count"] == 0
    assert current["anomaly_count"] == 1
    assert original is not current
