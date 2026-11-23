"""Raw last-hour frequency buckets, independent of the recent-feed/chart window."""

from contextlib import closing
from datetime import datetime, timedelta, timezone

import pytest

from sigrift.bridge.models import DetectionRecord
from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.detection_analytics import DetectionAnalyticsStore
from sigrift.bridge.storage.detection_crud import DetectionCrudStore


def observation(freq, *, node="radio-a", age=0, signal_class="bpsk"):
    return DetectionRecord(
        node_id=node,
        freq_hz=freq,
        signal_class=signal_class,
        confidence=0.9,
        power_dbm=-50,
        timestamp=datetime.now(timezone.utc) - timedelta(seconds=age),
    )


@pytest.fixture
def stores(tmp_path):
    with closing(SharedContext(tmp_path / "frequencies.db")) as ctx:
        yield ctx, DetectionCrudStore(ctx), DetectionAnalyticsStore(ctx)


def test_empty_hour_is_zero(stores):
    _, _, stats = stores
    result = stats.get_stats().model_dump()
    assert result["active_frequencies"] == 0
    assert result["total_detections"] == 0


@pytest.mark.parametrize("hours", [1, 6, 24])
def test_floor_buckets_use_last_hour_not_selected_chart_window(stores, hours):
    ctx, crud, stats = stores
    # The first three frequencies share one floor bucket, despite crossing
    # the midpoint. The fourth starts the adjacent bucket. Class/power do
    # not create additional frequency buckets. Old and zero frequencies do not count.
    rows = [
        observation(433_900_000),
        observation(433_949_999),
        observation(433_999_999, signal_class="qam16"),
        observation(434_000_000),
        observation(500_000_000, age=3590),
        observation(600_000_000, age=3610),
        observation(700_000_000, age=7200),
        observation(0),
    ]
    assert crud.insert_batch(rows) == 8
    before = list(
        ctx.get_conn().execute("SELECT * FROM detections ORDER BY detection_id")
    )
    result = stats.get_stats(hours=hours)
    assert result.active_frequencies == 3
    assert result.total_detections == (6 if hours == 1 else 8)
    assert (
        list(ctx.get_conn().execute("SELECT * FROM detections ORDER BY detection_id"))
        == before
    )


def test_node_and_fixed_tenant_scope(stores):
    ctx, crud, stats = stores
    crud.insert_batch([observation(100_000), observation(200_000, node="radio-b")])
    with closing(SharedContext(ctx._db_path, tenant_id="other")) as foreign:
        DetectionCrudStore(foreign).insert_batch([observation(300_000)])
        assert DetectionAnalyticsStore(foreign).get_stats().active_frequencies == 1
    assert stats.get_stats().active_frequencies == 2
    assert stats.get_stats(node_id="radio-a").active_frequencies == 1
    assert stats.get_stats(node_id="absent").active_frequencies == 0


def test_insert_invalidates_cached_count_and_reopen_preserves_observations(stores):
    ctx, crud, stats = stores
    assert stats.get_stats().active_frequencies == 0
    crud.insert_batch([observation(1), observation(99_999), observation(100_000)])
    assert stats.get_stats().active_frequencies == 2
    with closing(SharedContext(ctx._db_path)) as reopened:
        assert DetectionAnalyticsStore(reopened).get_stats().active_frequencies == 2
        assert DetectionCrudStore(reopened).row_count() == 3


def test_authenticated_stats_api_exposes_hour_count_with_node_filter(
    client, detection_store
):
    detection_store.insert_batch(
        [
            observation(433_900_000),
            observation(433_999_999),
            observation(434_000_000, node="radio-b"),
            observation(600_000_000, age=7200),
        ]
    )
    response = client.get("/api/detections/stats?hours=24")
    assert response.status_code == 200
    assert response.json()["active_frequencies"] == 2
    assert response.json()["total_detections"] == 4
    filtered = client.get("/api/detections/stats?hours=24&node_id=radio-a")
    assert filtered.status_code == 200
    assert filtered.json()["active_frequencies"] == 1
    assert filtered.json()["total_detections"] == 3
