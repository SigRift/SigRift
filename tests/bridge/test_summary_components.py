"""Receiver transactions preserve legacy evidence without inventing precision."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import sqlite3
import threading

import pytest

from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.detection_summaries import (
    DetectionSummaryStore,
    SummaryConflict,
)
from sigrift.edge.summary_protocol import canonical_json


def hour_ago(hours=0):
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime(
        "%Y-%m-%dT%H:00:00Z"
    )


def row(count=1, hour=None):
    return dict(
        hour=hour or hour_ago(),
        signal_class="bpsk",
        family="PSK",
        freq_bin_hz=915e6,
        detection_count=count,
        avg_confidence=0.8,
        min_confidence=0.7,
        max_confidence=0.9,
        avg_snr_db=None,
        avg_power_dbm=-50,
        avg_anomaly=0.1,
        max_anomaly=0.2,
    )


def payload(count=1, *, node="node-1", stream="a" * 32, hour=None):
    value = dict(
        protocol="rf-summary-v2",
        stream_id=stream,
        node_id=node,
        hour=hour or hour_ago(),
        generation=count,
        summaries=[row(count, hour)],
        high_anomaly_detections=[],
    )
    return sign(value)


def sign(value):
    value.pop("payload_digest", None)
    value["payload_digest"] = hashlib.sha256(canonical_json(value)).hexdigest()
    return value


@pytest.fixture
def receiver(tmp_path):
    ctx = SharedContext(tmp_path / "receiver.db")
    try:
        yield ctx, DetectionSummaryStore(ctx)
    finally:
        ctx.close()


def test_upgrade_preserves_exact_legacy_base_and_immediate_independent_contribution(
    receiver,
):
    ctx, store = receiver
    original = row(7)
    original.update(avg_confidence=0.8123, avg_snr_db=7.12)
    store.insert_summaries("node-1", [original])
    before = tuple(
        ctx.get_conn().execute("SELECT * FROM detection_summaries_hourly").fetchone()
    )
    body = payload()
    first = store.accept_snapshot(body)
    assert store.accept_snapshot(body) == first
    assert (
        tuple(
            ctx.get_conn()
            .execute("SELECT * FROM detection_summaries_hourly")
            .fetchone()
        )
        == before
    )
    components = {r["component"]: r for r in store.get_summaries(node_id="node-1")}
    assert set(components) == {"legacy_base", "stream_summary"}
    assert components["legacy_base"]["detection_count"] == 7
    assert components["legacy_base"]["avg_snr_db"] == 7.12
    assert components["stream_summary"]["detection_count"] == 1
    assert components["stream_summary"]["avg_snr_db"] is None
    assert "pooled_mean" not in components["legacy_base"]
    assert (
        ctx.get_conn().execute("SELECT COUNT(*) FROM rf_summary_streams").fetchone()[0]
        == 1
    )


def test_snapshot_failure_rolls_back_registration_and_preserves_legacy_writes(receiver):
    ctx, store = receiver
    ctx.get_conn().execute(
        "CREATE TRIGGER break_component BEFORE INSERT ON rf_summary_components BEGIN SELECT RAISE(ABORT,'storage fault'); END"
    )
    with pytest.raises(sqlite3.IntegrityError):
        store.accept_snapshot(payload())
    assert (
        ctx.get_conn().execute("SELECT COUNT(*) FROM rf_summary_streams").fetchone()[0]
        == 0
    )
    store.insert_summaries("node-1", [row(3)])
    ctx.get_conn().execute("DROP TRIGGER break_component")
    store.accept_snapshot(payload())
    assert sorted(r["detection_count"] for r in store.get_summaries()) == [1, 3]


def test_old_direct_sql_is_refused_and_other_nodes_remain_writable(receiver):
    ctx, store = receiver
    store.insert_summaries("node-1", [row(2)])
    store.accept_snapshot(payload())
    with pytest.raises(SummaryConflict):
        store.insert_summaries("node-1", [row(99)])
    for sql in (
        "UPDATE detection_summaries_hourly SET detection_count=99 WHERE node_id='node-1'",
        "INSERT OR REPLACE INTO detection_summaries_hourly(hour,node_id,signal_class,family,freq_bin_hz,detection_count,tenant_id) SELECT hour,node_id,signal_class,family,freq_bin_hz,99,tenant_id FROM detection_summaries_hourly WHERE node_id='node-1'",
    ):
        with pytest.raises(sqlite3.IntegrityError), ctx.write_transaction() as conn:
            conn.execute(sql)
    store.insert_summaries("node-2", [row(4)])
    assert store.get_summaries(node_id="node-2")[0]["detection_count"] == 4
    assert sorted(
        r["detection_count"] for r in store.get_summaries(node_id="node-1")
    ) == [1, 2]


def test_raw_rollup_is_separate_and_does_not_block_unregistered_nodes(receiver):
    ctx, store = receiver
    hour = hour_ago(3)
    store.insert_summaries("node-1", [row(7, hour)])
    store.accept_snapshot(payload(2, hour=hour))
    with ctx.write_transaction() as conn:
        for node in ("node-1", "node-2"):
            conn.execute(
                "INSERT INTO detections(detection_id,node_id,timestamp,signal_class,confidence,family,freq_hz,snr_db,power_dbm,tenant_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    node + "-raw",
                    node,
                    hour,
                    "bpsk",
                    0.9,
                    "PSK",
                    915e6,
                    15,
                    -60,
                    "default",
                ),
            )
    assert store.rollup_from_raw(1) == 2
    protected = {r["component"]: r for r in store.get_summaries(node_id="node-1")}
    assert {k: r["detection_count"] for k, r in protected.items()} == {
        "legacy_base": 7,
        "stream_summary": 2,
        "raw_rollup": 1,
    }
    assert protected["raw_rollup"]["legacy_overlap"] == "unknown"
    assert store.get_summaries(node_id="node-2")[0]["detection_count"] == 1
    assert store.rollup_from_raw(1) == 2
    assert {
        r["component"]: r["detection_count"]
        for r in store.get_summaries(node_id="node-1")
    } == {"legacy_base": 7, "stream_summary": 2, "raw_rollup": 1}


@pytest.mark.parametrize(
    "change", ["old", "same_changed", "changed_stream", "missing_bin"]
)
def test_stale_conflicting_or_shrinking_snapshot_preserves_state(receiver, change):
    _, store = receiver
    store.accept_snapshot(payload(2))
    before = store.get_summaries()
    candidate = payload(1 if change == "old" else 2)
    if change == "same_changed":
        candidate["summaries"][0]["avg_confidence"] = 0.81
    elif change == "changed_stream":
        candidate["stream_id"] = "b" * 32
    elif change == "missing_bin":
        candidate = payload(3)
        candidate["summaries"][0]["signal_class"] = "qpsk"
    with pytest.raises(SummaryConflict):
        store.accept_snapshot(sign(candidate))
    assert store.get_summaries() == before


@pytest.mark.parametrize("value", [True, -1, 0, 2**63, 1.5])
def test_invalid_generations_never_register(receiver, value):
    ctx, store = receiver
    candidate = payload()
    candidate["generation"] = value
    with pytest.raises(ValueError):
        store.accept_snapshot(sign(candidate))
    assert (
        ctx.get_conn().execute("SELECT COUNT(*) FROM rf_summary_streams").fetchone()[0]
        == 0
    )


def test_two_independent_connections_register_only_one_stream(tmp_path):
    path = tmp_path / "shared.db"
    first, second = SharedContext(path), SharedContext(path)
    gate = threading.Barrier(2)
    try:

        def run(ctx, stream):
            gate.wait(timeout=3)
            try:
                DetectionSummaryStore(ctx).accept_snapshot(payload(stream=stream))
                return "accepted"
            except SummaryConflict:
                return "refused"

        with ThreadPoolExecutor(2) as pool:
            futures = [
                pool.submit(run, ctx, stream)
                for ctx, stream in ((first, "a" * 32), (second, "b" * 32))
            ]
            assert sorted(f.result(timeout=5) for f in futures) == [
                "accepted",
                "refused",
            ]
        assert len(DetectionSummaryStore(first).get_summaries()) == 1
    finally:
        first.close()
        second.close()


def test_fixed_tenant_components_and_legacy_unique_index_do_not_cross(tmp_path):
    path = tmp_path / "tenants.db"
    local, foreign = SharedContext(path), SharedContext(path, tenant_id="foreign")
    try:
        a, b = DetectionSummaryStore(local), DetectionSummaryStore(foreign)
        a.insert_summaries("node-1", [row(4)])
        a.accept_snapshot(payload(2))
        b.insert_summaries("node-1", [row(8)])
        b.accept_snapshot(payload(3, stream="b" * 32))
        assert sorted(r["detection_count"] for r in a.get_summaries()) == [2, 4]
        assert sorted(r["detection_count"] for r in b.get_summaries()) == [3, 8]
    finally:
        local.close()
        foreign.close()


def test_retention_does_not_allow_stale_snapshot_to_resurrect_deleted_component(
    receiver,
):
    _, store = receiver
    body = payload(2, hour=hour_ago(72))
    store.accept_snapshot(body)
    store.cleanup_summaries(max_age_days=1)
    assert store.get_summaries(hours=96) == []
    with pytest.raises(SummaryConflict, match="retired"):
        store.accept_snapshot(body)
    with pytest.raises(SummaryConflict, match="retired"):
        store.accept_snapshot(payload(3, hour=body["hour"]))
