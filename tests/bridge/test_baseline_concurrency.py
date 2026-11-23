"""Regression tests: baseline save/prune vs. concurrent scoring (review C5).

``score_batch`` runs in ``asyncio.to_thread`` while the periodic autosave
runs ``save()`` / ``prune()`` in another thread.  Without one lock per
manager, iterating the baseline dicts while a batch added entries raised
"dictionary changed size during iteration" and baselines stopped being
persisted under steady ingest.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import pytest

from sigrift.bridge.anomaly.baseline import BaselineManager
from sigrift.bridge.anomaly.bt_scorer import BtAnomalyScorer, BtBaselineManager
from sigrift.bridge.anomaly.scorer import AnomalyScorer
from sigrift.bridge.anomaly.wifi_scorer import WifiAnomalyScorer, WifiBaselineManager


@pytest.fixture(autouse=True)
def _fast_thread_switching():
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        yield
    finally:
        sys.setswitchinterval(old)


def _race(
    writer: Callable[[int], None], reader: Callable[[], None], seconds: float = 1.5
):
    """Run *writer* (with a counter) and *reader* concurrently; return errors."""
    errors: list[BaseException] = []
    stop = threading.Event()

    def run_writer() -> None:
        i = 0
        try:
            while not stop.is_set():
                writer(i)
                i += 1
        except BaseException as exc:  # pragma: no cover - the bug
            errors.append(exc)

    def run_reader() -> None:
        try:
            while not stop.is_set():
                reader()
        except BaseException as exc:  # pragma: no cover - the bug
            errors.append(exc)

    threads = [threading.Thread(target=run_writer), threading.Thread(target=run_reader)]
    for t in threads:
        t.start()
    time.sleep(seconds)
    stop.set()
    for t in threads:
        t.join(timeout=10)
    return errors


def test_wifi_save_while_scoring_new_bssids(tmp_path: Path) -> None:
    mgr = WifiBaselineManager()
    scorer = WifiAnomalyScorer(mgr)
    path = tmp_path / "wifi.json"

    def batch(i: int) -> None:
        records = [
            {
                "bssid": f"02:00:{i % 256:02x}:{j:02x}:{(i // 256) % 256:02x}:01",
                "ssid": f"net-{i}-{j}",
                "channel": 6,
                "signal_dbm": -50.0,
                "security": "WPA2",
            }
            for j in range(20)
        ]
        scorer.score_batch(records, "n1")

    errors = _race(batch, lambda: mgr.save(str(path)))
    assert errors == []
    saved = json.loads(path.read_text())
    assert saved["baselines"]


def test_rf_save_while_updating_new_classes(tmp_path: Path) -> None:
    mgr = BaselineManager()
    path = tmp_path / "rf.json"

    def update(i: int) -> None:
        # One frequency bin: its class/hour dicts grow while save() runs.
        for j in range(10):
            mgr.update(433.92e6, f"class-{i}-{j}", 0.9, power_dbm=-60.0, hour=i % 24)

    errors = _race(update, lambda: mgr.save(str(path)))
    assert errors == []
    assert json.loads(path.read_text())["baselines"]


def test_rf_scoring_while_updating(tmp_path: Path) -> None:
    mgr = BaselineManager()
    scorer = AnomalyScorer(mgr)
    for _ in range(5):
        mgr.update(433.92e6, "bpsk", 0.9, power_dbm=-60.0, hour=1)

    def update(i: int) -> None:
        mgr.update(433.92e6, f"c{i}", 0.9, power_dbm=-60.0, hour=i % 24)

    def score() -> None:
        scorer.score(
            {
                "signal_class": "bpsk",
                "confidence": 0.9,
                "freq_hz": 433.92e6,
                "power_dbm": -60.0,
                "snr_db": 10.0,
            }
        )

    assert _race(update, score) == []


def test_bt_prune_and_save_while_scoring(tmp_path: Path) -> None:
    mgr = BtBaselineManager()
    scorer = BtAnomalyScorer(mgr)
    path = tmp_path / "bt.json"
    stale = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()

    def batch(i: int) -> None:
        records = [
            {
                "device_addr": f"AA:BB:{i % 256:02X}:{j:02X}:{(i // 256) % 256:02X}:00",
                "device_name": "x",
                "rssi_dbm": -70.0,
            }
            for j in range(20)
        ]
        scorer.score_batch(records, "n1")
        # Age some entries so prune() has work to do.
        with mgr.lock:
            for bl in list(mgr.baselines.values())[:5]:
                bl.last_seen = stale

    def prune_and_save() -> None:
        mgr.prune(max_age_hours=1)
        mgr.save(path)

    assert _race(batch, prune_and_save) == []
    assert "baselines" in json.loads(path.read_text())


def test_updates_during_save_stay_dirty(tmp_path: Path) -> None:
    mgr = WifiBaselineManager()
    mgr.update("02:00:00:00:00:01", "a", 6, "WPA2", -50.0, 0, 0.0, 1)
    real_write = __import__(
        "sigrift.bridge.anomaly.wifi_scorer", fromlist=["write_json_atomic"]
    ).write_json_atomic

    def slow_write(path, data):
        # An update lands after the snapshot, before the write finishes.
        mgr.update("02:00:00:00:00:02", "b", 6, "WPA2", -50.0, 0, 0.0, 1)
        real_write(path, data)

    import sigrift.bridge.anomaly.wifi_scorer as ws

    orig = ws.write_json_atomic
    ws.write_json_atomic = slow_write
    try:
        mgr.save(str(tmp_path / "w.json"))
    finally:
        ws.write_json_atomic = orig
    assert mgr.dirty  # the late update is saved next time
    mgr.save(str(tmp_path / "w.json"))
    assert not mgr.dirty


# ---------------------------------------------------------------------------
# Readers outside the managers: bundle export and the admin reset (repair)
# ---------------------------------------------------------------------------


def test_bundle_export_while_scoring_new_bssids() -> None:
    from sigrift.bridge import bundles

    mgr = WifiBaselineManager()
    scorer = WifiAnomalyScorer(mgr)

    def batch(i: int) -> None:
        records = [
            {
                "bssid": f"02:01:{i % 256:02x}:{j:02x}:{(i // 256) % 256:02x}:01",
                "ssid": f"net-{i}-{j}",
                "channel": 6,
                "signal_dbm": -50.0,
                "security": "WPA2",
            }
            for j in range(20)
        ]
        scorer.score_batch(records, "n1")

    errors = _race(batch, lambda: bundles.serialize_wifi_manager(mgr))
    assert errors == []
    assert json.loads(bundles.serialize_wifi_manager(mgr))["baselines"]


def test_rf_bundle_export_while_updating_new_classes() -> None:
    from sigrift.bridge import bundles

    mgr = BaselineManager()

    def update(i: int) -> None:
        for j in range(10):
            mgr.update(433.92e6, f"class-{i}-{j}", 0.9, power_dbm=-60.0, hour=i % 24)

    errors = _race(update, lambda: bundles.serialize_rf_manager(mgr))
    assert errors == []


def _blocked_by_lock(lock, action: Callable[[], object]) -> bool:
    """True if *action* waits while another thread holds *lock*."""
    held = threading.Event()
    release = threading.Event()

    def holder() -> None:
        with lock:
            held.set()
            release.wait(10)

    holder_thread = threading.Thread(target=holder)
    holder_thread.start()
    held.wait(5)
    done = threading.Event()
    worker = threading.Thread(target=lambda: (action(), done.set()))
    worker.start()
    finished_early = done.wait(0.3)
    release.set()
    holder_thread.join(10)
    worker.join(10)
    assert done.is_set(), "action never finished"
    return not finished_early


@pytest.mark.parametrize(
    "factory, serialize",
    [
        (BaselineManager, "serialize_rf_manager"),
        (WifiBaselineManager, "serialize_wifi_manager"),
        (BtBaselineManager, "serialize_bt_manager"),
    ],
)
def test_bundle_serializers_take_the_manager_lock(factory, serialize) -> None:
    from sigrift.bridge import bundles

    mgr = factory()
    assert _blocked_by_lock(mgr.lock, lambda: getattr(bundles, serialize)(mgr))


def test_admin_reset_and_preset_guard_take_the_manager_lock(bridge_app, client) -> None:
    from types import SimpleNamespace

    from sigrift.bridge.routers.maintenance import _guard_learned_state

    for attr, factory in (
        ("rf_baseline_mgr", BaselineManager),
        ("wifi_baseline_mgr", WifiBaselineManager),
        ("bt_baseline_mgr", BtBaselineManager),
    ):
        setattr(bridge_app.state, attr, factory())
    for attr in ("rf_baseline_mgr", "wifi_baseline_mgr", "bt_baseline_mgr"):
        mgr = getattr(bridge_app.state, attr)
        target = attr.split("_")[0]

        def reset(target: str = target) -> None:
            resp = client.post(f"/api/admin/baselines/reset?target={target}")
            assert resp.status_code == 200, resp.text

        assert _blocked_by_lock(mgr.lock, reset), attr

    request = SimpleNamespace(app=bridge_app)
    manifest = SimpleNamespace(kind="preset")
    assert _blocked_by_lock(
        bridge_app.state.rf_baseline_mgr.lock,
        lambda: _guard_learned_state(request, manifest, False),
    )
