"""Tests for the crash-safe baseline autosave dirty-flag contract.

Covers the dirty/clean lifecycle the bridge lifespan autosave task relies on
(``_periodic_baseline_save`` in app.py), across the RF, WiFi, and BT baseline
managers, plus the BT prune-before-save behaviour.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from sigrift.bridge.anomaly.baseline import BaselineManager
from sigrift.bridge.anomaly.bt_scorer import BtBaselineManager
from sigrift.bridge.anomaly.wifi_scorer import WifiBaselineManager


def _wifi_update(mgr: WifiBaselineManager, bssid: str = "aa:bb:cc:dd:ee:ff") -> None:
    mgr.update(
        bssid=bssid,
        ssid="net",
        channel=6,
        security="WPA2",
        signal_dbm=-50.0,
        client_count=1,
        retry_rate=0.0,
        hour=12,
    )


def _bt_update(mgr: BtBaselineManager, addr: str = "11:22:33:44:55:66") -> None:
    mgr.update(addr, {"device_name": "x", "rssi_dbm": -60.0})


class TestDirtyFlagLifecycle:
    """A fresh manager is clean; update() dirties it; save() cleans it."""

    def test_rf_dirty_lifecycle(self, tmp_path: Path):
        mgr = BaselineManager()
        assert mgr.dirty is False
        assert mgr.updates_since_save == 0
        mgr.update(433_920_000, "ook", 0.9, -60.0, 12)
        assert mgr.dirty is True
        assert mgr.updates_since_save == 1
        mgr.save(str(tmp_path / "baselines.json"))
        assert mgr.dirty is False
        assert mgr.updates_since_save == 0

    def test_wifi_dirty_lifecycle(self, tmp_path: Path):
        mgr = WifiBaselineManager()
        assert mgr.dirty is False
        _wifi_update(mgr)
        assert mgr.dirty is True
        mgr.save(str(tmp_path / "wifi_baselines.json"))
        assert mgr.dirty is False

    def test_bt_dirty_lifecycle(self, tmp_path: Path):
        mgr = BtBaselineManager()
        assert mgr.dirty is False
        _bt_update(mgr)
        assert mgr.dirty is True
        mgr.save(tmp_path / "bt_baselines.json")
        assert mgr.dirty is False


class TestSaveIfDirtyTick:
    """Mirror the autosave task's 'only save when dirty' gate."""

    def test_clean_tick_does_not_rewrite(self, tmp_path: Path):
        mgr = BaselineManager()
        path = tmp_path / "baselines.json"
        mgr.update(433_920_000, "ook", 0.9, -60.0, 12)
        # First tick: dirty -> saves.
        assert mgr.dirty
        mgr.save(str(path))
        mtime_after_save = path.stat().st_mtime_ns

        # Second tick with no new updates: the gate skips the save, so the file
        # is untouched (no needless churn of a multi-MB file on a Pi).
        assert mgr.dirty is False
        if mgr.dirty:  # pragma: no cover - documents the gate
            mgr.save(str(path))
        assert path.stat().st_mtime_ns == mtime_after_save

    def test_new_update_redirties_after_save(self, tmp_path: Path):
        mgr = BaselineManager()
        path = tmp_path / "baselines.json"
        mgr.update(433_920_000, "ook", 0.9, -60.0, 12)
        mgr.save(str(path))
        assert mgr.dirty is False
        mgr.update(868_000_000, "lora-css", 0.8, -70.0, 13)
        assert mgr.dirty is True


class TestBtPruneBeforeSave:
    """prune() (previously never called) drops stale MAC-keyed baselines."""

    def test_prune_removes_stale_devices(self, tmp_path: Path):
        mgr = BtBaselineManager()
        _bt_update(mgr, "11:22:33:44:55:66")
        _bt_update(mgr, "aa:bb:cc:dd:ee:ff")
        # Age one device well past the 168h window.
        stale = mgr.baselines["11:22:33:44:55:66"]
        stale.last_seen = (
            datetime.now(timezone.utc) - timedelta(hours=200)
        ).isoformat()
        removed = mgr.prune(max_age_hours=168)
        assert removed == 1
        assert "11:22:33:44:55:66" not in mgr.baselines
        assert "aa:bb:cc:dd:ee:ff" in mgr.baselines

    def test_prune_then_save_roundtrip(self, tmp_path: Path):
        mgr = BtBaselineManager()
        _bt_update(mgr, "aa:bb:cc:dd:ee:ff")
        mgr.prune()
        path = tmp_path / "bt_baselines.json"
        mgr.save(path)
        reloaded = BtBaselineManager()
        reloaded.load(path)
        assert "aa:bb:cc:dd:ee:ff" in reloaded.baselines
