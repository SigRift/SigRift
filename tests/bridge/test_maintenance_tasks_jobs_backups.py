"""Maintenance router: task failures, capture purges, anomaly sweeps, the
job activity feed, baseline resets and backup pruning / decryption refusals.

Covers the parts of ``sigrift.bridge.routers.maintenance`` that run outside
the happy path: a crashing task, a missing capture store, a resolved or
unscorable anomaly, an audit history that cannot be read, a backup that
cannot be pruned, an encrypted backup that was truncated or tampered with,
a backup key that is set but unusable (refused, never a plaintext backup).
"""

from __future__ import annotations

import logging
import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet, InvalidToken

import sigrift.bridge.routers.maintenance as maint

_URL = "/api/admin/maintenance"


def _rf_anomalies(store) -> list[int]:
    return store.insert_rf_anomalies_batch(
        [
            {
                "detection_id": f"det-{cls}",
                "signal_class": cls,
                "freq_hz": 446.0e6 + i * 12_500,
                "node_id": "edge-1",
                "timestamp": "2026-11-10T00:00:00+00:00",
                "anomaly_score": 0.9,
            }
            for i, cls in enumerate(("dmr", "p25", "nxdn"))
        ]
    )


def _wifi_anomalies(store) -> list[int]:
    return [
        store.insert_wifi_anomaly(
            {
                "bssid": f"aa:bb:cc:11:22:{i:02x}",
                "ssid": f"Net{i}",
                "anomaly_score": 0.8,
                "priority": "critical",
                "node_id": "node-01",
                "timestamp": "2026-11-10T00:00:00+00:00",
            }
        )
        for i in range(3)
    ]


class _RfScorer:
    """dmr has resolved, p25 is still anomalous, nxdn cannot be scored."""

    def score(self, anomaly):
        if anomaly["signal_class"] == "nxdn":
            raise ValueError("unscorable")
        return SimpleNamespace(score=0.1 if anomaly["signal_class"] == "dmr" else 0.8)


class _WifiScorer:
    """Net0 has resolved, Net1 does not say, Net2 cannot be re-evaluated."""

    def reevaluate(self, anomaly):
        if anomaly["ssid"] == "Net2":
            raise KeyError("baseline gone")
        return {"still_anomalous": False} if anomaly["ssid"] == "Net0" else {}


def _active(rows) -> set[str]:
    return {r.get("signal_class") or r.get("ssid") for r in rows}


# ---------------------------------------------------------------------------
# POST /maintenance: failures and capture stores
# ---------------------------------------------------------------------------


class TestTaskFailures:
    def test_a_crashing_task_is_a_generic_500_and_a_failed_job(
        self, client, detection_store, app_state, monkeypatch
    ):
        def _boom() -> None:
            raise sqlite3.OperationalError("disk I/O error on /srv/sigrift/x.db")

        monkeypatch.setattr(detection_store, "optimize", _boom)
        resp = client.post(_URL, json={"task": "optimize"})
        assert resp.status_code == 500
        # The client gets no internal detail (paths, driver messages) ...
        assert resp.json() == {"detail": "Internal maintenance error"}
        # ... the job record keeps it for the operator, marked failed ...
        job = app_state.job_log[-1]
        assert (job["task"], job["status"]) == ("optimize", "failed")
        assert "disk I/O error" in job["error"]
        assert job["result"] is None
        # ... and a run that did not complete is not audited as one.
        assert detection_store.get_audit_log(action="maintenance_optimize") == []

    @pytest.mark.parametrize(
        ("task", "attr", "detail"),
        [
            ("purge_iq_captures", "iq_store", "IQ store not available"),
            ("purge_pcap_captures", "pcap_store", "Pcap store not available"),
        ],
    )
    def test_purging_captures_without_their_store_is_404(
        self, client, bridge_app, app_state, task, attr, detail
    ):
        setattr(bridge_app.state, attr, None)
        resp = client.post(_URL, json={"task": task, "retention_days": 7})
        assert (resp.status_code, resp.json()["detail"]) == (404, detail)
        assert (app_state.job_log[-1]["status"], app_state.job_log[-1]["error"]) == (
            "failed",
            detail,
        )

    def test_capture_purges_delete_only_expired_files(self, client, tmp_path):
        expired = time.time() - 30 * 86400
        for folder, ext in (("iq_captures", ".iq.gz"), ("pcap_captures", ".pcap.gz")):
            old = tmp_path / folder / f"old{ext}"
            old.write_bytes(b"old")
            os.utime(old, (expired, expired))
            (tmp_path / folder / f"new{ext}").write_bytes(b"new")

        for task, folder, ext in (
            ("purge_iq_captures", "iq_captures", ".iq.gz"),
            ("purge_pcap_captures", "pcap_captures", ".pcap.gz"),
        ):
            resp = client.post(_URL, json={"task": task, "retention_days": 7})
            assert resp.status_code == 200, resp.text
            assert resp.json()["deleted"] == 1
            left = sorted(p.name for p in (tmp_path / folder).glob(f"*{ext}"))
            assert left == [f"new{ext}"]

    @pytest.mark.parametrize("task", ["purge_old_data", "full_cleanup"])
    def test_bulk_purges_skip_capture_stores_that_are_not_wired(
        self, client, bridge_app, tmp_path, task
    ):
        expired = time.time() - 400 * 86400
        old = tmp_path / "iq_captures" / "old.iq.gz"
        old.write_bytes(b"old")
        os.utime(old, (expired, expired))
        bridge_app.state.iq_store = None
        bridge_app.state.pcap_store = None
        resp = client.post(_URL, json={"task": task, "retention_days": 1})
        assert resp.status_code == 200, resp.text
        deleted = resp.json()["deleted"]
        assert (deleted["iq_captures"], deleted["pcap_captures"]) == (0, 0)
        assert old.exists()

    def test_aggregate_detections_rolls_old_rows_into_one_hourly_bucket(
        self, client, detection_store
    ):
        conn = detection_store.get_connection()
        hour = (datetime.now(timezone.utc) - timedelta(hours=3)).replace(
            minute=10, second=0, microsecond=0
        )
        for i in range(2):
            conn.execute(
                "INSERT INTO detections "
                "(timestamp, node_id, signal_class, confidence, freq_hz) "
                "VALUES (?, ?, ?, ?, ?)",
                [
                    (hour + timedelta(minutes=i)).isoformat(),
                    "node-agg",
                    "bpsk",
                    0.9,
                    4e8,
                ],
            )
        conn.commit()
        resp = client.post(_URL, json={"task": "aggregate_detections"})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["aggregated"] == 1
        assert body["note"] == "Aggregated raw detections into hourly buckets"
        row = conn.execute(
            "SELECT detection_count FROM detection_aggregates WHERE node_id = ?",
            ["node-agg"],
        ).fetchone()
        assert row["detection_count"] == 2


# ---------------------------------------------------------------------------
# POST /maintenance: anomaly re-evaluation and bulk dismissal
# ---------------------------------------------------------------------------


class TestAnomalySweeps:
    def test_rf_reeval_dismisses_only_what_the_scorer_resolved(
        self, client, bridge_app, detection_store
    ):
        _rf_anomalies(detection_store)
        # Without a scorer nothing can be judged resolved: nothing dismissed.
        bridge_app.state.rf_scorer = None
        body = client.post(_URL, json={"task": "reeval_dismiss_rf"}).json()
        assert (body["processed"], body["dismissed"], body["still_active"]) == (3, 0, 3)

        bridge_app.state.rf_scorer = _RfScorer()
        body = client.post(_URL, json={"task": "reeval_dismiss_rf"}).json()
        # A scorer error keeps the anomaly active (never dismissed by error).
        assert (body["processed"], body["dismissed"], body["still_active"]) == (3, 1, 2)
        active = detection_store.get_rf_anomalies(min_score=0.0)
        assert _active(active) == {"p25", "nxdn"}

    def test_wifi_reeval_dismisses_only_what_the_scorer_resolved(
        self, client, bridge_app, detection_store
    ):
        _wifi_anomalies(detection_store)
        bridge_app.state.wifi_scorer = None
        body = client.post(_URL, json={"task": "reeval_dismiss_wifi"}).json()
        assert (body["processed"], body["dismissed"], body["still_active"]) == (3, 0, 3)

        bridge_app.state.wifi_scorer = _WifiScorer()
        body = client.post(_URL, json={"task": "reeval_dismiss_wifi"}).json()
        assert (body["processed"], body["dismissed"], body["still_active"]) == (3, 1, 2)
        active = detection_store.get_wifi_anomalies(min_score=0.0)
        assert _active(active) == {"Net1", "Net2"}

    def test_dismiss_all_dismisses_every_active_anomaly(self, client, detection_store):
        _rf_anomalies(detection_store)
        _wifi_anomalies(detection_store)
        for task, count in (("dismiss_all_rf", 3), ("dismiss_all_wifi", 3)):
            resp = client.post(_URL, json={"task": task})
            assert resp.status_code == 200, resp.text
            assert resp.json()["dismissed"] == count
        assert detection_store.get_rf_anomalies(min_score=0.0) == []
        assert detection_store.get_wifi_anomalies(min_score=0.0) == []
        # A second sweep finds nothing left to dismiss.
        for task in ("dismiss_all_rf", "dismiss_all_wifi"):
            assert client.post(_URL, json={"task": task}).json()["dismissed"] == 0


# ---------------------------------------------------------------------------
# GET /jobs
# ---------------------------------------------------------------------------


class TestJobs:
    def test_live_jobs_come_first_then_the_audit_history(
        self, client, detection_store, app_state
    ):
        scheduled = detection_store.log_audit(
            action="maintenance_purge_old_data",
            target_id="system",
            operator="system",
            note="retention=90d",
        )
        manual = detection_store.log_audit(
            action="maintenance_vacuum",
            target_id="system",
            operator="key-ops",
            note="retention=7d",
        )
        detection_store.log_audit(
            action="admin_backup", target_id="system", operator="key-ops"
        )
        live = {
            "id": "job1",
            "task": "vacuum",
            "trigger": "manual",
            "status": "completed",
            "started_at": manual["timestamp"],
            "finished_at": manual["timestamp"],
            "duration_s": 0.1,
            "result": {"vacuumed": True},
            "error": None,
        }
        app_state.job_log.append(live)

        body = client.get("/api/admin/jobs").json()
        assert body["next_scheduled_cleanup"] is None
        # An audit row stamped with a live job's start time is taken as that
        # job's own and not listed twice; non-maintenance actions are not
        # jobs; operator "system" is the scheduler.
        assert body["jobs"] == [
            live,
            {
                "task": "purge_old_data",
                "trigger": "scheduled",
                "status": "completed",
                "started_at": scheduled["timestamp"],
                "finished_at": scheduled["timestamp"],
                "duration_s": None,
                "note": "retention=90d",
                "operator": "system",
            },
        ]
        assert client.get("/api/admin/jobs?limit=1").json()["jobs"] == [live]

    def test_next_scheduled_cleanup_is_the_next_hourly_tick(
        self, client, bridge_app, app_state, monkeypatch
    ):
        t0 = datetime(2026, 11, 18, 6, 0, tzinfo=timezone.utc)
        app_state.started_at = t0
        monkeypatch.setattr(maint, "_utcnow", lambda: t0 + timedelta(minutes=135))
        bridge_app.state._cleanup_task = SimpleNamespace(done=lambda: False)
        body = client.get("/api/admin/jobs").json()
        assert body["next_scheduled_cleanup"] == (t0 + timedelta(hours=3)).isoformat()
        # A finished (crashed or cancelled) scheduler announces nothing.
        bridge_app.state._cleanup_task = SimpleNamespace(done=lambda: True)
        assert client.get("/api/admin/jobs").json()["next_scheduled_cleanup"] is None

    def test_unreadable_history_yields_no_history(self):
        class _LockedStore:
            def get_connection(self):
                raise sqlite3.OperationalError("database is locked")

        assert maint._fetch_maintenance_history(_LockedStore(), 10) == []


# ---------------------------------------------------------------------------
# POST /baselines/reset
# ---------------------------------------------------------------------------


class TestBaselineReset:
    def test_unknown_target_clears_nothing(self, client, bridge_app):
        rf = bridge_app.state.rf_baseline_mgr
        rf.update(433_920_000, "ook", 0.9, -60.0, 3, snr_db=20.0, bandwidth_hz=25e3)
        resp = client.post("/api/admin/baselines/reset?target=everything")
        assert resp.json() == {
            "status": "error",
            "detail": "No baselines found for target 'everything'",
        }
        assert len(rf.baselines) == 1

    def test_reset_all_skips_scorers_that_are_not_running(self, client, bridge_app):
        bridge_app.state.rf_baseline_mgr = None
        bridge_app.state.wifi_baseline_mgr = None
        bt = bridge_app.state.bt_baseline_mgr
        bt.update("11:22:33:44:55:66", {"device_name": "tag", "rssi_dbm": -61.0})
        resp = client.post("/api/admin/baselines/reset")
        assert resp.json()["status"] == "ok"
        assert resp.json()["reset"] == {"bt": 1}
        assert bt.baselines == {}
        bridge_app.state.bt_baseline_mgr = None
        resp = client.post("/api/admin/baselines/reset?target=bt")
        assert resp.json()["status"] == "error"


# ---------------------------------------------------------------------------
# Backups: listing, pruning, encrypted-file refusals
# ---------------------------------------------------------------------------


@pytest.fixture
def backup_key(monkeypatch) -> None:
    """A fresh backup key, with the module's cached Fernet reset and restored."""
    monkeypatch.setenv("BRIDGE_BACKUP_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(maint, "_backup_fernet", None)


class TestBackups:
    def test_listing_before_any_backup_is_empty(self, client, detection_store):
        assert not (Path(detection_store.db_path).parent / "backups").exists()
        resp = client.get("/api/admin/backups")
        assert resp.json() == {"count": 0, "backups": []}

    def test_prune_keeps_going_past_a_backup_it_cannot_delete(self, tmp_path, caplog):
        backups = tmp_path / "backups"
        backups.mkdir()
        stuck = backups / "detections_backup_000.db"
        stuck.mkdir()  # unlink() of a directory fails on every platform
        os.utime(stuck, (1000, 1000))
        for i in (1, 2, 3):
            p = backups / f"detections_backup_{i:03d}.db"
            p.write_bytes(b"db")
            p.with_suffix(".db.sha256").write_text("x  " + p.name + "\n")
            os.utime(p, (1000 + i, 1000 + i))

        with caplog.at_level(logging.WARNING, logger=maint.logger.name):
            maint._prune_old_backups(backups, keep=2)

        assert stuck.is_dir()
        assert "Failed to prune backup: detections_backup_000.db" in caplog.text
        # The next-oldest is still pruned, its checksum sidecar with it.
        assert sorted(p.name for p in backups.iterdir()) == [
            "detections_backup_000.db",
            "detections_backup_002.db",
            "detections_backup_002.db.sha256",
            "detections_backup_003.db",
            "detections_backup_003.db.sha256",
        ]

    def test_truncated_encrypted_backup_is_refused(self, tmp_path, backup_key):
        src = tmp_path / "b.db"
        src.write_bytes(os.urandom(2048))
        enc = maint._encrypt_backup_file(src)
        enc.write_bytes(enc.read_bytes()[:-16])
        with pytest.raises(ValueError, match="Truncated encrypted backup chunk"):
            maint._decrypt_backup_file(enc, tmp_path / "out.db")

    def test_tampered_encrypted_backup_is_refused(self, tmp_path, backup_key):
        src = tmp_path / "b.db"
        src.write_bytes(os.urandom(2048))
        enc = maint._encrypt_backup_file(src)
        raw = bytearray(enc.read_bytes())
        at = len(maint._BACKUP_ENC_MAGIC) + 4 + 40  # inside the Fernet token
        raw[at] = ord("A") if raw[at] != ord("A") else ord("B")
        enc.write_bytes(bytes(raw))
        with pytest.raises(InvalidToken):
            maint._decrypt_backup_file(enc, tmp_path / "out.db")


# ---------------------------------------------------------------------------
# Backups: the encryption key (D-9) fails closed
# ---------------------------------------------------------------------------

_KEY_REFUSAL = "BRIDGE_BACKUP_ENCRYPTION_KEY is set but is not a valid Fernet key"


@pytest.fixture(params=["truncated", "not-base64"])
def malformed_backup_key(request, monkeypatch) -> str:
    """A backup key that is set but unusable, the cached Fernet reset."""
    # 30 bytes once decoded (a key cut short), or not a key at all.
    valid = Fernet.generate_key().decode()
    key = valid[:-4] if request.param == "truncated" else "not-a-fernet-key"
    monkeypatch.setenv("BRIDGE_BACKUP_ENCRYPTION_KEY", key)
    monkeypatch.setattr(maint, "_backup_fernet", None)
    return key


def _backups_dir(detection_store) -> Path:
    return Path(detection_store.db_path).parent / "backups"


class TestBackupKey:
    def test_a_malformed_key_refuses_the_backup_and_writes_nothing(
        self, client, detection_store, malformed_backup_key, caplog
    ):
        with caplog.at_level(logging.ERROR, logger=maint.logger.name):
            resp = client.post("/api/admin/backup")
        assert resp.status_code == 500
        detail = resp.json()["detail"]
        assert detail.startswith(_KEY_REFUSAL)
        assert "No backup was written" in detail
        # Neither the answer nor the log quotes the key.
        assert malformed_backup_key not in resp.text
        assert "BRIDGE_BACKUP_ENCRYPTION_KEY" in caplog.text
        assert malformed_backup_key not in caplog.text
        # No plaintext copy of the database, and no backup audited.
        assert not _backups_dir(detection_store).exists()
        assert detection_store.get_audit_log(action="admin_backup") == []

    def test_the_helpers_never_fall_back_to_plaintext(
        self, tmp_path, malformed_backup_key
    ):
        src = tmp_path / "b.db"
        src.write_bytes(b"SQLite format 3\x00")
        with pytest.raises(ValueError, match=_KEY_REFUSAL):
            maint._encrypt_backup_file(src)
        enc = tmp_path / "b.db.enc"
        enc.write_bytes(maint._BACKUP_ENC_MAGIC)
        with pytest.raises(ValueError, match=_KEY_REFUSAL):
            maint._decrypt_backup_file(enc, tmp_path / "out.db")
        assert sorted(p.name for p in tmp_path.iterdir()) == ["b.db", "b.db.enc"]

    def test_a_valid_key_writes_only_the_encrypted_backup(
        self, client, detection_store, backup_key
    ):
        resp = client.post("/api/admin/backup")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert (body["encrypted"], body["backup_file"][-7:]) == (True, ".db.enc")
        assert sorted(p.name for p in _backups_dir(detection_store).iterdir()) == [
            body["backup_file"],
            body["backup_file"] + ".sha256",
        ]

    @pytest.mark.parametrize(
        "value", [None, "", "   "], ids=["unset", "empty", "blank"]
    )
    def test_an_unset_key_still_writes_a_plaintext_backup(
        self, client, detection_store, monkeypatch, value
    ):
        if value is None:
            monkeypatch.delenv("BRIDGE_BACKUP_ENCRYPTION_KEY", raising=False)
        else:
            monkeypatch.setenv("BRIDGE_BACKUP_ENCRYPTION_KEY", value)
        monkeypatch.setattr(maint, "_backup_fernet", None)
        resp = client.post("/api/admin/backup")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert (body["encrypted"], body["backup_file"][-3:]) == (False, ".db")
        assert sorted(p.name for p in _backups_dir(detection_store).iterdir()) == [
            body["backup_file"],
            body["backup_file"] + ".sha256",
        ]
