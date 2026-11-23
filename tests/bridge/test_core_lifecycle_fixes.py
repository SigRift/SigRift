"""Regression tests for core lifecycle fixes (review C10, C11, C12, b64 residual).

* C10: EdgeSyslogClient.stop() sends the queued backlog (bounded).
* C11: SharedContext.close() closes pool-thread connections.
* C12: AlertEngine / watch-band cooldowns on a fresh process, watch bands
  evaluated on ingest, rule trigger stats persisted.
* b64: TOTP secrets stored as ``b64:`` are encrypted once a valid
  BRIDGE_MFA_KEY is set.
"""

from __future__ import annotations

import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import sigrift.bridge.storage.users as users_mod
from sigrift.bridge.alert_engine import AlertEngine, evaluate_watch_bands
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.edge_syslog import EdgeSyslogClient
from sigrift.bridge.storage.base import SharedContext

# ---------------------------------------------------------------------------
# C10: syslog backlog drained on stop
# ---------------------------------------------------------------------------


def _client_with_slow_send(delay: float) -> tuple[EdgeSyslogClient, list[str]]:
    client = EdgeSyslogClient(host="127.0.0.1", port=9, protocol="udp")
    sent: list[str] = []

    def fake_send(msg: str) -> None:
        time.sleep(delay)
        sent.append(msg)

    client._send_message = fake_send  # type: ignore[method-assign]
    client._connect = lambda: None  # type: ignore[method-assign]
    return client, sent


def test_syslog_stop_sends_the_whole_backlog() -> None:
    client, sent = _client_with_slow_send(0.002)
    client.start()
    for i in range(150):
        assert client.send("warning", f"event {i}")
    client.stop(drain_timeout=10.0)
    assert len(sent) == 150
    assert sent[-1].endswith("event 149")


def test_syslog_drain_is_bounded() -> None:
    client, sent = _client_with_slow_send(0.05)
    client.start()
    for i in range(100):
        client.send("warning", f"event {i}")
    started = time.monotonic()
    client.stop(drain_timeout=0.3)
    assert time.monotonic() - started < 3.0
    assert 0 < len(sent) < 100
    assert client.stats()["dropped"] >= 100 - len(sent) - 1


def test_syslog_refuses_new_messages_while_draining() -> None:
    client, sent = _client_with_slow_send(0.0)
    client.start()
    client.stop()
    client._drain_deadline = time.monotonic() + 5  # simulate mid-drain
    assert client.send("warning", "late") is False
    client._drain_deadline = None


# ---------------------------------------------------------------------------
# C11: SharedContext.close() closes connections of other threads
# ---------------------------------------------------------------------------


def test_close_closes_pool_thread_connections(tmp_path: Path, caplog) -> None:
    # Round 4 (Q8): close() no longer closes a *live* pool thread's
    # connection from the closing thread (the thread may be mid-statement;
    # closing under it crashes the interpreter).  The pool thread retires
    # it itself on its next use, and close() closes it once the thread has
    # exited — so no connection leaks either way.
    ctx = SharedContext(db_path=tmp_path / "close.db")
    with ThreadPoolExecutor(max_workers=1) as pool:
        conn = pool.submit(ctx.get_conn).result()
        pool.submit(lambda: conn.execute("SELECT 1").fetchone()).result()
        with caplog.at_level("WARNING"):
            ctx.close()
        assert not [r for r in caplog.records if "closing connection" in r.message]
        # The pool thread transparently gets a fresh connection afterwards,
        # and its old one is closed.
        fresh = pool.submit(lambda: ctx.get_conn().execute("SELECT 1").fetchone())
        assert tuple(fresh.result()) == (1,)
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            conn.execute("SELECT 1")
    assert len(ctx._conn_registry) == 1  # only the fresh one remains registered
    ctx.close()  # its thread has exited now
    assert not ctx._conn_registry


# ---------------------------------------------------------------------------
# C12: alert engine cooldowns, watch bands, trigger stats
# ---------------------------------------------------------------------------

_RULE = {
    "rule_id": "r-1",
    "name": "loud",
    "enabled": True,
    "cooldown_seconds": 300,
    "conditions": [{"field": "power_dbm", "operator": "gt", "value": -30}],
}


def test_alert_engine_first_match_not_suppressed_early_after_boot() -> None:
    # monotonic() smaller than the cooldown (a freshly booted host).
    engine = AlertEngine(cooldowns={})
    results = engine.evaluate({"power_dbm": -10.0, "freq_hz": 1e8}, [_RULE], now=5.0)
    assert [r["rule_id"] for r in results] == ["r-1"]
    # ...and the cooldown applies to the next one.
    assert engine.evaluate({"power_dbm": -10.0, "freq_hz": 1e8}, [_RULE], now=6.0) == []


def test_watch_band_first_activity_not_suppressed_early_after_boot() -> None:
    band = {
        "watch_id": "w-1",
        "enabled": True,
        "freq_min_hz": 430e6,
        "freq_max_hz": 440e6,
        "cooldown_seconds": 300,
    }
    hits = evaluate_watch_bands({"freq_hz": 433.92e6}, [band], {}, {}, now=5.0)
    assert [b["watch_id"] for b in hits] == ["w-1"]


def test_malformed_watch_band_is_skipped() -> None:
    bands = [
        {"watch_id": "bad", "freq_min_hz": None, "freq_max_hz": "x"},
        {
            "watch_id": "bad2",
            "freq_min_hz": 1,
            "freq_max_hz": 1e9,
            "trigger": "power_threshold",
            "power_threshold_dbm": "loud",
        },
        {"watch_id": "ok", "freq_min_hz": 1, "freq_max_hz": 1e9},
    ]
    hits = evaluate_watch_bands(
        {"freq_hz": 433.92e6, "power_dbm": -10.0}, bands, {}, {}, now=1.0
    )
    assert [b["watch_id"] for b in hits] == ["ok"]


def _batch(node_id: str, **det) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "node_id": node_id,
        "period_start": (now - timedelta(minutes=1)).isoformat(),
        "period_end": now.isoformat(),
        "detections": [
            {
                "node_id": node_id,
                "signal_class": "fm",
                "confidence": 0.9,
                "freq_hz": 433.92e6,
                "power_dbm": -10.0,
                **det,
            }
        ],
    }


def test_watch_band_evaluated_on_ingest(
    client: TestClient, bridge_app, registered_node: str
) -> None:
    persistence = bridge_app.state.persistence
    persistence.add_watch_band(
        {
            "watch_id": "w-ism",
            "name": "ISM 433",
            "enabled": True,
            "freq_min_hz": 433e6,
            "freq_max_hz": 435e6,
            "trigger": "new_activity",
            "severity": "critical",
        }
    )
    resp = client.post("/api/detections/batch", json=_batch(registered_node))
    assert resp.status_code == 201, resp.text
    alerts = [a for a in persistence.get_alerts() if a.get("watch_id") == "w-ism"]
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "critical"
    assert "ISM 433" in alerts[0]["message"]


def test_rule_trigger_count_persisted_on_ingest(
    client: TestClient, bridge_app, registered_node: str
) -> None:
    persistence = bridge_app.state.persistence
    persistence.set_alert_rules([dict(_RULE, trigger_count=0, last_triggered_at=None)])
    resp = client.post("/api/detections/batch", json=_batch(registered_node))
    assert resp.status_code == 201, resp.text
    [rule] = persistence.get_alert_rules()
    assert rule["trigger_count"] == 1
    assert rule["last_triggered_at"]


# ---------------------------------------------------------------------------
# Residual: b64: TOTP secrets re-encrypted once a valid key exists
# ---------------------------------------------------------------------------


@pytest.fixture
def _fresh_fernet(monkeypatch: pytest.MonkeyPatch):
    for name in ("BRIDGE_ENV", "BRIDGE_MODE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(users_mod, "_fernet_instance", None)
    yield
    users_mod._fernet_instance = None


def _totp_column(store: DetectionStore, user_id: int) -> str:
    row = (
        store._ctx.get_conn()
        .execute("SELECT totp_secret FROM users WHERE id = ?", (user_id,))
        .fetchone()
    )
    return row[0]


def test_b64_totp_secret_encrypted_when_key_appears(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _fresh_fernet
) -> None:
    from cryptography.fernet import Fernet

    db = tmp_path / "users.db"
    monkeypatch.delenv("BRIDGE_MFA_KEY", raising=False)
    store = DetectionStore(db_path=db)
    store.users.create_user("alice", "correct horse battery staple")
    user = store.users.get_user_full("alice")
    store.users.set_totp_secret(user["id"], "JBSWY3DPEHPK3PXP")
    assert _totp_column(store, user["id"]).startswith("b64:")
    store.close()

    monkeypatch.setenv("BRIDGE_MFA_KEY", Fernet.generate_key().decode())
    users_mod._fernet_instance = None
    restarted = DetectionStore(db_path=db)  # startup
    stored = _totp_column(restarted, user["id"])
    assert stored.startswith("fernet:")
    assert restarted.users.get_user_by_id(user["id"])["totp_secret"] == (
        "JBSWY3DPEHPK3PXP"
    )
    # Idempotent: nothing left to convert on the next start.
    assert restarted.users.reencrypt_legacy_totp_secrets() == 0


def test_no_reencryption_without_a_valid_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _fresh_fernet
) -> None:
    monkeypatch.setenv("BRIDGE_MFA_KEY", "not-a-fernet-key")
    store = DetectionStore(db_path=tmp_path / "u.db")
    store.users.create_user("bob", "correct horse battery staple")
    user = store.users.get_user_full("bob")
    store.users.set_totp_secret(user["id"], "JBSWY3DPEHPK3PXP")
    assert store.users.reencrypt_legacy_totp_secrets() == 0
    assert _totp_column(store, user["id"]).startswith("b64:")
