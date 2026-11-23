"""Tests for async safety improvements (Sprint 4 items 8, 9, 10, 15)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from sigrift.lib.shiny.persistence import PersistenceManager
from sigrift.lib.shiny.state import WebSocketClientSet

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# WebSocketClientSet tests (Item 10)
# ---------------------------------------------------------------------------


class _FakeWS:
    """Minimal fake WebSocket for testing."""

    def __init__(self, ws_id: int = 0) -> None:
        self.ws_id = ws_id
        self.sent: list[Any] = []
        self.should_fail = False

    async def send_json(self, data: dict) -> None:
        if self.should_fail:
            raise RuntimeError("connection closed")
        self.sent.append(("json", data))

    async def send_text(self, data: str) -> None:
        if self.should_fail:
            raise RuntimeError("connection closed")
        self.sent.append(("text", data))

    def __hash__(self) -> int:
        return hash(self.ws_id)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _FakeWS):
            return self.ws_id == other.ws_id
        return NotImplemented


async def test_wsclientset_add_remove() -> None:
    ws_set = WebSocketClientSet()
    ws = _FakeWS(1)

    await ws_set.add(ws)
    assert len(ws_set) == 1

    await ws_set.remove(ws)
    assert len(ws_set) == 0


async def test_wsclientset_remove_missing_is_noop() -> None:
    ws_set = WebSocketClientSet()
    ws = _FakeWS(1)
    # Should not raise
    await ws_set.remove(ws)
    assert len(ws_set) == 0


async def test_wsclientset_broadcast_dict() -> None:
    ws_set = WebSocketClientSet()
    ws1 = _FakeWS(1)
    ws2 = _FakeWS(2)
    await ws_set.add(ws1)
    await ws_set.add(ws2)

    payload = {"type": "alert", "message": "test"}
    await ws_set.broadcast(payload)

    assert ("json", payload) in ws1.sent
    assert ("json", payload) in ws2.sent


async def test_wsclientset_broadcast_text() -> None:
    ws_set = WebSocketClientSet()
    ws = _FakeWS(1)
    await ws_set.add(ws)

    await ws_set.broadcast("hello")
    assert ("text", "hello") in ws.sent


async def test_wsclientset_broadcast_removes_dead_clients() -> None:
    ws_set = WebSocketClientSet()
    ws_good = _FakeWS(1)
    ws_dead = _FakeWS(2)
    ws_dead.should_fail = True

    await ws_set.add(ws_good)
    await ws_set.add(ws_dead)
    assert len(ws_set) == 2

    await ws_set.broadcast({"event": "test"})

    # Dead client should have been removed
    assert len(ws_set) == 1
    assert ("json", {"event": "test"}) in ws_good.sent


async def test_wsclientset_snapshot() -> None:
    ws_set = WebSocketClientSet()
    ws1 = _FakeWS(1)
    ws2 = _FakeWS(2)
    await ws_set.add(ws1)
    await ws_set.add(ws2)

    snap = ws_set.snapshot()
    assert len(snap) == 2
    assert set(snap) == {ws1, ws2}


async def test_wsclientset_bool() -> None:
    ws_set = WebSocketClientSet()
    assert not ws_set

    ws = _FakeWS(1)
    await ws_set.add(ws)
    assert ws_set


async def test_wsclientset_concurrent_add_remove() -> None:
    ws_set = WebSocketClientSet()

    async def add_remove(i: int) -> None:
        ws = _FakeWS(i)
        await ws_set.add(ws)
        await asyncio.sleep(0)
        await ws_set.remove(ws)

    await asyncio.gather(*(add_remove(i) for i in range(50)))
    assert len(ws_set) == 0


# ---------------------------------------------------------------------------
# PersistenceManager.acknowledge_alert / remove_alert tests (Item 9)
# ---------------------------------------------------------------------------


@pytest.fixture()
def persistence(tmp_path: Path) -> PersistenceManager:
    pm = PersistenceManager(data_dir=tmp_path, auto_save_interval=0)
    pm.load_all()
    return pm


def _make_alert(alert_id: str) -> dict[str, Any]:
    return {
        "alert_id": alert_id,
        "name": "test_rule",
        "severity": "warning",
        "message": "test alert",
        "node_id": "edge-01",
        "triggered_at": "2026-01-01T00:00:00+00:00",
        "acknowledged": False,
        "acknowledged_at": None,
    }


async def test_acknowledge_alert_success(persistence: PersistenceManager) -> None:
    alert = _make_alert("alert_1")
    persistence.add_alert(alert)

    result = persistence.acknowledge_alert("alert_1")
    assert result is True

    alerts = persistence.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["acknowledged"] is True
    assert alerts[0]["acknowledged_at"] is not None


async def test_acknowledge_alert_not_found(persistence: PersistenceManager) -> None:
    result = persistence.acknowledge_alert("nonexistent")
    assert result is False


async def test_acknowledge_alert_marks_dirty(persistence: PersistenceManager) -> None:
    persistence.add_alert(_make_alert("alert_1"))
    persistence._dirty = False

    persistence.acknowledge_alert("alert_1")
    assert persistence._dirty is True


async def test_remove_alert_success(persistence: PersistenceManager) -> None:
    persistence.add_alert(_make_alert("alert_1"))
    persistence.add_alert(_make_alert("alert_2"))

    result = persistence.remove_alert("alert_1")
    assert result is True

    alerts = persistence.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["alert_id"] == "alert_2"


async def test_remove_alert_not_found(persistence: PersistenceManager) -> None:
    result = persistence.remove_alert("nonexistent")
    assert result is False


async def test_remove_alert_marks_dirty(persistence: PersistenceManager) -> None:
    persistence.add_alert(_make_alert("alert_1"))
    persistence._dirty = False

    persistence.remove_alert("alert_1")
    assert persistence._dirty is True


async def test_acknowledge_alert_under_lock(persistence: PersistenceManager) -> None:
    """Verify acknowledge_alert works correctly under concurrent access."""
    for i in range(10):
        persistence.add_alert(_make_alert(f"alert_{i}"))

    def ack(aid: str) -> bool:
        return persistence.acknowledge_alert(aid)

    asyncio.get_event_loop()
    results = await asyncio.gather(
        *(asyncio.to_thread(ack, f"alert_{i}") for i in range(10))
    )
    assert all(results)

    alerts = persistence.get_alerts()
    assert all(a["acknowledged"] for a in alerts)


async def test_remove_alert_under_lock(persistence: PersistenceManager) -> None:
    """Verify remove_alert works correctly under concurrent access."""
    for i in range(10):
        persistence.add_alert(_make_alert(f"alert_{i}"))

    def remove(aid: str) -> bool:
        return persistence.remove_alert(aid)

    asyncio.get_event_loop()
    results = await asyncio.gather(
        *(asyncio.to_thread(remove, f"alert_{i}") for i in range(10))
    )
    assert all(results)
    assert len(persistence.get_alerts()) == 0


# ---------------------------------------------------------------------------
# Auto-save uses asyncio.to_thread (Item 8)
# ---------------------------------------------------------------------------


async def test_auto_save_loop_uses_to_thread(persistence: PersistenceManager) -> None:
    """Verify _auto_save_loop offloads save_all to a thread."""
    persistence._auto_save_interval = 0.05
    persistence._dirty = True

    save_calls: list[str] = []
    original_save = persistence.save_all

    def tracking_save() -> None:
        import threading

        save_calls.append(threading.current_thread().name)
        original_save()

    persistence.save_all = tracking_save

    task = asyncio.create_task(persistence._auto_save_loop())
    await asyncio.sleep(0.15)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert len(save_calls) > 0
    # Verify save was called from a thread pool thread, not the main thread
    import threading

    main_thread_name = threading.current_thread().name
    for name in save_calls:
        assert name != main_thread_name, (
            f"save_all ran on main thread ({name}); expected a pool thread"
        )
