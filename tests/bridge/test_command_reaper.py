"""Tests for _reap_expired_commands() in routers/nodes.py.

Covers expired command removal, future lease preservation,
multi-node reaping, return count accuracy, and empty-state handling.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from sigrift.bridge.routers.nodes import _reap_expired_commands
from sigrift.bridge.state import AppState


_FIXED_NOW = datetime(2026, 3, 4, 12, 0, 0, tzinfo=timezone.utc)


def _fake_utcnow() -> datetime:
    return _FIXED_NOW


def _make_command(command_id: str, node_id: str, lease_expires_at: str,
                  cmd_status: str = "queued") -> dict:
    """Build a command dict for both pending_commands and command_history."""
    return {
        "command_id": command_id,
        "node_id": node_id,
        "command": "scan",
        "status": cmd_status,
        "params": {},
        "queued_at": "2026-03-04T11:00:00",
        "lease_expires_at": lease_expires_at,
        "dispatched_at": None,
        "acked_at": None,
        "completed_at": None,
    }



class TestReapExpiredCommand(unittest.TestCase):
    """A command with lease_expires_at in the past should be reaped."""

    def setUp(self):
        self.app_state = AppState()

    @patch("sigrift.bridge.routers.nodes._utcnow", _fake_utcnow)
    def test_expired_command_removed_from_pending(self):
        expired_time = (_FIXED_NOW - timedelta(minutes=1)).isoformat()
        cmd = _make_command("cmd-exp-1", "node-a", expired_time)
        self.app_state.pending_commands["node-a"] = [cmd]
        self.app_state.command_history.append(dict(cmd))

        reaped = _reap_expired_commands(self.app_state)

        self.assertEqual(reaped, 1)
        self.assertNotIn("node-a", self.app_state.pending_commands)

    @patch("sigrift.bridge.routers.nodes._utcnow", _fake_utcnow)
    def test_expired_command_history_status_set_to_expired(self):
        expired_time = (_FIXED_NOW - timedelta(minutes=1)).isoformat()
        cmd = _make_command("cmd-exp-2", "node-a", expired_time)
        self.app_state.pending_commands["node-a"] = [cmd]
        self.app_state.command_history.append(dict(cmd))

        _reap_expired_commands(self.app_state)

        entry = next(
            e for e in self.app_state.command_history
            if e["command_id"] == "cmd-exp-2"
        )
        self.assertEqual(entry["status"], "expired")



class TestReapFutureCommand(unittest.TestCase):
    """A command with lease_expires_at in the future should NOT be reaped."""

    @patch("sigrift.bridge.routers.nodes._utcnow", _fake_utcnow)
    def test_future_command_not_reaped(self):
        app_state = AppState()
        future_time = (_FIXED_NOW + timedelta(minutes=5)).isoformat()
        cmd = _make_command("cmd-future-1", "node-a", future_time)
        app_state.pending_commands["node-a"] = [cmd]
        app_state.command_history.append(dict(cmd))

        reaped = _reap_expired_commands(app_state)

        self.assertEqual(reaped, 0)
        self.assertIn("node-a", app_state.pending_commands)
        self.assertEqual(len(app_state.pending_commands["node-a"]), 1)
        entry = next(
            e for e in app_state.command_history
            if e["command_id"] == "cmd-future-1"
        )
        self.assertEqual(entry["status"], "queued")



class TestReapMultiNode(unittest.TestCase):
    """Only expired commands are reaped across multiple nodes."""

    @patch("sigrift.bridge.routers.nodes._utcnow", _fake_utcnow)
    def test_only_expired_reaped_across_nodes(self):
        app_state = AppState()

        expired_time = (_FIXED_NOW - timedelta(minutes=2)).isoformat()
        future_time = (_FIXED_NOW + timedelta(minutes=5)).isoformat()

        cmd_exp = _make_command("cmd-mn-1", "node-a", expired_time)
        cmd_ok = _make_command("cmd-mn-2", "node-b", future_time)

        app_state.pending_commands["node-a"] = [cmd_exp]
        app_state.pending_commands["node-b"] = [cmd_ok]
        app_state.command_history.append(dict(cmd_exp))
        app_state.command_history.append(dict(cmd_ok))

        reaped = _reap_expired_commands(app_state)

        self.assertEqual(reaped, 1)
        # node-a fully cleared
        self.assertNotIn("node-a", app_state.pending_commands)
        # node-b untouched
        self.assertIn("node-b", app_state.pending_commands)
        self.assertEqual(len(app_state.pending_commands["node-b"]), 1)

    @patch("sigrift.bridge.routers.nodes._utcnow", _fake_utcnow)
    def test_mixed_commands_same_node(self):
        """One expired and one future command on the same node."""
        app_state = AppState()

        expired_time = (_FIXED_NOW - timedelta(minutes=1)).isoformat()
        future_time = (_FIXED_NOW + timedelta(minutes=5)).isoformat()

        cmd_exp = _make_command("cmd-mix-1", "node-a", expired_time)
        cmd_ok = _make_command("cmd-mix-2", "node-a", future_time)

        app_state.pending_commands["node-a"] = [cmd_exp, cmd_ok]
        app_state.command_history.append(dict(cmd_exp))
        app_state.command_history.append(dict(cmd_ok))

        reaped = _reap_expired_commands(app_state)

        self.assertEqual(reaped, 1)
        self.assertIn("node-a", app_state.pending_commands)
        self.assertEqual(len(app_state.pending_commands["node-a"]), 1)
        self.assertEqual(
            app_state.pending_commands["node-a"][0]["command_id"], "cmd-mix-2"
        )



class TestReapReturnCount(unittest.TestCase):
    """Return count must match the number of commands actually reaped."""

    @patch("sigrift.bridge.routers.nodes._utcnow", _fake_utcnow)
    def test_return_count_matches_reaped(self):
        app_state = AppState()
        expired_time = (_FIXED_NOW - timedelta(minutes=1)).isoformat()

        cmds = []
        for i in range(3):
            cmd = _make_command(f"cmd-cnt-{i}", "node-a", expired_time)
            cmds.append(cmd)
            app_state.command_history.append(dict(cmd))

        app_state.pending_commands["node-a"] = cmds

        reaped = _reap_expired_commands(app_state)
        self.assertEqual(reaped, 3)



class TestReapEmpty(unittest.TestCase):
    """Empty pending_commands should return 0 without error."""

    @patch("sigrift.bridge.routers.nodes._utcnow", _fake_utcnow)
    def test_empty_pending_returns_zero(self):
        app_state = AppState()
        self.assertEqual(app_state.pending_commands, {})

        reaped = _reap_expired_commands(app_state)
        self.assertEqual(reaped, 0)


if __name__ == "__main__":
    unittest.main()
