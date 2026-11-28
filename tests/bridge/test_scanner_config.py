"""Tests for ``sigrift.edge.scanner_config`` runtime poll-reload."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from sigrift.edge import scanner_config


@pytest.fixture
def config_path(tmp_path, monkeypatch):
    """Redirect the module to a tmpdir-scoped config file."""
    path = tmp_path / "mlrf-scanner-config.json"
    monkeypatch.setenv("MLRF_SCANNER_CONFIG_PATH", str(path))
    return path


def test_reload_summarize_no_file_returns_current(config_path):
    assert scanner_config.reload_summarize(True) is True
    assert scanner_config.reload_summarize(False) is False


def test_reload_summarize_flips_true_to_false(config_path):
    config_path.write_text(json.dumps({"summarize": False}))
    assert scanner_config.reload_summarize(True) is False


def test_reload_summarize_flips_false_to_true(config_path):
    config_path.write_text(json.dumps({"summarize": True}))
    assert scanner_config.reload_summarize(False) is True


def test_reload_summarize_accepts_string_truthy(config_path):
    config_path.write_text(json.dumps({"summarize": "yes"}))
    assert scanner_config.reload_summarize(False) is True


def test_reload_summarize_accepts_string_falsy(config_path):
    config_path.write_text(json.dumps({"summarize": "0"}))
    assert scanner_config.reload_summarize(True) is False


def test_reload_summarize_no_key_returns_current(config_path):
    config_path.write_text(json.dumps({"other_field": 42}))
    assert scanner_config.reload_summarize(True) is True


def test_reload_summarize_bad_json_returns_current(config_path, caplog):
    config_path.write_text("not json {{{")
    with caplog.at_level(logging.WARNING, logger=scanner_config.logger.name):
        assert scanner_config.reload_summarize(True) is True
    # getMessage(), not .message: caplog appends a record before formatting
    # it, so a record logged concurrently by a background thread left over
    # from another test (common under xdist) may not have .message yet.
    assert any(
        r.name == scanner_config.logger.name
        and "Could not read scanner config" in r.getMessage()
        for r in caplog.records
    )


def test_write_config_persists_atomically(config_path):
    out = scanner_config.write_config({"summarize": False, "extra": 1})
    assert out == config_path
    assert json.loads(config_path.read_text()) == {"summarize": False, "extra": 1}
    # No leftover tmp file after a successful replace.
    assert not config_path.with_suffix(config_path.suffix + ".tmp").exists()


def test_write_config_never_follows_a_planted_temp_name(config_path, tmp_path):
    # The directory belongs to the scanners' user while the agent writes as
    # root: a symlink planted at the old fixed temp name must not be
    # followed (it would overwrite its target as root).
    victim = tmp_path / "victim"
    victim.write_text("untouched")
    planted = config_path.with_suffix(config_path.suffix + ".tmp")
    planted.symlink_to(victim)
    scanner_config.write_config({"summarize": True})
    assert victim.read_text() == "untouched"
    assert planted.is_symlink()
    assert json.loads(config_path.read_text()) == {"summarize": True}
    assert not config_path.is_symlink()
    # Readable by the scanner units (another user), and no temp file left.
    assert config_path.stat().st_mode & 0o777 == 0o644
    names = sorted(p.name for p in config_path.parent.iterdir())
    assert names == sorted([config_path.name, planted.name, victim.name])


def test_write_config_missing_dir_error_is_actionable(tmp_path, monkeypatch):
    # The agent unit runs as pi and cannot create /var/lib/sigrift-edge when
    # no unit with StateDirectory=sigrift-edge has run: the error must name
    # the directory and the fix rather than a bare errno.  (A regular file in
    # place of the directory reproduces the failure even when run as root.)
    blocker = tmp_path / "sigrift-edge"
    blocker.write_text("not a directory")
    monkeypatch.setenv("MLRF_SCANNER_CONFIG_PATH", str(blocker / "scanner-config.json"))
    with pytest.raises(OSError) as info:
        scanner_config.write_config({"summarize": True})
    msg = str(info.value)
    assert str(blocker) in msg
    assert "StateDirectory=sigrift-edge" in msg
    assert "MLRF_SCANNER_CONFIG_PATH" in msg


def test_write_then_reload_roundtrip(config_path):
    scanner_config.write_config({"summarize": False})
    assert scanner_config.reload_summarize(True) is False
    scanner_config.write_config({"summarize": True})
    assert scanner_config.reload_summarize(False) is True


def test_reload_transition_is_logged(config_path, caplog):
    config_path.write_text(json.dumps({"summarize": False}))
    with caplog.at_level(logging.INFO):
        scanner_config.reload_summarize(True)
    assert any(
        "summarize toggled True -> False" in r.getMessage() for r in caplog.records
    )


def test_reload_no_transition_is_quiet(config_path, caplog):
    config_path.write_text(json.dumps({"summarize": True}))
    with caplog.at_level(logging.INFO):
        scanner_config.reload_summarize(True)
    # Same value: no transition log.
    assert not any("summarize toggled" in r.getMessage() for r in caplog.records)


def test_node_agent_update_config_writes_file(config_path):
    """Bridge sends update_config -> node_agent persists payload to disk."""
    from sigrift.edge import node_agent

    node_agent._dispatch_command(
        {
            "command": "update_config",
            "command_id": "test-cmd-1",
            "params": {"summarize": False},
        }
    )
    assert json.loads(config_path.read_text()) == {"summarize": False}


def test_node_agent_update_config_empty_params(config_path):
    """Missing params shouldn't crash; should write an empty dict."""
    from sigrift.edge import node_agent

    node_agent._dispatch_command(
        {"command": "update_config", "command_id": "test-cmd-2"}
    )
    assert json.loads(config_path.read_text()) == {}


def test_default_path_is_not_under_tmp(monkeypatch):
    """The agent->scanner handoff must not live in /tmp (Q15).

    Each edge unit runs with ``PrivateTmp=yes``, so a file the agent writes
    under its private ``/tmp`` is invisible to the scanner's private
    ``/tmp``. The default must be a shared state dir instead.
    """
    monkeypatch.delenv("MLRF_SCANNER_CONFIG_PATH", raising=False)
    default = scanner_config._default_path()
    assert not str(default).startswith("/tmp/"), default
    assert str(default) == scanner_config.DEFAULT_SCANNER_CONFIG_PATH
    assert default == Path("/var/lib/sigrift-edge/scanner-config.json")


def test_env_override_still_wins(tmp_path, monkeypatch):
    override = tmp_path / "custom.json"
    monkeypatch.setenv("MLRF_SCANNER_CONFIG_PATH", str(override))
    assert scanner_config._default_path() == override
