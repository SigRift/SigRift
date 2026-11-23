"""Tests for the root-logging fix in PR K.

The bridge set the root logger's *level* to INFO but never attached a
*handler*, so application ``logger.info`` records were silently dropped
(only WARNING+ reached stderr via Python's last-resort handler). That
hid the WAL-checkpoint diagnostics during the 2026-06 WAL incident.
``_ensure_root_log_handler`` attaches a stdout handler so app INFO logs
actually emit.
"""

from __future__ import annotations

import logging

import pytest

from sigrift.bridge.app import _ensure_root_log_handler


@pytest.fixture(autouse=True)
def _restore_root_logging():
    """Snapshot + restore root logger handlers/level around each test."""
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    yield
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)


def _our_handlers():
    return [
        h
        for h in logging.getLogger().handlers
        if getattr(h, "_sigrift_app_handler", False)
    ]


def test_handler_added_when_missing():
    # Strip any of our handlers first.
    root = logging.getLogger()
    root.handlers[:] = [
        h for h in root.handlers if not getattr(h, "_sigrift_app_handler", False)
    ]
    assert _our_handlers() == []

    _ensure_root_log_handler("INFO")
    handlers = _our_handlers()
    assert len(handlers) == 1
    assert root.level == logging.INFO


def test_idempotent_no_duplicate_handler():
    root = logging.getLogger()
    root.handlers[:] = [
        h for h in root.handlers if not getattr(h, "_sigrift_app_handler", False)
    ]
    _ensure_root_log_handler("INFO")
    _ensure_root_log_handler("INFO")
    _ensure_root_log_handler("DEBUG")
    assert len(_our_handlers()) == 1, "must not stack handlers across calls"


def test_level_honoured():
    _ensure_root_log_handler("DEBUG")
    assert logging.getLogger().level == logging.DEBUG


def _reset_our_handlers():
    """Drop any pre-existing tagged handler so the next
    ``_ensure_root_log_handler`` binds a fresh one to the *current* stdout.

    The idempotency guard means a handler added by an earlier test (in the
    same xdist worker) lingers bound to that test's now-torn-down capture
    stream — so the canary would emit to a dead stream and capfd would see
    nothing. Stripping first forces a fresh bind.
    """
    root = logging.getLogger()
    root.handlers[:] = [
        h for h in root.handlers if not getattr(h, "_sigrift_app_handler", False)
    ]


def test_info_record_actually_emits(capfd):
    """An app logger.info call must reach stdout once the handler exists."""
    _reset_our_handlers()
    _ensure_root_log_handler("INFO")
    logging.getLogger("sigrift.bridge.test").info("pr-k-canary-line")
    for h in _our_handlers():
        h.flush()
    out, _err = capfd.readouterr()
    assert "pr-k-canary-line" in out, (
        f"INFO log should reach stdout; captured stdout was: {out!r}"
    )


def test_warning_still_works(capfd):
    _reset_our_handlers()
    _ensure_root_log_handler("INFO")
    logging.getLogger("sigrift.bridge.test").warning("pr-k-warn-canary")
    for h in _our_handlers():
        h.flush()
    out, _err = capfd.readouterr()
    assert "pr-k-warn-canary" in out
