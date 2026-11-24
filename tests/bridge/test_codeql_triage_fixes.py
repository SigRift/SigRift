"""Fixes from the 2026-11-24 CodeQL triage.

* The bridge's stdout log formatter keeps each message on one line, so a
  logged value with CR/LF or another control character cannot forge a log
  line; tracebacks keep theirs.
* A short operator-set API key draws a startup warning that never logs it.
* Detection and batch ids follow the gateway's ``validate_record_id``, on
  the Bridge and in the rf-summary sender contract.
* Webhook URL checks: a hostname getaddrinfo cannot encode is "Cannot
  resolve hostname", not the private-network refusal.
* IQ and pcap purges, and the orphan-sidecar sweep, say when they could not
  delete a file instead of reporting a silent "0 removed".
* Threat-signature matching failures are logged once per failure streak.
* webhooks.json, which holds signing secrets, is written owner-only.
"""

from __future__ import annotations

import asyncio
import logging
import os
import stat
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from sigrift.bridge.anomaly.pcap_store import PcapStore
from sigrift.bridge.anomaly.scorer import AnomalyScorer
from sigrift.bridge.app import (
    _ensure_root_log_handler,
    _warn_if_short_env_key,
    SingleLineFormatter,
)
from sigrift.bridge.iq_store import IQStore
from sigrift.bridge.models import DetectionBatch, DetectionRecord
from sigrift.bridge.persistence import PersistenceManager
from sigrift.bridge.routers import webhook_management
from sigrift.edge.summary_protocol import valid_record_id

# ---------------------------------------------------------------------------
# Log formatter
# ---------------------------------------------------------------------------


def _record(msg: str, *args: object, exc_info=None) -> logging.LogRecord:
    return logging.LogRecord(
        "sigrift.bridge.test", logging.WARNING, __file__, 1, msg, args, exc_info
    )


def test_formatter_escapes_cr_and_lf_in_the_message():
    fmt = SingleLineFormatter("%(levelname)s %(message)s")
    out = fmt.format(_record("login failed for %s", "eve\r\n2026 [ERROR] forged"))
    assert out == "WARNING login failed for eve\\r\\n2026 [ERROR] forged"
    assert "\n" not in out and "\r" not in out


@pytest.mark.parametrize(
    ("raw", "shown"),
    [
        ("\x1b[1A\x1b[2K", "\\x1b[1A\\x1b[2K"),  # cursor up, erase line
        ("a\x0bb\x0cc", "a\\x0bb\\x0cc"),
        ("a\x85b\u2028c\u2029d", "a\\x85b\\u2028c\\u2029d"),
        ("a\x00b\x7fc", "a\\x00b\\x7fc"),
        ("tab\tand caf\u00e9 stay", "tab\tand caf\u00e9 stay"),
    ],
)
def test_formatter_escapes_every_control_character_but_tab(raw, shown):
    fmt = SingleLineFormatter("%(message)s")
    out = fmt.format(_record("%s", raw))
    assert out == shown
    assert len(out.splitlines()) == 1


def test_formatter_keeps_a_traceback_on_its_own_lines():
    fmt = SingleLineFormatter("%(levelname)s %(message)s")
    try:
        raise ValueError("boom")
    except ValueError:
        exc_info = sys.exc_info()
    out = fmt.format(_record("step %s failed", "a\nb", exc_info=exc_info))
    first, _, rest = out.partition("\n")
    assert first == "WARNING step a\\nb failed"
    assert rest.startswith("Traceback (most recent call last):")
    assert rest.rstrip().endswith("ValueError: boom")


def test_root_handler_uses_the_single_line_formatter():
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    try:
        root.handlers[:] = [
            h for h in root.handlers if not getattr(h, "_sigrift_app_handler", False)
        ]
        _ensure_root_log_handler("INFO")
        ours = [h for h in root.handlers if getattr(h, "_sigrift_app_handler", False)]
        assert len(ours) == 1
        assert isinstance(ours[0].formatter, SingleLineFormatter)
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)


# ---------------------------------------------------------------------------
# Short operator-set keys
# ---------------------------------------------------------------------------


def test_a_short_env_key_warns_without_logging_the_key(caplog):
    with caplog.at_level(logging.WARNING, logger="sigrift.bridge.app"):
        _warn_if_short_env_key("BRIDGE_MASTER_KEY", "hunter2-hunter2")
    assert "BRIDGE_MASTER_KEY is only 15 characters long" in caplog.text
    assert "hunter2" not in caplog.text


@pytest.mark.parametrize("value", ["", "k" * 32, "k" * 43])
def test_an_empty_or_long_env_key_draws_no_warning(caplog, value):
    with caplog.at_level(logging.WARNING, logger="sigrift.bridge.app"):
        _warn_if_short_env_key("BRIDGE_LOCAL_NODE_KEY", value)
    assert caplog.records == []


# ---------------------------------------------------------------------------
# Detection and batch ids
# ---------------------------------------------------------------------------

_GOOD_IDS = ["a1b2c3d4e5f60718", "edge-1:2026-11-24T10:00:00.5", "x" * 128, ""]
_BAD_IDS = ["a\nb", "a\rb", "a/b", "a b", "a..b", "x" * 129, "café"]


def _det(det_id: str) -> dict:
    return {"id": det_id, "node_id": "n1", "signal_class": "bpsk", "confidence": 0.5}


@pytest.mark.parametrize("det_id", _GOOD_IDS)
def test_detection_ids_the_gateway_accepts_pass(det_id):
    assert DetectionRecord.model_validate(_det(det_id)).detection_id == det_id


@pytest.mark.parametrize("det_id", _BAD_IDS)
def test_detection_ids_the_gateway_refuses_are_refused(det_id):
    with pytest.raises(ValidationError, match="detection_id must match"):
        DetectionRecord.model_validate(_det(det_id))


def _batch(batch_id: str) -> dict:
    return {"node_id": "n1", "batch_id": batch_id, "period_start": 0, "period_end": 1}


@pytest.mark.parametrize("batch_id", _GOOD_IDS)
def test_batch_ids_the_gateway_accepts_pass(batch_id):
    assert DetectionBatch.model_validate(_batch(batch_id)).batch_id == batch_id


@pytest.mark.parametrize("batch_id", _BAD_IDS)
def test_batch_ids_the_gateway_refuses_are_refused(batch_id):
    with pytest.raises(ValidationError, match="batch_id must match"):
        DetectionBatch.model_validate(_batch(batch_id))


def test_default_ids_pass_the_validators():
    # Pydantic does not validate defaults, so feed them back in.
    batch_id = DetectionBatch.model_validate(
        {"node_id": "n1", "period_start": 0, "period_end": 1}
    ).batch_id
    assert DetectionBatch.model_validate(_batch(batch_id)).batch_id == batch_id
    det = _det("x")
    del det["id"]
    det_id = DetectionRecord.model_validate(det).detection_id
    assert DetectionRecord.model_validate(_det(det_id)).detection_id == det_id


@pytest.mark.parametrize("det_id", _GOOD_IDS[:-1])
def test_summary_protocol_accepts_the_same_ids(det_id):
    assert valid_record_id(det_id)


@pytest.mark.parametrize("det_id", ["", None, 7, *_BAD_IDS])
def test_summary_protocol_refuses_ids_the_bridge_would_refuse(det_id):
    # The sender checks before journaling: a row the receiver refuses
    # would otherwise pin its hour.
    assert not valid_record_id(det_id)


# ---------------------------------------------------------------------------
# Webhook URL check
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("error", "detail"),
    [
        (UnicodeEncodeError("idna", "x", 0, 1, "label too long"), "Cannot resolve"),
        (OSError("no route"), "Cannot resolve"),
        (ValueError("blocked address"), "must not target private"),
    ],
)
def test_webhook_url_errors_get_the_right_message(monkeypatch, error, detail):
    def resolve(_host: str) -> list[str]:
        raise error

    monkeypatch.setattr(webhook_management, "_resolve_and_check_ip", resolve)
    with pytest.raises(HTTPException) as caught:
        asyncio.run(webhook_management._validate_webhook_url("https://example.com/h"))
    assert caught.value.status_code == 400
    assert detail in caught.value.detail


# ---------------------------------------------------------------------------
# Purges that cannot delete
# ---------------------------------------------------------------------------


def _old_files(base: Path, suffix: str, n: int) -> list[Path]:
    old = time.time() - 30 * 86400
    files = []
    for i in range(n):
        path = base / f"cap{i}{suffix}"
        path.write_bytes(b"x")
        os.utime(path, (old, old))
        files.append(path)
    return files


def _refuse_unlink_of(monkeypatch, refused: set[str]) -> None:
    real_unlink = Path.unlink

    def unlink(self: Path, *args, **kwargs):
        if self.name in refused:
            raise PermissionError(13, "Permission denied", str(self))
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", unlink)


def test_pcap_purge_reports_files_it_could_not_delete(tmp_path, monkeypatch, caplog):
    store = PcapStore(base_dir=tmp_path)
    files = _old_files(tmp_path, ".pcap.gz", 3)
    _refuse_unlink_of(monkeypatch, {files[0].name})
    with caplog.at_level(logging.WARNING, logger="sigrift.bridge.anomaly.pcap_store"):
        assert store.cleanup(max_age_days=7) == 2
    assert files[0].exists()
    assert "could not remove 1 files" in caplog.text
    assert "Permission denied" in caplog.text


def test_iq_purge_reports_files_it_could_not_delete(tmp_path, monkeypatch, caplog):
    store = IQStore(base_dir=tmp_path)
    files = _old_files(tmp_path, ".iq.gz", 2)
    _refuse_unlink_of(monkeypatch, {f.name for f in files})
    with caplog.at_level(logging.WARNING, logger="sigrift.bridge.iq_store"):
        assert store.cleanup(max_age_days=7) == 0
    assert "IQ cleanup: could not remove 2 files" in caplog.text


def test_orphan_sidecar_sweep_reports_files_it_could_not_delete(
    tmp_path, monkeypatch, caplog
):
    store = IQStore(base_dir=tmp_path)
    orphans = _old_files(tmp_path, ".quality.json", 1)
    _refuse_unlink_of(monkeypatch, {orphans[0].name})
    with caplog.at_level(logging.WARNING, logger="sigrift.bridge.iq_store"):
        assert store.sweep_orphan_sidecars() == 0
    assert "could not remove 1 orphaned sidecar files" in caplog.text


def test_a_purge_racing_another_stays_quiet(tmp_path, monkeypatch, caplog):
    # A file removed meanwhile (FileNotFoundError) is not a failure.
    store = PcapStore(base_dir=tmp_path)
    files = _old_files(tmp_path, ".pcap.gz", 1)
    real_unlink = Path.unlink

    def unlink(self: Path, *args, **kwargs):
        real_unlink(self)
        raise FileNotFoundError(2, "No such file", str(self))

    monkeypatch.setattr(Path, "unlink", unlink)
    with caplog.at_level(logging.WARNING, logger="sigrift.bridge.anomaly.pcap_store"):
        assert store.cleanup(max_age_days=7) == 0
    assert not files[0].exists()
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


# ---------------------------------------------------------------------------
# Threat-signature matching failures
# ---------------------------------------------------------------------------


class _SigStore:
    def __init__(self) -> None:
        self.fail = True

    def match_by_parameters(self, **_kw):
        if self.fail:
            raise RuntimeError("no such table: threat_signatures")
        return [{"match_score": 0.9}]


def test_signature_matching_failures_are_logged_once_per_streak(caplog):
    sig_store = _SigStore()
    scorer = SimpleNamespace(_sig_store=sig_store)
    score = AnomalyScorer._signature_match_score
    det = {"freq_hz": 433.92e6, "signal_class": "fsk"}
    with caplog.at_level(logging.INFO, logger="sigrift.bridge.anomaly.scorer"):
        assert score(scorer, det) == 0.0
        assert score(scorer, det) == 0.0
        sig_store.fail = False
        assert score(scorer, det) == 0.9
        sig_store.fail = True
        assert score(scorer, det) == 0.0
    messages = [r.getMessage() for r in caplog.records]
    assert messages == [
        "Threat-signature matching failed; the signature dimension scores 0 "
        "until it works again",
        "Threat-signature matching works again",
        "Threat-signature matching failed; the signature dimension scores 0 "
        "until it works again",
    ]


# ---------------------------------------------------------------------------
# webhooks.json mode
# ---------------------------------------------------------------------------


def test_webhooks_json_is_written_owner_only(tmp_path):
    pm = PersistenceManager(tmp_path, auto_save_interval=0)
    pm.load_all()
    pm.set_webhooks(
        [
            {
                "id": "hook-1",
                "url": "https://example.com/h",
                "enabled": True,
                "signing_secret": "synthetic-secret",
            }
        ]
    )
    mode = stat.S_IMODE((tmp_path / "webhooks.json").stat().st_mode)
    assert mode == 0o600
