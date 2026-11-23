"""Tests for sigrift.bridge.detection_reporter.

Covers filtering, deduplication, class-change detection, buffering,
batch upload with retry/gzip/auth, timeout handling, and anomaly scoring.
All network calls are mocked — tests run fully offline.
"""

from __future__ import annotations

import gzip
import json
import tempfile
import threading
import time
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from sigrift.bridge.detection_reporter import (
    DetectionReporter,
    REPORTER_VERSION,
    _class_to_family,
    _DedupEntry,
)
from sigrift.bridge import API_VERSION


@pytest.fixture(autouse=True)
def _isolated_cwd(tmp_path, monkeypatch):
    """Run each test in its own directory.

    A reporter built without ``data_dir``/``saf_db_path`` opens the relative
    ``saf_buffer.db``. Sharing one file across xdist workers made the first
    ``PRAGMA journal_mode=WAL`` on a fresh checkout race between processes and
    fail with "database is locked"; it also left the file in the repo root.
    """
    monkeypatch.chdir(tmp_path)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_classification(
    cls: str = "bpsk",
    confidence: float = 0.85,
    family: str | None = None,
    inference_ms: float = 5.0,
) -> dict:
    return {
        "class": cls,
        "confidence": confidence,
        "family": family or _class_to_family(cls),
        "inference_ms": inference_ms,
    }


def _make_reporter(**overrides) -> DetectionReporter:
    """Build a DetectionReporter with sane test defaults."""
    defaults = dict(
        server_url="https://bridge.test:8443",
        api_key="test-key-abc123",
        node_id="edge-01",
        flush_interval_seconds=999,  # don't auto-flush
        dedup_window_seconds=0,      # disable dedup by default
        repeat_report_interval=9999, # disable repeat suppression
    )
    defaults.update(overrides)
    return DetectionReporter(**defaults)


# ---------------------------------------------------------------------------
# _class_to_family
# ---------------------------------------------------------------------------


class TestClassToFamily:
    def test_known_classes(self):
        assert _class_to_family("bpsk") == "PSK"
        assert _class_to_family("ook") == "ASK"
        assert _class_to_family("16qam") == "QAM"
        assert _class_to_family("fm") == "ANALOG"
        assert _class_to_family("2fsk") == "FSK"
        assert _class_to_family("ofdm-256") == "OFDM"
        assert _class_to_family("16apsk") == "APSK"
        assert _class_to_family("4pam") == "PAM"
        assert _class_to_family("2msk") == "MSK"

    def test_unknown_class(self):
        assert _class_to_family("bogus") == "UNKNOWN"


# ---------------------------------------------------------------------------
# _DedupEntry
# ---------------------------------------------------------------------------


class TestDedupEntry:
    def test_creation(self):
        e = _DedupEntry("bpsk", 0.9, 15.0, -60.0, 1000.0)
        assert e.signal_class == "bpsk"
        assert e.count == 1
        assert e.first_seen == 1000.0
        assert e.last_seen == 1000.0
        assert e.max_confidence == pytest.approx(0.9)
        assert e.max_snr_db == pytest.approx(15.0)
        assert e.max_power_dbm == pytest.approx(-60.0)

    def test_update_tracks_maxima(self):
        e = _DedupEntry("bpsk", 0.8, 10.0, -70.0, 1000.0)
        e.update(0.95, 20.0, -50.0, 1001.0)
        assert e.count == 2
        assert e.max_confidence == pytest.approx(0.95)
        assert e.max_snr_db == pytest.approx(20.0)
        assert e.max_power_dbm == pytest.approx(-50.0)
        assert e.last_seen == pytest.approx(1001.0)
        # first_seen should not change
        assert e.first_seen == pytest.approx(1000.0)

    def test_update_does_not_lower_maxima(self):
        e = _DedupEntry("bpsk", 0.95, 20.0, -40.0, 1000.0)
        e.update(0.5, 5.0, -80.0, 1001.0)
        assert e.max_confidence == pytest.approx(0.95)
        assert e.max_snr_db == pytest.approx(20.0)
        assert e.max_power_dbm == pytest.approx(-40.0)


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


class TestFiltering:
    def test_low_confidence_filtered(self):
        r = _make_reporter(min_confidence=0.5)
        result = r.report(
            _make_classification(confidence=0.3),
            freq_hz=433.92e6, snr_db=15.0, power_dbm=-60.0,
        )
        assert result is False
        assert r.get_stats()["total_filtered"] == 1
        assert r.get_stats()["total_buffered"] == 0

    def test_low_snr_filtered(self):
        r = _make_reporter(min_snr_db=3.0)
        result = r.report(
            _make_classification(confidence=0.9),
            freq_hz=433.92e6, snr_db=1.0, power_dbm=-60.0,
        )
        assert result is False
        assert r.get_stats()["total_filtered"] == 1

    def test_passing_detection_accepted(self):
        r = _make_reporter(min_confidence=0.5, min_snr_db=3.0)
        result = r.report(
            _make_classification(confidence=0.9),
            freq_hz=433.92e6, snr_db=15.0, power_dbm=-60.0,
        )
        assert result is True
        assert r.get_stats()["total_buffered"] == 1
        assert r.get_stats()["total_filtered"] == 0

    def test_exactly_at_threshold_passes(self):
        r = _make_reporter(min_confidence=0.5, min_snr_db=3.0)
        result = r.report(
            _make_classification(confidence=0.5),
            freq_hz=433.92e6, snr_db=3.0, power_dbm=-60.0,
        )
        assert result is True

    def test_just_below_confidence_filtered(self):
        r = _make_reporter(min_confidence=0.5)
        result = r.report(
            _make_classification(confidence=0.499),
            freq_hz=433.92e6, snr_db=15.0, power_dbm=-60.0,
        )
        assert result is False


# ---------------------------------------------------------------------------
# Class-change detection and repeat suppression
# ---------------------------------------------------------------------------


class TestClassChangeDetection:
    @pytest.fixture(autouse=True)
    def _setup(self):
        self.reporter = _make_reporter(
            repeat_report_interval=5,
            dedup_window_seconds=0,
        )

    def _report(self, cls: str = "bpsk", freq: float = 433.92e6) -> bool:
        with self.reporter._dedup_lock:
            self.reporter._dedup.clear()
        return self.reporter.report(
            _make_classification(cls=cls, confidence=0.9),
            freq_hz=freq, snr_db=15.0, power_dbm=-60.0,
        )

    def test_first_detection_accepted(self):
        assert self._report("bpsk") is True

    def test_same_class_suppressed(self):
        assert self._report("bpsk") is True
        assert self._report("bpsk") is False
        assert self._report("bpsk") is False
        assert self._report("bpsk") is False

    def test_same_class_reported_at_interval(self):
        assert self._report("bpsk") is True   # count=1
        assert self._report("bpsk") is False  # count=2
        assert self._report("bpsk") is False  # count=3
        assert self._report("bpsk") is False  # count=4
        assert self._report("bpsk") is True   # count=5

    def test_class_change_accepted(self):
        assert self._report("bpsk") is True
        assert self._report("qpsk") is True

    def test_different_frequencies_independent(self):
        assert self._report("bpsk", freq=433.92e6) is True
        assert self._report("bpsk", freq=868.0e6) is True


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


class TestDeduplication:
    def test_same_class_same_freq_deduped(self):
        r = _make_reporter(
            dedup_window_seconds=1.0,
            repeat_report_interval=1,  # disable repeat suppression
        )
        cls = _make_classification(cls="bpsk", confidence=0.9)
        r1 = r.report(cls, freq_hz=433.92e6, snr_db=15.0, power_dbm=-60.0)
        assert r1 is True
        r2 = r.report(cls, freq_hz=433.92e6, snr_db=15.0, power_dbm=-60.0)
        assert r2 is False
        assert r.get_stats()["total_deduped"] == 1

    def test_different_class_same_freq_not_deduped(self):
        r = _make_reporter(dedup_window_seconds=1.0)
        r1 = r.report(
            _make_classification(cls="bpsk"), freq_hz=433.92e6,
            snr_db=15.0, power_dbm=-60.0,
        )
        r2 = r.report(
            _make_classification(cls="qpsk"), freq_hz=433.92e6,
            snr_db=15.0, power_dbm=-60.0,
        )
        assert r1 is True
        assert r2 is True

    def test_same_class_different_freq_not_deduped(self):
        r = _make_reporter(dedup_window_seconds=1.0)
        cls = _make_classification(cls="bpsk")
        r1 = r.report(cls, freq_hz=433.92e6, snr_db=15.0, power_dbm=-60.0)
        r2 = r.report(cls, freq_hz=868.0e6, snr_db=15.0, power_dbm=-60.0)
        assert r1 is True
        assert r2 is True

    def test_dedup_expires_after_window(self):
        r = _make_reporter(dedup_window_seconds=1.0)
        cls = _make_classification(cls="bpsk")

        base_time = 1_000_000.0
        with patch("time.time", return_value=base_time):
            r1 = r.report(cls, freq_hz=433.92e6, snr_db=15.0, power_dbm=-60.0)
        assert r1 is True

        # Advance past window and reset class-change tracker
        with patch("time.time", return_value=base_time + 1.5):
            r._last_class.clear()
            r2 = r.report(cls, freq_hz=433.92e6, snr_db=15.0, power_dbm=-60.0)
        assert r2 is True


# ---------------------------------------------------------------------------
# Buffering and record structure
# ---------------------------------------------------------------------------


class TestBuffering:
    def test_record_structure(self):
        r = _make_reporter()
        r.report(
            _make_classification(cls="bpsk", confidence=0.92, inference_ms=7.5),
            freq_hz=433.92e6, snr_db=15.5, power_dbm=-62.3,
        )
        assert len(r._buffer) == 1
        rec = r._buffer[0]
        assert rec["node_id"] == "edge-01"
        assert rec["signal_class"] == "bpsk"
        assert rec["confidence"] == pytest.approx(0.92)
        assert rec["family"] == "PSK"
        assert rec["freq_hz"] == pytest.approx(433.92e6)
        assert rec["snr_db"] == pytest.approx(15.5)
        assert rec["power_dbm"] == pytest.approx(-62.3)
        assert rec["inference_ms"] == pytest.approx(7.5)
        assert isinstance(rec["id"], str)
        assert len(rec["id"]) == 16
        assert isinstance(rec["timestamp"], float)

    def test_buffer_bounded_by_max_buffer(self):
        r = _make_reporter(max_buffer=5, batch_size=9999)
        classes = ["bpsk", "qpsk", "8psk", "16psk", "32psk", "16qam", "32qam"]
        for i, cls in enumerate(classes):
            r.report(
                _make_classification(cls=cls),
                freq_hz=float(i) * 1e6, snr_db=15.0, power_dbm=-60.0,
            )
        assert len(r._buffer) <= 5

    def test_iq_hash_truncated_to_16(self):
        r = _make_reporter()
        r.report(
            _make_classification(),
            freq_hz=433.92e6, snr_db=15.0, power_dbm=-60.0,
            iq_hash="abcdef0123456789extra_stuff",
        )
        assert r._buffer[0]["iq_hash"] == "abcdef0123456789"

    def test_optional_fields_gain_lna_bandwidth(self):
        r = _make_reporter()
        r.report(
            _make_classification(),
            freq_hz=433.92e6, snr_db=15.0, power_dbm=-60.0,
            gain_db=32.5, lna_state="auto", bandwidth_hz=25000.0,
        )
        rec = r._buffer[0]
        assert rec["gain_db"] == pytest.approx(32.5)
        assert rec["lna_state"] == "auto"
        assert rec["bandwidth_hz"] == pytest.approx(25000.0)

    def test_optional_fields_absent_when_not_provided(self):
        r = _make_reporter()
        r.report(
            _make_classification(),
            freq_hz=433.92e6, snr_db=15.0, power_dbm=-60.0,
        )
        rec = r._buffer[0]
        assert "gain_db" not in rec
        assert "lna_state" not in rec
        assert "bandwidth_hz" not in rec
        assert "iq_hash" not in rec


# ---------------------------------------------------------------------------
# IQ fingerprint
# ---------------------------------------------------------------------------


class TestIqFingerprint:
    def test_bytes_input(self):
        fp = DetectionReporter.iq_fingerprint(b"\x00" * 1024)
        assert len(fp) == 16
        assert all(c in "0123456789abcdef" for c in fp)

    def test_deterministic(self):
        data = b"\x01\x02\x03\x04" * 256
        assert DetectionReporter.iq_fingerprint(data) == DetectionReporter.iq_fingerprint(data)

    def test_different_data_different_hash(self):
        fp1 = DetectionReporter.iq_fingerprint(b"\x00" * 1024)
        fp2 = DetectionReporter.iq_fingerprint(b"\xff" * 1024)
        assert fp1 != fp2

    def test_list_input(self):
        fp = DetectionReporter.iq_fingerprint([0.0] * 256)
        assert len(fp) == 16


# ---------------------------------------------------------------------------
# Upload — mocked urllib
# ---------------------------------------------------------------------------


class TestUpload:
    """Test _upload() directly with urllib.request.urlopen mocked out."""

    def _make_payload(self) -> dict:
        return {
            "node_id": "edge-01",
            "batch_id": "abcd1234",
            "period_start": 1000.0,
            "period_end": 1001.0,
            "detections": [{"signal_class": "bpsk", "confidence": 0.9}],
            "summary": {
                "total_detections": 1,
                "class_counts": {"bpsk": 1},
                "avg_confidence": 0.9,
                "dominant_class": "bpsk",
                "dominant_family": "PSK",
            },
        }

    def test_successful_upload(self):
        r = _make_reporter(max_retries=3, base_retry_delay=0.01)
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({"accepted": True}).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
            result = r._upload(self._make_payload())

        assert result is True
        assert mock_open.call_count == 1

    def test_gzip_compression_of_payload(self):
        r = _make_reporter()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"ok":true}'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        captured_requests = []

        def capture_urlopen(req, **kwargs):
            captured_requests.append(req)
            return mock_resp

        with patch("urllib.request.urlopen", side_effect=capture_urlopen):
            r._upload(self._make_payload())

        assert len(captured_requests) == 1
        req = captured_requests[0]
        # Verify Content-Encoding header
        assert req.get_header("Content-encoding") == "gzip"
        # Verify the data is actually gzip-compressed and decompresses to valid JSON
        raw = req.data
        decompressed = gzip.decompress(raw)
        payload = json.loads(decompressed)
        assert payload["node_id"] == "edge-01"
        assert payload["detections"][0]["signal_class"] == "bpsk"

    def test_auth_headers_present(self):
        r = _make_reporter(api_key="secret-key-42", node_id="edge-77")
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"ok":true}'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        captured_requests = []

        def capture_urlopen(req, **kwargs):
            captured_requests.append(req)
            return mock_resp

        with patch("urllib.request.urlopen", side_effect=capture_urlopen):
            r._upload(self._make_payload())

        req = captured_requests[0]
        assert req.get_header("X-api-key") == "secret-key-42"
        assert req.get_header("X-node-id") == "edge-77"
        assert req.get_header("X-api-version") == API_VERSION
        assert req.get_header("X-reporter-version") == REPORTER_VERSION
        assert req.get_header("Content-type") == "application/json"

    def test_upload_url(self):
        r = _make_reporter(server_url="https://bridge.test:8443/")
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"ok":true}'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        captured_requests = []

        def capture_urlopen(req, **kwargs):
            captured_requests.append(req)
            return mock_resp

        with patch("urllib.request.urlopen", side_effect=capture_urlopen):
            r._upload(self._make_payload())

        assert captured_requests[0].full_url == "https://bridge.test:8443/api/detections/batch"

    def test_retry_on_transient_failure(self):
        r = _make_reporter(max_retries=3, base_retry_delay=0.01, max_retry_delay=0.02)

        call_count = 0

        def side_effect(req, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise urllib.error.HTTPError(
                    req.full_url, 503, "Service Unavailable", {}, None,
                )
            resp = MagicMock()
            resp.status = 200
            resp.read.return_value = b'{"ok":true}'
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        with patch("urllib.request.urlopen", side_effect=side_effect):
            result = r._upload(self._make_payload())

        assert result is True
        assert call_count == 3

    def test_all_retries_exhausted_returns_false(self):
        r = _make_reporter(max_retries=3, base_retry_delay=0.01, max_retry_delay=0.02)

        def always_fail(req, **kwargs):
            raise urllib.error.HTTPError(
                req.full_url, 500, "Internal Server Error", {}, None,
            )

        with patch("urllib.request.urlopen", side_effect=always_fail):
            result = r._upload(self._make_payload())

        assert result is False
        stats = r.get_stats()
        assert stats["total_upload_failures"] == 3

    def test_timeout_error_retried(self):
        r = _make_reporter(max_retries=2, base_retry_delay=0.01, max_retry_delay=0.02)

        call_count = 0

        def side_effect(req, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise TimeoutError("Connection timed out")
            resp = MagicMock()
            resp.status = 200
            resp.read.return_value = b'{"ok":true}'
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        with patch("urllib.request.urlopen", side_effect=side_effect):
            result = r._upload(self._make_payload())

        assert result is True
        assert call_count == 2

    def test_connection_error_retried(self):
        r = _make_reporter(max_retries=2, base_retry_delay=0.01, max_retry_delay=0.02)

        call_count = 0

        def side_effect(req, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise urllib.error.URLError("Connection refused")
            resp = MagicMock()
            resp.status = 200
            resp.read.return_value = b'{"ok":true}'
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        with patch("urllib.request.urlopen", side_effect=side_effect):
            result = r._upload(self._make_payload())

        assert result is True
        assert call_count == 2

    def test_ssl_context_passed_to_urlopen(self):
        r = _make_reporter()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"ok":true}'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
            r._upload(self._make_payload())

        _, kwargs = mock_open.call_args
        assert kwargs.get("context") is r._ssl_ctx
        assert kwargs.get("timeout") == 15


# ---------------------------------------------------------------------------
# Flush integration (mocked network)
# ---------------------------------------------------------------------------


class TestFlush:
    def test_do_flush_uploads_buffered_detections(self):
        r = _make_reporter(batch_size=999)
        # Buffer some detections
        for i, cls in enumerate(["bpsk", "qpsk", "8psk"]):
            r.report(
                _make_classification(cls=cls),
                freq_hz=float(i) * 1e6, snr_db=15.0, power_dbm=-60.0,
            )
        assert len(r._buffer) == 3

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"ok":true}'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            r._do_flush()

        assert len(r._buffer) == 0
        stats = r.get_stats()
        assert stats["total_uploaded"] == 3
        assert stats["total_batches_sent"] == 1

    def test_do_flush_noop_when_buffer_empty(self):
        r = _make_reporter()
        with patch("urllib.request.urlopen") as mock_open:
            r._do_flush()
        mock_open.assert_not_called()

    def test_flush_on_batch_size_reached(self):
        r = _make_reporter(batch_size=3)
        captured_payloads = []

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"ok":true}'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        def capture(req, **kwargs):
            raw = gzip.decompress(req.data)
            captured_payloads.append(json.loads(raw))
            return mock_resp

        with patch("urllib.request.urlopen", side_effect=capture):
            for i, cls in enumerate(["bpsk", "qpsk", "8psk"]):
                r.report(
                    _make_classification(cls=cls),
                    freq_hz=float(i) * 1e6, snr_db=15.0, power_dbm=-60.0,
                )

        assert len(captured_payloads) == 1
        payload = captured_payloads[0]
        assert len(payload["detections"]) == 3
        assert payload["node_id"] == "edge-01"
        assert isinstance(payload["batch_id"], str)
        assert isinstance(payload["summary"], dict)

    def test_flush_payload_summary(self):
        r = _make_reporter(batch_size=4)
        captured_payloads = []

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"ok":true}'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        def capture(req, **kwargs):
            raw = gzip.decompress(req.data)
            captured_payloads.append(json.loads(raw))
            return mock_resp

        with patch("urllib.request.urlopen", side_effect=capture):
            for i, cls in enumerate(["bpsk", "bpsk", "qpsk", "bpsk"]):
                r.report(
                    _make_classification(cls=cls, confidence=0.8),
                    freq_hz=float(i) * 1e6, snr_db=15.0, power_dbm=-60.0,
                )

        summary = captured_payloads[0]["summary"]
        assert summary["total_detections"] == 4
        assert summary["class_counts"]["bpsk"] == 3
        assert summary["class_counts"]["qpsk"] == 1
        assert summary["dominant_class"] == "bpsk"
        assert summary["dominant_family"] == "PSK"
        assert summary["avg_confidence"] == pytest.approx(0.8)

    def test_failed_batch_enqueued_to_saf(self, tmp_path):
        r = _make_reporter(batch_size=2, max_retries=1, base_retry_delay=0.01,
                           saf_db_path=tmp_path / "saf_drop.db")

        def always_fail(req, **kwargs):
            raise urllib.error.HTTPError(
                req.full_url, 500, "fail", {}, None,
            )

        with patch("urllib.request.urlopen", side_effect=always_fail):
            r.report(
                _make_classification(cls="bpsk"),
                freq_hz=100e6, snr_db=15.0, power_dbm=-60.0,
            )
            r.report(
                _make_classification(cls="qpsk"),
                freq_hz=200e6, snr_db=15.0, power_dbm=-60.0,
            )

        stats = r.get_stats()
        assert stats["saf_enqueued"] == 1  # batch saved to SAF instead of dropped
        assert stats["saf_pending"] == 1
        assert stats["total_uploaded"] == 0

    def test_stop_flushes_remaining_buffer(self, tmp_path):
        r = _make_reporter(batch_size=999,
                           saf_db_path=tmp_path / "saf_stop.db")
        r.report(
            _make_classification(), freq_hz=100e6, snr_db=15.0, power_dbm=-60.0,
        )
        assert len(r._buffer) == 1

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"ok":true}'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            r.stop()

        assert len(r._buffer) == 0
        assert r.get_stats()["total_uploaded"] >= 1


# ---------------------------------------------------------------------------
# get_stats
# ---------------------------------------------------------------------------


class TestGetStats:
    def test_initial_stats(self):
        r = _make_reporter()
        stats = r.get_stats()
        assert stats["total_received"] == 0
        assert stats["total_filtered"] == 0
        assert stats["total_deduped"] == 0
        assert stats["total_buffered"] == 0
        assert stats["total_uploaded"] == 0
        assert stats["total_upload_failures"] == 0
        assert stats["total_batches_sent"] == 0
        assert stats["total_dropped"] == 0
        assert stats["total_anomalies"] == 0
        assert stats["buffer_size"] == 0
        assert stats["anomaly_scoring"] is False

    def test_stats_update_after_reports(self):
        r = _make_reporter(min_confidence=0.5)
        # One accepted, one filtered
        r.report(
            _make_classification(confidence=0.9),
            freq_hz=100e6, snr_db=15.0, power_dbm=-60.0,
        )
        r.report(
            _make_classification(confidence=0.3),
            freq_hz=200e6, snr_db=15.0, power_dbm=-60.0,
        )
        stats = r.get_stats()
        assert stats["total_received"] == 2
        assert stats["total_buffered"] == 1
        assert stats["total_filtered"] == 1
        assert stats["buffer_size"] == 1


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_reports_no_corruption(self):
        r = _make_reporter(batch_size=9999)
        classes = ["bpsk", "qpsk", "8psk", "16psk", "16qam",
                   "64qam", "ook", "fm", "2fsk", "ofdm-256"]
        errors = []

        def worker(wid: int):
            try:
                for i in range(50):
                    cls = classes[(wid * 50 + i) % len(classes)]
                    r.report(
                        _make_classification(cls=cls, confidence=0.9),
                        freq_hz=float(wid * 1000 + i) * 1e6,
                        snr_db=15.0, power_dbm=-60.0,
                    )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(j,)) for j in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        stats = r.get_stats()
        assert stats["total_received"] == 200
        assert stats["total_buffered"] > 0


# ---------------------------------------------------------------------------
# Anomaly scoring
# ---------------------------------------------------------------------------


class TestAnomalyScoring:
    def test_disabled_by_default(self):
        r = _make_reporter()
        assert r.anomaly_scoring is False
        assert r.get_stats()["anomaly_scoring"] is False

    def test_no_anomaly_fields_when_disabled(self):
        r = _make_reporter()
        r.report(
            _make_classification(), freq_hz=433.92e6, snr_db=15.0, power_dbm=-60.0,
        )
        rec = r._buffer[0]
        assert "anomaly_score" not in rec
        assert "baseline_status" not in rec

    def test_enabled_adds_anomaly_fields(self):
        try:
            from sigrift.bridge.anomaly.baseline import BaselineManager
            from sigrift.bridge.anomaly.scorer import AnomalyScorer
        except ImportError:
            pytest.skip("Anomaly package not available")

        r = _make_reporter(anomaly_scoring=True)
        assert r.anomaly_scoring is True
        r.report(
            _make_classification(confidence=0.9),
            freq_hz=433.92e6, snr_db=15.0, power_dbm=-60.0,
        )
        rec = r._buffer[0]
        assert isinstance(rec["anomaly_score"], float)
        assert rec["baseline_status"] in ("learning", "stable")

    def test_baseline_learning_initially(self):
        try:
            from sigrift.bridge.anomaly.baseline import BaselineManager
        except ImportError:
            pytest.skip("Anomaly package not available")

        r = _make_reporter(anomaly_scoring=True)
        r.report(
            _make_classification(), freq_hz=433.92e6, snr_db=15.0, power_dbm=-60.0,
        )
        assert r._buffer[0]["baseline_status"] == "learning"

    def test_stats_include_baseline_frequencies(self):
        try:
            from sigrift.bridge.anomaly.baseline import BaselineManager
        except ImportError:
            pytest.skip("Anomaly package not available")

        r = _make_reporter(anomaly_scoring=True)
        stats = r.get_stats()
        assert isinstance(stats["baseline_frequencies"], int)
        assert stats["anomaly_scoring"] is True

    def test_baseline_save_and_load(self):
        try:
            from sigrift.bridge.anomaly.baseline import BaselineManager
        except ImportError:
            pytest.skip("Anomaly package not available")

        with tempfile.TemporaryDirectory() as tmpdir:
            r = _make_reporter(
                anomaly_scoring=True,
                data_dir=tmpdir,
                repeat_report_interval=1,
            )
            # Feed detections at unique freqs to build baselines
            for i in range(20):
                with r._dedup_lock:
                    r._dedup.clear()
                r.report(
                    _make_classification(cls="bpsk", confidence=0.9),
                    freq_hz=float(i) * 1e6, snr_db=15.0, power_dbm=-60.0,
                )

            assert len(r._baseline_manager.baselines) > 0
            saved_count = len(r._baseline_manager.baselines)

            r._baseline_manager.save(str(Path(tmpdir) / "baselines.json"))

            # New reporter should load saved baselines
            r2 = _make_reporter(
                anomaly_scoring=True,
                data_dir=tmpdir,
                node_id="edge-02",
            )
            assert len(r2._baseline_manager.baselines) == saved_count


# ---------------------------------------------------------------------------
# Start / stop lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    def test_start_creates_flush_thread(self):
        r = _make_reporter()
        assert r._flush_thread is None
        r.start()
        assert r._flush_thread is not None
        assert r._flush_thread.is_alive()
        assert r._running is True
        r._running = False
        r._flush_thread.join(timeout=3)

    def test_start_idempotent(self):
        r = _make_reporter()
        r.start()
        thread1 = r._flush_thread
        r.start()  # second call should be a no-op
        assert r._flush_thread is thread1
        r._running = False
        r._flush_thread.join(timeout=3)

    def test_stop_joins_thread(self):
        r = _make_reporter()
        r.start()
        assert r._running is True
        with patch("urllib.request.urlopen"):
            r.stop()
        assert r._running is False
        assert r._flush_thread is None


class TestSummarizeReplaceSemantics:
    """Verify summarize=True replaces (rather than augments) raw uploads.

    These tests target the live edge reporter at
    ``sigrift.edge.detection_reporter`` (the runtime path imported by
    ``rf_scan.py``). The other tests in this file still target the older
    ``sigrift.bridge.detection_reporter`` twin for legacy SAF coverage;
    when that twin is finally removed, this class's local import can be
    promoted to the file-level one.
    """

    @staticmethod
    def _make_reporter(data_dir, **overrides):
        from sigrift.edge.detection_reporter import (
            DetectionReporter as EdgeReporter,
        )

        defaults = dict(
            server_url="https://bridge.test:8443",
            data_dir=data_dir,
            api_key="test-key-abc123",
            node_id="edge-01",
            flush_interval_seconds=999,
            dedup_window_seconds=0,
            repeat_report_interval=9999,
        )
        defaults.update(overrides)
        return EdgeReporter(**defaults)

    def _report(self, r, freq_hz: float = 433.92e6, **overrides):
        kw = dict(freq_hz=freq_hz, snr_db=15.0, power_dbm=-60.0)
        cls = overrides.pop("cls", "bpsk")
        conf = overrides.pop("confidence", 0.9)
        kw.update(overrides)
        return r.report(_make_classification(cls=cls, confidence=conf), **kw)

    def test_buffer_stays_empty_when_summarize(self, tmp_path):
        """report() should NOT append to raw _buffer when summarize=True;
        detections feed only the accumulator."""
        r = self._make_reporter(tmp_path, summarize=True)
        for i in range(5):
            self._report(r, freq_hz=433.92e6 + i * 30_000)
        assert len(r._buffer) == 0, "raw buffer must be empty in replace mode"
        assert r._accumulator is not None
        snap = r._accumulator.snapshot()
        assert snap is not None
        assert sum(s["detection_count"] for s in snap["summaries"]) == 5

    def test_buffer_used_when_not_summarize(self, tmp_path):
        """Legacy path: summarize=False still buffers raw detections."""
        r = self._make_reporter(tmp_path, summarize=False)
        for i in range(3):
            self._report(r, freq_hz=433.92e6 + i * 30_000)
        assert len(r._buffer) == 3
        assert r._accumulator is None

    def test_snapshot_does_not_clear(self, tmp_path):
        """snapshot() must leave accumulator state intact so the next
        snapshot still contains the cumulative bins (bridge UPSERTs)."""
        r = self._make_reporter(tmp_path, summarize=True)
        for i in range(4):
            self._report(r, freq_hz=433.92e6 + i * 30_000)
        snap1 = r._accumulator.snapshot()
        snap2 = r._accumulator.snapshot()
        assert snap1 is not None and snap2 is not None
        c1 = sum(s["detection_count"] for s in snap1["summaries"])
        c2 = sum(s["detection_count"] for s in snap2["summaries"])
        assert c1 == c2 == 4

    def test_acknowledgement_retains_cumulative_state_without_pending_upload(
        self, tmp_path
    ):
        """An acknowledged hour stays cumulative for later observations."""
        r = self._make_reporter(tmp_path, summarize=True)
        assert self._report(r)
        accumulator = r._accumulator
        (hour,) = accumulator.pending_hours()
        generation, body = accumulator.pending_snapshot(hour)
        accumulator.acknowledge(hour, generation)
        assert accumulator.pending_hours() == []
        assert accumulator.snapshot()["summaries"][0]["detection_count"] == 1
        assert self._report(r, freq_hz=434e6)
        assert accumulator.pending_hours() == [hour]
        assert (
            sum(row["detection_count"] for row in accumulator.snapshot()["summaries"])
            == 2
        )
        assert accumulator.pending_snapshot(hour)[1] != body

    def test_high_anomaly_still_bypasses(self, tmp_path):
        """High-anomaly detections must still appear in the summary
        payload's ``high_anomaly_detections`` bypass list."""
        r = self._make_reporter(tmp_path, summarize=True, summary_anomaly_threshold=0.5)
        # Direct-feed a high-anomaly record to verify the bypass list.
        assert r._accumulator.accumulate(
            {
                "id": "high-anomaly-bypass",
            "node_id": "edge-01",
                "signal_class": "bpsk",
                "family": "psk",
                "freq_hz": 100e6,
                "confidence": 0.8,
                "anomaly_score": 0.95,
                "timestamp": time.time(),
            }
        )
        snap = r._accumulator.snapshot()
        assert snap is not None
        assert len(snap["high_anomaly_detections"]) == 1


class TestBaselinePersistenceWiring:
    """MLRF_DATA_DIR wiring: edge baselines survive a reporter restart.

    Regression guard for the fix that makes rf_scan pass data_dir through to
    DetectionReporter (edge nodes previously relearned from zero every restart).
    """

    def test_no_data_dir_means_no_persistence(self):
        r = _make_reporter(anomaly_scoring=True)
        if r._baseline_manager is None:
            pytest.skip("anomaly package unavailable")
        assert r._baselines_path() is None

    def test_data_dir_persists_and_reloads(self, tmp_path):
        r1 = _make_reporter(anomaly_scoring=True, data_dir=str(tmp_path))
        if r1._baseline_manager is None:
            pytest.skip("anomaly package unavailable")
        r1._baseline_manager.update(433_920_000, "ook", 0.9, -60.0, 12)
        r1.stop()  # shutdown save writes baselines.json
        assert (tmp_path / "baselines.json").exists()

        r2 = _make_reporter(anomaly_scoring=True, data_dir=str(tmp_path))
        assert r2._baseline_manager is not None
        assert r2._baseline_manager.get_baseline(433_920_000) is not None


@pytest.fixture(autouse=True)
def _close_summary_journal_resources(monkeypatch):
    # Track only resource ownership. Construction, SQLite and all behavior use
    # the real journal; tests explicitly exercise stop() independently of close.
    from sigrift.edge import summary_journal

    real_journal = summary_journal.SummaryJournal
    created = []

    def tracked(*args, **kwargs):
        journal = real_journal(*args, **kwargs)
        created.append(journal)
        return journal

    monkeypatch.setattr(summary_journal, "SummaryJournal", tracked)
    yield
    for journal in reversed(created):
        journal.close()
