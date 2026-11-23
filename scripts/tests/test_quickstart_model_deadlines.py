"""Real stalled transfers exercise the shipped limits, without shortening them.

The outer process-group watchdog fails the test and cleans up if the installer
does not return itself. It never supplies curl with a test-only timeout.
"""

from __future__ import annotations

import json
import os
import signal
import socketserver
import subprocess
import threading
import time
from types import SimpleNamespace

import pytest

import test_quickstart_model_download as transfers

release_server = transfers.release_server
pytestmark = transfers.pytestmark


def run_bounded(tmp_path, server, *, watchdog=18, **options):
    command, env = transfers.model_command(tmp_path, server, **options)
    started = time.monotonic()
    child = subprocess.Popen(
        command,
        cwd=tmp_path,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        try:
            stdout, stderr = child.communicate(timeout=watchdog)
        except subprocess.TimeoutExpired:
            pytest.fail(
                "Shipped model download did not finish before the test watchdog"
            )
        return (
            subprocess.CompletedProcess(command, child.returncode, stdout, stderr),
            time.monotonic() - started,
        )
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.communicate(timeout=3)
        assert child.poll() is not None


def assert_clean(models):
    assert not list(models.glob(".model-download.*"))


@pytest.mark.parametrize(
    "path", ["/release", "/" + transfers.MODEL_NAME, "/SHA256SUMS"]
)
def test_stalled_required_transfer_fails_cleanly_and_plain_retry_succeeds(
    tmp_path, release_server, path
):
    release_server.stall_path = path
    release_server.stall_before_headers = path == "/release"
    first, elapsed = run_bounded(tmp_path, release_server)
    assert release_server.stalled.is_set()
    assert 8 <= elapsed < 18
    assert first.returncode == 1
    assert "selected SDR requires a model; no scanner was started" in first.stderr
    assert release_server.requests[path] == 1  # No hidden request retry.
    models = tmp_path / "models"
    assert not list(models.glob("*.onnx"))
    assert_clean(models)
    assert (tmp_path / "outer-exit").read_text() == "preserved"

    release_server.stall_path = None
    release_server.release_stall.set()
    second, _ = run_bounded(tmp_path, release_server)
    assert second.returncode == 0
    assert release_server.requests[path] == 2
    assert "OK (sha256 verified)" in second.stdout
    assert (models / "open-default.onnx").read_bytes() == transfers.MODEL
    assert (models / "open-default_metadata.json").read_bytes() == transfers.METADATA
    assert_clean(models)


def test_stalled_metadata_falls_back_to_previous_sidecar_for_the_same_model(
    tmp_path, release_server
):
    models = tmp_path / "models"
    models.mkdir()
    previous = b'{"classes": ["previous complete metadata"]}\n'
    (models / transfers.META_NAME).write_bytes(previous)
    release_server.stall_path = "/" + transfers.META_NAME
    result, elapsed = run_bounded(tmp_path, release_server)
    assert release_server.stalled.is_set()
    assert 8 <= elapsed < 18
    assert result.returncode == 0
    assert "Metadata download failed" in result.stderr
    assert f"using models/{transfers.META_NAME} from an earlier run" in result.stderr
    assert release_server.requests[release_server.stall_path] == 1
    assert (models / "open-default.onnx").read_bytes() == transfers.MODEL
    assert (models / "open-default_metadata.json").read_bytes() == previous
    assert "OK (sha256 verified)" in result.stdout
    assert_clean(models)


@pytest.mark.timeout(45)
def test_continuous_metadata_transfer_hits_overall_deadline(tmp_path, release_server):
    release_server.stream_path = "/" + transfers.META_NAME
    result, elapsed = run_bounded(tmp_path, release_server, watchdog=38)
    assert release_server.stalled.is_set()
    assert 28 <= elapsed < 38  # Above 1KiB/s; the 30s overall cap must apply.
    assert result.returncode == 1  # No class names: the model is not activated.
    assert "Operation timed out" in result.stderr
    assert "Operation too slow" not in result.stderr
    assert "Metadata download failed" in result.stderr
    assert release_server.requests[release_server.stream_path] == 1
    models = tmp_path / "models"
    assert not list(models.glob("*.onnx"))
    assert not (models / transfers.META_NAME).exists()
    assert not (models / "open-default_metadata.json").exists()
    assert_clean(models)


def test_tls_handshake_stall_is_bounded_without_an_http_response(tmp_path):
    stop = threading.Event()
    client_hellos = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            client_hellos.append(self.request.recv(4096))
            stop.wait(timeout=25)

    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            endpoint = SimpleNamespace(
                base=f"https://127.0.0.1:{server.server_address[1]}"
            )
            result, elapsed = run_bounded(tmp_path, endpoint)
            assert len(client_hellos) == 1
            assert client_hellos[0].startswith(b"\x16\x03")  # Genuine TLS ClientHello.
            assert 8 <= elapsed < 18
            assert result.returncode == 1
            assert "GitHub API request failed" in result.stdout
            assert not list((tmp_path / "models").glob("*.onnx"))
            assert_clean(tmp_path / "models")
        finally:
            stop.set()
            server.shutdown()
            thread.join(timeout=3)
            assert not thread.is_alive()


def test_healthy_download_forwards_finite_limits_to_all_real_curl_calls(
    tmp_path, release_server
):
    result, _ = run_bounded(tmp_path, release_server)
    assert result.returncode == 0
    assert "OK (sha256 verified)" in result.stdout
    calls = [
        json.loads(line)
        for line in (tmp_path / "curl-calls.jsonl").read_text().splitlines()
    ]
    assert len(calls) == 4
    assert set(release_server.requests.values()) == {1}
    for call in calls:
        # The 15-minute model cap is checked at the real curl boundary, not by
        # spending 15 minutes on a test. Its low-speed abort is exercised above.
        for flag, value in {
            "--connect-timeout": "10",
            "--speed-time": "10",
            "--speed-limit": "1024",
            "--retry": "0",
        }.items():
            assert call.count(flag) == 1
            assert call[call.index(flag) + 1] == value
        cap = "900" if call[-1].endswith("/" + transfers.MODEL_NAME) else "30"
        assert call.count("--max-time") == 1
        assert call[call.index("--max-time") + 1] == cap
    models = tmp_path / "models"
    assert (models / "open-default.onnx").read_bytes() == transfers.MODEL
    assert (models / "open-default_metadata.json").read_bytes() == transfers.METADATA
    assert_clean(models)
