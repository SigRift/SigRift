"""Finite daemon/queue behavior; classifier, MQTT and HTTP are external seams.

No hardware/model accuracy or durable sample-delivery claim is made here.
"""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace
import threading

import numpy as np
import pytest

import sigrift.edge.node as node


class MQTTBoundary:
    def __init__(self):
        self.calls = []
        self.after_publish = None
        self.connect_error = None
        self.disconnect_error = None

    def connect(self, host, port):
        self.calls.append(("connect", host, port))
        if self.connect_error:
            raise self.connect_error

    def loop_start(self):
        self.calls.append(("loop_start",))

    def loop_stop(self):
        self.calls.append(("loop_stop",))

    def disconnect(self):
        self.calls.append(("disconnect",))
        if self.disconnect_error:
            raise self.disconnect_error

    def publish(self, topic, payload, qos):
        self.calls.append(("publish", topic, json.loads(payload), qos))
        if self.after_publish:
            self.after_publish(topic)


@pytest.fixture
def edge(monkeypatch):
    mqtt = MQTTBoundary()
    classifier = SimpleNamespace(
        available=True,
        classify=lambda iq: (
            "bpsk",
            0.95,
            "psk",
            {"noise": 0.01, "qam": 0.02, "bpsk": 0.95, "fsk": 0.02},
        ),
    )
    monkeypatch.setattr(node, "HailoClassifier", lambda *_: classifier)
    monkeypatch.setattr(node, "create_mqtt_client", lambda _config: mqtt)
    config = node.NodeConfig(
        "unit-node",
        location="synthetic fixture",
        dwell_time_ms=0,
        samples_per_capture=32,
        scan_frequencies_mhz=[433.92, 915.0],
    )
    result = node.EdgeNode(config)
    return result, mqtt, classifier


@pytest.fixture
def uploader():
    value = node.SampleUploader("http://127.0.0.1:1", node_id="unit-node")
    yield value
    value.stop()
    assert value.upload_thread is None or not value.upload_thread.is_alive()


def test_queue_capacity_is_bounded_and_keeps_accepted_order(uploader, caplog):
    iq = np.array([1 + 2j, 3 + 4j], dtype=np.complex64)
    accepted = [
        uploader.queue_sample(iq, 433_920_000, 0.2, "unknown") for _ in range(100)
    ]
    assert all(accepted) and len(set(accepted)) == 100
    with caplog.at_level(logging.WARNING):
        assert uploader.queue_sample(iq, 915_000_000, 0.1, "unknown") is None
    rows = [uploader.upload_queue.get_nowait() for _ in range(100)]
    assert [row["sample_id"] for row in rows] == accepted
    assert all(row["freq_hz"] == 433_920_000 for row in rows)
    assert "queue full" in caplog.text.lower()


def test_worker_recovers_after_upload_exception_and_stop_joins_owned_thread(
    uploader, monkeypatch, caplog
):
    seen = []
    delivered = threading.Event()

    def upload(sample):
        seen.append(sample["predicted_class"])
        if len(seen) == 1:
            raise OSError("synthetic upload boundary failure")
        delivered.set()

    monkeypatch.setattr(uploader, "_upload_sample", upload)
    iq = np.ones(4, dtype=np.complex64)
    uploader.queue_sample(iq, 433_920_000, 0.1, "first")
    uploader.queue_sample(iq, 915_000_000, 0.2, "second")
    with caplog.at_level(logging.ERROR):
        uploader.start()
        assert delivered.wait(2)
        uploader.stop()
    assert seen == ["first", "second"] and not uploader.running
    assert not uploader.upload_thread.is_alive()
    assert "synthetic upload boundary failure" in caplog.text


@pytest.mark.parametrize("status", [200, 503, "exception"])
@pytest.mark.parametrize("key", ["", "synthetic-api-key"])
def test_upload_boundary_receives_exact_iq_metadata_and_auth(
    uploader, monkeypatch, caplog, status, key
):
    import sys

    seen = []

    def post(url, **kwargs):
        seen.append((url, kwargs))
        if status == "exception":
            raise OSError("synthetic transport failure")
        return SimpleNamespace(status_code=status)

    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(post=post))
    uploader.api_key = key
    iq = np.array([-1 + 1j, 0.25 - 0.5j], dtype=np.complex64)
    ident = uploader.queue_sample(iq, 433_920_000, 0.25, "unknown")
    sample = uploader.upload_queue.get_nowait()
    with caplog.at_level(logging.DEBUG):
        uploader._upload_sample(sample)
    url, request = seen[0]
    assert url == "http://127.0.0.1:1/api/samples/upload" and request["timeout"] == 30
    assert request["files"]["iq_data"] == (
        ident + ".bin",
        iq.tobytes(),
        "application/octet-stream",
    )
    assert request["data"] == {
        "sample_id": ident,
        "node_id": "unit-node",
        "freq_hz": 433_920_000,
        "confidence": 0.25,
        "predicted_class": "unknown",
        "timestamp": sample["timestamp"],
    }
    assert request["headers"] == ({"X-API-Key": key} if key else {})
    assert ("Uploaded sample" in caplog.text) is (status == 200)
    assert ("Upload failed" in caplog.text) is (status != 200)


def test_daemon_normal_stop_publishes_detection_and_idle_status_then_cleans_up(
    edge, uploader, monkeypatch
):
    value, mqtt, _classifier = edge
    value.uploader = uploader
    monkeypatch.setattr(value.sdr, "check_connection", lambda: True)
    iq = np.exp(2j * np.pi * np.arange(32) / 8).astype(np.complex64)
    monkeypatch.setattr(value.sdr, "capture", lambda *_: iq)
    monkeypatch.setattr(node, "HAS_PSUTIL", False)

    def published(topic):
        if topic.startswith("rf/detections/"):
            value.running = False

    mqtt.after_publish = published
    uploader.start()
    value.run()
    deliveries = [call for call in mqtt.calls if call[0] == "publish"]
    detection = deliveries[0]
    status = deliveries[1]
    assert detection[1] == "rf/detections/unit-node" and detection[3] == 1
    assert (
        detection[2]["signal_class"] == "bpsk"
        and detection[2]["freq_hz"] == 433_920_000
    )
    assert detection[2]["metadata"]["top_3"] == [
        ["bpsk", 0.95],
        ["qam", 0.02],
        ["fsk", 0.02],
    ]
    assert (
        status[1] == "rf/status/unit-node"
        and status[2]["status"] == "idle"
        and status[3] == 0
    )
    assert value.samples_processed == 32 and value.detections_count == 1
    assert not value.running and not uploader.upload_thread.is_alive()
    assert mqtt.calls[-2:] == [("loop_stop",), ("disconnect",)]


@pytest.mark.parametrize("error", [KeyboardInterrupt, RuntimeError])
def test_daemon_capture_failure_or_interrupt_cleans_mqtt_and_real_upload_thread(
    edge, uploader, monkeypatch, error
):
    value, mqtt, _ = edge
    value.uploader = uploader
    monkeypatch.setattr(value.sdr, "check_connection", lambda: True)

    def fail(*_):
        raise error("synthetic capture boundary")

    monkeypatch.setattr(value.sdr, "capture", fail)
    uploader.start()
    if error is KeyboardInterrupt:
        value.run()
    else:
        with pytest.raises(RuntimeError, match="capture boundary"):
            value.run()
    assert not value.running and not uploader.upload_thread.is_alive()
    assert mqtt.calls[-2:] == [("loop_stop",), ("disconnect",)]


def test_disconnected_mqtt_is_reported_without_starting_network_loop(edge, caplog):
    value, mqtt, _ = edge
    mqtt.connect_error = ConnectionRefusedError("local broker unavailable")
    with caplog.at_level(logging.ERROR):
        assert value.connect_mqtt() is False
    assert mqtt.calls == [("connect", "localhost", 1883)]
    assert "local broker unavailable" in caplog.text


def test_uploader_stops_even_when_mqtt_disconnect_fails(edge, uploader, monkeypatch):
    value, mqtt, _ = edge
    value.uploader = uploader
    monkeypatch.setattr(value.sdr, "check_connection", lambda: True)

    def stop(*_):
        value.running = False
        return None

    monkeypatch.setattr(value.sdr, "capture", stop)
    monkeypatch.setattr(node, "HAS_PSUTIL", False)
    mqtt.disconnect_error = ConnectionResetError("broker closed during shutdown")
    uploader.start()
    with pytest.raises(ConnectionResetError, match="during shutdown"):
        value.run()
    assert not uploader.running
    assert not uploader.upload_thread.is_alive()


def test_mqtt_disconnect_attempted_even_if_loop_stop_raises(edge, monkeypatch):
    value, mqtt, _ = edge

    def fail():
        raise OSError("MQTT loop-stop boundary")

    monkeypatch.setattr(mqtt, "loop_stop", fail)
    with pytest.raises(OSError, match="loop-stop boundary"):
        value.disconnect_mqtt()
    assert mqtt.calls == [("disconnect",)]


@pytest.mark.parametrize(
    "confidence,name,upload,reported_name,priority",
    [
        (0.95, "bpsk", False, "bpsk", 3),
        (0.6, "bpsk", False, "bpsk", 2),
        (0.55, "bpsk", False, "bpsk", 2),
        (0.4, "bpsk", True, "bpsk", 2),
        (0.2, "bpsk", True, "unknown", 3),
    ],
)
def test_scan_thresholds_upload_and_report_actual_sample_counts(
    edge, uploader, monkeypatch, confidence, name, upload, reported_name, priority
):
    value, _mqtt, classifier = edge
    value.uploader = uploader
    iq = np.exp(2j * np.pi * np.arange(32) / 8).astype(np.complex64)
    monkeypatch.setattr(value.sdr, "capture", lambda *_: iq)
    classifier.classify = lambda _iq: (name, confidence, "psk", {name: confidence})
    detection = value.scan_frequency(915_000_000)
    assert detection.signal_class == reported_name and detection.priority == priority
    assert detection.family == ("unknown" if reported_name == "unknown" else "psk")
    assert detection.node_id == "unit-node" and detection.confidence == confidence
    assert value.samples_processed == 32 and value.detections_count == 1
    assert uploader.upload_queue.qsize() == int(upload)
    if upload:
        queued = uploader.upload_queue.get_nowait()
        assert (
            queued["sample_id"] == detection.sample_ref
            and queued["freq_hz"] == 915_000_000
        )
        np.testing.assert_array_equal(queued["iq_data"], iq)
    else:
        assert detection.sample_ref is None


@pytest.mark.parametrize("kind", ["missing", "quiet"])
def test_missing_or_quiet_capture_does_not_classify_or_publish_detection(
    edge, monkeypatch, kind
):
    value, mqtt, classifier = edge

    def forbidden(_iq):
        raise AssertionError("No classification for missing/quiet capture")

    classifier.classify = forbidden
    # Impulse has equal FFT-bin power, so the actual estimator returns 0dB.
    iq = np.zeros(32, dtype=np.complex64)
    iq[0] = 1
    monkeypatch.setattr(
        value.sdr, "capture", lambda *_: None if kind == "missing" else iq
    )
    assert value.scan_frequency(433_920_000) is None
    assert value.samples_processed == (0 if kind == "missing" else 32)
    assert value.detections_count == 0 and not mqtt.calls


def test_low_confidence_without_uploader_still_reports_unknown(edge, monkeypatch):
    value, _mqtt, classifier = edge
    monkeypatch.setattr(
        value.sdr,
        "capture",
        lambda *_: np.exp(2j * np.pi * np.arange(32) / 8).astype(np.complex64),
    )
    classifier.classify = lambda _iq: ("bpsk", 0.2, "psk", {"bpsk": 0.2})
    detection = value.scan_frequency(433_920_000)
    assert detection.signal_class == "unknown" and detection.sample_ref is None


@pytest.mark.parametrize("temperature", [None, 48.5, "unavailable"])
def test_status_contains_metrics_without_failing_on_optional_temperature(
    edge, monkeypatch, temperature
):
    import time

    value, mqtt, classifier = edge
    value.running = True
    value.start_time = time.time() - 1
    value.sdr.available = True
    classifier.available = False

    def temperatures():
        if temperature == "unavailable":
            raise OSError("Temperature sensor unavailable")
        return (
            {}
            if temperature is None
            else {"cpu_thermal": [SimpleNamespace(current=temperature)]}
        )

    monkeypatch.setattr(node, "HAS_PSUTIL", True)
    monkeypatch.setattr(
        node,
        "psutil",
        SimpleNamespace(
            cpu_percent=lambda: 12.5,
            virtual_memory=lambda: SimpleNamespace(percent=34.5),
            sensors_temperatures=temperatures,
        ),
    )
    value.publish_status()
    payload = mqtt.calls[0][2]
    assert payload["cpu_percent"] == 12.5 and payload["memory_percent"] == 34.5
    assert payload["temperature_c"] == (48.5 if temperature == 48.5 else 0)
    assert payload["status"] == "scanning" and payload["uptime_seconds"] >= 1
    assert payload["hailo_status"] == "unavailable" and payload["rtl_status"] == "ok"


def test_mqtt_absent_paths_are_inert(edge):
    value, mqtt, _ = edge
    value.mqtt_client = None
    assert value.connect_mqtt() is False
    value.disconnect_mqtt()
    value.publish_status()
    value.publish_detection(None)
    assert not mqtt.calls


def test_cli_reads_real_yaml_before_starting_daemon(tmp_path, monkeypatch):
    import sys

    path = tmp_path / "node.yaml"
    path.write_text(
        "node_id: saved-node\nlocation: fixture\nrtl_tcp_host: 127.0.0.1\nrtl_tcp_port: 2345\nscan_frequencies_mhz: [433.92]\nsamples_per_capture: 64\n"
    )
    seen = []

    class Boundary:
        def __init__(self, config):
            seen.append(config)

        def run(self):
            seen.append("run")

    monkeypatch.setattr(node, "EdgeNode", Boundary)
    monkeypatch.setattr(
        sys, "argv", ["node.py", "--config", str(path), "--node-id", "ignored"]
    )
    assert node.main() == 0 and seen[1] == "run"
    assert seen[0].node_id == "saved-node" and seen[0].rtl_tcp_port == 2345
    assert seen[0].samples_per_capture == 64 and seen[0].scan_frequencies_mhz == [
        433.92
    ]


def test_invalid_yaml_does_not_initialize_any_node(tmp_path, monkeypatch):
    import sys
    import yaml

    path = tmp_path / "invalid.yaml"
    path.write_text("node_id: [unterminated")

    def forbidden(_config):
        raise AssertionError("Invalid configuration must not start hardware")

    monkeypatch.setattr(node, "EdgeNode", forbidden)
    monkeypatch.setattr(sys, "argv", ["node.py", "--config", str(path)])
    with pytest.raises(yaml.YAMLError):
        node.main()


def exception_chain(error):
    result = []
    while error is not None:
        result.append(str(error))
        error = error.__context__
    return result


def test_double_mqtt_failure_attempts_both_finalizers_and_retains_both_errors(
    edge, monkeypatch
):
    value, mqtt, _ = edge

    def fail_loop():
        mqtt.calls.append(("loop_stop",))
        raise OSError("loop-stop-original")

    monkeypatch.setattr(mqtt, "loop_stop", fail_loop)
    mqtt.disconnect_error = ConnectionResetError("disconnect-secondary")
    with pytest.raises(ConnectionResetError) as caught:
        value.disconnect_mqtt()
    assert mqtt.calls == [("loop_stop",), ("disconnect",)]
    assert exception_chain(caught.value) == [
        "disconnect-secondary",
        "loop-stop-original",
    ]


def test_scan_and_all_cleanup_failures_preserve_chain_and_join_real_upload_thread(
    edge, monkeypatch
):
    value, mqtt, _ = edge
    upload = node.SampleUploader("http://127.0.0.1:1")
    value.uploader = upload
    original_stop = upload.stop
    calls = []
    monkeypatch.setattr(value.sdr, "check_connection", lambda: True)

    def capture(*_):
        raise RuntimeError("scan-original")

    def loop_stop():
        calls.append("mqtt-loop")
        raise OSError("loop-secondary")

    def disconnect():
        calls.append("mqtt-disconnect")
        raise ConnectionResetError("disconnect-third")

    def stop_upload():
        calls.append("uploader-stop")
        original_stop()
        raise ValueError("upload-stop-last")

    monkeypatch.setattr(value.sdr, "capture", capture)
    monkeypatch.setattr(mqtt, "loop_stop", loop_stop)
    monkeypatch.setattr(mqtt, "disconnect", disconnect)
    monkeypatch.setattr(upload, "stop", stop_upload)
    upload.start()
    try:
        with pytest.raises(ValueError) as caught:
            value.run()
        assert calls == ["mqtt-loop", "mqtt-disconnect", "uploader-stop"]
        assert exception_chain(caught.value) == [
            "upload-stop-last",
            "disconnect-third",
            "loop-secondary",
            "scan-original",
        ]
        assert (
            not value.running
            and not upload.running
            and not upload.upload_thread.is_alive()
        )
    finally:
        original_stop()
