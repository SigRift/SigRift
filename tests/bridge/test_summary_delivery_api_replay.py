"""Socket-level lost response around the real authenticated Bridge ingest route."""

import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import threading

from sigrift.edge.detection_reporter import DetectionReporter


def test_committed_summary_with_lost_response_retries_stable_ids_and_alerts_once(
    client, bridge_app, persistence, registered_node, master_key, monkeypatch, tmp_path
):
    for name in (
        "MLRF_CA_CERT",
        "MLRF_CA_BUNDLE",
        "MLRF_INSECURE_TLS",
        "MLRF_CLIENT_CERT",
        "MLRF_CLIENT_KEY",
        "BRIDGE_CA_BUNDLE",
    ):
        monkeypatch.delenv(name, raising=False)
    persistence.set_alert_rules(
        [
            {
                "rule_id": "summary-retry-rule",
                "name": "summary retry",
                "enabled": True,
                "cooldown_seconds": 0,
                "conditions": [{"field": "power_dbm", "operator": "gt", "value": -100}],
                "trigger_count": 0,
                "last_triggered_at": None,
            }
        ]
    )
    payloads, outcomes, errors = [], [], []

    class Relay(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                assert self.path == "/api/detections/ingest-summary"
                assert self.headers["X-API-Key"] == master_key
                assert self.headers["X-Node-ID"] == registered_node
                body = self.rfile.read(int(self.headers["Content-Length"]))
                payloads.append(json.loads(gzip.decompress(body)))
                # The only substituted boundary is transport: actual app auth,
                # node binding, SQLite writes and post-ingest hooks all run.
                response = client.post(
                    self.path,
                    content=body,
                    headers={
                        "X-API-Key": self.headers["X-API-Key"],
                        "X-Node-ID": self.headers["X-Node-ID"],
                        "Content-Encoding": "gzip",
                        "Content-Type": "application/json",
                    },
                )
                assert response.status_code == 201, response.text
                outcomes.append(response.json())
                if len(payloads) == 1:
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                self.send_response(201)
                self.send_header("Content-Length", str(len(response.content)))
                self.end_headers()
                self.wfile.write(response.content)
            except BaseException as exc:
                errors.append(type(exc).__name__)
                raise

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Relay)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    reporter = DetectionReporter(
        f"http://127.0.0.1:{server.server_port}",
        master_key,
        registered_node,
        summarize=True,
        data_dir=tmp_path / "edge-data",
        summary_anomaly_threshold=0,
    )
    try:
        assert reporter.report({"class": "bpsk", "confidence": 0.95}, 915e6, 15, -55)
        reporter.stop()
        assert len(payloads) == 1
        detection_id = payloads[0]["high_anomaly_detections"][0]["id"]
        stored = bridge_app.state.detection_store.get_detection_by_id(detection_id)
        assert stored is not None
        assert outcomes[0]["inserted_raw"] == 1
        assert outcomes[0]["alerts_created"] == 1
        first_alerts = persistence.get_alerts()
        assert (
            len([a for a in first_alerts if a.get("detection_id") == detection_id]) == 1
        )
        reporter.stop()
        assert len(payloads) == 2
        assert payloads[0] == payloads[1]
        assert outcomes[1]["inserted_raw"] == outcomes[1]["alerts_created"] == 0
        assert reporter.get_stats()["summary_pending_hours"] == 0
        assert (
            bridge_app.state.detection_store.get_detection_by_id(detection_id) == stored
        )
        assert persistence.get_alerts() == first_alerts
        assert persistence.get_alert_rules()[0]["trigger_count"] == 1
        reporter.stop()
        assert len(payloads) == 2  # Acknowledged snapshots are not retransmitted.
    finally:
        reporter.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert not errors
