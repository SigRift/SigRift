"""Round-5 regression tests for the bridge (group BR5).

* V3 — protocol_decode jobs get captures that can be decoded: captures too
  short to hold a frame (an edge's 4096-sample classifier window) are not
  queued, and a manual capture tasked with a signal class is decoded.
* V4 / V11 / K8b — a detection's decode is queued once, whichever of the
  IQ upload route and post-ingest sees it first, at the uploaded rate.
* V5 / K8b — ingest-hook claims live in detections.db: a redelivery to
  another worker process fires nothing.
* V10 / K8b — webhook and syslog delivery run in the background, in
  their own threads: a dead endpoint never delays the ingest hook, even
  with a small default executor.
* V9 / K10 — the start-up warning about UC_PROXY_SECRET says what happens.
* W1 / K7b — only SENSOR / NODE keys are bound on first use, a node
  another key is bound to cannot be claimed, an unbound viewer key is
  refused with BRIDGE_ALLOW_UNBOUND_NODE_KEYS too, and an admin binds an
  existing key with PUT /api/admin/keys/{key_id}/permissions.
* W2 — summary-mode ingest runs post-ingest for its high-anomaly
  detections, once per detection, also when the detection's IQ arrived
  first (the real detection replaces the IQ route's stub).
"""

from __future__ import annotations

import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import gzip
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import numpy as np
import pytest
from fastapi.testclient import TestClient

import sigrift.bridge.app as app_module
import sigrift.bridge.dependencies as deps
import sigrift.bridge.notifications as notifications_mod
from sigrift.bridge.decode_pipeline import (
    ProtocolDecodePipeline,
    decode_skip_reason,
    protocol_decode_job_handler,
    queue_protocol_decode_once,
)
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.models import DetectionRecord
from sigrift.bridge.persistence import NodeAlreadyBound, PersistenceManager
from sigrift.bridge.state import AppState
from sigrift.bridge.storage.ingest_claims import IngestClaimStore
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
)

_SECRET = "round5-proxy-secret-0123456789abcdef"


@pytest.fixture(autouse=True)
def _fresh_state():
    deps._verified_key_cache.clear()
    yield
    deps._verified_key_cache.clear()


@pytest.fixture
def proxy_secret(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
    return _SECRET


@pytest.fixture
def anon(bridge_app) -> TestClient:
    return TestClient(bridge_app)


def _gw() -> dict[str, str]:
    return {"X-Rust-Proxy": _SECRET}


def _add_key(
    persistence: PersistenceManager,
    key_id: str,
    role: str,
    node_id: str | None = None,
    expires_at: str | None = None,
) -> str:
    raw = generate_api_key(32)
    hash_hex, salt = hash_credential(raw)
    meta = {"role": role, "description": "", "created_at": "", "expires_at": expires_at}
    if node_id is not None:
        meta["node_id"] = node_id
    assert persistence.add_key(
        key_id, hash_hex, salt, lookup_hash=compute_lookup_hash(raw), meta=meta
    )
    return raw


def _register(client: TestClient, *node_ids: str) -> None:
    for node_id in node_ids:
        resp = client.post("/api/nodes/register", json={"node_id": node_id})
        assert resp.status_code == 200, resp.text


def _heartbeat(client: TestClient, key: str, node_id: str):
    return client.post(
        "/api/nodes/heartbeat", json={"node_id": node_id}, headers={"X-API-Key": key}
    )


def _bind(anon: TestClient, key_id: str, node_id: str):
    return anon.post(
        "/api/internal/bind-node-key",
        json={"key_id": key_id, "node_id": node_id},
        headers=_gw(),
    )


def _decode_jobs(app) -> list[dict]:
    return [
        j for j in app.state.job_queue.list_jobs() if j["job_type"] == "protocol_decode"
    ]


def _accept_decode_jobs(app) -> None:
    """Register a protocol_decode handler, so the queue takes the jobs."""
    app.state.job_queue.register_handler("protocol_decode", lambda job_id, p: {})


_RULE = {
    "rule_id": "r-loud",
    "name": "loud",
    "enabled": True,
    "cooldown_seconds": 0,
    "conditions": [{"field": "power_dbm", "operator": "gt", "value": -30}],
    "trigger_count": 0,
    "last_triggered_at": None,
}
_BAND = {
    "watch_id": "w-ism",
    "name": "ISM 433",
    "enabled": True,
    "freq_min_hz": 433e6,
    "freq_max_hz": 435e6,
    "trigger": "new_activity",
    "severity": "critical",
}


def _gateway_detection(det_id: str, node_id: str = "edge-a", **fields) -> dict:
    """A detection the way the gateway serializes it after its insert."""
    det = {
        "detection_id": det_id,
        "node_id": node_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "signal_class": "fm",
        "confidence": 0.9,
        "family": "analog",
        "freq_hz": 433.92e6,
        "snr_db": 12.0,
        "power_dbm": -10.0,
        "anomaly_score": 0.1,
        "baseline_status": "stable",
    }
    det.update(fields)
    return det


# -- Synthetic DMR (ETSI TS 102 361-1), as in test_decode_pipeline_demod.py ----

_SYMBOL = {(0, 1): 3, (0, 0): 1, (1, 0): -1, (1, 1): -3}
_DMR_BS_VOICE_SYNC = 0x755FD7DF75F7


def _bits(value: int, width: int) -> list[int]:
    return [(value >> (width - 1 - i)) & 1 for i in range(width)]


def _dmr_capture(n_bursts: int, sample_rate: float, seed: int = 6) -> np.ndarray:
    """4FSK DMR voice bursts (with CACH gaps) at *sample_rate*, light noise."""
    rng = np.random.default_rng(seed)

    def rand(n: int) -> list[int]:
        return rng.integers(0, 2, n).tolist()

    stream = rand(200)
    for _ in range(n_bursts):
        stream += rand(108) + _bits(_DMR_BS_VOICE_SYNC, 48) + rand(108) + rand(24)
    stream += rand(200)
    symbols = np.array(
        [_SYMBOL[(stream[i], stream[i + 1])] for i in range(0, len(stream) - 1, 2)]
    )
    sps = sample_rate / 4800.0
    n = int(len(symbols) * sps)
    freq = symbols[(np.arange(n) / sps).astype(np.int64)] * 648.0
    smooth = max(1, int(sps / 2))
    freq = np.convolve(freq, np.ones(smooth) / smooth, mode="same")
    iq = np.exp(1j * 2 * np.pi * np.cumsum(freq) / sample_rate)
    iq = iq + 0.2 * (rng.standard_normal(n) + 1j * rng.standard_normal(n))
    return iq.astype(np.complex64)


def _gz(iq: np.ndarray) -> bytes:
    return gzip.compress(np.asarray(iq, dtype=np.complex64).tobytes())


def _real_decoder(app):
    """The production protocol_decode handler, with the real demodulators."""
    pipe = ProtocolDecodePipeline(app.state.decoded_message_store, None)
    handler = protocol_decode_job_handler(pipe, app.state.iq_store)
    app.state.job_queue.register_handler("protocol_decode", handler)
    return handler


def _batch(node_id: str, det_id: str, signal_class: str = "dmr") -> dict:
    now = datetime.now(timezone.utc)
    return {
        "node_id": node_id,
        "period_start": (now - timedelta(minutes=1)).isoformat(),
        "period_end": now.isoformat(),
        "detections": [
            {
                "id": det_id,
                "node_id": node_id,
                "signal_class": signal_class,
                "confidence": 0.9,
                "freq_hz": 446e6,
            }
        ],
    }


# ---------------------------------------------------------------------------
# V3 — decode jobs only for captures that can hold a frame
# ---------------------------------------------------------------------------

#: What an edge uploads for a classifier detection: rf_scan's INPUT_SAMPLES
#: window at the RTL-SDR scan rate (2 ms).
_EDGE_WINDOW = 4096
_EDGE_RATE = 2_048_000.0


class TestDecodeNeedsAFrame:
    @pytest.mark.parametrize("cls", ["dmr", "p25", "lora-css", "meshtastic"])
    def test_an_edge_classifier_window_cannot_be_decoded(self, cls: str) -> None:
        reason = decode_skip_reason(cls, _EDGE_WINDOW, _EDGE_RATE)
        assert reason is not None and "too short" in reason
        # One second at the same rate is plenty for any of them.
        assert decode_skip_reason(cls, int(_EDGE_RATE), _EDGE_RATE) is None

    def test_edge_sized_upload_is_not_queued(
        self, client, bridge_app, registered_node
    ) -> None:
        _real_decoder(bridge_app)
        resp = client.post(
            "/api/detections/batch", json=_batch(registered_node, "det-edge")
        )
        assert resp.status_code == 201, resp.text
        iq = _dmr_capture(1, _EDGE_RATE)[:_EDGE_WINDOW]
        resp = client.put(
            "/api/detections/det-edge/iq",
            content=_gz(iq),
            headers={
                "Content-Encoding": "gzip",
                "X-Sample-Rate": str(_EDGE_RATE),
                # An uploader's claim does not count: the real length does.
                "X-IQ-Samples": "100000000",
            },
        )
        assert resp.status_code == 201, resp.text
        # Before: a job was queued and "decoded" 0 messages.
        assert _decode_jobs(bridge_app) == []
        assert "capture too short for dmr" in resp.json()["protocol_decode_skipped"]
        assert "protocol_decode_job_id" not in resp.json()

    def test_job_handler_reports_a_short_capture_as_skipped(self, bridge_app) -> None:
        handler = _real_decoder(bridge_app)
        bridge_app.state.iq_store.store(
            "det-short", _gz(_dmr_capture(1, _EDGE_RATE)[:_EDGE_WINDOW])
        )
        result = handler(
            "j",
            {
                "detection_id": "det-short",
                "signal_class": "dmr",
                "sample_rate": _EDGE_RATE,
            },
        )
        # Before: {"status": "decoded", "messages": 0}.
        assert result["status"] == "skipped"
        assert "too short" in result["reason"]

    def _task_capture(self, client, node_id: str, **body) -> str:
        resp = client.post(
            f"/api/nodes/{node_id}/capture",
            json={"freq_hz": 446e6, "sample_rate": 1e6, "duration_ms": 200, **body},
        )
        assert resp.status_code == 200, resp.text
        return resp.json()["command_id"]

    def _upload_manual(self, client, persistence, node_id, command_id, iq, rate):
        """Upload a capture the way rf_scan.execute_iq_capture does."""
        raw = _add_key(persistence, f"key-{node_id}", "sensor", node_id=node_id)
        det_id = f"iq_{command_id}_{node_id}_{int(time.time())}"
        resp = client.put(
            f"/api/detections/{det_id}/iq",
            content=_gz(iq),
            headers={
                "X-API-Key": raw,
                "Content-Type": "application/octet-stream",
                "Content-Encoding": "gzip",
                "X-Sample-Rate": str(float(rate)),
                "X-IQ-Samples": str(len(iq)),
                "X-Node-Id": node_id,
                "X-Freq-Hz": str(446e6),
            },
        )
        assert resp.status_code == 201, resp.text
        return det_id, resp.json()

    def test_tasked_manual_capture_is_decoded_by_the_real_demodulators(
        self, client, bridge_app, persistence, registered_node
    ) -> None:
        handler = _real_decoder(bridge_app)
        command_id = self._task_capture(client, registered_node, signal_class="DMR")
        [cmd] = bridge_app.state.app_state.pending_commands[registered_node]
        assert cmd["params"]["signal_class"] == "DMR"  # normalize_class keeps case

        iq = _dmr_capture(4, 1_000_000.0)
        det_id, result = self._upload_manual(
            client, persistence, registered_node, command_id, iq, 1_000_000.0
        )
        # Before: the stub was class "iq_capture" and never decoded.
        stub = bridge_app.state.detection_store.get_detection_by_id(det_id)
        assert stub["signal_class"].lower() == "dmr"
        [job] = _decode_jobs(bridge_app)
        assert result["protocol_decode_job_id"] == job["job_id"]
        assert job["params"]["sample_rate"] == 1_000_000.0

        outcome = handler(job["job_id"], job["params"])
        assert outcome["status"] == "decoded", outcome
        assert outcome["messages"] == 4 and outcome["stored"] == 4
        rows = bridge_app.state.decoded_message_store.get_messages(detection_id=det_id)
        assert len(rows) == 4
        assert {r["protocol"] for r in rows} == {"dmr"}
        assert {r["node_id"] for r in rows} == {registered_node}

    def test_capture_of_a_detection_takes_its_class(
        self, client, bridge_app, persistence, registered_node
    ) -> None:
        _accept_decode_jobs(bridge_app)
        resp = client.post(
            "/api/detections/batch",
            json=_batch(registered_node, "det-p25", signal_class="p25"),
        )
        assert resp.status_code == 201, resp.text
        command_id = self._task_capture(client, registered_node, detection_id="det-p25")
        det_id, result = self._upload_manual(
            client,
            persistence,
            registered_node,
            command_id,
            np.ones(200_000, dtype=np.complex64),
            1_000_000.0,
        )
        stub = bridge_app.state.detection_store.get_detection_by_id(det_id)
        assert stub["signal_class"] == "p25"
        assert "protocol_decode_job_id" in result

    def test_capture_request_detection_must_be_the_nodes(
        self, client, registered_node
    ) -> None:
        _register(client, "other-node")
        resp = client.post(
            "/api/detections/batch", json=_batch("other-node", "det-elsewhere")
        )
        assert resp.status_code == 201, resp.text
        resp = client.post(
            f"/api/nodes/{registered_node}/capture",
            json={"freq_hz": 446e6, "detection_id": "det-elsewhere"},
        )
        assert resp.status_code == 422
        resp = client.post(
            f"/api/nodes/{registered_node}/capture",
            json={"freq_hz": 446e6, "detection_id": "no-such-detection"},
        )
        assert resp.status_code == 404

    def test_a_capture_request_only_tags_its_own_nodes_upload(
        self, client, bridge_app, persistence, registered_node
    ) -> None:
        _register(client, "node-b")
        command_id = self._task_capture(client, registered_node, signal_class="dmr")
        det_id, _ = self._upload_manual(
            client,
            persistence,
            "node-b",
            command_id,
            np.ones(200_000, dtype=np.complex64),
            1_000_000.0,
        )
        stub = bridge_app.state.detection_store.get_detection_by_id(det_id)
        assert stub["signal_class"] == "iq_capture"

    def test_uploader_may_name_the_class(
        self, client, bridge_app, registered_node
    ) -> None:
        _accept_decode_jobs(bridge_app)
        h = {"Content-Encoding": "gzip", "X-Node-Id": registered_node}
        resp = client.put(
            "/api/detections/manual-1/iq",
            content=_gz(np.ones(200_000, dtype=np.complex64)),
            headers={**h, "X-Signal-Class": "dmr", "X-Sample-Rate": "1000000"},
        )
        assert resp.status_code == 201, resp.text
        stub = bridge_app.state.detection_store.get_detection_by_id("manual-1")
        assert stub["signal_class"] == "dmr"
        assert "protocol_decode_job_id" in resp.json()

        resp = client.put(
            "/api/detections/manual-2/iq",
            content=_gz(np.ones(1000, dtype=np.complex64)),
            headers={**h, "X-Signal-Class": "d m r"},
        )
        assert resp.status_code == 400
        assert not bridge_app.state.iq_store.exists("manual-2")
        assert bridge_app.state.detection_store.get_detection_by_id("manual-2") is None


# ---------------------------------------------------------------------------
# V4 / V11 — one decode per detection, at the uploaded rate
# ---------------------------------------------------------------------------


def _gateway_inserts(store: DetectionStore, det_id: str, signal_class="dmr") -> dict:
    """What the gateway's native ingest stores before it answers the edge."""
    store.insert_batch(
        [
            DetectionRecord(
                id=det_id,
                node_id="edge-a",
                signal_class=signal_class,
                confidence=0.9,
                freq_hz=446e6,
                power_dbm=-60.0,
            )
        ]
    )
    return _gateway_detection(
        det_id, signal_class=signal_class, freq_hz=446e6, power_dbm=-60.0
    )


def _upload(client, det_id: str, rate: float = 1_000_000.0, n: int = 200_000):
    resp = client.put(
        f"/api/detections/{det_id}/iq",
        content=_gz(np.ones(n, dtype=np.complex64)),
        headers={"Content-Encoding": "gzip", "X-Sample-Rate": str(rate)},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


class TestDecodeQueuedOnce:
    def _hook(self, anon, det: dict) -> dict:
        resp = anon.post(
            "/api/internal/ingest-hook",
            json={"node_id": "edge-a", "detections": [det]},
            headers=_gw(),
        )
        assert resp.status_code == 200, resp.text
        return resp.json()

    def test_iq_upload_before_the_hook_queues_one_decode_at_its_rate(
        self, client, anon, bridge_app, detection_store, proxy_secret
    ) -> None:
        _accept_decode_jobs(bridge_app)
        det = _gateway_inserts(detection_store, "gw-dmr-1")
        assert "protocol_decode_job_id" in _upload(client, "gw-dmr-1")
        # The hook arrives later (it is queued in the gateway).
        assert self._hook(anon, det)["decode_jobs"] == 0
        # Before: a second job, at the 2.048 MHz default.
        [job] = _decode_jobs(bridge_app)
        assert job["params"]["sample_rate"] == 1_000_000.0

    def test_hook_before_the_iq_upload_queues_one_decode(
        self, client, anon, bridge_app, detection_store, proxy_secret
    ) -> None:
        _accept_decode_jobs(bridge_app)
        det = _gateway_inserts(detection_store, "gw-dmr-2")
        assert self._hook(anon, det)["decode_jobs"] == 0  # no IQ yet
        assert "protocol_decode_job_id" in _upload(client, "gw-dmr-2")
        assert len(_decode_jobs(bridge_app)) == 1

    def test_a_stored_but_unindexed_capture_is_left_to_the_upload_route(
        self, anon, bridge_app, detection_store, proxy_secret
    ) -> None:
        # The IQ route stores the file, then indexes it (with its rate),
        # then queues: a hook in between must not queue at a guessed rate.
        _accept_decode_jobs(bridge_app)
        det = _gateway_inserts(detection_store, "gw-dmr-3")
        bridge_app.state.iq_store.store(
            "gw-dmr-3", _gz(np.ones(200_000, dtype=np.complex64))
        )
        assert self._hook(anon, det)["decode_jobs"] == 0
        assert _decode_jobs(bridge_app) == []

    def test_post_ingest_queues_an_indexed_capture_once_with_its_rate(
        self, client, anon, bridge_app, detection_store, proxy_secret
    ) -> None:
        _accept_decode_jobs(bridge_app)
        det = _gateway_inserts(detection_store, "gw-dmr-4")
        bridge_app.state.iq_store.store(
            "gw-dmr-4", _gz(np.ones(200_000, dtype=np.complex64))
        )
        bridge_app.state.iq_metadata_store.index_capture(
            "gw-dmr-4", {"sample_rate": 1_000_000.0, "n_samples": 200_000}
        )
        assert self._hook(anon, det)["decode_jobs"] == 1
        [job] = _decode_jobs(bridge_app)
        assert job["params"]["sample_rate"] == 1_000_000.0
        # The IQ route's own try is a no-op now.
        assert _upload(client, "gw-dmr-4")["protocol_decode_skipped"] == (
            "already queued"
        )
        assert len(_decode_jobs(bridge_app)) == 1

    def test_the_decode_claim_is_shared_between_processes(self, tmp_path) -> None:
        db = tmp_path / "shared.db"
        a = IngestClaimStore(DetectionStore(db_path=db)._ctx)
        b = IngestClaimStore(DetectionStore(db_path=db)._ctx)
        assert a.claim_decode("det-x", now=time.time(), source="iq_upload")
        assert not b.claim_decode("det-x", now=time.time(), source="post_ingest")
        b.release_decode("det-x")
        assert a.claim_decode("det-x", now=time.time())

    def test_a_job_that_cannot_be_queued_releases_its_claim(
        self, detection_store
    ) -> None:
        claims = IngestClaimStore(detection_store._ctx)

        class FullQueue:
            def submit_nowait(self, job_type, params):
                raise asyncio.QueueFull

        kwargs = dict(
            detection_id="det-y",
            signal_class="dmr",
            sample_rate=1e6,
            n_samples=200_000,
        )
        result = asyncio.run(queue_protocol_decode_once(FullQueue(), claims, **kwargs))
        assert result.job_id is None and result.skipped == "not queued"
        assert not claims.decode_claimed("det-y")


# ---------------------------------------------------------------------------
# V5 — hook claims shared by every worker process
# ---------------------------------------------------------------------------


@pytest.fixture
def two_workers(tmp_path: Path, proxy_secret):
    """Two bridge apps on the same data: two worker processes, in effect.

    Each has its own DetectionStore (its own SQLite connections) on one
    detections.db, and its own PersistenceManager on one data dir.
    """
    from sigrift.bridge.app import create_test_app

    db = tmp_path / "test_detections.db"
    apps = []
    for _ in range(2):
        persistence = PersistenceManager(
            data_dir=tmp_path / "data", auto_save_interval=0
        )
        persistence.load_all()
        persistence.set_alert_rules([dict(_RULE)])
        apps.append(
            create_test_app(
                tmp_path=tmp_path,
                detection_store=DetectionStore(db_path=db),
                persistence=persistence,
                app_state=AppState(),
            )
        )
    return apps


class TestHookClaimsAcrossWorkers:
    _BODY = {"node_id": "edge-a", "detections": [_gateway_detection("gw-x-1")]}

    def test_a_redelivery_to_another_worker_fires_nothing(self, two_workers) -> None:
        first, second = (TestClient(app) for app in two_workers)
        one = first.post("/api/internal/ingest-hook", json=self._BODY, headers=_gw())
        assert one.status_code == 200, one.text
        assert one.json()["accepted"] == 1
        assert one.json()["alerts_created"] == 1
        # The gateway retries (its first attempt timed out); the retry is
        # answered by the other worker.  Before: accepted 1, alerts again.
        two = second.post("/api/internal/ingest-hook", json=self._BODY, headers=_gw())
        assert two.status_code == 200, two.text
        assert two.json()["accepted"] == 0
        assert two.json()["duplicates"] == 1
        assert two.json()["alerts_created"] == 0
        assert two_workers[1].state.persistence.get_alerts() == []

    def test_concurrent_deliveries_to_two_workers_fire_once(self, two_workers) -> None:
        async def _race() -> list[dict]:
            clients = [
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app), base_url="http://bridge"
                )
                for app in two_workers
            ]
            try:
                responses = await asyncio.gather(
                    *(
                        c.post(
                            "/api/internal/ingest-hook", json=self._BODY, headers=_gw()
                        )
                        for c in clients * 2
                    )
                )
            finally:
                for c in clients:
                    await c.aclose()
            return [r.json() for r in responses]

        results = asyncio.run(_race())
        assert sorted(r["accepted"] for r in results) == [0, 0, 0, 1]
        assert sum(r["alerts_created"] for r in results) == 1


# ---------------------------------------------------------------------------
# V10 — the hook never waits for a webhook or syslog target
# ---------------------------------------------------------------------------


@pytest.fixture
def blackhole():
    """An owned HTTP receiver that records requests but sends no response."""
    received, release = [], threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append(body)
            assert release.wait(8), "Owned receiver did not receive cleanup"

        def log_message(self, *_args):
            pass

    class Port(int):
        pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = Port(server.server_port)
    port.requests = received
    try:
        yield port
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(3)
        assert not thread.is_alive()


def _hook_two_matching(app, *, receiver=None) -> tuple[float, dict]:
    """POST a hook with two rule-matching detections; (seconds, body)."""
    body = {
        "node_id": "edge-a",
        "detections": [_gateway_detection("slow-1"), _gateway_detection("slow-2")],
    }

    async def _run() -> tuple[float, dict]:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://bridge"
        ) as ac:
            started = time.monotonic()
            resp = await ac.post("/api/internal/ingest-hook", json=body, headers=_gw())
            elapsed = time.monotonic() - started
            assert resp.status_code == 200, resp.text
            result = resp.json()
            notifier = app.state.notifier
            forwarder = app.state.syslog_forwarder
            result["_pending_webhooks"] = getattr(notifier, "pending_deliveries", 0)
            result["_pending_syslog"] = getattr(forwarder, "pending_forwards", 0)
            if receiver is not None:
                # Ingest accepts intents before endpoint discovery. Prove both
                # eventually reach the actual stalled receiver after the quick
                # response, without counting a local-only configuration cache.
                result["_accepted_webhooks"] = notifier.initial_dispatch["accepted"]
                deadline = time.monotonic() + 1.5
                while len(receiver.requests) < 2 and time.monotonic() < deadline:
                    await asyncio.sleep(0.01)
                assert len(receiver.requests) == 2
                result["_active_webhooks"] = notifier.pending_deliveries
            # Cancel what is still in flight (the endpoints never answer).
            if hasattr(notifier, "stop_deliveries"):
                await notifier.stop_deliveries(grace_seconds=0)
            if hasattr(forwarder, "stop_forwards"):
                await forwarder.stop_forwards(grace_seconds=0)
        return elapsed, result

    return asyncio.run(_run())


class TestHookNeverWaitsForThirdParties:
    def test_a_dead_webhook_does_not_delay_the_hook(
        self, bridge_app, persistence, proxy_secret, blackhole, monkeypatch
    ) -> None:
        monkeypatch.setenv("BRIDGE_WEBHOOK_ALLOW_HOSTS", "127.0.0.1")
        # One 2 s attempt per delivery: before, the hook waited for each
        # alert's webhook in turn (about 4 s here; ~40 s with the real
        # 10 s timeout, 3 attempts and 5 s sleeps).
        monkeypatch.setattr(notifications_mod, "_TIMEOUT_SECONDS", 2)
        monkeypatch.setattr(notifications_mod, "_MAX_RETRIES", 0)
        persistence.set_alert_rules([dict(_RULE)])
        notifier = bridge_app.state.notifier
        notifier.add_webhook(f"http://127.0.0.1:{blackhole}/hook")
        persistence.set_webhooks(notifier.webhooks)
        notifier.load(persistence.current_webhooks())

        elapsed, result = _hook_two_matching(bridge_app, receiver=blackhole)
        assert result["alerts_created"] == 2
        assert elapsed < 1.0, elapsed
        assert result["_accepted_webhooks"] == 2
        assert result["_active_webhooks"] == 2
        assert len(blackhole.requests) == 2

    def test_a_stuck_syslog_target_does_not_delay_the_hook(
        self, bridge_app, persistence, proxy_secret, monkeypatch
    ) -> None:
        forwarder = bridge_app.state.syslog_forwarder
        forwarder.add_target(host="127.0.0.1", port=9, protocol="tcp")
        monkeypatch.setattr(
            forwarder, "forward", lambda alert: time.sleep(1.5) or 0, raising=False
        )
        persistence.set_alert_rules([dict(_RULE)])

        elapsed, result = _hook_two_matching(bridge_app)
        assert result["alerts_created"] == 2
        assert elapsed < 1.0, elapsed
        assert result["_pending_syslog"] == 2

    def test_dead_endpoints_never_take_the_default_executor(
        self, bridge_app, persistence, proxy_secret, blackhole, monkeypatch
    ) -> None:
        """A small host: the default pool has 5 threads (1 vCPU: cpus + 4).

        Before, every webhook post and syslog send ran in that pool: 5
        webhook threads plus 2 syslog threads stuck on dead endpoints took
        all of it, and the next hook's claims and inserts waited behind
        them for the endpoints' timeouts (the gateway gives a hook 10 s).
        """
        from concurrent.futures import ThreadPoolExecutor

        monkeypatch.setenv("BRIDGE_WEBHOOK_ALLOW_HOSTS", "127.0.0.1")
        monkeypatch.setattr(notifications_mod, "_TIMEOUT_SECONDS", 3)
        monkeypatch.setattr(notifications_mod, "_MAX_RETRIES", 0)
        persistence.set_alert_rules([dict(_RULE)])
        notifier = bridge_app.state.notifier
        notifier.add_webhook(f"http://127.0.0.1:{blackhole}/hook")
        persistence.set_webhooks(notifier.webhooks)
        notifier.load(persistence.current_webhooks())
        forwarder = bridge_app.state.syslog_forwarder
        forwarder.add_target(host="127.0.0.1", port=9, protocol="tcp")
        monkeypatch.setattr(
            forwarder, "forward", lambda alert: time.sleep(3) or 0, raising=False
        )

        async def _run() -> list[tuple[float, int]]:
            loop = asyncio.get_running_loop()
            loop.set_default_executor(ThreadPoolExecutor(max_workers=5))
            answers = []
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=bridge_app),
                base_url="http://bridge",
            ) as ac:
                for n in range(4):
                    body = {
                        "node_id": "edge-a",
                        "detections": [
                            _gateway_detection(f"pool-{n}-a"),
                            _gateway_detection(f"pool-{n}-b"),
                        ],
                    }
                    started = time.monotonic()
                    resp = await ac.post(
                        "/api/internal/ingest-hook", json=body, headers=_gw()
                    )
                    elapsed = time.monotonic() - started
                    assert resp.status_code == 200, resp.text
                    answers.append((elapsed, resp.json()["alerts_created"]))
                    # Let the deliveries this hook started reach their
                    # endpoints (hooks are spread out in practice).
                    await asyncio.sleep(0.2)
            # All five owned HTTP workers really reached the stalled receiver;
            # the default-executor latency assertion is not a no-endpoint pass.
            assert len(blackhole.requests) >= 5
            assert notifier.initial_dispatch["accepted"] == 8
            await notifier.stop_deliveries(grace_seconds=0)
            await forwarder.stop_forwards(grace_seconds=0)
            return answers

        answers = asyncio.run(_run())
        assert [created for _elapsed, created in answers] == [2, 2, 2, 2]
        assert all(elapsed < 1.0 for elapsed, _created in answers), answers

    def test_a_full_backlog_goes_to_the_retry_queue(self) -> None:
        mgr = notifications_mod.NotificationManager()
        mgr._max_pending = 1
        mgr.add_webhook("https://hooks.example.com/x")
        release = asyncio.Event()

        async def slow_deliver(webhook, alert):
            await release.wait()
            return True

        mgr._deliver = slow_deliver

        async def _run() -> None:
            assert mgr.submit({"severity": "critical", "alert_id": "a1"}) == 1
            assert mgr.submit({"severity": "critical", "alert_id": "a2"}) == 1
            assert mgr.pending_deliveries == 1
            assert mgr.backlog_deferred == 1
            [entry] = mgr.failed_queue
            assert entry["payload"]["alert"]["id"] == "a2"
            release.set()
            await mgr.stop_deliveries(grace_seconds=1.0)
            assert mgr.pending_deliveries == 0

        asyncio.run(_run())

    def test_nothing_to_deliver_starts_nothing(self) -> None:
        mgr = notifications_mod.NotificationManager()
        mgr.add_webhook("https://hooks.example.com/x", severity_filter=["critical"])

        async def _run() -> None:
            assert mgr.submit({"severity": "info"}) == 0
            assert mgr.pending_deliveries == 0

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# V9 / K10 — the start-up warning says what an unusable secret does
# ---------------------------------------------------------------------------


class TestGatewayTrustWarning:
    def _logged(self, caplog, monkeypatch, require: bool, secret: bytes):
        monkeypatch.setattr(app_module, "_REQUIRE_PROXY", require)
        monkeypatch.setattr(app_module, "_PROXY_SECRET", secret)
        with caplog.at_level(logging.WARNING, logger=app_module.logger.name):
            app_module._log_gateway_trust_status()
        return [r for r in caplog.records if r.name == app_module.logger.name]

    @pytest.mark.parametrize("secret", [b"", b"uppercrust-internal"])
    def test_require_proxy_without_a_secret_says_everything_is_refused(
        self, caplog, monkeypatch, secret
    ) -> None:
        [record] = self._logged(caplog, monkeypatch, True, secret)
        assert record.levelno == logging.CRITICAL
        assert "refused with 403" in record.getMessage()
        assert "disabled" not in record.getMessage()

    @pytest.mark.parametrize("secret", [b"", b"uppercrust-internal"])
    def test_without_require_proxy_it_names_what_breaks(
        self, caplog, monkeypatch, secret
    ) -> None:
        # Before: "proxy trust check is disabled", only for an unset value.
        [record] = self._logged(caplog, monkeypatch, False, secret)
        message = record.getMessage()
        assert record.levelno == logging.WARNING
        assert "/api/internal/*" in message and "403" in message
        assert "not restricted" in message
        assert "disabled" not in message

    def test_a_usable_secret_logs_nothing(self, caplog, monkeypatch) -> None:
        assert self._logged(caplog, monkeypatch, True, _SECRET.encode()) == []


# ---------------------------------------------------------------------------
# W1 / K7b — who is bound on first use
# ---------------------------------------------------------------------------


class TestK7bFirstUseBinding:
    def test_unbound_viewer_key_is_not_a_node_credential(
        self, client, anon, bridge_app, persistence
    ) -> None:
        _register(client, "n1")
        raw = _add_key(persistence, "grafana", "viewer")
        resp = _heartbeat(anon, raw, "n1")
        # Before: 200, and "grafana" was bound to n1 for good.
        assert resp.status_code == 403
        assert resp.json() == {"detail": "Node endpoints require a node API key"}
        resp = anon.post(
            "/api/detections/batch",
            json=_batch("n1", "forged"),
            headers={"X-API-Key": raw},
        )
        assert resp.status_code == 403
        resp = anon.put(
            "/api/detections/forged-iq/iq",
            content=_gz(np.ones(1000, dtype=np.complex64)),
            headers={"X-API-Key": raw, "Content-Encoding": "gzip", "X-Node-Id": "n1"},
        )
        assert resp.status_code == 403
        assert "node_id" not in persistence.get_key_meta()["grafana"]
        assert bridge_app.state.detection_store.get_detection_by_id("forged") is None

    def test_bind_node_key_refuses_a_viewer_key(
        self, anon, persistence, proxy_secret
    ) -> None:
        _add_key(persistence, "grafana", "viewer")
        resp = _bind(anon, "grafana", "edge-a")
        assert resp.status_code == 409  # the gateway answers the batch 403
        assert resp.json() == {
            "node_id": "edge-a",
            "detail": "Node endpoints require a node API key",
        }
        assert "node_id" not in persistence.get_key_meta()["grafana"]

    def test_unbound_analyst_key_is_operator_tooling(
        self, client, anon, persistence, proxy_secret
    ) -> None:
        _register(client, "n1", "n2")
        raw = _add_key(persistence, "ops-script", "analyst")
        assert _heartbeat(anon, raw, "n1").status_code == 200
        assert _heartbeat(anon, raw, "n2").status_code == 200
        assert "node_id" not in persistence.get_key_meta()["ops-script"]
        resp = _bind(anon, "ops-script", "edge-a")
        assert resp.status_code == 200
        assert resp.json() == {"node_id": "edge-a", "bound": False}
        assert "node_id" not in persistence.get_key_meta()["ops-script"]

    def test_a_bound_analyst_key_keeps_its_node(self, client, anon, persistence):
        _register(client, "n1", "n2")
        raw = _add_key(persistence, "ops-n1", "analyst", node_id="n1")
        assert _heartbeat(anon, raw, "n1").status_code == 200
        assert _heartbeat(anon, raw, "n2").status_code == 403

    def test_first_key_to_claim_a_node_wins(
        self, client, anon, persistence, proxy_secret
    ) -> None:
        _register(client, "n1", "n2")
        owner = _add_key(persistence, "sensor-a", "sensor")
        assert _heartbeat(anon, owner, "n1").status_code == 200
        assert persistence.get_key_meta()["sensor-a"]["node_id"] == "n1"

        other = _add_key(persistence, "sensor-b", "node")
        resp = _heartbeat(anon, other, "n1")
        # Before: 200 — a second key took n1's commands.
        assert resp.status_code == 403
        assert "node already has a bound key" in resp.json()["detail"]
        assert "node_id" not in persistence.get_key_meta()["sensor-b"]
        resp = _bind(anon, "sensor-b", "n1")
        assert resp.status_code == 409
        assert resp.json() == {
            "node_id": "n1",
            "detail": "node already has a bound key",
        }
        # It can still claim a node nobody holds.
        assert _heartbeat(anon, other, "n2").status_code == 200
        assert persistence.get_key_meta()["sensor-b"]["node_id"] == "n2"

    def test_an_admin_bound_extra_key_may_act_for_the_node(
        self, client, anon, persistence
    ) -> None:
        _register(client, "n1")
        assert _heartbeat(anon, _add_key(persistence, "a", "sensor"), "n1").status_code
        extra = _add_key(persistence, "n1-wifi", "sensor", node_id="n1")
        assert _heartbeat(anon, extra, "n1").status_code == 200

    def test_an_expired_key_does_not_hold_its_node(
        self, client, anon, persistence
    ) -> None:
        _register(client, "n1")
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        _add_key(persistence, "old-key", "sensor", node_id="n1", expires_at=past)
        raw = _add_key(persistence, "new-key", "sensor")
        assert _heartbeat(anon, raw, "n1").status_code == 200
        assert persistence.get_key_meta()["new-key"]["node_id"] == "n1"

    def test_a_key_named_after_the_node_holds_it(
        self, anon, persistence, proxy_secret
    ) -> None:
        _add_key(persistence, "edge-9", "node")
        _add_key(persistence, "sensor-x", "sensor")
        resp = _bind(anon, "sensor-x", "edge-9")
        assert resp.status_code == 409
        assert resp.json()["detail"] == "node already has a bound key"

    def test_keys_racing_for_one_node_cannot_both_win(self, persistence) -> None:
        for i in range(8):
            _add_key(persistence, f"race-{i}", "sensor")
        won: list[str] = []
        lost: list[str] = []
        barrier = threading.Barrier(8)

        def claim(key_id: str) -> None:
            barrier.wait()
            try:
                persistence.bind_key_to_node(
                    key_id, "n1", holds_node=deps._holds_node("n1")
                )
                won.append(key_id)
            except NodeAlreadyBound:
                lost.append(key_id)

        threads = [
            threading.Thread(target=claim, args=(f"race-{i}",)) for i in range(8)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(won) == 1 and len(lost) == 7
        meta = persistence.get_key_meta()
        assert [k for k in meta if meta[k].get("node_id") == "n1"] == won

    @pytest.mark.parametrize("role", ["sensor", "node"])
    def test_escape_hatch_keeps_node_keys_unbound(
        self, client, anon, persistence, monkeypatch, role
    ) -> None:
        monkeypatch.setenv(deps.ALLOW_UNBOUND_NODE_KEYS_ENV, "1")
        _register(client, "n1", "n2")
        raw = _add_key(persistence, "shared", role)
        assert _heartbeat(anon, raw, "n1").status_code == 200
        assert _heartbeat(anon, raw, "n2").status_code == 200
        assert "node_id" not in persistence.get_key_meta()["shared"]

    def test_escape_hatch_still_refuses_a_viewer_key(
        self, client, anon, persistence, monkeypatch
    ) -> None:
        """The setting concerns node keys; the gateway refuses viewers too.

        Before, a dashboard key could heartbeat as any node (and take its
        queued commands) once the setting was on.
        """
        monkeypatch.setenv(deps.ALLOW_UNBOUND_NODE_KEYS_ENV, "1")
        _register(client, "n1")
        raw = _add_key(persistence, "grafana", "viewer")
        resp = _heartbeat(anon, raw, "n1")
        assert resp.status_code == 403
        assert resp.json()["detail"] == deps.NODE_KEY_REQUIRED
        assert "node_id" not in persistence.get_key_meta()["grafana"]


class TestAdminBindsKeysExplicitly:
    """K7b: extra keys for a node are bound by an admin, also existing keys."""

    def _put(self, client: TestClient, key_id: str, body: dict):
        return client.put(f"/api/admin/keys/{key_id}/permissions", json=body)

    def test_an_admin_binds_an_existing_key_to_a_claimed_node(
        self, client, anon, persistence, proxy_secret
    ) -> None:
        _register(client, "n1")
        first = _add_key(persistence, "edge-1", "sensor")
        second = _add_key(persistence, "edge-2", "sensor")
        assert _heartbeat(anon, first, "n1").status_code == 200
        refused = _heartbeat(anon, second, "n1")
        assert refused.status_code == 403
        assert "PUT /api/admin/keys/{key_id}/permissions" in refused.json()["detail"]
        assert _bind(anon, "edge-2", "n1").status_code == 409

        # Before: no route could set node_id on an existing key (422).
        resp = self._put(client, "edge-2", {"node_id": "n1"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["node_id"] == "n1"
        meta = persistence.get_key_meta()["edge-2"]
        assert meta["node_id"] == "n1"
        assert meta["role"] == "sensor"
        assert _heartbeat(anon, second, "n1").status_code == 200
        assert _heartbeat(anon, first, "n1").status_code == 200
        assert _bind(anon, "edge-2", "n1").json() == {"node_id": "n1", "bound": True}

    def test_an_admin_rebinds_and_unbinds_a_key(
        self, client, anon, persistence
    ) -> None:
        _register(client, "n1", "n2")
        raw = _add_key(persistence, "edge-1", "sensor", node_id="n1")
        assert self._put(client, "edge-1", {"node_id": "n2"}).status_code == 200
        assert _heartbeat(anon, raw, "n1").status_code == 403
        assert _heartbeat(anon, raw, "n2").status_code == 200
        # A role change alone leaves the binding as it is.
        assert self._put(client, "edge-1", {"role": "node"}).status_code == 200
        assert persistence.get_key_meta()["edge-1"]["node_id"] == "n2"
        resp = self._put(client, "edge-1", {"node_id": None})
        assert resp.status_code == 200
        assert resp.json()["node_id"] is None
        assert "node_id" not in persistence.get_key_meta()["edge-1"]

    def test_an_invalid_node_id_changes_nothing(self, client, persistence) -> None:
        _add_key(persistence, "edge-1", "sensor")
        resp = self._put(client, "edge-1", {"role": "node", "node_id": "no spaces"})
        assert resp.status_code == 400
        meta = persistence.get_key_meta()["edge-1"]
        assert meta["role"] == "sensor"
        assert "node_id" not in meta

    def test_an_analyst_cannot_bind_keys(self, anon, persistence) -> None:
        analyst = _add_key(persistence, "ops", "analyst")
        _add_key(persistence, "edge-1", "sensor")
        resp = anon.put(
            "/api/admin/keys/edge-1/permissions",
            json={"node_id": "n1"},
            headers={"X-API-Key": analyst},
        )
        assert resp.status_code == 403
        assert "node_id" not in persistence.get_key_meta()["edge-1"]


# ---------------------------------------------------------------------------
# W2 — summary-mode ingest runs post-ingest
# ---------------------------------------------------------------------------


class TestSummaryIngestRunsPostIngest:
    def _snapshot(self, node_id: str) -> dict:
        return {
            "node_id": node_id,
            "summaries": [],
            "high_anomaly_detections": [
                {
                    "id": "hi-1",
                    "node_id": node_id,
                    "signal_class": "fm",
                    "confidence": 0.9,
                    "freq_hz": 433.92e6,
                    "power_dbm": -10.0,
                    "anomaly_score": 0.9,
                    "decoded_messages": [
                        {
                            "protocol": "adsb",
                            "payload_hex": "8d4840d6202cc371c32ce0576098",
                            "metadata": {"icao": "abc123"},
                        }
                    ],
                }
            ],
        }

    def test_high_anomaly_detections_alert_once(
        self, client, bridge_app, persistence, registered_node
    ) -> None:
        persistence.add_watch_band(dict(_BAND))
        persistence.set_alert_rules([dict(_RULE)])
        resp = client.post(
            "/api/detections/ingest-summary", json=self._snapshot(registered_node)
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["inserted_raw"] == 1
        # Anomaly alert (score 0.9), the rule and the watch band.  Before:
        # stored, and nothing else.
        assert resp.json()["alerts_created"] == 3
        alerts = persistence.get_alerts()
        assert {a["name"] for a in alerts if a.get("detection_id") == "hi-1"} >= {
            "anomaly_detected",
            "rule_loud",
        }
        assert [a for a in alerts if a.get("watch_id") == "w-ism"]
        assert persistence.get_alert_rules()[0]["trigger_count"] == 1
        store = bridge_app.state.decoded_message_store
        assert len(store.get_messages(detection_id="hi-1")) == 1

        # The edge re-sends the hour's snapshot every flush: nothing again.
        again = client.post(
            "/api/detections/ingest-summary", json=self._snapshot(registered_node)
        )
        assert again.status_code == 201, again.text
        assert again.json()["inserted_raw"] == 0
        assert again.json()["alerts_created"] == 0
        assert len(persistence.get_alerts()) == len(alerts)
        assert persistence.get_alert_rules()[0]["trigger_count"] == 1
        assert len(store.get_messages(detection_id="hi-1")) == 1


class TestRealDetectionReplacesTheIqStub:
    """W2: IQ uploaded before the detection reaches the bridge.

    In summary mode a high-anomaly detection is staged for IQ too; one
    reported while the summary POST is in flight has its IQ uploaded
    before any snapshot holds it.  The IQ route stores a stub detection
    for the id; before, the real detection's insert then conflicted, so it
    was dropped as a duplicate and post_ingest never ran for it.
    """

    def _snapshot(self, node_id: str, det_id: str = "hi-1") -> dict:
        snap = TestSummaryIngestRunsPostIngest()._snapshot(node_id)
        snap["high_anomaly_detections"][0]["id"] = det_id
        return snap

    def test_summary_detection_replaces_its_stub_and_alerts(
        self, client, bridge_app, persistence, registered_node
    ) -> None:
        persistence.set_alert_rules([dict(_RULE)])
        store = bridge_app.state.detection_store
        _upload_iq_for(client, persistence, registered_node, "hi-1")
        stub = store.get_detection_by_id("hi-1")
        assert stub["signal_class"] == "iq_capture"

        resp = client.post(
            "/api/detections/ingest-summary", json=self._snapshot(registered_node)
        )
        assert resp.status_code == 201, resp.text
        # Before: inserted_raw 0 and alerts_created 0 (the stub won).
        assert resp.json()["inserted_raw"] == 1
        assert resp.json()["alerts_created"] == 2  # anomaly + rule
        row = store.get_detection_by_id("hi-1")
        assert row["signal_class"] == "fm"
        assert row["anomaly_score"] == pytest.approx(0.9)
        assert row["has_iq_capture"]
        assert persistence.get_alert_rules()[0]["trigger_count"] == 1

        again = client.post(
            "/api/detections/ingest-summary", json=self._snapshot(registered_node)
        )
        assert again.json()["inserted_raw"] == 0
        assert again.json()["alerts_created"] == 0

    def test_batch_detection_replaces_its_stub(
        self, client, bridge_app, persistence, registered_node
    ) -> None:
        persistence.set_alert_rules([dict(_RULE)])
        _upload_iq_for(client, persistence, registered_node, "b-1")
        body = _batch(registered_node, "b-1", signal_class="fm")
        body["detections"][0]["power_dbm"] = -10.0
        resp = client.post("/api/detections/batch", json=body)
        assert resp.status_code == 201, resp.text
        assert resp.json()["inserted"] == 1
        assert resp.json()["alerts_created"] == 1
        # Before: the stored row stayed the stub (iq_capture, -100 dBm).
        row = bridge_app.state.detection_store.get_detection_by_id("b-1")
        assert (row["signal_class"], row["power_dbm"]) == ("fm", -10.0)

    def test_a_decodable_detection_is_decoded_once_after_its_stub(
        self, client, bridge_app, persistence, registered_node
    ) -> None:
        _accept_decode_jobs(bridge_app)
        _upload_iq_for(client, persistence, registered_node, "d-1", rate=1e6, n=200_000)
        assert _decode_jobs(bridge_app) == []  # the stub's class: not decodable
        snap = self._snapshot(registered_node, "d-1")
        snap["high_anomaly_detections"][0].update(signal_class="dmr", freq_hz=446e6)
        resp = client.post("/api/detections/ingest-summary", json=snap)
        assert resp.status_code == 201, resp.text
        # Before: the dmr detection was dropped as a duplicate of the
        # stub, so nothing was decoded.
        [job] = _decode_jobs(bridge_app)
        assert job["params"]["detection_id"] == "d-1"
        assert job["params"]["signal_class"] == "dmr"
        assert job["params"]["sample_rate"] == 1_000_000.0
        again = client.post("/api/detections/ingest-summary", json=snap)
        assert again.status_code == 201, again.text
        assert len(_decode_jobs(bridge_app)) == 1

    def test_another_nodes_detection_does_not_take_over_a_stub(
        self, client, bridge_app, persistence
    ) -> None:
        _register(client, "n1", "n2")
        persistence.set_alert_rules([dict(_RULE)])
        _upload_iq_for(client, persistence, "n1", "x-1")
        resp = client.post(
            "/api/detections/ingest-summary", json=self._snapshot("n2", "x-1")
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["inserted_raw"] == 0
        row = bridge_app.state.detection_store.get_detection_by_id("x-1")
        assert (row["node_id"], row["signal_class"]) == ("n1", "iq_capture")

    def test_a_real_detection_is_never_overwritten(
        self, client, bridge_app, persistence, registered_node
    ) -> None:
        store = bridge_app.state.detection_store
        first = client.post(
            "/api/detections/batch",
            json=_batch(registered_node, "r-1", signal_class="fm"),
        )
        assert first.status_code == 201, first.text
        resp = client.post(
            "/api/detections/ingest-summary",
            json=self._snapshot(registered_node, "r-1"),
        )
        assert resp.json()["inserted_raw"] == 0
        assert store.get_detection_by_id("r-1")["anomaly_score"] == 0.0
        # A second stub for the id (another upload) changes nothing either.
        assert (
            store.insert_batch_new_ids(
                [
                    DetectionRecord(
                        id="r-1",
                        node_id=registered_node,
                        signal_class="iq_capture",
                        confidence=0.0,
                        freq_hz=0.0,
                    )
                ]
            )
            == set()
        )
        assert store.get_detection_by_id("r-1")["signal_class"] == "fm"


def _upload_iq_for(
    client,
    persistence,
    node_id: str,
    det_id: str,
    rate: float = 2.048e6,
    n: int = 4096,
) -> None:
    """Upload IQ for *det_id* as *node_id*'s edge does, before its detection."""
    raw = _add_key(persistence, f"key-{node_id}-{det_id}", "sensor", node_id=node_id)
    resp = client.put(
        f"/api/detections/{det_id}/iq",
        content=_gz(np.ones(n, dtype=np.complex64)),
        headers={
            "X-API-Key": raw,
            "Content-Encoding": "gzip",
            "X-Sample-Rate": str(rate),
            "X-IQ-Samples": str(n),
            "X-Node-Id": node_id,
        },
    )
    assert resp.status_code == 201, resp.text
