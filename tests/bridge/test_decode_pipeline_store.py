"""Regression tests: decoded protocol messages are kept (review C6).

The pipeline was built with ``decoded_store=None`` so ``decode_iq``
returned ``[]`` even after a successful decode, ``detection_id`` was never
passed, ingest called the coroutine ``job_queue.submit`` without awaiting
it (no decode job ever ran), and ``app.state.decoded_message_store`` was
never set, so edge-decoded messages in detection batches were dropped.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

from sigrift.bridge.decode_pipeline import ProtocolDecodePipeline
from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.decoded_messages import DecodedMessageStore
from sigrift.lib.protocol.base import DecodedMessage


@pytest.fixture
def ctx(tmp_path: Path) -> SharedContext:
    return SharedContext(db_path=tmp_path / "decoded.db")


def _decoded_messages() -> list[DecodedMessage]:
    return [
        DecodedMessage(
            protocol="dmr",
            source_id="1001",
            dest_id="2002",
            message_type="voice",
            payload=b"\x01\x02",
            text="hello",
            metadata={"slot": 1},
            confidence=0.8,
        )
    ]


def _pipeline(store, monkeypatch: pytest.MonkeyPatch) -> ProtocolDecodePipeline:
    # These tests cover what happens to decoded messages (records,
    # storage, the job handler); demodulation + decoding is stubbed as a
    # whole.  It used to stub the demodulator with a made-up
    # ``demodulate(iq, sample_rate)`` signature, which hid that the real
    # demodulators reject it (review Q6) — test_decode_pipeline_demod.py
    # runs the real ones.
    pipe = ProtocolDecodePipeline(store, crypto_key_store=None)
    monkeypatch.setattr(
        pipe, "_decode_messages", lambda iq, sc, protocol, rate: _decoded_messages()
    )
    return pipe


def _iq() -> np.ndarray:
    return np.ones(1024, dtype=np.complex64)


class TestPipeline:
    def test_messages_returned_without_a_store(self, monkeypatch) -> None:
        pipe = _pipeline(None, monkeypatch)
        out = pipe.decode_iq(_iq(), "dmr", 446e6, 2e6, "n1", detection_id="det-1")
        assert len(out) == 1
        assert out[0]["detection_id"] == "det-1"
        assert out[0]["protocol"] == "dmr"
        assert out[0]["id"] is None

    def test_messages_stored_with_detection_id(self, ctx, monkeypatch) -> None:
        store = DecodedMessageStore(ctx)
        pipe = _pipeline(store, monkeypatch)
        out = pipe.decode_iq(_iq(), "dmr", 446e6, 2e6, "n1", detection_id="det-2")
        assert out[0]["id"] is not None
        [row] = store.get_messages(detection_id="det-2")
        assert row["protocol"] == "dmr"
        assert row["source_id"] == "1001"
        assert row["payload_hex"] == "0102"
        assert row["text"] == "hello"
        assert row["node_id"] == "n1"

    def test_store_failure_still_returns_the_message(self, monkeypatch) -> None:
        class Broken:
            def store_message(self, record):
                raise RuntimeError("disk full")

        out = _pipeline(Broken(), monkeypatch).decode_iq(
            _iq(), "dmr", 446e6, 2e6, "n1", detection_id="det-3"
        )
        assert len(out) == 1 and out[0]["id"] is None


class TestDecodedMessageStore:
    def test_untrusted_record_is_bounded(self, ctx) -> None:
        store = DecodedMessageStore(ctx)
        msg_id = store.store_message(
            {
                "protocol": "adsb",
                "source_id": "x" * 10_000,
                "gps_lat": "not a number",
                "gps_lon": float("nan"),
                "encrypted": "yes",
                "metadata": {"nested": [1, 2]},
                "payload_length": True,
                "unknown_column": "ignored",
            }
        )
        [row] = store.get_messages()
        assert row["id"] == msg_id
        assert len(row["source_id"]) == 128
        assert row["gps_lat"] is None and row["gps_lon"] is None
        assert row["encrypted"] == 1
        assert row["metadata"] == '{"nested": [1, 2]}'
        assert row["payload_length"] is None
        assert row["timestamp"]

    def test_protocol_required(self, ctx) -> None:
        with pytest.raises(ValueError):
            DecodedMessageStore(ctx).store_message({"source_id": "a"})

    def test_row_cap(self, ctx, monkeypatch) -> None:
        import sigrift.bridge.storage.decoded_messages as dm

        monkeypatch.setattr(dm, "_PRUNE_EVERY", 5)
        store = DecodedMessageStore(ctx, max_rows=10)
        for i in range(40):
            store.store_message({"protocol": "dmr", "source_id": str(i)})
        assert store.count() <= 10 + 5
        newest = store.get_messages(limit=1)[0]
        assert newest["source_id"] == "39"

    def test_existing_narrow_table_is_used(self, ctx) -> None:
        conn = ctx.get_conn()
        conn.execute(
            "CREATE TABLE decoded_messages (id INTEGER PRIMARY KEY, "
            "protocol TEXT NOT NULL, timestamp TEXT NOT NULL, "
            "tenant_id TEXT NOT NULL DEFAULT 'default')"
        )
        conn.commit()
        store = DecodedMessageStore(ctx)
        store.store_message({"protocol": "p25", "source_id": "dropped"})
        assert store.get_messages()[0]["protocol"] == "p25"


def _batch(node_id: str, **det) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "node_id": node_id,
        "period_start": (now - timedelta(minutes=1)).isoformat(),
        "period_end": now.isoformat(),
        "detections": [
            {
                "id": "det-decode-1",
                "node_id": node_id,
                "signal_class": "dmr",
                "confidence": 0.9,
                "freq_hz": 446e6,
                **det,
            }
        ],
    }


class TestIngestWiring:
    def test_ingest_queues_protocol_decode_job(
        self, client: TestClient, bridge_app, registered_node: str
    ) -> None:
        # Queued at ingest only when the IQ is already stored (a job without
        # IQ is always skipped); ``has_iq_capture`` alone is not enough —
        # edges never set it and upload the IQ after the batch.
        queue = bridge_app.state.job_queue
        queue.register_handler("protocol_decode", lambda job_id, params: {})
        resp = client.post(
            "/api/detections/batch", json=_batch(registered_node, has_iq_capture=True)
        )
        assert resp.status_code == 201, resp.text
        assert [
            j for j in queue.list_jobs() if j["job_type"] == "protocol_decode"
        ] == []

        _store_indexed_iq(bridge_app, "det-decode-1")
        resp = client.post("/api/detections/batch", json=_batch(registered_node))
        assert resp.status_code == 201, resp.text
        jobs = [j for j in queue.list_jobs() if j["job_type"] == "protocol_decode"]
        assert len(jobs) == 1
        assert jobs[0]["params"]["detection_id"] == "det-decode-1"

    def test_edge_decoded_messages_are_stored(
        self, client: TestClient, bridge_app, registered_node: str
    ) -> None:
        resp = client.post(
            "/api/detections/batch",
            json=_batch(
                registered_node,
                decoded_messages=[
                    {"protocol": "dmr", "source_id": "77", "message_type": "data"}
                ],
            ),
        )
        assert resp.status_code == 201, resp.text
        store = bridge_app.state.decoded_message_store
        [row] = store.get_messages(detection_id="det-decode-1")
        assert row["source_id"] == "77"
        assert row["node_id"] == registered_node


# ---------------------------------------------------------------------------
# Repair pass: decode on IQ upload (C6), bounded batch storage (NEW)
# ---------------------------------------------------------------------------


def _gzip_iq(n: int = 65536) -> bytes:
    """A stand-in capture (the decode is stubbed) long enough to hold a frame.

    65 536 samples: 32 ms at 2.048 MHz, 65 ms at 1 MHz.  A shorter one,
    such as an edge's 4096-sample classifier window, is not queued for
    decoding at all (round 5, review V3).
    """
    import gzip

    return gzip.compress(np.ones(n, dtype=np.complex64).tobytes())


def _store_indexed_iq(app, detection_id: str, rate: float = 2_048_000.0) -> None:
    """Store a capture and index it, as ``PUT /api/detections/{id}/iq`` does.

    Post-ingest takes the capture's sample rate and length from the index
    (round 5, review V11: it used to queue at a guessed 2.048 MHz).
    """
    app.state.iq_store.store(detection_id, _gzip_iq())
    app.state.iq_metadata_store.index_capture(
        detection_id, {"sample_rate": rate, "n_samples": 65536}
    )


def _decode_jobs(queue) -> list[dict]:
    return [j for j in queue.list_jobs() if j["job_type"] == "protocol_decode"]


class TestDecodableClasses:
    @pytest.mark.parametrize(
        "cls", ["lora-css", "meshtastic", "lora-meshtastic", "dmr", "p25", "LoRa"]
    )
    def test_decodable(self, cls: str) -> None:
        from sigrift.bridge.decode_pipeline import is_decodable

        assert is_decodable(cls)

    @pytest.mark.parametrize("cls", ["iq_capture", "dect", "fm", "", None, 7])
    def test_not_decodable(self, cls) -> None:
        from sigrift.bridge.decode_pipeline import is_decodable

        assert not is_decodable(cls)

    def test_canonical_lora_class_reaches_the_lora_demodulator(self) -> None:
        # Detections are stored as "lora-css" (class_map); the pipeline
        # only knew "lora", so stored LoRa detections never demodulated.
        pipe = ProtocolDecodePipeline(None, crypto_key_store=None)
        assert type(pipe._select_demodulator("lora-css")).__name__ == (
            "LoRaCSSDemodulator"
        )
        assert pipe._map_signal_to_protocol("lora-css") == "lora_phy"
        assert pipe._map_signal_to_protocol("lora-meshtastic") == "meshtastic"


class TestDecodeOnIqUpload:
    """A decodable detection is decoded once its IQ is uploaded.

    Edges post the detection batch first and upload IQ afterwards, and they
    never set ``has_iq_capture``: before the repair, no decode job ever ran
    for real edge traffic.
    """

    @pytest.fixture
    def decode_handler(self, bridge_app, monkeypatch):
        from sigrift.bridge.decode_pipeline import protocol_decode_job_handler

        pipe = _pipeline(bridge_app.state.decoded_message_store, monkeypatch)
        handler = protocol_decode_job_handler(pipe, bridge_app.state.iq_store)
        bridge_app.state.job_queue.register_handler("protocol_decode", handler)
        return handler

    def test_upload_queues_a_decode_that_finds_the_iq(
        self, client: TestClient, bridge_app, registered_node: str, decode_handler
    ) -> None:
        queue = bridge_app.state.job_queue
        resp = client.post("/api/detections/batch", json=_batch(registered_node))
        assert resp.status_code == 201, resp.text
        assert _decode_jobs(queue) == []  # no IQ yet: nothing to decode

        resp = client.put(
            "/api/detections/det-decode-1/iq",
            content=_gzip_iq(),
            headers={"Content-Encoding": "gzip", "X-Sample-Rate": "1000000"},
        )
        assert resp.status_code == 201, resp.text
        [job] = _decode_jobs(queue)
        assert resp.json()["protocol_decode_job_id"] == job["job_id"]
        params = job["params"]
        assert params["detection_id"] == "det-decode-1"
        assert params["signal_class"] == "dmr"
        assert params["node_id"] == registered_node
        assert params["sample_rate"] == 1_000_000.0
        assert params["freq_hz"] == 446e6

        result = decode_handler(job["job_id"], params)
        assert result["status"] == "decoded", result
        assert result["messages"] == 1 and result["stored"] == 1
        [row] = bridge_app.state.decoded_message_store.get_messages(
            detection_id="det-decode-1"
        )
        assert row["node_id"] == registered_node
        assert row["protocol"] == "dmr"

    @pytest.mark.parametrize("rate", ["999.9", "500", "250000001", "1e12"])
    def test_absurd_sample_rate_is_refused(
        self,
        client: TestClient,
        bridge_app,
        registered_node: str,
        decode_handler,
        rate: str,
    ) -> None:
        # The rate sizes the decode job's resampling (BR2-V1).
        assert (
            client.post(
                "/api/detections/batch", json=_batch(registered_node)
            ).status_code
            == 201
        )
        resp = client.put(
            "/api/detections/det-decode-1/iq",
            content=_gzip_iq(),
            headers={"Content-Encoding": "gzip", "X-Sample-Rate": rate},
        )
        assert resp.status_code == 400, resp.text
        assert "x-sample-rate" in resp.json()["detail"]
        assert _decode_jobs(bridge_app.state.job_queue) == []
        assert not bridge_app.state.iq_store.exists("det-decode-1")

    @pytest.mark.parametrize(
        ("rate", "why"),
        [
            # Below the 9.6 kHz a 4FSK channel needs.
            ("1000", "too low for dmr"),
            # The decode analyses the first 2 Mi samples: 8.4 ms at
            # 250 MS/s, shorter than one 27.5 ms DMR burst.
            ("250e6", "capture too short for dmr"),
        ],
    )
    def test_sample_rate_range_is_inclusive(
        self,
        client: TestClient,
        bridge_app,
        registered_node: str,
        decode_handler,
        rate: str,
        why: str,
    ) -> None:
        assert (
            client.post(
                "/api/detections/batch", json=_batch(registered_node)
            ).status_code
            == 201
        )
        resp = client.put(
            "/api/detections/det-decode-1/iq",
            content=_gzip_iq(),
            headers={"Content-Encoding": "gzip", "X-Sample-Rate": rate},
        )
        # Both ends of the range are accepted and kept with the capture ...
        assert resp.status_code == 201, resp.text
        meta = bridge_app.state.iq_metadata_store.get_metadata("det-decode-1")
        assert meta["sample_rate"] == float(rate)
        # ... but no DMR frame can be decoded at either (round 5, review V3:
        # such jobs used to be queued and report "decoded", 0 messages).
        assert _decode_jobs(bridge_app.state.job_queue) == []
        assert why in resp.json()["protocol_decode_skipped"]

    def test_upload_for_undecodable_detection_queues_nothing(
        self, client: TestClient, bridge_app, registered_node: str, decode_handler
    ) -> None:
        batch = _batch(registered_node)
        batch["detections"][0]["signal_class"] = "fm"
        assert client.post("/api/detections/batch", json=batch).status_code == 201
        resp = client.put(
            "/api/detections/det-decode-1/iq",
            content=_gzip_iq(),
            headers={"Content-Encoding": "gzip"},
        )
        assert resp.status_code == 201, resp.text
        assert "protocol_decode_job_id" not in resp.json()
        assert _decode_jobs(bridge_app.state.job_queue) == []

    def test_batch_after_iq_queues_the_decode(
        self, client: TestClient, bridge_app, registered_node: str, decode_handler
    ) -> None:
        # IQ first (stored with a stub detection), detection batch second.
        _store_indexed_iq(bridge_app, "det-decode-1")
        resp = client.post("/api/detections/batch", json=_batch(registered_node))
        assert resp.status_code == 201, resp.text
        [job] = _decode_jobs(bridge_app.state.job_queue)
        assert job["params"]["detection_id"] == "det-decode-1"

    def test_queue_full_does_not_fail_the_upload(
        self, client: TestClient, bridge_app, registered_node: str, decode_handler
    ) -> None:
        import asyncio

        queue = bridge_app.state.job_queue

        def full(*args, **kwargs):
            raise asyncio.QueueFull

        assert (
            client.post(
                "/api/detections/batch", json=_batch(registered_node)
            ).status_code
            == 201
        )
        queue.submit_nowait = full
        resp = client.put(
            "/api/detections/det-decode-1/iq",
            content=_gzip_iq(),
            headers={"Content-Encoding": "gzip"},
        )
        assert resp.status_code == 201, resp.text
        assert "protocol_decode_job_id" not in resp.json()

    def test_handler_without_iq_is_skipped(self, bridge_app, decode_handler) -> None:
        assert (
            decode_handler("j", {"detection_id": "nope", "signal_class": "dmr"})[
                "status"
            ]
            == "skipped"
        )


class TestBatchStorage:
    def test_store_messages_is_one_transaction(self, ctx, monkeypatch) -> None:
        store = DecodedMessageStore(ctx)
        calls = []
        real = ctx.write_transaction

        def counting():
            calls.append(1)
            return real()

        monkeypatch.setattr(ctx, "write_transaction", counting)
        ids = store.store_messages(
            [{"protocol": "dmr", "source_id": str(i)} for i in range(200)]
            + [{"source_id": "no protocol"}, "not a dict", {"protocol": "p25"}]
        )
        assert len(calls) == 1
        assert len(ids) == 203
        assert ids[200] is None and ids[201] is None
        assert all(isinstance(i, int) for i in ids[:200] + ids[202:])
        assert store.count() == 201

    def test_huge_numbers_do_not_break_a_batch(self, ctx) -> None:
        store = DecodedMessageStore(ctx)
        ids = store.store_messages(
            [{"protocol": "dmr", "payload_length": 10**400, "gps_lat": 10**400}]
        )
        [row] = store.get_messages()
        assert ids == [row["id"]]
        assert row["payload_length"] is None and row["gps_lat"] is None

    def test_pipeline_stores_a_decode_in_one_call(self, monkeypatch) -> None:
        calls: list[int] = []

        class Recording:
            def store_messages(self, records):
                calls.append(len(records))
                return list(range(1, len(records) + 1))

            def store_message(self, record):  # pragma: no cover - not used
                raise AssertionError("per-message insert")

        out = _pipeline(Recording(), monkeypatch).decode_iq(
            _iq(), "dmr", 446e6, 2e6, "n1", detection_id="det-4"
        )
        assert calls == [1]
        assert out[0]["id"] == 1


def _multi_batch(node_id: str, n_dets: int, per_det: int) -> dict:
    batch = _batch(node_id)
    template = batch["detections"][0]
    batch["detections"] = [
        {
            **template,
            "id": f"det-many-{d}",
            "decoded_messages": [
                {"protocol": "dmr", "source_id": f"{d}-{m}", "node_id": "spoofed"}
                for m in range(per_det)
            ]
            + ["not an object"],
        }
        for d in range(n_dets)
    ]
    return batch


class TestEdgeDecodedIngestBounds:
    def test_per_detection_and_per_batch_caps(
        self, client: TestClient, bridge_app, registered_node: str, caplog
    ) -> None:
        import logging

        store = bridge_app.state.decoded_message_store
        with caplog.at_level(logging.WARNING, logger="sigrift.bridge.routers"):
            resp = client.post(
                "/api/detections/batch", json=_multi_batch(registered_node, 2, 80)
            )
        assert resp.status_code == 201, resp.text
        assert store.count() == 100  # 50 per detection
        assert any("dropped 62 edge-decoded" in r.getMessage() for r in caplog.records)

        resp = client.post(
            "/api/detections/batch", json=_multi_batch(registered_node, 25, 50)
        )
        assert resp.status_code == 201, resp.text
        assert store.count() == 100 + 1000  # 1000 per batch

    def test_messages_attributed_to_the_batch_node(
        self, client: TestClient, bridge_app, registered_node: str
    ) -> None:
        resp = client.post(
            "/api/detections/batch", json=_multi_batch(registered_node, 1, 1)
        )
        assert resp.status_code == 201, resp.text
        [row] = bridge_app.state.decoded_message_store.get_messages()
        assert row["node_id"] == registered_node
        assert row["detection_id"] == "det-many-0"

    def test_storage_runs_off_the_event_loop_in_one_call(
        self, client: TestClient, bridge_app, registered_node: str, monkeypatch
    ) -> None:
        import asyncio

        store = bridge_app.state.decoded_message_store
        real = store.store_messages
        seen: list[tuple[int, bool]] = []

        def recording(records):
            try:
                asyncio.get_running_loop()
                on_loop = True
            except RuntimeError:
                on_loop = False
            records = list(records)
            seen.append((len(records), on_loop))
            return real(records)

        monkeypatch.setattr(store, "store_messages", recording)
        monkeypatch.setattr(
            store,
            "store_message",
            lambda record: pytest.fail("per-message insert on the event loop"),
        )
        resp = client.post(
            "/api/detections/batch", json=_multi_batch(registered_node, 3, 5)
        )
        assert resp.status_code == 201, resp.text
        assert seen == [(15, False)]


def test_ingest_with_unusable_detection_id_still_succeeds(
    client: TestClient, registered_node: str
) -> None:
    # The "is the IQ already stored?" check must not turn an id that cannot
    # name a capture file into a 500 for the whole batch.  This id passes
    # the gateway's id rule (ASCII, 120 characters), but its ':' makes the
    # IQ store hex-encode it, and 240 hex characters are too long.
    batch = _batch(registered_node)
    batch["detections"][0]["id"] = "x:" * 60
    resp = client.post("/api/detections/batch", json=batch)
    assert resp.status_code == 201, resp.text
