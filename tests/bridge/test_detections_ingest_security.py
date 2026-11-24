"""Security tests for detection ingest (``routers/detections.py``).

* Both ingest routes refuse a body over 1 MB (413) and store nothing.
* ``/ingest-summary`` refuses corrupt / truncated gzip and invalid JSON
  (400) and a malformed body (422) before any work: nothing is stored and
  an unbound scanner key is not bound to a node by a rejected request.
* A key bound to a node cannot ingest as another node, and a detection
  that names another node is stored as the batch's node (both routes).
* Edge-decoded messages are attributed to the accepted detection, never to
  the node, detection or tenant a message names.
* The per-node ingest tracking maps and the anomaly-alert cooldown map are
  bounded (an edge cannot grow them without limit); a cooldown suppresses
  repeat alerts until it is dropped.
* The confidence floor keeps low-confidence detections from alerting.
* The read routes need VIEWER: SENSOR and NODE keys are refused, by the
  full app and by the router's own guards without the gateway proxy.
"""

from __future__ import annotations

import gzip
import itertools
import time
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.persistence import PersistenceManager
from sigrift.bridge.routers import detections
from sigrift.lib.security import credentials
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
)


@pytest.fixture(autouse=True)
def _fast_pbkdf2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(credentials, "_PBKDF2_ITERATIONS", 1_000)


@pytest.fixture(autouse=True)
def _fresh_ingest_tracking(monkeypatch: pytest.MonkeyPatch) -> None:
    # Process-wide ingest state: other tests in the same worker ingest for
    # the same node ids, and the per-node batch count decides when the
    # correlation stage runs (it may adjust anomaly scores).
    monkeypatch.setattr(detections, "_raw_ingest_nodes", {})
    monkeypatch.setattr(detections, "_summary_ingest_nodes", {})
    monkeypatch.setattr(detections, "_node_batch_count", OrderedDict())


def _add_key(
    persistence: PersistenceManager, key_id: str, role: str, node_id: str | None = None
) -> str:
    raw = generate_api_key(32)
    digest, salt = hash_credential(raw)
    meta: dict[str, Any] = {"role": role, "description": "", "created_at": ""}
    if node_id is not None:
        meta["node_id"] = node_id
    assert persistence.add_key(
        key_id, digest, salt, lookup_hash=compute_lookup_hash(raw), meta=meta
    )
    return raw


def _register(client: TestClient, *node_ids: str) -> None:
    for node_id in node_ids:
        resp = client.post("/api/nodes/register", json={"node_id": node_id})
        assert resp.status_code == 200, resp.text


def _batch(node_id: str, *dets: dict[str, Any]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    return {
        "node_id": node_id,
        "period_start": (now - timedelta(minutes=1)).isoformat(),
        "period_end": now.isoformat(),
        "detections": [
            {
                "node_id": node_id,
                "signal_class": "bpsk",
                "confidence": 0.9,
                "freq_hz": 433.92e6,
                **det,
            }
            for det in dets
        ],
    }


# ---------------------------------------------------------------------------
# Size and shape validation
# ---------------------------------------------------------------------------


def test_body_over_one_megabyte_is_413_and_stores_nothing(
    client, registered_node, detection_store
):
    body = _batch(registered_node, {"id": "big"})
    body["padding"] = "x" * 1_048_576
    for path in ("/api/detections/batch", "/api/detections/ingest-summary"):
        resp = client.post(path, json=body)
        assert resp.status_code == 413, path
        assert resp.json()["detail"] == "Request body exceeds 1MB limit"
    assert detection_store.get_detection_by_id("big") is None
    assert detection_store.row_count() == 0


_GZIP = {"Content-Encoding": "gzip"}
_MALFORMED_SUMMARIES = [
    ("corrupt-gzip", b"\x1f\x8b\x08\x00garbage-after-gzip-magic", _GZIP, 400),
    (
        "truncated-gzip",
        gzip.compress(b'{"node_id": "n1", "summaries": []}')[:-12],
        _GZIP,
        400,
    ),
    ("not-gzip", b"plain text, not gzip", _GZIP, 400),
    ("bad-json", b"{not json", {}, 400),
    ("bad-utf8", b"\xff\xfe\x00", {}, 400),
    ("bad-node-id", b'{"node_id": "../n1", "summaries": []}', {}, 422),
    ("bad-summaries", b'{"node_id": "n1", "summaries": "all of them"}', {}, 422),
    (
        "bad-detection",
        b'{"node_id": "n1", "high_anomaly_detections": [{"confidence": 7}]}',
        {},
        422,
    ),
    ("not-an-object", b'["node_id", "n1"]', {}, 422),
]


def test_malformed_summary_is_refused_before_any_work(
    bridge_app, client, persistence, detection_store
):
    _register(client, "n1")
    raw = _add_key(persistence, "edge_key", "sensor")
    edge = TestClient(bridge_app, headers={"X-API-Key": raw})
    for case, content, headers, expected in _MALFORMED_SUMMARIES:
        resp = edge.post(
            "/api/detections/ingest-summary",
            content=content,
            headers={"Content-Type": "application/json", **headers},
        )
        assert resp.status_code == expected, (case, resp.text)
        # A refused request neither stores anything nor binds the key (K4).
        assert "node_id" not in persistence.get_key_meta()["edge_key"], case
        assert detection_store.row_count() == 0, case
        assert "n1" not in detections.get_summary_ingest_nodes(), case

    # The same key, with a well-formed gzip body: accepted, and bound now.
    resp = edge.post(
        "/api/detections/ingest-summary",
        content=gzip.compress(b'{"node_id": "n1", "summaries": []}'),
        headers={"Content-Type": "application/json", **_GZIP},
    )
    assert resp.status_code == 201, resp.text
    assert persistence.get_key_meta()["edge_key"]["node_id"] == "n1"


# ---------------------------------------------------------------------------
# Node binding
# ---------------------------------------------------------------------------


def test_bound_key_ingests_only_as_its_own_node(
    bridge_app, client, persistence, detection_store
):
    _register(client, "n1", "n2")
    raw = _add_key(persistence, "edge_key", "sensor", node_id="n1")
    edge = TestClient(bridge_app, headers={"X-API-Key": raw})

    resp = edge.post("/api/detections/batch", json=_batch("n2", {"id": "forged"}))
    assert resp.status_code == 403, resp.text
    assert detection_store.get_detection_by_id("forged") is None
    assert "n2" not in detections.get_raw_ingest_nodes()

    # A detection naming another node is stored as the batch's (bound) node,
    # on both ingest routes.
    resp = edge.post(
        "/api/detections/batch", json=_batch("n1", {"id": "raw", "node_id": "n2"})
    )
    assert resp.status_code == 201, resp.text
    summary = _batch("n1", {"id": "summary", "node_id": "n2"})
    resp = edge.post(
        "/api/detections/ingest-summary",
        json={
            "node_id": "n1",
            "summaries": [],
            "high_anomaly_detections": summary["detections"],
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["inserted_raw"] == 1
    for det_id in ("raw", "summary"):
        assert detection_store.get_detection_by_id(det_id)["node_id"] == "n1"
    assert persistence.get_key_meta()["edge_key"]["node_id"] == "n1"


# ---------------------------------------------------------------------------
# Edge-decoded messages: attribution
# ---------------------------------------------------------------------------


@pytest.fixture
def scanner(bridge_app, persistence, registered_node) -> TestClient:
    """A SENSOR key bound to the registered node, as an edge uses it."""
    raw = _add_key(persistence, "edge_key", "sensor", node_id=registered_node)
    return TestClient(bridge_app, headers={"X-API-Key": raw})


def test_edge_decoded_message_cannot_claim_another_detection(
    scanner, bridge_app, registered_node
):
    resp = scanner.post(
        "/api/detections/batch",
        json=_batch(
            registered_node,
            {
                "id": "det-own",
                "decoded_messages": [
                    {
                        "protocol": "dmr",
                        "source_id": "77",
                        "node_id": "victim-node",
                        "detection_id": "victim-det",
                    }
                ],
            },
        ),
    )
    assert resp.status_code == 201, resp.text
    store = bridge_app.state.decoded_message_store
    assert store.get_messages(detection_id="victim-det") == []
    [row] = store.get_messages(detection_id="det-own")
    assert (row["node_id"], row["source_id"]) == (registered_node, "77")


def test_edge_decoded_message_cannot_claim_another_tenant(
    scanner, bridge_app, registered_node, detection_store
):
    from sigrift.bridge.storage.decoded_messages import DecodedMessageStore
    from sigrift.bridge.storage.base import SharedContext

    resp = scanner.post(
        "/api/detections/batch",
        json=_batch(
            registered_node,
            {
                "id": "det-own",
                "decoded_messages": [
                    {"protocol": "dmr", "source_id": "77", "tenant_id": "victim"}
                ],
            },
        ),
    )
    assert resp.status_code == 201, resp.text
    victim_ctx = SharedContext(detection_store.db_path, tenant_id="victim")
    try:
        injected = DecodedMessageStore(victim_ctx).get_messages()
    finally:
        victim_ctx.close()
    own = bridge_app.state.decoded_message_store.get_messages(detection_id="det-own")
    assert (len(own), injected) == (1, [])


def test_edge_decoded_adsb_track_is_attributed_to_the_batch(
    scanner, registered_node, detection_store
):
    # ADS-B messages also feed the aircraft track store: the track belongs
    # to the batch's node and the bridge's tenant, not to the ones the
    # message's metadata names.
    from sigrift.bridge.storage.aircraft import AircraftStore

    detection_store._aircraft = AircraftStore(detection_store._ctx)
    resp = scanner.post(
        "/api/detections/batch",
        json=_batch(
            registered_node,
            {
                "id": "det-adsb",
                "signal_class": "adsb",
                "freq_hz": 1090e6,
                "decoded_messages": [
                    {
                        "protocol": "adsb",
                        "source_id": "A1B2C3",
                        "tenant_id": "victim",
                        "metadata": {
                            "icao_address": "A1B2C3",
                            "node_id": "victim-node",
                            "tenant_id": "victim",
                        },
                    }
                ],
            },
        ),
    )
    assert resp.status_code == 201, resp.text
    rows = (
        detection_store.get_connection()
        .execute("SELECT icao_address, node_id, tenant_id FROM aircraft_tracks")
        .fetchall()
    )
    assert [tuple(row) for row in rows] == [("A1B2C3", registered_node, "default")]


def test_edge_decoded_records_reach_the_stores_without_a_tenant():
    # The router strips a message's (and its ADS-B metadata's) tenant_id
    # before either store sees it, so a store that honoured a record's
    # tenant could not be steered by an edge either.
    from types import SimpleNamespace

    from sigrift.bridge.routers.detections import _store_edge_decoded

    class Recording:
        def __init__(self):
            self.records: list[dict] = []

        def store_messages(self, records):
            self.records.extend(dict(r) for r in records)
            return list(range(len(records)))

        def insert_position(self, track):
            self.records.append(dict(track))

    decoded, aircraft = Recording(), Recording()
    det = SimpleNamespace(detection_id="det-1", node_id="node-a", freq_hz=1090e6)
    message = {
        "protocol": "adsb",
        "tenant_id": "victim",
        "metadata": {"icao_address": "A1B2C3", "tenant_id": "victim"},
    }
    stored = _store_edge_decoded(decoded, aircraft, [det], {"det-1": [message]})
    assert stored == 1
    [record] = decoded.records
    assert "tenant_id" not in record
    assert (record["node_id"], record["detection_id"]) == ("node-a", "det-1")
    [track] = aircraft.records
    assert "tenant_id" not in track
    assert track == {"icao_address": "A1B2C3", "node_id": "node-a"}


def test_decoded_and_aircraft_stores_write_their_own_tenant(tmp_path):
    # Whoever calls them (edge ingest, POST /api/aircraft/, the decode
    # pipeline, which names tenant "default"), a row is the store's tenant.
    from sigrift.bridge.storage.aircraft import AircraftStore
    from sigrift.bridge.storage.base import SharedContext
    from sigrift.bridge.storage.decoded_messages import DecodedMessageStore

    ctx = SharedContext(tmp_path / "tenants.db", tenant_id="site-a")
    try:
        decoded = DecodedMessageStore(ctx)
        aircraft = AircraftStore(ctx)
        decoded.store_message({"protocol": "dmr", "tenant_id": "victim"})
        decoded.store_messages(
            [
                {"protocol": "p25", "tenant_id": "default"},
                {"protocol": "tetra", "tenant_id": None},
                {"protocol": "nxdn"},
            ]
        )
        aircraft.insert_position({"icao_address": "A1B2C3", "tenant_id": "victim"})
        aircraft.insert_position({"icao_address": "D4E5F6"})
        conn = ctx.get_conn()
        tenants = {
            table: {row[0] for row in conn.execute(f"SELECT tenant_id FROM {table}")}
            for table in ("decoded_messages", "aircraft_tracks")
        }
        assert tenants == {
            "decoded_messages": {"site-a"},
            "aircraft_tracks": {"site-a"},
        }
        assert len(decoded.get_messages()) == 4
        assert len(aircraft.get_active_aircraft()) == 2
    finally:
        ctx.close()


# ---------------------------------------------------------------------------
# Bounded per-node state
# ---------------------------------------------------------------------------


class _FakeTime:
    """Stands in for the ``time`` module of routers/detections.py: the
    functions given replace their namesakes, every other name is the real
    module's."""

    def __init__(self, **functions: Any) -> None:
        self.__dict__.update(functions)

    def __getattr__(self, name: str) -> Any:
        return getattr(time, name)


@pytest.fixture
def tracking(monkeypatch: pytest.MonkeyPatch):
    """Small ingest-tracking maps and a strictly increasing clock."""
    monkeypatch.setattr(detections, "_RAW_INGEST_MAX_ENTRIES", 2)
    ticks = itertools.count(1_000)
    monkeypatch.setattr(detections, "time", _FakeTime(time=lambda: float(next(ticks))))


def test_ingest_tracking_keeps_only_the_most_recent_nodes(client, tracking):
    _register(client, "n1", "n2", "n3")
    for node_id in ("n1", "n2", "n3"):
        resp = client.post("/api/detections/batch", json=_batch(node_id))
        assert resp.status_code == 201, resp.text
        resp = client.post(
            "/api/detections/ingest-summary", json={"node_id": node_id, "summaries": []}
        )
        assert resp.status_code == 201, resp.text
    status = client.get("/api/detections/ingest-status").json()
    assert sorted(status["raw_ingest_nodes"]) == ["n2", "n3"]
    assert sorted(status["summary_ingest_nodes"]) == ["n2", "n3"]


def test_anomaly_alert_cooldowns_expire_and_are_capped_oldest_first(
    client, app_state, persistence, monkeypatch
):
    # The cooldown map is pruned at most every 10 minutes (600 s): entries
    # older than two cooldowns (600 s) first, then the oldest down to the
    # cap.  A cap of 2 instead of 50,000, and a monotonic clock the test
    # moves; the time of the last pruning is process-wide, so it is
    # restored afterwards.
    monkeypatch.setattr(detections, "_COOLDOWN_MAX_ENTRIES", 2)
    monkeypatch.setattr(
        detections, "_cooldown_last_evict", detections._cooldown_last_evict
    )
    start = time.monotonic() + 10_000.0  # long after any earlier pruning
    clock = [start]
    monkeypatch.setattr(detections, "time", _FakeTime(monotonic=lambda: clock[0]))
    _register(client, "n1", "n2")

    def alerted(at: int, node_id: str, *mhz: int) -> list[int]:
        """Ingest one hot detection per frequency at *at* seconds; return
        the frequencies that alerted."""
        clock[0] = start + at
        seen = {a["detection_id"] for a in persistence.get_alerts()}
        # A warning-level score: its cooldown is the 300 s one.
        dets = [
            {"id": f"{node_id}-{at}:{f}", "anomaly_score": 0.75, "freq_hz": f * 1e6}
            for f in mhz
        ]
        resp = client.post("/api/detections/batch", json=_batch(node_id, *dets))
        assert resp.status_code == 201, resp.text
        new = [a["detection_id"] for a in persistence.get_alerts()]
        assert resp.json()["alerts_created"] == len(set(new) - seen)
        return sorted(int(d.split(":")[1]) for d in set(new) - seen)

    assert alerted(0, "n2", 105) == [105]  # pruned (nothing to prune) at 0
    # Pruned at 700: n2's 105 MHz cooldown (700 s old) is dropped.
    assert alerted(700, "n1", 101) == [101]
    assert len(app_state.anomaly_alert_cooldowns) == 1
    assert alerted(1100, "n1", 102) == [102]
    # 102 MHz is still cooling down.
    assert alerted(1101, "n1", 103, 104, 102) == [103, 104]
    # Pruned at 1350: 101 is stale, which leaves 102, 103 and 104, over the
    # cap of 2: the oldest (102) goes, so it alerts again; 103 and 104 are
    # still cooling down.
    assert alerted(1350, "n1", 102, 103, 104) == [102]


def test_a_warning_cooldown_does_not_hold_back_a_critical_alert(
    client, persistence, monkeypatch
):
    # Critical alerts wait only the 60 s critical cooldown since the
    # bucket's last alert; warnings wait 300 s, whatever came before.
    monkeypatch.setattr(
        detections, "_cooldown_last_evict", detections._cooldown_last_evict
    )
    # No FHSS/correlation pass (every 5th batch): it may adjust scores.
    monkeypatch.setattr(detections, "_ANALYSIS_EVERY_N", 10_000)
    start = time.monotonic() + 20_000.0
    clock = [start]
    monkeypatch.setattr(detections, "time", _FakeTime(monotonic=lambda: clock[0]))
    _register(client, "n1")

    def alerted(at: int, score: float) -> list[str]:
        """Ingest one detection at 101 MHz at *at* seconds; return the
        severities of the alerts it created."""
        clock[0] = start + at
        seen = {a["alert_id"] for a in persistence.get_alerts()}
        det = {"id": f"n1-{at}", "anomaly_score": score, "freq_hz": 101e6}
        resp = client.post("/api/detections/batch", json=_batch("n1", det))
        assert resp.status_code == 201, resp.text
        return [
            a["severity"] for a in persistence.get_alerts() if a["alert_id"] not in seen
        ]

    assert alerted(0, 0.75) == ["warning"]
    assert alerted(30, 0.95) == []  # 30 s after the warning
    assert alerted(61, 0.95) == ["critical"]  # held back 300 s before
    assert alerted(100, 0.95) == []  # 39 s after the critical one
    assert alerted(122, 0.95) == ["critical"]
    assert alerted(200, 0.75) == []  # a warning still waits 300 s


def test_a_failing_recent_detections_fetch_is_logged_once_per_streak(
    client, registered_node, detection_store, monkeypatch, caplog
):
    # FHSS + correlation load the last minute of detections; when that
    # fails they degrade, which is logged once per failure streak.
    monkeypatch.setattr(detections, "_ANALYSIS_EVERY_N", 1)
    monkeypatch.setattr(detections, "_recent_fetch_state", {"failing": False})
    failing = {"on": False}
    real_get_recent = detection_store.get_recent

    def get_recent(*args, **kwargs):
        if failing["on"]:
            raise RuntimeError("database is locked")
        return real_get_recent(*args, **kwargs)

    monkeypatch.setattr(detection_store, "get_recent", get_recent)
    caplog.set_level("INFO", logger="sigrift.bridge.routers.detections")
    for i, fail in enumerate([True, True, False, True]):
        failing["on"] = fail
        resp = client.post(
            "/api/detections/batch", json=_batch(registered_node, {"id": f"r{i}"})
        )
        assert resp.status_code == 201, resp.text
    messages = [
        r.getMessage() for r in caplog.records if "recent detections" in r.getMessage()
    ]
    warning = (
        "Could not load recent detections; FHSS analysis uses only the current "
        "batch and correlation is skipped until it works"
    )
    assert messages == [warning, "Loading recent detections works again", warning]


def test_confidence_floor_keeps_low_confidence_detections_from_alerting(
    client, registered_node, persistence
):
    resp = client.put(
        "/api/admin/detection-config", json={"rf_min_confidence_floor": 0.5}
    )
    assert resp.status_code == 200
    resp = client.post(
        "/api/detections/batch",
        json=_batch(
            registered_node,
            {"id": "weak", "anomaly_score": 0.95, "confidence": 0.3, "freq_hz": 101e6},
            {
                "id": "strong",
                "anomaly_score": 0.95,
                "confidence": 0.9,
                "freq_hz": 915e6,
            },
        ),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["alerts_created"] == 1
    alerted = {a.get("detection_id") for a in persistence.get_alerts()}
    assert "strong" in alerted and "weak" not in alerted


# ---------------------------------------------------------------------------
# Read routes need VIEWER
# ---------------------------------------------------------------------------


_READ_ROUTES = [
    ("GET", "/api/detections/secret-det", None),
    ("GET", "/api/detections/ingest-status", None),
    ("POST", "/api/detections/query", {}),
    ("GET", "/api/detections/count", None),
    ("GET", "/api/detections/recent", None),
]


def _ingest_secret(client: TestClient, node_id: str) -> None:
    resp = client.post(
        "/api/detections/batch", json=_batch(node_id, {"id": "secret-det"})
    )
    assert resp.status_code == 201, resp.text


def test_scanner_keys_cannot_read_detections(
    bridge_app, client, persistence, detection_store, registered_node
):
    _ingest_secret(client, registered_node)
    for role in ("sensor", "node"):
        raw = _add_key(persistence, f"{role}_key", role, node_id=registered_node)
        scanner = TestClient(bridge_app, headers={"X-API-Key": raw})
        for method, path, body in _READ_ROUTES:
            # /recent is refused first by the gateway-proxy middleware.
            detail = (
                "Insufficient role for this endpoint"
                if path.endswith("/recent")
                else "Viewer role required"
            )
            resp = scanner.request(method, path, json=body)
            assert resp.status_code == 403, (role, path, resp.text)
            assert resp.json()["detail"] == detail, (role, path)
            assert "secret-det" not in resp.text
    viewer = TestClient(
        bridge_app, headers={"X-API-Key": _add_key(persistence, "viewer_key", "viewer")}
    )
    assert viewer.get("/api/detections/secret-det").json()["node_id"] == registered_node


def test_router_guards_hold_without_the_gateway_proxy(
    bridge_app, client, persistence, registered_node
):
    # The router mounted alone, with the app's state but none of its
    # middleware: its own guards must refuse scanner keys on every read
    # route (the proxy's path list is not the router's access control).
    _ingest_secret(client, registered_node)
    bare = FastAPI()
    bare.state = bridge_app.state
    bare.include_router(detections.router, prefix="/api/detections")
    for role in ("sensor", "node"):
        raw = _add_key(persistence, f"{role}_key", role, node_id=registered_node)
        scanner = TestClient(bare, headers={"X-API-Key": raw})
        for method, path, body in _READ_ROUTES:
            resp = scanner.request(method, path, json=body)
            assert (resp.status_code, resp.json()) == (
                403,
                {"detail": "Viewer role required"},
            ), (role, path)
    viewer = TestClient(
        bare, headers={"X-API-Key": _add_key(persistence, "viewer_key", "viewer")}
    )
    for method, path, body in _READ_ROUTES:
        resp = viewer.request(method, path, json=body)
        assert resp.status_code == 200, (path, resp.text)
    recent = viewer.get("/api/detections/recent").json()["detections"]
    assert [d["detection_id"] for d in recent] == ["secret-det"]
