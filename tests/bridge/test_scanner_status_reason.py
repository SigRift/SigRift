"""The optional scanner-status "reason": edge wire body, bridge lease and outputs."""

import json
import logging
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from sigrift.bridge.models import ScannerStatusRequest
from sigrift.bridge.routers import nodes
from sigrift.bridge.scanner_status import (
    SCANNER_PROTOCOLS,
    SCANNER_REASONS,
    SCANNER_REPORTS_FIELD,
    scanner_status_snapshot,
)
from sigrift.edge.scanner_status import CaptureActivity, ScannerStatusReporter

from .test_scanner_status import node, scanner_api  # noqa: F401

# The edge reporter tests wait for a reporter thread with generous limits
# below. The project default of 30 s per test (pyproject.toml) is too short for
# them on a loaded CI runner.
pytestmark = pytest.mark.timeout(180)
# A state that must be REACHED; the polls return as soon as it is.
WAIT = 60.0

REASONS = (
    "starting",
    "sensor_absent",
    "sensor_changed",
    "sensor_unusable",
    "capture_failed",
)


def post(api, body, *, node_id="radio-one", key="sensor"):
    client, _, _, keys, _ = api
    return client.post(
        f"/api/nodes/{node_id}/scanner-status", headers=keys[key], json=body
    )


# ---------------------------------------------------------------------------
# Bridge
# ---------------------------------------------------------------------------


def test_closed_lists_match_on_both_sides():
    import typing

    from sigrift.bridge.scanner_status import ScannerReason
    from sigrift.edge import scanner_status as edge
    from sigrift.edge import sensor_presence

    assert set(SCANNER_REASONS) == set(REASONS) == edge._REASONS
    assert set(typing.get_args(ScannerReason)) == set(REASONS)
    assert sensor_presence.REASONS == set(REASONS)


@pytest.mark.parametrize("protocol", SCANNER_PROTOCOLS)
@pytest.mark.parametrize("reason", REASONS)
def test_every_protocol_accepts_every_reason_and_returns_it(
    scanner_api,  # noqa: F811
    protocol,
    reason,
):
    response = post(
        scanner_api, {"protocol": protocol, "state": "error", "reason": reason}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "error" and body["reason"] == reason
    assert body["active"] is False and body["expires_in_seconds"] == 0
    assert node(scanner_api)["scanner_status"][protocol] == body
    client, _, _, keys, _ = scanner_api
    row = next(
        row
        for row in client.get("/api/nodes/", headers=keys["admin"]).json()
        if row["node_id"] == "radio-one"
    )
    assert row["scanner_status"][protocol]["reason"] == reason


@pytest.mark.parametrize("state", ["running", "stopped"])
@pytest.mark.parametrize("reason", REASONS)
def test_reason_without_error_state_is_refused(scanner_api, state, reason):  # noqa: F811
    response = post(scanner_api, {"protocol": "sdr", "state": state, "reason": reason})
    assert response.status_code == 422
    assert node(scanner_api)["scanner_status"] == {}


@pytest.mark.parametrize(
    "reason",
    ["unknown", "", "SENSOR_ABSENT", "sensor_absent ", 1, True, ["starting"], {}],
)
def test_reason_outside_the_closed_list_is_refused(scanner_api, reason):  # noqa: F811
    response = post(
        scanner_api, {"protocol": "sdr", "state": "error", "reason": reason}
    )
    assert response.status_code == 422
    assert node(scanner_api)["scanner_status"] == {}


def test_extra_fields_and_client_time_still_forbidden_with_reason(scanner_api):  # noqa: F811
    for extra in ({"reported_at": "2099-01-01T00:00:00Z"}, {"detail": "hci0"}):
        body = {"protocol": "wifi", "state": "error", "reason": "sensor_absent"}
        response = post(scanner_api, {**body, **extra})
        assert response.status_code == 422
    assert node(scanner_api)["scanner_status"] == {}


def test_no_reason_reads_null_and_a_later_report_clears_it(scanner_api):  # noqa: F811
    _, persistence, _, _, _ = scanner_api
    plain = post(scanner_api, {"protocol": "wifi", "state": "error"}).json()
    assert plain["reason"] is None
    stored = persistence.get_nodes()["radio-one"][SCANNER_REPORTS_FIELD]["wifi"]
    assert set(stored) == {"state", "reported_at"}
    assert (
        post(
            scanner_api,
            {"protocol": "wifi", "state": "error", "reason": "sensor_changed"},
        ).json()["reason"]
        == "sensor_changed"
    )
    stored = persistence.get_nodes()["radio-one"][SCANNER_REPORTS_FIELD]["wifi"]
    assert stored["reason"] == "sensor_changed"
    # Explicit null is the same as leaving the field out.
    cleared = post(scanner_api, {"protocol": "wifi", "state": "error", "reason": None})
    assert cleared.status_code == 200 and cleared.json()["reason"] is None
    assert node(scanner_api)["scanner_status"]["wifi"]["reason"] is None
    post(scanner_api, {"protocol": "wifi", "state": "error", "reason": "starting"})
    running = post(scanner_api, {"protocol": "wifi", "state": "running"}).json()
    assert running["reason"] is None and running["active"] is True
    assert (
        "reason"
        not in (persistence.get_nodes()["radio-one"][SCANNER_REPORTS_FIELD]["wifi"])
    )


def test_expired_error_lease_does_not_keep_a_stale_reason(scanner_api):  # noqa: F811
    _, _, now, _, _ = scanner_api
    post(scanner_api, {"protocol": "sdr", "state": "error", "reason": "sensor_absent"})
    now[0] += timedelta(seconds=119)
    assert node(scanner_api)["scanner_status"]["sdr"]["reason"] == "sensor_absent"
    now[0] += timedelta(seconds=1)
    current = node(scanner_api)["scanner_status"]["sdr"]
    assert current["state"] == "error" and current["reason"] is None


@pytest.mark.parametrize(
    "record",
    [
        {"state": "running", "reason": "sensor_absent"},
        {"state": "stopped", "reason": "sensor_absent"},
        {"state": "error", "reason": "/dev/bus/usb/001/004"},
        {"state": "error", "reason": ["sensor_absent"]},
        {"state": "error", "reason": 7},
    ],
)
def test_saved_reason_is_shown_only_when_valid_with_error(record):
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    saved = {"wifi": {**record, "reported_at": now.isoformat()}}
    row = scanner_status_snapshot(saved, now + timedelta(seconds=5))["wifi"]
    assert row["reason"] is None
    assert row["state"] == record["state"]


def test_snapshot_shape_used_by_every_output_carries_reason():
    """Node list/detail, the status websocket, deployment and setup checklist
    all serialise this one snapshot, so the key is present everywhere."""
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    saved = {
        "sdr": {"state": "error", "reason": "starting", "reported_at": now.isoformat()},
        "wifi": {"state": "running", "reported_at": now.isoformat()},
    }
    rows = scanner_status_snapshot(saved, now)
    assert set(rows["sdr"]) == {
        "protocol",
        "state",
        "reported_at",
        "expires_in_seconds",
        "active",
        "reason",
    }
    assert rows["sdr"]["reason"] == "starting" and rows["wifi"]["reason"] is None
    response = nodes._node_to_response("n", {SCANNER_REPORTS_FIELD: saved})
    dumped = response.model_dump(mode="json")["scanner_status"]
    assert dumped["wifi"]["reason"] is None
    assert set(dumped["sdr"]) == set(rows["sdr"])


# ---------------------------------------------------------------------------
# Edge reporter
# ---------------------------------------------------------------------------


@pytest.fixture
def endpoint(monkeypatch):
    """Real HTTP server. ``mode`` is "new" (accepts reasons) or "old" (a bridge
    from before reasons: refuses an unknown field with ``old_status``)."""
    # This server runs in the test process; on a loaded runner it can take
    # longer than the product's 3 s per request to answer. Nothing here tests
    # that limit, so it is lengthened (a request still returns at once).
    monkeypatch.setattr("sigrift.edge.scanner_status._REQUEST_TIMEOUT", 20.0)
    observed = []
    config = {"mode": "new", "old_status": 422, "status": 200}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            observed.append(body)
            if config["mode"] == "old" and set(body) - {"protocol", "state"}:
                status = config["old_status"]
            else:
                status = config["status"]
            self.send_response(status)
            self.end_headers()
            self.wfile.write(b"PRIVATE-RESPONSE-MARKER")

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", observed, config
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=30)


def reporter(url, capture_state=lambda: "running", protocol="wifi", **kwargs):
    return ScannerStatusReporter(
        url,
        "owned-node",
        protocol,
        ssl.create_default_context,
        lambda: {"X-API-Key": "PRIVATE-KEY-MARKER"},
        capture_state,
        **kwargs,
    )


def run_once(rep, observed, count=1):
    rep.start()
    deadline = time.monotonic() + WAIT
    while len(observed) < count and time.monotonic() < deadline:
        time.sleep(0.005)
    # Stopping earlier would test only the final report.
    assert len(observed) >= count, observed
    rep.stop()


@pytest.mark.parametrize("protocol", SCANNER_PROTOCOLS)
@pytest.mark.parametrize("reason", REASONS)
def test_edge_sends_reason_only_with_error_and_bridge_model_accepts_it(
    endpoint, protocol, reason
):
    url, observed, _ = endpoint
    rep = reporter(url, protocol=protocol)
    assert rep.report("error", reason)
    assert rep.report("error")
    assert rep.report("running", reason)
    assert rep.report("stopped", reason)
    assert observed == [
        {"protocol": protocol, "state": "error", "reason": reason},
        {"protocol": protocol, "state": "error"},
        {"protocol": protocol, "state": "running"},
        {"protocol": protocol, "state": "stopped"},
    ]
    for body in observed:
        ScannerStatusRequest(**body)  # The wire body is what the bridge accepts.


@pytest.mark.parametrize("reason", ["unknown", "", "/dev/bus/usb/001/004", 3])
def test_edge_invalid_reason_raises_and_sends_nothing(endpoint, reason):
    url, observed, _ = endpoint
    rep = reporter(url)
    with pytest.raises((ValueError, TypeError)):
        rep.report("error", reason)
    with pytest.raises((ValueError, TypeError)):
        rep.stop("error", reason)
    assert observed == []


@pytest.mark.parametrize(
    "value,expected",
    [
        (("error", "sensor_absent"), {"state": "error", "reason": "sensor_absent"}),
        (("error", None), {"state": "error"}),
        (("running", "sensor_absent"), {"state": "running"}),
        (("running", None), {"state": "running"}),
        ("error", {"state": "error"}),
        # Malformed values are treated like any invalid callback value today.
        (("error", "PRIVATE-hci0"), {"state": "error"}),
        (("running", "PRIVATE-hci0"), {"state": "error"}),
        (("running",), {"state": "error"}),
        (("error", "sensor_absent", "x"), {"state": "error"}),
        (("PRIVATE-state", "sensor_absent"), {"state": "error"}),
    ],
)
def test_capture_state_callable_may_return_state_and_reason(
    endpoint, caplog, value, expected
):
    url, observed, _ = endpoint
    run_once(reporter(url, lambda: value, interval=0.02), observed)
    assert observed[0] == {"protocol": "wifi", **expected}
    assert observed[-1] == {"protocol": "wifi", "state": "stopped"}
    assert "PRIVATE" not in caplog.text


def test_old_bridge_gets_one_resend_without_reason_then_no_more_reasons(
    endpoint, caplog
):
    url, observed, config = endpoint
    # An older bridge's strict model refuses the unknown field with 422.
    config.update(mode="old", old_status=422)
    rep = reporter(url)
    with caplog.at_level(logging.INFO, logger="sigrift.edge.scanner_status"):
        assert rep.report("error", "sensor_absent")
        assert rep.report("error", "sensor_changed")
        assert rep.report("running")
    assert observed == [
        {"protocol": "wifi", "state": "error", "reason": "sensor_absent"},
        {"protocol": "wifi", "state": "error"},
        {"protocol": "wifi", "state": "error"},
        {"protocol": "wifi", "state": "running"},
    ]
    infos = [r for r in caplog.records if r.levelno == logging.INFO]
    assert len(infos) == 1 and "reason" in infos[0].getMessage()
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert "PRIVATE" not in caplog.text and url not in caplog.text


def test_old_bridge_fallback_reports_a_failed_resend(endpoint, caplog):
    url, observed, config = endpoint
    config.update(mode="old", status=500)
    assert not reporter(url).report("error", "starting")
    assert observed == [
        {"protocol": "wifi", "state": "error", "reason": "starting"},
        {"protocol": "wifi", "state": "error"},
    ]
    assert "HTTP 500" in caplog.text


# 400 can have causes other than the reason field, so it is not a sign of an
# older bridge.
@pytest.mark.parametrize("status", [400, 401, 403, 404, 429, 500])
def test_other_refusals_are_single_shot_and_keep_reasons(endpoint, caplog, status):
    url, observed, config = endpoint
    config["status"] = status
    rep = reporter(url)
    assert not rep.report("error", "sensor_absent")
    assert len(observed) == 1
    config["status"] = 200
    assert rep.report("error", "sensor_absent")
    assert observed[-1].get("reason") == "sensor_absent"
    assert str(status) in caplog.text


def test_plain_state_on_old_bridge_is_not_resent(endpoint):
    url, observed, config = endpoint
    config.update(mode="old", status=422)
    assert not reporter(url).report("error")
    assert observed == [{"protocol": "wifi", "state": "error"}]


def test_final_report_may_carry_a_reason(endpoint):
    url, observed, _ = endpoint
    rep = reporter(url, lambda: "running", interval=0.02)
    rep.start()
    deadline = time.monotonic() + WAIT
    while not observed and time.monotonic() < deadline:
        time.sleep(0.005)
    assert observed  # A running report first, so the final one is the last.
    rep.stop("error", "sensor_absent")
    assert observed[-1] == {
        "protocol": "wifi",
        "state": "error",
        "reason": "sensor_absent",
    }
    rep2 = reporter(url, lambda: "running", interval=0.02)
    rep2.stop("stopped", "sensor_absent")  # Not started: nothing sent, no error.
    assert rep2._final_reason is None


def test_capture_activity_status_says_why_it_is_not_running(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr("sigrift.edge.scanner_status.time.monotonic", lambda: clock[0])
    activity = CaptureActivity()
    assert activity.status() == ("error", "starting")
    assert activity.state() == "error"
    activity.failed("sensor_absent")
    assert activity.status() == ("error", "sensor_absent")
    activity.succeeded()
    assert activity.status() == ("running", None)
    assert activity.state() == "running"
    clock[0] += 60
    assert activity.status() == ("error", "capture_failed")  # Stalled capture.
    activity.succeeded()
    activity.failed()
    assert activity.status() == ("error", "capture_failed")
    activity.failed("sensor_changed")
    assert activity.status() == ("error", "sensor_changed")
    with pytest.raises(ValueError):
        activity.failed("PRIVATE-reason")
    assert activity.status() == ("error", "sensor_changed")


def test_capture_activity_status_is_a_ready_capture_state_callable(endpoint):
    url, observed, _ = endpoint
    activity = CaptureActivity()
    activity.failed("sensor_absent")
    run_once(reporter(url, activity.status, protocol="sdr", interval=0.02), observed)
    assert observed[0] == {
        "protocol": "sdr",
        "state": "error",
        "reason": "sensor_absent",
    }


def test_stop_waits_for_a_report_its_resend_and_the_final_report(monkeypatch):
    """Worst case at stop: the in-flight report, its one resend and the final
    report each take the full per-request timeout."""
    from sigrift.edge import scanner_status as edge

    assert 3 * edge._REQUEST_TIMEOUT < 10  # Docker's default stop window.
    timeouts, joins = [], []

    class Opener:
        def open(self, _request, timeout):
            timeouts.append(timeout)
            raise TimeoutError

    monkeypatch.setattr(edge.urllib.request, "build_opener", lambda *_: Opener())
    rep = reporter("http://127.0.0.1:9")
    rep.report("error", "sensor_absent")
    assert timeouts == [edge._REQUEST_TIMEOUT]

    class Thread:
        def join(self, timeout):
            joins.append(timeout)

        def is_alive(self):
            return False

    rep._thread = Thread()
    rep.stop()
    assert joins and joins[0] >= 3 * edge._REQUEST_TIMEOUT
    assert joins[0] <= 10
