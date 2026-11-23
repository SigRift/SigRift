"""Actual RF reporter restart through production TLS/auth and visible retained data.

Synthetic observations exercise software delivery only; no physical capture or
unique total across unknown legacy/stream overlap is claimed.
"""

import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

import pytest

from .conftest import Client, expect


_CHILD = r"""
import json,sys,time
from types import SimpleNamespace
from sigrift.edge import detection_reporter as edge
config=json.load(sys.stdin)
stamp=[config['timestamp']]
# Only synthetic observation timestamps are fixed; TLS/deadlines use real time.
edge.time=SimpleNamespace(time=lambda:stamp[0],monotonic=time.monotonic,sleep=time.sleep)
reporter=edge.DetectionReporter(config['url'],config['key'],config['node'],
    data_dir=config['data'],summarize=True,summary_anomaly_threshold=0,
    dedup_window_seconds=0,repeat_report_interval=1)
try:
    for confidence in config['confidences']:
        assert reporter.report({'class':'bpsk','family':'PSK','confidence':confidence},915e6,15,-55)
        stamp[0]+=.01
    reporter.stop()
    assert reporter.get_stats()['summary_pending_hours']==0
    accumulator=reporter._accumulator
    assert len(accumulator._hours)==1
    hour,bucket=next(iter(accumulator._hours.items()))
    body=json.loads(accumulator._body(bucket,hour))
finally:
    reporter.close()
print(json.dumps(body))
"""


def _run_reporter(settings, key, node, directory, stamp, confidences):
    environment = dict(os.environ)
    for name in tuple(environment):
        if name.startswith("MLRF_") or name in {
            "BRIDGE_CA_BUNDLE",
            "SSLKEYLOGFILE",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        }:
            environment.pop(name, None)
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    if os.environ.get("SIGRIFT_E2E_CA_CERT"):
        environment["MLRF_CA_CERT"] = os.environ["SIGRIFT_E2E_CA_CERT"]
    result = subprocess.run(
        [sys.executable, "-c", _CHILD],
        input=json.dumps(
            {
                "url": settings.base_url,
                "key": key,
                "node": node,
                "data": str(directory),
                "timestamp": stamp,
                "confidences": confidences,
            }
        ),
        text=True,
        capture_output=True,
        env=environment,
        timeout=45,
    )
    # Credentials travel only over stdin to an owned child, never argv/logs.
    assert result.returncode == 0, "Actual RF reporter child failed"
    return json.loads(result.stdout)


@pytest.mark.disposable
@pytest.mark.timeout(240)
def test_summary_restart_preserves_ids_and_rejects_stale_generation(
    disposable, admin_api, settings, authenticated_page, tmp_path
):
    page = authenticated_page
    node = "e2e-summary-" + secrets.token_hex(5)
    admin_api.request(
        "POST", "/api/nodes/register", {"node_id": node, "host": "synthetic.invalid"}
    )
    sensor = Client(settings)
    key = admin_api.request(
        "POST",
        "/api/admin/keys",
        {
            "description": "disposable journal restart proof",
            "role": "sensor",
            "node_id": node,
        },
        status=201,
        retry_key_creation=True,
        stage="scanner_key",
    )
    lease_path = f"/api/nodes/{node}/scanner-status"
    last = None
    try:
        assert isinstance(key.get("key_id"), str) and key["key_id"]
        assert isinstance(key.get("raw_key"), str) and key["raw_key"]
        stamp = time.time()
        stamp = min(stamp, int(stamp // 3600) * 3600 + 3590)
        first = _run_reporter(
            settings, key["raw_key"], node, tmp_path / "journal", stamp, [0.7, 0.9]
        )
        assert first["generation"] == 2
        originals = {
            row["id"]: admin_api.request("GET", f"/api/detections/{row['id']}")
            for row in first["high_anomaly_detections"]
        }
        assert len(originals) == 2
        last = _run_reporter(
            settings, key["raw_key"], node, tmp_path / "journal", stamp + 1, [0.8]
        )
        assert last["stream_id"] == first["stream_id"]
        assert last["hour"] == first["hour"]
        assert last["generation"] == 3
        ids = {row["id"] for row in last["high_anomaly_detections"]}
        assert len(ids) == 3 and set(originals) < ids
        for identity, stored in originals.items():
            assert admin_api.request("GET", f"/api/detections/{identity}") == stored
        for identity in ids - set(originals):
            assert (
                admin_api.request("GET", f"/api/detections/{identity}")["node_id"]
                == node
            )
        sensor.request(
            "POST",
            "/api/detections/ingest-summary",
            first,
            key=key["raw_key"],
            status=409,
        )
        replay = sensor.request(
            "POST",
            "/api/detections/ingest-summary",
            last,
            key=key["raw_key"],
            status=201,
        )
        assert replay["summary_receipt"]["generation"] == 3
        assert replay["inserted_raw"] == 0
        assert replay["alerts_created"] == 0
        # Explicit synthetic lease enables the actual feed for a browser check.
        sensor.request(
            "POST",
            lease_path,
            {"protocol": "sdr", "state": "running"},
            key=key["raw_key"],
        )
        expect(page.locator('[data-tab="rf"]')).to_be_visible(timeout=15000)
        page.locator('[data-tab="rf"]').click()
        expect(page.locator("#det-feed-tbody")).to_contain_text(node, timeout=20000)
    finally:
        try:
            if isinstance(key.get("raw_key"), str) and key["raw_key"]:
                sensor.request(
                    "POST",
                    lease_path,
                    {"protocol": "sdr", "state": "stopped"},
                    key=key["raw_key"],
                )
        finally:
            admin_api.request(
                "DELETE",
                f"/api/admin/keys/{key['key_id']}",
                retry_key_cleanup=True,
                stage="scanner_cleanup",
            )
            if last is not None:
                sensor.request(
                    "POST",
                    "/api/detections/ingest-summary",
                    last,
                    key=key["raw_key"],
                    status=401,
                    stage="scanner_revocation",
                )
