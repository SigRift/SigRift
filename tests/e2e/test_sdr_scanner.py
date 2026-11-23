"""Synthetic RF ingest-to-browser coverage; physical SDR capture is separate."""

import re
import time

import pytest
from .conftest import expect


@pytest.mark.disposable
def test_synthetic_detection_reaches_api_and_visible_feed(
    authenticated_page, admin_api, synthetic_scanner, scanner_lease
):
    fresh_id = synthetic_scanner["observe_rf"]()
    payload = admin_api.request("GET", "/api/detections/recent?limit=100")
    detections = payload["detections"]
    assert isinstance(detections, list)
    assert payload["count"] == len(detections)
    matches = [item for item in detections if item["detection_id"] == fresh_id]
    assert len(matches) == 1
    assert matches[0]["node_id"] == synthetic_scanner["node_id"]
    assert matches[0]["freq_hz"] == 433920000
    stats = admin_api.request("GET", "/api/detections/stats")
    frequency_count = stats["active_frequencies"]
    assert type(frequency_count) is int and frequency_count > 0
    page = authenticated_page
    with scanner_lease("sdr"):
        expect(page.locator('[data-tab="rf"]')).to_be_visible(timeout=15000)
        page.locator('[data-tab="rf"]').click()
        # Require the server's complete last-hour count on initial activation;
        # opening a feed page or changing range controls must not be necessary.
        expect(page.locator("#det-kpi-freqs")).to_have_text(
            str(frequency_count), timeout=20000
        )
        # The table groups rows, so also require this exact new record in the
        # shipped controller's displayed feed. evaluate uses no string eval.
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if page.evaluate(
                "id => { const d = window.dashboard.detectionDashboard; "
                "return !!d && Array.isArray(d.feed) && "
                "d.feed.some(row => row.detection_id === id); }",
                fresh_id,
            ):
                break
            time.sleep(0.2)
        else:
            raise AssertionError("Fresh authenticated detection did not reach the feed")
        expect(page.locator("#det-feed-tbody")).to_contain_text(
            synthetic_scanner["node_id"], timeout=20000
        )


@pytest.mark.disposable
def test_sdr_views_require_a_live_scanner_and_stop_without_losing_history(
    authenticated_page, admin_api, synthetic_scanner, scanner_lease, output_path
):
    from pathlib import Path

    stored_before = admin_api.request(
        "GET", "/api/detections/" + synthetic_scanner["detection_id"]
    )
    assert stored_before["detection_id"] == synthetic_scanner["detection_id"]
    page = authenticated_page
    snapshots = Path(output_path)
    snapshots.mkdir(parents=True, exist_ok=True)
    tabs = ("rf", "spectrum-analysis", "drone", "iot")
    for tab in tabs:
        expect(page.locator(f'[data-tab="{tab}"]')).to_be_hidden()
    for protocol in ("sdr", "wifi", "bluetooth", "zigbee"):
        expect(page.locator(f"#summary-{protocol}")).to_be_hidden()
    for generic in ("stat-nodes", "stat-alerts", "panel-nodes", "panel-alerts"):
        expect(page.locator(f"#{generic}")).to_be_visible()
    page.locator("#dashboard-tabs").screenshot(
        path=str(snapshots / "synthetic-scanner-tabs-idle.png")
    )
    with scanner_lease("sdr"):
        for tab in tabs:
            expect(page.locator(f'[data-tab="{tab}"]')).to_be_visible(timeout=15000)
        expect(page.locator("#summary-sdr")).to_be_visible(timeout=15000)
        for protocol in ("wifi", "bluetooth", "zigbee"):
            expect(page.locator(f"#summary-{protocol}")).to_be_hidden()
        page.locator("#dashboard-tabs").screenshot(
            path=str(snapshots / "synthetic-scanner-tabs-sdr.png")
        )
        page.locator('[data-tab="rf"]').click()
        expect(page.locator("#panel-detections")).to_be_visible()
        page.locator('[data-tab="spectrum-analysis"]').click()
        expect(page.locator("#tab-spectrum-analysis")).to_be_visible()
    for tab in tabs:
        expect(page.locator(f'[data-tab="{tab}"]')).to_be_hidden(timeout=15000)
    expect(page.locator("#tab-summary")).to_be_visible()
    expect(page.locator("#summary-sdr")).to_be_hidden()
    # Stored RF history and general health remain available after capture stops.
    for generic in (
        "stat-nodes",
        "stat-alerts",
        "panel-nodes",
        "panel-alerts",
        "panel-active-freqs",
    ):
        expect(page.locator(f"#{generic}")).to_be_visible()
    # Synthetic authenticated reports exercise the formerly always-visible
    # Bluetooth/Zigbee groups without claiming physical adapters are present.
    with scanner_lease("bluetooth"), scanner_lease("zigbee"):
        for protocol in ("bluetooth", "zigbee"):
            expect(page.locator(f"#summary-{protocol}")).to_be_visible(timeout=15000)
            expect(page.locator(f'[data-tab="{protocol}"]')).to_be_visible()
        expect(page.locator("#summary-wifi")).to_be_hidden()
        expect(page.locator("#summary-sdr")).to_be_hidden()
    for protocol in ("bluetooth", "zigbee"):
        expect(page.locator(f"#summary-{protocol}")).to_be_hidden(timeout=15000)
    # The unavailable saved/deep link cannot open a hidden scanner panel.
    page.evaluate("window.dashboard.activateTab('spectrum-analysis')")
    expect(page.locator("#tab-summary")).to_be_visible()
    stored_after = admin_api.request(
        "GET", "/api/detections/" + synthetic_scanner["detection_id"]
    )
    assert stored_after == stored_before


@pytest.mark.disposable
def test_sensor_key_can_report_only_its_bound_scanner_and_cannot_renew_after_revocation(
    synthetic_scanner, admin_api, settings, authenticated_page
):
    """The installed hardware uses SENSOR; do not upgrade it to mask a route failure."""
    from .conftest import Client

    page = authenticated_page
    expect(page.locator('[data-tab="rf"]')).to_be_hidden()
    node_id = synthetic_scanner["node_id"]
    other = node_id + "-sensor-other"
    admin_api.request("POST", "/api/nodes/register", {"node_id": other})
    sensor = Client(settings)
    key = admin_api.request(
        "POST",
        "/api/admin/keys",
        {
            "description": "disposable SENSOR lease proof",
            "role": "sensor",
            "node_id": node_id,
        },
        status=201,
        retry_key_creation=True,
        stage="scanner_key",
    )
    path = f"/api/nodes/{node_id}/scanner-status"
    running = {"protocol": "sdr", "state": "running"}
    try:
        assert isinstance(key.get("key_id"), str) and key["key_id"]
        assert isinstance(key.get("raw_key"), str) and key["raw_key"]
        result = sensor.request(
            "POST", path, running, key=key["raw_key"], stage="scanner_status"
        )
        assert result["active"] is True and result["expires_in_seconds"] == 120
        expect(page.locator('[data-tab="rf"]')).to_be_visible(timeout=15000)
        page.locator('[data-tab="rf"]').click()
        expect(page.locator("#panel-detections")).to_be_visible()
        # A real authenticated capture failure hides the unavailable tab but
        # remains visible globally; a fresh running report alone clears it.
        failed = sensor.request(
            "POST",
            path,
            {"protocol": "sdr", "state": "error"},
            key=key["raw_key"],
            stage="scanner_status",
        )
        assert failed["active"] is False
        expect(page.locator('[data-tab="rf"]')).to_be_hidden(timeout=15000)
        # Other protocols on the same session-scoped node may also be stopped.
        # Keep those warnings visible and select this exact node's SDR report.
        warning = page.locator("#scanner-warning-list li").filter(
            has=page.locator("strong").filter(
                has_text=re.compile(r"^" + re.escape(node_id) + r" · SDR — ")
            )
        )
        expect(page.locator("#scanner-warning")).to_be_visible()
        expect(warning).to_contain_text("SDR — Capture error reported")
        expect(warning).to_contain_text("adapter connection")
        page.locator('[data-tab="alerts"]').click()
        expect(warning).to_be_visible()
        page.locator("#scanner-warning-setup").click()
        expect(page.locator("#tab-summary")).to_be_visible()
        expect(page.locator("#panel-setup-checklist")).to_be_in_viewport()
        renewed = sensor.request(
            "POST", path, running, key=key["raw_key"], stage="scanner_status"
        )
        assert renewed["active"] is True
        expect(page.locator('[data-tab="rf"]')).to_be_visible(timeout=15000)
        expect(warning).to_have_count(0)
        page.locator('[data-tab="rf"]').click()
        sensor.request(
            "POST",
            f"/api/nodes/{other}/scanner-status",
            running,
            key=key["raw_key"],
            status=403,
            stage="scanner_status",
        )
        result = sensor.request(
            "POST",
            path,
            {"protocol": "sdr", "state": "stopped"},
            key=key["raw_key"],
            stage="scanner_status",
        )
        assert result["active"] is False and result["expires_in_seconds"] == 0
        expect(page.locator('[data-tab="rf"]')).to_be_hidden(timeout=15000)
        expect(page.locator("#tab-summary")).to_be_visible()
        expect(warning).to_contain_text("SDR — Scanner stopped")
    finally:
        admin_api.request(
            "DELETE",
            f"/api/admin/keys/{key['key_id']}",
            retry_key_cleanup=True,
            stage="scanner_cleanup",
        )
        sensor.request(
            "POST",
            path,
            running,
            key=key["raw_key"],
            status=401,
            stage="scanner_revocation",
        )
