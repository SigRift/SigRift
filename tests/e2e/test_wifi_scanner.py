"""Synthetic Wi-Fi ingest-to-browser coverage; no physical capture claim."""

import re
import time

import pytest
from .conftest import expect


@pytest.mark.disposable
def test_synthetic_wifi_ingest_reaches_api_and_visible_table(
    synthetic_scanner, admin_api, authenticated_page, scanner_lease
):
    payload = admin_api.request("GET", "/api/wifi/networks")
    networks = payload["networks"]
    assert isinstance(networks, list)
    assert payload["count"] == len(networks)
    matches = [n for n in networks if n["ssid"] == synthetic_scanner["ssid"]]
    assert len(matches) == 1, "One aggregate per synthetic BSSID is required"
    network = matches[0]
    assert network["avg_signal_dbm"] == -45
    assert network["client_count"] == 0
    assert network["frame_count"] == 1
    assert network["last_seen"]
    assert synthetic_scanner["node_id"] in network["node_ids"]
    # These filters were silently ignored by the old gateway shadow route.
    other_band = admin_api.request("GET", "/api/wifi/networks?band=5GHz")
    assert all(n["ssid"] != synthetic_scanner["ssid"] for n in other_band["networks"])
    other_node = admin_api.request("GET", "/api/wifi/networks?node_id=missing-e2e-node")
    assert other_node == {"count": 0, "networks": []}
    # Earlier dashboard flows may have populated this aggregate before
    # ingest. Production intentionally retains it for at most 30 seconds.
    # Require the exact new node to appear within a bounded cache window.
    deadline = time.monotonic() + 40
    while True:
        stats = admin_api.request("GET", "/api/wifi/stats")
        if synthetic_scanner["node_id"] in stats.get("wifi_node_ids", []):
            break
        assert time.monotonic() < deadline, (
            "Synthetic Wi-Fi node did not reach aggregate stats within 40 seconds"
        )
        time.sleep(1)
    assert stats["total_networks"] >= 1
    assert isinstance(stats["total_clients"], int)
    assert stats["band_breakdown"]["2.4GHz"]["network_count"] >= 1
    assert synthetic_scanner["node_id"] in stats["wifi_node_ids"]
    anomaly_count = stats["anomaly_count"]
    assert type(anomaly_count) is int and anomaly_count >= 0
    anomalies = admin_api.request("GET", "/api/wifi/anomalies?min_score=0.3&limit=1")
    assert anomalies["total"] == anomaly_count
    page = authenticated_page
    with scanner_lease("wifi"):
        expect(page.locator('[data-tab="wifi"]')).to_be_visible(timeout=15000)
        # Observe Summary before ever opening Wi-Fi: its own 30-second poll
        # must display the real active queue total, including numeric zero.
        expect(page.locator("#tab-summary")).to_be_visible()
        expect(page.locator("#summary-wifi")).to_be_visible()
        expect(page.locator("#sum-wifi-anomalies")).to_have_text(
            str(anomaly_count), timeout=45000
        )
        page.locator('[data-tab="wifi"]').click()
        expect(page.locator("#wifi-network-tbody")).to_contain_text(
            synthetic_scanner["ssid"], timeout=20000
        )
        row = page.locator(".wifi-net-row").filter(has_text=synthetic_scanner["ssid"])
        expect(row.locator("td").nth(6)).to_have_text("-45 dBm")
        expect(row.locator("td").nth(7)).to_have_text("0")
        expect(row.locator("td").nth(8)).to_have_text(re.compile(r"\d"))
        expect(page.locator("#wifi-stat-networks")).to_have_text(
            str(stats["total_networks"])
        )
        expect(page.locator("#wifi-stat-clients")).to_have_text(
            str(stats["total_clients"])
        )


@pytest.mark.disposable
def test_wifi_navigation_requires_node_bound_live_status(
    authenticated_page, admin_api, synthetic_scanner, scanner_lease, settings
):
    from .conftest import Client

    page = authenticated_page
    expect(page.locator('[data-tab="wifi"]')).to_be_hidden()
    # Actual gateway auth failures cannot create another node's lease.
    other = synthetic_scanner["node_id"] + "-other"
    admin_api.request("POST", "/api/nodes/register", {"node_id": other})
    synthetic_scanner["report"]("wifi", "running", target=other, status=403)
    Client(settings).request(
        "POST",
        f"/api/nodes/{synthetic_scanner['node_id']}/scanner-status",
        {"protocol": "wifi", "state": "running"},
        status=401,
        stage="scanner_status",
    )
    with scanner_lease("wifi"):
        expect(page.locator('[data-tab="wifi"]')).to_be_visible(timeout=15000)
        page.locator('[data-tab="wifi"]').click()
        expect(page.locator("#panel-wifi")).to_be_visible()
        expect(page.locator("#wifi-stats-bar")).to_be_visible()
        # No dedicated Bluetooth/Zigbee/ADS-B producer is running in this stack.
        for tab in ("bluetooth", "zigbee", "adsb"):
            expect(page.locator(f'[data-tab="{tab}"]')).to_be_hidden()
    expect(page.locator('[data-tab="wifi"]')).to_be_hidden(timeout=15000)
    expect(page.locator("#tab-summary")).to_be_visible()
