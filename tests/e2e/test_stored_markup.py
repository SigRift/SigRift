"""Hostile stored text renders as inert text in the real dashboard and admin.

Edge nodes, radio neighbours and other administrators all write text the
pages later show: a node's host and its heartbeat's hardware, agent and
signal-class names; Bluetooth device names and manufacturers; an API key's
description and the audit entry that records it. Each case stores markup
through the public API (or the admin form), then opens the deployed pages
through the gateway, with its real CSP, and requires the text to be on the
page while no element it carried exists and none of its handlers ran.
Alert messages and notes are covered by test_alert_text.py.

Bluetooth text goes in through /api/bluetooth/ingest-summary, the route
the shipped scanner (sigrift.lib.bt_scanner) posts to, which stores it as
sent, so the page's own escaping is what is under test. Every radio ingest
route now stores names as heard, Wi-Fi SSIDs included;
tests/bridge/js/wifi_rendering.test.cjs and radio_text_markup.test.cjs cover
how wifi.js renders a hostile SSID.
"""

from __future__ import annotations

import re
import secrets
from urllib.parse import urlsplit

import pytest

from .conftest import expect, expect_admin_ready, expect_dashboard, navigate

FLAG = "__e2eStoredMarkupRan"
MARKUP = f"<img src=x onerror=window.{FLAG}=1><svg onload=window.{FLAG}=1></svg>"


def payload(label, *, quotes=True):
    """Visible *label*, then markup whose handlers would set the page flag."""
    return f"{label} {MARKUP} &amp;" + (" \"'" if quotes else "")


def assert_inert(page, *rows):
    """No element *rows* show carries a handler from the markup; none ran.

    Scoped to this test's own rows: Bluetooth devices outlive their node,
    so a table can still list an earlier run's hostile device.
    """
    for row in rows:
        handlers = row.locator(
            f'[onerror*="{FLAG}"], [onload*="{FLAG}"], [onmouseover*="{FLAG}"]'
        )
        expect(handlers).to_have_count(0)
    assert page.evaluate(f"window.{FLAG} || 0") == 0, "Stored markup ran"


@pytest.fixture
def markup_node(disposable, disposable_admin):
    """Register one node; ``report(**fields)`` sends its heartbeat.

    Sent with the admin's own session, which may act for any node: the
    pages render what a node key could send in the same fields.
    """
    api = disposable_admin.client
    suffix = secrets.token_hex(3)
    node_id = "e2e-markup-" + suffix
    leases = []

    def report(*, host, hardware, agent, signal_class, cpu_temp=None):
        api.request(
            "POST",
            "/api/nodes/register",
            {"node_id": node_id, "host": host, "capabilities": {"test_fixture": True}},
        )
        metrics = {"agent_version": agent, "hardware": hardware}
        if cpu_temp is not None:
            metrics["cpu_temp"] = cpu_temp
        accepted = api.request(
            "POST",
            "/api/nodes/heartbeat",
            {
                "node_id": node_id,
                "metrics": metrics,
                "detection_summary": {
                    "period_seconds": 60,
                    "total_detections": 3,
                    "class_counts": {signal_class: 3},
                },
            },
        )
        assert accepted["accepted"] is True

    def bluetooth(name, manufacturer):
        """Report one BLE device the way the shipped scanner does."""
        mac = "02:e2:" + ":".join(suffix[i : i + 2] for i in range(0, 6, 2)) + ":01"
        result = api.request(
            "POST",
            "/api/bluetooth/ingest-summary",
            {
                "node_id": node_id,
                "scan_period_s": 30,
                "total_observations": 1,
                "devices": [
                    {
                        "device_addr": mac,
                        "device_name": name,
                        "device_type": "ble",
                        "manufacturer": manufacturer,
                        # Strongest on the stack: the table shows the
                        # strongest twenty first.
                        "rssi_avg_dbm": -20,
                        "rssi_max_dbm": -20,
                        "observation_count": 1,
                    }
                ],
            },
            status=201,
        )
        assert result["inserted"] == 1
        # A live scanner lease makes the Bluetooth tab available.
        leases.append("bluetooth")
        api.request(
            "POST",
            f"/api/nodes/{node_id}/scanner-status",
            {"protocol": "bluetooth", "state": "running"},
            stage="scanner_status",
        )
        return mac

    try:
        yield {
            "node_id": node_id,
            "suffix": suffix,
            "report": report,
            "bluetooth": bluetooth,
            "api": api,
        }
    finally:
        for protocol in leases:
            api.request(
                "POST",
                f"/api/nodes/{node_id}/scanner-status",
                {"protocol": protocol, "state": "stopped"},
                status=(200, 404),
                stage="scanner_status",
            )
        api.request("DELETE", f"/api/nodes/{node_id}", status=(200, 204, 404))


def open_dashboard(page, settings, api):
    page.context.add_cookies(api.browser_cookies())
    with page.expect_response(
        lambda response: urlsplit(response.url).path == "/api/nodes/"
    ) as nodes:
        navigate(page, settings.base_url + "/dashboard")
        expect_dashboard(page)
    assert nodes.value.status == 200
    # The table is drawn from that answer; this waits for the drawing only.


def node_row(page, node_id):
    row = page.locator("#nodes-tbody tr").filter(has_text=node_id)
    expect(row).to_have_count(1)
    return row


def bluetooth_row(page, mac, suffix):
    page.locator('[data-tab="bluetooth"]').click()
    # The table lists the strongest twenty; devices outlive their node, so
    # search for this one by the suffix its name and manufacturer carry.
    page.locator("#bt-manufacturer-search").fill(suffix)
    device = page.locator(f'#bt-device-tbody tr[data-addr="{mac}"]')
    expect(device).to_have_count(1)
    return device


@pytest.mark.disposable
def test_hostile_node_and_radio_text_is_inert_on_dashboard_and_admin(
    page, settings, markup_node
):
    node_id, suffix, api = (markup_node[k] for k in ("node_id", "suffix", "api"))
    text = {
        "host": payload(f"host-{suffix}"),
        "agent": payload(f"agent-{suffix}"),
        # Quotes are left out of the fields the dashboard also puts in an
        # attribute; the attribute cases are the tests below.
        "hardware": payload(f"radio-{suffix}", quotes=False),
        # Markup first, so the bar's shortened label carries some too.
        "signal_class": f"<b>{suffix}</b>" + payload("", quotes=False),
    }
    markup_node["report"](**text)
    name = payload(f"bt-{suffix}", quotes=False)
    manufacturer = payload(f"maker-{suffix}")
    mac = markup_node["bluetooth"](name, manufacturer)

    open_dashboard(page, settings, api)
    row = node_row(page, node_id)
    for field in ("host", "agent", "hardware"):
        expect(row).to_contain_text(text[field])
    bar = row.locator(".node-class-bar")
    expect(bar).to_have_attribute("title", re.compile(re.escape(text["signal_class"])))
    expect(bar).to_contain_text(f"<b>{suffix}")
    expect(bar.locator("b")).to_have_count(0)
    assert_inert(page, row)

    device = bluetooth_row(page, mac, suffix)
    expect(device.locator("td").nth(1)).to_have_text(name)
    expect(device.locator("td").nth(3)).to_have_text(manufacturer)
    assert_inert(page, device)

    # The admin page's Nodes tab renders the same registration (admin.js).
    navigate(page, settings.base_url + "/admin")
    expect_admin_ready(page, settings)
    page.locator("#nodes-link").click()
    admin_row = page.locator("#admin-nodes-tbody tr").filter(has_text=node_id)
    expect(admin_row.locator('[data-label="Host"]')).to_have_text(text["host"])
    assert_inert(page, admin_row)


@pytest.mark.disposable
def test_node_reported_text_cannot_add_attributes_on_dashboard(
    page, settings, markup_node
):
    suffix = markup_node["suffix"]
    breakout = f'" onmouseover="window.{FLAG}=1" data-e2e="'
    hardware, signal_class = f"radio-{suffix}{breakout}", f"class-{suffix}{breakout}"
    markup_node["report"](
        host="host-" + suffix,
        agent="agent-" + suffix,
        hardware=hardware,
        signal_class=signal_class,
    )
    open_dashboard(page, settings, markup_node["api"])
    row = node_row(page, markup_node["node_id"])
    assert_inert(page, row)
    expect(row.locator(".node-status-compact")).to_have_attribute(
        "title", re.compile(re.escape(hardware))
    )
    expect(row.locator(".node-class-bar")).to_have_attribute(
        "title", re.compile(re.escape(signal_class))
    )


@pytest.mark.disposable
def test_bluetooth_name_cannot_add_attributes_on_dashboard(page, settings, markup_node):
    suffix = markup_node["suffix"]
    name = f'bt-{suffix}" onmouseover="window.{FLAG}=1" data-e2e="'
    markup_node["report"](
        host="host-" + suffix,
        agent="agent-" + suffix,
        hardware="radio-" + suffix,
        signal_class="bpsk",
    )
    mac = markup_node["bluetooth"](name, "maker-" + suffix)
    open_dashboard(page, settings, markup_node["api"])
    device = bluetooth_row(page, mac, suffix)
    assert_inert(page, device)
    expect(device.locator("td").nth(1)).to_have_text(name)


@pytest.mark.disposable
def test_node_reported_non_numeric_temperature_keeps_the_node_table(
    page, settings, markup_node
):
    suffix = markup_node["suffix"]
    markup_node["report"](
        host="host-" + suffix,
        agent="agent-" + suffix,
        hardware="radio-" + suffix,
        signal_class="bpsk",
        cpu_temp="hot",
    )
    open_dashboard(page, settings, markup_node["api"])
    row = node_row(page, markup_node["node_id"])
    expect(row).to_contain_text("radio-" + suffix)


def _create_key_in_admin_form(page, description):
    with page.expect_response(
        lambda response: urlsplit(response.url).path == "/api/admin/keys"
        and response.request.method == "POST"
    ) as created:
        page.locator("#new-key-desc").fill(description)
        page.locator("#new-key-role").select_option("viewer")
        page.locator("#create-key-btn").click()
    assert created.value.status == 201, created.value.status
    key_id = created.value.json()["key_id"]
    # The raw key is revealed once; acknowledge and close the dialog.
    page.locator("#admin-rawkey-ack").check()
    page.get_by_role("button", name="Done").click()
    expect(page.locator("#admin-rawkey-code")).to_have_count(0)
    return key_id


@pytest.mark.disposable
def test_hostile_key_description_is_inert_in_key_table_and_audit_log(
    page, settings, disposable_admin
):
    api = disposable_admin.client
    label = "key-" + secrets.token_hex(4)
    description = payload(label)
    key_id = None
    page.context.add_cookies(api.browser_cookies())
    try:
        navigate(page, settings.base_url + "/admin")
        expect_admin_ready(page, settings)
        key_id = _create_key_in_admin_form(page, description)

        row = page.locator("#keys-tbody tr").filter(has_text=key_id)
        expect(row.locator('[data-label="Desc"]')).to_have_text(description)
        assert_inert(page, row)

        # The audit log records the description: a shortened preview in its
        # row, and the full entry in the detail dialog. Both show the start
        # of the markup as text.
        page.locator("#audit-link").click()
        entry = (
            page.locator("#audit-tbody tr")
            .filter(has_text=key_id)
            .filter(has_text="admin_create_key")
        )
        expect(entry).to_have_count(1, timeout=15_000)
        expect(entry.locator('[data-label="Details"]')).to_contain_text(f"{label} <img")
        assert_inert(page, entry)
        entry.get_by_role("button", name="View").click()
        detail = page.locator("#audit-detail-body")
        expect(detail).to_contain_text(f"{label} {MARKUP} &amp;")
        assert_inert(page, detail)
    finally:
        keys = (
            [key_id]
            if key_id
            else [
                key["key_id"]
                for key in api.request("GET", "/api/admin/keys")
                if key.get("description") == description
            ]
        )
        for owned in keys:
            api.request(
                "DELETE",
                f"/api/admin/keys/{owned}",
                status=(200, 404),
                retry_key_cleanup=True,
            )
