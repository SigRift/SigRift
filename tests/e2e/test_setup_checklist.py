"""Real lease/API/browser setup checks; no claim about physical adapter inventory."""

from pathlib import Path
import secrets
from urllib.parse import urlsplit

import pytest

from .conftest import expect


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    return {**browser_context_args, "has_touch": True}


@pytest.fixture
def quiet_setup_node(disposable, admin_api):
    node_id = "synthetic-quiet-setup-" + secrets.token_hex(5)
    admin_api.request("POST", "/api/nodes/register", {"node_id": node_id})
    try:
        yield node_id
    finally:
        # All rows/leases belong to this one disposable fixture node.
        admin_api.request("DELETE", f"/api/nodes/{node_id}", status=(200, 204))


def checklist_url(url):
    return urlsplit(url).path == "/api/nodes/setup-checklist"


def refresh(page):
    with page.expect_response(
        lambda response: response.request.method == "GET"
        and checklist_url(response.url)
    ) as result:
        page.locator("#setup-checklist-refresh").click()
    assert result.value.status == 200


def row(page, node, protocol="wifi"):
    return page.locator(
        f'#setup-checklist-rows tr[data-setup-node="{node}"][data-setup-protocol="{protocol}"]'
    )


def report(admin_api, node, state):
    return admin_api.request(
        "POST",
        f"/api/nodes/{node}/scanner-status",
        {"protocol": "wifi", "state": state},
        stage="scanner_status",
    )


@pytest.mark.disposable
def test_setup_inventory_unknown_quiet_capture_error_and_read_only_recovery(
    authenticated_page, admin_api, quiet_setup_node, output_path
):
    page = authenticated_page
    node = quiet_setup_node
    page.locator('[data-tab="summary"]').click()
    expect(page.locator("#panel-setup-checklist")).to_be_visible()
    refresh(page)
    target = row(page, node)
    expect(target).to_contain_text("Unreported — host check needed")
    expect(target).to_contain_text("Not reported")
    expect(target).to_contain_text("No stored observations")
    # A registered quiet node does not prove absent or present adapters.
    current = admin_api.request("GET", "/api/nodes/setup-checklist")
    actual = next(item for item in current["nodes"] if item["node_id"] == node)
    assert current["host_inventory"] == "per_node" and actual["scanner_status"] == {}
    assert actual["observations"]["wifi_record"]["status"] == "empty"
    assert report(admin_api, node, "running")["active"] is True
    refresh(page)
    expect(target).to_contain_text("Running — capture verified")
    expect(target).to_contain_text("No stored observations")
    expect(target).to_contain_text("Quiet air")
    # Native buttons support keyboard collapse; only this panel's preference is
    # persisted. Status keeps updating outside the hidden detail table.
    toggle = page.locator("#setup-checklist-toggle")
    expect(toggle).to_have_accessible_name("Hide details")
    toggle.focus()
    page.keyboard.press("Enter")
    expect(page.locator("#setup-checklist-body")).to_be_hidden()
    expect(toggle).to_have_attribute("aria-expanded", "false")
    expect(toggle).to_have_accessible_name("Show details")
    expect(page.locator("#setup-checklist-overview")).to_contain_text("capture")
    page.reload(wait_until="domcontentloaded")
    expect(page.locator("#setup-checklist-body")).to_be_hidden()
    expect(toggle).to_have_accessible_name("Show details")
    toggle.focus()
    page.keyboard.press("Space")
    expect(toggle).to_have_attribute("aria-expanded", "true")
    expect(toggle).to_have_accessible_name("Hide details")
    expect(page.locator("#setup-checklist-body")).to_be_visible()
    refresh(page)
    expect(target.locator('[data-check-state="running"]')).to_contain_text("Verified")
    expect(target.locator('[data-check-state="empty"]')).to_contain_text("No data yet")
    # Real disposable state: synthetic node, valid capture, no stored traffic.
    # A tall element screenshot can scroll its title behind the sticky header.
    # Frame the actual rendered panel without hiding or rewriting any UI/data.
    viewport = page.viewport_size
    assert viewport is not None
    page.set_viewport_size({**viewport, "height": 2000})
    try:
        panel = page.locator("#panel-setup-checklist")
        panel.evaluate("element => element.scrollIntoView({block: 'center'})")
        panel_box = panel.bounding_box()
        header_box = page.locator(".dashboard-header").bounding_box()
        assert panel_box and header_box
        assert panel_box["y"] >= header_box["y"] + header_box["height"]
        assert panel_box["y"] + panel_box["height"] <= 2000
        panel.screenshot(
            path=str(Path(output_path) / "synthetic-quiet-capture-checklist.png")
        )
    finally:
        page.set_viewport_size(viewport)
    report(admin_api, node, "error")
    refresh(page)
    expect(target).to_contain_text("Capture error")
    expect(target).to_contain_text("wifi-scan logs")
    report(admin_api, node, "running")
    refresh(page)
    expect(target).to_contain_text("Running — capture verified")

    # Genuine failed transport; never fabricate a successful API body or DOM.
    page.route(checklist_url, lambda route: route.abort())
    page.locator("#setup-checklist-refresh").click()
    expect(page.locator("#setup-checklist-status")).to_contain_text("Refresh failed")
    expect(target).to_contain_text("Running — capture verified")
    page.unroute(checklist_url)
    refresh(page)
    expect(page.locator("#setup-checklist-status")).not_to_contain_text(
        "Refresh failed"
    )
    expect(target).to_contain_text("Running — capture verified")

    help_button = page.get_by_role(
        "button", name="About Setup and capture checklist", exact=True
    )
    help_button.focus()
    tip = page.get_by_role("tooltip")
    expect(tip).to_be_visible()
    expect(tip).to_contain_text("cannot inspect or change host permissions")
    page.keyboard.press("Escape")
    expect(tip).to_be_hidden()
    expect(help_button).to_be_focused()
    help_button.tap()
    expect(tip).to_be_visible()
    expect(tip).to_contain_text("A running capture can be quiet")
    page.keyboard.press("Escape")
    report(admin_api, node, "stopped")
    refresh(page)
    expect(target).to_contain_text("Stopped")
    expect(target).to_contain_text("No stored observations")


@pytest.mark.disposable
@pytest.mark.timeout(180)
def test_setup_capture_expires_during_real_network_loss_then_renews(
    authenticated_page, admin_api, quiet_setup_node
):
    page = authenticated_page
    node = quiet_setup_node
    page.locator('[data-tab="summary"]').click()
    report(admin_api, node, "running")
    refresh(page)
    target = row(page, node)
    expect(target).to_contain_text("Running — capture verified")
    # Leave real server-issued120s lease and real monotonic timer unchanged.
    page.route(checklist_url, lambda route: route.abort())
    try:
        page.locator("#setup-checklist-refresh").click()
        expect(page.locator("#setup-checklist-status")).to_contain_text(
            "Refresh failed"
        )
        expect(target).to_contain_text("Report expired / unconfirmed", timeout=130000)
        expect(target).to_contain_text("No stored observations")
        result = admin_api.request("GET", "/api/nodes/setup-checklist")
        current = next(item for item in result["nodes"] if item["node_id"] == node)
        assert current["scanner_status"]["wifi"]["active"] is False
        assert current["scanner_status"]["wifi"]["expires_in_seconds"] == 0
    finally:
        page.unroute(checklist_url)
    report(admin_api, node, "running")
    refresh(page)
    expect(target).to_contain_text("Running — capture verified")
    expect(page.locator("#setup-checklist-status")).not_to_contain_text(
        "Refresh failed"
    )


@pytest.mark.disposable
def test_authenticated_host_checks_show_missing_blocked_ready_without_claiming_capture(
    authenticated_page, admin_api, quiet_setup_node, settings
):
    """Synthetic host receipts travel through real auth/API; no physical probe claim."""
    from .conftest import Client

    node = quiet_setup_node
    page = authenticated_page
    page.locator('[data-tab="summary"]').click()
    worker = Client(settings)
    keys = []
    body = {
        "sdr": {
            "adapter": "unknown",
            "selection": "not_selected",
            "reason": "not_checked",
        },
        "wifi": {
            "adapter": "missing",
            "selection": "selected",
            "reason": "selected_absent",
        },
    }
    path = f"/api/nodes/{node}/setup-readiness"
    try:
        for role in ("sensor", "node"):
            key = admin_api.request(
                "POST",
                "/api/admin/keys",
                {
                    "description": "disposable synthetic host check",
                    "role": role,
                    "node_id": node,
                },
                status=201,
                retry_key_creation=True,
                stage="scanner_key",
            )
            keys.append(key)
            assert isinstance(key.get("key_id"), str) and key["key_id"]
            assert isinstance(key.get("raw_key"), str) and key["raw_key"]
            result = worker.request("POST", path, body, key=key["raw_key"])
            assert result["fresh"] is True and result["expires_in_seconds"] == 300
            refresh(page)
            target = row(page, node)
            expect(target).to_contain_text("Selected adapter missing")
            expect(target).to_contain_text("Reconnect the saved adapter")
            expect(target).to_contain_text("Not reported")
            expect(target).to_contain_text("No stored observations")
            worker.request(
                "POST",
                f"/api/nodes/{node}-other/setup-readiness",
                body,
                key=key["raw_key"],
                status=403,
            )
        key = keys[-1]
        body["wifi"].update(adapter="blocked", reason="permissions")
        worker.request("POST", path, body, key=key["raw_key"])
        refresh(page)
        expect(target).to_contain_text("Scanner permissions missing")
        expect(target).to_contain_text("This page cannot change permissions")
        body["wifi"].update(adapter="ready", reason="checked")
        worker.request("POST", path, body, key=key["raw_key"])
        refresh(page)
        expect(target).to_contain_text("Ready when checked · saved choice")
        expect(target).to_contain_text("Not reported")
        assert report(admin_api, node, "running")["active"] is True
        refresh(page)
        expect(target).to_contain_text("Running — capture verified")
        expect(target).to_contain_text("No stored observations")
        expect(target).to_contain_text("Quiet air")
        # Refresh reads stored evidence only; it does not manufacture another
        # host check or require a host/root command from the browser.
        before = admin_api.request("GET", "/api/nodes/setup-checklist")
        first = next(item for item in before["nodes"] if item["node_id"] == node)
        refresh(page)
        after = admin_api.request("GET", "/api/nodes/setup-checklist")
        last = next(item for item in after["nodes"] if item["node_id"] == node)
        assert (
            first["setup_readiness"]["checked_at"]
            == last["setup_readiness"]["checked_at"]
        )
    finally:
        for key in keys:
            admin_api.request(
                "DELETE",
                f"/api/admin/keys/{key['key_id']}",
                retry_key_cleanup=True,
                stage="scanner_cleanup",
            )
            if key.get("raw_key"):
                worker.request(
                    "POST",
                    path,
                    body,
                    key=key["raw_key"],
                    status=401,
                    stage="scanner_revocation",
                )
