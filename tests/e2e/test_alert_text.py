"""Encoded alert fields become literal visible text, never executable markup."""

import html
import secrets
import time

import pytest

from .conftest import expect, expect_admin_ready, navigate


def _assert_markup_is_inert(page):
    expect(page.locator('[onerror*="__alertTextExecuted"]')).to_have_count(0)
    expect(page.locator('[onload*="__alertTextExecuted"]')).to_have_count(0)
    assert page.evaluate("window.__alertTextExecuted || 0") == 0


@pytest.mark.disposable
def test_alert_messages_and_ack_notes_are_literal_text(
    authenticated_page, settings, admin_api, disposable
):
    page = authenticated_page
    suffix = secrets.token_hex(5)
    name = (
        f"E2E '{suffix}' <img src=x onerror=window.__alertTextExecuted=1> &amp; &#x27;"
    )
    message = f"Alert rule '{name}' created"
    note = f"Checked '{suffix}' <svg onload=window.__alertTextExecuted=1> &amp; &lt;safe&gt;"
    alert = admin_api.request(
        "POST", "/api/alerts/rules", {"name": name, "severity": "warning"}, status=201
    )
    alert_id = alert["alert_id"]
    try:
        assert alert["message"] == html.escape(message)
        acknowledged = admin_api.request(
            "PUT", f"/api/alerts/{alert_id}/ack", {"note": note}
        )
        assert acknowledged["ack_note"] == html.escape(note)
        navigate(page, settings.base_url + "/dashboard")
        page.locator('[data-tab="summary"]').click()
        page.locator("#alert-hide-acked").uncheck()
        row = page.locator("#alerts-list .alert-item").filter(has_text=message)
        expect(row.locator(".alert-msg")).to_have_text(message)
        expect(row.locator(".alert-msg")).to_be_visible()
        expect(row.locator(".ack-note")).to_have_text('"' + note + '"')
        _assert_markup_is_inert(page)
        page.locator('[data-tab="alerts"]').click()
        page.locator("#alerts-tab-hide-acked").uncheck()
        dedicated = page.locator("#alerts-tab-tbody tr").filter(has_text=message)
        expect(dedicated.locator(".alert-msg-cell")).to_have_text(message)
        expect(dedicated.locator(".alert-msg-cell")).to_be_visible()
        _assert_markup_is_inert(page)
        # The top timeline describes the actual stored alert literally and opens
        # its already-loaded Alerts row without a new filter/deep-link contract.
        page.locator('[data-tab="summary"]').click()
        canvas = page.locator("#threat-timeline-canvas")
        canvas.scroll_into_view_if_needed()
        point = None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            point = page.evaluate(
                """id => {
                    const canvas = document.getElementById('threat-timeline-canvas');
                    const box = canvas.getBoundingClientRect();
                    const point = window.dashboard._tlPoints.find(p => p.event.alertId === id);
                    if (!point) return null;
                    return {x: box.left + point.x * box.width / canvas.width,
                            y: box.top + point.y * box.height / canvas.height};
                }""",
                alert_id,
            )
            if point is not None:
                break
            time.sleep(0.1)
        assert point is not None, "The real recent alert must appear on the timeline"
        # Several recent alerts can occupy the same screen pixel. Traverse the
        # actual keyboard selection to this exact stored alert without changing
        # the timeline's events, drawing coordinates, or visible text.
        canvas.focus()
        alert_count = page.evaluate(
            "window.dashboard._tlPoints.filter(p => p.event.protocol === 'alert').length"
        )
        assert 0 < alert_count <= 200, "Timeline navigation must remain bounded"
        selected = (
            "window.dashboard._tlSelected && window.dashboard._tlSelected.event.alertId"
        )
        for _ in range(alert_count):
            if page.evaluate(selected) == alert_id:
                break
            canvas.press("ArrowRight")
        assert page.evaluate(selected) == alert_id
        expect(page.locator("#threat-timeline-summary")).to_contain_text(message)
        _assert_markup_is_inert(page)
        canvas.press("Enter")
        expect(page.locator('[data-tab="alerts"]')).to_have_attribute(
            "aria-selected", "true"
        )
        expect(dedicated).to_be_focused()
        navigate(page, settings.base_url + "/admin")
        expect_admin_ready(page, settings)
        page.locator("#alerts-link").click()
        admin_row = page.locator("#admin-alerts-tbody tr").filter(has_text=alert_id)
        expect(admin_row.locator('[data-label="Message"]')).to_have_text(message)
        expect(admin_row.locator('[data-label="Message"]')).to_be_visible()
        # Mixed-origin alert.name deliberately retains its existing contract.
        expect(admin_row.locator('[data-label="Name"]')).to_have_text(html.escape(name))
        _assert_markup_is_inert(page)
    finally:
        admin_api.request("DELETE", f"/api/alerts/rules/{alert_id}")
