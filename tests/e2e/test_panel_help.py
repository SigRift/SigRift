"""Real panel help interactions; screenshot contains authored explanation only."""

from pathlib import Path

import pytest

from .conftest import expect


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    # Exercise real touch events as well as keyboard and mouse on this page.
    return {**browser_context_args, "has_touch": True}


def test_dashboard_and_admin_help_support_keyboard_and_tap_without_collapsing(
    authenticated_page, output_path
):
    page = authenticated_page
    # Help must not change the text labels used by existing freshness lookup.
    assert page.evaluate(
        "['SDR', 'Wi-Fi', 'Bluetooth SIGINT', 'Zigbee'].every(label => "
        "window.dashboard._findSummaryGroup(label) !== null)"
    )
    button = page.get_by_role("button", name="About Edge Nodes", exact=True)
    button.scroll_into_view_if_needed()
    card = button.locator(
        "xpath=ancestor::*[contains(concat(' ',normalize-space(@class),' '),' card ')][1]"
    )
    before = card.get_attribute("class")
    button.focus()
    tip = page.get_by_role("tooltip")
    expect(tip).to_be_visible()
    expect(tip).to_contain_text("Online means the node is checking in")
    expect(button).to_have_attribute("aria-describedby", "panel-help-tooltip")
    page.keyboard.press("Escape")
    expect(tip).to_be_hidden()
    expect(button).to_be_focused()
    button.press("Enter")
    expect(tip).to_be_visible()
    expect(card).to_have_attribute("class", before)
    snapshots = Path(output_path)
    snapshots.mkdir(parents=True, exist_ok=True)
    tip.screenshot(path=str(snapshots / "synthetic-panel-help.png"))
    button.click()
    expect(tip).to_be_hidden()
    button.hover()
    # Move away and back so this is a real new pointer entry after the click.
    page.locator("#dashboard-tabs").hover()
    button.hover()
    expect(tip).to_be_visible()
    tip.hover()
    expect(tip).to_be_visible()
    page.keyboard.press("Escape")
    expect(tip).to_be_hidden()
    page.goto("/admin")
    admin_help = page.get_by_role("button", name="About API Key Management", exact=True)
    admin_help.tap()
    tip = page.get_by_role("tooltip")
    expect(tip).to_be_visible()
    expect(tip).to_contain_text("least privilege")
    # Outside click dismisses without an API mutation or exposing any key material.
    page.locator(".header-title").click()
    expect(tip).to_be_hidden()
