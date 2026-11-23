"""Real browser/session remains usable through deterministic bootstrap errors."""

import re
from urllib.parse import urlsplit

from .conftest import expect, expect_admin_ready, navigate


def test_admin_bootstrap_recovers_without_reauthentication(
    authenticated_page, settings
):
    page = authenticated_page
    # Intercept only this idempotent bootstrap request. Both successful
    # recoveries must reach the real authenticated production endpoint.
    outcomes = [429, "real", 503, "network", "real"]
    observed = []

    def bootstrap(route):
        assert outcomes, "Unexpected admin bootstrap retry"
        outcome = outcomes.pop(0)
        observed.append(outcome)
        if outcome == "real":
            route.continue_()
        elif outcome == "network":
            route.abort("failed")
        else:
            route.fulfill(
                status=outcome,
                headers={"Retry-After": "1"} if outcome == 429 else {},
                content_type="text/plain",
                body="Temporary admin service failure",
            )

    page.route(settings.base_url + "/api/admin/stats", bootstrap)
    navigate(page, settings.base_url + "/admin")
    status = page.locator("#admin-status")
    expect(status).to_have_attribute("role", "status")
    expect(status).to_be_visible()
    expect(status).to_contain_text("rate limited")
    expect(page.locator("#admin-auth-retry")).to_be_hidden()
    expect_admin_ready(page, settings)
    assert observed == [429, "real"]

    with page.expect_response(
        lambda response: urlsplit(response.url).path == "/api/admin/stats"
        and response.status == 503
    ):
        page.reload()
    retry = page.get_by_role("button", name="Retry connection", exact=True)
    expect(status).to_contain_text("Please try again.")
    expect(retry).to_be_visible()
    expect(page).to_have_url(re.compile(r"/admin(?:[?#].*)?$"))
    assert page.request.get(settings.base_url + "/api/auth/me").status == 200
    with page.expect_event(
        "requestfailed",
        predicate=lambda request: urlsplit(request.url).path == "/api/admin/stats",
    ):
        retry.click()
    expect(status).to_contain_text("Please try again.")
    expect(retry).to_be_visible()
    expect(page).to_have_url(re.compile(r"/admin(?:[?#].*)?$"))
    assert page.request.get(settings.base_url + "/api/auth/me").status == 200
    retry.click()
    expect_admin_ready(page, settings)
    expect(retry).to_be_hidden()
    assert not outcomes and observed == [429, "real", 503, "network", "real"]
