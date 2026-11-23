"""Real admin form/server rejection, with no outbound notification target."""

import secrets
import time
from urllib.parse import urlsplit

import pytest

from .conftest import expect, expect_admin_ready, navigate


@pytest.mark.disposable
@pytest.mark.timeout(180)
def test_webhook_rejection_is_visible_preserves_input_and_saves_nothing(
    authenticated_page, settings, admin_api, disposable
):
    page = authenticated_page
    path = "/api/admin/webhooks"
    # These routes share the real sensitive 10/minute admin bucket with
    # earlier tests. Respect its window; never replay a rejected mutation.
    time.sleep(61)
    before = admin_api.request("GET", path)["webhooks"]
    before_ids = {item["id"] for item in before}
    name = "E2E synthetic rejected webhook " + secrets.token_hex(5)
    with page.expect_response(
        lambda response: response.request.method == "GET"
        and urlsplit(response.url).path == path
    ) as loaded:
        navigate(page, settings.base_url + "/admin#notifications")
        expect_admin_ready(page, settings)
    assert loaded.value.status == 200
    page.locator("#admin-add-webhook-btn").click()
    form = page.locator("#admin-webhook-form")
    url = page.locator("#webhook-url-input")
    label = page.locator("#webhook-name-input")
    label.fill(name)

    # Blank input is caught locally. The real server subsequently rejects a
    # loopback destination before HTTP delivery; no third party is contacted.
    mutations = []

    def record(request):
        if request.method == "POST" and urlsplit(request.url).path == path:
            mutations.append(request.method)

    page.on("request", record)
    try:
        page.locator("#webhook-save-btn").click()
        expect(page.locator("#toast-container")).to_contain_text("URL is required.")
        expect(url).to_be_focused()
        assert mutations == []
        url.fill("http://127.0.0.1/synthetic-rejected-target")
        with page.expect_response(
            lambda response: response.request.method == "POST"
            and urlsplit(response.url).path == path
        ) as rejected:
            page.locator("#webhook-save-btn").click()
        assert rejected.value.status == 400
        expect(page.locator("#toast-container")).to_contain_text(
            "Webhook URLs must not target private/internal networks"
        )
        expect(form).to_be_visible()
        expect(label).to_have_value(name)
        expect(url).to_have_value("http://127.0.0.1/synthetic-rejected-target")
        assert mutations == ["POST"]
        after = admin_api.request("GET", path)["webhooks"]
        assert {item["id"] for item in after} == before_ids
        assert all(item["name"] != name for item in after)

        # Cancel really exits the unsuccessful edit; reopening starts a new
        # form rather than accidentally resubmitting the rejected destination.
        page.locator("#webhook-cancel-btn").click()
        expect(form).to_be_hidden()
        page.locator("#admin-add-webhook-btn").click()
        expect(url).to_have_value("")
        expect(label).to_have_value("")
        assert mutations == ["POST"]
        page.locator("#webhook-cancel-btn").click()
    finally:
        page.remove_listener("request", record)
