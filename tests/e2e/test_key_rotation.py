"""An API key rotated in the admin page is replaced on both tiers at once.

The bridge rotates keys, and refuses to unless the request came over TLS:
here the gateway terminates TLS and says so in X-Forwarded-Proto, so a
rotation through it succeeding shows the gateway passes that on. (The
bridge's own refusal of a plaintext rotation is not reachable from outside
the stack, which only the gateway can reach; tests/bridge covers it.) The
gateway then authenticates that key itself on its native routes, from the
same key file. So one rotation through the admin page must retire the old
credential, and admit the new one, on a route the gateway serves and on a
route it forwards to the bridge, with nothing restarted in between.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlsplit

import pytest

from .conftest import Client, expect, expect_admin_ready, navigate

NATIVE = "/api/detections/recent"  # answered by the gateway
PROXIED = "/api/nodes/"  # forwarded to the bridge


@pytest.mark.disposable
def test_key_rotated_in_admin_page_is_replaced_on_native_and_proxied_routes(
    page, settings, disposable_admin
):
    api = disposable_admin.client
    key = api.request(
        "POST",
        "/api/admin/keys",
        {"description": "e2e rotation " + secrets.token_hex(5), "role": "viewer"},
        status=201,
        retry_key_creation=True,
    )
    old = key["raw_key"]
    holder = Client(settings)  # no cookies: only the key authenticates
    try:
        for path in (NATIVE, PROXIED):
            holder.request("GET", path, key=old)

        page.context.add_cookies(api.browser_cookies())
        navigate(page, settings.base_url + "/admin")
        expect_admin_ready(page, settings)
        row = page.locator("#keys-tbody tr").filter(has_text=key["key_id"])
        row.get_by_role("button", name="Rotate", exact=True).click()
        with page.expect_response(
            lambda response: urlsplit(response.url).path
            == f"/api/admin/keys/{key['key_id']}/rotate"
        ) as rotated:
            page.get_by_role("button", name="Rotate Key", exact=True).click()
        assert rotated.value.status == 200, rotated.value.status

        # The dialog shows the new key once; acknowledging hides it and
        # closing it leaves no copy in the page.
        shown = page.locator("#admin-rawkey-code")
        new = shown.text_content()
        assert new == rotated.value.json()["raw_key"] and new != old
        page.locator("#admin-rawkey-ack").check()
        expect(shown).to_have_count(1)
        expect(shown).not_to_contain_text(new)
        page.get_by_role("button", name="Done", exact=True).click()
        expect(shown).to_have_count(0)
        expect(page.locator("#key-rotate-result")).to_contain_text("Key rotated.")
        assert new not in page.content(), "The rotated key stayed in the page"

        for path in (NATIVE, PROXIED):
            holder.request("GET", path, key=old, status=401)
            holder.request("GET", path, key=new)
    finally:
        api.request(
            "DELETE",
            f"/api/admin/keys/{key['key_id']}",
            status=(200, 404),
            retry_key_cleanup=True,
        )
