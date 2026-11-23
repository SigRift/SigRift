"""Real API/browser status for a synthetic scanner, without optional SSH setup."""

import re
import secrets
from urllib.parse import urlsplit

import pytest

from .conftest import Client, expect


@pytest.mark.disposable
@pytest.mark.timeout(180)
def test_default_deployment_separates_scanner_reports_from_optional_ssh(
    disposable, authenticated_page, admin_api, settings
):
    page = authenticated_page
    node_id = "synthetic-deployment-" + secrets.token_hex(5)
    worker = Client(settings)
    key = None
    admin_api.request(
        "POST", "/api/nodes/register", {"node_id": node_id, "host": "edge"}
    )
    path = f"/api/nodes/{node_id}/scanner-status"

    def refresh():
        with page.expect_response(
            lambda response: response.request.method == "GET"
            and urlsplit(response.url).path == "/api/nodes/deployment"
        ) as received:
            page.locator("#deploy-refresh-btn").click()
        assert received.value.status == 200
        return received.value.json()["nodes"][node_id]

    def cell(label):
        table = page.locator("#deploy-table-wrap table")
        headers = table.locator("thead th").all_text_contents()
        index = headers.index(node_id)
        row = table.locator("tbody tr").filter(
            has=page.locator("td.deploy-prop-label", has_text=re.compile(f"^{label}$"))
        )
        return row.locator("td").nth(index)

    try:
        key = admin_api.request(
            "POST",
            "/api/admin/keys",
            {
                "description": "disposable Deployment status proof",
                "role": "sensor",
                "node_id": node_id,
            },
            status=201,
            retry_key_creation=True,
            stage="scanner_key",
        )
        assert isinstance(key.get("key_id"), str) and key["key_id"]
        assert isinstance(key.get("raw_key"), str) and key["raw_key"]
        page.locator('[data-tab="deployment"]').click()
        expect(page.locator("#deploy-refresh-btn")).to_be_enabled()
        initial = refresh()
        assert initial["ssh_status"] == "not_configured"
        assert initial["reachable"] is False
        assert initial["scanner_status"] == {}
        expect(cell("Node contact")).to_contain_text("Recent contact")
        expect(cell("Scanner reports")).to_have_text("No scanner report")
        expect(cell("Audit status")).to_contain_text("SSH audit not configured")

        for state, text in (
            ("error", "SDR: error reported"),
            ("running", "SDR: reporting"),
            ("stopped", "SDR: stopped"),
        ):
            report = worker.request(
                "POST",
                path,
                {"protocol": "sdr", "state": state},
                key=key["raw_key"],
                stage="scanner_status",
            )
            assert report["active"] is (state == "running")
            observed = refresh()
            assert observed["scanner_status"]["sdr"]["state"] == state
            assert observed["scanner_status"]["sdr"]["active"] is (state == "running")
            assert observed["node_status"] == "active"
            assert observed["ssh_status"] == "not_configured"
            expect(cell("Scanner reports")).to_have_text(text)
            expect(cell("Node contact")).to_contain_text("Recent contact")
            expect(cell("Audit status")).to_contain_text("SSH audit not configured")
            expect(page.locator("#deploy-cache-info")).not_to_contain_text("Fresh scan")
            expect(cell("Audit status")).not_to_contain_text("Could not resolve")
            expect(cell("Audit status")).not_to_contain_text("No ED25519")
            expect(page.locator("#deploy-table-wrap th.deploy-node-err")).to_have_count(
                0
            )
    finally:
        try:
            if key:
                admin_api.request(
                    "DELETE",
                    f"/api/admin/keys/{key['key_id']}",
                    retry_key_cleanup=True,
                    stage="scanner_cleanup",
                )
                worker.request(
                    "POST",
                    path,
                    {"protocol": "sdr", "state": "running"},
                    key=key["raw_key"],
                    status=401,
                    stage="scanner_revocation",
                )
        finally:
            admin_api.request("DELETE", f"/api/nodes/{node_id}", status=(200, 204))
