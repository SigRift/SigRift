"""Real reviewed RF alert baseline, durable management and native ingest effects."""

import secrets
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from .conftest import expect, navigate


@pytest.mark.disposable
def test_rf_alert_known_pattern_review_edit_remove_and_preserved_detections(
    authenticated_page,
    admin_api,
    synthetic_scanner,
    settings,
    scanner_lease,
    output_path,
):
    page = authenticated_page
    suffix = secrets.token_hex(5)
    node_id = synthetic_scanner["node_id"]
    source = "known-source-" + suffix
    condition = None
    note = 'Synthetic lab RF source; literal "quoted" & <text> ' + suffix
    owned_ids = set()
    owned_sources = {source}
    pattern_api = "/api/detections/known-signals"

    def detections(records, score=0.95, signal_class="bpsk", power_dbm=-60):
        result = admin_api.request(
            "POST",
            "/api/detections/batch",
            {
                "node_id": node_id,
                "batch_id": "known-batch-" + secrets.token_hex(5),
                "detections": [
                    {
                        "detection_id": ident,
                        "signal_class": signal_class,
                        "confidence": 0.99,
                        "anomaly_score": score,
                        "freq_hz": freq,
                        "power_dbm": power_dbm,
                    }
                    for ident, freq in records
                ],
            },
        )
        assert result["inserted"] == len(records) and result["rejected"] == 0

    def alert_for(ident):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            alerts = admin_api.request("GET", "/api/alerts/?limit=500")
            matches = [a for a in alerts if a.get("rf_detection_id") == ident]
            if matches:
                return matches[0], alerts
            time.sleep(0.25)
        raise AssertionError("Native ingest did not produce the expected RF alert")

    try:
        condition = admin_api.request(
            "POST",
            "/api/alerts/rules/conditions",
            {
                "name": "Known RF E2E " + suffix,
                "conditions": [
                    {"field": "node_id", "operator": "eq", "value": node_id},
                    {
                        "field": "freq_hz",
                        "operator": "between",
                        "value": [510e6, 520e6],
                    },
                ],
                "cooldown_seconds": 0,
                "notify_webhook": False,
            },
            status=201,
        )
        detections([(source, 515e6)])
        alert, _ = alert_for(source)
        stored_before = admin_api.request("GET", f"/api/detections/{source}")
        page.locator('[data-tab="alerts"]').click()
        page.locator("#alerts-tab-refresh-btn").click()
        entry = page.locator(f'[data-known-detection="{source}"]').last
        expect(entry).to_be_visible(timeout=20000)
        entry.click()
        dialog = page.get_by_role("dialog", name="Mark RF signal as known")
        expect(dialog.locator('[name="node_id"]')).to_have_value(node_id)
        expect(dialog.locator('[name="all_nodes"]')).not_to_be_checked()
        expect(dialog.locator('[name="any_modulation"]')).to_be_checked()
        expect(dialog.locator('[name="signal_class"]')).to_have_value("bpsk")
        expect(dialog.locator('[name="signal_class"]')).to_be_disabled()
        expect(dialog.locator('[name="freq_min_mhz"]')).to_have_value("514.95")
        expect(dialog.locator('[name="freq_max_mhz"]')).to_have_value("515.05")
        dialog.locator('[name="note"]').fill(note)
        snapshots = Path(output_path)
        snapshots.mkdir(parents=True, exist_ok=True)
        dialog.screenshot(path=str(snapshots / "synthetic-known-rf-pattern-review.png"))
        with page.expect_response(
            lambda r: r.request.method == "PUT"
            and urlsplit(r.url).path.endswith(f"/{source}/baseline")
        ) as save:
            dialog.get_by_role("button", name="Save known pattern", exact=True).click()
        assert save.value.status == 200
        pattern = save.value.json()["pattern"]
        owned_ids.add(pattern["pattern_id"])
        assert pattern["signal_class"] == "*" and pattern["node_id"] == node_id
        expect(dialog.get_by_role("status")).to_contain_text("Known pattern saved")
        expect(dialog).to_contain_text(note)
        assert dialog.locator("img, script").count() == 0
        dialog.get_by_role("button", name="Close", exact=True).click()
        assert admin_api.request("GET", f"/api/detections/{source}") == stored_before

        # A fresh document reads committed state, then edits and removes the
        # actual rule. No browser route interception or database injection.
        navigate(page, settings.base_url + "/dashboard")
        page.locator('[data-tab="alerts"]').click()
        page.locator("#known-signals-manage").click()
        manager = page.get_by_role("dialog", name="Known RF patterns")
        row = manager.locator(".known-signal-entry").filter(has_text=note)
        expect(row).to_be_visible()
        expect(row).to_contain_text("Any modulation (frequency only)")
        row.get_by_role("button", name="Edit", exact=True).click()
        expect(manager.locator('[name="any_modulation"]')).to_be_checked()
        manager.locator('[name="any_modulation"]').uncheck()
        specific = manager.locator('[name="signal_class"]')
        specific.fill("invalid class")
        assert specific.evaluate("field => field.validity.patternMismatch")
        manager.get_by_role("button", name="Save changes", exact=True).click()
        expect(specific).to_be_visible()
        specific.fill("qpsk")
        assert specific.evaluate("field => field.checkValidity()")
        manager.locator('[name="any_modulation"]').check()
        manager.locator('[name="freq_max_mhz"]').fill("515.1")
        with page.expect_response(
            lambda r: r.request.method == "PUT"
            and urlsplit(r.url).path == pattern_api + "/" + pattern["pattern_id"]
        ) as edit:
            manager.get_by_role("button", name="Save changes", exact=True).click()
        assert edit.value.status == 200
        current = next(
            p
            for p in admin_api.request("GET", pattern_api)["patterns"]
            if p["pattern_id"] == pattern["pattern_id"]
        )
        assert current["freq_max_hz"] == 515100000 and current["revision"] == 2
        assert current["signal_class"] == "*"
        manager.get_by_role("button", name="Close", exact=True).click()

        matching = "known-match-" + suffix
        control = "known-control-" + suffix
        # Both classification and submitted power differ from the reviewed
        # source. The outside-range control must still produce a native alert.
        detections(
            [(matching, 515e6), (control, 516e6)], signal_class="qpsk", power_dbm=-12
        )
        _, alerts = alert_for(
            control
        )  # positive control proves this native hook completed
        assert not any(a.get("rf_detection_id") == matching for a in alerts)
        # Native ingestion computes its own score before the Bridge alert hook.
        # Preserve the actual stored record rather than assuming the submitted
        # fixture score survives that independent scoring stage.
        stored_matching = admin_api.request("GET", f"/api/detections/{matching}")
        assert 0 <= stored_matching["anomaly_score"] <= 1
        assert stored_matching["signal_class"] == "qpsk"
        assert stored_matching["power_dbm"] == -12
        assert admin_api.request("GET", f"/api/detections/{source}") == stored_before
        page.locator("#known-signals-manage").click()
        manager = page.get_by_role("dialog", name="Known RF patterns")
        page.once("dialog", lambda confirm: confirm.accept())
        with page.expect_response(
            lambda r: r.request.method == "DELETE"
            and urlsplit(r.url).path == pattern_api + "/" + pattern["pattern_id"]
        ) as removed:
            manager.locator(".known-signal-entry").filter(has_text=note).get_by_role(
                "button", name="Remove", exact=True
            ).click()
        assert removed.value.status == 200
        owned_ids.remove(pattern["pattern_id"])
        expect(manager.get_by_role("status")).to_contain_text(
            "alerts are enabled again"
        )
        manager.get_by_role("button", name="Close", exact=True).click()
        after = "known-after-undo-" + suffix
        detections([(after, 515e6)], signal_class="qpsk", power_dbm=-75)
        alert_for(after)
        assert (
            admin_api.request("GET", f"/api/detections/{matching}") == stored_matching
        )
        assert admin_api.request("GET", f"/api/detections/{source}") == stored_before

        # An independently read-back low-score RF detection also has an entry.
        ordinary = "known-low-score-" + suffix
        owned_sources.add(ordinary)
        # Use the canonical classifier label. "qam16" is unknown and correctly
        # receives the native unknown-class risk boost, so it is not a normal
        # low-score positive control.
        detections([(ordinary, 915e6)], score=0.01, signal_class="16qam")
        stored_ordinary = admin_api.request("GET", f"/api/detections/{ordinary}")
        assert stored_ordinary["signal_class"] == "16qam"
        assert stored_ordinary["family"] == "QAM"
        # Below the native anomaly-broadcast and UI "interesting" boundary.
        assert 0 <= stored_ordinary["anomaly_score"] < 0.3
        with scanner_lease("sdr"):
            expect(page.locator('[data-tab="rf"]')).to_be_visible(timeout=15000)
            page.locator('[data-tab="rf"]').click()
            feed = (
                page.locator("#det-feed-tbody .det-feed-row")
                .filter(has_text=node_id)
                .filter(has_text="16qam")
            )
            expect(feed.first).to_be_visible(timeout=20000)
            feed.first.click()
            with page.expect_response(
                lambda r: urlsplit(r.url).path.endswith(f"/{ordinary}/baseline")
            ) as preview:
                page.locator("#dd-mark-known").click()
            assert preview.value.status == 200
            expect(
                page.get_by_role("dialog", name="Mark RF signal as known").locator(
                    '[name="node_id"]'
                )
            ).to_have_value(node_id)
            ordinary_dialog = page.get_by_role("dialog", name="Mark RF signal as known")
            with page.expect_response(
                lambda r: r.request.method == "PUT"
                and urlsplit(r.url).path.endswith(f"/{ordinary}/baseline")
            ) as ordinary_save:
                ordinary_dialog.get_by_role(
                    "button", name="Save known pattern", exact=True
                ).click()
            assert ordinary_save.value.status == 200
            ordinary_pattern = ordinary_save.value.json()["pattern"]
            owned_ids.add(ordinary_pattern["pattern_id"])
            with page.expect_response(
                lambda r: r.request.method == "DELETE"
                and urlsplit(r.url).path
                == pattern_api + "/" + ordinary_pattern["pattern_id"]
            ) as undo:
                ordinary_dialog.get_by_role(
                    "button", name="Undo / remove this pattern", exact=True
                ).click()
            assert undo.value.status == 200 and undo.value.json()["removed"] is True
            owned_ids.remove(ordinary_pattern["pattern_id"])
            expect(ordinary_dialog.get_by_role("status")).to_contain_text(
                "alerts are enabled again"
            )
            assert (
                admin_api.request("GET", f"/api/detections/{ordinary}")
                == stored_ordinary
            )
            assert all(
                p["pattern_id"] != ordinary_pattern["pattern_id"]
                for p in admin_api.request("GET", pattern_api)["patterns"]
            )
    finally:
        # Identify only this test's source, including a committed save whose
        # response was lost; never remove another operator's matching rule.
        for pattern in admin_api.request("GET", pattern_api)["patterns"]:
            if (
                pattern["source_detection_id"] in owned_sources
                or pattern["pattern_id"] in owned_ids
            ):
                admin_api.request(
                    "DELETE",
                    pattern_api
                    + "/"
                    + pattern["pattern_id"]
                    + "?revision="
                    + str(pattern["revision"]),
                )
        if condition is not None:
            admin_api.request(
                "DELETE", "/api/alerts/rules/conditions/" + condition["rule_id"]
            )
