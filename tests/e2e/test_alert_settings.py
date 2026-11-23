"""Reviewed frequency-range settings preserve native detections and other alerts."""

import secrets
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from .conftest import expect, navigate


@pytest.mark.disposable
def test_alert_settings_create_edit_remove_range_without_source_detection(
    authenticated_page, admin_api, synthetic_scanner, settings, output_path
):
    page = authenticated_page
    node_id = synthetic_scanner["node_id"]
    suffix = secrets.token_hex(5)
    note = "Synthetic FM settings " + suffix
    pattern_api = "/api/detections/known-signals"
    owned_ids = set()
    rule = None

    def ingest(records):
        result = admin_api.request(
            "POST",
            "/api/detections/batch",
            {
                "node_id": node_id,
                "batch_id": "range-" + secrets.token_hex(5),
                "detections": [
                    {
                        "detection_id": ident,
                        "freq_hz": frequency,
                        "signal_class": signal_class,
                        "confidence": 0.99,
                        "anomaly_score": 0.99,
                        "power_dbm": power,
                    }
                    for ident, frequency, signal_class, power in records
                ],
            },
        )
        assert result["inserted"] == len(records) and result["rejected"] == 0
        return {
            ident: admin_api.request("GET", "/api/detections/" + ident)
            for ident, *_ in records
        }

    def wait_for_alert(ident):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            alerts = admin_api.request("GET", "/api/alerts/?limit=500")
            # Public AlertResponse omits the stored internal rule_id. Match
            # the unique condition name, node and exact RF record together.
            if any(
                a.get("rf_detection_id") == ident
                and a.get("name") == "rule_" + rule["name"]
                and a.get("node_id") == node_id
                for a in alerts
            ):
                return alerts
            time.sleep(0.25)
        raise AssertionError("Outside-band or removed-rule RF control did not alert")

    try:
        rule = admin_api.request(
            "POST",
            "/api/alerts/rules/conditions",
            {
                "name": "FM settings test " + suffix,
                "conditions": [
                    {"field": "node_id", "operator": "eq", "value": node_id},
                    {"field": "freq_hz", "operator": "between", "value": [80e6, 120e6]},
                ],
                "cooldown_seconds": 0,
                "notify_webhook": False,
            },
            status=201,
        )
        page.locator('[data-tab="alerts"]').click()
        page.locator("#alerts-settings-btn").click()
        dialog = page.get_by_role("dialog", name="Alert settings", exact=True)
        dialog.get_by_role(
            "button", name="Ignore FM broadcast range…", exact=True
        ).click()
        expect(
            dialog.get_by_label("Minimum frequency (MHz)", exact=True)
        ).to_have_value("88")
        expect(
            dialog.get_by_label("Maximum frequency (MHz)", exact=True)
        ).to_have_value("108")
        expect(
            dialog.get_by_label("Any modulation (frequency only)", exact=True)
        ).to_be_checked()
        expect(
            dialog.get_by_label("Apply to all nodes (broader scope)", exact=True)
        ).not_to_be_checked()
        expect(
            dialog.locator("datalist option").filter(has_text=node_id)
        ).to_have_count(1)
        dialog.get_by_label("Node", exact=True).fill(node_id)
        dialog.get_by_label("Reason (optional)", exact=True).fill(note)
        snapshots = Path(output_path)
        snapshots.mkdir(parents=True, exist_ok=True)
        dialog.screenshot(path=str(snapshots / "synthetic-fm-alert-settings.png"))
        with page.expect_response(
            lambda r: r.request.method == "POST" and urlsplit(r.url).path == pattern_api
        ) as created:
            dialog.get_by_role("button", name="Save alert rule", exact=True).click()
        assert created.value.status == 201
        pattern = created.value.json()
        owned_ids.add(pattern["pattern_id"])
        assert pattern["source_detection_id"] is None
        assert pattern["signal_class"] == "*" and pattern["node_id"] == node_id
        assert pattern["freq_min_hz"] == 88e6 and pattern["freq_max_hz"] == 108e6
        expect(dialog.get_by_role("status")).to_contain_text("Known pattern saved")
        dialog.get_by_role("button", name="Close", exact=True).click()

        navigate(page, settings.base_url + "/dashboard")
        page.locator('[data-tab="alerts"]').click()
        page.locator("#alerts-settings-btn").click()
        dialog = page.get_by_role("dialog", name="Alert settings", exact=True)
        row = dialog.locator(".known-signal-entry").filter(has_text=note)
        expect(row).to_be_visible()
        row.get_by_role("button", name="Edit", exact=True).click()
        dialog.get_by_label("Minimum frequency (MHz)", exact=True).fill("87.5")
        with page.expect_response(
            lambda r: r.request.method == "PUT"
            and urlsplit(r.url).path == pattern_api + "/" + pattern["pattern_id"]
        ) as edited:
            dialog.get_by_role("button", name="Save changes", exact=True).click()
        assert edited.value.status == 200
        assert edited.value.json()["freq_min_hz"] == 87500000
        expect(dialog.get_by_role("status")).to_contain_text("Known pattern saved")

        inside = "range-inside-" + suffix
        outside = "range-outside-" + suffix
        # One native batch preserves ingest order. The outside condition-rule
        # alert proves this same rule pass completed after considering inside.
        before = ingest([(inside, 100e6, "qpsk", -12), (outside, 109e6, "bpsk", -70)])
        alerts = wait_for_alert(outside)
        assert not any(a.get("rf_detection_id") == inside for a in alerts)
        assert before == {
            ident: admin_api.request("GET", "/api/detections/" + ident)
            for ident in before
        }
        with page.expect_response(
            lambda r: r.request.method == "DELETE"
            and urlsplit(r.url).path == pattern_api + "/" + pattern["pattern_id"]
        ) as removed:
            dialog.get_by_role(
                "button", name="Undo / remove this pattern", exact=True
            ).click()
        assert removed.value.status == 200 and removed.value.json()["removed"] is True
        expect(dialog.get_by_role("status")).to_contain_text("alerts are enabled again")
        assert not any(
            p["pattern_id"] == pattern["pattern_id"]
            for p in admin_api.request("GET", pattern_api)["patterns"]
        )
        again = "range-restored-" + suffix
        ingest([(again, 100e6, "qpsk", -12)])
        wait_for_alert(again)
        assert before == {
            ident: admin_api.request("GET", "/api/detections/" + ident)
            for ident in before
        }
        # Named bands are editable starting bounds, not an automatic rule.
        # Exercise a non-FM preset and a separate wholly custom range through
        # the shipped UI, then reload to prove both persisted independently.
        dialog.get_by_role("button", name="Close", exact=True).click()
        page.locator("#alerts-settings-btn").click()
        dialog = page.get_by_role("dialog", name="Alert settings", exact=True)
        picker = dialog.get_by_label("Named RF band", exact=True)
        picker.select_option(label="ISM 433 · 433.05–434.79 MHz")
        dialog.get_by_role("button", name="Review selected band", exact=True).click()
        expect(
            dialog.get_by_label("Minimum frequency (MHz)", exact=True)
        ).to_have_value("433.05")
        expect(
            dialog.get_by_label("Maximum frequency (MHz)", exact=True)
        ).to_have_value("434.79")
        expect(dialog.get_by_label("Node", exact=True)).to_have_value("")
        expect(
            dialog.get_by_label("Apply to all nodes (broader scope)", exact=True)
        ).not_to_be_checked()
        dialog.get_by_label("Minimum frequency (MHz)", exact=True).fill("433.1")
        dialog.get_by_label("Maximum frequency (MHz)", exact=True).fill("434.5")
        dialog.get_by_label("Node", exact=True).fill(node_id)
        dialog.get_by_label("Reason (optional)", exact=True).fill(note + " named")
        with page.expect_response(
            lambda r: r.request.method == "POST" and urlsplit(r.url).path == pattern_api
        ) as named_response:
            dialog.get_by_role("button", name="Save alert rule", exact=True).click()
        assert named_response.value.status == 201
        named = named_response.value.json()
        owned_ids.add(named["pattern_id"])
        assert named["freq_min_hz"] == 433100000 and named["freq_max_hz"] == 434500000
        assert named["node_id"] == node_id and named["signal_class"] == "*"
        assert named["source_detection_id"] is None
        dialog.get_by_role("button", name="Manage known patterns", exact=True).click()
        dialog = page.get_by_role("dialog", name="Known RF patterns", exact=True)
        dialog.get_by_role(
            "button", name="Add custom frequency range", exact=True
        ).click()
        expect(
            dialog.get_by_label("Minimum frequency (MHz)", exact=True)
        ).to_have_value("")
        dialog.get_by_label("Minimum frequency (MHz)", exact=True).fill("905.25")
        dialog.get_by_label("Maximum frequency (MHz)", exact=True).fill("906.75")
        dialog.get_by_label("Node", exact=True).fill(node_id)
        dialog.get_by_label("Reason (optional)", exact=True).fill(note + " custom")
        with page.expect_response(
            lambda r: r.request.method == "POST" and urlsplit(r.url).path == pattern_api
        ) as custom_response:
            dialog.get_by_role("button", name="Save alert rule", exact=True).click()
        assert custom_response.value.status == 201
        custom = custom_response.value.json()
        owned_ids.add(custom["pattern_id"])
        assert custom["freq_min_hz"] == 905250000 and custom["freq_max_hz"] == 906750000
        assert custom["node_id"] == node_id and custom["signal_class"] == "*"
        assert custom["source_detection_id"] is None
        persisted = {
            p["pattern_id"]: p
            for p in admin_api.request("GET", pattern_api)["patterns"]
        }
        assert persisted[named["pattern_id"]] == named
        assert persisted[custom["pattern_id"]] == custom
        navigate(page, settings.base_url + "/dashboard")
        page.locator('[data-tab="alerts"]').click()
        page.locator("#alerts-settings-btn").click()
        dialog = page.get_by_role("dialog", name="Alert settings", exact=True)
        for reason, minimum, maximum in [
            (note + " named", "433.1", "434.5"),
            (note + " custom", "905.25", "906.75"),
        ]:
            row = dialog.locator(".known-signal-entry").filter(has_text=reason)
            row.get_by_role("button", name="Edit", exact=True).click()
            expect(
                dialog.get_by_label("Minimum frequency (MHz)", exact=True)
            ).to_have_value(minimum)
            expect(
                dialog.get_by_label("Maximum frequency (MHz)", exact=True)
            ).to_have_value(maximum)
            expect(dialog.get_by_label("Node", exact=True)).to_have_value(node_id)
            dialog.get_by_role(
                "button", name="Manage known patterns", exact=True
            ).click()
            dialog = page.get_by_role("dialog", name="Known RF patterns", exact=True)
    finally:
        for pattern in admin_api.request("GET", pattern_api)["patterns"]:
            if pattern["pattern_id"] in owned_ids or pattern["note"] in {
                note,
                note + " named",
                note + " custom",
            }:
                admin_api.request(
                    "DELETE",
                    pattern_api
                    + "/"
                    + pattern["pattern_id"]
                    + "?revision="
                    + str(pattern["revision"]),
                )
        if rule:
            admin_api.request(
                "DELETE", "/api/alerts/rules/conditions/" + rule["rule_id"]
            )
