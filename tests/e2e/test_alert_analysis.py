"""Alert analysis panel against real RF alerts, roles and the alert tone.

Synthetic RF detections traverse the real gateway ingest and the Bridge's
condition-rule hook. Nothing is written to a database directly, no route is
intercepted and CSP stays enforced. The tone check only counts the browser's
own AudioContext construction; it does not replace the dashboard's code.
"""

import html
import re
import secrets
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from .conftest import Client, expect, expect_dashboard, navigate

PATTERN_API = "/api/detections/known-signals"
ANALYSIS_KNOWN_API = "/api/alerts/analysis/known"
MARK_KNOWN = "Mark as known…"

# Counts AudioContext/oscillator creation, then defers to the real browser
# implementation, so the dashboard's own tone code runs unchanged.
TONE_SPY = """(() => {
    const spy = {contexts: 0, oscillators: 0};
    Object.defineProperty(window, "__alertToneSpy", {value: spy});
    for (const name of ["AudioContext", "webkitAudioContext"]) {
        const Original = window[name];
        if (typeof Original !== "function") continue;
        window[name] = class extends Original {
            constructor(...args) { spy.contexts += 1; super(...args); }
            createOscillator(...args) {
                spy.oscillators += 1;
                return super.createOscillator(...args);
            }
        };
    }
})();"""


def mhz(hz):
    # Mirrors alert_analysis.js: kHz precision, no trailing ".0".
    text = repr(round(hz / 1e3) / 1e3)
    return text[:-2] if text.endswith(".0") else text


def range_label(low_hz, high_hz):
    if low_hz == high_hz:
        return mhz(low_hz) + " MHz"
    return f"{mhz(low_hz)}–{mhz(high_hz)} MHz"


def create_rule(admin_api, name, node_id, low_hz, high_hz):
    return admin_api.request(
        "POST",
        "/api/alerts/rules/conditions",
        {
            "name": name,
            "severity": "warning",
            "conditions": [
                {"field": "node_id", "operator": "eq", "value": node_id},
                {"field": "freq_hz", "operator": "between", "value": [low_hz, high_hz]},
            ],
            "cooldown_seconds": 0,
            "notify_webhook": False,
        },
        status=201,
    )


def ingest(admin_api, node_id, records):
    """One native batch; ingest order is preserved within the alert hook."""
    result = admin_api.request(
        "POST",
        "/api/detections/batch",
        {
            "node_id": node_id,
            "batch_id": "analysis-batch-" + secrets.token_hex(5),
            "detections": [
                {
                    "detection_id": ident,
                    "signal_class": signal_class,
                    "confidence": 0.99,
                    "anomaly_score": 0.05,
                    "freq_hz": frequency,
                    "power_dbm": -60,
                }
                for ident, frequency, signal_class in records
            ],
        },
    )
    assert result["inserted"] == len(records) and result["rejected"] == 0


def wait_for_rule_alerts(admin_api, rule, detection_ids):
    """Every listed detection has this rule's alert; returns all alerts."""
    name = "rule_" + rule["name"]
    deadline = time.monotonic() + 20
    while True:
        alerts = admin_api.request("GET", "/api/alerts/?limit=500")
        seen = {a.get("rf_detection_id") for a in alerts if a.get("name") == name}
        if set(detection_ids) <= seen:
            return alerts
        assert time.monotonic() < deadline, (
            "Native ingest did not produce the expected rule alerts"
        )
        time.sleep(0.25)


def linked(alerts, detection_ids):
    return [a for a in alerts if a.get("rf_detection_id") in set(detection_ids)]


def analysis(client, include_acknowledged=False):
    # Same window and limit the panel requests for the default feed filter.
    query = "?hours=24&limit=10"
    if include_acknowledged:
        query += "&include_acknowledged=true"
    return client.request("GET", "/api/alerts/analysis" + query)


def frequency_group(result, node_id, low_hz):
    found = [
        g
        for g in result["frequencies"]
        if g["node_id"] == node_id and g["suggested_pattern"]["freq_min_hz"] == low_hz
    ]
    assert len(found) == 1, "Expected exactly one analysis group for this bucket"
    return found[0]


def alert_type(result, name):
    found = [t for t in result["alert_types"] if t["name"] == name]
    assert len(found) == 1, "Expected the rule's alert type in the analysis"
    return found[0]


def group_cells(group, actions):
    return [
        range_label(group["freq_min_hz"], group["freq_max_hz"]),
        group["node_id"],
        ", ".join(f"{c['signal_class']} ×{c['count']}" for c in group["classes"]),
        ", ".join(t["name"] for t in group["alert_types"]),
        f"{group['open']} / {group['count']}",
        actions,
    ]


def remove_patterns(admin_api, predicate):
    for pattern in admin_api.request("GET", PATTERN_API)["patterns"]:
        if predicate(pattern):
            admin_api.request(
                "DELETE",
                f"{PATTERN_API}/{pattern['pattern_id']}?revision={pattern['revision']}",
            )


def wait_until(page, predicate, message, argument=None):
    # CDP evaluation respects the deployed CSP, unlike wait_for_function's
    # string-eval polling.
    deadline = time.monotonic() + 20
    while not page.evaluate(predicate, argument):
        assert time.monotonic() < deadline, message
        page.wait_for_timeout(50)


@pytest.mark.disposable
def test_alert_analysis_groups_rf_alerts_and_marks_a_group_known(
    authenticated_page, admin_api, synthetic_scanner, output_path
):
    page = authenticated_page
    node_id = synthetic_scanner["node_id"]
    suffix = secrets.token_hex(5)
    note = "Synthetic analysis group " + suffix
    group_ids = [f"analysis-{suffix}-{n}" for n in range(3)]
    control_id = f"analysis-{suffix}-control"
    records = [
        (group_ids[0], 467.52e6, "bpsk"),
        (group_ids[1], 467.54e6, "qpsk"),
        (group_ids[2], 467.56e6, "bpsk"),
        # Last in the batch: once its rule alert exists, the hook finished
        # every earlier detection. A different 100 kHz bucket stays open.
        (control_id, 468.25e6, "bpsk"),
    ]
    rule = None
    owned = set()
    try:
        rule = create_rule(
            admin_api, "Analysis E2E " + suffix, node_id, 467.5e6, 468.5e6
        )
        type_name = "rule_" + rule["name"]
        ingest(admin_api, node_id, records)
        alerts = wait_for_rule_alerts(admin_api, rule, group_ids + [control_id])
        stored = {
            ident: admin_api.request("GET", "/api/detections/" + ident)
            for ident, *_ in records
        }
        group_alerts = linked(alerts, group_ids)
        control_alerts = linked(alerts, [control_id])
        assert group_alerts and control_alerts
        assert not any(a["acknowledged"] for a in group_alerts + control_alerts)

        # The backend's grouping, checked against the alert list itself.
        result = analysis(admin_api)
        assert result["can_manage"] is True and result["bucket_hz"] == 100_000
        group = frequency_group(result, node_id, 467.5e6)
        assert group["count"] == group["open"] == len(group_alerts)
        assert group["freq_min_hz"] == 467.52e6 and group["freq_max_hz"] == 467.56e6
        assert {c["signal_class"]: c["count"] for c in group["classes"]} == Counter(
            stored[a["rf_detection_id"]]["signal_class"] for a in group_alerts
        )
        assert group["suggested_pattern"] == {
            "freq_min_hz": 467.5e6,
            "freq_max_hz": 467.6e6,
            "signal_class": "*",
            "node_id": node_id,
        }
        assert group["covered_by"] == []
        assert type_name in [t["name"] for t in group["alert_types"]]
        control = frequency_group(result, node_id, 468.2e6)
        assert control["open"] == control["count"] == len(control_alerts)
        kind = alert_type(result, type_name)
        assert kind["count"] == kind["open"] == 4
        assert kind["severities"] == {"warning": 4}
        assert kind["top_frequencies"] == [
            {
                "node_id": node_id,
                "freq_min_hz": 467.5e6,
                "freq_max_hz": 467.6e6,
                "count": 3,
            },
            {
                "node_id": node_id,
                "freq_min_hz": 468.2e6,
                "freq_max_hz": 468.3e6,
                "count": 1,
            },
        ]

        # The shipped panel renders those groups above the Alert Feed.
        page.locator('[data-tab="alerts"]').click()
        panel = page.locator("#panel-alert-analysis")
        expect(panel.get_by_role("heading", name="Alert analysis")).to_be_visible()
        assert panel.evaluate(
            "panel => Boolean(panel.compareDocumentPosition("
            "document.getElementById('panel-alerts-tab')) & Node.DOCUMENT_POSITION_FOLLOWING)"
        ), "Alert analysis must precede the Alert Feed"
        freq_rows = page.locator("#alert-analysis-freq-body tr")
        row = freq_rows.filter(has_text=range_label(467.52e6, 467.56e6)).filter(
            has_text=node_id
        )
        expect(row.locator("td")).to_have_text(
            group_cells(group, MARK_KNOWN), timeout=20000
        )
        control_row = freq_rows.filter(has_text=range_label(468.25e6, 468.25e6)).filter(
            has_text=node_id
        )
        expect(control_row.locator("td")).to_have_text(group_cells(control, MARK_KNOWN))
        top = "; ".join(
            [
                f"{range_label(467.5e6, 467.6e6)} ({node_id}) ×3",
                f"{range_label(468.2e6, 468.3e6)} ({node_id}) ×1",
            ]
        )
        type_row = page.locator("#alert-analysis-type-body tr").filter(
            has_text=type_name
        )
        expect(type_row.locator("td")).to_have_text(
            [type_name, "warning ×4", top, "4 / 4"]
        )
        expect(page.locator("#alert-analysis-summary")).to_have_text(
            re.compile(
                r"^\d+ alert\(s\) in window · \d+ frequency group\(s\) of 100 kHz"
            )
        )
        snapshots = Path(output_path)
        snapshots.mkdir(parents=True, exist_ok=True)
        panel.screenshot(path=str(snapshots / "synthetic-alert-analysis.png"))

        # Review the suggested pattern and acknowledge the alerts it covers.
        row.get_by_role("button", name=MARK_KNOWN, exact=True).click()
        dialog = page.get_by_role("dialog", name="Mark frequency as known")
        expect(dialog.locator('[name="freq_min_mhz"]')).to_have_value("467.5")
        expect(dialog.locator('[name="freq_max_mhz"]')).to_have_value("467.6")
        expect(dialog.locator('[name="any_modulation"]')).to_be_checked()
        expect(dialog.locator('[name="signal_class"]')).to_be_disabled()
        expect(dialog.locator('[name="node_id"]')).to_have_value(node_id)
        expect(dialog.locator('[name="all_nodes"]')).not_to_be_checked()
        expect(
            dialog.get_by_label(
                f"Acknowledge the {len(group_alerts)} open alert(s) this covers",
                exact=True,
            )
        ).to_be_checked()
        dialog.locator('[name="note"]').fill(note)
        with page.expect_response(
            lambda r: r.request.method == "POST"
            and urlsplit(r.url).path == ANALYSIS_KNOWN_API
        ) as saved:
            dialog.get_by_role("button", name="Save known pattern", exact=True).click()
        assert saved.value.status == 200
        body = saved.value.json()
        pattern = body["pattern"]
        owned.add(pattern["pattern_id"])
        assert pattern["freq_min_hz"] == 467.5e6 and pattern["freq_max_hz"] == 467.6e6
        assert pattern["signal_class"] == "*" and pattern["node_id"] == node_id
        assert pattern["note"] == note and pattern["source_detection_id"] is None
        assert body["effect"] == "suppress_matching_rf_alerts"
        covered = {a["alert_id"] for a in group_alerts}
        assert set(body["acknowledged_alert_ids"]) == covered
        assert body["acknowledged_count"] == len(covered)
        expect(dialog).to_have_count(0)
        expect(
            page.locator("#toast-container .toast").filter(
                has_text=f"Known pattern saved; {len(covered)} alert(s) acknowledged"
            )
        ).to_be_attached()

        # The Alert Feed shows the covered alerts acknowledged, the control open.
        for alert_id in covered:
            feed_row = page.locator(f'#alerts-tab-tbody tr[data-alert-id="{alert_id}"]')
            expect(feed_row).to_have_class(re.compile(r"(^|\s)acknowledged(\s|$)"))
            expect(feed_row.locator(".alerts-acked-label")).to_have_text("Acked")
        for alert in control_alerts:
            feed_row = page.locator(
                f'#alerts-tab-tbody tr[data-alert-id="{alert["alert_id"]}"]'
            )
            expect(feed_row.locator("[data-ack-alert-tab]")).to_be_visible()

        # The API agrees, and the analysis neither changed detections nor
        # acknowledged anything outside the reviewed pattern.
        current = {
            a["alert_id"]: a for a in admin_api.request("GET", "/api/alerts/?limit=500")
        }
        ack_note = html.escape(f"Covered by known RF pattern {pattern['pattern_id']}")
        for alert_id in covered:
            assert current[alert_id]["acknowledged"] is True
            assert current[alert_id]["ack_note"] == ack_note
            assert current[alert_id]["acknowledged_at"]
            assert current[alert_id]["acknowledged_by"]
        assert all(
            current[a["alert_id"]]["acknowledged"] is False for a in control_alerts
        )
        assert stored == {
            ident: admin_api.request("GET", "/api/detections/" + ident)
            for ident in stored
        }
        assert [
            p
            for p in admin_api.request("GET", PATTERN_API)["patterns"]
            if p["pattern_id"] == pattern["pattern_id"]
        ] == [pattern]

        # Open alerts only (default): the covered group has none left.
        expect(row).to_have_count(0)
        expect(control_row.locator("td")).to_have_text(group_cells(control, MARK_KNOWN))
        expect(type_row.locator("td")).to_have_text(
            [
                type_name,
                "warning ×1",
                f"{range_label(468.2e6, 468.3e6)} ({node_id}) ×1",
                "1 / 1",
            ]
        )
        # Including acknowledged alerts, the group shows as already known.
        page.locator("#alert-analysis-include-acked").check()
        known = frequency_group(
            analysis(admin_api, include_acknowledged=True), node_id, 467.5e6
        )
        assert known["open"] == 0 and known["count"] == len(group_alerts)
        assert pattern["pattern_id"] in known["covered_by"]
        expect(row.locator("td")).to_have_text(group_cells(known, "Already known"))
        expect(row.locator("[data-analysis-known]")).to_have_count(0)
        expect(type_row.locator("td").nth(3)).to_have_text("1 / 4")

        # The saved pattern suppresses future matching RF alerts only.
        suppressed = f"analysis-{suffix}-suppressed"
        control_after = f"analysis-{suffix}-control-after"
        ingest(
            admin_api,
            node_id,
            [(suppressed, 467.58e6, "qpsk"), (control_after, 468.27e6, "bpsk")],
        )
        alerts = wait_for_rule_alerts(admin_api, rule, [control_after])
        assert not linked(alerts, [suppressed])
    finally:
        remove_patterns(
            admin_api, lambda p: p["pattern_id"] in owned or p["note"] == note
        )
        if rule is not None:
            admin_api.request(
                "DELETE", "/api/alerts/rules/conditions/" + rule["rule_id"]
            )


@pytest.mark.disposable
def test_viewer_sees_alert_analysis_but_cannot_mark_known(
    page, settings, admin_api, synthetic_scanner
):
    node_id = synthetic_scanner["node_id"]
    suffix = secrets.token_hex(5)
    username = "e2e_analysis_viewer_" + suffix
    password = "E2E-" + secrets.token_urlsafe(24) + "9!"
    ids = [f"analysis-viewer-{suffix}-{n}" for n in range(2)]
    rule = None
    user_created = False

    def suggested(pattern):
        return (
            pattern["node_id"] == node_id
            and pattern["freq_min_hz"] == 469.1e6
            and pattern["freq_max_hz"] == 469.2e6
        )

    try:
        rule = create_rule(
            admin_api, "Analysis viewer E2E " + suffix, node_id, 469.1e6, 469.2e6
        )
        ingest(
            admin_api, node_id, [(ids[0], 469.12e6, "bpsk"), (ids[1], 469.14e6, "bpsk")]
        )
        group_alerts = linked(wait_for_rule_alerts(admin_api, rule, ids), ids)
        admin_api.request(
            "POST",
            "/api/admin/users",
            {"username": username, "password": password, "role": "viewer"},
            status=201,
        )
        user_created = True
        viewer = Client(settings)
        login = viewer.login(username, password)
        assert viewer.has_session() and not login.get("password_change_required")
        assert viewer.request("GET", "/api/auth/me")["role"] == "viewer"

        result = analysis(viewer)
        assert result["can_manage"] is False
        group = frequency_group(result, node_id, 469.1e6)
        assert group["open"] == group["count"] == len(group_alerts)
        assert group["covered_by"] == []

        page.context.add_cookies(viewer.browser_cookies())
        navigate(page, settings.base_url + "/dashboard")
        expect_dashboard(page)
        page.locator('[data-tab="alerts"]').click()
        row = (
            page.locator("#alert-analysis-freq-body tr")
            .filter(has_text=range_label(469.12e6, 469.14e6))
            .filter(has_text=node_id)
        )
        expect(row.locator("td")).to_have_text(group_cells(group, ""), timeout=20000)
        expect(
            page.locator("#alert-analysis-type-body tr").filter(
                has_text="rule_" + rule["name"]
            )
        ).to_be_visible()
        expect(
            page.locator("#alert-analysis-freq-body [data-analysis-known]")
        ).to_have_count(0)

        # The server refuses the write itself, not only the hidden button.
        denied = viewer.request(
            "POST",
            ANALYSIS_KNOWN_API,
            {**group["suggested_pattern"], "note": "viewer " + suffix},
            status=403,
        )
        assert denied["detail"] == "Analyst role required"
        assert not any(
            suggested(p) for p in admin_api.request("GET", PATTERN_API)["patterns"]
        )
        current = {
            a["alert_id"]: a for a in admin_api.request("GET", "/api/alerts/?limit=500")
        }
        assert all(
            current[a["alert_id"]]["acknowledged"] is False for a in group_alerts
        )
    finally:
        # Only this session's node and exact bucket, in case a refusal regressed.
        remove_patterns(admin_api, suggested)
        if user_created:
            admin_api.request(
                "DELETE", "/api/admin/users/" + username, status=(200, 404)
            )
        if rule is not None:
            admin_api.request(
                "DELETE", "/api/alerts/rules/conditions/" + rule["rule_id"]
            )


@pytest.mark.disposable
def test_new_alert_tone_is_silent_only_while_alerts_tab_is_open(
    page, settings, admin_api, synthetic_scanner
):
    node_id = synthetic_scanner["node_id"]
    suffix = secrets.token_hex(5)
    rule = None
    page.add_init_script(TONE_SPY)
    # Real login cookies, as authenticated_page, but after the spy is installed.
    page.context.add_cookies(admin_api.browser_cookies())
    navigate(page, settings.base_url + "/dashboard")
    expect_dashboard(page)
    assert page.evaluate(
        "() => typeof AudioContext === 'function' && window.__alertToneSpy.contexts === 0"
    )
    wait_until(
        page,
        "() => Boolean(window.dashboard && window.dashboard.wsConns.alerts"
        " && window.dashboard.wsConns.alerts.readyState === WebSocket.OPEN)",
        "The dashboard's alert WebSocket did not open",
    )

    def tones():
        return page.evaluate("() => ({...window.__alertToneSpy})")

    def deliver(ident, frequency):
        """Ingest one matching detection; return once the dashboard handled it."""
        ingest(admin_api, node_id, [(ident, frequency, "bpsk")])
        # _onAlertWS shows this toast and decides the tone in one synchronous
        # call, so the toast's presence means the tone decision was made.
        expect(
            page.locator("#toast-container .toast")
            .filter(has_text=f"Rule '{rule['name']}' triggered on {node_id}")
            .filter(has_text=f"{frequency / 1e6:.2f} MHz")
        ).to_be_attached(timeout=20000)

    try:
        rule = create_rule(
            admin_api, "Analysis tone E2E " + suffix, node_id, 470.0e6, 470.9e6
        )
        summary_tab = page.locator('[data-tab="summary"]')
        alerts_tab = page.locator('[data-tab="alerts"]')
        expect(summary_tab).to_have_attribute("aria-selected", "true")

        # Positive control: another tab is open, so the alert is audible.
        before = tones()
        deliver(f"analysis-tone-{suffix}-summary", 470.12e6)
        after = tones()
        assert after["contexts"] > before["contexts"]
        assert after["oscillators"] > before["oscillators"]

        # The Alerts tab is open and the page visible: no tone at all.
        alerts_tab.click()
        expect(alerts_tab).to_have_attribute("aria-selected", "true")
        assert page.evaluate(
            "() => window.dashboard.alertsDashboard._active === true"
            " && document.visibilityState === 'visible'"
        )
        before = tones()
        deliver(f"analysis-tone-{suffix}-alerts", 470.34e6)
        expect(
            page.locator("#alerts-tab-tbody tr")
            .filter(has_text=rule["name"])
            .filter(has_text="470.34 MHz")
        ).to_be_visible()
        assert tones() == before, "An alert tone played while the Alerts tab was open"

        # Leaving the tab restores the tone.
        summary_tab.click()
        expect(summary_tab).to_have_attribute("aria-selected", "true")
        before = tones()
        deliver(f"analysis-tone-{suffix}-after", 470.56e6)
        assert tones()["contexts"] > before["contexts"]
    finally:
        if rule is not None:
            admin_api.request(
                "DELETE", "/api/alerts/rules/conditions/" + rule["rule_id"]
            )
