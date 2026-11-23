"""The controls that used inline script work under the gateway's script CSP.

The gateway sends ``script-src 'self'``: an inline ``<script>`` or an
``onclick=`` attribute is refused, and its control silently does nothing.
The documentation menu (dashboard and admin headers) and the spectrogram's
Export PNG button used them. Every test here, like every other browser
test, also fails on any CSP violation its pages report, and in
``SIGRIFT_E2E_CSP=reviewed`` on a page without the reviewed policy
(``conftest.CspWatcher``, checked by ``no_uncaught_browser_errors``).

Every gate expects no CSP problem, so a watcher that stopped recording
would pass them all. The first tests here are its positive control: pages
the test serves itself, whatever the build under test, with markup the
reviewed policy refuses.
"""

import re
import secrets
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from .conftest import (
    CspWatcher,
    expect,
    expect_admin_ready,
    expect_dashboard,
    navigate,
    reviewed_csp,
)

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
#: Same-origin paths no server route serves: the test fulfils them itself.
PROBE = "/e2e-csp-probe/"
PROBE_PAGE = "<!doctype html><title>CSP probe</title><p>probe</p>"
#: Markup injected into a loaded page that the reviewed policy refuses: a
#: handler attribute (it fires on the broken image) and an inline script.
INJECT_INLINE_SCRIPT = """() => {
    document.body.insertAdjacentHTML('beforeend',
        '<img alt="" src="data:," onerror="window.__sigriftProbeRan = true">');
    const script = document.createElement('script');
    script.textContent = 'window.__sigriftProbeRan = true';
    document.body.appendChild(script);
}"""
INJECT_HANDLER = """() => document.body.insertAdjacentHTML('beforeend',
    '<img alt="" src="data:," onerror="window.__sigriftProbeRan = true">')"""
#: The policy the gateway sent before this release.
OLDER_GATEWAY_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-hashes'; "
    "style-src 'self' 'unsafe-inline'; img-src 'self' data: "
    "https://*.tile.openstreetmap.org; connect-src 'self' wss: ws:; "
    "font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)


def serve_probes(context, settings, headers_for):
    """Fulfil every probe path of *context* with ``headers_for(path)``."""

    def fulfil(route):
        path = urlsplit(route.request.url).path
        route.fulfill(
            status=200,
            headers={"content-type": "text/html", **headers_for(path)},
            body=PROBE_PAGE,
        )

    context.route(settings.base_url + PROBE + "**", fulfil)


def refused(violations):
    return sorted(
        (violation["page"], violation["directive"], violation["blocked"])
        for violation in violations
    )


def load_the_served_login_page(page, settings):
    """Load the served login page, and its scripts, in the test's ``page``.

    The candidate gate measures the shipped JavaScript each browser test
    runs in its ``page`` and fails a test that ran none
    (``SIGRIFT_E2E_JS_COVERAGE``, ``conftest.collect_javascript_coverage``).
    The watcher's controls run on pages the test serves itself, or in
    browser contexts of their own; as ``test_browser_coverage`` does, the
    test's page loads a served page as well. Its CSP is the suite's to
    check (``no_uncaught_browser_errors``).
    """
    navigate(page, settings.base_url + "/login")
    expect(page.locator("#username")).to_be_visible()


def test_the_watcher_records_what_the_policy_refuses(page, settings, csp_watcher):
    """The suite's own watcher (any SIGRIFT_E2E_CSP mode), on the test's
    page and on a popup it opens, reports each refused inline script."""
    load_the_served_login_page(page, settings)
    assert csp_watcher.problems() == [], "The served login page has no CSP problem"
    reviewed = {"content-security-policy": reviewed_csp()}
    serve_probes(page.context, settings, lambda path: reviewed)
    navigate(page, settings.base_url + PROBE + "page")
    assert csp_watcher.problems() == [], "A page without inline script"

    page.evaluate(INJECT_INLINE_SCRIPT)
    violations = csp_watcher.wait_for_violations(2)
    assert refused(violations) == [
        (PROBE + "page", "script-src-attr", "inline"),
        (PROBE + "page", "script-src-elem", "inline"),
    ]
    assert page.evaluate("() => window.__sigriftProbeRan") is None
    problems = csp_watcher.problems()
    assert len(problems) == 2
    assert all(p.startswith(f"CSP violation on {PROBE}page: ") for p in problems)
    csp_watcher.clear()

    # A popup opened with window.open(url), as the dashboard opens reports.
    with page.expect_popup() as pending:
        page.evaluate(
            "url => { window.open(url); }", settings.base_url + PROBE + "popup"
        )
    popup = pending.value
    popup.wait_for_load_state("domcontentloaded")
    popup.evaluate(INJECT_HANDLER)
    violations = csp_watcher.wait_for_violations(1)
    assert refused(violations) == [(PROBE + "popup", "script-src-attr", "inline")]
    popup.close()
    # Caused on purpose: the test passes only if nothing else was reported.
    csp_watcher.clear()


def test_reviewed_mode_flags_each_document_without_the_reviewed_policy(
    page, browser, browser_context_args, settings
):
    """``SIGRIFT_E2E_CSP=reviewed`` (the candidate gate): a same-origin
    document with no policy, another policy or only a report-only one is a
    problem; a subresource or another origin's document is not checked."""
    load_the_served_login_page(page, settings)
    policies = {
        PROBE + "reviewed": {"content-security-policy": reviewed_csp()},
        PROBE + "none": {},
        PROBE + "older": {"content-security-policy": OLDER_GATEWAY_CSP},
        PROBE + "report-only": {"content-security-policy-report-only": reviewed_csp()},
    }
    context = browser.new_context(**browser_context_args)
    try:
        watcher = CspWatcher(context, settings.base_url, "reviewed")
        serve_probes(context, settings, lambda path: policies.get(path, {}))
        context.route(
            "https://csp-probe.invalid/**",
            lambda route: route.fulfill(
                status=200, headers={"content-type": "text/html"}, body=PROBE_PAGE
            ),
        )
        page = context.new_page()
        for path in policies:
            navigate(page, settings.base_url + path)
        page.evaluate("url => fetch(url).then(r => r.text())", PROBE + "fetched")
        navigate(page, "https://csp-probe.invalid/elsewhere")
        assert watcher.problems() == [
            f"Not the reviewed CSP: {PROBE}none (HTTP 200): None",
            f"Not the reviewed CSP: {PROBE}older (HTTP 200): {OLDER_GATEWAY_CSP!r}",
            f"Not the reviewed CSP: {PROBE}report-only (HTTP 200): None",
        ]
    finally:
        context.close()


def test_enforce_mode_refuses_inline_script_on_a_served_page(
    page, browser, browser_context_args, settings
):
    """``SIGRIFT_E2E_CSP=enforce``: a page the server sends, whatever its
    policy, reaches the browser with the reviewed script policy."""
    load_the_served_login_page(page, settings)
    context = browser.new_context(**browser_context_args)
    try:
        watcher = CspWatcher(context, settings.base_url, "enforce")
        page = context.new_page()
        response = navigate(page, settings.base_url + "/login")
        directives = {
            d.split()[0]: d.split()[1:]
            for d in response.headers["content-security-policy"].split(";")
            if d.split()
        }
        assert directives["script-src"] == ["'self'"]
        assert directives["object-src"] == ["'none'"]
        expect(page.locator("#username")).to_be_visible()
        assert watcher.problems() == [], "The login page has no inline script"
        page.evaluate(INJECT_HANDLER)
        violations = watcher.wait_for_violations(1)
        assert refused(violations) == [("/login", "script-src-attr", "inline")]
        assert page.evaluate("() => window.__sigriftProbeRan") is None
    finally:
        context.close()


@pytest.mark.parametrize("path", ["/dashboard", "/admin"])
def test_documentation_menu_opens_and_closes(authenticated_page, settings, path):
    page = authenticated_page
    if path == "/admin":
        navigate(page, settings.base_url + "/admin")
        expect_admin_ready(page, settings)
    button = page.locator(".docs-dropdown .help-icon")
    menu = page.locator(".docs-dropdown-menu")
    expect(menu).to_be_hidden()
    button.click()
    expect(menu).to_be_visible()
    expect(menu.get_by_role("link", name="API Reference")).to_be_visible()
    # A click elsewhere on the page closes it.
    page.locator(".dashboard-header .header-title").click()
    expect(menu).to_be_hidden()
    # The button toggles it.
    button.click()
    expect(menu).to_be_visible()
    button.click()
    expect(menu).to_be_hidden()


def test_documentation_pages_open_from_the_menu(authenticated_page, settings):
    page = authenticated_page
    page.locator(".docs-dropdown .help-icon").click()
    menu = page.locator(".docs-dropdown-menu")
    for name, path, heading in (
        ("API Reference", "/static/docs/api_reference.html", "API Reference"),
        ("Operations Guide", "/documentation/", "SigRift Documentation"),
        ("Deployment Guide", "/static/docs/deployment_guide.html", "Deployment Guide"),
    ):
        with page.expect_popup() as pending:
            menu.get_by_role("link", name=name).click()
        document = pending.value
        document.wait_for_load_state("domcontentloaded")
        assert urlsplit(document.url).path == path
        expect(document.locator("h1").first).to_have_text(heading)
        document.close()
        # Choosing a link is a click inside the menu: it stays open.
        expect(menu).to_be_visible()

    # The index links every guide, and /documentation/{page} redirects to it.
    navigate(page, settings.base_url + "/documentation/")
    for guide in ("operations_guide", "api_reference", "deployment_guide"):
        expect(
            page.locator(f'a.card[href="/static/docs/{guide}.html"]')
        ).to_be_visible()
    navigate(page, settings.base_url + "/documentation/operations_guide.html")
    assert urlsplit(page.url).path == "/static/docs/operations_guide.html"
    expect(page.locator("h1").first).to_have_text("Operations Guide")


@pytest.mark.disposable
def test_export_png_downloads_the_spectrogram(
    authenticated_page,
    admin_api,
    synthetic_scanner,
    scanner_lease,
    settings,
    disposable,
):
    """A detection with an IQ capture opens its spectrogram; Export saves it."""
    page = authenticated_page
    node_id = synthetic_scanner["node_id"]
    detection_id = "e2e-csp-iq-" + secrets.token_hex(5)
    # A band no other browser test uses, so its feed row groups no other
    # detection (the feed groups by class and band, to 10 kHz).
    freq_hz = 868e6 + secrets.randbelow(90) * 1e4
    result = admin_api.request(
        "POST",
        "/api/detections/batch",
        {
            "node_id": node_id,
            "batch_id": "e2e-csp-batch-" + secrets.token_hex(5),
            "detections": [
                {
                    "detection_id": detection_id,
                    "signal_class": "bpsk",
                    "confidence": 0.99,
                    "anomaly_score": 0.01,
                    "freq_hz": freq_hz,
                    "snr_db": 24,
                }
            ],
        },
    )
    assert result["inserted"] == 1 and result["rejected"] == 0
    synthetic_scanner["upload_iq"](detection_id)
    assert admin_api.request("GET", f"/api/detections/{detection_id}")["has_iq_capture"]

    with scanner_lease("sdr"):
        # Load the feed after the upload, so it carries the capture flag.
        navigate(page, settings.base_url + "/dashboard")
        expect_dashboard(page)
        rf_tab = page.locator('[data-tab="rf"]')
        expect(rf_tab).to_be_visible(timeout=15000)
        rf_tab.click()
        band = page.evaluate("freq => ChartUtils.formatFreq(freq)", freq_hz)
        row = page.locator(
            f'#det-feed-tbody .det-feed-row[data-dd-class="bpsk"][data-dd-freq="{band}"]'
        )
        expect(row).to_have_count(1, timeout=20000)
        expect(row).to_contain_text(node_id)
        row.click()
        expect(page.locator("#deep-dive-overlay")).to_be_visible()
        card = page.locator("#spectrogram-card")
        expect(card).to_be_visible()
        expect(card).to_have_attribute("data-detection-id", detection_id)
        # The deep-dive with a spectrogram is taller than the window. The
        # overlay scrolls to Export PNG and back up to the close button;
        # before it scrolled, both sat above the window, out of reach.
        with page.expect_download() as pending:
            card.get_by_role("button", name="Export PNG").click()
        download = pending.value
        assert re.fullmatch(r"spectrogram_\d+\.png", download.suggested_filename)
        assert Path(download.path()).read_bytes()[:8] == PNG_SIGNATURE
        page.locator("#deep-dive-close").click()
        expect(page.locator("#deep-dive-overlay")).to_be_hidden()
