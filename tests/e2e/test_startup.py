"""Startup and login initialization work without permitting inline JavaScript."""

from urllib.parse import urlsplit

from .conftest import expect, expect_dashboard, navigate, tighten_script_policy


def require_external_scripts(page, settings, path="/static/startup.html"):
    """Serve *path* with the reviewed script policy, whatever the server sent.

    These pages ran under ``script-src 'self'`` before the gateway sent it;
    the suite-wide form is ``SIGRIFT_E2E_CSP=enforce`` (conftest).
    """

    def restrict(route):
        response = route.fetch(max_redirects=0)
        assert response.status == 200, "Startup page did not load"
        headers = dict(response.headers)
        policy = headers.get("content-security-policy", "")
        script_directives = [
            directive
            for directive in policy.split(";")
            if directive.strip().split()[:1] == ["script-src"]
        ]
        assert len(script_directives) == 1, "Expected exactly one script policy"
        headers["content-security-policy"] = tighten_script_policy(policy)
        # Preserve the actual page and response; tighten only script policy.
        route.fulfill(response=response, headers=headers)

    page.route(settings.base_url + path, restrict)


def test_login_light_theme_is_applied_under_strict_script_csp(page, settings):
    require_external_scripts(page, settings, "/login?theme=light")
    with page.expect_response(
        lambda response: urlsplit(response.url).path == "/static/login_theme.js"
    ) as script:
        navigate(page, settings.base_url + "/login?theme=light")
    assert script.value.status == 200
    expect(page.locator("html")).to_have_attribute("data-theme", "light")
    expect(page.locator("#login-submit")).to_be_visible()


def test_startup_page_observes_real_completed_check_under_strict_csp(
    authenticated_page, settings
):
    page = authenticated_page
    require_external_scripts(page, settings)
    status = page.request.get(settings.base_url + "/api/integrity-status")
    assert status.status == 200
    assert status.json()["state"] in {"passed", "skipped"}, (
        "The candidate must finish its database check before browser testing"
    )
    with page.expect_response(
        lambda response: urlsplit(response.url).path == "/static/startup.js"
    ) as script:
        navigate(page, settings.base_url + "/static/startup.html")
    assert script.value.status == 200
    expect(page).to_have_url(settings.base_url + "/dashboard")
    expect_dashboard(page)


def test_startup_http_failure_retries_and_failure_detail_remains_literal_text(
    authenticated_page, settings
):
    page = authenticated_page
    require_external_scripts(page, settings)
    phase = {"status": 503, "body": {"state": "passed"}, "calls": 0}

    def status_response(route):
        phase["calls"] += 1
        route.fulfill(status=phase["status"], json=phase["body"])

    page.route(settings.base_url + "/api/integrity-status", status_response)
    navigate(page, settings.base_url + "/static/startup.html")
    expect(page.locator("#message")).to_contain_text("Connecting to server")
    assert page.url == settings.base_url + "/static/startup.html"
    phase.update(status=200, body={"state": "running", "db_size_mb": 0})
    expect(page.locator("#message")).to_contain_text("Checking database integrity")
    expect(page.locator("#progress-fill")).to_have_class(
        "progress-bar-fill indeterminate"
    )
    expect(page.locator("#est-remaining")).to_have_text("--")
    detail = (
        '<img src=x onerror="window.startupInjected=true"> &amp; <script>bad()</script>'
    )
    phase.update(status=200, body={"state": "failed", "error": detail})
    expect(page.locator("#message")).to_have_text("Check failed: " + detail)
    expect(page.locator("#message img, #message script")).to_have_count(0)
    assert page.evaluate("window.startupInjected === undefined")
    assert page.url == settings.base_url + "/static/startup.html"
    assert phase["calls"] >= 3
