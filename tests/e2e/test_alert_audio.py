"""Real critical-alert delivery obeys the dashboard's audio toggle."""

import secrets
import time

import pytest

from .conftest import expect, navigate


# Replace only output devices: API, WebSocket, dashboard rendering and timers
# remain real. No actual sound or operating-system notification is emitted.
# The sink reports notification permission as granted: headless Chromium
# reports "denied" whatever the context was granted, and permission is not
# what this test is about.
_OUTPUT_SINKS = r"""
(() => {
    localStorage.setItem('bridge_alert_sound', 'on');
    localStorage.setItem('bridge_browser_notifications', 'on');
    window.__alertAudioProbe = {starts: 0, notifications: []};
    class AudioSink {
        constructor() { this.currentTime = 0; this.destination = {}; }
        createOscillator() {
            return {frequency: {value: 0}, type: 'sine', connect() {},
                    start() { window.__alertAudioProbe.starts++; }, stop() {}};
        }
        createGain() { return {gain: {value: 0}, connect() {}}; }
        close() { return Promise.resolve(); }
        resume() { return Promise.resolve(); }
    }
    window.AudioContext = AudioSink;
    window.webkitAudioContext = AudioSink;
    class NotificationSink {
        static get permission() { return 'granted'; }
        static requestPermission() { return Promise.resolve('granted'); }
        constructor(title, options) {
            window.__alertAudioProbe.notifications.push({title, ...options});
        }
        close() {}
    }
    window.Notification = NotificationSink;
})();
"""


def _wait_for_browser_value(page, expression, *, arg=None, message):
    """Poll through Playwright evaluation without wait_for_function's CSP eval."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if page.evaluate(expression, arg):
            return
        page.wait_for_timeout(100)
    raise AssertionError(message)


@pytest.mark.disposable
def test_critical_alert_audio_toggle_covers_sound_and_notifications(
    authenticated_page, settings, admin_api, disposable
):
    page = authenticated_page
    page.add_init_script(_OUTPUT_SINKS)
    navigate(page, settings.base_url + "/dashboard")
    _wait_for_browser_value(
        page,
        "window.dashboard && window.dashboard.wsConns.alerts && "
        "window.dashboard.wsConns.alerts.readyState === WebSocket.OPEN",
        message="The real alert WebSocket did not open",
    )
    # Stay off the Alerts tab: while the operator is looking at it the
    # dashboard plays no tone at all, muted or not.
    expect(page.locator("#browser-notification-toggle")).to_have_attribute(
        "aria-pressed", "true"
    )
    toggle = page.locator("#alert-sound-toggle")
    icon = page.locator("#alert-sound-icon")
    expect(icon).to_have_text("🔊")
    created = []

    def critical(label):
        name = "E2E audio " + label + " " + secrets.token_hex(5)
        alert = admin_api.request(
            "POST",
            "/api/alerts/rules",
            {"name": name, "severity": "critical"},
            status=201,
        )
        created.append(alert["alert_id"])
        # Only the real incoming alert WebSocket invokes browser notifications,
        # and the same handler then decides whether to play the tone.
        _wait_for_browser_value(
            page,
            "name => window.__alertAudioProbe.notifications.some(n => n.body.includes(name))",
            arg=name,
            message="The real alert WebSocket did not deliver its notification",
        )
        return name

    def notification_is_silent(name):
        return page.evaluate(
            "name => window.__alertAudioProbe.notifications.find(n => n.body.includes(name)).silent",
            name,
        )

    try:
        toggle.click()
        expect(icon).to_have_text("🔇")
        before = page.evaluate("window.__alertAudioProbe.starts")
        muted = critical("muted")
        # The tone is decided in the handler that sent the notification;
        # give a late one a moment to show up.
        page.wait_for_timeout(1000)
        assert page.evaluate("window.__alertAudioProbe.starts") == before
        assert notification_is_silent(muted) is True

        toggle.click()
        expect(icon).to_have_text("🔊")
        audible = critical("enabled")
        _wait_for_browser_value(
            page,
            "before => window.__alertAudioProbe.starts > before",
            arg=before,
            message="The enabled-audio positive control did not attempt playback",
        )
        assert notification_is_silent(audible) is False

        # Repeat after an audio context has been used.
        toggle.click()
        expect(icon).to_have_text("🔇")
        before = page.evaluate("window.__alertAudioProbe.starts")
        muted_again = critical("muted-again")
        page.wait_for_timeout(1000)
        assert page.evaluate("window.__alertAudioProbe.starts") == before
        assert notification_is_silent(muted_again) is True
    finally:
        for alert_id in created:
            admin_api.request("DELETE", f"/api/alerts/rules/{alert_id}")
