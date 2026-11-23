"""Real browser sockets stop receiving data after durable credential revocation.

These checks traverse native RF and proxied Bridge alert feeds, using only
public APIs and disposable identities. Tenant reassignment and in-flight
credential races additionally have real-store integration regressions.
"""

import secrets
import time

import pytest

from .conftest import Client, navigate


@pytest.mark.disposable
@pytest.mark.parametrize("feed", ["native", "proxied"])
@pytest.mark.parametrize("credential", ["session", "api_key"])
def test_live_feed_refuses_further_data_after_credential_revocation(
    page, settings, admin_api, synthetic_scanner, disposable, feed, credential
):
    suffix = secrets.token_hex(6)
    username = "e2e_stream_" + suffix
    description = "Synthetic live-feed revocation " + suffix
    node_id = synthetic_scanner["node_id"]
    before, after = "before-revoke-" + suffix, "after-revoke-" + suffix
    key = None
    actor = None
    rule = None
    revoked = False
    path = "/ws/feed" if feed == "native" else "/api/alerts/ws/alerts"

    def emit(ident):
        result = admin_api.request(
            "POST",
            "/api/detections/batch",
            {
                "node_id": node_id,
                "batch_id": "revocation-" + ident,
                "detections": [{
                    "detection_id": ident,
                    "signal_class": "bpsk",
                    "confidence": 0.99,
                    "freq_hz": 649e6,
                }],
            },
        )
        assert result["inserted"] == 1 and result["rejected"] == 0

    try:
        if feed == "proxied":
            rule = admin_api.request(
                "POST",
                "/api/alerts/rules/conditions",
                {
                    "name": description,
                    "conditions": [
                        {"field": "node_id", "operator": "eq", "value": node_id},
                        {"field": "freq_hz", "operator": "eq", "value": 649e6},
                    ],
                    "cooldown_seconds": 0,
                    "notify_webhook": False,
                },
                status=201,
            )
        # Load a real shipped page for strict JavaScript/source collection,
        # without the dashboard's background sockets or navigation on logout.
        page.context.clear_cookies()
        navigate(page, settings.base_url + "/login")
        if credential == "session":
            password = "E2E-" + secrets.token_urlsafe(24) + "9!"
            admin_api.request(
                "POST", "/api/admin/users",
                {"username": username, "password": password, "role": "viewer"},
                status=201,
            )
            actor = Client(settings)
            actor.login(username, password)
            assert actor.has_session()
            page.context.add_cookies(actor.browser_cookies())
            protocols = ["bridge-v1"]
        else:
            key = admin_api.request(
                "POST", "/api/admin/keys",
                {"description": description, "role": "viewer"},
                status=201, retry_key_creation=True,
            )
            protocols = ["bridge-v1", key["raw_key"]]

        page.evaluate(
            """({path, protocols}) => {
                const url = new URL(path, location.href);
                url.protocol = 'wss:';
                const socket = new WebSocket(url, protocols);
                const probe = {socket, opened: false, closed: null, seen: []};
                window.__liveAuthProbe = probe;
                socket.onopen = () => { probe.opened = true; };
                socket.onclose = event => { probe.closed = event.code; };
                socket.onmessage = event => {
                    try {
                        const record = JSON.parse(event.data);
                        if (typeof record.detection_id === 'string')
                            probe.seen.push(record.detection_id);
                    } catch (_) { /* Control frames are not detection payloads. */ }
                };
            }""",
            {"path": path, "protocols": protocols},
        )
        def wait_for_probe(predicate, argument=None):
            # CDP function invocation respects the deployed CSP without the
            # string-eval polling used internally by wait_for_function.
            deadline = time.monotonic() + 20
            while not page.evaluate(predicate, argument):
                assert time.monotonic() < deadline, "Expected WebSocket state did not arrive"
                page.wait_for_timeout(50)

        wait_for_probe("() => window.__liveAuthProbe.opened")
        emit(before)
        wait_for_probe("id => window.__liveAuthProbe.seen.includes(id)", before)
        if credential == "session":
            actor.request("POST", "/api/auth/logout", {})
            # Replay the browser's retained HttpOnly cookie after API logout.
            assert page.request.get(settings.base_url + "/api/auth/me").status == 401
        else:
            admin_api.request(
                "DELETE", "/api/admin/keys/" + key["key_id"],
                retry_key_cleanup=True,
            )
            Client(settings).request(
                "GET", "/api/detections/recent", key=key["raw_key"], status=401
            )
        revoked = True
        emit(after)
        wait_for_probe("() => window.__liveAuthProbe.closed !== null")
        observed = page.evaluate(
            "({closed: window.__liveAuthProbe.closed, seen: window.__liveAuthProbe.seen})"
        )
        assert observed["closed"] in (4001, 4003)
        assert before in observed["seen"]
        assert after not in observed["seen"], "A revoked browser received new data"
        # An independent authorized read proves the post-revocation write and
        # Bridge hook completed; silence is not explained by failed ingestion.
        stored = admin_api.request("GET", "/api/detections/" + after)
        assert stored["detection_id"] == after
        if feed == "proxied":
            deadline = time.monotonic() + 20
            while True:
                alerts = admin_api.request("GET", "/api/alerts/?limit=500")
                if any(a.get("rf_detection_id") == after for a in alerts):
                    break
                assert time.monotonic() < deadline, "Post-revocation alert hook did not complete"
                time.sleep(0.25)
    finally:
        cleanup_errors = []

        def cleanup(operation):
            try:
                operation()
            except Exception as error:
                # Attempt every owned cleanup even if a browser context or API
                # request failed. Keep credentials/response bodies out of errors.
                cleanup_errors.append(type(error).__name__)

        if not page.is_closed():
            cleanup(lambda: page.evaluate("window.__liveAuthProbe?.socket.close()"))
            cleanup(page.context.clear_cookies)
        if feed == "proxied":
            def cleanup_rules():
                owned_rules = [rule] if rule else [
                    item for item in admin_api.request("GET", "/api/alerts/rules/conditions")
                    if item.get("name") == description
                ]
                for item in owned_rules:
                    cleanup(lambda: admin_api.request(
                        "DELETE", "/api/alerts/rules/conditions/" + item["rule_id"],
                        status=(200, 404),
                    ))

            cleanup(cleanup_rules)
        if credential == "session":
            # The unique fixture identity is ours even if creation's response
            # was lost. Deleting an absent fixture is an accepted cleanup case.
            cleanup(lambda: admin_api.request(
                "DELETE", "/api/admin/users/" + username, status=(200, 404)
            ))
        elif not revoked:
            # Recover our committed key even if its creation response was lost.
            def cleanup_keys():
                owned = [key] if key else [
                    item for item in admin_api.request("GET", "/api/admin/keys")
                    if item.get("description") == description
                ]
                for item in owned:
                    cleanup(lambda: admin_api.request(
                        "DELETE", "/api/admin/keys/" + item["key_id"],
                        status=(200, 404), retry_key_cleanup=True,
                    ))

            cleanup(cleanup_keys)
        assert not cleanup_errors, "Owned fixture cleanup failed: " + ", ".join(cleanup_errors)
