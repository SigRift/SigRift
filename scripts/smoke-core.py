#!/usr/bin/env python3
"""Exercise real gateway/bridge contracts on a disposable Compose stack.

Creates users, API keys, detections and an alert rule. The stack's volumes
must be discarded afterwards. Uses only the standard library; never logs
passwords, session tokens, API keys or MFA material.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
import secrets
import ssl
import struct
import subprocess
import time
import urllib.error
import urllib.request


class Client:
    def __init__(self, base_url: str, context: ssl.SSLContext):
        self.base_url = base_url.rstrip("/")
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(self.cookies),
        )

    def request(
        self,
        method,
        path,
        body=None,
        *,
        status=200,
        key=None,
        csrf=True,
        retry_login_limit=False,
    ):
        headers = {"Content-Type": "application/json"}
        if key:
            headers["X-API-Key"] = key
        for cookie in self.cookies:
            if csrf and cookie.name == "csrf_token":
                headers["X-CSRF-Token"] = cookie.value
        req = urllib.request.Request(
            self.base_url + path,
            data=None if body is None else json.dumps(body).encode(),
            headers=headers,
            method=method,
        )
        expected = (status,) if isinstance(status, int) else status
        for attempt in range(2):
            try:
                response = self.opener.open(req, timeout=30)
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                delay = None
                # Earlier install/staging smokes share the persisted per-IP
                # login budget. Respect one short server-directed cooldown;
                # never relax security limits or retry other operations.
                if (
                    retry_login_limit
                    and method == "POST"
                    and path == "/api/auth/login"
                    and attempt == 0
                    and response.code == 429
                    and 429 not in expected
                ):
                    retry_after = response.headers.get("Retry-After", "")
                    if (
                        retry_after.isascii()
                        and retry_after.isdecimal()
                        and len(retry_after) <= 2
                    ):
                        seconds = int(retry_after)
                        if 1 <= seconds <= 60:
                            delay = seconds
                if delay is None:
                    if response.code not in expected:
                        # Bodies can contain secrets; report only route/status.
                        raise AssertionError(
                            f"{method} {path}: HTTP {response.code}, expected {expected}"
                        )
                    data = response.read()
                    try:
                        return json.loads(data) if data else {}
                    except json.JSONDecodeError:
                        return {}
            # Close the response before waiting. The extra second avoids
            # racing the expiry boundary of a sliding-window limiter.
            print(f"Login rate-limited; retrying once after {delay + 1}s", flush=True)
            time.sleep(delay + 1)

    def login(self, username, password):
        return self.request(
            "POST",
            "/api/auth/login",
            {"username": username, "password": password},
            retry_login_limit=True,
        )

    def has_session(self):
        """True once the server set an HttpOnly session cookie in the jar.

        The session is the cookie, not the login body: newer gateways no
        longer return ``session_token`` in JSON. Works with either.
        """
        return any(
            cookie.name == "session_token"
            and bool(cookie.value)
            and any(key.lower() == "httponly" for key in cookie._rest)
            for cookie in self.cookies
        )


def totp(secret):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    digest = hmac.new(
        key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1
    ).digest()
    offset = digest[-1] & 15
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def mfa_login(user, username, password, secret):
    """Sign *user* in with the password, then the TOTP for *secret*.

    The password step must ask for the second one and must not set the
    session cookie by itself; MFA verify must. Returns the verification
    body, so the caller can check that a replay is refused.
    """
    challenge = user.login(username, password)
    assert challenge.get("mfa_required") and challenge.get("mfa_token"), (
        "the password step asked for no MFA challenge"
    )
    verification = {"mfa_token": challenge["mfa_token"], "totp_code": totp(secret)}
    assert not user.has_session(), "the password step alone issued a session"
    user.request("POST", "/api/auth/mfa/verify", verification)
    assert user.has_session(), "MFA verify issued no session cookie"
    return verification


def eventually(check, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.25)
    raise AssertionError("asynchronous ingest hook did not complete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disposable", action="store_true", required=True)
    parser.add_argument("--base-url", default="https://localhost:8444")
    parser.add_argument("--ca-cert", required=True)
    parser.add_argument("--bridge-container", required=True)
    args = parser.parse_args()
    context = ssl.create_default_context(cafile=args.ca_cert)
    password = os.environ["BRIDGE_ADMIN_PASSWORD"]
    admin = Client(args.base_url, context)
    login = admin.login(os.environ.get("BRIDGE_ADMIN_USER", "admin"), password)
    assert admin.has_session(), "admin did not get a full session"
    assert not login.get("password_change_required"), (
        "seeded admin needs password change"
    )
    assert admin.request("GET", "/api/auth/me").get("username")
    admin.request("GET", "/api/status")  # Python-proxied authenticated route.
    assert admin.request("GET", "/health")["post_ingest_hooks"]["enabled"]
    admin.request("POST", "/api/internal/ingest-hook", {}, status=(403, 404))
    subprocess.run(
        ["docker", "exec", "-i", args.bridge_container, "python3", "-"],
        input="""import urllib.request, urllib.error
try:
    urllib.request.urlopen('http://localhost:8001/api/status', timeout=5)
except urllib.error.HTTPError as exc:
    assert exc.code == 403, exc.code
else:
    raise AssertionError('bridge accepted a request without the proxy secret')
""",
        text=True,
        check=True,
    )
    print("OK: TLS, login, proxied session auth, internal-route isolation", flush=True)

    suffix = secrets.token_hex(5)
    admin.request(
        "POST",
        "/api/alerts/rules/conditions",
        {"name": f"csrf-must-fail-{suffix}", "conditions": [], "enabled": False},
        status=403,
        csrf=False,
    )
    node_id = f"smoke-{suffix}"
    key = admin.request(
        "POST",
        "/api/admin/keys",
        {"description": "disposable smoke", "role": "sensor", "node_id": node_id},
        status=201,
    )
    rule = admin.request(
        "POST",
        "/api/alerts/rules/conditions",
        {
            "name": f"smoke-{suffix}",
            "conditions": [{"field": "node_id", "operator": "eq", "value": node_id}],
            "cooldown_seconds": 0,
            "notify_webhook": False,
        },
        status=201,
    )
    batch = {
        "node_id": node_id,
        "batch_id": f"smoke-batch-{suffix}",
        "detections": [
            {
                "detection_id": f"smoke-detection-{suffix}",
                "signal_class": "bpsk",
                "confidence": 0.95,
                "freq_hz": 433_920_000,
                "snr_db": 20.0,
            }
        ],
    }
    sensor = Client(args.base_url, context)
    result = sensor.request("POST", "/api/detections/batch", batch, key=key["raw_key"])
    assert result["inserted"] == 1 and result["rejected"] == 0
    rule_path = f"/api/alerts/rules/conditions/{rule['rule_id']}"
    eventually(lambda: admin.request("GET", rule_path)["trigger_count"] == 1)
    assert any(
        a["name"] == f"rule_{rule['name']}"
        for a in admin.request("GET", "/api/alerts/")
    )

    def hooks_drained():
        stats = admin.request("GET", "/health")["post_ingest_hooks"]
        assert stats["failed_batches"] == stats["dropped_batches"] == 0
        return stats["delivered_batches"] == stats["enqueued_batches"]

    eventually(hooks_drained)
    enqueued = admin.request("GET", "/health")["post_ingest_hooks"]["enqueued_batches"]
    duplicate = sensor.request(
        "POST", "/api/detections/batch", batch, key=key["raw_key"]
    )
    assert duplicate["inserted"] == 0
    # A duplicate must not enqueue work: queued_batches alone can be zero
    # while a hook is in flight, so it cannot prove deduplication.
    assert (
        admin.request("GET", "/health")["post_ingest_hooks"]["enqueued_batches"]
        == enqueued
    )
    assert admin.request("GET", rule_path)["trigger_count"] == 1
    admin.request("DELETE", f"/api/admin/keys/{key['key_id']}")
    sensor.request(
        "POST", "/api/detections/batch", batch, key=key["raw_key"], status=(401, 403)
    )
    print(
        "OK: node ingest -> bridge alert, deduplication, immediate key revocation",
        flush=True,
    )

    # A real user exercises password-change scopes and MFA across the Rust
    # native handlers and Python-proxied endpoints using the same database.
    username = f"smoke_{suffix}"
    initial = "Initial-" + secrets.token_urlsafe(24) + "9!"
    changed = "Changed-" + secrets.token_urlsafe(24) + "9!"
    admin.request(
        "POST",
        "/api/admin/users",
        {"username": username, "password": initial, "role": "analyst"},
        status=201,
    )
    # Fixture setup: only auto-generated bootstrap accounts carry this flag;
    # admin-created users do not. Set it in the disposable shared database,
    # then exercise the real login/change-password handlers on both sides.
    subprocess.run(
        ["docker", "exec", "-i", args.bridge_container, "python3", "-", username],
        input="""import sqlite3, sys
with sqlite3.connect('/app/src/sigrift/bridge/data/detections.db') as db:
    result = db.execute('UPDATE users SET must_change_password = 1 WHERE username = ?', (sys.argv[1],))
    assert result.rowcount == 1
""",
        text=True,
        check=True,
    )
    user = Client(args.base_url, context)
    scoped = user.login(username, initial)
    assert scoped.get("password_change_required"), (
        "new user received unrestricted session"
    )
    user.request("GET", "/api/status", status=403)
    user.request(
        "POST",
        "/api/auth/change-password",
        {"current_password": initial, "new_password": changed},
    )
    user = Client(args.base_url, context)
    user.login(username, changed)
    assert user.has_session()
    user.request("GET", "/api/status")
    setup = user.request("POST", "/api/auth/mfa/setup", {})
    user.request(
        "POST", "/api/auth/mfa/verify-setup", {"totp_code": totp(setup["secret"])}
    )
    user = Client(args.base_url, context)
    verification = mfa_login(user, username, changed, setup["secret"])
    user.request("GET", "/api/status")
    user.request("POST", "/api/auth/mfa/verify", verification, status=(400, 401))
    # A mutating Python route proves MFA issued usable CSRF/session cookies.
    user.request(
        "POST",
        "/api/alerts/rules/conditions",
        {"name": f"mfa-{suffix}", "conditions": [], "enabled": False},
        status=201,
    )
    print(
        "OK: forced password change, MFA enrollment/login/replay rejection, CSRF",
        flush=True,
    )


if __name__ == "__main__":
    main()
