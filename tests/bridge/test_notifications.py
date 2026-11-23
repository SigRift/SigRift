"""Tests for NotificationManager webhook management and delivery."""

from __future__ import annotations

import hashlib
import hmac
import time
from unittest.mock import patch

import pytest

from sigrift.bridge.notifications import (
    NotificationManager,
    _is_port_allowed,
    _resolve_and_check_ip,
    BLOCKED_PORTS,
    _RETRY_DELAY_SECONDS,
    _MAX_RETRY_QUEUE_ATTEMPTS,
)


class TestWebhookManagement:
    """CRUD operations on webhook configs."""

    def test_add_webhook(self):
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook", name="Test Hook")
        assert wh["url"] == "https://example.com/hook"
        assert wh["name"] == "Test Hook"
        assert wh["enabled"] is True
        assert wh["delivery_count"] == 0
        assert wh["failure_count"] == 0
        assert wh["last_error"] is None
        assert len(wh["id"]) == 12  # hex(6)

    def test_add_webhook_defaults(self):
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook")
        assert wh["name"] == "https://example.com/hook"
        assert wh["severity_filter"] == ["critical", "warning"]

    def test_add_webhook_custom_severity(self):
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook", severity_filter=["critical"])
        assert wh["severity_filter"] == ["critical"]

    def test_remove_webhook_found(self):
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook")
        assert mgr.remove_webhook(wh["id"]) is True
        assert len(mgr.webhooks) == 0

    def test_remove_webhook_not_found(self):
        mgr = NotificationManager()
        assert mgr.remove_webhook("nonexistent") is False

    def test_update_webhook(self):
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook", name="Old Name")
        result = mgr.update_webhook(wh["id"], {"name": "New Name", "enabled": False})
        assert result is not None
        assert isinstance(result, dict)
        assert result["name"] == "New Name"
        assert result["enabled"] is False

    def test_update_webhook_ignores_disallowed_fields(self):
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook")
        original_id = wh["id"]
        mgr.update_webhook(wh["id"], {"id": "hacked", "delivery_count": 999})
        assert wh["id"] == original_id
        assert wh["delivery_count"] == 0

    def test_update_webhook_not_found(self):
        mgr = NotificationManager()
        assert mgr.update_webhook("nonexistent", {"name": "x"}) is None

    def test_test_webhook_found(self):
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook")
        found = mgr.test_webhook(wh["id"])
        assert found is not None
        assert isinstance(found, dict)
        assert found["id"] == wh["id"]

    def test_test_webhook_not_found(self):
        mgr = NotificationManager()
        assert mgr.test_webhook("nonexistent") is None

    def test_load_webhooks(self):
        mgr = NotificationManager()
        hooks = [{"id": "abc", "url": "https://example.com", "enabled": True}]
        mgr.load(hooks)
        assert len(mgr.webhooks) == 1
        assert mgr.webhooks[0]["id"] == "abc"

    def test_webhooks_property_returns_list(self):
        mgr = NotificationManager()
        assert mgr.webhooks == []

    def test_delivery_log_bounded(self):
        mgr = NotificationManager()
        assert mgr.delivery_log == []


class TestBuildPayload:
    """Test webhook payload construction."""

    def test_build_payload_basic(self):
        alert = {
            "alert_id": "a-001",
            "name": "High CPU",
            "severity": "critical",
            "message": "CPU at 95%",
            "node_id": "node-01",
            "triggered_at": "2026-02-13T00:00:00Z",
        }
        payload = NotificationManager._build_payload(alert)
        assert payload["event"] == "alert"
        assert payload["source"] == "sigrift"
        assert payload["alert"]["id"] == "a-001"
        assert payload["alert"]["severity"] == "critical"
        assert payload["alert"]["node_id"] == "node-01"

    def test_build_payload_excludes_internal_keys(self):
        alert = {
            "alert_id": "a-001",
            "name": "Test",
            "severity": "warning",
            "message": "msg",
            "acknowledged": True,
            "acknowledged_at": "2026-02-13T00:00:00Z",
            "is_rule": True,
            "thresholds": {},
            "extra_field": "should_be_in_context",
        }
        payload = NotificationManager._build_payload(alert)
        assert "extra_field" in payload["context"]
        assert "acknowledged" not in payload["context"]
        assert "thresholds" not in payload["context"]


class TestNotify:
    """Test async notification delivery."""

    @pytest.mark.asyncio
    async def test_notify_no_webhooks(self):
        mgr = NotificationManager()
        count = await mgr.notify({"severity": "critical"})
        assert count == 0

    @pytest.mark.asyncio
    async def test_notify_disabled_webhook_skipped(self):
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook")
        wh["enabled"] = False
        count = await mgr.notify({"severity": "critical"})
        assert count == 0

    @pytest.mark.asyncio
    async def test_notify_severity_filter(self):
        mgr = NotificationManager()
        mgr.add_webhook("https://example.com/hook", severity_filter=["critical"])
        # "info" doesn't match the filter
        count = await mgr.notify({"severity": "info"})
        assert count == 0

    @pytest.mark.asyncio
    async def test_notify_delivery_success(self):
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook", severity_filter=["critical"])
        with patch.object(mgr, "_http_post", return_value=200):
            count = await mgr.notify(
                {
                    "severity": "critical",
                    "alert_id": "test-1",
                    "name": "test",
                }
            )
        assert count == 1
        assert wh["delivery_count"] == 1
        assert wh["last_error"] is None

    @pytest.mark.asyncio
    async def test_notify_delivery_failure(self):
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook", severity_filter=["critical"])
        with patch.object(mgr, "_http_post", side_effect=ConnectionError("refused")):
            with patch("sigrift.bridge.notifications.asyncio.sleep", return_value=None):
                count = await mgr.notify(
                    {
                        "severity": "critical",
                        "alert_id": "test-1",
                    }
                )
        assert count == 0
        assert wh["failure_count"] == 1
        assert "refused" in wh["last_error"]

    @pytest.mark.asyncio
    async def test_delivery_log_recorded(self):
        mgr = NotificationManager()
        mgr.add_webhook("https://example.com/hook", severity_filter=["warning"])
        with patch.object(mgr, "_http_post", return_value=200):
            await mgr.notify({"severity": "warning", "alert_id": "test-2"})
        assert len(mgr.delivery_log) == 1
        assert mgr.delivery_log[0]["success"] is True


class TestWebhookHealthTracking:
    """Test webhook health fields (last_success, last_failure, consecutive_failures)."""

    def test_add_webhook_has_health_fields(self):
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook")
        assert wh["last_success"] is None
        assert wh["last_failure"] is None
        assert wh["consecutive_failures"] == 0

    @pytest.mark.asyncio
    async def test_success_updates_health(self):
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook", severity_filter=["critical"])
        with patch.object(mgr, "_http_post", return_value=200):
            await mgr.notify({"severity": "critical", "alert_id": "h-1"})
        assert wh["last_success"] is not None
        assert isinstance(wh["last_success"], str)
        assert wh["consecutive_failures"] == 0

    @pytest.mark.asyncio
    async def test_failure_updates_health(self):
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook", severity_filter=["critical"])
        with patch.object(mgr, "_http_post", side_effect=ConnectionError("down")):
            with patch("sigrift.bridge.notifications.asyncio.sleep", return_value=None):
                await mgr.notify({"severity": "critical", "alert_id": "h-2"})
        assert wh["last_failure"] is not None
        assert isinstance(wh["last_failure"], str)
        assert wh["consecutive_failures"] == 1

    @pytest.mark.asyncio
    async def test_consecutive_failures_reset_on_success(self):
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook", severity_filter=["critical"])
        # First: fail
        with patch.object(mgr, "_http_post", side_effect=ConnectionError("down")):
            with patch("sigrift.bridge.notifications.asyncio.sleep", return_value=None):
                await mgr.notify({"severity": "critical", "alert_id": "h-3"})
        assert wh["consecutive_failures"] == 1
        # Then: succeed
        with patch.object(mgr, "_http_post", return_value=200):
            await mgr.notify({"severity": "critical", "alert_id": "h-4"})
        assert wh["consecutive_failures"] == 0


class TestFailedRetryQueue:
    """Test persistent webhook retry queue."""

    def test_failed_queue_initially_empty(self):
        mgr = NotificationManager()
        assert mgr.failed_queue == []

    @pytest.mark.asyncio
    async def test_failed_delivery_enqueues(self):
        mgr = NotificationManager()
        mgr.add_webhook("https://example.com/hook", severity_filter=["critical"])
        with patch.object(mgr, "_http_post", side_effect=ConnectionError("refused")):
            with patch("sigrift.bridge.notifications.asyncio.sleep", return_value=None):
                await mgr.notify({"severity": "critical", "alert_id": "q-1"})
        assert len(mgr.failed_queue) == 1
        entry = mgr.failed_queue[0]
        assert entry["attempts"] == 1
        assert "refused" in entry["last_error"]
        assert "webhook_id" in entry
        assert isinstance(entry["webhook_id"], str)
        assert "payload" in entry
        assert isinstance(entry["payload"], dict)
        assert "next_retry" in entry
        assert isinstance(entry["next_retry"], (int, float))

    @pytest.mark.asyncio
    async def test_retry_failed_success(self):
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook", severity_filter=["critical"])
        # Enqueue a failure
        with patch.object(mgr, "_http_post", side_effect=ConnectionError("refused")):
            with patch("sigrift.bridge.notifications.asyncio.sleep", return_value=None):
                await mgr.notify({"severity": "critical", "alert_id": "r-1"})
        assert len(mgr._failed_queue) == 1

        # Set next_retry to now so it's eligible
        mgr._failed_queue[0]["next_retry"] = time.monotonic() - 1

        # Retry succeeds
        with patch.object(mgr, "_http_post", return_value=200):
            successes = await mgr.retry_failed()
        assert successes == 1
        assert len(mgr._failed_queue) == 0
        assert wh["consecutive_failures"] == 0

    @pytest.mark.asyncio
    async def test_retry_failed_still_failing(self):
        mgr = NotificationManager()
        mgr.add_webhook("https://example.com/hook", severity_filter=["critical"])
        with patch.object(mgr, "_http_post", side_effect=ConnectionError("refused")):
            with patch("sigrift.bridge.notifications.asyncio.sleep", return_value=None):
                await mgr.notify({"severity": "critical", "alert_id": "r-2"})

        mgr._failed_queue[0]["next_retry"] = time.monotonic() - 1

        # Retry also fails
        with patch.object(mgr, "_http_post", side_effect=ConnectionError("still down")):
            successes = await mgr.retry_failed()
        assert successes == 0
        assert len(mgr._failed_queue) == 1
        assert mgr._failed_queue[0]["attempts"] == 2

    @pytest.mark.asyncio
    async def test_retry_drops_after_max_attempts(self):
        mgr = NotificationManager()
        mgr.add_webhook("https://example.com/hook", severity_filter=["critical"])
        with patch.object(mgr, "_http_post", side_effect=ConnectionError("refused")):
            with patch("sigrift.bridge.notifications.asyncio.sleep", return_value=None):
                await mgr.notify({"severity": "critical", "alert_id": "r-3"})

        # Set attempts to max - 1 so next failure hits the limit
        mgr._failed_queue[0]["attempts"] = _MAX_RETRY_QUEUE_ATTEMPTS - 1
        mgr._failed_queue[0]["next_retry"] = time.monotonic() - 1

        with patch.object(mgr, "_http_post", side_effect=ConnectionError("still down")):
            successes = await mgr.retry_failed()
        assert successes == 0
        assert len(mgr._failed_queue) == 0  # dropped

    @pytest.mark.asyncio
    async def test_retry_skips_not_ready(self):
        mgr = NotificationManager()
        mgr.add_webhook("https://example.com/hook", severity_filter=["critical"])
        with patch.object(mgr, "_http_post", side_effect=ConnectionError("refused")):
            with patch("sigrift.bridge.notifications.asyncio.sleep", return_value=None):
                await mgr.notify({"severity": "critical", "alert_id": "r-4"})

        # next_retry is in the future, should be skipped
        mgr._failed_queue[0]["next_retry"] = time.monotonic() + 9999

        with patch.object(mgr, "_http_post", return_value=200):
            successes = await mgr.retry_failed()
        assert successes == 0
        assert len(mgr._failed_queue) == 1  # still in queue

    @pytest.mark.asyncio
    async def test_retry_drops_deleted_webhook(self):
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook", severity_filter=["critical"])
        with patch.object(mgr, "_http_post", side_effect=ConnectionError("refused")):
            with patch("sigrift.bridge.notifications.asyncio.sleep", return_value=None):
                await mgr.notify({"severity": "critical", "alert_id": "r-5"})

        mgr._failed_queue[0]["next_retry"] = time.monotonic() - 1
        # Remove the webhook
        mgr.remove_webhook(wh["id"])

        successes = await mgr.retry_failed()
        assert successes == 0
        assert len(mgr._failed_queue) == 0  # dropped, webhook gone

    @pytest.mark.asyncio
    async def test_retry_exponential_backoff(self):
        mgr = NotificationManager()
        mgr.add_webhook("https://example.com/hook", severity_filter=["critical"])
        with patch.object(mgr, "_http_post", side_effect=ConnectionError("refused")):
            with patch("sigrift.bridge.notifications.asyncio.sleep", return_value=None):
                await mgr.notify({"severity": "critical", "alert_id": "r-6"})

        mgr._failed_queue[0]["next_retry"] = time.monotonic() - 1

        before = time.monotonic()
        with patch.object(mgr, "_http_post", side_effect=ConnectionError("still down")):
            await mgr.retry_failed()

        # After attempt 2, delay should be _RETRY_DELAY_SECONDS * 2^2 = 20
        entry = mgr._failed_queue[0]
        expected_delay = min(300, _RETRY_DELAY_SECONDS * (2 ** entry["attempts"]))
        assert entry["next_retry"] >= before + expected_delay - 1


class TestPortValidation:
    """Test port blocking for webhook URLs."""

    def test_standard_ports_allowed(self):
        assert _is_port_allowed(80) is True
        assert _is_port_allowed(443) is True
        assert _is_port_allowed(8080) is True
        assert _is_port_allowed(8443) is True

    def test_none_port_allowed(self):
        assert _is_port_allowed(None) is True

    def test_blocked_ports_rejected(self):
        for port in BLOCKED_PORTS:
            assert _is_port_allowed(port) is False, f"Port {port} should be blocked"

    def test_high_port_allowed(self):
        assert _is_port_allowed(9090) is True
        assert _is_port_allowed(3000) is True

    def test_low_port_rejected(self):
        # Ports below 1024 (other than 80/443) should be rejected
        assert _is_port_allowed(22) is False
        assert _is_port_allowed(25) is False
        assert _is_port_allowed(53) is False


class TestDNSRebindingProtection:
    """Test DNS re-validation at delivery time."""

    @pytest.mark.asyncio
    async def test_delivery_checks_dns_at_delivery_time(self):
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook", severity_filter=["critical"])

        # Mock DNS resolution to return a private IP (DNS rebinding)
        def fake_resolve(hostname):
            raise ValueError("Webhook target resolves to blocked network: 127.0.0.1")

        with patch(
            "sigrift.bridge.notifications._resolve_and_check_ip",
            side_effect=fake_resolve,
        ):
            count = await mgr.notify({"severity": "critical", "alert_id": "dns-1"})

        assert count == 0
        assert wh["failure_count"] == 1
        assert "blocked network" in wh["last_error"]

    @pytest.mark.asyncio
    async def test_delivery_blocked_port_rejected(self):
        mgr = NotificationManager()
        wh = mgr.add_webhook(
            "https://example.com:6379/hook", severity_filter=["critical"]
        )

        with patch("sigrift.bridge.notifications._resolve_and_check_ip"):
            count = await mgr.notify({"severity": "critical", "alert_id": "port-1"})

        assert count == 0
        assert wh["failure_count"] == 1
        assert "blocked" in wh["last_error"].lower()

    @pytest.mark.asyncio
    async def test_dns_rebinding_enqueues_to_failed_queue(self):
        mgr = NotificationManager()
        mgr.add_webhook("https://example.com/hook", severity_filter=["critical"])

        def fake_resolve(hostname):
            raise ValueError("Webhook target resolves to blocked network")

        with patch(
            "sigrift.bridge.notifications._resolve_and_check_ip",
            side_effect=fake_resolve,
        ):
            await mgr.notify({"severity": "critical", "alert_id": "dns-2"})

        assert len(mgr.failed_queue) == 1

    def test_resolve_and_check_ip_blocks_loopback(self):
        """_resolve_and_check_ip raises for loopback addresses."""
        with patch("sigrift.bridge.notifications.socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (2, 1, 6, "", ("127.0.0.1", 0)),
            ]
            with pytest.raises(ValueError, match="blocked network"):
                _resolve_and_check_ip("evil.example.com")

    def test_resolve_and_check_ip_allows_public(self):
        """_resolve_and_check_ip allows public IP addresses."""
        with patch("sigrift.bridge.notifications.socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (2, 1, 6, "", ("93.184.216.34", 0)),
            ]
            # Should not raise
            _resolve_and_check_ip("example.com")


class TestRetryQueueEndpoint:
    """Test the /api/admin/webhooks/retry-queue endpoint."""

    def test_retry_queue_empty(self, client):
        resp = client.get("/api/admin/webhooks/retry-queue")
        assert resp.status_code == 200
        data = resp.json()
        assert data["queue_size"] == 0
        assert data["entries"] == []

    def test_retry_queue_with_entries(self, client, bridge_app):
        notifier = bridge_app.state.notifier
        # Manually add a failed queue entry
        notifier._failed_queue.append(
            {
                "webhook_id": "test-wh",
                "payload": {"event": "alert"},
                "attempts": 2,
                "last_error": "Connection refused",
                "next_retry": time.monotonic() + 60,
            }
        )
        resp = client.get("/api/admin/webhooks/retry-queue")
        assert resp.status_code == 200
        data = resp.json()
        assert data["queue_size"] == 1
        assert data["entries"][0]["webhook_id"] == "test-wh"
        assert data["entries"][0]["attempts"] == 2
        assert data["entries"][0]["last_error"] == "Connection refused"
        assert data["entries"][0]["retry_in_seconds"] > 0


class TestAdminPortValidation:
    """Test port validation in webhook creation via admin endpoint."""

    def test_create_webhook_blocked_port_rejected(self, client):
        with patch(
            "sigrift.bridge.routers.webhook_management.socket.getaddrinfo"
        ) as mock_gai:
            mock_gai.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
            resp = client.post(
                "/api/admin/webhooks",
                json={
                    "url": "https://example.com:6379/hook",
                    "name": "Redis SSRF",
                },
            )
        assert resp.status_code == 400
        assert "not allowed" in resp.json()["detail"].lower()

    def test_create_webhook_allowed_port_accepted(self, client, bridge_app):
        with patch(
            "sigrift.bridge.routers.webhook_management.socket.getaddrinfo"
        ) as mock_gai:
            mock_gai.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
            resp = client.post(
                "/api/admin/webhooks",
                json={
                    "url": "https://example.com:8443/hook",
                    "name": "Valid Hook",
                },
            )
        assert resp.status_code == 201


class TestWebhookHMACSigning:
    """Test HMAC-SHA256 signing of webhook payloads."""

    def test_add_webhook_generates_signing_secret(self):
        """New webhooks should have a signing_secret generated."""
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook")
        assert "signing_secret" in wh
        assert isinstance(wh["signing_secret"], str)
        assert len(wh["signing_secret"]) == 64  # hex(32)

    def test_compute_signature_format(self):
        """compute_signature returns sha256=<hex_digest> format."""
        secret = "a" * 64
        body = b'{"test": true}'
        sig = NotificationManager.compute_signature(secret, body)
        assert sig.startswith("sha256=")
        hex_part = sig[len("sha256=") :]
        assert len(hex_part) == 64  # SHA-256 hex digest length

    def test_compute_signature_correctness(self):
        """Computed signature matches manual HMAC-SHA256."""
        secret = "mysecret123"
        body = b'{"event": "alert"}'
        sig = NotificationManager.compute_signature(secret, body)
        expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        assert sig == f"sha256={expected}"

    def test_different_secrets_produce_different_signatures(self):
        """Different secrets produce different signatures for the same body."""
        body = b'{"event": "alert"}'
        sig1 = NotificationManager.compute_signature("secret1", body)
        sig2 = NotificationManager.compute_signature("secret2", body)
        assert sig1 != sig2

    @pytest.mark.asyncio
    async def test_delivery_sends_signature_header(self):
        """_http_post is called with the HMAC signature."""
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook", severity_filter=["critical"])
        signing_secret = wh["signing_secret"]

        captured_args = {}

        def mock_http_post(url, data, signature=None, addresses=None):
            captured_args["addresses"] = addresses
            captured_args["url"] = url
            captured_args["data"] = data
            captured_args["signature"] = signature
            return 200

        with patch.object(mgr, "_http_post", side_effect=mock_http_post):
            count = await mgr.notify(
                {
                    "severity": "critical",
                    "alert_id": "sig-1",
                    "name": "test",
                }
            )

        assert count == 1
        # The delivery connects to the addresses vetted at check time.
        assert captured_args["addresses"]
        assert captured_args["signature"] is not None
        assert isinstance(captured_args["signature"], str)
        assert captured_args["signature"].startswith("sha256=")

        # Verify the signature matches the payload
        expected = NotificationManager.compute_signature(
            signing_secret,
            captured_args["data"],
        )
        assert captured_args["signature"] == expected

    @pytest.mark.asyncio
    async def test_delivery_without_signing_secret(self):
        """Webhooks without signing_secret still deliver (no signature header)."""
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook", severity_filter=["critical"])
        # Remove signing_secret to simulate legacy webhook
        del wh["signing_secret"]

        captured_args = {}

        def mock_http_post(url, data, signature=None, addresses=None):
            captured_args["addresses"] = addresses
            captured_args["signature"] = signature
            return 200

        with patch.object(mgr, "_http_post", side_effect=mock_http_post):
            count = await mgr.notify(
                {
                    "severity": "critical",
                    "alert_id": "sig-2",
                }
            )

        assert count == 1
        assert captured_args["signature"] is None

    def test_create_webhook_endpoint_returns_signing_secret(self, client):
        """POST /api/admin/webhooks returns signing_secret in the response."""
        with patch(
            "sigrift.bridge.routers.webhook_management.socket.getaddrinfo"
        ) as mock_gai:
            mock_gai.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
            resp = client.post(
                "/api/admin/webhooks",
                json={
                    "url": "https://example.com/hook",
                    "name": "Signed Hook",
                },
            )
        assert resp.status_code == 201
        data = resp.json()
        assert "signing_secret" in data
        assert isinstance(data["signing_secret"], str)
        assert len(data["signing_secret"]) == 64
        assert "message" in data
        assert isinstance(data["message"], str)
        assert "Save this signing secret" in data["message"]

    def test_list_webhooks_hides_signing_secret(self, client):
        """GET /api/admin/webhooks does not expose signing_secret."""
        with patch(
            "sigrift.bridge.routers.webhook_management.socket.getaddrinfo"
        ) as mock_gai:
            mock_gai.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
            client.post(
                "/api/admin/webhooks",
                json={
                    "url": "https://example.com/hook",
                    "name": "Hidden Secret Hook",
                },
            )
        resp = client.get("/api/admin/webhooks")
        assert resp.status_code == 200
        data = resp.json()
        for wh in data["webhooks"]:
            assert "signing_secret" not in wh
