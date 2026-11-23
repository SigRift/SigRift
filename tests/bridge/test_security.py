"""Security tests for The Bridge.

Covers:
  - SQL injection in query parameters
  - Malformed JSON body to batch ingest
  - Oversized payload (very large batch)
  - Invalid/missing API key
  - Wrong HTTP methods on endpoints
  - XSS in node_id or signal_class fields
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# SQL injection
# ---------------------------------------------------------------------------

class TestSQLInjection:
    """Verify SQL injection attempts are safely handled."""

    def test_sqli_in_node_id_registration(self, client: TestClient) -> None:
        """SQL injection in node_id during registration is rejected by validation."""
        resp = client.post("/api/nodes/register", json={
            "node_id": "'; DROP TABLE detections;--",
            "host": "10.0.0.1",
            "port": 8080,
        })
        # The _validate_id pattern only allows [a-zA-Z0-9_-], so this should fail
        assert resp.status_code == 422

    def test_sqli_in_query_signal_class(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """SQL injection in signal_class query param is harmless."""
        resp = client.post("/api/detections/query", json={
            "signal_class": "bpsk' OR 1=1;--",
        })
        # Should be rejected by model validation or return empty (parameterised queries)
        assert resp.status_code in (200, 422)
        if resp.status_code == 200:
            # If 200, the query just returns no results (parameterised)
            assert resp.json()["count"] == 0

    def test_sqli_in_query_node_id(self, client: TestClient) -> None:
        """SQL injection in node_id query param is harmless."""
        resp = client.post("/api/detections/query", json={
            "node_id": "x' UNION SELECT * FROM keys;--",
        })
        assert resp.status_code in (200, 422)
        if resp.status_code == 200:
            assert resp.json()["count"] == 0

    def test_sqli_in_recent_node_id_param(self, client: TestClient) -> None:
        """SQL injection via query string param is safely handled."""
        resp = client.get(
            "/api/detections/recent",
            params={"node_id": "'; DROP TABLE detections;--"},
        )
        # Parameterised queries ensure this is safe
        assert resp.status_code == 200
        assert resp.json()["count"] == 0

    def test_sqli_in_export_node_id(self, client: TestClient) -> None:
        """SQL injection in export endpoint node_id param."""
        resp = client.get(
            "/api/export/detections",
            params={"node_id": "x'; DELETE FROM detections;--"},
        )
        # Should be safe via parameterised queries
        assert resp.status_code == 200

# ---------------------------------------------------------------------------
# Malformed JSON
# ---------------------------------------------------------------------------

class TestMalformedJSON:
    """Verify malformed requests are rejected gracefully."""

    def test_invalid_json_body(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Invalid JSON body returns 400 or 422."""
        resp = client.post(
            "/api/detections/batch",
            content=b"not valid json {{{",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code in (400, 422)

    def test_empty_body(self, client: TestClient) -> None:
        """Empty body returns 400 or 422."""
        resp = client.post(
            "/api/detections/batch",
            content=b"",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code in (400, 422)

    def test_wrong_content_type(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Non-JSON content type is rejected."""
        resp = client.post(
            "/api/detections/batch",
            content=b"<xml>not json</xml>",
            headers={"Content-Type": "application/xml"},
        )
        assert resp.status_code in (400, 422)

    def test_missing_required_fields(self, client: TestClient) -> None:
        """Missing required fields return 422."""
        resp = client.post("/api/detections/batch", json={
            "detections": [],
        })
        assert resp.status_code == 422

    def test_invalid_confidence_range(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Confidence outside [0, 1] is rejected."""
        now = datetime.now(timezone.utc)
        resp = client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=1)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {
                    "node_id": registered_node,
                    "signal_class": "bpsk",
                    "confidence": 5.0,  # invalid
                },
            ],
        })
        assert resp.status_code == 422

# ---------------------------------------------------------------------------
# Oversized payload
# ---------------------------------------------------------------------------

class TestOversizedPayload:
    """Verify the system handles very large batches gracefully."""

    def test_large_batch(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """A very large batch (1000 detections) is accepted or gracefully handled."""
        now = datetime.now(timezone.utc)
        detections = [
            {
                "node_id": registered_node,
                "signal_class": "bpsk",
                "confidence": 0.9,
                "family": "psk",
                "freq_hz": 433.92e6,
            }
            for _ in range(1000)
        ]
        resp = client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=5)).isoformat(),
            "period_end": now.isoformat(),
            "detections": detections,
        })
        # Should accept (each detection gets a unique ID from uuid default)
        assert resp.status_code == 201
        data = resp.json()
        assert data["accepted"] is True
        assert data["inserted"] == 1000

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

class TestAuthSecurity:
    """Test authentication edge cases."""

    def test_no_api_key(self, bridge_app: FastAPI) -> None:
        """Requests without API key return 401."""
        unauth = TestClient(bridge_app)
        resp = unauth.get("/api/detections/stats")
        assert resp.status_code == 401

    def test_invalid_api_key(self, bridge_app: FastAPI) -> None:
        """Invalid API key returns 401."""
        bad = TestClient(bridge_app, headers={"X-API-Key": "totally-bogus-key"})
        resp = bad.get("/api/detections/stats")
        assert resp.status_code == 401

    def test_empty_api_key(self, bridge_app: FastAPI) -> None:
        """Empty API key header returns 401."""
        empty = TestClient(bridge_app, headers={"X-API-Key": ""})
        resp = empty.get("/api/detections/stats")
        assert resp.status_code == 401

    def test_api_key_via_query_param(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """API key can also be passed via query parameter."""
        no_header = TestClient(bridge_app)
        resp = no_header.get(
            "/api/detections/stats",
            params={"api_key": master_key},
        )
        assert resp.status_code == 200

# ---------------------------------------------------------------------------
# Wrong HTTP methods
# ---------------------------------------------------------------------------

class TestWrongMethods:
    """Verify wrong HTTP methods return 405."""

    def test_get_on_batch_endpoint(self, client: TestClient) -> None:
        """GET on POST-only /api/detections/batch returns 404 or 405.

        FastAPI routes GET /api/detections/batch to the /{detection_id}
        catch-all handler (which returns 404) rather than matching the
        POST-only /batch route and returning 405.
        """
        resp = client.get("/api/detections/batch")
        assert resp.status_code in (404, 405)

    def test_delete_on_stats_endpoint(self, client: TestClient) -> None:
        """DELETE on GET-only /api/detections/stats returns 405."""
        resp = client.delete("/api/detections/stats")
        assert resp.status_code == 405

    def test_put_on_keys_list(self, client: TestClient) -> None:
        """PUT on /api/keys/ (GET/POST only) returns 405."""
        resp = client.put("/api/keys/", json={})
        assert resp.status_code == 405

    def test_post_on_recent(self, client: TestClient) -> None:
        """POST on GET-only /api/detections/recent returns 405."""
        resp = client.post("/api/detections/recent", json={})
        assert resp.status_code == 405

# ---------------------------------------------------------------------------
# XSS / HTML injection
# ---------------------------------------------------------------------------

class TestXSSPrevention:
    """Verify HTML/script injection is escaped or rejected."""

    def test_xss_in_node_id_rejected(self, client: TestClient) -> None:
        """Script tags in node_id are rejected by validation."""
        resp = client.post("/api/nodes/register", json={
            "node_id": "<script>alert(1)</script>",
            "host": "10.0.0.1",
            "port": 8080,
        })
        # node_id validation pattern rejects special chars
        assert resp.status_code == 422

    @pytest.mark.parametrize("node_id", ["edge-01\n", "\nedge-01", "edge-01\r\n"])
    def test_node_id_with_a_newline_rejected(
        self, client: TestClient, registered_node: str, node_id: str,
    ) -> None:
        """A trailing newline is refused like any other character outside
        [a-zA-Z0-9_-] (it used to pass the pattern's ``$``): "edge-01\\n"
        would list as a second node that looks like "edge-01".  The gateway's
        ``validate_node_id`` refuses the same ids.
        """
        resp = client.post("/api/nodes/register", json={
            "node_id": node_id, "host": "10.0.0.1", "port": 8080,
        })
        assert resp.status_code == 422
        resp = client.post("/api/keys/", json={"key_id": node_id})
        assert resp.status_code == 422
        now = datetime.now(timezone.utc)
        resp = client.post("/api/detections/batch", json={
            "node_id": node_id,
            "period_start": (now - timedelta(minutes=1)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [],
        })
        assert resp.status_code == 422
        ids = [n["node_id"] for n in client.get("/api/nodes/").json()]
        assert ids == [registered_node]

    def test_xss_in_key_description_escaped(self, client: TestClient) -> None:
        """HTML in key description is escaped, not reflected raw."""
        resp = client.post("/api/keys/", json={
            "key_id": "xss-test-key",
            "description": "<script>alert('xss')</script>",
        })
        assert resp.status_code == 201
        data = resp.json()
        # html.escape should convert < > to &lt; &gt;
        assert "<script>" not in data["description"]
        assert "&lt;script&gt;" in data["description"]

    def test_xss_in_alert_name_escaped(self, client: TestClient) -> None:
        """HTML in alert name is escaped."""
        resp = client.post("/api/alerts/rules", json={
            "name": "<img onerror=alert(1) src=x>",
            "severity": "warning",
            "thresholds": {},
        })
        assert resp.status_code == 201
        data = resp.json()
        assert "<img" not in data["name"]

    def test_signal_class_validation_blocks_html(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Signal class with HTML chars is rejected by pattern validation."""
        now = datetime.now(timezone.utc)
        resp = client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=1)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {
                    "node_id": registered_node,
                    "signal_class": "<script>evil</script>",
                    "confidence": 0.9,
                },
            ],
        })
        # _SIGNAL_CLASS_PATTERN only allows [a-zA-Z0-9_/.-]
        assert resp.status_code == 422

    @pytest.mark.parametrize(
        "field", [{"signal_class": "lora-css\n"}, {"backend": "onnx\n"}],
    )
    def test_detection_fields_with_a_trailing_newline_rejected(
        self, client: TestClient, registered_node: str, field: dict,
    ) -> None:
        """As the gateway's validate_signal_class / validate_backend do."""
        now = datetime.now(timezone.utc)
        detection = {
            "node_id": registered_node,
            "signal_class": "lora-css",
            "confidence": 0.9,
        }
        batch = {
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=1)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [detection],
        }
        resp = client.post("/api/detections/batch", json=batch)
        assert resp.status_code == 201, resp.text
        resp = client.post(
            "/api/detections/batch",
            json={**batch, "detections": [{**detection, **field}]},
        )
        assert resp.status_code == 422

# ---------------------------------------------------------------------------
# MAC Anonymization
# ---------------------------------------------------------------------------

class TestMacAnonymization:
    """Tests for MAC address pseudonymization."""

    def test_consistent_pseudonyms(self) -> None:
        """Same MAC + same secret produces same output."""
        from sigrift.bridge.detection_store import DetectionStore
        secret = b"test-secret-1234"
        mac = "aa:bb:cc:dd:ee:ff"
        result1 = DetectionStore._anonymize_mac(mac, secret)
        result2 = DetectionStore._anonymize_mac(mac, secret)
        assert result1 == result2

    def test_preserves_oui_prefix(self) -> None:
        """OUI (first 3 octets) should be preserved."""
        from sigrift.bridge.detection_store import DetectionStore
        secret = b"test-secret-1234"
        mac = "aa:bb:cc:dd:ee:ff"
        result = DetectionStore._anonymize_mac(mac, secret)
        parts = result.split(":")
        assert parts[0] == "aa"
        assert parts[1] == "bb"
        assert parts[2] == "cc"

    def test_different_secrets_different_pseudonyms(self) -> None:
        """Different secrets should produce different pseudonyms."""
        from sigrift.bridge.detection_store import DetectionStore
        mac = "aa:bb:cc:dd:ee:ff"
        r1 = DetectionStore._anonymize_mac(mac, b"secret-A")
        r2 = DetectionStore._anonymize_mac(mac, b"secret-B")
        assert r1 != r2

# ---------------------------------------------------------------------------
# SSID Sanitization
# ---------------------------------------------------------------------------

class TestSSIDSanitization:
    """Tests for SSID control character stripping and truncation.

    SSIDs are stored as heard otherwise: pages escape them on output.
    """

    def test_control_char_stripping(self) -> None:
        """Control characters should be removed from SSIDs."""
        from sigrift.bridge.routers.wifi import _sanitize_ssid
        result = _sanitize_ssid("Test\x00\x01\x1fNet\x7f")
        assert "\x00" not in result
        assert "\x01" not in result
        assert "\x1f" not in result
        assert "\x7f" not in result

    def test_ssid_length_truncation(self) -> None:
        """SSIDs should be truncated to 32 bytes."""
        from sigrift.bridge.routers.wifi import _sanitize_ssid
        result = _sanitize_ssid("A" * 50)
        assert result == "A" * 32
        # Truncated at a byte, not inside a multi-byte character.
        assert _sanitize_ssid("\u00e9" * 20) == "\u00e9" * 16

    def test_markup_and_quotes_are_kept_as_heard(self) -> None:
        """No HTML escaping: the stored SSID is the text the AP sent."""
        from sigrift.bridge.routers.wifi import _sanitize_ssid
        assert _sanitize_ssid("Joe's \"Cafe\" & <b>") == "Joe's \"Cafe\" & <b>"

# ---------------------------------------------------------------------------
# Admin Auth Enforcement
# ---------------------------------------------------------------------------

class TestAdminEndpointSecurity:
    """Verify admin endpoints reject non-master keys."""

    def test_admin_endpoints_reject_non_master(
        self, bridge_app: FastAPI,
    ) -> None:
        """Admin endpoints return 403 with a regular API key."""
        from sigrift.lib.security.credentials import generate_api_key, hash_credential

        persistence = bridge_app.state.persistence
        raw_key = generate_api_key(length=32)
        hash_hex, salt = hash_credential(raw_key)
        persistence.set_key("regular_user", hash_hex, salt)
        persistence.set_key_meta("regular_user", {"role": "analyst"})

        c = TestClient(bridge_app, headers={"X-API-Key": raw_key})
        endpoints = [
            "/api/admin/keys", "/api/admin/nodes", "/api/admin/alerts",
            "/api/admin/audit", "/api/admin/config", "/api/admin/stats",
            "/api/admin/sessions",
        ]
        for ep in endpoints:
            resp = c.get(ep)
            assert resp.status_code == 403, f"{ep} should reject regular keys"

# ---------------------------------------------------------------------------
# Batch Ingest Size Validation
# ---------------------------------------------------------------------------

class TestBatchIngestSizeLimit:
    """Verify batch ingest rejects oversized payloads."""

    def test_body_size_check_exists(self) -> None:
        """Verify the 1MB limit constant is in the detections router."""
        import inspect
        from sigrift.bridge.routers import detections
        source = inspect.getsource(detections.ingest_batch)
        assert "1_048_576" in source or "1048576" in source

# ---------------------------------------------------------------------------
# Audit Log Records Admin Operations
# ---------------------------------------------------------------------------

class TestAuditLogRecordsAdmin:
    """Verify admin actions are recorded in audit log."""

    def test_key_creation_logged(self, client: TestClient) -> None:
        """Creating a key via admin should be logged."""
        resp = client.post("/api/admin/keys", json={"description": "audit-test"})
        assert resp.status_code == 201

        resp = client.get("/api/admin/audit?action=admin_create_key")
        assert resp.status_code == 200
        entries = resp.json()["entries"]
        assert isinstance(entries, list)
        assert len(entries) >= 1
        assert any(e["action"] == "admin_create_key" for e in entries)

# ---------------------------------------------------------------------------
# SSRF Protection
# ---------------------------------------------------------------------------

class TestSSRFProtection:
    """Verify webhook creation blocks SSRF targets."""

    def test_webhook_blocks_localhost(self, client: TestClient) -> None:
        """Webhook URL pointing to localhost is rejected."""
        resp = client.post("/api/admin/webhooks", json={
            "url": "http://127.0.0.1/hook",
            "name": "test-webhook",
            "severity_filter": ["critical"],
        })
        assert resp.status_code == 400
        assert "private" in resp.json()["detail"].lower()

    def test_webhook_blocks_private_10(self, client: TestClient) -> None:
        """Webhook URL in 10.0.0.0/8 range is rejected."""
        resp = client.post("/api/admin/webhooks", json={
            "url": "http://10.1.2.3/hook",
            "name": "test-webhook",
            "severity_filter": ["critical"],
        })
        assert resp.status_code == 400
        assert "private" in resp.json()["detail"].lower()

    def test_webhook_blocks_private_192(self, client: TestClient) -> None:
        """Webhook URL in 192.168.0.0/16 range is rejected."""
        resp = client.post("/api/admin/webhooks", json={
            "url": "http://192.168.1.1/hook",
            "name": "test-webhook",
            "severity_filter": ["warning"],
        })
        assert resp.status_code == 400
        assert "private" in resp.json()["detail"].lower()

    def test_webhook_blocks_aws_imds(self, client: TestClient) -> None:
        """Webhook URL targeting AWS IMDS (169.254.169.254) is rejected."""
        resp = client.post("/api/admin/webhooks", json={
            "url": "http://169.254.169.254/latest/meta-data/",
            "name": "evil-webhook",
            "severity_filter": ["critical"],
        })
        assert resp.status_code == 400
        assert "private" in resp.json()["detail"].lower()

    def test_webhook_blocks_dns_rebinding(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Webhook blocks DNS names resolving to private IPs."""
        import socket

        def mock_getaddrinfo(host: str, port, family, *args, **kwargs):
            # Simulate DNS rebinding: hostname resolves to 127.0.0.1
            if host == "evil.example.com":
                return [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
                ]
            return socket.getaddrinfo(host, port, family, *args, **kwargs)

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

        resp = client.post("/api/admin/webhooks", json={
            "url": "http://evil.example.com/hook",
            "name": "rebinding-test",
            "severity_filter": ["critical"],
        })
        assert resp.status_code == 400
        assert "private" in resp.json()["detail"].lower()

    def test_webhook_allows_public_url(
        self, client: TestClient, bridge_app: FastAPI, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Webhook allows public IP addresses."""
        import socket

        def mock_getaddrinfo(host: str, port, family, *args, **kwargs):
            # Simulate public IP resolution
            if host == "safe.example.com":
                return [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
                ]
            return socket.getaddrinfo(host, port, family, *args, **kwargs)

        monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

        resp = client.post("/api/admin/webhooks", json={
            "url": "http://safe.example.com/hook",
            "name": "public-webhook",
            "severity_filter": ["critical", "warning"],
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["webhook"]["url"] == "http://safe.example.com/hook"

# ---------------------------------------------------------------------------
# Gzip Bomb Protection
# ---------------------------------------------------------------------------

class TestGzipBombProtection:
    """Verify gzip bomb protection on detections batch endpoint."""

    def test_legitimate_gzip_accepted(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Legitimate gzip-compressed batch is accepted."""
        import gzip
        import json

        now = datetime.now(timezone.utc)
        payload = {
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=1)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {
                    "node_id": registered_node,
                    "signal_class": "bpsk",
                    "confidence": 0.9,
                    "family": "psk",
                    "freq_hz": 433.92e6,
                }
                for _ in range(10)
            ],
        }
        compressed = gzip.compress(json.dumps(payload).encode())

        resp = client.post(
            "/api/detections/batch",
            content=compressed,
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["accepted"] is True
        assert data["inserted"] == 10

    def test_gzip_bomb_rejected(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Gzip bomb (>50MB decompressed) is rejected with 413."""
        import gzip

        # Create a highly compressible payload that expands beyond 50MB
        # A string of zeros compresses extremely well
        large_payload = b"0" * (51 * 1024 * 1024)  # 51 MB of zeros
        compressed = gzip.compress(large_payload)

        resp = client.post(
            "/api/detections/batch",
            content=compressed,
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            },
        )
        assert resp.status_code == 413
        assert "50MB" in resp.json()["detail"]

    def test_invalid_gzip_rejected(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Invalid gzip data is rejected with 400."""
        resp = client.post(
            "/api/detections/batch",
            content=b"this is not valid gzip data",
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            },
        )
        assert resp.status_code == 400
        assert "decompress" in resp.json()["detail"].lower()

# ---------------------------------------------------------------------------
# Request Size Middleware
# ---------------------------------------------------------------------------

class TestRequestSizeLimitMiddleware:
    """Verify request size middleware enforces 10MB limit."""

    def test_oversized_request_rejected(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Request with Content-Length > 10MB returns 413."""
        # Send a request with a fake Content-Length header > 10MB
        # TestClient doesn't enforce the actual body size, so we just test the header check
        resp = client.post(
            "/api/detections/batch",
            content=b"{}",
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(11 * 1024 * 1024),  # 11 MB
            },
        )
        assert resp.status_code == 413

    def test_request_within_limit_accepted(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Request within 10MB limit is accepted."""
        now = datetime.now(timezone.utc)
        payload = {
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=1)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {
                    "node_id": registered_node,
                    "signal_class": "bpsk",
                    "confidence": 0.9,
                    "family": "psk",
                    "freq_hz": 433.92e6,
                }
            ],
        }

        # Normal request (well under 10MB)
        resp = client.post("/api/detections/batch", json=payload)
        assert resp.status_code == 201
