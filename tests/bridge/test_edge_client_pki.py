"""Tests for edge-scanner client-cert (mTLS) auth — PKI Phase A.

The five edge scanners (node_agent, rf_scan, wifi_scan,
detection_reporter, bt_scanner) each carry an identical client-cert
helper block. ``node_agent`` is imported here as the representative —
it is the only scanner with no third-party imports — and exercises the
shared logic: env detection, SSL-context wiring, and header selection.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import sigrift.edge.node_agent as na


def _write_cert_key(tmp_path: Path) -> tuple[str, str]:
    """Generate a throwaway EC cert + key; return their paths as strings."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-edge")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "client.crt"
    key_path = tmp_path / "client.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


def _write_mismatched_cert_key(tmp_path: Path) -> tuple[str, str]:
    """Write a cert and a NON-matching key — both files exist but
    ssl.load_cert_chain rejects the pair (the regenerate-cert-not-key
    operational footgun)."""
    cert_path, key_path = _write_cert_key(tmp_path)
    unrelated = ec.generate_private_key(ec.SECP256R1())
    Path(key_path).write_bytes(
        unrelated.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@pytest.fixture(autouse=True)
def _clear_pki_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test starts with client-cert env unset and mTLS inactive."""
    monkeypatch.delenv("MLRF_CLIENT_CERT", raising=False)
    monkeypatch.delenv("MLRF_CLIENT_KEY", raising=False)
    monkeypatch.setattr(na, "_cert_auth_active", False)


class TestCertPairDetection:
    def test_no_env_means_no_pair(self) -> None:
        assert na._client_cert_pair() is None

    def test_both_set_and_existing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cert, key = _write_cert_key(tmp_path)
        monkeypatch.setenv("MLRF_CLIENT_CERT", cert)
        monkeypatch.setenv("MLRF_CLIENT_KEY", key)
        assert na._client_cert_pair() == (cert, key)

    def test_partial_env_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cert, _ = _write_cert_key(tmp_path)
        monkeypatch.setenv("MLRF_CLIENT_CERT", cert)
        # MLRF_CLIENT_KEY left unset
        assert na._client_cert_pair() is None

    def test_missing_files_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MLRF_CLIENT_CERT", "/nonexistent/c.crt")
        monkeypatch.setenv("MLRF_CLIENT_KEY", "/nonexistent/c.key")
        assert na._client_cert_pair() is None


class TestAuthHeaders:
    def test_api_key_header_without_cert(self) -> None:
        assert na._auth_headers("secret-key") == {"X-API-Key": "secret-key"}

    def test_no_api_key_header_under_mtls(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import ssl

        cert, key = _write_cert_key(tmp_path)
        monkeypatch.setenv("MLRF_CLIENT_CERT", cert)
        monkeypatch.setenv("MLRF_CLIENT_KEY", key)
        # mTLS is "active" only once the cert has actually loaded.
        na._apply_client_cert(ssl.create_default_context())
        # Under mTLS the identity is the certificate — no API key is sent.
        assert na._auth_headers("secret-key") == {}

    def test_broken_cert_falls_back_to_api_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import ssl

        # Cert + key files both exist, but the pair does not load.
        cert, key = _write_mismatched_cert_key(tmp_path)
        monkeypatch.setenv("MLRF_CLIENT_CERT", cert)
        monkeypatch.setenv("MLRF_CLIENT_KEY", key)
        na._apply_client_cert(ssl.create_default_context())
        # The load failed, so mTLS is not active — the scanner must still
        # send X-API-Key rather than no credential at all.
        assert na._cert_auth_active is False
        assert na._auth_headers("secret-key") == {"X-API-Key": "secret-key"}


class TestApplyClientCert:
    def test_loads_cert_into_context(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import ssl

        cert, key = _write_cert_key(tmp_path)
        monkeypatch.setenv("MLRF_CLIENT_CERT", cert)
        monkeypatch.setenv("MLRF_CLIENT_KEY", key)
        ctx = ssl.create_default_context()
        na._apply_client_cert(ctx)
        # A cert chain is now loaded and mTLS auth is marked active.
        assert ctx.get_ca_certs() is not None  # context usable
        assert ctx.cert_store_stats()["x509"] >= 0
        assert na._cert_auth_active is True

    def test_noop_without_env(self) -> None:
        import ssl

        ctx = ssl.create_default_context()
        # No env configured — must not raise.
        na._apply_client_cert(ctx)
