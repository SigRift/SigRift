"""Tests for the embedded certificate authority.

Covers the CA module (``sigrift.bridge.ca``) and the ``/api/ca/*``
endpoints — Phase A of the PKI rollout.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.ca import CAError, CertificateAuthority


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _private_secrets_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep each test's CA private key in its own tmp dir.

    Without BRIDGE_SECRETS_DIR the key goes to ``secrets/`` next to the
    data dir — for ``tmp_path / "ca"`` that is the parent of ``tmp_path``,
    shared by every test in the session.
    """
    monkeypatch.setenv("BRIDGE_SECRETS_DIR", str(tmp_path / "secrets"))


def _make_csr(common_name: str = "csr-subject-ignored") -> bytes:
    """Return a PEM CSR signed by a fresh EC key."""
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def _load_cert(pem: str | bytes) -> x509.Certificate:
    if isinstance(pem, str):
        pem = pem.encode()
    return x509.load_pem_x509_certificate(pem)


# ---------------------------------------------------------------------------
# CA bootstrap
# ---------------------------------------------------------------------------


class TestBootstrap:
    def test_ensure_ca_creates_cert_and_key(self, tmp_path: Path) -> None:
        ca = CertificateAuthority(tmp_path / "ca")
        assert not ca.is_initialized
        ca.ensure_ca()
        assert ca.is_initialized
        assert (tmp_path / "ca" / "ca.crt").exists()
        assert ca.key_path == tmp_path / "secrets" / "ca" / "ca.key"
        assert ca.key_path.exists()
        # The private key stays out of the CA dir the gateway can read.
        assert not (tmp_path / "ca" / "ca.key").exists()

    def test_ca_is_a_ca_cert(self, tmp_path: Path) -> None:
        ca = CertificateAuthority(tmp_path / "ca")
        ca.ensure_ca()
        cert = _load_cert(ca.ca_cert_pem)
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True

    def test_ensure_ca_idempotent(self, tmp_path: Path) -> None:
        ca = CertificateAuthority(tmp_path / "ca")
        ca.ensure_ca()
        cert_bytes = (tmp_path / "ca" / "ca.crt").read_bytes()
        ca.ensure_ca()  # second call must not regenerate
        assert (tmp_path / "ca" / "ca.crt").read_bytes() == cert_bytes

    def test_ca_key_is_private_mode(self, tmp_path: Path) -> None:
        ca = CertificateAuthority(tmp_path / "ca")
        ca.ensure_ca()
        mode = ca.key_path.stat().st_mode & 0o777
        assert mode == 0o600

    def test_signing_before_bootstrap_raises(self, tmp_path: Path) -> None:
        ca = CertificateAuthority(tmp_path / "ca")
        with pytest.raises(CAError):
            ca.sign_csr(_make_csr(), identity="x", role="node")


# ---------------------------------------------------------------------------
# CSR signing
# ---------------------------------------------------------------------------


class TestSigning:
    @pytest.fixture
    def ca(self, tmp_path: Path) -> CertificateAuthority:
        ca = CertificateAuthority(tmp_path / "ca")
        ca.ensure_ca()
        return ca

    def test_sign_produces_client_auth_cert(self, ca: CertificateAuthority) -> None:
        result = ca.sign_csr(_make_csr(), identity="local-edge", role="node")
        cert = _load_cert(result["cert_pem"])

        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

    def test_signed_cert_chains_to_ca(self, ca: CertificateAuthority) -> None:
        result = ca.sign_csr(_make_csr(), identity="local-edge", role="node")
        leaf = _load_cert(result["cert_pem"])
        ca_cert = _load_cert(ca.ca_cert_pem)
        # Raises on failure, returns None on success.
        assert leaf.verify_directly_issued_by(ca_cert) is None

    def test_identity_becomes_cn_and_san(self, ca: CertificateAuthority) -> None:
        result = ca.sign_csr(_make_csr(), identity="scanner-7", role="node")
        cert = _load_cert(result["cert_pem"])
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "scanner-7"
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert san.value.get_values_for_type(x509.DNSName) == ["scanner-7"]

    def test_csr_subject_is_ignored(self, ca: CertificateAuthority) -> None:
        """A CSR claiming a different CN cannot override the granted identity."""
        result = ca.sign_csr(
            _make_csr(common_name="admin-impersonator"),
            identity="honest-node",
            role="node",
        )
        cert = _load_cert(result["cert_pem"])
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "honest-node"

    def test_invalid_role_rejected(self, ca: CertificateAuthority) -> None:
        with pytest.raises(CAError):
            ca.sign_csr(_make_csr(), identity="x", role="keymaster")

    @pytest.mark.parametrize("bad", ["", "-leading", "has space", "a/b", "x" * 300])
    def test_invalid_identity_rejected(
        self, ca: CertificateAuthority, bad: str
    ) -> None:
        with pytest.raises(CAError):
            ca.sign_csr(_make_csr(), identity=bad, role="node")

    def test_malformed_csr_rejected(self, ca: CertificateAuthority) -> None:
        with pytest.raises(CAError):
            ca.sign_csr(
                b"-----BEGIN CERTIFICATE REQUEST-----\nnonsense\n",
                identity="x",
                role="node",
            )

    def test_bad_ttl_rejected(self, ca: CertificateAuthority) -> None:
        with pytest.raises(CAError):
            ca.sign_csr(_make_csr(), identity="x", role="node", ttl_days=0)

    def test_issue_cert_generates_matching_keypair(
        self, ca: CertificateAuthority
    ) -> None:
        result = ca.issue_cert(identity="auto-keyed", role="node")
        assert "cert_pem" in result and "key_pem" in result

        key = serialization.load_pem_private_key(
            result["key_pem"].encode(), password=None
        )
        cert = _load_cert(result["cert_pem"])
        # The cert must be bound to the public half of the generated key.
        assert cert.public_key().public_numbers() == key.public_key().public_numbers()
        assert cert.verify_directly_issued_by(_load_cert(ca.ca_cert_pem)) is None

    def test_issue_cert_rejects_bad_identity(self, ca: CertificateAuthority) -> None:
        with pytest.raises(CAError):
            ca.issue_cert(identity="bad identity", role="node")


# ---------------------------------------------------------------------------
# Revocation + CRL
# ---------------------------------------------------------------------------


class TestRevocationAndCRL:
    @pytest.fixture
    def ca(self, tmp_path: Path) -> CertificateAuthority:
        ca = CertificateAuthority(tmp_path / "ca")
        ca.ensure_ca()
        return ca

    def test_empty_crl_is_signed_and_valid(self, ca: CertificateAuthority) -> None:
        crl = x509.load_pem_x509_crl(ca.generate_crl())
        ca_cert = _load_cert(ca.ca_cert_pem)
        assert crl.is_signature_valid(ca_cert.public_key())
        assert len(crl) == 0

    def test_revoked_serial_appears_in_crl(self, ca: CertificateAuthority) -> None:
        keep = ca.sign_csr(_make_csr(), identity="keeper", role="node")
        kill = ca.sign_csr(_make_csr(), identity="doomed", role="node")

        assert ca.revoke(kill["serial"]) is True

        crl = x509.load_pem_x509_crl(ca.generate_crl())
        revoked_serials = {entry.serial_number for entry in crl}
        assert int(kill["serial"]) in revoked_serials
        assert int(keep["serial"]) not in revoked_serials

    def test_revoke_unknown_serial_returns_false(
        self, ca: CertificateAuthority
    ) -> None:
        assert ca.revoke("99999999") is False

    def test_revoke_is_idempotent(self, ca: CertificateAuthority) -> None:
        issued = ca.sign_csr(_make_csr(), identity="n", role="node")
        assert ca.revoke(issued["serial"]) is True
        first = ca.get_cert(issued["serial"])["revoked_at"]
        assert ca.revoke(issued["serial"]) is True
        assert ca.get_cert(issued["serial"])["revoked_at"] == first

    def test_registry_survives_reopen(self, tmp_path: Path) -> None:
        ca = CertificateAuthority(tmp_path / "ca")
        ca.ensure_ca()
        issued = ca.sign_csr(_make_csr(), identity="persisted", role="node")

        reopened = CertificateAuthority(tmp_path / "ca")
        rows = reopened.list_certs()
        assert [r["serial"] for r in rows] == [issued["serial"]]
        assert rows[0]["identity"] == "persisted"

    def test_foreign_cert_not_issued_by_our_ca(self, ca: CertificateAuthority) -> None:
        """A cert from an unrelated CA must not verify against ours."""
        foreign = CertificateAuthority(ca._dir.parent / "foreign-ca")
        foreign.ensure_ca()
        foreign_leaf = _load_cert(
            foreign.sign_csr(_make_csr(), identity="intruder", role="node")["cert_pem"]
        )
        our_ca = _load_cert(ca.ca_cert_pem)
        with pytest.raises(Exception):
            foreign_leaf.verify_directly_issued_by(our_ca)


# ---------------------------------------------------------------------------
# /api/ca/* endpoints
# ---------------------------------------------------------------------------


class TestCaEndpoints:
    def test_get_ca_pem(self, client: TestClient) -> None:
        resp = client.get("/api/ca/ca.pem")
        assert resp.status_code == 200
        cert = _load_cert(resp.content)
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True

    def test_ca_pem_is_unauthenticated(self, bridge_app: FastAPI) -> None:
        """Trust bootstrap: ca.pem must be reachable without an API key."""
        no_auth = TestClient(bridge_app)
        assert no_auth.get("/api/ca/ca.pem").status_code == 200

    def test_sign_endpoint(self, client: TestClient) -> None:
        resp = client.post(
            "/api/ca/sign",
            json={
                "csr_pem": _make_csr().decode(),
                "identity": "local-edge",
                "role": "node",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["identity"] == "local-edge"
        assert data["role"] == "node"
        assert "cert_pem" in data and "ca_pem" in data
        leaf = _load_cert(data["cert_pem"])
        assert leaf.verify_directly_issued_by(_load_cert(data["ca_pem"])) is None

    def test_issue_endpoint_returns_cert_and_key(self, client: TestClient) -> None:
        resp = client.post(
            "/api/ca/issue",
            json={"identity": "auto-node", "role": "node"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["identity"] == "auto-node"
        assert "cert_pem" in data and "key_pem" in data and "ca_pem" in data
        leaf = _load_cert(data["cert_pem"])
        assert leaf.verify_directly_issued_by(_load_cert(data["ca_pem"])) is None

    def test_sign_endpoint_rejects_bad_csr(self, client: TestClient) -> None:
        resp = client.post(
            "/api/ca/sign",
            json={"csr_pem": "not a csr", "identity": "x", "role": "node"},
        )
        assert resp.status_code == 400

    def test_sign_endpoint_requires_master_key(self, bridge_app: FastAPI) -> None:
        no_auth = TestClient(bridge_app)
        resp = no_auth.post(
            "/api/ca/sign",
            json={
                "csr_pem": _make_csr().decode(),
                "identity": "x",
                "role": "node",
            },
        )
        assert resp.status_code in (401, 403)

    def test_certs_listing(self, client: TestClient) -> None:
        client.post(
            "/api/ca/sign",
            json={
                "csr_pem": _make_csr().decode(),
                "identity": "listed-node",
                "role": "node",
            },
        )
        resp = client.get("/api/ca/certs")
        assert resp.status_code == 200
        assert any(c["identity"] == "listed-node" for c in resp.json())

    def test_revoke_endpoint_and_crl(self, client: TestClient) -> None:
        signed = client.post(
            "/api/ca/sign",
            json={
                "csr_pem": _make_csr().decode(),
                "identity": "to-revoke",
                "role": "node",
            },
        ).json()
        serial = signed["serial"]

        resp = client.post(f"/api/ca/revoke/{serial}")
        assert resp.status_code == 200

        crl = x509.load_pem_x509_crl(client.get("/api/ca/crl.pem").content)
        assert int(serial) in {entry.serial_number for entry in crl}

    def test_revoke_unknown_serial_404(self, client: TestClient) -> None:
        assert client.post("/api/ca/revoke/123456789").status_code == 404
