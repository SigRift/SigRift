"""Security-path tests for the ``/api/ca/*`` router, end to end over HTTP.

Everything goes through the real bridge app (``create_test_app``), real
API keys in the real key store, real EC keys and CSRs, and the CA's real
files in tmp dirs. The issued certificates are checked with
``cryptography``'s path verifier, so "chains to the CA with the right
constraints" means what a TLS client verifier would accept.

``test_ca.py::TestCaEndpoints`` has the basic happy paths and one
unauthenticated ``/sign``; ``test_gateway_cert_trust.py`` covers forged
gateway headers on ``GET /certs``. This file adds the full lifecycle, the
role matrix for every CA operation, unusable keys, gateway-asserted roles
on the admin operations, input validation, the sensitive rate limit, and
that no private key ever comes back from a listing or a public endpoint.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.ca import CertificateAuthority
from sigrift.bridge.persistence import PersistenceManager
from sigrift.bridge.routers import ca as ca_router
from sigrift.bridge.state import AppState
from sigrift.lib.security.credentials import generate_api_key, hash_credential

_PROXY_SECRET = "ca-router-test-proxy-secret"


@pytest.fixture(autouse=True)
def _private_secrets_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BRIDGE_SECRETS_DIR", str(tmp_path / "secrets"))


@pytest.fixture
def anon(bridge_app: FastAPI) -> TestClient:
    return TestClient(bridge_app)


def _client_with_key(
    bridge_app: FastAPI,
    persistence: PersistenceManager,
    key_id: str,
    role: str,
    **meta: object,
) -> TestClient:
    """A client authenticating with a freshly stored key of *role*."""
    raw = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw)
    persistence.set_key(key_id, hash_hex, salt)
    persistence.set_key_meta(key_id, {"role": role, **meta})
    return TestClient(bridge_app, headers={"X-API-Key": raw})


def _csr_pem(key: ec.EllipticCurvePrivateKey | None = None) -> str:
    key = key or ec.generate_private_key(ec.SECP256R1())
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ignored")]))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )


def _cert(pem: str | bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode() if isinstance(pem, str) else pem)


def _verify_client_cert(
    leaf: x509.Certificate, root: x509.Certificate, at: datetime | None = None
) -> list[x509.GeneralName]:
    verifier = (
        PolicyBuilder()
        .store(Store([root]))
        .time(at or datetime.now(timezone.utc))
        .build_client_verifier()
    )
    return verifier.verify(leaf, []).subjects


def _assert_client_leaf_profile(leaf: x509.Certificate, identity: str) -> None:
    bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical and bc.value.ca is False
    ku = leaf.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku.critical and ku.value.digital_signature
    assert not (
        ku.value.key_cert_sign or ku.value.crl_sign or ku.value.key_encipherment
    )
    eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert list(eku.value) == [ExtendedKeyUsageOID.CLIENT_AUTH]
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert san.value.get_values_for_type(x509.DNSName) == [identity]
    cn = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert [a.value for a in cn] == [identity]


def _gateway_headers(role: str, secret: str = _PROXY_SECRET) -> dict[str, str]:
    return {
        "x-auth-method": "client-cert",
        "x-auth-role": role,
        "x-auth-key-id": "gw-agent",
        "x-rust-proxy": secret,
    }


def _no_private_key(text: str | bytes) -> bool:
    if isinstance(text, bytes):
        text = text.decode("latin-1")
    return "PRIVATE KEY" not in text


# ---------------------------------------------------------------------------
# Full lifecycle over HTTP: init -> issue -> verify -> list -> revoke -> CRL
# ---------------------------------------------------------------------------


class TestLifecycle:
    def test_init_issue_verify_revoke(
        self,
        anon: TestClient,
        client: TestClient,
        bridge_app: FastAPI,
        persistence: PersistenceManager,
        app_state: AppState,
    ) -> None:
        # init: the first request bootstraps the CA lazily, unauthenticated.
        resp = anon.get("/api/ca/ca.pem")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/x-pem-file"
        assert _no_private_key(resp.content)
        root = _cert(resp.content)
        assert root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca

        authority = bridge_app.state.ca
        data_dir = Path(persistence.data_dir)
        assert authority.key_path.is_file()
        assert data_dir not in authority.key_path.parents  # gateway mounts data/
        assert not list(data_dir.rglob("*.key"))
        assert authority.key_path.stat().st_mode & 0o077 == 0

        # issue (CSR): only the node's public key is used.
        node_key = ec.generate_private_key(ec.SECP256R1())
        signed = client.post(
            "/api/ca/sign",
            json={"csr_pem": _csr_pem(node_key), "identity": "edge-01", "role": "node"},
        )
        assert signed.status_code == 201
        signed = signed.json()
        assert "key_pem" not in signed
        assert _cert(signed["ca_pem"]) == root
        leaf = _cert(signed["cert_pem"])
        assert leaf.public_key() == node_key.public_key()
        assert _verify_client_cert(leaf, root) == [x509.DNSName("edge-01")]
        _assert_client_leaf_profile(leaf, "edge-01")
        with pytest.raises(VerificationError):  # and it expires
            _verify_client_cert(
                leaf, root, leaf.not_valid_after_utc + timedelta(minutes=1)
            )

        # issue (bridge-generated key): the key matches and is returned once.
        issued = client.post(
            "/api/ca/issue",
            json={"identity": "viewer-01", "role": "viewer", "ttl_days": 7},
        )
        assert issued.status_code == 201
        issued = issued.json()
        other = _cert(issued["cert_pem"])
        key = serialization.load_pem_private_key(issued["key_pem"].encode(), None)
        assert key.public_key() == other.public_key()
        assert _verify_client_cert(other, root) == [x509.DNSName("viewer-01")]
        _assert_client_leaf_profile(other, "viewer-01")
        assert other.not_valid_after_utc - other.not_valid_before_utc == timedelta(
            days=7, minutes=5
        )

        # list: metadata only.
        viewer = _client_with_key(bridge_app, persistence, "ops-viewer", "viewer")
        listing = viewer.get("/api/ca/certs")
        assert listing.status_code == 200
        assert _no_private_key(listing.content)
        rows = {r["serial"]: r for r in listing.json()}
        assert set(rows) == {signed["serial"], issued["serial"]}
        assert rows[signed["serial"]]["role"] == "node"
        assert rows[issued["serial"]]["role"] == "viewer"
        assert not any(r["revoked"] for r in rows.values())
        for row in rows.values():
            assert "key_pem" not in row and "cert_pem" not in row

        # revoke: idempotent, reflected in the CRL and the registry listing.
        assert client.post(f"/api/ca/revoke/{signed['serial']}").json() == {
            "status": "ok",
            "revoked": signed["serial"],
        }
        first_revoked_at = authority.get_cert(signed["serial"])["revoked_at"]
        assert client.post(f"/api/ca/revoke/{signed['serial']}").status_code == 200
        assert authority.get_cert(signed["serial"])["revoked_at"] == first_revoked_at

        crl_resp = anon.get("/api/ca/crl.pem")
        assert crl_resp.status_code == 200
        assert crl_resp.headers["content-type"] == "application/x-pem-file"
        crl = x509.load_pem_x509_crl(crl_resp.content)
        assert crl.issuer == root.subject
        assert crl.is_signature_valid(root.public_key())
        assert {r.serial_number for r in crl} == {int(signed["serial"])}
        rows = {r["serial"]: r for r in viewer.get("/api/ca/certs").json()}
        assert rows[signed["serial"]]["revoked"] is True
        assert rows[issued["serial"]]["revoked"] is False

        # audit trail
        events = [e["event_type"] for e in app_state.activity_log]
        assert events.count("cert_issued") == 2
        assert events.count("cert_revoked") == 2
        # The CA object is created once and reused.
        assert bridge_app.state.ca is authority

    def test_ca_survives_an_app_restart(
        self,
        client: TestClient,
        tmp_path: Path,
        persistence: PersistenceManager,
        master_key: str,
    ) -> None:
        """A second app on the same data dir serves the same CA and registry."""
        from sigrift.bridge.app import create_test_app

        root = _cert(client.get("/api/ca/ca.pem").content)
        serial = client.post(
            "/api/ca/issue", json={"identity": "edge-01", "role": "node"}
        ).json()["serial"]
        client.post(f"/api/ca/revoke/{serial}")

        restarted = TestClient(
            create_test_app(
                tmp_path=tmp_path, persistence=persistence, master_key=master_key
            ),
            headers={"X-API-Key": master_key},
        )
        assert _cert(restarted.get("/api/ca/ca.pem").content) == root
        crl = x509.load_pem_x509_crl(restarted.get("/api/ca/crl.pem").content)
        assert int(serial) in {r.serial_number for r in crl}
        leaf = _cert(
            restarted.post(
                "/api/ca/issue", json={"identity": "edge-02", "role": "node"}
            ).json()["cert_pem"]
        )
        assert _verify_client_cert(leaf, root) == [x509.DNSName("edge-02")]


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------

_ADMIN_OPS = [
    ("post", "/api/ca/sign", "sign"),
    ("post", "/api/ca/issue", "issue"),
    ("post", "/api/ca/revoke/{serial}", None),
]


def _call(client: TestClient, method: str, path: str, kind: str | None, serial: str):
    body = None
    if kind == "sign":
        body = {"csr_pem": _csr_pem(), "identity": "intruder", "role": "admin"}
    elif kind == "issue":
        body = {"identity": "intruder", "role": "admin"}
    return getattr(client, method)(path.format(serial=serial), json=body)


class TestAuthorization:
    @pytest.fixture
    def serial(self, client: TestClient) -> str:
        return client.post(
            "/api/ca/issue", json={"identity": "victim", "role": "node"}
        ).json()["serial"]

    @pytest.mark.parametrize(("method", "path", "kind"), _ADMIN_OPS)
    @pytest.mark.parametrize("key", [None, "not-a-real-key"])
    def test_admin_operations_need_a_valid_key(
        self,
        bridge_app: FastAPI,
        client: TestClient,
        serial: str,
        method: str,
        path: str,
        kind: str | None,
        key: str | None,
    ) -> None:
        caller = TestClient(bridge_app, headers={"X-API-Key": key} if key else {})
        assert _call(caller, method, path, kind, serial).status_code == 401
        assert [c["identity"] for c in bridge_app.state.ca.list_certs()] == ["victim"]
        assert bridge_app.state.ca.get_cert(serial)["revoked"] is False

    @pytest.mark.parametrize(("method", "path", "kind"), _ADMIN_OPS)
    @pytest.mark.parametrize("role", ["sensor", "node", "viewer", "analyst"])
    def test_admin_operations_refuse_roles_below_admin(
        self,
        bridge_app: FastAPI,
        persistence: PersistenceManager,
        serial: str,
        method: str,
        path: str,
        kind: str | None,
        role: str,
    ) -> None:
        caller = _client_with_key(bridge_app, persistence, f"k-{role}", role)
        resp = _call(caller, method, path, kind, serial)
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Admin role required"
        assert [c["identity"] for c in bridge_app.state.ca.list_certs()] == ["victim"]
        assert bridge_app.state.ca.get_cert(serial)["revoked"] is False

    def test_an_admin_role_key_may_run_every_operation(
        self, bridge_app: FastAPI, persistence: PersistenceManager, serial: str
    ) -> None:
        admin = _client_with_key(bridge_app, persistence, "ops-admin", "admin")
        for method, path, kind in _ADMIN_OPS:
            resp = _call(admin, method, path, kind, serial)
            assert resp.status_code in (200, 201), (path, resp.text)
        assert bridge_app.state.ca.get_cert(serial)["revoked"] is True

    @pytest.mark.parametrize(
        "meta",
        [
            {"revoked": True},
            {"enabled": False},
            {"expires_at": "2000-01-01T00:00:00+00:00"},
            {"expires_at": "not a date"},
        ],
        ids=["revoked", "disabled", "expired", "garbled-expiry"],
    )
    def test_an_unusable_admin_key_is_refused(
        self,
        bridge_app: FastAPI,
        persistence: PersistenceManager,
        serial: str,
        meta: dict,
    ) -> None:
        admin = _client_with_key(bridge_app, persistence, "old-admin", "admin", **meta)
        for method, path, kind in _ADMIN_OPS:
            assert _call(admin, method, path, kind, serial).status_code == 401, path
        assert admin.get("/api/ca/certs").status_code == 401
        assert bridge_app.state.ca.get_cert(serial)["revoked"] is False

    @pytest.mark.parametrize(
        ("role", "status"), [("sensor", 403), ("node", 403), ("viewer", 200)]
    )
    def test_certs_listing_needs_viewer(
        self,
        anon: TestClient,
        bridge_app: FastAPI,
        persistence: PersistenceManager,
        role: str,
        status: int,
    ) -> None:
        assert anon.get("/api/ca/certs").status_code == 401
        caller = _client_with_key(bridge_app, persistence, f"k-{role}", role)
        assert caller.get("/api/ca/certs").status_code == status

    def test_gateway_asserted_roles_on_admin_operations(
        self,
        anon: TestClient,
        bridge_app: FastAPI,
        serial: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", _PROXY_SECRET)
        body = {"identity": "via-gateway", "role": "node"}
        # Forged trust headers (wrong / default proxy secret) authenticate nothing.
        for secret in ("forged", "uppercrust-internal", ""):
            resp = anon.post(
                "/api/ca/issue", json=body, headers=_gateway_headers("admin", secret)
            )
            assert resp.status_code == 401, secret
        # A genuine viewer cert is authenticated but not authorised.
        resp = anon.post("/api/ca/issue", json=body, headers=_gateway_headers("viewer"))
        assert resp.status_code == 403
        resp = anon.post(
            f"/api/ca/revoke/{serial}", headers=_gateway_headers("analyst")
        )
        assert resp.status_code == 403
        assert bridge_app.state.ca.get_cert(serial)["revoked"] is False
        # A genuine admin cert may issue.
        resp = anon.post("/api/ca/issue", json=body, headers=_gateway_headers("admin"))
        assert resp.status_code == 201
        assert resp.json()["identity"] == "via-gateway"

    def test_gateway_headers_need_a_configured_secret(
        self, anon: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("UC_PROXY_SECRET", raising=False)
        resp = anon.post(
            "/api/ca/issue",
            json={"identity": "x", "role": "node"},
            headers=_gateway_headers("admin", secret=""),
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Input validation and error hygiene
# ---------------------------------------------------------------------------


class TestValidation:
    def test_issue_with_an_invalid_role_is_a_400_and_issues_nothing(
        self, client: TestClient, bridge_app: FastAPI, app_state: AppState
    ) -> None:
        for role in ("keymaster", "KEYMASTER", "root"):
            resp = client.post("/api/ca/issue", json={"identity": "x", "role": role})
            assert resp.status_code == 400
            assert "invalid role" in resp.json()["detail"]
        resp = client.post("/api/ca/issue", json={"identity": "bad id", "role": "node"})
        assert resp.status_code == 400
        assert "invalid identity" in resp.json()["detail"]
        assert bridge_app.state.ca.list_certs() == []
        assert not any(e["event_type"] == "cert_issued" for e in app_state.activity_log)

    @pytest.mark.parametrize(
        "body",
        [
            {"identity": "", "role": "node"},
            {"identity": "a" * 254, "role": "node"},
            {"identity": "x", "role": "node", "ttl_days": 0},
            {"identity": "x", "role": "node", "ttl_days": 826},
            {"identity": "x", "role": "node", "ttl_days": "forever"},
            {"role": "node"},
        ],
    )
    def test_malformed_bodies_are_422(
        self, client: TestClient, bridge_app: FastAPI, body: dict
    ) -> None:
        assert client.post("/api/ca/issue", json=body).status_code == 422
        sign_body = {"csr_pem": _csr_pem(), **body}
        assert client.post("/api/ca/sign", json=sign_body).status_code == 422
        assert client.post("/api/ca/sign", json=body).status_code == 422  # no CSR
        authority = getattr(bridge_app.state, "ca", None)  # 422 before any CA use
        assert authority is None or authority.list_certs() == []

    def test_a_tampered_csr_is_a_400(
        self, client: TestClient, bridge_app: FastAPI
    ) -> None:
        good = x509.load_pem_x509_csr(_csr_pem().encode())
        der = bytearray(good.public_bytes(serialization.Encoding.DER))
        at = bytes(der).rindex(good.signature) + len(good.signature) // 2
        der[at] ^= 0x01
        pem = x509.load_der_x509_csr(bytes(der)).public_bytes(
            serialization.Encoding.PEM
        )
        resp = client.post(
            "/api/ca/sign",
            json={"csr_pem": pem.decode(), "identity": "edge", "role": "node"},
        )
        assert resp.status_code == 400
        assert resp.json()["detail"] == "CSR signature is invalid"
        assert bridge_app.state.ca.list_certs() == []

    def test_a_private_key_sent_as_csr_is_not_echoed(self, client: TestClient) -> None:
        key_pem = (
            ec.generate_private_key(ec.SECP256R1())
            .private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            .decode()
        )
        resp = client.post(
            "/api/ca/sign",
            json={"csr_pem": key_pem, "identity": "edge", "role": "node"},
        )
        assert resp.status_code == 400
        assert _no_private_key(resp.text)
        for line in key_pem.splitlines()[1:-1]:
            assert line not in resp.text

    @pytest.mark.parametrize("serial", ["123456789", "abc", "0x1f", "-1", "1e9"])
    def test_revoking_an_unknown_serial_is_a_404(
        self, client: TestClient, serial: str
    ) -> None:
        issued = client.post(
            "/api/ca/issue", json={"identity": "keep", "role": "node"}
        ).json()
        resp = client.post(f"/api/ca/revoke/{serial}")
        assert resp.status_code == 404
        crl = x509.load_pem_x509_crl(client.get("/api/ca/crl.pem").content)
        assert len(crl) == 0
        rows = client.get("/api/ca/certs").json()
        assert [r["revoked"] for r in rows if r["serial"] == issued["serial"]] == [
            False
        ]

    def test_an_identity_with_a_trailing_newline_is_rejected(
        self, client: TestClient, bridge_app: FastAPI
    ) -> None:
        resp = client.post(
            "/api/ca/issue", json={"identity": "edge-01\n", "role": "node"}
        )
        assert resp.status_code in (400, 422)
        assert bridge_app.state.ca.list_certs() == []
        resp = client.post(
            "/api/ca/sign",
            json={"csr_pem": _csr_pem(), "identity": "edge-01\n", "role": "node"},
        )
        assert resp.status_code == 400
        assert "invalid identity" in resp.json()["detail"]
        assert bridge_app.state.ca.list_certs() == []


# ---------------------------------------------------------------------------
# A CA whose files need an operator: 503, nothing signed or overwritten
# ---------------------------------------------------------------------------


def _ca_dir(persistence: PersistenceManager) -> Path:
    return Path(persistence.data_dir) / "ca"


def _key_pem() -> bytes:
    return ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


class _Clock:
    """Stands in for the router's monotonic clock."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def past_the_retry_delay(self) -> None:
        self.now += ca_router._RETRY_AFTER_FAILURE_SECONDS + 1


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    fake = _Clock()
    monkeypatch.setattr(ca_router, "_clock", fake)
    return fake


class TestUnavailableCa:
    def test_a_key_without_its_cert_is_a_503_and_is_kept(
        self,
        anon: TestClient,
        client: TestClient,
        bridge_app: FastAPI,
        persistence: PersistenceManager,
        tmp_path: Path,
        clock: _Clock,
    ) -> None:
        """E.g. ca.crt lost, or a second data dir sharing the secrets dir."""
        key = tmp_path / "secrets" / "ca" / "ca.key"
        key.parent.mkdir(parents=True)
        key.write_bytes(_key_pem())
        before = key.read_bytes()

        for path in ("/api/ca/ca.pem", "/api/ca/crl.pem"):
            resp = anon.get(path)
            assert resp.status_code == 503, path
            # Public endpoints name no files on the bridge host.
            assert str(tmp_path) not in resp.text and "ca.key" not in resp.text
        resp = client.post("/api/ca/issue", json={"identity": "edge", "role": "node"})
        assert resp.status_code == 503
        assert "Refusing to create a new CA" in resp.json()["detail"]
        assert client.get("/api/ca/certs").status_code == 503

        assert key.read_bytes() == before
        assert not (_ca_dir(persistence) / "ca.crt").exists()
        assert getattr(bridge_app.state, "ca", None) is None  # not cached

        # Once the operator moves the key aside, the CA is created on the
        # first request after the retry delay.
        key.rename(key.with_name("ca.retired.key"))
        clock.past_the_retry_delay()
        assert anon.get("/api/ca/ca.pem").status_code == 200
        assert bridge_app.state.ca is not None

    def test_a_cert_without_its_key_is_a_503_and_the_cert_is_kept(
        self,
        anon: TestClient,
        client: TestClient,
        bridge_app: FastAPI,
        persistence: PersistenceManager,
        tmp_path: Path,
        clock: _Clock,
    ) -> None:
        """E.g. bridge_secrets not restored, or BRIDGE_SECRETS_DIR changed.

        The first request of any kind (here an anonymous GET /ca.pem) used
        to create a new CA over ca.crt, so no issued certificate chained.
        """
        authority = CertificateAuthority(_ca_dir(persistence))
        authority.ensure_ca()
        serial = authority.issue_cert(identity="edge", role="node")["serial"]
        cert = authority.ca_cert_pem
        registry = (_ca_dir(persistence) / "registry.json").read_bytes()
        key = authority.key_path.read_bytes()
        authority.key_path.unlink()

        for path in ("/api/ca/ca.pem", "/api/ca/crl.pem"):
            resp = anon.get(path)
            assert resp.status_code == 503, path
            assert str(tmp_path) not in resp.text and "ca.key" not in resp.text
        resp = client.post("/api/ca/issue", json={"identity": "next", "role": "node"})
        assert resp.status_code == 503
        assert "but no private key at" in resp.json()["detail"]

        assert (_ca_dir(persistence) / "ca.crt").read_bytes() == cert
        assert (_ca_dir(persistence) / "registry.json").read_bytes() == registry
        assert not authority.key_path.exists()
        assert getattr(bridge_app.state, "ca", None) is None

        # Restoring the key brings the same CA back.
        authority.key_path.write_bytes(key)
        clock.past_the_retry_delay()
        assert anon.get("/api/ca/ca.pem").content == cert
        leaf = _cert(
            client.post(
                "/api/ca/issue", json={"identity": "next", "role": "node"}
            ).json()["cert_pem"]
        )
        assert _verify_client_cert(leaf, _cert(cert)) == [x509.DNSName("next")]
        assert authority.get_cert(serial) is not None

    def test_an_unusable_ca_is_not_reopened_on_every_request(
        self,
        anon: TestClient,
        client: TestClient,
        bridge_app: FastAPI,
        tmp_path: Path,
        clock: _Clock,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Anonymous requests must not redo the start-up and flood the log."""
        key = tmp_path / "secrets" / "ca" / "ca.key"
        key.parent.mkdir(parents=True)
        key.write_bytes(_key_pem())
        opened: list[Path] = []

        class CountingCA(CertificateAuthority):
            def __init__(self, ca_dir, **kwargs) -> None:  # noqa: ANN001, ANN003
                opened.append(Path(ca_dir))
                super().__init__(ca_dir, **kwargs)

        monkeypatch.setattr(ca_router, "CertificateAuthority", CountingCA)
        with caplog.at_level(logging.ERROR, logger="sigrift.bridge.routers.ca"):
            for _ in range(5):
                assert anon.get("/api/ca/ca.pem").status_code == 503
                assert anon.get("/api/ca/crl.pem").status_code == 503
            # Callers who may see the reason still get it from the memo.
            resp = client.post("/api/ca/issue", json={"identity": "e", "role": "node"})
            assert resp.status_code == 503
            assert "Refusing to create a new CA" in resp.json()["detail"]
        assert len(opened) == 1
        unavailable = [
            r for r in caplog.records if "authority unavailable" in r.getMessage()
        ]
        assert len(unavailable) == 1

        # It keeps retrying: after the delay it opens the CA again.
        clock.past_the_retry_delay()
        assert anon.get("/api/ca/ca.pem").status_code == 503
        assert len(opened) == 2
        key.rename(key.with_name("ca.retired.key"))
        clock.past_the_retry_delay()
        assert anon.get("/api/ca/ca.pem").status_code == 200
        assert anon.get("/api/ca/crl.pem").status_code == 200
        assert len(opened) == 3
        assert bridge_app.state.ca_failure is None

    @pytest.mark.parametrize("broken", ["malformed", "unreadable"])
    def test_an_unloadable_key_is_a_503_not_a_500(
        self,
        anon: TestClient,
        client: TestClient,
        bridge_app: FastAPI,
        tmp_path: Path,
        broken: str,
    ) -> None:
        if broken == "unreadable" and os.geteuid() == 0:
            pytest.skip("root ignores file permissions")
        assert anon.get("/api/ca/ca.pem").status_code == 200
        authority = bridge_app.state.ca
        if broken == "malformed":
            authority.key_path.write_bytes(b"-----BEGIN PRIVATE KEY-----\nnope\n")
        else:
            authority.key_path.chmod(0o000)
        try:
            resp = anon.get("/api/ca/crl.pem")
            assert resp.status_code == 503
            assert str(tmp_path) not in resp.text and "ca.key" not in resp.text
            resp = client.post("/api/ca/issue", json={"identity": "e", "role": "node"})
            assert resp.status_code == 503
            assert "cannot be used" in resp.json()["detail"]
            assert "PRIVATE KEY" not in resp.text
        finally:
            authority.key_path.chmod(0o600)
        assert authority.list_certs() == []

    def test_the_certs_listing_names_no_host_paths_below_admin(
        self,
        client: TestClient,
        bridge_app: FastAPI,
        persistence: PersistenceManager,
        tmp_path: Path,
    ) -> None:
        """A viewer key must not learn where the CA private key lives."""
        client.post("/api/ca/issue", json={"identity": "edge", "role": "node"})
        (_ca_dir(persistence) / "registry.json").write_bytes(b"{broken")
        for role in ("viewer", "analyst"):
            caller = _client_with_key(bridge_app, persistence, f"k-{role}", role)
            resp = caller.get("/api/ca/certs")
            assert resp.status_code == 503
            assert resp.json()["detail"] == ca_router._GENERIC_UNAVAILABLE_DETAIL
            assert str(tmp_path) not in resp.text
        admin = _client_with_key(bridge_app, persistence, "k-admin", "admin")
        for caller in (admin, client):  # an admin key, the master key
            resp = caller.get("/api/ca/certs")
            assert resp.status_code == 503
            assert "registry.json" in resp.json()["detail"]

    def test_the_certs_listing_hides_a_bootstrap_failure_below_admin(
        self,
        bridge_app: FastAPI,
        persistence: PersistenceManager,
        tmp_path: Path,
    ) -> None:
        key = tmp_path / "secrets" / "ca" / "ca.key"
        key.parent.mkdir(parents=True)
        key.write_bytes(_key_pem())
        viewer = _client_with_key(bridge_app, persistence, "k-viewer", "viewer")
        resp = viewer.get("/api/ca/certs")
        assert resp.status_code == 503
        assert resp.json()["detail"] == ca_router._GENERIC_UNAVAILABLE_DETAIL
        assert str(tmp_path) not in resp.text and "ca.key" not in resp.text

    def test_a_key_that_does_not_match_the_cert_is_a_503(
        self,
        anon: TestClient,
        client: TestClient,
        bridge_app: FastAPI,
        tmp_path: Path,
    ) -> None:
        assert anon.get("/api/ca/ca.pem").status_code == 200
        authority = bridge_app.state.ca
        authority.key_path.write_bytes(
            ec.generate_private_key(ec.SECP256R1()).private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        for path, body in (
            ("/api/ca/issue", {"identity": "edge", "role": "node"}),
            ("/api/ca/sign", {"csr_pem": _csr_pem(), "identity": "e", "role": "node"}),
        ):
            resp = client.post(path, json=body)
            assert resp.status_code == 503, path
            assert "does not belong to the CA certificate" in resp.json()["detail"]
        resp = anon.get("/api/ca/crl.pem")
        assert resp.status_code == 503
        assert str(tmp_path) not in resp.text and "ca.key" not in resp.text
        assert anon.get("/api/ca/ca.pem").status_code == 200  # still public
        assert authority.list_certs() == []

    def test_a_corrupt_registry_is_a_503_and_is_never_overwritten(
        self,
        anon: TestClient,
        client: TestClient,
        bridge_app: FastAPI,
        persistence: PersistenceManager,
        tmp_path: Path,
    ) -> None:
        serial = client.post(
            "/api/ca/issue", json={"identity": "edge", "role": "node"}
        ).json()["serial"]
        assert client.post(f"/api/ca/revoke/{serial}").status_code == 200
        registry = _ca_dir(persistence) / "registry.json"
        broken = registry.read_bytes().rstrip()[:-1] + b",}"
        registry.write_bytes(broken)

        for method, path, body in (
            ("get", "/api/ca/certs", None),
            ("post", f"/api/ca/revoke/{serial}", None),
            ("post", "/api/ca/issue", {"identity": "next", "role": "node"}),
            (
                "post",
                "/api/ca/sign",
                {"csr_pem": _csr_pem(), "identity": "next", "role": "node"},
            ),
        ):
            resp = client.get(path) if method == "get" else client.post(path, json=body)
            assert resp.status_code == 503, path
            assert "registry" in resp.json()["detail"]
        resp = anon.get("/api/ca/crl.pem")  # no CRL that leaves out revocations
        assert resp.status_code == 503
        assert str(tmp_path) not in resp.text

        assert registry.read_bytes() == broken
        assert not [p for p in registry.parent.iterdir() if p.suffix == ".tmp"]


# ---------------------------------------------------------------------------
# Rate limiting of issuance
# ---------------------------------------------------------------------------


class TestRateLimit:
    def test_sign_and_issue_share_a_per_key_sensitive_limit(
        self,
        client: TestClient,
        bridge_app: FastAPI,
        persistence: PersistenceManager,
    ) -> None:
        for i in range(5):
            assert (
                client.post(
                    "/api/ca/sign",
                    json={"csr_pem": _csr_pem(), "identity": f"s{i}", "role": "node"},
                ).status_code
                == 201
            )
            assert (
                client.post(
                    "/api/ca/issue", json={"identity": f"i{i}", "role": "node"}
                ).status_code
                == 201
            )
        for path, body in (
            ("/api/ca/issue", {"identity": "over", "role": "node"}),
            (
                "/api/ca/sign",
                {"csr_pem": _csr_pem(), "identity": "over", "role": "node"},
            ),
        ):
            resp = client.post(path, json=body)
            assert resp.status_code == 429
            assert int(resp.headers["Retry-After"]) >= 1
        assert len(bridge_app.state.ca.list_certs()) == 10
        # The bucket is per key: another admin is unaffected.
        other = _client_with_key(bridge_app, persistence, "ops-admin", "admin")
        resp = other.post("/api/ca/issue", json={"identity": "other", "role": "node"})
        assert resp.status_code == 201
