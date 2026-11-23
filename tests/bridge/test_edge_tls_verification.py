"""Edge agents must verify the bridge's TLS certificate by default.

The edge scanners send the API key (or an mTLS identity) to the bridge, and
the node_agent heartbeat response carries remote commands (update,
update_config, iq_capture). Verification must therefore be ON unless the
operator explicitly opts out with MLRF_INSECURE_TLS=1:

* MLRF_CA_CERT / MLRF_CA_BUNDLE -> verify against that CA bundle
* neither set                   -> verify against the system trust store
* MLRF_INSECURE_TLS=1 (exactly)  -> CERT_NONE + a loud warning

A CA path that does not exist logs one error and falls back to the system
trust store (still verifying). A CA path that exists but cannot be loaded
(unreadable, not PEM, a private key) raises TLSConfigError -- never a
silent fallback -- and every agent turns that into one clear startup error
and a non-zero exit instead of a traceback on its first request. A CA
directory (OpenSSL capath) is read lazily by OpenSSL, so it is probed: one
that cannot be listed, is empty, or has no loadable hash-named certificate
is the same startup error.

sigrift.lib.shiny.node_agent, once a stale copy that disabled verification
by default, is now an alias of sigrift.edge.node_agent.

Also covers clamping of the remote ``iq_capture`` command in rf_scan.
"""

from __future__ import annotations

import importlib
import ipaddress
import logging
import os
import runpy
import shutil
import socket
import ssl
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import sigrift.edge.detection_reporter as detection_reporter
import sigrift.edge.node_agent as node_agent

_REPO_SRC = Path(node_agent.__file__).resolve().parents[2]

_TLS_ENV = (
    "MLRF_CA_CERT",
    "MLRF_CA_BUNDLE",
    "MLRF_INSECURE_TLS",
    "MLRF_CLIENT_CERT",
    "MLRF_CLIENT_KEY",
    "BRIDGE_CA_BUNDLE",
)


# ---------------------------------------------------------------------------
# Module loading (rf_scan / wifi_scan touch the filesystem at import time)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def rf_scan(tmp_path_factory: pytest.TempPathFactory) -> ModuleType:
    if "sigrift.edge.rf_scan" in sys.modules:
        return sys.modules["sigrift.edge.rf_scan"]
    tmp = tmp_path_factory.mktemp("rf_scan")
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("MLRF_LOG_DIR", str(tmp / "logs"))
        mp.setenv("MLRF_AGENT_DIR", str(tmp / "agent"))
        return importlib.import_module("sigrift.edge.rf_scan")


@pytest.fixture(scope="module")
def wifi_scan() -> ModuleType:
    if "sigrift.edge.wifi_scan" in sys.modules:
        return sys.modules["sigrift.edge.wifi_scan"]
    real_mkdir = Path.mkdir

    def _no_opt_mkdir(self: Path, *args: object, **kwargs: object) -> None:
        # wifi_scan logs to /opt/rf-edge/logs; force its OSError fallback.
        if str(self).startswith("/opt"):
            raise OSError("not writable in tests")
        real_mkdir(self, *args, **kwargs)  # type: ignore[arg-type]

    with patch.object(Path, "mkdir", _no_opt_mkdir):
        return importlib.import_module("sigrift.edge.wifi_scan")


@pytest.fixture(scope="module")
def signal_tester() -> ModuleType:
    return importlib.import_module("sigrift.tools.signal_tester")


_EDGE_MODULES = ["node_agent", "rf_scan", "wifi_scan", "detection_reporter"]


def _load_edge_module(request: pytest.FixtureRequest, name: str) -> ModuleType:
    if name == "node_agent":
        return node_agent
    if name == "detection_reporter":
        return detection_reporter
    return request.getfixturevalue(name)


@pytest.fixture(params=_EDGE_MODULES)
def edge_module(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> ModuleType:
    mod = _load_edge_module(request, request.param)
    monkeypatch.setattr(mod, "_insecure_tls_warned", False)
    monkeypatch.setattr(mod, "_missing_ca_logged", set())
    monkeypatch.setattr(mod, "_cert_auth_active", False)
    return mod


@pytest.fixture(autouse=True)
def _clean_tls_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _TLS_ENV:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(scope="module")
def ca_pem(tmp_path_factory: pytest.TempPathFactory) -> str:
    """A throwaway self-signed CA certificate (PEM path)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sigrift-test-ca")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path = tmp_path_factory.mktemp("ca") / "ca.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(path)


def _assert_verifying(ctx: ssl.SSLContext) -> None:
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def _ca_subjects(ctx: ssl.SSLContext) -> list[str]:
    return [
        value
        for cert in ctx.get_ca_certs()
        for rdn in cert["subject"]
        for key, value in rdn
        if key == "commonName"
    ]


# ---------------------------------------------------------------------------
# Shared policy (node_agent, rf_scan, wifi_scan)
# ---------------------------------------------------------------------------


class TestEdgeTLSPolicy:
    def test_verifies_by_default(self, edge_module: ModuleType) -> None:
        _assert_verifying(edge_module._build_ssl_context())

    def test_insecure_only_with_explicit_opt_in(
        self, edge_module: ModuleType, monkeypatch: pytest.MonkeyPatch, caplog
    ) -> None:
        monkeypatch.setenv("MLRF_INSECURE_TLS", "1")
        with caplog.at_level(logging.WARNING):
            ctx = edge_module._build_ssl_context()
        assert ctx.verify_mode == ssl.CERT_NONE
        assert ctx.check_hostname is False
        assert any(
            r.levelno >= logging.WARNING and "MLRF_INSECURE_TLS" in r.getMessage()
            for r in caplog.records
        )

    def test_insecure_warning_logged_once(
        self, edge_module: ModuleType, monkeypatch: pytest.MonkeyPatch, caplog
    ) -> None:
        monkeypatch.setenv("MLRF_INSECURE_TLS", "1")
        with caplog.at_level(logging.WARNING):
            edge_module._build_ssl_context()
            edge_module._build_ssl_context()
            assert edge_module._check_tls_config() is True
        warnings = [r for r in caplog.records if "MLRF_INSECURE_TLS" in r.getMessage()]
        assert len(warnings) == 1

    @pytest.mark.parametrize("value", ["", "0", "true", "yes", "on", "2"])
    def test_other_insecure_values_still_verify(
        self, edge_module: ModuleType, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("MLRF_INSECURE_TLS", value)
        _assert_verifying(edge_module._build_ssl_context())

    @pytest.mark.parametrize("var", ["MLRF_CA_CERT", "MLRF_CA_BUNDLE"])
    def test_ca_bundle_is_trusted(
        self,
        edge_module: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        ca_pem: str,
        var: str,
    ) -> None:
        monkeypatch.setenv(var, ca_pem)
        ctx = edge_module._build_ssl_context()
        _assert_verifying(ctx)
        assert _ca_subjects(ctx) == ["sigrift-test-ca"]

    def test_ca_bundle_wins_over_insecure(
        self, edge_module: ModuleType, monkeypatch: pytest.MonkeyPatch, ca_pem: str
    ) -> None:
        monkeypatch.setenv("MLRF_CA_CERT", ca_pem)
        monkeypatch.setenv("MLRF_INSECURE_TLS", "1")
        _assert_verifying(edge_module._build_ssl_context())

    def test_missing_ca_file_keeps_verification(
        self, edge_module: ModuleType, monkeypatch: pytest.MonkeyPatch, caplog
    ) -> None:
        monkeypatch.setenv("MLRF_CA_CERT", "/nonexistent/ca.pem")
        with caplog.at_level(logging.ERROR):
            ctx = edge_module._build_ssl_context()
        _assert_verifying(ctx)
        errors = [r for r in caplog.records if "/nonexistent/ca.pem" in r.getMessage()]
        assert len(errors) == 1
        # Logged once, not on every heartbeat / upload.
        with caplog.at_level(logging.ERROR):
            edge_module._build_ssl_context()
        errors = [r for r in caplog.records if "/nonexistent/ca.pem" in r.getMessage()]
        assert len(errors) == 1


_SHARED_TLS_HELPERS = (
    "_ca_bundle_source",
    "_load_ca_context",
    "_insecure_tls_requested",
    "_build_ssl_context",
    "_check_tls_config",
)


@pytest.mark.parametrize("name", _EDGE_MODULES[1:])
def test_inlined_tls_helpers_do_not_drift(
    request: pytest.FixtureRequest, name: str
) -> None:
    """The helpers are inlined (the agents also run as standalone files), so
    pin them to node_agent's source: a stale copy is how lib/shiny's agent
    ended up disabling verification by default."""
    import inspect

    mod = _load_edge_module(request, name)
    for helper in _SHARED_TLS_HELPERS:
        assert inspect.getsource(getattr(mod, helper)) == inspect.getsource(
            getattr(node_agent, helper)
        ), f"{name}.{helper} differs from node_agent.{helper}"
    assert issubclass(mod.TLSConfigError, ValueError)


# ---------------------------------------------------------------------------
# A CA file that exists but cannot be loaded is a clear, fatal config error
# ---------------------------------------------------------------------------


def _private_key_pem() -> bytes:
    return ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


_BAD_CA_CONTENTS = {
    "not_pem": b"this is not a certificate\n",
    "empty": b"",
    # The operator pointed MLRF_CA_CERT at the gateway's key.pem by mistake.
    "private_key": None,
    "corrupt_pem": b"-----BEGIN CERTIFICATE-----\nZZZZ\n-----END CERTIFICATE-----\n",
}


@pytest.fixture(params=sorted(_BAD_CA_CONTENTS))
def bad_ca(request: pytest.FixtureRequest, tmp_path: Path) -> str:
    content = _BAD_CA_CONTENTS[request.param]
    path = tmp_path / f"{request.param}.pem"
    path.write_bytes(_private_key_pem() if content is None else content)
    return str(path)


@pytest.fixture
def unreadable_ca(ca_pem: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """A real CA file this process cannot read (0600 root-owned, agent as pi).

    chmod does not stop root, so under root the open() failure is injected.
    """
    path = tmp_path / "root-only-ca.pem"
    path.write_bytes(Path(ca_pem).read_bytes())
    path.chmod(0o000)
    if os.geteuid() == 0:
        real = ssl.create_default_context

        def fake(*args: object, **kwargs: object) -> ssl.SSLContext:
            if kwargs.get("cafile") == str(path):
                raise PermissionError(13, "Permission denied", str(path))
            return real(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(ssl, "create_default_context", fake)
    return str(path)


class TestUnusableCABundle:
    @pytest.mark.parametrize("var", ["MLRF_CA_CERT", "MLRF_CA_BUNDLE"])
    def test_bad_file_raises_clear_error(
        self,
        edge_module: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        bad_ca: str,
        var: str,
    ) -> None:
        monkeypatch.setenv(var, bad_ca)
        with pytest.raises(edge_module.TLSConfigError) as err:
            edge_module._build_ssl_context()
        msg = str(err.value)
        assert f"{var}={bad_ca}" in msg
        assert "PEM CA certificate" in msg
        assert isinstance(err.value.__cause__, OSError)  # ssl.SSLError is an OSError

    def test_unreadable_file_raises(
        self,
        edge_module: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        unreadable_ca: str,
    ) -> None:
        monkeypatch.setenv("MLRF_CA_CERT", unreadable_ca)
        with pytest.raises(edge_module.TLSConfigError) as err:
            edge_module._build_ssl_context()
        assert "Permission denied" in str(err.value)
        assert unreadable_ca in str(err.value)

    def test_unstattable_path_is_not_treated_as_missing(
        self,
        edge_module: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog,
    ) -> None:
        """EACCES on stat (parent dir not searchable) must not mean 'missing'.

        Path.is_file() returns False there, which used to fall back to the
        system trust store as if no CA had been pinned.
        """
        hidden = str(tmp_path / "locked" / "ca.pem")
        real_stat = os.stat
        real_ctx = ssl.create_default_context

        def fake_stat(path, *args, **kwargs):
            if os.fspath(path) == hidden:
                raise PermissionError(13, "Permission denied", hidden)
            return real_stat(path, *args, **kwargs)

        def fake_ctx(*args: object, **kwargs: object) -> ssl.SSLContext:
            if kwargs.get("cafile") == hidden:
                raise PermissionError(13, "Permission denied", hidden)
            return real_ctx(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(os, "stat", fake_stat)
        monkeypatch.setattr(ssl, "create_default_context", fake_ctx)
        monkeypatch.setenv("MLRF_CA_CERT", hidden)
        with caplog.at_level(logging.ERROR):
            with pytest.raises(edge_module.TLSConfigError):
                edge_module._build_ssl_context()
        assert not any("does not exist" in r.getMessage() for r in caplog.records)

    def test_bad_ca_is_not_downgraded_by_insecure_flag(
        self, edge_module: ModuleType, monkeypatch: pytest.MonkeyPatch, bad_ca: str
    ) -> None:
        monkeypatch.setenv("MLRF_CA_CERT", bad_ca)
        monkeypatch.setenv("MLRF_INSECURE_TLS", "1")
        with pytest.raises(edge_module.TLSConfigError):
            edge_module._build_ssl_context()

    def test_bad_primary_ca_does_not_fall_through_to_secondary(
        self,
        edge_module: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        bad_ca: str,
        ca_pem: str,
    ) -> None:
        monkeypatch.setenv("MLRF_CA_CERT", bad_ca)
        monkeypatch.setenv("MLRF_CA_BUNDLE", ca_pem)
        with pytest.raises(edge_module.TLSConfigError):
            edge_module._build_ssl_context()

    def test_startup_check_logs_one_error_and_fails(
        self,
        edge_module: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        bad_ca: str,
        caplog,
    ) -> None:
        monkeypatch.setenv("MLRF_CA_CERT", bad_ca)
        with caplog.at_level(logging.INFO):
            assert edge_module._check_tls_config() is False
        errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
        assert len(errors) == 1
        assert f"MLRF_CA_CERT={bad_ca}" in errors[0].getMessage()
        assert not any(
            "TLS verification enabled" in r.getMessage() for r in caplog.records
        )

    def test_startup_check_passes_for_good_ca(
        self,
        edge_module: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        ca_pem: str,
        caplog,
    ) -> None:
        monkeypatch.setenv("MLRF_CA_CERT", ca_pem)
        with caplog.at_level(logging.INFO):
            assert edge_module._check_tls_config() is True
        assert any(
            "TLS verification enabled" in r.getMessage() and ca_pem in r.getMessage()
            for r in caplog.records
        )

    def test_startup_check_passes_for_missing_ca(
        self, edge_module: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("MLRF_CA_CERT", "/nonexistent/ca.pem")
        assert edge_module._check_tls_config() is True


# ---------------------------------------------------------------------------
# A CA directory (OpenSSL capath) is probed at startup
# ---------------------------------------------------------------------------
# OpenSSL reads a capath lazily, during each handshake, so without a probe an
# unreadable or empty directory "loads" fine, the agent logs "TLS
# verification enabled" and then every request fails "certificate verify
# failed".


@pytest.fixture(scope="module")
def tls_pki(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    """A CA, a server certificate for 127.0.0.1 it signed, and a hashed CA dir."""
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("the openssl CLI is needed to compute the CA subject hash")
    tmp = tmp_path_factory.mktemp("pki")
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sigrift-dir-ca")])
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ca_ski, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    srv_key = ec.generate_private_key(ec.SECP256R1())
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
        .issuer_name(ca_name)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(srv_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_pem_bytes = ca_cert.public_bytes(serialization.Encoding.PEM)
    ca_file = tmp / "ca.pem"
    ca_file.write_bytes(ca_pem_bytes)
    cert_file = tmp / "server.pem"
    cert_file.write_bytes(srv_cert.public_bytes(serialization.Encoding.PEM))
    key_file = tmp / "server.key"
    key_file.write_bytes(
        srv_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    subject_hash = subprocess.run(
        [openssl, "x509", "-noout", "-subject_hash", "-in", str(ca_file)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    ca_dir = tmp / "ca-dir"
    ca_dir.mkdir()
    (ca_dir / f"{subject_hash}.0").write_bytes(ca_pem_bytes)
    return {
        "ca_pem": ca_pem_bytes.decode(),
        "ca_dir": str(ca_dir),
        "subject_hash": subject_hash,
        "cert": str(cert_file),
        "key": str(key_file),
    }


def _handshake(client_ctx: ssl.SSLContext, pki: dict[str, str]) -> dict:
    """TLS handshake with a local server presenting pki's cert; the peer cert."""
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(pki["cert"], pki["key"])
    with socket.create_server(("127.0.0.1", 0)) as listener:
        listener.settimeout(10)

        def serve() -> None:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            with conn:
                try:
                    with server_ctx.wrap_socket(conn, server_side=True):
                        pass
                except (ssl.SSLError, OSError):
                    pass  # the client rejected us; the client side asserts

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            with socket.create_connection(listener.getsockname(), timeout=10) as raw:
                with client_ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                    return tls.getpeercert()
        finally:
            thread.join(10)


def _assert_fatal_ca(
    mod: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    path: str,
    reason: str,
) -> None:
    """*path* is a TLSConfigError at runtime and one clear error at startup."""
    monkeypatch.setenv("MLRF_CA_CERT", path)
    with pytest.raises(mod.TLSConfigError):
        mod._build_ssl_context()
    caplog.clear()
    with caplog.at_level(logging.INFO):
        assert mod._check_tls_config() is False
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1
    msg = errors[0].getMessage()
    assert f"MLRF_CA_CERT={path} cannot be loaded" in msg
    assert reason in msg
    assert f"uid {os.getuid()}" in msg
    assert not any("TLS verification enabled" in r.getMessage() for r in caplog.records)


@pytest.fixture
def unreadable_ca_dir(
    tls_pki: dict[str, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A hashed CA dir this process cannot list (0700 root-owned, agent as pi).

    chmod does not stop root, so under root the listdir() failure is injected.
    """
    path = tmp_path / "root-only-ca-dir"
    path.mkdir()
    (path / f"{tls_pki['subject_hash']}.0").write_text(tls_pki["ca_pem"])
    path.chmod(0o000)
    if os.geteuid() == 0:
        real = os.listdir

        def fake(target=".", *args: object, **kwargs: object) -> list[str]:
            if os.fspath(target) == str(path):
                raise PermissionError(13, "Permission denied", str(path))
            return real(target, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(os, "listdir", fake)
    yield str(path)
    path.chmod(0o700)


class TestCADirectory:
    def test_hashed_directory_verifies_a_real_handshake(
        self,
        edge_module: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        tls_pki: dict[str, str],
        caplog,
    ) -> None:
        monkeypatch.setenv("MLRF_CA_BUNDLE", tls_pki["ca_dir"])
        with caplog.at_level(logging.INFO):
            assert edge_module._check_tls_config() is True
        assert any(
            f"TLS verification enabled (MLRF_CA_BUNDLE={tls_pki['ca_dir']})"
            in r.getMessage()
            for r in caplog.records
        )
        ctx = edge_module._build_ssl_context()
        _assert_verifying(ctx)
        peer = _handshake(ctx, tls_pki)
        assert peer["subject"] == ((("commonName", "127.0.0.1"),),)

    def test_without_the_directory_the_same_server_is_rejected(
        self, edge_module: ModuleType, tls_pki: dict[str, str]
    ) -> None:
        """Control for the handshake test: the CA dir is what makes it pass."""
        with pytest.raises(ssl.SSLCertVerificationError):
            _handshake(edge_module._build_ssl_context(), tls_pki)

    def test_one_loadable_hashed_cert_is_enough(
        self,
        edge_module: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        tls_pki: dict[str, str],
        tmp_path: Path,
    ) -> None:
        """Junk next to a good entry (sorted first here) does not fail startup."""
        (tmp_path / "00000000.0").write_bytes(b"not a certificate\n")
        (tmp_path / "README").write_text("not hash-named, ignored\n")
        (tmp_path / f"{tls_pki['subject_hash']}.0").write_text(tls_pki["ca_pem"])
        monkeypatch.setenv("MLRF_CA_CERT", str(tmp_path))
        assert edge_module._check_tls_config() is True
        peer = _handshake(edge_module._build_ssl_context(), tls_pki)
        assert peer["subject"] == ((("commonName", "127.0.0.1"),),)

    def test_empty_directory_is_fatal(
        self,
        edge_module: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog,
    ) -> None:
        """Docker bind-mounts a missing host cert.pem as an empty directory."""
        stand_in = tmp_path / "cert.pem"
        stand_in.mkdir()
        _assert_fatal_ca(
            edge_module, monkeypatch, caplog, str(stand_in), "empty directory"
        )

    def test_unreadable_directory_is_fatal(
        self,
        edge_module: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        unreadable_ca_dir: str,
        caplog,
    ) -> None:
        _assert_fatal_ca(
            edge_module, monkeypatch, caplog, unreadable_ca_dir, "Permission denied"
        )

    def test_directory_without_hashed_certs_is_fatal(
        self,
        edge_module: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        tls_pki: dict[str, str],
        tmp_path: Path,
        caplog,
    ) -> None:
        """A good CA under a plain name is invisible to OpenSSL's capath lookup."""
        (tmp_path / "ca.pem").write_text(tls_pki["ca_pem"])
        _assert_fatal_ca(
            edge_module, monkeypatch, caplog, str(tmp_path), "openssl rehash"
        )

    def test_directory_with_only_unloadable_hashed_entries_is_fatal(
        self,
        edge_module: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog,
    ) -> None:
        (tmp_path / "0123abcd.0").write_bytes(b"this is not a certificate\n")
        (tmp_path / "deadbeef.1").write_bytes(_private_key_pem())
        _assert_fatal_ca(
            edge_module,
            monkeypatch,
            caplog,
            str(tmp_path),
            "none of the 2 hash-named CA certificates",
        )

    def test_node_agent_main_exits_cleanly_on_empty_directory(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog
    ) -> None:
        def no_heartbeat(*args: object, **kwargs: object) -> bool:
            raise AssertionError("heartbeat attempted with an unusable CA dir")

        monkeypatch.setattr(node_agent, "send_heartbeat", no_heartbeat)
        monkeypatch.setattr(node_agent, "collect_metrics", lambda: {})
        monkeypatch.setattr(
            sys, "argv", ["node_agent", "--node-id", "n", "--api-key", "k", "--once"]
        )
        monkeypatch.setenv("MLRF_CA_CERT", str(tmp_path))
        with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as exit_info:
            node_agent.main()
        assert exit_info.value.code == 1
        assert any("empty directory" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# Call sites actually use the verifying context
# ---------------------------------------------------------------------------


class _Captured(Exception):
    pass


class TestCallSites:
    def test_node_agent_heartbeat_verifies(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: dict = {}

        def fake_urlopen(req, context=None, timeout=None):
            seen["ctx"] = context
            seen["headers"] = dict(req.header_items())
            raise _Captured()

        monkeypatch.setattr(node_agent.urllib.request, "urlopen", fake_urlopen)
        monkeypatch.setattr(node_agent, "_cert_auth_active", False)
        ok = node_agent.send_heartbeat("https://bridge.test", "secret", "node-1", {})
        assert ok is False
        _assert_verifying(seen["ctx"])
        assert seen["headers"].get("X-api-key") == "secret"

    def test_wifi_reporter_verifies(self, wifi_scan: ModuleType) -> None:
        reporter = wifi_scan.WifiReporter(
            server_url="https://bridge.test", api_key="k", node_id="n"
        )
        _assert_verifying(reporter._ssl_ctx)

    def test_node_agent_heartbeat_fails_closed_on_bad_ca(
        self, monkeypatch: pytest.MonkeyPatch, bad_ca: str, caplog
    ) -> None:
        """A CA file that goes bad after startup fails the heartbeat, not the agent."""

        def fake_urlopen(*args: object, **kwargs: object) -> None:
            raise AssertionError("must not contact the bridge without a CA")

        monkeypatch.setattr(node_agent.urllib.request, "urlopen", fake_urlopen)
        monkeypatch.setenv("MLRF_CA_CERT", bad_ca)
        with caplog.at_level(logging.ERROR):
            ok = node_agent.send_heartbeat(
                "https://bridge.test", "secret", "node-1", {}
            )
        assert ok is False
        assert any(bad_ca in r.getMessage() for r in caplog.records)

    def test_node_agent_main_exits_cleanly_on_bad_ca(
        self, monkeypatch: pytest.MonkeyPatch, bad_ca: str, caplog
    ) -> None:
        def no_heartbeat(*args: object, **kwargs: object) -> bool:
            raise AssertionError("heartbeat attempted with an unusable CA")

        monkeypatch.setattr(node_agent, "send_heartbeat", no_heartbeat)
        monkeypatch.setattr(node_agent, "collect_metrics", lambda: {})
        monkeypatch.setattr(
            sys, "argv", ["node_agent", "--node-id", "n", "--api-key", "k", "--once"]
        )
        monkeypatch.setenv("MLRF_CA_CERT", bad_ca)
        with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as exit_info:
            node_agent.main()
        assert exit_info.value.code == 1
        assert any(f"MLRF_CA_CERT={bad_ca}" in r.getMessage() for r in caplog.records)

    def test_node_agent_main_runs_with_good_ca(
        self, monkeypatch: pytest.MonkeyPatch, ca_pem: str
    ) -> None:
        calls: list[tuple] = []
        monkeypatch.setattr(
            node_agent, "send_heartbeat", lambda *a, **kw: calls.append(a) or True
        )
        monkeypatch.setattr(node_agent, "collect_metrics", lambda: {})
        monkeypatch.setattr(node_agent.signal, "signal", lambda *a: None)
        monkeypatch.setattr(
            sys, "argv", ["node_agent", "--node-id", "n", "--api-key", "k", "--once"]
        )
        monkeypatch.setenv("MLRF_CA_CERT", ca_pem)
        node_agent.main()
        assert len(calls) == 1

    def test_wifi_reporter_raises_on_bad_ca(
        self, wifi_scan: ModuleType, monkeypatch: pytest.MonkeyPatch, bad_ca: str
    ) -> None:
        monkeypatch.setenv("MLRF_CA_CERT", bad_ca)
        with pytest.raises(wifi_scan.TLSConfigError):
            wifi_scan.WifiReporter(
                server_url="https://bridge.test", api_key="k", node_id="n"
            )

    def test_wifi_main_exits_cleanly_on_bad_ca(
        self,
        wifi_scan: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        bad_ca: str,
        caplog,
    ) -> None:
        def no_reporter(*args: object, **kwargs: object) -> None:
            raise AssertionError("reporter built with an unusable CA")

        monkeypatch.setattr(wifi_scan, "WifiReporter", no_reporter)
        monkeypatch.setattr(sys, "argv", ["wifi_scan"])
        monkeypatch.setenv("MLRF_BRIDGE_URL", "https://bridge.test")
        monkeypatch.setenv("MLRF_BRIDGE_KEY", "k")
        monkeypatch.setenv("MLRF_NODE_ID", "n")
        monkeypatch.setenv("MLRF_CA_CERT", bad_ca)
        with caplog.at_level(logging.ERROR):
            assert wifi_scan.main() == 1
        assert any(f"MLRF_CA_CERT={bad_ca}" in r.getMessage() for r in caplog.records)

    def test_rf_scan_main_exits_cleanly_on_bad_ca(
        self, rf_scan: ModuleType, monkeypatch: pytest.MonkeyPatch, bad_ca: str, caplog
    ) -> None:
        def no_server() -> None:
            raise AssertionError("rf_scan kept starting with an unusable CA")

        monkeypatch.setattr(rf_scan, "start_status_server", no_server)
        monkeypatch.setitem(
            rf_scan.state, "capture_mode", rf_scan.state.get("capture_mode")
        )
        monkeypatch.setenv("MLRF_BRIDGE_URL", "https://bridge.test")
        monkeypatch.setenv("MLRF_BRIDGE_KEY", "k")
        monkeypatch.setenv("MLRF_NODE_ID", "n")
        monkeypatch.setenv("MLRF_MODEL_PATH", "/nonexistent/model.onnx")
        monkeypatch.setenv("MLRF_CA_BUNDLE", bad_ca)
        with caplog.at_level(logging.ERROR):
            assert rf_scan.main() == 1
        assert any(f"MLRF_CA_BUNDLE={bad_ca}" in r.getMessage() for r in caplog.records)

    def test_no_unconditional_cert_none_left(self) -> None:
        """Every CERT_NONE in the edge agents sits behind MLRF_INSECURE_TLS."""
        edge_dir = Path(node_agent.__file__).parent
        shiny_agent = _REPO_SRC / "sigrift" / "lib" / "shiny" / "node_agent.py"
        for path in [*sorted(edge_dir.glob("*.py")), shiny_agent]:
            lines = path.read_text().splitlines()
            for i, line in enumerate(lines):
                if "CERT_NONE" in line or "check_hostname = False" in line:
                    window = "\n".join(lines[max(0, i - 6) : i])
                    assert "_insecure_tls_requested()" in window or (
                        'MLRF_INSECURE_TLS", "") == "1"' in window
                    ), f"{path.name}:{i + 1} disables TLS verification unconditionally"


class TestDetectionReporterCABundle:
    def _make(self):
        from sigrift.edge.detection_reporter import DetectionReporter

        return DetectionReporter(
            server_url="https://bridge.test:8443",
            api_key="k",
            node_id="n",
            flush_interval_seconds=999,
        )

    def test_mlrf_ca_bundle_honoured(
        self, monkeypatch: pytest.MonkeyPatch, ca_pem: str
    ) -> None:
        monkeypatch.setenv("MLRF_CA_BUNDLE", ca_pem)
        ctx = self._make()._ssl_ctx
        _assert_verifying(ctx)
        assert _ca_subjects(ctx) == ["sigrift-test-ca"]

    def test_missing_bundle_falls_back_to_system_store(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BRIDGE_CA_BUNDLE", "/nonexistent/bundle.pem")
        _assert_verifying(self._make()._ssl_ctx)

    @pytest.mark.parametrize(
        "var", ["MLRF_CA_CERT", "MLRF_CA_BUNDLE", "BRIDGE_CA_BUNDLE"]
    )
    def test_ca_env_read_at_construction(
        self, monkeypatch: pytest.MonkeyPatch, ca_pem: str, var: str
    ) -> None:
        """MLRF_CA_CERT used to be read once at import time."""
        monkeypatch.setenv(var, ca_pem)
        assert _ca_subjects(self._make()._ssl_ctx) == ["sigrift-test-ca"]

    @pytest.mark.parametrize(
        "var", ["MLRF_CA_CERT", "MLRF_CA_BUNDLE", "BRIDGE_CA_BUNDLE"]
    )
    def test_bad_bundle_raises_clear_error(
        self, monkeypatch: pytest.MonkeyPatch, bad_ca: str, var: str
    ) -> None:
        monkeypatch.setenv(var, bad_ca)
        with pytest.raises(detection_reporter.TLSConfigError, match=var):
            self._make()

    def test_main_exits_cleanly_on_bad_ca(
        self, monkeypatch: pytest.MonkeyPatch, bad_ca: str, caplog
    ) -> None:
        def no_reporter(*args: object, **kwargs: object) -> None:
            raise AssertionError("reporter built with an unusable CA")

        monkeypatch.setattr(detection_reporter, "DetectionReporter", no_reporter)
        monkeypatch.setattr(sys, "argv", ["detection_reporter", "--test"])
        monkeypatch.setenv("BRIDGE_CA_BUNDLE", bad_ca)
        with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as exit_info:
            detection_reporter.main()
        assert exit_info.value.code == 1
        assert any(
            f"BRIDGE_CA_BUNDLE={bad_ca}" in r.getMessage() for r in caplog.records
        )


# ---------------------------------------------------------------------------
# sigrift.lib.shiny.node_agent: was a stale, verify-off copy; now an alias
# ---------------------------------------------------------------------------

_SHINY_AGENT = _REPO_SRC / "sigrift" / "lib" / "shiny" / "node_agent.py"


class TestShinyNodeAgentAlias:
    def test_is_the_edge_agent(self) -> None:
        alias = importlib.import_module("sigrift.lib.shiny.node_agent")
        from sigrift.lib.shiny import node_agent as from_package

        assert alias is node_agent
        assert from_package is node_agent

    def test_heartbeat_verifies_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        alias = importlib.import_module("sigrift.lib.shiny.node_agent")
        seen: dict = {}

        def fake_urlopen(req, context=None, timeout=None):
            seen["ctx"] = context
            raise _Captured()

        monkeypatch.setattr(alias.urllib.request, "urlopen", fake_urlopen)
        monkeypatch.setattr(alias, "_cert_auth_active", False)
        assert alias.send_heartbeat("https://bridge.test", "k", "n", {}) is False
        _assert_verifying(seen["ctx"])

    def test_missing_ca_cert_does_not_disable_verification(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The old copy fell back to CERT_NONE when MLRF_CA_CERT was missing."""
        alias = importlib.import_module("sigrift.lib.shiny.node_agent")
        monkeypatch.setattr(alias, "_missing_ca_logged", set())
        monkeypatch.setenv("MLRF_CA_CERT", "/nonexistent/ca.pem")
        _assert_verifying(alias._build_ssl_context())

    def test_insecure_only_with_explicit_opt_in(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        alias = importlib.import_module("sigrift.lib.shiny.node_agent")
        monkeypatch.setattr(alias, "_insecure_tls_warned", False)
        monkeypatch.setenv("MLRF_INSECURE_TLS", "1")
        assert alias._build_ssl_context().verify_mode == ssl.CERT_NONE

    def test_running_it_runs_the_edge_main(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[bool] = []
        monkeypatch.setattr(node_agent, "main", lambda: calls.append(True))
        runpy.run_path(str(_SHINY_AGENT), run_name="__main__")
        assert calls == [True]

    def test_script_runs_from_a_checkout_without_pythonpath(
        self, tmp_path: Path
    ) -> None:
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        out = subprocess.run(
            [sys.executable, "-I", str(_SHINY_AGENT), "--help"],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert out.returncode == 0, out.stderr
        assert "--node-id" in out.stdout

    def test_no_tls_bypass_left_in_lib_shiny(self) -> None:
        for path in sorted(_SHINY_AGENT.parent.rglob("*.py")):
            text = path.read_text()
            for needle in ("CERT_NONE", "check_hostname = False", "verify=False"):
                assert needle not in text, f"{path}: {needle}"


class TestSignalTesterTLS:
    def test_verifies_by_default(self, signal_tester: ModuleType) -> None:
        _assert_verifying(signal_tester._bridge_ssl_context())

    def test_insecure_opt_in(
        self, signal_tester: ModuleType, monkeypatch: pytest.MonkeyPatch, caplog
    ) -> None:
        monkeypatch.setenv("MLRF_INSECURE_TLS", "1")
        with caplog.at_level(logging.WARNING):
            ctx = signal_tester._bridge_ssl_context()
        assert ctx.verify_mode == ssl.CERT_NONE
        assert any("MLRF_INSECURE_TLS" in r.getMessage() for r in caplog.records)

    def test_ca_cert(
        self, signal_tester: ModuleType, monkeypatch: pytest.MonkeyPatch, ca_pem: str
    ) -> None:
        monkeypatch.setenv("MLRF_CA_CERT", ca_pem)
        ctx = signal_tester._bridge_ssl_context()
        _assert_verifying(ctx)
        assert _ca_subjects(ctx) == ["sigrift-test-ca"]

    def test_inject_uses_verifying_context(
        self, signal_tester: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import urllib.request

        seen: dict = {}

        def fake_urlopen(req, context=None, timeout=None):
            seen["ctx"] = context
            raise _Captured("stop")

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        out = signal_tester.inject_to_bridge([], "https://bridge.test", "k")
        assert out["status"] == "error"
        _assert_verifying(seen["ctx"])


# ---------------------------------------------------------------------------
# Remote iq_capture clamping (rf_scan)
# ---------------------------------------------------------------------------


class TestIQCaptureCommand:
    def test_normal_request(self, rf_scan: ModuleType) -> None:
        p = rf_scan.parse_iq_capture_command(
            {
                "freq_hz": 433.92e6,
                "duration_ms": 500,
                "sample_rate": 2.4e6,
                "command_id": "abc-1",
            }
        )
        assert p["n_samples"] == 1_200_000
        assert p["freq_hz"] == 433.92e6
        assert p["command_id"] == "abc-1"

    def test_defaults(self, rf_scan: ModuleType) -> None:
        p = rf_scan.parse_iq_capture_command({"freq_hz": 915e6})
        assert p["n_samples"] == 2_400_000
        assert p["command_id"] == "manual"

    def test_minimum_is_input_samples(self, rf_scan: ModuleType) -> None:
        p = rf_scan.parse_iq_capture_command(
            {"freq_hz": 915e6, "duration_ms": 0.001, "sample_rate": 1e6}
        )
        assert p["n_samples"] == rf_scan.INPUT_SAMPLES

    @pytest.mark.parametrize(
        ("duration_ms", "sample_rate"),
        [(60_000, 61.44e6), (60_000, 2.4e6), (10_000, 20e6)],
    )
    def test_huge_requests_are_capped(
        self, rf_scan: ModuleType, duration_ms: float, sample_rate: float
    ) -> None:
        p = rf_scan.parse_iq_capture_command(
            {"freq_hz": 915e6, "duration_ms": duration_ms, "sample_rate": sample_rate}
        )
        assert p["n_samples"] == rf_scan.IQ_CAPTURE_MAX_SAMPLES

    @pytest.mark.parametrize(
        "cmd",
        [
            None,
            [],
            "iq",
            {"freq_hz": 0},
            {"freq_hz": -1e6},
            {"freq_hz": 1e12},
            {"freq_hz": float("nan")},
            {"freq_hz": "915e6"},
            {"freq_hz": True},
            {"freq_hz": 915e6, "duration_ms": 0},
            {"freq_hz": 915e6, "duration_ms": -5},
            {"freq_hz": 915e6, "duration_ms": float("inf")},
            {"freq_hz": 915e6, "duration_ms": 1e12},
            {"freq_hz": 915e6, "duration_ms": None},
            {"freq_hz": 915e6, "sample_rate": 0},
            {"freq_hz": 915e6, "sample_rate": 1e15},
            {"freq_hz": 915e6, "sample_rate": float("nan")},
            {"freq_hz": 915e6, "sample_rate": [1]},
        ],
    )
    def test_nonsense_rejected(self, rf_scan: ModuleType, cmd: object) -> None:
        with pytest.raises(ValueError):
            rf_scan.parse_iq_capture_command(cmd)

    def test_capture_endpoint_rejects_nonsense(self, rf_scan: ModuleType) -> None:
        import json
        import threading
        import urllib.error
        import urllib.request
        from http.server import HTTPServer

        srv = HTTPServer(("127.0.0.1", 0), rf_scan.StatusHandler)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{srv.server_address[1]}/capture"

        def post(body: object) -> int:
            req = urllib.request.Request(
                url, data=json.dumps(body).encode(), method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    return resp.status
            except urllib.error.HTTPError as e:
                return e.code

        try:
            while not rf_scan.capture_queue.empty():
                rf_scan.capture_queue.get_nowait()
            assert post({"freq_hz": 915e6, "duration_ms": -1}) == 400
            assert post(["not", "a", "dict"]) == 400
            assert rf_scan.capture_queue.empty()
            assert post({"freq_hz": 915e6, "duration_ms": 100}) == 200
            assert rf_scan.capture_queue.qsize() == 1
        finally:
            while not rf_scan.capture_queue.empty():
                rf_scan.capture_queue.get_nowait()
            srv.shutdown()
            srv.server_close()

    def test_command_id_sanitised(self, rf_scan: ModuleType) -> None:
        p = rf_scan.parse_iq_capture_command(
            {"freq_hz": 915e6, "command_id": "../x/y?z#" + "a" * 200}
        )
        assert "/" not in p["command_id"] and "?" not in p["command_id"]
        assert len(p["command_id"]) <= 64
        assert p["command_id"].startswith(".._x_y_z_")


def test_env_is_clean() -> None:
    """Guard: the autouse fixture really strips TLS env for these tests."""
    for var in _TLS_ENV:
        assert var not in os.environ
