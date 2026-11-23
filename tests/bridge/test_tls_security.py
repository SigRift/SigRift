"""Exercise TLS policy with real certificate validation and in-memory handshakes."""

from datetime import datetime, timedelta, timezone
import ssl
import subprocess

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import pytest

from sigrift.lib.security import tls


def _identity(directory, name, issuer=None, client=False):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer[0].subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=issuer is None, path_length=None), True)
    )
    if issuer:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.CLIENT_AUTH
                    if client
                    else ExtendedKeyUsageOID.SERVER_AUTH
                ]
            ),
            False,
        ).add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
    cert = builder.sign(issuer[1] if issuer else key, hashes.SHA256())
    cert_path, key_path = directory / f"{name}.crt", directory / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    return cert, key, cert_path, key_path


@pytest.fixture
def identities(tmp_path):
    ca = _identity(tmp_path, "trusted-ca")
    other_ca = _identity(tmp_path, "other-ca")
    return {
        "ca": ca,
        "other_ca": other_ca,
        "server": _identity(tmp_path, "server.test", ca),
        "client": _identity(tmp_path, "client.test", ca, client=True),
        "untrusted_server": _identity(tmp_path, "untrusted-server.test", other_ca),
        "untrusted_client": _identity(
            tmp_path, "untrusted-client.test", other_ca, client=True
        ),
    }


def _handshake(server_context, client_context, hostname="server.test"):
    """Drive OpenSSL, including TLS 1.3's delayed client-certificate check."""
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    client = client_context.wrap_bio(
        client_in, client_out, server_side=False, server_hostname=hostname
    )
    complete = set()
    for _ in range(20):
        for peer, name in ((client, "client"), (server, "server")):
            if name not in complete:
                try:
                    peer.do_handshake()
                    complete.add(name)
                except ssl.SSLWantReadError:
                    pass
        client_in.write(server_out.read())
        server_in.write(client_out.read())
        if len(complete) == 2:
            client.write(b"authenticated application data")
            server_in.write(client_out.read())
            assert server.read(64) == b"authenticated application data"
            return server, client
    pytest.fail("TLS handshake did not complete within bounded BIO exchanges")


def _server(identities, mutual_tls=False):
    return tls.create_tls_context(
        *identities["server"][2:],
        ca_path=identities["ca"][2],
        mutual_tls=mutual_tls,
    )


@pytest.mark.parametrize("mutual_tls", [False, True])
def test_trusted_server_and_client_exchange_data(identities, mutual_tls):
    client = tls.create_tls_context(
        *identities["client"][2:],
        ca_path=identities["ca"][2],
        server=False,
        mutual_tls=mutual_tls,
    )
    server = _server(identities, mutual_tls)
    server_peer, client_peer = _handshake(server, client)
    assert client.verify_mode == ssl.CERT_REQUIRED
    assert client.check_hostname
    assert client.minimum_version == ssl.TLSVersion.TLSv1_2
    assert server.minimum_version == ssl.TLSVersion.TLSv1_2
    assert not server.check_hostname
    assert server.verify_mode == (ssl.CERT_REQUIRED if mutual_tls else ssl.CERT_NONE)
    assert client_peer.getpeercert()["subjectAltName"] == (("DNS", "server.test"),)
    if mutual_tls:
        assert server_peer.getpeercert()["subjectAltName"] == (("DNS", "client.test"),)


@pytest.mark.parametrize("mutual_tls", [False, True])
def test_client_uses_default_trust_with_or_without_mutual_tls(
    identities, monkeypatch, mutual_tls
):
    def load_test_trust(context):
        context.load_verify_locations(str(identities["ca"][2]))

    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", load_test_trust)
    client = tls.create_tls_context(
        *identities["client"][2:], server=False, mutual_tls=mutual_tls
    )
    _handshake(_server(identities, mutual_tls), client)


@pytest.mark.parametrize("mutual_tls", [False, True])
def test_system_trust_load_failure_keeps_verification_required(
    identities, monkeypatch, caplog, mutual_tls
):
    def unavailable_trust(context):
        raise OSError("trust store unavailable")

    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", unavailable_trust)
    client = tls.create_tls_context(server=False, mutual_tls=mutual_tls)
    assert client.verify_mode == ssl.CERT_REQUIRED
    assert client.check_hostname
    with pytest.raises(ssl.SSLCertVerificationError):
        _handshake(_server(identities), client)
    assert "Failed to load system CA certs" in caplog.text


@pytest.mark.parametrize("client_identity", [None, "untrusted_client"])
def test_mutual_tls_rejects_missing_or_untrusted_client(identities, client_identity):
    paths = identities[client_identity][2:] if client_identity else ()
    client = tls.create_tls_context(*paths, ca_path=identities["ca"][2], server=False)
    with pytest.raises(ssl.SSLError):
        _handshake(_server(identities, mutual_tls=True), client)


@pytest.mark.parametrize("mutual_tls", [False, True])
def test_client_rejects_wrong_hostname(identities, mutual_tls):
    client = tls.create_tls_context(
        ca_path=identities["ca"][2], server=False, mutual_tls=mutual_tls
    )
    with pytest.raises(ssl.SSLCertVerificationError):
        _handshake(_server(identities), client, hostname="wrong.test")


@pytest.mark.parametrize("mutual_tls", [False, True])
def test_explicit_ca_rejects_server_trusted_only_by_defaults(
    identities, monkeypatch, mutual_tls
):
    def load_other_trust(context):
        context.load_verify_locations(str(identities["other_ca"][2]))

    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", load_other_trust)
    server = tls.create_tls_context(*identities["untrusted_server"][2:])
    client = tls.create_tls_context(
        ca_path=identities["ca"][2], server=False, mutual_tls=mutual_tls
    )
    with pytest.raises(ssl.SSLCertVerificationError):
        _handshake(server, client, hostname="untrusted-server.test")


def test_protocols_below_tls12_cannot_negotiate(identities):
    server = _server(identities)
    server.maximum_version = ssl.TLSVersion.TLSv1_1
    client = tls.create_tls_context(ca_path=identities["ca"][2], server=False)
    with pytest.raises(ssl.SSLError):
        _handshake(server, client)


@pytest.mark.parametrize("missing", ["cert", "key", "ca"])
def test_missing_configured_file_is_reported(identities, tmp_path, missing):
    paths = dict(
        cert_path=identities["server"][2],
        key_path=identities["server"][3],
        ca_path=identities["ca"][2],
    )
    paths[missing + "_path"] = tmp_path / "missing.pem"
    with pytest.raises(FileNotFoundError, match="not found"):
        tls.create_tls_context(**paths)


@pytest.mark.parametrize("field", ["cert_path", "key_path"])
@pytest.mark.parametrize("server", [False, True])
def test_partial_identity_configuration_is_rejected(identities, field, server):
    path = identities["server"][2 if field == "cert_path" else 3]
    with pytest.raises(ValueError, match="together"):
        tls.create_tls_context(server=server, **{field: path})


@pytest.mark.parametrize("bad_field", ["cert_path", "key_path", "ca_path"])
def test_invalid_pem_is_rejected(identities, tmp_path, bad_field):
    invalid = tmp_path / "invalid.pem"
    invalid.write_text("not a certificate or private key")
    paths = dict(
        cert_path=identities["server"][2],
        key_path=identities["server"][3],
        ca_path=identities["ca"][2],
    )
    paths[bad_field] = invalid
    with pytest.raises(ssl.SSLError):
        tls.create_tls_context(**paths)


def test_self_signed_generation_produces_usable_matching_identity(tmp_path):
    cert, key = tmp_path / "certs" / "dev.crt", tmp_path / "keys" / "dev.key"
    tls.generate_self_signed_cert(cert, key, common_name="development.test", days=2)
    generated = x509.load_pem_x509_certificate(cert.read_bytes())
    private_key = serialization.load_pem_private_key(key.read_bytes(), password=None)
    assert generated.subject == generated.issuer
    assert (
        generated.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        == "development.test"
    )
    assert generated.not_valid_after_utc - generated.not_valid_before_utc == timedelta(
        days=2
    )
    assert (
        generated.public_key().public_numbers()
        == private_key.public_key().public_numbers()
    )
    server = tls.create_tls_context(cert, key)
    client = tls.create_tls_context(ca_path=cert, server=False)
    _handshake(server, client, hostname="development.test")


@pytest.mark.parametrize(
    ("failure", "error", "message"),
    [
        (FileNotFoundError(), FileNotFoundError, "OpenSSL not found"),
        (
            subprocess.CalledProcessError(1, ["openssl"], stderr="generation rejected"),
            RuntimeError,
            "generation rejected",
        ),
    ],
)
def test_certificate_tool_failure_is_reported(
    tmp_path, monkeypatch, failure, error, message
):
    def failed_generation(*args, **kwargs):
        raise failure

    monkeypatch.setattr(tls.subprocess, "run", failed_generation)
    cert, key = tmp_path / "failed.crt", tmp_path / "failed.key"
    with pytest.raises(error, match=message):
        tls.generate_self_signed_cert(cert, key)
    assert not cert.exists()
    assert not key.exists()
