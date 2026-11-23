"""Security-path tests for the embedded CA (``sigrift.bridge.ca``).

``test_ca.py`` covers the happy paths and ``test_ca_secrets_dir.py`` the
key-location migration. This file covers what an attacker or a broken
deployment would exercise: the leaf and CA certificate profiles checked
with a real path verifier (wrong CA, expiry, server use, a leaf acting as
a CA), CSRs that try to smuggle in extensions or carry a bad signature,
input validation, file permissions and planted temp-file symlinks, a
corrupt registry, CRL edge cases, private keys staying out of the
registry and the logs, and the ``migrate-key`` command run in-process.
"""

from __future__ import annotations

import errno
import json
import logging
import os
import re
import runpy
import stat
import sys
import time
import warnings
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from sigrift.bridge import ca as ca_mod
from sigrift.bridge.ca import (
    VALID_CERT_ROLES,
    CAError,
    CertificateAuthority,
    validate_identity,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _private_secrets_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test's CA private key goes to its own tmp secrets dir."""
    monkeypatch.setenv("BRIDGE_SECRETS_DIR", str(tmp_path / "secrets"))


@pytest.fixture
def ca(tmp_path: Path) -> CertificateAuthority:
    authority = CertificateAuthority(tmp_path / "data" / "ca")
    authority.ensure_ca()
    return authority


def _separate_ca(root: Path) -> CertificateAuthority:
    """An unrelated CA with its own key dir.

    Every CA dir named ``ca`` maps to ``$BRIDGE_SECRETS_DIR/ca/ca.key``, so
    a second one under the same secrets dir would share (and clobber) the
    first one's key: see ``test_ensure_ca_never_overwrites_a_private_key``.
    """
    return CertificateAuthority(root / "ca", key_dir=root / "keys")


def _key_pem(key: ec.EllipticCurvePrivateKey | None = None) -> bytes:
    key = key or ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _csr(
    key: ec.EllipticCurvePrivateKey | None = None,
    *,
    extensions: list[tuple[x509.ExtensionType, bool]] = (),
) -> bytes:
    key = key or ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "requested-name")])
    )
    for ext, critical in extensions:
        builder = builder.add_extension(ext, critical=critical)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def _cert(pem: str | bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode() if isinstance(pem, str) else pem)


def _client_verifier(root: x509.Certificate, at: datetime):
    return PolicyBuilder().store(Store([root])).time(at).build_client_verifier()


def _registry(ca: CertificateAuthority) -> dict:
    return json.loads((ca._dir / "registry.json").read_text(encoding="utf-8"))


def _write_registry(ca: CertificateAuthority, data: dict) -> None:
    (ca._dir / "registry.json").write_text(json.dumps(data), encoding="utf-8")


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


# ---------------------------------------------------------------------------
# Leaf and CA certificate profiles, checked with a real path verifier
# ---------------------------------------------------------------------------


class TestCertificateProfiles:
    def test_leaf_verifies_as_a_client_cert_for_its_identity_only(
        self, ca: CertificateAuthority
    ) -> None:
        leaf = _cert(ca.issue_cert(identity="edge-7", role="node")["cert_pem"])
        root = _cert(ca.ca_cert_pem)
        verified = _client_verifier(root, datetime.now(timezone.utc)).verify(leaf, [])
        assert verified.subjects == [x509.DNSName("edge-7")]
        assert verified.chain[-1] == root

    def test_leaf_is_rejected_outside_its_validity_window(
        self, ca: CertificateAuthority
    ) -> None:
        leaf = _cert(
            ca.issue_cert(identity="edge-7", role="node", ttl_days=1)["cert_pem"]
        )
        root = _cert(ca.ca_cert_pem)
        for when in (
            leaf.not_valid_after_utc + timedelta(minutes=1),  # expired
            leaf.not_valid_before_utc - timedelta(minutes=1),  # not yet valid
        ):
            with pytest.raises(VerificationError, match="not valid at validation"):
                _client_verifier(root, when).verify(leaf, [])

    def test_leaf_is_rejected_by_another_ca(
        self, ca: CertificateAuthority, tmp_path: Path
    ) -> None:
        other = _separate_ca(tmp_path / "other")
        other.ensure_ca()
        leaf = _cert(ca.issue_cert(identity="edge-7", role="node")["cert_pem"])
        with pytest.raises(VerificationError):
            _client_verifier(
                _cert(other.ca_cert_pem), datetime.now(timezone.utc)
            ).verify(leaf, [])

    def test_leaf_is_not_usable_as_a_server_cert(
        self, ca: CertificateAuthority
    ) -> None:
        leaf = _cert(ca.issue_cert(identity="edge-7", role="node")["cert_pem"])
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert list(eku) == [ExtendedKeyUsageOID.CLIENT_AUTH]
        verifier = (
            PolicyBuilder()
            .store(Store([_cert(ca.ca_cert_pem)]))
            .build_server_verifier(x509.DNSName("edge-7"))
        )
        with pytest.raises(VerificationError, match="EKU"):
            verifier.verify(leaf, [])

    def test_leaf_cannot_act_as_a_ca(self, ca: CertificateAuthority) -> None:
        issued = ca.issue_cert(identity="edge-7", role="admin")
        leaf = _cert(issued["cert_pem"])
        bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.critical and bc.value.ca is False
        ku = leaf.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.critical
        assert ku.value.digital_signature is True
        assert ku.value.key_cert_sign is False and ku.value.crl_sign is False

        # A certificate signed with the leaf's key does not chain through it.
        leaf_key = serialization.load_pem_private_key(
            issued["key_pem"].encode(), password=None
        )
        child_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        child = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]))
            .issuer_name(leaf.subject)
            .public_key(child_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("x")]), False)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    leaf_key.public_key()
                ),
                False,
            )
            .sign(leaf_key, hashes.SHA256())
        )
        with pytest.raises(VerificationError):
            _client_verifier(_cert(ca.ca_cert_pem), now).verify(child, [leaf])

    def test_leaf_validity_and_registry_dates_match(
        self, ca: CertificateAuthority
    ) -> None:
        issued = ca.issue_cert(identity="edge-7", role="node", ttl_days=30)
        leaf = _cert(issued["cert_pem"])
        issued_at = datetime.fromisoformat(issued["issued_at"])
        # Back-dated 5 minutes for clock skew, lifetime exactly ttl_days.
        assert abs(
            leaf.not_valid_before_utc - (issued_at - timedelta(minutes=5))
        ) < timedelta(seconds=1)
        assert abs(
            leaf.not_valid_after_utc - (issued_at + timedelta(days=30))
        ) < timedelta(seconds=1)
        entry = ca.get_cert(issued["serial"])
        assert abs(
            datetime.fromisoformat(entry["not_after"]) - leaf.not_valid_after_utc
        ) < timedelta(seconds=1)
        assert entry["fingerprint_sha256"] == leaf.fingerprint(hashes.SHA256()).hex()

    def test_leaf_aki_names_the_ca_key(self, ca: CertificateAuthority) -> None:
        leaf = _cert(ca.issue_cert(identity="edge-7", role="node")["cert_pem"])
        root = _cert(ca.ca_cert_pem)
        aki = leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        ski = root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        assert aki.value.key_identifier == ski.value.digest
        assert leaf.issuer == root.subject

    def test_ca_cert_profile(self, ca: CertificateAuthority) -> None:
        root = _cert(ca.ca_cert_pem)
        assert root.verify_directly_issued_by(root) is None  # self-signed
        assert isinstance(root.public_key(), ec.EllipticCurvePublicKey)
        assert root.public_key().curve.name == "secp256r1"
        bc = root.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.critical and bc.value.ca is True and bc.value.path_length == 0
        ku = root.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.critical
        assert ku.value.key_cert_sign and ku.value.crl_sign
        assert not ku.value.digital_signature and not ku.value.key_encipherment
        lifetime = root.not_valid_after_utc - root.not_valid_before_utc
        assert lifetime == timedelta(days=3650, minutes=5)

    def test_serials_are_unique_and_registry_keys_are_decimal(
        self, ca: CertificateAuthority
    ) -> None:
        serials = [
            ca.sign_csr(_csr(), identity=f"n{i}", role="node")["serial"]
            for i in range(5)
        ]
        assert len(set(serials)) == 5
        for serial in serials:
            assert serial.isdigit() and int(serial) > 0
            assert int(serial).bit_length() <= 159  # RFC 5280: at most 20 octets
        assert sorted(_registry(ca)["issued"]) == sorted(serials)


# ---------------------------------------------------------------------------
# CSR handling
# ---------------------------------------------------------------------------


class TestCsrHandling:
    def test_csr_extensions_are_ignored(self, ca: CertificateAuthority) -> None:
        """A CSR asking for CA rights, extra SANs or server auth gets none."""
        csr = _csr(
            extensions=[
                (x509.BasicConstraints(ca=True, path_length=None), True),
                (
                    x509.SubjectAlternativeName(
                        [x509.DNSName("admin"), x509.DNSName("*.example.com")]
                    ),
                    False,
                ),
                (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False),
                (
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=True,
                        key_encipherment=True,
                        data_encipherment=True,
                        key_agreement=True,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    True,
                ),
            ]
        )
        leaf = _cert(ca.sign_csr(csr, identity="honest", role="node")["cert_pem"])
        assert (
            leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            is False
        )
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert san.value.get_values_for_type(x509.DNSName) == ["honest"]
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert list(eku.value) == [ExtendedKeyUsageOID.CLIENT_AUTH]
        ku = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
        assert not ku.key_cert_sign and not ku.crl_sign and not ku.key_encipherment

    def test_cert_binds_the_csr_public_key(self, ca: CertificateAuthority) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = _cert(ca.sign_csr(_csr(key), identity="edge", role="node")["cert_pem"])
        assert leaf.public_key() == key.public_key()

    def test_csr_with_a_bad_signature_is_rejected(
        self, ca: CertificateAuthority
    ) -> None:
        good = x509.load_pem_x509_csr(_csr())
        der = bytearray(good.public_bytes(serialization.Encoding.DER))
        sig = good.signature
        start = bytes(der).rindex(sig)
        der[start + len(sig) // 2] ^= 0x01  # flip a bit inside the signature
        tampered = x509.load_der_x509_csr(bytes(der))
        assert not tampered.is_signature_valid
        pem = tampered.public_bytes(serialization.Encoding.PEM)
        with pytest.raises(CAError, match="signature is invalid"):
            ca.sign_csr(pem, identity="edge", role="node")
        assert ca.list_certs() == []

    @pytest.mark.parametrize("kind", ["empty", "der", "certificate", "private_key"])
    def test_non_csr_input_is_rejected_without_echoing_it(
        self, ca: CertificateAuthority, kind: str
    ) -> None:
        key_pem = _key_pem()
        blob = {
            "empty": b"",
            "der": x509.load_pem_x509_csr(_csr()).public_bytes(
                serialization.Encoding.DER
            ),
            "certificate": ca.ca_cert_pem,
            "private_key": key_pem,
        }[kind]
        with pytest.raises(CAError, match="could not parse CSR") as exc:
            ca.sign_csr(blob, identity="edge", role="node")
        body = b"".join(key_pem.splitlines()[1:-1]).decode()
        assert body[:32] not in str(exc.value)
        assert "PRIVATE KEY" not in str(exc.value)
        assert ca.list_certs() == []


# ---------------------------------------------------------------------------
# Identity / role / lifetime validation
# ---------------------------------------------------------------------------


class TestIssuanceValidation:
    @pytest.mark.parametrize(
        "identity", ["a", "A1", "a" * 253, "edge-01.site_a", "10.0.0.1"]
    )
    def test_valid_identities(self, identity: str) -> None:
        assert validate_identity(identity) == identity

    @pytest.mark.parametrize(
        "identity",
        [
            "a" * 254,
            "edge-",
            "edge.",
            ".edge",
            "_edge",
            "*.example.com",
            "édge",
            "edge\x00",
            "edge\r",
            "edge\nother",
            "\nedge",
            "edge\n",
            "a" * 253 + "\n",
            "edge/../x",
            "CN=admin,O=x",
        ],
    )
    def test_invalid_identities_are_rejected_and_leave_no_trace(
        self, ca: CertificateAuthority, identity: str
    ) -> None:
        with pytest.raises(CAError, match="invalid identity"):
            ca.issue_cert(identity=identity, role="node")
        assert ca.list_certs() == []

    def test_identity_with_a_trailing_newline_is_rejected(
        self, ca: CertificateAuthority
    ) -> None:
        """'$' with re.match also matches before a final newline (fullmatch)."""
        with pytest.raises(CAError):
            validate_identity("edge-1\n")
        with pytest.raises(CAError):
            ca.issue_cert(identity="edge-1\n", role="node")
        assert ca.list_certs() == []

    @pytest.mark.parametrize("identity", ["edge-1\n", "a" * 253 + "\n"])
    def test_the_identity_pattern_alone_rejects_a_trailing_newline(
        self, identity: str
    ) -> None:
        """\\Z, not '$': safe even where it is applied with match or search."""
        assert ca_mod._IDENTITY_RE.match(identity) is None
        assert ca_mod._IDENTITY_RE.search(identity) is None
        assert ca_mod._IDENTITY_RE.match(identity.rstrip("\n"))

    @pytest.mark.parametrize("identity", ["edge-1\n", "edge-1 x", "edge-1/.."])
    def test_validate_identity_needs_a_whole_string_match(
        self, identity: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """fullmatch, not match: safe even with a pattern missing its anchors."""
        unanchored = ca_mod._IDENTITY_RE.pattern.removeprefix(r"\A").removesuffix(r"\Z")
        assert unanchored != ca_mod._IDENTITY_RE.pattern
        monkeypatch.setattr(ca_mod, "_IDENTITY_RE", re.compile(unanchored))
        with pytest.raises(CAError, match="invalid identity"):
            validate_identity(identity)
        assert validate_identity("edge-1") == "edge-1"

    def test_a_registry_entry_with_a_newline_can_still_be_listed_and_revoked(
        self, ca: CertificateAuthority
    ) -> None:
        """Only issuance validates identities: old entries stay manageable."""
        serial = ca.issue_cert(identity="edge-1", role="node")["serial"]
        data = _registry(ca)
        data["issued"][serial]["identity"] = "edge-1\n"
        _write_registry(ca, data)
        assert [r["identity"] for r in ca.list_certs()] == ["edge-1\n"]
        assert ca.get_cert(serial)["identity"] == "edge-1\n"
        assert ca.revoke(serial) is True
        crl = x509.load_pem_x509_crl(ca.generate_crl())
        assert {r.serial_number for r in crl} == {int(serial)}

    @pytest.mark.parametrize("role", ["KEYMASTER", "Admin", "admin ", "", "root"])
    def test_invalid_roles_are_rejected(
        self, ca: CertificateAuthority, role: str
    ) -> None:
        with pytest.raises(CAError, match="invalid role"):
            ca.sign_csr(_csr(), identity="edge", role=role)
        assert ca.list_certs() == []

    def test_every_valid_role_is_recorded(self, ca: CertificateAuthority) -> None:
        for role in sorted(VALID_CERT_ROLES):
            issued = ca.sign_csr(_csr(), identity=f"id-{role}", role=role)
            assert ca.get_cert(issued["serial"])["role"] == role
        assert "keymaster" not in VALID_CERT_ROLES

    @pytest.mark.parametrize(("ttl", "ok"), [(825, True), (826, False), (-1, False)])
    def test_ttl_bounds(self, ca: CertificateAuthority, ttl: int, ok: bool) -> None:
        if ok:
            leaf = _cert(
                ca.issue_cert(identity="e", role="node", ttl_days=ttl)["cert_pem"]
            )
            lifetime = leaf.not_valid_after_utc - leaf.not_valid_before_utc
            assert lifetime == timedelta(days=ttl, minutes=5)
        else:
            with pytest.raises(CAError, match="ttl_days"):
                ca.issue_cert(identity="e", role="node", ttl_days=ttl)
            assert ca.list_certs() == []


# ---------------------------------------------------------------------------
# CA key and certificate handling
# ---------------------------------------------------------------------------


class TestCaKeyHandling:
    def test_public_accessors_before_bootstrap_raise(self, tmp_path: Path) -> None:
        fresh = CertificateAuthority(tmp_path / "data" / "ca")
        with pytest.raises(CAError, match="not initialised"):
            fresh.ca_cert_pem
        with pytest.raises(CAError, match="not initialised"):
            fresh.generate_crl()
        with pytest.raises(CAError, match="not initialised"):
            fresh.issue_cert(identity="edge", role="node")

    def test_missing_key_means_not_initialised(self, ca: CertificateAuthority) -> None:
        ca.key_path.unlink()
        assert not ca.is_initialized
        with pytest.raises(CAError, match="not initialised"):
            ca.sign_csr(_csr(), identity="edge", role="node")

    def test_a_key_that_does_not_match_the_ca_cert_is_refused(
        self, ca: CertificateAuthority
    ) -> None:
        """E.g. the secrets volume restored from a different backup."""
        ca.key_path.write_bytes(_key_pem())
        with pytest.raises(CAError):
            ca.sign_csr(_csr(), identity="edge", role="node")
        assert ca.list_certs() == []

    def test_a_mismatched_key_signs_nothing_and_says_what_to_do(
        self, ca: CertificateAuthority
    ) -> None:
        serial = ca.issue_cert(identity="edge", role="node")["serial"]
        ca.revoke(serial)
        registry = (ca._dir / "registry.json").read_bytes()
        foreign = _key_pem()
        ca.key_path.write_bytes(foreign)

        for attempt in (
            lambda: ca.issue_cert(identity="other", role="node"),
            lambda: ca.sign_csr(_csr(), identity="other", role="node"),
            ca.generate_crl,
        ):
            with pytest.raises(ca_mod.CAStateError) as exc:
                attempt()
            message = str(exc.value)
            assert "does not belong to the CA certificate" in message
            assert "same backup" in message and "ca.replaced.*.key" in message
            assert "PRIVATE KEY" not in message
        assert (ca._dir / "registry.json").read_bytes() == registry
        assert ca.key_path.read_bytes() == foreign
        # Reopening and ensure_ca() leave both files alone too.
        reopened = CertificateAuthority(ca._dir)
        reopened.ensure_ca()
        assert reopened.key_path.read_bytes() == foreign

    @pytest.mark.parametrize(
        ("broken", "why"),
        [
            ("malformed_key", "not an unencrypted PEM private key"),
            ("encrypted_key", "not an unencrypted PEM private key"),
            ("rsa_key", "not an EC private key"),
            ("unreadable_key", "cannot be read"),
            ("malformed_cert", "not a PEM certificate"),
            ("unreadable_cert", "cannot be read"),
        ],
    )
    def test_an_unloadable_key_or_cert_is_a_state_error(
        self, ca: CertificateAuthority, broken: str, why: str
    ) -> None:
        """Refused like the other broken-CA states (a 503, not a 500)."""
        if broken.startswith("unreadable") and os.geteuid() == 0:
            pytest.skip("root ignores file permissions")
        registry = (ca._dir / "registry.json").read_bytes()
        target = ca._dir / "ca.crt" if broken.endswith("cert") else ca.key_path
        if broken == "malformed_key":
            target.write_bytes(b"-----BEGIN PRIVATE KEY-----\nnot a key\n")
        elif broken == "encrypted_key":
            target.write_bytes(
                ec.generate_private_key(ec.SECP256R1()).private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.BestAvailableEncryption(b"test-only-passphrase"),
                )
            )
        elif broken == "rsa_key":
            target.write_bytes(_key_pem(rsa.generate_private_key(65537, 2048)))
        elif broken == "malformed_cert":
            target.write_bytes(b"-----BEGIN CERTIFICATE-----\nnot a cert\n")
        else:
            target.chmod(0o000)
        try:
            for attempt in (
                lambda: ca.issue_cert(identity="edge", role="node"),
                lambda: ca.sign_csr(_csr(), identity="edge", role="node"),
                ca.generate_crl,
            ):
                with pytest.raises(ca_mod.CAStateError, match=why) as exc:
                    attempt()
                message = str(exc.value)
                assert str(target) in message
                assert "PRIVATE KEY" not in message and "CERTIFICATE-" not in message
        finally:
            target.chmod(0o600 if target == ca.key_path else 0o644)
        if broken == "unreadable_cert":
            target.chmod(0o000)
            try:
                with pytest.raises(ca_mod.CAStateError, match="cannot be read"):
                    ca.ca_cert_pem
            finally:
                target.chmod(0o644)
        assert (ca._dir / "registry.json").read_bytes() == registry

    def test_ensure_ca_never_overwrites_a_private_key(self, tmp_path: Path) -> None:
        first = CertificateAuthority(tmp_path / "data-1" / "ca")
        first.ensure_ca()
        key = first.key_path.read_bytes()

        second = CertificateAuthority(tmp_path / "data-2" / "ca")
        assert second.key_path == first.key_path  # same secrets dir, same name
        with pytest.raises(CAError, match="Refusing to create a new CA"):
            second.ensure_ca()
        assert not (tmp_path / "data-2" / "ca" / "ca.crt").exists()

        kept = [p.read_bytes() for p in first.key_path.parent.glob("*.key")]
        assert any(k == key for k in kept), "the first CA's private key is gone"
        leaf = _cert(first.issue_cert(identity="edge", role="node")["cert_pem"])
        assert leaf.verify_directly_issued_by(_cert(first.ca_cert_pem)) is None

    def test_a_lost_ca_cert_is_refused_and_the_key_kept(
        self, ca: CertificateAuthority
    ) -> None:
        key = ca.key_path.read_bytes()
        cert = ca.ca_cert_pem
        serial = ca.issue_cert(identity="edge", role="node")["serial"]
        (ca._dir / "ca.crt").unlink()

        with pytest.raises(ca_mod.CAStateError) as exc:
            ca.ensure_ca()
        message = str(exc.value)
        assert str(ca.key_path) in message and str(ca._dir / "ca.crt") in message
        for action in ("restore it from the same backup", "--secrets-dir", "aside"):
            assert action in message
        assert ca.key_path.read_bytes() == key
        assert sorted(p.name for p in ca.key_path.parent.iterdir()) == ["ca.key"]

        # Once ca.crt is back, the same CA carries on.
        (ca._dir / "ca.crt").write_bytes(cert)
        ca.ensure_ca()
        assert ca.ca_cert_pem == cert
        assert ca.get_cert(serial) is not None
        leaf = _cert(ca.issue_cert(identity="edge-2", role="node")["cert_pem"])
        assert leaf.verify_directly_issued_by(_cert(cert)) is None

    @pytest.mark.parametrize("with_cert", [False, True])
    def test_a_dangling_key_symlink_is_not_replaced(
        self, tmp_path: Path, with_cert: bool
    ) -> None:
        """E.g. the key lives on a volume that is not mounted (yet)."""
        authority = CertificateAuthority(tmp_path / "data" / "ca")
        cert = None
        if with_cert:
            authority.ensure_ca()
            cert = authority.ca_cert_pem
            authority.key_path.unlink()
        else:
            authority.key_path.parent.mkdir(parents=True)
        authority.key_path.symlink_to(tmp_path / "unmounted" / "ca.key")
        with pytest.raises(ca_mod.CAStateError, match="symlink to a file that does"):
            authority.ensure_ca()
        assert authority.key_path.is_symlink()
        assert not (tmp_path / "unmounted").exists()
        if with_cert:
            assert authority.ca_cert_pem == cert
        else:
            assert not (authority._dir / "ca.crt").exists()

    def test_an_interrupted_first_bootstrap_is_refused_with_a_way_out(
        self, tmp_path: Path
    ) -> None:
        """The key is written before ca.crt: a kill in between leaves key-only.

        (A failure the process survives removes the key again; see
        test_a_failed_first_bootstrap_removes_the_key_it_created.)
        """
        authority = CertificateAuthority(tmp_path / "data" / "ca")
        authority.key_path.parent.mkdir(parents=True)
        # What a start-up killed right after writing the key leaves behind.
        ca_mod._create_private_file(authority.key_path, _key_pem())
        key = authority.key_path.read_bytes()

        with pytest.raises(ca_mod.CAStateError, match="interrupted") as exc:
            authority.ensure_ca()
        message = str(exc.value)
        assert "move the key aside" in message
        # A concurrent start-up looks the same for a moment: retry comes first.
        assert message.index("wait for it to finish and retry") < message.index(
            "move the key aside"
        )
        assert authority.key_path.read_bytes() == key
        assert not (authority._dir / "ca.crt").exists()
        # The way out: move the key aside, and the next run starts afresh.
        authority.key_path.rename(authority.key_path.with_name("ca.retired.key"))
        authority.ensure_ca()
        assert authority._matches_cert(authority.key_path.read_bytes())

    @pytest.mark.parametrize(
        "failure",
        [
            PermissionError(errno.EACCES, "Permission denied"),  # data/ca restored
            OSError(errno.ENOSPC, "No space left on device"),
            KeyboardInterrupt(),
        ],
        ids=["eacces", "enospc", "interrupt"],
    )
    def test_a_failed_first_bootstrap_removes_the_key_it_created(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        failure: BaseException,
    ) -> None:
        """ca.crt never written: no certificate was issued, so retrying works."""
        authority = CertificateAuthority(tmp_path / "data" / "ca")
        real_write = ca_mod._atomic_write
        seen: list[bytes] = []

        def fail_on_the_cert(path: Path, data: bytes, *, mode: int) -> None:
            if path.name != "ca.crt":
                return real_write(path, data, mode=mode)
            seen.append(authority.key_path.read_bytes())  # the key was there
            raise failure

        with monkeypatch.context() as patch, caplog.at_level(logging.WARNING):
            patch.setattr(ca_mod, "_atomic_write", fail_on_the_cert)
            with pytest.raises(type(failure)):
                authority.ensure_ca()
        assert len(seen) == 1
        assert not authority.key_path.exists() and not authority.key_path.is_symlink()
        assert not (authority._dir / "ca.crt").exists()
        assert sorted(authority.key_path.parent.iterdir()) == []
        text = "\n".join(r.getMessage() for r in caplog.records)
        assert "removed the new CA private key" in text
        assert "PRIVATE KEY" not in text

        # The next start-up creates the CA without anyone moving files.
        authority.ensure_ca()
        assert authority._matches_cert(authority.key_path.read_bytes())
        leaf = _cert(authority.issue_cert(identity="edge", role="node")["cert_pem"])
        assert leaf.verify_directly_issued_by(_cert(authority.ca_cert_pem)) is None

    def test_a_failed_bootstrap_leaves_a_key_it_did_not_create(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Only the file this call created is removed, never a replacement."""
        authority = CertificateAuthority(tmp_path / "data" / "ca")
        theirs = _key_pem()

        def replaced_then_fail(path: Path, data: bytes, *, mode: int) -> None:
            other = authority.key_path.with_name("other.key")
            other.write_bytes(theirs)
            os.replace(other, authority.key_path)  # e.g. an operator restore
            raise OSError(errno.EACCES, "Permission denied")

        monkeypatch.setattr(ca_mod, "_atomic_write", replaced_then_fail)
        with pytest.raises(OSError, match="Permission denied"):
            authority.ensure_ca()
        assert authority.key_path.read_bytes() == theirs
        assert not (authority._dir / "ca.crt").exists()

    def test_a_failed_registry_write_keeps_the_new_ca(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ca.crt written: the CA exists, so its key is never removed."""
        authority = CertificateAuthority(tmp_path / "data" / "ca")
        real_write = ca_mod._atomic_write

        def fail_on_the_registry(path: Path, data: bytes, *, mode: int) -> None:
            if path.name == "registry.json":
                raise OSError(errno.ENOSPC, "No space left on device")
            return real_write(path, data, mode=mode)

        with monkeypatch.context() as patch:
            patch.setattr(ca_mod, "_atomic_write", fail_on_the_registry)
            with pytest.raises(OSError, match="No space left"):
                authority.ensure_ca()
        assert authority.is_initialized
        assert authority._matches_cert(authority.key_path.read_bytes())
        cert = authority.ca_cert_pem
        authority.ensure_ca()
        assert authority.ca_cert_pem == cert
        serial = authority.issue_cert(identity="edge", role="node")["serial"]
        assert list(_registry(authority)["issued"]) == [serial]

    def test_a_lost_ca_key_is_refused_and_the_cert_kept(
        self, ca: CertificateAuthority
    ) -> None:
        """The mirror of a lost ca.crt: a new CA would replace ca.crt."""
        serial = ca.issue_cert(identity="edge", role="node")["serial"]
        cert = ca.ca_cert_pem
        key = ca.key_path.read_bytes()
        registry = (ca._dir / "registry.json").read_bytes()
        ca.key_path.unlink()

        for authority in (ca, CertificateAuthority(ca._dir)):
            with pytest.raises(ca_mod.CAStateError) as exc:
                authority.ensure_ca()
            message = str(exc.value)
            assert "Refusing to create a new CA" in message
            assert str(ca._dir / "ca.crt") in message and str(ca.key_path) in message
            for action in ("bridge_secrets", "--secrets-dir", "move ca.crt aside"):
                assert action in message
            assert "PRIVATE KEY" not in message
        assert ca.ca_cert_pem == cert
        assert (ca._dir / "registry.json").read_bytes() == registry
        assert not ca.key_path.exists()
        assert sorted(ca.key_path.parent.iterdir()) == []

        # Once the key is back, the same CA carries on.
        ca.key_path.write_bytes(key)
        ca.ensure_ca()
        assert ca.ca_cert_pem == cert and ca.get_cert(serial) is not None
        leaf = _cert(ca.issue_cert(identity="edge-2", role="node")["cert_pem"])
        assert leaf.verify_directly_issued_by(_cert(cert)) is None

    def test_another_secrets_dir_does_not_replace_the_ca(
        self, ca: CertificateAuthority, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """E.g. BRIDGE_SECRETS_DIR differs between runs, or the volume is gone."""
        cert = ca.ca_cert_pem
        monkeypatch.setenv("BRIDGE_SECRETS_DIR", str(tmp_path / "elsewhere"))
        moved = CertificateAuthority(ca._dir)
        assert moved.key_path != ca.key_path
        with pytest.raises(ca_mod.CAStateError, match="but no private key at"):
            moved.ensure_ca()
        assert ca.ca_cert_pem == cert
        assert not moved.key_path.exists()

    def test_a_dangling_ca_cert_symlink_is_not_replaced(self, tmp_path: Path) -> None:
        authority = CertificateAuthority(tmp_path / "data" / "ca")
        authority._dir.mkdir(parents=True)
        (authority._dir / "ca.crt").symlink_to(tmp_path / "unmounted" / "ca.crt")
        with pytest.raises(ca_mod.CAStateError, match="but no private key at"):
            authority.ensure_ca()
        assert (authority._dir / "ca.crt").is_symlink()
        assert not authority.key_path.exists()

    def test_a_key_created_concurrently_is_kept(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Another process (bridge or pki_bootstrap) wins the race: no clobber."""
        authority = CertificateAuthority(tmp_path / "data" / "ca")
        theirs = _key_pem()
        real_link = os.link

        def other_process_first(src, dst, **kwargs):
            Path(dst).write_bytes(theirs)
            return real_link(src, dst, **kwargs)

        monkeypatch.setattr(ca_mod.os, "link", other_process_first)
        with pytest.raises(ca_mod.CAStateError, match="appeared"):
            authority.ensure_ca()
        assert authority.key_path.read_bytes() == theirs
        assert not (authority._dir / "ca.crt").exists()
        assert sorted(p.name for p in authority.key_path.parent.iterdir()) == ["ca.key"]

    def test_bootstrap_without_hard_links_still_never_clobbers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def no_hard_links(src, dst, **kwargs):
            raise OSError(errno.EPERM, "Operation not permitted")

        monkeypatch.setattr(ca_mod.os, "link", no_hard_links)
        authority = CertificateAuthority(tmp_path / "data" / "ca")
        authority.ensure_ca()
        assert _mode(authority.key_path) == 0o600
        assert authority._matches_cert(authority.key_path.read_bytes())
        assert sorted(p.name for p in authority.key_path.parent.iterdir()) == ["ca.key"]
        leaf = _cert(authority.issue_cert(identity="edge", role="node")["cert_pem"])
        assert leaf.verify_directly_issued_by(_cert(authority.ca_cert_pem)) is None

    def test_bootstrap_without_hard_links_keeps_a_key_created_concurrently(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The in-place fallback is exclusive too: it never clobbers a key."""
        authority = CertificateAuthority(tmp_path / "data" / "ca")
        theirs = _key_pem()

        def other_process_first_and_no_hard_links(src, dst, **kwargs):
            Path(dst).write_bytes(theirs)
            raise OSError(errno.EPERM, "Operation not permitted")

        monkeypatch.setattr(ca_mod.os, "link", other_process_first_and_no_hard_links)
        with pytest.raises(ca_mod.CAStateError, match="appeared"):
            authority.ensure_ca()
        assert authority.key_path.read_bytes() == theirs
        assert not (authority._dir / "ca.crt").exists()
        assert sorted(p.name for p in authority.key_path.parent.iterdir()) == ["ca.key"]

    def test_a_planted_symlink_at_the_temp_name_is_not_followed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The key's temp file is created exclusively, without following links."""
        authority = CertificateAuthority(tmp_path / "data" / "ca")
        authority.key_path.parent.mkdir(parents=True)
        victim = tmp_path / "victim.txt"
        victim.write_bytes(b"original")
        real_urandom = os.urandom
        monkeypatch.setattr(
            ca_mod.os, "urandom", lambda n: b"\xab" * 8 if n == 8 else real_urandom(n)
        )
        planted = authority.key_path.with_name(f".ca.key.{'ab' * 8}.tmp")
        planted.symlink_to(victim)

        # Not reported as a key that "appeared": nothing is at ca.key.
        with pytest.raises(FileExistsError):
            authority.ensure_ca()
        assert victim.read_bytes() == b"original"
        assert planted.is_symlink()
        assert not authority.key_path.exists() and not authority.key_path.is_symlink()
        assert not (authority._dir / "ca.crt").exists()

    def test_matches_cert(self, ca: CertificateAuthority, tmp_path: Path) -> None:
        assert ca._matches_cert(ca.key_path.read_bytes()) is True
        assert ca._matches_cert(_key_pem()) is False
        assert ca._matches_cert(b"-----BEGIN PRIVATE KEY-----\ngarbage\n") is False
        no_cert = CertificateAuthority(
            tmp_path / "empty" / "ca", key_dir=tmp_path / "empty" / "keys"
        )
        assert no_cert._matches_cert(ca.key_path.read_bytes()) is False

    def test_a_corrupt_legacy_key_never_replaces_the_ca_key(
        self, ca: CertificateAuthority
    ) -> None:
        good = ca.key_path.read_bytes()
        legacy = ca._dir / "ca.key"
        legacy.write_bytes(b"-----BEGIN PRIVATE KEY-----\nnot a key\n")

        reopened = CertificateAuthority(ca._dir)

        assert reopened.key_path.read_bytes() == good
        assert not legacy.exists()
        set_aside = list(reopened.key_path.parent.glob("ca.legacy.*.key"))
        assert len(set_aside) == 1 and _mode(set_aside[0]) == 0o600
        leaf = _cert(reopened.issue_cert(identity="edge", role="node")["cert_pem"])
        assert leaf.verify_directly_issued_by(_cert(reopened.ca_cert_pem)) is None

    def test_rebootstrap_keeps_existing_revocations(
        self, ca: CertificateAuthority
    ) -> None:
        """Losing ca.crt/ca.key must not also drop the revocation records."""
        serial = ca.sign_csr(_csr(), identity="gone", role="node")["serial"]
        assert ca.revoke(serial)
        old_root = ca.ca_cert_pem
        (ca._dir / "ca.crt").unlink()
        ca.key_path.unlink()

        ca.ensure_ca()

        assert ca.ca_cert_pem != old_root
        assert ca.get_cert(serial)["revoked"] is True
        crl = x509.load_pem_x509_crl(ca.generate_crl())
        assert crl.is_signature_valid(_cert(ca.ca_cert_pem).public_key())
        assert int(serial) in {r.serial_number for r in crl}


# ---------------------------------------------------------------------------
# File permissions and atomic writes
# ---------------------------------------------------------------------------


class TestFilePermissions:
    @pytest.mark.parametrize("umask", [0o000, 0o077])
    def test_modes_do_not_depend_on_the_umask(self, tmp_path: Path, umask: int) -> None:
        old = os.umask(umask)
        try:
            authority = CertificateAuthority(tmp_path / "data" / "ca")
            authority.ensure_ca()
            serial = authority.issue_cert(identity="edge", role="node")["serial"]
            authority.revoke(serial)
        finally:
            os.umask(old)
        assert _mode(authority.key_path) == 0o600
        assert _mode(authority.key_path.parent) == 0o700
        assert _mode(authority._dir / "registry.json") == 0o600
        # The gateway must be able to read the CA cert whatever the umask.
        assert _mode(authority._dir / "ca.crt") == 0o644

    def test_a_loose_existing_key_and_key_dir_are_tightened(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """E.g. restored from a backup, or copied in, with the default mode."""
        authority = CertificateAuthority(tmp_path / "data" / "ca")
        authority.ensure_ca()
        key = authority.key_path.read_bytes()
        authority.key_path.chmod(0o644)
        authority.key_path.parent.chmod(0o755)
        (tmp_path / "secrets").chmod(0o755)

        with caplog.at_level(logging.WARNING, logger="sigrift.bridge.ca"):
            reopened = CertificateAuthority(authority._dir)

        assert _mode(reopened.key_path) == 0o600
        assert _mode(reopened.key_path.parent) == 0o700
        assert reopened.key_path.read_bytes() == key
        # Not the CA's to change: the secrets dir itself, the gateway's files.
        assert _mode(tmp_path / "secrets") == 0o755
        assert _mode(reopened._dir / "ca.crt") == 0o644
        messages = [r.getMessage() for r in caplog.records]
        assert any(
            str(reopened.key_path) in m and "0644" in m and "0600" in m
            for m in messages
        )
        text = "\n".join(messages)
        assert "PRIVATE KEY" not in text
        assert key.splitlines()[1].decode() not in text

    def test_tightening_never_adds_permission_bits(self, tmp_path: Path) -> None:
        """Bits outside 0600/0700 go; a read-only key or dir stays read-only."""
        authority = CertificateAuthority(tmp_path / "data" / "ca")
        authority.ensure_ca()
        key_dir = authority.key_path.parent
        authority.key_path.chmod(0o444)
        key_dir.chmod(0o555)
        try:
            CertificateAuthority(authority._dir)
            assert _mode(authority.key_path) == 0o400
            assert _mode(key_dir) == 0o500
        finally:
            key_dir.chmod(0o700)

    @pytest.mark.parametrize("kind", ["directory", "fifo"])
    def test_only_a_regular_key_file_is_tightened(
        self, tmp_path: Path, kind: str
    ) -> None:
        """Something else at ca.key is not the CA's key: its mode is left alone."""
        key_path = tmp_path / "secrets" / "ca" / "ca.key"
        key_path.parent.mkdir(parents=True, mode=0o700)
        if kind == "directory":
            key_path.mkdir()
            key_path.chmod(0o755)
        else:
            os.mkfifo(key_path)
            key_path.chmod(0o644)
        before = _mode(key_path)

        authority = CertificateAuthority(tmp_path / "data" / "ca")

        assert authority.key_path == key_path
        assert _mode(key_path) == before

    def test_a_precreated_loose_key_dir_is_tightened_on_bootstrap(
        self, tmp_path: Path
    ) -> None:
        key_dir = tmp_path / "secrets" / "ca"
        key_dir.mkdir(parents=True)
        key_dir.chmod(0o755)
        authority = CertificateAuthority(tmp_path / "data" / "ca")
        authority.ensure_ca()
        assert authority.key_path.parent == key_dir
        assert _mode(key_dir) == 0o700
        assert _mode(authority.key_path) == 0o600

    def test_a_key_kept_in_the_ca_dir_is_tightened_but_not_the_ca_dir(
        self, tmp_path: Path
    ) -> None:
        """The legacy/ephemeral fall-back: the gateway still reads data/ca."""
        ca_dir = tmp_path / "data" / "ca"
        authority = CertificateAuthority(ca_dir, key_dir=ca_dir)
        authority.ensure_ca()
        ca_dir.chmod(0o755)
        authority.key_path.chmod(0o640)

        reopened = CertificateAuthority(ca_dir, key_dir=ca_dir)

        assert reopened.key_path == ca_dir / "ca.key"
        assert _mode(reopened.key_path) == 0o600
        assert _mode(ca_dir) == 0o755

    def test_the_ca_dir_is_never_tightened_under_another_spelling(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ca_dir = tmp_path / "data" / "ca"
        CertificateAuthority(ca_dir).ensure_ca()
        ca_dir.chmod(0o755)
        (tmp_path / "data").chmod(0o755)
        monkeypatch.chdir(tmp_path)

        CertificateAuthority(ca_dir, key_dir=Path("data") / "ca")
        CertificateAuthority(ca_dir / "sub" / "..", key_dir=ca_dir)
        CertificateAuthority(ca_dir, key_dir=tmp_path / "data")  # holds the CA dir

        assert _mode(ca_dir) == 0o755
        assert _mode(tmp_path / "data") == 0o755

    def test_symlinks_are_not_followed_when_tightening(self, tmp_path: Path) -> None:
        authority = CertificateAuthority(tmp_path / "data" / "ca")
        authority.ensure_ca()
        target = tmp_path / "elsewhere.key"
        target.write_bytes(authority.key_path.read_bytes())
        target.chmod(0o644)
        authority.key_path.unlink()
        authority.key_path.symlink_to(target)
        shared = tmp_path / "shared"
        shared.mkdir()
        shared.chmod(0o755)
        (tmp_path / "linked-keys").symlink_to(shared)

        CertificateAuthority(tmp_path / "data" / "ca")
        CertificateAuthority(tmp_path / "data" / "ca", key_dir=tmp_path / "linked-keys")

        assert _mode(target) == 0o644
        assert _mode(shared) == 0o755

    def test_a_key_that_cannot_be_tightened_is_logged_not_raised(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """E.g. a root-owned restored key in a bridge running as uid 1500."""
        authority = CertificateAuthority(tmp_path / "data" / "ca")
        authority.ensure_ca()
        authority.key_path.chmod(0o644)

        def refuse(fd: int, mode: int) -> None:
            raise PermissionError(errno.EPERM, "Operation not permitted")

        with monkeypatch.context() as patch, caplog.at_level(logging.WARNING):
            patch.setattr(ca_mod.os, "fchmod", refuse)
            reopened = CertificateAuthority(authority._dir)
            reopened.ensure_ca()
        assert _mode(reopened.key_path) == 0o644
        assert any("could not be restricted" in r.getMessage() for r in caplog.records)
        leaf = _cert(reopened.issue_cert(identity="edge", role="node")["cert_pem"])
        assert leaf.verify_directly_issued_by(_cert(reopened.ca_cert_pem)) is None

    def test_planted_temp_symlinks_are_not_followed(self, tmp_path: Path) -> None:
        ca_dir = tmp_path / "data" / "ca"
        key_dir = tmp_path / "secrets" / "ca"
        ca_dir.mkdir(parents=True)
        key_dir.mkdir(parents=True)
        victim = tmp_path / "victim.txt"
        victim.write_bytes(b"original")
        for planted in (
            key_dir / "ca.key.tmp",
            ca_dir / "ca.crt.tmp",
            ca_dir / "registry.json.tmp",
        ):
            planted.symlink_to(victim)

        authority = CertificateAuthority(ca_dir)
        authority.ensure_ca()

        assert victim.read_bytes() == b"original"
        assert not authority.key_path.is_symlink()
        assert authority.key_path.read_bytes().startswith(b"-----BEGIN PRIVATE KEY")
        assert _mode(authority.key_path) == 0o600
        assert not any(
            p.name.endswith(".tmp") for p in (*ca_dir.iterdir(), *key_dir.iterdir())
        )

    def test_a_stale_temp_copy_of_the_key_is_removed_on_start_up(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Left by a start-up killed between writing and removing it."""
        authority = CertificateAuthority(tmp_path / "data" / "ca")
        authority.ensure_ca()
        key = authority.key_path.read_bytes()
        key_dir = authority.key_path.parent
        old = time.time() - 3600
        stale = key_dir / f".ca.key.{'1' * 16}.tmp"
        stale.write_bytes(key)
        os.utime(stale, (old, old))
        # A bootstrap running right now in another process keeps its own.
        fresh = key_dir / f".ca.key.{'2' * 16}.tmp"
        fresh.write_bytes(key)
        # Never followed or removed: a symlink, a directory, another name.
        victim = tmp_path / "victim.txt"
        victim.write_bytes(b"original")
        os.utime(victim, (old, old))
        linked = key_dir / f".ca.key.{'3' * 16}.tmp"
        linked.symlink_to(victim)
        os.utime(linked, (old, old), follow_symlinks=False)
        a_dir = key_dir / f".ca.key.{'4' * 16}.tmp"
        a_dir.mkdir()
        os.utime(a_dir, (old, old))
        other = key_dir / ".ca.key.notours.tmp"
        other.write_bytes(b"x")
        os.utime(other, (old, old))

        with caplog.at_level(logging.WARNING, logger="sigrift.bridge.ca"):
            CertificateAuthority(authority._dir)

        assert not stale.exists()
        assert fresh.read_bytes() == key
        assert linked.is_symlink() and victim.read_bytes() == b"original"
        assert a_dir.is_dir() and other.exists()
        assert authority.key_path.read_bytes() == key
        text = "\n".join(r.getMessage() for r in caplog.records)
        assert str(stale) in text
        assert "PRIVATE KEY" not in text

    @pytest.mark.skipif(
        hasattr(os, "geteuid") and os.geteuid() == 0,
        reason="root ignores directory permissions",
    )
    def test_an_unwritable_secrets_dir_keeps_the_key_where_it_is(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A real EACCES on the move (not EXDEV) never loses the CA key."""
        data = tmp_path / "data"
        legacy = CertificateAuthority(data / "ca", key_dir=data / "ca")
        legacy.ensure_ca()
        key = legacy.key_path.read_bytes()
        key_dir = tmp_path / "secrets" / "ca"
        key_dir.mkdir(parents=True)
        key_dir.chmod(0o500)
        try:
            with caplog.at_level(logging.ERROR, logger="sigrift.bridge.ca"):
                authority = CertificateAuthority(data / "ca")
        finally:
            key_dir.chmod(0o700)

        assert authority.key_path == data / "ca" / "ca.key"
        assert authority.key_path.read_bytes() == key
        assert not (key_dir / "ca.key").exists()
        assert any("Could not move" in r.getMessage() for r in caplog.records)
        leaf = _cert(authority.issue_cert(identity="edge", role="node")["cert_pem"])
        assert leaf.verify_directly_issued_by(_cert(authority.ca_cert_pem)) is None

    def test_unused_name_skips_existing_files_and_symlinks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _Frozen(datetime):
            @classmethod
            def now(cls, tz=None):  # noqa: ANN001
                return datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

        monkeypatch.setattr(ca_mod, "datetime", _Frozen)
        first = ca_mod._unused_name(tmp_path, "legacy")
        assert first == tmp_path / "ca.legacy.20260102T030405Z.key"
        first.write_bytes(b"taken")
        # A dangling symlink is "taken" too: never write through it.
        (tmp_path / "ca.legacy.20260102T030405Z.1.key").symlink_to(tmp_path / "nowhere")
        third = ca_mod._unused_name(tmp_path, "legacy")
        assert third == tmp_path / "ca.legacy.20260102T030405Z.2.key"
        assert third.suffix == ".key"


# ---------------------------------------------------------------------------
# Registry integrity
# ---------------------------------------------------------------------------


class TestRegistry:
    @staticmethod
    def _assert_refused_and_untouched(
        ca: CertificateAuthority, why: str, *, operations: tuple = ()
    ) -> None:
        """Every registry operation refuses; the file is never written."""
        registry = ca._dir / "registry.json"
        before = registry.lstat()
        readable = registry.exists() and os.access(registry, os.R_OK)
        content = registry.read_bytes() if readable else None
        for operation in operations or (
            ca.list_certs,
            lambda: ca.get_cert("1"),
            lambda: ca.revoke("1"),
            ca.generate_crl,
            lambda: ca.issue_cert(identity="next", role="node"),
            lambda: ca.sign_csr(_csr(), identity="next", role="node"),
        ):
            with pytest.raises(ca_mod.CAStateError, match=why) as exc:
                operation()
            assert "restore it from a backup" in str(exc.value)
        after = registry.lstat()
        assert (after.st_ino, after.st_mtime_ns) == (before.st_ino, before.st_mtime_ns)
        if content is not None:
            assert registry.read_bytes() == content
        assert [p.name for p in ca._dir.iterdir() if p.name.endswith(".tmp")] == []

    def test_a_corrupt_registry_is_refused_not_reset(
        self, ca: CertificateAuthority
    ) -> None:
        """A reset would drop the revocation and every issued cert's record."""
        kept = ca.sign_csr(_csr(), identity="edge", role="node")["serial"]
        revoked = ca.sign_csr(_csr(), identity="gone", role="node")["serial"]
        ca.revoke(revoked)
        registry = ca._dir / "registry.json"
        good = registry.read_text(encoding="utf-8")
        registry.write_text(good.rstrip()[:-1] + ",}", encoding="utf-8")

        self._assert_refused_and_untouched(ca, "is not valid JSON")
        # Repairing the file brings everything back, revocation included.
        registry.write_text(good, encoding="utf-8")
        assert {r["serial"] for r in ca.list_certs()} == {kept, revoked}
        crl = x509.load_pem_x509_crl(ca.generate_crl())
        assert {r.serial_number for r in crl} == {int(revoked)}

    @pytest.mark.parametrize(
        "content",
        [
            [],
            {"other": {}},
            "issued",
            {},
            {"issued": []},
            {"issued": "x"},
            {"issued": None},
            {"issued": {"1": "x"}},
            {"issued": {"1": {}, "2": None}},
            # Keys must be canonical decimal serials a certificate can carry.
            {"issued": {"abc": {}}},
            {"issued": {"0x1f": {}}},
            {"issued": {"01": {}}},
            {"issued": {"0": {}}},
            {"issued": {"-1": {}}},
            {"issued": {"+1": {}}},
            {"issued": {" 1": {}}},
            {"issued": {"1.0": {}}},
            {"issued": {"\u0661": {}}},  # ARABIC-INDIC DIGIT ONE: isdigit() is true
            {"issued": {str(2**159): {}}},
            {"issued": {"9" * 5000: {}}},  # beyond int()'s default digit limit
            # The fields the CA reads must have the right type.
            {"issued": {"1": {"revoked": "yes"}}},
            {"issued": {"1": {"revoked": 1}}},
            {"issued": {"1": {"revoked": None}}},
            {"issued": {"1": {"revoked": True, "revoked_at": 5}}},
            {"issued": {"1": {"issued_at": 5}}},
            {"issued": {"1": {"not_after": []}}},
        ],
    )
    def test_a_registry_of_the_wrong_shape_is_refused(
        self, ca: CertificateAuthority, content: object
    ) -> None:
        (ca._dir / "registry.json").write_text(json.dumps(content), encoding="utf-8")
        self._assert_refused_and_untouched(ca, "is not a CA registry")

    def test_a_registry_that_is_not_utf8_is_refused(
        self, ca: CertificateAuthority
    ) -> None:
        (ca._dir / "registry.json").write_bytes(b'{"issued": {"\xff": {}}}')
        self._assert_refused_and_untouched(ca, "is not valid JSON")

    @pytest.mark.skipif(
        hasattr(os, "geteuid") and os.geteuid() == 0,
        reason="root ignores file permissions",
    )
    def test_an_unreadable_registry_is_refused_not_reset(
        self, ca: CertificateAuthority
    ) -> None:
        """E.g. restored with the wrong owner; the CA dir is still writable."""
        for i in range(3):
            ca.issue_cert(identity=f"n{i}", role="node")
        registry = ca._dir / "registry.json"
        registry.chmod(0o000)
        try:
            self._assert_refused_and_untouched(
                ca,
                "cannot be read",
                operations=(
                    ca.list_certs,
                    lambda: ca.revoke("1"),
                    ca.generate_crl,
                    lambda: ca.issue_cert(identity="next", role="node"),
                ),
            )
        finally:
            registry.chmod(0o600)
        assert len(ca.list_certs()) == 3

    def test_a_registry_that_is_a_dangling_symlink_is_refused(
        self, ca: CertificateAuthority, tmp_path: Path
    ) -> None:
        registry = ca._dir / "registry.json"
        registry.unlink()
        registry.symlink_to(tmp_path / "unmounted" / "registry.json")
        self._assert_refused_and_untouched(ca, "dangling symlink")
        assert registry.is_symlink()

    def test_wrong_registry_entries_are_named_without_echoing_much(
        self, ca: CertificateAuthority
    ) -> None:
        _write_registry(ca, {"issued": {"12": {"revoked": "yes"}}})
        with pytest.raises(ca_mod.CAStateError, match="'12' has a 'revoked'"):
            ca.list_certs()
        _write_registry(ca, {"issued": {"x" * 5000 + "\nforged log line": {}}})
        with pytest.raises(ca_mod.CAStateError) as exc:
            ca.list_certs()
        assert "\n" not in str(exc.value) and len(str(exc.value)) < 1000

    def test_a_registry_with_null_or_missing_fields_is_still_usable(
        self, ca: CertificateAuthority
    ) -> None:
        """null and missing are how a hand-edited entry says 'unknown'."""
        serial = ca.issue_cert(identity="edge", role="node")["serial"]
        data = _registry(ca)
        data["issued"]["7"] = {"identity": "old", "issued_at": None, "revoked": True}
        data["issued"]["8"] = {"identity": "older"}
        _write_registry(ca, data)
        assert [r["serial"] for r in ca.list_certs()] == [serial, "7", "8"]
        crl = x509.load_pem_x509_crl(ca.generate_crl())
        assert {r.serial_number for r in crl} == {7}

    def test_only_a_missing_registry_is_empty(self, ca: CertificateAuthority) -> None:
        (ca._dir / "registry.json").unlink()
        assert ca.list_certs() == []
        assert ca.get_cert("1") is None
        assert ca.revoke("1") is False
        assert len(x509.load_pem_x509_crl(ca.generate_crl())) == 0
        serial = ca.issue_cert(identity="edge", role="node")["serial"]
        assert list(_registry(ca)["issued"]) == [serial]
        assert _mode(ca._dir / "registry.json") == 0o600

    def test_nothing_is_signed_before_the_registry_is_read(
        self, ca: CertificateAuthority, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (ca._dir / "registry.json").write_text("{not json", encoding="utf-8")
        signed: list[object] = []
        real_sign = x509.CertificateBuilder.sign

        def spy(builder, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
            signed.append(builder)
            return real_sign(builder, *args, **kwargs)

        monkeypatch.setattr(x509.CertificateBuilder, "sign", spy)
        with pytest.raises(ca_mod.CAStateError):
            ca.issue_cert(identity="edge", role="node")
        assert signed == []

    def test_registry_never_holds_private_keys(self, ca: CertificateAuthority) -> None:
        issued = ca.issue_cert(identity="edge", role="node")
        ca.sign_csr(_csr(), identity="other", role="node")
        raw = (ca._dir / "registry.json").read_text(encoding="utf-8")
        assert "PRIVATE KEY" not in raw
        assert issued["key_pem"].splitlines()[1] not in raw
        for row in ca.list_certs():
            assert "key_pem" not in row and "cert_pem" not in row
        assert "key_pem" not in ca.get_cert(issued["serial"])

    def test_private_keys_are_never_logged(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        data = tmp_path / "data"
        with caplog.at_level(logging.DEBUG):
            legacy = CertificateAuthority(data / "ca", key_dir=data / "ca")
            legacy.ensure_ca()
            ca_key = legacy.key_path.read_bytes()
            authority = CertificateAuthority(data / "ca")  # moves the key
            issued = authority.issue_cert(identity="edge", role="node")
            authority.sign_csr(_csr(), identity="other", role="node")
            authority.revoke(issued["serial"])
            authority.generate_crl()
        text = "\n".join(r.getMessage() for r in caplog.records)
        assert "Moved the CA private key" in text  # the run was logged ...
        assert "PRIVATE KEY" not in text  # ... but no key material
        for pem in (ca_key.decode(), issued["key_pem"]):
            for line in pem.splitlines()[1:-1]:
                assert line not in text

    def test_concurrent_issuance_and_revocation_lose_no_entries(
        self, ca: CertificateAuthority
    ) -> None:
        with ThreadPoolExecutor(max_workers=8) as pool:
            serials = list(
                pool.map(
                    lambda i: ca.issue_cert(identity=f"n{i}", role="node")["serial"],
                    range(8),
                )
            )
            assert all(pool.map(ca.revoke, serials))
        rows = ca.list_certs()
        assert sorted(r["serial"] for r in rows) == sorted(serials)
        assert all(r["revoked"] for r in rows)
        crl = x509.load_pem_x509_crl(ca.generate_crl())
        assert {r.serial_number for r in crl} == {int(s) for s in serials}


# ---------------------------------------------------------------------------
# Revocation and CRL
# ---------------------------------------------------------------------------


class TestCrl:
    def test_crl_tolerates_bad_revocation_dates(self, ca: CertificateAuthority) -> None:
        a = ca.sign_csr(_csr(), identity="a", role="node")["serial"]
        b = ca.sign_csr(_csr(), identity="b", role="node")["serial"]
        data = _registry(ca)
        data["issued"][a].update(revoked=True, revoked_at="not a date")
        data["issued"][b].update(revoked=True, revoked_at=None)
        _write_registry(ca, data)

        before = datetime.now(timezone.utc).replace(microsecond=0)
        crl = x509.load_pem_x509_crl(ca.generate_crl())

        assert crl.is_signature_valid(_cert(ca.ca_cert_pem).public_key())
        entries = {r.serial_number: r for r in crl}
        assert set(entries) == {int(a), int(b)}
        for entry in entries.values():
            assert entry.revocation_date_utc >= before - timedelta(seconds=1)

    def test_crl_revocation_dates_a_crl_cannot_hold_fall_back_to_now(
        self, ca: CertificateAuthority
    ) -> None:
        """Before 1950 a CRL cannot express the date; a naive one means UTC."""
        early = ca.sign_csr(_csr(), identity="a", role="node")["serial"]
        naive = ca.sign_csr(_csr(), identity="b", role="node")["serial"]
        data = _registry(ca)
        data["issued"][early].update(revoked=True, revoked_at="1900-01-01T00:00:00")
        data["issued"][naive].update(revoked=True, revoked_at="2026-01-02T03:04:05")
        _write_registry(ca, data)

        before = datetime.now(timezone.utc).replace(microsecond=0)
        crl = x509.load_pem_x509_crl(ca.generate_crl())

        entries = {r.serial_number: r.revocation_date_utc for r in crl}
        assert entries[int(early)] >= before - timedelta(seconds=1)
        assert entries[int(naive)] == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

    def test_crl_is_signed_by_this_ca_with_a_bounded_lifetime(
        self, ca: CertificateAuthority, tmp_path: Path
    ) -> None:
        crl = x509.load_pem_x509_crl(ca.generate_crl())
        root = _cert(ca.ca_cert_pem)
        assert crl.issuer == root.subject
        assert crl.is_signature_valid(root.public_key())
        other = _separate_ca(tmp_path / "other")
        other.ensure_ca()
        assert not crl.is_signature_valid(_cert(other.ca_cert_pem).public_key())
        assert crl.next_update_utc - crl.last_update_utc == timedelta(days=7, minutes=5)

    @pytest.mark.parametrize("variant", ["leading_zero", "hex", "plus", "space"])
    def test_revoke_needs_the_exact_registry_serial(
        self, ca: CertificateAuthority, variant: str
    ) -> None:
        serial = ca.sign_csr(_csr(), identity="edge", role="node")["serial"]
        other = {
            "leading_zero": "0" + serial,
            "hex": hex(int(serial)),
            "plus": "+" + serial,
            "space": f" {serial}",
        }[variant]
        assert ca.revoke(other) is False
        assert ca.get_cert(serial)["revoked"] is False
        assert len(x509.load_pem_x509_crl(ca.generate_crl())) == 0


# ---------------------------------------------------------------------------
# migrate-key command line, in-process
# ---------------------------------------------------------------------------


class TestMigrateKeyCommand:
    """``_main`` run in-process (the subprocess tests cannot be measured).

    Its ``logging.basicConfig`` is a no-op here: pytest's handlers are
    already on the root logger.
    """

    def test_moves_a_legacy_key_and_reports_where_it_is(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        data = tmp_path / "data"
        legacy = CertificateAuthority(data / "ca", key_dir=data / "ca")
        legacy.ensure_ca()
        key = legacy.key_path.read_bytes()

        with caplog.at_level(logging.INFO, logger="sigrift.bridge.ca"):
            rc = ca_mod._main(["migrate-key", "--data-dir", str(data)])

        assert rc == 0
        moved = tmp_path / "secrets" / "ca" / "ca.key"
        assert moved.read_bytes() == key and _mode(moved) == 0o600
        assert not (data / "ca" / "ca.key").exists()
        messages = [r.getMessage() for r in caplog.records]
        assert f"CA private key: {moved}" in messages

    def test_no_ca_is_a_quiet_no_op(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.INFO, logger="sigrift.bridge.ca"):
            rc = ca_mod._main(["migrate-key", "--data-dir", str(tmp_path / "data")])
        assert rc == 0
        assert not (tmp_path / "secrets").exists()
        assert not any("CA private key:" in r.getMessage() for r in caplog.records)

    def test_a_command_is_required(self) -> None:
        with pytest.raises(SystemExit) as exc:
            ca_mod._main([])
        assert exc.value.code == 2

    def test_module_entry_point_exits_with_the_command_status(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            ["sigrift.bridge.ca", "migrate-key", "--data-dir", str(tmp_path / "data")],
        )
        with warnings.catch_warnings():
            # runpy warns that the module is already imported; expected here.
            warnings.simplefilter("ignore", RuntimeWarning)
            with pytest.raises(SystemExit) as exc:
                runpy.run_module("sigrift.bridge.ca", run_name="__main__")
        assert exc.value.code == 0
