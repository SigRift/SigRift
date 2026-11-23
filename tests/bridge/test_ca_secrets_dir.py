"""The CA private key lives outside the data dir the gateway mounts (K6).

The gateway mounts the bridge data volume (it needs detections.db,
keys.json and the CA certificate/registry), so the CA private key moves
to the bridge's secrets directory (``BRIDGE_SECRETS_DIR``, a volume only
the bridge mounts). A key an earlier version left in ``data/ca/`` is
moved — not copied — the first time the CA is opened, and by
``python3 -m sigrift.bridge.ca migrate-key`` at container start-up.
"""

from __future__ import annotations

import errno
import importlib.util
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from sigrift.bridge import ca as ca_mod
from sigrift.bridge.ca import CertificateAuthority, secrets_dir

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _no_secrets_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BRIDGE_SECRETS_DIR", raising=False)


def _old_layout_ca(data_dir: Path) -> bytes:
    """A CA as earlier versions wrote it: key next to the cert. Returns the key."""
    old = CertificateAuthority(data_dir / "ca", key_dir=data_dir / "ca")
    old.ensure_ca()
    key = (data_dir / "ca" / "ca.key").read_bytes()
    assert key.startswith(b"-----BEGIN PRIVATE KEY-----")
    return key


def _other_key_pem() -> bytes:
    return ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _csr() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )


def _assert_signs_for_its_cert(ca: CertificateAuthority) -> None:
    leaf = x509.load_pem_x509_certificate(
        ca.sign_csr(_csr(), identity="node-1", role="node")["cert_pem"].encode()
    )
    root = x509.load_pem_x509_certificate(ca.ca_cert_pem)
    assert leaf.verify_directly_issued_by(root) is None


# ── where the key goes ──────────────────────────────────────────────────


def test_default_secrets_dir_is_next_to_the_data_dir(tmp_path: Path) -> None:
    assert secrets_dir(tmp_path / "data") == tmp_path / "secrets"


def test_secrets_dir_env_wins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BRIDGE_SECRETS_DIR", str(tmp_path / "vault"))
    assert secrets_dir(tmp_path / "data") == tmp_path / "vault"


def test_new_ca_keeps_its_key_out_of_the_data_dir(tmp_path: Path) -> None:
    data = tmp_path / "data"
    ca = CertificateAuthority(data / "ca")
    ca.ensure_ca()
    assert (data / "ca" / "ca.crt").is_file()
    assert not (data / "ca" / "ca.key").exists()
    assert not list(data.rglob("*.key"))
    assert ca.key_path == tmp_path / "secrets" / "ca" / "ca.key"
    assert ca.key_path.stat().st_mode & 0o777 == 0o600
    assert ca.key_path.parent.stat().st_mode & 0o077 == 0
    _assert_signs_for_its_cert(ca)


def test_bridge_secrets_dir_env_places_the_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BRIDGE_SECRETS_DIR", str(tmp_path / "vault"))
    ca = CertificateAuthority(tmp_path / "data" / "ca")
    ca.ensure_ca()
    assert ca.key_path == tmp_path / "vault" / "ca" / "ca.key"
    assert ca.key_path.is_file()


# ── migration of an existing key ────────────────────────────────────────


def test_existing_key_is_moved_not_copied(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    data = tmp_path / "data"
    key = _old_layout_ca(data)
    cert = (data / "ca" / "ca.crt").read_bytes()

    with caplog.at_level(logging.INFO, logger="sigrift.bridge.ca"):
        ca = CertificateAuthority(data / "ca")

    assert not (data / "ca" / "ca.key").exists()
    assert ca.key_path.read_bytes() == key
    assert ca.key_path.stat().st_mode & 0o777 == 0o600
    assert (data / "ca" / "ca.crt").read_bytes() == cert  # cert stays put
    assert any("Moved the CA private key" in r.getMessage() for r in caplog.records)
    # Same CA: is_initialized, no regeneration, still signs for ca.crt.
    assert ca.is_initialized
    ca.ensure_ca()
    assert (data / "ca" / "ca.crt").read_bytes() == cert
    _assert_signs_for_its_cert(ca)


def test_move_works_across_filesystems(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "data"
    key = _old_layout_ca(data)
    real_replace = os.replace

    def replace(src, dst):
        if Path(src) == data / "ca" / "ca.key":
            raise OSError(errno.EXDEV, "Invalid cross-device link")
        return real_replace(src, dst)

    monkeypatch.setattr(ca_mod.os, "replace", replace)
    ca = CertificateAuthority(data / "ca")
    assert not (data / "ca" / "ca.key").exists()
    assert ca.key_path.read_bytes() == key
    assert ca.key_path.stat().st_mode & 0o777 == 0o600


def test_a_failed_move_keeps_using_the_key_where_it_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    data = tmp_path / "data"
    key = _old_layout_ca(data)

    def refuse(src, dst):
        raise PermissionError(errno.EACCES, "Permission denied", str(dst))

    monkeypatch.setattr(ca_mod, "_move_private_file", refuse)
    with caplog.at_level(logging.ERROR, logger="sigrift.bridge.ca"):
        ca = CertificateAuthority(data / "ca")
    assert ca.key_path == data / "ca" / "ca.key"
    assert ca.key_path.read_bytes() == key
    assert any("Could not move" in r.getMessage() for r in caplog.records)
    _assert_signs_for_its_cert(ca)


def test_identical_leftover_copy_is_removed(tmp_path: Path) -> None:
    data = tmp_path / "data"
    key = _old_layout_ca(data)
    ca = CertificateAuthority(data / "ca")  # moves it
    (data / "ca" / "ca.key").write_bytes(key)  # e.g. restored from a backup
    CertificateAuthority(data / "ca")
    assert not (data / "ca" / "ca.key").exists()
    assert ca.key_path.read_bytes() == key


def test_conflicting_keys_keep_the_one_matching_the_cert(tmp_path: Path) -> None:
    data = tmp_path / "data"
    key = _old_layout_ca(data)
    key_dir = tmp_path / "secrets" / "ca"
    key_dir.mkdir(parents=True)
    stray = _other_key_pem()
    (key_dir / "ca.key").write_bytes(stray)

    ca = CertificateAuthority(data / "ca")

    assert not (data / "ca" / "ca.key").exists()
    assert ca.key_path.read_bytes() == key  # the one that belongs to ca.crt
    kept = [p for p in key_dir.iterdir() if p.name.startswith("ca.replaced.")]
    # It keeps the .key suffix, so the *.key ignore rules cover it (Q21).
    assert [p.suffix for p in kept] == [".key"]
    assert len(kept) == 1 and kept[0].read_bytes() == stray
    _assert_signs_for_its_cert(ca)


def test_a_stale_legacy_key_leaves_the_data_dir(tmp_path: Path) -> None:
    data = tmp_path / "data"
    ca = CertificateAuthority(data / "ca")
    ca.ensure_ca()
    current = ca.key_path.read_bytes()
    stale = _other_key_pem()
    (data / "ca" / "ca.key").write_bytes(stale)

    CertificateAuthority(data / "ca")

    assert not (data / "ca" / "ca.key").exists()
    assert ca.key_path.read_bytes() == current
    moved = [p for p in ca.key_path.parent.iterdir() if p.name.startswith("ca.legacy.")]
    assert [p.suffix for p in moved] == [".key"]
    assert len(moved) == 1 and moved[0].read_bytes() == stale


def test_a_key_dir_that_is_the_ca_dir_by_another_name_keeps_the_key(
    tmp_path: Path,
) -> None:
    """A symlinked key dir must not make the one key look like two.

    The key and "legacy" paths spell the same file, so the migration's
    same-bytes branch used to unlink it: the only CA private key was gone.
    """
    data = tmp_path / "data"
    key = _old_layout_ca(data)
    alias = tmp_path / "secrets-ca"
    alias.symlink_to(data / "ca", target_is_directory=True)

    reopened = CertificateAuthority(data / "ca", key_dir=alias)

    assert (data / "ca" / "ca.key").read_bytes() == key
    assert reopened.key_path.read_bytes() == key
    leaf = reopened.issue_cert(identity="edge", role="node")["cert_pem"].encode()
    issuer = x509.load_pem_x509_certificate(reopened.ca_cert_pem)
    x509.load_pem_x509_certificate(leaf).verify_directly_issued_by(issuer)


def test_a_key_path_symlinked_to_the_legacy_key_keeps_the_key(tmp_path: Path) -> None:
    data = tmp_path / "data"
    key = _old_layout_ca(data)
    key_dir = tmp_path / "secrets" / "ca"
    key_dir.mkdir(parents=True, mode=0o700)
    (key_dir / "ca.key").symlink_to(data / "ca" / "ca.key")

    CertificateAuthority(data / "ca", key_dir=key_dir)

    assert (data / "ca" / "ca.key").read_bytes() == key


def test_a_hard_linked_legacy_key_leaves_the_data_dir(tmp_path: Path) -> None:
    data = tmp_path / "data"
    key = _old_layout_ca(data)
    key_dir = tmp_path / "secrets" / "ca"
    key_dir.mkdir(parents=True, mode=0o700)
    os.link(data / "ca" / "ca.key", key_dir / "ca.key")

    CertificateAuthority(data / "ca", key_dir=key_dir)

    assert not (data / "ca" / "ca.key").exists()
    assert (key_dir / "ca.key").read_bytes() == key


def test_set_aside_key_names_are_git_ignored() -> None:
    """A set-aside CA key in a checkout's secrets dir is never committed (Q21).

    For a from-source bridge the default secrets dir is inside the git
    checkout; whatever ``_unused_name`` picks there (or in a secrets dir
    elsewhere in the checkout) must be ignored.
    """
    inside = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
    )
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        pytest.skip("not a git work tree")
    default_dir = secrets_dir(ROOT / "src" / "sigrift" / "bridge" / "data") / "ca"
    names = [
        ca_mod._unused_name(directory, kind)
        for directory in (default_dir, ROOT / "secrets" / "ca")
        for kind in ("replaced", "legacy")
    ]
    r = subprocess.run(
        ["git", "-C", str(ROOT), "check-ignore", "--no-index", *map(str, names)],
        capture_output=True,
        text=True,
    )
    assert sorted(r.stdout.split()) == sorted(map(str, names)), r.stderr


def test_a_symlinked_legacy_key_is_not_followed(tmp_path: Path) -> None:
    data = tmp_path / "data"
    (data / "ca").mkdir(parents=True)
    target = tmp_path / "elsewhere.pem"
    target.write_bytes(_other_key_pem())
    (data / "ca" / "ca.key").symlink_to(target)

    ca = CertificateAuthority(data / "ca")

    assert (data / "ca" / "ca.key").is_symlink()
    assert not ca.key_path.exists()


def test_key_stays_when_the_secrets_dir_is_not_a_volume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Old compose file: data is a volume, /app/secrets is not → keep the key."""
    data = tmp_path / "data"
    key = _old_layout_ca(data)
    devices = {Path("/"): 1, tmp_path / "secrets": 1, data / "ca": 2}

    def st_dev(path: Path) -> int | None:
        for candidate in (path, *path.parents):
            if candidate in devices:
                return devices[candidate]
        return 1

    monkeypatch.setattr(ca_mod, "_st_dev", st_dev)
    with caplog.at_level(logging.WARNING, logger="sigrift.bridge.ca"):
        ca = CertificateAuthority(data / "ca")

    assert ca.key_path == data / "ca" / "ca.key"
    assert ca.key_path.read_bytes() == key
    assert not (tmp_path / "secrets").exists()
    assert any("bridge_secrets" in r.getMessage() for r in caplog.records)
    _assert_signs_for_its_cert(ca)


def test_key_moves_when_the_secrets_dir_is_a_volume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "data"
    _old_layout_ca(data)
    devices = {Path("/"): 1, tmp_path / "secrets": 3, data / "ca": 2}

    def st_dev(path: Path) -> int | None:
        for candidate in (path, *path.parents):
            if candidate in devices:
                return devices[candidate]
        return 1

    monkeypatch.setattr(ca_mod, "_st_dev", st_dev)
    ca = CertificateAuthority(data / "ca")
    assert ca.key_path == tmp_path / "secrets" / "ca" / "ca.key"
    assert not (data / "ca" / "ca.key").exists()


# ── container start-up command and host-side provisioning ───────────────


def test_migrate_key_command(tmp_path: Path) -> None:
    data = tmp_path / "data"
    key = _old_layout_ca(data)
    env = {
        "PATH": os.environ["PATH"],
        "PYTHONPATH": str(ROOT / "src"),
        "BRIDGE_SECRETS_DIR": str(tmp_path / "vault"),
    }
    r = subprocess.run(
        [sys.executable, "-m", "sigrift.bridge.ca", "migrate-key"]
        + ["--data-dir", str(data)],
        capture_output=True,
        text=True,
        env=env,
    )
    assert r.returncode == 0, r.stderr
    assert not (data / "ca" / "ca.key").exists()
    assert (tmp_path / "vault" / "ca" / "ca.key").read_bytes() == key
    assert "Moved the CA private key" in r.stderr


def test_migrate_key_command_without_a_ca_is_a_no_op(tmp_path: Path) -> None:
    env = {
        "PATH": os.environ["PATH"],
        "PYTHONPATH": str(ROOT / "src"),
        "BRIDGE_SECRETS_DIR": str(tmp_path / "vault"),
    }
    r = subprocess.run(
        [sys.executable, "-m", "sigrift.bridge.ca", "migrate-key"]
        + ["--data-dir", str(tmp_path / "data")],
        capture_output=True,
        text=True,
        env=env,
    )
    assert r.returncode == 0, r.stderr
    assert not (tmp_path / "vault").exists()
    assert not (tmp_path / "data").exists()


def test_pki_bootstrap_uses_the_secrets_dir(tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location(
        "pki_bootstrap_k6", ROOT / "scripts" / "pki_bootstrap.py"
    )
    pki_bootstrap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pki_bootstrap)
    data = tmp_path / "data"
    rc = pki_bootstrap.main(
        ["--data-dir", str(data), "--secrets-dir", str(tmp_path / "vault"), "edge-1"]
    )
    assert rc == 0
    assert (data / "ca" / "ca.crt").is_file()
    assert not (data / "ca" / "ca.key").exists()
    assert (tmp_path / "vault" / "ca" / "ca.key").is_file()
