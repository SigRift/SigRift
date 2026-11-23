"""Tests for scripts/pki_bootstrap.py — PKI Phase A cert provisioning."""

from __future__ import annotations

import importlib.util
import os
import runpy
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "pki_bootstrap.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("pki_bootstrap", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pki_bootstrap = _load_script()


@pytest.fixture(autouse=True)
def isolated_secrets(monkeypatch):
    monkeypatch.delenv("BRIDGE_SECRETS_DIR", raising=False)


def _run(data: Path, *identities: str, out: Path | None = None) -> int:
    args = ["--data-dir", str(data)]
    if out is not None:
        args += ["--out-dir", str(out)]
    return pki_bootstrap.main(args + list(identities))


def _snapshot(directory: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in directory.iterdir()}


def _assert_bundle(bundle: Path) -> None:
    assert set(_snapshot(bundle)) == {"client.crt", "client.key", "ca.crt"}
    leaf = x509.load_pem_x509_certificate((bundle / "client.crt").read_bytes())
    ca = x509.load_pem_x509_certificate((bundle / "ca.crt").read_bytes())
    key = serialization.load_pem_private_key(
        (bundle / "client.key").read_bytes(), password=None
    )
    leaf.verify_directly_issued_by(ca)
    assert leaf.public_key().public_numbers() == key.public_key().public_numbers()
    assert stat.S_IMODE((bundle / "client.key").stat().st_mode) == 0o600


def _bundle(out_dir: Path, identity: str) -> Path:
    return out_dir / identity


class TestProvisioning:
    def test_provisions_bundles_for_each_agent(self, tmp_path: Path) -> None:
        data_dir = tmp_path / "data"
        rc = pki_bootstrap.main(
            ["--data-dir", str(data_dir), "local-edge:node", "wifi-scan:node"]
        )
        assert rc == 0

        for identity in ("local-edge", "wifi-scan"):
            bundle = data_dir / "edge_certs" / identity
            assert (bundle / "client.crt").is_file()
            assert (bundle / "client.key").is_file()
            assert (bundle / "ca.crt").is_file()

    def test_issued_cert_chains_to_ca(self, tmp_path: Path) -> None:
        data_dir = tmp_path / "data"
        assert pki_bootstrap.main(["--data-dir", str(data_dir), "scanner-1"]) == 0

        bundle = data_dir / "edge_certs" / "scanner-1"
        leaf = x509.load_pem_x509_certificate((bundle / "client.crt").read_bytes())
        ca = x509.load_pem_x509_certificate((bundle / "ca.crt").read_bytes())
        # Raises on failure, returns None on success.
        assert leaf.verify_directly_issued_by(ca) is None

    def test_key_file_is_private_mode(self, tmp_path: Path) -> None:
        data_dir = tmp_path / "data"
        pki_bootstrap.main(["--data-dir", str(data_dir), "scanner-2"])
        key = data_dir / "edge_certs" / "scanner-2" / "client.key"
        assert key.stat().st_mode & 0o777 == 0o600

    def test_default_role_is_node(self, tmp_path: Path) -> None:
        data_dir = tmp_path / "data"
        pki_bootstrap.main(["--data-dir", str(data_dir), "no-role-given"])
        # The CA registry records the role the cert was issued with.
        from sigrift.bridge.ca import CertificateAuthority

        ca = CertificateAuthority(data_dir / "ca")
        rows = [r for r in ca.list_certs() if r["identity"] == "no-role-given"]
        assert rows and rows[0]["role"] == "node"

    def test_custom_out_dir(self, tmp_path: Path) -> None:
        data_dir = tmp_path / "data"
        out_dir = tmp_path / "elsewhere"
        rc = pki_bootstrap.main(
            ["--data-dir", str(data_dir), "--out-dir", str(out_dir), "edge-x"]
        )
        assert rc == 0
        assert (out_dir / "edge-x" / "client.crt").is_file()

    def test_ca_is_reused_across_runs(self, tmp_path: Path) -> None:
        data_dir = tmp_path / "data"
        pki_bootstrap.main(["--data-dir", str(data_dir), "first"])
        ca_pem_1 = (data_dir / "ca" / "ca.crt").read_bytes()
        pki_bootstrap.main(["--data-dir", str(data_dir), "second"])
        ca_pem_2 = (data_dir / "ca" / "ca.crt").read_bytes()
        # A second run must not regenerate the CA.
        assert ca_pem_1 == ca_pem_2


class TestArgParsing:
    @pytest.mark.parametrize("spec", ["", " :node", ":"])
    def test_empty_identity_rejected(self, tmp_path, spec):
        with pytest.raises(SystemExit) as exc:
            _run(tmp_path / "data", spec)
        assert exc.value.code == 2
        assert not (tmp_path / "data").exists()

    def test_whitespace_and_empty_role(self, tmp_path):
        assert _run(tmp_path / "data", "  node  : ") == 0
        _assert_bundle(tmp_path / "data" / "edge_certs" / "node")

    def test_invalid_role_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit):
            pki_bootstrap.main(["--data-dir", str(tmp_path), "edge:bogus-role"])

    def test_agent_required(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit):
            pki_bootstrap.main(["--data-dir", str(tmp_path)])


class TestSafeProvisioning:
    def test_existing_bundle_is_preserved_and_other_identities_succeed(
        self, tmp_path, capsys, caplog
    ):
        from sigrift.bridge.ca import CertificateAuthority

        data = tmp_path / "data"
        assert _run(data, "existing") == 0
        original = _snapshot(data / "edge_certs" / "existing")
        capsys.readouterr()
        assert _run(data, "before", "existing", "after") == 1
        assert _snapshot(data / "edge_certs" / "existing") == original
        for name in ("before", "existing", "after"):
            _assert_bundle(data / "edge_certs" / name)
        assert [
            line.split("\t")[0] for line in capsys.readouterr().out.splitlines()
        ] == ["before", "after"]
        assert "new --out-dir" in caplog.text
        assert len(CertificateAuthority(data / "ca").list_certs()) == 3

    @pytest.mark.parametrize("destination", ["file", "directory", "link", "dangling"])
    def test_existing_identity_destination_is_never_modified(
        self, tmp_path, destination
    ):
        from sigrift.bridge.ca import CertificateAuthority

        data = tmp_path / "data"
        out = tmp_path / "bundles"
        out.mkdir(mode=0o700)
        target = out / "node"
        victim = tmp_path / "victim"
        victim.mkdir()
        (victim / "sentinel").write_bytes(b"unrelated existing data")
        if destination == "file":
            target.write_bytes(b"existing file")
        elif destination == "directory":
            target.mkdir()
            (target / "client.key").symlink_to(victim / "sentinel")
        else:
            target.symlink_to(victim if destination == "link" else tmp_path / "absent")
        before = target.lstat()
        assert _run(data, "node", out=out) == 1
        assert target.lstat() == before
        assert (victim / "sentinel").read_bytes() == b"unrelated existing data"
        assert _snapshot(victim) == {"sentinel": b"unrelated existing data"}
        assert CertificateAuthority(data / "ca").list_certs() == []

    @pytest.mark.parametrize("mode", [0o777, 0o775, 0o702])
    def test_writable_output_directory_is_refused(self, tmp_path, mode):
        out = tmp_path / "bundles"
        out.mkdir()
        out.chmod(mode)
        try:
            assert _run(tmp_path / "data", "node", out=out) == 1
            assert list(out.iterdir()) == []
            assert stat.S_IMODE(out.stat().st_mode) == mode
        finally:
            out.chmod(0o700)

    def test_symlink_output_directory_is_refused(self, tmp_path):
        victim = tmp_path / "victim"
        victim.mkdir(mode=0o700)
        out = tmp_path / "bundles"
        out.symlink_to(victim, target_is_directory=True)
        assert _run(tmp_path / "data", "node", out=out) == 1
        assert out.is_symlink()
        assert list(victim.iterdir()) == []

    def test_ca_filesystem_failure_is_reported(self, tmp_path, caplog, capsys):
        data = tmp_path / "data"
        data.mkdir()
        (data / "ca").write_bytes(b"existing unrelated file")
        assert _run(data, "node") == 1
        assert (data / "ca").read_bytes() == b"existing unrelated file"
        assert capsys.readouterr().out == ""
        assert "CA bootstrap failed" in caplog.text

    def test_traversal_identity_does_not_prevent_other_bundles(self, tmp_path, capsys):
        data = tmp_path / "data"
        assert _run(data, "first", "../escape", "last") == 1
        assert not (data / "escape").exists()
        assert sorted(p.name for p in (data / "edge_certs").iterdir()) == [
            "first",
            "last",
        ]
        assert [
            line.split("\t")[0] for line in capsys.readouterr().out.splitlines()
        ] == ["first", "last"]

    def test_publish_observes_complete_private_matching_bundle(
        self, tmp_path, monkeypatch
    ):
        original_rename = os.rename
        original_open = os.open
        published = []
        key_created = []

        def observe_creation(path, flags, mode=0o777, *, dir_fd=None):
            fd = original_open(path, flags, mode, dir_fd=dir_fd)
            if path == "client.key":
                info = os.fstat(fd)
                key_created.append((stat.S_IMODE(info.st_mode), info.st_size))
            return fd

        def inspect_then_rename(source, destination, **kwargs):
            # Observe the real filesystem at the publication boundary, without
            # replacing cryptography or the actual rename operation.
            directory = tmp_path / "bundles" / source
            _assert_bundle(directory)
            assert stat.S_IMODE(directory.stat().st_mode) == 0o700
            assert not (tmp_path / "bundles" / destination).exists()
            published.append(destination)
            return original_rename(source, destination, **kwargs)

        monkeypatch.setattr(os, "rename", inspect_then_rename)
        monkeypatch.setattr(os, "open", observe_creation)
        old_umask = os.umask(0o022)
        try:
            assert _run(tmp_path / "data", "node", out=tmp_path / "bundles") == 0
        finally:
            os.umask(old_umask)
        assert published == ["node"]
        assert key_created == [(0o600, 0)]
        assert sorted(p.name for p in (tmp_path / "bundles").iterdir()) == ["node"]

    def test_output_owned_by_another_principal_is_refused_and_fd_closed(
        self, tmp_path, monkeypatch, capsys
    ):
        out = tmp_path / "bundles"
        out.mkdir(mode=0o700)
        original_open = os.open
        descriptors = []

        def observe_output_open(path, flags, mode=0o777, *, dir_fd=None):
            fd = original_open(path, flags, mode, dir_fd=dir_fd)
            if path == out:
                descriptors.append(fd)
            return fd

        # Model a different invoking principal at the OS-identity boundary;
        # do not require privilege or change ownership of any host directory.
        owner = out.stat().st_uid
        monkeypatch.setattr(os, "geteuid", lambda: owner + 1)
        monkeypatch.setattr(os, "open", observe_output_open)
        assert _run(tmp_path / "data", "node", out=out) == 1
        assert capsys.readouterr().out == ""
        assert list(out.iterdir()) == []
        assert len(descriptors) == 1
        with pytest.raises(OSError):
            os.fstat(descriptors[0])

    @pytest.mark.parametrize("kind", ["malformed", "encrypted", "non_ec"])
    def test_real_invalid_ca_key_fails_without_publishing(self, tmp_path, kind, capsys):
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        from sigrift.bridge.ca import CertificateAuthority

        data = tmp_path / "data"
        secrets = tmp_path / "secrets"
        ca = CertificateAuthority(data / "ca", key_dir=secrets / "ca")
        ca.ensure_ca()
        if kind == "malformed":
            broken = b"not a PEM key"
        else:
            key = (
                ec.generate_private_key(ec.SECP256R1())
                if kind == "encrypted"
                else rsa.generate_private_key(public_exponent=65537, key_size=2048)
            )
            encryption = (
                serialization.BestAvailableEncryption(b"test-only-passphrase")
                if kind == "encrypted"
                else serialization.NoEncryption()
            )
            broken = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                encryption,
            )
        (secrets / "ca" / "ca.key").write_bytes(broken)
        assert (
            pki_bootstrap.main(
                ["--data-dir", str(data), "--secrets-dir", str(secrets), "node"]
            )
            == 1
        )
        assert ca.list_certs() == []
        assert list((data / "edge_certs").iterdir()) == []
        assert capsys.readouterr().out == ""
        assert (secrets / "ca" / "ca.key").read_bytes() == broken

    @pytest.mark.parametrize("ttl", [0, 826])
    def test_invalid_ttl_uses_real_ca_validation(self, tmp_path, ttl, capsys):
        assert (
            pki_bootstrap.main(
                ["--data-dir", str(tmp_path / "data"), "--ttl-days", str(ttl), "node"]
            )
            == 1
        )
        assert list((tmp_path / "data" / "edge_certs").iterdir()) == []
        assert capsys.readouterr().out == ""

    def test_failed_key_creation_cleans_and_revokes_only_failed_identity(
        self, tmp_path, monkeypatch, capsys
    ):
        from sigrift.bridge.ca import CertificateAuthority

        data = tmp_path / "data"
        original_open = os.open
        attempts = []

        def fail_first_key(path, flags, mode=0o777, *, dir_fd=None):
            if path == "client.key":
                attempts.append(path)
                if len(attempts) == 1:
                    raise OSError("injected filesystem key-creation failure")
            return original_open(path, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr(os, "open", fail_first_key)
        assert _run(data, "failed", "good") == 1
        assert [
            line.split("\t")[0] for line in capsys.readouterr().out.splitlines()
        ] == ["good"]
        assert sorted(p.name for p in (data / "edge_certs").iterdir()) == ["good"]
        _assert_bundle(data / "edge_certs" / "good")
        rows = {
            r["identity"]: r for r in CertificateAuthority(data / "ca").list_certs()
        }
        assert rows["failed"]["revoked"] is True
        assert rows["good"]["revoked"] is False

    @pytest.mark.parametrize("arrival", ["before_recheck", "at_rename"])
    def test_concurrent_nonempty_destination_is_preserved(
        self, tmp_path, monkeypatch, arrival
    ):
        from sigrift.bridge.ca import CertificateAuthority

        data = tmp_path / "data"
        out = tmp_path / "bundles"
        original_rename = os.rename
        original_fsync = os.fsync
        synced = []

        def competing_bundle():
            (out / "node").mkdir()
            (out / "node" / "sentinel").write_bytes(b"complete concurrent bundle")

        def sync_then_arrive(fd):
            original_fsync(fd)
            synced.append(fd)
            # Only the new bundle's final CA file, not the CA's own atomic
            # writes. The publication recheck must notice this destination.
            if len(synced) == 3:
                competing_bundle()

        def arrive_then_rename(source, destination, **kwargs):
            competing_bundle()
            return original_rename(source, destination, **kwargs)

        if arrival == "before_recheck":
            monkeypatch.setattr(os, "fsync", sync_then_arrive)
        else:
            monkeypatch.setattr(os, "rename", arrive_then_rename)
        assert _run(data, "node", out=out) == 1
        assert _snapshot(out / "node") == {"sentinel": b"complete concurrent bundle"}
        assert sorted(p.name for p in out.iterdir()) == ["node"]
        rows = CertificateAuthority(data / "ca").list_certs()
        assert len(rows) == 1 and rows[0]["revoked"] is True

    @pytest.mark.parametrize(
        "failure", ["remove_stage", "write_revocation", "missing_serial"]
    )
    def test_cleanup_failures_are_visible_without_claiming_success(
        self, tmp_path, monkeypatch, capsys, caplog, failure
    ):
        from sigrift.bridge.ca import CertificateAuthority

        data = tmp_path / "data"
        registry = data / "ca" / "registry.json"

        def fail_publication(source, destination, **kwargs):
            if failure == "write_revocation":
                # Real registry temp-file collision prevents the revoke write.
                (data / "ca" / "registry.json.tmp").mkdir()
            elif failure == "missing_serial":
                registry.unlink()
            raise OSError("injected publication failure")

        monkeypatch.setattr(os, "rename", fail_publication)
        if failure == "remove_stage":

            def reject_remove(*args, **kwargs):
                raise PermissionError("injected staging cleanup failure")

            monkeypatch.setattr(pki_bootstrap.shutil, "rmtree", reject_remove)
        assert _run(data, "node") == 1
        assert capsys.readouterr().out == ""
        assert not (data / "edge_certs" / "node").exists()
        if failure == "remove_stage":
            stages = list((data / "edge_certs").iterdir())
            assert len(stages) == 1
            _assert_bundle(stages[0])
            assert stat.S_IMODE(stages[0].stat().st_mode) == 0o700
            assert "Could not remove private staging directory" in caplog.text
            assert CertificateAuthority(data / "ca").list_certs()[0]["revoked"] is True
        else:
            assert list((data / "edge_certs").iterdir()) == []
            assert "Could not revoke unpublished certificate" in caplog.text
            if failure == "write_revocation":
                assert (
                    CertificateAuthority(data / "ca").list_certs()[0]["revoked"]
                    is False
                )


class TestCLI:
    def test_real_process_preserves_partial_success_and_exit_status(self, tmp_path):
        data = tmp_path / "data"
        result = subprocess.run(
            [
                sys.executable,
                str(_SCRIPT),
                "--data-dir",
                str(data),
                "first",
                "../bad",
                "last",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 1
        assert [line.split("\t")[0] for line in result.stdout.splitlines()] == [
            "first",
            "last",
        ]
        assert "1 agent(s) failed to provision" in result.stderr
        assert "PRIVATE KEY" not in result.stdout + result.stderr
        for name in ("first", "last"):
            _assert_bundle(data / "edge_certs" / name)

    def test_entrypoint_exits_with_actual_success(self, tmp_path, monkeypatch, capsys):
        data = tmp_path / "data"
        # run_path executes the shipped __main__ guard; isolate its documented
        # checkout-path insertion and argv from the surrounding test process.
        monkeypatch.setattr(sys, "path", sys.path.copy())
        monkeypatch.setattr(
            sys, "argv", [str(_SCRIPT), "--data-dir", str(data), "node"]
        )
        with pytest.raises(SystemExit) as exc:
            runpy.run_path(str(_SCRIPT), run_name="__main__")
        assert exc.value.code == 0
        assert capsys.readouterr().out.startswith("node\tMLRF_CLIENT_CERT=")
        _assert_bundle(data / "edge_certs" / "node")
