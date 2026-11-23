"""CA bootstrap when writing or removing the new private key fails.

``test_ca_security.py`` covers a failure *after* the key is in place (the
certificate write).  These cover the disk filling up *while* the key is
written — no copy, partial or whole, of the private key may be left behind
— and a key that cannot be removed again after the certificate failed,
which must be reported as still there (and then refused, never reused or
replaced, by the next start-up).
"""

from __future__ import annotations

import errno
import logging
import os
from pathlib import Path

import pytest

from sigrift.bridge import ca as ca_mod
from sigrift.bridge.ca import CertificateAuthority


@pytest.fixture(autouse=True)
def _private_secrets_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BRIDGE_SECRETS_DIR", str(tmp_path / "secrets"))


def _files_holding_a_private_key(root: Path) -> list[Path]:
    return [
        path
        for path in root.rglob("*")
        if path.is_file() and b"PRIVATE KEY" in path.read_bytes()
    ]


class _DiskFillsUp:
    """A binary file that takes half of a private key, then fails with ENOSPC."""

    def __init__(self, real):
        self._real = real

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self._real.close()
        return False

    def fileno(self):
        return self._real.fileno()

    def write(self, data):
        if b"PRIVATE KEY" in data:
            self._real.write(data[: len(data) // 2])
            self._real.flush()
            raise OSError(errno.ENOSPC, "No space left on device")
        return self._real.write(data)


def test_a_key_write_that_fills_the_disk_leaves_no_copy_of_the_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ca_dir = tmp_path / "data" / "ca"
    authority = CertificateAuthority(ca_dir)
    real_fdopen = os.fdopen

    def fdopen(fd, mode="r", *args, **kwargs):
        handle = real_fdopen(fd, mode, *args, **kwargs)
        return _DiskFillsUp(handle) if mode == "wb" else handle

    with monkeypatch.context() as patch:
        patch.setattr(ca_mod.os, "fdopen", fdopen)
        with pytest.raises(OSError, match="No space left"):
            authority.ensure_ca()

    assert _files_holding_a_private_key(tmp_path) == []
    assert sorted(authority.key_path.parent.iterdir()) == []
    assert not authority.is_initialized
    assert not (ca_dir / "ca.crt").exists()

    # Space again: the next start-up creates the CA from scratch.
    authority.ensure_ca()
    assert authority.is_initialized
    assert _files_holding_a_private_key(tmp_path) == [authority.key_path]


def test_a_new_key_that_cannot_be_removed_again_is_reported_and_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    ca_dir = tmp_path / "data" / "ca"
    authority = CertificateAuthority(ca_dir)
    real_write = ca_mod._atomic_write
    real_unlink = os.unlink

    def fail_on_the_cert(path: Path, data: bytes, *, mode: int) -> None:
        if path.name == "ca.crt":
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_write(path, data, mode=mode)

    def unlink(path, *args, **kwargs):
        if os.fspath(path) == os.fspath(authority.key_path):
            raise PermissionError(errno.EACCES, "Permission denied")
        return real_unlink(path, *args, **kwargs)

    with monkeypatch.context() as patch, caplog.at_level(logging.WARNING):
        patch.setattr(ca_mod, "_atomic_write", fail_on_the_cert)
        patch.setattr(ca_mod.os, "unlink", unlink)
        # The original failure is what the caller sees.
        with pytest.raises(OSError, match="No space left"):
            authority.ensure_ca()

    text = "\n".join(record.getMessage() for record in caplog.records)
    assert "could not be removed again" in text
    assert "move it aside before retrying" in text
    assert "removed the new CA private key" not in text
    assert "PRIVATE KEY" not in text
    key = authority.key_path.read_bytes()
    assert b"PRIVATE KEY" in key
    assert not (ca_dir / "ca.crt").exists()

    # The next start-up neither reuses nor replaces the leftover key.
    with pytest.raises(ca_mod.CAStateError, match="already a private key"):
        authority.ensure_ca()
    assert authority.key_path.read_bytes() == key
    assert not (ca_dir / "ca.crt").exists()
