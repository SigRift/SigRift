"""Inter-process locking of the embedded CA's registry (``sigrift.bridge.ca``).

``registry.json`` is the only record of the certificates the CA issued and
of their revocations, and the gateway enforces revocation from it alone.
Every change to it is a read-modify-write, and more than one process can
make one at the same time: the bridge (each worker has a CA of its own)
and ``scripts/pki_bootstrap.py`` run against the same data directory. A
lock that only serialises the threads of one process lets one of them
write back a registry it read before the other's change, so a revocation
that returned success comes undone (the revoked certificate
authenticates again) or an issued certificate is missing (the gateway
refuses it).

These tests run the competing CA in a separate process, as in production,
and check the outcome on disk: nothing is lost, a busy lock (or one the
filesystem cannot take) fails closed with nothing changed, the lock file
cannot be used to redirect, block or bypass the lock, and waiting for it
lasts at most the documented 5 seconds, does not starve a long waiter and
holds up no other request to the bridge.
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import errno
import json
import os
import stat
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from sigrift.bridge import ca as ca_mod
from sigrift.bridge.ca import CAStateError, CertificateAuthority

fcntl = pytest.importorskip("fcntl")  # POSIX: the lock is an flock

_ROOT = Path(__file__).resolve().parents[2]
_SRC = _ROOT / "src"
_SCRIPT = _ROOT / "scripts" / "pki_bootstrap.py"

# The lock file's documented name, next to registry.json (PKI_ARCHITECTURE.md).
_LOCK_NAME = ".ca.lock"

# How long a test waits for a child process to reach a point or finish.
_CHILD_DEADLINE = 60.0

# The lock wait as shipped, before the fixture below lengthens it: 5 seconds
# (PKI_ARCHITECTURE.md, CHANGELOG), so a change behind a stopped holder is
# a 503 within that time.
_SHIPPED_LOCK_TIMEOUT = ca_mod._LOCK_TIMEOUT_SECONDS


@pytest.fixture(autouse=True)
def _private_secrets_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BRIDGE_SECRETS_DIR", str(tmp_path / "secrets"))
    # The waits below are released explicitly; a slow machine must not turn
    # them into a lock timeout. (raising=False: the setting is new.)
    monkeypatch.setattr(ca_mod, "_LOCK_TIMEOUT_SECONDS", 30.0, raising=False)


@pytest.fixture
def dirs(tmp_path: Path) -> tuple[Path, Path]:
    """``(ca_dir, key_dir)`` of a CA shared by this process and its children."""
    return tmp_path / "data" / "ca", tmp_path / "secrets" / "ca"


@pytest.fixture
def ca(dirs: tuple[Path, Path]) -> CertificateAuthority:
    ca_dir, key_dir = dirs
    authority = CertificateAuthority(ca_dir, key_dir=key_dir)
    authority.ensure_ca()
    return authority


def _registry(ca_dir: Path) -> dict[str, dict]:
    return json.loads((ca_dir / "registry.json").read_text(encoding="utf-8"))["issued"]


def _csr() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )


def _child_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (str(_SRC), env.get("PYTHONPATH", "")) if p
    )
    return env


def _wait_for(path: Path, child: subprocess.Popen) -> None:
    deadline = time.monotonic() + _CHILD_DEADLINE
    while not path.exists():
        if child.poll() is not None:
            out, err = child.communicate()
            pytest.fail(f"child exited {child.returncode} early: {err.decode()}")
        if time.monotonic() > deadline:
            child.kill()
            pytest.fail(f"child never reached {path.name}")
        time.sleep(0.01)


@contextlib.contextmanager
def _held_lock(path: Path) -> Iterator[int]:
    """Hold the CA lock as another process would (a descriptor of its own)."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield fd
    finally:
        os.close(fd)


class _FakeTime:
    """Stands in for ``time`` in ``sigrift.bridge.ca``: sleeping moves the clock.

    So a wait of seconds for the lock takes no time, and its length is
    exact. Gives up after a simulated minute, should the wait never end.
    """

    def __init__(self) -> None:
        self.start = self.now = 1000.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        assert seconds > 0
        self.sleeps.append(seconds)
        self.now += seconds
        if self.now - self.start > 60:
            raise AssertionError("waited for the CA lock for over a minute")

    def __getattr__(self, name: str) -> Any:
        return getattr(time, name)


def _open_fds() -> list[str]:
    return sorted(os.listdir("/dev/fd"))


# A child process that stops, the first time it gets to *pause_at*, until
# the test creates the "go" file -- the process descheduled inside its
# change. "registry": its first registry write, after the registry was read
# and changed in memory. "key": creating the CA, before the CA private key
# is written. Nothing else is changed; the rest of the command line says
# what the child runs.
_PAUSED_CHILD = r"""
import runpy, sys, time
from pathlib import Path
from sigrift.bridge import ca as ca_mod

reached, go, pause_at, what, *rest = sys.argv[1:]

def paused(real):
    def wrapper(*args, **kwargs):
        if not Path(reached).exists():
            Path(reached).touch()
            deadline = time.monotonic() + 60
            while not Path(go).exists():
                if time.monotonic() > deadline:
                    raise SystemExit("never released")
                time.sleep(0.01)
        return real(*args, **kwargs)
    return wrapper

if pause_at == "registry":
    ca_mod.CertificateAuthority._write_registry = paused(
        ca_mod.CertificateAuthority._write_registry)
elif pause_at == "key":
    ca_mod._create_private_file = paused(ca_mod._create_private_file)
else:
    raise SystemExit(f"unknown {pause_at!r}")
if what == "pki_bootstrap":
    sys.argv = [rest[0], *rest[1:]]
    runpy.run_path(rest[0], run_name="__main__")
elif what == "ensure_ca":
    ca_mod.CertificateAuthority(rest[0], key_dir=rest[1]).ensure_ca()
else:
    raise SystemExit(f"unknown {what!r}")
"""


def _start_paused(
    tmp_path: Path, *args: str, pause_at: str = "registry"
) -> tuple[subprocess.Popen, Path]:
    reached, go = tmp_path / "reached", tmp_path / "go"
    child = subprocess.Popen(
        [sys.executable, "-c", _PAUSED_CHILD, str(reached), str(go), pause_at, *args],
        env=_child_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _wait_for(reached, child)
    return child, go


def _finish(child: subprocess.Popen, go: Path) -> int:
    go.touch()
    try:
        _out, err = child.communicate(timeout=_CHILD_DEADLINE)
    except subprocess.TimeoutExpired:
        child.kill()
        raise
    assert child.returncode == 0, err.decode()
    return child.returncode


# ---------------------------------------------------------------------------
# Two processes, one registry
# ---------------------------------------------------------------------------


class TestConcurrentProcesses:
    @pytest.mark.parametrize("bridge_change", ["revoke", "issue"])
    def test_pki_bootstrap_does_not_undo_a_concurrent_bridge_change(
        self,
        ca: CertificateAuthority,
        dirs: tuple[Path, Path],
        tmp_path: Path,
        bridge_change: str,
    ) -> None:
        """The reported case: pki_bootstrap mid-issue, the bridge revokes (or issues).

        pki_bootstrap (the real script, in its own process) has read the
        registry and is about to write it back with the certificate it is
        issuing. The bridge -- this process, with a CA of its own, as
        ``POST /api/ca/revoke/{serial}`` or ``/api/ca/issue`` -- changes the
        registry meanwhile. Both changes must be on disk afterwards.
        """
        ca_dir, key_dir = dirs
        victim = ca.issue_cert(identity="compromised-node", role="node")["serial"]
        child, go = _start_paused(
            tmp_path,
            "pki_bootstrap",
            str(_SCRIPT),
            "--data-dir",
            str(ca_dir.parent),
            "--secrets-dir",
            str(key_dir.parent),
            "--out-dir",
            str(tmp_path / "bundles"),
            "new-node:node",
        )
        with ThreadPoolExecutor(max_workers=1) as pool:
            if bridge_change == "revoke":
                change = pool.submit(ca.revoke, victim)
            else:
                change = pool.submit(ca.issue_cert, identity="by-admin", role="node")
            time.sleep(0.5)
            waited = not change.done()
            _finish(child, go)
            result = change.result(timeout=_CHILD_DEADLINE)

        issued = _registry(ca_dir)
        by_identity = {entry["identity"]: s for s, entry in issued.items()}
        assert "new-node" in by_identity  # pki_bootstrap's certificate
        if bridge_change == "revoke":
            assert result is True
            assert issued[victim]["revoked"] is True, "the revocation was lost"
            assert issued[victim]["revoked_at"]
            crl = x509.load_pem_x509_crl(ca.generate_crl())
            assert {r.serial_number for r in crl} == {int(victim)}
        else:
            assert result["serial"] in issued, "the bridge's certificate was lost"
            assert by_identity["by-admin"] == result["serial"]
        assert issued[by_identity["new-node"]]["revoked"] is False
        # The bridge's change waited for pki_bootstrap's write.
        assert waited

    def test_creating_the_registry_does_not_clobber_one_written_meanwhile(
        self, dirs: tuple[Path, Path], tmp_path: Path
    ) -> None:
        """``ensure_ca``'s "create registry.json if it is missing".

        The first start-up has written ca.key and ca.crt and found no
        registry; before it writes an empty one, another process (which
        now sees a complete CA) issues a certificate. The empty registry
        must not replace that one.
        """
        ca_dir, key_dir = dirs
        child, go = _start_paused(tmp_path, "ensure_ca", str(ca_dir), str(key_dir))
        other = CertificateAuthority(ca_dir, key_dir=key_dir)
        with ThreadPoolExecutor(max_workers=1) as pool:
            change = pool.submit(other.issue_cert, identity="early", role="node")
            time.sleep(0.5)
            waited = not change.done()
            _finish(child, go)
            serial = change.result(timeout=_CHILD_DEADLINE)["serial"]
        assert list(_registry(ca_dir)) == [serial], "the issued certificate was lost"
        assert waited

    def test_a_second_start_up_waits_for_the_ca_instead_of_refusing_it(
        self, dirs: tuple[Path, Path], tmp_path: Path
    ) -> None:
        """Two first start-ups on an empty data directory at the same time.

        As two bridge workers (``BRIDGE_WORKERS=2``), or the bridge and
        pki_bootstrap. One is creating the CA; the other waits for the lock
        meanwhile. When it gets it, the CA is complete, and it must use that
        CA: not take its key for one left behind without a certificate and
        refuse it (a 503 from every CA route of that worker, ``ca.pem`` and
        ``crl.pem`` included, or pki_bootstrap exiting 1).
        """
        ca_dir, key_dir = dirs
        child, go = _start_paused(
            tmp_path, "ensure_ca", str(ca_dir), str(key_dir), pause_at="key"
        )
        other = CertificateAuthority(ca_dir, key_dir=key_dir)
        with ThreadPoolExecutor(max_workers=1) as pool:
            opening = pool.submit(other.ensure_ca)
            time.sleep(0.5)
            waited = not opening.done()
            _finish(child, go)
            opening.result(timeout=_CHILD_DEADLINE)
        assert waited
        created = (ca_dir / "ca.crt").read_bytes()
        assert other.ca_cert_pem == created
        leaf = other.issue_cert(identity="edge", role="node")
        assert list(_registry(ca_dir)) == [leaf["serial"]]
        ca_cert = x509.load_pem_x509_certificate(created)
        leaf_cert = x509.load_pem_x509_certificate(leaf["cert_pem"].encode())
        assert leaf_cert.issuer == ca_cert.subject

    def test_uninstrumented_processes_lose_nothing(
        self, ca: CertificateAuthority, dirs: tuple[Path, Path], tmp_path: Path
    ) -> None:
        """Two CA processes issuing and revoking flat out, nothing patched.

        As two bridge workers (``BRIDGE_WORKERS`` > 1), or the bridge and
        pki_bootstrap. Every issuance and revocation that returned success
        is in the registry and the CRL, and none of them fails.
        """
        ca_dir, key_dir = dirs
        start = tmp_path / "start"
        worker = r"""
import json, sys, time
from pathlib import Path
from sigrift.bridge.ca import CertificateAuthority
ca_dir, key_dir, start, out, tag, count = sys.argv[1:]
ca = CertificateAuthority(ca_dir, key_dir=key_dir)
Path(out + ".ready").touch()
while not Path(start).exists():
    time.sleep(0.001)
issued, revoked, errors = [], [], []
for i in range(int(count)):
    try:
        serial = ca.issue_cert(identity=f"{tag}-{i}", role="node")["serial"]
        issued.append(serial)
        if i % 2:
            if ca.revoke(serial):
                revoked.append(serial)
            else:
                errors.append(f"revoke({serial}) returned False")
    except Exception as exc:
        errors.append(repr(exc))
Path(out).write_text(json.dumps(
    {"issued": issued, "revoked": revoked, "errors": errors}))
"""
        outs = [tmp_path / f"worker-{tag}.json" for tag in ("a", "b")]
        children = [
            subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    worker,
                    str(ca_dir),
                    str(key_dir),
                    str(start),
                    str(out),
                    out.stem,
                    "40",
                ],
                env=_child_env(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for out in outs
        ]
        for child, out in zip(children, outs):
            _wait_for(Path(str(out) + ".ready"), child)
        start.touch()
        for child in children:
            _out, err = child.communicate(timeout=_CHILD_DEADLINE * 2)
            assert child.returncode == 0, err.decode()
        results = [json.loads(out.read_text()) for out in outs]

        assert [r["errors"] for r in results] == [[], []]
        issued = {s for r in results for s in r["issued"]}
        revoked = {s for r in results for s in r["revoked"]}
        assert len(issued) == 80 and len(revoked) == 40
        registry = _registry(ca_dir)
        assert sorted(issued - set(registry)) == [], "issued certificates lost"
        assert sorted(s for s in revoked if not registry[s]["revoked"]) == [], (
            "revocations lost"
        )
        assert all(registry[s]["revoked"] is False for s in issued - revoked)
        crl = x509.load_pem_x509_crl(ca.generate_crl())
        assert {str(r.serial_number) for r in crl} == revoked
        assert [p.name for p in ca_dir.iterdir() if p.name.endswith(".tmp")] == []


# ---------------------------------------------------------------------------
# A lock held elsewhere
# ---------------------------------------------------------------------------


class TestHeldLock:
    def test_a_change_waits_for_the_lock(self, ca: CertificateAuthority) -> None:
        serial = ca.issue_cert(identity="edge", role="node")["serial"]
        with ThreadPoolExecutor(max_workers=1) as pool:
            with _held_lock(ca._dir / _LOCK_NAME):
                change = pool.submit(ca.revoke, serial)
                time.sleep(0.3)
                assert not change.done()
                assert ca.get_cert(serial)["revoked"] is False
            assert change.result(timeout=10) is True
        assert ca.get_cert(serial)["revoked"] is True

    def test_two_objects_in_one_process_exclude_each_other(
        self, ca: CertificateAuthority, dirs: tuple[Path, Path]
    ) -> None:
        """The lock is the file's, not the object's: a second CA object (as
        a second app instance or a test client would open) waits too."""
        serial = ca.issue_cert(identity="edge", role="node")["serial"]
        other = CertificateAuthority(dirs[0], key_dir=dirs[1])
        with ThreadPoolExecutor(max_workers=1) as pool:
            with ca._exclusive():
                change = pool.submit(other.revoke, serial)
                time.sleep(0.3)
                assert not change.done()
                # Re-entrant in the thread that holds it.
                assert ca.revoke(serial) is True
            assert change.result(timeout=10) is True
        assert ca.get_cert(serial)["revoked"] is True

    def test_a_lock_held_too_long_fails_closed_with_nothing_changed(
        self, ca: CertificateAuthority, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A stopped process holding the lock: 503 in the bridge, not a hang."""
        serial = ca.issue_cert(identity="edge", role="node")["serial"]
        registry = ca._dir / "registry.json"
        before = registry.read_bytes()
        monkeypatch.setattr(ca_mod, "_LOCK_TIMEOUT_SECONDS", 0.2, raising=False)
        with _held_lock(ca._dir / _LOCK_NAME):
            for change in (
                lambda: ca.revoke(serial),
                lambda: ca.issue_cert(identity="next", role="node"),
                lambda: ca.sign_csr(_csr(), identity="next", role="node"),
            ):
                started = time.monotonic()
                with pytest.raises(CAStateError, match="another process") as exc:
                    change()
                assert time.monotonic() - started < 5
                assert str(ca._dir / _LOCK_NAME) in str(exc.value)
                assert "Nothing was issued, revoked or created" in str(exc.value)
            # Reading does not take the lock: the gateway-facing CRL, the
            # listing and an existing CA's ensure_ca keep working.
            assert [r["serial"] for r in ca.list_certs()] == [serial]
            assert ca.get_cert(serial)["revoked"] is False
            assert len(x509.load_pem_x509_crl(ca.generate_crl())) == 0
            CertificateAuthority(ca._dir, key_dir=ca.key_path.parent).ensure_ca()
        assert registry.read_bytes() == before
        assert ca.revoke(serial) is True  # once it is released

    def test_a_lock_file_replaced_while_waiting_is_locked_again(
        self, ca: CertificateAuthority
    ) -> None:
        """Locking the old file of a removed lock file would exclude no one.

        While this CA waits, the lock file is removed and another process
        creates and locks a new one. When the old holder lets go, this CA
        must wait for the new holder, not proceed on the unlinked file.
        """
        serial = ca.issue_cert(identity="edge", role="node")["serial"]
        lock = ca._dir / _LOCK_NAME
        old_fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        new_fd = None
        try:
            fcntl.flock(old_fd, fcntl.LOCK_EX)
            with ThreadPoolExecutor(max_workers=1) as pool:
                change = pool.submit(ca.revoke, serial)
                time.sleep(0.3)
                assert not change.done()
                lock.unlink()
                new_fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
                fcntl.flock(new_fd, fcntl.LOCK_EX)
                os.close(old_fd)
                old_fd = None
                time.sleep(0.3)
                assert not change.done(), "proceeded on a lock file no one else uses"
                assert ca.get_cert(serial)["revoked"] is False
                os.close(new_fd)
                new_fd = None
                assert change.result(timeout=10) is True
        finally:
            for fd in (old_fd, new_fd):
                if fd is not None:
                    os.close(fd)
        assert ca.get_cert(serial)["revoked"] is True

    def test_a_lock_file_removed_while_waiting_is_created_and_locked_again(
        self, ca: CertificateAuthority, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The lock file removed, and not created again, while this CA waits.

        Say an operator deletes it while one change holds it and this one
        waits. When the holder lets go, this CA must not go ahead on the
        removed file: the next change to arrive would create a new lock
        file, lock it at once and run alongside. It creates the file again
        and locks that, so a change arriving meanwhile waits for it.
        """
        serial = ca.issue_cert(identity="edge", role="node")["serial"]
        lock = ca._dir / _LOCK_NAME
        inside, leave = threading.Event(), threading.Event()
        real_write = CertificateAuthority._write_registry

        def paused_write(self: CertificateAuthority, data: dict) -> None:
            inside.set()
            assert leave.wait(_CHILD_DEADLINE)
            real_write(self, data)

        monkeypatch.setattr(CertificateAuthority, "_write_registry", paused_write)
        old_fd: int | None = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(old_fd, fcntl.LOCK_EX)
        with ThreadPoolExecutor(max_workers=1) as pool:
            change = pool.submit(ca.revoke, serial)
            try:
                time.sleep(0.3)
                assert not change.done()
                lock.unlink()
                os.close(old_fd)  # the holder lets go; no lock file now
                old_fd = None
                assert inside.wait(10), "the change never went ahead"
                newcomer = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
                try:
                    with pytest.raises(BlockingIOError):
                        fcntl.flock(newcomer, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(newcomer)
            finally:
                # Also on failure, so the change can finish and the pool stop.
                leave.set()
                if old_fd is not None:
                    os.close(old_fd)
            assert change.result(timeout=10) is True
        assert ca.get_cert(serial)["revoked"] is True

    def test_a_change_behind_a_stopped_holder_fails_after_5_seconds(
        self, ca: CertificateAuthority, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The wait as shipped and documented: 5 seconds, then a 503.

        Not minutes: an admin's revoke or issue during a pki_bootstrap
        stopped mid-change (Ctrl-Z) would keep the admin waiting that long.
        """
        serial = ca.issue_cert(identity="edge", role="node")["serial"]
        monkeypatch.setattr(ca_mod, "_LOCK_TIMEOUT_SECONDS", _SHIPPED_LOCK_TIMEOUT)
        clock = _FakeTime()
        monkeypatch.setattr(ca_mod, "time", clock)
        with _held_lock(ca._dir / _LOCK_NAME):
            with pytest.raises(CAStateError, match="within 5 seconds"):
                ca.revoke(serial)
        waited = clock.now - clock.start
        assert 5.0 <= waited <= 5.0 + max(clock.sleeps)
        assert ca.get_cert(serial)["revoked"] is False

    def test_a_long_wait_tries_the_lock_as_often_as_a_new_one(
        self, ca: CertificateAuthority, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No backing off: a change that has waited long is not starved.

        A holder's next change (pki_bootstrap issuing one bundle after
        another, a worker's next request) takes the lock again milliseconds
        after letting it go, as does any change that has just arrived: it
        tries at once. A waiter that tried less and less often would miss
        those gaps, release after release, until it timed out.
        """
        serial = ca.issue_cert(identity="edge", role="node")["serial"]
        clock = _FakeTime()
        monkeypatch.setattr(ca_mod, "_LOCK_TIMEOUT_SECONDS", 2.0)
        monkeypatch.setattr(ca_mod, "time", clock)
        with _held_lock(ca._dir / _LOCK_NAME):
            with pytest.raises(CAStateError, match="another process"):
                ca.revoke(serial)
        assert max(clock.sleeps) <= 0.002

    @pytest.mark.parametrize("route", ["revoke", "issue", "sign"])
    def test_over_http_a_change_waiting_for_the_lock_holds_up_nothing_else(
        self, bridge_app, master_key: str, route: str
    ) -> None:
        """The wait is not on the event loop: the worker serves other requests.

        Else, behind a stopped pki_bootstrap, every admin sign, issue or
        revoke would stall all of this worker's traffic (ingest, WebSocket
        feeds, the public CRL) for as long as it waits.
        """
        # One event loop for every request, as in a bridge worker.
        with TestClient(bridge_app, headers={"X-API-Key": master_key}) as shared:
            issued = shared.post(
                "/api/ca/issue", json={"identity": "edge-01", "role": "node"}
            )
            assert issued.status_code == 201
            serial = issued.json()["serial"]
            authority: CertificateAuthority = bridge_app.state.ca
            if route == "revoke":
                path, body, expected = f"/api/ca/revoke/{serial}", None, 200
            elif route == "issue":
                path, expected = "/api/ca/issue", 201
                body = {"identity": "edge-02", "role": "node"}
            else:
                path, expected = "/api/ca/sign", 201
                body = {"csr_pem": _csr().decode(), "identity": "edge-02"}
            with ThreadPoolExecutor(max_workers=2) as pool:
                with _held_lock(authority._dir / _LOCK_NAME):
                    change = pool.submit(shared.post, path, json=body)
                    time.sleep(0.3)
                    assert not change.done()
                    other = pool.submit(shared.get, "/api/ca/crl.pem")
                    try:
                        crl = other.result(timeout=5)
                    except concurrent.futures.TimeoutError:
                        pytest.fail("a request waited for another's CA change")
                    assert crl.status_code == 200
                    assert len(x509.load_pem_x509_crl(crl.content)) == 0
                    assert not change.done()
                assert change.result(timeout=10).status_code == expected
        if route == "revoke":
            assert authority.get_cert(serial)["revoked"] is True
        else:
            assert len(authority.list_certs()) == 2

    def test_over_http_a_busy_lock_is_a_503_and_nothing_is_revoked(
        self, client: TestClient, bridge_app, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        issued = client.post(
            "/api/ca/issue", json={"identity": "edge-01", "role": "node"}
        )
        assert issued.status_code == 201
        serial = issued.json()["serial"]
        authority: CertificateAuthority = bridge_app.state.ca
        monkeypatch.setattr(ca_mod, "_LOCK_TIMEOUT_SECONDS", 0.2, raising=False)
        with _held_lock(authority._dir / _LOCK_NAME):
            resp = client.post(f"/api/ca/revoke/{serial}")
            assert resp.status_code == 503
            assert "another process" in resp.json()["detail"]
            again = client.post("/api/ca/issue", json={"identity": "x", "role": "node"})
            assert again.status_code == 503
        assert authority.get_cert(serial)["revoked"] is False
        assert len(authority.list_certs()) == 1
        assert client.post(f"/api/ca/revoke/{serial}").status_code == 200
        assert authority.get_cert(serial)["revoked"] is True


# ---------------------------------------------------------------------------
# The lock file itself
# ---------------------------------------------------------------------------


class TestLockFile:
    def test_it_is_a_private_empty_file_next_to_the_registry(
        self, dirs: tuple[Path, Path]
    ) -> None:
        ca_dir, key_dir = dirs
        old_umask = os.umask(0)
        try:
            authority = CertificateAuthority(ca_dir, key_dir=key_dir)
            authority.ensure_ca()
            authority.issue_cert(identity="edge", role="node")
        finally:
            os.umask(old_umask)
        lock = ca_dir / _LOCK_NAME
        info = lock.lstat()
        assert stat.S_ISREG(info.st_mode)
        assert stat.S_IMODE(info.st_mode) == 0o600
        assert info.st_size == 0
        # Not in the key directory: every process that shares the registry
        # must share the lock, whatever key directory it was given.
        assert not (key_dir / _LOCK_NAME).exists()

    @pytest.mark.parametrize("dangling", [False, True])
    def test_a_symlink_there_is_not_followed(
        self, ca: CertificateAuthority, tmp_path: Path, dangling: bool
    ) -> None:
        serial = ca.issue_cert(identity="edge", role="node")["serial"]
        registry = ca._dir / "registry.json"
        before = registry.read_bytes()
        target = tmp_path / "elsewhere"
        if not dangling:
            target.write_bytes(b"not the CA's")
            target.chmod(0o644)
        lock = ca._dir / _LOCK_NAME
        lock.unlink(missing_ok=True)
        lock.symlink_to(target)
        for change in (
            lambda: ca.revoke(serial),
            lambda: ca.issue_cert(identity="next", role="node"),
        ):
            with pytest.raises(CAStateError, match="symlink"):
                change()
        assert lock.is_symlink()
        if dangling:
            assert not target.exists() and not target.is_symlink()
        else:
            assert target.read_bytes() == b"not the CA's"
            assert stat.S_IMODE(target.stat().st_mode) == 0o644
        assert registry.read_bytes() == before

    @pytest.mark.parametrize("kind", ["fifo", "directory"])
    def test_something_else_there_is_refused_without_hanging(
        self, ca: CertificateAuthority, kind: str
    ) -> None:
        serial = ca.issue_cert(identity="edge", role="node")["serial"]
        lock = ca._dir / _LOCK_NAME
        lock.unlink(missing_ok=True)
        if kind == "fifo":
            os.mkfifo(lock, 0o600)
        else:
            lock.mkdir()
        with ThreadPoolExecutor(max_workers=1) as pool:
            change = pool.submit(ca.revoke, serial)
            with pytest.raises(CAStateError, match=str(lock)):
                change.result(timeout=10)
        assert ca.get_cert(serial)["revoked"] is False

    @pytest.mark.parametrize("error", [errno.ENOLCK, errno.EOPNOTSUPP])
    def test_a_filesystem_without_locks_fails_closed(
        self,
        dirs: tuple[Path, Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        error: int,
    ) -> None:
        """``flock`` refused (some network or FUSE mounts): no change, no CA.

        Going ahead without the lock would bring back the lost revocations
        and certificates it is there to prevent, unnoticed.
        """
        ca_dir, key_dir = dirs
        authority = CertificateAuthority(ca_dir, key_dir=key_dir)
        authority.ensure_ca()
        serial = authority.issue_cert(identity="edge", role="node")["serial"]
        registry = ca_dir / "registry.json"
        before = registry.read_bytes()
        csr = _csr()
        real = ca_mod._fcntl

        def flock(fd: int, operation: int) -> None:
            if operation == real.LOCK_UN:
                return real.flock(fd, operation)
            raise OSError(error, os.strerror(error))

        monkeypatch.setattr(
            ca_mod,
            "_fcntl",
            SimpleNamespace(
                flock=flock,
                LOCK_EX=real.LOCK_EX,
                LOCK_SH=real.LOCK_SH,
                LOCK_NB=real.LOCK_NB,
                LOCK_UN=real.LOCK_UN,
            ),
        )
        fds = _open_fds()
        for change in (
            lambda: authority.revoke(serial),
            lambda: authority.issue_cert(identity="next", role="node"),
            lambda: authority.sign_csr(csr, identity="next", role="node"),
        ):
            with pytest.raises(CAStateError, match="cannot be locked"):
                change()
        assert registry.read_bytes() == before
        assert authority.get_cert(serial)["revoked"] is False
        assert _open_fds() == fds  # the lock file's descriptor closed
        # Creating a CA there fails the same way, with nothing created.
        fresh = CertificateAuthority(
            tmp_path / "other" / "ca", key_dir=tmp_path / "other-secrets" / "ca"
        )
        with pytest.raises(CAStateError, match="cannot be locked"):
            fresh.ensure_ca()
        assert not fresh.is_initialized
        assert not fresh.key_path.exists()
        assert not (tmp_path / "other" / "ca" / "ca.crt").exists()

    @pytest.mark.skipif(
        hasattr(os, "geteuid") and os.geteuid() == 0,
        reason="root ignores file permissions",
    )
    def test_a_read_only_ca_dir_still_serves_reads(
        self, ca: CertificateAuthority
    ) -> None:
        """Opening and reading an existing CA needs no lock file.

        E.g. a CA directory mounted read-only for a tool that only lists
        certificates or publishes the CRL. A change cannot be made there, and
        says why instead of failing with a bare PermissionError.
        """
        serial = ca.issue_cert(identity="edge", role="node")["serial"]
        (ca._dir / _LOCK_NAME).unlink(missing_ok=True)
        ca._dir.chmod(0o555)
        try:
            reader = CertificateAuthority(ca._dir, key_dir=ca.key_path.parent)
            reader.ensure_ca()
            assert [r["serial"] for r in reader.list_certs()] == [serial]
            assert len(x509.load_pem_x509_crl(reader.generate_crl())) == 0
            with pytest.raises(CAStateError, match="lock"):
                reader.revoke(serial)
            assert not (ca._dir / _LOCK_NAME).exists()
        finally:
            ca._dir.chmod(0o755)
        assert ca.get_cert(serial)["revoked"] is False

    def test_an_uninitialised_ca_still_has_nothing_to_revoke(
        self, tmp_path: Path
    ) -> None:
        authority = CertificateAuthority(tmp_path / "nowhere" / "ca")
        assert authority.revoke("1") is False
        with pytest.raises(CAStateError, match="not initialised"):
            authority.issue_cert(identity="edge", role="node")
        assert not (tmp_path / "nowhere").exists()
