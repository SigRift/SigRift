"""Security paths of the bridge lifespan (``sigrift.bridge.app.lifespan``).

Each test runs the real lifespan against a temporary data directory (the
helpers of ``test_lifespan``).  Covers what ``test_lifespan``,
``test_key_store_integrity``, ``test_persistence_security`` and
``test_mfa_key_validation`` leave out:

* production refusals: a default ``UC_PROXY_SECRET``, a missing
  ``BRIDGE_MASTER_KEY``, no users and no ``BRIDGE_ADMIN_PASSWORD``;
* the ``BRIDGE_ALLOW_UNBOUND_NODE_KEYS`` start-up warning;
* ``BRIDGE_LOCAL_NODE_KEY``: rotating it revokes the old value (over HTTP),
  a value another key holds is refused, an unwritable keys.json refuses
  start-up, neither a heartbeat of that key nor a saved node record with
  an unreadable ``last_seen`` stops the next start;
* shutdown with ``BRIDGE_BACKGROUND_TASKS`` disabled: it runs to its end
  (the final save); enabled: every periodic task is stopped before it;
* the generated admin password file: owner-only, removed on shutdown, a
  write failure still leaves a must-change admin and no partial file, a
  planted symlink or file at its name is replaced, never written through.
"""

from __future__ import annotations

import errno
import json
import os
import secrets
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient

import sigrift.bridge.app as app_module
import sigrift.bridge.dependencies as deps
import sigrift.bridge.storage.users as users_storage
from sigrift.bridge.app import lifespan
from sigrift.bridge.constants import LOCAL_SCANNER_KEY_ID
from sigrift.bridge.persistence import KeyStoreWriteError
from sigrift.lib.security import credentials
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
    verify_credential,
)

from .test_lifespan import (
    _lifespan_env,
    _patch_data_paths,
    _patch_detection_store,
    _patch_iq_store,
    _patch_pcap_store,
    _patch_persistence_dir,
)

_ADMIN_PASSWORD = "p-app-lifespan-admin-password"
_PW_FILE_NAME = "sigrift-admin-pw"

needs_unprivileged = pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0,
    reason="needs POSIX permissions that bind the test user (not root)",
)


@pytest.fixture(autouse=True)
def _fast_pbkdf2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(credentials, "_PBKDF2_ITERATIONS", 1_000)


@pytest.fixture(autouse=True)
def _fresh_cache():
    deps._verified_key_cache.clear()
    yield
    deps._verified_key_cache.clear()


@pytest.fixture(autouse=True)
def _no_cached_fernet(monkeypatch: pytest.MonkeyPatch) -> None:
    """The lifespan caches the BRIDGE_MFA_KEY Fernet: keep it to the test."""
    monkeypatch.setattr(users_storage, "_fernet_instance", None)


@pytest.fixture
def data(tmp_path: Path) -> Path:
    d = tmp_path / "data"
    d.mkdir()
    return d


@contextmanager
def _booted(
    data: Path,
    *,
    keys_dir: Path | None = None,
    routes: bool = False,
    **env_values: str,
) -> Iterator[TestClient]:
    """Run the real lifespan against *data*; yield a client while it runs.

    *keys_dir*: the persistence (keys.json) directory, when it is not
    *data*.  *routes*: mount the middleware and routers, for HTTP checks.
    BRIDGE_MASTER_KEY and BRIDGE_ADMIN_PASSWORD default to fixed values so
    no master_key.txt or admin password file is written.
    """
    app = FastAPI(lifespan=lifespan)
    if routes:
        app_module._register_middleware(app)
        app_module._mount_routers(app)
    env = _lifespan_env(data)
    env.update(
        {
            "BRIDGE_ENV": "",
            "BRIDGE_MODE": "",
            "BRIDGE_MASTER_KEY": "p-app-lifespan-master-key-0123456789",
            "BRIDGE_LOCAL_NODE_KEY": "",
            "BRIDGE_LOCAL_NODE_ID": "local-edge",
            "BRIDGE_ADMIN_USER": "admin",
            "BRIDGE_ADMIN_PASSWORD": _ADMIN_PASSWORD,
            "BRIDGE_ALLOW_UNBOUND_NODE_KEYS": "",
            "BRIDGE_CORS_ORIGINS": "",
            "UC_PROXY_SECRET": "",
        }
    )
    env.update(env_values)
    with (
        patch.dict(os.environ, env),
        _patch_data_paths(data),
        _patch_persistence_dir(keys_dir or data),
        _patch_detection_store(data),
        _patch_iq_store(data),
        _patch_pcap_store(data),
    ):
        with TestClient(app) as client:
            yield client


def _start(data: Path, **env_values: str) -> None:
    with _booted(data, **env_values):
        pass


def _keys_json(keys_dir: Path) -> dict:
    return json.loads((keys_dir / "keys.json").read_text())["keys"]


def _production(**overrides: str) -> dict[str, str]:
    env = {
        "BRIDGE_ENV": "production",
        # conftest turns CSRF off for the suite; production refuses that.
        "BRIDGE_CSRF": "",
        "BRIDGE_MFA_KEY": Fernet.generate_key().decode(),
        "BRIDGE_AUDIT_KEY": secrets.token_urlsafe(32),
        "UC_PROXY_SECRET": secrets.token_urlsafe(32),
        "BRIDGE_MASTER_KEY": secrets.token_urlsafe(32),
    }
    env.update(overrides)
    return env


# ---------------------------------------------------------------------------
# Production refusals
# ---------------------------------------------------------------------------


class TestProductionRefusals:
    def test_starts_when_every_secret_is_set(self, data):
        env = _production()
        with _booted(data, **env) as client:
            stored = client.app.state.persistence.get_key_store()["master"]
            assert verify_credential(env["BRIDGE_MASTER_KEY"], *stored)

    @pytest.mark.parametrize("secret", ["", "uppercrust-internal"])
    def test_a_missing_or_default_proxy_secret_is_refused(self, data, secret):
        with pytest.raises(RuntimeError, match="strong UC_PROXY_SECRET"):
            _start(data, **_production(UC_PROXY_SECRET=secret))
        # Refused before the key store is opened.
        assert not (data / "keys.json").exists()

    def test_a_missing_master_key_is_refused(self, data):
        with pytest.raises(RuntimeError, match="BRIDGE_MASTER_KEY env var is required"):
            _start(data, **_production(BRIDGE_MASTER_KEY=""))
        # No master key was generated in its place.
        assert "master" not in (
            _keys_json(data) if (data / "keys.json").exists() else {}
        )

    def test_no_users_and_no_admin_password_is_refused(self, data, temp_dir):
        with pytest.raises(RuntimeError, match="BRIDGE_ADMIN_PASSWORD"):
            _start(data, **_production(BRIDGE_ADMIN_PASSWORD=""))
        # Refused before a password is generated or written anywhere.
        assert list(temp_dir.iterdir()) == []

    def test_existing_users_need_no_admin_password(self, data):
        env = _production()
        _start(data, **env)
        # A restart with users in place: the variable is only for seeding.
        with _booted(data, **{**env, "BRIDGE_ADMIN_PASSWORD": ""}) as client:
            store = client.app.state.detection_store
            assert store.verify_password("admin", _ADMIN_PASSWORD)


# ---------------------------------------------------------------------------
# Start-up warnings about weakened node binding
# ---------------------------------------------------------------------------


class TestUnboundNodeKeysWarning:
    _NEEDLE = "BRIDGE_ALLOW_UNBOUND_NODE_KEYS is set"

    def test_the_escape_hatch_is_logged(self, data, caplog):
        _start(data, BRIDGE_ALLOW_UNBOUND_NODE_KEYS="1")
        assert any(
            r.levelname == "WARNING" and self._NEEDLE in r.getMessage()
            for r in caplog.records
        )

    def test_nothing_is_logged_without_it(self, data, caplog):
        _start(data)
        assert self._NEEDLE not in caplog.text


# ---------------------------------------------------------------------------
# BRIDGE_LOCAL_NODE_KEY
# ---------------------------------------------------------------------------


def _heartbeat(client: TestClient, key: str) -> int:
    return client.post(
        "/api/nodes/heartbeat",
        json={"node_id": "local-edge"},
        headers={"X-API-Key": key},
    ).status_code


class TestLocalNodeKey:
    def test_rotating_it_revokes_the_old_value(self, data):
        old, new = generate_api_key(32), generate_api_key(32)
        with _booted(data, routes=True, BRIDGE_LOCAL_NODE_KEY=old) as client:
            assert _heartbeat(client, old) == 200
        with _booted(data, routes=True, BRIDGE_LOCAL_NODE_KEY=new) as client:
            assert _heartbeat(client, old) == 401
            assert _heartbeat(client, new) == 200
        entry = _keys_json(data)[LOCAL_SCANNER_KEY_ID]
        assert entry["lookup_hash"] == compute_lookup_hash(new)
        assert entry["role"] == "node"

    def test_a_value_another_key_holds_is_refused(self, data):
        _start(data)
        raw = generate_api_key(32)
        hash_hex, salt = hash_credential(raw)
        keys = _keys_json(data)
        keys["operator-key"] = {
            "hash": hash_hex,
            "salt": salt.hex(),
            "lookup_hash": compute_lookup_hash(raw),
            "role": "analyst",
        }
        (data / "keys.json").write_text(json.dumps({"keys": keys}))
        with pytest.raises(
            RuntimeError, match="BRIDGE_LOCAL_NODE_KEY cannot be registered"
        ):
            _start(data, BRIDGE_LOCAL_NODE_KEY=raw)
        after = _keys_json(data)
        # The operator's key is neither taken over nor downgraded to NODE.
        assert after["operator-key"] == keys["operator-key"]
        assert LOCAL_SCANNER_KEY_ID not in after

    def test_a_node_heartbeat_cannot_stop_the_next_start(self, data):
        node_key = generate_api_key(32)
        with _booted(data, routes=True, BRIDGE_LOCAL_NODE_KEY=node_key) as client:
            resp = client.post(
                "/api/nodes/heartbeat",
                json={"node_id": "local-edge", "metrics": {"last_seen": "never"}},
                headers={"X-API-Key": node_key},
            )
            assert resp.status_code == 200
        _start(data, BRIDGE_LOCAL_NODE_KEY=node_key)

    def test_a_saved_node_record_with_bad_values_does_not_stop_the_start(self, data):
        # What a heartbeat could save before its metrics were checked (or a
        # hand edit): the start-up count reads these as nodes of unknown
        # status, and the node listing still answers.
        master = "p-app-lifespan-master-key-0123456789"
        (data / "nodes.json").write_text(
            json.dumps(
                {
                    "nodes": {
                        "old-edge": {
                            "last_seen": "never",
                            "registered_at": 7,
                            "capabilities": "x",
                            "cpu_percent": "high",
                        },
                        "naive-edge": {"last_seen": "2001-01-01T00:00:00"},
                        "future-edge": {"last_seen": "2099-01-01T00:00:00+00:00"},
                        "recent-edge": {
                            "last_seen": datetime.now(timezone.utc).isoformat()
                        },
                    }
                }
            )
        )
        with _booted(data, routes=True) as client:
            listing = client.get("/api/nodes/", headers={"X-API-Key": master})
            assert listing.status_code == 200, listing.text
            assert {n["node_id"]: n["status"] for n in listing.json()} == {
                "old-edge": "unknown",
                "naive-edge": "offline",
                "future-edge": "unknown",
                "recent-edge": "active",
            }
            # Only the node really heard from counts as active at start-up.
            assert client.app.state.correlator._total_active_nodes == 1

    def test_a_saved_node_with_a_bad_position_does_not_stop_tdoa(self, data):
        # The lifespan's TDOA callback reads every node's position. One
        # record saved with a latitude or position that is not a number
        # (float("x") raised) used to abort it for every correlated cluster.
        (data / "nodes.json").write_text(
            json.dumps(
                {
                    "nodes": {
                        "geo-a": {"latitude": 10.0, "longitude": 20.0},
                        "geo-b": {"latitude": 10.01, "longitude": 20},
                        "bad-geo": {
                            "latitude": "x",
                            "longitude": 20.0,
                            "position_x": 1.0,
                            "position_y": 1.0,
                        },
                        "far-geo": {"latitude": 91.0, "longitude": 0.0},
                        "bad-xy": {"position_x": "x", "position_y": 1.0},
                        "xy": {"position_x": 3, "position_y": 4.5},
                    }
                }
            )
        )
        with (
            patch(
                "sigrift.providers.adapters.detections_to_observations",
                return_value=[],
            ) as to_observations,
            _booted(data) as client,
        ):
            client.app.state.correlator._tdoa_callback([])
        (call,) = to_observations.call_args_list
        assert call.args[1] == {
            "geo-a": {"lat": 10.0, "lon": 20.0},
            "geo-b": {"lat": 10.01, "lon": 20.0},
            "xy": {"x_m": 3.0, "y_m": 4.5},
        }

    @needs_unprivileged
    def test_an_unwritable_key_store_refuses_to_start(self, tmp_path, data, caplog):
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir()
        _start(data, keys_dir=keys_dir)
        before = (keys_dir / "keys.json").read_bytes()
        os.chmod(keys_dir, 0o500)
        try:
            with pytest.raises(KeyStoreWriteError):
                _start(
                    data,
                    keys_dir=keys_dir,
                    BRIDGE_LOCAL_NODE_KEY=generate_api_key(32),
                )
        finally:
            os.chmod(keys_dir, 0o700)
        assert (keys_dir / "keys.json").read_bytes() == before
        assert "Refusing to start: BRIDGE_LOCAL_NODE_KEY" in caplog.text


# ---------------------------------------------------------------------------
# Shutdown with BRIDGE_BACKGROUND_TASKS disabled
# ---------------------------------------------------------------------------


def test_shutdown_completes_with_background_tasks_disabled(data):
    _start(data, BRIDGE_BACKGROUND_TASKS="false")


_PERIODIC_TASKS = (
    "_cleanup_task",
    "_stale_resolve_task",
    "_daily_snap_task",
    "_wal_task",
    "_reaper_task",
    "_corr_maint_task",
    "_baseline_save_task",
)


@pytest.mark.parametrize("value", ["false", "0", "no", "disabled"])
def test_disabled_background_tasks_still_get_the_final_save(data, caplog, value):
    caplog.set_level("INFO", logger="sigrift.bridge.app")
    with _booted(data, BRIDGE_BACKGROUND_TASKS=value) as client:
        state = client.app.state
        assert [n for n in _PERIODIC_TASKS if getattr(state, n, None)] == []
        persistence = state.persistence
        persistence.set_node(
            "bg-off-node", {"node_id": "bg-off-node", "status": "offline"}
        )
    # Shutdown ran to its end: the final save and the store close.
    assert persistence._auto_save_task is None
    assert "SigRift bridge stopped" in caplog.text
    with _booted(data, BRIDGE_BACKGROUND_TASKS=value) as client:
        assert "bg-off-node" in client.app.state.persistence.get_nodes()


def test_shutdown_stops_every_periodic_task_before_the_final_save(data):
    with _booted(
        data, BRIDGE_BACKGROUND_TASKS="true", BRIDGE_BASELINE_SAVE_INTERVAL="900"
    ) as client:
        state = client.app.state
        tasks = {name: getattr(state, name, None) for name in _PERIODIC_TASKS}
        # (It ends itself when stopped: done, not cancelled.)
        tasks["materializer"] = state.materializer._task
        assert None not in tasks.values(), tasks
        persistence = state.persistence
        stop_auto_save = persistence.stop_auto_save
        # Still running at the final save, which comes before the baseline
        # saves and the store close: the shutdown must have stopped them
        # by then (the event loop's own end would cancel them, but only
        # after the bridge has closed).
        running_at_final_save: list[str] = []

        async def _final_save() -> None:
            running_at_final_save.extend(n for n, t in tasks.items() if not t.done())
            await stop_auto_save()

        persistence.stop_auto_save = _final_save
        assert not any(t.done() for t in tasks.values())
    assert running_at_final_save == []
    assert all(tasks[name].cancelled() for name in _PERIODIC_TASKS)


# ---------------------------------------------------------------------------
# Generated admin password file (SEC-M18)
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """tempfile.gettempdir() for the test: the file never lands in /tmp."""
    d = tmp_path / "tmp"
    d.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(d))
    return d


@pytest.fixture
def permissive_umask() -> Iterator[None]:
    """umask 022, so a file is only owner-only when the bridge makes it so.

    Under a 077 umask the file would be created 0600 even without the
    bridge's chmod, and the mode check would prove nothing.
    """
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


class TestAdminPasswordFile:
    def test_it_is_owner_only_and_removed_on_shutdown(
        self, data, temp_dir, permissive_umask
    ):
        pw_file = temp_dir / _PW_FILE_NAME
        with _booted(data, BRIDGE_ADMIN_PASSWORD="") as client:
            assert stat.S_IMODE(pw_file.stat().st_mode) == 0o600
            lines = dict(
                line.split(": ", 1) for line in pw_file.read_text().splitlines()
            )
            assert lines["username"] == "admin"
            store = client.app.state.detection_store
            assert store.verify_password("admin", lines["password"])
            assert store.users.get_user("admin")["must_change_password"] is True
        assert not pw_file.exists()

    def test_a_write_failure_still_leaves_a_must_change_admin(
        self, data, tmp_path, monkeypatch, caplog
    ):
        missing = tmp_path / "no-such-dir"
        monkeypatch.setattr(tempfile, "tempdir", str(missing))
        with _booted(data, BRIDGE_ADMIN_PASSWORD="") as client:
            user = client.app.state.detection_store.users.get_user("admin")
            assert user is not None
            assert user["must_change_password"] is True
        assert "Could not write admin password file" in caplog.text
        assert not missing.exists()

    @pytest.mark.parametrize("step", ["fchmod", "write"])
    def test_a_failed_write_leaves_no_partial_file(self, tmp_path, monkeypatch, step):
        # The file was created, then making it 0600 or writing the password
        # failed (EPERM, ENOSPC): the half-made file is removed, as nothing
        # else would delete it (after a failed write the lifespan forgets
        # the name, so the 60 s auto-delete and the shutdown skip it).
        path = tmp_path / _PW_FILE_NAME
        fds: list[int] = []
        fchmod = os.fchmod
        fdopen = os.fdopen

        def failing_fchmod(fd: int, mode: int) -> None:
            fds.append(fd)
            if step == "fchmod":
                raise OSError(errno.EPERM, "Operation not permitted")
            fchmod(fd, mode)

        class _FullDisk:
            def __init__(self, fh) -> None:
                self._fh = fh

            def __enter__(self):
                return self

            def __exit__(self, *exc) -> None:
                self._fh.close()

            def write(self, text: str) -> int:
                # Part of it reached the file before the disk was full.
                self._fh.write(text[:12])
                self._fh.flush()
                raise OSError(errno.ENOSPC, "No space left on device")

        with monkeypatch.context() as mp:
            mp.setattr(os, "fchmod", failing_fchmod)
            mp.setattr(os, "fdopen", lambda *a, **k: _FullDisk(fdopen(*a, **k)))
            with pytest.raises(OSError) as raised:
                app_module._write_owner_only_file(
                    path, "username: admin\npassword: x\n"
                )
        expected = errno.EPERM if step == "fchmod" else errno.ENOSPC
        assert raised.value.errno == expected
        assert not os.path.lexists(path)
        # The descriptor was closed too, not leaked.
        (fd,) = fds
        with pytest.raises(OSError) as closed:
            os.fstat(fd)
        assert closed.value.errno == errno.EBADF

    def test_a_supplied_password_writes_no_file(self, data, temp_dir):
        with _booted(data) as client:
            store = client.app.state.detection_store
            assert store.verify_password("admin", _ADMIN_PASSWORD)
            assert store.users.get_user("admin")["must_change_password"] is False
            assert not (temp_dir / _PW_FILE_NAME).exists()

    @pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
    def test_a_planted_symlink_does_not_receive_the_password(
        self, data, temp_dir, tmp_path
    ):
        captured = tmp_path / "captured"
        (temp_dir / _PW_FILE_NAME).symlink_to(captured)
        _start(data, BRIDGE_ADMIN_PASSWORD="")
        assert not captured.exists() or "password:" not in captured.read_text()

    @pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
    def test_a_planted_symlink_to_an_existing_file_is_not_followed(
        self, data, temp_dir, tmp_path, permissive_umask
    ):
        target = tmp_path / "readable-by-the-planter"
        target.write_text("planted\n")
        target.chmod(0o644)
        pw_file = temp_dir / _PW_FILE_NAME
        pw_file.symlink_to(target)
        with _booted(data, BRIDGE_ADMIN_PASSWORD=""):
            # The link was replaced by the bridge's own owner-only file.
            assert not pw_file.is_symlink()
            assert stat.S_IMODE(pw_file.lstat().st_mode) == 0o600
            assert "password: " in pw_file.read_text()
        assert target.read_text() == "planted\n"
        assert stat.S_IMODE(target.stat().st_mode) == 0o644

    @pytest.mark.skipif(not hasattr(os, "link"), reason="needs hard links")
    def test_a_planted_file_is_replaced_not_written_into(
        self, data, temp_dir, tmp_path, permissive_umask
    ):
        # The planter keeps a second name for the file it planted (or a
        # file an earlier run left): the password never reaches that inode.
        pw_file = temp_dir / _PW_FILE_NAME
        pw_file.write_text("planted\n")
        pw_file.chmod(0o666)
        handle = tmp_path / "planter-handle"
        os.link(pw_file, handle)
        with _booted(data, BRIDGE_ADMIN_PASSWORD="") as client:
            assert not os.path.samefile(pw_file, handle)
            assert stat.S_IMODE(pw_file.stat().st_mode) == 0o600
            lines = dict(
                line.split(": ", 1) for line in pw_file.read_text().splitlines()
            )
            store = client.app.state.detection_store
            assert store.verify_password("admin", lines["password"])
        assert handle.read_text() == "planted\n"
        assert not pw_file.exists()

    def test_an_entry_that_cannot_be_replaced_gets_no_password(
        self, data, temp_dir, caplog
    ):
        # A directory at the name (as for another user's file in a sticky
        # /tmp, the bridge cannot remove it): nothing is written.
        blocker = temp_dir / _PW_FILE_NAME
        blocker.mkdir()
        with _booted(data, BRIDGE_ADMIN_PASSWORD="") as client:
            user = client.app.state.detection_store.users.get_user("admin")
            assert user["must_change_password"] is True
        assert "Could not write admin password file" in caplog.text
        assert blocker.is_dir() and list(blocker.iterdir()) == []
