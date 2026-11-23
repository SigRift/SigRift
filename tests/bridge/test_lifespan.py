"""Tests for production lifespan startup/shutdown logic.

The test app in conftest.py skips the lifespan and manually wires
dependencies.  These tests exercise the real lifespan context manager
to catch initialization and cleanup bugs.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.app import lifespan


def _make_app_with_lifespan() -> FastAPI:
    """Create a minimal FastAPI app wired to the production lifespan."""
    return FastAPI(title="lifespan-test", lifespan=lifespan)


@pytest.fixture
def tmp_data_dir(tmp_path: Path) -> Path:
    """Isolated data directory for lifespan tests."""
    d = tmp_path / "data"
    d.mkdir()
    return d


def _lifespan_env(tmp_data_dir: Path) -> dict[str, str]:
    """Return env overrides that redirect all file I/O to tmp_data_dir."""
    return {
        "BRIDGE_LOG_LEVEL": "WARNING",
        # Prevent family classifier loading from real path
        "BRIDGE_FAMILY_MODEL": str(tmp_data_dir / "nonexistent_model.pth"),
        "BRIDGE_FINGERPRINT_MODEL": str(tmp_data_dir / "nonexistent_fp.pth"),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _patch_data_paths(tmp_data_dir: Path):
    """Patch module-level paths so lifespan writes to tmp_data_dir."""
    return patch.multiple(
        "sigrift.bridge.app",
        _STATIC_DIR=tmp_data_dir / "static",
        _TEMPLATES_DIR=tmp_data_dir / "templates",
    )


def _patch_persistence_dir(tmp_data_dir: Path):
    """Patch PersistenceManager default data dir."""
    return patch(
        "sigrift.bridge.app.PersistenceManager",
        wraps=_persistence_factory(tmp_data_dir),
    )


def _persistence_factory(tmp_data_dir: Path):
    """Return a PersistenceManager constructor that defaults to tmp_data_dir."""
    from sigrift.bridge.persistence import PersistenceManager as _Real

    class _TmpPersistenceManager(_Real):
        def __init__(self, data_dir=None, auto_save_interval=60.0):
            super().__init__(
                data_dir=data_dir or tmp_data_dir,
                auto_save_interval=auto_save_interval,
            )

    return _TmpPersistenceManager


def _patch_detection_store(tmp_data_dir: Path):
    """Patch DetectionStore to use a temp database."""
    from sigrift.bridge.detection_store import DetectionStore as _Real

    class _TmpDetectionStore(_Real):
        def __init__(self, db_path=None):
            super().__init__(db_path=db_path or (tmp_data_dir / "test.db"))

    return patch("sigrift.bridge.app.DetectionStore", wraps=_TmpDetectionStore)


def _patch_iq_store(tmp_data_dir: Path):
    """Patch IQStore to use a temp directory."""
    from sigrift.bridge.iq_store import IQStore as _Real

    class _TmpIQStore(_Real):
        def __init__(self, base_dir=None):
            super().__init__(base_dir=base_dir or (tmp_data_dir / "iq"))

    return patch("sigrift.bridge.app.IQStore", wraps=_TmpIQStore)


def _patch_pcap_store(tmp_data_dir: Path):
    """Patch PcapStore to use a temp directory."""
    from sigrift.bridge.anomaly.pcap_store import PcapStore as _Real

    class _TmpPcapStore(_Real):
        def __init__(self, base_dir=None):
            super().__init__(base_dir=base_dir or (tmp_data_dir / "pcap"))

    return patch("sigrift.bridge.app.PcapStore", wraps=_TmpPcapStore)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestLifespanStartup:
    """Verify the lifespan initializes all expected state."""

    def test_startup_sets_app_state_attributes(self, tmp_data_dir: Path):
        """After lifespan startup, app.state has all required attributes."""
        app = _make_app_with_lifespan()
        env = _lifespan_env(tmp_data_dir)

        with (
            patch.dict(os.environ, env),
            _patch_data_paths(tmp_data_dir),
            _patch_persistence_dir(tmp_data_dir),
            _patch_detection_store(tmp_data_dir),
            _patch_iq_store(tmp_data_dir),
            _patch_pcap_store(tmp_data_dir),
        ):
            with TestClient(app):
                # Core services
                assert hasattr(app.state, "persistence")
                assert hasattr(app.state, "app_state")
                assert hasattr(app.state, "detection_store")
                assert hasattr(app.state, "iq_store")

                # Anomaly scoring
                assert hasattr(app.state, "rf_scorer")
                assert hasattr(app.state, "rf_baseline_mgr")
                assert hasattr(app.state, "wifi_scorer")
                assert hasattr(app.state, "wifi_baseline_mgr")
                assert hasattr(app.state, "bt_scorer")
                assert hasattr(app.state, "bt_baseline_mgr")
                assert hasattr(app.state, "correlator")

                # Notification and syslog
                assert hasattr(app.state, "notifier")
                assert hasattr(app.state, "syslog_forwarder")

                # IQ / fingerprint / analysis
                assert hasattr(app.state, "iq_metadata_store")
                assert hasattr(app.state, "fingerprint_store")
                assert hasattr(app.state, "fingerprint_service")
                assert hasattr(app.state, "signature_library_store")
                assert hasattr(app.state, "bitstream_store")
                assert hasattr(app.state, "preamble_store")
                assert hasattr(app.state, "packet_store")

                # Geolocation and mapping
                assert hasattr(app.state, "geolocation_store")
                assert hasattr(app.state, "map_store")
                assert hasattr(app.state, "emitter_tracker")
                assert hasattr(app.state, "track_store")
                assert hasattr(app.state, "tdoa_engine")

                # Job queue
                assert hasattr(app.state, "job_queue")

                # Pcap store
                assert hasattr(app.state, "pcap_store")

                # Spectrum
                assert hasattr(app.state, "spectrum_streamer")
                assert hasattr(app.state, "spectrum_poller")

                # WebSocket limiter
                assert hasattr(app.state, "ws_limiter")

                # Detection config
                assert hasattr(app.state, "detection_config")

    def test_startup_creates_persistence_manager(self, tmp_data_dir: Path):
        """PersistenceManager is created with auto-save running."""
        app = _make_app_with_lifespan()
        env = _lifespan_env(tmp_data_dir)

        with (
            patch.dict(os.environ, env),
            _patch_data_paths(tmp_data_dir),
            _patch_persistence_dir(tmp_data_dir),
            _patch_detection_store(tmp_data_dir),
            _patch_iq_store(tmp_data_dir),
            _patch_pcap_store(tmp_data_dir),
        ):
            with TestClient(app):
                pm = app.state.persistence
                assert pm._auto_save_task is not None
                assert hasattr(pm._auto_save_task, 'done')
                assert not pm._auto_save_task.done()

    def test_startup_creates_detection_store(self, tmp_data_dir: Path):
        """DetectionStore is created and accessible."""
        app = _make_app_with_lifespan()
        env = _lifespan_env(tmp_data_dir)

        with (
            patch.dict(os.environ, env),
            _patch_data_paths(tmp_data_dir),
            _patch_persistence_dir(tmp_data_dir),
            _patch_detection_store(tmp_data_dir),
            _patch_iq_store(tmp_data_dir),
            _patch_pcap_store(tmp_data_dir),
        ):
            with TestClient(app):
                ds = app.state.detection_store
                # Should be able to get a connection
                conn = ds.get_connection()
                assert conn is not None
                assert hasattr(conn, 'execute')


class TestLifespanMasterKey:
    """Verify master key generation and handling during lifespan."""

    def test_generates_master_key_when_empty(self, tmp_data_dir: Path):
        """When no keys exist, lifespan generates an initial master key."""
        app = _make_app_with_lifespan()
        env = _lifespan_env(tmp_data_dir)

        with (
            patch.dict(os.environ, env),
            _patch_data_paths(tmp_data_dir),
            _patch_persistence_dir(tmp_data_dir),
            _patch_detection_store(tmp_data_dir),
            _patch_iq_store(tmp_data_dir),
            _patch_pcap_store(tmp_data_dir),
        ):
            with TestClient(app):
                pm = app.state.persistence
                key_store = pm.get_key_store()
                assert "master" in key_store
                assert isinstance(key_store["master"], (list, tuple))
                # Key entry should have a hash and salt
                entry = key_store["master"]
                assert len(entry) >= 2
                assert isinstance(entry[0], str) and len(entry[0]) > 0
                assert isinstance(entry[1], (str, bytes)) and len(entry[1]) > 0

    def test_master_key_generated_no_file(self, tmp_data_dir: Path):
        """When no env var is set, a master key is generated but NOT written to disk."""
        app = _make_app_with_lifespan()
        env = _lifespan_env(tmp_data_dir)
        # Ensure no env key is set
        env["BRIDGE_MASTER_KEY"] = ""

        from sigrift.bridge.app import _STATIC_DIR
        prod_key_file = _STATIC_DIR.parent / "data" / ".master_key"
        had_key_before = prod_key_file.exists()

        with (
            patch.dict(os.environ, env),
            _patch_data_paths(tmp_data_dir),
            _patch_persistence_dir(tmp_data_dir),
            _patch_detection_store(tmp_data_dir),
            _patch_iq_store(tmp_data_dir),
            _patch_pcap_store(tmp_data_dir),
        ):
            with TestClient(app):
                pm = app.state.persistence
                key_store = pm.get_key_store()
                assert "master" in key_store
                assert isinstance(key_store["master"], (list, tuple))
                # Key entry should have a hash and salt
                entry = key_store["master"]
                assert isinstance(entry[0], str) and len(entry[0]) > 0
                assert isinstance(entry[1], (str, bytes)) and len(entry[1]) > 0
                # No new key file should have been created
                if not had_key_before:
                    assert not prod_key_file.exists()

    def test_master_key_from_env_var(self, tmp_data_dir: Path):
        """When BRIDGE_MASTER_KEY is set, it is used instead of generating."""
        app = _make_app_with_lifespan()
        env = _lifespan_env(tmp_data_dir)
        test_key = "test-env-master-key-1234567890"
        env["BRIDGE_MASTER_KEY"] = test_key

        with (
            patch.dict(os.environ, env),
            _patch_data_paths(tmp_data_dir),
            _patch_persistence_dir(tmp_data_dir),
            _patch_detection_store(tmp_data_dir),
            _patch_iq_store(tmp_data_dir),
            _patch_pcap_store(tmp_data_dir),
        ):
            with TestClient(app):
                pm = app.state.persistence
                key_store = pm.get_key_store()
                assert "master" in key_store
                assert isinstance(key_store["master"], (list, tuple))

                # Verify the env key was actually used (can be verified)
                from sigrift.lib.security.credentials import verify_credential
                stored_hash, stored_salt = key_store["master"][0], key_store["master"][1]
                assert verify_credential(test_key, stored_hash, stored_salt)

    def test_production_mode_requires_security_keys(self, tmp_data_dir: Path):
        """When BRIDGE_ENV=production and no MFA/audit keys, startup fails."""
        app = _make_app_with_lifespan()
        env = _lifespan_env(tmp_data_dir)
        env["BRIDGE_ENV"] = "production"
        env["BRIDGE_MFA_KEY"] = ""
        env["BRIDGE_AUDIT_KEY"] = ""
        env["BRIDGE_MASTER_KEY"] = ""
        # The suite turns CSRF off (conftest.py), which production refuses.
        env["BRIDGE_CSRF"] = ""

        with (
            patch.dict(os.environ, env),
            _patch_data_paths(tmp_data_dir),
            _patch_persistence_dir(tmp_data_dir),
            _patch_detection_store(tmp_data_dir),
            _patch_iq_store(tmp_data_dir),
            _patch_pcap_store(tmp_data_dir),
        ):
            with pytest.raises(RuntimeError, match="BRIDGE_MFA_KEY"):
                with TestClient(app):
                    pass


class TestLifespanShutdown:
    """Verify lifespan shutdown properly cleans up resources."""

    def test_auto_save_stopped_after_shutdown(self, tmp_data_dir: Path):
        """Auto-save task is stopped when the lifespan exits."""
        app = _make_app_with_lifespan()
        env = _lifespan_env(tmp_data_dir)

        with (
            patch.dict(os.environ, env),
            _patch_data_paths(tmp_data_dir),
            _patch_persistence_dir(tmp_data_dir),
            _patch_detection_store(tmp_data_dir),
            _patch_iq_store(tmp_data_dir),
            _patch_pcap_store(tmp_data_dir),
        ):
            with TestClient(app) as _client:
                pm = app.state.persistence
                # During startup, auto-save should be running
                assert pm._auto_save_task is not None
                assert hasattr(pm._auto_save_task, 'done')

            # After exiting the context, auto-save should be stopped
            assert pm._auto_save_task is None

    def test_background_tasks_cancelled_after_shutdown(self, tmp_data_dir: Path):
        """Background cleanup and WAL tasks are cancelled on shutdown."""
        app = _make_app_with_lifespan()
        env = _lifespan_env(tmp_data_dir)

        with (
            patch.dict(os.environ, env),
            _patch_data_paths(tmp_data_dir),
            _patch_persistence_dir(tmp_data_dir),
            _patch_detection_store(tmp_data_dir),
            _patch_iq_store(tmp_data_dir),
            _patch_pcap_store(tmp_data_dir),
        ):
            with TestClient(app) as _client:
                cleanup_task = app.state._cleanup_task
                wal_task = app.state._wal_task
                daily_snap_task = app.state._daily_snap_task
                assert not cleanup_task.done()
                assert not wal_task.done()
                assert not daily_snap_task.done()

            # After shutdown all background tasks should be cancelled
            assert cleanup_task.done()
            assert wal_task.done()
            assert daily_snap_task.done()


class TestLifespanAdminUser:
    """Verify default admin user seeding during lifespan."""

    def test_seeds_default_admin_user(self, tmp_data_dir: Path):
        """When users table is empty, lifespan creates a default admin user."""
        app = _make_app_with_lifespan()
        env = _lifespan_env(tmp_data_dir)
        env["BRIDGE_ADMIN_USER"] = "testadmin"
        env["BRIDGE_ADMIN_PASSWORD"] = "testpass123"

        with (
            patch.dict(os.environ, env),
            _patch_data_paths(tmp_data_dir),
            _patch_persistence_dir(tmp_data_dir),
            _patch_detection_store(tmp_data_dir),
            _patch_iq_store(tmp_data_dir),
            _patch_pcap_store(tmp_data_dir),
        ):
            with TestClient(app):
                ds = app.state.detection_store
                # Admin user should have been created
                user = ds.get_user("testadmin")
                assert user is not None
                assert isinstance(user, dict)
                assert user["role"] == "admin"


class TestLifespanJobQueue:
    """Verify job queue initialization during lifespan."""

    def test_job_queue_started(self, tmp_data_dir: Path):
        """Job queue is started and has registered handlers."""
        app = _make_app_with_lifespan()
        env = _lifespan_env(tmp_data_dir)

        with (
            patch.dict(os.environ, env),
            _patch_data_paths(tmp_data_dir),
            _patch_persistence_dir(tmp_data_dir),
            _patch_detection_store(tmp_data_dir),
            _patch_iq_store(tmp_data_dir),
            _patch_pcap_store(tmp_data_dir),
        ):
            with TestClient(app):
                jq = app.state.job_queue
                assert "spectrogram" in jq._handlers
                # fingerprint handler is conditionally registered based on license tier


# ---------------------------------------------------------------------------
# SEC-M18: Admin password temp file must land outside the shared data dir
# ---------------------------------------------------------------------------


class TestAdminPasswordFileLocation:
    """Regression guard: the auto-generated admin password file goes into
    /tmp (container-local), NOT into the bridge data directory (which is
    a shared docker volume that the gateway container also mounts).

    See SEC-M18 + SECURITY.md § "Data volume isolation" for context.
    """

    def test_password_file_not_in_data_dir(self, tmp_data_dir: Path):
        """Running lifespan with no admin user must not write a
        password file into the data directory."""
        import tempfile as _tempfile

        app = _make_app_with_lifespan()
        env = _lifespan_env(tmp_data_dir)
        # Explicitly unset BRIDGE_ADMIN_PASSWORD so the auto-gen path
        # fires — that's the path the test exercises.
        env.pop("BRIDGE_ADMIN_PASSWORD", None)

        with (
            patch.dict(os.environ, env, clear=False),
            _patch_data_paths(tmp_data_dir),
            _patch_persistence_dir(tmp_data_dir),
            _patch_detection_store(tmp_data_dir),
            _patch_iq_store(tmp_data_dir),
            _patch_pcap_store(tmp_data_dir),
        ):
            os.environ.pop("BRIDGE_ADMIN_PASSWORD", None)
            with TestClient(app):
                # Must NOT have been written to the data dir
                assert not (tmp_data_dir / ".admin_password").exists(), (
                    "admin password file leaked into shared data dir "
                    "— this is the bug SEC-M18 fixed"
                )
                # The real file lives in /tmp under tempfile.gettempdir().
                # We don't assert its presence here (it may have been
                # auto-deleted by the 60s cleanup task already, and the
                # path isn't deterministic under parallel xdist workers).
                # The negative assertion above is the meaningful one.
                _ = _tempfile.gettempdir()  # noqa: F841 (documents intent)
