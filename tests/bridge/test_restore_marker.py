"""The bridge refuses to start on a volume whose restore did not finish.

``install-release.sh`` / ``quickstart.sh`` put ``.sigrift-restore-incomplete``
at the root of each volume they restore and remove it when the restore is
complete.  While one exists in bridge_data or bridge_secrets the bridge's
lifespan refuses before it touches either volume, with one log line that
names the file and the next step, and ``python3 -m sigrift.bridge.ca
migrate-key`` (run before uvicorn by the image CMD) leaves the CA files
alone.  The bridge never reads, creates or removes the marker.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from sigrift.bridge import ca, persistence, restore_marker
from sigrift.bridge.restore_marker import (
    RESTORE_MARKER_NAME,
    RestoreIncompleteError,
    check_restore_markers,
    find_restore_marker,
    restore_incomplete_message,
)
from sigrift.bridge.storage import base

from .test_lifespan import (
    _lifespan_env,
    _make_app_with_lifespan,
    _patch_data_paths,
    _patch_detection_store,
    _patch_iq_store,
    _patch_pcap_store,
    _patch_persistence_dir,
)


@pytest.fixture
def volumes(tmp_path: Path) -> tuple[Path, Path]:
    data, secrets = tmp_path / "data", tmp_path / "secrets"
    data.mkdir()
    secrets.mkdir()
    return data, secrets


def test_no_marker_starts(volumes) -> None:
    data, secrets = volumes
    assert find_restore_marker(data, secrets) is None
    check_restore_markers(data, secrets)  # no exception


def test_a_marker_in_bridge_data_refuses_with_one_line_naming_it_and_the_next_step(
    volumes, caplog: pytest.LogCaptureFixture
) -> None:
    data, secrets = volumes
    marker = data / RESTORE_MARKER_NAME
    marker.write_text("restore 2026-11-27T10:00:00Z\n")
    with caplog.at_level(logging.DEBUG, logger="sigrift.bridge.restore_marker"):
        with pytest.raises(RestoreIncompleteError) as refused:
            check_restore_markers(data, secrets)
    message = str(refused.value)
    assert message == (
        f"FATAL: restore incomplete — refusing to start: {marker} exists, so a "
        "restore of this volume by install-release.sh or quickstart.sh did not "
        "finish and its files may be half replaced. Next step: in the install "
        "folder run 'bash install-release.sh --status' (source checkout: "
        "'scripts/quickstart.sh --status') and follow it (--resume or --abort). "
        f"Remove {marker} by hand only if you restored the volume yourself and "
        "know it is complete."
    )
    assert message == restore_incomplete_message(marker)
    assert "--status" in message and str(marker) in message
    assert "\n" not in message
    assert isinstance(refused.value, RuntimeError)
    [record] = caplog.records
    assert record.levelno == logging.CRITICAL
    assert record.getMessage() == message


def test_a_marker_in_bridge_secrets_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "data"
    data.mkdir()
    secrets = tmp_path / "elsewhere" / "secrets"
    secrets.mkdir(parents=True)
    (secrets / RESTORE_MARKER_NAME).touch()
    monkeypatch.setenv("BRIDGE_SECRETS_DIR", str(secrets))
    assert find_restore_marker(data) == secrets / RESTORE_MARKER_NAME
    with pytest.raises(RestoreIncompleteError, match="restore incomplete"):
        check_restore_markers(data)


def test_without_bridge_secrets_dir_the_secrets_dir_is_next_to_the_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("BRIDGE_SECRETS_DIR", raising=False)
    data = tmp_path / "data"
    data.mkdir()
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / RESTORE_MARKER_NAME).touch()
    assert find_restore_marker(data) == tmp_path / "secrets" / RESTORE_MARKER_NAME


@pytest.mark.parametrize("kind", ["file", "directory", "dangling-symlink", "mode-000"])
def test_any_entry_counts(volumes, kind: str) -> None:
    data, secrets = volumes
    marker = data / RESTORE_MARKER_NAME
    if kind == "file":
        marker.write_text("")
    elif kind == "directory":
        marker.mkdir()
    elif kind == "dangling-symlink":
        marker.symlink_to(data / "gone")
        assert not marker.exists()
    else:
        marker.write_text("x")
        marker.chmod(0)
    try:
        with pytest.raises(RestoreIncompleteError):
            check_restore_markers(data, secrets)
    finally:
        if kind == "mode-000":
            marker.chmod(0o600)


def test_the_marker_is_never_read_or_removed(volumes) -> None:
    data, secrets = volumes
    marker = data / RESTORE_MARKER_NAME
    marker.write_text("journal: step 4 of 7\n")
    os.utime(marker, (1_700_000_000, 1_700_000_000))
    before = marker.stat()
    for _ in range(2):
        with pytest.raises(RestoreIncompleteError):
            check_restore_markers(data, secrets)
    after = marker.stat()
    assert marker.read_text() == "journal: step 4 of 7\n"
    assert (after.st_mtime, after.st_atime) == (before.st_mtime, before.st_atime)
    assert sorted(p.name for p in data.iterdir()) == [RESTORE_MARKER_NAME]
    assert list(secrets.iterdir()) == []


def test_the_default_is_the_bridge_data_dir() -> None:
    assert (
        restore_marker.DEFAULT_DATA_DIR
        == persistence._DEFAULT_DATA_DIR
        == base._DEFAULT_DB_PATH.parent
        == ca._DEFAULT_DATA_DIR
    )


def test_the_lifespan_refuses_before_touching_the_volumes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_data_dir = tmp_path / "data"
    tmp_data_dir.mkdir()
    marker = tmp_data_dir / RESTORE_MARKER_NAME
    marker.write_text("")
    monkeypatch.setattr(restore_marker, "DEFAULT_DATA_DIR", tmp_data_dir)
    monkeypatch.setenv("BRIDGE_SECRETS_DIR", str(tmp_path / "secrets"))
    app = _make_app_with_lifespan()
    with (
        patch.dict(os.environ, _lifespan_env(tmp_data_dir)),
        _patch_data_paths(tmp_data_dir),
        _patch_persistence_dir(tmp_data_dir) as persistence_manager,
        _patch_detection_store(tmp_data_dir) as detection_store,
        _patch_iq_store(tmp_data_dir),
        _patch_pcap_store(tmp_data_dir),
    ):
        with pytest.raises(RuntimeError, match="restore incomplete"):
            with TestClient(app):
                pass  # pragma: no cover - startup must refuse
        persistence_manager.assert_not_called()
        detection_store.assert_not_called()
    assert marker.exists()
    assert sorted(p.name for p in tmp_data_dir.iterdir()) == [RESTORE_MARKER_NAME]


def test_ca_migrate_key_leaves_a_half_restored_volume_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = tmp_path / "data"
    (data / "ca").mkdir(parents=True)
    key = data / "ca" / "ca.key"
    key.write_bytes(b"placeholder CA key, half restored\n")
    (data / RESTORE_MARKER_NAME).touch()
    secrets = tmp_path / "secrets"
    monkeypatch.setenv("BRIDGE_SECRETS_DIR", str(secrets))
    assert ca._main(["migrate-key", "--data-dir", str(data)]) == 0
    assert key.read_bytes() == b"placeholder CA key, half restored\n"
    assert not secrets.exists() or list(secrets.iterdir()) == []
