"""Real filesystem proof that canonical aliases must not consume directories."""

from pathlib import Path

import pytest

import test_quickstart_model_download as download_tests
from test_quickstart_model_download import (
    METADATA,
    META_NAME,
    MODEL,
    MODEL_NAME,
    run_model_block,
)

release_server = download_tests.release_server


@pytest.mark.parametrize("mode", ["download", "local"])
@pytest.mark.parametrize("kind", ["directory", "directory-symlink"])
@pytest.mark.parametrize("alias", ["open-default.onnx", "open-default_metadata.json"])
def test_existing_directory_alias_is_preserved_without_false_activation(
    tmp_path, release_server, mode, kind, alias
):
    models = tmp_path / "models"
    models.mkdir()
    target = models / alias if kind == "directory" else tmp_path / "operator-data"
    target.mkdir()
    sentinel = target / "keep.txt"
    sentinel.write_bytes(b"operator-owned content\n")
    if kind == "directory-symlink":
        (models / alias).symlink_to(target, target_is_directory=True)
    if mode == "local":
        (models / MODEL_NAME).write_bytes(MODEL)
        (models / META_NAME).write_bytes(METADATA)

    result = run_model_block(tmp_path, release_server)

    assert "Active model:" not in result.stdout
    assert set(target.iterdir()) == {sentinel}
    assert sentinel.read_bytes() == b"operator-owned content\n"
    if kind == "directory-symlink":
        assert (models / alias).readlink() == Path(target)


def test_metadata_directory_conflict_preserves_the_existing_model_alias(
    tmp_path, release_server
):
    models = tmp_path / "models"
    models.mkdir()
    (models / MODEL_NAME).write_bytes(MODEL)
    (models / META_NAME).write_bytes(METADATA)
    # An existing alias target is intentionally not another discoverable .onnx.
    (models / "previous-model").write_bytes(b"previous complete model")
    (models / "open-default.onnx").symlink_to("previous-model")
    (models / "open-default_metadata.json").mkdir()

    result = run_model_block(tmp_path, release_server)

    assert result.returncode != 0
    assert "Active model:" not in result.stdout
    assert (models / "open-default.onnx").readlink() == Path("previous-model")
    assert (models / "previous-model").read_bytes() == b"previous complete model"
    assert not list((models / "open-default_metadata.json").iterdir())


@pytest.mark.parametrize("metadata", [False, True])
def test_canonical_named_release_assets_remain_regular_complete_files(
    tmp_path, release_server, monkeypatch, metadata
):
    monkeypatch.setattr(download_tests, "MODEL_NAME", "open-default.onnx")
    monkeypatch.setattr(download_tests, "META_NAME", "open-default_metadata.json")
    release_server.metadata = metadata

    result = run_model_block(tmp_path, release_server)

    if not metadata:
        # Without its class names the model is not even downloaded.
        assert result.returncode == 1
        assert "has no open-default_metadata.json asset" in result.stderr
        assert not (tmp_path / "models/open-default.onnx").exists()
        return
    assert result.returncode == 0
    model = tmp_path / "models/open-default.onnx"
    assert model.is_file() and not model.is_symlink()
    assert model.read_bytes() == MODEL
    sidecar = tmp_path / "models/open-default_metadata.json"
    assert sidecar.is_file() and not sidecar.is_symlink()
    assert sidecar.read_bytes() == METADATA
    assert "Active model: open-default.onnx" in result.stdout


def test_current_model_gains_its_metadata_alias_once_the_sidecar_appears(
    tmp_path, release_server
):
    models = tmp_path / "models"
    models.mkdir()
    (models / MODEL_NAME).write_bytes(MODEL)
    (models / "open-default.onnx").symlink_to(MODEL_NAME)
    # The sidecar arrived after the model alias was made.
    (models / META_NAME).write_bytes(METADATA)

    result = run_model_block(tmp_path, release_server)

    assert result.returncode == 0
    assert f"Using model: {MODEL_NAME}" in result.stdout
    assert (models / "open-default.onnx").readlink() == Path(MODEL_NAME)
    assert (models / "open-default_metadata.json").readlink() == Path(META_NAME)


def test_switching_to_a_newer_model_without_a_sidecar_fails_and_keeps_both_aliases(
    tmp_path, release_server
):
    import os

    models = tmp_path / "models"
    models.mkdir()
    (models / MODEL_NAME).write_bytes(MODEL)
    (models / META_NAME).write_bytes(METADATA)
    # Set the aliases up in a legacy run; the managed slice would go on to
    # scanner setup, which this harness does not provide.
    assert run_model_block(tmp_path, release_server).returncode == 0

    newer = models / "operator-model.onnx"
    newer.write_bytes(b"operator model without a sidecar")
    stamp = (models / MODEL_NAME).stat().st_mtime + 60
    os.utime(newer, (stamp, stamp))
    result = run_model_block(tmp_path, release_server, managed=True)

    assert result.returncode == 1
    assert "models/operator-model.onnx has no models/operator-model_metadata.json" in (
        result.stderr
    )
    assert (models / "open-default.onnx").readlink() == Path(MODEL_NAME)
    assert (models / "open-default_metadata.json").readlink() == Path(META_NAME)
    assert (models / META_NAME).read_bytes() == METADATA


def test_unmanaged_switch_to_a_model_without_a_sidecar_drops_the_stale_metadata_alias(
    tmp_path, release_server
):
    import os

    models = tmp_path / "models"
    models.mkdir()
    (models / MODEL_NAME).write_bytes(MODEL)
    (models / META_NAME).write_bytes(METADATA)
    assert run_model_block(tmp_path, release_server).returncode == 0
    assert (models / "open-default_metadata.json").readlink() == Path(META_NAME)

    # A legacy install is only warned, so the newer model becomes active.
    # The alias must not keep naming the previous model's class list.
    newer = models / "operator-model.onnx"
    newer.write_bytes(b"operator model without a sidecar")
    stamp = (models / MODEL_NAME).stat().st_mtime + 60
    os.utime(newer, (stamp, stamp))
    result = run_model_block(tmp_path, release_server)

    assert result.returncode == 0
    assert "WARNING: models/operator-model.onnx has no" in result.stderr
    assert (models / "open-default.onnx").readlink() == Path(newer.name)
    alias = models / "open-default_metadata.json"
    assert not alias.is_symlink() and not alias.exists()
    assert (models / META_NAME).read_bytes() == METADATA


def test_a_real_metadata_file_under_the_canonical_name_is_never_removed(
    tmp_path, release_server
):
    models = tmp_path / "models"
    models.mkdir()
    (models / "operator-model.onnx").write_bytes(b"operator model without a sidecar")
    (models / "open-default_metadata.json").write_bytes(METADATA)

    result = run_model_block(tmp_path, release_server)

    assert result.returncode == 0
    assert (models / "open-default_metadata.json").read_bytes() == METADATA


def test_a_failed_model_alias_keeps_the_stale_metadata_alias(tmp_path, release_server):
    models = tmp_path / "models"
    models.mkdir()
    (models / "previous_metadata.json").write_bytes(METADATA)
    (models / "open-default_metadata.json").symlink_to("previous_metadata.json")
    (models / "operator-model.onnx").write_bytes(b"operator model without a sidecar")
    # The model alias cannot be replaced, so nothing else may change.
    (models / "open-default.onnx").mkdir()

    result = run_model_block(tmp_path, release_server)

    assert result.returncode != 0
    assert (models / "open-default_metadata.json").readlink() == Path(
        "previous_metadata.json"
    )
