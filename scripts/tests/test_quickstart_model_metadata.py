"""The model's metadata sidecar is required: no labels, no activated model.

These drive the shipped quickstart model block against the same loopback
release server as test_quickstart_model_download.py.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import test_quickstart_model_download as transfers
from test_quickstart_model_download import (
    METADATA,
    META_NAME,
    MODEL,
    MODEL_NAME,
    run_model_block,
)

release_server = transfers.release_server
pytestmark = transfers.pytestmark

REFUSED = "selected SDR requires a model; no scanner was started"


def assert_nothing_activated(models):
    assert not list(models.glob("*.onnx"))
    assert not (models / "open-default.onnx").is_symlink()
    assert not (models / "SHA256SUMS").exists()
    assert not list(models.glob(".model-download.*"))


def test_failed_metadata_download_refuses_model_then_retry_activates_both(
    tmp_path, release_server
):
    release_server.truncate_metadata = 1
    first = run_model_block(tmp_path, release_server)
    models = tmp_path / "models"
    assert first.returncode == 1
    assert REFUSED in first.stderr
    assert f"without {META_NAME}, so {MODEL_NAME} was not activated" in first.stderr
    assert not (models / META_NAME).exists()
    assert_nothing_activated(models)

    second = run_model_block(tmp_path, release_server)
    assert second.returncode == 0
    assert (models / "open-default.onnx").readlink() == Path(MODEL_NAME)
    assert (models / "open-default_metadata.json").read_bytes() == METADATA


def test_failed_metadata_publish_refuses_model_and_keeps_destination(
    tmp_path, release_server
):
    models = tmp_path / "models"
    (models / META_NAME).mkdir(parents=True)
    (models / META_NAME / "operator-owned").write_bytes(b"preserved")
    result = run_model_block(tmp_path, release_server)
    assert result.returncode == 1
    assert f"Could not publish {META_NAME}" in result.stderr
    assert f"so {MODEL_NAME} was not activated" in result.stderr
    assert list((models / META_NAME).iterdir()) == [models / META_NAME / "operator-owned"]
    assert_nothing_activated(models)


@pytest.mark.parametrize("previous", [None, b'{"classes": ["older release"]}\n'])
def test_failed_model_publish_rolls_back_the_new_sidecar(
    tmp_path, release_server, previous
):
    models = tmp_path / "models"
    (models / MODEL_NAME).mkdir(parents=True)
    if previous is not None:
        (models / META_NAME).write_bytes(previous)
    result = run_model_block(tmp_path, release_server, discover=False)
    assert result.returncode == 1
    assert "Could not publish completed model" in result.stderr
    if previous is None:
        assert not (models / META_NAME).exists()  # No orphaned sidecar.
    else:
        assert (models / META_NAME).read_bytes() == previous
    assert list((models / MODEL_NAME).iterdir()) == []
    assert not (models / "open-default.onnx").is_symlink()
    assert not list(models.glob(".model-download.*"))


def test_release_without_metadata_asset_refuses_before_downloading(
    tmp_path, release_server
):
    release_server.metadata = False
    result = run_model_block(tmp_path, release_server)
    assert result.returncode == 1
    assert f"has no {META_NAME} asset" in result.stderr
    assert "cannot\n    label detections without it" in result.stderr
    assert release_server.requests["/" + MODEL_NAME] == 0
    assert_nothing_activated(tmp_path / "models")


def test_previous_sidecar_for_the_same_stem_stands_in_for_a_failed_download(
    tmp_path, release_server
):
    models = tmp_path / "models"
    models.mkdir()
    previous = b'{"classes": ["previous complete sidecar"]}\n'
    (models / META_NAME).write_bytes(previous)
    release_server.truncate_metadata = 1
    result = run_model_block(tmp_path, release_server)
    assert result.returncode == 0
    assert f"using models/{META_NAME} from an earlier run" in result.stderr
    assert (models / "open-default.onnx").readlink() == Path(MODEL_NAME)
    assert (models / "open-default_metadata.json").read_bytes() == previous
    assert not list(models.glob(".model-download.*"))


@pytest.mark.parametrize(
    "other", ["other-model_metadata.json", "open-default_metadata.json"]
)
def test_sidecar_for_a_different_stem_does_not_stand_in(
    tmp_path, release_server, other
):
    models = tmp_path / "models"
    models.mkdir()
    (models / other).write_bytes(b'{"classes": ["another model"]}\n')
    release_server.truncate_metadata = 1
    result = run_model_block(tmp_path, release_server)
    assert result.returncode == 1
    assert "was not activated" in result.stderr
    assert (models / other).read_bytes() == b'{"classes": ["another model"]}\n'
    assert not (models / META_NAME).exists()
    assert_nothing_activated(models)


def test_metadata_checksum_mismatch_fails_closed_then_retry_succeeds(
    tmp_path, release_server
):
    release_server.sums_list_metadata = True
    release_server.metadata_mismatch = True
    first = run_model_block(tmp_path, release_server)
    models = tmp_path / "models"
    assert first.returncode == 1
    assert f"CHECKSUM MISMATCH for {META_NAME}" in first.stderr
    assert not (models / META_NAME).exists()
    assert_nothing_activated(models)

    release_server.metadata_mismatch = False
    second = run_model_block(tmp_path, release_server)
    assert second.returncode == 0
    assert f"OK ({META_NAME} sha256 verified)" in second.stdout
    assert (models / "open-default_metadata.json").read_bytes() == METADATA


def test_metadata_checksum_opt_out_matches_the_model_policy(tmp_path, release_server):
    release_server.sums_list_metadata = True
    release_server.metadata_mismatch = True
    result = run_model_block(tmp_path, release_server, skip_checksum=True)
    assert result.returncode == 0
    assert release_server.requests["/SHA256SUMS"] == 0
    assert (tmp_path / "models/open-default_metadata.json").read_bytes() == METADATA


def test_checksum_file_without_metadata_entry_proceeds(tmp_path, release_server):
    release_server.sums_list_metadata = False
    result = run_model_block(tmp_path, release_server)
    assert result.returncode == 0
    assert f"SHA256SUMS does not list {META_NAME}" in result.stdout
    assert "OK (sha256 verified)" in result.stdout
    models = tmp_path / "models"
    assert (models / "open-default.onnx").readlink() == Path(MODEL_NAME)
    assert (models / "open-default_metadata.json").read_bytes() == METADATA


def snapshot(models):
    """Every entry in models/: link target, file bytes, or a directory."""
    return {
        path.name: ("link", os.readlink(path))
        if path.is_symlink()
        else ("dir", None)
        if path.is_dir()
        else ("file", path.read_bytes())
        for path in models.iterdir()
    }


@pytest.mark.parametrize("name", ["local-model.onnx", "open-default.onnx"])
@pytest.mark.parametrize("sidecar", [None, "directory", "dangling-symlink"])
def test_local_model_without_sidecar_is_refused_and_nothing_changes(
    tmp_path, release_server, name, sidecar
):
    models = tmp_path / "models"
    models.mkdir()
    (models / name).write_bytes(MODEL)
    meta = name.removesuffix(".onnx") + "_metadata.json"
    if sidecar == "directory":
        (models / meta).mkdir()
    elif sidecar == "dangling-symlink":
        (models / meta).symlink_to("absent_metadata.json")
    os.chmod(models / name, 0o600)
    before = snapshot(models)

    result = run_model_block(tmp_path, release_server, managed=True)

    assert result.returncode == 1
    assert result.stderr.count("Error:") == 1  # One message, not a cascade.
    assert "WARNING" not in result.stderr
    assert f"models/{name} has no models/{meta}" in result.stderr
    assert 'JSON file holds the model\'s class names: a "classes" list' in result.stderr
    assert "model's output order" in result.stderr
    assert "Add it next to the model, or remove models/" + name in result.stderr
    assert "downloads the release model with its metadata" in result.stderr
    assert "No RF model is available" not in result.stdout
    assert release_server.requests["/release"] == 0
    assert snapshot(models) == before
    assert (models / name).stat().st_mode & 0o777 == 0o600  # Not even perms.


@pytest.mark.parametrize("name", ["local-model.onnx", "open-default.onnx"])
def test_unmanaged_install_is_only_warned_about_a_model_without_sidecar(
    tmp_path, release_server, name
):
    # A legacy install starts its scanner itself; the scanner decides
    # whether the model's outputs fit its built-in class list.
    models = tmp_path / "models"
    models.mkdir()
    (models / name).write_bytes(MODEL)
    meta = name.removesuffix(".onnx") + "_metadata.json"

    result = run_model_block(tmp_path, release_server)

    assert result.returncode == 0
    assert "Error:" not in result.stderr
    assert f"WARNING: models/{name} has no models/{meta}" in result.stderr
    assert "refuses to start without it, unless the model's" in result.stderr
    assert release_server.requests["/release"] == 0
    assert (models / "open-default.onnx").read_bytes() == MODEL


@pytest.mark.parametrize("name", ["local-model.onnx", "open-default.onnx"])
@pytest.mark.parametrize("kind", ["file", "symlink-to-file"])
def test_local_model_with_sidecar_activates(tmp_path, release_server, name, kind):
    models = tmp_path / "models"
    models.mkdir()
    (models / name).write_bytes(MODEL)
    meta = name.removesuffix(".onnx") + "_metadata.json"
    if kind == "file":
        (models / meta).write_bytes(METADATA)
    else:
        (tmp_path / "kept-elsewhere.json").write_bytes(METADATA)
        (models / meta).symlink_to(tmp_path / "kept-elsewhere.json")
    result = run_model_block(tmp_path, release_server)
    assert result.returncode == 0
    assert "Error" not in result.stderr
    assert release_server.requests["/release"] == 0
    assert (models / "open-default.onnx").read_bytes() == MODEL
    assert (models / "open-default_metadata.json").read_bytes() == METADATA


def test_sidecar_lookup_uses_this_models_name_not_the_first_listed(
    tmp_path, release_server
):
    release_server.decoys = True
    result = run_model_block(tmp_path, release_server)
    assert result.returncode == 0
    models = tmp_path / "models"
    assert release_server.requests["/" + transfers.OTHER_META_NAME] == 0
    assert release_server.requests["/other-model.onnx"] == 0
    assert (models / "open-default.onnx").readlink() == Path(MODEL_NAME)
    assert (models / "open-default_metadata.json").read_bytes() == METADATA
    assert not (models / transfers.OTHER_META_NAME).exists()


def test_percent_encoded_asset_url_keeps_the_asset_name(
    tmp_path, release_server, monkeypatch
):
    model, meta = "release+model.onnx", "release+model_metadata.json"
    monkeypatch.setattr(transfers, "MODEL_NAME", model)
    monkeypatch.setattr(transfers, "META_NAME", meta)
    release_server.sums_list_metadata = True
    result = run_model_block(tmp_path, release_server)
    assert result.returncode == 0, result.stderr
    assert f"OK ({meta} sha256 verified)" in result.stdout
    models = tmp_path / "models"
    assert (models / "open-default.onnx").readlink() == Path(model)
    assert (models / model).read_bytes() == MODEL
    assert (models / "open-default_metadata.json").readlink() == Path(meta)
    assert (models / meta).read_bytes() == METADATA


unreadable_needs_non_root = pytest.mark.skipif(
    os.geteuid() == 0, reason="root reads files with mode 000"
)


@unreadable_needs_non_root
@pytest.mark.parametrize("model_publish", ["succeeds", "fails"])
def test_unreadable_previous_sidecar_is_replaced_by_the_verified_one(
    tmp_path, release_server, model_publish
):
    models = tmp_path / "models"
    models.mkdir()
    old = models / META_NAME
    old.write_bytes(b'{"classes": ["older release"]}\n')
    old.chmod(0)
    if model_publish == "fails":
        (models / MODEL_NAME).mkdir()
    release_server.sums_list_metadata = True
    result = run_model_block(tmp_path, release_server, discover=False)
    assert f"Could not back up {META_NAME}" in result.stderr
    if model_publish == "succeeds":
        assert result.returncode == 0
        assert (models / "open-default_metadata.json").readlink() == Path(META_NAME)
    else:
        # No backup to restore: the new sidecar stays rather than nothing.
        assert result.returncode == 1
        assert "Could not publish completed model" in result.stderr
    assert old.read_bytes() == METADATA
    assert not list(models.glob(".model-download.*"))


def test_same_stem_sidecar_symlink_does_not_stand_in_for_a_failed_download(
    tmp_path, release_server
):
    models = tmp_path / "models"
    models.mkdir()
    (models / "elsewhere.json").write_bytes(b'{"classes": ["another model"]}\n')
    (models / META_NAME).symlink_to("elsewhere.json")
    release_server.truncate_metadata = 1
    result = run_model_block(tmp_path, release_server)
    assert result.returncode == 1
    assert f"without {META_NAME}, so {MODEL_NAME} was not activated" in result.stderr
    assert (models / META_NAME).readlink() == Path("elsewhere.json")
    assert_nothing_activated(models)


def test_previous_sidecar_stands_in_when_the_new_one_cannot_be_published(
    tmp_path, release_server
):
    models = tmp_path / "models"
    models.mkdir()
    previous = b'{"classes": ["previous complete sidecar"]}\n'
    (models / META_NAME).write_bytes(previous)
    result = run_model_block(tmp_path, release_server, stage_as_directory=META_NAME)
    assert result.returncode == 0, result.stderr
    assert (
        f"Could not publish new metadata; using models/{META_NAME} from an earlier run"
        in result.stderr
    )
    assert (models / "open-default.onnx").readlink() == Path(MODEL_NAME)
    assert (models / "open-default_metadata.json").read_bytes() == previous
    assert not list(models.glob(".model-download.*"))


def test_metadata_that_cannot_be_hashed_fails_closed(tmp_path, release_server):
    models = tmp_path / "models"
    models.mkdir()
    previous = b'{"classes": ["previous complete sidecar"]}\n'
    (models / META_NAME).write_bytes(previous)
    release_server.sums_list_metadata = True
    result = run_model_block(tmp_path, release_server, stage_as_directory=META_NAME)
    assert result.returncode == 1
    assert "Could not hash downloaded metadata — refusing unverified metadata" in result.stderr
    assert "CHECKSUM MISMATCH" not in result.stderr
    assert (models / META_NAME).read_bytes() == previous
    assert not list(models.glob("*.onnx"))
    assert not (models / "open-default.onnx").is_symlink()
    assert not list(models.glob(".model-download.*"))
