"""Webhook security configuration must outlive stale delivery worker state."""

from __future__ import annotations

import copy
import json

import pytest

from sigrift.bridge.persistence import PersistenceManager


def manager(path):
    value = PersistenceManager(path, auto_save_interval=0)
    value.load_all()
    return value


@pytest.mark.parametrize("change", ["delete", "disable", "url", "secret"])
def test_stale_delivery_metrics_cannot_restore_remote_security_config(tmp_path, change):
    initial = manager(tmp_path)
    original = {
        "id": "hook-1",
        "url": "https://example.com/old",
        "enabled": True,
        "signing_secret": "synthetic-old-secret",
        "delivery_count": 0,
    }
    initial.set_webhooks([original])
    initial.save_all()
    stale = manager(tmp_path)
    old = stale.get_webhooks()
    stale.set_webhooks(old)
    editor = manager(tmp_path)
    edited = copy.deepcopy(original)
    if change == "disable":
        edited["enabled"] = False
    elif change == "url":
        edited["url"] = "https://example.com/new"
    elif change == "secret":
        edited["signing_secret"] = "synthetic-new-secret"
    editor.set_webhooks([] if change == "delete" else [edited])
    editor.save_all()
    # Delivery metrics were changed locally after the other process's edit.
    old[0]["delivery_count"] = 1
    stale.save_all()
    actual = json.loads((tmp_path / "webhooks.json").read_text())["webhooks"]
    if change == "delete":
        assert actual == []
    else:
        assert actual[0]["url"] == edited["url"]
        assert actual[0]["enabled"] == edited["enabled"]
        assert actual[0]["signing_secret"] == edited["signing_secret"]


def test_legacy_revision_is_committed_once_and_failed_write_mints_nothing(tmp_path):
    legacy = {
        "webhooks": [
            {"id": "legacy", "url": "https://example.com/hook", "enabled": True}
        ]
    }
    path = tmp_path / "webhooks.json"
    path.write_text(json.dumps(legacy))
    pm = manager(tmp_path)
    # Create the interprocess lock before refusing new directory entries.
    with pm._file_lock:
        pass
    original = path.read_bytes()
    tmp_path.chmod(0o500)
    try:
        with pytest.raises(PermissionError):
            pm.current_webhooks()
        assert path.read_bytes() == original
        assert "delivery_revision" not in pm.get_webhooks()[0]
    finally:
        tmp_path.chmod(0o700)
    first = pm.current_webhooks()
    assert len(first[0]["delivery_revision"]) == 32
    assert manager(tmp_path).current_webhooks() == first
    assert json.loads(path.read_text())["webhooks"] == first
    assert not list(tmp_path.glob(".webhooks*.tmp"))


@pytest.mark.parametrize(
    "malformed",
    [
        {},
        {"webhooks": {}},
        {"webhooks": [{"id": "x"}]},
        {"webhooks": [{"id": "x", "url": "https://example.com", "enabled": "false"}]},
    ],
)
def test_malformed_authority_is_never_empty_success(tmp_path, malformed):
    pm = manager(tmp_path)
    (tmp_path / "webhooks.json").write_text(json.dumps(malformed))
    with pytest.raises((ValueError, KeyError)):
        pm.current_webhooks()


def test_checked_id_mutations_preserve_other_worker_creation_and_fence_cycles(tmp_path):
    first, second = manager(tmp_path), manager(tmp_path)
    first.change_webhook(
        "a", create={"id": "a", "url": "https://example.com/a", "enabled": True}
    )
    original = first.current_webhooks()[0]["delivery_revision"]
    second.change_webhook(
        "b", create={"id": "b", "url": "https://example.com/b", "enabled": True}
    )
    first.change_webhook("a", updates={"enabled": False})
    second.change_webhook("a", updates={"enabled": True})
    current = first.current_webhooks()
    assert {value["id"] for value in current} == {"a", "b"}
    enabled_revision = next(value for value in current if value["id"] == "a")[
        "delivery_revision"
    ]
    assert enabled_revision != original
    first.change_webhook("a", updates={"url": "https://example.com/other"})
    second.change_webhook("a", updates={"url": "https://example.com/a"})
    final = first.current_webhooks()
    assert next(value for value in final if value["id"] == "a")[
        "delivery_revision"
    ] not in {original, enabled_revision}


def test_snapshot_restore_preserves_user_fields_but_never_old_delivery_revision(
    tmp_path, detection_store
):
    pm = manager(tmp_path)
    hook = {
        "id": "a",
        "url": "https://example.com/a",
        "enabled": True,
        "signing_secret": "disposable",
    }
    pm.set_webhooks([hook])
    saved = pm.current_webhooks()[0]
    conn = detection_store.get_connection()
    snapshot = pm.create_config_snapshot("manual", db_conn=conn, require_complete=True)
    assert snapshot is not None
    pm.change_webhook("a", updates={"url": "https://example.com/changed"})
    changed = pm.current_webhooks()[0]["delivery_revision"]
    assert pm.restore_config_snapshot(conn, snapshot) == ["webhooks.json"]
    restored = pm.current_webhooks()[0]
    assert {k: v for k, v in restored.items() if k != "delivery_revision"} == hook
    assert restored["delivery_revision"] not in {saved["delivery_revision"], changed}
    # The backup itself remains byte-for-byte semantic evidence of its old state.
    assert (
        pm.get_config_snapshot(conn, snapshot)["files"]["webhooks.json"]["webhooks"][0]
        == saved
    )
