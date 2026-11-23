"""Tests for key metadata persistence and expiry enforcement.

Covers Sprint 5 Item 20:
  - Key metadata (created_at, expires_at, role, description) survives restart
  - Expired keys are rejected during validation
  - list_keys returns persisted metadata after reload
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
)
from sigrift.bridge.dependencies import _resolve_key_role, Role
from sigrift.bridge.persistence import PersistenceManager


# ---------------------------------------------------------------------------
# Persistence round-trip
# ---------------------------------------------------------------------------


class TestKeyMetaPersistence:
    """Key metadata survives save/reload cycle."""

    def test_metadata_survives_reload(self, tmp_path: Path) -> None:
        """Metadata written via set_key_meta is present after load_all."""
        data_dir = tmp_path / "data"

        # --- First instance: create key + metadata, save ---
        pm1 = PersistenceManager(data_dir=data_dir, auto_save_interval=0)
        pm1.load_all()

        raw_key = generate_api_key(length=32)
        hash_hex, salt = hash_credential(raw_key)
        pm1.set_key("test-key", hash_hex, salt, lookup_hash=compute_lookup_hash(raw_key))

        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=24)
        pm1.set_key_meta("test-key", {
            "role": "analyst",
            "description": "Test key",
            "created_at": now.isoformat(),
            "expires_at": expires.isoformat(),
        })
        pm1.save_all()

        # --- Second instance: reload from disk ---
        pm2 = PersistenceManager(data_dir=data_dir, auto_save_interval=0)
        pm2.load_all()

        meta = pm2.get_key_meta()
        assert "test-key" in meta
        assert isinstance(meta["test-key"], dict)
        assert meta["test-key"]["role"] == "analyst"
        assert meta["test-key"]["description"] == "Test key"
        assert meta["test-key"]["created_at"] == now.isoformat()
        assert meta["test-key"]["expires_at"] == expires.isoformat()

    def test_key_store_survives_reload(self, tmp_path: Path) -> None:
        """Key hash+salt survive save/reload."""
        data_dir = tmp_path / "data"

        pm1 = PersistenceManager(data_dir=data_dir, auto_save_interval=0)
        pm1.load_all()

        raw_key = generate_api_key(length=32)
        hash_hex, salt = hash_credential(raw_key)
        pm1.set_key("persist-key", hash_hex, salt)
        pm1.save_all()

        pm2 = PersistenceManager(data_dir=data_dir, auto_save_interval=0)
        pm2.load_all()

        store = pm2.get_key_store()
        assert "persist-key" in store
        assert isinstance(store["persist-key"], (list, tuple))
        assert store["persist-key"][0] == hash_hex

    def test_fast_index_survives_reload(self, tmp_path: Path) -> None:
        """Fast-hash lookup index survives save/reload."""
        data_dir = tmp_path / "data"

        pm1 = PersistenceManager(data_dir=data_dir, auto_save_interval=0)
        pm1.load_all()

        raw_key = generate_api_key(length=32)
        hash_hex, salt = hash_credential(raw_key)
        lookup = compute_lookup_hash(raw_key)
        pm1.set_key("indexed-key", hash_hex, salt, lookup_hash=lookup)
        pm1.save_all()

        pm2 = PersistenceManager(data_dir=data_dir, auto_save_interval=0)
        pm2.load_all()

        idx = pm2.get_key_fast_index()
        assert isinstance(idx, dict)
        assert lookup in idx
        assert idx[lookup] == "indexed-key"

    def test_multiple_keys_metadata_preserved(self, tmp_path: Path) -> None:
        """Multiple keys with different metadata all survive reload."""
        data_dir = tmp_path / "data"

        pm = PersistenceManager(data_dir=data_dir, auto_save_interval=0)
        pm.load_all()

        for i in range(5):
            raw = generate_api_key(length=32)
            h, s = hash_credential(raw)
            kid = f"key-{i}"
            pm.set_key(kid, h, s, lookup_hash=compute_lookup_hash(raw))
            pm.set_key_meta(kid, {
                "role": "viewer" if i % 2 == 0 else "analyst",
                "description": f"Key number {i}",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "expires_at": None,
            })

        pm.save_all()

        pm2 = PersistenceManager(data_dir=data_dir, auto_save_interval=0)
        pm2.load_all()

        meta = pm2.get_key_meta()
        for i in range(5):
            kid = f"key-{i}"
            assert kid in meta
            assert isinstance(meta[kid], dict)
            assert meta[kid]["description"] == f"Key number {i}"
            expected_role = "viewer" if i % 2 == 0 else "analyst"
            assert meta[kid]["role"] == expected_role


# ---------------------------------------------------------------------------
# Expiry enforcement
# ---------------------------------------------------------------------------


class TestExpiryEnforcement:
    """Expired keys are rejected by _resolve_key_role."""

    def test_expired_key_rejected(self) -> None:
        """A key past its expires_at returns (None, None)."""
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        meta = {
            "test-key": {
                "role": "analyst",
                "expires_at": past,
            }
        }
        key_id, role = _resolve_key_role("test-key", meta)
        assert key_id is None
        assert role is None

    def test_valid_key_accepted(self) -> None:
        """A key before its expires_at is accepted."""
        future = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        meta = {
            "test-key": {
                "role": "analyst",
                "expires_at": future,
            }
        }
        key_id, role = _resolve_key_role("test-key", meta)
        assert key_id == "test-key"
        assert role == Role.ANALYST

    def test_no_expiry_accepted(self) -> None:
        """A key with no expires_at is accepted."""
        meta = {
            "test-key": {
                "role": "viewer",
                "expires_at": None,
            }
        }
        key_id, role = _resolve_key_role("test-key", meta)
        assert key_id == "test-key"
        assert role == Role.VIEWER

    def test_master_key_always_admin(self) -> None:
        """Master key always resolves to ADMIN regardless of metadata."""
        meta = {
            "master": {
                "role": "viewer",  # should be overridden
                "expires_at": None,
            }
        }
        key_id, role = _resolve_key_role("master", meta)
        assert key_id == "master"
        assert role == Role.ADMIN

    def test_expired_key_rejected_after_reload(self, tmp_path: Path) -> None:
        """Expired key metadata persists and is still enforced after reload."""
        data_dir = tmp_path / "data"

        pm = PersistenceManager(data_dir=data_dir, auto_save_interval=0)
        pm.load_all()

        raw = generate_api_key(length=32)
        h, s = hash_credential(raw)
        pm.set_key("expired-key", h, s, lookup_hash=compute_lookup_hash(raw))

        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        pm.set_key_meta("expired-key", {
            "role": "analyst",
            "description": "Already expired",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": past,
        })
        pm.save_all()

        # Reload
        pm2 = PersistenceManager(data_dir=data_dir, auto_save_interval=0)
        pm2.load_all()

        meta = pm2.get_key_meta()
        key_id, role = _resolve_key_role("expired-key", meta)
        assert key_id is None
        assert role is None


# ---------------------------------------------------------------------------
# Router integration: list_keys returns persisted metadata
# ---------------------------------------------------------------------------


class TestListKeysFromPersistence:
    """GET /api/keys/ returns metadata from persistence, not module-level dict."""

    def test_list_keys_shows_description_after_create(
        self, client: TestClient,
    ) -> None:
        """Newly created key's description appears in the listing."""
        client.post("/api/keys/", json={
            "key_id": "described-key",
            "description": "My test key",
        })
        resp = client.get("/api/keys/")
        assert resp.status_code == 200
        keys_by_id = {k["key_id"]: k for k in resp.json()}
        assert "described-key" in keys_by_id
        assert isinstance(keys_by_id["described-key"], dict)
        assert keys_by_id["described-key"]["description"] == "My test key"

    def test_list_keys_shows_expiry(self, client: TestClient) -> None:
        """Key with expiry has expires_at in listing."""
        resp = client.post("/api/keys/", json={
            "key_id": "expiry-key",
            "description": "Expiring",
            "expires_in_hours": 48,
        })
        assert resp.status_code == 201
        created = resp.json()
        assert created["expires_at"] is not None
        assert isinstance(created["expires_at"], str)

        resp = client.get("/api/keys/")
        keys_by_id = {k["key_id"]: k for k in resp.json()}
        assert keys_by_id["expiry-key"]["expires_at"] is not None
        assert isinstance(keys_by_id["expiry-key"]["expires_at"], str)

    def test_expired_key_rejected_on_auth(
        self, bridge_app: FastAPI, client: TestClient,
    ) -> None:
        """An expired key is rejected when used for authentication."""
        # Create a key
        resp = client.post("/api/keys/", json={
            "key_id": "will-expire",
            "description": "Will be expired",
        })
        raw_key = resp.json()["raw_key"]

        # Manually set expires_at to the past in persistence
        persistence: PersistenceManager = bridge_app.state.persistence
        meta = persistence.get_key_meta().get("will-expire", {})
        meta["expires_at"] = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        ).isoformat()
        persistence.set_key_meta("will-expire", meta)

        # Now try to use the expired key
        expired_client = TestClient(
            bridge_app, headers={"X-API-Key": raw_key},
        )
        resp = expired_client.get("/api/keys/")
        assert resp.status_code == 401
