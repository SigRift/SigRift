"""Tests for Reference IQ Signature Library (Phase 2 Item 5).

Covers:
  - SignatureLibraryStore storage operations
  - REST API endpoints at /api/signatures
  - RBAC enforcement
  - Similarity search and signal matching
  - Export/import roundtrip
"""

from __future__ import annotations

import gzip
import json

import numpy as np
import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _random_embedding(seed: int = 42) -> list[float]:
    """Generate a random L2-normalized 32-dim embedding."""
    rng = np.random.default_rng(seed)
    emb = rng.standard_normal(32).astype(np.float32)
    emb /= np.linalg.norm(emb)
    return emb.tolist()


def _random_features(seed: int = 42) -> list[float]:
    """Generate a random 49-dim feature vector."""
    rng = np.random.default_rng(seed)
    return rng.standard_normal(54).astype(np.float32).tolist()


def _make_iq_bytes(n_samples: int = 256, seed: int = 0) -> bytes:
    """Create gzip-compressed float32 interleaved IQ data."""
    rng = np.random.default_rng(seed)
    i_vals = rng.standard_normal(n_samples).astype(np.float32)
    q_vals = rng.standard_normal(n_samples).astype(np.float32)
    interleaved = np.empty(2 * n_samples, dtype=np.float32)
    interleaved[0::2] = i_vals
    interleaved[1::2] = q_vals
    return gzip.compress(interleaved.tobytes())


# ===========================================================================
# Storage tests
# ===========================================================================


class TestSignatureLibraryStore:
    """Tests for the SignatureLibraryStore class."""

    @pytest.fixture
    def store(self, detection_store):
        """Create a SignatureLibraryStore using the test detection store context."""
        from sigrift.bridge.storage.signature_library import SignatureLibraryStore

        return SignatureLibraryStore(detection_store._ctx)

    def test_add_signature(self, store):
        """add_signature stores and retrieves a signature."""
        emb = _random_embedding(1)
        feats = _random_features(1)
        sig_id = store.add_signature(
            name="Test BPSK",
            protocol="custom",
            signal_class="bpsk",
            embedding=emb,
            features=feats,
            center_freq_hz=433.92e6,
            bandwidth_hz=200e3,
            description="Test signature",
            tags=["test", "bpsk"],
        )
        sig = store.get_signature(sig_id)
        assert sig is not None
        assert isinstance(sig, dict)
        assert sig["name"] == "Test BPSK"
        assert sig["protocol"] == "custom"
        assert sig["signal_class"] == "bpsk"
        assert sig["description"] == "Test signature"
        assert sig["center_freq_hz"] == pytest.approx(433.92e6)
        assert sig["tags"] == ["test", "bpsk"]
        assert len(sig["embedding"]) == 32
        assert len(sig["features_48dim"]) == 54

    def test_list_signatures(self, store):
        """list_signatures returns all stored signatures."""
        store.add_signature(name="Sig1", protocol="wifi", signal_class="ofdm")
        store.add_signature(name="Sig2", protocol="bluetooth", signal_class="gfsk")
        store.add_signature(name="Sig3", protocol="zigbee", signal_class="oqpsk")
        sigs = store.list_signatures()
        assert len(sigs) == 3

    def test_list_filter_protocol(self, store):
        """list_signatures filters by protocol."""
        store.add_signature(name="WiFi1", protocol="wifi", signal_class="ofdm")
        store.add_signature(name="WiFi2", protocol="wifi", signal_class="dsss")
        store.add_signature(name="BT1", protocol="bluetooth", signal_class="gfsk")
        sigs = store.list_signatures(protocol="wifi")
        assert len(sigs) == 2
        assert all(s["protocol"] == "wifi" for s in sigs)

    def test_list_filter_signal_class(self, store):
        """list_signatures filters by signal_class."""
        store.add_signature(name="BPSK1", protocol="custom", signal_class="bpsk")
        store.add_signature(name="BPSK2", protocol="wifi", signal_class="bpsk")
        store.add_signature(name="QPSK1", protocol="custom", signal_class="qpsk")
        sigs = store.list_signatures(signal_class="bpsk")
        assert len(sigs) == 2
        assert all(s["signal_class"] == "bpsk" for s in sigs)

    def test_list_filter_tags(self, store):
        """list_signatures filters by tags."""
        store.add_signature(
            name="Tagged1",
            protocol="custom",
            signal_class="bpsk",
            tags=["military", "test"],
        )
        store.add_signature(
            name="Tagged2",
            protocol="custom",
            signal_class="qpsk",
            tags=["civilian"],
        )
        store.add_signature(
            name="Tagged3",
            protocol="custom",
            signal_class="ofdm",
            tags=["military", "production"],
        )
        sigs = store.list_signatures(tags=["military"])
        assert len(sigs) == 2
        names = {s["name"] for s in sigs}
        assert "Tagged1" in names
        assert "Tagged3" in names

    def test_search_similar(self, store):
        """search_similar returns signatures above similarity threshold."""
        emb1 = _random_embedding(10)
        emb2 = _random_embedding(11)
        # Create a similar embedding (same direction, slightly perturbed)
        emb_similar = emb1.copy()
        emb_similar[0] += 0.01
        norm = np.linalg.norm(emb_similar)
        emb_similar = [x / norm for x in emb_similar]

        store.add_signature(
            name="Ref1",
            protocol="custom",
            signal_class="bpsk",
            embedding=emb1,
        )
        store.add_signature(
            name="Ref2",
            protocol="custom",
            signal_class="qpsk",
            embedding=emb2,
        )

        results = store.search_similar(emb_similar, top_k=10, threshold=0.9)
        assert len(results) >= 1
        assert isinstance(results[0], dict)
        assert results[0]["name"] == "Ref1"
        assert results[0]["similarity"] > 0.9

    def test_match_signal_found(self, store):
        """match_signal returns best match above threshold."""
        emb = _random_embedding(20)
        store.add_signature(
            name="Known Signal",
            protocol="wifi",
            signal_class="ofdm",
            embedding=emb,
        )
        # Match with the same embedding should give similarity ~1.0
        match = store.match_signal(emb, threshold=0.8)
        assert match is not None
        assert isinstance(match, dict)
        assert match["name"] == "Known Signal"
        assert match["similarity"] > 0.99

    def test_match_signal_not_found(self, store):
        """match_signal returns None when no match above threshold."""
        emb1 = _random_embedding(30)
        emb2 = _random_embedding(31)
        store.add_signature(
            name="Ref",
            protocol="custom",
            signal_class="bpsk",
            embedding=emb1,
        )
        match = store.match_signal(emb2, threshold=0.99)
        assert match is None

    def test_update_signature(self, store):
        """update_signature modifies specified fields."""
        sig_id = store.add_signature(
            name="Original",
            protocol="custom",
            signal_class="bpsk",
        )
        updated = store.update_signature(sig_id, name="Updated", description="New desc")
        assert updated is True
        sig = store.get_signature(sig_id)
        assert sig["name"] == "Updated"
        assert sig["description"] == "New desc"

    def test_delete_signature(self, store):
        """delete_signature removes the record."""
        sig_id = store.add_signature(
            name="ToDelete",
            protocol="custom",
            signal_class="bpsk",
        )
        assert store.get_signature(sig_id) is not None
        assert isinstance(store.get_signature(sig_id), dict)
        deleted = store.delete_signature(sig_id)
        assert deleted is True
        assert store.get_signature(sig_id) is None

    def test_add_tag(self, store):
        """add_tag appends a tag to the signature."""
        sig_id = store.add_signature(
            name="TagTest",
            protocol="custom",
            signal_class="bpsk",
            tags=["initial"],
        )
        result = store.add_tag(sig_id, "new_tag")
        assert result is True
        sig = store.get_signature(sig_id)
        assert "new_tag" in sig["tags"]
        assert "initial" in sig["tags"]

    def test_remove_tag(self, store):
        """remove_tag removes a tag from the signature."""
        sig_id = store.add_signature(
            name="TagTest",
            protocol="custom",
            signal_class="bpsk",
            tags=["keep", "remove_me"],
        )
        result = store.remove_tag(sig_id, "remove_me")
        assert result is True
        sig = store.get_signature(sig_id)
        assert "remove_me" not in sig["tags"]
        assert "keep" in sig["tags"]

    def test_verify(self, store):
        """verify_signature marks the signature as verified."""
        sig_id = store.add_signature(
            name="Unverified",
            protocol="custom",
            signal_class="bpsk",
        )
        sig = store.get_signature(sig_id)
        assert sig["verified"] == 0
        store.verify_signature(sig_id)
        sig = store.get_signature(sig_id)
        assert sig["verified"] == 1

    def test_get_stats(self, store):
        """get_stats returns counts by protocol and signal_class."""
        store.add_signature(name="S1", protocol="wifi", signal_class="ofdm")
        store.add_signature(name="S2", protocol="wifi", signal_class="dsss")
        store.add_signature(
            name="S3",
            protocol="bluetooth",
            signal_class="gfsk",
            verified=True,
        )
        stats = store.get_stats()
        assert stats["total"] == 3
        assert stats["by_protocol"]["wifi"] == 2
        assert stats["by_protocol"]["bluetooth"] == 1
        assert stats["by_signal_class"]["ofdm"] == 1
        assert stats["by_signal_class"]["gfsk"] == 1
        assert stats["verified_count"] == 1

    def test_export_import_roundtrip(self, store):
        """export then import produces equivalent data."""
        emb = _random_embedding(50)
        feats = _random_features(50)
        sig_id = store.add_signature(
            name="Roundtrip",
            protocol="lora",
            signal_class="css",
            embedding=emb,
            features=feats,
            center_freq_hz=868e6,
            tags=["export_test"],
            description="Roundtrip test",
        )
        exported = store.export_signatures([sig_id])
        assert len(exported) == 1
        assert exported[0]["name"] == "Roundtrip"

        # Delete original
        store.delete_signature(sig_id)
        assert store.get_signature(sig_id) is None

        # Import
        count = store.import_signatures(exported)
        assert count == 1

        # Verify imported data
        imported = store.get_signature(sig_id)
        assert imported is not None
        assert isinstance(imported, dict)
        assert imported["name"] == "Roundtrip"
        assert imported["protocol"] == "lora"
        assert imported["signal_class"] == "css"
        assert imported["center_freq_hz"] == pytest.approx(868e6)
        assert "export_test" in imported["tags"]

    def test_list_filter_verified(self, store):
        """list_signatures filters by verified flag."""
        store.add_signature(
            name="V1",
            protocol="custom",
            signal_class="bpsk",
            verified=True,
        )
        store.add_signature(
            name="V2",
            protocol="custom",
            signal_class="qpsk",
        )
        verified = store.list_signatures(verified=True)
        assert len(verified) == 1
        assert verified[0]["name"] == "V1"

    def test_delete_nonexistent(self, store):
        """delete_signature returns False for nonexistent ID."""
        assert store.delete_signature("nonexistent-id") is False

    def test_update_nonexistent(self, store):
        """update_signature returns False for nonexistent ID."""
        assert store.update_signature("nonexistent-id", name="Foo") is False


# ===========================================================================
# API tests
# ===========================================================================


class TestSignatureLibraryAPI:
    """Tests for the /api/signatures REST endpoints."""

    def test_list_signatures_viewer(self, client: TestClient):
        """VIEWER can list signatures."""
        resp = client.get("/api/signatures/")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_create_requires_admin(self, client: TestClient, bridge_app):
        """Non-ADMIN (ANALYST key) cannot create via POST /."""
        from sigrift.lib.security.credentials import generate_api_key, hash_credential

        # Create an ANALYST-level key
        analyst_key = generate_api_key(length=32)
        h, s = hash_credential(analyst_key)
        bridge_app.state.persistence.set_key("analyst_test", h, s)
        bridge_app.state.persistence.set_key_meta(
            "analyst_test", {"role": "analyst", "description": "test analyst"}
        )

        analyst_client = TestClient(
            bridge_app,
            headers={"X-API-Key": analyst_key},
        )
        resp = analyst_client.post(
            "/api/signatures/",
            data={"name": "Test", "protocol": "wifi", "signal_class": "ofdm"},
        )
        assert resp.status_code == 403

    def test_create_and_get_signature(self, client: TestClient):
        """ADMIN can create a signature and retrieve it."""
        resp = client.post(
            "/api/signatures/",
            data={
                "name": "Test WiFi OFDM",
                "protocol": "wifi",
                "signal_class": "ofdm",
                "description": "Test reference signature",
                "tags": json.dumps(["test", "wifi"]),
            },
        )
        assert resp.status_code == 201
        sig = resp.json()
        assert sig["name"] == "Test WiFi OFDM"
        assert sig["protocol"] == "wifi"

        # GET by id
        resp2 = client.get(f"/api/signatures/{sig['id']}")
        assert resp2.status_code == 200
        assert resp2.json()["name"] == "Test WiFi OFDM"

    def test_create_with_iq_file(self, client: TestClient):
        """ADMIN can upload a signature with IQ file."""
        iq_data = _make_iq_bytes(256, seed=42)
        resp = client.post(
            "/api/signatures/",
            data={
                "name": "IQ Signature",
                "protocol": "custom",
                "signal_class": "bpsk",
                "sample_rate_hz": "1000000",
                "center_freq_hz": "433920000",
            },
            files={"iq_file": ("test.iq.gz", iq_data, "application/octet-stream")},
        )
        assert resp.status_code == 201
        sig = resp.json()
        assert sig["iq_samples"] == 256
        assert sig["iq_file_path"] is not None
        assert isinstance(sig["iq_file_path"], str)
        # Embedding should have been computed
        assert sig.get("embedding") is not None or sig.get("features_48dim") is not None

    def _upload(self, client: TestClient, payload: bytes):
        return client.post(
            "/api/signatures/",
            data={"name": "Bounded", "protocol": "custom", "signal_class": "bpsk"},
            files={"iq_file": ("x.iq", payload, "application/octet-stream")},
        )

    def test_create_with_raw_iq_file_is_compressed(self, client: TestClient):
        """A raw (non-gzip) complex64 upload is accepted and compressed."""
        import numpy as np

        raw = (np.ones(128, dtype=np.complex64)).tobytes()
        resp = self._upload(client, raw)
        assert resp.status_code == 201, resp.text
        assert resp.json()["iq_samples"] == 128

    def test_gzip_bomb_rejected_with_413(self, client: TestClient, monkeypatch):
        """C1 (signature path): a gzip upload that inflates past the IQ
        sample cap is refused before anything is stored, without inflating
        it fully (previously an unbounded gzip.decompress)."""
        import gzip

        monkeypatch.setenv("BRIDGE_IQ_MAX_SAMPLES", "1024")
        bomb = gzip.compress(b"\0" * (8 * 1024 * 64))
        resp = self._upload(client, bomb)
        assert resp.status_code == 413, resp.text
        names = [sig["name"] for sig in client.get("/api/signatures/").json()]
        assert "Bounded" not in names

    def test_raw_iq_over_cap_rejected_with_413(self, client: TestClient, monkeypatch):
        monkeypatch.setenv("BRIDGE_IQ_MAX_SAMPLES", "16")
        resp = self._upload(client, b"\0" * (8 * 17))
        assert resp.status_code == 413, resp.text

    def test_malformed_iq_rejected_with_400(self, client: TestClient):
        import gzip

        assert self._upload(client, b"\0" * 7).status_code == 400
        # gzip magic but not whole complex64 samples: rejected, not re-gzipped
        assert self._upload(client, gzip.compress(b"\0" * 7)).status_code == 400
        assert self._upload(client, b"\x1f\x8bnot-gzip").status_code == 400

    def test_create_from_detection(self, client: TestClient, detection_store):
        """ANALYST can create a signature from a detection."""
        # Insert a detection
        from sigrift.bridge.tests.conftest import make_detection

        det = make_detection(signal_class="qpsk", freq_hz=915e6)
        detection_store.insert_batch([det])
        det_id = det.detection_id

        resp = client.post(
            f"/api/signatures/from-detection/{det_id}",
            json={
                "name": "From Detection",
                "protocol": "custom",
                "description": "Created from detection",
                "tags": ["auto"],
            },
        )
        assert resp.status_code == 201
        sig = resp.json()
        assert sig["name"] == "From Detection"
        assert sig["signal_class"] == "qpsk"
        assert sig["source"] == f"detection:{det_id}"

    def test_create_from_detection_not_found(self, client: TestClient):
        """Creating from nonexistent detection returns 404."""
        resp = client.post(
            "/api/signatures/from-detection/nonexistent",
            json={
                "name": "No Det",
                "protocol": "custom",
            },
        )
        assert resp.status_code == 404

    def test_update_signature(self, client: TestClient):
        """ANALYST (ADMIN in test) can update a signature."""
        # Create first
        resp = client.post(
            "/api/signatures/",
            data={"name": "Original", "protocol": "custom", "signal_class": "bpsk"},
        )
        sig_id = resp.json()["id"]

        # Update
        resp2 = client.put(
            f"/api/signatures/{sig_id}",
            json={"name": "Updated Name", "description": "Updated desc"},
        )
        assert resp2.status_code == 200
        assert resp2.json()["name"] == "Updated Name"
        assert resp2.json()["description"] == "Updated desc"

    def test_delete_requires_admin(self, client: TestClient, bridge_app):
        """Non-ADMIN cannot delete."""
        from sigrift.lib.security.credentials import generate_api_key, hash_credential

        analyst_key = generate_api_key(length=32)
        h, s = hash_credential(analyst_key)
        bridge_app.state.persistence.set_key("analyst_del", h, s)
        bridge_app.state.persistence.set_key_meta(
            "analyst_del", {"role": "analyst", "description": "test analyst"}
        )

        # Create as admin
        resp = client.post(
            "/api/signatures/",
            data={"name": "ToDelete", "protocol": "custom", "signal_class": "bpsk"},
        )
        sig_id = resp.json()["id"]

        # Try delete as analyst
        analyst_client = TestClient(
            bridge_app,
            headers={"X-API-Key": analyst_key},
        )
        resp2 = analyst_client.delete(f"/api/signatures/{sig_id}")
        assert resp2.status_code == 403

    def test_delete_signature(self, client: TestClient):
        """ADMIN can delete a signature."""
        resp = client.post(
            "/api/signatures/",
            data={"name": "Delete Me", "protocol": "custom", "signal_class": "bpsk"},
        )
        sig_id = resp.json()["id"]

        resp2 = client.delete(f"/api/signatures/{sig_id}")
        assert resp2.status_code == 200
        assert resp2.json()["ok"] is True

        # Verify deleted
        resp3 = client.get(f"/api/signatures/{sig_id}")
        assert resp3.status_code == 404

    def test_match_signal(self, client: TestClient):
        """POST /match returns match results."""
        emb = _random_embedding(100)

        # Create a reference with known embedding
        # Need to use store directly since POST / does not accept embedding param
        store = client.app.state.signature_library_store
        store.add_signature(
            name="Match Target",
            protocol="wifi",
            signal_class="ofdm",
            embedding=emb,
        )

        resp = client.post(
            "/api/signatures/match",
            json={"embedding": emb, "threshold": 0.8},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["matched"] is True
        assert data["match"]["name"] == "Match Target"

    def test_match_signal_no_match(self, client: TestClient):
        """POST /match returns matched=False when no match."""
        emb1 = _random_embedding(200)
        emb2 = _random_embedding(201)

        store = client.app.state.signature_library_store
        store.add_signature(
            name="Far Away",
            protocol="custom",
            signal_class="bpsk",
            embedding=emb1,
        )

        resp = client.post(
            "/api/signatures/match",
            json={"embedding": emb2, "threshold": 0.99},
        )
        assert resp.status_code == 200
        assert resp.json()["matched"] is False

    def test_search_similar(self, client: TestClient):
        """POST /search returns ranked results."""
        emb1 = _random_embedding(300)
        emb2 = _random_embedding(301)

        store = client.app.state.signature_library_store
        store.add_signature(
            name="Similar1",
            protocol="custom",
            signal_class="bpsk",
            embedding=emb1,
        )
        store.add_signature(
            name="Similar2",
            protocol="custom",
            signal_class="qpsk",
            embedding=emb2,
        )

        resp = client.post(
            "/api/signatures/search",
            json={"embedding": emb1, "top_k": 10, "threshold": 0.0},
        )
        assert resp.status_code == 200
        results = resp.json()
        assert len(results) >= 1
        assert isinstance(results[0], dict)
        # First result should be the exact match
        assert results[0]["name"] == "Similar1"
        assert results[0]["similarity"] > 0.99

    def test_stats(self, client: TestClient):
        """GET /stats returns library statistics."""
        store = client.app.state.signature_library_store
        store.add_signature(name="S1", protocol="wifi", signal_class="ofdm")
        store.add_signature(
            name="S2",
            protocol="bluetooth",
            signal_class="gfsk",
            verified=True,
        )

        resp = client.get("/api/signatures/stats")
        assert resp.status_code == 200
        stats = resp.json()
        assert stats["total"] >= 2
        assert isinstance(stats["total"], int)
        assert "by_protocol" in stats
        assert isinstance(stats["by_protocol"], dict)
        assert "by_signal_class" in stats
        assert isinstance(stats["by_signal_class"], dict)

    def test_verify_signature(self, client: TestClient):
        """PUT /{id}/verify marks signature as verified."""
        resp = client.post(
            "/api/signatures/",
            data={"name": "Verify Me", "protocol": "custom", "signal_class": "bpsk"},
        )
        sig_id = resp.json()["id"]

        resp2 = client.put(f"/api/signatures/{sig_id}/verify")
        assert resp2.status_code == 200
        assert resp2.json()["verified"] == 1

    def test_update_tags(self, client: TestClient):
        """PUT /{id}/tags updates tags."""
        resp = client.post(
            "/api/signatures/",
            data={"name": "Tag Update", "protocol": "custom", "signal_class": "bpsk"},
        )
        sig_id = resp.json()["id"]

        resp2 = client.put(
            f"/api/signatures/{sig_id}/tags",
            json={"tags": ["new_tag1", "new_tag2"]},
        )
        assert resp2.status_code == 200
        assert resp2.json()["tags"] == ["new_tag1", "new_tag2"]

    def test_export(self, client: TestClient):
        """POST /export returns signature data as JSON."""
        store = client.app.state.signature_library_store
        sig_id = store.add_signature(
            name="Export Me",
            protocol="custom",
            signal_class="bpsk",
            embedding=_random_embedding(400),
        )

        resp = client.post(
            "/api/signatures/export",
            json={"sig_ids": [sig_id]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["signatures"][0]["name"] == "Export Me"

    def test_import_requires_admin(self, client: TestClient, bridge_app):
        """Non-ADMIN cannot import."""
        from sigrift.lib.security.credentials import generate_api_key, hash_credential

        analyst_key = generate_api_key(length=32)
        h, s = hash_credential(analyst_key)
        bridge_app.state.persistence.set_key("analyst_imp", h, s)
        bridge_app.state.persistence.set_key_meta(
            "analyst_imp", {"role": "analyst", "description": "test analyst"}
        )

        analyst_client = TestClient(
            bridge_app,
            headers={"X-API-Key": analyst_key},
        )
        resp = analyst_client.post(
            "/api/signatures/import",
            json={"signatures": [{"name": "X", "protocol": "y", "signal_class": "z"}]},
        )
        assert resp.status_code == 403

    def test_import_signatures(self, client: TestClient):
        """ADMIN can import signatures from JSON."""
        resp = client.post(
            "/api/signatures/import",
            json={
                "signatures": [
                    {"name": "Imp1", "protocol": "wifi", "signal_class": "ofdm"},
                    {"name": "Imp2", "protocol": "bluetooth", "signal_class": "gfsk"},
                ],
            },
        )
        assert resp.status_code == 201
        assert resp.json()["imported"] == 2

    def test_get_nonexistent(self, client: TestClient):
        """GET /{id} returns 404 for nonexistent signature."""
        resp = client.get("/api/signatures/nonexistent-id")
        assert resp.status_code == 404

    def test_match_requires_embedding_or_detection(self, client: TestClient):
        """POST /match returns 400 when no embedding or detection_id."""
        resp = client.post(
            "/api/signatures/match",
            json={"threshold": 0.8},
        )
        assert resp.status_code == 400
