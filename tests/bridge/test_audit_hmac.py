"""Tests for audit log HMAC chain tamper detection.

Covers:
  - Chain is valid after multiple inserts
  - Tampered entry is detected
  - Deleted entry breaks the chain
  - verify_chain endpoint works
  - SEC-M7: Tenant-scoped HMAC chains (multi-tenant isolation)
"""

from __future__ import annotations

from pathlib import Path


from sigrift.bridge.detection_store import DetectionStore


class TestAuditHMACChain:
    """Tests for the HMAC chain integrity feature."""

    def test_chain_valid_after_inserts(self, detection_store: DetectionStore) -> None:
        """Chain verification passes after multiple inserts."""
        detection_store.log_audit(
            action="dismiss", target_id="det_001", operator="key_a"
        )
        detection_store.log_audit(
            action="baseline", target_id="det_002", operator="key_b"
        )
        detection_store.log_audit(
            action="feedback", target_id="det_003", operator="key_a"
        )

        result = detection_store.verify_audit_chain()
        assert result["valid"] is True
        assert result["checked"] == 3
        assert result["total"] == 3
        assert result["errors"] == []

    def test_tampered_entry_detected(self, detection_store: DetectionStore) -> None:
        """Modifying an entry's action field is detected by verification."""
        detection_store.log_audit(
            action="dismiss", target_id="det_001", operator="key_a"
        )
        detection_store.log_audit(
            action="baseline", target_id="det_002", operator="key_b"
        )
        detection_store.log_audit(
            action="feedback", target_id="det_003", operator="key_a"
        )

        # Tamper with the second entry
        conn = detection_store.get_connection()
        conn.execute(
            "UPDATE audit_log SET action = 'tampered' WHERE target_id = 'det_002'"
        )
        conn.commit()

        result = detection_store.verify_audit_chain()
        assert result["valid"] is False
        assert len(result["errors"]) >= 1
        # The tampered entry should be detected
        error_ids = [e["id"] for e in result["errors"]]
        # Entry 2 was tampered, so its HMAC will be wrong
        assert any(eid >= 2 for eid in error_ids)

    def test_deleted_entry_breaks_chain(self, detection_store: DetectionStore) -> None:
        """Deleting an entry breaks the chain for subsequent entries."""
        detection_store.log_audit(
            action="dismiss", target_id="det_001", operator="key_a"
        )
        detection_store.log_audit(
            action="baseline", target_id="det_002", operator="key_b"
        )
        detection_store.log_audit(
            action="feedback", target_id="det_003", operator="key_a"
        )

        # Delete the second entry
        conn = detection_store.get_connection()
        conn.execute("DELETE FROM audit_log WHERE target_id = 'det_002'")
        conn.commit()

        result = detection_store.verify_audit_chain()
        assert result["valid"] is False
        assert len(result["errors"]) >= 1

    def test_empty_log_is_valid(self, detection_store: DetectionStore) -> None:
        """An empty audit log passes verification."""
        result = detection_store.verify_audit_chain()
        assert result["valid"] is True
        assert result["total"] == 0
        assert result["checked"] == 0
        assert result["errors"] == []

    def test_single_entry_valid(self, detection_store: DetectionStore) -> None:
        """A single audit entry passes verification."""
        detection_store.log_audit(
            action="dismiss", target_id="det_001", operator="key_a"
        )
        result = detection_store.verify_audit_chain()
        assert result["valid"] is True
        assert result["checked"] == 1

    def test_hmac_stored_in_db(self, detection_store: DetectionStore) -> None:
        """Each entry has a non-empty hmac_chain value stored."""
        detection_store.log_audit(
            action="dismiss", target_id="det_001", operator="key_a"
        )
        detection_store.log_audit(
            action="baseline", target_id="det_002", operator="key_b"
        )

        conn = detection_store.get_connection()
        rows = conn.execute(
            "SELECT hmac_chain FROM audit_log ORDER BY id ASC"
        ).fetchall()
        assert len(rows) == 2
        for row in rows:
            assert row["hmac_chain"] != ""
            assert len(row["hmac_chain"]) == 64  # SHA-256 hex digest

    def test_chain_survives_reopen(self, tmp_path: Path) -> None:
        """Chain is valid after closing and reopening the store."""
        db_path = tmp_path / "hmac_persist.db"

        store1 = DetectionStore(db_path=db_path)
        store1.log_audit(action="dismiss", target_id="det_001", operator="key_a")
        store1.log_audit(action="baseline", target_id="det_002", operator="key_b")
        store1.close()

        store2 = DetectionStore(db_path=db_path)
        # Insert more entries after reopening
        store2.log_audit(action="feedback", target_id="det_003", operator="key_a")

        result = store2.verify_audit_chain()
        assert result["valid"] is True
        assert result["checked"] == 3
        store2.close()

    def test_tampered_timestamp_detected(self, detection_store: DetectionStore) -> None:
        """Modifying a timestamp is detected."""
        detection_store.log_audit(
            action="dismiss", target_id="det_001", operator="key_a"
        )
        detection_store.log_audit(
            action="baseline", target_id="det_002", operator="key_b"
        )

        conn = detection_store.get_connection()
        conn.execute(
            "UPDATE audit_log SET timestamp = '2020-01-01T00:00:00+00:00' WHERE target_id = 'det_001'"
        )
        conn.commit()

        result = detection_store.verify_audit_chain()
        assert result["valid"] is False


class TestAuditChainEndpoint:
    """Tests for the /api/admin/audit/verify endpoint."""

    def test_verify_endpoint_empty(self, client) -> None:
        """Verify endpoint returns valid for empty log."""
        resp = client.get("/api/admin/audit/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True

    def test_verify_endpoint_after_inserts(self, client, detection_store) -> None:
        """Verify endpoint returns valid after audit entries."""
        detection_store.log_audit(
            action="dismiss", target_id="det_001", operator="key_a"
        )
        detection_store.log_audit(
            action="baseline", target_id="det_002", operator="key_b"
        )

        resp = client.get("/api/admin/audit/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["checked"] == 2

    def test_verify_endpoint_detects_tamper(self, client, detection_store) -> None:
        """Verify endpoint detects a tampered entry."""
        detection_store.log_audit(
            action="dismiss", target_id="det_001", operator="key_a"
        )
        detection_store.log_audit(
            action="baseline", target_id="det_002", operator="key_b"
        )

        conn = detection_store.get_connection()
        conn.execute(
            "UPDATE audit_log SET action = 'hacked' WHERE target_id = 'det_001'"
        )
        conn.commit()

        resp = client.get("/api/admin/audit/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is False
        assert len(data["errors"]) >= 1


class TestTenantScopedChain:
    """SEC-M7: HMAC chains are scoped per-tenant."""

    def test_independent_tenant_chains(self, tmp_path: Path) -> None:
        """Entries from tenant A do not affect tenant B's chain verification."""
        db_path = tmp_path / "multi_tenant.db"

        store_a = DetectionStore(db_path=db_path, tenant_id="tenant_a")
        store_b = DetectionStore(db_path=db_path, tenant_id="tenant_b")

        store_a.log_audit(action="dismiss", target_id="det_a1", operator="op_a")
        store_a.log_audit(action="baseline", target_id="det_a2", operator="op_a")

        store_b.log_audit(action="feedback", target_id="det_b1", operator="op_b")

        result_a = store_a.verify_audit_chain()
        assert result_a["valid"] is True
        assert result_a["total"] == 2
        assert result_a["checked"] == 2

        result_b = store_b.verify_audit_chain()
        assert result_b["valid"] is True
        assert result_b["total"] == 1
        assert result_b["checked"] == 1

        store_a.close()
        store_b.close()

    def test_tamper_in_one_tenant_does_not_affect_other(self, tmp_path: Path) -> None:
        """Tampering with tenant A's entries does not invalidate tenant B's chain."""
        db_path = tmp_path / "multi_tenant_tamper.db"

        store_a = DetectionStore(db_path=db_path, tenant_id="tenant_a")
        store_b = DetectionStore(db_path=db_path, tenant_id="tenant_b")

        store_a.log_audit(action="dismiss", target_id="det_a1", operator="op_a")
        store_a.log_audit(action="baseline", target_id="det_a2", operator="op_a")

        store_b.log_audit(action="feedback", target_id="det_b1", operator="op_b")
        store_b.log_audit(action="dismiss", target_id="det_b2", operator="op_b")

        # Tamper with tenant A's entry
        conn = store_a.get_connection()
        conn.execute(
            "UPDATE audit_log SET action = 'hacked' WHERE target_id = 'det_a1'"
        )
        conn.commit()

        # Tenant A's chain should be broken
        result_a = store_a.verify_audit_chain()
        assert result_a["valid"] is False
        assert len(result_a["errors"]) >= 1

        # Tenant B's chain should still be valid
        result_b = store_b.verify_audit_chain()
        assert result_b["valid"] is True

        store_a.close()
        store_b.close()

    def test_delete_in_one_tenant_does_not_affect_other(self, tmp_path: Path) -> None:
        """Deleting an entry from tenant A does not break tenant B's chain."""
        db_path = tmp_path / "multi_tenant_delete.db"

        store_a = DetectionStore(db_path=db_path, tenant_id="tenant_a")
        store_b = DetectionStore(db_path=db_path, tenant_id="tenant_b")

        store_a.log_audit(action="dismiss", target_id="det_a1", operator="op_a")
        store_a.log_audit(action="baseline", target_id="det_a2", operator="op_a")
        store_a.log_audit(action="feedback", target_id="det_a3", operator="op_a")

        store_b.log_audit(action="dismiss", target_id="det_b1", operator="op_b")
        store_b.log_audit(action="baseline", target_id="det_b2", operator="op_b")

        # Delete a tenant A entry
        conn = store_a.get_connection()
        conn.execute("DELETE FROM audit_log WHERE target_id = 'det_a2'")
        conn.commit()

        # Tenant A's chain should be broken
        result_a = store_a.verify_audit_chain()
        assert result_a["valid"] is False

        # Tenant B's chain should still be valid
        result_b = store_b.verify_audit_chain()
        assert result_b["valid"] is True

        store_a.close()
        store_b.close()

    def test_interleaved_inserts_maintain_per_tenant_chains(
        self, tmp_path: Path
    ) -> None:
        """Interleaving inserts across tenants keeps each tenant's HMAC chain correct."""
        db_path = tmp_path / "multi_tenant_interleaved.db"

        store_a = DetectionStore(db_path=db_path, tenant_id="tenant_a")
        store_b = DetectionStore(db_path=db_path, tenant_id="tenant_b")

        # Interleave: A, B, A, B, A
        store_a.log_audit(action="dismiss", target_id="det_a1", operator="op_a")
        store_b.log_audit(action="dismiss", target_id="det_b1", operator="op_b")
        store_a.log_audit(action="baseline", target_id="det_a2", operator="op_a")
        store_b.log_audit(action="baseline", target_id="det_b2", operator="op_b")
        store_a.log_audit(action="feedback", target_id="det_a3", operator="op_a")

        result_a = store_a.verify_audit_chain()
        # HMAC chain is correct — no tamper errors
        assert result_a["errors"] == []
        assert result_a["total"] == 3
        assert result_a["checked"] == 3
        # SEC-M7: ID gaps from other tenants' rows are accounted for,
        # so valid multi-tenant deployments should report no gaps
        assert result_a["valid"] is True
        assert len(result_a["gaps"]) == 0

        result_b = store_b.verify_audit_chain()
        assert result_b["errors"] == []
        assert result_b["total"] == 2
        assert result_b["checked"] == 2

        store_a.close()
        store_b.close()

    def test_single_tenant_backward_compatible(
        self, detection_store: DetectionStore
    ) -> None:
        """Default single-tenant deployment works identically to before."""
        detection_store.log_audit(
            action="dismiss", target_id="det_001", operator="key_a"
        )
        detection_store.log_audit(
            action="baseline", target_id="det_002", operator="key_b"
        )
        detection_store.log_audit(
            action="feedback", target_id="det_003", operator="key_a"
        )

        result = detection_store.verify_audit_chain()
        assert result["valid"] is True
        assert result["checked"] == 3
        assert result["total"] == 3

    def test_gap_detection_scoped_to_tenant(self, tmp_path: Path) -> None:
        """ID gaps from other tenants' entries are not flagged as gaps."""
        db_path = tmp_path / "multi_tenant_gaps.db"

        store_a = DetectionStore(db_path=db_path, tenant_id="tenant_a")
        store_b = DetectionStore(db_path=db_path, tenant_id="tenant_b")

        # Insert: A(id=1), B(id=2), A(id=3)
        # Tenant A sees ids 1 and 3 — there's a gap, but it's because
        # tenant B's entry is in between, not because of deletion.
        store_a.log_audit(action="dismiss", target_id="det_a1", operator="op_a")
        store_b.log_audit(action="dismiss", target_id="det_b1", operator="op_b")
        store_a.log_audit(action="baseline", target_id="det_a2", operator="op_a")

        # Tenant A will see a gap in IDs (1 -> 3), which is expected
        # in multi-tenant. The chain itself should still be valid
        # (HMACs chain correctly within tenant).
        result_a = store_a.verify_audit_chain()
        # The HMACs are correct even with ID gap
        assert result_a["errors"] == []
        assert result_a["checked"] == 2

        # Tenant B should have no gaps and valid chain
        result_b = store_b.verify_audit_chain()
        assert result_b["valid"] is True
        assert result_b["checked"] == 1

        store_a.close()
        store_b.close()


class TestAuditChainHeadIsLocked:
    """G2 (bridge side): the chain-head read and the insert of a new audit
    entry happen under SQLite's write lock, so another process appending to
    the same chain (the Rust gateway shares detections.db) cannot commit
    between them and fork the chain."""

    def test_other_connection_cannot_write_between_head_read_and_insert(
        self, detection_store: DetectionStore, tmp_path: Path
    ) -> None:
        import sqlite3

        detection_store.log_audit(action="dismiss", target_id="det_001")
        conn = detection_store.get_connection()
        outcome: list[str] = []

        def interloper(statement: str) -> None:
            # Runs when this thread's connection reads the chain head.
            if "SELECT hmac_chain FROM audit_log" not in statement or outcome:
                return
            other = sqlite3.connect(tmp_path / "test_detections.db", timeout=0.2)
            try:
                other.execute(
                    "INSERT INTO audit_log (timestamp, action, target_id, tenant_id,"
                    " hmac_chain) VALUES ('2026-01-01T00:00:00+00:00', 'gw', 'x',"
                    " 'default', 'gateway-hmac')"
                )
                other.commit()
                outcome.append("interloper committed")
            except sqlite3.OperationalError as exc:
                outcome.append(f"blocked: {exc}")
            finally:
                other.close()

        conn.set_trace_callback(interloper)
        try:
            detection_store.log_audit(action="baseline", target_id="det_002")
        finally:
            conn.set_trace_callback(None)

        assert outcome and outcome[0].startswith("blocked"), outcome
        result = detection_store.verify_audit_chain()
        assert result["valid"] is True, result
        assert result["total"] == 2
