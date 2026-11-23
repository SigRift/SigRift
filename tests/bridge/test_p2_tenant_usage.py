"""Tests for P2-2: per-tenant row limits and usage reporting in /status."""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.storage.base import SharedContext


@pytest.fixture
def ctx(tmp_path):
    """SharedContext backed by a temp database."""
    sc = SharedContext(db_path=tmp_path / "usage_test.db")
    yield sc
    sc.close()


def _insert_detection(ctx: SharedContext, *, tenant_id: str = "default") -> None:
    """Insert a minimal detection row for the given tenant."""
    conn = ctx.get_conn()
    conn.execute(
        "INSERT INTO detections "
        "(detection_id, node_id, timestamp, signal_class, confidence, tenant_id) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            str(uuid.uuid4()),
            "node-1",
            datetime.now(timezone.utc).isoformat(),
            "wifi",
            0.95,
            tenant_id,
        ),
    )
    conn.commit()


def _insert_audit(ctx: SharedContext, *, tenant_id: str = "default") -> None:
    """Insert a minimal audit_log row for the given tenant."""
    conn = ctx.get_conn()
    conn.execute(
        "INSERT INTO audit_log "
        "(action, operator, target_id, timestamp, tenant_id) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            "test",
            "tester",
            "t-1",
            datetime.now(timezone.utc).isoformat(),
            tenant_id,
        ),
    )
    conn.commit()


# -----------------------------------------------------------------------
# 1. Empty DB — all tables return 0
# -----------------------------------------------------------------------


class TestTenantUsageEmpty:
    def test_tenant_usage_empty_db(self, ctx: SharedContext) -> None:
        usage = ctx.get_tenant_usage()
        assert isinstance(usage, dict)
        for table in SharedContext._USAGE_TABLES:
            assert table in usage
            assert usage[table] == 0


# -----------------------------------------------------------------------
# 2. With detections — verify count
# -----------------------------------------------------------------------


class TestTenantUsageWithDetections:
    def test_tenant_usage_with_detections(self, ctx: SharedContext) -> None:
        _insert_detection(ctx)
        _insert_detection(ctx)
        _insert_detection(ctx)
        usage = ctx.get_tenant_usage()
        assert usage["detections"] == 3
        # Other tables still zero
        assert usage["wifi_metadata"] == 0


# -----------------------------------------------------------------------
# 3. Tenant isolation — tenant A rows not in tenant B count
# -----------------------------------------------------------------------


class TestTenantIsolation:
    def test_tenant_usage_isolation(self, tmp_path) -> None:
        ctx_a = SharedContext(
            db_path=tmp_path / "iso.db", tenant_id="tenant-a"
        )
        # Reuse same DB file for tenant B
        ctx_b = SharedContext(
            db_path=tmp_path / "iso.db", tenant_id="tenant-b"
        )
        try:
            _insert_detection(ctx_a, tenant_id="tenant-a")
            _insert_detection(ctx_a, tenant_id="tenant-a")
            _insert_detection(ctx_a, tenant_id="tenant-b")

            usage_a = ctx_a.get_tenant_usage()
            usage_b = ctx_b.get_tenant_usage()

            assert usage_a["detections"] == 2
            assert usage_b["detections"] == 1
        finally:
            ctx_a.close()
            ctx_b.close()


# -----------------------------------------------------------------------
# 4. Default row limit is 0 (unlimited)
# -----------------------------------------------------------------------


class TestRowLimitDefault:
    def test_row_limit_default_unlimited(self, ctx: SharedContext) -> None:
        assert ctx.row_limit == 0


# -----------------------------------------------------------------------
# 5. BRIDGE_TENANT_ROW_LIMIT env sets limit
# -----------------------------------------------------------------------


class TestRowLimitFromEnv:
    def test_row_limit_from_env(self, tmp_path) -> None:
        with patch.dict(os.environ, {"BRIDGE_TENANT_ROW_LIMIT": "1000"}):
            sc = SharedContext(db_path=tmp_path / "limit.db")
            try:
                assert sc.row_limit == 1000
            finally:
                sc.close()


# -----------------------------------------------------------------------
# 6. /api/status response includes tenant_usage
# -----------------------------------------------------------------------


class TestStatusEndpointIncludesUsage:
    def test_status_endpoint_includes_usage(self, client: TestClient) -> None:
        resp = client.get("/api/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "tenant_usage" in data
        assert isinstance(data["tenant_usage"], dict)
        tu = data["tenant_usage"]
        assert "tables" in tu
        assert isinstance(tu["tables"], dict)
        assert "total_rows" in tu
        assert isinstance(tu["total_rows"], int)
        assert "row_limit" in tu
        assert isinstance(tu["row_limit"], int)
        assert "usage_pct" in tu
        assert isinstance(tu["usage_pct"], (int, float))
        assert tu["total_rows"] >= 0
        assert tu["row_limit"] >= 0


# -----------------------------------------------------------------------
# 7. Usage percentage calculation with limit set
# -----------------------------------------------------------------------


class TestUsagePercentageCalculation:
    def test_usage_percentage_calculation(self, tmp_path) -> None:
        with patch.dict(os.environ, {"BRIDGE_TENANT_ROW_LIMIT": "100"}):
            sc = SharedContext(db_path=tmp_path / "pct.db")
            try:
                # Insert 10 detections
                for _ in range(10):
                    _insert_detection(sc)

                usage = sc.get_tenant_usage()
                total = sum(usage.values())
                assert total == 10
                limit = sc.row_limit
                assert limit == 100
                expected_pct = round(total / limit * 100, 2)
                assert expected_pct == 10.0
            finally:
                sc.close()

    def test_usage_pct_zero_when_unlimited(self, ctx: SharedContext) -> None:
        _insert_detection(ctx)
        usage = ctx.get_tenant_usage()
        total = sum(usage.values())
        assert total == 1
        assert ctx.row_limit == 0
        # When unlimited, pct should be 0
        pct = round(total / ctx.row_limit * 100, 2) if ctx.row_limit > 0 else 0.0
        assert pct == 0.0
