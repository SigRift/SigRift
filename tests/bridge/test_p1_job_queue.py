"""Tests for P1-8: In-process analysis job queue.

Covers:
  - AnalysisJobQueue creation, start, and stop
  - Job submission and completion
  - Failed job error storage
  - Queue size limits
  - Job cancellation
  - Async handler support
  - API endpoints (list, get, submit, cancel)
  - RBAC enforcement on submit (requires ANALYST) and cancel (requires ADMIN)
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.bridge.job_queue import AnalysisJobQueue
from sigrift.bridge.persistence import PersistenceManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_key_and_store(
    persistence: PersistenceManager,
    key_id: str,
    role: str = "admin",
) -> str:
    """Create an API key in persistence and return the raw key string."""
    raw_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key(key_id, hash_hex, salt)
    persistence.set_key_meta(key_id, {"role": role, "description": f"test {role}"})
    return raw_key


def _echo_handler(job_id: str, params: dict) -> dict:
    """Simple handler that echoes params back."""
    return {"echo": params, "job_id": job_id}


def _failing_handler(job_id: str, params: dict) -> dict:
    """Handler that always raises."""
    raise RuntimeError("intentional test failure")


async def _async_handler(job_id: str, params: dict) -> dict:
    """Async handler."""
    await asyncio.sleep(0.01)
    return {"async": True, "value": params.get("value", 0)}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def viewer_key(persistence: PersistenceManager) -> str:
    return _make_key_and_store(persistence, "viewer_key_jq", role="viewer")


@pytest.fixture
def analyst_key(persistence: PersistenceManager) -> str:
    return _make_key_and_store(persistence, "analyst_key_jq", role="analyst")


@pytest.fixture
def admin_key(master_key: str) -> str:
    return master_key


@pytest.fixture
def viewer_client(bridge_app: FastAPI, viewer_key: str) -> TestClient:
    return TestClient(bridge_app, headers={"X-API-Key": viewer_key})


@pytest.fixture
def analyst_client(bridge_app: FastAPI, analyst_key: str) -> TestClient:
    return TestClient(bridge_app, headers={"X-API-Key": analyst_key})


@pytest.fixture
def admin_client(bridge_app: FastAPI, admin_key: str) -> TestClient:
    return TestClient(bridge_app, headers={"X-API-Key": admin_key})


# ---------------------------------------------------------------------------
# Unit tests — AnalysisJobQueue
# ---------------------------------------------------------------------------


class TestAnalysisJobQueue:
    """Unit tests for the AnalysisJobQueue class."""

    def test_create_queue(self):
        """Queue can be created with custom parameters."""
        q = AnalysisJobQueue(max_workers=4, max_queue_size=50)
        assert q.max_workers == 4
        assert q.max_queue_size == 50
        assert not q._running

    @pytest.mark.asyncio
    async def test_start_stop(self):
        """Queue starts workers and stops cleanly."""
        q = AnalysisJobQueue(max_workers=2)
        await q.start()
        assert q._running is True
        assert len(q._workers) == 2
        await q.stop()
        assert not q._running
        assert len(q._workers) == 0

    @pytest.mark.asyncio
    async def test_submit_returns_job_id(self):
        """Submitting a job returns a job_id string."""
        q = AnalysisJobQueue(max_workers=1)
        q.register_handler("echo", _echo_handler)
        await q.start()
        try:
            job_id = await q.submit("echo", {"msg": "hello"})
            assert isinstance(job_id, str)
            assert len(job_id) == 32  # hex UUID
        finally:
            await q.stop()

    @pytest.mark.asyncio
    async def test_job_executes_and_completes(self):
        """A submitted job runs to completion with correct result."""
        q = AnalysisJobQueue(max_workers=1)
        q.register_handler("echo", _echo_handler)
        await q.start()
        try:
            job_id = await q.submit("echo", {"msg": "test"})
            # Wait for completion
            for _ in range(50):
                job = q.get_job_status(job_id)
                if job and job["status"] == "completed":
                    break
                await asyncio.sleep(0.05)
            job = q.get_job_status(job_id)
            assert job is not None
            assert isinstance(job, dict)
            assert job["status"] == "completed"
            assert job["result"]["echo"]["msg"] == "test"
            assert job["started_at"] is not None
            assert isinstance(job["started_at"], str)
            assert job["completed_at"] is not None
            assert isinstance(job["completed_at"], str)
            assert job["error"] is None
        finally:
            await q.stop()

    @pytest.mark.asyncio
    async def test_failed_job_stores_error(self):
        """A job whose handler raises stores the error message."""
        q = AnalysisJobQueue(max_workers=1)
        q.register_handler("fail", _failing_handler)
        await q.start()
        try:
            job_id = await q.submit("fail", {})
            for _ in range(50):
                job = q.get_job_status(job_id)
                if job and job["status"] == "failed":
                    break
                await asyncio.sleep(0.05)
            job = q.get_job_status(job_id)
            assert job is not None
            assert isinstance(job, dict)
            assert job["status"] == "failed"
            assert "intentional test failure" in job["error"]
            assert job["result"] is None
        finally:
            await q.stop()

    @pytest.mark.asyncio
    async def test_async_handler(self):
        """Async handlers are awaited correctly."""
        q = AnalysisJobQueue(max_workers=1)
        q.register_handler("async_op", _async_handler)
        await q.start()
        try:
            job_id = await q.submit("async_op", {"value": 42})
            for _ in range(50):
                job = q.get_job_status(job_id)
                if job and job["status"] == "completed":
                    break
                await asyncio.sleep(0.05)
            job = q.get_job_status(job_id)
            assert job["status"] == "completed"
            assert job["result"]["async"] is True
            assert job["result"]["value"] == 42
        finally:
            await q.stop()

    @pytest.mark.asyncio
    async def test_queue_size_limit(self):
        """Submitting beyond max_queue_size raises QueueFull."""
        q = AnalysisJobQueue(max_workers=0, max_queue_size=2)
        q.register_handler("echo", _echo_handler)
        # Don't start workers -- jobs will pile up
        # Manually set running to allow submit
        q._running = True
        await q.submit("echo", {"i": 1})
        await q.submit("echo", {"i": 2})
        with pytest.raises(asyncio.QueueFull):
            await q.submit("echo", {"i": 3})

    @pytest.mark.asyncio
    async def test_unknown_job_type_raises(self):
        """Submitting an unregistered job type raises ValueError."""
        q = AnalysisJobQueue()
        await q.start()
        try:
            with pytest.raises(ValueError, match="Unknown job type"):
                await q.submit("nonexistent", {})
        finally:
            await q.stop()

    @pytest.mark.asyncio
    async def test_cancel_pending_job(self):
        """A pending job can be cancelled."""
        q = AnalysisJobQueue(max_workers=0, max_queue_size=10)
        q.register_handler("echo", _echo_handler)
        q._running = True
        job_id = await q.submit("echo", {})
        assert q.cancel_job(job_id) is True
        job = q.get_job_status(job_id)
        assert job["status"] == "cancelled"

    @pytest.mark.asyncio
    async def test_cancel_completed_job_fails(self):
        """A completed job cannot be cancelled."""
        q = AnalysisJobQueue(max_workers=1)
        q.register_handler("echo", _echo_handler)
        await q.start()
        try:
            job_id = await q.submit("echo", {"x": 1})
            for _ in range(50):
                job = q.get_job_status(job_id)
                if job and job["status"] == "completed":
                    break
                await asyncio.sleep(0.05)
            assert q.cancel_job(job_id) is False
        finally:
            await q.stop()

    @pytest.mark.asyncio
    async def test_list_jobs(self):
        """list_jobs returns jobs with optional status filter."""
        q = AnalysisJobQueue(max_workers=1)
        q.register_handler("echo", _echo_handler)
        await q.start()
        try:
            await q.submit("echo", {"i": 1})
            await q.submit("echo", {"i": 2})
            # Wait for both to complete
            for _ in range(100):
                all_jobs = q.list_jobs()
                if all(j["status"] == "completed" for j in all_jobs):
                    break
                await asyncio.sleep(0.05)
            all_jobs = q.list_jobs()
            assert len(all_jobs) == 2
            completed = q.list_jobs(status_filter="completed")
            assert len(completed) == 2
            pending = q.list_jobs(status_filter="pending")
            assert len(pending) == 0
        finally:
            await q.stop()

    def test_get_nonexistent_job(self):
        """get_job_status returns None for unknown job_id."""
        q = AnalysisJobQueue()
        assert q.get_job_status("nonexistent") is None


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------


class TestJobEndpoints:
    """Test the /api/jobs endpoints."""

    def test_list_jobs_empty(self, client: TestClient):
        """GET /api/jobs returns empty list initially."""
        resp = client.get("/api/jobs")
        assert resp.status_code == 200
        data = resp.json()
        assert data["jobs"] == []
        assert data["count"] == 0

    def test_submit_requires_analyst(self, viewer_client: TestClient):
        """POST /api/jobs requires ANALYST role -- viewer is rejected."""
        resp = viewer_client.post(
            "/api/jobs",
            json={"job_type": "echo", "params": {}},
        )
        assert resp.status_code == 403

    def test_submit_analyst_allowed(
        self, analyst_client: TestClient, bridge_app: FastAPI,
    ):
        """POST /api/jobs succeeds with ANALYST role (with registered handler)."""
        # Register a handler on the test app's queue
        jq: AnalysisJobQueue = bridge_app.state.job_queue
        jq.register_handler("echo", _echo_handler)
        jq._running = True

        resp = analyst_client.post(
            "/api/jobs",
            json={"job_type": "echo", "params": {"msg": "hi"}},
        )
        assert resp.status_code == 202
        data = resp.json()
        assert "job_id" in data
        assert isinstance(data["job_id"], str)
        assert data["status"] == "pending"

    def test_submit_unknown_type(
        self, analyst_client: TestClient, bridge_app: FastAPI,
    ):
        """POST /api/jobs with unknown job_type returns 400."""
        bridge_app.state.job_queue._running = True
        resp = analyst_client.post(
            "/api/jobs",
            json={"job_type": "nonexistent_handler", "params": {}},
        )
        assert resp.status_code == 400
        assert "Unknown job type" in resp.json()["detail"]

    def test_get_job_status(
        self, analyst_client: TestClient, bridge_app: FastAPI, client: TestClient,
    ):
        """GET /api/jobs/{job_id} returns the job details."""
        jq: AnalysisJobQueue = bridge_app.state.job_queue
        jq.register_handler("echo", _echo_handler)
        jq._running = True

        resp = analyst_client.post(
            "/api/jobs",
            json={"job_type": "echo", "params": {"x": 1}},
        )
        job_id = resp.json()["job_id"]

        resp2 = client.get(f"/api/jobs/{job_id}")
        assert resp2.status_code == 200
        job = resp2.json()["job"]
        assert job["job_id"] == job_id
        assert job["job_type"] == "echo"

    def test_get_nonexistent_job(self, client: TestClient):
        """GET /api/jobs/{bad_id} returns 404."""
        resp = client.get("/api/jobs/nonexistent123")
        assert resp.status_code == 404

    def test_cancel_requires_admin(
        self,
        analyst_client: TestClient,
        bridge_app: FastAPI,
    ):
        """DELETE /api/jobs/{id} requires ADMIN role."""
        jq: AnalysisJobQueue = bridge_app.state.job_queue
        jq.register_handler("echo", _echo_handler)
        jq._running = True

        resp = analyst_client.post(
            "/api/jobs",
            json={"job_type": "echo", "params": {}},
        )
        job_id = resp.json()["job_id"]
        del_resp = analyst_client.delete(f"/api/jobs/{job_id}")
        assert del_resp.status_code == 403

    def test_cancel_admin_allowed(
        self,
        analyst_client: TestClient,
        admin_client: TestClient,
        bridge_app: FastAPI,
    ):
        """DELETE /api/jobs/{id} succeeds with ADMIN role for pending job."""
        jq: AnalysisJobQueue = bridge_app.state.job_queue
        jq.register_handler("echo", _echo_handler)
        jq._running = True

        resp = analyst_client.post(
            "/api/jobs",
            json={"job_type": "echo", "params": {}},
        )
        job_id = resp.json()["job_id"]
        del_resp = admin_client.delete(f"/api/jobs/{job_id}")
        assert del_resp.status_code == 200
        assert del_resp.json()["status"] == "cancelled"

    def test_list_with_status_filter(
        self, analyst_client: TestClient, bridge_app: FastAPI, client: TestClient,
    ):
        """GET /api/jobs?status=pending filters correctly."""
        jq: AnalysisJobQueue = bridge_app.state.job_queue
        jq.register_handler("echo", _echo_handler)
        jq._running = True

        analyst_client.post(
            "/api/jobs",
            json={"job_type": "echo", "params": {"i": 1}},
        )

        resp = client.get("/api/jobs?status=pending")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["count"], int)
        assert data["count"] >= 1
        assert all(j["status"] == "pending" for j in data["jobs"])
