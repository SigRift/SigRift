"""Tests for map / floor plan storage and API endpoints.

Covers MapStore CRUD operations, coordinate conversions,
zone management, and all REST API endpoints.
"""

from __future__ import annotations

import struct
import uuid
import zlib
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.storage.maps import MapStore
from sigrift.bridge.storage.base import SharedContext


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_png() -> bytes:
    """Create a minimal 1x1 white PNG."""
    def chunk(chunk_type: bytes, data: bytes) -> bytes:
        c = chunk_type + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    raw = zlib.compress(b"\x00\xff\xff\xff")
    idat = chunk(b"IDAT", raw)
    iend = chunk(b"IEND", b"")
    return sig + ihdr + idat + iend


def _make_plan_id() -> str:
    return uuid.uuid4().hex[:12]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ctx(tmp_path: Path) -> SharedContext:
    """Shared context with temp database."""
    return SharedContext(db_path=tmp_path / "test_maps.db")


@pytest.fixture
def map_store(ctx: SharedContext) -> MapStore:
    """MapStore instance for testing."""
    return MapStore(ctx)


@pytest.fixture
def map_app(tmp_path: Path, map_store: MapStore) -> FastAPI:
    """Minimal FastAPI app with maps router wired up."""
    from sigrift.bridge.app import CombinedMiddleware
    from sigrift.bridge.routers import maps
    from sigrift.bridge.dependencies import RateLimiter, set_rate_limiter
    from sigrift.bridge.persistence import PersistenceManager
    from sigrift.lib.security.credentials import generate_api_key, hash_credential

    app = FastAPI()
    app.add_middleware(CombinedMiddleware)

    # Persistence + auth
    persistence = PersistenceManager(data_dir=tmp_path / "data", auto_save_interval=0)
    persistence.load_all()
    raw_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key("master", hash_hex, salt)

    app.state.persistence = persistence

    # Map store + floor plan dir
    floor_plan_dir = tmp_path / "floor_plans"
    floor_plan_dir.mkdir(parents=True, exist_ok=True)
    app.state.map_store = map_store
    app.state.floor_plan_dir = str(floor_plan_dir)

    # Rate limiter
    limiter = RateLimiter(max_requests=1000, window_seconds=60.0)
    set_rate_limiter(limiter)

    from sigrift.bridge.dependencies import WSConnectionLimiter, set_ws_limiter
    ws_limiter = WSConnectionLimiter(max_concurrent=10, max_per_minute=30)
    set_ws_limiter(ws_limiter)

    # Mount maps router
    app.include_router(maps.router, prefix="/api/maps", tags=["maps"])

    # Store raw key for tests
    app.state._test_api_key = raw_key

    return app


@pytest.fixture
def map_client(map_app: FastAPI) -> TestClient:
    """Test client with auth headers."""
    key = map_app.state._test_api_key
    return TestClient(map_app, headers={"X-API-Key": key})


@pytest.fixture
def sample_plan(map_store: MapStore, tmp_path: Path) -> dict[str, Any]:
    """Create a sample floor plan."""
    plan_id = _make_plan_id()
    img_path = tmp_path / f"{plan_id}.png"
    img_path.write_bytes(_minimal_png())
    return map_store.add_floor_plan(
        plan_id=plan_id,
        name="Building A - Floor 1",
        image_path=str(img_path),
        building="Building A",
        floor="1",
        description="Main floor",
        origin_x=0.0,
        origin_y=0.0,
        scale_x=0.1,
        scale_y=0.1,
        width_px=100,
        height_px=80,
    )


# ===========================================================================
# Storage tests
# ===========================================================================


class TestMapStore:
    """Tests for MapStore storage layer."""

    def test_add_floor_plan(self, map_store: MapStore, tmp_path: Path):
        plan_id = _make_plan_id()
        img = tmp_path / "test.png"
        img.write_bytes(_minimal_png())
        result = map_store.add_floor_plan(
            plan_id=plan_id,
            name="Test Plan",
            image_path=str(img),
            building="B1",
            floor="2",
        )
        assert result["id"] == plan_id
        assert result["name"] == "Test Plan"
        assert result["building"] == "B1"
        assert result["floor"] == "2"
        assert isinstance(result["created_at"], str)

    def test_get_floor_plan(self, map_store: MapStore, sample_plan: dict):
        plan = map_store.get_floor_plan(sample_plan["id"])
        assert isinstance(plan, dict)
        assert plan["name"] == "Building A - Floor 1"
        assert plan["building"] == "Building A"

    def test_get_floor_plan_not_found(self, map_store: MapStore):
        assert map_store.get_floor_plan("nonexistent") is None

    def test_list_floor_plans(self, map_store: MapStore, sample_plan: dict):
        plans = map_store.list_floor_plans()
        assert isinstance(plans, list)
        assert len(plans) >= 1
        assert any(p["id"] == sample_plan["id"] for p in plans)

    def test_list_filter_building(self, map_store: MapStore, sample_plan: dict, tmp_path: Path):
        # Add another plan in different building
        pid2 = _make_plan_id()
        img = tmp_path / f"{pid2}.png"
        img.write_bytes(_minimal_png())
        map_store.add_floor_plan(
            plan_id=pid2, name="Other", image_path=str(img), building="Building B"
        )
        plans_a = map_store.list_floor_plans(building="Building A")
        plans_b = map_store.list_floor_plans(building="Building B")
        assert isinstance(plans_a, list)
        assert isinstance(plans_b, list)
        assert len(plans_a) >= 1
        assert len(plans_b) >= 1
        assert all(p["building"] == "Building A" for p in plans_a)
        assert all(p["building"] == "Building B" for p in plans_b)

    def test_update_floor_plan(self, map_store: MapStore, sample_plan: dict):
        updated = map_store.update_floor_plan(
            sample_plan["id"], name="Updated Name", scale_x=0.5
        )
        assert isinstance(updated, dict)
        assert updated["name"] == "Updated Name"
        assert updated["scale_x"] == 0.5

    def test_update_floor_plan_not_found(self, map_store: MapStore):
        result = map_store.update_floor_plan("nonexistent", name="X")
        assert result is None

    def test_delete_floor_plan(self, map_store: MapStore, sample_plan: dict):
        # Add a zone first
        map_store.add_zone(
            zone_id="z1", floor_plan_id=sample_plan["id"],
            name="Zone 1", polygon=[[0, 0], [10, 0], [10, 10]],
        )
        deleted = map_store.delete_floor_plan(sample_plan["id"])
        assert deleted is True
        assert map_store.get_floor_plan(sample_plan["id"]) is None
        # Zones should be deleted too
        assert len(map_store.get_zones(sample_plan["id"])) == 0

    def test_delete_floor_plan_not_found(self, map_store: MapStore):
        assert map_store.delete_floor_plan("nonexistent") is False

    def test_add_zone(self, map_store: MapStore, sample_plan: dict):
        zone = map_store.add_zone(
            zone_id="z1",
            floor_plan_id=sample_plan["id"],
            name="Restricted Area",
            polygon=[[0, 0], [5, 0], [5, 5], [0, 5]],
            zone_type="restricted",
            color="#ff0000",
        )
        assert zone["name"] == "Restricted Area"
        assert zone["zone_type"] == "restricted"
        assert zone["color"] == "#ff0000"
        assert len(zone["polygon"]) == 4

    def test_get_zones(self, map_store: MapStore, sample_plan: dict):
        map_store.add_zone(
            zone_id="z1", floor_plan_id=sample_plan["id"],
            name="Zone A", polygon=[[0, 0], [1, 0], [1, 1]],
        )
        map_store.add_zone(
            zone_id="z2", floor_plan_id=sample_plan["id"],
            name="Zone B", polygon=[[2, 2], [3, 2], [3, 3]],
        )
        zones = map_store.get_zones(sample_plan["id"])
        assert len(zones) == 2
        # Polygon should be parsed from JSON
        assert isinstance(zones[0]["polygon"], list)

    def test_delete_zone(self, map_store: MapStore, sample_plan: dict):
        map_store.add_zone(
            zone_id="z1", floor_plan_id=sample_plan["id"],
            name="Zone", polygon=[[0, 0], [1, 0], [1, 1]],
        )
        assert map_store.delete_zone("z1") is True
        assert len(map_store.get_zones(sample_plan["id"])) == 0

    def test_delete_zone_not_found(self, map_store: MapStore):
        assert map_store.delete_zone("nonexistent") is False

    def test_local_to_pixel(self, map_store: MapStore, sample_plan: dict):
        # scale_x = 0.1, scale_y = 0.1, origin at (0,0), no rotation
        # local (1.0, 2.0) -> pixel (10.0, 20.0)
        result = map_store.local_to_pixel(sample_plan["id"], 1.0, 2.0)
        assert isinstance(result, tuple)
        px, py = result
        assert abs(px - 10.0) < 0.01
        assert abs(py - 20.0) < 0.01

    def test_local_to_pixel_not_found(self, map_store: MapStore):
        assert map_store.local_to_pixel("nonexistent", 0, 0) is None

    def test_pixel_to_local(self, map_store: MapStore, sample_plan: dict):
        # Inverse of local_to_pixel
        result = map_store.pixel_to_local(sample_plan["id"], 10.0, 20.0)
        assert isinstance(result, tuple)
        x, y = result
        assert abs(x - 1.0) < 0.01
        assert abs(y - 2.0) < 0.01

    def test_pixel_to_local_not_found(self, map_store: MapStore):
        assert map_store.pixel_to_local("nonexistent", 0, 0) is None

    def test_roundtrip_conversion(self, map_store: MapStore, sample_plan: dict):
        """local -> pixel -> local should give back original coords."""
        orig_x, orig_y = 3.5, 7.2
        px_result = map_store.local_to_pixel(sample_plan["id"], orig_x, orig_y)
        assert isinstance(px_result, tuple)
        local_result = map_store.pixel_to_local(sample_plan["id"], *px_result)
        assert isinstance(local_result, tuple)
        assert abs(local_result[0] - orig_x) < 0.01
        assert abs(local_result[1] - orig_y) < 0.01

    def test_stats(self, map_store: MapStore, sample_plan: dict):
        map_store.add_zone(
            zone_id="z1", floor_plan_id=sample_plan["id"],
            name="Zone", polygon=[[0, 0], [1, 0], [1, 1]],
        )
        stats = map_store.get_stats()
        assert isinstance(stats, dict)
        assert isinstance(stats["floor_plans"], int)
        assert stats["floor_plans"] >= 1
        assert isinstance(stats["zones"], int)
        assert stats["zones"] >= 1
        assert isinstance(stats["buildings"], int)
        assert stats["buildings"] >= 1


# ===========================================================================
# API tests
# ===========================================================================


class TestMapAPI:
    """Tests for map REST API endpoints."""

    def test_list_floor_plans_empty(self, map_client: TestClient):
        resp = map_client.get("/api/maps/floor-plans")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_create_floor_plan(self, map_client: TestClient):
        png = _minimal_png()
        resp = map_client.post(
            "/api/maps/floor-plans",
            files={"image": ("plan.png", png, "image/png")},
            data={
                "name": "Test Plan",
                "building": "HQ",
                "floor": "1",
                "scale_x": "0.05",
                "scale_y": "0.05",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Test Plan"
        assert data["building"] == "HQ"
        assert isinstance(data["id"], str)

    def test_create_requires_admin(self, map_app: FastAPI):
        """Non-ADMIN key should get 403."""
        from sigrift.lib.security.credentials import generate_api_key, hash_credential
        viewer_key = generate_api_key(length=32)
        h, s = hash_credential(viewer_key)
        map_app.state.persistence.set_key("viewer1", h, s)
        map_app.state.persistence.set_key_meta("viewer1", {"role": "viewer"})
        client = TestClient(map_app, headers={"X-API-Key": viewer_key})
        resp = client.post(
            "/api/maps/floor-plans",
            files={"image": ("plan.png", _minimal_png(), "image/png")},
            data={"name": "Blocked"},
        )
        assert resp.status_code == 403

    def test_get_floor_plan(self, map_client: TestClient):
        # Create first
        png = _minimal_png()
        create_resp = map_client.post(
            "/api/maps/floor-plans",
            files={"image": ("plan.png", png, "image/png")},
            data={"name": "Get Test"},
        )
        plan_id = create_resp.json()["id"]

        resp = map_client.get(f"/api/maps/floor-plans/{plan_id}")
        assert resp.status_code == 200
        assert resp.json()["name"] == "Get Test"

    def test_get_floor_plan_not_found(self, map_client: TestClient):
        resp = map_client.get("/api/maps/floor-plans/nonexistent")
        assert resp.status_code == 404

    def test_update_floor_plan(self, map_client: TestClient):
        create_resp = map_client.post(
            "/api/maps/floor-plans",
            files={"image": ("plan.png", _minimal_png(), "image/png")},
            data={"name": "Update Test"},
        )
        plan_id = create_resp.json()["id"]

        resp = map_client.put(
            f"/api/maps/floor-plans/{plan_id}",
            json={"name": "Updated", "scale_x": 0.25},
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Updated"
        assert resp.json()["scale_x"] == 0.25

    def test_update_not_found(self, map_client: TestClient):
        resp = map_client.put(
            "/api/maps/floor-plans/nonexistent",
            json={"name": "X"},
        )
        assert resp.status_code == 404

    def test_delete_floor_plan(self, map_client: TestClient):
        create_resp = map_client.post(
            "/api/maps/floor-plans",
            files={"image": ("plan.png", _minimal_png(), "image/png")},
            data={"name": "Delete Test"},
        )
        plan_id = create_resp.json()["id"]

        resp = map_client.delete(f"/api/maps/floor-plans/{plan_id}")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        # Verify deleted
        resp2 = map_client.get(f"/api/maps/floor-plans/{plan_id}")
        assert resp2.status_code == 404

    def test_delete_requires_admin(self, map_app: FastAPI):
        """Non-ADMIN key should get 403."""
        from sigrift.lib.security.credentials import generate_api_key, hash_credential
        viewer_key = generate_api_key(length=32)
        h, s = hash_credential(viewer_key)
        map_app.state.persistence.set_key("viewer2", h, s)
        map_app.state.persistence.set_key_meta("viewer2", {"role": "viewer"})
        client = TestClient(map_app, headers={"X-API-Key": viewer_key})
        resp = client.delete("/api/maps/floor-plans/anything")
        assert resp.status_code == 403

    def test_serve_image(self, map_client: TestClient):
        png = _minimal_png()
        create_resp = map_client.post(
            "/api/maps/floor-plans",
            files={"image": ("plan.png", png, "image/png")},
            data={"name": "Image Test"},
        )
        plan_id = create_resp.json()["id"]

        resp = map_client.get(f"/api/maps/floor-plans/{plan_id}/image")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "image/png"
        assert resp.content[:4] == b"\x89PNG"

    def test_serve_image_not_found(self, map_client: TestClient):
        resp = map_client.get("/api/maps/floor-plans/nonexistent/image")
        assert resp.status_code == 404

    def test_add_zone(self, map_client: TestClient):
        # Create plan first
        create_resp = map_client.post(
            "/api/maps/floor-plans",
            files={"image": ("plan.png", _minimal_png(), "image/png")},
            data={"name": "Zone Test"},
        )
        plan_id = create_resp.json()["id"]

        resp = map_client.post(
            f"/api/maps/floor-plans/{plan_id}/zones",
            json={
                "name": "Server Room",
                "polygon": [[0, 0], [10, 0], [10, 10], [0, 10]],
                "zone_type": "restricted",
                "color": "#ff0000",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Server Room"
        assert data["zone_type"] == "restricted"

    def test_add_zone_plan_not_found(self, map_client: TestClient):
        resp = map_client.post(
            "/api/maps/floor-plans/nonexistent/zones",
            json={
                "name": "Zone",
                "polygon": [[0, 0], [1, 0], [1, 1]],
            },
        )
        assert resp.status_code == 404

    def test_get_zones(self, map_client: TestClient):
        create_resp = map_client.post(
            "/api/maps/floor-plans",
            files={"image": ("plan.png", _minimal_png(), "image/png")},
            data={"name": "Zones List Test"},
        )
        plan_id = create_resp.json()["id"]

        # Add two zones
        for name in ["Zone A", "Zone B"]:
            map_client.post(
                f"/api/maps/floor-plans/{plan_id}/zones",
                json={"name": name, "polygon": [[0, 0], [1, 0], [1, 1]]},
            )

        resp = map_client.get(f"/api/maps/floor-plans/{plan_id}/zones")
        assert resp.status_code == 200
        zones = resp.json()
        assert len(zones) == 2

    def test_delete_zone(self, map_client: TestClient):
        create_resp = map_client.post(
            "/api/maps/floor-plans",
            files={"image": ("plan.png", _minimal_png(), "image/png")},
            data={"name": "Del Zone Test"},
        )
        plan_id = create_resp.json()["id"]

        zone_resp = map_client.post(
            f"/api/maps/floor-plans/{plan_id}/zones",
            json={"name": "Temp Zone", "polygon": [[0, 0], [1, 0], [1, 1]]},
        )
        zone_id = zone_resp.json()["id"]

        resp = map_client.delete(f"/api/maps/zones/{zone_id}")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_delete_zone_not_found(self, map_client: TestClient):
        resp = map_client.delete("/api/maps/zones/nonexistent")
        assert resp.status_code == 404

    def test_view_combined(self, map_client: TestClient):
        create_resp = map_client.post(
            "/api/maps/floor-plans",
            files={"image": ("plan.png", _minimal_png(), "image/png")},
            data={"name": "View Test", "scale_x": "0.1", "scale_y": "0.1"},
        )
        plan_id = create_resp.json()["id"]

        # Add a zone
        map_client.post(
            f"/api/maps/floor-plans/{plan_id}/zones",
            json={"name": "Main", "polygon": [[0, 0], [5, 0], [5, 5]]},
        )

        resp = map_client.get(f"/api/maps/view/{plan_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert "floor_plan" in data
        assert isinstance(data["floor_plan"], dict)
        assert "name" in data["floor_plan"]
        assert "nodes" in data
        assert isinstance(data["nodes"], list)
        assert "emitters" in data
        assert isinstance(data["emitters"], list)
        assert "zones" in data
        assert isinstance(data["zones"], list)
        assert data["floor_plan"]["image_url"] == f"/api/maps/floor-plans/{plan_id}/image"
        assert len(data["zones"]) == 1

    def test_view_not_found(self, map_client: TestClient):
        resp = map_client.get("/api/maps/view/nonexistent")
        assert resp.status_code == 404

    def test_overlay(self, map_client: TestClient):
        resp = map_client.get("/api/maps/overlay")
        assert resp.status_code == 200
        data = resp.json()
        assert "nodes" in data
        assert isinstance(data["nodes"], list)
        assert "emitters" in data
        assert isinstance(data["emitters"], list)
        assert "floor_plans" in data
        assert isinstance(data["floor_plans"], list)

    def test_overlay_with_geo_plan(self, map_client: TestClient):
        """Floor plans with geo coords should appear in overlay."""
        create_resp = map_client.post(
            "/api/maps/floor-plans",
            files={"image": ("plan.png", _minimal_png(), "image/png")},
            data={
                "name": "Geo Plan",
                "geo_lat": "37.7749",
                "geo_lon": "-122.4194",
                "scale_x": "0.1",
                "scale_y": "0.1",
            },
        )
        assert create_resp.status_code == 201

        resp = map_client.get("/api/maps/overlay")
        data = resp.json()
        assert len(data["floor_plans"]) >= 1
        geo_plan = data["floor_plans"][0]
        assert isinstance(geo_plan, dict)
        assert "bounds" in geo_plan
        assert isinstance(geo_plan["bounds"], list)
        assert len(geo_plan["bounds"]) == 2

    def test_stats(self, map_client: TestClient):
        # Create a plan and zone
        create_resp = map_client.post(
            "/api/maps/floor-plans",
            files={"image": ("plan.png", _minimal_png(), "image/png")},
            data={"name": "Stats Test", "building": "HQ"},
        )
        plan_id = create_resp.json()["id"]
        map_client.post(
            f"/api/maps/floor-plans/{plan_id}/zones",
            json={"name": "Zone", "polygon": [[0, 0], [1, 0], [1, 1]]},
        )

        resp = map_client.get("/api/maps/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["floor_plans"], int)
        assert data["floor_plans"] >= 1
        assert isinstance(data["zones"], int)
        assert data["zones"] >= 1
        assert isinstance(data["buildings"], int)
        assert data["buildings"] >= 1

    def test_list_with_building_filter(self, map_client: TestClient):
        """GET /floor-plans?building=X filters correctly."""
        for bld in ["Alpha", "Beta"]:
            map_client.post(
                "/api/maps/floor-plans",
                files={"image": ("plan.png", _minimal_png(), "image/png")},
                data={"name": f"{bld} Plan", "building": bld},
            )

        resp = map_client.get("/api/maps/floor-plans?building=Alpha")
        assert resp.status_code == 200
        plans = resp.json()
        assert all(p["building"] == "Alpha" for p in plans)

    def test_create_parses_png_dimensions(self, map_client: TestClient):
        """Upload should parse width/height from PNG header."""
        png = _minimal_png()
        resp = map_client.post(
            "/api/maps/floor-plans",
            files={"image": ("plan.png", png, "image/png")},
            data={"name": "Dimensions Test"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["width_px"] == 1
        assert data["height_px"] == 1
