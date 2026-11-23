"""Tests for MBTiles offline map support (A-48).

Unit tests cover tile serving, format detection, metadata, status, delete.
Integration tests cover upload with validation, TMS y-flip math, and
end-to-end upload -> serve -> delete lifecycle.
"""

import io
import os
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware

from sigrift.bridge.routers import mbtiles


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_mbtiles(
    path: Path,
    tiles: list[tuple[int, int, int, bytes]] | None = None,
    metadata: dict[str, str] | None = None,
) -> None:
    """Create a minimal MBTiles file."""
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE metadata (name TEXT, value TEXT)")
    conn.execute(
        "CREATE TABLE tiles (zoom_level INTEGER, tile_column INTEGER, "
        "tile_row INTEGER, tile_data BLOB)"
    )
    conn.execute(
        "CREATE UNIQUE INDEX idx_tiles ON tiles (zoom_level, tile_column, tile_row)"
    )
    meta = {"name": "Test Tiles", "format": "png", "bounds": "-180,-85,180,85",
            "minzoom": "0", "maxzoom": "5"}
    if metadata:
        meta.update(metadata)
    for k, v in meta.items():
        conn.execute("INSERT INTO metadata VALUES (?, ?)", (k, v))
    if tiles:
        for z, x, y, data in tiles:
            conn.execute("INSERT INTO tiles VALUES (?, ?, ?, ?)", (z, x, y, data))
    conn.commit()
    conn.close()


def _create_mbtiles_bytes(
    tiles: list[tuple[int, int, int, bytes]] | None = None,
) -> bytes:
    """Create an MBTiles file in memory and return its bytes."""
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".mbtiles", delete=False) as f:
        tmp = Path(f.name)
    _create_mbtiles(tmp, tiles=tiles)
    data = tmp.read_bytes()
    tmp.unlink()
    return data


def _make_app(mbtiles_path: str | None = None) -> FastAPI:
    """Create a FastAPI app with mbtiles router and mock auth."""
    app = FastAPI()

    from sigrift.bridge.dependencies import require_api_key, rate_limit, Role

    app.dependency_overrides[require_api_key] = lambda: "test-key"
    app.dependency_overrides[rate_limit] = lambda: "test-key"

    class _FakeAuth(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.key_role = Role.ADMIN
            return await call_next(request)

    app.add_middleware(_FakeAuth)
    app.include_router(mbtiles.router, prefix="/api/maps")
    return app


# ---------------------------------------------------------------------------
# Tile data constants
# ---------------------------------------------------------------------------

PNG_DATA = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
JPEG_DATA = b"\xff\xd8\xff\xe0" + b"\x00" * 50
WEBP_DATA = b"RIFF" + b"\x00" * 4 + b"WEBP" + b"\x00" * 40
import gzip as _gzip
GZIP_DATA = _gzip.compress(b"fake pbf vector tile data")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_mbtiles(tmp_path):
    """Create a temporary MBTiles file with test tiles."""
    path = tmp_path / "test.mbtiles"
    _create_mbtiles(path, tiles=[
        # TMS coordinates
        (0, 0, 0, PNG_DATA),
        (1, 0, 1, PNG_DATA),       # z=1, tms_y=1 -> xyz_y=0
        (1, 1, 0, JPEG_DATA),      # z=1, tms_y=0 -> xyz_y=1
        (2, 0, 0, WEBP_DATA),      # z=2, tms_y=0 -> xyz_y=3
        (2, 1, 1, GZIP_DATA),      # z=2, tms_y=1 -> xyz_y=2
    ])
    return path


# ---------------------------------------------------------------------------
# Unit: status
# ---------------------------------------------------------------------------

def test_mbtiles_status_not_installed(tmp_path):
    """Status returns installed=false when no file exists."""
    path = tmp_path / "missing.mbtiles"
    app = _make_app()
    client = TestClient(app)

    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(path)}):
        resp = client.get("/api/maps/tiles/status")
    assert resp.status_code == 200
    assert resp.json()["installed"] is False


def test_mbtiles_status_installed(tmp_mbtiles):
    """Status returns metadata when an MBTiles file is present."""
    app = _make_app()
    client = TestClient(app)

    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(tmp_mbtiles)}):
        resp = client.get("/api/maps/tiles/status")
    data = resp.json()
    assert data["installed"] is True
    assert data["name"] == "Test Tiles"
    assert data["tile_count"] == 5
    assert "size_mb" in data
    assert isinstance(data["size_mb"], (int, float))


# ---------------------------------------------------------------------------
# Unit: tile serving and format detection
# ---------------------------------------------------------------------------

def test_serve_tile_png(tmp_mbtiles):
    """PNG tile detected and served with correct content-type."""
    app = _make_app()
    client = TestClient(app)

    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(tmp_mbtiles)}):
        resp = client.get("/api/maps/tiles/0/0/0")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/png"
    assert resp.headers["cache-control"] == "public, max-age=86400"
    assert resp.content[:4] == b"\x89PNG"


def test_serve_tile_jpeg(tmp_mbtiles):
    """JPEG tile detected and served with correct content-type."""
    app = _make_app()
    client = TestClient(app)

    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(tmp_mbtiles)}):
        # z=1, x=1, XYZ y=1 -> TMS y = 2^1-1-1 = 0
        resp = client.get("/api/maps/tiles/1/1/1")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/jpeg"


def test_serve_tile_webp(tmp_mbtiles):
    """WebP tile detected and served with correct content-type."""
    app = _make_app()
    client = TestClient(app)

    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(tmp_mbtiles)}):
        # z=2, x=0, XYZ y=3 -> TMS y = 2^2-1-3 = 0
        resp = client.get("/api/maps/tiles/2/0/3")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/webp"


def test_serve_tile_gzip_pbf(tmp_mbtiles):
    """Gzip-compressed PBF tile detected as protobuf with Content-Encoding."""
    app = _make_app()
    client = TestClient(app)

    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(tmp_mbtiles)}):
        # z=2, x=1, XYZ y=2 -> TMS y = 2^2-1-2 = 1
        resp = client.get("/api/maps/tiles/2/1/2")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/x-protobuf"


def test_serve_tile_not_found(tmp_mbtiles):
    """Missing tile returns 404."""
    app = _make_app()
    client = TestClient(app)

    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(tmp_mbtiles)}):
        resp = client.get("/api/maps/tiles/5/999/999")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Unit: TMS y-flip correctness
# ---------------------------------------------------------------------------

def test_tms_y_flip_z0():
    """At z=0, XYZ y=0 -> TMS y=0 (only one tile)."""
    app = _make_app()
    client = TestClient(app)
    path = "/tmp/tms_test_z0.mbtiles"
    _create_mbtiles(Path(path), tiles=[(0, 0, 0, PNG_DATA)])

    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": path}):
        resp = client.get("/api/maps/tiles/0/0/0")
    assert resp.status_code == 200
    Path(path).unlink(missing_ok=True)


def test_tms_y_flip_z1():
    """At z=1: XYZ y=0 -> TMS y=1, XYZ y=1 -> TMS y=0."""
    app = _make_app()
    client = TestClient(app)
    path = "/tmp/tms_test_z1.mbtiles"
    # Store tiles at TMS y=0 and TMS y=1
    _create_mbtiles(Path(path), tiles=[
        (1, 0, 0, b"\xff\xd8" + b"\x00" * 10),  # TMS y=0 -> should be XYZ y=1
        (1, 0, 1, PNG_DATA),                      # TMS y=1 -> should be XYZ y=0
    ])

    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": path}):
        # XYZ y=0 should hit TMS y=1 (PNG)
        resp = client.get("/api/maps/tiles/1/0/0")
        assert resp.headers["content-type"] == "image/png"

        # XYZ y=1 should hit TMS y=0 (JPEG)
        resp = client.get("/api/maps/tiles/1/0/1")
        assert resp.headers["content-type"] == "image/jpeg"

    Path(path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Unit: metadata
# ---------------------------------------------------------------------------

def test_metadata_endpoint(tmp_mbtiles):
    """Get metadata returns all key-value pairs."""
    app = _make_app()
    client = TestClient(app)

    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(tmp_mbtiles)}):
        resp = client.get("/api/maps/tiles/metadata")
    data = resp.json()
    assert data["name"] == "Test Tiles"
    assert data["format"] == "png"
    assert data["minzoom"] == "0"
    assert data["maxzoom"] == "5"
    assert data["bounds"] == "-180,-85,180,85"


# ---------------------------------------------------------------------------
# Unit: delete
# ---------------------------------------------------------------------------

def test_delete_mbtiles(tmp_mbtiles):
    """Delete removes the MBTiles bundle."""
    app = _make_app()
    client = TestClient(app)

    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(tmp_mbtiles)}):
        resp = client.delete("/api/maps/tiles")
    assert resp.status_code == 200
    assert not tmp_mbtiles.exists()


def test_delete_mbtiles_not_found(tmp_path):
    """Delete returns 404 when no bundle installed."""
    path = tmp_path / "missing.mbtiles"
    app = _make_app()
    client = TestClient(app)

    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(path)}):
        resp = client.delete("/api/maps/tiles")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Integration: upload validation
# ---------------------------------------------------------------------------

def test_upload_valid_mbtiles(tmp_path):
    """Upload a valid MBTiles file returns 201 with tile_count."""
    app = _make_app()
    target = tmp_path / "uploaded.mbtiles"
    client = TestClient(app)

    mbtiles_bytes = _create_mbtiles_bytes(tiles=[
        (0, 0, 0, PNG_DATA),
        (1, 0, 0, PNG_DATA),
    ])

    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(target)}):
        resp = client.post(
            "/api/maps/tiles/upload",
            files={"file": ("map.mbtiles", io.BytesIO(mbtiles_bytes), "application/octet-stream")},
        )
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "installed"
    assert data["tile_count"] == 2
    assert target.exists()


def test_upload_rejects_wrong_extension(tmp_path):
    """Upload rejects files without .mbtiles extension."""
    app = _make_app()
    target = tmp_path / "uploaded.mbtiles"
    client = TestClient(app)

    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(target)}):
        resp = client.post(
            "/api/maps/tiles/upload",
            files={"file": ("map.sqlite", io.BytesIO(b"not a real file"), "application/octet-stream")},
        )
    assert resp.status_code == 400
    assert "extension" in resp.json()["detail"].lower()


def test_upload_rejects_non_sqlite(tmp_path):
    """Upload rejects files that aren't valid SQLite databases."""
    app = _make_app()
    target = tmp_path / "uploaded.mbtiles"
    client = TestClient(app)

    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(target)}):
        resp = client.post(
            "/api/maps/tiles/upload",
            files={"file": ("bad.mbtiles", io.BytesIO(b"this is not sqlite"), "application/octet-stream")},
        )
    assert resp.status_code == 400


def test_upload_rejects_missing_tiles_table(tmp_path):
    """Upload rejects an SQLite DB that has no 'tiles' table."""
    app = _make_app()
    target = tmp_path / "uploaded.mbtiles"
    client = TestClient(app)

    # Create a valid SQLite but without tiles table
    bad_db = tmp_path / "no_tiles.mbtiles"
    conn = sqlite3.connect(str(bad_db))
    conn.execute("CREATE TABLE metadata (name TEXT, value TEXT)")
    conn.execute("INSERT INTO metadata VALUES ('name', 'Bad DB')")
    conn.commit()
    conn.close()
    bad_bytes = bad_db.read_bytes()

    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(target)}):
        resp = client.post(
            "/api/maps/tiles/upload",
            files={"file": ("bad.mbtiles", io.BytesIO(bad_bytes), "application/octet-stream")},
        )
    assert resp.status_code == 400
    assert "tiles" in resp.json()["detail"].lower()


def test_upload_rejects_missing_metadata_table(tmp_path):
    """Upload rejects an SQLite DB that has no 'metadata' table."""
    app = _make_app()
    target = tmp_path / "uploaded.mbtiles"
    client = TestClient(app)

    bad_db = tmp_path / "no_meta.mbtiles"
    conn = sqlite3.connect(str(bad_db))
    conn.execute(
        "CREATE TABLE tiles (zoom_level INTEGER, tile_column INTEGER, "
        "tile_row INTEGER, tile_data BLOB)"
    )
    conn.commit()
    conn.close()
    bad_bytes = bad_db.read_bytes()

    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(target)}):
        resp = client.post(
            "/api/maps/tiles/upload",
            files={"file": ("bad.mbtiles", io.BytesIO(bad_bytes), "application/octet-stream")},
        )
    assert resp.status_code == 400
    assert "metadata" in resp.json()["detail"].lower()


def test_upload_size_limit(tmp_path):
    """Upload rejects files exceeding BRIDGE_MBTILES_MAX_UPLOAD_MB."""
    app = _make_app()
    target = tmp_path / "uploaded.mbtiles"
    client = TestClient(app)

    # Set a tiny limit (1 byte effectively)
    with patch.dict(os.environ, {
        "BRIDGE_MBTILES_PATH": str(target),
        "BRIDGE_MBTILES_MAX_UPLOAD_MB": "0",
    }):
        resp = client.post(
            "/api/maps/tiles/upload",
            files={"file": ("big.mbtiles", io.BytesIO(b"\x00" * 1024), "application/octet-stream")},
        )
    # 0 MB limit means 0 bytes — any upload exceeds it
    assert resp.status_code == 413


# ---------------------------------------------------------------------------
# Integration: upload -> serve -> delete lifecycle
# ---------------------------------------------------------------------------

def test_full_lifecycle(tmp_path):
    """Upload a bundle, serve tiles from it, verify metadata, then delete."""
    app = _make_app()
    target = tmp_path / "lifecycle.mbtiles"
    client = TestClient(app)

    # 1. Initially not installed
    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(target)}):
        resp = client.get("/api/maps/tiles/status")
        assert resp.json()["installed"] is False

    # 2. Upload
    mbtiles_bytes = _create_mbtiles_bytes(tiles=[
        (0, 0, 0, PNG_DATA),
        (1, 0, 1, JPEG_DATA),  # TMS y=1 -> XYZ y=0
    ])
    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(target)}):
        resp = client.post(
            "/api/maps/tiles/upload",
            files={"file": ("tiles.mbtiles", io.BytesIO(mbtiles_bytes), "application/octet-stream")},
        )
        assert resp.status_code == 201

    # 3. Verify status
    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(target)}):
        resp = client.get("/api/maps/tiles/status")
        data = resp.json()
        assert data["installed"] is True
        assert data["tile_count"] == 2

    # 4. Serve a tile
    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(target)}):
        resp = client.get("/api/maps/tiles/0/0/0")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "image/png"

    # 5. Serve the JPEG tile via y-flip
    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(target)}):
        resp = client.get("/api/maps/tiles/1/0/0")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "image/jpeg"

    # 6. Check metadata
    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(target)}):
        resp = client.get("/api/maps/tiles/metadata")
        assert resp.json()["name"] == "Test Tiles"

    # 7. Delete
    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(target)}):
        resp = client.delete("/api/maps/tiles")
        assert resp.status_code == 200
        assert not target.exists()

    # 8. Confirm not installed
    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(target)}):
        resp = client.get("/api/maps/tiles/status")
        assert resp.json()["installed"] is False


# ---------------------------------------------------------------------------
# Edge cases: corrupt files, unknown formats, upload replace
# ---------------------------------------------------------------------------

def test_status_corrupt_mbtiles(tmp_path):
    """Status returns installed=True with error when MBTiles is corrupt."""
    path = tmp_path / "corrupt.mbtiles"
    path.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)  # fake header
    app = _make_app()
    client = TestClient(app)

    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(path)}):
        resp = client.get("/api/maps/tiles/status")
    data = resp.json()
    assert data["installed"] is True
    assert "error" in data
    assert isinstance(data["error"], str)


def test_serve_tile_unknown_format_defaults_to_pbf(tmp_path):
    """Unknown tile format defaults to application/x-protobuf."""
    path = tmp_path / "unknown_fmt.mbtiles"
    unknown_data = b"\x00\x01\x02\x03" + b"\xff" * 50  # no known magic bytes
    _create_mbtiles(path, tiles=[(0, 0, 0, unknown_data)])
    app = _make_app()
    client = TestClient(app)

    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(path)}):
        resp = client.get("/api/maps/tiles/0/0/0")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/x-protobuf"


def test_upload_replaces_existing(tmp_path):
    """Upload replaces an existing MBTiles bundle atomically."""
    target = tmp_path / "replace.mbtiles"
    app = _make_app()
    client = TestClient(app)

    # First upload
    bytes1 = _create_mbtiles_bytes(tiles=[(0, 0, 0, PNG_DATA)])
    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(target)}):
        resp = client.post(
            "/api/maps/tiles/upload",
            files={"file": ("v1.mbtiles", io.BytesIO(bytes1), "application/octet-stream")},
        )
        assert resp.status_code == 201
        assert resp.json()["tile_count"] == 1

    # Second upload with more tiles
    bytes2 = _create_mbtiles_bytes(tiles=[
        (0, 0, 0, PNG_DATA),
        (1, 0, 0, JPEG_DATA),
        (1, 1, 0, JPEG_DATA),
    ])
    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(target)}):
        resp = client.post(
            "/api/maps/tiles/upload",
            files={"file": ("v2.mbtiles", io.BytesIO(bytes2), "application/octet-stream")},
        )
        assert resp.status_code == 201
        assert resp.json()["tile_count"] == 3

    # Verify new data is served
    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(target)}):
        resp = client.get("/api/maps/tiles/status")
        assert resp.json()["tile_count"] == 3


def test_serve_tile_no_bundle_returns_404(tmp_path):
    """Requesting a tile when no bundle is installed returns 404."""
    path = tmp_path / "nonexistent.mbtiles"
    app = _make_app()
    client = TestClient(app)

    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(path)}):
        resp = client.get("/api/maps/tiles/0/0/0")
    assert resp.status_code == 404


def test_metadata_no_bundle_returns_404(tmp_path):
    """Requesting metadata when no bundle is installed returns 404."""
    path = tmp_path / "nonexistent.mbtiles"
    app = _make_app()
    client = TestClient(app)

    with patch.dict(os.environ, {"BRIDGE_MBTILES_PATH": str(path)}):
        resp = client.get("/api/maps/tiles/metadata")
    assert resp.status_code == 404
