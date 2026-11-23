"""MBTiles offline map tile server for air-gapped/SCIF deployments.

Serves map tiles from a local MBTiles (SQLite) file so the dashboard
works without internet access.  Supports standard TMS/XYZ tile URLs.

Configuration:
  - BRIDGE_MBTILES_PATH: Path to .mbtiles file (default: data/offline.mbtiles)
  - BRIDGE_MBTILES_MAX_UPLOAD_MB: Maximum upload size in MB (default: 500)
"""

from __future__ import annotations

import logging
import os
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, status
from fastapi.responses import Response

from sigrift.bridge.dependencies import Role, require_role

logger = logging.getLogger(__name__)

router = APIRouter()

_DEFAULT_MBTILES_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "offline.mbtiles"
)
_MAX_UPLOAD_MB = 500


def _get_mbtiles_path() -> Path:
    raw = os.environ.get("BRIDGE_MBTILES_PATH", "").strip()
    if raw:
        return Path(raw)
    return _DEFAULT_MBTILES_PATH


def _get_max_upload_bytes() -> int:
    raw = os.environ.get("BRIDGE_MBTILES_MAX_UPLOAD_MB", "").strip()
    try:
        return int(raw) * 1024 * 1024 if raw else _MAX_UPLOAD_MB * 1024 * 1024
    except ValueError:
        return _MAX_UPLOAD_MB * 1024 * 1024


def _open_mbtiles(path: Path) -> sqlite3.Connection:
    """Open an MBTiles file read-only."""
    if not path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No offline map bundle installed",
        )
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


@router.get("/tiles/status")
def mbtiles_status(
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Check if an offline map bundle is installed."""
    path = _get_mbtiles_path()
    if not path.exists():
        return {"installed": False, "path": str(path)}

    try:
        conn = _open_mbtiles(path)
        metadata = {}
        for row in conn.execute("SELECT name, value FROM metadata"):
            metadata[row["name"]] = row["value"]
        tile_count = conn.execute("SELECT COUNT(*) as cnt FROM tiles").fetchone()["cnt"]
        conn.close()

        return {
            "installed": True,
            "path": str(path),
            "name": metadata.get("name", ""),
            "description": metadata.get("description", ""),
            "format": metadata.get("format", ""),
            "bounds": metadata.get("bounds", ""),
            "minzoom": metadata.get("minzoom", ""),
            "maxzoom": metadata.get("maxzoom", ""),
            "tile_count": tile_count,
            "size_mb": round(path.stat().st_size / (1024 * 1024), 1),
        }
    except Exception as exc:
        logger.warning("Failed to read MBTiles metadata: %s", exc)
        return {"installed": True, "path": str(path), "error": str(exc)}


@router.get("/tiles/{z}/{x}/{y}")
def serve_tile(
    z: int,
    x: int,
    y: int,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> Response:
    """Serve a map tile from the offline MBTiles bundle.

    Uses TMS y-axis convention (flipped from XYZ).  The tile endpoint
    automatically flips y for standard web map libraries.
    """
    path = _get_mbtiles_path()
    conn = _open_mbtiles(path)

    # TMS y-flip: MBTiles uses TMS convention where y=0 is at bottom
    tms_y = (1 << z) - 1 - y

    try:
        row = conn.execute(
            "SELECT tile_data FROM tiles WHERE zoom_level = ? AND tile_column = ? AND tile_row = ?",
            (z, x, tms_y),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tile not found: {z}/{x}/{y}",
        )

    tile_data = row["tile_data"]

    # Detect format from content
    if tile_data[:2] == b"\x1f\x8b":
        # gzip-compressed (PBF/MVT)
        return Response(
            content=tile_data,
            media_type="application/x-protobuf",
            headers={
                "Content-Encoding": "gzip",
                "Cache-Control": "public, max-age=86400",
                "Access-Control-Allow-Origin": "*",
            },
        )
    elif tile_data[:4] == b"\x89PNG":
        return Response(
            content=tile_data,
            media_type="image/png",
            headers={"Cache-Control": "public, max-age=86400"},
        )
    elif tile_data[:2] in (b"\xff\xd8",):
        return Response(
            content=tile_data,
            media_type="image/jpeg",
            headers={"Cache-Control": "public, max-age=86400"},
        )
    elif tile_data[:4] == b"RIFF":
        return Response(
            content=tile_data,
            media_type="image/webp",
            headers={"Cache-Control": "public, max-age=86400"},
        )
    else:
        # Default: assume PBF vector tiles
        return Response(
            content=tile_data,
            media_type="application/x-protobuf",
            headers={"Cache-Control": "public, max-age=86400"},
        )


@router.get("/tiles/metadata")
def get_metadata(
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, str]:
    """Get metadata from the MBTiles file."""
    path = _get_mbtiles_path()
    conn = _open_mbtiles(path)
    try:
        metadata = {}
        for row in conn.execute("SELECT name, value FROM metadata"):
            metadata[row["name"]] = row["value"]
        return metadata
    finally:
        conn.close()


@router.post("/tiles/upload", status_code=201)
async def upload_mbtiles(
    request: Request,
    file: UploadFile = File(...),
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Upload an MBTiles file as the offline map bundle (ADMIN only).

    Replaces any existing bundle.  The file is validated to ensure it
    has the expected MBTiles schema (metadata + tiles tables).
    """
    max_bytes = _get_max_upload_bytes()
    path = _get_mbtiles_path()

    # Validate filename
    if file.filename and not file.filename.endswith(".mbtiles"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must have .mbtiles extension",
        )

    # Stream to a temp file first
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".mbtiles.tmp")
    total_bytes = 0
    try:
        with open(tmp_path, "wb") as f:
            while chunk := await file.read(65536):
                total_bytes += len(chunk)
                if total_bytes > max_bytes:
                    tmp_path.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"File exceeds maximum size of {max_bytes // (1024 * 1024)} MB",
                    )
                f.write(chunk)

        # Validate MBTiles structure
        try:
            conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            # Check required tables
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if "tiles" not in tables:
                conn.close()
                tmp_path.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid MBTiles: missing 'tiles' table",
                )
            if "metadata" not in tables:
                conn.close()
                tmp_path.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid MBTiles: missing 'metadata' table",
                )
            tile_count = conn.execute("SELECT COUNT(*) FROM tiles").fetchone()[0]
            conn.close()
        except sqlite3.Error as exc:
            tmp_path.unlink(missing_ok=True)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid MBTiles file: {exc}",
            )

        # Atomically replace
        tmp_path.replace(path)

    except HTTPException:
        raise
    except Exception as exc:
        tmp_path.unlink(missing_ok=True)
        logger.error("MBTiles upload failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Upload failed",
        )

    logger.info(
        "MBTiles bundle installed: %s (%.1f MB, %d tiles)",
        path,
        total_bytes / (1024 * 1024),
        tile_count,
    )

    return {
        "status": "installed",
        "path": str(path),
        "size_mb": round(total_bytes / (1024 * 1024), 1),
        "tile_count": tile_count,
    }


@router.delete("/tiles")
def delete_mbtiles(
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, str]:
    """Remove the offline map bundle (ADMIN only)."""
    path = _get_mbtiles_path()
    if not path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No offline map bundle installed",
        )
    path.unlink()
    logger.info("MBTiles bundle removed: %s", path)
    return {"status": "removed", "path": str(path)}
