"""Spectrum occupancy analysis and wideband FFT monitor endpoints for The Bridge.

Provides frequency-band occupancy, waterfall time-frequency data,
pre-defined band summaries, recent spectrum activity timeline,
wideband FFT snapshot ingestion / monitoring, and live spectrum
viewer with rtl_tcp proxy or HTTP-based node polling.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json as _json
import logging
import time
import urllib.request
from typing import Any

import numpy as np

# Private/reserved networks — block SSRF to internal services
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private_ip(host: str) -> bool:
    """Check if a host resolves to a blocked/private IP (SSRF protection)."""
    try:
        addr = ipaddress.ip_address(host)
        if any(addr in net for net in _BLOCKED_NETWORKS):
            return True
    except ValueError:
        pass  # hostname, not IP — allow (registered nodes only)
    return False


from fastapi import (  # noqa: E402
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)

from sigrift.bridge.dependencies import (  # noqa: E402
    Role,
    enforce_node_binding,
    get_ws_limiter,
    require_role,
    require_ws_auth,
)
from sigrift.bridge.instrumentation import get_tracer, trace_span  # noqa: E402
from sigrift.bridge.state import AppState  # noqa: E402
from sigrift.bridge.utils import get_detection_store, utcnow  # noqa: E402
from sigrift.lib.security.validation import validate_host  # noqa: E402
from sigrift.lib.shiny.models import _validate_id  # noqa: E402
from sigrift.lib.shiny.node_metrics import (  # noqa: E402
    stored_capabilities,
    stored_metric,
    stored_port,
)

logger = logging.getLogger(__name__)
_tracer = get_tracer(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# GET /nodes -- list registered nodes for spectrum viewer dropdown
# ---------------------------------------------------------------------------


@router.get("/nodes")
async def list_spectrum_nodes(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """Return registered nodes for the spectrum viewer node dropdown.

    Stored values of the wrong type (a record saved before heartbeat metrics
    were checked, or edited by hand) read as absent, so one bad record
    cannot fail the dropdown (see ``sigrift.lib.shiny.node_metrics``).
    """
    from sigrift.bridge.persistence import PersistenceManager

    persistence: PersistenceManager = request.app.state.persistence
    nodes = persistence.get_nodes()
    result = []
    for node_id, data in nodes.items():
        host = data.get("host")
        caps = stored_capabilities(data.get("capabilities"))
        result.append(
            {
                "node_id": node_id,
                "host": host if isinstance(host, str) else "",
                "status": stored_metric(data, "status") or "unknown",
                "hardware": stored_metric(data, "hardware"),
                "rtl_tcp_port": stored_port(data.get("rtl_tcp_port")) or 1234,
                "capture_mode": caps.get("capture_mode", ""),
            }
        )
    return result


# ---------------------------------------------------------------------------
# HTTP-based spectrum poller (for nodes without exposed rtl_tcp)
# ---------------------------------------------------------------------------


class _NodeSpectrumPoller:
    """Polls a node's edge-monitor HTTP service for status and generates
    synthetic spectrum frames from the node's reported frequencies.

    When rtl_tcp is not directly reachable from the Bridge, this poller
    connects to the node's HTTP service (port 8080), reads its scanning
    config (frequencies, capture_mode), and produces FFT-like frames
    that the WebSocket clients can render.
    """

    def __init__(self) -> None:
        self.connected = False
        self.node_id = ""
        self.host = ""
        self.port = 8080
        self.center_freq: float = 433_920_000.0
        self.sample_rate: float = 2_048_000.0
        self.gain: float = 40.0
        self.node_status: dict[str, Any] = {}
        self.clients: list[Any] = []
        self._task: asyncio.Task[None] | None = None
        self._running = False
        self._frames_sent = 0
        self._connected_since: float | None = None

    async def connect(self, host: str, port: int, node_id: str) -> bool:
        """Verify the node's HTTP service is reachable."""
        if _is_private_ip(host):
            logger.warning("Blocked SSRF attempt to private IP: %s", host)
            return False
        if self.connected:
            await self.disconnect()
        try:
            url = f"http://{host}:{port}/"
            status_data = await asyncio.to_thread(self._fetch_node_status, url)
            if not status_data or status_data.get("service") not in (
                "rf-edge-monitor",
                "rf-scan",
            ):
                return False
            self.host = host
            self.port = port
            self.node_id = node_id
            self.node_status = status_data
            self.connected = True
            self._connected_since = time.time()
            self._frames_sent = 0
            logger.info(
                "Connected to node %s HTTP service at %s:%d", node_id, host, port
            )
            return True
        except Exception as exc:
            logger.warning(
                "Failed to connect to node HTTP service %s:%d: %s", host, port, exc
            )
            return False

    @staticmethod
    def _fetch_node_status(url: str) -> dict[str, Any]:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return _json.loads(resp.read())

    async def disconnect(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        self.connected = False
        self._connected_since = None
        self.node_id = ""
        logger.info("Disconnected from node HTTP service")

    async def set_params(
        self,
        freq_hz: float | None = None,
        gain_db: float | None = None,
        sample_rate_hz: float | None = None,
    ) -> None:
        if freq_hz is not None:
            self.center_freq = freq_hz
        if gain_db is not None:
            self.gain = gain_db
        if sample_rate_hz is not None:
            self.sample_rate = sample_rate_hz

    async def start_streaming(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._poll_loop())

    async def _poll_loop(self) -> None:
        """Poll node status and generate spectrum frames."""
        from sigrift.lib.shiny.spectrum_streamer import SpectrumStreamer

        target_fps = 5
        interval = 1.0 / target_fps
        poll_interval = 10.0
        last_poll = 0.0

        try:
            while self._running and self.connected:
                if not self.clients:
                    await asyncio.sleep(0.2)
                    continue

                now = time.time()

                # Periodically refresh node status
                if now - last_poll > poll_interval:
                    try:
                        url = f"http://{self.host}:{self.port}/"
                        self.node_status = await asyncio.to_thread(
                            self._fetch_node_status, url
                        )
                        last_poll = now
                    except Exception:
                        pass

                # Generate a synthetic spectrum frame from node's frequency list
                freqs = self.node_status.get("frequencies", [])
                n_bins = 512
                f0_hz = self.center_freq - self.sample_rate / 2
                f1_hz = self.center_freq + self.sample_rate / 2
                f0_mhz = f0_hz / 1e6
                f1_mhz = f1_hz / 1e6

                # Build noise floor + peaks at known frequencies
                noise_floor = -60.0 + np.random.normal(0, 2.0, n_bins).astype(
                    np.float32
                )
                for freq_mhz in freqs:
                    freq_hz = freq_mhz * 1e6
                    if f0_hz <= freq_hz <= f1_hz:
                        bin_idx = int((freq_hz - f0_hz) / (f1_hz - f0_hz) * n_bins)
                        bin_idx = max(0, min(n_bins - 1, bin_idx))
                        # Add a peak with some width
                        width = max(1, n_bins // 50)
                        for j in range(-width, width + 1):
                            idx = bin_idx + j
                            if 0 <= idx < n_bins:
                                atten = abs(j) / max(width, 1) * 20
                                noise_floor[idx] = max(
                                    noise_floor[idx],
                                    -20.0 + np.random.normal(0, 1) - atten,
                                )

                magnitudes = [round(float(v), 1) for v in noise_floor]
                signals = SpectrumStreamer.identify_signals(f0_hz, f1_hz)

                payload = {
                    "type": "spectrum",
                    "magnitudes_db": magnitudes,
                    "f0": round(f0_mhz, 3),
                    "f1": round(f1_mhz, 3),
                    "fc": round(self.center_freq / 1e6, 3),
                    "bw": round(self.sample_rate / 1e6, 2),
                    "bins": n_bins,
                    "t": round(now, 3),
                    "signals": signals,
                    "node_id": self.node_id,
                    "source": "node_poll",
                }

                await self.clients.broadcast(payload)

                self._frames_sent += 1
                await asyncio.sleep(interval)

        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.warning("Spectrum poll loop error: %s", exc)
            self.connected = False

    def get_config(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "connected": self.connected,
            "host": self.host,
            "port": self.port,
            "node_id": self.node_id,
            "frames_sent": self._frames_sent,
            "source": "node_poll",
        }
        if self.connected:
            result["center_freq_hz"] = self.center_freq
            result["sample_rate_hz"] = self.sample_rate
            result["gain_db"] = self.gain
            result["node_frequencies"] = self.node_status.get("frequencies", [])
            result["capture_mode"] = self.node_status.get("capture_mode", "")
            result["rtl_connected"] = self.node_status.get("rtl_connected", False)
        if self._connected_since:
            from datetime import datetime, timezone

            result["connected_since"] = datetime.fromtimestamp(
                self._connected_since, tz=timezone.utc
            ).isoformat()
        return result


# ---------------------------------------------------------------------------
# POST /connect -- connect to a registered node for spectrum viewing
# ---------------------------------------------------------------------------


@router.post("/connect")
async def spectrum_connect(
    request: Request,
    body: dict[str, Any],
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Connect to a registered node for spectrum streaming.

    Tries rtl_tcp first (port 1234); if unreachable, falls back to
    polling the node's HTTP service (port 8080) for status data.  A stored
    port that is not a whole number from 1 to 65535 reads as that default;
    a node without a valid host is a 409, not a connection attempt.
    """
    from sigrift.bridge.persistence import PersistenceManager

    node_id = body.get("node_id")
    if not node_id:
        raise HTTPException(status_code=422, detail="node_id is required")

    persistence: PersistenceManager = request.app.state.persistence
    nodes = persistence.get_nodes()
    if node_id not in nodes:
        raise HTTPException(status_code=404, detail=f"Node {node_id!r} not found")

    node_data = nodes[node_id]
    # A record saved before heartbeat metrics were checked (or edited by
    # hand) can hold a value of another type here: it must not be a 500.
    host = node_data.get("host", "127.0.0.1")
    try:
        host = validate_host(host if isinstance(host, str) else "")
    except ValueError:
        raise HTTPException(
            status_code=409, detail=f"Node {node_id!r} has no valid host registered"
        ) from None
    http_port = stored_port(node_data.get("port")) or 8080
    rtl_tcp_port = stored_port(node_data.get("rtl_tcp_port")) or 1234

    freq = body.get("center_freq_hz")
    gain = body.get("gain_db")
    rate = body.get("sample_rate_hz")

    # Try rtl_tcp first
    streamer = request.app.state.spectrum_streamer
    ok = await streamer.connect(host, rtl_tcp_port)
    if ok:
        await streamer.set_params(freq_hz=freq, gain_db=gain, sample_rate_hz=rate)
        await streamer.start_streaming()
        conn_cfg = {
            "connected": True,
            "node_id": node_id,
            "host": host,
            "port": rtl_tcp_port,
            "source": "rtl_tcp",
            "center_freq_hz": freq,
            "sample_rate_hz": rate,
            "gain_db": gain,
        }
        persistence.set_spectrum_connection(conn_cfg)
        return conn_cfg

    # Fall back to HTTP polling — verify node is reachable
    try:
        url = f"http://{host}:{http_port}/"
        node_status = await asyncio.to_thread(
            _NodeSpectrumPoller._fetch_node_status, url
        )
        if not node_status or node_status.get("service") not in (
            "rf-edge-monitor",
            "rf-scan",
        ):
            raise ValueError("Not an rf-edge-monitor service")
    except Exception:
        raise HTTPException(
            status_code=502,
            detail=f"Cannot reach node {node_id} — rtl_tcp ({host}:{rtl_tcp_port}) "
            f"and HTTP service ({host}:{http_port}) both unreachable",
        )

    conn_cfg = {
        "connected": True,
        "node_id": node_id,
        "host": host,
        "port": http_port,
        "source": "node_poll",
        "center_freq_hz": freq,
        "sample_rate_hz": rate,
        "gain_db": gain,
    }
    persistence.set_spectrum_connection(conn_cfg)
    return conn_cfg


# ---------------------------------------------------------------------------
# GET /disconnect -- disconnect from spectrum source
# ---------------------------------------------------------------------------


@router.get("/disconnect")
async def spectrum_disconnect(
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Disconnect from spectrum source (rtl_tcp or node poller)."""
    streamer = request.app.state.spectrum_streamer
    await streamer.disconnect()
    persistence = request.app.state.persistence
    persistence.set_spectrum_connection({"connected": False})
    return {"connected": False}


# ---------------------------------------------------------------------------
# GET /config -- current streamer status/config
# ---------------------------------------------------------------------------


@router.get("/config")
async def spectrum_config(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return current spectrum streamer configuration and status."""
    # Check poller first (more likely in use)
    poller: _NodeSpectrumPoller = request.app.state.spectrum_poller
    if poller.connected:
        return poller.get_config()

    # Fall back to rtl_tcp streamer
    streamer = request.app.state.spectrum_streamer
    st = streamer.get_status()
    result: dict[str, Any] = {
        "connected": st.connected,
        "host": st.host,
        "port": st.port,
        "frames_sent": st.frames_sent,
        "source": "rtl_tcp",
    }
    if st.params:
        result["center_freq_hz"] = st.params.center_freq_hz
        result["sample_rate_hz"] = st.params.sample_rate_hz
        result["gain_db"] = st.params.gain_db
        result["fft_size"] = st.params.fft_size
    if st.connected_since:
        result["connected_since"] = st.connected_since.isoformat()
    return result


# ---------------------------------------------------------------------------
# WS /ws/spectrum -- live FFT data stream
# ---------------------------------------------------------------------------


@router.websocket("/ws/spectrum")
async def ws_spectrum(websocket: WebSocket) -> None:
    """Stream live FFT spectrum data to authenticated WebSocket clients.

    Each WS connection runs its own poll loop, reading the spectrum
    connection config from app state. This avoids cross-worker issues
    with multi-process uvicorn deployments.
    """
    key_id, subprotocol = await require_ws_auth(websocket)
    if subprotocol:
        await websocket.accept(subprotocol=subprotocol)
    else:
        await websocket.accept()

    app_state: AppState = websocket.app.state.app_state
    streamer = websocket.app.state.spectrum_streamer
    await app_state.ws_spectrum_clients.add(websocket)
    await streamer.clients.add(websocket)
    logger.info("Spectrum viewer WS client connected: %s", key_id)

    # Read connection config from shared state
    persistence = websocket.app.state.persistence
    spec_cfg = persistence.get_spectrum_connection()

    # Start a per-connection streaming task if we have an active connection
    stream_task: asyncio.Task[None] | None = None
    if spec_cfg and spec_cfg.get("connected"):
        stream_task = asyncio.create_task(_ws_stream_loop(websocket, spec_cfg))

    try:
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                continue
            if data == "ping":
                await websocket.send_text("pong")
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        if stream_task is not None:
            stream_task.cancel()
            try:
                await stream_task
            except asyncio.CancelledError:
                pass
        await app_state.ws_spectrum_clients.remove(websocket)
        await streamer.clients.remove(websocket)
        client_ip = getattr(websocket.state, "ws_client_ip", None)
        if client_ip:
            get_ws_limiter().release(client_ip)
        logger.info("Spectrum viewer WS client disconnected: %s", key_id)


async def _ws_stream_loop(
    websocket: WebSocket,
    spec_cfg: dict[str, Any],
) -> None:
    """Per-connection streaming loop that polls the node and sends frames."""
    from sigrift.lib.shiny.spectrum_streamer import SpectrumStreamer

    host = spec_cfg.get("host", "")
    port = int(spec_cfg.get("port", 8080))
    node_id = spec_cfg.get("node_id", "")
    center_freq = float(spec_cfg.get("center_freq_hz", 433_920_000))
    sample_rate = float(spec_cfg.get("sample_rate_hz", 2_048_000))
    source = spec_cfg.get("source", "node_poll")

    interval = 0.2  # 5 fps
    poll_interval = 10.0
    last_poll = 0.0
    node_status: dict[str, Any] = {}

    try:
        while True:
            now = time.time()

            # Periodically refresh node status from its HTTP service
            if source == "node_poll" and now - last_poll > poll_interval:
                try:
                    url = f"http://{host}:{port}/"
                    node_status = await asyncio.to_thread(
                        _NodeSpectrumPoller._fetch_node_status, url
                    )
                    last_poll = now
                except Exception:
                    pass

            # Generate spectrum frame
            freqs = node_status.get("frequencies", [])
            n_bins = 512
            f0_hz = center_freq - sample_rate / 2
            f1_hz = center_freq + sample_rate / 2

            noise_floor = -60.0 + np.random.normal(0, 2.0, n_bins).astype(np.float32)
            for freq_mhz in freqs:
                freq_hz = freq_mhz * 1e6
                if f0_hz <= freq_hz <= f1_hz:
                    bin_idx = int((freq_hz - f0_hz) / (f1_hz - f0_hz) * n_bins)
                    bin_idx = max(0, min(n_bins - 1, bin_idx))
                    width = max(1, n_bins // 50)
                    for j in range(-width, width + 1):
                        idx = bin_idx + j
                        if 0 <= idx < n_bins:
                            atten = abs(j) / max(width, 1) * 20
                            noise_floor[idx] = max(
                                noise_floor[idx],
                                -20.0 + np.random.normal(0, 1) - atten,
                            )

            signals = SpectrumStreamer.identify_signals(f0_hz, f1_hz)
            payload = {
                "type": "spectrum",
                "magnitudes_db": [round(float(v), 1) for v in noise_floor],
                "f0": round(f0_hz / 1e6, 3),
                "f1": round(f1_hz / 1e6, 3),
                "fc": round(center_freq / 1e6, 3),
                "bw": round(sample_rate / 1e6, 2),
                "bins": n_bins,
                "t": round(now, 3),
                "signals": signals,
                "node_id": node_id,
                "source": source,
            }

            try:
                await websocket.send_json(payload)
            except Exception:
                break

            await asyncio.sleep(interval)

    except asyncio.CancelledError:
        pass
    except Exception as exc:
        logger.debug("Spectrum WS stream loop ended: %s", exc)


# ---------------------------------------------------------------------------
# GET /occupancy -- frequency band occupancy
# ---------------------------------------------------------------------------


@router.get("/occupancy")
async def get_occupancy(
    request: Request,
    hours: int = Query(24, ge=1, le=168),
    bin_width_hz: int = Query(1_000_000, ge=10_000, le=100_000_000),
    node_id: str | None = Query(None),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return frequency band occupancy over a time window."""
    store = get_detection_store(request)
    results = await asyncio.to_thread(
        store.get_spectrum_occupancy,
        hours=hours,
        bin_width_hz=bin_width_hz,
        node_id=node_id,
    )
    return {
        "hours": hours,
        "bin_width_hz": bin_width_hz,
        "bins": results,
    }


# ---------------------------------------------------------------------------
# GET /waterfall -- time-frequency power matrix
# ---------------------------------------------------------------------------


@router.get("/waterfall")
async def get_waterfall(
    request: Request,
    hours: int = Query(1, ge=1, le=168),
    freq_min_hz: float | None = Query(None, ge=0),
    freq_max_hz: float | None = Query(None, ge=0),
    time_resolution_sec: int = Query(60, ge=10, le=3600),
    bin_width_hz: int = Query(1_000_000, ge=10_000, le=100_000_000),
    node_id: str | None = Query(None),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return time-frequency data for waterfall display."""
    with trace_span(
        _tracer,
        "get_waterfall",
        attributes={
            "waterfall.hours": hours,
            "waterfall.time_resolution_sec": time_resolution_sec,
            "waterfall.bin_width_hz": bin_width_hz,
        },
    ):
        store = get_detection_store(request)
        return await asyncio.to_thread(
            store.get_spectrum_waterfall,
            hours=hours,
            freq_min_hz=freq_min_hz,
            freq_max_hz=freq_max_hz,
            time_resolution_sec=time_resolution_sec,
            bin_width_hz=bin_width_hz,
            node_id=node_id,
        )


# ---------------------------------------------------------------------------
# GET /bands -- pre-defined band summary
# ---------------------------------------------------------------------------


@router.get("/bands")
async def get_bands(
    request: Request,
    hours: int = Query(24, ge=1, le=168),
    node_id: str | None = Query(None),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return occupancy stats per known frequency band."""
    store = get_detection_store(request)
    bands = await asyncio.to_thread(
        store.get_spectrum_bands,
        hours=hours,
        node_id=node_id,
    )
    return {
        "hours": hours,
        "bands": bands,
    }


# ---------------------------------------------------------------------------
# GET /bandwidth -- bandwidth distribution by signal class
# ---------------------------------------------------------------------------


@router.get("/bandwidth")
async def get_bandwidth_distribution(
    request: Request,
    hours: int = Query(24, ge=1, le=168),
    node_id: str | None = Query(None),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return bandwidth distribution statistics grouped by signal class."""
    store = get_detection_store(request)
    results = await asyncio.to_thread(
        store.get_bandwidth_distribution,
        hours=hours,
        node_id=node_id,
    )
    return {
        "hours": hours,
        "classes": results,
    }


# ---------------------------------------------------------------------------
# GET /activity -- recent spectrum activity timeline
# ---------------------------------------------------------------------------


@router.get("/activity")
async def get_activity(
    request: Request,
    hours: int = Query(4, ge=1, le=168),
    node_id: str | None = Query(None),
    limit: int = Query(500, ge=1, le=5000),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return recent spectrum activity as individual detections."""
    store = get_detection_store(request)
    results = await asyncio.to_thread(
        store.get_spectrum_activity,
        hours=hours,
        node_id=node_id,
        limit=limit,
    )
    return {
        "hours": hours,
        "count": len(results),
        "activity": results,
    }


# ===========================================================================
# Wideband FFT Spectrum Monitor
# ===========================================================================


# ---------------------------------------------------------------------------
# POST /snapshots -- edge nodes POST compressed PSD data
# ---------------------------------------------------------------------------


@router.post("/snapshots", status_code=status.HTTP_201_CREATED)
async def ingest_snapshot(
    request: Request,
    _key_id: str = Depends(require_role(Role.SENSOR)),
) -> dict[str, Any]:
    """Ingest a wideband FFT spectrum snapshot from an edge node.

    Accepts gzip-compressed JSON with fields: node_id, center_freq_hz,
    bandwidth_hz, fft_size, psd_dbm (array of power values per bin).
    """
    import gzip as _gzip
    import json as _json
    import zlib as _zlib

    raw_body = await request.body()
    if len(raw_body) > 2_097_152:  # 2MB
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Request body exceeds 2MB limit",
        )

    # Decompress gzip if needed
    if request.headers.get("content-encoding") == "gzip":
        try:
            from io import BytesIO as _BytesIO

            _MAX_DECOMPRESSED = 20 * 1024 * 1024  # 20 MB
            dec = _gzip.GzipFile(fileobj=_BytesIO(raw_body))
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = dec.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_DECOMPRESSED:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="Decompressed payload exceeds 20MB limit",
                    )
                chunks.append(chunk)
            raw_body = b"".join(chunks)
        except HTTPException:
            raise
        except (OSError, ValueError, EOFError, _zlib.error):
            # EOFError: truncated stream; zlib.error: corrupt deflate
            # behind a valid header — client garbage, 400 not 500.
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to decompress gzip body",
            )

    try:
        payload = _json.loads(raw_body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON: {exc}",
        )

    # Validate required fields
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="JSON body must be an object",
        )
    required = ["node_id", "center_freq_hz", "bandwidth_hz", "fft_size", "psd_dbm"]
    for field in required:
        if field not in payload:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Missing required field: {field}",
            )
    try:
        _validate_id(payload["node_id"], "node_id")
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from None
    await enforce_node_binding(request, _key_id, payload["node_id"])

    psd = payload["psd_dbm"]
    if not isinstance(psd, list) or len(psd) == 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="psd_dbm must be a non-empty array",
        )

    fft_size = int(payload["fft_size"])
    bandwidth_hz = float(payload["bandwidth_hz"])
    center_freq_hz = float(payload["center_freq_hz"])

    # Compute derived fields
    bin_width_hz = bandwidth_hz / fft_size if fft_size > 0 else 0
    noise_floor_dbm = _estimate_noise_floor(psd)
    peak_idx = max(
        range(len(psd)), key=lambda i: psd[i] if psd[i] is not None else -999
    )
    peak_power_dbm = psd[peak_idx] if psd[peak_idx] is not None else None
    start_freq = center_freq_hz - bandwidth_hz / 2
    peak_freq_hz = start_freq + peak_idx * bin_width_hz

    timestamp = payload.get("timestamp", utcnow().isoformat())

    snapshot = {
        "node_id": payload["node_id"],
        "timestamp": timestamp,
        "center_freq_hz": center_freq_hz,
        "bandwidth_hz": bandwidth_hz,
        "fft_size": fft_size,
        "bin_width_hz": bin_width_hz,
        "psd_dbm": psd,
        "noise_floor_dbm": noise_floor_dbm,
        "peak_freq_hz": peak_freq_hz,
        "peak_power_dbm": peak_power_dbm,
    }

    store = get_detection_store(request)
    row_id = await asyncio.to_thread(store.insert_spectrum_snapshot, snapshot)

    # Broadcast to spectrum monitor WebSocket clients
    app_state: AppState = request.app.state.app_state
    await _broadcast_spectrum_monitor(
        app_state,
        {
            "type": "snapshot",
            "node_id": payload["node_id"],
            "timestamp": timestamp,
            "center_freq_hz": center_freq_hz,
            "bandwidth_hz": bandwidth_hz,
            "fft_size": fft_size,
            "noise_floor_dbm": noise_floor_dbm,
            "peak_freq_hz": peak_freq_hz,
            "peak_power_dbm": peak_power_dbm,
        },
    )

    logger.info(
        "Spectrum snapshot from %s: center=%.1f MHz, bw=%.1f MHz, %d bins",
        payload["node_id"],
        center_freq_hz / 1e6,
        bandwidth_hz / 1e6,
        len(psd),
    )

    return {
        "accepted": True,
        "id": row_id,
        "node_id": payload["node_id"],
        "bins": len(psd),
    }


# ---------------------------------------------------------------------------
# GET /monitor -- latest wideband view across all nodes
# ---------------------------------------------------------------------------


@router.get("/monitor")
async def get_monitor(
    request: Request,
    node_id: str | None = Query(None),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return latest wideband snapshot per node (or for a specific node)."""
    store = get_detection_store(request)
    snapshots = await asyncio.to_thread(
        store.get_spectrum_wideband_view,
        node_id=node_id,
    )
    return {
        "count": len(snapshots),
        "snapshots": snapshots,
    }


# ---------------------------------------------------------------------------
# GET /monitor/history -- PSD history for a specific node+freq
# ---------------------------------------------------------------------------


@router.get("/monitor/history")
async def get_monitor_history(
    request: Request,
    node_id: str = Query(...),
    hours: int = Query(1, ge=1, le=168),
    center_freq_hz: float | None = Query(None),
    limit: int = Query(500, ge=1, le=5000),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return PSD snapshot history for a specific node."""
    store = get_detection_store(request)
    snapshots = await asyncio.to_thread(
        store.get_spectrum_snapshots,
        node_id=node_id,
        hours=hours,
        center_freq_hz=center_freq_hz,
        limit=limit,
    )
    return {
        "node_id": node_id,
        "hours": hours,
        "count": len(snapshots),
        "snapshots": snapshots,
    }


# ---------------------------------------------------------------------------
# GET /monitor/peaks -- detected peaks above noise floor
# ---------------------------------------------------------------------------


@router.get("/monitor/peaks")
async def get_monitor_peaks(
    request: Request,
    hours: int = Query(4, ge=1, le=168),
    min_power_dbm: float | None = Query(None),
    threshold_db: float = Query(10.0, ge=1.0, le=50.0),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return detected peaks above noise floor in recent snapshots.

    Each peak includes ``classified: bool`` indicating whether it
    matches a known detection in the detections table, and
    ``signal_class: str|null`` for classified peaks.  Unclassified
    peaks are signals the classifier missed.
    """
    store = get_detection_store(request)
    peaks = await asyncio.to_thread(
        store.detect_spectrum_peaks,
        hours=hours,
        threshold_db=threshold_db,
        min_power_dbm=min_power_dbm,
    )
    return {
        "hours": hours,
        "threshold_db": threshold_db,
        "count": len(peaks),
        "peaks": peaks,
    }


# ---------------------------------------------------------------------------
# GET /monitor/stitch -- stitched wideband sweep view
# ---------------------------------------------------------------------------


@router.get("/monitor/stitch")
async def get_monitor_stitched(
    request: Request,
    node_id: str = Query(...),
    minutes: int = Query(5, ge=1, le=60),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return a stitched wideband PSD from recent snapshots.

    Combines adjacent-frequency snapshots from the same node within
    the last *minutes* into a single wideband view covering the full
    swept range.
    """
    store = get_detection_store(request)
    result = await asyncio.to_thread(
        store.stitch_spectrum_sweeps,
        node_id=node_id,
        minutes=minutes,
    )
    if result is None:
        return {
            "node_id": node_id,
            "stitched": False,
            "reason": "No recent snapshots for this node",
        }
    return {
        "stitched": True,
        **result,
    }


# ---------------------------------------------------------------------------
# GET /monitor/compare -- historical PSD comparison
# ---------------------------------------------------------------------------


@router.get("/monitor/compare")
async def get_monitor_compare(
    request: Request,
    node_id: str = Query(...),
    hours: int = Query(4, ge=1, le=168),
    center_freq_hz: float | None = Query(None),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Compare current PSD to historical average for a node.

    Returns the current PSD, the averaged PSD over *hours*, and a
    per-bin delta in dB.  New peaks (significantly above historical
    average) are highlighted.
    """
    store = get_detection_store(request)
    result = await asyncio.to_thread(
        store.compare_spectrum_psd,
        node_id=node_id,
        hours=hours,
        center_freq_hz=center_freq_hz,
    )
    if result is None:
        return {
            "node_id": node_id,
            "available": False,
            "reason": "No snapshots available for comparison",
        }
    return {
        "available": True,
        **result,
    }


# ---------------------------------------------------------------------------
# GET /fhss -- list detected FHSS signals
# ---------------------------------------------------------------------------


@router.get("/fhss")
async def get_fhss_events(
    request: Request,
    hours: int = Query(24, ge=1, le=168),
    node_id: str | None = Query(None),
    min_hop_rate: float | None = Query(None, ge=0),
    limit: int = Query(100, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return detected FHSS (frequency-hopping) signals."""
    store = get_detection_store(request)
    events = await asyncio.to_thread(
        store.get_fhss_events,
        hours=hours,
        node_id=node_id,
        min_hop_rate=min_hop_rate,
        limit=limit,
        offset=offset,
    )
    total = await asyncio.to_thread(
        store.count_fhss_events,
        hours=hours,
        node_id=node_id,
    )
    return {
        "hours": hours,
        "total": total,
        "count": len(events),
        "offset": offset,
        "events": events,
    }


# ---------------------------------------------------------------------------
# GET /fhss/{fhss_id} -- FHSS event detail with hop pattern
# ---------------------------------------------------------------------------


@router.get("/fhss/{fhss_id}")
async def get_fhss_event_detail(
    fhss_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return FHSS event detail including full hop pattern."""
    from fastapi import HTTPException

    store = get_detection_store(request)
    event = await asyncio.to_thread(store.get_fhss_event_by_id, fhss_id)
    if event is None:
        raise HTTPException(
            status_code=404,
            detail=f"FHSS event {fhss_id!r} not found",
        )
    return event


# ---------------------------------------------------------------------------
# WebSocket: real-time spectrum monitor stream
# ---------------------------------------------------------------------------


@router.websocket("/ws/spectrum-monitor")
async def ws_spectrum_monitor(websocket: WebSocket) -> None:
    """Stream spectrum snapshot events to authenticated WebSocket clients."""
    key_id, subprotocol = await require_ws_auth(websocket)
    if subprotocol:
        await websocket.accept(subprotocol=subprotocol)
    else:
        await websocket.accept()

    app_state: AppState = websocket.app.state.app_state
    await app_state.ws_spectrum_monitor_clients.add(websocket)
    logger.info("Spectrum monitor WS client connected: %s", key_id)

    try:
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                continue
            if data == "ping":
                await websocket.send_text("pong")
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        await app_state.ws_spectrum_monitor_clients.remove(websocket)
        client_ip = getattr(websocket.state, "ws_client_ip", None)
        if client_ip:
            get_ws_limiter().release(client_ip)
        logger.info("Spectrum monitor WS client disconnected: %s", key_id)


# ---------------------------------------------------------------------------
# Broadcast helper
# ---------------------------------------------------------------------------


async def _broadcast_spectrum_monitor(
    app_state: AppState,
    data: dict[str, Any],
) -> None:
    """Push spectrum snapshot event to all connected monitor WS clients."""
    await app_state.ws_spectrum_monitor_clients.broadcast(data)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def _estimate_noise_floor(psd: list[float | None]) -> float | None:
    """Estimate noise floor as the median of non-None PSD values."""
    values = [v for v in psd if v is not None]
    if not values:
        return None
    values.sort()
    mid = len(values) // 2
    if len(values) % 2 == 0:
        return (values[mid - 1] + values[mid]) / 2
    return values[mid]
