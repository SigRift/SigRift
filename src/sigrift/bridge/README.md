# SigRift Bridge -- RF Signal Intelligence Dashboard & API

The SigRift bridge is a FastAPI-based backend for real-time RF signal
detection, classification, and monitoring.  It ingests detection events
from edge sensor nodes, scores them for anomalies, and exposes a REST +
WebSocket API consumed by the bundled single-page dashboard.

## Key Features

- **Detection ingest** -- batch and streaming ingest of RF detections with
  gzip support and dedup.
- **Anomaly scoring** -- pluggable scorers (isolation forest, autoencoder,
  correlation) with per-dimension breakdown.
- **Spectrum analysis** -- real-time spectrum waterfall via WebSocket,
  occupancy tracking, and snapshot storage.
- **Bluetooth / WiFi monitoring** -- BLE scan ingest, WiFi anomaly
  detection, OUI lookup, and vulnerability scanning.
- **RBAC authentication** -- API-key and session-based auth with
  role hierarchy (sensor / node / viewer / analyst / admin).
- **WebSocket feeds** -- live detection stream, spectrum waterfall,
  node status, and alert notifications.
- **Syslog forwarding** -- RFC 5424 structured syslog over UDP/TCP/TLS
  to external SIEMs.
- **Floor-plan maps** -- upload floor plans, define zones, overlay
  geolocated detections.
- **Signal fingerprinting** -- contrastive-learned 32-dim embeddings for
  emitter re-identification and clustering.

## Directory Structure

```
bridge/
  app.py                 # FastAPI application factory and lifespan
  models.py              # Pydantic request/response models
  dependencies.py        # Dependency injection (auth, rate limiting)
  detection_store.py     # Core SQLite-backed detection storage
  persistence.py         # Config and state persistence manager
  routers/               # FastAPI routers (one per feature domain)
    detections.py        #   Detection CRUD + batch ingest
    spectrum.py          #   Spectrum analysis + WebSocket waterfall
    bluetooth.py         #   BLE scan ingest + anomaly endpoints
    wifi.py              #   WiFi monitoring + anomaly re-eval
    admin.py             #   Admin dashboard + node management
    auth.py              #   Login / logout / session management
    health.py            #   Health check + system metrics
    training.py          #   ML training run management
    ...                  #   (maps, alerts, clusters, keys, etc.)
  storage/               # SQLite sub-stores (one per domain)
    base.py              #   Shared DB context + migration helpers
    users.py             #   User accounts and sessions
    audit.py             #   Audit log
    ...
  anomaly/               # Anomaly detection engines
    scorer.py            #   RF anomaly scorer
    isolation_forest.py  #   Isolation-forest model
    correlator.py        #   Cross-node correlation
    ...
  static/                # Frontend JS/CSS (single-page dashboard)
  templates/             # Jinja2 HTML templates
  tests/                 # Pytest test suite
```

## Running

```bash
# Install dependencies (from the repo root). The requirement files are
# hash-checked locks; torch comes from the PyTorch CPU index in its own
# step (never add that index as an --extra-index-url).
pip install --require-hashes -r src/sigrift/bridge/requirements.txt
pip install --require-hashes --no-deps -r src/sigrift/bridge/requirements-torch-cpu.txt

# Start the server on loopback — the Rust gateway terminates TLS on 8444
PYTHONPATH=src uvicorn sigrift.bridge.app:app --host 127.0.0.1 --port 8001

# Or with auto-reload during development
PYTHONPATH=src uvicorn sigrift.bridge.app:app --host 127.0.0.1 --port 8001 --reload
```

## Testing

```bash
PYTHONPATH=src pytest tests/bridge/ -v
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `BRIDGE_MASTER_KEY` | *(none)* | Master API key for admin operations |
| `BRIDGE_ADMIN_USER` | `admin` | Default admin username |
| `BRIDGE_ADMIN_PASSWORD` | *(none)* | Default admin password |
| `BRIDGE_LOG_LEVEL` | `INFO` | Logging verbosity |
| `BRIDGE_RETENTION_DAYS` | `90` | Data retention policy in days |
| `BRIDGE_SPECTRUM_RETENTION_DAYS` | *(BRIDGE_RETENTION_DAYS)* | Retention for the `spectrum_materialized` table; falls back to `BRIDGE_RETENTION_DAYS` |
| `BRIDGE_FINGERPRINT_MODEL` | *(none)* | Path to fingerprint encoder model |
| `BRIDGE_FAMILY_MODEL` | *(none)* | Path to family classifier model |
| `BRIDGE_CORS_ORIGINS` | *(none)* | Comma-separated CORS allowed origins |
