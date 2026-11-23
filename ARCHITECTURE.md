# SigRift Architecture

## System Overview

SigRift is a distributed RF/TSCM (Technical Surveillance Countermeasures)
platform for detecting, classifying, and geolocating radio frequency signals
in sensitive environments.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Edge Nodes (Field)                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│  │ RPi + SDR│  │ RPi + SDR│  │ RPi + SDR│  │ RPi + SDR│   ...    │
│  │ node_agent│  │ rf_scan  │  │ wifi_scan│  │ bt_scan  │          │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘          │
│       └──────────────┴──────────────┴──────────────┘               │
│                          │ HTTPS / API Key                         │
└──────────────────────────┼─────────────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────────────┐
│                      Rust Gateway (:8444)                           │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  TLS Termination (rustls)                                    │   │
│  │  Authentication (sessions, API keys, MFA/TOTP)               │   │
│  │  CSRF Validation                                             │   │
│  │  Rate Limiting (login, account lockout)                      │   │
│  │  RF Detection Ingest + Anomaly Scoring (hot path)            │   │
│  │  Security Headers (CSP, HSTS, Cache-Control)                 │   │
│  └──────────────────────────┬───────────────────────────────────┘   │
│                              │ HTTP Proxy (localhost)               │
│                              │ + X-Auth-User / X-Auth-Role          │
│                              │ + Authorization: Bearer              │
└──────────────────────────────┼──────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    Python Backend (:8001)                            │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  ASGI Middleware (proxy trust)                               │   │
│  │  FastAPI Routers (role-based access control)                 │   │
│  │  39 Storage Backends (SQLite via SharedContext)              │   │
│  │  Anomaly Scoring Pipeline (12 dimensions + signatures)       │   │
│  │  Cross-Correlation Engine (SDR ↔ WiFi ↔ BT ↔ Zigbee)       │   │
│  │  Alert Engine (rule evaluation, cooldowns)                   │   │
│  │  Provider Plugin System (entry point discovery)              │   │
│  │  Dashboard (Jinja2 templates + vanilla JS)                   │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                      │
│                    SQLite (WAL mode, shared)                         │
└──────────────────────────────────────────────────────────────────────┘
```

## Two-Layer Security Architecture

The Rust gateway is the **security boundary** for external HTTPS
traffic. All browser + remote-agent requests pass through it; Python
runs on localhost only and trusts Rust-injected headers. The default
single-host compose stack also runs three local data-source services
that bypass the gateway by design — they push data **into** the
bridge via the same authenticated API any remote edge agent would
use.

| Concern | Handled By | Mechanism |
|---------|-----------|-----------|
| TLS termination | Rust | rustls + ring |
| Session auth | Rust | SHA-256 token hash, PBKDF2 passwords |
| API key auth | Rust | PBKDF2 hash, constant-time comparison |
| MFA/TOTP | Rust | Fernet-encrypted secrets, RFC 6238 |
| CSRF | Rust | Double-submit cookie (sessions), `Origin` check (client certificates) |
| Rate limiting | Rust | SQLite-backed (login: 5/min, lockout: 10 failures) |
| RF ingest scoring | Rust | Isolation Forest, baseline z-scores |
| Application logic | Python | FastAPI routers, storage, ML pipeline |

### Local-host data sources (in-stack sidecars)

The default Compose stack runs three services that read directly
from local hardware and publish into the bridge. They authenticate
with `BRIDGE_LOCAL_NODE_KEY` (a NODE-role API key pre-seeded into
the bridge on first boot) and hit the gateway over loopback like
any other client.

```
┌─────────────────────────────────────────────────────────────────┐
│  Host hardware (USB, wlan, bluez)                               │
│                                                                 │
│  USB SDR ──┐                                                    │
│            └─→ rtl-tcp (devices: /dev/bus/usb, plugdev gid)     │
│                  └─→ scan  (ONNX inference, normal container)   │
│                        │                                        │
│  wlan iface ─→ wifi-scan  (cap NET_ADMIN/NET_RAW only,          │
│                            network_mode: host, user root)       │
│                                                                 │
│  HCI / DBus  ─→ bt-scan   (cap NET_ADMIN/NET_RAW only,          │
│                            network_mode: host)                  │
│                                                                 │
│  All three POST to https://gateway:8444 (or 127.0.0.1:UC_PORT   │
│  for host-net services) authenticated with BRIDGE_LOCAL_NODE_KEY│
└─────────────────────────────────────────────────────────────────┘
```

The privilege escalation is scoped:

- `rtl-tcp` and `scan` are normal containers — `rtl-tcp` just gets
  `/dev/bus/usb` + the plugdev gid to open the dongle.
- `wifi-scan` and `bt-scan` need `network_mode: host` plus
  `NET_ADMIN`/`NET_RAW` (everything else dropped; not `privileged`)
  for monitor-mode / raw-HCI access. See
  [INSTALL.md §"Privileged sidecars"](INSTALL.md#privileged-sidecars)
  for the rationale and opt-out (`profiles: ["disabled"]`).

### Trust Headers (Rust → Python)

```
X-Rust-Proxy: <UC_PROXY_SECRET>     # proves request came through gateway
X-Auth-User: admin                   # authenticated username
X-Auth-Role: admin                   # RBAC role
Authorization: Bearer <token>        # the session token the gateway verified, for Python validation
```

Python trusts these headers **only** when `X-Rust-Proxy` matches `UC_PROXY_SECRET`.
The client's own `Authorization`, `X-Session-Token` and `session_token`
cookie are never forwarded: the bridge gets a session token only for a
session the gateway verified
(see "Proxied requests" in `src/gateway/README.md`).

## Add-on packages

This community build (MIT) ships with no licensing code, no tier
checks, and no feature gates. Every endpoint, tab, and script that ships
in this repo is unconditionally available.

A separate add-on package, `sigrift-sentinel`, layers additional
capability on top via the provider plugin system: extra routers
(OIDC SSO, STIX/TAXII, fingerprinting, fuzzing) and additional
storage backends (TDOA, fingerprint, fuzz-session). Install it side-
by-side with `pip install -e sentinel/` when present. The community
bridge runs identically with or without sentinel; sentinel-only
routers and stores are mounted via guarded imports and stay absent
when the package is missing.

For sentinel licensing enquiries, use
[GitHub Discussions](https://github.com/SigRift/SigRift/discussions).

## Provider Plugin System

Optional add-on features implement abstract interfaces and register
via Python entry points. Core discovers them at runtime — no
compile-time imports, so this build has no hard dependency on
anything those packages ship.

```
sigrift/providers/
├── base.py        # Abstract interfaces (GeoProvider, FingerprintProvider, …)
├── null.py        # Safe fallbacks when no provider installed
├── registry.py    # Entry point discovery + caching
├── adapters.py    # Detection dict ↔ SignalObservation converters
└── geo_rss.py     # RSSGeoProvider — community RSS multilateration
```

### Provider Types

| Interface | Purpose | Community Impl | Commercial Impl |
|-----------|---------|---------------|------------------|
| `GeoProvider` | Signal geolocation | RSS multilateration | TDOA, AOA, Hybrid |
| `AlertProvider` | External alerting | Webhook | SIEM, Email, SMS |
| `ReportProvider` | Report generation | HTML / CSV | PDF, STIX bundle |
| `IngestProvider` | Protocol decoders | Base decoders | Advanced / proprietary |
| `FingerprintProvider` | Device / PHY embeddings | Null | Learned DSP + ML model |
| `FuzzProvider` | Protocol frame fuzzing | Null | DMR / P25 / LoRa mutators |
| `OidcProvider` | SSO authentication flow | Null | OIDC + SCIM |

"Null" in this table means a no-op implementation that returns empty
results or a 402 response; routes that depend on a commercial provider
return 404 / 402 on the community build rather than crashing.

### Registration

Providers register via `pyproject.toml` entry points. Community
registrations are shown below; commercial registrations live in the
`sigrift-sentinel` package's pyproject:

```toml
# Community (this repository):
[project.entry-points."sigrift.geo_providers"]
rss = "sigrift.providers.geo_rss:RSSGeoProvider"

# Commercial (sigrift-sentinel, separate package):
[project.entry-points."sigrift.geo_providers"]
tdoa = "sigrift_sentinel.providers.geo_tdoa:TdoaProvider"

[project.entry-points."sigrift.fingerprint_providers"]
sentinel = "sigrift_sentinel.fingerprint.provider:SentinelFingerprintProvider"

[project.entry-points."sigrift.fuzz_providers"]
sentinel = "sigrift_sentinel.fuzz.provider:SentinelFuzzProvider"

[project.entry-points."sigrift.oidc_providers"]
sentinel = "sigrift_sentinel.oidc.provider:SentinelOidcProvider"
```

Core discovers at runtime:
```python
from sigrift.providers.registry import get_geo_provider
provider = get_geo_provider("tdoa", config={"coordinate_mode": "2d"})
estimate = provider.estimate(observations)  # GeoEstimate or NullGeo fallback
```

### Geolocation Flow

```
Correlator detects 3+ node cluster (100ms spread)
    │
    ▼
_tdoa_callback(cluster_detections)
    │
    ├── Extract node positions from persistence
    ├── detections_to_observations(dets, positions)
    ├── get_geo_provider("tdoa", config={"coordinate_mode": ...})
    │       │
    │       ├── TDOA installed → TDOAGeoProvider.estimate()
    │       └── Not installed  → NullGeoProvider (confidence=0, silent skip)
    │
    ├── geo_estimate_to_tdoa_dict(estimate)
    └── detection_store.store_tdoa_estimate(tdoa_dict)
```

## Detection Pipeline

```
Edge Node → API Key Auth → Rust Ingest Handler → Anomaly Scoring
         → SQLite Insert → Cross-Correlation → Alert Engine
         → TDOA Callback (if 3+ nodes) → WebSocket Broadcast
```

### Anomaly Scoring (12 active dimensions + 2 opt-in)

Source of truth: `_DEFAULT_WEIGHTS` in
`src/sigrift/bridge/anomaly/scorer.py`. The raw active-dimension
weights sum to ~1.18 and are auto-normalized to 1.0 at scoring
time; the two opt-in dimensions ship at weight 0.0 and require
extra metadata in detections to be useful.

| Dimension | Weight | Description |
|-----------|--------|-------------|
| novel_class | 0.22 | Signal class not seen before |
| signature_match | 0.15 | Matches a curated TSCM threat signature |
| low_confidence | 0.14 | Classifier uncertainty |
| power_zscore | 0.13 | Unusual power level |
| rare_class | 0.12 | Infrequently observed class |
| snr_zscore | 0.10 | Unusual SNR |
| iq_quality | 0.08 | IQ sample anomalies |
| spectral_anomaly | 0.07 | Spectral shape deviation |
| timing_anomaly | 0.05 | Unusual timing pattern (hour-of-day for class) |
| modulation_anomaly | 0.05 | Unexpected modulation params |
| quiet_frequency | 0.04 | Detection on a rarely-used frequency bin |
| correlation | 0.03 | Cross-source correlation boost (SDR + WiFi/BT/Zigbee) |
| bandwidth_anomaly | **0.00** (opt-in) | Requires `bandwidth_hz` on the detection |
| inter_arrival_anomaly | **0.00** (opt-in) | Requires timestamp-based inter-arrival tracking |

Composite score 0.0–1.0. Priority labels:
`<0.3` normal, `0.3-0.5` interesting, `0.5-0.7` anomalous,
`>=0.7` critical. During the learning phase (first 300 detections
per scope, `min_learning_detections=300`), scores are dampened.

#### Two scorers, one anomaly pipeline

The Python pipeline above is the canonical anomaly scorer. The
Rust gateway also ships a 10-dimension scorer
(`src/gateway/crates/sigrift-gateway-core/src/scoring/`,
documented in `src/gateway/README.md`) that runs on the hot ingest
path before the detection is persisted. Its `ScoringWeights`
defaults are aligned with the Python scorer (`novel_class 0.22`,
`rare_class 0.14`, `low_confidence 0.14`, `power_zscore 0.10`,
`snr_zscore 0.08`, `timing_anomaly 0.07`, `quiet_frequency 0.04`,
`iq_quality 0.08`, `spectral_anomaly 0.07`, `modulation_anomaly
0.06`, summing to 1.0). On the batch ingest path the three
IQ-dependent dimensions score 0.0, so the gateway can drop or
down-prioritise obvious noise without crossing the proxy boundary.
Python then re-scores the survivors with the full 12/14-dim model
above. The two scorers are intentionally not fully in sync —
gateway is fast and coarse, Python is deep and authoritative.

### Multi-Node Correlation

```
Node 1 ──┐
Node 2 ──┤── NodeCorrelator (time window 15s, freq tolerance 100kHz)
Node 3 ──┘        │
                   ├── 2 nodes: +10% score boost
                   ├── 3 nodes: +15% score boost, TDOA eligible
                   └── 1 node:  -10% score dampen (possible local interference)
```

### Cross-Layer Correlation

```
SDR detection ──┐
WiFi scanner  ──┤── CrossCorrelator (500ms window)
BT scanner    ──┤       │
Zigbee scanner──┘       ├── confirmed (SDR + protocol match)
                        ├── multi_source (SDR + 2+ protocols)
                        └── unmatched_sdr (no protocol confirmation)
```

## Data Architecture

### SQLite (WAL Mode)

Single shared database accessed by both Rust and Python.

**Core tables:** `detections`, `detection_aggregates`, `sessions`, `users`,
`audit_log`, `rate_limit_login`, `account_lockout`

**Protocol tables:** `wifi_metadata`, `wifi_anomalies`, `bt_devices`,
`bt_anomalies`, `zigbee_devices`, `decoded_messages`

**Analysis tables:** `rf_anomalies`, `fhss_events`, `cross_correlations`,
`spectrum_analytics`, `reference_signatures`

**Geolocation tables:** `tdoa_estimates`, `tracks`, `track_points`

**Operational tables:** `incidents`, `sweep_sessions`, `iq_metadata_index`

### Storage Pattern

```python
DetectionStore (facade)
├── _ctx: SharedContext (connection pool, write lock, cache)
├── _wifi: WifiMetadataStore
├── _bt: BluetoothStore
├── _tdoa: TDOAStore
├── _spectrum: SpectrumAnalyticsStore
├── _signatures: SignatureLibraryStore
├── _fingerprints: FingerprintStore (optional — requires sentinel)
├── _fuzz: FuzzSessionStore (optional — requires sentinel)
└── ... (39 sub-store files in src/sigrift/bridge/storage/)
```

### Learned-State Persistence and Bundles

The anomaly baseline managers (RF/WiFi/BT) persist their learned
statistics as JSON in the bridge data dir — written at graceful
shutdown and autosaved every `BRIDGE_BASELINE_SAVE_INTERVAL` seconds
(default 900; 0 disables), so an ungraceful stop loses at most one
interval of learning. Edge nodes persist their local baselines the
same way when `MLRF_DATA_DIR` is set (the compose `edge_data` volume,
or the systemd unit's `StateDirectory`).

That state is portable as versioned **bundles** — gzip tar archives
with an integrity-checked manifest, two kinds: `export` (lossless same-site
backup, may be MAC-keyed) and `preset` (fully synthetic,
site-transferable, RF-only; four profiles ship in-repo and can seed a
first boot via `SIGRIFT_PRESET`). Export/import runs through the
`/api/admin/baselines/*` + `/api/admin/presets/*` routers or the
`python -m sigrift.bridge.bundles` CLI. Every untrusted bundle passes
an ordered fail-fast validation pipeline (transport size → archive
safety → manifest schema → per-member SHA-256/size → structural
bounds → preset sanitation → compatibility hashes) that reports
failures as structured per-check results, and preset applies are
guarded against silently replacing substantial learned state.
Format contract: [docs/bundle-format.md](docs/bundle-format.md);
reference implementation: `src/sigrift/bridge/bundles.py`.

## Edge Node Architecture

```
┌─────────────────────────────────────────┐
│  Raspberry Pi 4/5 + RTL-SDR / HackRF   │
│                                          │
│  node_agent.py    → Heartbeat (30s)      │
│  rf_scan.py       → IQ capture + classify│
│  detection_reporter.py → Batch upload    │
│  wifi_scan.py     → WiFi monitoring      │
│  bt_scanner.py    → BLE scanning         │
│                                          │
│  Services: sigrift-agent, rf-edge,       │
│            sigrift-bt-scanner, wifi-scan  │
└──────────────────────────────────────────┘
```

Agents authenticate with API keys (SENSOR role). Commands are queued via
`/api/nodes/{node_id}/command` and dispatched on next heartbeat.

This is the layout of a manually configured edge node
([src/sigrift/edge/README.md](src/sigrift/edge/README.md)). The one-line
edge installer (`/api/edge/install.sh`) sets up `node_agent.py` only, so
a node installed that way sends heartbeats but no detections. Manual
remote scanners were not part of the release soak.

## Directory Structure

```
SigRift/
├── src/
│   ├── sigrift/                       # Python package (PYTHONPATH=src)
│   │   ├── bridge/                    # FastAPI backend
│   │   │   ├── routers/               # 47 API router files
│   │   │   ├── storage/               # 39 SQLite storage backend files
│   │   │   └── anomaly/               # Scoring, correlation, FHSS, drift
│   │   ├── lib/                       # ML models, DSP, taxonomy
│   │   │   ├── dsp/                   # Signal processing, demodulation
│   │   │   ├── protocol/              # Protocol decoders (LoRa, DMR, P25)
│   │   │   ├── crypto/                # Fuzzing, key management
│   │   │   ├── security/              # Credential hashing helpers
│   │   │   └── taxonomy.py            # Signal class + family lookup
│   │   ├── providers/                 # Plugin interfaces + registry
│   │   ├── tools/                     # CLI tools
│   │   └── edge/                      # Edge node agents (node_agent,
│   │                                  # rf_scan, wifi_scan, bt_scanner)
│   └── gateway/                       # Rust security gateway (workspace)
│       └── crates/
│           ├── sigrift-gateway-core/  # Shared library (no licence code)
│           │   └── src/
│           │       ├── auth/          # Sessions, API keys, MFA
│           │       ├── middleware/    # Auth, CSRF, security headers
│           │       ├── proxy/         # Reverse proxy to Python
│           │       ├── ingest/        # RF detection batch handler
│           │       ├── scoring/       # Rust 10-dim hot-path scorer
│           │       ├── analysis/      # FHSS, correlator, alerts
│           │       ├── audit/         # Tamper-evident audit chain
│           │       ├── db/            # SQLite connection pool
│           │       ├── storage/       # Gateway-owned SQLite ops
│           │       ├── ws/            # WebSocket detection feeds
│           │       └── …              # config, builder, query, models
│           └── sigrift-gateway/       # Community binary (thin wrapper)
├── tests/
│   ├── bridge/                        # Python tests (~7,500)¹
│   └── e2e/                           # Playwright end-to-end suite
├── SECURITY.md                        # Security architecture
├── INSTALL.md                         # Deployment guide
└── ARCHITECTURE.md                    # This file
```

Rust unit + integration tests live inside the gateway crates
themselves (`cargo test --workspace`).

¹ Approximate; `docs/metrics.json` records the current counts.
