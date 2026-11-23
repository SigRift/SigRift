# SigRift Bridge Deployment Guide

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Deployment Topology                         │
│                                                                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                        │
│  │ Edge     │  │ Edge     │  │ Edge     │   SDR + ML inference    │
│  │ Node 01  │  │ Node 02  │  │ Node N   │   on each node         │
│  │ (RTL-SDR)│  │ (HackRF) │  │ (custom) │                        │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘                        │
│       │              │              │                              │
│       │    HTTPS POST /api/detections/batch                       │
│       │    (mTLS or API key auth)                                 │
│       ▼              ▼              ▼                              │
│  ┌─────────────────────────────────────────┐                      │
│  │        SigRift bridge (FastAPI)          │                      │
│  │                                         │                      │
│  │  ┌─────────┐ ┌──────────┐ ┌──────────┐ │                      │
│  │  │ Ingest  │ │ Anomaly  │ │ Dashboard│ │                      │
│  │  │ Router  │ │ Scoring  │ │ & API    │ │                      │
│  │  │         │ │ (3-tier) │ │          │ │                      │
│  │  └────┬────┘ └────┬─────┘ └────┬─────┘ │                      │
│  │       │           │            │        │                      │
│  │  ┌────▼───────────▼────────────▼─────┐  │                      │
│  │  │  SharedContext (write lock, cache) │  │                      │
│  │  │  └── encryption.py (SQLCipher)    │  │                      │
│  │  └────────────────┬──────────────────┘  │                      │
│  │                   │                     │                      │
│  │  ┌────────────────▼──────────────────┐  │                      │
│  │  │  SQLite (WAL mode)                │  │                      │
│  │  │  detections.db [AES-256 optional] │  │                      │
│  │  └───────────────────────────────────┘  │                      │
│  └─────────────────────────────────────────┘                      │
│       │              │                                            │
│       ▼              ▼                                            │
│  WebSocket push   Syslog/CEF/STIX                                │
│  to dashboards    to SIEM                                        │
└─────────────────────────────────────────────────────────────────────┘
```

```
┌───────────────────────────────────────────────────────────────┐
│                   Request Processing Pipeline                 │
│                                                               │
│  HTTP Request                                                 │
│      │                                                        │
│      ▼                                                        │
│  CombinedMiddleware (CORS, CSRF, OTel tracing)               │
│      │                                                        │
│      ▼                                                        │
│  Authentication (API key │ Session+Cookie)                    │
│      │                                                        │
│      ▼                                                        │
│  RBAC Authorization (viewer < operator < admin < superadmin)  │
│      │                                                        │
│      ▼                                                        │
│  Router Handler                                               │
│      │                                                        │
│      ├── Ingest: WriteQueue → batch insert → anomaly scoring  │
│      │   └── Tier 1: statistical (Welford, CUSUM, MAD)        │
│      │   └── Tier 2: Isolation Forest (11-dim)                │
│      │   └── Tier 3: autoencoder (32-dim)                     │
│      │   └── Calibrator: Platt scaling per-band               │
│      │   └── DriftDetector: retrain trigger (2σ)              │
│      │                                                        │
│      ├── Query: cache check → SQL → response                  │
│      │                                                        │
│      └── Admin: audit log, key mgmt, backup, cleanup          │
│                                                               │
│      ▼                                                        │
│  WebSocket broadcast (detections, anomalies, spectrum)        │
└───────────────────────────────────────────────────────────────┘
```

## Launch Parameters

### Quick Start

```bash
# Development (single worker, no TLS)
PYTHONPATH=src python -m sigrift.bridge

# Production (loopback only — the Rust gateway terminates TLS on 8444)
BRIDGE_ENV=production \
BRIDGE_MASTER_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))") \
BRIDGE_MFA_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())") \
BRIDGE_HOST=127.0.0.1 BRIDGE_PORT=8001 \
PYTHONPATH=src python -m sigrift.bridge
```

`BRIDGE_WORKERS` is read only by `python -m sigrift.bridge`; with
`python -m uvicorn sigrift.bridge.app:app` pass `--workers N` instead
(an environment variable has no effect there). More than one worker
process is supported for ingest: the gateway's post-ingest hooks and
`protocol_decode` jobs are claimed in `detections.db`, which every worker
shares, so a hook the gateway re-sends to another worker fires nothing
twice, and the workers (and `scripts/pki_bootstrap.py`) change the CA
registry under a file lock (`data/ca/.ca.lock`, see PKI_ARCHITECTURE.md),
so none of them undoes another's certificate issuance or revocation.
Node command queues, live WebSocket feeds and alert cooldowns are still
kept per worker, though, so keep `BRIDGE_WORKERS=1` (the default) unless
you have measured that one worker is the bottleneck.

### Entry Point (`__main__.py`)

```bash
PYTHONPATH=src python -m sigrift.bridge
```

Reads three env vars:

| Variable | Default | Description |
|----------|---------|-------------|
| `BRIDGE_WORKERS` | `1` | Uvicorn worker processes |
| `BRIDGE_HOST` | `0.0.0.0` | Bind address |
| `BRIDGE_PORT` | `8000` | Bind port |

---

## Environment Variables

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `BRIDGE_ENV` | *(empty)* | `production`/`prod` enables fail-closed security. `development`/`dev`/`test` relaxes defaults. |
| `BRIDGE_WORKERS` | `1` | Uvicorn worker count |
| `BRIDGE_HOST` | `0.0.0.0` | Bind address |
| `BRIDGE_PORT` | `8000` | Bind port |
| `BRIDGE_LOG_LEVEL` | `INFO` | Python log level (DEBUG, INFO, WARNING, ERROR) |
| `BRIDGE_LOG_FORMAT` | *(empty)* | Set to `json` for structured JSON logs |
| `BRIDGE_CORS_ORIGINS` | *(empty)* | Comma-separated CORS origins (empty = disabled) |

### Security (Required in Production)

| Variable | Default | Description |
|----------|---------|-------------|
| `BRIDGE_MASTER_KEY` | *(auto-generated in dev)* | Master API key. **Required** when `BRIDGE_ENV=production`. |
| `BRIDGE_ADMIN_PASSWORD` | *(auto-generated in dev)* | Initial admin password. Auto-deleted after 60s if generated. |
| `BRIDGE_MFA_KEY` | *(empty)* | Fernet key for TOTP encryption: 44 base64 characters ending in `=` that decode to 32 bytes (URL-safe `-_` or standard `+/` alphabet; the gateway applies the same rule). Generate: `python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'`. **Startup fails in production if unset or invalid**; dev warns and stores TOTP secrets as base64. A 43-character key (the unpadded `secrets.token_urlsafe(32)` value older installers wrote) is repaired by **appending `=`**, which keeps TOTP secrets already encrypted with it readable — do not replace it. Existing `b64:` secrets stay readable after a valid key is set. |
| `BRIDGE_AUDIT_KEY` | *(auto-generated in dev)* | HMAC secret for audit chain integrity (any strong string, e.g. `python3 -c 'import secrets; print(secrets.token_urlsafe(32))'`). **Required at startup in production.** In dev, falls back to `BRIDGE_MASTER_KEY` domain separation or `data/audit.key`. |
| `BRIDGE_KEY_VERIFY_CACHE_TTL` | `60` | Seconds a successful API-key PBKDF2 verification is remembered (per worker), so repeat requests skip the 600k-iteration hash. Rotating or revoking a key invalidates its entry immediately. `0` disables. |
| `BRIDGE_ENCRYPTION_KEY` | *(empty)* | DAR acknowledgement flag — set to any non-empty value to suppress the health warning after configuring filesystem-level encryption (LUKS/dm-crypt). Not used when SQLCipher is active. |

In development, the audit key is resolved once per `data/audit.key` path for the
process lifetime. This remains the bridge module's data location, independent of
individual SQLite database paths. If persistence fails, one ephemeral key keeps
that process's audit chains consistent; the failure is logged without key bytes.
Later filesystem recovery or key-file replacement takes effect only in a new
process. An ephemeral chain cannot be verified after its key is lost on restart.
Forked children retain already resolved keys and reset the resolution lock;
independently started processes do not share an ephemeral fallback. Use a stable
configured key for audit chains shared across processes or restarts.
`BRIDGE_AUDIT_KEY`, legacy `BRIDGE_AUDIT_SECRET`, and the domain-separated
`BRIDGE_MASTER_KEY` still take precedence on every lookup. Changing those
credentials is an explicit key change, not an automatic migration of old audit
entries. Production never uses the development file or cached fallback.

### SQLCipher (Optional)

> **Not supported in this release:** SQLCipher database encryption does
> not work end to end yet and must not be relied on; see
> [Data-at-Rest Encryption](#data-at-rest-encryption).

| Variable | Default | Description |
|----------|---------|-------------|
| `BRIDGE_DB_ENCRYPTION_KEY` | *(empty)* | SQLCipher passphrase. When set (with `pysqlcipher3` installed), all databases are transparently encrypted. |
| `BRIDGE_DB_ENCRYPTION_KEY_FILE` | *(empty)* | Path to file containing SQLCipher passphrase (must be chmod 600). Checked only when `BRIDGE_DB_ENCRYPTION_KEY` is not set. |
| `BRIDGE_SQLCIPHER_KDF_ITER` | `256000` | PBKDF2 iterations. Lower = faster, less secure. `64000` reduces overhead from ~15% to ~5%. |
| `BRIDGE_SQLCIPHER_PAGE_SIZE` | `4096` | SQLCipher cipher page size. |

### Security (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `BRIDGE_CSRF` | *(auto)* | `enabled` (production default) or `disabled` (dev default). CSRF Double Submit Cookie for session-auth requests. Production refuses to start unless it is unset, empty or `enabled` (trimmed, any letter case): the bridge with `BRIDGE_ENV` or `BRIDGE_MODE` `production` or `prod`, the gateway with `BRIDGE_ENV` `production`, `prod` or unset. Elsewhere both start with a warning: the bridge turns its check off for any other value, the gateway only for exactly `disabled` (any other value leaves the gateway's check at the `BRIDGE_ENV` default). |
| `BRIDGE_SESSION_BINDING` | `ip` | Session validation: `strict` (IP+UA), `ip`, `warn`, or `none` |
| `BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES` | `30` | Session inactivity timeout, in minutes. An empty value, one below 1 or one that is not an integer gives the default. Read by the bridge and the gateway, which apply the same rule; set the same value on both, written with the digits 0-9 (the gateway refuses to start on other digits; `src/gateway/README.md`, "Sessions and cookies"). |
| `BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS` | `24` | Session lifetime from login, in hours, whatever the activity. An empty value, or one that is not an integer from 1 to 10000000 (about 1141 years), is logged and gives the default. Read by the bridge and the gateway, which apply the same rule; set the same value on both, written with the digits 0-9. |
| `BRIDGE_ADMIN_USER` | `admin` | Default admin username |
| `BRIDGE_QUERY_PARAM_AUTH` | *(auto)* | API key in query string: `disabled` (production), `deprecated` (dev), `enabled` |
| `BRIDGE_WS_QUERY_AUTH` | `disabled` | WebSocket query param auth |
| `BRIDGE_MAX_KEY_LIFETIME_DAYS` | `365` | Max API key expiration: the default lifetime, and the cap on a longer `expires_in_hours` (`POST /api/keys/`) or `expires_days` (`POST /api/admin/keys`), so every created key expires. `POST /api/keys/` answers 422 for an `expires_in_hours` above 10000000 (416666 days) or not a finite number; `POST /api/admin/keys` for an `expires_days` below 1, above 3650 or not an integer. A setting above 416666 days acts as that 10000000-hour ceiling. |
| `BRIDGE_TRUSTED_PROXIES` | `127.0.0.1,::1` | Peers trusted for X-Forwarded-For, X-Forwarded-Host and X-Forwarded-Proto (the gateway's own requests are always trusted through `X-Rust-Proxy`): IPs, CIDRs or host names (loopback is always trusted). A host name that does not resolve yet is logged as an error and re-resolved in the background when an untrusted peer connects; resolved names are refreshed every 60 s. Prefer the gateway's fixed IP or subnet. |
| `BRIDGE_PCAP_MAX_BYTES` | `67108864` | Largest decompressed WiFi pcap accepted (larger uploads get 413) |
| `BRIDGE_ALLOW_UNBOUND_NODE_KEYS` | *(off)* | `1` leaves unbound node/sensor API keys unbound (they may act for any node, the pre-binding behaviour). An unbound viewer key is still refused on node routes (403 `Node endpoints require a node API key`), with or without it. Read by the bridge and the gateway. Has no effect on client certificates. |

#### Node credentials

Node-scoped routes (heartbeat, commands, detection / WiFi / BT / Zigbee /
spectrum ingest, IQ upload), and the gateway's detection ingest, accept a
credential only for its own node:

- **API key**: a key with `node_id` in `keys.json` acts only for that node,
  whatever its role. An unbound `node` or `sensor` key is bound to the
  first node it is used for — unless another live key is already bound to
  that node: then it is refused (403; the gateway's ingest answers 403
  too), because the first key to claim a node wins. To give a node a
  second key (one per agent, a replacement), create the key with that
  `node_id` (admin panel, `POST /api/admin/keys` with `"node_id"`), or
  bind an existing key: `PUT /api/admin/keys/{key_id}/permissions` with
  `{"node_id": "<node id>"}` (`{"node_id": null}` unbinds it; a key named
  after a registered node stays bound to that node). An admin's binding
  replaces an earlier one and may give a node several keys. An unbound
  `viewer` key is not a node credential (403 `Node endpoints require a
  node API key`) and is never bound; an unbound `analyst` key is operator
  tooling: it is never bound and may act for any node (changed in the
  2026-11 release: both used to be bound to the first node they named).
- **Client certificate** (mTLS through the gateway): below `admin`, the
  certificate's identity **is** the node id. Every agent on a node presents
  the same certificate, issued with `{"identity": "<node id>", "role":
  "node"}` (`POST /api/ca/issue`), and reports that id as `MLRF_NODE_ID`.
  A certificate issued for an agent or service name (`local-edge` on a node
  whose `MLRF_NODE_ID` is the host name, or `wifi-scan`) gets a 403 on every
  node route, and the bridge logs an error naming the fix. A node id that
  starts or ends with `-` or `_` cannot be a certificate identity, so such a
  node must use an API key.
- **Admin** keys and certificates act for any node.

### Database

| Variable | Default | Description |
|----------|---------|-------------|
| `BRIDGE_SQLITE_CACHE_SIZE` | `-64000` | SQLite page cache (negative = KB). Default 64 MB. |
| `BRIDGE_SQLITE_MMAP_SIZE` | `268435456` | Memory-mapped I/O window. Default 256 MB. |
| `BRIDGE_TENANT_ROW_LIMIT` | `0` | Max rows per tenant (0 = unlimited) |
| `BRIDGE_RETENTION_DAYS` | `90` | Data retention for cleanup tasks |
| `BRIDGE_SPECTRUM_RETENTION_DAYS` | *(BRIDGE_RETENTION_DAYS)* | Retention for `spectrum_materialized` (the largest table); falls back to `BRIDGE_RETENTION_DAYS`. The periodic cleanup loop prunes rows older than this in batches. |
| `BRIDGE_BACKUP_RETENTION` | `5` | Number of backup files to keep |

### Write Queue

| Variable | Default | Description |
|----------|---------|-------------|
| `BRIDGE_WQ_BATCH_SIZE` | `100` | Detection insert batch size |
| `BRIDGE_WQ_FLUSH_MS` | `500` | Flush interval in milliseconds |

### Edge Node / Scanner

| Variable | Default | Description |
|----------|---------|-------------|
| `MLRF_BRIDGE_URL` | `https://localhost:8444` | Central bridge URL (via the gateway) |
| `MLRF_API_KEY` | *(empty)* | Node API key |
| `MLRF_NODE_ID` | `node-01` | Unique node identifier |
| `MLRF_CA_BUNDLE` | *(system)* | CA bundle for TLS verification |
| `MLRF_DATA_DIR` | *(empty)* | Local data directory |
| `MLRF_ANOMALY` | *(empty)* | Enable anomaly scoring (`true`/`1`/`yes`) |

### Bluetooth Scanner

| Variable | Default | Description |
|----------|---------|-------------|
| `MLRF_BT_ENABLED` | *(empty)* | Enable BT scanning |
| `MLRF_BT_ADAPTER` | `hci0` | Bluetooth adapter |
| `MLRF_BT_SCAN_INTERVAL` | `30` | Scan interval (seconds) |

### Zigbee Scanner

| Variable | Default | Description |
|----------|---------|-------------|
| `MLRF_ZB_DEVICE` | *(empty)* | Serial device (e.g., `/dev/ttyUSB0`) |
| `MLRF_ZB_BAUD` | `115200` | Serial baud rate |
| `MLRF_ZB_SCAN_INTERVAL` | `60` | Scan interval (seconds) |
| `MLRF_ZB_DEMO` | `0` | Set `1` for synthetic demo data |

### Spectrum Sweeper

| Variable | Default | Description |
|----------|---------|-------------|
| `MLRF_SWEEP_ENABLED` | *(empty)* | Enable spectrum sweeping |
| `MLRF_SWEEP_INTERVAL` | `60` | Sweep interval (seconds) |
| `MLRF_SWEEP_FREQ_START` | `70000000` | Start frequency (Hz) |
| `MLRF_SWEEP_FREQ_END` | `6000000000` | End frequency (Hz) |
| `MLRF_SWEEP_BIN_SIZE` | *(auto)* | FFT bin size |
| `MLRF_SWEEP_BACKEND` | `auto` | Backend: `auto`, `rtlsdr`, `hackrf` |

### Syslog Forwarding

| Variable | Default | Description |
|----------|---------|-------------|
| `MLRF_SYSLOG_SERVER` | *(empty)* | Syslog host (empty = disabled) |
| `MLRF_SYSLOG_PORT` | `514` | Syslog port |
| `MLRF_SYSLOG_PROTOCOL` | `udp` | `udp` or `tcp` |
| `MLRF_SYSLOG_FACILITY` | `local0` | Syslog facility |
| `MLRF_SYSLOG_SEVERITY` | `info` | Severity level |

### Webhooks

Alert webhooks are delivered with SSRF protection. Changed in the
2026-11 security release:

- **Only globally routable targets.** Every address the webhook host
  resolves to must be public (`ipaddress.is_global`). Loopback, RFC 1918,
  link-local, **CGNAT `100.64.0.0/10` (this includes Tailscale `100.x`
  addresses)**, `0.0.0.0` / `::`, reserved and multicast addresses are
  refused when the webhook is created and on every delivery. IPv4-mapped
  (`::ffff:a.b.c.d`) and well-known NAT64 (`64:ff9b::a.b.c.d`, DNS64 sites)
  addresses are judged by the IPv4 address they reach; the local-use NAT64
  prefix `64:ff9b:1::/48` is refused.
- **Internal targets need an allow-list entry** in
  `BRIDGE_WEBHOOK_ALLOW_HOSTS` (for example a Tailscale or LAN receiver).
- **Ports:** 80, 443, 8080, 8443 and 1024–65535, except 2379, 3306, 5432,
  6379, 8500, 9200, 11211 and 27017.
- **Pinned resolution, no redirects.** The host is resolved once per
  delivery and the connection goes to that checked address (the URL host is
  still sent as `Host` and used for TLS SNI and certificate checks), so DNS
  rebinding cannot redirect it. A `3xx` answer counts as a failed delivery.
- **Egress proxy.** `https_proxy` / `http_proxy` / `no_proxy` (either case,
  read like `urllib` does) are honoured, but only as an HTTP `CONNECT`
  tunnel to the already-checked IP address — for `http://` webhooks too.
  The proxy must therefore allow `CONNECT` to the webhook's port (Squid's
  default `SSL_ports` allows only 443; add e.g. `acl SSL_ports port 80` for
  plain-HTTP webhooks). Proxy URL credentials are sent as
  `Proxy-Authorization: Basic`. Only `http://` (or `https://`, spoken to
  with plain-TCP `CONNECT`, as `urllib` did) proxy URLs are supported. The
  bridge still resolves the webhook host itself (it needs a resolver).
- **Retries.** A delivery is tried 3 times (5 s apart); a failure then goes
  to a retry queue that a background task retries up to 4 more times with
  exponential backoff (after about 5 s, 20 s, 40 s and 80 s; capped at
  300 s). The queue is bounded; beyond the cap the oldest entry is dropped.
  Dropped entries are logged and counted (`dropped` in
  `GET /api/admin/webhooks/retry-queue`).
- **In the background.** Webhooks (and syslog forwards) for alerts created
  by ingest — the bridge's own batch and summary ingest and the gateway's
  post-ingest hook — are delivered by background tasks: at most 5 HTTP
  posts at once and 256 deliveries in flight (beyond that a delivery goes
  straight to the retry queue). The posts, their DNS lookups and the
  syslog sends run in their own threads (5 for webhooks, 2 for syslog),
  not in the pool the bridge's database work uses, which has only
  CPUs + 4 threads. An unreachable or slow receiver therefore
  never delays ingest or the gateway's hook; the alert itself is stored
  and pushed to the dashboard at once. At shutdown, deliveries still in
  flight get 2 s, then are cancelled.

| Variable | Default | Description |
|----------|---------|-------------|
| `BRIDGE_WEBHOOK_ALLOW_HOSTS` | *(empty)* | Comma-separated host names, IP addresses or CIDRs that may be webhook targets although they are not globally routable (e.g. `alerts.lan,10.0.5.0/24,100.101.102.103`). A listed host name exempts every address it resolves to; a listed IP/CIDR exempts those addresses for any host. |
| `BRIDGE_WEBHOOK_RETRY_QUEUE_MAX` | `1000` | Most failed deliveries kept for background retry. |
| `BRIDGE_CA_BUNDLE` | *(empty)* | CA bundle for verifying `https://` webhook receivers that use a private PKI. Certificates are always verified. |
| `https_proxy` / `http_proxy` / `no_proxy` | *(empty)* | Egress proxy for webhooks (CONNECT tunnel to the vetted address, see above). |

### IQ Captures, Analysis Jobs and Decoded Messages

| Variable | Default | Description |
|----------|---------|-------------|
| `BRIDGE_IQ_MAX_SAMPLES` | `33554432` | Most complex samples (32 Mi = 256 MiB decompressed) one IQ capture may hold. Uploads are inflated incrementally and refused (HTTP 413, nothing stored) past the cap, so a small gzip "bomb" cannot exhaust memory; at most 64 concatenated gzip members are accepted. Captures stored by older releases above the cap are not loaded. |
| `BRIDGE_IQ_ANALYSIS_MAX_SAMPLES` | `2097152` | Samples (from the start of a capture) that the IQ consumers inflate and analyse: the `/iq` visualization, `/spectrogram`, `/modulation`, spectrogram jobs, protocol decoding, signature matching and creation (`/api/signatures/match`, `/api/signatures/from-detection/{id}`, reference uploads; the stored `iq_samples` still counts the whole capture) and `/api/bitstreams/extract`. All-zero IQ compresses ~1000:1, so a small upload can hold a cap-sized capture; the analysis stays bounded regardless. Results are bounded too: the PSD has at most 2048 bins, a `/spectrogram` at most 1 Mi cells (a very high `overlap` is lowered and the one used is reported), values rounded to 0.1 dB. Never more than `BRIDGE_IQ_MAX_SAMPLES`. |
| `BRIDGE_JOB_MAX_FINISHED` | `200` | Finished analysis jobs (`/api/jobs`) kept; older ones are evicted. |
| `BRIDGE_JOB_FINISHED_TTL_S` | `3600` | Seconds a finished job (and its result) is kept. |
| `BRIDGE_JOB_MAX_RESULT_BYTES` | `8388608` | Largest job result (JSON bytes); a larger result fails the job. Spectrogram jobs size themselves to fit it. |
| `BRIDGE_JOB_RESULT_BUDGET_BYTES` | `67108864` | Total (compressed) size of all kept job results; the oldest finished jobs are evicted beyond it. |
| `BRIDGE_JOB_SPECTROGRAM_MAX_SEGMENTS` | `512` | Most time rows in a spectrogram job result (consecutive segments are averaged). Large `nfft` values get fewer rows: a result holds at most 256 Ki cells (rows × bins), with dB values rounded to 0.1 dB. |
| `BRIDGE_JOB_STOP_TIMEOUT_S` | `5` | At shutdown, seconds to wait for analysis-job handler threads still running (they cannot be interrupted) before shutdown continues. |
| `BRIDGE_SHUTDOWN_THREAD_WAIT_S` | `5` | At shutdown, after the job queue and write queue have stopped, seconds to wait for other worker threads (cancelled maintenance tasks) before the database is closed. A connection still used by a live thread is never closed under it. |
| `BRIDGE_DECODED_MAX_ROWS` | `200000` | Row cap of the `decoded_messages` table (protocol messages decoded by the bridge from uploaded IQ, and messages edges attach to detection batches); the oldest rows are removed first. A batch carries at most 50 edge-decoded messages per detection and 1000 in all; the rest are dropped with a warning. |

Protocol decoding (LoRa / Meshtastic, DMR, P25) runs as a background
`protocol_decode` job once a decodable detection's IQ capture has been
uploaded; its result and the stored rows reference the detection id.
DMR and P25 captures are resampled to 48 kHz, channel-filtered and 4FSK
demodulated, and every burst / frame in the capture is decoded. LoRa and
Meshtastic captures are demodulated at their chip rate, but a frame is
only stored when its header check and CRC pass; the CSS demodulator has
no fine frame synchronisation yet, so expect few or no LoRa messages
from uploaded IQ.

A job is queued only for a capture that can hold a frame, counting the
`BRIDGE_IQ_ANALYSIS_MAX_SAMPLES` the job decodes: one DMR burst
(27.5 ms), a P25 frame sync and NID (13.3 ms), or a LoRa preamble, sync
word, SFD and header at SF7 and the widest bandwidth the rate holds
(5.4 ms at 500 kHz). The IQ an edge uploads with a classifier detection
is that detection's 4096-sample window (2 ms at 2.048 MHz), too short for
any of them: the upload answers `protocol_decode_skipped` with the reason
instead of queuing a job that would "decode" nothing. To decode a
channel, task a manual capture of it (`POST /api/nodes/{node_id}/capture`,
default 1 s) with `"signal_class": "dmr"` (or `p25`, `lora-css`,
`meshtastic`), or with `"detection_id"` of the detection to capture (its
class is used): the capture's stub detection gets that class and is
decoded. An uploader can also name the class of a standalone capture with
an `X-Signal-Class` header. Each detection is decoded at most once —
whether the IQ upload or the ingest (or the gateway's ingest hook) sees
it with its IQ first — at the sample rate the upload reported.

**Changed in this release:** an IQ upload (`PUT /api/detections/{id}/iq`)
whose `X-Sample-Rate` is outside 1 kHz – 250 MHz is refused with HTTP 400
(nothing is stored); edges always report the rate the device ran at
(61.44 MHz at most). The rate sizes the decode job's resampling, so
decoding is also skipped, at debug level, for captures it cannot hold: a
DMR / P25 capture below 9.6 kHz (2 samples per symbol) or above
196.6 MHz (4096 × 48 kHz), a LoRa capture below 125 kHz. At most `BRIDGE_IQ_ANALYSIS_MAX_SAMPLES` samples are
demodulated, after resampling too.

**Shutdown.** On SIGTERM the bridge first saves its state (nodes,
alerts, history, ...), then waits — bounded — for running analysis jobs
(`BRIDGE_JOB_STOP_TIMEOUT_S`), the detection write queue (up to 10 s) and
other worker threads (`BRIDGE_SHUTDOWN_THREAD_WAIT_S`), saves what changed
meanwhile and closes the database. Docker kills a container 10 s after
SIGTERM by default; give the bridge service `stop_grace_period: 30s` so
that the waits, and the detection writes still queued, can finish.

### Feature Flags

| Variable | Default | Description |
|----------|---------|-------------|
| `BRIDGE_GEOLOCATION_ENABLED` | `false` | Enable geolocation/TDOA (ITAR-controlled) |
| `BRIDGE_DEPLOYMENT_SSH_CONFIG` | unset | Optional operator-owned JSON file of explicit SSH audit targets; see the dashboard Deployment Guide. Normal scanner reporting requires no SSH setup. |
| `BRIDGE_MBTILES_PATH` | `data/mbtiles` | MBTiles map storage path |
| `BRIDGE_MBTILES_MAX_UPLOAD_MB` | `100` | Max MBTiles upload size |

---

### Optional SSH host audits

The Deployment tab shows current node contact and scanner reports without SSH.
The registered node `host` is an advertised application address, not proof of an
SSH endpoint. In particular, quickstart's `local-edge`/`edge` registration does
not mean that an SSH server exists in the scanner container. Missing SSH setup
does not make a reporting scanner offline.

Host auditing is an advanced, explicit opt-in. Set `BRIDGE_DEPLOYMENT_SSH_CONFIG`
to a readable JSON file mapping registered node IDs to `host`, `user`, optional
`port` (default 22), `known_hosts_file`, and `identity_file`. The two file paths
must be absolute paths readable by the Bridge process. Mount configuration and
credentials read-only; do not place private keys in node registration or API
requests. The [dashboard Deployment Guide](static/docs/deployment_guide.html#optional-ssh-audit)
contains a complete nonsecret example.

Upgrading an older SSH-audited installation requires this explicit target file;
automatic `pi@node.host` probing is no longer used. Audits always require strict
host-key verification, ignore ambient SSH configuration, and no longer honor
`BRIDGE_SSH_HOST_KEY_CHECKING` overrides. Obtain and independently verify the
host fingerprint before provisioning `known_hosts`. A changed key requires
investigation, not automatic acceptance. This feature never installs keys,
changes SSH servers, or modifies the host.

SSH results are cached for five minutes; Refresh requests another audit. Each
request runs at most four SSH processes concurrently, with a ten-second limit
per target and at most 32 targets in the configuration. Node contact and scanner
lease lifetimes are recomputed for each response even when SSH results are
cached. A new response timestamp is not a successful host or radio health check.

## Systemd Configuration

### Main Service (`sigrift-bridge.service`)

```ini
[Unit]
Description=SigRift Bridge - RF Signal Intelligence Dashboard
After=network.target

[Service]
Type=simple
User=sigrift
WorkingDirectory=/opt/sigrift
ExecStart=/usr/bin/python3 -m uvicorn sigrift.bridge.app:app \
    --host 127.0.0.1 --port 8001
Restart=always
RestartSec=10

# Environment
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=/opt/sigrift/src
Environment=BRIDGE_WQ_BATCH_SIZE=100
Environment=BRIDGE_WQ_FLUSH_MS=500

# Security hardening
ProtectSystem=strict
ReadWritePaths=/opt/sigrift/src/sigrift/bridge/data /opt/sigrift/src/sigrift/bridge/logs
NoNewPrivileges=true
PrivateTmp=true

# Logging (journald rotation)
StandardOutput=append:/opt/sigrift/src/sigrift/bridge/logs/bridge.log
StandardError=append:/opt/sigrift/src/sigrift/bridge/logs/bridge.log

[Install]
WantedBy=multi-user.target
```

The bridge binds to loopback only; expose it through the Rust gateway
(`sigrift-gateway.service`, TLS on port 8444 — see `INSTALL.md`) or a
reverse proxy.

**Install and enable:**

```bash
sudo cp sigrift-bridge.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sigrift-bridge
```

### Backup Service (`sigrift-backup.service`)

```ini
[Unit]
Description=SigRift Database Backup
After=network.target

[Service]
Type=oneshot
User=sigrift
ExecStart=/bin/bash -c '\
    BACKUP_DIR="/var/backups/sigrift"; \
    mkdir -p "$BACKUP_DIR"; \
    DB_PATH="/opt/sigrift/src/sigrift/bridge/data/detections.db"; \
    BACKUP_FILE="$BACKUP_DIR/detections-$(date +%%Y%%m%%d%%H%%M%%S).db"; \
    sqlite3 "$DB_PATH" ".backup $BACKUP_FILE" && \
    gzip "$BACKUP_FILE" && \
    find "$BACKUP_DIR" -name "detections-*.db.gz" -mtime +30 -delete && \
    echo "Backup completed: ${BACKUP_FILE}.gz"'
ProtectSystem=strict
ReadWritePaths=/var/backups/sigrift
ReadOnlyPaths=/opt/sigrift/src/sigrift/bridge/data
NoNewPrivileges=true
PrivateTmp=true
```

### Backup Timer (`sigrift-backup.timer`)

```ini
[Unit]
Description=Nightly SigRift Database Backup

[Timer]
OnCalendar=*-*-* 02:00:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
```

**Install:**

```bash
sudo cp sigrift-backup.service sigrift-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sigrift-backup.timer
```

### Log Rotation (`logrotate.conf`)

Rotates `/var/log/sigrift/bridge.log` daily with 14-day retention and 100 MB size cap.
Uses `copytruncate` so uvicorn does not need to reopen file handles.

**Install:**

```bash
sudo mkdir -p /var/log/sigrift
sudo chown sigrift:sigrift /var/log/sigrift
sudo cp logrotate.conf /etc/logrotate.d/sigrift-bridge
```

If using the default systemd unit (which logs to `/opt/sigrift/src/sigrift/bridge/logs/`),
update `StandardOutput` to point at `/var/log/sigrift/bridge.log` or adjust the
path in `logrotate.conf` to match.

---

## Docker

### Dockerfile

- Base: `python:3.11-slim`
- Runs as unprivileged `appuser`
- Port 8001 (no TLS — front with the Rust gateway or a reverse proxy)
- Health check: `GET /api/healthz` every 30s

### Build

```bash
# From the repo root
docker build -t bridge:latest -f src/sigrift/bridge/Dockerfile .

# Tag for registry
docker tag bridge:latest registry.example.com/sigrift/bridge:$(git rev-parse --short HEAD)
```

### Run (Standalone)

```bash
# Generate secrets
export BRIDGE_MASTER_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
export BRIDGE_MFA_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
# Initial admin password: generate it, and keep it in a password manager.
# It is not forced to change at first login (see below).
export BRIDGE_ADMIN_PASSWORD=$(openssl rand -base64 24)
# Audit-chain HMAC key: production refuses to start without it. Any strong,
# non-empty string works; keep it, since the audit chain is verified with it.
export BRIDGE_AUDIT_KEY=$(openssl rand -base64 24)
# Gateway-to-bridge proxy secret: production refuses to start if it is unset
# or the old public default. If you run the gateway, give it the same value.
export UC_PROXY_SECRET=$(openssl rand -base64 24)

# Run with persistent data volume
docker run -d --name bridge \
  -p 8001:8001 \
  -v bridge_data:/app/src/sigrift/bridge/data \
  -e BRIDGE_ENV=production \
  -e BRIDGE_MASTER_KEY="$BRIDGE_MASTER_KEY" \
  -e BRIDGE_MFA_KEY="$BRIDGE_MFA_KEY" \
  -e BRIDGE_AUDIT_KEY="$BRIDGE_AUDIT_KEY" \
  -e UC_PROXY_SECRET="$UC_PROXY_SECRET" \
  -e BRIDGE_ADMIN_PASSWORD="$BRIDGE_ADMIN_PASSWORD" \
  --restart unless-stopped \
  bridge:latest

# Verify
docker logs bridge --tail 20
curl -sf http://localhost:8001/api/healthz
```

The bridge reads `BRIDGE_ADMIN_PASSWORD` only to create the first admin
account, when no users exist. A password supplied this way is **not
forced to change** at first login, so it must be strong: generate it as
above instead of choosing a memorable one. Only the password the bridge
generates itself (outside production, when `BRIDGE_ADMIN_PASSWORD` is
unset) must be changed at first login.

### docker-compose.yml

The repo's top-level `docker-compose.yml` is the maintained stack: the
bridge stays internal (`expose: 8001`, no host port) and the Rust
gateway terminates TLS on port 8444. A minimal standalone equivalent:

```yaml
services:
  bridge:
    build:
      context: .
      dockerfile: src/sigrift/bridge/Dockerfile
    ports:
      - "8001:8001"
    volumes:
      - bridge_data:/app/src/sigrift/bridge/data
    environment:
      - BRIDGE_ENV=production
      - BRIDGE_MASTER_KEY=${BRIDGE_MASTER_KEY}
      - BRIDGE_MFA_KEY=${BRIDGE_MFA_KEY}
      - BRIDGE_ADMIN_PASSWORD=${BRIDGE_ADMIN_PASSWORD}
    healthcheck:
      test: ["CMD", "python3", "-c",
             "import urllib.request; urllib.request.urlopen('http://localhost:8001/api/healthz')"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    restart: unless-stopped

volumes:
  bridge_data:
```

### docker-compose with TLS Reverse Proxy

If you are not using the bundled Rust gateway, terminate TLS at a
reverse proxy instead:

```yaml
services:
  bridge:
    build:
      context: .
      dockerfile: src/sigrift/bridge/Dockerfile
    volumes:
      - bridge_data:/app/src/sigrift/bridge/data
    environment:
      - BRIDGE_ENV=production
      - BRIDGE_MASTER_KEY=${BRIDGE_MASTER_KEY}
      - BRIDGE_MFA_KEY=${BRIDGE_MFA_KEY}
      - BRIDGE_ADMIN_PASSWORD=${BRIDGE_ADMIN_PASSWORD}
      - BRIDGE_TRUSTED_PROXIES=172.16.0.0/12
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "8444:443"
    volumes:
      - ./certs:/etc/nginx/certs:ro
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      bridge:
        condition: service_healthy
    restart: unless-stopped

volumes:
  bridge_data:
```

Corresponding `nginx.conf`:

```nginx
server {
    listen 443 ssl;
    ssl_certificate /etc/nginx/certs/cert.pem;
    ssl_certificate_key /etc/nginx/certs/key.pem;

    location / {
        proxy_pass http://bridge:8001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws {
        proxy_pass http://bridge:8001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

nginx reaches the bridge from its own container address, so list it in
`BRIDGE_TRUSTED_PROXIES` (for example `BRIDGE_TRUSTED_PROXIES=nginx`).
Otherwise the bridge ignores its `X-Forwarded-For` and `X-Forwarded-Proto`:
client addresses show as nginx's and key rotation is refused as not TLS.

Without the gateway, the bridge serves `/api/auth/login`,
`/api/auth/change-password` and the admin user routes itself. A wrong
current password on `POST /api/auth/change-password` counts toward the
same account lockout as a failed login (10 failures in 30 minutes, then
429 with `Retry-After: 1800` for both) and is audited as `auth_failure`.
While the account is locked, its owner cannot change the password either,
even from a valid session. An admin reset
(`POST /api/admin/users/{username}/reset-password`) is not limited by the
lockout, but it does not lift it: logins stay locked until the window
passes. A password reset or change ends the user's pending MFA logins, and a
login or password change that verified the old password while a reset
committed gets 401 and no session (see `SECURITY.md`, "Rate Limiting").

### Volumes and Data Persistence

The `/app/src/sigrift/bridge/data` directory must be a persistent volume. It contains:

- `detections.db` — Main SQLite database (all state)
- `keys.json` — API key metadata
- `baselines.json`, `wifi_baselines.json`, `bt_baselines.json` — RF baselines
- `master.key`, `audit.key` — Auto-generated keys (dev mode)

**Never run without a persistent volume in production** — container restarts will lose all data.

#### API key store recovery (`keys.json`, `keys.json.bak`)

The bridge keeps `keys.json.bak`, a copy of the last good `keys.json`, and
never starts with an empty key store because `keys.json` is unreadable or
missing:

- An unreadable `keys.json` is restored from `keys.json.bak` at startup; a
  copy of the unreadable file is kept as `keys.json.corrupt-<UTC time>`
  (`keys.json` itself is replaced atomically, so a crash during recovery
  never leaves it missing). Without a usable backup, startup is refused.
- **Changed in this release:** a *missing* `keys.json` next to a
  `keys.json.bak` that holds keys is **restored from the backup** (logged
  at CRITICAL) instead of starting with no API keys, and a missing
  `keys.json` next to an **unreadable** `keys.json.bak` **refuses startup**
  (`KeyStoreCorruptError`). Only with neither file (a fresh install), or a
  backup without keys, does the bridge start with an empty key store.
- **To reset the API keys on purpose, stop the bridge and move both
  `keys.json` and `keys.json.bak` aside.** Earlier releases' CRITICAL
  message said to move only `keys.json` aside; doing only that now gets
  the keys restored from `keys.json.bak`.

### Environment File

Create a `.env` file alongside `docker-compose.yml`:

```bash
BRIDGE_MASTER_KEY=<generate with: python3 -c "import secrets; print(secrets.token_urlsafe(32))">
BRIDGE_MFA_KEY=<generate with: python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">
BRIDGE_ADMIN_PASSWORD=<initial admin password>
```

Keep `.env` out of version control (add to `.gitignore`).

---

## SQLite Pragmas (Applied at Startup)

| Pragma | Value | Purpose |
|--------|-------|---------|
| `journal_mode` | `WAL` | Write-Ahead Logging for concurrent reads |
| `busy_timeout` | `30000` | 30s wait on lock contention |
| `synchronous` | `NORMAL` | Safe with WAL, faster than FULL |
| `cache_size` | `-64000` | 64 MB page cache (configurable) |
| `mmap_size` | `268435456` | 256 MB memory-mapped I/O (configurable) |
| `temp_store` | `MEMORY` | Temp tables in RAM |
| `wal_autocheckpoint` | `1000` | Auto-checkpoint at ~4 MB |
| `journal_size_limit` | `67108864` | Cap WAL at 64 MB |

---

## Dev vs Production Behavior

| Behavior | Dev/Test | Production (`BRIDGE_ENV=production`) |
|----------|----------|--------------------------------------|
| Master key | Auto-generated, saved to `data/master.key` | **Required** via env var — startup fails |
| Admin password | Auto-generated, written to a 0600 temp file (deleted after 60 s), never logged | **Required** via env var when no users exist — startup fails |
| MFA encryption | Gracefully disabled (unset or invalid key → base64, warns) | **Required** — unset or invalid `BRIDGE_MFA_KEY` fails startup |
| Audit HMAC key | Auto-generated, saved to `data/audit.key` | **Required** — startup fails |
| CSRF protection | Disabled | Enabled |
| Query param auth | Deprecated (warns) | Disabled (rejected) |
| Admin password auto-delete | After 60s | After 60s |
| SQLCipher encryption | Optional (off by default) | Not yet supported end to end; use filesystem-level encryption (see [Data-at-Rest Encryption](#data-at-rest-encryption)) |

---

## Data-at-Rest Encryption

The bridge supports two approaches to data-at-rest encryption:

1. **SQLCipher** (application-level) — transparent encryption of the SQLite database via `pysqlcipher3`
2. **Filesystem-level** (LUKS/dm-crypt/BitLocker) — encrypt the volume containing the data directory

> **Not supported in this release.** Database encryption at rest with
> SQLCipher is not yet supported end to end and must not be relied on:
> the shipped images do not install `pysqlcipher3`, and with
> `pysqlcipher3` installed and a key set the bridge fails at start-up
> (`TypeError: Row() argument 1 must be sqlite3.Cursor`). To protect data
> at rest, use filesystem-level encryption
> ([Option 2](#option-2-filesystem-level-encryption)).

### Option 1: SQLCipher (not yet supported end to end)

SQLCipher provides transparent, page-level AES-256 encryption of the entire database file. WAL, SHM, and backup files are also encrypted.

**Prerequisites:**

```bash
# Debian/Ubuntu
sudo apt-get install libsqlcipher-dev
pip install pysqlcipher3

# macOS
brew install sqlcipher
pip install pysqlcipher3

# Verify
python3 -c "from pysqlcipher3 import dbapi2; print('OK')"
```

**Enable encryption:**

```bash
# Generate a strong key
export BRIDGE_DB_ENCRYPTION_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

# Or use a key file (chmod 600)
echo "$BRIDGE_DB_ENCRYPTION_KEY" > /opt/sigrift/src/sigrift/bridge/data/db.key
chmod 600 /opt/sigrift/src/sigrift/bridge/data/db.key
export BRIDGE_DB_ENCRYPTION_KEY_FILE=/opt/sigrift/src/sigrift/bridge/data/db.key
```

**Auto-migration:** If an existing plaintext database is detected on startup with a key configured, the bridge automatically encrypts it in-place. The original unencrypted file is preserved as `detections.db.unencrypted.bak`.

**Performance tuning:**

```bash
# Reduce KDF iterations for ~5% overhead instead of ~15% (still secure)
export BRIDGE_SQLCIPHER_KDF_ITER=64000
```

**What is NOT encrypted with SQLCipher:**
- `mbtiles` map tile files (read-only, not sensitive)
- In-memory databases (no data at rest)

**Key management:**
- **Key loss = permanent data loss.** Back up the key separately from the database.
- Store the key in a secrets manager, KMS, or HSM in production.
- Key rotation: `PRAGMA rekey='<new_key>'` (requires pysqlcipher3).

```
┌─────────────────────────────────────────────────────────┐
│                    SQLCipher Data Flow                   │
│                                                         │
│  Application                                            │
│      │                                                  │
│      ▼                                                  │
│  open_db(path, key)                                     │
│      │                                                  │
│      ├── PRAGMA key='...'    ◄── First stmt on connect  │
│      ├── PRAGMA kdf_iter=N                              │
│      ├── PRAGMA cipher_page_size=4096                   │
│      │                                                  │
│      ▼                                                  │
│  pysqlcipher3 (dbapi2)                                  │
│      │                                                  │
│      ▼                                                  │
│  ┌──────────────────────┐                               │
│  │  detections.db       │  AES-256-CBC encrypted pages  │
│  │  detections.db-wal   │  Also encrypted               │
│  │  detections.db-shm   │  Also encrypted               │
│  └──────────────────────┘                               │
└─────────────────────────────────────────────────────────┘
```

### Option 2: Filesystem-Level Encryption

If SQLCipher is not installed, encrypt the partition or volume containing the data directory.

**Linux: LUKS/dm-crypt**

```bash
# Create an encrypted partition (one-time setup)
sudo cryptsetup luksFormat /dev/sdX1
sudo cryptsetup open /dev/sdX1 sigrift-data
sudo mkfs.ext4 /dev/mapper/sigrift-data
sudo mount /dev/mapper/sigrift-data /opt/sigrift/src/sigrift/bridge/data

# Verify encryption is active
lsblk -f          # Look for "crypto_LUKS" type
cryptsetup status sigrift-data
```

Add to `/etc/crypttab` for auto-unlock at boot (with a keyfile or TPM).

**Docker:** Use encrypted host filesystem, encrypted volume driver, or cloud provider disk encryption (AWS EBS, GCP PD, Azure Disk).

**macOS / Windows (development):**
- **macOS**: Enable FileVault (on by default on Apple Silicon).
- **Windows**: Enable BitLocker on the data drive.

**Suppressing the health warning:** after confirming filesystem
encryption is active, set `BRIDGE_ENCRYPTION_KEY` in the bridge's
environment. With Docker Compose, add it under the bridge service in
`docker-compose.override.yml` (`.env` and shell exports are not passed to
the bridge):

```yaml
services:
  bridge:
    environment:
      - BRIDGE_ENCRYPTION_KEY=luks-configured
```

For a systemd install, put `BRIDGE_ENCRYPTION_KEY=luks-configured` in the
unit's environment file.

### What is stored in the database

- RF detections (frequency, signal class, anomaly scores)
- User credentials (PBKDF2-HMAC-SHA256 hashed passwords, session tokens)
- TOTP/MFA secrets (Fernet-encrypted if `BRIDGE_MFA_KEY` is set, base64 otherwise)
- Audit logs and HMAC chains
- Anomaly baselines and calibration state
- API key metadata

---

## Filesystem Layout

```
/opt/sigrift/
  src/sigrift/
    bridge/
      app.py                    # FastAPI application
      __main__.py               # Entry point
      data/
        detections.db           # Main SQLite database
        detections.db-wal       # WAL file
        detections.db-shm       # Shared memory
        master.key              # Auto-generated master key (dev)
        audit.key               # Auto-generated audit key (dev)
        keys.json               # API key metadata
        baselines.json          # RF signal baselines
        wifi_baselines.json     # WiFi baselines
        bt_baselines.json       # Bluetooth baselines
        fingerprint_encoder.pth # ML model (optional)
        family_classifier.pth   # ML model (optional)
        mbtiles/                # Map tiles (optional)
      logs/
        bridge.log              # Application log
      logrotate.conf            # Log rotation config
  tls/
    cert.pem                    # Gateway TLS certificate
    key.pem                     # Gateway TLS private key
```

---

## Minimal Production Checklist

```bash
# 1. Generate secrets
export BRIDGE_MASTER_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
export BRIDGE_MFA_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export BRIDGE_ADMIN_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")
export BRIDGE_AUDIT_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
export UC_PROXY_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
export BRIDGE_ENV=production

# 2. Generate TLS certs for the gateway (or use real ones)
mkdir -p tls
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout tls/key.pem -out tls/cert.pem \
  -days 365 -subj "/CN=gateway"

# 3. Create service user
sudo useradd -r -s /bin/false sigrift

# 4. Install and start
sudo cp sigrift-bridge.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sigrift-bridge

# 5. Enable backups
sudo cp sigrift-backup.service sigrift-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sigrift-backup.timer

# 6. Verify (direct to the bridge; via the gateway use https://localhost:8444)
curl -sf http://127.0.0.1:8001/api/healthz
journalctl -u sigrift-bridge -f
```

