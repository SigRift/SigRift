# SigRift gateway

High-performance Rust detection ingest microservice for the SigRift bridge.

## Why

The Python/FastAPI ingest pipeline in the SigRift bridge saturates a single uvicorn worker at ~5.7 detections/sec with 5 edge nodes. The SigRift gateway ports the hot path to Rust while leaving the admin/config/dashboard UI in Python.

## Architecture

```
Edge Nodes ──POST /batch──► SigRift gateway (Rust/axum)
                                │
                                ├── Normalize signal classes (40→30 canonical)
                                ├── Score anomalies (7-dimension weighted scorer)
                                ├── Detect FHSS (sliding window hop analysis)
                                ├── Cross-node correlation (frequency + time matching)
                                ├── Evaluate alert rules
                                ├── Store to SQLite (shared WAL-mode DB)
                                └── Broadcast via WebSocket
                                        │
Dashboard ◄── Python/FastAPI ◄──reads───┘
```

Both services share the same `detections.db` SQLite file via WAL mode. The Python app owns the schema and runs its migrations. The gateway reads and writes the bridge's tables, never migrates them, and refuses a database migrated by a newer bridge; it adds only a few tables of its own (see [Database Compatibility](#database-compatibility)).

## Modules

| Module | Description |
|--------|-------------|
| `ingest::handler` | POST /batch endpoint — full pipeline |
| `ingest::normalize` | Signal class → canonical class + family mapping |
| `ingest::validate` | Input validation, gzip decompression with bomb protection |
| `scoring::scorer` | 7-dimension anomaly scorer with weighted composite |
| `scoring::baseline` | EWMA frequency baselines with Welford variance tracking |
| `scoring::weights` | Configurable scoring dimension weights |
| `analysis::fhss` | FHSS detection via sliding-window frequency hop analysis |
| `analysis::correlator` | Multi-node signal correlation (time + frequency matching) |
| `analysis::alert` | Alert rule evaluation engine |
| `auth::api_key` | SHA256 API key validation with role-based access |
| `ws::auth` | WebSocket authentication before the upgrade, and re-validation of open sockets |
| `ws::feed` | WebSocket detection broadcast feed (and the runner shared by all broadcast feeds) |
| `ws::anomaly_feed` | WebSocket anomaly broadcast feed |
| `proxy::ws_proxy` | Authenticated WebSocket proxy to the bridge, with connection caps |
| `audit::store` | HMAC-chained audit log, archive anchor, retention |
| `db::*` | SQLite connection pool, batch insert, anomaly upsert |
| `class_map` | Static signal class → family lookup tables |
| `cache` | TTL cache with prefix invalidation |

## Anomaly Scoring Dimensions

The gateway scorer defines 10 dimensions to match the Python scorer's schema, but only 7 are active on the batch ingest hot path (the three IQ-dependent dimensions — `iq_quality`, `spectral_anomaly`, `modulation_anomaly` — score 0.0 here because raw IQ samples are not part of the batch payload). The active weights, taken from `crates/sigrift-gateway-core/src/scoring/weights.rs`:

| Dimension | Weight | Description |
|-----------|--------|-------------|
| novel_class | 0.22 | Signal class never seen at this frequency |
| rare_class | 0.14 | Signal class with low historical probability |
| low_confidence | 0.14 | ML classifier confidence below normal |
| power_zscore | 0.10 | Signal power deviates from EWMA baseline |
| snr_zscore | 0.08 | SNR deviates from EWMA baseline |
| timing_anomaly | 0.07 | Signal class unusual at this hour |
| quiet_frequency | 0.04 | Rarely-used frequency bin |

Inactive on batch ingest (weights reserved for parity with the Python scorer): `iq_quality` (0.08), `spectral_anomaly` (0.07), `modulation_anomaly` (0.06).

Scores map to priority labels: `<0.3` normal, `0.3-0.5` interesting, `0.5-0.7` anomalous, `>=0.7` critical. During the learning phase (first 100 detections per 100 kHz frequency bin), baseline-dependent dimensions are dampened to 0.75x; `novel_class` is never dampened so unknown signals still score at full weight.

### Divergence from the Python scorer (intentional)

The gateway runs this fast 7-active-dimension score on every detection as it lands. The Python bridge re-scores selected detections with a deeper scorer (`src/sigrift/bridge/anomaly/scorer.py`) that adds correlation, signature-match, bandwidth, and inter-arrival dimensions for surfacing in the UI. The two scorers share dimension names and core weights by design; the bridge layer is where richer cross-source context is folded in.

## Building

Run from `src/gateway/` (or substitute repo-root-relative paths):

```bash
cargo build --release
```

## Running

From `src/gateway/`:

```bash
./target/release/sigrift-gateway \
  --db-path ../sigrift/bridge/data/detections.db \
  --host 0.0.0.0 \
  --port 8444 \
  --keys-path ../sigrift/bridge/data/keys.json
```

See `--help` for all options including `--baseline-alpha`, `--pool-size`, `--max-body-size`, `--active-nodes`, and `--log-level`.

### Production secrets

`BRIDGE_ENV` defaults to `production`. With `BRIDGE_ENV=production` (or `prod`) the gateway refuses to start unless all of these are set, to the same values the bridge uses:

| Variable | Requirement | Generate with |
|---|---|---|
| `UC_PROXY_SECRET` | non-empty, not `uppercrust-internal` | `python3 -c 'import secrets; print(secrets.token_urlsafe(32))'` |
| `BRIDGE_AUDIT_KEY` | non-empty | `python3 -c 'import secrets; print(secrets.token_urlsafe(32))'` |
| `BRIDGE_MFA_KEY` | a valid Fernet key (see below) | `python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'` |

The gateway does not need `BRIDGE_MASTER_KEY`. If `BRIDGE_AUDIT_KEY` is unset it still derives the audit key from the deprecated `BRIDGE_AUDIT_SECRET` / `BRIDGE_MASTER_KEY` fallbacks for backward compatibility, and warns at startup.

`BRIDGE_MFA_KEY` is valid when, after trimming surrounding whitespace, it is exactly 44 characters: 43 characters from `A-Z a-z 0-9 - _ + /` followed by `=`, decoding to 32 bytes. This is the same rule the bridge and the installers use, and it matches what Python's `Fernet` accepts, so both the URL-safe and the standard base64 alphabet work. A 43-character key (the `secrets.token_urlsafe(32)` output that older installs used) is not valid, but appending `=` makes it valid and keeps the same 32 bytes, so existing encrypted TOTP secrets stay readable. For any other invalid key, generate a new one. The gateway never encrypts with an invalid key. In development it stores new TOTP secrets base64-encoded (`b64:`) instead, as the bridge does. It still decrypts secrets that an older gateway wrote under the 43-character form. If a user's TOTP secret cannot be decrypted, that user can still finish an MFA login with a backup code.

With any other `BRIDGE_ENV` (e.g. `development`, `test`) the gateway starts anyway and logs each problem. `UC_PROXY_SECRET` is still needed in every mode, development included:

- A bridge with `BRIDGE_REQUIRE_PROXY=true` (as in the compose stack) refuses every request the gateway proxies without it.
- The bridge's gateway-only API (`/api/internal/*`) refuses every call without it, whatever `BRIDGE_REQUIRE_PROXY` says. So a development gateway without a usable `UC_PROXY_SECRET` (empty, or the old default `uppercrust-internal`) logs one error at startup, and runs with node-key binding and post-ingest hooks **disabled**: unbound node keys stay unbound and can submit for any node (as with `BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1`), and no alert rules, watch-band alerts, webhooks, edge-decoded message storage or protocol-decode jobs run for ingested batches. `GET /health` then shows `post_ingest_hooks.enabled: false` and counts the detections in `hooks_disabled`.

### Startup

Before it changes anything in the database, the gateway refuses to start (exit 1) on a database that a newer bridge has migrated; see [Database Compatibility](#database-compatibility).

Before it listens, the gateway waits up to 60 s for the bridge to answer `GET {UC_PYTHON_URL}/api/version`, then checks the database's schema again. The probe sends `X-Rust-Proxy: <UC_PROXY_SECRET>` like every proxied request, so it passes a bridge that runs with `BRIDGE_REQUIRE_PROXY=true`. If the bridge answers 403, the secrets differ (or `UC_PROXY_SECRET` is empty). The gateway then logs that as an error and starts at once, without waiting.

### Shutdown

On SIGTERM (`docker stop`) or Ctrl-C the gateway:

1. stops accepting connections, and gives the requests in progress up to 3 s to finish;
2. gives the post-ingest hooks still queued up to 5 s to reach the bridge (one attempt each; it stops at the first failure);
3. saves the rest to the hook spool (see [POST /batch](#post-batch));
4. logs a last summary of the hook counters, which `GET /health` no longer shows once it has exited: a warning with the totals of hooks lost since it started (`failed_*`: given up after the retries or refused by the bridge, including during the 3 s above; `dropped_*`: the queue or the spool was full, or the spool could not be written), or an info line when none was lost; then exits.

That fits in Docker's default 10 s stop timeout. Before, the gateway ignored SIGTERM (it is PID 1 in its container), so Docker killed it after 10 s.

## Testing

From `src/gateway/`:

```bash
cargo test                    # 69 tests (61 unit + 8 integration)
```

## Benchmarks

From `src/gateway/`:

```bash
cargo bench                   # normalize, scoring, and DB insert throughput
```

## API

### POST /batch

Accepts a JSON (or gzip-compressed JSON) batch: `{"node_id": ..., "detections": [...]}`. Requires SENSOR role or higher, usually an API key in the `X-API-Key` header.

The same holds for `POST /api/detections/batch`. When CSRF protection is on, a batch sent with a user session (the `session_token` cookie, or the session token in `Authorization: Bearer` or `X-Session-Token`) needs the CSRF token, as every other session `POST` does: an `X-CSRF-Token` header equal to the `csrf_token` cookie. Otherwise it gets 403 `{"detail": "CSRF token missing or mismatch"}`. A batch sent with an API key or a client certificate needs no CSRF token. An agent's certificate batch carries no `Origin`, so the `Origin` check on client certificates (see [Client certificates (mTLS)](#client-certificates-mtls)) does not affect it. (The bridge exempts both batch paths from its CSRF check; the gateway serves them itself and does not.)

The gateway listens on TLS port 8444 by default (see `docker-compose.yml` and `crates/sigrift-gateway-core/src/config.rs`). Port 8001 is the Python bridge and is `expose:`-only in the compose stack — not host-published.

```bash
curl -X POST -k https://localhost:8444/batch \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: <key>' \
  -d '{"node_id":"edge-01","detections":[{"signal_class":"qpsk","confidence":0.95,"freq_hz":2400000000}]}'
```

The `-k` flag bypasses certificate verification and is acceptable for local self-signed-cert development (see `INSTALL.md`). For production, use a real certificate and drop `-k`.

Node binding:

- A key bound to a node (`node_id` in `keys.json`) can only submit batches whose `node_id` is that node, whatever its role. Any other batch gets 403.
- An unbound node key (role SENSOR or NODE) is bound to the batch's node on its first batch ("trust on first use"). The gateway asks the bridge to bind it: `POST {UC_PYTHON_URL}/api/internal/bind-node-key` with `{"key_id", "node_id"}` and `X-Rust-Proxy`. The bridge makes the same atomic `keys.json` change its own node routes make, and the gateway reloads the file afterwards.
  - The bridge answers 200: the batch is accepted.
  - The bridge answers 409 because the key is bound to another node, or 404 (unknown key): the batch gets 403 `{"detail": "API key is bound to a different node"}`.
  - The bridge answers 409 because another key is already bound to that node (the first key to claim a node keeps it): the batch gets 403 `{"detail": "Node '<node>' already has a bound API key; an admin must bind this key to it explicitly"}`. To give a node a second key, create or update the key with that `node_id` as an admin.
  - The bridge answers 409 (or 403) `{"detail": "Node endpoints require a node API key"}` because its role for the key is not a node role: the batch gets 403 with that detail. This happens when a key's role was just changed and the gateway has not reloaded `keys.json` yet.
  - Any other answer, or no answer within 2 s: the batch gets 503 (fail closed).
  - With `BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1` (also `true`, `yes`, `on`) in the gateway's environment, unbound node keys (SENSOR or NODE) stay unbound and can submit for any node, as before. It concerns node keys only: VIEWER keys, including keys stored without a role, are still refused (below), as on the bridge's own node routes. Set it on the bridge too. The gateway logs a warning at startup when it is set. Without a usable `UC_PROXY_SECRET` (development only, see [Production secrets](#production-secrets)) the gateway does the same for node keys, because the bridge refuses the binding request; VIEWER keys are refused then too.
  - The bridge's legacy rule still applies in that mode: a key whose id is the id of a node registered with the bridge is that node's key, and can only submit for that node (403 `{"detail": "API key is bound to node '<key id>'"}` otherwise). The gateway reads the registered nodes from the bridge's `nodes.json`, in the same directory as `keys.json` (`UC_KEYS_PATH`), and re-reads it when it changes. The bridge saves that file periodically, so a node registered in the last minute or so may not be listed yet. Once the bridge applies the rule for a key on its own node routes (a heartbeat, for example), it also writes the binding to `keys.json`.
- An unbound VIEWER key gets 403 `{"detail": "Node endpoints require a node API key"}`, with or without `BRIDGE_ALLOW_UNBOUND_NODE_KEYS`: a dashboard key is not a node credential, and it is never bound automatically. Bind it to a node explicitly (as an admin), or give it the `node` role, if it really is one. The gateway decides this without asking the bridge.
- An unbound ANALYST key can submit for any node and stays unbound (operator tooling), like an ANALYST session.
- The legacy rule above also applies to unbound VIEWER and ANALYST keys: one named after a registered node can only submit for that node. For these keys the gateway applies it from its copy of `nodes.json` alone (no binding request), so a VIEWER key named after a node registered so recently that the bridge has not saved `nodes.json` yet gets 403 `Node endpoints require a node API key` until the bridge saves it, or until the key's first request on one of the bridge's own node routes (a heartbeat) writes the binding to `keys.json`. Keys stored without a role are VIEWER keys (below); older gateways read them as SENSOR and asked the bridge to bind them, which used the bridge's live node list. Give a key that a node uses the `node` role to avoid that window.
- The role is the one the bridge uses. A key stored without a role, or with a value that names no role (null, a number, an unknown or padded name), is a VIEWER key, and the bridge's `master` key is ADMIN whatever `keys.json` stores for it. A key whose id starts with `node_`, `rtlsdr_`, `hackrf_`, `sensor_`, `edge_` or `sdr_` and that is stored with a role of ANALYST or higher (`analyst`, `admin` or `keymaster`, in any letter case) is a NODE key, as on the bridge (it changes the role when it loads `keys.json`, and writes the change at its next key change). So such a key is bound on its first batch like any node key, and is not ANALYST operator tooling.
- An unbound ADMIN or KEYMASTER key can submit for any node.
- A client certificate below ADMIN can only submit for the node its identity names (the certificate identity is the node id; there is no trust on first use). An ADMIN-or-above certificate can submit for any node.
- A user session of ANALYST or above can submit for any node. A session below ANALYST gets 403 `{"detail": "Node endpoints require a node API key"}`.

Validation:

- Each detection's `node_id` must equal the batch's `node_id`. If it is missing, the batch's value is used.
- A detection without `detection_id` keeps the `id` the edge agents send (it is the id their later IQ upload and decoded messages refer to). Without either, the gateway generates one. A detection whose id is already stored (a batch sent again) is not stored twice.
- Each detection is checked against the bridge's rules:
  - `signal_class`: `[A-Za-z0-9_/.-]{1,128}`.
  - `detection_id`: `[A-Za-z0-9_.:-]{1,128}`, no `..`.
  - `timestamp`: an ISO 8601 / RFC 3339 time or a Unix number.
  - `confidence`: 0–1.
  - `freq_hz`: 0–10¹² Hz.
  - Numeric fields: finite.
  - `backend`: `[A-Za-z0-9_-]{1,32}`.
  - `lna_state`: at most 64 characters, no control characters.
- A detection that fails is dropped on its own. The rest of the batch is still stored. The response counts the dropped ones in `rejected`, and `rejected_reasons` gives the count per reason (for example `{"node_mismatch": 1}`).
- A malformed batch `node_id` or `batch_id` rejects the whole batch with 400.

Post-ingest work (alert rules, watch bands, rule trigger counts, webhooks, storing edge-decoded messages, protocol-decode jobs) runs on the bridge. After a batch is stored, the gateway queues its newly stored detections for the bridge's `POST /api/internal/ingest-hook` (authenticated by `X-Rust-Proxy`):

- The body is `{"node_id", "detections": [as stored], "decoded_messages": [each message the edge attached to one of them, with its "detection_id" and "node_id"], "received_at"}`.
- A batch of more than 500 detections is sent as several requests.
- Edge-decoded messages are bounded as on the bridge: at most 50 per detection and 1000 per batch, each at most 16 KiB. Entries that are not objects are dropped too, and all drops are counted.
- The queue holds at most 10 000 detections (and 64 MiB). When it is full, the oldest queued batch is dropped and counted, with a warning on the first drop and every 100th.
- One background task sends the queue in order. A 5xx or connection error is retried: 3 attempts, 0.5 s then 1 s apart. After the last failure the item is dropped and the task pauses 2 s. A 2xx is done; a 4xx is logged and the item dropped.
- When the gateway stops (SIGTERM or Ctrl-C, see [Shutdown](#shutdown)), what is still queued gets 5 s to be delivered, then the rest is saved to the hook spool: `UC_HOOK_SPOOL_PATH`, by default `gateway-post-ingest-hooks.spool` in the directory of `UC_BASELINE_PATH` (`/app/data` in the container). The file has mode 0600, holds one hook body per line and is at most 64 MiB (the oldest items are left out first). At the next start it is queued again, before anything new, and deleted. The bridge ignores a detection it has already hooked, so a hook sent twice does no harm.
- Hooks are still best-effort: whatever is queued when the gateway is killed (no shutdown signal, or a crash), or does not fit the queue or the spool, is lost, and counted or logged. The last line the gateway logs about hooks at shutdown gives the totals lost since it started.
- Without a usable `UC_PROXY_SECRET` (development only) nothing is queued, because the bridge would refuse it: the detections are counted in `hooks_disabled`. A spool from an earlier run is kept until the gateway starts with the secret set.
- The counters are in `GET /health`.

So alerts for a batch are created asynchronously, and `alerts_created` in the ingest response is always 0.

The anomaly baselines track a class under its canonical name. Every class outside the canonical taxonomy shares one `unknown` entry, so sensors cannot make the gateway track arbitrary names (the stored detection keeps its class). At most 8192 frequency bins, 64 signal classes per bin and 32 768 (bin, class) entries in all are tracked. When a cap is reached, the least recently updated bin (or, within a bin, class) is evicted. A `baselines.json` written by an older gateway is folded into this shape on load. The file is written as compact JSON.

### WebSockets

Gateway-native feeds:

- `/ws/feed` (also `/api/detections/ws/feed`): detection records, VIEWER or above.
- `/ws/anomalies`: anomalies above the scoring threshold, VIEWER or above.
- `/ws/audit`: every audit entry the gateway writes, ADMIN only.

Proxied to the bridge, VIEWER or above:

- `/ws/status`, `/ws/alerts`, `/ws/wifi`, `/ws/bluetooth`, `/ws/zigbee`, `/ws/spectrum`, `/ws/spectrum-monitor`
- the `/api/...` paths the dashboard uses: `/api/nodes/ws/status`, `/api/alerts/ws/alerts`, `/api/wifi/ws/wifi`, `/api/bluetooth/ws/bluetooth`, `/api/zigbee/ws/zigbee`, `/api/spectrum/ws/spectrum`, `/api/spectrum/ws/spectrum-monitor`

Authentication happens before the upgrade:

- The gateway accepts the same credentials as HTTP: the session cookie, `Authorization`, `X-Session-Token`, `X-API-Key`, `?api_key=`, or a client certificate.
- It also accepts a credential in the subprotocol list, `Sec-WebSocket-Protocol: bridge-v1, <credential>`. The credential is an API key or a session token. This is what the dashboard sends. The server answers with `bridge-v1`.
- A session token in the subprotocol list gets the same checks as one from the cookie: expiry, idle timeout, disabled user and session binding (`BRIDGE_SESSION_BINDING`). It is not subject to the `Origin` check below, because a browser never sends it by itself.
- An unauthenticated upgrade gets 401. A role that is too low gets 403. Nothing is upgraded in either case, and no connection to the bridge is opened.
- A session limited to MFA setup or a password change cannot open WebSockets.
- A session taken from the cookie, or a client certificate, is refused (403) when the browser's `Origin` is a different origin (scheme, host or port). Both are ambient credentials: the browser sends the cookie, and presents its certificate, on a handshake that a page on another origin starts. A request without an `Origin` (an agent, not a browser) is not checked, and neither is an API key. To allow an origin explicitly, list it in `UC_CORS_ORIGINS` exactly as the browser sends it, scheme included.
- This origin is worked out as follows:
  - The scheme is `https` when the gateway serves TLS itself (`UC_TLS_CERT` and `UC_TLS_KEY`), and `http` otherwise. A page served over plain `http` on the same host is another origin than the `https` gateway.
  - The host and port are those of the `Host` header (or, for HTTP/2, the request's authority). The scheme's default port can be left out on either side.
  - `X-Forwarded-Proto` and `X-Forwarded-Host` count only when the direct peer is a trusted proxy (`UC_TRUSTED_PROXIES`, see [Client IP and trusted proxies](#client-ip-and-trusted-proxies)). From any other peer they are ignored. From a trusted proxy, `X-Forwarded-Proto` replaces the scheme and `X-Forwarded-Host` names this host too. If either header has several entries, only the last one counts (the one the proxy added). When a trusted proxy's `X-Forwarded-Proto` is not `http` or `https` (`ws` and `wss` also count), no origin is this origin: a cookie or certificate handshake with an `Origin` is then accepted only from an origin listed in `UC_CORS_ORIGINS`.
- Behind a reverse proxy: list the address it connects from in `UC_TRUSTED_PROXIES`. The default, `127.0.0.1,::1`, covers only a proxy in the gateway's own network namespace: on the same host when the gateway runs outside a container. In the compose stack it does not cover a proxy on the host. That proxy reaches the gateway through Docker's published port, so the gateway sees it connect from the gateway address of the stack's default network (for example `172.18.0.1`; `docker network inspect` shows it), not from `127.0.0.1`. A proxy in another container connects from that container's address. `docker-compose.yml` does not pass `UC_TRUSTED_PROXIES` to the gateway, so add it to the gateway's `environment` (for example in a `docker-compose.override.yml`). Prefer that one address to the network's subnet: every address in `UC_TRUSTED_PROXIES` may set `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host`, and the edge containers share that network. (The network's gateway address also stands for every other process on the host that uses the published port, as `127.0.0.1` does outside a container.) Forward the original `Host`, or set `X-Forwarded-Host`. If the proxy terminates TLS in front of a plaintext gateway listener, it must also send `X-Forwarded-Proto: https` (for nginx, `proxy_set_header X-Forwarded-Proto $scheme;`). Without it the gateway takes the scheme to be `http`, and refuses the dashboard's cookie WebSockets from the `https` page. A proxy outside `UC_TRUSTED_PROXIES` has neither header honoured, so it must forward the original `Host`, and its scheme must be the gateway listener's. A refused handshake is logged with the origin the gateway expected (`expected_scheme`, `expected_hosts`) and whether the peer was a trusted proxy (`trusted_proxy`).

Proxied sockets:

- The gateway opens the bridge connection only after the client is authenticated. It turns `http://` into `ws://` and `https://` into `wss://`.
- The gateway forwards the client's query string and its `Sec-WebSocket-Protocol` unchanged.
- It forwards the credential it verified, in the form the bridge reads, so the bridge authenticates the client again:
  - A session goes as the `session_token` cookie, whether it came from the cookie, `Authorization`, `X-Session-Token` or the subprotocol list.
  - An API key goes as `X-API-Key`, whether it came from `X-API-Key`, `Authorization`, `?api_key=` or the subprotocol list. (The bridge refuses a key in the query string unless `BRIDGE_WS_QUERY_AUTH=enabled`.)
  - Other credentials the client sent are not forwarded. For example, a stale session cookie next to a valid API key is dropped, because the bridge would refuse the socket on it.
- It sets `X-Rust-Proxy`, `X-Forwarded-For` and the identity headers of the verified principal exactly as the HTTP proxy does. It forwards the client's `User-Agent`, which the bridge's `BRIDGE_SESSION_BINDING=strict` check compares with the one stored at login. No other client header reaches the bridge.
- The subprotocol the bridge selects is echoed to the client. If the bridge refuses with a 4xx, the client gets the same status.
- When either side closes, the other side is closed too, with the same close code.
- Concurrent proxied sockets are capped. The limits are `UC_WS_PROXY_MAX_PER_IP` (default 32, per client IP as resolved through `UC_TRUSTED_PROXIES`) and `UC_WS_PROXY_MAX_TOTAL` (default 1024). `0` turns a cap off. Over the per-IP cap the upgrade gets 429; over the total cap it gets 503.

Open sockets:

- The credential of an open socket is checked again every `UC_WS_REVALIDATE_SECS` (default 30 s). An API key is also checked as soon as `keys.json` is reloaded.
- The socket is closed with code 4001 when its API key is revoked, disabled, expired or below the route's role. It is also closed when its session is logged out or expired (absolute or idle timeout), or when the user is disabled or demoted.
- This check does not extend the session. A socket that is the only activity of a session closes when the session's idle timeout passes.
- A client-certificate socket is looked up in the CA registry again (the registry reloads when the bridge changes it). It is closed with 4001 when the certificate is revoked, expired or removed, or its role drops below the route's. It is also closed when its entry becomes one the bridge could not have written (see [Client certificates (mTLS)](#client-certificates-mtls)), even if the new value looks like a higher role: a role edited to `ADMIN` or `keymaster` closes the socket, and only the gateway's WARN log (`field="role"`) says why. Revoking a certificate does not end its TLS connection, so this check is what closes the socket.

Native feed messages:

- A feed sends JSON messages.
- A client that falls behind the broadcast buffer gets `{"type": "lagged", "dropped": N}` and keeps receiving.
- When the feed ends, the socket is closed.

### Audit log

Every audit entry is HMAC-chained to the previous one. The bridge appends to the same chain. Gateway writes take the database write lock before they read the chain head (`BEGIN IMMEDIATE`). A busy database is retried a few times. An entry that still cannot be written is logged at `error`.

`GET /api/admin/audit` (`limit`, default 200; `offset`, default 0) lists entries newest first by id, the order they were written in. Its filters, `count` and `total` are the bridge's:

- The filters are `action`, `operator`, `node_id` and `target_id` (exact), `search` (part of the note, target id or action, matched literally: `%`, `_` and `\` are not wildcards), `start` and `end` (inclusive timestamps) and `severity` (`info` also matches entries that record no severity; an empty `severity` is no filter). Any other empty filter applies as given: `?action=` selects only entries whose action is empty.
- The response is `{count, total, offset, limit, entries}`. `count` is the size of this page. `total` is the number of entries the filters select over all pages. The gateway reads the page and `total` in the same snapshot.

It differs from the bridge's `GET /api/admin/audit` in these ways:

- The bridge orders entries by timestamp, not id. The bridge writes timestamps to the microsecond and the gateway to the second, so entries written within the same second can sort differently. A page can then hold different entries on the two, although `total` is the same.
- A `limit` outside 1 to 1000 is clamped, and a negative `offset` is read as 0. The bridge answers both with 422.
- A filter given twice (`?action=login&action=dismiss`) is a 400. The bridge uses the last value.
- Entries have no `target_ids` field.

`POST /api/admin/audit/archive` (`{"days": N}`, default 90):

- It moves the oldest entries to `audit_log_archive`. Only an unbroken run from the start of the chain moves, and every entry in it is older than N days.
- It records an HMAC-sealed archive anchor in `audit_anchor`: the id and HMAC of the last archived entry.
- It appends an `archive_marker` entry with the operator, count, `terminal_hmac` and `last_archived_id`.
- If the entries to archive fail verification, nothing is archived (409).

`DELETE /api/admin/audit?days=N`:

- It deletes archived entries older than N days.
- It only deletes entries in the archive table up to the anchor. It never deletes live entries.
- It is recorded as an `audit_purge` entry.

`GET /api/admin/audit/verify` starts from the anchor, so the chain stays valid after an archive. It reports an edited or missing anchor, and entries removed after it.

An entry without an HMAC is accepted only before the chain's first signed entry: such rows were written before the chain existed. The gateway and the bridge sign every entry they write, so an unsigned entry after a signed one was appended, or rewritten and its HMAC blanked, without the key. It is reported with the `expected` "an HMAC: only entries before the chain's first signed entry may have none" and an empty `actual`. An archived prefix that ended with a signed entry counts as signed, so blanking every live entry after an archive is reported too. The bridge's verifier applies the same rule. Older releases of both accepted any unsigned entry.

Both archive and purge refuse a `days` value below `UC_AUDIT_MIN_RETENTION_DAYS` (default 7, at least 1) with 400.

Every change made through `PUT /api/admin/settings/security` is recorded as a `security_settings_changed` entry. The entry has the operator and the old and new value of each changed setting. It is written before the change is applied. If it cannot be written, nothing changes and the request gets 500. Once it is written, the change is applied even if the client disconnects.

`PUT /api/admin/settings/security` refuses with 400, and then applies and records nothing from the request. Its `detail` says which setting is wrong and why (`must be an integer`, `must be a number`, `must be at least 1`, `must be at most N`):

- a `session_absolute_timeout_hours` or `session_idle_timeout_minutes` below 1, whatever number it is (`0`, `-24`, `0.5`). Such a timeout would end every session at once.
- a `session_absolute_timeout_hours` above 10000000 (about 1141 years, the ceiling the bridge puts on an API key's `expires_in_hours`), whatever number it is (`10000001`, `1e20`). Older gateways accepted it, and then every login failed (from about 2.3e9 hours) or got a session that its first request deleted (from about 7e7 hours).
- a `session_idle_timeout_minutes` above 18446744073709551615, the largest integer the gateway's JSON parser holds.
- a `session_absolute_timeout_hours` or `session_idle_timeout_minutes` within those bounds that is not a JSON integer (a string, `null`, or a number written with a fraction or an exponent, such as `1.5`, `24.0` or `1e3`). Older gateways ignored such a value and answered 200.
- a `rate_limit_max` or `lockout_max` outside 1 to 4294967295 (the range `UC_RATE_LIMIT_MAX` and `UC_LOCKOUT_MAX` accept), whatever number it is (`0`, `0.5`, `-1`, `4294967296`, `1e20`), or one that is not a JSON integer (a string, `null`, `1.5`, `7.0`, `1e3`). A count of 0 refuses every login, administrators' included, since an attempt is allowed only below the count. Older gateways applied 0, wrapped a count above 4294967295 (`4294967296` was applied as 0 and `4294967297` as 1) and ignored the others.
- a `rate_limit_window_secs` or `lockout_window_secs` below 1 (`0`, `0.5`, `1e-9`, `-1`), or one that is not a number (a string, `null`). Such a window counts no earlier attempt (a negative one none at all, one below a second practically none), so it turns the rate limit or the lockout off. Older gateways applied it. A window may have a fraction (`90.5`). `lockout_window_secs` is at most 86400 (see Account lockout below); `rate_limit_window_secs` has no upper bound here, but the limit holds over the whole window only up to 60 seconds (see Login rate limit below).

A huge `session_idle_timeout_minutes` is accepted and means no idle limit. One above 9223372036854775807 is used as 9223372036854775807, so a client that reads that value as a JavaScript number and sends it back (`9223372036854776000`) is not refused. A session's `expires_at` is never later than `9999-12-31T23:59:59+00:00`, the last second the gateway and the bridge can read.

### GET /health

Returns 200 and `{"status": "ok", "post_ingest_hooks": {...}}`. `post_ingest_hooks.enabled` is `false` when the hooks are disabled (no usable `UC_PROXY_SECRET`). The `post_ingest_hooks` counters are: `queued_batches`, `queued_detections`, `queued_bytes`, `capacity_detections`, `enqueued_batches`, `enqueued_detections`, `delivered_batches`, `delivered_detections`, `dropped_batches` and `dropped_detections` (dropped from a full queue, or from a full spool at shutdown), `failed_batches` and `failed_detections` (given up after the retries, refused by the bridge, or queued after the shutdown spool was written), `retries`, `decoded_messages_dropped`, `hooks_disabled` (detections not hooked because the hooks are disabled), and `restored_batches` and `restored_detections` (queued again from the spool at startup).

### Request paths

axum matches routes on the raw path, while the bridge's server percent-decodes the path before routing. So before routing (and before every path-based check: native routes, auth exemptions, session scopes, CSRF exemptions, the proxy's filters) the gateway normalizes the path:

- It decodes percent-encoded unreserved characters (`A-Z a-z 0-9 - . _ ~`) and routes and forwards the result. For example, `/api/auth/mfa/%64isable` is the gateway's own `/api/auth/mfa/disable`, with its MFA attempt limits, and is not proxied. Other escapes stay as they are.
- It refuses a path that holds an encoded slash (`%2F`) with 400, because the bridge would read it as a `/`.
- It refuses with 400 `{"detail": "Invalid path"}` a path that holds a control character, encoded or not: any byte below 0x20 (`%00`, `%09`, `%0A`, `%0D`, ...) or 0x7F (`%7F`). The bridge decodes `%0A` to a line feed, and its route patterns end in `$`, which in Python also matches just before a final line feed. So `/api/detections/batch%0A` would miss the gateway's own route and be served by the bridge's copy of `/api/detections/batch`, without the gateway's checks. The proxy checks this again before it forwards a request.
- It refuses with 400 `{"detail": "Invalid path"}`, after that decoding, a path that holds a backslash (`\`), a `.` or `..` segment (also when written `%2E`), or an empty segment other than a trailing slash (`//`). The URL parser the proxy uses reads `\` as `/` in http(s) URLs and removes or resolves dot segments, so the bridge would otherwise get a different path than the one the gateway routed and checked. Browsers and the edge agents never send such paths. As a second check, the proxy forwards a request only when the path of the URL it sends is still the routed path, and never when that URL path is `/api/internal`.
- It answers 404 to `/api/internal` and everything below it, in any letter case and however it is encoded, and never proxies it. That is the bridge's gateway-only API, authenticated by the proxy secret the gateway adds to proxied requests.

### Proxied requests

What the catch-all proxy forwards to the bridge, and what it returns:

- It forwards `GET`, `HEAD`, `POST`, `PUT`, `PATCH` and `DELETE`. `OPTIONS` never reaches it: the gateway's CORS layer answers every `OPTIONS` request itself, with or without an `Origin`. Any other method (`TRACE`, `CONNECT`, extension methods) gets 405 with `Allow: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS` before the body is read. Older gateways forwarded such methods as `GET`.
- The gateway checks how a request is framed (RFC 9112 §6.1) before anything else can answer it: before CORS, the body limit, the path checks, authentication, a native route or the proxy. A request with `Content-Length` and then `Transfer-Encoding` gets 400. hyper, the gateway's HTTP library, drops a `Content-Length` that comes after `Transfer-Encoding` and reads that request by its chunked body. The gateway closes the connection after every HTTP/1.1 request that carries `Transfer-Encoding`, whatever the response. So a front proxy that framed such a request by its `Content-Length` cannot have the rest read as another request. Browsers and the edge agents send `Content-Length` and keep their connections. hyper itself refuses conflicting `Content-Length` values. The proxy never forwards the client's `Content-Length`: the bridge gets the body the gateway read, framed by its real length (`Content-Length: 0` for an empty `POST`, `PUT` or `PATCH`).
- A header sent more than once is forwarded with every value, in order, in both directions; `Set-Cookie` fields are never merged. A backend `Set-Cookie` for `session_token` or `bridge_token` (its name read as a browser reads it, without the whitespace around it) is dropped and logged at WARN with the request path: only the gateway issues session cookies, so no proxied route can plant or end a session in the browser. The one exception is `session_token` from the SSO routes, `/api/oidc` and the paths below it (the path as sent, case-sensitive, not percent-decoded): the bridge mounts the `sigrift-sentinel` add-on's OIDC router there when it is installed, the gateway does not shadow it, and its callback can hand the browser the SSO session only as a cookie. The community bridge serves nothing under `/api/oidc`. `bridge_token` is never relayed. Other cookies, `csrf_token` among them, are relayed. The client's Cookie fields (HTTP/2 may split them) reach the bridge as one field, without `session_token` and `bridge_token`: the verified session is sent as `Authorization`. A cookie is matched by its name as the bridge reads it, without the whitespace around it, so `session_token =<token>` is dropped too (a field that is not visible ASCII is dropped whole). Older gateways dropped only a cookie that started with `session_token=`, so the bridge, which trims the name, got and accepted `session_token =<token>` from any client IP.
- The client's `Authorization` and `X-Session-Token` headers, like its `session_token` cookie, are never forwarded. The bridge gets a session token only for the session the gateway verified, as `Authorization: Bearer <token>`, whichever header or cookie carried it. The bridge resolves a session token it gets by itself, but not with every check the gateway made: the shipped compose file turns its IP binding off (`BRIDGE_SESSION_BINDING=none`). So a session the gateway refused, such as one bound to another client IP, is not passed on, and the request is proxied as an anonymous one. Older gateways forwarded these headers whenever they had not verified a session, and the bridge then accepted the token without the gateway's binding check. `X-API-Key` is still forwarded: the bridge checks the key against the same `keys.json`.
- Hop-by-hop headers are not forwarded, nor the headers a `Connection` field names (RFC 9110 §7.6.1), in either direction. The gateway sets its own headers after that filter, so a client that names them only drops its own copies.
- The forwarding headers are the gateway's own, never the client's: a client's `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `X-Forwarded-Prefix`, `Forwarded` and `X-Real-IP` are dropped, also on HTTP/2 requests, which have no `Host` header. The bridge gets:
  - `X-Forwarded-For`: the client IP (see [Client IP and trusted proxies](#client-ip-and-trusted-proxies)).
  - `Host` and `X-Forwarded-Host`: the authority the client addressed. That is the request target's authority (HTTP/2's `:authority`, or an absolute-form HTTP/1.1 target), else the `Host` header. So the bridge's links and redirects name the gateway, not `UC_PYTHON_URL`.
  - `X-Forwarded-Proto`: the scheme the client used. When the direct peer is in `UC_TRUSTED_PROXIES` and its `X-Forwarded-Proto` is `http` or `https` (for a list, the rightmost entry), it is that value, on either listener. A load balancer that takes plain http from its clients and re-encrypts to the gateway's TLS listener should say `http`. Otherwise it is the listener's scheme, whatever the request says: `https` on the TLS listener (`UC_TLS_CERT` / `UC_TLS_KEY`), `http` on the plaintext one. The bridge builds its URLs with this header, and rotates an API key only when it says `https`.

  The WebSocket proxy sends the same `X-Forwarded-Host` and `X-Forwarded-Proto`.
- The bridge's internal address (`UC_PYTHON_URL`) is kept from the client. In an HTML response, `UC_PYTHON_URL` is removed where it is followed by `/`, `?`, `#` or the end of the URL, so the links become relative to the gateway; it is not removed where a longer host, port or path segment follows. A compressed body (`Content-Encoding` other than gzip, which the proxy decodes) or a byte range (206) is not rewritten. A rewritten body is sent with its own length, and a strong `ETag` is marked weak. A `HEAD` for an HTML page that is not compressed is sent without `Content-Length` (the bridge's is the length before the rewrite) and with the weak `ETag`. A `304` to a client that revalidates with the weak `ETag` carries the weak one too. A `Location` or `Content-Location` on the same origin as `UC_PYTHON_URL` (scheme, host, port) and below its path is sent as the gateway path it maps to, with its query and fragment, unless that path would start with `//`, which a browser reads as another host. Every other `Location` is passed on unchanged.

### Security headers

Every response, proxied or the gateway's own (errors included), carries the gateway's `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` and `Content-Security-Policy`, and `Strict-Transport-Security` when HSTS is on and the listener is TLS. A backend's copy of any of them is replaced, never merged. The policy (`middleware/security.rs`):

```
default-src 'self'; script-src 'self'; object-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://*.tile.openstreetmap.org; connect-src 'self' wss: ws:; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
```

Scripts load only from the gateway's origin: an inline `<script>` block, an event-handler attribute (`onclick=`) or a `javascript:` URL is refused, so a page's behaviour lives in files under `src/sigrift/bridge/static/` and is bound with `addEventListener`. Styles still allow `'unsafe-inline'`. A bridge run without a gateway sends the same policy; `testdata/security_headers_parity.json` pins both. `UC_CSP_MODE` (`--csp-mode`) is `strict` by default; the compose stack passes it from `.env`. `report-only` sends the policy as `Content-Security-Policy-Report-Only`: the browser runs what it would refuse and logs a violation to its console (the gateway has no reporting endpoint). `disabled` sends no policy. Use either only for a diagnosis. Older gateways sent `script-src 'self' 'unsafe-inline' 'unsafe-hashes'` and no `object-src`. Upgrade the gateway and the bridge together: in front of an older bridge this gateway refuses that bridge's inline handlers (its documentation menu and Export PNG button).

## Database Compatibility

The gateway shares the SigRift bridge's SQLite database in WAL mode. The Python app owns the schema and runs its migrations (`schema_version`); the gateway never migrates the bridge's tables. At startup it:

1. Refuses to start when `schema_version` holds a migration newer than the newest bridge migration this gateway was built with (`NEWEST_KNOWN_BRIDGE_MIGRATION` in `crates/sigrift-gateway-core/src/db/schema.rs`). It exits 1 with an error starting `schema: Database schema has migrations [...] newer than this gateway build` that names them, before step 3 changes anything. The bridge refuses such a database too. Versions at or below the newest known one are accepted, including the gaps in the bridge's list (39, 44). A database without `schema_version` is fresh: the gateway may start before the bridge has created its tables, and goes on. A `schema_version` that cannot be read (damaged, locked, an unexpected table shape) also refuses.
2. Logs a warning naming the bridge tables it needs that do not exist yet (the bridge creates them).
3. Adds what it manages itself, when missing: the `scope` column of `sessions`, and the `password_history`, `nodes` and `pending_commands` tables.

When its wait for the bridge ends (see [Startup](#startup)), the gateway runs the check of step 1 again, before it listens: the bridge migrates the database before it answers, so a gateway started first next to a newer bridge refuses there. That is the last check. It runs also when the wait gave up after 60 s, and a migration the bridge commits after it (a bridge slower than that to start, or one upgraded on its own while the gateway runs) is refused only at the gateway's next start.

So upgrade and roll back the gateway and the bridge together (`src/sigrift/bridge/UPGRADE.md`). Gateways from before this check do not refuse a newer database; do not start one on it.

A new bridge migration needs `NEWEST_KNOWN_BRIDGE_MIGRATION` set to it, after checking the gateway still works with the new schema: the gateway's `newest_known_bridge_migration_matches_the_bridge` test and the bridge's `tests/bridge/test_gateway_schema_guard_parity.py` fail until it is.

Tables used:

- `detections` — INSERT + SELECT (for FHSS/correlation lookback)
- `rf_anomalies` — UPSERT with dedup key (`signal_class|freq_100kHz_bucket`)
- `fhss_events` — INSERT

## Auth

Reads API keys from the same `keys.json` that the SigRift bridge manages, and reloads it whenever the file changes, so keys revoked or added by the bridge take effect on the next request (a reload that fails, e.g. a truncated file, keeps the previous key set). Keys past their `expires_at` are rejected. The presented key is looked up by its `lookup_hash` (SHA-256) and verified with PBKDF2-HMAC-SHA256 (600k iterations, on the blocking thread pool) against that one entry only. While every entry has a `lookup_hash`, unknown keys are rejected without running PBKDF2.

Older entries without a `lookup_hash` ("legacy" entries, listed by `key_id` in a startup warning) are still accepted. As on the bridge, a key that matches no `lookup_hash` is checked against every usable legacy entry, which costs one PBKDF2 per legacy entry. To bound that cost:

- at most 2 such scans run at once;
- at most 8 more wait for a slot;
- any further unknown key is rejected immediately, without PBKDF2.

Under a flood of unknown keys, legacy keys can be refused on gateway-native routes, but other gateway work keeps running. Using a legacy key once on a bridge route records its `lookup_hash`, which removes this cost; you can also rotate the key.

All API-key PBKDF2 work together runs on at most 4 blocking threads. A request that disconnects mid-check still holds its slot until its PBKDF2 finishes. Results are cached by the verification itself, so a disconnected request still saves the work it paid for: successes for 60 s, failures until the next reload. Each cache holds up to 1024 keys and is emptied when full. Every reload clears both caches.

Role hierarchy: SENSOR(0) < NODE(1) < VIEWER(2) < ANALYST(3) < ADMIN(4) < KEYMASTER(5).

If a description in `keys.json` holds a lone UTF-16 surrogate (Python writes it as `"\ud800"`, which strict JSON parsers reject), the gateway reads it as U+FFFD and logs the entry's `key_id`. The rest of the file still loads.

### Role ceilings

A caller can create an API key or a user, or give one a role, only up to its own role. Only a KEYMASTER can assign KEYMASTER. A caller can change, rotate, revoke, disable or reset the password of a key or user only if it could have granted that principal's current role. So an ADMIN cannot take over a KEYMASTER account. The `master` key cannot be revoked or have its role changed through `/api/admin/keys`. Only the master key itself or a KEYMASTER can rotate it. A refused request gets a 403. The gateway enforces these rules for users and MFA administration (its native routes); for API keys the bridge enforces them (see below).

### API key management

`/api/admin/keys*` (list, create, revoke, change role, rotate) is **not** a gateway route: the gateway proxies it to the bridge, which is the only writer of `keys.json` — the file both the gateway and the bridge authenticate against (the gateway picks up every change on its next request; see above).

Older gateways served these routes themselves and stored keys in an `api_keys` table in detections.db that nothing authenticates against: keys created from the dashboard never worked, and the dashboard could neither list nor revoke, rotate or re-role the real keys. If that table still has rows, the gateway logs a warning at start-up with their key ids. Re-create any of those keys you still need, and check the key list for keys you meant to revoke, rotate or re-role through the old API. The table itself is left untouched.

### Client IP and trusted proxies

`UC_TRUSTED_PROXIES` (default `127.0.0.1,::1`) lists the IPs and CIDR networks (IPv4 or IPv6) of reverse proxies in front of the gateway. Entries that cannot be parsed are logged and ignored. The client IP is used for the per-IP login rate limit, audit records and IP session binding. It is resolved as follows:

- If the direct peer is not a trusted proxy, the client IP is the peer address, and `X-Forwarded-For` is ignored.
- If the direct peer is a trusted proxy, the gateway reads `X-Forwarded-For` from right to left, skips trusted proxies, and takes the first address that is not trusted. A client cannot choose its own address by sending the header, because a proxy appends to it.
- If an entry in the header is not an IP address, the gateway uses the last trusted hop.
- If the peer address is unknown, the client IP is `unknown`. The header is never consulted in that case.

Behind a trusted proxy, the client IP is now the address the proxy saw, not the leftmost header entry. Sessions bound to the old value fail the IP binding check once, and those users log in again.

A trusted proxy also vouches for the scheme the client used, through its `X-Forwarded-Proto` (see [Proxied requests](#proxied-requests)). Behind a TLS-terminating reverse proxy, list its address here and have it set `X-Forwarded-Proto` (nginx: `proxy_set_header X-Forwarded-Proto $scheme;`).

The HTTP and WebSocket proxies send this client IP to the bridge as `X-Forwarded-For` (replacing any header the client sent). It is in canonical form: an IPv4 client of a dual-stack listener is `198.51.100.7`, not `::ffff:198.51.100.7`. That is the value gateway sessions are bound to, so the bridge's IP binding check compares the same address.

### Login rate limit

Each client IP (resolved as above) gets `UC_RATE_LIMIT_MAX` login attempts (default 5) within any `UC_RATE_LIMIT_WINDOW` seconds (default 60), as with the bridge's login. Further attempts get 429 with `Retry-After: 60` before the password is checked. A refused attempt is not counted, so the client can try again as soon as one of its counted attempts is older than the window. Checking the limit and counting the attempt are one atomic statement, so parallel attempts cannot exceed the limit. The attempts are kept in the bridge-owned `rate_limit_login` table; if it cannot be read or written, the login gets 503.

`UC_RATE_LIMIT_MAX` and `UC_RATE_LIMIT_WINDOW` (and `rate_limit_max` and `rate_limit_window_secs` in `PUT /api/admin/settings/security`) are at least 1. A count of 0 would refuse every login, administrators' included, and a window of 0 would count no attempt, so no limit: 0 stops the gateway from starting, and the settings API refuses it, or a window below 1, with 400. Older gateways accepted 0.

The limit holds over the whole window only while `UC_RATE_LIMIT_WINDOW` is 60 or less. The bridge prunes the table with its own fixed 60-second window: its periodic cleanup (every `BRIDGE_CLEANUP_INTERVAL` seconds, default 1800) deletes the attempts older than 60 seconds. With a longer window, each of these cleanups clears attempts the gateway still counts, and a limited client gets its `UC_RATE_LIMIT_MAX` attempts again. With `UC_RATE_LIMIT_WINDOW=3600` and the default interval, for example, a client can make about twice `UC_RATE_LIMIT_MAX` attempts an hour.

### Account lockout

After `UC_LOCKOUT_MAX` failed password logins (default 10) for one username within `UC_LOCKOUT_WINDOW` seconds (default 1800), further logins for it get 429 with `Retry-After: 1800` before the password is checked, until the oldest failure is older than the window. Each attempt is counted before its password check, unknown usernames included; a successful login clears the count. The failures are kept in the bridge-owned `account_lockout` table, shared with the bridge's own login; if it cannot be read or written, the login gets 503.

The current password of `POST /api/auth/change-password` counts toward the same lockout, so a stolen session gets no more password guesses than a login does. Each change that gets as far as checking the current password is counted before the check. A wrong current password gets 401 `Current password is incorrect` and an `auth_failure` audit entry. A right one clears the count, as a successful login does. A locked account gets the login's 429 (`Retry-After: 1800`, `Account temporarily locked due to too many failed attempts.`) on a password change too, even with the right current password, and nothing is checked or counted. Logins and password changes share the one budget: failed changes lock the logins of that account, and failed logins lock its password changes. A request refused before the current password is checked (a weak new password, a malformed body) is not counted. If the lockout table cannot be read or written, the change gets 503. A user whose account is locked cannot change their password until the window has passed, or until an admin resets it (`POST /api/admin/users/{username}/reset-password`): a reset also clears that account's lockout failures, so its user can log in with the new password at once. (The reset also ends the user's sessions. If the failures cannot be cleared, the reset still succeeds and the gateway logs a warning.) Older gateways checked the current password with no limit, and a reset left the failures counted.

`UC_LOCKOUT_MAX` and `UC_LOCKOUT_WINDOW` (and `lockout_max` and `lockout_window_secs` in `PUT /api/admin/settings/security`) are at least 1, as for the rate limit above: a count of 0 would lock every account, administrators' included, and a window of 0 would count no failure, so no lockout. 0 stops the gateway from starting, and the settings API refuses it, or a window below 1, with 400. Older gateways accepted 0.

`UC_LOCKOUT_WINDOW` (and `lockout_window_secs` in `PUT /api/admin/settings/security`) is at most 86400 (24 hours). The bridge's periodic cleanup keeps lockout failures for 24 hours, and the gateway prunes them to its own window every 5 minutes, so any window up to 24 hours holds in full. A longer `UC_LOCKOUT_WINDOW` stops the gateway from starting, and the settings API refuses a longer `lockout_window_secs` with 400. (Older bridges deleted the failures after 30 minutes, so a longer window unlocked accounts at the bridge's next cleanup: upgrade both together.) The same window applies to the MFA attempt limit below.

### Sessions and cookies

The password login (`/api/auth/login`) and the MFA login (`/api/auth/mfa/verify`) create sessions the same way:

- The session is bound to the client IP and User-Agent.
- The session token goes only into the HttpOnly `session_token` cookie (and the JSON response for API clients).
- A `csrf_token` double-submit cookie is set.
- The JS-readable `bridge_token` cookie that older gateways set is no longer issued, and a stale copy is expired on login and logout.
- The body must be declared JSON: exactly one `Content-Type` whose media type is `application/json` (any letter case, parameters allowed). Anything else, a missing one included, gets 415 `{"detail": "Content-Type must be application/json"}` before anything is checked or counted. Both steps are exempt from the CSRF token, and an attacker page can post a cross-site `text/plain` or form-encoded body without a CORS preflight, so this is what stops it signing a browser into another account (login CSRF). Older gateways read any body as JSON.

Logout (`/api/auth/logout`) expires `session_token`, `csrf_token` and `bridge_token` when it leaves the caller signed out: on 200 (the session ended), and on 401 (no session token, or one that names no session) when the request carried one of those cookies, so a stale HttpOnly cookie, which the page's JavaScript cannot clear, does not outlive its session. A 401 for a request that carried none of them sets no cookie. Logout is exempt from the CSRF token, and a cross-site form post carries none of these `SameSite=Lax` cookies; browsers apply the `Set-Cookie` of a top-level navigation's response whatever its `SameSite`, so expiring them there would let any site sign a visitor's dashboard out. A 500 or 503 sets no cookie: the session may still exist, and a retry needs the cookie to end it.

`BRIDGE_CSRF` in production: the gateway refuses to start when `BRIDGE_ENV` is `production` or `prod`, or unset (the gateway's default is production), unless `BRIDGE_CSRF` is unset, empty or `enabled` (trimmed, any letter case). The bridge refuses the same values, but only when `BRIDGE_ENV` or `BRIDGE_MODE` is `production` or `prod`: it counts an unset `BRIDGE_ENV` as development and only warns. Outside production both start with a warning, and they read the value differently. The gateway turns its double-submit check off only for exactly `disabled`; any other value leaves it at the `BRIDGE_ENV` default (on, except with `development`, `dev` or `test`), and its warning says so. The bridge turns its check off for every value other than `enabled`.

A session can also be created with a restricted scope. The scope is part of the session row from the moment it is created. If the gateway cannot work out the scope, the login fails instead of creating a full session.

- `password_change_only`: the user row has `must_change_password` set. Only `/api/auth/change-password`, `/api/auth/logout` and `/api/auth/me` are allowed. Every other route, gateway-native or proxied, gets 403 `{"detail":"password change required"}`. Changing the password clears the flag and lifts the restriction on that session.
- `mfa_setup_only`: the tenant requires MFA and the user has not set it up. Only `/api/auth/mfa/*` and logout are allowed.
- Any other non-empty scope fails closed: only logout and `/api/auth/me` are allowed.

The two login steps (`/api/auth/login` and `/api/auth/mfa/verify`), `/health` and `/api/version` ignore any session the request carries, so a browser that still holds a restricted session cookie can still log in.

A request carries its session in `Authorization: Bearer <token>`, `X-Session-Token` or the `session_token` cookie, read in that order; one that carries only whitespace is skipped. The `Bearer` scheme is matched in any letter case (`bearer`, `BEARER`; RFC 9110 §11.1), as the bridge matches it. One space must follow the scheme, and the token is what comes after it, without surrounding whitespace. An API key in `Authorization: Bearer`, logout and the WebSocket origin rule read the header the same way. A cookie's name is what comes before its first `=`, without surrounding whitespace, as the bridge (Starlette) reads it, so `session_token =<token>` is the session cookie; its value is trimmed too. The shared table `crates/sigrift-gateway-core/testdata/session_token_parity.json` pins the gateway and the bridge to the same reading. It leaves out the two cases they read differently: of several `session_token` cookies the gateway takes the first one with a value and the bridge the last one, and the bridge unquotes a quoted value. Behind the gateway neither matters, as the proxy forwards no `session_token` cookie. Older gateways read only `Bearer` and only `session_token=`. A `bearer <token>` or `session_token =<token>` session got 401 on the gateway's own routes and was proxied with the token still in it, so the bridge accepted it without the gateway's IP binding check (see [Proxied requests](#proxied-requests)). Older bridges stopped at an empty `Authorization: Bearer` or `X-Session-Token` instead of reading the next source.

With a restricted session, a page or asset request (`GET` or `HEAD` outside `/api` and `/ws`, such as `/`, `/login` or `/static/login.js`) is served as an anonymous request instead of getting 403. The restricted session is not passed on to the bridge. So after a reload or in a new tab, the browser can still load the login page, and logging in again shows the password-change (or MFA setup) form.

A session is refused and deleted when it is past its absolute expiry or its idle timeout, or when its `expires_at`, or a `last_active` that is not NULL, cannot be read as a timestamp. A NULL `last_active` means no idle information, so only the absolute expiry applies. Timestamps are read in one layout: `YYYY-MM-DD`, `T` or a space, `HH:MM:SS`, an optional fraction, and an optional `Z` or `±HH:MM` offset. Without an offset the time is UTC. This is what the gateway, the bridge and SQLite's `datetime()` write.

The bridge applies the same rule in the same order when it resolves a session itself (a bridge-only deployment, or direct access to its port).

The session timeouts come from `BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS` (default 24) and `BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES` (default 30), or the `--session-absolute-timeout-hours` and `--session-idle-timeout-minutes` options. The bridge reads the same variables, so give both services the same values. The gateway reads them as the bridge does:

- Surrounding whitespace is ignored, and Python's `int()` syntax is accepted: `+3`, `007` and `1_000` are 3, 7 and 1000.
- An empty value gives the default.
- A value below 1, or one that is not an integer (`abc`, `1.5`), gives the default, with a warning in the gateway's log. Older gateways used a value below 1 as it was, which ended every session at once, and refused to start on a value that was not a plain integer.
- A value of more than 4300 digits (leading zeros count, a sign and underscores do not) gives the default, with a warning: Python's `int()` refuses it (`sys.get_int_max_str_digits()`). The gateway does not follow a limit changed with `PYTHONINTMAXSTRDIGITS` or `-X int_max_str_digits` on the bridge.
- An absolute timeout above 10000000 hours (about 1141 years) gives the default, with a warning. The bridge applies the same ceiling the same way.
- Unlike the bridge, the gateway reads only the digits 0-9. A value written with other digits (`１５`) stops it from starting, with a message that names the variable: the bridge reads `１５` as 15, and the gateway's default (30 minutes) would keep sessions the bridge has ended. So does a value with another number character where a digit goes (`²`, `⅕`), which the bridge reads as its default, since telling the two apart needs the Unicode tables of the bridge's Python version.

`UC_MAX_SESSIONS_PER_USER` (default 50, 0 = unlimited) is enforced at login: the user's oldest sessions beyond it are deleted. `DELETE /api/admin/sessions/{prefix}` needs 8–64 hex characters that match exactly one session.

The gateway drops these client-supplied headers on every route before any handler, proxy or WebSocket sees them: `x-rust-proxy`, `x-auth-*` and `x-license-*`. Only the gateway sets them.

An unknown or disabled username costs the same PBKDF2 as a wrong password, so response timing does not reveal which usernames exist.

A login or password change commits only while the password it verified is still the stored one. A password reset (`POST /api/admin/users/{username}/reset-password`) or change committed while one runs, during its PBKDF2 or its second-factor check, wins: the login gets 401 and no session, and the change gets 401 and changes nothing. A change also needs its own session to still exist and the account to be enabled when it commits.

### MFA

The token from the password step is single-use: of several parallel requests with one token, only one is accepted. A TOTP code is also single-use within the 90-second replay window, and so is each backup code. A password change or reset ends the user's pending MFA logins: their tokens no longer complete a login.

Every second-factor check is counted per user: login verification, `verify-setup`, `disable` and `regenerate-backup-codes`. Each check is reserved before it runs. After `UC_LOCKOUT_MAX` failed checks within `UC_LOCKOUT_WINDOW` seconds, further checks for that user get 429 with `Retry-After`, even with a correct code, until the window has passed. A successful check resets the count. The count lives in the gateway-owned `mfa_attempts` table.

### Client certificates (mTLS)

`UC_CA_REGISTRY_PATH` points at the bridge CA's `registry.json`. The gateway looks up a presented certificate by its serial number. The entry must also match the certificate's SHA-256 fingerprint (`fingerprint_sha256`, which the bridge CA always records) and its identity. Revoking a certificate marks its serial, so a revoked certificate is refused even while the same identity holds a newer valid one. The registry acts as the revocation list. A certificate that is not in the registry is refused, even if it chains to the CA. The gateway reloads the file on the next lookup after it changes (a new mtime, size or inode), and reads again a version it read within 2 seconds of its mtime, since a write in the same timestamp tick can keep the mtime.

An entry the bridge could not have written authorises no certificate: its `identity` is missing, empty or not a string, its `role` is missing or is not exactly one of the roles the bridge CA issues (`sensor`, `node`, `viewer`, `analyst`, `admin`, in lower case), its `revoked` is present but not `true`, `false` or `null`, its `fingerprint_sha256` is present but not 64 hex digits (upper case, `:` separators and surrounding spaces are accepted), its `not_after` is present but not an RFC 3339 timestamp with an offset, or another key in the file names the same serial (`66` and `066`, or one key twice). A role is never guessed: `keymaster` (in any letter case) is refused, because KEYMASTER is never delegated to a certificate, and so are an unknown role, another spelling of a role (`ADMIN`, or `admin` with spaces around it) and a role that is not a string. None of them falls back to `sensor` or any other role. The gateway logs the serial and the field at WARN when it loads the registry. The admin UI does not check these shapes and can list such an entry as valid (it shows a missing role as `node`), so look in the gateway log when a registered certificate is refused.

A client certificate is an ambient credential, as the session cookie is: a browser that holds one presents it on any TLS handshake to the gateway, whichever page started the request, and SameSite does not apply to it. So a `POST`, `PUT`, `PATCH` or `DELETE` that a certificate authenticates (no API key on the request) is refused with 403 `{"detail": "Cross-origin request refused"}` when the browser's `Origin` is a different origin. The rule is the one WebSocket handshakes get (see [WebSockets](#websockets)): this origin is `https` at the `Host`, or what a trusted proxy's `X-Forwarded-Proto` and `X-Forwarded-Host` say, an origin listed in `UC_CORS_ORIGINS` is allowed, and `null` is refused. The check holds whether CSRF protection is on or off, on gateway-native and proxied routes alike, and the refusal is logged at WARN with the origin the gateway expected. It does not apply to a request without an `Origin` (an agent, not a browser), to `GET`, `HEAD` and `OPTIONS`, to the CSRF-exempt paths (`/api/auth/login`, `/api/auth/logout`, `/api/auth/mfa/verify`, `/api/version`, `/api/health`, `/health`), or to an API key. A certificate never needs the CSRF token.
