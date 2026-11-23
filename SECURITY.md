# SigRift Security

## Reporting a Vulnerability

We take security seriously and appreciate reports from the community.

**How to report — GitHub private vulnerability reporting:**
Open a private report at
<https://github.com/SigRift/SigRift/security/advisories/new>. Only you and
the maintainers can see it, and it stays private until a fix is ready.
This is the only reporting channel; the project has no security mailbox.

**Please include:**
- Affected component (Rust gateway, Python backend, edge agent, provider
  plugin) and version or commit SHA.
- A clear description of the issue and its impact.
- Reproduction steps, proof-of-concept, or a minimal exploit.
- Your assessment of severity and any known mitigations.
- Whether you wish to be credited in the advisory.

**What to expect:**
- Acknowledgement within **3 business days**.
- A triage decision and target remediation window within **10 business days**.
- Coordinated disclosure: we will agree an embargo date with you, ship a
  fix, publish a GitHub Security Advisory with a CVE where appropriate,
  and credit you unless you request otherwise.

**Please do not:**
- File a public GitHub issue for a suspected vulnerability.
- Post details to social media, mailing lists, or chat before coordinated
  disclosure.
- Test against infrastructure or devices you do not own or are not
  authorized to assess — acceptable-use terms in [LEGAL.md](LEGAL.md)
  apply to security research as well.

## Scope

In scope: the SigRift Rust gateway, Python backend, edge agents, first-party
provider plugins in this repository, default deployment configuration, and
the sample installation scripts.

Out of scope: third-party dependencies (please report upstream), operator
misconfiguration, social-engineering attacks against maintainers,
denial-of-service from RF layer or volumetric network attacks, and
issues in forks or downstream distributions we do not maintain.

## Safe Harbor

Good-faith security research consistent with this policy, performed
against your own deployments or with explicit written authorization, will
not be pursued by the SigRift project. This does not waive third-party
rights; you remain responsible for compliance with applicable law and
the acceptable-use terms in [LEGAL.md](LEGAL.md).

---

## Architecture Overview

SigRift uses a two-tier architecture: a **Rust gateway** handles authentication,
TLS termination, and security-critical operations, proxying to a **Python backend**
for application logic. The split keeps authentication and TLS out of the Python
layer, but it is not an isolation boundary for credentials: the bridge shares the
data volume that holds password hashes and TOTP secrets, and it holds
`BRIDGE_MFA_KEY`, so compromising the Python layer exposes them (see
[Data volume isolation](#data-volume-isolation-docker-compose-default)).

## Architecture

```
Internet → [Rust Gateway :8444 (TLS)] → [Python Backend :8001 (localhost)]
               ├── Auth (login, sessions, API keys)
               ├── MFA (TOTP setup/verify, backup codes)
               ├── CSRF validation
               ├── Rate limiting (login, account lockout)
               ├── Security headers (CSP, HSTS, X-Frame-Options)
               ├── RF detection ingest + scoring
               └── Proxy → Python for application routes
```

### What Rust Handles (security boundary)
- TLS termination (rustls, ring crypto)
- Session creation/validation (PBKDF2-SHA256, 600K iterations)
- API key validation (constant-time comparison)
- MFA/TOTP (Fernet-encrypted secrets, RFC 6238)
- CSRF double-submit cookie validation (sessions), and the `Origin` check
  for mutating requests authenticated by a client certificate
- Login rate limiting (5/min per IP, 10 failures → account lockout)
- Security headers (CSP, HSTS, Cache-Control)
- RF detection batch ingest + anomaly scoring. After a batch is stored the
  gateway hands the accepted detections to the bridge
  (`/api/internal/ingest-hook`, authenticated by `X-Rust-Proxy` only), which
  runs the alert rules, watch bands, webhooks and decode queueing for them.
  This happens **asynchronously**: the ingest response's `alerts_created`
  is always `0`, alerts appear a moment later, and the gateway's
  `GET /health` counts hand-overs that were dropped or failed
  (`post_ingest_hooks`). The bridge runs them once per detection id
  (claimed in `detections.db`, so a re-sent hook fires nothing twice)
  and delivers the resulting webhooks in the background. On SIGTERM the
  gateway gives queued hand-overs 5 s, then spools the rest (mode 0600)
  to `gateway-post-ingest-hooks.spool` in its data directory and sends
  them first at the next start. Only a gateway stop spools: while the
  gateway runs, a hand-over the bridge does not take in 3 attempts (it
  is down or restarting) is dropped and counted in `failed_*`, so no
  alerts or webhooks fire for those detections. Without a usable
  `UC_PROXY_SECRET` (development only) the hand-overs are disabled and
  counted in `hooks_disabled`. The gateway answers `/api/internal/*`
  from outside with 404 and never proxies it.

### What Python Handles (behind Rust proxy)
- Application routers (46 router files)
- Storage backends (SQLite via DetectionStore)
- Alert engine, correlation, anomaly pipeline
- Dashboard HTML/JS serving
- WebSocket feeds

### Trust Headers (Rust → Python)
When proxying requests, Rust injects these headers:

| Header | Purpose | Example |
|--------|---------|---------|
| `X-Rust-Proxy` | Proxy secret (proves request came through Rust) | `<UC_PROXY_SECRET>` |
| `X-Auth-User` | Authenticated username | `admin` |
| `X-Auth-Role` | User's RBAC role | `admin` |
| `Authorization` | The session token the gateway verified (Bearer), for Python validation | `Bearer <token>` |

Python trusts these headers **only** when `X-Rust-Proxy` matches `UC_PROXY_SECRET`.
The client's own `Authorization` and `X-Session-Token` headers and its
`session_token` cookie (matched by its name as the bridge reads it, so
`session_token =<token>` too) are never forwarded: a session token the
gateway refused (for example one bound to another client IP) does not
reach the bridge.

## Required Environment Variables

### Production (`BRIDGE_ENV=production`)

All of these are **required** — the application refuses to start without them.
The Rust gateway needs `BRIDGE_AUDIT_KEY`, `BRIDGE_MFA_KEY` and
`UC_PROXY_SECRET` as well, with the same values as the bridge (the shipped
`docker-compose.yml` passes them to both); in production it refuses to start
without `BRIDGE_AUDIT_KEY` or with an invalid `BRIDGE_MFA_KEY`. It does **not**
get `BRIDGE_MASTER_KEY`: the master admin API key stays in the bridge, out of
the internet-facing container.

| Variable | Purpose | Generate With |
|----------|---------|---------------|
| `BRIDGE_MFA_KEY` | Fernet encryption key for TOTP secrets. Valid means, after trimming whitespace: exactly 44 characters — 43 from `[A-Za-z0-9-_+/]`, then `=` — decoding to 32 bytes (bridge, gateway and installers apply the same rule; neither service encrypts with any other key). A 43-character `token_urlsafe` value is **not** valid: append `=` to such a key (same bytes, existing encrypted TOTP secrets stay readable) rather than replacing it | `python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"` (equivalent to `Fernet.generate_key()`) |
| `BRIDGE_AUDIT_KEY` | HMAC key for tamper-evident audit chain (bridge and gateway) | `python3 -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `BRIDGE_MASTER_KEY` | Master API key the bridge registers on first boot. Bridge only. The bridge refuses to start in production without it (`src/sigrift/bridge/app.py`: `"BRIDGE_MASTER_KEY env var is required when BRIDGE_ENV=production"`). | `python3 -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `UC_PROXY_SECRET` | Shared secret between Rust and Python | `python3 -c "import secrets; print(secrets.token_urlsafe(32))"` |

### Recommended

| Variable | Default | Purpose |
|----------|---------|---------|
| `UC_TLS_CERT` | (none) | TLS certificate path |
| `UC_TLS_KEY` | (none) | TLS private key path |
| `BRIDGE_SESSION_BINDING` | `none`¹ | Session binding mode: `strict`, `ip`, `warn`, `none` |

### Development/Test

In `BRIDGE_ENV=test` or `BRIDGE_ENV=development`:
- `BRIDGE_MFA_KEY`: optional (TOTP secrets fall back to unencrypted `b64:` storage, warns). An invalid key behaves the same way in both services — neither encrypts with it — and is fatal in production. `b64:` secrets stay readable after a valid key is set.
- `BRIDGE_AUDIT_KEY`: optional (uses weak default, warns)
- `BRIDGE_MASTER_KEY`: optional (bridge auto-generates and writes to `data/master_key.txt` chmod 0600; warns)
- `UC_PROXY_SECRET`: **required with the shipped `docker-compose.yml` in
  every mode.** The bridge runs with `BRIDGE_REQUIRE_PROXY=true` there and
  refuses every proxied request (403 `Direct access denied`) while it is
  empty, and the compose healthcheck keeps the bridge unhealthy, so the
  gateway does not start. Only a gateway and bridge run by hand without
  `BRIDGE_REQUIRE_PROXY` can leave it unset. Neither service generates a
  value: both start and log the problem, the gateway sends an empty
  `x-rust-proxy`, and the bridge does not trust the gateway's identity
  headers (client-certificate logins through the gateway are refused)
  and refuses its gateway-only API (`/api/internal/*`). The gateway
  therefore runs with node-key binding and post-ingest hooks
  **disabled** (one error at start-up): its detection ingest leaves
  unbound node keys unbound and accepts their batches for any node (as
  with `BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1`), while the bridge's own node
  routes (heartbeats, WiFi / BT ingest, node commands, IQ uploads) still
  bind such a key on first use — after which the gateway's ingest holds
  it to that node too — and no alert rules, watch-band alerts, webhooks
  or decode jobs run for the batches the gateway ingests.
- CSRF validation: disabled

## Authentication

### Password Hashing
- **Algorithm:** PBKDF2-HMAC-SHA256
- **Iterations:** 600,000
- **Salt:** 32 bytes (cryptographic random)
- **Output:** 32 bytes
- **Legacy fallback:** Salted SHA-256 (auto-upgraded on next login)

### Session Management
- Tokens: 64 hex characters (32 bytes random)
- Storage: SHA-256 hash in SQLite (raw token never stored)
- Absolute timeout: 24 hours
- Idle timeout: 30 minutes (NIST 800-63B)
- A session whose expiry or last activity cannot be read as a timestamp is
  refused and deleted, never kept without a limit
- Session binding: configurable (`strict` | `ip` | `warn` | `none`)
- Max sessions per user: 50 (oldest evicted)
- **Password change invalidates all other sessions**

#### Session binding modes

| Mode | Validates | Fail action | Use when |
|------|-----------|-------------|----------|
| `strict` | Client IP + User-Agent | Reject session | Production, single-device users, lowest hijack risk |
| `ip` | Client IP only | Reject session | Production, tolerating browser upgrades that change UA |
| `warn` | Client IP | Log warning, allow | Staging, auditing hijack-like patterns without blocking |
| `none` | — | Allow | Dev + mobile/VPN/NAT users whose IP changes; the shipping default¹ |

¹ **The shipping default is `none`** so mobile users behind NAT,
corporate VPN clients, and dual-stack IPv4/IPv6 flips don't get
spuriously logged out. Enable binding via either:

**A. Admin UI (recommended for operators)** — Dashboard → Admin → System → **Session Binding**. Pick a mode, click Save. The UI shows you whether the gateway is currently enforcing a different value (set by `BRIDGE_SESSION_BINDING` at container startup) and tells you when a restart is required to apply.

**B. Env var (for IaC / new deployments)** — Set `BRIDGE_SESSION_BINDING=ip` (or `strict`) in your `.env` or compose file before first start. The env var is what the gateway actually reads on startup.

The admin UI persists to `data/session_binding.json`; the gateway reads from env. After changing via the UI, either run `docker compose restart gateway` or update the env var and run `docker compose up -d` for the new mode to take effect.

### API Keys
- Hashing: PBKDF2-HMAC-SHA256 (same as passwords)
- Roles: SENSOR → NODE → VIEWER → ANALYST → ADMIN → KEYMASTER
- **Missing or unknown role.** A `keys.json` key stored without a role,
  or with a value that names no role (null, a number, `""`, `superuser`,
  a padded name), authenticates as VIEWER on the bridge and on the
  gateway alike: least privilege, and never a node credential. Role
  names are case-insensitive. The bridge's `master` key is always ADMIN,
  whatever `keys.json` stores for it (the bridge writes it without a
  role), and like any key it is refused once revoked, disabled or
  expired. Both services are tested against one shared table,
  `src/gateway/crates/sigrift-gateway-core/testdata/key_role_parity.json`.
- Rotation: via `/api/admin/keys/{key_id}/rotate`
- **Node binding.** A key with a `node_id` in `keys.json` (set when the
  key is created) may act only for that node, whatever its role. A NODE
  or SENSOR key without one is bound to the **first node it reports
  for** — its first heartbeat, detection batch or other node-scoped
  request, whether the bridge or the gateway's detection ingest handles
  it — and from then on gets 403 for any other node (`API key … is bound
  to node …` from the bridge, `API key is bound to a different node` from
  the gateway's ingest). The first key to claim a node keeps it: an
  unbound key reporting for a node that another key is bound to is
  refused (403; the bridge's `bind-node-key` answers 409 `node already
  has a bound key`), so a newly minted node key cannot take over a node
  that already has one; an admin binds further keys by creating them
  with that `node_id`. Use one key per node, shared by its agents. If
  the gateway cannot reach the bridge to record the binding,
  it refuses the batch (503) rather than accept it unbound.
  `BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1` (set on the bridge **and** the gateway;
  the shipped compose files pass it to both) keeps unbound node keys
  unbound, as before; both log a warning at start-up. Only NODE and
  SENSOR keys are bound automatically: an unbound VIEWER key is not a
  node credential (403 `Node endpoints require a node API key` on node
  routes, also with `BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1`), an unbound
  ANALYST key is operator tooling and may act for any node, and ADMIN
  and KEYMASTER keys are never bound. A key whose id starts with
  `node_`, `rtlsdr_`, `hackrf_`, `sensor_`, `edge_` or `sdr_` is a NODE
  key even when it is stored with a role of ANALYST or higher (`analyst`,
  `admin` or `keymaster`, in any letter case); the bridge stores such a
  key as `node` and refuses to assign it an operator role (400). A client
  certificate below ADMIN acts only for the node its identity names (its
  identity must be the node's `MLRF_NODE_ID`; certificates minted per
  agent are refused — see INSTALL.md, "Upgrading"), and
  `BRIDGE_ALLOW_UNBOUND_NODE_KEYS` does not change that.
- **Key changes are saved before they succeed.** Creating, rotating,
  re-roling, binding or revoking a key writes `keys.json` — which the
  gateway and the other bridge workers read — before the request
  succeeds. When `keys.json` cannot be written (a full disk, a read-only
  mount) the request gets 503 and is not audited as done. The change is
  undone, except a revocation or a downgrade: that stays in effect on the
  worker that took it (fail closed), is audited with
  `"pending": "not yet saved"`, and is written by the next save or by
  repeating the request (200, audited as usual). That save never undoes
  what another worker saved for the same key meanwhile: a key it revoked
  stays revoked, a credential it rotated stays rotated (the downgrade is
  applied to the new credential), and when both changed the role the
  lower one is kept. Until then the gateway
  and the other workers still accept the key with the role `keys.json`
  holds, and changing that key needs the caller to be at or above that
  role (K5). In the same situation a node key's first-use binding is
  refused (the gateway answers 503) rather than kept in memory, and the
  bridge refuses to start when it must save the initial master key,
  re-sync `BRIDGE_MASTER_KEY` or register `BRIDGE_LOCAL_NODE_KEY` (see
  TROUBLESHOOTING.md).

### MFA/TOTP (Rust-only)
- Algorithm: HMAC-SHA1 (RFC 6238)
- Period: 30 seconds, window: ±1
- Secret: 20 bytes (160 bits), Base32-encoded
- At-rest encryption: Fernet (AES-128-CBC + HMAC-SHA256)
- Backup codes: 10 codes, SHA-256 hashed, single-use
- Replay protection: per-tenant tracking
- **All MFA endpoints handled by Rust gateway — Python never accesses MFA keys**

## Transport Security

- **TLS:** rustls with ring backend (modern cipher suites only)
- **HSTS:** `max-age=31536000; includeSubDomains` (production only)
- **Cookies:** `HttpOnly`, `SameSite=Lax`, `Secure` (production only)
- **CSP:** `default-src 'self'; script-src 'self'; object-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://*.tile.openstreetmap.org; connect-src 'self' wss: ws:; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`, from the gateway on every response (it replaces the bridge's), and from a bridge run without a gateway. Scripts load only from the origin: no inline script, event-handler attribute or `javascript:` URL runs, so markup injected into a page cannot run script. Styles still allow `'unsafe-inline'`. The shared table `src/gateway/crates/sigrift-gateway-core/testdata/security_headers_parity.json` pins both services to this value, and `tests/bridge/test_csp_static_lock.py` keeps inline script out of the pages. `UC_CSP_MODE=report-only` (console reports only) or `disabled` turns it off for a diagnosis; the compose stack passes it to the gateway from `.env`.

## Data Security

- **Audit log:** HMAC-SHA256 tamper-evident chain
- **TOTP secrets:** Fernet-encrypted at rest
- **Database:** SQLite (filesystem permissions; for encryption at rest use filesystem-level encryption — SQLCipher is not yet supported end to end, see [DEPLOYMENT.md](src/sigrift/bridge/DEPLOYMENT.md#data-at-rest-encryption))
- **Backups:** Recommend encrypted filesystem (dm-crypt, LUKS)

### Data volume isolation (docker-compose default)

The default `docker-compose.yml` mounts the named volume
`bridge_data` in both the bridge and gateway containers
(`/app/src/sigrift/bridge/data` and `/app/data` respectively).
Everything under that volume is readable by whichever container has
the right UID — effectively, if you own one of the two processes you
can read the other's files.

The **bridge-owned** files stored there that matter in a gateway-compromise
scenario:
- `detections.db` (scan data, and the `users` table: password hashes and Fernet-encrypted TOTP secrets)
- `keys.json` (API key metadata; keys themselves are PBKDF2 hashed)
- `ca/ca.crt`, `ca/registry.json` (the CA certificate and issued-cert
  registry — public trust material the gateway needs for mTLS)
- `audit.key` (present only in dev mode when `BRIDGE_AUDIT_KEY` isn't set — see below)

And the **not-stored-here** bits (intentionally):
- **The CA private key** (`ca.key`) lives in a second volume,
  `bridge_secrets` (`/app/secrets`, `BRIDGE_SECRETS_DIR`), mounted on the
  bridge only. A bridge upgraded from an older version moves the key
  there on start-up (see PKI_ARCHITECTURE.md).
- **Admin password temp file.** When the bridge auto-generates an initial
  admin password (`BRIDGE_ADMIN_PASSWORD` unset + no users exist + not
  production), it writes the plaintext to `/tmp/sigrift-admin-pw` inside
  the bridge container, NOT to the shared volume. The file auto-deletes
  after 60s. Read it with `docker compose exec bridge cat /tmp/sigrift-admin-pw`.

### The bridge serves the gateway only

The bridge has no host port and sits on a compose network (`backend`)
that only the gateway shares, so the edge agents and scanners — which
parse attacker-controlled radio traffic — cannot reach it except
through the gateway's TLS, authentication and rate limits. On top of
that, compose sets `BRIDGE_REQUIRE_PROXY=true` (requests without the
gateway's `X-Rust-Proxy: <UC_PROXY_SECRET>` header are refused) and
`BRIDGE_TRUSTED_PROXIES` to the gateway's fixed address on that network,
so only the gateway's `X-Forwarded-For` is believed.

### `BRIDGE_AUDIT_KEY` in dev

If `BRIDGE_AUDIT_KEY` isn't set and you're not in production mode, the
audit HMAC machinery generates a random key on first start and persists
it to `data/audit.key` (inside the shared volume). This lets the HMAC
chain survive restarts — but it also means a gateway-container compromise
gives the attacker the audit key, and therefore the ability to forge audit
entries retroactively.

**For production deployments, always set `BRIDGE_AUDIT_KEY` to a strong
random value in `.env`.** `scripts/quickstart.sh` generates one for you
via `python3 -c 'import secrets; print(secrets.token_urlsafe(32))'`.

## Rate Limiting

| Endpoint | Limit | Lockout |
|----------|-------|---------|
| `/api/auth/login` | 5 attempts / 60s per IP | 10 failures → 30 min account lockout |
| `/api/auth/change-password` (gateway and the bridge's own route) | Session required | Wrong current passwords count toward the same account lockout; a locked account gets 429; an admin password reset clears the lockout |
| All authenticated | Token-validated | Session timeout enforced |

A password reset or change ends the user's pending MFA logins, and a
login, MFA challenge or password change that verified the old password
is refused if the reset or change commits while it runs (gateway and
bridge).

## Startup Sequence

```
1. Rust gateway starts
   ├── Verify UC_PROXY_SECRET (production: must be strong)
   ├── Verify BRIDGE_AUDIT_KEY is set + BRIDGE_MFA_KEY is a valid Fernet key (production: required)
   ├── Load TLS certificate
   ├── Create DB connection pool
   ├── Load API keys
   ├── Wait for Python backend health
   └── Start listening on :8444

2. Python backend starts
   ├── Verify BRIDGE_MFA_KEY + BRIDGE_AUDIT_KEY (production: required)
   ├── Load configuration
   ├── Initialize DetectionStore (SQLite)
   ├── Load RF baselines
   ├── Seed threat signatures (82 TSCM signatures)
   ├── Seed default alert rules
   └── Start listening on :8001 (localhost only)
```
