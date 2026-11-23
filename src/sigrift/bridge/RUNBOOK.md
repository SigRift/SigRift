# SigRift Bridge Operations Runbook

## Service Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                  SigRift Bridge Process                       │
│                                                              │
│  uvicorn (main)                                              │
│      │                                                       │
│      ├── FastAPI app (app.py)                                │
│      │   ├── Routers: auth, detections, spectrum, admin, ... │
│      │   ├── CombinedMiddleware (CORS, CSRF, metrics)        │
│      │   └── WebSocket manager                               │
│      │                                                       │
│      ├── Background Tasks                                    │
│      │   ├── WAL checkpoint (every 5 min)                    │
│      │   ├── Admin password auto-delete (60s)                │
│      │   ├── Data cleanup (retention-based)                  │
│      │   └── SecurityState cleanup                           │
│      │                                                       │
│      └── Storage Layer                                       │
│          ├── SharedContext (thread-local connections)         │
│          │   └── encryption.py (SQLCipher or plain sqlite3)  │
│          ├── DetectionStore (facade → sub-stores)            │
│          ├── AuditStore (HMAC chain)                         │
│          ├── UserStore (sessions, credentials)               │
│          └── SecurityStateStore (rate limits, lockouts)       │
│                                                              │
│  Data Directory:                                             │
│  ┌─────────────────────────────────────────┐                 │
│  │ data/                                   │                 │
│  │ ├── detections.db  (main DB, WAL mode)  │                 │
│  │ ├── detections.db-wal                   │                 │
│  │ ├── detections.db-shm                   │                 │
│  │ ├── keys.json      (API key metadata)   │                 │
│  │ ├── baselines.json (RF baselines)       │                 │
│  │ ├── master.key     (dev only)           │                 │
│  │ └── audit.key      (dev only)           │                 │
│  └─────────────────────────────────────────┘                 │
└──────────────────────────────────────────────────────────────┘
```

## Service Management

### Start

```bash
# Development
PYTHONPATH=src python -m sigrift.bridge

# Production (systemd)
sudo systemctl start sigrift-bridge

# Production (manual; loopback only — the Rust gateway terminates TLS on 8444)
BRIDGE_ENV=production \
BRIDGE_MASTER_KEY=<key> \
BRIDGE_MFA_KEY=<fernet-key> \
BRIDGE_HOST=127.0.0.1 BRIDGE_PORT=8001 \
PYTHONPATH=src python -m sigrift.bridge
```

`BRIDGE_WORKERS` only applies to `python -m sigrift.bridge` (with
`python -m uvicorn` use `--workers`). Keep it at 1 unless one worker is the
bottleneck: ingest hooks and decode jobs are claimed in `detections.db`
across workers, but node command queues and live WebSocket feeds are per
worker (see DEPLOYMENT.md).

### Stop

```bash
sudo systemctl stop sigrift-bridge
# Or send SIGTERM to the uvicorn master process
kill -TERM $(pidof uvicorn)
```

Shutdown sequence: stops auto-save (performs final save), closes DetectionStore, flushes write queue.

### Restart

```bash
sudo systemctl restart sigrift-bridge
```

### Key Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `BRIDGE_ENV` | *(empty)* | `production` enables fail-closed security |
| `BRIDGE_WORKERS` | `1` | Uvicorn worker count |
| `BRIDGE_HOST` | `0.0.0.0` | Bind address |
| `BRIDGE_PORT` | `8000` | Bind port |
| `BRIDGE_LOG_LEVEL` | `INFO` | Log verbosity |
| `BRIDGE_MASTER_KEY` | *(auto in dev)* | Master API key. Required in production |
| `BRIDGE_MFA_KEY` | *(empty)* | Fernet key for TOTP encryption |
| `BRIDGE_AUDIT_KEY` | *(auto in dev)* | HMAC secret for audit chain |
| `BRIDGE_SQLITE_CACHE_SIZE` | `-64000` | SQLite page cache (negative = KB, default 64 MB) |
| `BRIDGE_SQLITE_MMAP_SIZE` | `268435456` | Memory-mapped I/O (default 256 MB) |

### Docker

```bash
# Start
docker compose up -d

# Stop (graceful — flushes write queue)
docker compose down

# Restart
docker compose restart bridge

# Logs (follow)
docker compose logs -f bridge

# Logs (last 100 lines)
docker compose logs --tail 100 bridge

# Shell into running container
docker compose exec bridge bash

# Check container health status
docker inspect --format='{{.State.Health.Status}}' sigrift-bridge-1
```

### Docker Health Checks

The Dockerfile includes a built-in healthcheck hitting `GET /api/health` every 30s. Docker reports container status as `healthy`, `unhealthy`, or `starting`.

```bash
# View health check history
docker inspect --format='{{json .State.Health}}' sigrift-bridge-1 | python3 -m json.tool

# Manual probe from host
curl -sf http://localhost:8001/api/healthz
```

### Docker-Specific Failure Modes

**Container exits immediately (exit code 1)**:
- Missing required env vars (`BRIDGE_MASTER_KEY`, `BRIDGE_MFA_KEY` in production).
- Database corruption detected by `PRAGMA quick_check`.
- Migration failure — check logs: `docker compose logs bridge | grep "Migration.*failed"`.

**Container healthy but not reachable**:
- Port not published — verify `ports:` in compose file.
- Firewall blocking — check `iptables -L` or `ufw status`.

**Data loss after restart**:
- Missing persistent volume. Verify: `docker volume ls | grep bridge_data`.
- If volume was removed, restore from backup into a new volume:
  ```bash
  docker volume create bridge_data
  docker run --rm -v bridge_data:/data -v /backup:/backup alpine \
    cp /backup/detections.db /data/detections.db
  ```

**SQLite locking errors**:
- Multiple containers sharing the same volume. **Only one bridge container may write to a given database file.** SQLite does not support multi-process writes across containers.

---

## SQLCipher Encryption

> **Not supported in this release.** Database encryption at rest with
> SQLCipher is not yet supported end to end and must not be relied on;
> to protect data at rest, use filesystem-level encryption (see
> [DEPLOYMENT.md, Data-at-Rest Encryption](DEPLOYMENT.md#data-at-rest-encryption)).
> The procedures below describe the code path for when it is supported.

### Verifying Encryption Status

```bash
# Via health endpoint (requires API key)
curl -s -H "X-API-Key: $KEY" http://localhost:8001/api/health | python3 -c "
import sys, json
h = json.load(sys.stdin)
warnings = h.get('security_warnings', [])
dar = [w for w in warnings if 'encryption' in w.lower()]
if dar: print('WARNING:', dar[0])
else: print('OK: no DAR warnings')
"

# Via startup log
journalctl -u sigrift-bridge | grep -i "SQLCipher\|encryption"
# Expected when active: "SQLCipher encryption ACTIVE (version=X.Y.Z, kdf_iter=256000)"
```

### Encryption Failure Modes

**"pysqlcipher3 is not installed" RuntimeError on startup:**
- `BRIDGE_DB_ENCRYPTION_KEY` is set but `pysqlcipher3` package is missing.
- Fix: `apt-get install libsqlcipher-dev && pip install pysqlcipher3`

**"file is not a database" after enabling encryption:**
- An existing plaintext DB should auto-migrate on first startup. If auto-migration failed, the DB may be in an inconsistent state.
- Recovery: restore from `.unencrypted.bak` (created during auto-migration) and retry.

**"file is not a database" after losing encryption key:**
- The DB is encrypted but the key is missing or wrong.
- Recovery: **impossible without the correct key.** Restore from backup + key.

**Key file permission error:**
- `BRIDGE_DB_ENCRYPTION_KEY_FILE` must be chmod 600. The bridge rejects group/other-readable key files.
- Fix: `chmod 600 /path/to/db.key`

### Key Rotation

```bash
# 1. Stop the service
sudo systemctl stop sigrift-bridge

# 2. Rekey the database
python3 -c "
from pysqlcipher3 import dbapi2
conn = dbapi2.connect('data/detections.db')
conn.execute(\"PRAGMA key='OLD_KEY'\")
conn.execute(\"PRAGMA rekey='NEW_KEY'\")
conn.close()
print('Rekeyed successfully')
"

# 3. Update the key in env/file
export BRIDGE_DB_ENCRYPTION_KEY=NEW_KEY

# 4. Restart
sudo systemctl start sigrift-bridge
```

---

## Health Checks

### Endpoints

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `GET /api/healthz` | None | Liveness probe. Returns `{"status": "ok"}` |
| `GET /api/ready` | None | Readiness probe. Verifies DB connection via `SELECT 1` |
| `GET /api/health` | VIEWER | Version, security warnings, disk usage percentage |
| `GET /api/status` | VIEWER | Node counts, alerts, detection metrics, tenant usage |
| `GET /api/metrics` | VIEWER | Ingest rate, WS clients, DB size, WAL size, cache stats |

### Automated Monitoring

```bash
# Liveness check (suitable for load balancer)
curl -sf http://localhost:8001/api/healthz

# Full health (requires API key)
curl -H "X-API-Key: $KEY" http://localhost:8001/api/health

# Check disk usage from health response
curl -s -H "X-API-Key: $KEY" http://localhost:8001/api/health | python3 -c "
import sys, json
h = json.load(sys.stdin)
pct = h.get('disk_usage_pct', 0)
if pct >= 90: print(f'CRITICAL: disk {pct}%'); sys.exit(2)
elif pct >= 80: print(f'WARNING: disk {pct}%'); sys.exit(1)
else: print(f'OK: disk {pct}%')
"
```

---

## Failure Modes and Recovery

### Database Corruption

**Symptoms**: Startup crash with `PRAGMA quick_check` failure. Queries returning unexpected errors.

**Detection**: The bridge runs `PRAGMA quick_check` on first database connection. Failure raises `sqlite3.DatabaseError` and prevents startup.

**Recovery**:

> **RF summary fences.** Restoring a backup over a database with registered RF
> summary streams (migration 56 and later) removes their fences. Run the check in
> [UPGRADE.md](UPGRADE.md) ("Docker Rollback") first; if it is not `0`, repair
> forward instead (docs/rf-summary-recovery.md, "Downgrade restriction").

```bash
# 1. Stop the service
sudo systemctl stop sigrift-bridge

# 2. Check if pre-migration backup exists
ls -la data/detections.db.pre-migration

# 3. Manual integrity check
sqlite3 data/detections.db "PRAGMA integrity_check;"

# 4. If corrupted, restore from backup
cp data/detections.db data/detections.db.corrupt
cp data/detections.db.pre-migration data/detections.db
# Or restore from nightly backup
cp /backup/bridge/detections.db.YYYYMMDD data/detections.db

# 5. Remove WAL/SHM files (they belong to the old DB)
rm -f data/detections.db-wal data/detections.db-shm

# 6. Restart
sudo systemctl start sigrift-bridge
```

**Prevention**: Pre-migration backups are created automatically. Configure nightly backups externally.

### Disk Space Alerts

**Symptoms**: Health endpoint reports `disk_usage_pct >= 80` (warning) or `>= 90` (critical). Database writes may fail.

**Detection**: `GET /api/health` includes `disk_usage_pct` and `security_warnings` when thresholds exceeded.

**Recovery**:

```bash
# 1. Check current usage
df -h $(dirname data/detections.db)

# 2. Archive old audit entries (>90 days default)
curl -X POST -H "X-API-Key: $ADMIN_KEY" \
  http://localhost:8001/api/admin/audit/archive

# 3. Run data cleanup (retention-based)
curl -X POST -H "X-API-Key: $ADMIN_KEY" \
  http://localhost:8001/api/admin/cleanup

# 4. Force WAL checkpoint to reclaim WAL space
sqlite3 data/detections.db "PRAGMA wal_checkpoint(TRUNCATE);"

# 5. Vacuum to reclaim deleted row space (requires downtime)
sudo systemctl stop sigrift-bridge
sqlite3 data/detections.db "VACUUM;"
sudo systemctl start sigrift-bridge
```

**Prevention**: Set `BRIDGE_RETENTION_DAYS` (default 90), and `BRIDGE_SPECTRUM_RETENTION_DAYS` for the `spectrum_materialized` table specifically (the largest on disk; falls back to `BRIDGE_RETENTION_DAYS`). Monitor `disk_usage_pct` via `/api/health`. If `spectrum_materialized` has already grown huge with duplicates from past restarts, the periodic prune only bounds it by age — a one-time in-place dedup may be needed to reclaim space (do NOT `full_refresh` if `spectrum_snapshots` is empty; that rebuilds from an empty source and drops history).

### WAL File Growth

**Symptoms**: `detections.db-wal` file grows large (>64 MB). Visible in `GET /api/metrics` `database.wal_size_mb`.

**Detection**: The WAL journal size limit is set to 64 MB (`journal_size_limit=67108864`). Auto-checkpoint runs every ~4 MB of writes (`wal_autocheckpoint=1000`). A background task runs `PRAGMA wal_checkpoint(PASSIVE)` every 300 seconds.

**Recovery**:

```bash
# PASSIVE checkpoint (non-blocking, safe while running)
sqlite3 data/detections.db "PRAGMA wal_checkpoint(PASSIVE);"

# TRUNCATE checkpoint (blocks briefly, resets WAL file size to zero)
sqlite3 data/detections.db "PRAGMA wal_checkpoint(TRUNCATE);"

# If WAL remains large, check for long-running readers
# SQLite WAL cannot checkpoint past the oldest active reader
```

**Prevention**: The scheduled WAL checkpoint task handles this automatically. If disabled, ensure external checkpointing.

### Migration Failures

**Symptoms**: Startup crash with `RuntimeError: Migration N (description) failed: ...`

**Detection**: Migration runner raises `RuntimeError` on any failure (fail-fast). The error message includes the migration number and SQL error.

**Recovery**:

```bash
# 1. Stop the service (it will have already crashed)

# 2. Restore the pre-migration backup
cp data/detections.db.pre-migration data/detections.db
rm -f data/detections.db-wal data/detections.db-shm

# 3. Investigate the failed migration in storage/base.py _MIGRATIONS list
# Common causes: column already exists, constraint violation, syntax error

# 4. If the migration needs manual fix, apply it via sqlite3 CLI
sqlite3 data/detections.db "..."

# 5. Then mark it as applied
sqlite3 data/detections.db \
  "INSERT INTO schema_version (version, description, applied_at) VALUES (N, 'manual fix', datetime('now'));"

# 6. Restart
sudo systemctl start sigrift-bridge
```

### Edge Node Disconnection

**Symptoms**: Missing detections from one or more nodes. Node shows as `stale` or `offline` in `GET /api/status`.

**Detection**: `GET /api/status` reports node status based on last heartbeat. `stale` = no heartbeat in 5 minutes. `offline` = no heartbeat in 15 minutes.

**Recovery**: Edge nodes use a Store-and-Forward (SAF) SQLite buffer (`detection_reporter.py` `SAFBuffer`). When the connection to the bridge is restored:

1. The SAF replay loop retries every 60 seconds.
2. Buffered detections are replayed in order, stopping on first failure.
3. Successfully replayed entries are deleted from the SAF buffer.
4. Entries older than 72 hours are automatically purged.

No manual intervention required unless the edge node itself is down.

---

## Log Analysis

### Log Format

Default: `%(asctime)s [%(levelname)s] %(name)s: %(message)s` with ISO 8601 timestamps.

Set `BRIDGE_LOG_FORMAT=json` for structured JSON output (suitable for log aggregation).

### Key Log Patterns

```
# Successful startup
INFO  sigrift.bridge.storage.base: DetectionStore initialised: data/detections.db
INFO  sigrift.bridge.app: Data directory permissions hardened: .../data

# Migration applied
INFO  sigrift.bridge.storage.base: Migration 42 applied: remove FK constraints...

# Authentication events
INFO  sigrift.bridge.routers.auth: User logged in: admin from 10.0.0.1
WARNING sigrift.bridge.routers.auth: Failed to audit-log auth failure for unknown_user

# Audit chain
INFO  sigrift.bridge.storage.audit: Audit: user_login on admin
WARNING sigrift.bridge.storage.audit: Audit chain gap detected: 2 row(s) missing between id 15 and id 18

# Database issues
CRITICAL sigrift.bridge.storage.base: Database integrity check FAILED
WARNING sigrift.bridge.storage.base: Pre-migration backup failed: [Errno 28] No space left on device

# WAL checkpoint
DEBUG sigrift.bridge.storage.base: WAL checkpoint (PASSIVE): busy=0, log=150, checkpointed=150
```

### Audit Chain Verification

```bash
# Via API (admin only)
curl -H "X-API-Key: $ADMIN_KEY" \
  http://localhost:8001/api/admin/audit/verify

# Response
{
  "valid": true,
  "total": 1523,
  "checked": 1520,
  "errors": [],
  "gaps": []
}
```

A non-empty `errors` list indicates HMAC mismatches (possible tampering). A non-empty `gaps` list indicates deleted rows.

---

## Performance Tuning

### SQLite Configuration

| Variable | Default | Tuning Guidance |
|----------|---------|-----------------|
| `BRIDGE_SQLITE_CACHE_SIZE` | `-64000` (64 MB) | Increase for read-heavy workloads. `-128000` = 128 MB. Negative values are KB |
| `BRIDGE_SQLITE_MMAP_SIZE` | `268435456` (256 MB) | Increase to DB file size for best read performance. Set to 0 to disable mmap |

Additional PRAGMAs set automatically:
- `journal_mode=WAL` -- concurrent readers with single writer
- `synchronous=NORMAL` -- safe for WAL mode, better performance than FULL
- `temp_store=MEMORY` -- temp tables in RAM
- `wal_autocheckpoint=1000` -- checkpoint every ~4 MB of writes
- `journal_size_limit=67108864` -- 64 MB WAL cap

### Write Queue

| Variable | Default | Tuning Guidance |
|----------|---------|-----------------|
| `BRIDGE_WQ_BATCH_SIZE` | `100` | Higher = fewer DB transactions, more latency. 200-500 for high ingest |
| `BRIDGE_WQ_FLUSH_MS` | `500` | Lower = less latency, more transactions. 100-250 for real-time needs |

### Cache

PartitionedCache with 2048 total entries (domain-routed). TTL varies by domain. Cache stats available via `GET /api/metrics`.

---

## Backup and Restore

### Automated Backups

Pre-migration backups are created automatically at `data/detections.db.pre-migration` before any schema migration.

For nightly backups, use the system backup timer or an external tool:

```bash
# SQLite online backup (safe while the bridge is running)
sqlite3 data/detections.db ".backup /backup/bridge/detections.db.$(date +%Y%m%d)"

# Rotate old backups (keep last N, configured via BRIDGE_BACKUP_RETENTION)
ls -1t /backup/bridge/detections.db.* | tail -n +6 | xargs rm -f
```

### Restore Procedure

> **RF summary fences.** Restoring a backup over a database with registered RF
> summary streams (migration 56 and later) removes their fences. Run the check in
> [UPGRADE.md](UPGRADE.md) ("Docker Rollback") first; if it is not `0`, repair
> forward instead (docs/rf-summary-recovery.md, "Downgrade restriction").

```bash
# 1. Stop the service
sudo systemctl stop sigrift-bridge

# 2. Back up the current (possibly corrupt) database
mv data/detections.db data/detections.db.old
rm -f data/detections.db-wal data/detections.db-shm

# 3. Restore from backup
cp /backup/bridge/detections.db.YYYYMMDD data/detections.db

# 4. Verify integrity
sqlite3 data/detections.db "PRAGMA integrity_check;"

# 5. Restart (migrations will apply any pending schema changes)
sudo systemctl start sigrift-bridge

# 6. Verify via health endpoint
curl -sf http://localhost:8001/api/healthz
```

### Backup Contents

The SQLite database contains all persistent state:
- Detections, aggregates, anomalies
- User accounts, sessions, MFA configuration
- API key metadata
- Audit log (HMAC chain)
- Baselines and feedback
- Configuration snapshots
- Login failures, rate limit state

The `data/` directory also contains:
- `keys.json` -- API key store (mode 0600)
- `audit.key` -- Auto-generated audit HMAC key (dev mode only, mode 0600)
- Baseline pickle files
- IQ capture files

Back up the entire `data/` directory for a complete restore.

---

## Security Incident Response

### Session Revocation

```bash
# Revoke a specific user's sessions (admin)
curl -X DELETE -H "X-API-Key: $ADMIN_KEY" \
  http://localhost:8001/api/admin/users/compromised_user

# This disables the account AND invalidates all sessions
```

Password changes also invalidate all sessions for that user.

### API Key Rotation

```bash
# 1. Create a new key
curl -X POST -H "X-API-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"role": "sensor", "node_id": "node-01", "expires_days": 90}' \
  http://localhost:8001/api/admin/keys

# 2. Deploy the new key to the edge node

# 3. Revoke the old key
curl -X DELETE -H "X-API-Key: $ADMIN_KEY" \
  http://localhost:8001/api/keys/<old_key_id>
```

`expires_days` is a whole number of days from 1 to 3650, capped at
`BRIDGE_MAX_KEY_LIFETIME_DAYS` (default 365). Omit it (or send `null`) for
that default lifetime: every key created here expires, so rotate long-lived
node keys before they lapse. Zero, a negative number or anything above 3650
is refused with 422 and no key is created, so a typo such as `-30` is never
taken as the default. The admin panel's *Expires (days)* field applies the
same rule: leave it blank for the default lifetime.

### Audit Trail Review

```bash
# Recent auth failures
curl -H "X-API-Key: $ADMIN_KEY" \
  "http://localhost:8001/api/audit?action=auth_failure&limit=50"

# All actions by a specific operator
curl -H "X-API-Key: $ADMIN_KEY" \
  "http://localhost:8001/api/audit?operator=suspect_user&limit=100"

# Verify chain integrity
curl -H "X-API-Key: $ADMIN_KEY" \
  http://localhost:8001/api/admin/audit/verify

# Search audit log
curl -H "X-API-Key: $ADMIN_KEY" \
  "http://localhost:8001/api/audit?search=keyword&start=2026-03-01T00:00:00Z"
```

### Checklist

1. Identify scope: which accounts/keys/nodes are affected
2. Revoke compromised credentials (sessions, API keys)
3. Review audit log for unauthorized actions
4. Verify audit chain integrity (detect tampering)
5. Rotate `BRIDGE_MASTER_KEY` and `BRIDGE_AUDIT_KEY` if master key compromised
6. Review and rotate edge node API keys
7. Check for unauthorized user accounts or role escalation
8. Document incident timeline from audit log
