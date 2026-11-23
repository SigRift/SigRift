# SigRift Bridge Upgrade Guide

## Pre-Upgrade Checklist

1. **Verify current health**
   ```bash
   curl -sf http://localhost:8001/api/healthz
   curl -s -H "X-API-Key: $KEY" http://localhost:8001/api/health | python3 -m json.tool
   ```
   Do not proceed if health check returns warnings or errors.

2. **Check disk space**
   ```bash
   df -h $(dirname data/detections.db)
   ```
   Ensure at least 2x the current database size is free (for pre-migration backup + potential VACUUM).

3. **Create manual backup**
   ```bash
   sqlite3 data/detections.db ".backup data/detections.db.pre-upgrade-$(date +%Y%m%d%H%M)"
   # The Wi-Fi and Bluetooth baselines too: a rollback needs them as they were
   for f in wifi_baselines.json bt_baselines.json; do
     if [ -e "data/$f" ]; then cp -p "data/$f" "data/$f.pre-upgrade"; fi
   done
   ```
   In Docker the database is in the `bridge_data` volume and the image has
   no sqlite3 CLI: take the backup with step 2 of
   [Docker Upgrade](#docker-upgrade) instead. See
   [Baseline Files (Radio Text as Heard)](#baseline-files-radio-text-as-heard)
   for why the baselines are copied.

4. **Verify audit chain integrity**
   ```bash
   curl -s -H "X-API-Key: $ADMIN_KEY" http://localhost:8001/api/admin/audit/verify \
     | tee audit-verify-pre-upgrade.json
   ```
   Ensure `"valid": true` before upgrading. If it is not, keep the saved
   output: it tells entries that already failed apart from any that fail
   after the upgrade (see [Audit Chain Record Format](#audit-chain-record-format-v3)).

5. **Note current schema version**
   ```bash
   sqlite3 data/detections.db "SELECT MAX(version) FROM schema_version;"
   ```

6. **Review release notes** for breaking changes, new environment variables, or deprecated features.

---

## Migration System

### How It Works

The bridge uses a numbered migration system in `storage/base.py`. Migrations run automatically on startup.

- **Migration table**: `schema_version` tracks applied migrations (version, description, applied_at).
- **43 migrations** as of v3.3 (covering schema additions from wifi anomalies through FK constraint rebuild).
- **Idempotent**: Each migration checks `schema_version` before applying. Already-applied migrations are skipped.
- **Ordered**: Migrations run in version order. Gaps in version numbers are allowed.
- **Gateway**: the gateway refuses a database with a migration newer than `NEWEST_KNOWN_BRIDGE_MIGRATION` (`src/gateway/crates/sigrift-gateway-core/src/db/schema.rs`). A new migration needs that constant set to it, after checking the gateway still works with the new schema; until then the bridge and gateway test suites fail.

### Safety Features

| Feature | Description |
|---------|-------------|
| Pre-migration backup | Database copied to `detections.db.pre-migration` before any pending migration runs |
| Fail-fast | `RuntimeError` raised on any migration failure. Service does not start with a partially-migrated schema |
| FK safety | `PRAGMA foreign_keys=OFF` during migration execution to prevent spurious validation errors from table recreation patterns |
| FK re-enabled | `PRAGMA foreign_keys=ON` after each migration completes |
| Commit per migration | Each migration is committed individually, so partial progress is preserved if a later migration fails |
| Newer-schema refusal | The bridge refuses to start on a database containing migrations newer than its own newest one, before the base schema or any migration runs. The Rust gateway, which opens the same database, does the same against the newest bridge migration it was built with, before it changes anything in the database (it adds its own tables and the `sessions.scope` column). It checks again when its wait for the bridge ends (the bridge answered, or 60 s passed), before it listens; a migration committed after that is refused only at the gateway's next start. Both exit with an error naming the unknown migrations |

### Startup Sequence

```
┌──────────────────────────────────────────────────────────────┐
│                    Startup / Migration Flow                   │
│                                                              │
│  Start                                                       │
│    │                                                         │
│    ▼                                                         │
│  ┌─ Encryption key configured? ─┐                            │
│  │ YES                    NO    │                            │
│  ▼                        │     │                            │
│  Plaintext DB exists? ──► │     │                            │
│  │ YES              NO    │     │                            │
│  ▼                  │     │     │                            │
│  Auto-encrypt       │     │     │                            │
│  (.unencrypted.bak) │     │     │                            │
│  │                  │     │     │                            │
│  └──────┬───────────┘     │     │                            │
│         │                 │     │                            │
│         ▼                 │     │                            │
│  open_db() ◄──────────────┘     │                            │
│  (SQLCipher or plain)           │                            │
│         │                       │                            │
│         ▼                       │                            │
│  open_db() ◄────────────────────┘                            │
│  (plain sqlite3)                                             │
│         │                                                    │
│         ▼                                                    │
│  PRAGMA quick_check ──── FAIL ──► RuntimeError (crash)       │
│         │ OK                                                 │
│         ▼                                                    │
│  Schema newer than build? ── YES ──► RuntimeError (crash)    │
│         │ NO                                                 │
│         ▼                                                    │
│  Create base schema (if new)                                 │
│         │                                                    │
│         ▼                                                    │
│  Check schema_version                                        │
│         │                                                    │
│         ▼                                                    │
│  Pending migrations? ── NO ──► Normal startup                │
│         │ YES                                                │
│         ▼                                                    │
│  Copy .pre-migration backup                                  │
│         │                                                    │
│         ▼                                                    │
│  ┌─ For each migration ──────────────────┐                   │
│  │  FK OFF → SQL → FK ON → commit        │                   │
│  │  │                                    │                   │
│  │  ├── OK ──► next migration            │                   │
│  │  └── FAIL ──► RuntimeError (crash)    │                   │
│  └───────────────────────────────────────┘                   │
│         │                                                    │
│         ▼                                                    │
│  PRAGMA foreign_keys=ON                                      │
│         │                                                    │
│         ▼                                                    │
│  Normal startup (lifespan tasks, routers, etc.)              │
└──────────────────────────────────────────────────────────────┘
```

---

## Upgrade Procedure

The bridge and the Rust gateway share the audit chain in `detections.db`:
upgrade both to the same release in the same maintenance window, and roll
both back together (see [Audit Chain Record Format](#audit-chain-record-format-v3)).

### Standard Upgrade (Bare Metal)

```bash
# 1. Stop the service
sudo systemctl stop sigrift-bridge

# 2. Deploy new code
cd /opt/sigrift
git pull origin main  # or deploy artifact

# 3. Install dependencies (hash-checked locks; torch in its own step)
pip install --require-hashes -r src/sigrift/bridge/requirements.txt
pip install --require-hashes --no-deps -r src/sigrift/bridge/requirements-torch-cpu.txt

# 4. Start the service (migrations run automatically)
sudo systemctl start sigrift-bridge
#    ...and install and restart the gateway of the same release.

# 5. Verify
curl -sf http://localhost:8001/api/healthz
curl -s -H "X-API-Key: $KEY" http://localhost:8001/api/health
```

### Docker Upgrade

These commands are for the stack built from source with `docker-compose.yml`
(`build:`, no `image:`). Run them in the directory that holds it, with the
same `-p` / `-f` options (or `COMPOSE_PROJECT_NAME` / `COMPOSE_FILE`) the
stack was started with. Compose names the images `<project>-bridge` and
`<project>-gateway` and the data volume `<project>_bridge_data` (the project
is the directory name unless set), so the commands ask compose for the
images and work in the volume through the bridge service, instead of
naming either. A stack that runs pinned registry images (`image:` set, as
`install-release.sh` does) keeps the previous release's tag instead of
step 1; see [Docker Rollback](#docker-rollback).

```bash
# 1. Keep the images the stack runs now, for a rollback
docker tag "$(docker compose images -q bridge)" sigrift-bridge:previous
docker tag "$(docker compose images -q gateway)" sigrift-gateway:previous

# 2. Back up the database (Pre-Upgrade Checklist step 3, for Docker).
#    Stop both services first: the gateway has the database open too. The
#    copy is kept in the data volume, next to the database, owned by the
#    bridge's user (the image has no sqlite3 CLI; a file copy of the
#    stopped database also works for an encrypted one).
docker compose stop gateway bridge
docker compose run --rm --no-deps bridge sh -c '
  cd /app/src/sigrift/bridge/data &&
  rm -f detections.db.pre-upgrade detections.db-wal.pre-upgrade &&
  cp -p detections.db detections.db.pre-upgrade &&
  if [ -e detections.db-wal ]; then
    cp -p detections.db-wal detections.db-wal.pre-upgrade
  fi &&
  for f in wifi_baselines.json bt_baselines.json; do
    rm -f "$f.pre-upgrade"
    if [ -e "$f" ]; then cp -p "$f" "$f.pre-upgrade" || exit 1; fi
  done &&
  ls -l detections.db*'

# 3. Build the new images (bridge and gateway: they share the audit chain)
#    and recreate their containers (the data volume persists)
docker compose build --no-cache bridge gateway
docker compose up -d bridge gateway

# 4. Verify
docker compose logs --tail 20 bridge gateway
docker compose exec bridge python3 -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8001/api/healthz').read().decode())"

# 5. Check migration applied
docker compose exec bridge python3 -c "
import sqlite3
conn = sqlite3.connect('/app/src/sigrift/bridge/data/detections.db')
v = conn.execute('SELECT MAX(version) FROM schema_version').fetchone()[0]
print(f'Schema version: {v}')
"
```

To keep an off-host copy as well, copy `detections.db.pre-upgrade` out of the
volume (for example `docker compose cp
bridge:/app/src/sigrift/bridge/data/detections.db.pre-upgrade backups/`).

### Docker Rollback

> **Check RF summary state before any rollback.** Once a node has registered a
> versioned RF summary stream (migration 56 and later), restoring a pre-upgrade
> database deletes the stream, generation and retired-hour fences, and older code
> cannot read the separate summary components. Stale or delayed snapshots are then
> accepted again and counts can go backwards. Check first:
>
> ```bash
> # Bare metal (service stopped or running):
> sqlite3 data/detections.db "SELECT (SELECT COUNT(*) FROM rf_summary_streams)
>   + (SELECT COUNT(*) FROM rf_summary_generations)
>   + (SELECT COUNT(*) FROM rf_summary_components);"
> # Docker (the image has no sqlite3 CLI; run this before `docker compose down`):
> docker compose exec bridge python3 -c "import sqlite3; c = sqlite3.connect('/app/src/sigrift/bridge/data/detections.db'); print(sum(c.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0] for t in ('rf_summary_streams', 'rf_summary_generations', 'rf_summary_components')))"
> ```
>
> If the result is not `0`, do **not** roll back: keep the upgraded database and
> scanner journal and repair forward. A `no such table` error means migration 56
> never ran, so this check does not block the rollback. An encrypted (SQLCipher)
> database needs the same key the bridge uses; the plain commands above cannot read it.
> Rolling back the code only (keeping the database) also fails once the database has
> a migration newer than the target build: that bridge refuses to start, and so does
> a gateway from this release on, also when only the gateway is rolled back. A
> gateway from before this release does not check: never start one on such a
> database. See
> [docs/rf-summary-recovery.md](../../../docs/rf-summary-recovery.md), "Downgrade
> restriction".

Run these in the same directory, with the same compose options, as the
upgrade. They need the copy from step 2 of [Docker Upgrade](#docker-upgrade);
without it there is nothing to restore, so do not roll back the images alone
(see below).

```bash
# 1. Stop both services (the rest of the stack can keep running)
docker compose stop gateway bridge

# 2. Restore the pre-upgrade database in the data volume. The upgraded
#    database is kept as detections.db.failed. Without a
#    detections.db.pre-upgrade it exits with status 1 and changes nothing:
#    then do not go on to step 3.
docker compose run --rm --no-deps bridge sh -c '
  cd /app/src/sigrift/bridge/data &&
  test -e detections.db.pre-upgrade &&
  for f in detections.db detections.db-wal; do
    if [ -e "$f" ]; then cp -p "$f" "$f.failed"; fi
  done &&
  cp -p detections.db.pre-upgrade detections.db &&
  rm -f detections.db-wal detections.db-shm &&
  if [ -e detections.db-wal.pre-upgrade ]; then
    cp -p detections.db-wal.pre-upgrade detections.db-wal
  fi &&
  for f in wifi_baselines.json bt_baselines.json; do
    if [ -e "$f.pre-upgrade" ]; then cp -p "$f.pre-upgrade" "$f" || exit 1; fi
  done &&
  ls -l detections.db*'

# 3. Give the previous images (bridge and gateway together) the names
#    compose runs, and start them. image_of prints one service's own image
#    name (`docker compose config --images gateway` also lists the bridge,
#    which the gateway depends on). The && chain starts nothing if a tag
#    fails, so the two never run at different versions.
image_of() {
  docker compose config --format json | python3 -c '
import json, sys
c = json.load(sys.stdin)
print(c["services"][sys.argv[1]].get("image") or c["name"] + "-" + sys.argv[1])
' "$1"
}
docker tag sigrift-bridge:previous "$(image_of bridge)" &&
docker tag sigrift-gateway:previous "$(image_of gateway)" &&
docker compose up -d --no-build bridge gateway
docker compose images bridge gateway   # the IDs of the sigrift-*:previous images
```

With pinned registry images (`image:` in the compose file), skip step 3's
`docker tag` lines: after steps 1 and 2, pin the previous release's tags
again and start the stack with them. For an `install-release.sh` install,
run the previous release's installer with `SIGRIFT_VERSION` set to that
release.

Restoring the database is not optional when the release being rolled back
writes a newer audit record format: see
[Audit Chain Record Format](#audit-chain-record-format-v3). Step 2 also
puts back the Wi-Fi and Bluetooth baselines the upgrade copied; see
[Baseline Files (Radio Text as Heard)](#baseline-files-radio-text-as-heard).

### Zero-Downtime Strategy (Single Server)

True zero-downtime is not possible with a single-server SQLite deployment because migrations require exclusive write access. However, downtime can be minimized:

```bash
# 1. Pre-deploy: pull code but don't restart
cd /opt/sigrift-staging
git pull origin main
pip install --require-hashes -r src/sigrift/bridge/requirements.txt
pip install --require-hashes --no-deps -r src/sigrift/bridge/requirements-torch-cpu.txt

# 2. Brief maintenance window
sudo systemctl stop sigrift-bridge

# 3. Swap code directories
mv /opt/sigrift /opt/sigrift-old
mv /opt/sigrift-staging /opt/sigrift

# 4. Start (migrations apply during startup, typically <5 seconds)
sudo systemctl start sigrift-bridge

# 5. Verify immediately
curl -sf http://localhost:8001/api/healthz
```

Typical downtime: 5-30 seconds depending on number of pending migrations.

Edge nodes with SAF buffering continue collecting data during the upgrade window and replay buffered detections after reconnection.

---

## Rollback Procedures

### Rollback After Failed Migration

If the service fails to start due to a migration error:

```bash
# 1. Check the error log for the failing migration number
journalctl -u sigrift-bridge --no-pager | grep "Migration.*failed"

# 2. Restore pre-migration backup
cp data/detections.db.pre-migration data/detections.db
rm -f data/detections.db-wal data/detections.db-shm

# 3. Revert code to previous version
cd /opt/sigrift
git checkout v<previous-version>
# Install that version's own requirements. Versions with hash-checked
# locks (src/sigrift/bridge/requirements-torch-cpu.txt exists):
#   pip install --require-hashes -r src/sigrift/bridge/requirements.txt
#   pip install --require-hashes --no-deps -r src/sigrift/bridge/requirements-torch-cpu.txt
# Older versions:
#   pip install -r src/sigrift/bridge/requirements.txt

# 4. Start with old code
sudo systemctl start sigrift-bridge
```

### Rollback After Successful Migration

If the upgrade succeeds but introduces a regression:

> **Check RF summary state before any rollback.** Once a node has registered a
> versioned RF summary stream (migration 56 and later), restoring a pre-upgrade
> database deletes the stream, generation and retired-hour fences, and older code
> cannot read the separate summary components. Stale or delayed snapshots are then
> accepted again and counts can go backwards. Check first:
>
> ```bash
> # Bare metal (service stopped or running):
> sqlite3 data/detections.db "SELECT (SELECT COUNT(*) FROM rf_summary_streams)
>   + (SELECT COUNT(*) FROM rf_summary_generations)
>   + (SELECT COUNT(*) FROM rf_summary_components);"
> # Docker (the image has no sqlite3 CLI; run this before `docker compose down`):
> docker compose exec bridge python3 -c "import sqlite3; c = sqlite3.connect('/app/src/sigrift/bridge/data/detections.db'); print(sum(c.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0] for t in ('rf_summary_streams', 'rf_summary_generations', 'rf_summary_components')))"
> ```
>
> If the result is not `0`, do **not** roll back: keep the upgraded database and
> scanner journal and repair forward. A `no such table` error means migration 56
> never ran, so this check does not block the rollback. An encrypted (SQLCipher)
> database needs the same key the bridge uses; the plain commands above cannot read it.
> Rolling back the code only (keeping the database) also fails once the database has
> a migration newer than the target build: that bridge refuses to start, and so does
> a gateway from this release on, also when only the gateway is rolled back. A
> gateway from before this release does not check: never start one on such a
> database. See
> [docs/rf-summary-recovery.md](../../../docs/rf-summary-recovery.md), "Downgrade
> restriction".

```bash
# 1. Stop the service
sudo systemctl stop sigrift-bridge

# 2. Restore from pre-upgrade manual backup (with the baselines, see
#    "Baseline Files (Radio Text as Heard)" below)
cp data/detections.db.pre-upgrade-YYYYMMDDHHMMM data/detections.db
rm -f data/detections.db-wal data/detections.db-shm
for f in wifi_baselines.json bt_baselines.json; do
  if [ -e "data/$f.pre-upgrade" ]; then cp -p "data/$f.pre-upgrade" "data/$f"; fi
done

# 3. Revert code
cd /opt/sigrift
git checkout v<previous-version>
# Install that version's own requirements. Versions with hash-checked
# locks (src/sigrift/bridge/requirements-torch-cpu.txt exists):
#   pip install --require-hashes -r src/sigrift/bridge/requirements.txt
#   pip install --require-hashes --no-deps -r src/sigrift/bridge/requirements-torch-cpu.txt
# Older versions:
#   pip install -r src/sigrift/bridge/requirements.txt

# 4. Restart
sudo systemctl start sigrift-bridge
```

Note: Data ingested between the upgrade and rollback will be lost. Edge nodes with SAF buffering will re-send data that was not acknowledged.

### Baseline Files (Radio Text as Heard)

From this release the bridge stores the text radios send (Wi-Fi SSIDs,
security and frame text, Bluetooth names, types and manufacturers, Zigbee
names) as received; earlier releases stored most of it HTML-escaped once.
Two baseline files in the data directory, next to `detections.db`, follow:

- `wifi_baselines.json` moves to schema 2. The upgraded bridge decodes a
  schema 1 file's SSIDs on load (exactly the five entities the old escaping
  wrote: `&amp;`, `&lt;`, `&gt;`, `&quot;`, `&#x27;`) and writes schema 2 on
  its next save.
- `bt_baselines.json` keeps its layout, but a device name or manufacturer
  learned escaped is replaced by the same text as heard.

An older bridge reads both files as they are (it does not check
`schema_version`) while its ingest still escapes what it hears. Started on
the upgraded files, it misses evil twins of every learned SSID that has
`&`, `<`, `>`, `"` or `'` in it until it learns that SSID again, and raises
`spoofed_identity` for Bluetooth devices whose names have them. So the
upgrade steps above copy both files to `<file>.pre-upgrade` and the
rollback steps put them back. Without those copies, keep
`wifi_baselines.json` (only those SSIDs are affected, and the next upgrade
merges what the older bridge learned) and delete `bt_baselines.json` before
starting the older bridge, so it relearns Bluetooth devices instead of
reporting them as spoofed.

Bundles behave the same way: an older bridge that imports a `wifi_baselines`
or `bt_baselines` component exported by this release has the same gaps, so
leave those components out of a bundle meant for one (`export --components`
without `wifi` and `bt`). This release still imports bundles from older
ones, decoding their Wi-Fi baselines as it does a schema 1 file.

---

## Version Compatibility

### API Versioning

The bridge uses API version headers:
- `GET /api/version` returns `api_version`, `server_version`, `supported_versions`
- Response header `X-API-Version` on all responses
- Edge nodes negotiate version on connect

### Database Schema Compatibility

- **Forward compatible**: New versions can read old databases (migrations add columns/tables, never remove).
- **Not backward compatible**: Old code cannot read a database that has had new migrations applied (new columns may be required, views may reference new tables).
  Builds that include the newer-schema refusal stop at startup with an error naming the unknown migrations; earlier builds do not check and must not be started on such a database.
  The gateway has the same refusal from this release on: it exits 1 with `schema: Database schema has migrations [...] newer than this gateway build` before it changes the database, and checks again when its wait for the bridge ends, before it listens. A migration the bridge commits after that wait (a bridge slower than 60 s to start, or one upgraded on its own while the gateway runs) is refused only at the gateway's next start, so upgrade and roll back the two together. A database without `schema_version` (fresh, or not migrated by the bridge yet) is not refused. Earlier gateways do not check: they add their own tables to such a database and serve it.
- **Version skipping**: Safe. The migration runner applies all pending migrations in order regardless of how many versions were skipped.

### Audit Chain Record Format (v3)

Audit entries written from this release on are signed as record format v3,
which also authenticates `target_ids` and `tenant_id` and length-prefixes
every field. The bridge and the Rust gateway both append to and verify the
same `audit_log` chain, and only this release's verifiers know v3. The
format is one-way: no version is stored on a row and stored entries are
never re-signed, so there is no downgrade migration.

- **Upgrade the gateway and the bridge together**, and never run an older
  bridge or gateway against a database this release has written. An older
  side reports every v3 entry as tampered in `GET /api/admin/audit/verify`
  (`"valid": false`, one error per new entry), and an older gateway refuses
  to archive ("the audit chain fails verification in the range to be
  archived"), so nothing more can be archived or purged.
- **A rollback needs the pre-upgrade database backup** (Pre-Upgrade
  Checklist, step 3; in Docker, step 2 of [Docker Upgrade](#docker-upgrade)).
  Rolling the code back without restoring it leaves
  every entry written since the upgrade permanently unverifiable by the
  older release.
- Entries written before the upgrade (v1/v2) are not rewritten. They keep
  verifying, with the coverage their own version gives.
- Entries that failed verification before the upgrade still fail. This
  includes genuine entries an older bridge wrote with a non-float
  `freq_hz` (an integer, `None`, NaN, `-0.0` or a boolean) or with `None`
  as `signal_class`, `node_id`, `operator` or `note`: they were hashed as
  that value but are verified as the value stored, so they cannot be told
  apart from tampering. The bridge's routes pass stored detection values,
  so such entries come mainly from code calling `log_audit` directly.
  Triage them by hand against the output saved in Pre-Upgrade Checklist
  step 4. This release stores and hashes those values as they read back,
  so new entries verify.
- An error from `GET /api/admin/audit/verify` (bridge and gateway) no
  longer carries the computed HMAC in `expected`: that digest was a valid
  signature for the entry's tampered content, which anyone able to write
  the database could store to re-sign the chain. `expected` is now a fixed
  description; tooling should rely on `id` and `actual`.
- An entry without an HMAC is now accepted only before the chain's first
  signed entry (rows written before the chain existed). The bridge and the
  gateway sign every entry they write, as 0.1.0 did, so an unsigned entry
  after a signed one, which older verifiers skipped, was written without
  the key: `GET /api/admin/audit/verify` (bridge and gateway) now reports
  it, with an empty `actual`. Such an error after the upgrade points to
  tampering, not to the upgrade.

### SQLCipher Encryption Compatibility

> **Not supported in this release.** Database encryption at rest with
> SQLCipher is not yet supported end to end and must not be relied on;
> to protect data at rest, use filesystem-level encryption (see
> [DEPLOYMENT.md, Data-at-Rest Encryption](DEPLOYMENT.md#data-at-rest-encryption)).
> The notes below describe the code path for when it is supported.

- **Enabling SQLCipher on an existing deployment**: Set `BRIDGE_DB_ENCRYPTION_KEY` and install `pysqlcipher3`. On next startup, the plaintext database is automatically encrypted in-place. A `.unencrypted.bak` backup is preserved.
- **Disabling SQLCipher**: Remove `BRIDGE_DB_ENCRYPTION_KEY`. The encrypted database cannot be read without the key — you must restore from the `.unencrypted.bak` or decrypt first.
- **Key loss**: The database is unrecoverable without the encryption key. Always back up the key separately.
- **Backup files**: When SQLCipher is active, online backups (`/api/admin/backup`) and pre-migration backups are also encrypted with the same key.

### Web-Framework (FastAPI/Starlette) Upgrade Notes

Upgraded 2026-06-10 to fastapi 0.136.3 + starlette 1.2.1 (from
0.128.0 / 0.50.0). APIs the bridge relies on that are sensitive to
future framework bumps:

- **`TemplateResponse(request, "name.html")`** — starlette 1.0 removed
  the old `("name.html", {"request": request})` signature (call sites:
  `app.py` login/dashboard/admin pages, `lib/shiny/app.py`).
- **Strict JSON Content-Type** (fastapi 0.132+): routes with JSON body
  params reject requests without `Content-Type: application/json`.
  All edge clients send it; any new scanner/agent POST must too.
- **`CombinedMiddleware`** (`app.py`) is raw ASGI and mutates
  `scope["server"]`/`scope["scheme"]` and injects headers on
  `http.response.start` — re-verify against `tests/bridge/test_correlation_id.py`
  on framework bumps.
- **`TestClient.portal`** (undocumented) is used by
  `test_ws_broadcast.py` / `test_performance.py` to schedule broadcasts
  during open websocket sessions — check it still exists when bumping
  starlette.
- Response JSON is serialized by pydantic-core since fastapi 0.130 —
  numeric endpoints emitting NaN/Inf or numpy scalars are the paths to
  spot-check.

### Environment Variable Changes

When upgrading, check for:
- New required variables (especially when `BRIDGE_ENV=production`)
- New optional variables (e.g., `BRIDGE_DB_ENCRYPTION_KEY` for SQLCipher — not yet supported end to end in this release; see [SQLCipher Encryption Compatibility](#sqlcipher-encryption-compatibility))
- Changed defaults (e.g., `BRIDGE_SESSION_BINDING` changed from `warn` to `ip`)
- Deprecated variables (logged at WARNING level on startup)

---

## Post-Upgrade Verification

### Immediate Checks

```bash
# 1. Service is running
curl -sf http://localhost:8001/api/healthz

# 2. Database is accessible
curl -sf http://localhost:8001/api/ready

# 3. No security warnings (or only expected ones)
curl -s -H "X-API-Key: $KEY" http://localhost:8001/api/health | python3 -c "
import sys, json
h = json.load(sys.stdin)
warnings = h.get('security_warnings', [])
if warnings: print('Warnings:', warnings)
else: print('No security warnings')
"

# 4. Schema version updated
sqlite3 data/detections.db "SELECT version, description, applied_at FROM schema_version ORDER BY version DESC LIMIT 5;"

# 5. API version
curl -s http://localhost:8001/api/version | python3 -m json.tool
```

### Functional Checks

```bash
# 6. Detection ingest working (check rate > 0 if nodes are active)
curl -s -H "X-API-Key: $KEY" http://localhost:8001/api/metrics | python3 -c "
import sys, json
m = json.load(sys.stdin)
print('Ingest rate:', m.get('ingest', {}).get('detections_per_second', 'N/A'))
"

# 7. Nodes reporting
curl -s -H "X-API-Key: $KEY" http://localhost:8001/api/status | python3 -c "
import sys, json
s = json.load(sys.stdin)
print(f'Nodes: {s[\"active_nodes\"]} active, {s[\"stale_nodes\"]} stale, {s[\"offline_nodes\"]} offline')
"

# 8. Audit chain still valid
curl -s -H "X-API-Key: $ADMIN_KEY" http://localhost:8001/api/admin/audit/verify | python3 -c "
import sys, json
v = json.load(sys.stdin)
print('Audit chain valid:', v.get('valid'))
if v.get('errors'): print('Errors:', len(v['errors']))
if v.get('gaps'): print('Gaps:', len(v['gaps']))
"

# 9. Test a dashboard query
curl -s -H "X-API-Key: $KEY" "http://localhost:8001/api/detections/stats?hours=1" | python3 -m json.tool
```

### Rollback Decision

If any of checks 1-5 fail, roll back immediately using the pre-upgrade backup. If checks 6-9 show degradation, investigate before deciding -- the issue may be environmental rather than upgrade-related.

---

## Add-on packages

This community build ships every feature it includes unconditionally — no
tier checks, no node limits, no feature gates. There is no upgrade path
between editions in this tree.

A separate add-on package (`sigrift-sentinel`) provides additional
routers (OIDC SSO, STIX/TAXII, fingerprinting) and is installed
side-by-side via `pip install -e sentinel/` when present. The community
bridge runs identically with or without it; sentinel-only routers are
mounted via guarded imports and stay absent when the package is missing.
