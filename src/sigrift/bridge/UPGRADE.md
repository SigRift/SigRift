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
   The bridge **refuses to migrate** when it cannot make
   `detections.db.pre-migration` (usually a full disk): it logs how much the
   copy needs and how much is free, and starts no migration. The free space
   is checked before the copy is written (the database and its WAL, plus
   max(64 MB, 2%)), so a copy that cannot fit writes nothing, however often
   Compose restarts the refused bridge.
   `BRIDGE_ALLOW_MIGRATION_WITHOUT_BACKUP=1` in the bridge's environment
   overrides that (only with a backup of your own; remove it afterwards:
   `/api/health` warns, and every start logs a WARNING, while it is set). A
   release install generated before v0.2.0 lists the bridge's environment
   without it: add it under `services: bridge: environment:` in
   `docker-compose.override.yml` too.
   After a successful upgrade the copy is kept for 7 days while at least
   max(1 GB, the database's size) stays free and the disk is under 80% used,
   so plan for it on large databases; the periodic cleanup removes it
   earlier (WARNING) once that stops being true.

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
| Pre-migration backup | Database copied to `detections.db.pre-migration` (SQLite online backup, WAL included) before any pending migration runs. A copy that cannot be made stops the run before any migration (`RuntimeError`, with a CRITICAL line giving the space the copy needs and the space free, and naming an older copy if one is there), unless `BRIDGE_ALLOW_MIGRATION_WITHOUT_BACKUP=1` (an `/api/health` warning while it is set). The free space is checked first, so a copy that cannot fit is refused without writing anything. The bridge never deletes an older copy to make room. After a successful upgrade the copy is **kept** (the database as it was just before the migrations) while at least max(1 GB, the database's size) stays free and the disk is under 80% used; otherwise it is removed at once with a WARNING. A new database keeps none. Kept copies are swept 7 days after they were made, at startup and on every periodic cleanup (`BRIDGE_CLEANUP_INTERVAL`, first in each cycle), which also removes a kept copy early, with a WARNING, once the space rule above fails, and a `detections.db.pre-migration.XXXXXX` left by a copy that was interrupted, 7 days after it was written |
| Restore marker | The bridge, and `python3 -m sigrift.bridge.ca migrate-key` before it, refuse to touch the volumes while `.sigrift-restore-incomplete` exists at the root of `bridge_data` or `bridge_secrets` (a restore by `install-release.sh` / `quickstart.sh` that did not finish). One CRITICAL line names the file and the next step (`install-release.sh --status`); the bridge never reads, creates or removes the marker |
| Fail-fast | `RuntimeError` raised on any migration failure. Service does not start with a partially-migrated schema |
| FK safety | `PRAGMA foreign_keys=OFF` during migration execution to prevent spurious validation errors from table recreation patterns |
| FK re-enabled | `PRAGMA foreign_keys=ON` after each migration completes |
| Commit per migration | Each migration is committed individually, so partial progress is preserved if a later migration fails |
| Restore marker (written by `install-release.sh --rollback`) | `.sigrift-restore-incomplete` at the root of the `bridge_data` volume (`/app/src/sigrift/bridge/data/` in the bridge container) and of `bridge_secrets` means a restore was interrupted and the data is half restored. The installers never start a stack while it exists; see "Restore marker" under [Release Install Upgrade](#release-install-upgrade-install-releasesh) |
| Restore point (release installs) | Every `install-release.sh` upgrade takes a full restore point of both data volumes once the stack is stopped, after a `PRAGMA quick_check` and a WAL checkpoint; `install-release.sh --rollback` restores it (INSTALL.md, "Rolling back"). It is not an off-host backup |
| Newer-schema refusal | The bridge refuses to start on a database containing migrations newer than its own newest one, before the base schema or any migration runs. The Rust gateway, which opens the same database, does the same against the newest bridge migration it was built with, before it changes anything in the database (it adds its own tables and the `sessions.scope` column). It checks again when its wait for the bridge ends (the bridge answered, or 60 s passed), before it listens; a migration committed after that is refused only at the gateway's next start. Both exit with an error naming the unknown migrations |

### Startup Sequence

```
┌──────────────────────────────────────────────────────────────┐
│                    Startup / Migration Flow                   │
│                                                              │
│  Start                                                       │
│    │                                                         │
│    ▼                                                         │
│  Restore marker present? ── YES ──► refuse (RuntimeError)    │
│    │ NO                                                      │
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
│  Copy .pre-migration ── FAIL ──► RuntimeError, unless        │
│         │ OK      BRIDGE_ALLOW_MIGRATION_WITHOUT_BACKUP=1    │
│         ▼                                                    │
│  ┌─ For each migration ──────────────────┐                   │
│  │  FK OFF → SQL → FK ON → commit        │                   │
│  │  │                                    │                   │
│  │  ├── OK ──► next migration            │                   │
│  │  └── FAIL ──► RuntimeError (crash)    │                   │
│  └───────────────────────────────────────┘                   │
│         │                                                    │
│         ▼                                                    │
│  Keep the copy 7 days (removed at once:                      │
│  new database / low space)                                   │
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

### Release Install Upgrade (install-release.sh)

A stack installed with `install-release.sh` runs pinned registry images
and is upgraded by the new release's installer: unpack the release
anywhere and run `bash install-release.sh` there (INSTALL.md, "Upgrading
a release install", has the details and the refusals). It finds the one
release install on the host (or the one `--upgrade DIR` names) and:

1. checks, changing nothing, which install it acts on and that the
   running bridge, `.env` and the shell agree on the keys the data
   depends on (checked against the data in the stack's own bridge image);
2. pulls the new images while the old stack runs;
3. takes a files-only restore point, `.sigrift/snapshots/<time>-<version>-files/`:
   `.env`, the compose files, `VERSION`, `tls/` and the installer files;
4. copies the new installer into the install folder;
5. stops every container of the stack (the gateway has the database open
   too) and holds it: `docker-compose.yml` becomes a placeholder that
   declares no volume, the real files wait in `.sigrift/held/`;
6. `prechecks`: `PRAGMA quick_check` and a WAL checkpoint on the stopped
   database, read in the old bridge image; a failed check undoes the run;
7. `restore-point`: a full restore point of both volumes,
   `.sigrift/snapshots/<time>-<version>-full/` (or `SIGRIFT_SNAPSHOT_DIR`),
   every member hashed, sealed with a MAC; a failure (full disk, a file
   that still changes) undoes the run;
8. switches the compose file (regenerated from the new template when it
   is an unedited installer template, else its image tags), `VERSION` and
   `.env` (an existing `.env` is never replaced; a missing key is added
   only where nothing depends on it);
9. starts the bridge alone and waits while it migrates (at least 10
   minutes, longer while `Migration N applied` lines appear), then the
   gateway. When the new version never becomes healthy and took no data
   (checked live and again on the stopped data), the run rolls back to
   the restore point by itself (exit status 5);
10. checks the schema, the TOTP secrets, the audit chain, the newest
    detection and the RF summary fences against the values from before the
    stop, and writes its records.

Steps 4 to 10 run detached from the terminal and are journaled in
`.sigrift/journal.json`, so an upgrade that stopped (exit status 4) can
be resumed or, before the new bridge started, undone. Run these in the
install folder, in the release folder the upgrade was started from, or
anywhere with the install folder named (`--status DIR`):

```bash
bash install-release.sh --status   # where it stands
bash install-release.sh --resume   # run the remaining steps again
bash install-release.sh --abort    # files back from the restore point, old stack started
```

`--resume` and `--abort` act on the journal's own project on the Docker
daemon the upgrade ran on, whatever `COMPOSE_PROJECT_NAME` or
`COMPOSE_FILE` the shell exports, and refuse when this shell's docker
talks to another daemon.
An upgrade that is up but failed its checks is resumed (the checks run
again) or closed as it is with `--resume --accept`, which the host
record's history keeps as `accepted`.

**Restore points and rollback.** The full restore point leaves out
`backups/`, `exports/`, the `-shm` and the bridge's own `.pre-migration`
copy, which stays a second line of defence, not a backup.
`bash install-release.sh --rollback` restores it in this order: the
restore point is staged beside the live data (`.sigrift-restore-<id>/` in
each volume, every member checked), the stack is stopped and held, the
staged copy is checked again, the revocations made since (API keys,
client certificates, users, backup codes, webhooks, protocol keys; a CA
replaced since stays) are carried onto it, the rollback is recorded in the
restored audit chain, then the marker is written and the restored tree
swapped in by renames; the state before stays in `.sigrift-replaced-<id>/`
until `--rollback --finish` or the next upgrade. Only then are the files
restored, the images tagged and the marker removed; the held compose file
starts the restored version (`--pull never --force-recreate`). Passwords,
TOTP secrets and webhook secrets changed since are listed, not carried,
and need `--revert-credentials`.

**Restore marker.** `.sigrift-restore-incomplete` is written by
`install-release.sh --rollback` at the root of both volumes
(`bridge_secrets` first) immediately before the first rename of live
data, and removed (`bridge_data` last) once the swap, the files and the
images are done, before any container starts; an `--abort` of the
rollback writes it again while it reverses the swap. The content is the
installer's (JSON with the operation and its id); only its existence
counts, in either volume, even as a dangling symlink. While one exists,
`install-release.sh` and `scripts/quickstart.sh` refuse to start a stack
(`--status` reports it and the volume), and a bridge that knows the
marker refuses to start; the gateway does not check it, so never `docker
start` a container or run the held compose file by hand while it exists.
The installer creates and removes it; remove it by hand only if you
restored that volume yourself and know the restore is complete
(TROUBLESHOOTING.md, "A restore marker without a journal").

### Source Install Upgrade (scripts/quickstart.sh)

`git pull && scripts/quickstart.sh` in a checkout with data is a guarded
upgrade since v0.2.0 (QUICKSTART.md, "Restore points and rollback"): the
current images are tagged `sigrift-prev-<commit>`, the new ones are built
while the stack serves, and the stack is stopped and held while a full
restore point is taken; it includes `edge_data` (and `/opt/sigrift/pki`
when the PKI overlay is used). Quickstart does not roll back by itself:
`git checkout <commit> && scripts/quickstart.sh --rollback`.

### Docker Upgrade

These commands are for the stack built from source with `docker-compose.yml`
(`build:`, no `image:`). Run them in the directory that holds it, with the
same `-p` / `-f` options (or `COMPOSE_PROJECT_NAME` / `COMPOSE_FILE`) the
stack was started with. Compose names the images `<project>-bridge` and
`<project>-gateway` and the data volume `<project>_bridge_data` (the project
is the directory name unless set), so the commands ask compose for the
images and work in the volume through the bridge service, instead of
naming either. A stack that runs pinned registry images (`image:` set, as
`install-release.sh` does) is upgraded by its installer instead; see
[Release Install Upgrade](#release-install-upgrade-install-releasesh)
(step 2 below still copies its database) and, to go back,
[Docker Rollback](#docker-rollback).

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

A release install (one made with `install-release.sh`) rolls back with
`bash install-release.sh --rollback` instead, which applies the RF check
above by itself and restores both volumes from its restore point.

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

When migrations ran, `detections.db.pre-migration` now always exists: the
bridge does not migrate without it (unless
`BRIDGE_ALLOW_MIGRATION_WITHOUT_BACKUP=1` was set).

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

The `detections.db.pre-migration` a successful upgrade keeps (for 7 days,
while space allows) is the database as it was just before the migrations
ran: the database only. Use it instead of a manual backup only together
with the baselines and `keys.json` of that same moment, and never once an
RF summary row exists (the check above). It also still holds any protocol
decryption key revoked since: restoring it brings such a key back (revoke
it again).

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
- `GET /api/version` returns `api_version`, `server_version` (the API
  server's version, unchanged at 4.0.0 across releases), `release` (the
  image's release tag such as `v0.2.0`, `main-<sha12>` for a main build, or
  `dev` for any other build) and `supported_versions`. `/api/health` reports
  `release` too
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

New in v0.2.0:
- `BRIDGE_KEYSTORE_KEY` (new, optional, bridge only): the Fernet key that
  encrypts the protocol decryption keys saved in the database (see
  [Protocol decryption keys across upgrades](#protocol-decryption-keys-across-upgrades)).
  Bound to the data: never change or remove it once keys are saved.
- `BRIDGE_ALLOW_MIGRATION_WITHOUT_BACKUP` (new override): `1` lets the
  bridge migrate when it cannot make `detections.db.pre-migration`. For one
  upgrade only: `/api/health` warns while it is set.
- `SIGRIFT_RELEASE` (set in the image by the release workflows; do not set
  it by hand): the release `/api/version` reports.

### Protocol decryption keys across upgrades

With `BRIDGE_KEYSTORE_KEY` set, every key imported in Admin → Crypto Keys
(`POST /api/crypto/keys`) is saved in `detections.db` (table
`crypto_keys`), encrypted with it, and loaded again at every start, after
the built-in defaults and before any decode job, under the same `key_id`.
An upgrade, a restart or a move with `detections.db` plus `.env` therefore
keeps them. Revoking a key deletes its row (with `secure_delete`); copies
made before the revoke (the kept `.pre-migration`, backups) still hold it.
The built-in keys are never saved. `BRIDGE_KEYSTORE_KEY` must not repeat
`BRIDGE_MFA_KEY` or `BRIDGE_AUDIT_KEY`, which the gateway holds
(`/api/health` warns). Without the variable keys stay memory-only, as before, and are lost
at every restart.

A missing, invalid or different `BRIDGE_KEYSTORE_KEY` never deletes a row:
the saved keys stay in the database, unloaded, new imports stay
memory-only, and `/api/health` (`crypto_key_persistence`, a
`Protocol decryption keys: ...` warning) and the console's Crypto Keys tab
say why. Restore the value they were saved with and restart the bridge to
load them again. If that value is lost for good,
`python3 -m sigrift.bridge.storage.crypto_keys forget-unreadable --yes`
(in the bridge container) deletes the rows the current value cannot read;
restart and import those keys again. See INSTALL.md, "Protocol decryption
keys".

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
