# Troubleshooting

Common first-run errors with fixes. If your problem isn't listed,
search the
[issue tracker](https://github.com/SigRift/SigRift/issues);
if still nothing, open a new issue with the `bug` label and include
your OS, Python/Rust versions, and the full error output.

---

## `docker compose build` fails with "failed to compute cache key: /src/sigrift/bridge/requirements.txt: not found"

The compose build context is the repo root (not any subdirectory). Run
`docker compose build` (or `scripts/quickstart.sh`) from the top of the
`SigRift` checkout, not from `src/sigrift/bridge/` or elsewhere:

```bash
cd SigRift                   # repo root — the directory containing docker-compose.yml
docker compose build
```

If the Dockerfile path itself is wrong (COPY line references a file at
the wrong location), that's a bug — please open an issue with the full
`docker compose build` output.

---

## `docker compose up` fails with "port already allocated"

The gateway's host port (default 8444) is in use. The bridge listens
only on the compose-internal network, so this only ever bites on the
gateway.

```bash
# See what's holding the port
sudo ss -tlnp | grep -E ':8444\s'
```

If you can kill the other process, do it. Otherwise pick a free
port — `docker-compose.yml:37-38` reads `"${UC_PORT:-8444}:8444"`,
so all you need is an env var:

```bash
echo 'UC_PORT=8544' >> .env
scripts/quickstart.sh        # re-run; picks up the new port
```

Then access `https://localhost:8544/`. Don't edit
`docker-compose.yml` directly — it's tracked, and `git pull` will
flag a conflict on every upgrade.

A **release install** (`install-release.sh`) is different: the port was
written into its `docker-compose.yml` when that file was generated
(`UC_PORT` at install time, 8444 by default). Change the gateway's
`ports:` entry there, then `docker compose up -d`. A second release
stack beside the first one needs `--new-instance` and its own port:
`UC_PORT=8544 bash install-release.sh --new-instance`. If the port clash
came from running the installer of a newly unpacked release, see
"A second, empty dashboard after unpacking a new release" below.

---

## install-release.sh says "this host already runs SigRift"

Before it changes anything, the release installer looks at the Docker
Compose labels of every container and volume on the host. Each of these
refusals exits with status 3, changes nothing and prints one next
command:

- **"this host runs 2 SigRift release installs"**: the run cannot tell
  which one to upgrade. Name it: `bash install-release.sh --upgrade
  /path/to/that/install`.
- **"already runs SigRift from a source checkout"**: a release install
  cannot upgrade a quickstart install (update that one with `git pull &&
  scripts/quickstart.sh` in its checkout). To run a release stack beside
  it on purpose, give it its own port: `UC_PORT=8454 bash
  install-release.sh --new-instance`.
- **"SigRift data whose install folder is not known"**: a stack was taken
  down with `docker compose down`, which removes the containers and the
  folder they name. Pass that folder (the one with its `.env` and
  `docker-compose.yml`): `--upgrade /path/to/that/folder`. A folder the
  data volume's record names counts only when that folder's own
  `.sigrift/install.json` has the same install id (the containers can
  write the volume, so the record alone is a hint, shown as "which does
  not confirm it").
- **"this folder has no data yet and this host already runs SigRift"**: a
  folder with a `.env` but no data of its own, beside another install. If
  you meant to upgrade that install, use `--upgrade` with its folder; a
  separate stack needs `--new-instance` and a free `UC_PORT`.
- **"… so this run does not upgrade it without being told"**: the one
  release install's folder does not belong to you (or root), someone
  else can change it, or it is inside Docker's own data folder. Check
  the folder, then name it: `--upgrade /path/to/that/folder`.
- **"this installer has no release version"**: an installer without a
  `VERSION` (a checkout's `scripts/install-release.sh`) would install the
  moving `:main` images, so it never upgrades an install by itself, also
  not one a shell's `COMPOSE_PROJECT_NAME` names. Name the version and
  the folder: `SIGRIFT_VERSION=vX.Y.Z bash install-release.sh --upgrade
  DIR`.
- **"pulls its images from ghcr.io/<account>/"**: the install's
  `docker-compose.yml` names another registry account than the one this
  run pulls from (`SIGRIFT_OWNER`, default `sigrift`). Set
  `SIGRIFT_OWNER` to that account to upgrade it with those images.

With exactly one release install on the host, `bash install-release.sh`
from a newly unpacked release upgrades it in place instead (INSTALL.md,
"Upgrading a release install").

---

## A second, empty dashboard after unpacking a new release (older installers)

The installer of v0.1.0, run in a newly unpacked release
folder, start a second stack: Docker Compose names a stack after its
folder, so the new folder gets new, empty volumes and a new `.env` with
new secrets. Its bridge starts with an empty database and asks for a new
admin; its gateway then fails on the port the old one holds (8444).
Nothing of the old install is changed: its data is still in the old
project's volumes.

Undo it in the **new** folder only, and never with `-v` in the old one:

```bash
cd /path/to/the/new/folder
docker compose down          # its containers; its empty volumes stay until you remove them
```

Then upgrade the old install with the current installer, which upgrades
it in place: run `bash install-release.sh` from the newly unpacked
release (or `--upgrade /path/to/the/old/install`). The empty volumes of
the second stack are named after the new folder (`docker volume ls`);
remove them with `docker volume rm` once you are sure which they are.

---

## "this folder's .env is not pinned" after renaming the install folder

Docker Compose names a stack's volumes after its project, which is the
folder name unless `.env` sets `COMPOSE_PROJECT_NAME`. The current
installers pin it in `.env` on their first run, so a renamed folder keeps
its data. A folder renamed **before** that has a project with no data.
When exactly one orphaned project matches (its volumes exist, no other
folder uses them, its last folder is known from its containers or its
volume record and is gone, and this folder's `.env` verifies its data:
the TOTP secrets, or the audit chain with a key from this `.env`), the
installer adopts it by itself and pins it. Otherwise it lists the
candidates and refuses; name the right one:

```bash
bash install-release.sh --adopt-project sigrift-v010
scripts/quickstart.sh --adopt-project sigrift   # a source checkout (also --adopt-project=NAME)
```

A stack taken down (`docker compose down`) before the rename leaves no
record of its folder, and a copy of that folder made since would look
exactly the same, so that case always needs the name. It still refuses
when this `.env` contradicts that project's data (its keys do not verify
it, or its record names another install). To start this folder with
empty data instead, use `--new-instance`.

Related refusals before anything changes:

- **"names a project with no data, but this folder's data is in project
  …"**: a `COMPOSE_PROJECT_NAME` left in your shell (from another stack)
  would start this folder on new, empty volumes. `unset
  COMPOSE_PROJECT_NAME` and run again, or add `--new-instance` for a
  separate stack on purpose.
- **"this folder's data could be in more than one Docker Compose
  project"**: containers of several projects were started from this
  folder. Name the one that is its own with `--adopt-project NAME`.
- **"… has data that this folder's .env does not match"**: the project
  the folder's name gives has data that this `.env` does not verify.
  Another install may have had this folder's name (name this folder's
  own project with `--adopt-project`), or `.env` lost the key the data
  was written with (look in `.env.bak.*~` and `.sigrift/snapshots/`).

A folder whose containers were started under another project name (a
`COMPOSE_PROJECT_NAME` exported at the time) needs nothing: the
installer finds the project in the containers' labels and pins it.

---

## A copied install folder

**"this folder is a copy of …"** or **"this folder and … address the same
Docker Compose project"**: both folders would drive one stack and its
data, and an upgrade from one would leave the other with old files on
migrated data. Run the installer on the original folder (the next
command names it). For a second install, unpack a release into a new
folder and use `--new-instance` with its own `UC_PORT`; do not copy an
install folder.

---

## The installer refuses an older release

**"vX is older than the installed vY"** or **"the vX bridge knows
database migrations up to N, but this install's database is at migration
M"**: a newer release can change the data one way, and an older bridge
refuses a database with a newer migration, so the installer never
installs an older release over it. To go back, restore the database copy
made before the upgrade first: INSTALL.md, "Upgrading a release install",
"Going back".

---

## quickstart.sh refuses before it changes anything

`scripts/quickstart.sh` runs the same checks as the release installer
before host preparation, prompts, certificates or models (exit status 3,
"Nothing was changed.", one next command):

- **"a fresh quickstart here would start a second, empty stack"**: this
  host already runs SigRift. Update that install in its own folder; for a
  separate stack on purpose, give it a free port: `UC_PORT=8454
  scripts/quickstart.sh --new-instance`.
- **"there is no .env here, but project … has data"**: the data needs the
  secrets that were in `.env`; new ones would lock users out. Put `.env`
  back from a backup (`ls -la .env.bak.*~`).
- A key that differs from the running bridge, or that does not verify the
  data: as in "The installer says a key differs from the running bridge"
  below; `scripts/quickstart.sh --keep-running-secrets` keeps the running
  values.
- A checkout renamed before the pin: `scripts/quickstart.sh
  --adopt-project NAME` (see above).

The flags `--new-instance`, `--adopt-project NAME` and
`--keep-running-secrets` combine with every mode except `--renew-tls`.

---

## The installer cannot read .env

**"exists but cannot be read as UTF-8 text"**: `.env` belongs to another
user (an earlier run with `sudo` makes it root's) or holds a byte that is
not UTF-8. Read as empty it would be planned as a new `.env`, so the run
stops instead. `ls -l .env` shows its owner: give it back to the user
who runs the installer (`sudo chown "$(id -u):$(id -g)" .env`), or fix
the byte. **".env is a symbolic link"**: an edit replaces the file by a
rename, which would replace the link, and a restore point keeps only the
link; replace the link with a copy of the file it points to.

---

## The installer says a key differs from the running bridge / no key matches the data

The keys in `.env` that the data depends on (`BRIDGE_MFA_KEY` encrypts
the TOTP secrets, `BRIDGE_AUDIT_KEY` signs the audit chain, and others)
must be the ones the data was written with. Before it changes anything,
the installer compares `.env`, your shell and the running bridge's
environment (values are never shown) and checks each candidate against
the data, in the stack's own bridge image:

- **"is set in your shell and differs from .env"**: docker compose would
  use the shell's value. `unset` it and run again.
- **"the running bridge uses a different … than .env, and the data needs
  the running one"**: `.env` was edited after the stack started, or the
  stack was started with a value from a shell. Keep the running values
  with `--keep-running-secrets` (written into `.env`, the previous text
  kept as `.env.bak.<time>~`).
- **"neither .env's … nor the running bridge's verifies this install's
  data"**: the right value is in neither place. Look in older copies:
  `ls -la .env.bak.*~ .sigrift/snapshots/` (restore points keep `.env`
  under `files/`).
- **".env has no BRIDGE_MFA_KEY, but N users' TOTP secrets are encrypted
  with one"**: a new key would lock those users out of MFA. Put the old
  value back from a backup and run again. With a database the installer
  cannot read (encrypted, or damaged) it refuses the same way, since it
  cannot tell whether such secrets exist.
- **".env's BRIDGE_MFA_KEY does not verify this install's N TOTP
  secrets, and no running bridge has one that does"** (or the same for
  the audit key): the stack is down or runs with the same wrong value,
  and starting the new release with it would migrate the data first and
  fail its checks afterwards. Find the value the data was written with in
  older copies, as above.
- **"the bridge and the gateway run with different … values"**: the
  next command depends on which value the data verifies: the bridge's
  (`--keep-running-secrets` writes it into `.env` and the start gives it
  to both), or `.env`'s (`docker compose up -d --force-recreate`).
- **".env has no … and only your shell sets one"**: a value the installer
  cannot check against the data (a key for stored protocol keys,
  backups or an encrypted database) is never written into `.env` from a
  shell. If it is the right one, add it to `.env` yourself; otherwise
  `unset` it.

A key missing from `.env` that the running bridge still has is put back
by itself when the data shows it is the right one, or when nothing can
check it (the running bridge uses it).

---

## docker compose up prints "SigRift is mid-upgrade"

`docker-compose.yml` is the installer's placeholder (its first line is
`# SigRift hold stub`): an upgrade stopped the stack, and the real
compose files are in `.sigrift/held/`. The placeholder starts nothing
that touches the data, so a reboot or a plain `docker compose up` during
an upgrade cannot damage it. Do not edit or delete it; ask the installer
where the upgrade stands:

```bash
bash install-release.sh --status
```

---

## An upgrade was interrupted

An upgrade journals its steps in `.sigrift/journal.json`; its output is
in `.sigrift/logs/upgrade-<time>.log`. It goes on when the terminal
closes. When it stops (exit status 4: the new bridge did not become
healthy, a check failed after the start, the power went), `--status`
says at which step and what to run:

- `bash install-release.sh --resume` runs the remaining steps again;
  each is safe to repeat. A plain re-run to the same version does the
  same.
- `bash install-release.sh --abort` (try `--abort --dry-run` first) puts
  the held files and every file of the restore point back and starts the
  old containers again as they were. It refuses once the new bridge has
  started: that bridge may have migrated the database, which the old
  release cannot read. Then fix the cause (`docker compose logs
  --tail=50 bridge`) and resume. It also refuses, changing nothing, a
  restore point that is incomplete or damaged, and a database that a
  newer bridge has already migrated (one started by hand).
- **"is up, but a check failed"** (the journal says `verify_failed`):
  `--resume` runs the checks again. Once you have looked at what failed,
  `bash install-release.sh --resume --accept` closes the upgrade as it
  is (the host record's history says `accepted`).

These work in the install folder, in the release folder the upgrade was
started from (it finds the install), or with the install folder named:
`bash install-release.sh --status /path/to/the/install`. The install
folder may still hold the older installer, which has none of them; the
new release's does. `--resume` and `--abort` act on the journal's project
whatever `COMPOSE_PROJECT_NAME` your shell exports. **"this shell's docker talks
to another Docker daemon"**: `DOCKER_HOST` or the Docker context points
elsewhere than where the stack runs; `docker context ls` shows which.

A run that finds another one still working on the folder refuses with
"another installer run is working on"; follow that one's log instead.
A cron `--renew-tls` waits for the next run while an upgrade has the
stack stopped or is still running, says so on stderr, and fails (exit
status 1) once the certificate expires within 7 days.

A `.sigrift-restore-incomplete` marker at the root of the `bridge_data`
or `bridge_secrets` volume (reported by `--status`) means a restore was
interrupted and the data is half restored. The installers refuse to
start a stack on it, and so does the bridge. The installer creates and
removes it: resume the operation that wrote it, or restore again; remove
it by hand only if you restored that volume yourself and know the
restore is complete.

---

## `docker compose up` fails with "Pool overlaps with other one on this address space"

The gateway <-> bridge `backend` network has a fixed subnet (default
`10.203.84.0/28`), and another docker network on this host already uses
an overlapping one — typically a second SigRift stack (a second clone,
a release install next to a quickstart). Re-run the installer
(`scripts/quickstart.sh` or `bash install-release.sh`): it picks a free
`/28` and records it in `.env`. By hand, give this stack its own subnet
in `.env`, all three together:

```bash
docker network inspect $(docker network ls -q) \
    --format '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}'   # what is taken
cat >> .env <<'ENV'
SIGRIFT_BACKEND_SUBNET=10.203.84.16/28
SIGRIFT_BACKEND_IP_RANGE=10.203.84.24/29
SIGRIFT_GATEWAY_BACKEND_IP=10.203.84.18
ENV
docker compose up -d
```

The gateway address must be inside the subnet and outside the range.

---

## Bridge stays "unhealthy" / every API call returns 403 "Direct access denied — use the Rust gateway"

`UC_PROXY_SECRET` is empty (or the old public default). The bridge runs
with `BRIDGE_REQUIRE_PROXY=true` in the shipped `docker-compose.yml`, in
development mode too, and refuses every request without the gateway's
secret; its healthcheck reports it unhealthy so the gateway does not
start (`docker compose up` ends with "dependency failed to start").
`docker inspect --format '{{json .State.Health}}' <bridge container>`
shows `UC_PROXY_SECRET is empty`. Generate one and start the stack again
(the same value reaches the gateway):

```bash
echo "UC_PROXY_SECRET=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" >> .env
docker compose up -d
```

---

## Gateway logs: "FATAL: production mode requires a strong UC_PROXY_SECRET"

(Or the bridge logs: `BRIDGE_MASTER_KEY env var is required when
BRIDGE_ENV=production`.)

You're running `BRIDGE_ENV=production` without secrets configured.
Generate all four and put them in `.env`. `BRIDGE_MFA_KEY` must be a
Fernet key (urlsafe-base64 of 32 bytes); the other three are random
tokens:

```bash
echo "BRIDGE_MFA_KEY=$(python3 -c 'import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())')" >> .env
for v in BRIDGE_AUDIT_KEY BRIDGE_MASTER_KEY UC_PROXY_SECRET; do
  echo "$v=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
done >> .env
```

The gateway reads the same `BRIDGE_AUDIT_KEY` / `BRIDGE_MFA_KEY` /
`UC_PROXY_SECRET` (the shipped `docker-compose.yml` passes them to both
services; `BRIDGE_MASTER_KEY` goes to the bridge only) and, in
production, refuses to start without `BRIDGE_AUDIT_KEY` or with a
`BRIDGE_MFA_KEY` that isn't a valid Fernet key (44 characters: 43
base64, then `=`). If the key is 43 characters long, append `=` to keep
existing encrypted TOTP secrets readable — don't generate a new one; see
INSTALL.md "Upgrade note: `BRIDGE_MFA_KEY`".

`BRIDGE_MASTER_KEY` is the master API key the bridge registers on
first boot (`src/sigrift/bridge/app.py`, the `BRIDGE_MASTER_KEY env
var is required when BRIDGE_ENV=production` guard). Missing it in
production aborts startup the same way a weak `UC_PROXY_SECRET`
does.

Or, for a dev machine you're just evaluating on: set `BRIDGE_ENV=test`
or `BRIDGE_ENV=development` — the bridge will auto-generate weak
secrets and warn loudly. `UC_PROXY_SECRET` is the exception: with the
shipped `docker-compose.yml` it is required in every mode (see the
"Direct access denied" entry above).

---

## Bridge logs: "Keys file not found — all requests will be rejected"

The bridge can't read `data/keys.json`. Either the path is wrong
(`UC_KEYS_PATH` env var) or the file doesn't exist yet. The first
API key is created from the dashboard once you log in; there's no
pre-seed.

Steps:
1. Log in to the dashboard as `admin` (password printed on first boot).
2. Go to **Admin → API Keys → New Key** (the "Admin" link is in the dashboard header, top-right).
3. Copy the value (shown only once) and put it in your edge agent's
   config or the `X-API-Key` header.

---

## Key changes return 503 "Key change could not be saved" / bridge logs "Refusing to start: … must be saved to …/keys.json"

The bridge cannot write `data/keys.json`: the disk is full (a Pi's SD
card, often) or the data volume is mounted read-only. The gateway and
the other bridge workers read `keys.json`, so the bridge refuses a key
change it cannot save instead of keeping it in memory:

- **Creating, rotating, re-roling or binding a key:** 503 `Key change
  could not be saved; try again`. Nothing changed.
- **Revoking or downgrading a key:** 503 `Key change applied on this
  worker only: …`. That worker no longer accepts the key (or its old
  role), but the gateway and the other workers still do until a save
  succeeds. The audit log records the change with
  `"pending": "not yet saved"`. Once the disk is fixed, repeat the
  request (or wait for the next periodic save): the repeat answers 200
  and is audited as usual. If another worker revoked or rotated the key
  in the meantime, that change stands: the pending downgrade never
  brings a revoked key or an old credential back.
- **A node key's first heartbeat or batch** (the first-use binding, also
  for a legacy key named after its node): 500 from the bridge, 503
  through the gateway. The node retries and is bound once `keys.json`
  can be written.
- **Startup:** the bridge refuses to start (a CRITICAL log line naming
  `keys.json`) when it must save the initial master key, re-sync
  `BRIDGE_MASTER_KEY` or register `BRIDGE_LOCAL_NODE_KEY`. A legacy
  `node_local_edge` duplicate it cannot remove is only logged.

A read-only data directory without `data/.persistence.lock` refuses
every key change the same way (503, nothing changed).

Steps:
1. Check free space and the mount: `df -h` and `mount` (look for `ro`)
   on the host or in the bridge container.
2. Check ownership: `ls -ln data/` — `keys.json` and the directory must
   be writable by the bridge's UID.
3. Repeat the refused request, and restart the bridge if it refused to
   start.

---

## Anomaly autoencoder: "No module named 'torch'"

`requirements.txt` does **not** contain PyTorch: the CPU wheel lives on
the PyTorch index, and mixing two indexes in one `pip install` lets pip
take a same-named package from either. The bridge imports torch
(`sigrift.lib.taxonomy`), so a source checkout installs it in a second
step, from that index only, exactly as the Dockerfile does — hash-checked,
and without its dependencies (they are already in `requirements.txt`):

```bash
pip install --require-hashes --no-deps \
    -r src/sigrift/bridge/requirements-torch-cpu.txt
```

(The file names the PyTorch CPU index itself.) PyTorch wheels are
large, so on a slow or metered connection consider caching it once
with `pip download --no-deps --require-hashes -d wheelhouse/
-r src/sigrift/bridge/requirements-torch-cpu.txt`.

---

## "ModuleNotFoundError: No module named 'sigrift_sentinel'" in logs

The bridge is trying to load the commercial `sigrift-sentinel`
plugin. This is benign on community installs — it's logged at DEBUG
level only, and the runtime falls back to the null provider for that
feature (returns 402 / 404 on the affected endpoint).

You only need sigrift-sentinel if you're running the commercial
edition. Community users can safely ignore this message.

---

## Browser: "Your connection is not private" / self-signed cert

Expected on the default docker-compose setup. The gateway ships with
a self-signed certificate for localhost testing. Click "Advanced" →
"Proceed to localhost (unsafe)" in Chrome / Firefox / Safari.

For anything other than a single-user lab, replace with a real cert:
Let's Encrypt via a front-end reverse proxy (nginx, Caddy, Traefik),
or your internal CA. See
[INSTALL.md §"Advanced: distributed deployment"](INSTALL.md#advanced-distributed-deployment)
for the production posture (real TLS, `UC_HOST=0.0.0.0`, secrets
generation).

---

## `rtl_sdr: usb_claim_interface error -6`

The RTL-SDR kernel driver is still bound. Unbind it:

```bash
sudo rmmod dvb_usb_rtl28xxu rtl2832 rtl2830 2>/dev/null || true

# Make it permanent:
echo 'blacklist dvb_usb_rtl28xxu' | sudo tee /etc/modprobe.d/blacklist-rtl.conf
echo 'blacklist rtl2832'           | sudo tee -a /etc/modprobe.d/blacklist-rtl.conf
echo 'blacklist rtl2830'           | sudo tee -a /etc/modprobe.d/blacklist-rtl.conf
```

Unplug and re-plug the dongle after the blacklist.

---

## HackRF: "libusb error: LIBUSB_ERROR_BUSY" / "no permission"

Two common causes.

1. **Another process has it open** — `gqrx`, `inspectrum`, another
   SigRift agent. Stop it.
2. **Permission denied (no udev rule)** — install the HackRF udev
   rules and add your user to the `plugdev` group:
   ```bash
   sudo apt install hackrf      # installs udev rules on Debian/Ubuntu
   sudo usermod -aG plugdev $USER
   # Log out and back in for the group change to take effect.
   ```

---

## Edge agent: "Failed to connect to gateway: SSL: CERTIFICATE_VERIFY_FAILED"

Self-signed cert on the gateway. Edge agents always verify TLS: against
`MLRF_CA_CERT` (or `MLRF_CA_BUNDLE`) when set, otherwise against the
system trust store — which doesn't know a self-signed cert. Options:

1. **Normal fix:** copy the gateway's `cert.pem` (or the CA that issued
   it) to the edge node and set
   `MLRF_CA_CERT=/etc/ssl/certs/sigrift-ca.pem` in the agent's
   environment. For the in-stack compose services this is wired by the
   quickstart override (`./tls/cert.pem` mounted at
   `/app/tls/cert.pem`); if you
   hand-edited `docker-compose.override.yml`, add the same mount +
   `MLRF_CA_CERT=/app/tls/cert.pem` for `edge`, `scan`, `wifi-scan` and
   `bt-scan`.
2. Still failing with the right CA (`certificate is not valid for
   '<host>'`, `IP address mismatch`)? The cert's subjectAltName must
   cover the exact name or IP the agent dials: `DNS:gateway` for
   `edge`/`scan`, `IP:127.0.0.1` for the host-network
   `wifi-scan`/`bt-scan`, and for a remote node the host name or IP in
   its `--api-url`. Check with
   `openssl x509 -in tls/cert.pem -noout -ext subjectAltName`. Certs from
   older installers list only `localhost` (and `gateway`/`bridge`):
   re-run `scripts/quickstart.sh` / `install-release.sh` (add extra
   names with `SIGRIFT_TLS_SANS=name,ip`), which regenerates the cert,
   then copy the new `cert.pem` to the edge node — see INSTALL.md
   "Gateway certificate for remote edge nodes" (or TAILSCALE.md
   "TLS cert SAN", option (b), for a manual cert).
3. **Throwaway dev/test labs only:** `MLRF_INSECURE_TLS=1` explicitly
   disables verification (the agent logs a warning). Never set it
   across an untrusted network hop or in any committed config.

---

## Edge agent: 403 "Client certificate '…' may only submit batches for node '…'"

(From the bridge's node routes — heartbeats, WiFi / BT ingest:
`Client certificate '…' may only act for node '…', not '…'`.)

The agent presents an mTLS client certificate (`MLRF_CLIENT_CERT`)
whose identity is not its node id. A `node` certificate acts only for
the node whose `MLRF_NODE_ID` equals its identity, and an agent with a
certificate loaded sends no API key, so nothing falls back. Certificates
minted one per agent (`wifi-scan`, `bt-scan`, `local-edge` on a node
called something else), as older docs suggested, hit this after the
upgrade. Issue one certificate for the node — `POST /api/ca/issue` with
`{"identity": "<MLRF_NODE_ID>", "role": "node"}`, or
`scripts/pki_bootstrap.py <node id>:node` — mount it into every agent of
that node, and revoke the old ones; or unset `MLRF_CLIENT_CERT` /
`MLRF_CLIENT_KEY` to go back to the node's API key. See
PKI_ARCHITECTURE.md, "Upgrading from per-agent certificates".

---

## Edge agent: 403 "Node '…' already has a bound API key" / "API key is bound to …" / "Node endpoints require a node API key"

API keys act for one node (SECURITY.md, "API Keys"):

- **`Node '<node>' already has a bound API key; an admin must bind this
  key to it explicitly`** (or the bridge's `… node already has a bound
  key …`): another key already claimed this node. Use that node's
  existing key for all of its agents, or have an admin create the extra
  key with `"node_id": "<node>"`.
- **`API key is bound to a different node`** / **`API key … is bound to
  node …`**: this key was bound to another node by its first report. Give
  each node its own key; check `MLRF_NODE_ID` if the node id changed.
- **`Node endpoints require a node API key`**: the key has the `viewer`
  role (or it is a dashboard login session below `analyst`). Agents need
  a key with the `node` role.
- **503 `Node binding is unavailable; try again later`**: the gateway
  could not reach the bridge to record the binding of a new key; check
  `docker compose logs bridge`.

`BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1` (bridge and gateway) leaves node keys
unbound, as older versions did; it does not change certificates, and a
`viewer` key is still refused.

---

## Detections arrive but no alerts, webhooks or decoded messages

Alert rules, watch bands, webhooks, edge-decoded messages and
`protocol_decode` jobs for the batches the gateway ingests run in the
bridge, a moment after the batch is stored (`alerts_created` in the
ingest response is always `0`). `curl -sk https://127.0.0.1:8444/health`
shows the hand-over counters under `post_ingest_hooks`:

- `"enabled": false`, `hooks_disabled` growing, and an error in
  `docker compose logs gateway` at start-up naming `UC_PROXY_SECRET`:
  the gateway has no usable proxy secret (empty, or the old default
  `uppercrust-internal`; allowed in development only), and the bridge
  refuses the hand-over without it. Set the same strong
  `UC_PROXY_SECRET` for both services and restart them.
- `failed_*` growing (and `Post-ingest hook failed after retries —
  dropped` in `docker compose logs gateway`): the bridge refused a
  hand-over, or did not take it in 3 attempts (0.5 s, then 1 s apart)
  because it was down, restarting or failing — `docker compose restart
  bridge`, a crash, an upgrade that recreated the bridge while the
  gateway kept running. Those hand-overs are **dropped, not spooled**
  (only a gateway stop spools), so their detections stay without
  alerts, webhooks and decode jobs; see `docker compose logs bridge`.
- `dropped_*` growing: the queue (10 000 detections or 64 MiB) was
  full, and the oldest batches in it were dropped.
- `restored_*` after a restart: hand-overs the gateway spooled at its
  last graceful stop (`gateway-post-ingest-hooks.spool` in its data
  directory) and sent again; the bridge ignores detections it has
  already handled.

---

## "database is locked" errors in logs

SQLite WAL mode handles most concurrent access, but very write-heavy
workloads (50+ edge nodes pushing detections simultaneously) can
still contend. Mitigations:

1. Increase `UC_SQLITE_BUSY_TIMEOUT` (ms) — default is 5000.
2. Run the bridge with a dedicated disk (not over NFS, not on a USB
   thumbdrive).
3. Migrate to PostgreSQL — planned for a future release.

---

## Admin password lost

The auto-generated admin password is written to
`/tmp/sigrift-admin-pw` (mode 0600) inside the bridge container on
first boot, then auto-deleted after 60 s. If you missed that window,
two ways to recover:

**Option A — set a new password directly in the bridge container**
(preferred; keeps users, API keys, detections, audit log). Note that
`BRIDGE_ADMIN_PASSWORD` only seeds the admin account when the users
table is empty — once the account exists, changing the env var and
restarting does nothing. Instead, write the new password through the
bridge's own storage layer:

```bash
read -r -s -p "New admin password: " NEW_ADMIN_PW; echo
export NEW_ADMIN_PW
docker compose exec -e NEW_ADMIN_PW bridge python3 -c '
import os
from sigrift.bridge.detection_store import DetectionStore
ok = DetectionStore().users.set_password("admin", os.environ["NEW_ADMIN_PW"])
print("password updated" if ok else "ERROR: user admin not found")
'
unset NEW_ADMIN_PW
```

The change takes effect on the next login — no restart needed.
Existing sessions stay valid; force-logout from the admin panel if
you suspect the old password was compromised.

**Option B — full reset** (loses all bridge state — users, API keys,
detections, audit log):

```bash
docker compose down -v   # wipes the bridge_data volume
docker compose up -d     # first-boot path runs again
```

If `BRIDGE_ADMIN_PASSWORD` is set in `.env` (the quickstart script
writes it there), the re-seeded admin account uses that password. If
it isn't set, a production bridge (the default `BRIDGE_ENV`) refuses
to start until it is. Only outside production does the bridge
auto-generate one and write it to `/tmp/sigrift-admin-pw`
(auto-deleted after 60 s):

```bash
docker compose exec bridge cat /tmp/sigrift-admin-pw
```

If you're running from source instead of Docker, run the Option A
snippet directly on the host (inside the project venv, with
`PYTHONPATH=src` and `NEW_ADMIN_PW` exported) — it writes to the same
`data/detections.db` the bridge process uses.

---

## "sigrift_sentinel.storage.fuzz_sessions — licensed but sentinel not installed"

Community edition doesn't ship the fuzz subsystem. Either:

- You configured a licence-tier flag that grants `PROTOCOL_FUZZING`
  but didn't install the commercial package. If so, install
  `sigrift-sentinel` from the commercial distribution channel, or
  unset the flag.
- You meant to run the community edition — ignore the log line. It's
  informational only.

---

## Everything scores anomalous after moving the sensor

The anomaly baselines were learned at the old site, so the new site's
normal traffic looks novel. Three ways out, least to most surgical:

1. **Reset and relearn** — `POST /api/admin/baselines/reset` (ADMIN
   role; `?target=rf|wifi|bt|all`, default `all`). The scorer goes
   back into learning mode (~300 detections per frequency bin before
   scores are undampened).
2. **Apply a synthetic preset** — skips the cold start:
   `POST /api/admin/presets/{profile}/apply` with one of
   `urban-dense`, `suburban-residential`, `rural-quiet`,
   `office-commercial`. Returns `409` if it would replace more than
   1000 learned RF detections — export first, then retry with
   `?force=true`.
3. **Import a prior export** — if you have a bundle exported at the
   new site before (e.g. from a previous install there),
   `POST /api/admin/baselines/import` restores it. See
   [INSTALL.md §"Backup, restore, and migration"](INSTALL.md#backup-restore-and-migration-learned-state-bundles).

---

## Edge node relearns its baselines after every reboot

The edge scanner only persists learned anomaly baselines when
`MLRF_DATA_DIR` points at a writable directory; unset, it relearns
from zero on every restart.

- **Docker compose:** the stock `docker-compose.yml` already sets
  `MLRF_DATA_DIR=/app/data` on the `edge` service, backed by the
  `edge_data` volume. If you copied an older compose file, add both.
- **systemd installs:** the unit sets
  `MLRF_DATA_DIR=/var/lib/sigrift-edge` and
  `StateDirectory=sigrift-edge` (systemd creates and chowns the
  directory for the service user). Add the same two lines to a
  hand-rolled unit.

---

## Bundle import rejected with HTTP 422

`POST /api/admin/baselines/import` validates before it applies
(`dry_run` defaults to true) and rejects a bad bundle with a
per-check report naming the member, the failed check, and the fix.
The common checks:

| Check | Cause | Fix |
|---|---|---|
| `sha256` | Member content doesn't match the manifest digest — truncated download or hand-edited archive. | Re-download or re-export; don't edit a bundle in place. |
| `archive_safety` | Unsafe tar member: absolute path, `..`, symlink/hardlink/device, or a duplicate name. | The file wasn't produced by SigRift tooling — re-export with `POST /api/admin/baselines/export` or the CLI. |
| `member_size` | A member's declared uncompressed size exceeds the bundle ceiling — a decompression-bomb guard, checked before the payload is ever read. | Re-export; if the learned state is genuinely that large, export fewer `components` per bundle. |
| `taxonomy_overlap` | Fewer than 50 % of the bundle's signal classes exist in the running model — usually a different classifier model or SigRift version. | Re-export from a matching install, or retry with `?force=true` if the mismatch is intentional. |
| `preset_forbidden` | A `kind: preset` bundle carries MAC-keyed members presets may never contain (`wifi_baselines`, `bt_baselines`). | It's an export mislabelled as a preset — import it as an export, or regenerate the preset. |
| `finite` | NaN/Infinity or absurdly large floats in a component. | Corrupt serialization — re-export from a healthy bridge. |
| `schema_version` | The bundle's schema is newer than this build supports. | Upgrade SigRift, or re-export from a version matching this one. |

Member-scoped checks are prefixed with the file name in the report
(e.g. `rf_baselines.json sha256`). To pre-flight a bundle offline:
`python -m sigrift.bridge.bundles validate BUNDLE` (non-zero exit on
failure). Full check list:
[docs/bundle-format.md](docs/bundle-format.md).

---

## Preset applied but power/SNR scores look off at first

Expected. A preset's power/SNR levels are synthetic, so your
receiver's absolute levels differ. The baseline EWMAs re-adapt with a
~100-sample half-life, and preset variance ships pre-widened
(default ×1.5) precisely so those first z-scores don't trip false
anomalies. It settles on its own as real detections flow — no action
needed unless it persists well past a few hundred detections per
active frequency bin.

---

## More help

- Search and file issues: https://github.com/SigRift/SigRift/issues
- Security-sensitive reports: see [SECURITY.md](SECURITY.md) — do
  **not** file a public issue for suspected vulnerabilities.
- Questions, including commercial / enterprise deployment support:
  https://github.com/SigRift/SigRift/discussions
