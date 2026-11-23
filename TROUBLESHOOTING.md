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
