# Install SigRift (community edition)

Start with a single-host dashboard: the Rust gateway, Python bridge,
and node-heartbeat agent, with scanner hardware and model downloads
inactive. Run `scripts/quickstart.sh --dashboard-only` from a source
checkout, then [enable hardware later](QUICKSTART.md#enable-hardware-later)
when needed. This is the path for evaluating SigRift or running a lab bench. See
[Advanced: distributed deployment](#advanced-distributed-deployment)
at the end of this document if you need multiple scanning nodes
talking to a central server.

If you run into trouble, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

Before you install, read [LEGAL.md](LEGAL.md) — installation and use
constitute acceptance of the acceptable-use terms.

---

## Prerequisites

| Component | Minimum | Recommended |
|---|---|---|
| OS | Linux kernel 5.10+ | Ubuntu 24.04 LTS / Debian 12 |
| Python | 3.11 | 3.12 |
| Rust (from source only) | 1.95 stable | 1.97 stable (what CI uses) |
| SQLite | 3.35+ | 3.45+ |
| Docker (quickstart path) | 24.0 | 28.0+, 28.3.3+ with firewalld (older engines let hosts on the same network segment reach ports published on `127.0.0.1`) |
| RAM | 4 GB | 8 GB |
| Disk | 20 GB | 100 GB (for IQ / PCAP capture) |

Community builds run on Ubuntu, Debian, Fedora, Arch, macOS, and
WSL2. Raspberry Pi 4/5 is supported for the combined single-host
install; smaller boards (Pi Zero 2 W) work for edge-only roles.

---

## Hardware support

For a single-host install you need one SDR if you want live scanning
(skip this table for a dashboard-only installation).

Physical capture was validated in 24-hour soaks on a Raspberry Pi 5 with an RTL-SDR Blog V4 and a USB Wi-Fi adapter in monitor mode; other receivers and hosts are untested.

In the table, **soak-validated** means used in those soaks.
**Supported, not soak-validated** means the code supports it, but it has
not been validated on hardware. In the soaks the Pi's built-in Wi-Fi was
only the management link, not a capture radio; Wi-Fi capture used the
USB adapter.

| Device | Status | Notes |
|---|---|---|
| **RTL-SDR v3** | supported, not soak-validated | Default. `librtlsdr` recommended over `rtl_sdr` CLI fallback. |
| **RTL-SDR Blog V4** | soak-validated | Use `librtlsdr` ≥ 0.8 for the new tuner (R828D). |
| **HackRF One** | supported, not soak-validated | `hackrf_transfer` binary required at runtime. |
| **Airspy R2 / Mini** | not supported | No Airspy or SoapySDR backend in this release. |
| **USRP B200 / B210** | best effort | UHD driver with `pip install pyuhd`; manual install on Debian. Not in CI. |
| **USRP N3xx / X3xx** | untested | Expected to work via UHD. Confirm before relying on it. |
| **Raspberry Pi 4 (4 GB)** | supported, not soak-validated | Good for single-host labs with an RTL-SDR. |
| **Raspberry Pi 5** | soak-validated | Better for HackRF due to USB-3 throughput. |
| **Raspberry Pi Zero 2 W** | supported, not soak-validated | Single-band RTL-SDR only; no ML inference. |
| **Jetson Nano / Orin Nano** | supported, not soak-validated | If you want on-host classifier inference. |

If your hardware isn't on the list and you get it working, please
open an issue with the `hardware:` prefix — we'll add it.

### Host prerequisites (one-time, root/sudo)

For dashboard-only setup, install a running Docker Engine with the Compose
plugin, `python3` 3.11+, `openssl`, and `curl`; cloning the repository also
requires `git`. Quickstart checks the runtime tools and daemon access before
prompting or writing configuration. Host Rust and radio
drivers are not needed for the containerized dashboard build. See
[QUICKSTART.md prerequisites](QUICKSTART.md#prerequisites).

For supported local RTL-SDR/Wi-Fi capture, use the managed selection path in
[Enable hardware later](QUICKSTART.md#enable-hardware-later). On Debian/Ubuntu,
host `iw` and `iproute2` provide read-only Wi-Fi discovery; the distribution's
`rtl-sdr`/udev package provides the `plugdev` group and device rules. Install
those packages explicitly if discovery reports them missing.

Run `scripts/quickstart.sh --scanners=auto` to discover available devices. If
an RTL receiver needs preparation, review and run the single scoped command
printed by setup. It releases only that receiver's DVB interface and sets only
its USB node permissions; it does not blacklist drivers globally or change
Wi-Fi connectivity. Root preparation is never invoked automatically.

---

## What the stack runs

`docker-compose.yml` defines seven services. The recommended
`scripts/quickstart.sh --dashboard-only` starts only `bridge`, `gateway`
and `edge`; the four hardware services stay behind an inactive profile.
Plain retries retain that mode. A fresh unflagged `scripts/quickstart.sh`
auto-selects only ready supported devices, otherwise starting the three core
services. Saved scanner selections are revalidated on retry. See [Enable hardware later](QUICKSTART.md#enable-hardware-later)
for switching deliberately or choosing only the scanners you need.

| Service | What it does | Notes |
|---|---|---|
| `bridge` | FastAPI app — routers, storage, alerting, dashboard rendering. No host port (`expose: 8001`), and only on the internal `backend` network, which it shares with the gateway alone; with `BRIDGE_REQUIRE_PROXY=true` it answers only requests carrying the gateway's `UC_PROXY_SECRET` header. | Owns the `bridge_data` volume (shared with the gateway) and the `bridge_secrets` volume (the CA private key — mounted on the bridge only). |
| `gateway` | Rust TLS terminator + auth proxy. Publishes the dashboard on `${SIGRIFT_BIND:-127.0.0.1}:${UC_PORT:-8444}` — this machine only unless you set `SIGRIFT_BIND=0.0.0.0` (see [Who can reach the dashboard](#who-can-reach-the-dashboard)). | Validates `UC_PROXY_SECRET`; loads `UC_TLS_CERT` / `UC_TLS_KEY` from the bind-mounted `./tls/` dir. |
| `edge` | Node-heartbeat agent. Reports liveness + system metrics to the bridge so the dashboard shows the host as a live node. | Authenticates with `BRIDGE_LOCAL_NODE_KEY`. No SDR ingest in this service. |
| `rtl-tcp` | Owns the USB SDR and exposes it as a TCP stream on the compose-internal network (port 1234). | Mounts `/dev/bus/usb`; runs with `group_add: ["46"]` (plugdev gid on Debian / Ubuntu). |
| `scan` | Reads IQ from `rtl-tcp`, runs ONNX inference against `/app/models/open-default.onnx`, POSTs detections back to the gateway. | Crash-loops with a clear error if no model is mounted; the rest of the stack is unaffected. |
| `wifi-scan` | Puts a wlan interface (default `wlan1`) into monitor mode, channel-hops, captures 802.11 management and data frames (first 512 bytes), decodes beacons + probes, batch-POSTs to `/api/wifi/ingest`, and keeps the last 500 raw frames in memory; its pcap upload on a Wi-Fi anomaly is refused for the in-stack node key in this release ([LEGAL.md](LEGAL.md) §4, "Wi-Fi capture scope"). | **`network_mode: host` + `NET_ADMIN`/`NET_RAW`** (all other capabilities dropped) — see below. |
| `bt-scan` | Uses BlueZ over the host DBus to discover Classic + BLE devices, posts to `/api/bluetooth/ingest`. CVE-matches the on-host BlueZ version. | **`network_mode: host` + `NET_ADMIN`/`NET_RAW`** (all other capabilities dropped) — see below. |

### Privileged sidecars

`wifi-scan` and `bt-scan` are the only services that run with
elevated host privileges. The Rust gateway is unaffected — these
sidecars don't sit in the request path, they only push data
**into** the bridge via the same authenticated API that any remote
edge agent would use. Because they parse attacker-controlled
over-the-air frames, they are **not** `privileged`: each starts from
`cap_drop: [ALL]` and adds back only what it needs (no extra devices,
default seccomp/AppArmor profiles stay on).

- **`wifi-scan`** — `cap_add: [NET_ADMIN, NET_RAW, SETUID, SETGID]`:
  `NET_ADMIN` for `ip link` / `iw … set monitor` / channel hops,
  `NET_RAW` for tcpdump's capture socket, and `SETUID`/`SETGID` so
  Debian's tcpdump can drop from root to its `tcpdump` user after
  opening the socket. `network_mode: host` is required because
  monitor mode is a per-netns property: Docker's default bridge net
  hides the host's wlan interfaces from the container. Runs as root
  (overrides the Dockerfile's `appuser`) because non-root processes
  can't use the capabilities, with `no-new-privileges:true`.
- **`bt-scan`** — `cap_add: [NET_ADMIN, NET_RAW]` for the raw HCI
  socket; `network_mode: host` plus the `/var/run/dbus` bind-mount so
  BlueZ speaks to the host's system bus instead of needing its own.
  Runs as uid 1500; HCI access comes from the file capabilities the
  edge image sets on `hcitool`, which is why this service must *not*
  use `no-new-privileges` (it makes the kernel ignore file
  capabilities).

These capability sets are derived from what the scanners execute and
have not been validated on every adapter/driver. If one needs more,
add that specific capability or device in
`docker-compose.override.yml` rather than reverting to
`privileged: true`.

To opt out of either: edit `docker-compose.override.yml` and add
`profiles: ["disabled"]` to the service entry, then
`docker compose up -d` (compose will skip services in unmatched
profiles). The other services keep running.

---

## Quickstart (default, single-host)

From a fresh clone, build a dashboard without scanner hardware or a model:

```bash
git clone https://github.com/SigRift/SigRift.git
cd SigRift
scripts/quickstart.sh --dashboard-only
```

For a fresh production-mode install, use
`BRIDGE_ENV=production scripts/quickstart.sh --dashboard-only` instead.
The source quickstart builds local images; the [release installer](#verifying-a-release)
pulls the prebuilt application images of a published code release
(v0.1.0 and later); the release files are signed with cosign.

What the dashboard-only command does:

1. Checks `python3` 3.11+, `openssl`, `curl`, Docker Compose and access to
   the selected Docker daemon before prompts or writes. Docker probes have
   ten-second deadlines; it does not start or reconfigure the daemon.
2. Prompts twice for an admin password, then an environment preset. The
   password is written only to the local, gitignored `.env` (mode 0600),
   never to output or logs.
3. Generates `BRIDGE_MFA_KEY`, `BRIDGE_AUDIT_KEY`, `BRIDGE_MASTER_KEY`,
   `UC_PROXY_SECRET` and `BRIDGE_LOCAL_NODE_KEY`. It saves dashboard-only
   mode, the selected `BRIDGE_ENV` (`development` by default), and the
   bind address/port (`127.0.0.1:8444` by default). Set
   `SIGRIFT_BIND=0.0.0.0` on the fresh invocation for LAN access, and
   choose production mode with it (see
   [Who can reach the dashboard](#who-can-reach-the-dashboard)).
4. Generates self-signed TLS and creates `docker-compose.override.yml`
   only if absent. The certificate covers localhost, the host's names and
   addresses, and any `SIGRIFT_TLS_SANS`; see
   [Gateway certificate for remote edge nodes](#gateway-certificate-for-remote-edge-nodes).
   The private key is group 1500 and mode 0640. Reruns renew an expiring
   certificate or add missing required names, preserving existing names.
5. Keeps all four hardware services inactive and skips model discovery,
   downloads and model-permission changes. Existing model files are untouched.
   [Enable hardware later](QUICKSTART.md#enable-hardware-later) explains the
   device selection, optional preparation and model requirements.
6. Verifies exactly `bridge`, `gateway` and `edge` are active, builds
   those images, and normalizes the owned volumes for container uid 1500.
7. Starts the active services and waits up to **240 seconds** for gateway
   health, then retries dependent-service startup if needed. The first
   source build has its own host/network-dependent duration; this is not
   a cold-install time limit.
8. Checks health, version, admin login, identity and recent detections over
   HTTPS. Each request has a five-second connection/TLS deadline and a
   15-second total deadline. Failed checks exit nonzero with log/retry
   guidance; the success banner appears only after all checks pass.

Plain `scripts/quickstart.sh` retries retain the saved mode, credentials,
settings and existing override. Do not delete `.env` or data volumes to
retry a failed build. An explicit shell `BRIDGE_ENV` accepts `production`
or `development`; for an existing installation that override affects only
one invocation. To change the saved mode permanently, edit `BRIDGE_ENV`
in `.env` and run `docker compose up -d`. Existing overrides, including
old generated ones, are preserved byte-for-byte; custom changes must be
made explicitly.

When the script reports success, open its printed **Dashboard** URL in
your browser, accept the self-signed certificate, and log in as `admin`
with the password you just typed. `https://localhost:8444/` is the default
local address; custom bindings or ports use the verified printed endpoint. The dashboard will show zero
detections until you attach a scan source — see
[Adding an edge agent](#adding-an-edge-agent-same-host) below, or
[QUICKSTART.md §"Edge / SDR scanning"](QUICKSTART.md#edge--sdr-scanning)
for the in-stack scan path.

### If the quickstart fails

Three common reasons:

1. **Docker isn't running** — start Docker Desktop or
   `sudo systemctl start docker`.
2. **Port 8444 in use** — set `UC_PORT=8544` (or anything free) in
   `.env` and rerun.
3. **Gateway doesn't become healthy in 240 s** — look at
   `docker compose logs gateway` and `docker compose logs bridge`.
   The [Troubleshooting guide](TROUBLESHOOTING.md) covers the common
   cases.

### Stopping, resetting, upgrading

```bash
docker compose down           # stop services, preserve all state
docker compose down -v        # DESTRUCTIVE — see warning below
git pull && scripts/quickstart.sh   # pull updates and rebuild
```

**`docker compose down -v` wipes the `bridge_data` and
`bridge_secrets` volumes.** Both the bridge and gateway containers
mount `bridge_data`; `bridge_secrets` (bridge only) holds the embedded
CA's private key, so after `down -v` every client certificate the
bridge issued is useless. Removing them deletes everything stored there:

- `detections.db` — every captured detection, alert, correlation
- `keys.json` — every API key (you'll need to mint NODE keys again)
- `audit.key` (when running in dev mode without `BRIDGE_AUDIT_KEY`
  set) — the audit-chain HMAC key; the chain restarts from scratch
- Active sessions and user accounts (including admin), so the
  bridge will run its first-boot flow again on the next `up`
- Learned anomaly baselines (RF/WiFi/BT) and the signal whitelist —
  the statistics the scoring pipeline has built up since install

`-v` also removes the `edge_data` volume, where the in-stack `edge`
service persists its learned anomaly baselines
(`MLRF_DATA_DIR=/app/data` in `docker-compose.yml`). Standalone edge
installs persist theirs under the systemd unit's `StateDirectory`
(`MLRF_DATA_DIR=/var/lib/sigrift-edge`) and are unaffected by
compose teardowns.

Plain `docker compose down` (no `-v`) stops the containers but
preserves the volume — detections, keys, audit history, and
accounts all survive. Use `down -v` only when you genuinely want
a clean slate.

Before a deliberate `down -v`, export the learned state so the wipe
is recoverable:

```bash
# Export the learned baselines to a bundle, then download it
curl -fsk -X POST -H "X-API-Key: <ADMIN_KEY>" \
    https://localhost:8444/api/admin/baselines/export
curl -fsk -H "X-API-Key: <ADMIN_KEY>" -O \
    https://localhost:8444/api/admin/baselines/exports/<filename-from-response>
```

After the reset, either import that bundle back (see
[Backup, restore, and migration](#backup-restore-and-migration-learned-state-bundles))
or set `SIGRIFT_PRESET=<profile>` in `.env` to re-seed the fresh
stack with a synthetic environment preset on first boot.

### Forced password change

`BRIDGE_ENV` defaults to `production` (in `docker-compose.yml` and in
the bridge image). In production, a first boot without
`BRIDGE_ADMIN_PASSWORD` is refused: the bridge stops with
`BRIDGE_ADMIN_PASSWORD env var is required when BRIDGE_ENV=production
and no users exist.` Set it in `.env` (the quickstart script does) and
start again.

Outside production (for example `BRIDGE_ENV=development` in `.env` on
an evaluation machine), a first boot without `BRIDGE_ADMIN_PASSWORD`
— say a plain `docker compose up -d` — makes the bridge auto-generate
an admin password, write it to `/tmp/sigrift-admin-pw` inside the
bridge container (chmod 0600, auto-deleted after 60 s; read it with
`docker compose exec bridge cat /tmp/sigrift-admin-pw`), and
**flag the admin account so your first
login is restricted to the change-password endpoint**. You'll be
prompted to set a real password before anything else in the
dashboard works. The quickstart script avoids this dance by taking
your password up front.

---

## Alternative: from-source single-host

If you'd rather not use Docker — development, customisation,
Raspberry Pi where Docker is heavy — three processes in separate
terminals:

```bash
git clone https://github.com/SigRift/SigRift.git
cd SigRift
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
# Hash-checked locks (src/sigrift/bridge/requirements*.txt, generated by
# scripts/lock-requirements.sh): pip refuses any file whose sha256 is not
# in the lock. Torch comes from the PyTorch CPU index only, in its own
# step — never add that index as an --extra-index-url.
pip install --require-hashes -r src/sigrift/bridge/requirements.txt
pip install --require-hashes --no-deps \
    -r src/sigrift/bridge/requirements-torch-cpu.txt
cargo build --release -p sigrift-gateway

# Generate secrets once. BRIDGE_MFA_KEY must be a Fernet key
# (urlsafe-base64 of 32 bytes); the rest are random tokens.
echo "export BRIDGE_MFA_KEY=$(python3 -c 'import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())')" > .env.sh
for v in BRIDGE_AUDIT_KEY BRIDGE_MASTER_KEY UC_PROXY_SECRET; do
  echo "export $v=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
done >> .env.sh

# Also pick an admin password and export it yourself (not in .env.sh
# if you don't want it persisted to disk):
read -s -p "Admin password: " BRIDGE_ADMIN_PASSWORD; echo
export BRIDGE_ADMIN_PASSWORD
source .env.sh
```

Terminal 1 — Python bridge:
```bash
BRIDGE_ENV=development PYTHONPATH=src \
  python3 -m uvicorn sigrift.bridge.app:app \
    --host 127.0.0.1 --port 8001
```

Terminal 2 — Rust gateway (loopback only for a single-host install):
```bash
UC_HOST=127.0.0.1 UC_PORT=8444 \
UC_PYTHON_URL=http://127.0.0.1:8001 \
  ./target/release/sigrift-gateway
```

Browse to `http://127.0.0.1:8444/` and log in.

**Note — this serves plaintext HTTP.** Without `UC_TLS_CERT` /
`UC_TLS_KEY` set, the gateway logs `Listening (plaintext)` and
serves unencrypted HTTP. That's acceptable on loopback only. For
anything reachable beyond this host, generate a cert (the quickstart
script's `openssl req` invocation works — see `scripts/quickstart.sh`
— or use a real cert per
[Advanced: distributed deployment](#advanced-distributed-deployment))
and set both env vars before starting the gateway:

```bash
UC_TLS_CERT=$PWD/tls/cert.pem UC_TLS_KEY=$PWD/tls/key.pem \
UC_HOST=127.0.0.1 UC_PORT=8444 \
UC_PYTHON_URL=http://127.0.0.1:8001 \
  ./target/release/sigrift-gateway
# then browse to https://127.0.0.1:8444/
```

---

## Adding an edge agent (same host)

Once the central services are up, start a scan agent pointing at
them.

### With docker-compose quickstart

Create a one-off override that mounts the host USB bus:

```bash
# One-time: create an API key with the `node` role in the dashboard
#   Admin (top-right) -> API Keys -> role Node -> Create Key -> copy it
echo 'SIGRIFT_LOCAL_API_KEY=<paste>' >> .env

cat > docker-compose.localnode.yml <<'EOF'
services:
  local-node:
    # Build the edge image from this checkout, as scripts/quickstart.sh
    # does, so it matches the rest of the stack:
    build: { context: ., dockerfile: src/sigrift/edge/Dockerfile }
    depends_on: [gateway]
    entrypoint: >
      python3 src/sigrift/edge/node_agent.py
      --node-id local-01
      --api-url https://gateway:8444
      --api-key ${SIGRIFT_LOCAL_API_KEY}
    # The agent verifies the gateway's TLS cert — trust the quickstart's
    # self-signed one explicitly.
    volumes:
      - ./tls/cert.pem:/app/tls/cert.pem:ro
    environment:
      - MLRF_CA_CERT=/app/tls/cert.pem
    devices:
      - /dev/bus/usb:/dev/bus/usb
    group_add:
      - "46"      # plugdev GID on Debian/Ubuntu; verify with `getent group plugdev`
    restart: unless-stopped
EOF

# With -f, compose no longer loads docker-compose.override.yml by itself:
# name it too, so the stack keeps the quickstart's settings, and start
# only the new agent.
docker compose -f docker-compose.yml -f docker-compose.override.yml \
    -f docker-compose.localnode.yml up -d --no-deps local-node
```

### With the from-source install

```bash
source .venv/bin/activate
# Create an API key with the `node` role first (Admin -> API Keys).
# The agent verifies TLS: point it at the gateway's cert (or CA).
MLRF_CA_CERT=/path/to/gateway/cert.pem \
python3 src/sigrift/edge/node_agent.py \
    --node-id local-01 \
    --api-url https://127.0.0.1:8444 \
    --api-key <KEY>
```

Within a few seconds of the agent starting, live detections should
stream in to the dashboard.

---

## GPU / CUDA inference (optional, amd64)

The default images are CPU-only — they run anywhere (Raspberry Pi,
laptop, CI) and keep the image small. On an **amd64 host with an NVIDIA
GPU** you can build CUDA-accelerated images with a single build arg:

```bash
# bridge: CUDA torch for the anomaly autoencoder
docker compose build --build-arg ACCEL=cuda bridge
# edge/scan: onnxruntime-gpu for the RF classifier
docker compose build --build-arg ACCEL=cuda scan
```

What it does:

- **Bridge** installs the CUDA build of `torch`; the anomaly
  autoencoder already selects the GPU automatically when
  `torch.cuda.is_available()`.
- **Edge / scan** installs `onnxruntime-gpu`; the ONNX classifier
  requests `CUDAExecutionProvider` and falls back to CPU if the GPU
  runtime isn't present, so the same image still runs on CPU.

Requirements and caveats:

- **arm64 is always CPU.** No CUDA `torch`/`onnxruntime` wheels exist
  for `linux/aarch64`; `ACCEL=cuda` is ignored there and the CPU wheel
  is used.
- **CUDA / cuDNN versions:** the edge image pins `onnxruntime-gpu==1.26.0`,
  which requires **CUDA 12.\*** and **cuDNN 9.\*** on the host/runtime.
  The CUDA `torch==2.12.0` wheel bundles its own CUDA libs, so it only
  needs a compatible NVIDIA driver. If you run a `cuda`-built edge image
  on a host without those libs, it logs a CUDA-load error and falls back
  to CPU (harmless, but build the default CPU image for CPU hosts).
- **Runtime GPU access** is separate from the build. Install the
  [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html)
  on the host and give the containers the GPU — e.g. add to your
  compose override:
  ```yaml
  services:
    scan:
      deploy:
        resources:
          reservations:
            devices:
              - { driver: nvidia, count: all, capabilities: [gpu] }
  ```
  (or `docker run --gpus all` for a standalone container).
- Confirm it took: the scan log prints
  `providers=['CUDAExecutionProvider', 'CPUExecutionProvider']` and the
  bridge autoencoder logs `device=cuda` when a GPU is in use.

---

## Running as a service (systemd)

For a persistent single-host install, drop these units in
`/etc/systemd/system/` and run as a dedicated `sigrift` user.
Adjust paths.

`/etc/systemd/system/sigrift-bridge.service`:
```ini
[Unit]
Description=SigRift Python bridge
After=network.target

[Service]
Type=simple
User=sigrift
Group=sigrift
WorkingDirectory=/opt/sigrift
EnvironmentFile=/etc/sigrift/secrets.env
EnvironmentFile=/etc/sigrift/bridge-secrets.env
Environment=PYTHONPATH=/opt/sigrift/src
Environment=BRIDGE_ENV=production
# Only requests carrying the gateway's UC_PROXY_SECRET header.
Environment=BRIDGE_REQUIRE_PROXY=true
ExecStart=/opt/sigrift/.venv/bin/python -m uvicorn sigrift.bridge.app:app --host 127.0.0.1 --port 8001
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/sigrift-gateway.service`:
```ini
[Unit]
Description=SigRift Rust gateway
After=sigrift-bridge.service
Requires=sigrift-bridge.service

[Service]
Type=simple
User=sigrift
Group=sigrift
WorkingDirectory=/opt/sigrift
EnvironmentFile=/etc/sigrift/secrets.env
Environment=BRIDGE_ENV=production
Environment=UC_HOST=127.0.0.1
Environment=UC_PORT=8444
Environment=UC_PYTHON_URL=http://127.0.0.1:8001
ExecStart=/opt/sigrift/target/release/sigrift-gateway
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/sigrift-node@.service` (templated; one instance
per node id):
```ini
[Unit]
Description=SigRift edge node %i
After=sigrift-gateway.service
Requires=sigrift-gateway.service

[Service]
Type=simple
User=sigrift
Group=plugdev
WorkingDirectory=/opt/sigrift
EnvironmentFile=/etc/sigrift/node-%i.env
ExecStart=/opt/sigrift/.venv/bin/python src/sigrift/edge/node_agent.py --node-id %i --api-url https://127.0.0.1:8444 --api-key ${SIGRIFT_API_KEY}
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`/etc/sigrift/secrets.env` (root:sigrift 0640) holds what both units
share: `BRIDGE_AUDIT_KEY`, `BRIDGE_MFA_KEY` and `UC_PROXY_SECRET` (and
`BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1` if you use it: both services bind node
keys, see SECURITY.md "API Keys").
`/etc/sigrift/bridge-secrets.env` holds what only the bridge needs:
`BRIDGE_MASTER_KEY` (the admin API key) and `BRIDGE_ADMIN_PASSWORD`.
Keep them apart so the internet-facing gateway process never holds the
master key (see "Production secrets"). The bridge keeps its CA private
key in `BRIDGE_SECRETS_DIR` (default: `src/sigrift/bridge/secrets/`,
next to the data dir); the units above run both services as one user,
so to keep the key from the gateway run the bridge as its own user and
make that directory `0700` for it. Each
`/etc/sigrift/node-<id>.env` sets `SIGRIFT_API_KEY` and
`MLRF_CA_CERT=<path to the gateway's cert or CA>` (the agent verifies
TLS).

`sudo systemctl daemon-reload && sudo systemctl enable --now
sigrift-bridge sigrift-gateway sigrift-node@local-01`.

---

## Security considerations (single-host)

- **Loopback by default.** The compose files publish the gateway on
  `127.0.0.1` unless `SIGRIFT_BIND` says otherwise (see
  [Who can reach the dashboard](#who-can-reach-the-dashboard)); the
  systemd templates bind it with `UC_HOST=127.0.0.1`. (`UC_HOST` inside
  the gateway *container* stays `0.0.0.0` — that is the container's own
  interface; what the host exposes is the `ports:` mapping.) A
  single-host install usually doesn't need external access; if it
  does, set `SIGRIFT_BIND=0.0.0.0` explicitly and put a real TLS cert
  in front.
- **The bridge serves the gateway only.** It has no host port, sits on
  a compose network only the gateway shares, refuses requests without
  the gateway's `UC_PROXY_SECRET` header (`BRIDGE_REQUIRE_PROXY=true`)
  and trusts `X-Forwarded-For` from the gateway's fixed address only
  (`BRIDGE_TRUSTED_PROXIES`).
- **The CA private key is not in the gateway's volume.** The gateway
  mounts `bridge_data` (it needs `detections.db`, `keys.json` and the
  CA *certificate*); the CA private key lives in `bridge_secrets`,
  which only the bridge mounts.
- **Edge agents verify the gateway's TLS certificate.** They trust
  `MLRF_CA_CERT` (or `MLRF_CA_BUNDLE`) when set, otherwise the system
  trust store, so a self-signed gateway cert must be handed to them:
  copy the gateway's `cert.pem` (or your CA) to the edge node and set
  `MLRF_CA_CERT=/path/to/cert.pem`. The host name or IP the node
  dials must be in the certificate's subjectAltName — see
  [Gateway certificate for remote edge nodes](#gateway-certificate-for-remote-edge-nodes).
  The `docker-compose.override.yml` that the quickstart writes already
  does this for the in-stack scanners. `MLRF_INSECURE_TLS=1` disables
  verification — a dev-only escape hatch for throwaway lab setups; never
  use it across a network hop.
- **Admin password is never printed.** The quickstart script prompts
  once and writes straight into a 0600 `.env`. If you bypass the
  script (plain `docker compose up`) and don't set
  `BRIDGE_ADMIN_PASSWORD`, the bridge refuses to start in
  production (the default `BRIDGE_ENV`). Only outside production
  does it auto-generate one, write it to a 0600 file that
  auto-deletes in 60 s, and force you to rotate it before using the
  dashboard (see [Forced password change](#forced-password-change)).
- **Dashboard is behind auth.** Single-host or not, login with
  username + password is required. Turn on MFA for production use.
- **Single-host ≠ single-tenant.** Multiple accounts are supported;
  audit log is per-user.

### Verifying the install

```bash
curl -fsk https://127.0.0.1:8444/health
# -> "ok"

ss -tlnp | grep ":8444\|:8001"
# compose: expect 127.0.0.1:8444 (or 0.0.0.0:8444 with SIGRIFT_BIND=0.0.0.0)
# and nothing on :8001 — the bridge has no host port.
# from source / systemd: the bridge on 127.0.0.1:8001 (loopback only).
docker compose port gateway 8444   # what docker publishes, exactly
```

### Who can reach the dashboard

`docker-compose.yml` (and the one `install-release.sh` writes) publish
the gateway on `${SIGRIFT_BIND:-127.0.0.1}:${UC_PORT:-8444}`:

| `SIGRIFT_BIND` in `.env` | Reachable from |
|---|---|
| unset or `127.0.0.1` (default) | this machine only |
| `0.0.0.0` | every IPv4 interface: browsers on your network, remote edge nodes |
| one address of this host (`192.168.1.5`, or `[fd00::5]` for IPv6) | that address only |

Both installers take it from the environment on the first run
(`SIGRIFT_BIND=0.0.0.0 scripts/quickstart.sh`) and record it in `.env`;
later, edit `.env` and run `docker compose up -d`. The host-network
scanners (`wifi-scan`, `bt-scan`) talk to `https://127.0.0.1:${UC_PORT}`,
which the first two settings serve; publishing on one specific address
instead needs their `MLRF_BRIDGE_URL` changed too.

Before you open the dashboard beyond this machine, use production mode
(`BRIDGE_ENV=production` in `.env`, then `docker compose up -d`; the
release installer already uses it). Quickstart's default development
mode turns CSRF protection off and does not mark the session cookie
`Secure`. On Docker Engine before 28.0 the default is weaker than it
looks: hosts on the same local network segment can reach a port
published on `127.0.0.1`, so use Engine 28.0+ (28.3.3+ on hosts running
firewalld). A `ufw` rule does not help: Docker's published ports bypass it.

Do not use `[::]` (the installers refuse it): docker
publishes an IPv6 host address on IPv6 only, so neither IPv4 clients nor
the scanners could connect. To serve IPv6 as well, keep
`SIGRIFT_BIND=0.0.0.0` and add a second port entry for the gateway in
`docker-compose.override.yml`, which `docker compose` merges with the
main file:

```yaml
services:
  gateway:
    ports:
      - "[::]:8444:8444"   # host port: your UC_PORT
```

The quickstart preserves an existing override, including its generated
header; no marker needs removing before you edit it. Keep its other
settings and TLS mounts when adding an override entry.

A fresh quickstart defaults to `BRIDGE_ENV=development` (a lab install),
or saves an explicit `BRIDGE_ENV=production`. A fresh `install-release.sh`
install defaults to production. Existing `.env` files retain their saved
mode. Both print which
address and mode the running stack actually uses when they finish.

The internal `backend` network (gateway ↔ bridge) uses the fixed subnet
`10.203.84.0/28` with the gateway at `10.203.84.2`, so the bridge can
trust exactly that address. Docker gives every other container on that
network (the bridge) an address from its IP range, `10.203.84.8/29`,
only — so the bridge, which starts first, can never take the gateway's
address. The default subnet lies outside Docker's default address pools
(`172.17.0.0/16`–`172.31.0.0/16` and `192.168.0.0/16`), so networks
docker numbers by itself never take it. Docker refuses a second network
with an overlapping explicit subnet
(`Pool overlaps with other one on this address space`), though — a
second SigRift stack on the same host (another checkout, a release
install next to a quickstart) needs its own. `scripts/quickstart.sh`
and `install-release.sh` check before they start the stack: when the subnet overlaps
another docker network or a network this host routes to, they pick a
free `/28` (from `10.203.84.0/28` on) and record all three settings in
`.env`, with a line saying so. A setting you made yourself is never
changed; they warn instead. By hand (plain `docker compose up`), set all
three in `.env`: `SIGRIFT_BACKEND_SUBNET`, `SIGRIFT_BACKEND_IP_RANGE`
(inside that subnet) and `SIGRIFT_GATEWAY_BACKEND_IP` — inside the subnet
but outside the range. A gateway address inside the range can be handed
to the bridge, and the gateway then fails to start with
`Address already in use`.

---

## Advanced: distributed deployment

When a single host isn't enough — multiple scanning receivers at
different locations, or you want to keep the SDR away from the
central server — split the stack across machines. Central server on
one box, edge agents on the others, all talking over HTTPS with API
keys.

### Central server

Same software as the single-host install; publish the gateway on
every interface (`SIGRIFT_BIND=0.0.0.0`) and put a real TLS cert on it.

```bash
git clone https://github.com/SigRift/SigRift.git
cd SigRift
cp .env.example .env   # edit: BRIDGE_ENV=production, SIGRIFT_BIND=0.0.0.0,
                       # secrets, TLS paths

docker compose up -d

# Or for a production-grade install, use the systemd units above with
# UC_HOST=0.0.0.0 and a real TLS cert pair.
```

### Edge nodes (one per remote host)

Each remote host only needs the Python parts (no Rust gateway,
no Docker required). This runs the heartbeat agent only; it does not
capture RF. Remote scanners are set up by hand (see
[src/sigrift/edge/README.md](src/sigrift/edge/README.md)) and were not
part of the release soak:

```bash
# On each Raspberry Pi / laptop / NUC / edge device
sudo apt install -y python3 python3-venv rtl-sdr hackrf libusb-1.0-0
git clone https://github.com/SigRift/SigRift.git
cd SigRift
python3 -m venv .venv && source .venv/bin/activate
pip install --require-hashes -r src/sigrift/bridge/requirements.txt

# Create an API key with the `node` role on the central server
# (dashboard -> Admin -> API Keys) and pass it in. Copy the gateway's
# TLS cert (or its CA) to the edge node first — the agent verifies TLS
# by default, and <GATEWAY> must be a name or address the cert lists
# (see below):
MLRF_CA_CERT=/etc/ssl/certs/sigrift-gateway.pem \
python3 src/sigrift/edge/node_agent.py \
    --node-id lab-01 \
    --api-url https://<GATEWAY>:8444 \
    --api-key <API_KEY>
```

Use one API key with the `node` role per node, shared by all of that
node's agents. Rotate them with the admin UI. A node key created without
a node is **bound to the first node it reports for** (its first
heartbeat or detection batch) and refused with 403 for every other node
from then on, so a key cannot be shared between nodes; create it with
its node id to bind it up front. The first key to claim a node keeps
it: another unbound key reporting for the same node gets 403 until an
admin creates it bound to that node. A `viewer` key is refused on node
routes, and an `analyst` key is never bound (operator tooling).
`BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1` in `.env` (both compose files pass it
to the bridge and the gateway) keeps unbound node keys unbound, as older
versions did; it does not make a `viewer` key a node credential — see
SECURITY.md, "API Keys".

Alerts for the detections a node posts (alert rules, watch bands,
webhooks) are created **asynchronously**: the gateway stores the batch,
answers with `alerts_created: 0`, and hands the detections to the bridge
in the background. They show up in the dashboard a moment later. A
graceful gateway stop keeps what it has not handed over yet (its hook
spool, sent at the next start); webhooks are delivered in the
background, so a slow receiver delays nothing else. While the bridge is
down or restarting and the gateway keeps running, a hand-over that fails
3 times is dropped, not spooled (see "Upgrading" below).

### Gateway certificate for remote edge nodes

Edge agents verify the gateway's certificate, including that it was
issued for the host name or IP address in `--api-url`. With a publicly
trusted certificate for that name nothing else is needed. With the
self-signed certificate that `scripts/quickstart.sh` and
`install-release.sh` generate, give the node a copy of that
certificate — `tls/cert.pem` next to the `docker-compose.yml` — and
make sure it lists the address the node dials:

- The generated certificate's subjectAltName covers `localhost`,
  `127.0.0.1`, `::1`, `gateway`, `bridge`, the host's short name and
  FQDN, and its non-loopback addresses (Docker's own bridge interfaces
  and IPv6 link-local / temporary addresses are left out because they
  change by themselves).
- Add anything else clients use — a DNS alias, a public or NAT
  address, a Tailscale name — with `SIGRIFT_TLS_SANS`, a
  comma-separated list of names and IPs:
  ```bash
  SIGRIFT_TLS_SANS=sigrift.example.org,203.0.113.7 scripts/quickstart.sh
  SIGRIFT_TLS_SANS=sigrift.example.org,203.0.113.7 bash install-release.sh
  ```
- Re-running the installer regenerates
  the certificate when a required name is missing — e.g. the host's
  address changed, or you added `SIGRIFT_TLS_SANS` — keeping every name
  the old one had, and recreates the containers that use it. **Copy the
  new `cert.pem` to every node that pinned the old one.** The unattended
  renewal mode (`--renew-tls`, below) never does this; it
  only warns about the missing names. Certificates
  from older installers listed only `localhost` (and `gateway` /
  `bridge`); re-running the installer upgrades them. To drop names,
  delete `tls/cert.pem` and `tls/key.pem` and re-run.
- A certificate that is not self-signed (yours, from a CA) is never
  replaced; the installer only warns about names it lacks.

Check what a certificate covers with
`openssl x509 -in tls/cert.pem -noout -ext subjectAltName`, and from
the node: `curl --cacert gateway-cert.pem https://<gateway>:8444/health`.

### Certificate renewal

The generated certificate is valid for 825 days. Edge agents verify
the gateway and refuse an expired certificate, so it has to be renewed
before then. Every run of `scripts/quickstart.sh` and `install-release.sh`
regenerates it when it expires within 30 days
(keeping its names) — as long as it is self-signed; one from a CA is
never touched, only warned about. To renew without a full re-run (for
example from a timer), each installer has a TLS-only mode. It renews the
certificate **only when it expires within 30 days, with exactly the
names it already has**, and then recreates the containers that use it.
It **never adds a name**: when the host gains an address (a new DHCP
lease or IPv6 prefix, a VPN interface) it logs a `WARNING: … lacks
subjectAltName …` and leaves the certificate alone, because a new
certificate would break every remote edge node that pinned the old one.
To add the names, re-run the installer, with
`SIGRIFT_TLS_SANS` for extra ones, and copy the new `cert.pem` to those
nodes.

```bash
openssl x509 -in tls/cert.pem -noout -enddate      # when does it expire?
bash install-release.sh --renew-tls                 # release install
scripts/quickstart.sh --renew-tls                   # quickstart install
```

A weekly cron entry (as the user that installed the stack) is enough:

```cron
# m h dom mon dow  command
17 4 * * 1  cd /opt/sigrift-release && bash install-release.sh --renew-tls >> tls-renew.log 2>&1
```

or a systemd timer (`/etc/systemd/system/sigrift-tls-renew.{service,timer}`):

```ini
# sigrift-tls-renew.service
[Unit]
Description=Renew the SigRift gateway's self-signed TLS certificate if due

[Service]
Type=oneshot
User=sigrift
WorkingDirectory=/opt/sigrift-release
ExecStart=/usr/bin/bash install-release.sh --renew-tls

# sigrift-tls-renew.timer
[Unit]
Description=Weekly SigRift TLS certificate check

[Timer]
OnCalendar=Mon 04:17
Persistent=true

[Install]
WantedBy=timers.target
```

`sudo systemctl enable --now sigrift-tls-renew.timer`. (The user needs
to run `docker`.) If recreating the containers fails after a renewal (an
`up` that fails, a full disk, a registry outage — the release
installer's renewal recreates with `--pull never`), `tls/.recreate-pending`
stays behind and the next run, renewal or full, recreates them again
until it works, so the gateway does not keep serving the old
certificate. The release installer removes the marker once `up`
succeeded. The quickstart, whose `up` may fail by design (an
SDR service without its hardware), remove it only when the gateway is
healthy again and every running container started after the
certificate changed: an `up` that failed before it reached the gateway
leaves the old one running, healthy, with the old certificate. Such a
run exits non-zero and names the services that still run from before.
**A renewed certificate is a new trust anchor: copy the
new `tls/cert.pem` to every edge node on another host that was given
the old one** (`--ca-cert` / `MLRF_CA_CERT`) — they cannot verify the
new one until you do. For many remote nodes, a certificate from a CA
they already trust avoids that (e.g. `tailscale cert`, see
TAILSCALE.md).

### Verifying a release

Prebuilt application releases start with v0.1.0: `install-release.sh`
pulls the bridge and gateway images of a code release by version tag
(the `v0.1.0-models` release contains classifier assets, not the
application installer). The release files (tarball, installer,
`SHA256SUMS`, SBOM) are signed with cosign; the images are not signed
yet. Replace `V` below with the release you install. The release
installer starts those two services in production by default; add edge
agents separately. It does not build the source quickstart's scanner
services.

Application release artefacts are signed with cosign keyless by the release
workflow, `.github/workflows/release.yml`, running for the release's
tag. Verify the signed checksum list with **exactly** that identity —
a regular expression over the repository URL would also accept a
signature made by any other workflow or branch of the repository —
then check what you downloaded against it, and only then run anything:

```bash
V=v0.1.0
R=https://github.com/SigRift/SigRift/releases/download/$V
for f in sigrift-$V.tar.gz SHA256SUMS SHA256SUMS.sig SHA256SUMS.pem; do
    curl -fsSLO "$R/$f"
done
cosign verify-blob \
    --certificate-identity "https://github.com/SigRift/SigRift/.github/workflows/release.yml@refs/tags/$V" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --signature SHA256SUMS.sig --certificate SHA256SUMS.pem SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
tar xzf sigrift-$V.tar.gz && cd sigrift-$V
bash install-release.sh            # SIGRIFT_BIND=0.0.0.0 for LAN access
```

`install-release.sh` is also published on its own (and listed in
`SHA256SUMS`) for installs without the tarball — download it the same
way instead of the tarball, and run it as
`SIGRIFT_VERSION=$V bash install-release.sh` (without a version it
installs the `:main` development images). Never pipe a download straight into
`bash`. Release candidates (`-rcN`) are marked as pre-releases and do
not move the `:latest` image tags.

### Production secrets

```bash
# Fernet key: urlsafe-base64 of 32 random bytes (what
# cryptography's Fernet.generate_key() returns).
echo "BRIDGE_MFA_KEY=$(python3 -c 'import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())')"
for v in BRIDGE_AUDIT_KEY BRIDGE_MASTER_KEY UC_PROXY_SECRET; do
  echo "$v=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
done
```

All four are required in `BRIDGE_ENV=production`. The bridge needs all
of them; the gateway needs the three it shares with the bridge —
`BRIDGE_MFA_KEY`, `BRIDGE_AUDIT_KEY`, `UC_PROXY_SECRET`, with the same
values — and **not** `BRIDGE_MASTER_KEY` (the shipped
`docker-compose.yml` and the systemd units above do exactly this):

- `BRIDGE_MFA_KEY` — Fernet key for at-rest TOTP secret encryption.
  Valid means: after trimming whitespace, exactly 44 characters — 43
  from `A–Z a–z 0–9 - _ + /`, then `=` — encoding 32 bytes (both the
  URL-safe and the standard base64 alphabet are accepted). A
  43-character `token_urlsafe` value is not one. Both services refuse
  to start in production without a valid key, and neither encrypts
  with an invalid one.
- `BRIDGE_AUDIT_KEY` — HMAC key for the tamper-evident audit chain,
  shared by both services. Both refuse to start in production without
  it.
- `BRIDGE_MASTER_KEY` — master API key the bridge registers on
  first boot. Bridge only. Required in production;
  `src/sigrift/bridge/app.py` refuses to start without it (see the
  `"BRIDGE_MASTER_KEY env var is required when BRIDGE_ENV=production"`
  guard).
- `UC_PROXY_SECRET` — shared secret between the Rust gateway and
  the Python bridge; the bridge validates strength at startup.

Set `BRIDGE_ADMIN_PASSWORD` too — the bridge refuses to start in
`BRIDGE_ENV=production` without it. systemd unit templates and an
example nginx reverse-proxy config are planned for a future
deployment guide.

---

## Backup, restore, and migration (learned-state bundles)

The anomaly-scoring pipeline learns your RF environment over time.
That learned state can be saved and restored as a versioned
**bundle** — a validated `.sigrift.tar.gz` archive. The format is
specified in [docs/bundle-format.md](docs/bundle-format.md); the
short version is that there are two kinds:

- **export** — a lossless, same-site backup (restore after
  `docker compose down -v` or a hardware migration). May contain
  MAC/BSSID-keyed WiFi/BT baselines. This is the restore direction
  the old one-way `/backup` endpoint lacked.
- **preset** — a site-transferable, fully synthetic starting point
  (RF-only, never MAC-keyed). See
  [QUICKSTART.md §"Environment presets"](QUICKSTART.md#environment-presets).

### Admin API

All endpoints live under `/api/admin` and require the ADMIN role
(`X-API-Key` header or an admin session):

| Endpoint | What it does |
|---|---|
| `POST /api/admin/baselines/export` | Build an export bundle. Optional body `{"components": [...]}` with any of `rf`, `wifi`, `bt`, `whitelist`, `detection_config` (default: all). |
| `GET /api/admin/baselines/exports` | List available export bundles. |
| `GET /api/admin/baselines/exports/{filename}` | Download a bundle. |
| `POST /api/admin/baselines/import?dry_run=true\|false&force=false&components=...` | Upload a bundle (multipart file). `dry_run` defaults to **true** — validate only, returning a per-check report. A bad bundle returns `422` naming the member, the failed check, and the fix. |
| `GET /api/admin/presets` | List the packaged presets. |
| `POST /api/admin/presets/{profile}/apply?force=false&dry_run=false` | Apply a preset. Returns `409` if more than 1000 learned RF detections would be replaced, unless `force=true` — learned state is never silently destroyed. |
| `GET /api/admin/baselines/status` | Learned-baseline summary, autosave interval, last applied bundle provenance. |

### CLI (headless / offline)

For hosts without a running dashboard, the same operations are
available as a CLI:

```bash
python -m sigrift.bridge.bundles export      --data-dir DIR [-o OUT]
python -m sigrift.bridge.bundles validate    BUNDLE
python -m sigrift.bridge.bundles import      BUNDLE --data-dir DIR [--dry-run] [--force]
python -m sigrift.bridge.bundles extract     BUNDLE --component rf -o baselines.json
python -m sigrift.bridge.bundles list-presets
```

`import` (and `extract` into a data dir) refuses to write when a
bridge appears to be running against that directory (a recently
modified `detections.db-wal`) unless `--force` — prefer the admin
API on a live system. See
[docs/bundle-format.md](docs/bundle-format.md) for the exact flags
and the validation pipeline every untrusted bundle passes through.

### Crash safety

The bridge autosaves dirty baselines every
`BRIDGE_BASELINE_SAVE_INTERVAL` seconds (default `900`; `0`
disables), not only at graceful shutdown, so learned state survives
an ungraceful stop. The interval is adjustable at runtime through
the admin config API.

---

## Upgrading

SigRift follows semantic versioning. For `0.x` releases, minor bumps
may include breaking changes — always read `CHANGELOG.md` before
upgrading.

```bash
git fetch --tags
git checkout v0.x.y
# quickstart install:
scripts/quickstart.sh
# or from-source:
docker compose pull && docker compose up -d --build
```

Database migrations (where needed) run automatically at bridge boot.
Back up `data/detections.db` before upgrading a production install.

### Upgrade note: loopback by default, proxy-only bridge, CA key volume

- **The dashboard is published on 127.0.0.1 by default.** The shipped
  `docker-compose.yml` used to publish port 8444 on every interface. A
  quickstart install updated with `git pull` is reachable from this
  machine only until you set `SIGRIFT_BIND=0.0.0.0` in `.env` (or
  re-run `SIGRIFT_BIND=0.0.0.0 scripts/quickstart.sh`) — do that if
  browsers on other machines or remote edge nodes use it. A
  `docker-compose.yml` that an older `install-release.sh` wrote is
  never rewritten and keeps its old `ports:` line; the installer's
  closing message says which address is in use.
- **New installs are production installs.** `install-release.sh` now
  writes `BRIDGE_ENV=production` (it always generated every key
  production needs). An existing `.env` is left as it is; switch an
  older `BRIDGE_ENV=development` install by editing `.env`, after
  checking `BRIDGE_AUDIT_KEY` is set (the installer warns if not).
- **The bridge answers the gateway only** (`BRIDGE_REQUIRE_PROXY=true`)
  and is on the `backend` network only; it trusts `X-Forwarded-For`
  from the gateway's fixed backend address instead of all of
  `172.16.0.0/12`. Anything else that called `http://bridge:8001`
  directly must go through `https://gateway:8444`. An older
  install-release `docker-compose.yml` gets a warning with the lines to
  add.
- **The CA private key moves to the `bridge_secrets` volume.** On its
  first start with the new compose file the bridge moves (not copies)
  `ca/ca.key` out of `bridge_data` and logs
  `Moved the CA private key from … to …`; the CA certificate and the
  issued-cert registry stay where the gateway reads them. With a
  compose file that lacks the volume the key stays in `bridge_data`
  (moving it into the container's own layer would lose it) and the
  bridge logs a warning — add the volume (the installer prints how).
  Back up both volumes together from now on.
- **Downgrading past this change needs one manual step.** An older
  bridge (one whose compose file has no `bridge_secrets` volume) looks
  for the key in `bridge_data` only; finding none there, it silently
  creates a **new CA** — overwriting `ca.crt` and invalidating every
  client certificate it issued. Before you switch to an older version,
  while this version's `docker-compose.yml` is still in place, copy the
  key back:

  ```bash
  docker compose run --rm --no-deps --entrypoint cp bridge \
      /app/secrets/ca/ca.key /app/src/sigrift/bridge/data/ca/ca.key
  ```

  (From source: `cp src/sigrift/bridge/secrets/ca/ca.key
  src/sigrift/bridge/data/ca/ca.key`, or from `$BRIDGE_SECRETS_DIR/ca/`.)
  Leave the copy in `bridge_secrets`: upgrading again, the bridge finds
  the same key in both places and removes the one in `bridge_data`.
- **Self-signed certificates are renewed** 30 days before they expire,
  and new ones are valid for 825 days (was 365). Remote edge nodes need
  the new `cert.pem` after a renewal — see
  [Certificate renewal](#certificate-renewal).
- **The backend network has a fixed subnet**, by default `10.203.84.0/28`
  (outside Docker's default pools). On a host that runs **more than one
  SigRift stack**, each needs its own: the installers pick a free one
  and write it to `.env` when the default is taken; a plain
  `docker compose up` of the second stack fails with
  `Pool overlaps with other one on this address space` until you set
  `SIGRIFT_BACKEND_SUBNET`, `SIGRIFT_BACKEND_IP_RANGE` and
  `SIGRIFT_GATEWAY_BACKEND_IP` in its `.env` (see
  [Who can reach the dashboard](#who-can-reach-the-dashboard)).
- **`UC_PROXY_SECRET` is required in every mode**, development
  included: without it the proxy-only bridge refuses every request the
  gateway proxies (403), and its healthcheck now reports it unhealthy so
  the gateway does not start. The installers have always generated one.
  A development gateway and bridge started by hand without it (or with
  the old default `uppercrust-internal`) and without
  `BRIDGE_REQUIRE_PROXY` still serve the dashboard, but the gateway logs
  an error at start-up and runs with **node-key binding and post-ingest
  hooks disabled**, because the bridge refuses both without the secret.
  The gateway's detection ingest then leaves unbound node keys unbound
  and accepts their batches for any node (as with
  `BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1`); the bridge's own node routes
  (heartbeats, WiFi / BT ingest, node commands, IQ uploads) still bind
  such a key on first use, and from then on the gateway's ingest holds it
  to that node too. No alert rules, watch-band alerts, webhooks,
  edge-decoded messages or decode jobs run for the batches the gateway
  ingests: its `GET /health` shows `post_ingest_hooks.enabled: false`
  and counts those detections in `hooks_disabled`.
- **Node API keys are bound to the first node they report for** — keys
  with the `node` or `sensor` role, by the bridge's node routes and by
  the gateway's detection ingest. A key used by more than one node keeps
  working for the first one and gets 403 for the others. **The first key
  to claim a node keeps it**: an unbound key that reports for a node
  another key is already bound to gets 403 (the gateway's ingest:
  `Node '<node>' already has a bound API key; an admin must bind this
  key to it explicitly`). Give each node one key and let all of its
  agents share it (the in-stack scanners share `BRIDGE_LOCAL_NODE_KEY`);
  a further key for the same node has to be created by an admin with
  that node's `node_id`. Keys bound before the upgrade stay bound.
  `BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1` (passed to both services) keeps
  node keys unbound, as before.
- **Viewer keys are not node credentials.** Heartbeats, node commands,
  detection / WiFi / BT ingest and IQ uploads made with an unbound
  `viewer` key get 403 `Node endpoints require a node API key` (older
  versions accepted them for any node), and the key is never bound to a
  node; `BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1` does not change that. An
  unbound `analyst` key is operator tooling, like an analyst session: it
  is never bound and may act for any node. Give edge agents a key with
  the `node` role.
- **Node client certificates act only for the node their identity
  names.** With mTLS (`docker-compose.pki.yml`, `MLRF_CLIENT_CERT`), a
  `node` or `sensor` client certificate is accepted by the gateway's
  ingest and the bridge's node routes only when its identity equals the
  agents' `MLRF_NODE_ID`, and the agents send no API key while a
  certificate is loaded. Certificates minted one per agent, as earlier
  versions of `PKI_ARCHITECTURE.md` and `scripts/pki_bootstrap.py`
  suggested (`local-edge`, `wifi-scan`, `bt-scan` on a node with another
  id), now get 403 on every heartbeat and batch (`Client certificate
  '<identity>' may only submit batches for node '<identity>'` from the
  gateway's detection ingest, `… may only act for node '<identity>',
  not '<node>'` from the bridge's node routes). Before upgrading, issue
  one certificate per node — `POST /api/ca/issue` with
  `{"identity": "<MLRF_NODE_ID>", "role": "node"}`, or
  `scripts/pki_bootstrap.py <node id>:node` — mount it into all of that
  node's agents, and revoke the old ones
  (`POST /api/ca/revoke/{serial}`); or unset `MLRF_CLIENT_CERT` /
  `MLRF_CLIENT_KEY` so the agents fall back to their API key. `BRIDGE_ALLOW_UNBOUND_NODE_KEYS` does not
  affect certificates.
- **Alerts for ingested detections are created asynchronously** by the
  bridge after the gateway stored the batch (`alerts_created` in the
  ingest response is always `0`). Before, alert rules and watch bands
  did not run for gateway-ingested batches at all. The bridge runs them
  once per detection, even when the gateway sends a batch again, and
  delivers their webhooks in the background, so a slow or dead webhook
  receiver no longer holds up ingest. When the gateway stops
  (`docker compose stop`, an upgrade, a TLS-renewal recreate) it gives
  the hand-overs still queued 5 s to reach the bridge and saves the rest
  in `gateway-post-ingest-hooks.spool` in its data directory (the
  `bridge_data` volume), which it sends first at the next start. Only a
  gateway stop spools: **while the bridge is down or restarting and the
  gateway keeps running** — `docker compose restart bridge`, a bridge
  that crashed or is still starting, or an upgrade, which recreates the
  bridge while the old gateway is still serving — the gateway tries each
  hand-over 3 times (0.5 s, then 1 s apart), then drops it, counts it in
  `post_ingest_hooks.failed_batches` / `failed_detections` in
  `GET /health` and logs `Post-ingest hook failed after retries —
  dropped`. The detections of those batches are stored, but no alert
  rules, watch-band alerts, webhooks or decode jobs run for them. What
  is queued when the gateway is killed or crashes, or what exceeds the
  queue (10 000 detections) or the spool (64 MiB), is lost too
  (overflows are counted in `GET /health` as `dropped_*`).
- **The bridge and the gateway get 30 s to stop.** The shipped compose
  files set `stop_grace_period: 30s` on both (Docker's default is 10 s,
  after which it kills the container): the bridge's shutdown waits —
  bounded — for analysis jobs, the detection write queue and worker
  threads before its last save, and the gateway spools undelivered
  hooks. A `docker-compose.yml` that an older `install-release.sh`
  wrote is never rewritten; the installer prints a note with the line
  to add to both services.

### Upgrade note: `BRIDGE_MFA_KEY` must be a valid Fernet key

Older versions of `scripts/install-release.sh`, the from-source
`.env.sh` recipe, the systemd "Production secrets" loop and some docs
generated `BRIDGE_MFA_KEY` with `secrets.token_urlsafe(32)`: 43
characters, the unpadded form of a Fernet key. The bridge and the
gateway now **refuse to start with `BRIDGE_ENV=production`** unless
`BRIDGE_MFA_KEY` is valid — exactly 44 characters, 43 base64 characters
(`A–Z a–z 0–9 - _ + /`) then `=`, encoding 32 bytes — and
`BRIDGE_AUDIT_KEY` is set. In development an invalid key logs a warning
and new TOTP secrets are stored `b64:`-encoded (not encrypted).

**Do not replace an old 43-character key — append `=` to it.** That is
the same 32 key bytes, so every TOTP secret already encrypted with it
stays readable. This matters because older gateways *did* encrypt with
the 43-character key: a gateway that received `BRIDGE_MFA_KEY` (systemd
`secrets.env`, the from-source setup, any compose file that passed it
to the gateway) stored `fernet:` secrets for users who enrolled MFA
through it, and replacing the key would lock all of them out of MFA.
Only Docker/compose installs whose gateway never got the key (the
shipped compose files before this release) hold nothing but `b64:`
secrets from it.

- **quickstart / install-release installs:** re-run
  `scripts/quickstart.sh` or `install-release.sh`. It reads
  `BRIDGE_MFA_KEY` from `.env` the way docker compose does (last
  assignment, `export ` prefix, quotes, ` # comment`) and: leaves a
  valid key alone; appends `=` to a 43-character key; rewrites any
  other value an older bridge or gateway could use to a valid key with
  the same 32 bytes; generates a new key only when the key is missing,
  empty, or no version could ever have used it; and only warns
  (changing nothing) when it cannot be sure how compose reads the line.
  The previous file is kept as `.env.bak.<time>~` (0600). Then
  `docker compose up -d`.
- **Hand-managed `.env`, systemd `/etc/sigrift/secrets.env`, from-source
  `.env.sh`:** fix the key yourself,
  then restart both services:
  - 43 characters (`token_urlsafe` output): append `=`.
  - Otherwise, check whether it decodes to 32 bytes the way older
    versions read it, and if so use the same bytes, correctly encoded:
    ```bash
    python3 - "$BRIDGE_MFA_KEY" <<'PY'
    import base64, binascii, sys
    k = sys.argv[1].strip()
    try:
        b = base64.urlsafe_b64decode(k + "=" * (-len(k) % 4))
    except (binascii.Error, ValueError):
        b = b""
    print(base64.urlsafe_b64encode(b).decode() if len(b) == 32 else "no: generate a new key")
    PY
    ```
  - Only if neither applies, generate a new key (nothing can have been
    encrypted with the old value):
    ```bash
    python3 -c 'import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'
    # or, with the cryptography package:
    python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
    ```
- Never replace a key that is already valid: secrets encrypted with it
  would become unreadable and users would have to re-enroll MFA.
- **Gateway environment:** the gateway needs `BRIDGE_AUDIT_KEY` and
  `BRIDGE_MFA_KEY` (same values as the bridge) — but not
  `BRIDGE_MASTER_KEY`, the admin API key, which only the bridge uses.
  The shipped `docker-compose.yml` passes exactly those two. For a
  `docker-compose.yml` generated by an older `install-release.sh` the
  script prints the lines to add (or says to remove
  `BRIDGE_MASTER_KEY` from the gateway); or move the file aside and
  re-run it to regenerate it. For systemd, move `BRIDGE_MASTER_KEY` and
  `BRIDGE_ADMIN_PASSWORD` from `secrets.env` into a bridge-only
  `bridge-secrets.env` (see "Running as a service").
- **Gateway certificate:** the self-signed certificate now lists the
  host's own names and addresses, so remote edge nodes can verify it
  with `--ca-cert`. Re-running the installer regenerates an older one;
  copy the new `tls/cert.pem` to your edge nodes (see
  [Gateway certificate for remote edge nodes](#gateway-certificate-for-remote-edge-nodes)).
- **Edge agents verify TLS:** the in-stack scanners trust the gateway's
  self-signed cert through `MLRF_CA_CERT`. `scripts/quickstart.sh`
  creates the required TLS mounts in a new `docker-compose.override.yml`
  but preserves every existing override. For an older file missing trust
  configuration, add `./tls/cert.pem:/app/tls/cert.pem:ro` and
  `MLRF_CA_CERT=/app/tls/cert.pem` to `edge`, `scan`, `wifi-scan` and
  `bt-scan` yourself, keeping its other settings and profiles.

---

## Commercial edition

This repository is the community edition. The commercial SigRift
edition adds TDOA geolocation, device / PHY-layer fingerprinting,
protocol fuzzing, OIDC / SSO, STIX / TAXII export, IQ capture,
advanced protocol decoders, edge model deployment pipelines, and
OTEL / CEF / syslog integrations — layered on top of this community
code as a `sigrift-sentinel` plugin package that registers via Python
entry points.

For commercial licensing enquiries, use
[GitHub Discussions](https://github.com/SigRift/SigRift/discussions).

---

## Next steps

- [QUICKSTART.md](QUICKSTART.md) — dashboard setup, retries and enabling hardware
- [ARCHITECTURE.md](ARCHITECTURE.md) — system design
- [SECURITY.md](SECURITY.md) — security posture and disclosure policy
- [CONTRIBUTING.md](CONTRIBUTING.md) — contributing code
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — common errors and fixes
