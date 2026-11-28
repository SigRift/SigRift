# RF Edge Monitor

Real-time RF signal classification on Raspberry Pi 5 with Hailo-8 NPU acceleration.

## Overview

The RF Edge Monitor continuously scans predefined frequencies using an RTL-SDR dongle, classifies detected signals using a neural network running on the Hailo NPU, and logs detections for analysis.

## Hardware Requirements

- Raspberry Pi 5 (4GB+ RAM recommended)
- Hailo-8 AI Kit (M.2 HAT with Hailo-8/8L NPU)
- RTL-SDR dongle (RTL2832U-based)
- Antenna appropriate for target frequencies

## Software Stack

| Component | Version | Purpose |
|-----------|---------|---------|
| Raspberry Pi OS | Bookworm 64-bit | Base OS |
| HailoRT | 4.23.0+ | NPU runtime |
| rtl-sdr | 0.6+ | SDR driver |
| Python | 3.11+ | Application runtime |
| ONNX Runtime | 1.16+ | Fallback inference |

## Directory Structure

```
/opt/rf-edge/
├── bin/
│   ├── monitor.py          # Main monitoring script
│   └── tail-unique.sh      # Log filter utility
├── lib/
│   └── node.py             # HailoClassifier class
├── models/
│   ├── hailo_classifier.hef           # Compiled Hailo model
│   ├── hailo_classifier.onnx          # ONNX fallback model
│   └── hailo_classifier_metadata.json # Model metadata
└── logs/
    ├── monitor_YYYYMMDD_HHMMSS.log    # Rotating log file
    ├── detections_YYYYMMDD_HHMMSS.jsonl # Detection records
    └── output.log                      # systemd stdout capture
```

## Installation

### 1. Install Dependencies

```bash
sudo apt update
sudo apt install -y rtl-sdr python3-numpy python3-pip

# Install ONNX Runtime (fallback)
pip3 install onnxruntime
```

### 2. Deploy Files

```bash
# Create directory structure
sudo mkdir -p /opt/rf-edge/{bin,lib,models,logs}
sudo chown -R pi:pi /opt/rf-edge

# Copy files from deployment package
scp -r edge/* pi@<pi-ip>:/opt/rf-edge/
```

### 3. Install systemd Service

```bash
sudo cp /opt/rf-edge/rf-edge.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable rf-edge
sudo systemctl start rf-edge
```

> **Note:** `rf-edge.service` runs with `PrivateTmp=yes` and sets
> `HAILO_MONITOR=1`. HailoRT writes its monitor data under `/tmp`, so with a
> private `/tmp` a shell's `hailortcli monitor` run outside the unit cannot
> see it. Run `hailortcli monitor` from inside the unit's namespace (e.g.
> `systemd-run --pty --machine .host -p JoinsNamespaceOf=rf-edge.service ...`),
> or drop `PrivateTmp` if you rely on it.

### 4. Scanner services and their secrets (`wifi-scan`, `zigbee-scan`)

`wifi-scan.service` and `zigbee-scan.service` read `MLRF_BRIDGE_URL`,
`MLRF_BRIDGE_KEY`, `MLRF_NODE_ID` and the TLS settings (`MLRF_CA_CERT`, ...)
from **`/etc/sigrift-edge/edge.env`**, one `KEY=value` per line. systemd reads
that file as root before it starts the service, so keep it root-owned and
private; the services never take the API key on their command line (argv is
readable by every local user through `ps` and `/proc/<pid>/cmdline`).

```bash
sudo install -d -o root -g root -m 0755 /etc/sigrift-edge
# New node: write the file. Existing node: copy the old shared file.
sudo install -o root -g root -m 0600 /home/pi/mlrf-agent/.env /etc/sigrift-edge/edge.env
sudo cp /opt/rf-edge/wifi-scan.service /opt/rf-edge/zigbee-scan.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl restart wifi-scan zigbee-scan
```

All three units run as `pi` with `NoNewPrivileges=yes` and an explicit
capability bounding set. `wifi-scan` no longer runs as root: it gets exactly
`CAP_NET_ADMIN` (monitor mode, channel hopping) and `CAP_NET_RAW` (tcpdump's
capture socket) as ambient capabilities. If an adapter needs more (for
example `/dev/rfkill`), add that one capability rather than going back to
`User=root`. Not yet tested on every radio/driver combination.

**Upgrading:** the old `wifi-scan.service` ran as root and read
`/home/pi/mlrf-agent/.env`, a file the `pi` user can edit (it could set
`PYTHONPATH`/`LD_PRELOAD` for a root process). Create
`/etc/sigrift-edge/edge.env` as above before installing the new units: a
missing file stops the service from starting.

### 5. Shared state directory for the agent (`mlrf-agent`, `mlrf-bt-scanner`)

A runtime `update_config` from the bridge (e.g. the summarize toggle) reaches
the scanners as a file, `/var/lib/sigrift-edge/scanner-config.json`, that
`mlrf-agent` writes and the scanners read (`MLRF_SCANNER_CONFIG_PATH`, below).
It used to live in `/tmp`, which no longer works: the units run with
`PrivateTmp=yes`, so each sees its own `/tmp`.

`/var/lib/sigrift-edge` is created (owned by `pi`) by systemd for any unit
that declares `StateDirectory=sigrift-edge`; `rf-edge.service` and
`wifi-scan.service` do. The `mlrf-agent` and `mlrf-bt-scanner` units are not
shipped here, and the agent runs as `pi`, which cannot create a directory
under `/var/lib`. On a node where neither `rf-edge` nor `wifi-scan` has run,
the agent then cannot write the file: it logs `Failed to write scanner
config: cannot write scanner config ...` and the toggle is lost. Give those
units the state directory too. Add it only to units that run as `User=pi`:
systemd re-owns the directory to each declaring unit's user when that unit
starts, so a root unit declaring it would lock the `pi` units out. A root
unit can read the file without it.

```bash
for u in mlrf-agent mlrf-bt-scanner; do   # only the ones with User=pi
  sudo mkdir -p /etc/systemd/system/$u.service.d
  printf '[Service]\nStateDirectory=sigrift-edge\n' |
    sudo tee /etc/systemd/system/$u.service.d/sigrift-state.conf >/dev/null
done
sudo systemctl daemon-reload
sudo systemctl restart mlrf-agent mlrf-bt-scanner
```

Or create the directory once (it persists across reboots):
`sudo install -d -o pi -g pi -m 0755 /var/lib/sigrift-edge`. If you set
`MLRF_SCANNER_CONFIG_PATH` to another location, set the same value on every
unit and make sure its directory exists and `pi` can write it.

### Dashboard (`lib/shiny`) node keys

When the edge agent heartbeats to the Shiny dashboard
(`/api/nodes/heartbeat`), the dashboard now binds each non-admin key to one
node. A key created with `node_id` is bound to that node. A node key created
without one (`purpose: "node"`) is bound to the first node it heartbeats
for, unless another key already holds that node. A key created without
`node_id` through the API or the dashboard's key form is a dashboard key
(`purpose: "dashboard"`) and is never accepted for a heartbeat; create node
keys with a node ID. **One key shared by several nodes now works only for
the first node that heartbeats with it**: the others get
`403 API key is bound to node ...`. Give each node its own key.

**Keys created before key purposes existed** (no `purpose` and no `node_id`
in the dashboard's `keys.json`; the dashboard lists them in a warning at
startup) are no longer accepted for heartbeats until they are classified:
such a key could be a node's own key or a shared dashboard key, and letting
it claim a node on first use would let any dashboard user take over a node
that has not heartbeated yet. After upgrading, bind each node's key to its
node with the master key, and mark the dashboard keys:

```bash
curl -X PATCH https://<dashboard>/api/keys/edge-02-key \
  -H "X-API-Key: $MASTER_KEY" -H 'Content-Type: application/json' \
  -d '{"node_id": "edge-02"}'
curl -X PATCH https://<dashboard>/api/keys/dashboard-viewer \
  -H "X-API-Key: $MASTER_KEY" -H 'Content-Type: application/json' \
  -d '{"purpose": "dashboard"}'
```

`{"node_id": null}` unbinds a key (to undo a wrong claim without revoking
it), and binding a further key to a node this way is allowed. For a one-off
migration, `SHINY_LEGACY_KEY_TOFU=1` in the dashboard's environment lets
such keys claim the first unclaimed node they heartbeat for again; set it
to an ISO date instead (`SHINY_LEGACY_KEY_TOFU=2026-12-01`) to have it end
by itself. Every claim made this way is logged as a warning and shown in
the activity feed. Setting `BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1` in the
dashboard's environment restores the old behaviour, in which any unbound
key may heartbeat as any node. That is insecure: any key holder can then
take a node's queued commands.

## Heartbeat agent installed by `edge-install.sh`

The bridge serves an installer for the heartbeat agent alone
(`node_agent`, no RF capture) at `/api/edge/install.sh`; the dashboard
shows the command while no edge agent reports. It clones SigRift to
`/opt/sigrift-edge`, makes a venv, writes `/etc/sigrift-edge.env` (0600,
it holds the node API key) and `sigrift-edge.service` (root, with
`ProtectSystem=strict`), and starts it.

```bash
# First install (copy the gateway's tls/cert.pem here first):
curl -sfL --cacert gateway-cert.pem https://<gateway>:8444/api/edge/install.sh | \
  sudo bash -s -- --api-url https://<gateway>:8444 --api-key <node-key> \
    [--node-id edge-01] --ca-cert gateway-cert.pem [--ref vX.Y.Z]

# Upgrade after a server upgrade, or re-run: no flags needed. Download first:
# piped into bash, a failed download runs an empty script that exits 0.
# (No --cacert for a publicly trusted gateway; the installer prints the line.)
f=$(mktemp) && curl -fsSL --cacert /etc/sigrift-edge/ca.pem -o "$f" \
  https://<gateway>:8444/api/edge/install.sh && sudo bash "$f"; rm -f "$f"
```

- **Kept on a re-run:** `MLRF_API_URL`, `MLRF_API_KEY`, `MLRF_NODE_ID`
  and the gateway trust (`MLRF_CA_CERT`, the certificate in
  `/etc/sigrift-edge/ca.pem`, or a `MLRF_INSECURE_TLS=1`, which is reused
  with a warning). A flag given replaces its value: `--ca-cert` replaces a
  kept `MLRF_INSECURE_TLS=1`, and `--insecure-tls` a kept CA (the file
  stays on disk, no longer used). A kept `MLRF_CA_CERT` whose file is gone
  stops the installer: pass `--ca-cert` again. A kept
  `MLRF_INSECURE_TLS=1` is warned about again in the summary.
- **Another gateway:** a new `--api-url` needs `--api-key` too (the kept
  key belongs to the old gateway; the installer stops without it), and
  the kept gateway trust is not reused: pass `--ca-cert` for a
  self-signed gateway.
- **Lines the installer does not manage** (your own `MLRF_*` settings,
  such as `MLRF_CLIENT_CERT` or `MLRF_STATUS_PORT`, and comments) are kept
  after its own lines. A re-run that changes nothing leaves the file
  byte-identical; one that changes it keeps the previous file as
  `/etc/sigrift-edge.env.bak` (always 0600, whatever mode the old file
  had). The file is read line by line, never sourced.
- **Which code:** the agent is checked out (detached, at the exact commit)
  at the release the server runs: the bridge fills its release tag into
  the served script. A development server, or a `main-<sha>` image,
  installs `main`. `--ref <tag-or-branch>` installs another. The tag must
  exist on `github.com/SigRift/SigRift`: a release candidate tag that is
  not published there fails to fetch, and the installer stops with a hint
  to pass `--ref`. Local edits under `/opt/sigrift-edge` are discarded.
- A running agent is **restarted** by a re-run.
- **State directory:** the agent writes `scanner-config.json` (a runtime
  `update_config` from the bridge) to `/var/lib/sigrift-edge` for the
  scanner units (step 5 above). The installer creates the directory when
  it is missing (root, 0755) and never re-owns an existing one; the unit
  grants it in `ReadWritePaths=/var/log /tmp -/var/lib/sigrift-edge` and has no
  `StateDirectory=`, which in this root unit would re-own the directory
  to root at every start and lock the `pi` scanner units out. The agent
  writes the file through a new random temporary name (`mkstemp`), never
  a fixed one a `pi` process could plant a symlink at, and the unit keeps
  `/proc/sys`, `/sys`, kernel modules and cgroups read-only
  (`ProtectKernelTunables=yes`, `ProtectKernelModules=yes`,
  `ProtectControlGroups=yes`).

## Configuration

Edit `/opt/rf-edge/bin/monitor.py` to configure:

```python
# Frequencies to monitor (MHz: description)
FREQUENCIES = {
    97.5: 'FM Broadcast',
    101.1: 'FM Broadcast',
    146.52: '2m Ham',
    162.55: 'NOAA Weather',
    433.92: 'ISM 433',
    462.5625: 'FRS Ch1',
    868.3: 'LoRa EU',
    915.0: 'ISM 915',
}

DWELL_TIME = 0.2              # Seconds per frequency
CONFIDENCE_THRESHOLD = 0.6    # Minimum confidence to log
SNR_THRESHOLD = 10.0          # Minimum SNR (dB) to log
STATUS_PORT = 8080            # HTTP status endpoint port
```

### Environment Variables

The following environment variables can be set in the `.env` file, systemd unit, or shell environment:

#### Edge Node Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MLRF_CA_CERT` | *(empty)* | Path to a CA certificate bundle used to verify the Bridge server's TLS certificate (set this for a self-signed or private-CA bridge). If not set, the system trust store is used. TLS verification (with hostname checking) is **always on** unless `MLRF_INSECURE_TLS=1`. A path that does not exist logs an error and the system trust store is used instead (still verifying). A path that exists but cannot be loaded (not readable by the agent's user, not a PEM CA certificate, e.g. a private key) is a **fatal startup error**: the agent logs one line naming the variable, the path and the reason and exits non-zero, rather than trusting something you did not configure. A directory is used as an OpenSSL hashed CA directory (as written by `openssl rehash`); because OpenSSL only reads such a directory during each handshake, the agent checks it at startup, and a directory it cannot list, an empty one (which is what Docker creates when a bind-mounted host file such as `cert.pem` does not exist yet) or one with no loadable `<8 hex digits>.0` certificate is the same fatal startup error. Honored by `node_agent`, `rf_scan`, `wifi_scan` and `detection_reporter` (which also accepts the legacy `BRIDGE_CA_BUNDLE`). `tools/signal_tester.py` (a one-shot test tool, not an agent) also verifies against `MLRF_CA_CERT` / `MLRF_CA_BUNDLE` but has none of these startup checks: a path that is not a regular file it can stat is treated as missing (system trust store), and a file it cannot load aborts the injection with a Python error. |
| `MLRF_CA_BUNDLE` | *(empty)* | Alternative name for `MLRF_CA_CERT` (used when `MLRF_CA_CERT` is unset or names a path that does not exist; an `MLRF_CA_CERT` file that exists but cannot be loaded is fatal, it never falls through to this one). |
| `MLRF_INSECURE_TLS` | *(empty)* | Set to exactly `1` to **disable** TLS certificate and hostname verification to the Bridge. A loud warning is logged: the API key, uploads and the remote commands carried in heartbeat responses (`update`, `update_config`, `iq_capture`) are then unauthenticated. Lab use only; prefer `MLRF_CA_CERT`. |
| `MLRF_SUMMARIZE` | *(empty)* | When truthy (`1`/`true`/`yes`), the scanner uploads compact hourly **summaries** (gzip-compressed) instead of raw per-observation batches, cutting bridge write pressure on high-rate nodes. Can also be flipped at runtime: the bridge admin `update_config` writes a flag the scan loop polls via `reload_summarize()`, so no node restart is needed. The summary POST is `Content-Encoding: gzip` — the bridge's summary routes decompress it. |
| `MLRF_SCANNER_CONFIG_PATH` | `/var/lib/sigrift-edge/scanner-config.json` | Path of the JSON file `mlrf-agent` writes on an `update_config` command and the scanners (`wifi_scan`, `rf_scan`, `bt_scanner`) poll via `reload_summarize()`. It must be a directory **both** the agent and the scanners can reach. The default lives under `/var/lib/sigrift-edge` (declared as `StateDirectory=sigrift-edge` on the units), **not** `/tmp`: the units run with `PrivateTmp=yes`, so each has its own `/tmp` and a file the agent wrote there would be invisible to a scanner. If you override this, set the **same** value on the `mlrf-agent` unit (or its env file) and on the scanner units. The `mlrf-agent` and `mlrf-bt-scanner` units (not shipped here) need `StateDirectory=sigrift-edge` too, or a pre-created directory: see [step 5](#5-shared-state-directory-for-the-agent-mlrf-agent-mlrf-bt-scanner). |
| `STATUS_BIND` | `127.0.0.1` | Bind address for the edge status HTTP server. Set to `0.0.0.0` only if external monitoring needs access. |
| `MLRF_RTL_SAMPLE_RATE` | `2048000` | `rf_scan`: rtl_tcp sample rate (Hz) for scanning. The agent now sets it explicitly on every connect, so the rate is known and can be restored after a remote `iq_capture` that asked for another one. The default is rtl_tcp's own default; if you start `rtl_tcp -s <rate>`, set the same rate here. |
| `MLRF_RTL_GAIN` | *(empty)* | `rf_scan`: rtl_tcp scan gain in dB. Unset leaves the gain rtl_tcp was started with; after a remote `iq_capture` that set a gain, the dongle goes back to tuner AGC. Set it if you start `rtl_tcp -g <gain>`. |

A remote `iq_capture` command's `sample_rate` and `gain_db` are applied to the
device where it supports them (rtl_tcp: 225–300 kHz or 0.9–3.2 MHz; HackRF:
2–20 MHz, gain split LNA-first over LNA 0–40 dB / VGA 0–62 dB; B210: whatever
UHD accepts) and the scan settings are restored afterwards. An unsupported
rate captures at the device's scan rate instead. The upload's
`X-Sample-Rate` is always the rate the device actually ran at, and the
capture length is computed from it.

`node.py` (MQTT edge node): `mqtt_use_tls: true` in its YAML config (or
`--mqtt-tls`) connects to the broker over TLS with certificate and hostname
verification, trusting `mqtt_ca_cert` (or `--mqtt-ca-cert`), else
`MLRF_CA_CERT` / `MLRF_CA_BUNDLE`, else the system store. The CA rules are
the ones in the `MLRF_CA_CERT` row above: a path that does not exist logs an
error and the next setting (finally the system store) is used, still
verifying; a path that exists but cannot be loaded -- including one the
service user cannot even stat, and an empty, unlistable or un-rehashed CA
directory -- is a fatal startup error (`node.py` exits 1 naming the setting
and path). A configured CA always verifies; only `MLRF_INSECURE_TLS=1` with
no CA configured turns verification off. Without TLS, credentials sent to a
non-local broker log a warning.

#### Bridge Server Variables

These are configured in the bridge systemd service (`sigrift-bridge.service`):

| Variable | Default | Description |
|----------|---------|-------------|
| `BRIDGE_WQ_BATCH_SIZE` | `100` | WriteQueue batch size for detection inserts. Larger values improve throughput at the cost of latency. |
| `BRIDGE_WQ_FLUSH_MS` | `500` | WriteQueue flush interval in milliseconds. Controls how often buffered detections are flushed to the database. |

## Usage

### Service Management

```bash
# Start/stop/restart
sudo systemctl start rf-edge
sudo systemctl stop rf-edge
sudo systemctl restart rf-edge

# View status
sudo systemctl status rf-edge

# View logs
journalctl -u rf-edge -f
```

### Log Monitoring

```bash
# Tail the main log
tail -f /opt/rf-edge/logs/monitor_*.log

# Show only unique signals (when classification changes)
/opt/rf-edge/bin/tail-unique.sh

# View detection records
tail -f /opt/rf-edge/logs/detections_*.jsonl | python3 -m json.tool
```

### Status API

The monitor exposes an HTTP endpoint on port 8080:

```bash
# Get JSON status
curl http://localhost:8080/status

# From remote host
curl http://<pi-ip>:8080/status
```

**Response fields:**

| Field | Description |
|-------|-------------|
| `service` | Service name |
| `status` | Running state |
| `uptime_seconds` | Time since start |
| `scan_count` | Total frequency scans |
| `detections` | Total logged detections |
| `last_scan` | ISO timestamp of last scan |
| `rtl_connected` | RTL-SDR connection status |
| `frequencies` | List of monitored frequencies |
| `dwell_time_ms` | Dwell time per frequency |
| `model` | Full model metadata |
| `log_file` | Current log file path |

## Model Information

The open-default classifier (the `v0.1.0-models` release) recognizes 16
signal classes, collapsed from 45 training classes (the map is in its
`_metadata.json`): noise, tone, am, fm, ask, psk, qam, fsk, gfsk, msk,
ofdm, lora-css, dsss, adsb, fpv-analog and pocsag.

**Model specs:**
- Input: 8192 IQ samples (I/Q interleaved)
- Accuracy: 92.3% overall on a held-out synthetic test set (94.6% best
  validation). It is lower on real receiver data; the scanner rescales
  each window to unit average power, without which accuracy drops sharply.
- Inference: ONNX Runtime on the CPU, which is what the release soak ran.

## Detection Log Format

Detections are logged to JSONL format:

```json
{
  "timestamp": "2026-02-10T04:14:38.123456+00:00",
  "frequency_mhz": 433.92,
  "description": "ISM 433",
  "snr_db": 15.2,
  "power_db": -28.5,
  "classification": "ook",
  "confidence": 0.847,
  "family": "ask"
}
```

## Troubleshooting

### RTL-SDR not connecting

```bash
# Check if rtl_tcp is running
pgrep rtl_tcp

# Start rtl_tcp manually
rtl_tcp -a 127.0.0.1 &

# Check USB device
lsusb | grep RTL
```

### Hailo not detected

```bash
# Check Hailo device
hailortcli fw-control identify

# Check PCIe
lspci | grep Hailo

# View Hailo logs
cat /opt/rf-edge/logs/hailort.log
```

### Low inference speed

If seeing "HEF was compiled for Hailo8L device, while the device itself is Hailo8":
- The model works but may have reduced performance
- Recompile the HEF for Hailo8 using the Hailo Dataflow Compiler

### Log rotation

Logs auto-rotate at 5MB with 3 backups. System logrotate also configured:

```bash
cat /etc/logrotate.d/rf-edge
```

## Development

### Updating the Model

1. Train new model on workstation (see `training/README.md` and
   `training/train_open_default.py`)
2. Export to ONNX
3. Compile to HEF using the Hailo Dataflow Compiler
4. Deploy to Pi:

```bash
scp models/hailo_classifier.hef pi@<pi-ip>:/opt/rf-edge/models/
scp models/hailo_classifier_metadata.json pi@<pi-ip>:/opt/rf-edge/models/
sudo systemctl restart rf-edge
```

### Adding Frequencies

Edit `FREQUENCIES` dict in `monitor.py` and restart:

```python
FREQUENCIES = {
    ...
    154.57: 'Marine VHF',  # Add new frequency
}
```

## Files Reference

| File | Description |
|------|-------------|
| `bin/monitor.py` | Main monitoring loop with HTTP status server |
| `bin/tail-unique.sh` | Filter log to show only classification changes |
| `lib/node.py` | HailoClassifier with ONNX fallback |
| `models/*.hef` | Compiled Hailo model |
| `models/*.onnx` | ONNX model for CPU fallback |
| `models/*_metadata.json` | Class names and model info |

## Performance

| Metric | Value |
|--------|-------|
| Scan rate | ~4.5 Hz (8 frequencies @ 200ms dwell) |
| Inference time | ~3ms (Hailo), ~10ms (ONNX) |
| Memory usage | ~150MB |
| CPU usage | ~15% (with Hailo), ~40% (ONNX only) |
| Hailo utilization | ~12% @ 200ms dwell |

## License

MIT — see the repository [LICENSE](../../../LICENSE) file.
