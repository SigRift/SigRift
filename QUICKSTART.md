# Quickstart

On a native Linux host, connect your SDR receiver and/or a spare monitor-capable Wi-Fi adapter, clone the repo and run `scripts/quickstart.sh`. A fresh run automatically selects ready local SDR/Wi-Fi devices and starts their scanners alongside the dashboard and node-heartbeat agent. The default dashboard URL is `https://localhost:8444/`, with self-signed TLS. For Docker Desktop or an intentional hardware-free install, use `scripts/quickstart.sh --dashboard-only` instead.

> A pre-built release-pull path (`install-release.sh`: skip the Rust build, pull pinned GHCR images) is available from `v0.1.0`; see [Verifying a release](INSTALL.md#verifying-a-release).

Read [LEGAL.md](LEGAL.md) before scanning anything other than your own signals.

---

## Prerequisites

- Docker Engine 24.0+ with Compose plugin v2 (2.24.4+ for managed scanner selection). Prefer Engine 28.0+ (28.3.3+ on hosts running firewalld): on older engines, hosts on the same local network segment can reach ports published on `127.0.0.1`
- `python3` 3.11+ and `openssl` (for secret + TLS generation)
- `curl` for startup checks and optional model downloads
- A free TCP port (default 8444), and Docker storage for dependencies, build cache, images and persistent data. Source-build resource needs and duration depend on the host; allow the first build to complete before judging startup time.
- **Optional** — an RTL-SDR dongle and Linux USB access for RF capture; a monitor-mode Wi-Fi adapter and Bluetooth adapter for their respective scanners. These four hardware services stay disabled in dashboard-only mode.

Linux, macOS (Docker Desktop), and WSL2 all work. Raspberry Pi 4/5 with 8 GB is supported and is the target hardware. Automatic scanner selection requires native, rootful Linux Docker on the same host. It does not infer local hardware through Docker Desktop or a remote context. Wi-Fi discovery needs host `iw` and `iproute2`; SDR preparation uses an existing `plugdev` group.

---

## Build and run

```bash
git clone https://github.com/SigRift/SigRift.git
cd SigRift
scripts/quickstart.sh
```

This is the scanner-enabled first-run path on native Linux. Discovery selects only ready devices, protects the radio carrying SSH or routed traffic, and never selects Bluetooth automatically. If several spare Wi-Fi adapters are suitable, use `scripts/quickstart.sh --scanners=auto --wifi-interface=wlan1`, replacing `wlan1` with your spare adapter. Most hosts need a one-time preparation before the scanners can use the hardware (releasing the receiver's TV driver, a udev rule, keeping NetworkManager off the spare adapter). When it is needed, quickstart shows exactly what it will change and asks once to run it with `sudo`, then carries on in the same run; see [preparing the host](#preparing-the-host).

Check the printed `Selected scanners:` line. With no ready selection, it says `none (dashboard only)` and setup starts only the dashboard and node-heartbeat agent. Missing permissions, a kernel-owned receiver or ambiguous devices need attention; dashboard startup alone does not establish capture. After correcting the reported hardware issue, run `scripts/quickstart.sh --scanners=auto` to discover it again. Plain retries keep the saved selection.

For Docker Desktop or a fresh install without scanners, run `scripts/quickstart.sh --dashboard-only`. That option skips hardware discovery and model downloads; plain retries retain dashboard-only mode. The quickstart script:

1. Prompts for an admin password (twice). The password is written only to `.env` (chmod 0600, gitignored); it is never echoed, never logged. Then asks which environment preset to seed the anomaly baselines with — see [Environment presets](#environment-presets) below.
2. Generates five secrets into `.env`: `BRIDGE_MFA_KEY`, `BRIDGE_AUDIT_KEY`, `BRIDGE_MASTER_KEY`, `UC_PROXY_SECRET`, and `BRIDGE_LOCAL_NODE_KEY` (the pre-seeded NODE-role key the in-stack scanner services authenticate with). It saves the selected `BRIDGE_ENV` (`development` by default, or an explicit `production`) and `SIGRIFT_BIND` (`127.0.0.1` by default) — see [Who can reach it](#who-can-reach-it).
3. Generates a self-signed TLS cert into `./tls/` (0755 dir; cert 0644; key group 1500 — the gateway container's — and 0640, so other host users cannot read it). Its subjectAltName covers `localhost`, `127.0.0.1`, `::1`, `gateway`, `bridge`, this host's short name, FQDN and addresses, plus any names/IPs in `SIGRIFT_TLS_SANS` (comma-separated). On a re-run it is regenerated when it lacks one of those (keeping its other names) or expires within 30 days; the containers are recreated to pick it up. `scripts/quickstart.sh --renew-tls` (for a timer — INSTALL.md "Certificate renewal") only renews a cert that expires within 30 days, keeping its names: it never adds one, so remote edge nodes that pinned the cert are not broken by an unattended run.
4. Creates `docker-compose.override.yml` if it is absent, mounting TLS and configuring edge certificate trust. Managed scanner selection is saved separately in `.sigrift-scanners.yml`; existing overrides are preserved byte-for-byte. Dashboard-only mode leaves all four scanner services behind the inactive `hardware` profile.
5. Validates the resolved Compose configuration and selected devices. Dashboard-only mode requires exactly `bridge`, `gateway` and `edge`. Managed setup rejects `COMPOSE_FILE` and `COMPOSE_PROFILES` overrides. A selected SDR requires a model; a failed required download stops setup with retry instructions before the scanner starts.
6. Builds only those active services. It creates the bridge volumes and normalizes their ownership to the containers' uid 1500 before starting them.
7. Starts the stack, waits up to **240 seconds** for gateway health, then retries starting active dependent services if Compose's initial health wait expired.
8. Reads the running gateway's published address and port, then checks gateway health, bridge version, admin login, the authenticated user and recent detections over HTTPS. Wildcard bindings use the matching loopback address for this local check; specific addresses and quoted port settings are supported. The port lookup has a ten-second deadline. Each request allows up to five seconds to connect (including TLS) and 15 seconds in total, so a stalled endpoint cannot leave this check waiting indefinitely. Any failed check returns a nonzero exit status with log and retry commands; it never prints the success banner for a failed check. Configuration and data remain available for diagnosis.

When the script reports success, open its printed dashboard URL, accept the self-signed cert, and log in with the username printed by setup and the password you configured. The default local installation is also available at `https://localhost:8444/`. The first source build downloads dependencies and compiles images; its duration is separate from the startup health deadline. No cold-build completion time is promised.

### Environment presets

The quickstart script also asks which **environment preset** to seed. A preset pre-warms the RF anomaly baselines so scoring starts working immediately, instead of spending ~300 detections per frequency bin in learning mode. Presets are **fully synthetic** — generated from SigRift's signal factory, they contain no data from any real site. They only pre-warm the RF baselines; timing patterns (what's normal at 3 am vs 3 pm) still learn locally from your own environment.

Four profiles ship in-repo — pick whichever best matches where the sensor lives:

- `urban-dense` — city centres, apartment blocks, busy spectrum
- `suburban-residential` — the prompt's default
- `rural-quiet` — remote sites with little RF traffic
- `office-commercial` — offices and commercial buildings

Answer `none` to skip seeding and learn from scratch. Non-interactively (CI, scripted installs), set `SIGRIFT_PRESET=<profile>` (or `none`) in the environment or `.env` before the first `docker compose up` — compose passes it through to the bridge. Seeding happens only on first boot while no learned state exists yet; it never overwrites what the bridge has already learned, and a bad preset logs an error and starts cold rather than blocking startup. See [docs/bundle-format.md](docs/bundle-format.md) for how presets are built and validated.

### Re-runs and upgrades

`scripts/quickstart.sh` keeps the saved mode, credentials and custom override, checks the TLS certificate, rebuilds images, and verifies startup. If an earlier build or startup failed, correct the reported problem and run the same command again; do not delete `.env` or data volumes to retry. To pull updates:

```bash
git pull
scripts/quickstart.sh        # retains saved scanner choices or dashboard-only mode
```

### Enable hardware later

On the same Linux host, connect the receiver and a **spare** monitor-capable Wi-Fi adapter, then run:

```bash
scripts/quickstart.sh --scanners=auto
# Or choose only the scanner you want:
scripts/quickstart.sh --scanners=wifi --wifi-interface=wlan1
scripts/quickstart.sh --scanners=sdr
```

A fresh unflagged run also auto-detects. An existing hardware-disabled override is a constraint on that implicit first-run choice; the explicit command above opts into discovery. Setup never selects Bluetooth automatically. A single ready Realtek `0bda:2832`/`0bda:2838` receiver and an unambiguous spare Wi-Fi radio can be selected. Multiple suitable Wi-Fi adapters require `--wifi-interface`. This first version refuses multiple SDR receivers instead of guessing an unstable device index.

Discovery is read-only. It checks USB permissions/kernel ownership, monitor capability, interface addresses, all routing tables and the SSH client route. Every interface on a protected radio is excluded, including a virtual sibling of the interface carrying SSH. It never disconnects that radio, changes network settings or opens the gateway to the LAN. Running Docker containers in other projects that expose the selected USB device or can control host Wi-Fi cause setup to refuse the competing selection. This check cannot rule out arbitrary host capture processes; stop those yourself before assigning the radio. Selecting a safe Wi-Fi adapter authorizes the worker to put **that adapter** into monitor mode when it starts. Do not repurpose it for connectivity while the scanner is running.

#### Preparing the host

A fresh host usually needs one preparation before the scanners can use the hardware. For the RTL-SDR receiver it is needed: without it the scanner cannot open the receiver. For the spare Wi-Fi adapter it is recommended, not required (see [NetworkManager and the spare adapter](#networkmanager-and-the-spare-adapter) below). Quickstart handles it in the same run:

- In a terminal, it prints exactly what it will change and asks once, `Run it now with sudo? [y/N]`. The default is No. After a yes it runs the step with `sudo`, plans again and starts the scanners that are now ready.
- With `--prepare-host`, it runs the step without asking (for unattended installs). Without a terminal it uses `sudo -n`, so it fails instead of waiting for a password; allow it in sudoers or run quickstart as root.
- Without a terminal and without the flag, it never asks: it prints the single command and continues as before. `--no-prepare-host` never asks and never runs it.

The review and the `sudo` run act on the same devices: quickstart first asks `prepare --check` which receiver and adapter need preparing, then passes exactly those to both (`--scanners=…`, `--usb=<port>`, `--wifi-interface=<name>`). Because `sudo` removes `SSH_CONNECTION` from the environment, quickstart also passes your SSH client address (`--ssh-client`), which is only ever used to protect more interfaces. If `prepare --check` refuses (for example because a file at one of the paths below was not written by this tool), quickstart prints `Skipped host preparation:` with the reason and the review command, and continues the install.

A declined or failed preparation never stops the install: the dashboard and any scanners that are already ready still start, and setup says what was skipped. The flags cannot be combined with `--dashboard-only`, `--renew-tls` or `--scanners=none`.

The same step on its own, and how to review it first:

```bash
python3 scripts/scanner_setup.py prepare --print   # no root; changes nothing
sudo python3 scripts/scanner_setup.py prepare
scripts/quickstart.sh --scanners=auto
```

`prepare --print` lists every file it would write, with its full content, and every command it would run, in order. `prepare` acts only on the devices discovery found and would select once prepared, and refuses a receiver or adapter named with `--usb` or `--wifi-interface` that its own discovery would not accept. It never touches a protected radio (the one carrying SSH or routed traffic), also when you name it with `--wifi-interface`. With several receivers or several spare adapters it prepares none of them until you choose one with `--usb=<port>` or `--wifi-interface=<name>`; `--scanners=sdr` or `--scanners=wifi` limits it to one kind. When you type `sudo python3 scripts/scanner_setup.py prepare` yourself, `sudo` hides whether you are logged in over SSH; `prepare` then prepares a Wi-Fi adapter only when `--wifi-interface` names it, and says so. On this host it changes:

- **The RTL-SDR receiver.** It does what `prepare-rtl` does: it releases only that receiver's `dvb_usb_rtl28xxu` interface and sets its device node to `root:plugdev` mode `0660`. It then installs the receiver's udev rule as `/etc/udev/rules.d/70-sigrift-sdr.rules` (root:root `0644`; exactly what `prepare-rtl --usb=<port> --print-udev-rule` prints) and runs `udevadm control --reload-rules` and `udevadm trigger --subsystem-match=usb`. The rule keeps the permissions across re-plugs and reboots; the scanner releases the TV driver itself when it opens the receiver. A receiver without a usable serial gets no rule; `prepare` says so, and `prepare-rtl` has to be run again after each re-plug or reboot.
- **The spare Wi-Fi adapter, only when NetworkManager runs.** NetworkManager takes a spare adapter back after every reboot, also one that `nmcli device set <adapter> managed no` released earlier. So `prepare` decides from the file, not from the adapter's current state: unless its own file for that adapter is in place and the adapter is unmanaged, it writes `/etc/NetworkManager/conf.d/90-sigrift-scanner.conf` (root:root `0644`), which tells NetworkManager to leave alone the one adapter with that permanent hardware address (`unmanaged-devices+=mac:<address>`, which adds to any list you set elsewhere), and runs `nmcli general reload`. It then checks that the adapter is `unmanaged` before doing anything else. If the file alone did not do it, `prepare` still runs `nmcli device set <adapter> managed no` so the adapter is free for now, says that the persistent setting did not take effect, and exits non-zero. It prepares an adapter only while NetworkManager reports it `unmanaged`, `disconnected` or `unavailable`; for `connecting`, `connected` or any other state it refuses and names the state, so you release an adapter in use on purpose (for example `sudo nmcli device disconnect wlan1`). Without NetworkManager there is nothing to do. Setup prints a `note:` line for an adapter that NetworkManager manages; that adapter can still be selected.

`prepare` needs root and refuses without it. It writes each file atomically and never overwrites a file it did not write. A file at either path that this tool did not write (no marker on its first line, or a symlink), or one it wrote for a different receiver or adapter, is left as it is, and `prepare` stops with a message before changing anything. A file it wrote earlier for the same receiver or adapter whose text differs (for example from an older version) is replaced. Running it again changes only what is not yet in place. It ends with a short summary: what changed, what was already in place, and the undo command.

To undo it:

```bash
python3 scripts/scanner_setup.py unprepare --print   # no root; changes nothing
sudo python3 scripts/scanner_setup.py unprepare
```

`unprepare` removes only those two files, and only when they carry this tool's marker, then reloads udev and NetworkManager. The receiver keeps its current permissions until it is re-plugged or the host reboots, which returns it to the default. NetworkManager takes the adapter back as soon as it reloads (measured on a Raspberry Pi); the Wi-Fi scanner keeps running and its capture pauses briefly whenever NetworkManager takes the adapter.

On an existing installation whose selected receiver has lost its preparation (after `unprepare`, a removed rule, or an install made before this step existed), a plain `scripts/quickstart.sh` retry offers the same step instead of stopping, and `--prepare-host` runs it. A scanner container that was started before the host was prepared still sees the receiver's old permissions, because Docker copies device nodes when a container starts; setup recreates such a container (one that is running but unhealthy) when it starts the scanners.

##### NetworkManager and the spare adapter

Preparing the Wi-Fi adapter is recommended, not required. Measured on a Raspberry Pi: when NetworkManager took the adapter while the scanner was capturing, capture stopped for about 17 seconds. The scanner logged `Ending capture round: wlan1 left monitor mode`, put the adapter back into monitor mode and resumed by itself, and then ran undisturbed for the following 56 minutes with NetworkManager still managing the adapter. Releasing the adapter again interrupted capture once more, for about 15 seconds. So an adapter that NetworkManager manages is still selected; setup prints a `note:` line for it, and `prepare` removes that interruption.

The manual equivalents, step by step:

```bash
sudo python3 scripts/scanner_setup.py prepare-rtl --usb=1-2            # releases the driver, sets root:plugdev 0660
python3 scripts/scanner_setup.py prepare-rtl --usb=1-2 --print-udev-rule  # no root; save as /etc/udev/rules.d/70-sigrift-sdr.rules
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=usb
sudo nmcli device set wlan1 managed no                                    # until the next reboot only
scripts/quickstart.sh --scanners=auto
```

Discovery still prints the `prepare-rtl --usb=<port>` line for a receiver that needs it, and below the device lines one line with the single `prepare` command for a host that needs any preparation. `prepare-rtl` releases only that receiver's TV driver interface and sets its verified, open USB device node to `root:plugdev` mode `0660`. It does not unload modules, write a global blacklist, change other devices or install a udev rule, so a re-plug or reboot resets it. The scanner then reports `error` with reason `sensor_unusable`: the receiver is connected, but it cannot be opened. A partial failure is reported; retry the same scoped command after correcting the problem. Unsupported drivers, missing `plugdev`, symlinked device nodes, non-USB nodes and non-root invocation are refused. `--print-udev-rule` needs no root and changes nothing. Its rule matches the receiver's USB port, model and serial, and sets group `plugdev` and mode `0660`. Its comment lines say where to save it, how to load it and how to undo it (delete the file and run the same two commands). The serial appears only in this local output and in the installed rule. A receiver without a serial, or with one that contains unusual characters, gets no rule.

Because `rtl-tcp` maps the receiver's whole USB bus directory and joins the receiver's group, setup refuses a receiver whose device node has group `root`, or a group that can also open another device on the same bus. `prepare` (or `prepare-rtl`) gives the receiver group `plugdev`.

Before prompting or creating setup files, managed selection checks the installed Compose parser with a read-only stdin configuration. It requires `!override` support (Compose 2.24.4+); a failure explains how to upgrade or choose a fresh dashboard-only install.

Selection is saved in the private, non-secret `.sigrift-scanners.yml` overlay. Before TLS/model work, desired device identities are atomically saved in a separate `0600` `.sigrift-scanners-pending.json` record. If a download fails, a plain retry revalidates those same devices and retries the transfer; the prior active overlay/workers remain unchanged. Successful activation clears the pending record. Explicit `--scanners=none` cancels pending hardware intent. Edited or symlinked pending records are refused, not overwritten. Existing `.env`, `docker-compose.override.yml`, exposure and data are preserved. Plain quickstart retries revalidate the saved identities; they do not silently downgrade a missing scanner or switch to a different device. Explicit `--scanners=auto` rediscovers; `--scanners=none` stops only previously managed workers and keeps the dashboard. Manually edited managed overlays and unrelated running scanner services require reconciliation instead of being overwritten or stopped. `COMPOSE_FILE`/`COMPOSE_PROFILES` must be unset for this managed path. Ordinary Compose commands do not load the extra overlay; use quickstart to start/recreate selected workers, and ordinary `docker compose down` to stop the project.

New Wi-Fi selections remember a fingerprint of the adapter's permanent hardware address and physical connection path. A plain retry can recognize that adapter on the same interface and USB port even if Linux assigns it a new internal radio number. Moving it to another port, renaming the interface, or replacing the adapter requires explicit reselection. If the driver cannot provide a reliable identity, setup refuses to guess. The fingerprint stays in the private selection files and is not sent in the dashboard host report.

When a selected sensor is unplugged, its scanner keeps running: it logs one line, reports `error` with reason `sensor_absent` to the dashboard and checks again every few seconds. While the SDR receiver is away, `docker compose ps` shows `rtl-tcp` as unhealthy; this is expected. When the same sensor is plugged back in, capture resumes without any action, even though Linux gives it a new device number or radio number, as long as the host still lets the scanner open it. On a host that needed preparation but has no udev rule (for example after `prepare-rtl` alone), the SDR instead reports `sensor_unusable` until `prepare` or `prepare-rtl` is run again. The next quickstart run, `--renew-tls` restart or `scanner_setup.py start` also refreshes those numbers in `.sigrift-scanners.yml`. The same sensor means the same USB port and identity for the SDR, and the same interface name and fingerprint for Wi-Fi. A different receiver or adapter in its place is not used: the scanner reports `sensor_changed`, and setup refuses it and prints the quickstart command that selects the new hardware. Moving a sensor to another USB port also needs that reselection. Overlays written by an earlier version are recognised and upgraded by the next quickstart run.

Older saved Wi-Fi selections need one explicit reselection to record that identity. Setup prints the command with **all** previously selected scanners, so keep those choices unless you intend to remove one. For example, a Wi-Fi-only installation uses `scripts/quickstart.sh --scanners=wifi --wifi-interface=wlan1`; one that also uses SDR keeps `--scanners=sdr,wifi`. Existing selection and configuration files are preserved if verification fails. This retry support does not install boot services or persistent USB permission/driver rules; only the explicit `prepare` step installs the udev rule.

Only selected SDR installs discover/download a model. Setup uses the newest `.onnx` under `models/`, or attempts the pinned `v0.1.0-models` release, then creates the canonical model/metadata aliases. A missing/empty model fails setup before starting the scanner. This is a file/readiness check, not a model-accuracy validation. Dashboard/Wi-Fi-only choices leave model files untouched.

Model-release requests allow ten seconds to connect, including TLS, and stop if transfer speed stays below 1 KiB/s for ten seconds. The model has a fifteen-minute total limit; release information, checksums and the metadata sidecar each have a thirty-second limit. Failed required downloads discard staged partial files and stop setup without starting the selected scanner. Correct the connection problem and run the same command again to retry the saved choice; no automatic request retries run. A model is activated only with its `<model>_metadata.json` sidecar, the JSON file whose `"classes"` list names the model's outputs in order. For a downloaded model, setup stops without activating it if the release has no sidecar for it or the sidecar does not match `SHA256SUMS`. If the sidecar download or its move into `models/` fails, setup also stops, unless a regular sidecar file for that same model is already in `models/` from an earlier run. A local model (the newest `.onnx` in `models/`, or a real `models/open-default.onnx`) without its sidecar stops managed scanner setup and changes nothing: add the sidecar, or remove the model so setup downloads the release model with its metadata. An older installation that starts its scanners itself gets a warning instead; its scanner then refuses to start unless the model's output count matches its built-in class list.

The success message distinguishes started processes from physical capture readiness. Scanner tabs depend on the worker's live capture lease; generic edge heartbeats or old observations cannot make a scanner tab live. For a failed start, inspect `docker compose logs --tail=60 scan rtl-tcp wifi-scan`, correct the reported problem and rerun quickstart. No host driver or permission preparation is ever automatic.

After setup, quickstart also attempts a sanitized host check for the installed local node. The dashboard's **Setup and capture checklist** keeps this report, live capture and the most recent stored data separate. The report contains only SDR/Wi-Fi readiness, saved-selection state and fixed reason codes; it sends no adapter serials, interface names, device paths or SSIDs. It uses the existing node-bound credential and installed gateway certificate. Dashboard-only installs explicitly report that hardware was not checked.

A host check is fresh for five minutes, then remains visible as a stale last check. This is an authenticated host self-report, not continuous hardware monitoring or independent proof of capture. A healthy capture lease remains meaningful when its host check is old or the air is quiet. An ordinary setup retry checks the same saved selection again; unplugged or blocked selected devices remain selected. When an existing installation cannot finish planning or starting a worker, quickstart attempts to report that condition using only its existing configuration. Failed delivery does not reverse a successful install or change saved choices. Separately managed scanner hosts need their own reporting integration; this step does not attribute their hardware to the dashboard host.

### Change an existing installation to dashboard-only

For a managed scanner installation, run `scripts/quickstart.sh --scanners=none`. It stops only workers in its saved selection, preserves data and leaves the three core services running. `--dashboard-only` remains the hardware-free option for a fresh install and for a previously managed selection.

A legacy installation without a managed selection must be adopted explicitly with `--scanners=auto` or `--scanners=none`; a plain retry fails before changing files. If unrelated scanner services are already running, stop/reconcile those project services yourself first. Existing custom Compose files, profiles and overrides are never silently converted. The historical `SIGRIFT_QUICKSTART_MODE=hardware` value alone no longer authorizes starting every hardware service.

### Stop / reset

```bash
docker compose down          # stop, preserve all state
docker compose down -v       # DESTRUCTIVE — wipes the bridge_data volume:
                              # detections.db, keys.json, sessions, user
                              # accounts (incl. admin), audit.key (in dev).
                              # Use only when you want a clean slate.
```

See [INSTALL.md §"Stopping, resetting, upgrading"](INSTALL.md#stopping-resetting-upgrading) for the full breakdown of what `-v` destroys — and how to export the learned anomaly baselines first so the wipe is recoverable.

---

## What the stack runs

`docker-compose.yml` defines seven services. A fresh plain quickstart starts the first three plus the ready SDR/Wi-Fi services it selects. `--dashboard-only` starts just the first three; Bluetooth is never selected automatically. [Enable hardware later](#enable-hardware-later) to discover newly connected devices or change a saved selection.

| Service | What it does | Notes |
|---|---|---|
| `bridge` | FastAPI app — routers, storage, alerting, dashboard rendering. Loopback-only (`expose: 8001`). | Owns the `bridge_data` volume. |
| `gateway` | Rust TLS terminator + auth proxy. Publishes the dashboard on `${UC_PORT:-8444}`. | Validates `UC_PROXY_SECRET`; loads TLS from the bind-mounted `./tls/` dir. |
| `edge` | Node-heartbeat agent. Reports liveness + system metrics to the bridge. | Authenticates with `BRIDGE_LOCAL_NODE_KEY`. No SDR ingest in this service. |
| `rtl-tcp` | Owns the USB SDR and exposes it as a TCP stream on the compose-internal network (port 1234). | Managed selection mounts only the selected receiver's USB bus directory (`/dev/bus/usb/<bus>`) and uses that receiver's numeric group. |
| `scan` | Reads IQ from `rtl-tcp`, runs ONNX inference against `/app/models/open-default.onnx`, POSTs detections to the gateway. | Managed setup refuses a missing/empty model before starting it. |
| `wifi-scan` | Puts a wlan interface (default `wlan1`) into monitor mode, channel-hops, captures 802.11 management and data frames (first 512 bytes), decodes beacons + probes, batch-POSTs to `/api/wifi/ingest`, and keeps the last 500 raw frames in memory; its pcap upload on a Wi-Fi anomaly is refused for the in-stack node key in this release ([LEGAL.md](LEGAL.md) §4, "Wi-Fi capture scope"). | **`network_mode: host` + `NET_ADMIN`/`NET_RAW`** — see below. |
| `bt-scan` | Uses BlueZ over the host DBus to discover Classic + BLE devices, posts to `/api/bluetooth/ingest`. | **`network_mode: host` + `NET_ADMIN`/`NET_RAW`** — see below. |

### About the privileged sidecars

`wifi-scan` and `bt-scan` are the only services that run with elevated host privileges. They are not in the request path — they only push data **into** the bridge over the same authenticated API a remote edge agent would use. Because they parse attacker-controlled over-the-air frames they are not `privileged`: all capabilities are dropped and only the needed ones added back.

- **`wifi-scan`** — runs as root with `NET_ADMIN` + `NET_RAW` (for `iw … set monitor` and `tcpdump`) plus `SETUID`/`SETGID` (tcpdump drops to its own user), and `no-new-privileges`; `network_mode: host` because monitor mode is a per-netns property and Docker's default bridge net hides the host's wlan interfaces.
- **`bt-scan`** — runs as uid 1500 with `NET_ADMIN` + `NET_RAW` in its bounding set for raw HCI access via `hcitool`'s file capabilities; `network_mode: host` plus a `/var/run/dbus` bind-mount so BlueZ speaks to the host system bus.

Both capability sets are derived from the scanners' code paths, not validated against every adapter; see [INSTALL.md §"Privileged sidecars"](INSTALL.md#privileged-sidecars).

Dashboard-only mode leaves both scanners inactive. Managed setup starts only selected services; Bluetooth remains inactive.

---

## What you should see

- Open the verified dashboard URL printed by setup (`https://localhost:8444/` with the default binding) and log in with the username printed by setup (`admin` by default) and the password you entered. A password supplied during setup does not require a forced change on first login.
- After login, Summary shows the local node-heartbeat agent and the **Setup and capture checklist**. Node contact confirms the agent is online; it does not mean a scanner is capturing. Dashboard-only setup reports hardware as not checked, starts no scanner, and has no RF/Wi-Fi observations. Scanner tabs appear only after their services report active capture.
- **Admin → API Keys** (top-right of the dashboard) lets you mint a NODE-role key for an edge agent.

### Who can reach it

The quickstart defaults to a lab install. For a **fresh** production installation on native Linux, including automatic scanner selection, run:

```bash
BRIDGE_ENV=production scripts/quickstart.sh
```

Add `--dashboard-only` for a hardware-free production installation.

The selected mode is written to the new `.env`, so later plain retries and Compose commands retain it. Explicit shell overrides accept `production` or `development`; unset `BRIDGE_ENV` to use an existing `.env`. Existing files are preserved: a shell override on a retry affects that invocation only. To change an existing installation permanently, edit `BRIDGE_ENV` in `.env` and run `docker compose up -d`.

- **Development mode by default.** With `BRIDGE_ENV=development`, generated secrets are real but CSRF and legacy-auth guards are relaxed, and weak secrets are only warned about. The production option above enables the production guards; every required secret is generated in either mode. The release installer (INSTALL.md "Verifying a release") also installs in production mode.
- **This machine only.** The gateway is published on `127.0.0.1:8444`. To reach the dashboard from other machines — or to connect edge nodes on other hosts — set `SIGRIFT_BIND=0.0.0.0` in `.env` (or run `SIGRIFT_BIND=0.0.0.0 scripts/quickstart.sh`) and `docker compose up -d`. Use production mode when you do (`BRIDGE_ENV=production`): development mode turns CSRF protection off and does not mark the session cookie `Secure`. On Docker Engine before 28.0, hosts on the same network segment can reach the `127.0.0.1` port anyway.

The script's closing message says which address and mode the running stack actually uses.

---

## Edge / SDR scanning

Two paths, depending on whether the SDR is on the same machine as the bridge.

### Same host (enable hardware explicitly)

Run `scripts/quickstart.sh --scanners=sdr` with a ready receiver and model. Setup starts `rtl-tcp` and `scan` alongside bridge/gateway/edge. They:

- `rtl-tcp` owns the selected receiver and exposes the SDR as a TCP stream on the compose-internal network (port 1234). It maps that receiver's USB bus directory, `/dev/bus/usb/<bus>`, so a re-plugged receiver with a new device number is still visible; the container can see the other device nodes on that bus, but only open those whose permissions allow it. Setup refuses a receiver whose group is `root` or can also open another device on that bus. Runs with the selected receiver's numeric group so appuser can open that device.
- `scan` reads IQ from `rtl-tcp`, runs ONNX inference against `/app/models/open-default.onnx` (the symlink quickstart creates), and posts detections back to the bridge using the pre-seeded NODE-role key.

You don't need to mint an API key by hand for this path — `BRIDGE_LOCAL_NODE_KEY` (in your generated `.env`) is pre-registered on bridge boot. Capture readiness and observations are separate from gateway health; check the live scanner status and logs.

For a host without scanner hardware, use the dashboard-only setup above. To convert an existing installation, follow [Change an existing installation to dashboard-only](#change-an-existing-installation-to-dashboard-only).

### SDR on a different host

The one-line installer below sets up the **heartbeat agent only** on another machine: that host then shows as a live node, but it does **not** capture RF or send detections. In this release, scanning with an SDR on another host means either a separate SigRift install there (`scripts/quickstart.sh --scanners=sdr`, with its own dashboard) or setting up `rf_scan` by hand as described in [src/sigrift/edge/README.md](src/sigrift/edge/README.md) (manual, and not covered by the release soak).

To install the heartbeat agent on another machine, pointed at the bridge over the network:

```bash
# 1. Mint a NODE-role API key in the dashboard
#    Admin (top-right) → API Keys → New → role: NODE → copy value (shown once)

# 2. Copy the gateway's self-signed certificate to the SDR host
#    (tls/cert.pem in the directory you ran quickstart.sh from)
scp <bridge-host>:SigRift/tls/cert.pem gateway-cert.pem

# 3. On the SDR host, install the standalone edge agent
curl -sfL --cacert gateway-cert.pem https://<bridge-host>:8444/api/edge/install.sh | \
    sudo bash -s -- \
        --api-url https://<bridge-host>:8444 \
        --ca-cert gateway-cert.pem \
        --api-key <YOUR_NODE_KEY>
```

The edge agent verifies the gateway's certificate, so `<bridge-host>` must be a name or address the certificate lists. quickstart.sh puts this host's short name, FQDN and addresses in it (check with `openssl x509 -in tls/cert.pem -noout -ext subjectAltName`); add others — a DNS alias, a NAT or Tailscale address — with `SIGRIFT_TLS_SANS=name,ip scripts/quickstart.sh`, then copy the regenerated `cert.pem` again. Certificates from older quickstart versions list only `localhost`: re-running quickstart.sh upgrades them. See [INSTALL.md §"Gateway certificate for remote edge nodes"](INSTALL.md#gateway-certificate-for-remote-edge-nodes).

The installer checks that it can verify the gateway, then creates `/opt/sigrift-edge/`, blacklists the kernel DVB drivers (ready for a manually installed scanner), and starts `sigrift-edge.service`, which runs the heartbeat agent (`sigrift.edge.node_agent`) only. See [INSTALL.md](INSTALL.md) §"Distributed deployment" for multi-edge fleet patterns.

---

## Restore points and rollback

A checkout with data keeps the same guards as a release install. Its
state directory is `${XDG_STATE_HOME:-~/.local/state}/sigrift/<project>/`
(the file `.sigrift-state` in the checkout names it, so `sudo` finds the
same one); keep it in the same backup class as your secrets.

- `git pull && scripts/quickstart.sh` is a guarded upgrade when the commit
  or an image changed: the images the stack runs get a
  `sigrift-prev-<commit>` tag, the new ones are built while the old stack
  serves, then the stack stops and a full restore point (both data volumes,
  `edge_data`, the PKI directory when its overlay is used, `.env` and
  `tls/`) is taken before the new images start. A re-run of the same
  commit takes none.
- Quickstart never rolls back by itself. A failed start prints the two
  commands: `git -C <checkout> checkout <commit> && scripts/quickstart.sh --rollback`.
- `--rollback` refuses unless the checkout is at the restore point's commit
  (`HEAD`) and `docker-compose.yml`, `docker-compose.pki.yml` and
  `docker-compose.staging.yml` are unmodified (`git stash` first). It
  re-tags the kept images (it rebuilds them from that checkout when they
  were pruned) and starts them with `--no-build`. It asks for the commit's
  first 12 characters (`--confirm`).
- While an operation runs, `docker-compose.yml` is a placeholder (the
  hold) and `git status` shows it modified; do not `git checkout --` it
  until `scripts/quickstart.sh --status` says the operation is done.
- The `sigrift-prev-*` images use disk until no restore point names their
  commit (each successful upgrade removes those tags).
- `--status`, `--resume`, `--abort`, `--snapshot`, `--list-snapshots`,
  `--rollback --finish`, `--export FILE [--move]`, `--import FILE` and
  `--reactivate` work as in INSTALL.md ("Upgrading a release install",
  "Move to new hardware").

---

## Where to next

- [INSTALL.md](INSTALL.md) — production install (real TLS, systemd, secrets management, distributed mode)
- [ARCHITECTURE.md](ARCHITECTURE.md) — what each piece does
- [SECURITY.md](SECURITY.md) — env-var reference, threat model
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — common first-run issues
- [LEGAL.md](LEGAL.md) — acceptable-use terms (read before scanning anything)
