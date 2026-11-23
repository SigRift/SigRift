# SigRift Production Readiness Checklist

Goes from quickstart-grade ("works on my Pi") to persistent-install-grade
("survives reboots, hardware swaps, operator turnover, and a security audit").
Group items by category, mark off as you go.

---

## 1. TLS / certs

The installers (`scripts/quickstart.sh`, `install-release.sh`) generate a
self-signed cert. That's fine on a tailnet but unacceptable when the
dashboard is reachable from anywhere else.

- [ ] **Replace self-signed cert with a real one.** Options:
  - Let's Encrypt via `certbot` + DNS-01 challenge (works behind firewalls)
  - Internal PKI (your org's existing CA) — issue a cert with SAN covering all
    DNS names the gateway is reached by (operator browser, compose internal
    DNS: `gateway`, `bridge`)
  - Cloudflare Origin Cert if fronting via Cloudflare
- [ ] **Drop the cert at `tls/{cert,key}.pem` in your install dir** (chown
      `root:1500`, mode `0640` key / `0644` cert) so the gateway picks it up
      unchanged.
- [ ] **Set up cert rotation.** For the installers' self-signed cert, a
      weekly `scripts/quickstart.sh --renew-tls` (or
      `bash install-release.sh --renew-tls`) renews it before it expires
      and recreates every running service that uses it (INSTALL.md
      "Certificate renewal"). After you replace a cert yourself (certbot,
      your CA), recreate the gateway and the heartbeat agent, then rerun
      the quickstart so it recreates the scanners it selected, with their
      overlay (naming scanners in `docker compose up` would start ones you
      never selected; the marker file tells the quickstart the cert
      changed): `docker compose up -d --force-recreate --no-deps gateway edge`,
      then `touch tls/.recreate-pending && scripts/quickstart.sh`. On an
      `install-release.sh` install, which runs only the bridge and
      gateway, recreate just `gateway`.
- [ ] **Document the cert's CA path** in your ops runbook — operators need it
      to verify the cert when SSHing in.

## 2. Auth hardening

- [ ] **Change the admin password** from the one set at install time.
      Use the dashboard's profile menu (preferred), or the container
      one-liner in
      [TROUBLESHOOTING.md §"Admin password lost"](TROUBLESHOOTING.md#admin-password-lost).
- [ ] **Enable MFA on every admin/analyst user** (admin panel → Users → MFA).
      TOTP secret stored encrypted with `BRIDGE_MFA_KEY`.
- [ ] **Mint per-scanner API keys** instead of using the single
      `BRIDGE_LOCAL_NODE_KEY` for all scanners. Each scanner gets its own
      key with `role=node`. Rate limits then apply per-scanner instead of
      aggregating.
- [ ] **Rotate `BRIDGE_MASTER_KEY`, `BRIDGE_AUDIT_KEY`, `BRIDGE_MFA_KEY`**
      on a schedule (quarterly is reasonable). Note that MFA secrets are
      encrypted with `BRIDGE_MFA_KEY` — rotating it requires re-enrolling
      all TOTP users. Audit chain breaks if `BRIDGE_AUDIT_KEY` rotates
      without a planned cutover.
- [ ] **Consider mTLS for scanner → gateway** if scanners run on hosts
      outside the trust boundary. Client certificates from the bridge's
      CA are opt-in (API keys stay the default); see
      [PKI_ARCHITECTURE.md](PKI_ARCHITECTURE.md).
- [ ] **Audit the keys list quarterly** — `GET /api/keys/` (viewer role)
      returns all keys masked. Revoke stale entries.

## 3. Network / firewall

- [ ] **Front the gateway with a reverse proxy** if it must be public-facing
      (nginx / caddy / traefik). Benefits: real WAF, request size caps,
      proper logging, automatic redirect from `:80`, support for ACME.
- [ ] **Restrict ingress** to the gateway port (`UC_PORT=8444` default) at
      the host firewall. Only the reverse proxy / known operator IPs should
      reach it directly.
- [ ] **iptables connection limits** as a cheap DoS pre-filter:
      ```
      iptables -A INPUT -p tcp --syn --dport 8444 \
        -m connlimit --connlimit-above 50 -j REJECT
      ```
- [ ] **Bind compose internal services to `127.0.0.1`**, never `0.0.0.0`,
      so `bridge:8001` and `rtl-tcp:1234` aren't reachable off-host even
      with a misconfigured firewall.
- [ ] **Use tailscale (or wireguard) for operator access** instead of
      exposing the dashboard publicly. Removes the entire "public-internet
      flood" threat surface.

## 4. Persistence + backups

- [ ] **Back up `bridge_secrets` with `bridge_data`.** The CA private key
      lives in the `bridge_secrets` volume (bridge only); losing it
      invalidates every issued client certificate.
- [ ] **Move the `bridge_data` docker volume to a known host path**
      (`/var/lib/sigrift/data` or similar) so backups don't have to traverse
      docker volume internals:
      ```yaml
      volumes:
        bridge_data:
          driver: local
          driver_opts:
            type: none
            o: bind
            device: /var/lib/sigrift/data
      ```
- [ ] **Back up `keys.json`, `detections.db`, `audit.log`, `users.json`,
      `nodes.json`, `.env`, `tls/`** on a schedule. Daily incremental,
      weekly full. Encrypt at rest (the audit log + keys file are sensitive).
- [ ] **Test a restore from backup** before you need it. Pull the most recent
      backup to a clean host, run `docker compose up`, log in, verify
      detections.db has recent records.
- [ ] **Document the recovery procedure** — what to restore, in what order,
      what to manually re-run after restore.
- [ ] **Off-host the backup** (not on the same machine). S3 / B2 / restic
      to remote target.

## 5. Disk + log management

- [ ] **Enable docker log rotation** (otherwise json-file logs grow unbounded):
      ```
      /etc/docker/daemon.json:
      {
        "log-driver": "json-file",
        "log-opts": { "max-size": "50m", "max-file": "5" }
      }
      ```
- [ ] **Cap `detections.db` growth** — set a retention policy via admin
      settings (e.g. 90 days); the bridge's periodic cleanup loop
      enforces it.
- [ ] **Monitor `/var/lib/docker` and the persistence dir** disk usage.
      Alert at 80%.
- [ ] **Log model file size** — ONNX models can be hundreds of MB; track
      their versions in `models/` in your install dir and prune old ones.

## 6. Monitoring / observability

- [ ] **Scrape `/api/healthz` (200 = up) and `/api/ready` (200 = bridge has
      finished lifespan)** from your monitoring system. Alert on 10+
      consecutive failures.
- [ ] **Scrape `/api/status` for per-node `last_seen`** and alert when a
      scanner goes stale (>120s) or offline (>300s).
- [ ] **Set up structured log aggregation** — ship bridge / gateway logs to
      Loki / ELK / CloudWatch. The bridge already logs JSON.
- [ ] **Audit log review cadence** — `/var/lib/sigrift/data/audit.log` is the
      chain-of-custody record. Set up a weekly automated review or alert on
      specific events (key creation, user deletion, settings changes).
- [ ] **Activity log retention** — decide how long to keep the rolling
      activity log (the one shown on the dashboard). Default trims at N
      entries; set a longer retention if you need post-incident forensics.
- [ ] **Metrics dashboard** — if running multiple deployments, hook
      `/api/system/metrics` (or similar) into Prometheus + Grafana.

## 7. Update / deploy strategy

- [ ] **Pin image tags to a release, not `:main`,** in production, by hand
      or via a GitOps tool (ArgoCD / Flux) that updates the tag from a
      release manifest.
- [ ] **Test updates on a staging host before production.** Let a new
      release run there for 24h before promoting it.
- [ ] **Document the rollback procedure.** Start from
      [UPGRADE.md §"Docker Rollback"](src/sigrift/bridge/UPGRADE.md#docker-rollback);
      a rollback needs the pre-upgrade database.
- [ ] **Subscribe to SigRift releases and advisories** (on GitHub:
      Watch → Custom → Releases, and the repository's Security →
      Advisories page).

## 8. Hardware (Pi 5 / sensor host specific)

- [ ] **UPS for the sensor host.** Even a small one — a 10-minute hold
      buys clean shutdown.
- [ ] **Stable hostname.** `MLRF_NODE_ID` defaults to `$HOSTNAME`; if the
      host renames mid-life, the node row in the bridge changes too. Set
      hostname explicitly during provisioning and don't change it.
- [ ] **Persistent USB mappings.** If you have multiple USB SDRs, use udev
      rules to give them stable `/dev/bus/usb/...` entries so `rtl-tcp -d 0`
      always picks the intended one.
- [ ] **Driver build-from-source caveats.** RTL8812BU (Archer T3U) DKMS
      module rebuilds on every kernel upgrade — verify it rebuilt before
      restarting the WiFi-dependent services.
- [ ] **Document the hardware inventory** per node (chipset IDs, USB ports,
      antenna types, location). Useful for triage.

## 9. OS hardening (host running compose)

- [ ] **SSH: keys only, no passwords.** Disable `PasswordAuthentication` in
      `/etc/ssh/sshd_config`.
- [ ] **Run `fail2ban`** against SSH (and the reverse proxy access logs if
      public).
- [ ] **Enable unattended security upgrades** (Debian `unattended-upgrades`,
      Ubuntu equivalent). Restrict to `*-security`.
- [ ] **`auditd` rules for the install dir's `.env` and `tls/`** so
      any read/write attempt is logged.
- [ ] **Remove unneeded packages.** A sensor host doesn't need a desktop
      environment.
- [ ] **Time sync** — `chronyd` or `systemd-timesyncd`. Audit timestamps
      depend on it.
- [ ] **Set a host-level resource floor** so docker can't OOM-kill itself
      (`vm.swappiness`, kernel hugepages off).

## 10. Compose hardening

- [ ] **Drop unneeded capabilities** per service. `wifi-scan` and `bt-scan`
      need privileged or `CAP_NET_ADMIN`; others should run as non-root
      with `cap_drop: [ALL]`.
- [ ] **Resource limits** (`mem_limit`, `cpus`) on each service so a
      runaway scanner can't starve the bridge.
- [ ] **`read_only: true`** for bridge + gateway, with `tmpfs:` mounts for
      `/tmp`. Edge containers may need writable scratch for IQ samples.
- [ ] **No `:latest` or `:main` in production compose** — see update strategy.
- [ ] **Healthchecks** — already present for bridge / gateway / rtl-tcp;
      add for `edge`, `scan` if their failure modes don't already crash
      the container.

## 11. Secrets management

- [ ] **`.env` permissions: `0600`, owned by `root`** (bootstrap already
      does this; verify it stuck).
- [ ] **Never commit `.env` to git.** The `.gitignore` covers it; double-check.
- [ ] **Use a secret manager** for the source of truth (HashiCorp Vault,
      AWS SSM Parameter Store, etc.) and fill `.env` from there, if your
      environment supports it.
- [ ] **Rotate secrets after operator turnover.** When someone with admin
      access leaves: rotate `BRIDGE_ADMIN_PASSWORD`, `BRIDGE_MASTER_KEY`,
      revoke their personal API keys, force-logout all sessions via the
      admin panel.

## 12. First-boot procedure (one-time per host)

A condensed runbook for spinning up a new production node:

1. Provision the host with your standard hardened base image (SSH keys,
   `unattended-upgrades`, `fail2ban`, time sync, monitoring agent).
2. Install docker + compose v2.
3. Install SigRift with `scripts/quickstart.sh` or the release installer
   (v0.1.0 and later; see [INSTALL.md](INSTALL.md)).
4. Drop your real TLS cert + key into the install dir's `tls/`.
5. Drop your real `.env` (from secrets manager / sealed-secrets / manually
   typed at the console — never via a file in cleartext on the wire).
6. `docker compose up -d`.
7. Check `https://<host>:8444/health` returns `ok` (INSTALL.md
   "Verifying the install").
8. Log into the dashboard and:
   - Change admin password
   - Enable MFA on all admin users
   - Mint per-scanner API keys
   - Verify each scanner node appears in the Edge-nodes panel
9. Schedule the first backup + verify the backup destination is reachable.
10. Add the host to your monitoring system's inventory.
11. Document the host in your asset registry (location, hardware, contact,
    last-touched date).

## 13. What this checklist does NOT cover

- **Multi-tenant deployments** — current model is single-tenant. Sharing a
  bridge between unrelated teams requires the full mTLS rollout plus
  tenant isolation at the API layer that doesn't exist today.
- **High availability** — there is no built-in clustering for the bridge.
  Active/passive with a shared persistence path + manual failover is the
  closest current option.
- **Compliance frameworks** — no formal compliance mapping (SOC 2,
  FedRAMP, ISO 27001, HIPAA) ships with the community edition; those
  would need additional controls and evidence collection on your side.
- **DDoS protection at scale** — `iptables --connlimit` + a reverse proxy
  handle nuisance floods; nation-state-grade DDoS requires a CDN / WAF.

---

## Quick verification

After working through the checklist, you should be able to answer "yes"
to all of these:

- Could a new operator take this over with only the docs?
- If the host died right now, how long to a fully restored deployment?
  (Goal: <1 hour from backup.)
- If a credential leaks, how long until it's rotated and revoked?
  (Goal: <15 minutes.)
- Is the dashboard reachable from the public internet without
  authentication? (Goal: no, ever.)
- Are all admin users on MFA? (Goal: yes, always.)
- Has the last backup been successfully restored to a test environment
  within the last 90 days? (Goal: yes.)

If any answer is "no" — that's where to focus next.
