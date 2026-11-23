# Deploying SigRift behind Tailscale

The recommended way to access a SigRift dashboard from anywhere without
exposing it to the public internet. Single setup, no port forwarding,
no public DNS, no Let's Encrypt dance, ACLs for free.

If you only ever access the dashboard from the same host (`localhost`),
you don't need this. The moment you want to reach it from your phone,
another machine, or a teammate — set up Tailscale.

---

## Why Tailscale

- **Zero-config remote access.** Sign in once on each device, your
  sensor host becomes reachable by its hostname from anywhere.
- **No internet exposure.** The dashboard never has to listen on
  `0.0.0.0` to be reachable — Tailscale gives the host a private
  WireGuard address on a virtual network only your devices see.
- **MagicDNS hostnames.** `https://sigrift-sensor.tailnet-example.ts.net:8444/`
  works from any logged-in device. No `/etc/hosts` edits.
- **ACLs in the admin console.** Restrict which devices / users can
  reach the dashboard without touching the host firewall.
- **Free up to 100 devices** (personal). Tailscale doesn't charge
  hobbyist deployments.

What it doesn't replace: the dashboard's own auth (admin password +
MFA) still applies. Tailscale is the outer perimeter; the application
auth is the inner one.

---

## Setup (5 min)

### 1. Install Tailscale on the sensor host

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

The second command prints a URL — open it once in any browser to
authenticate. The host then shows up in your Tailscale admin console
at <https://login.tailscale.com/admin/machines>.

Tag it (`tag:sigrift-sensor` or similar) so your ACLs can target the
class instead of individual devices.

### 2. Install Tailscale on your operator device

Phone / laptop / wherever you check the dashboard from. Sign in to
the same tailnet (or have someone else's tailnet share the sensor
via Tailscale's "node sharing" feature).

### 3. Reach the dashboard by MagicDNS hostname

```
https://<hostname>.<your-tailnet>.ts.net:8444/
```

Find the exact hostname in the Tailscale admin console — it's the
machine name with your tailnet's MagicDNS suffix appended. For
example, `sigrift-sensor.tailnet-example.ts.net`.

That's it for basic access.

---

## TLS cert SAN (avoid browser warnings)

The self-signed cert that `quickstart.sh` / `install-release.sh`
generates includes `DNS:localhost` and the host's local hostname in
its SAN — but NOT the Tailscale MagicDNS name. Browsers connecting
via `https://<host>.tailnet.ts.net:8444/` will warn about hostname
mismatch.

Three options, easiest first:

**(a) Accept the warning.** It's still TLS-encrypted; the cert is
just not signed for that exact name. Click through once per
browser. Fine for a single-operator deployment.

**(b) Add the Tailscale hostname to the SAN.** On the sensor host, from
the repo checkout where you ran `scripts/quickstart.sh` (the cert lives
in its `./tls/` dir), re-run it with the name in `SIGRIFT_TLS_SANS`: it
regenerates the self-signed cert with the extra name (keeping the
others — the host's names and LAN addresses; the host's Tailscale IP is
already among them) and recreates the containers that use it:

```bash
TS_NAME=$(tailscale status --json | jq -r '.Self.DNSName' | sed 's/\.$//')
SIGRIFT_TLS_SANS="$TS_NAME" scripts/quickstart.sh
```

Or by hand:

```bash
TS_NAME=$(tailscale status --json | jq -r '.Self.DNSName' | sed 's/\.$//')
openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:gateway,DNS:bridge,DNS:${TS_NAME},IP:127.0.0.1,IP:::1" \
  -keyout tls/key.pem \
  -out tls/cert.pem 2>/dev/null
# Cert world-readable; key only for the gateway container (gid 1500).
chmod 0644 tls/cert.pem
sudo chown root:1500 tls/key.pem && sudo chmod 0640 tls/key.pem

# Recreate the gateway and the heartbeat agent, then rerun the quickstart
# so it recreates the scanners it selected, with their overlay (wifi-scan
# verifies TLS too). Naming scanners in `docker compose up` would start
# ones you never selected. The marker file tells the quickstart that the
# cert changed; the rerun also adds any of the host's own names this
# cert lacks, keeping the Tailscale name.
docker compose up -d --force-recreate --no-deps gateway edge
touch tls/.recreate-pending && scripts/quickstart.sh
```

Edge nodes on other hosts that were given the old `tls/cert.pem`
(`--ca-cert`) need the new one.

**(c) Use Tailscale's built-in cert provisioning.** Tailscale can
issue a real Let's Encrypt cert for your tailnet hostname (see
<https://tailscale.com/kb/1153/enabling-https>). Drop it over
`tls/{cert,key}.pem` in your install dir and the gateway picks it
up the same way. No browser warnings, no manual SAN management.

---

## ACLs for multi-operator deployments

If more than one person needs access, define an ACL in the Tailscale
admin console to restrict which users / groups can reach which
sensors. Example tailnet ACL JSON:

```json
{
  "tagOwners": {
    "tag:sigrift-sensor":   ["group:admins"],
    "tag:sigrift-operator": ["group:admins"]
  },
  "acls": [
    {
      "action": "accept",
      "src":    ["tag:sigrift-operator"],
      "dst":    ["tag:sigrift-sensor:8444"]
    }
  ],
  "groups": {
    "group:admins":    ["alice@example.com"],
    "group:operators": ["alice@example.com", "bob@example.com"]
  }
}
```

This gives `bob@` reachability to the dashboard port without giving
him any other access to the sensor host (no SSH, no other services).

Combined with the dashboard's own role system (admin / analyst /
viewer), you get layered authorization.

---

## Isolated / locked-down tailnet deployment (requirements)

The hardened model: the SigRift host has **no LAN or public inbound** —
it's reachable only over the tailnet. This works because the host
fetches everything it needs itself and Tailscale is *outbound-only*, so
the host never needs an open inbound port.

### What the host still needs: outbound egress

Even "isolated," the host needs outbound internet for two things.

**1. Tailscale — to join and stay on the tailnet:**

| Egress | Port / proto | Need |
|---|---|---|
| `controlplane.tailscale.com`, `login.tailscale.com`, `log.tailscale.com` | TCP **443** (control plane prefers TCP **80**, falls back to 443) | **Required** — auth, key exchange, ACL/coordination |
| DERP relays (`derp*.tailscale.com`) | TCP **443** | **Required** — encrypted data relay when direct P2P isn't possible |
| direct WireGuard (any peer) | UDP **41641** | Optional — enables faster direct connections |
| STUN / NAT traversal | UDP **3478** | Optional — helps negotiate direct connections |

If your network allows **only outbound TCP 443**, Tailscale still works —
everything relays through DERP over 443 (slower: higher latency,
throughput caps). Opening the two UDP ports lets peers upgrade to direct
WireGuard. **No inbound ports are ever required.** (This is exactly why an
SSH tunnel or the tailnet reaches the dashboard on a network that blocks
direct `:8444` — the traffic rides allowed outbound paths.)

**2. SigRift install and upgrades:**

| Egress | Why |
|---|---|
| `ghcr.io`, `pkg-containers.githubusercontent.com` | `install-release.sh` pulls the `sigrift-bridge` / `sigrift-gateway` images on install and upgrade; GHCR serves the image layers from `pkg-containers.githubusercontent.com`. |
| Docker Hub | both installers pull their digest-pinned `alpine` helper image; `quickstart.sh` also pulls the base images it builds from |
| Debian mirrors, PyPI, crates.io, `download.pytorch.org` | `quickstart.sh` builds the images from source on install and upgrade |
| `api.github.com`, `github.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com` | `quickstart.sh` fetches the classifier from the GitHub Release; github.com redirects release-asset downloads to the `*.githubusercontent.com` hosts |
| your distro's package mirrors | installing Docker and host packages, if you do that over this network |

Install and upgrade traffic is only needed while you run the installer;
day to day, the host needs only the Tailscale egress above.

### Inbound: none

The host needs **zero inbound firewall openings**. Tailscale establishes
everything outbound (DERP-relayed if direct fails). Harden with:

```bash
sudo tailscale set --shields-up      # refuse all inbound, even from the tailnet
```

The host only ever initiates connections; SSH and the dashboard are
reached *over* the tailnet, not through host-firewall holes.

### Headless Tailscale bring-up (no browser on the box)

Use a pre-approved, **tagged**, reusable auth key (admin console →
Settings → Keys):

```bash
sudo tailscale up \
  --auth-key=tskey-auth-... \
  --hostname=sigrift-sensor \
  --advertise-tags=tag:sigrift-sensor \
  --ssh                       # optional: Tailscale SSH instead of host sshd
```

Key lifetimes — the part that bites people:

- The **auth key** is a single-use bootstrap (max 90 days). When it
  expires you mint a new one, but **devices already joined stay joined** —
  an expired auth key does *not* deauth existing nodes.
- The **device** persists on its own **node key** (180-day default). For
  an always-on sensor, set the device's **key expiry to *disabled*** in
  the admin console so it never drops off. (Tagged devices already have
  *auth-key* expiry disabled; disabling the *node-key* expiry is the
  separate setting that keeps a server up indefinitely.)
- Rotate the auth key periodically anyway and re-auth, to limit blast
  radius if a key leaks.

### Lock the dashboard to the tailnet only

The compose files publish `8444` on `127.0.0.1` only
(`docker-compose.yml`: `"${SIGRIFT_BIND:-127.0.0.1}:${UC_PORT:-8444}:8444"`),
so out of the box the tailnet cannot reach it either. Pick one:

- **Add the tailscale IP** (cleanest — nothing listens on the LAN). In
  `docker-compose.override.yml`, next to the loopback mapping the
  host-network scanners use:
  ```yaml
  services:
    gateway:
      ports:
        - "${TS_IP}:8444:8444"     # TS_IP=$(tailscale ip -4), in .env
  ```
- **Or publish on every interface and firewall it** to the tailscale
  interface (`SIGRIFT_BIND=0.0.0.0` in `.env`):
  ```bash
  sudo ufw allow in on tailscale0 to any port 8444 proto tcp
  sudo ufw deny 8444/tcp
  ```
  (Docker publishes ports through its own iptables chains, which `ufw`
  rules do not always cover — check from another LAN host that the port
  is really closed, or prefer the first option.)

Either option opens the dashboard beyond this machine, so switch to
production mode first (`BRIDGE_ENV=production` in `.env`, then
`docker compose up -d`): quickstart's default development mode turns CSRF
protection off and does not mark the session cookie `Secure`.

### HTTPS for the MagicDNS name

The installers' self-signed cert covers `localhost`, `gateway`, `bridge`
and the host's own names and addresses — it has **no tailnet name**, so
`https://<host>.<tailnet>.ts.net:8444/` warns. For a clean cert, enable
**MagicDNS** *and* **HTTPS Certificates** (two separate toggles, admin
console → DNS), then on the host, from your install dir:

```bash
sudo tailscale cert \
  --cert-file tls/cert.pem \
  --key-file  tls/key.pem \
  "$(tailscale status --json | jq -r '.Self.DNSName' | sed 's/\.$//')"
sudo chmod 0644 tls/cert.pem
sudo chown root:1500 tls/key.pem && sudo chmod 0640 tls/key.pem
# Recreate the gateway and the heartbeat agent, then rerun the quickstart
# so it recreates the scanners it selected, with their overlay (naming
# scanners in `docker compose up` would start ones you never selected; the
# marker file tells the quickstart that the cert changed). An
# install-release.sh install runs only the bridge and gateway: recreate
# just `gateway` there, and skip the quickstart line.
docker compose up -d --force-recreate --no-deps gateway edge
touch tls/.recreate-pending && scripts/quickstart.sh
```

The installers never replace a certificate they did not generate (only
self-signed ones are regenerated); they warn about the names this one
lacks. Note what those are: the in-stack scanners verify the gateway at
`https://gateway:8444` and `https://127.0.0.1:8444`, which a Let's
Encrypt cert for the MagicDNS name does not cover, so they cannot
connect with it. If you need them, keep the self-signed cert instead
and add the MagicDNS name to it with `SIGRIFT_TLS_SANS` ("TLS cert SAN"
above, option (b)).

These Let's Encrypt certs renew on a **90-day** cycle, and because they're
installed as static files (not managed by the Tailscale daemon), you must
re-run `tailscale cert` before expiry — schedule it with a systemd timer
or cron. (The "TLS cert SAN" section above covers the openssl + custom-SAN
alternative.) Caveat: the MagicDNS name goes into public Certificate
Transparency logs, so don't use a sensitive machine name.

### Restrict who can reach it (ACL)

Tag the host and gate only the dashboard port to operators (see "ACLs"
above for the full policy):

```json
{
  "acls": [
    { "action": "accept", "src": ["tag:sigrift-operator"], "dst": ["tag:sigrift-sensor:8444"] }
  ]
}
```

Tailnet perimeter + SigRift's own admin/MFA auth = two independent layers.

### Requirements checklist

- [ ] Outbound TCP 443 to `*.tailscale.com` (control plane + DERP) — minimum.
- [ ] (Optional) Outbound UDP 41641 + 3478 for direct WireGuard speed.
- [ ] Outbound to the install sources above while you install or upgrade.
- [ ] No inbound openings; `tailscale set --shields-up`.
- [ ] Headless join via tagged, pre-approved, reusable auth key; node-key expiry disabled.
- [ ] `8444` bound to the tailscale IP or firewalled to `tailscale0`.
- [ ] Cert SAN includes the MagicDNS name (`tailscale cert`), with a renewal timer.
- [ ] ACL limits operators to `tag:sigrift-sensor:8444`.

---

## Tailscale Funnel (optional — sharing without tailnet enrollment)

If you need to share the dashboard with someone who doesn't have
Tailscale installed (e.g. a client), Tailscale Funnel publishes it on a
public `*.ts.net` URL. **Anyone on the internet can reach a funneled
port:** Tailscale adds no authentication, so the dashboard's own login is
the only protection. Before funneling, switch the install to production
mode (`BRIDGE_ENV=production`; development mode turns CSRF protection
off) and enable MFA for every account.

The gateway serves HTTPS with its own certificate on
`127.0.0.1:8444`, so Funnel must proxy to an HTTPS target. With a
current Tailscale CLI that is (not tested in this release; check
`tailscale funnel --help` for your version):

```bash
sudo tailscale funnel --bg https+insecure://127.0.0.1:8444
sudo tailscale funnel status
```

---

## Subnet routing (advanced)

If your scanners live on a separate physical network (e.g. an isolated
RF lab subnet) and the sensor host has reachability there, advertise
that subnet through Tailscale so operators on the tailnet can reach
the scanners directly:

```bash
sudo tailscale up --advertise-routes=192.168.50.0/24
```

Approve the advertised route in the admin console. Operators then
reach `192.168.50.x` addresses transparently.

For a single-host deployment with everything in compose, you don't
need this.

---

## Quick verification

Once set up, run on an operator device:

```bash
tailscale status                                       # host shows online
curl -sk https://<host>.tailnet.ts.net:8444/health    # returns OK
```

Open the dashboard URL in a browser and log in. If you can do that
from your phone over LTE without any port forwarding on your home
router, Tailscale is working.

---

## Removing Tailscale

If you decide not to use it:

```bash
sudo tailscale down
sudo tailscale logout
sudo apt-get remove tailscale
```

The dashboard remains reachable via `https://<host-ip>:8444/` if the
host firewall allows it. Or restrict to `https://localhost:8444/` and
SSH-tunnel for remote access.

---

## Comparison with alternatives

| Approach | Setup time | Cert hassle | Public exposure | ACLs |
|---|---|---|---|---|
| Tailscale (this doc) | 5 min | optional | none | built-in |
| Wireguard manual | 30-60 min | manual | none | iptables |
| nginx + Let's Encrypt | 30 min | automated via certbot | yes | nginx config |
| Cloudflare Tunnel | 15 min | automated | via Cloudflare | Cloudflare Access |
| SSH tunnel only | 1 min | n/a | none | SSH keys |

Tailscale wins on setup-time × feature-completeness for the
single-tenant SigRift use case. For internet-facing public
deployments at scale, a real reverse proxy + WAF is the right answer.
