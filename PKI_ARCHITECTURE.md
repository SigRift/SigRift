# SigRift PKI Architecture

How SigRift issues and trusts mTLS client certificates. This is the
design reference for the PKI rollout.

> **Status:** Implemented, opt-in. The bridge CA, the gateway mTLS
> client verifier, edge-agent cert wiring (all five scanners), the
> admin-UI cert form, the `scripts/pki_bootstrap.py` provisioning tool
> and the `docker-compose.pki.yml` overlay are all in place. The
> installers do not turn it on; you provision the node certificate and
> add the overlay yourself (see [Enable the overlay](#enable-the-overlay)).
> PKI is additive — with the env vars unset, API-key auth is unchanged.

---

## Why PKI

The application-layer auth model is the `X-API-Key` header: the bridge
hashes the presented key (PBKDF2 + salt, with a SHA-256 fast index)
and maps it to a role. Transport is one-way TLS — the gateway presents
a server certificate, clients do not authenticate at the TLS layer.

Two consequences:

- A stolen API key alone is enough to impersonate an agent. Identity
  is shared-secret knowledge, not possession of a private key.
- Every scanner on a host shares one `BRIDGE_LOCAL_NODE_KEY`. A leak
  compromises all of them at once, and rate limits aggregate across
  them.

PKI gives each node its own keypair and certificate, shared by that
node's agents (a node certificate acts only for the node whose id is
its identity — see [Trust bootstrap](#trust-bootstrap)). Identity is
established at the TLS layer; a compromised certificate is revoked
individually without rotating shared secrets across the fleet.

---

## Trust model

```
            issues + signs                presents on
  Bridge CA ─────────────►  client cert ─────────────►  gateway
  (ca.crt + ca.key)          (per node)       mTLS       rustls verifies
       │                                                the cert chains
       │ writes                                          to ca.crt
       ▼                                                      │
  registry.json ◄──────── gateway reads (shared volume) ──────┘
  identity → role,        resolve role; reject a
  revoked flag            revoked or expired identity
```

- **The bridge is the issuing CA.** On first use it generates a
  self-signed CA certificate under `<bridge-data-dir>/ca/` (`ca.crt`,
  next to `registry.json`, which the gateway reads from the shared
  data volume) and its private key under the bridge's secrets
  directory, `$BRIDGE_SECRETS_DIR/ca/ca.key` (`/app/secrets/ca/ca.key`
  in the container, on the `bridge_secrets` volume that only the bridge
  mounts — never the internet-facing gateway).
- **Each node holds its own keypair**, which all of its agents use.
  With `/api/ca/sign` the private key never leaves the node: it sends a
  certificate signing request (CSR); the bridge signs it; the node
  receives only the certificate back.
- **The gateway verifies at the TLS layer.** The gateway is configured
  with the CA certificate as a rustls client-cert verifier, extracts
  the identity from a verified client certificate, and maps it to a
  role via the CA registry.
- **The bridge trusts the gateway's assertion.** The client certificate
  terminates at the gateway's TLS layer and never reaches the bridge,
  so the bridge cannot re-verify it. Instead, the gateway forwards the
  resolved identity and role as `x-auth-key-id` / `x-auth-role` with
  `x-auth-method: client-cert`, and the bridge honours them — but only
  when the request provably came through the gateway, i.e. the
  `x-rust-proxy` header carries the shared `UC_PROXY_SECRET`. The
  gateway strips any client-supplied copy of these headers before
  proxying, so they cannot be forged. If `UC_PROXY_SECRET` is unset or
  left at its insecure default, the bridge refuses to honour the trust
  headers (fail-safe — API-key auth is unaffected). An assertion whose
  role is `keymaster` is never honoured either.

There is exactly one CA per deployment. Cross-deployment federation
and multi-CA trust are out of scope.

---

## The certificate authority

Implemented in `src/sigrift/bridge/ca.py` as `CertificateAuthority`,
an embedded CA built on the `cryptography` library — no external CA
service or sidecar container. The module is standalone (depends only
on `cryptography` and the standard library).

### CA certificate

- EC P-256 key, self-signed.
- `BasicConstraints` CA with `path_length=0` (it may only sign leaf
  certs, never sub-CAs).
- `KeyUsage` limited to `keyCertSign` + `cRLSign`.
- 10-year lifetime. CA rotation is separate from per-certificate
  rotation and has no runbook yet (see [What is not covered](#what-is-not-covered)).

### Files

| File            | Where | Mode   | Contents                                     |
|-----------------|-------|--------|----------------------------------------------|
| `ca.crt`        | `<bridge-data-dir>/ca/` | `0644` | CA certificate — public trust material       |
| `registry.json` | `<bridge-data-dir>/ca/` | `0600` | Issued-cert metadata: serial, identity, role, fingerprint, expiry, revocation state |
| `ca.key`        | `$BRIDGE_SECRETS_DIR/ca/` | `0600` (dir `0700`) | CA private key — the deployment's most critical secret |
| `.ca.lock`      | `<bridge-data-dir>/ca/` | `0600` | Empty lock file: every change to `registry.json`, and creating the CA, holds a lock on it |

`ca.crt` and `registry.json` are written atomically (temp file +
rename). `ca.key` is created exclusively and never replaced: it is
written to a uniquely named `0600` temp file in the key directory and
hard-linked into place, so it appears complete or not at all, and two
processes creating a CA at the same time — even for two data directories
that share a key directory — cannot overwrite each other's key (on a
filesystem without hard links it is created in place, still
exclusively). A temp copy left behind in the key directory by a
start-up that was killed (`.ca.key.<random>.tmp`) is removed the next
time the CA is opened. The key is written before `ca.crt`; if writing
`ca.crt` then fails (say `EACCES` or `ENOSPC`), the new key is removed
again, since no certificate was issued with it. A key or key directory
restored or copied in with a looser mode is tightened to `0600` /
`0700` (never widened, symlinks not followed) when the CA is opened,
with a warning. The gateway
mounts the data volume (`UC_TLS_CLIENT_CA=/app/data/ca/ca.crt`,
`UC_CA_REGISTRY_PATH=/app/data/ca/registry.json`) but not the secrets
volume. `BRIDGE_SECRETS_DIR` defaults to `/app/secrets` in the bridge
image and to `secrets/` next to the data dir elsewhere
(`scripts/pki_bootstrap.py --secrets-dir` overrides it).

Several processes can change one CA directory at the same time: each
bridge worker (`BRIDGE_WORKERS` > 1, `uvicorn --workers`) has a CA of
its own, and `scripts/pki_bootstrap.py` can run against a live stack.
Issuing and revoking are read-modify-writes of `registry.json`, so each
one, and creating the CA, holds an advisory `flock` on `.ca.lock` from
reading the registry to writing it back. Without it, one process could
write back a registry it read before another's change: a revocation
that had been reported done came undone (and the gateway, which enforces
revocation from the registry, accepted the certificate again), or a
certificate already handed out was missing (and refused). The lock file
is created `0600` next to the registry, never through a symlink; a
symlink, a FIFO or anything else there is refused, not used. Reading
(`GET /api/ca/certs`, `crl.pem`, `ca.pem`) takes no lock, and opening an
existing CA needs no write access to its directory. A change waits up to
5 seconds for another process's; a holder that takes longer is stopped
or hung, and the change fails with a `503` (nothing issued or revoked).
The bridge waits on a thread of its own, so its other requests are
served meanwhile. The data directory must be on a filesystem where
`flock` works (a local disk or a Docker volume; the bridge's
`.persistence.lock` needs the same). `pki_bootstrap.py` and the bridge
must both be from a release with this lock: an older one takes no lock,
so stop the bridge while running an older `pki_bootstrap.py`.

Earlier versions kept `ca.key` in `<bridge-data-dir>/ca/`. The bridge
moves it (not copies) to the secrets directory when the CA is first
opened — the image does it at container start-up with
`python3 -m sigrift.bridge.ca migrate-key` — and logs
`Moved the CA private key from … to …`. It leaves the key where it is,
with a warning, when the secrets directory is on the container's own
root filesystem while the data dir is a volume (a compose file without
the `bridge_secrets` volume): moving it there would lose it on the next
recreate. If both locations hold a key, the one matching `ca.crt` is
kept as `ca.key` and the other is set aside next to it
(`ca.legacy.<time>.key` / `ca.replaced.<time>.key`), never deleted;
the same key in both places is simply removed from the data dir.

The move is one-way. A bridge from before it looks for the key in
`<bridge-data-dir>/ca/` only and, finding none, silently generates a
**new CA** on first use — overwriting `ca.crt` and invalidating every
client certificate already issued. Before downgrading to such a version,
copy `ca.key` back into the data dir while the newer compose file is
still in place:

```bash
docker compose run --rm --no-deps --entrypoint cp bridge \
    /app/secrets/ca/ca.key /app/src/sigrift/bridge/data/ca/ca.key
```

(from source: `$BRIDGE_SECRETS_DIR/ca/ca.key` →
`<bridge-data-dir>/ca/ca.key`). See INSTALL.md, "Upgrade note:
loopback by default, proxy-only bridge, CA key volume".

### When the CA refuses its files

The CA never signs, revokes, publishes a CRL or overwrites a file when
its files do not fit together; it waits for an operator instead. The
`/api/ca/*` requests that need the files in question return `503`
(while no CA can be opened, all of them do). The unauthenticated `ca.pem`
and `crl.pem`, and `GET /api/ca/certs` for a caller below admin, get a
generic detail; admin callers and the bridge log get the full message,
which names the files. A CA that could not be opened is tried again on
the first request at least 15 seconds after the last attempt, so it
comes back within seconds of the fix without a restart.

| Log / 503 message | Cause | What to do |
|---|---|---|
| `there is already a private key at … but no CA certificate at …` | `ca.crt` lost, a second data dir sharing the key dir, or a first start-up killed before it wrote `ca.crt` | If another bridge or `pki_bootstrap.py` is starting right now, wait and retry. Otherwise restore `ca.crt` from the same backup as the key; give a second data dir its own key dir (`--secrets-dir` / `BRIDGE_SECRETS_DIR`); or, only for a deliberate new CA or a killed first start-up, move the key aside (e.g. `ca.retired.<date>.key`). |
| `there is a CA certificate at … but no private key at …` | `bridge_secrets` not mounted or not restored, `BRIDGE_SECRETS_DIR` different from when the CA was created, `pki_bootstrap.py` run without `--secrets-dir` | Mount or restore `ca.key` (from the same backup as `ca.crt`), or point the secrets dir back. Only for a deliberate new CA, move `ca.crt` aside; every certificate must then be issued again. |
| `… does not belong to the CA certificate …` | `ca.key` and `ca.crt` from different backups | Restore both from the same backup, or check whether a set-aside `ca.legacy.*.key` / `ca.replaced.*.key` next to it is the right key. |
| `The CA private key … cannot be used` / `… is not an EC private key` / `The CA certificate … cannot be used` | Unreadable (owner or mode), corrupt, encrypted or not an EC key | Fix the owner or mode, or restore the file from the same backup as its partner. |
| `Could not take the CA lock … within 5 seconds` | Another process using the CA directory (a bridge worker, `pki_bootstrap.py`) holds `.ca.lock` and is stopped or hung | Nothing was issued or revoked: retry. If it persists, find the process holding `<bridge-data-dir>/ca/.ca.lock` (`lsof`, `fuser`) and let it finish or stop it. |
| `The CA lock file … is a symlink` / `is not a regular file` / `cannot be opened` / `cannot be locked` | Something other than the CA's empty lock file at `.ca.lock`, a CA directory this process cannot write, or a filesystem without `flock` | Remove whatever is at `.ca.lock` while no bridge or `pki_bootstrap.py` runs (it holds no data; the CA creates it again), fix the CA directory's owner or mode, or move the data directory to a filesystem with `flock`. |
| `The CA registry … cannot be read` / `is not valid JSON` / `is not a CA registry` | `registry.json` unreadable, truncated or hand-edited into the wrong shape | Repair it or restore it from a backup. **Do not delete it**: it is the only record of every revocation. Its shape is `{"issued": {"<serial>": {…}}}`, each serial a decimal integer without leading zeros; `revoked` is `true`/`false` and `revoked_at`, `issued_at` and `not_after` are strings or `null`. |

A bridge that starts with neither `ca.crt` nor `ca.key` creates a new
CA and keeps an existing `registry.json`.

### CA key protection and backup

`ca.key` is the single most critical secret in the deployment —
possession of it allows minting a certificate for any identity. It
must be:

- Backed up alongside `keys.json` — it is in a different volume
  (`bridge_secrets`), so back up both — with the same encryption-at-rest
  requirement, on the same schedule (see `PRODUCTION_READINESS.md`
  §4). SigRift does not back it up for you: the installers do not
  schedule backups, so the operator's backup job must include the
  `bridge_secrets` volume.
- Recoverable: if `ca.key` is lost, every issued certificate must be
  re-issued under a new CA. If it is *stolen*, the CA must be replaced
  and all certificates re-issued. Neither procedure is scripted or
  written up as a runbook yet.

---

## Certificate lifecycle

### Issuance

1. The agent generates a keypair and a CSR.
2. The CSR is submitted to the bridge (`POST /api/ca/sign`, admin
   authorization required).
3. The bridge signs a leaf certificate and records it in the
   registry.

The bridge decides the identity. The CSR contributes **only its
public key** — its subject and any extensions it carries are ignored.
The bridge sets:

- Subject CN = the granted identity.
- `SubjectAlternativeName` = a single DNS entry, `DNS:<identity>`.
  A plain DNS SAN is used rather than a SPIFFE URI: it is structured
  enough for a single-tenant deployment and works with every X.509
  tool.
- `ExtendedKeyUsage` = `clientAuth` only.
- `BasicConstraints` = not a CA.
- `KeyUsage` = `digitalSignature` only.

This means a malicious or buggy CSR cannot claim an identity, a role,
or a capability it was not granted — those come from the signed
request body, which is authorized separately.

### Identity and roles

The identity is a DNS-label-shaped string (e.g. `local-edge`,
`scanner-7`); for a `node` or `sensor` certificate it is the node id
the agents report (`MLRF_NODE_ID`). A certificate carries a role
drawn from the same hierarchy as API keys: `sensor`, `node`,
`viewer`, `analyst`, `admin`. Scanners are issued `node`.
`keymaster` is never delegated to a certificate: the CA refuses to issue
it, the gateway refuses a registry entry that carries it (see
[Revocation](#revocation)), and the bridge refuses a client-certificate
assertion (`x-auth-role`) that carries it, even from the gateway.

### Lifetime and rotation

- Default leaf lifetime is **90 days**.
- Scanner agents are expected to auto-rotate at roughly 75% of
  lifetime (~66 days): generate a fresh keypair, submit a new CSR,
  swap the certificate atomically. (The agent-side rotation loop is not
  implemented yet; it is a Phase B item. Until then, re-issue before
  expiry as described under [Trust bootstrap](#trust-bootstrap).)
- A maximum TTL of 825 days is enforced on signing.

### Revocation

- `POST /api/ca/revoke/{serial}` marks a certificate revoked in the
  registry (`registry.json`).
- The bundled gateway enforces revocation directly from that registry.
  `CertRegistry` re-reads `registry.json` whenever the file's mtime,
  size or inode changes, and a revoked or expired entry is rejected on
  the next certificate lookup. Since file timestamps are coarse (two
  writes in one tick can share an mtime), a version read within 2
  seconds of its mtime is read again on each lookup until a read falls
  outside that window. Because the bridge and gateway share the data
  volume, a revocation takes effect within a request cycle — there is
  no poll timer and no network fetch.
- A registry entry the bridge could not have written is refused too,
  so a corrupted or hand-edited `registry.json` fails closed: an
  `identity` that is missing, empty or not a string, a `role` that is
  missing or not exactly one of the certificate roles (`sensor`, `node`,
  `viewer`, `analyst`, `admin`, in lower case, as the CA writes them: so
  `keymaster` in any letter case, an unknown role and `ADMIN` are all
  refused, never mapped to another role), a `revoked` that is
  not `true`, `false` or `null`, a `fingerprint_sha256` that is not 64
  hex digits, a `not_after` that is not an RFC 3339 timestamp with an
  offset, or two keys for one serial (`66` and `066`). The gateway logs
  the serial and the field; the admin UI does not check these shapes.
- The bridge also publishes a signed CRL at `GET /api/ca/crl.pem`,
  listing every revoked serial, with a 7-day validity window. This
  exists for verifiers that cannot read the registry directly
  (out-of-stack or future external consumers); the in-stack gateway
  does not use it.

A registry-backed check was chosen over CRL polling for the in-stack
gateway: it is simple, needs no network fetch, works air-gapped, and
revocation propagates within a request cycle rather than on a poll
timer. OCSP can be revisited if a deployment needs cross-host
real-time revocation.

---

## API surface

All routes are mounted under `/api/ca`.

| Method + path             | Auth          | Purpose                                  |
|---------------------------|---------------|------------------------------------------|
| `POST /api/ca/sign`       | admin         | Sign a CSR into a client certificate     |
| `POST /api/ca/issue`      | admin         | Issue a cert with a bridge-generated keypair (response includes the private key) |
| `POST /api/ca/revoke/{serial}` | admin    | Revoke an issued certificate             |
| `GET  /api/ca/certs`      | viewer        | List issued certificates (metadata only) |
| `GET  /api/ca/ca.pem`     | none (public) | CA certificate, for trust bootstrap      |
| `GET  /api/ca/crl.pem`    | none (public) | Current certificate revocation list      |

`ca.pem` and `crl.pem` are intentionally unauthenticated. They are
public trust material: a scanner must fetch the CA certificate
*before* it holds a client certificate, and CRLs are published
unauthenticated by convention. Neither response exposes a private
key — `ca.pem` is the CA's public certificate, `crl.pem` lists only
revoked serial numbers.

`/api/ca/sign` and `/api/ca/issue` both mint a client certificate.
`sign` takes a CSR, so the private key never leaves the agent;
`issue` generates the keypair on the bridge and returns the key in
the response — used by the admin UI and `pki_bootstrap.py`, where the
operator needs the key file to install on the agent. That key travels
only over the already-TLS-protected admin session and is never stored
by the bridge.

### Trust bootstrap

A scanner obtains the CA certificate from `GET /api/ca/ca.pem` over
the existing server-cert-verified HTTPS connection. To prevent a
hijacked first fetch from silently swapping in a different CA, the
expected CA fingerprint should be pinned out-of-band. Agents have no
pinning option yet (a `MLRF_CA_FINGERPRINT` setting is planned); until
then, distribute `ca.crt` with the certificate bundle rather than
fetching it on first use.

For an in-stack compose deployment, `scripts/pki_bootstrap.py` does
this provisioning directly against the CA: it ensures the CA exists,
mints a certificate per requested identity, and writes a
`client.crt` / `client.key` / `ca.crt` bundle per identity. A deployment
bootstrap mounts the bundle into the node's scanner containers and
sets `MLRF_CLIENT_CERT` / `MLRF_CLIENT_KEY`.

`pki_bootstrap.py` never overwrites a bundle: if `<out-dir>/<identity>`
already exists (default out-dir `<data-dir>/edge_certs`), it refuses with
`identity '<identity>' already exists; use a new --out-dir`. To rotate or
re-issue, pass a fresh `--out-dir`, mount the new bundle, then revoke the
old certificate's serial. Rerunning the same command does not refresh a
certificate.

**A NODE certificate's identity must be the node id.** The gateway and
the bridge accept a `node`-role client certificate only for the node
whose id equals the certificate identity, so every agent of a node (edge,
scan, wifi-scan, bt-scan, …) shares one certificate issued for that
node's `MLRF_NODE_ID`; a per-agent identity such as `wifi-scan` would be
refused for every detection and heartbeat. The node id must also be a
valid certificate identity (letters, digits, `.`, `_`, `-`, starting and
ending with a letter or digit); a node whose id is not uses an API key.

```bash
# One bundle per NODE, named after the node id the agents report:
PYTHONPATH=src python3 scripts/pki_bootstrap.py \
    --data-dir /var/lib/sigrift/data \
    local-edge:node
```

**Upgrading from per-agent certificates.** Earlier versions of this
document and of `pki_bootstrap.py` minted one certificate per agent
(`local-edge:node wifi-scan:node bt-scan:node`, each bundle mounted into
the matching scanner container). Those certificates now get 403 on
every heartbeat and batch (`Client certificate '<identity>' may only
submit batches for node '<identity>'` from the gateway's detection
ingest, `… may only act for node '<identity>', not '<node>'` from the
bridge's node routes), unless their identity happens to be the node's
id. An agent with a certificate loaded sends no API key, so it does not
fall back to one. Before upgrading:

1. Issue one certificate per node, with identity = the node's
   `MLRF_NODE_ID` — `POST /api/ca/issue` with
   `{"identity": "<node id>", "role": "node"}`, or
   `pki_bootstrap.py --out-dir <new dir> <node id>:node` (a new
   `--out-dir` is required if that identity was minted before).
2. Mount it into **all** of that node's agents (`MLRF_CLIENT_CERT` /
   `MLRF_CLIENT_KEY`).
3. Revoke the per-agent certificates (`GET /api/ca/certs` lists their
   serials; `POST /api/ca/revoke/{serial}`).

Or unset `MLRF_CLIENT_CERT` / `MLRF_CLIENT_KEY` on the agents so they
authenticate with the node's API key again. `BRIDGE_ALLOW_UNBOUND_NODE_KEYS`
applies to API keys only, never to certificates.

---

## Enable the overlay

These steps are for the source compose stack (`scripts/quickstart.sh`),
derived from `docker-compose.pki.yml` and the CA routes in
`src/sigrift/bridge/routers/ca.py`. The overlay does not apply to an
`install-release.sh` install, whose compose file has only the bridge
and gateway. The overlay file's own header comment still describes an
older staging deployment (`scripts/bootstrap-staging.sh`,
`docker-compose.staging.yml`); those files are not in this repository,
so follow the steps here instead. `scripts/pki_bootstrap.py` needs the
CA directory on the host (`--data-dir`), which a compose install keeps
in a Docker volume, so use the dashboard or the API there.

1. **Create the CA and the node certificate**, with the stack running
   *without* the overlay. Under the overlay the gateway exits at
   start-up until the CA certificate (`ca/ca.crt` in the `bridge_data`
   volume) exists, and the bridge creates the CA on the first
   `/api/ca/*` request. As an admin, open **Admin → API Keys → Client
   Certificates (mTLS)**, mint a certificate with the node's
   `MLRF_NODE_ID` as its identity (from `.env`; `local-edge` when unset)
   and role **Node**, and download the certificate and the private key
   (the key is shown only once and the bridge does not store it). The
   API equivalent is `POST /api/ca/issue` with
   `{"identity": "<MLRF_NODE_ID>", "role": "node"}` as an admin; the
   response carries `cert_pem` and `key_pem`.
2. **Install them where the overlay mounts them.** The overlay fixes the
   host file names, whatever the identity:
   ```bash
   sudo install -d -m 0755 /opt/sigrift/pki
   sudo install -o root -g 1500 -m 0644 <identity>.crt /opt/sigrift/pki/local-edge.crt
   sudo install -o root -g 1500 -m 0640 <identity>.key /opt/sigrift/pki/local-edge.key
   ```
   `edge`, `scan` and `bt-scan` run as uid/gid 1500 (the edge image's
   `appuser`); `wifi-scan` runs as root with every capability dropped
   except `NET_ADMIN`, `NET_RAW`, `SETUID` and `SETGID`, so it cannot
   bypass file permissions either. `root:1500` with mode `0640` lets
   every agent read the key.
3. **Apply the overlay to the gateway and `edge`.** With `-f`, compose no
   longer loads `docker-compose.override.yml` (the quickstart's TLS
   settings) by itself, so name it too:
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.override.yml \
       -f docker-compose.pki.yml up -d
   ```
   This recreates the gateway, which now verifies client certificates
   against the bridge CA and still accepts API keys, and `edge`, which
   now presents the certificate. Scanners behind the quickstart's
   inactive `hardware` profile are left as they are.
4. **Scanners (optional).** The quickstart starts the scanners it
   selected from its own overlay, `.sigrift-scanners.yml`, which plain
   `docker compose` never loads. They keep authenticating with the node
   API key until you recreate them with both overlays, naming only the
   scanners that run now (`docker compose ps`) — naming a service starts
   it even when its profile is inactive:
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.override.yml \
       -f .sigrift-scanners.yml -f docker-compose.pki.yml \
       up -d --no-build --no-deps wifi-scan
   ```
5. **Check** each agent's log (`docker compose logs edge`, …) for
   `Client-cert (mTLS) auth enabled`. `Failed to load client cert …;
   falling back to API-key auth` means it cannot read the files, and
   neither line means it does not see them.

**A quickstart run undoes it.** Every quickstart run that starts or
recreates services (a retry, enabling hardware, a `--renew-tls` run that
renews the certificate) uses only the quickstart's files, so compose
recreates the gateway, `edge` and the selected scanners without the
overlay: the agents go back to the API key and the gateway stops
checking client certificates. Any other `docker compose up` that leaves
out `-f docker-compose.pki.yml` (a plain `docker compose up -d`, for
example) does the same to the gateway and `edge`. Repeat steps 3 and 4
afterwards.

---

## What is not covered

- **Installer wiring.** Neither `quickstart.sh` nor `install-release.sh`
  provisions the node's shared certificate (identity = `MLRF_NODE_ID`)
  or adds `docker-compose.pki.yml`; that is a manual step for now. The
  overlay mounts the certificate from `/opt/sigrift/pki/local-edge.crt`
  and `local-edge.key` on the host into `edge`, `scan`, `wifi-scan` and
  `bt-scan`, and under it the gateway exits at start-up until the bridge
  CA exists, so create the CA (any `/api/ca/*` request) and put the
  node's certificate there before adding the overlay — see
  [Enable the overlay](#enable-the-overlay).
- **Agent cert rotation.** Scanners load a cert at startup; the
  auto-rotation loop (re-mint at ~75% of lifetime) is a Phase B item.
- **CA fingerprint pinning** on agents (`MLRF_CA_FINGERPRINT`) — planned.
- **CA rotation and lost/stolen-key recovery runbooks**, and automated
  backup of `bridge_secrets` — not written yet.
- **Browser certificates for operators.** Deferred to Phase C —
  operators continue to use password + MFA. Service-to-service PKI is
  the Phase A/B priority.
- **Hardware-backed keys** (HSM / TPM) and **service-mesh
  integration** (SPIFFE/SVID, Istio) — not planned for the current
  rollout.
