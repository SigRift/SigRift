# Changelog

All notable changes to SigRift (community edition) are documented
here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **One-command host preparation for the scanners.** `scripts/scanner_setup.py
  prepare` does in one root step what a new host needed five steps for: it
  releases the RTL-SDR receiver's TV driver (as `prepare-rtl`), installs that
  receiver's udev rule as `/etc/udev/rules.d/70-sigrift-sdr.rules` and reloads
  udev, and, when NetworkManager runs, writes
  `/etc/NetworkManager/conf.d/90-sigrift-scanner.conf` (matching the spare
  Wi-Fi adapter by its permanent hardware address) unless that file is
  already in place and working, reloads NetworkManager and checks that the
  file itself made the adapter unmanaged; if it did not, it releases the
  adapter for now with `nmcli device set <if> managed no`, says the
  persistent setting did not take effect and exits non-zero. It prepares an
  adapter only in the NetworkManager states `unmanaged`, `disconnected` or
  `unavailable`, and refuses one that is connecting or connected. It targets
  only devices discovery would select, refuses a named `--usb` or
  `--wifi-interface` its own discovery would not accept, never touches a
  protected radio, never overwrites a file it did not write, and is
  idempotent. Under `sudo` without an SSH client address it prepares a Wi-Fi
  adapter only when `--wifi-interface` names it. `nmcli` and `udevadm` run
  with `LC_ALL=C`. `prepare --print` reviews every file and command without
  root and changes nothing; `prepare --check` names the targets;
  `unprepare` removes only the files that carry its marker.
- `scripts/quickstart.sh --prepare-host` runs that step without asking
  (`sudo -n` without a terminal); `--no-prepare-host` never asks or runs it.
  Both are refused with `--dashboard-only`, `--renew-tls` and
  `--scanners=none`. Quickstart passes the review and the `sudo` run exactly
  the targets `prepare --check` named, plus the SSH client address
  (`--ssh-client`) that `sudo` would otherwise drop, and reports a refused
  check as `Skipped host preparation:` with the reason before continuing.

### Changed
- A quickstart retry on an existing installation whose selected receiver has
  lost its preparation no longer stops with an error: it offers the one-time
  host preparation (or runs it with `--prepare-host`), plans again and
  continues. Measured on a Raspberry Pi: it used to exit in 2 seconds, even
  with `--prepare-host`.
- Starting the scanners now recreates a selected scanner container that is
  running but unhealthy. Docker copies device nodes when a container starts,
  so a receiver container started before the host was prepared kept the old
  permissions and never recovered on its own (measured on a Pi: quickstart's
  scanner start then timed out after 30 seconds).
- `unprepare` now says that NetworkManager takes the Wi-Fi adapter back right
  away; it previously said this happened only after a reboot.
- When the scanner plan says the host needs preparation, quickstart now
  shows what `prepare` will change and asks once (default No) when stdin and
  stdout are terminals, then plans again and continues the same run with the
  scanners that are ready. Without a terminal it never asks; it prints the
  single command and continues as before. A declined, refused or failed
  preparation never stops an install.
- The scanner plan adds one line, `Prepare this host (one command; add
  --print to review): sudo python3 scripts/scanner_setup.py prepare`, for a
  host that needs any preparation, and a `wifi <interface> note:` line for a
  ready adapter that NetworkManager manages, saying that capture pauses
  (about 17 seconds when measured on a Pi) and resumes by itself when
  NetworkManager takes the adapter, so preparing it is recommended, not
  required. Existing plan lines are unchanged; a plan that fails on an
  unprepared receiver (explicit `--scanners=sdr` or a saved-selection retry)
  now also names the single `prepare` command after the existing text.
  Whether such an adapter can be selected is one setting,
  `NM_MANAGED_POLICY`; it stays `warn` (selectable), and `require` reports it
  as needing preparation.
- **Relicensed from AGPL-3.0-only to MIT.** `LICENSE`, `NOTICE`, the
  package metadata (`pyproject.toml`, both gateway crates' `Cargo.toml`),
  the community model weights' licence and new export metadata, the README
  badge and the contributor docs now say MIT. Private preview builds made before
  this change were licensed under AGPL-3.0-only; anyone who obtained a copy
  under those terms keeps it under those terms (`NOTICE`). Contributions must not include
  copyleft-licensed code, including ports or translations of it
  (`CONTRIBUTING.md`).
- Preserve Leaflet 1.9.4's upstream BSD-2-Clause licence beside its
  vendored assets, and include SigRift's `LICENSE` and `NOTICE` in runtime
  images and release bundles. The model release (`v0.1.0-models`) ships its
  own `LICENSE` and `MODEL-NOTICE.txt`.
- For crates built on `sigrift-gateway-core` (a breaking change):
  `Config::session_absolute_timeout_hours` and
  `session_idle_timeout_minutes` are now the raw `Option<String>` of
  `BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS` and
  `BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES` (or their options), not `i64`.
  `Config::session_config()` reads them as the bridge does and returns
  the `SessionConfig` in use, or why the gateway must not start.
- Gateway user API: `POST /api/admin/users` and `PUT
  /api/admin/users/{username}` now check their fields as the bridge's user
  API does, and refuse with 422 and a string `detail` before anything is
  stored, revoked or audited. An unknown role is now a 422 `Invalid role`
  (it was a 400), so a client that matched on 400 must accept 422. Newly
  refused, also with 422: the machine roles `sensor` and `node`, in any
  spelling; on create, a username that is not 1 to 64 characters from
  `A-Z`, `a-z`, `0-9`, `_`, `-` and `.`, or that is `.` or `..`; and a
  `display_name` over 128 or an `email` over 256 characters (counted in
  characters). The 0.1.0 gateway accepted all of these, for example a user
  named `a b` or one with the role `sensor`. Accounts already stored that
  way stay listed and can still be updated, reset and disabled (except
  `.` and `..`, which no `{username}` route reaches); mixed-case roles
  (`Admin`) and `keymaster` (within the caller's grant ceiling) are still
  accepted. The password policy still answers 400, but its 8 and 128
  character limits now count characters, not UTF-8 bytes, as the bridge
  counts them: on create, admin password reset and change-password, a
  7-character password with accented letters is now refused, and a
  128-character one is accepted.
- **Login and MFA verify need `Content-Type: application/json`.** The
  gateway's `POST /api/auth/login` and `POST /api/auth/mfa/verify` now
  answer 415 `{"detail": "Content-Type must be application/json"}` to a
  body that is not declared `application/json`, before anything is
  checked or counted (no rate-limit attempt, no lockout failure, and an
  MFA challenge is not spent). Parameters are allowed and the media type
  is read in any letter case (`application/json; charset=utf-8`), but it
  must be exactly that type: `text/plain`, a form encoding, a missing
  `Content-Type`, two of them, `text/plain;charset=application/json` and
  `+json` types are refused. The 0.1.0 gateway read any body as JSON
  whatever its `Content-Type`, so a script that posts the JSON without
  the header must now add it (see Upgrade notes: `curl -d` without `-H`
  is refused). The browser pages, the installers, the smoke scripts and
  the e2e client already send it. The standalone bridge refuses such a
  login body with 422, as it did.
- **Logout expires a stale session cookie.** The gateway's
  `POST /api/auth/logout` now also expires `session_token`, `csrf_token`
  and `bridge_token` on a 401 (no session token, or one that names no
  session) when the request carried one of those cookies; a 200 expires
  them as before. A stale HttpOnly session cookie used to survive the
  401, and the page's JavaScript cannot clear it. A 401 for a request
  that carried none of them still sets no cookie: a cross-site form post
  carries none (they are `SameSite=Lax`), and expiring them on its 401
  would let any site sign a visitor's dashboard out. A `Bearer` or
  `X-Session-Token` that names no session, sent without the cookies,
  gets no cookie either. A 500 or 503 still sets no cookie, so the retry
  the dashboard offers can end the session. The bridge's logout now
  expires `csrf_token` on 200, and on 401 when the request carried
  `session_token` or `csrf_token`; it expired nothing. The status codes
  and bodies are unchanged.
- **The gateway no longer relays a backend `Set-Cookie` for
  `session_token` or `bridge_token`**, except `session_token` from the
  SSO routes under `/api/oidc`. Only the gateway issues session cookies;
  a proxied route's attempt to set or expire one (its name read as
  browsers read it, spaces around it ignored) is dropped and logged at
  WARN with the request path. The community bridge sets neither, so
  nothing in the community stack changes; `csrf_token` and other cookies
  pass as before. The `sigrift-sentinel` add-on's OIDC router, which the
  bridge mounts under `/api/oidc` and the gateway does not shadow, hands
  the browser its SSO session as a `session_token` cookie, so that one
  cookie is still relayed from `/api/oidc` and the paths below it (the
  path as sent, case-sensitive, not percent-decoded). `bridge_token` is
  never relayed. See the upgrade note for SSO deployments.

### Public-preview review follow-up
- Browser MFA uses the gateway/bridge challenge contract and accepts complete
  backup codes. A rejected code returns to sign-in for a fresh challenge.
- Dashboard sessions in a new tab retain account controls, and logout waits
  for server revocation.
- Gateway authentication, CSRF validation, logout, and proxying handle split
  HTTP/2 Cookie headers, preserving CSRF cookies across the Python boundary.
- Fresh installers use portable temporary files on macOS and Linux, and
  quickstart preserves a requested gateway port in its generated settings.
- Gateway container health probes now use the configured HTTP/TLS mode.
  The fresh-install workflow runs on pull requests and fails when the stack
  cannot start, instead of masking failed smoke checks.
- Installers preserve literal passwords containing dollars, quotes,
  backslashes, spaces and comment characters. Model selection and checksum
  validation use portable Python helpers on macOS and Linux.
- Explicit release-version changes update the two installer-managed image
  tags after Compose validation, preserving custom settings and a backup.
- Bridge authentication rejects disabled/revoked keys and malformed expiry
  metadata on HTTP, WebSockets and cache hits, matching the gateway.

### Upgrade notes — action required before upgrading a production install
- **Keep the gateway's and the nodes' clocks in sync (NTP).** The gateway
  now drops a detection dated more than 5 minutes ahead of its own clock
  (`future_timestamp` in the batch response's `rejected_reasons`). A node
  whose clock runs ahead loses those detections, and so does every node
  while the gateway's own clock lags: for example, a Pi gateway without a
  real-time clock before NTP has synced. The edge does not report the loss.
- **Check `BRIDGE_BACKUP_ENCRYPTION_KEY` if it is set.** A value that is
  not a valid Fernet key now makes `POST /api/admin/backup` fail with HTTP
  500 and write nothing. Before, it silently wrote an unencrypted backup.
  Set a valid key, or unset the variable to keep unencrypted backups.
- **Upgrade the gateway and the bridge together; a rollback needs the
  pre-upgrade database.** New audit entries are signed in a new record
  format (v3) that only this release's bridge and gateway verify. An older
  bridge or gateway reports every v3 entry as tampered in
  `GET /api/admin/audit/verify`, and an older gateway refuses to archive
  the audit log. Rolling the code back without restoring the pre-upgrade
  `detections.db` leaves every entry written since the upgrade
  permanently unverifiable by the older release. Entries written before
  the upgrade are not rewritten and keep verifying. See "Audit Chain
  Record Format (v3)" in `src/sigrift/bridge/UPGRADE.md`, which now
  upgrades the bridge and gateway containers together.
- **`BRIDGE_MFA_KEY` must be a valid Fernet key and `BRIDGE_AUDIT_KEY`
  must be set**, or the bridge and the gateway now refuse to start in
  production. Older installers wrote `BRIDGE_MFA_KEY` with
  `secrets.token_urlsafe(32)` (43 characters, not a Fernet key): append
  a single `=` to it — that keeps already-encrypted TOTP secrets
  readable — or re-run `scripts/quickstart.sh` / `scripts/install-release.sh`,
  which repair it the same way. Do **not** replace the key with a new one
  if users have MFA enrolled. See the upgrade section of `INSTALL.md`.
- **Production refuses to start with CSRF protection turned off.** With
  `BRIDGE_ENV` `production` or `prod`, the gateway and the bridge now stop
  at startup, naming `BRIDGE_CSRF`, unless it is unset, empty or
  `enabled` (any letter case, spaces ignored): "unset BRIDGE_CSRF or set
  it to enabled". `BRIDGE_CSRF=disabled` used to be honoured in
  production, and the bridge turned CSRF off for every other value too
  (`off`, `true`, `0`, ` enabled`), so all of them are refused. The
  gateway counts an unset `BRIDGE_ENV` as production (its default), so it
  refuses there too; the bridge counts it as development, so it only
  warns, and also refuses with `BRIDGE_MODE` `production` or `prod`, as
  its other production checks do. Outside production both start and warn,
  and the two services still read the value differently: the bridge
  turns its check off for every such value, the gateway only for exactly
  `disabled`, keeping its check at the `BRIDGE_ENV` default for any
  other value (on, except with `development`, `dev` or `test`), and its
  warning says so. The shipped compose files set no `BRIDGE_CSRF`;
  remove it from a production environment that does. The bridge now
  reads the value trimmed, so ` enabled ` enables the check. The admin
  switch `PUT /api/admin/settings/security` `{"csrf_enabled": false}`
  still turns the gateway's check off until a restart (admin only,
  audited).
- **Scripts that sign in must send `Content-Type: application/json`.**
  The gateway's login and MFA verify now answer 415 to any other body
  (see Changed). The most common way to hit it is `curl -d` without
  `-H`: `curl -c jar -d '{"username":…,"password":…}'
  https://host/api/auth/login` sends
  `Content-Type: application/x-www-form-urlencoded`, which 0.1.0
  accepted. Add `-H 'Content-Type: application/json'` (or use curl's
  `--json`, from curl 7.82) to cron jobs, monitoring checks and any other
  script that signs in.
- **`sigrift-sentinel` SSO behind the gateway:** the gateway now relays a
  backend session cookie only from the SSO routes under `/api/oidc`
  (see Changed). If an SSO sign-in lands on the dashboard signed out
  after the upgrade, and the gateway logs `Dropped a Set-Cookie for a
  session cookie from the backend` with another path, the add-on issues
  its session from a path outside `/api/oidc`: keep the previous gateway
  until the add-on is updated.
- The gateway container now receives `BRIDGE_AUDIT_KEY` and
  `BRIDGE_MFA_KEY` (and no longer `BRIDGE_MASTER_KEY`). A compose file
  generated by an older `install-release.sh` is not rewritten; the
  installer warns, and the gateway entries must be added by hand.
- Edge agents now **verify the gateway's TLS certificate by default**.
  Point `MLRF_CA_CERT` at the gateway cert (in-stack compose services and
  `/api/edge/install.sh --ca-cert` do this), and regenerate older
  self-signed certs (the installers do it on re-run) so their
  subjectAltName covers the hostname/IP remote nodes use; add extra names
  with `SIGRIFT_TLS_SANS`. `MLRF_INSECURE_TLS=1` disables verification
  (development only).
- **Node credentials act for one node.** A `node`/`sensor` API key
  without a `node_id` is bound to the first node it reports for (bridge
  node routes and gateway ingest), and the first key to claim a node
  keeps it: a further key for that node must be created bound to it by
  an admin. Unbound `viewer` keys are refused on node routes; `analyst`
  keys are never bound. `BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1` (bridge and
  gateway) keeps node keys unbound; it does not let `viewer` keys act
  for a node.
- **Node client certificates act only for the node their identity
  names.** With mTLS, a `node`/`sensor` certificate is accepted only when
  its identity equals the agents' `MLRF_NODE_ID`, and agents send no API
  key while a certificate is loaded, so per-agent certificates
  (`wifi-scan`, `bt-scan`, `local-edge` on a node with another id) get
  403 on every heartbeat and batch. Reissue one certificate per node
  (`POST /api/ca/issue` with `{"identity": "<MLRF_NODE_ID>", "role":
  "node"}` or `scripts/pki_bootstrap.py <node id>:node`), mount it into
  all of that node's agents and revoke the old ones.
  `BRIDGE_ALLOW_UNBOUND_NODE_KEYS` does not affect certificates.
- **Hand-edited client-certificate roles stop working.** The gateway now
  accepts a `role` in the CA's `registry.json` (`<bridge-data-dir>/ca/`)
  only when it is exactly `sensor`, `node`, `viewer`, `analyst` or
  `admin`, as the CA writes it. Another spelling (`Admin`, `ADMIN`) used
  to resolve case-insensitively, `keymaster` to KEYMASTER, and an unknown
  role, one with spaces around it or no role fell back to SENSOR. Such
  an entry now authorises no certificate: that agent's mTLS requests are
  no longer authenticated (401 wherever a role is needed) and its live
  sockets close with 4001. Entries the CA wrote are unaffected. Before
  upgrading, list the serials that would be refused with `jq -r '.issued
  | to_entries[] | select(.value.role | IN("sensor", "node", "viewer",
  "analyst", "admin") | not) | .key' registry.json`, and fix the role or
  reissue the certificate. After upgrading, the gateway logs each one at
  WARN with its serial and `field="role"` when it loads the registry.
- **API keys with a node key's id lose operator roles.** A key whose id
  starts with `node_`, `rtlsdr_`, `hackrf_`, `sensor_`, `edge_` or `sdr_`
  is now a NODE key on the bridge and the gateway whenever it is stored
  as `analyst`, `admin` or `keymaster` in any letter case. In 0.1.0 the
  bridge lowered only an exact `admin` or `analyst` and the gateway
  lowered none, so such a key kept its stored role on the gateway, and on
  the bridge too when stored as `keymaster` (which `PUT
  /api/admin/keys/{key_id}/permissions` could set), `ADMIN` or `Analyst`.
  It loses that role on upgrade, and its operator requests get 403. Both
  services log each such key at WARN when they load `keys.json` (the
  bridge: `Downgrading edge key <id> from <role> to node role`). `PUT
  /api/admin/keys/{key_id}/permissions` refuses an operator role for such
  a key with 400, and `POST /api/keys/` stores and returns such an id as a
  `node` key. Before upgrading, list the keys concerned with `jq -r '.keys
  | to_entries[] | select(.key |
  test("^(node|rtlsdr|hackrf|sensor|edge|sdr)_")) | select(.value.role |
  strings | ascii_downcase | IN("analyst", "admin", "keymaster")) | .key'
  keys.json` in the bridge's data directory, and give operator tooling a
  key whose id has none of these prefixes.
- **Check registered node hosts and ports after upgrading.** Before this
  release a node's own key could rewrite its node record through
  `POST /api/nodes/heartbeat` (bridge and Shiny dashboard; see Security).
  The upgrade stops new rewrites but does not repair a record already
  rewritten, and a valid host or port in it is still used: the bridge
  connects to the node's `host`, `port` and `rtl_tcp_port` for spectrum
  streaming and to its `host` for the SSH deploy of a rotated key.
  Compare each node's `host` and `port` in `GET /api/admin/nodes` (Shiny:
  `GET /api/nodes/`) with what you registered, and look for an
  `rtl_tcp_port` in the bridge's `nodes.json`, which no supported path
  writes: `jq -r '.nodes | to_entries[] | select(.value.rtl_tcp_port !=
  null) | .key' nodes.json` lists those nodes. Re-register any such node
  with `POST /api/nodes/register`, which replaces its whole record: set
  its map location and floor-plan position again if it had them.
- Alerts, watch bands, webhooks and decode jobs for detections the
  gateway ingests now run, asynchronously (`alerts_created` is always
  `0`); they need `UC_PROXY_SECRET`, which the shipped compose files
  require anyway. A gateway stop spools the hand-overs it still holds;
  those the bridge misses while it is down or restarting (a bridge
  restart, an upgrade) are dropped after 3 attempts and counted in
  `post_ingest_hooks.failed_*`. The bridge and gateway services get
  `stop_grace_period: 30s`. Details and the remaining changes: the
  "Upgrading" section of `INSTALL.md`.

- **API keys created from the dashboard through an older gateway never
  worked.** The gateway served `/api/admin/keys*` itself and stored them
  in a table nothing authenticates against; it now proxies key management
  to the bridge. If the gateway logs "Found API keys created through an
  older gateway's /api/admin/keys" at start-up, re-create the keys it
  lists that you still need, and check the dashboard's key list for keys
  you meant to revoke, rotate or re-role — the old API could not change
  them.

- **Shiny dashboard (`lib/shiny`) node keys.** A dashboard key is no
  longer a node credential: a node key is bound to the first node that
  heartbeats with it, and keys created before key purposes existed (no
  `purpose`, no `node_id`; listed in a startup warning) are refused for
  heartbeats until classified — bind each node's key with
  `PATCH /api/keys/<key> {"node_id": "<node>"}` and mark dashboard keys
  `{"purpose": "dashboard"}` (see `src/sigrift/edge/README.md`).
  `SHINY_LEGACY_KEY_TOFU=1` (or an end date) allows a one-off migration
  by first claim. One key shared by several nodes now works only for the
  first of them: give each node its own key.
- **Shiny dashboard (`lib/shiny`) viewer keys are read-only.** Creating an
  alert rule, acknowledging an alert, creating, rerunning or
  reprioritising a job, creating or changing a schedule, queueing a
  model evaluation, and connecting, disconnecting or retuning the
  spectrum source (`POST /api/spectrum/connect`, `GET
  /api/spectrum/disconnect`, `PUT /api/spectrum/config`) now need an
  `analyst` key (an `admin` key or the master key is one) and answer 403
  `analyst role required` to a `viewer` key — the default for `POST
  /api/keys/`, and the role of every key stored before roles existed
  (listed in a startup warning). Give the people who do these an analyst
  key: with the master key, pick the role in the dashboard's API Keys
  panel (new Role field) or send `"role": "analyst"` to `POST
  /api/keys/`. A key's role cannot be changed through the API: create a
  new key, or add `"role": "analyst"` to the key's entry in `keys.json`
  while the dashboard is stopped.
- Bridge: a key created with `POST /api/admin/keys` (the admin panel)
  without `expires_days` (or with `null`, or a blank expiry field in the
  panel) now expires after `BRIDGE_MAX_KEY_LIFETIME_DAYS` (default 365)
  instead of never, and a longer `expires_days` is capped to it, as
  `POST /api/keys/` already did. Keys created earlier keep their expiry;
  rotate long-lived node keys before they lapse. An `expires_days` of
  zero or less, or above 3650, is now a 422 and creates no key: zero or
  negative used to create a key that never expires, and from about 2.9
  million up it was a 500.
- Bridge: `POST /api/keys/` now answers 422 for an `expires_in_hours`
  above 10000000 or not finite. From 10000000 to about 7e7 hours this
  used to be accepted and capped to the maximum lifetime (201); above
  that it was a 500.

- **Gateway listening in plaintext behind a TLS-terminating reverse
  proxy.** The gateway told the bridge `X-Forwarded-Proto: https` on
  every request. Now it says `https` only on its own TLS listener, or
  when the direct peer is listed in `UC_TRUSTED_PROXIES` (default
  `127.0.0.1,::1`) and sends `X-Forwarded-Proto: https`. Otherwise the
  bridge gets `http`: its pages link `http://` assets (blocked as mixed
  content on an https page), and API key rotation answers 403. List the
  proxy's address in `UC_TRUSTED_PROXIES` and have it set the header
  (nginx: `proxy_set_header X-Forwarded-Proto $scheme;`). A gateway
  that serves TLS itself (the default install) still says `https`,
  unless a peer listed in `UC_TRUSTED_PROXIES` says
  `X-Forwarded-Proto: http`: a load balancer that took plain http from
  its client and re-encrypts. The bridge then gets `http`.

- **A reverse proxy in front of the gateway must be in
  `UC_TRUSTED_PROXIES` for the dashboard's WebSockets.** The gateway now
  honours `X-Forwarded-Host` and `X-Forwarded-Proto` only from a trusted
  proxy, and compares the `Origin`'s scheme. If a proxy rewrites `Host`
  (nginx's default `proxy_set_header Host $proxy_host`) or terminates TLS
  in front of a plaintext gateway listener, the dashboard's live feeds
  now get 403 "Cross-origin WebSocket refused" unless that proxy is
  trusted and sends `X-Forwarded-Host` / `X-Forwarded-Proto: https`. The
  default `127.0.0.1,::1` does not cover a proxy on the host of the
  compose stack: it connects through Docker's published port, from the
  gateway address of the stack's default network (for example
  `172.18.0.1`). Add `UC_TRUSTED_PROXIES` to the gateway's environment.
  The refusal is logged with the origin the gateway expected. See
  "WebSockets" in `src/gateway/README.md`.

- **The gateway refuses a `UC_LOCKOUT_WINDOW` above 86400 (24 hours).**
  It used to accept any window, but the bridge prunes the shared
  `account_lockout` table, so a longer password lockout did not hold (see
  Security). A longer `UC_LOCKOUT_WINDOW` (or `--lockout-window-secs`)
  now stops the gateway from starting with a message naming the option,
  and `PUT /api/admin/settings/security` answers 400
  `lockout_window_secs must be at most 86400` and changes nothing. The
  limit also applies to the MFA attempt limit, which uses the same
  window. Upgrade the bridge with the gateway: an older bridge still
  deletes lockout failures after 30 minutes. See "Account lockout" in
  `src/gateway/README.md`.

- **The gateway refuses a login limit of 0.** A `UC_RATE_LIMIT_MAX` or
  `UC_LOCKOUT_MAX` of 0 (or `--rate-limit-max=0`, `--lockout-max=0`)
  refused every login, administrators' included, and a
  `UC_RATE_LIMIT_WINDOW` or `UC_LOCKOUT_WINDOW` of 0 counted no attempt,
  which turned the rate limit or the lockout (and the MFA attempt limit)
  off. Each now stops the gateway from starting with a message naming
  the option; set at least 1. `PUT /api/admin/settings/security` refuses
  the same values with 400 (see Security). See "Login rate limit" and
  "Account lockout" in `src/gateway/README.md`.

- **Gateway password changes count toward the account lockout.** A wrong
  current password on `POST /api/auth/change-password` is now a failure
  like a failed login. Once an account has `UC_LOCKOUT_MAX` failures
  (default 10) within `UC_LOCKOUT_WINDOW`, from logins and password
  changes together, a password change gets 429 with `Retry-After: 1800`
  and `Account temporarily locked due to too many failed attempts.`, even
  with the right current password, until the window has passed. A locked
  account used to be able to change its password. Its user can wait out
  the window, or an admin can reset the password: a gateway password
  reset (`POST /api/admin/users/{username}/reset-password`) now also
  clears that account's lockout failures, so the user can log in with
  the new password at once. A reset used to leave them counted. If the
  bridge-owned `account_lockout` table cannot be read or written, the
  change gets 503.
- **Sessions the gateway refuses no longer work on proxied routes.** The
  gateway no longer forwards the client's `Authorization` and
  `X-Session-Token` headers to the bridge, nor a `session_token` cookie
  written with whitespace around its name (`session_token =<token>`). It
  sends only the session it verified, as `Authorization: Bearer`. It now
  reads such a cookie as the session cookie itself, as the bridge does.
  A session used from another client IP than the one it is bound to
  (`BRIDGE_SESSION_BINDING`, `ip` by default on the gateway) used to get
  401 on the gateway's own routes but still worked on routes proxied to
  the bridge, whose shipped binding is `none`. Such a request is now
  proxied as an anonymous one, so the bridge refuses it (401) wherever a
  login is needed, and that user must log in again. A client that sends
  another `Authorization` scheme to the bridge through the gateway no
  longer has it forwarded; the bridge reads none.
- **The gateway's Content-Security-Policy no longer allows inline
  script.** It now sends `script-src 'self'` (no `'unsafe-inline'`, no
  `'unsafe-hashes'`) and `object-src 'none'`; styles still allow
  `'unsafe-inline'`. The shipped pages keep working: their last inline
  `<script>` blocks and `onclick=` attributes moved into static files. A
  page or template you changed yourself to add an inline `<script>`
  block, an event-handler attribute (`onclick=`, `onload=`, ...) or a
  `javascript:` URL now does nothing there: the browser refuses it and
  logs a CSP violation in its developer console. Move that code into a
  file under `src/sigrift/bridge/static/` and load it with
  `<script src>`. For a diagnosis only, `UC_CSP_MODE=report-only` sends
  the policy as `Content-Security-Policy-Report-Only` (the browser then
  runs the inline code and logs each violation to its console; the
  gateway collects no reports) and `UC_CSP_MODE=disabled` sends no
  policy. Both remove the protection. A bridge run without a gateway now
  sends the same policy, which adds `base-uri 'self'`, `form-action
  'self'` and `font-src 'self'` to its own (it already refused inline
  script), and `payment=()` to its `Permissions-Policy`. In the compose
  stack (`docker-compose.yml`, and the compose file `install-release.sh`
  writes) the gateway now takes `UC_CSP_MODE` from `.env`, `strict` when
  unset; before, a value set there never reached it. A compose file an
  older `install-release.sh` wrote is not rewritten: add
  `- UC_CSP_MODE=${UC_CSP_MODE:-strict}` to its gateway's `environment:`.
  Upgrade and roll back the gateway and the bridge together (see above):
  this gateway in front of an older bridge refuses that bridge's inline
  handlers, so its documentation ("?") menu and Export PNG button do
  nothing; an older gateway in front of this bridge is fine. The bridge
  no longer serves FastAPI's generated `/docs` (Swagger UI) and `/redoc`
  pages, now 404: they loaded their script from a CDN, which neither
  service's policy ever allowed, so they were blank. `/openapi.json` is
  unchanged, and `static/docs/api_reference.html` documents the API.
- **Detection-config values a 0.1.0 bridge stored may stop applying.**
  `PUT /api/admin/detection-config`, `PUT /api/admin/protocols`, `POST
  /api/admin/auto-rescan` and bundle import now refuse (422) a number
  sent as a string, a boolean where a number belongs, a value out of
  range and an unknown key (see Fixed). A stored value those rules refuse
  (a string threshold, fractional snooze hours such as `0.5`, a string
  toggle, a string `auto_rescan` field, a weight object of more than 64
  entries) is left out once the bridge reads its configuration, and its
  default applies. After upgrading, look for the WARN
  `detection_config.json: stored values the configuration rules refuse
  are left out` in the bridge log, which names each one, and set those
  values again. Stored weights that sum to more than 2.0, or that with
  the default dimensions make more than 64 in one object, stay in force,
  but a `PUT` of that weight object (and so a `PUT` of the whole
  configuration `GET` returns) is refused until they fit.

### Security
- WebSocket auth fails closed when a session cannot be read. On the
  gateway, a session token in `Sec-WebSocket-Protocol` whose session or
  user row could not be read (a storage error) was taken as "no session",
  tried as an API key and refused with 401 as a bad credential; it is now
  refused with 503 `Authentication unavailable`, as the HTTP session path
  already did. The bridge did not fall through but let the storage error
  escape the handshake unhandled; it now refuses the upgrade with close
  code 1011 `Authentication unavailable`, the code its payload re-check
  already used, also for the errors of an encrypted (SQLCipher) store. A
  session whose user name, role, tenant or `enabled` flag holds a value
  of the wrong type, which the gateway already refused with 503, is now a
  storage error on the bridge too (1011 on a WebSocket, a server error on
  HTTP): an unreadable role was taken as viewer and an unreadable
  `enabled` as enabled. An unreadable scope stays refused as a restricted
  scope (4003 on a WebSocket).
- Gateway: login CSRF. Login and MFA verify are exempt from the CSRF
  token (a browser has none before it signs in) and read the body as
  JSON whatever its `Content-Type`. An attacker page could therefore
  post a cross-site `enctype="text/plain"` form, which needs no CORS
  preflight, whose field spelled a JSON object, and sign the victim's
  browser into the attacker's account. Both now answer 415 unless the
  body is declared `application/json` (see Changed).
- Gateway and bridge: the CSRF double-submit check compared the cookie
  and the `X-CSRF-Token` header with `!=`, which stops at the first
  differing character. Both now compare in constant time
  (`constant_time_eq`, `hmac.compare_digest`).
- Dashboard: a 401 logged the first 8 characters of the session token to
  the browser console. It now logs only the path.
- Gateway: the session cookie and the legacy `bridge_token` are no longer
  relayed from a proxied response (see Changed), so no bridge route but
  the SSO add-on's under `/api/oidc` can plant a session in the browser.
- Audit chain: `GET /api/admin/audit/verify` (bridge and gateway) skipped
  every entry without an HMAC as one written before the chain existed,
  wherever it was. So anyone able to write the database could append an
  unsigned entry (a forged `user_login`, say), or rewrite the newest
  entries and blank their HMACs (blanking every HMAC from an entry on
  hides a rewrite of any of them), and the chain still verified as
  intact. Both writers sign every entry, so an entry without an HMAC is
  now accepted only before the chain's first signed entry; after it, it
  is reported with the `expected` "an HMAC: only entries before the
  chain's first signed entry may have none" and an empty `actual`, and
  counted in `checked`. An archived prefix that ended with a signed entry
  (the gateway's archive anchor, or the terminal HMAC of an
  `archive_marker`) counts as signed, so blanking every live entry after
  an archive is reported as well, and the gateway refuses to archive a
  prefix with such an entry (409). Rows that predate the chain, before
  its first signed entry, still verify.
- Gateway: `PUT /api/admin/settings/security` applied a `rate_limit_max`
  or `lockout_max` of 0, which refuses every login, administrators'
  included, and cast larger counts to 32 bits, so `4294967296` was
  applied as 0 too (`4294967297` as 1). It also applied a
  `rate_limit_window_secs` or `lockout_window_secs` of 0, below a second
  or negative, which counts no earlier attempt and so turned the rate
  limit or the lockout off. It now refuses with 400, and applies and
  records nothing from the request: a count outside 1 to 4294967295 or
  that is not a JSON integer, and a window below 1 or that is not a
  number. A negative count, a fraction or a string used to be ignored
  with 200. `UC_RATE_LIMIT_MAX`, `UC_LOCKOUT_MAX`, `UC_RATE_LIMIT_WINDOW`
  and `UC_LOCKOUT_WINDOW` of 0 are refused at startup (see Upgrade
  notes).
- Node heartbeats (bridge and Shiny dashboard): `POST /api/nodes/heartbeat`
  copied every metric over the node's record, since `NodeMetrics` accepts
  extra fields. Any key bound to a node could so rewrite the `host`, `port`
  and `capabilities` an admin registered (the bridge connects to that host
  for spectrum streaming and SSH key deployment, and reads `rtl_tcp_port`
  from the record too), its `registered_at`, and the `last_seen` the server
  stamps: a future date kept a dead node active, and any other text made
  `GET /api/nodes/`, `GET /api/status` and the admin node list answer 500
  for every user and stopped every later bridge start. A heartbeat now
  stores only known metrics (`NodeMetrics`' own fields, the edge agent's,
  and the `mem_percent`, `gpu_percent` and `gpu_temp` the alert checks
  read), each only with a value of its type and range: percentages 0 to
  100, other numbers finite and not negative, temperatures -100 to 200 °C,
  counts whole, text up to 256 characters, never NaN or a bool for a
  number. Other names are ignored and a known metric with a bad value is
  cleared; the heartbeat is still accepted and still hands the node its
  queued commands. Of the `capabilities` a heartbeat updates only the edge
  agent's monitor fields (`agent_version`, `disk_percent`, `cpu_temp`,
  ...), as before, and a bad value now removes that entry. The rule is
  shared by both (`sigrift.lib.shiny.node_metrics`). Records already
  rewritten are not repaired: see Upgrade notes.
- Dashboard: the IQ download, the Wi-Fi pcap download link and the
  detection, RF anomaly and Wi-Fi anomaly exports put the key of an
  API-key sign-in in the URL (`?api_key=`/`&api_key=`), where browser
  history and proxy and server access logs keep it; with
  `BRIDGE_ENV=production` (query-key auth disabled) those downloads failed
  with 400. The links now carry no credential and are authenticated by the
  browser's session cookie, so a dashboard opened with an API key alone,
  with no password sign-in, can no longer download IQ, pcap or exports.
- Dashboard: a 401 (a session that expired or was signed out in another
  tab, or a revoked key) only rejected that request. With a leftover
  `csrf_token` cookie the page kept polling and showing data with no
  sign-in prompt. Any 401 now forgets the stored token or key and goes to
  sign-in once (`/login?next=<page>`), as the admin page does. A wrong or
  reused MFA code, also a 401, shows the server's reason instead and does
  not sign out.
- **API clients must escape radio text themselves.** Text a radio sends
  is now returned as received, no longer HTML-escaped once by the bridge
  (see Fixed): `ssid`, `security`, `reasons` and `frame_capture` in
  `GET /api/wifi/networks` and `GET /api/wifi/anomalies`, the gateway's
  own `GET /api/alerts` Wi-Fi rows (`ssid`, `reasons`), device names,
  types, class names and manufacturers in `GET /api/bluetooth/devices`
  (the gateway's own route as well), Zigbee device names in
  `GET /api/zigbee/devices`, the SSIDs and names in the Wi-Fi and
  Bluetooth whitelists, and the SSID or name a whitelist's audit note
  quotes (`Whitelisted AP <bssid> (<ssid>)`). Anyone in radio range
  chooses this text: a dashboard, SIEM view or script that inserts these
  fields into HTML must escape them, or a hostile SSID or device name
  injects markup. Alert messages, acknowledgement notes, condition-rule
  names and activity-log entries are still HTML-encoded once.
- **Back up the Wi-Fi and Bluetooth baselines before upgrading; restore
  them to roll back.** This release rewrites `wifi_baselines.json` as
  schema 2 (SSIDs as heard) on its first save, and Bluetooth baselines
  replace a name learned escaped with the name as heard. An older bridge
  reads both without converting them: its ingest still escapes SSIDs and
  names, so evil-twin matching misses every learned SSID with `&`, `<`,
  `>`, `"` or `'` until it learns that SSID again, and Bluetooth devices
  with such names raise `spoofed_identity` at every scan. Copy both files
  next to the database backup
  (`cp -p data/wifi_baselines.json data/wifi_baselines.json.pre-upgrade`,
  and the same for `bt_baselines.json`) and put them back with the
  database on a rollback. The same applies to importing a bundle exported
  by this release into an older bridge. See "Baseline Files (Radio Text
  as Heard)" in `src/sigrift/bridge/UPGRADE.md`.

### Security
- Dashboard, admin console and the other static pages: the HTML escaping
  helpers (`esc()` in `dashboard.js`, `admin.js`, `incidents.js`,
  `threats.js` and `sweeps.js`, `_escText`, `_sigEsc`, `_specEsc`,
  `_saEsc`, and the Shiny dashboard's) escaped `&`, `<` and `>` but not
  quotes, so text written into a quoted attribute could close it and add
  an event handler (stored XSS; the gateway's CSP allows inline handlers).
  A node-bound sensor key could do this with heartbeat fields (hardware and
  signal-class names in the node table's titles) and with detections it
  sends the bridge (a signal family in the RF anomaly filter and
  checkboxes, a detection ID in the Summary alerts); an analyst could do
  it with a condition-rule value, shown in the admin console's rule list
  and edit form. Every helper now escapes `& < > " '`, for text and for
  single- or double-quoted attributes.
- Values the pages wrote as markup without escaping now go through it:
  the admin node diagnostics' scanner count (`scan_count` and
  `anomaly_count`, which a sensor key sets by heartbeat: stored XSS into
  the admin console), ADS-B rows and map popups (callsign, ICAO address,
  source, last seen), drone rows, map popups for nodes, emitters and
  zones, the Wi-Fi device-cluster panel, sweep lists and details,
  training-run, scorer-weight and protocol labels, Zigbee channel and LQI,
  the RF anomaly Dismiss ID (a detection ID when the row has none) and
  frequency, a threat signature's frequencies, power, burst timings and
  test-match count, and counts the API returns (frequency, class, seen,
  frame, re-evaluation, row and delivery counts). The sweep list no longer
  builds inline `onclick` handlers from sweep IDs: they are data attributes, and
  sweep and device-cluster IDs are URL-encoded in requests. The pages no
  longer build CSS selectors from alert, node or floor-plan IDs or the URL
  hash, and the IQ capture dialog's fallback node option is built as text.
- Gateway: `POST /api/auth/change-password` checked the current password
  with no attempt limit. A stolen session could guess it without end
  (only 401 `Current password is incorrect`, nothing counted or audited)
  and, once it got it right, set a password of its choosing and log the
  owner's other sessions out. Each check is now reserved in the account
  lockout before its PBKDF2, atomically with the lockout check, as the
  login's is. So parallel guesses cannot exceed `UC_LOCKOUT_MAX` either.
  A wrong current password is audited as `auth_failure`, and a right one
  clears the count (see Upgrade notes).
- Gateway: the Content-Security-Policy allowed inline script
  (`script-src 'self' 'unsafe-inline' 'unsafe-hashes'`), and it replaces
  the bridge's stricter policy on every response. So had markup been
  injected into a dashboard page (a stored value some renderer failed to
  escape, say), an `onerror=` attribute or a `<script>` block in it would
  have run as script with the operator's session; no such injection is
  known. The policy is now `script-src 'self'` with `object-src 'none'`:
  injected markup cannot run script (see Upgrade notes). One shared table
  (`src/gateway/crates/sigrift-gateway-core/testdata/security_headers_parity.json`)
  pins the gateway's and the bridge's policies, and a static lock
  (`tests/bridge/test_csp_static_lock.py`) keeps inline script out of the
  templates, static pages, shipped JavaScript and the HTML the bridge
  builds. Every browser test now fails on a CSP violation, also in a
  window a page opens, and on the candidate gate on a page without the
  reviewed policy (`SIGRIFT_E2E_CSP=reviewed`); `tests/e2e/test_csp.py`
  checks that the browser suite records both.
- Gateway: the proxy forwarded the client's `Authorization` and
  `X-Session-Token` to the bridge whenever the gateway had not verified a
  session, and the bridge authenticates a session token itself. A
  session the gateway refused because it was bound to another client IP,
  sent as `Authorization: Bearer` or `X-Session-Token` from anywhere, so
  reached the bridge unchanged and was accepted there, since the shipped
  bridge does not check the binding. That held as well next to an API key
  the gateway accepted, as the bridge tries the session first. The proxy
  now drops both headers and sends the bridge only the session it
  verified (see Upgrade notes).
- Gateway: the session cookie was read, and dropped from proxied
  requests, only when it started with `session_token=`, while the bridge
  (Starlette's cookie parser) trims a cookie's name. A session sent as
  `Cookie: session_token =<token>` was thus no session to the gateway,
  reached the bridge unchanged and was accepted there from any client
  IP, whatever IP the session was bound to. The gateway now reads a
  cookie's name as the bridge does: such a cookie is the session, with
  the gateway's checks, and the proxy never forwards it.
- Gateway: the `Authorization` scheme was matched as `Bearer` exactly,
  while the bridge matches it in any letter case (RFC 9110 §11.1). A
  session sent as `bearer <token>` got 401 on the gateway's own routes
  and was proxied as an anonymous request with the token in it. The
  bridge authenticated it there without the gateway's IP binding check.
  Session lookup, logout, bearer API keys and the WebSocket cookie-origin
  rule now read the scheme in any letter case, as the bridge does. The
  shared table
  `src/gateway/crates/sigrift-gateway-core/testdata/session_token_parity.json`
  pins how both sides read a request's session token, the order of its
  sources included (`tests/bridge/test_session_token_parity.py` and the
  gateway's `session_tokens_are_read_as_on_the_bridge`). Bridge: an empty
  `Authorization: Bearer` or `X-Session-Token` stopped the session lookup
  there; it is now skipped, as on the gateway, and the next source read.
- Bridge with `BRIDGE_WORKERS` > 1: a key downgrade (or `revoked` /
  `enabled: false`) that one worker could not save (503 "Key change
  applied on this worker only") was retried by that worker's next save
  as the key's whole stale entry. If another worker had revoked or
  rotated the key in between, the retry wrote the key back with its old
  credential: a revoked key, or the leaked credential a rotation
  replaced, authenticated again on every worker and on the gateway, and
  the rotated-in credential stopped working. The retry now merges field
  by field: a key revoked on disk stays revoked, a rotated credential
  stays rotated (the downgrade is applied to it), and when both workers
  changed the role the lower one is kept. The pending worker also stops
  accepting such a key as soon as it re-reads `keys.json`.
- Account lockout with a `UC_LOCKOUT_WINDOW` above 1800: the bridge's
  periodic cleanup (every `BRIDGE_CLEANUP_INTERVAL`, default 1800 s)
  deleted every `account_lockout` failure older than its own 30-minute
  window, although the gateway counts the same table with its window.
  With `UC_LOCKOUT_WINDOW=86400` and `UC_LOCKOUT_MAX=10`, an attacker got
  about 10 password guesses per account every 30 to 60 minutes instead of
  10 a day. The bridge now keeps lockout failures for 24 hours (the
  gateway still prunes them to its own window every 5 minutes), and the
  gateway accepts a lockout window of at most 86400 seconds (see the
  upgrade note).
- Gateway: an API key stored in `keys.json` without a role, or with a
  value that names no role (null, a number, `""`, an unknown or padded
  name), authenticated as SENSOR on the gateway and as VIEWER on the
  bridge. So the gateway refused such a key on its own viewer routes
  (native detection queries, WebSocket feeds) while the bridge's routes
  served it, and took it for a node credential: with
  `BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1`, or without a usable
  `UC_PROXY_SECRET`, it accepted the key's detection batches for any
  node. The gateway now reads it as VIEWER, as the bridge does (and as
  the admin key listing shows it), so it is refused on node routes with
  403 `Node endpoints require a node API key`; give a key that a node
  really uses the `node` or `sensor` role
  (`PUT /api/admin/keys/{key_id}/permissions`). A role-less key named
  after a registered node still submits for that node, but the gateway
  now decides that from its copy of `nodes.json` instead of asking the
  bridge to bind the key, so for a node registered in the last minute or
  so (before the bridge saves `nodes.json`) its batches get that 403
  until the file is saved or the key's first heartbeat binds it. The
  bridge's `master`
  key, which the bridge writes without a role and always reads as ADMIN,
  was SENSOR on the gateway (VIEWER once rewritten, KEYMASTER if stored
  so) and is now ADMIN there too. One shared table
  (`src/gateway/crates/sigrift-gateway-core/testdata/key_role_parity.json`)
  pins both services' role resolution.
- Audit chain: new entries (record format v3, bridge and gateway) also
  authenticate `target_ids` (the IDs of a bulk operation) and
  `tenant_id`, and length-prefix every field, so a database writer
  without the key can no longer rewrite the ID list of a bulk action,
  move an entry to another tenant's chain, or shift text between adjacent
  fields undetected. Older entries keep the coverage of their version.
- Audit chain: `GET /api/admin/audit/verify` (bridge and gateway) no
  longer returns the computed HMAC as an error's `expected`. It was the
  valid HMAC for the entry's tampered content, so anyone who could write
  the database and read the endpoint could re-sign the chain with it;
  `expected` is now a fixed description.
- Gateway: the proxy forwarded methods it does not know (`TRACE`,
  `CONNECT`, extension methods) to the bridge as `GET`, so the bridge
  ran another method than the one authentication and CSRF had checked.
  They now get 405 with an `Allow` header naming the methods the bridge
  serves.
- Gateway: the bridge gets X-Forwarded-Proto, X-Forwarded-Host and Host
  from the gateway on every proxied request. On HTTP/2 (no Host header)
  a client's own `X-Forwarded-Host` / `X-Forwarded-Proto` (and
  `Forwarded`, `X-Real-IP`, ...) reached the bridge, which builds its
  URLs from them and checks the scheme before handing out a rotated API
  key. On a plaintext listener the gateway claimed `https` itself. The
  HTTP/2 authority is now forwarded as `Host`, so the bridge's links and
  redirects no longer name its internal address.
- Gateway: a request with both `Content-Length` and
  `Transfer-Encoding`, which a front proxy and the gateway can frame
  differently (request smuggling), left its connection open, so the
  bytes after the chunked body were read as another request. When
  `Content-Length` comes first, the request now gets 400, before CORS
  (which answers every `OPTIONS`), the body limit, the path checks or
  authentication can answer it. When it comes after, hyper drops it,
  and the request is answered, framed by its chunks. Either way, and
  after every other HTTP/1.1 request with `Transfer-Encoding`, the
  gateway now closes the connection (RFC 9112 §6.1). The proxy also
  forwarded the client's `Content-Length` next to the chunked body, so
  the bridge got the body cut short, or waited until the proxy timeout
  for bytes that never came; it now frames every forwarded body by the
  bytes it read.
- Gateway: the WebSocket `Origin` check for ambient credentials is
  stricter. The scheme is compared too (an `http://` page on the
  gateway's host is no longer this origin for the `https` gateway).
  `X-Forwarded-Proto` and `X-Forwarded-Host` count only from a proxy in
  `UC_TRUSTED_PROXIES`, and only their last entry. Handshakes
  authenticated by a client certificate are now checked like
  session-cookie ones. API keys stay exempt, as does a request without
  an `Origin`.
- Gateway: the security headers (CSP, `X-Frame-Options`,
  `X-Content-Type-Options`, HSTS and the rest) now wrap the whole served
  app, so the refusals of the middlewares (authentication, CSRF, the
  body limit, the path and framing checks) carry them too. Before, only
  the routes' and the proxy's answers had them.
- Gateway: a client-certificate entry in the CA registry
  (`registry.json`) whose `role` the bridge CA would never write now
  authorises no certificate, and the gateway logs its serial and
  `field="role"` at WARN when it loads the registry. Before, `keymaster`
  in any letter case resolved the certificate to KEYMASTER, which is never
  delegated to a certificate, and an unknown, empty, non-string or missing
  role silently fell back to SENSOR. A role must now be exactly `sensor`,
  `node`, `viewer`, `analyst` or `admin`, as the bridge writes it, so
  `ADMIN` and other spellings are refused too. Entries the bridge wrote
  are unaffected; fix or reissue any hand-edited entry the gateway log
  names (see the upgrade notes).
- Bridge: a client-certificate assertion from the gateway
  (`x-auth-method: client-cert`) whose `x-auth-role` is `keymaster`, in
  any letter case, is no longer honoured, even with a valid
  `x-rust-proxy`. It counts as no credential and is logged at WARN, so
  KEYMASTER cannot reach a certificate even if a gateway ever forwarded
  it. Before, the gateway's registry check was the only thing that kept
  it from one.
- Gateway: CSRF no longer exempts a request with `Upgrade: websocket`
  (a session `PUT` with that header could change the security settings
  without the token), nor the batch ingest paths (`/batch`,
  `/api/detections/batch`): a batch sent with a user session now needs
  the `X-CSRF-Token`, as every other session `POST` does. API-key and
  client-certificate ingest still need none.
- Gateway: a mutating request authenticated by a client certificate
  skipped CSRF protection altogether, though a browser that holds the
  certificate presents it on any TLS handshake to the gateway. A
  cross-site form (`text/plain` or urlencoded `POST`, no preflight)
  could make an operator's browser with an admin certificate create an
  admin account or disable a user's MFA. Such a request (`POST`, `PUT`,
  `PATCH`, `DELETE`; no API key) is now refused with 403 when its
  `Origin` is another origin and is not listed in `UC_CORS_ORIGINS`, the
  rule a certificate's WebSocket handshake already got, whether CSRF
  protection is on or off. Agents send no `Origin` and are unaffected;
  certificates still need no CSRF token.
- Gateway: `/api/admin/keys*` is proxied to the bridge — the only writer
  of `keys.json`, which both services authenticate against — instead of
  being served from a gateway-only `api_keys` table that no
  authentication path read. Dashboard key management (list, create,
  revoke, re-role, rotate, rotate-and-deploy) now acts on the real keys.
- Gateway: `keys.json` is reloaded when it changes, so revoked keys stop
  working without a restart; `expires_at`, `revoked` and `enabled` are
  enforced.
- Bridge: a key change that `keys.json` could not record (a full disk, a
  read-only data volume) was reported as done (200 or 201, and audited),
  although only the worker that took it had it: the gateway and the other
  workers, which read `keys.json`, kept accepting a revoked key, or a key
  at its old role, until a later save succeeded, and a restart before then
  lost the change. Creating, rotating, re-roling, binding and revoking a
  key (`/api/keys/`, `/api/admin/keys`) now answer 503 in that case: 503
  `Key change could not be saved; try again` when nothing changed, or, for
  a revocation or a downgrade, which stays in effect on that worker, a 503
  that says so, audited with `"pending": "not yet saved"` (repeat it once
  `keys.json` can be written). A node key's first-use binding is refused
  too (the gateway answers 503), and the bridge refuses to start when it
  must save the initial master key, re-sync `BRIDGE_MASTER_KEY` or register
  `BRIDGE_LOCAL_NODE_KEY`, with a CRITICAL log line naming `keys.json`.
  See "Key changes return 503" in `TROUBLESHOOTING.md`.
- Gateway and bridge: API keys are looked up by their lookup hash and
  PBKDF2 runs off the async runtime with bounded concurrency, so a flood
  of random `X-API-Key` values no longer stalls the service; the
  in-stack node key is no longer seeded twice (which left an unindexed
  entry in every default deployment). Password and backup-code hashing
  are offloaded too, and parallel logins can no longer race past the
  lockout counter.
- Gateway: the per-IP login rate limit allowed one attempt fewer than
  `UC_RATE_LIMIT_MAX` per `UC_RATE_LIMIT_WINDOW` (4 a minute with the
  default 5, none at all with `UC_RATE_LIMIT_MAX=1`). It also recorded
  the attempts it refused, so a client that kept trying stayed limited for
  as long as it kept trying. It now allows exactly `UC_RATE_LIMIT_MAX`
  attempts per window, as the bridge does, and records only the attempts
  it allows: a limited client can log in again once its allowed attempts
  are older than the window. The check and the record are one atomic
  statement, so parallel logins cannot exceed the limit, and a login is
  still refused (503) when the limiter's state cannot be read or written.
  If you raised `UC_RATE_LIMIT_MAX` by one to get the number of attempts
  you meant, lower it again.
- Gateway MFA: a stored TOTP secret that is empty, not Base32 or decodes
  to an all-zero key no longer accepts codes anyone can compute (HMAC with
  an empty key). The gateway logs why, with the username, and a backup
  code still completes the login. MFA setup no longer replaces an enrolled
  user's TOTP secret and backup codes when the user lookup fails, or when
  MFA is enabled while setup runs (two tabs, a retried request): it
  answers 409, or 404 for a deleted user. For crates built on
  `sigrift-gateway-core`: `auth::totp::compute_hotp` and `compute_totp`
  now return `Result<String, InvalidSecret>`, because an unusable secret
  has no code.
- Gateway user accounts: an admin, or a leaked admin API key, could give
  a user account a machine role (`sensor`, `node`), which the bridge never
  allows, or create an account named `.` or `..`, with any role up to
  admin, that no `{username}` route (update, disable, password reset, MFA
  disable) can reach past the gateway's path guard, so nobody could
  disable, demote or reset it through the API. Both are now refused (see
  "Changed"). `POST /api/auth/change-password` accepted the current
  password as the new one, so a forced change (`must_change_password`, as
  for the generated bootstrap admin password) could be completed while
  keeping the exposed password, also by appending NUL characters, which
  hash the same. The new password is now checked against the stored hash
  and refused with 400 `Password has been used recently. Choose a
  different password.` whenever `UC_PASSWORD_HISTORY_COUNT` is above 0,
  and on a forced change even when it is 0.
- Gateway and bridge fail closed in production on a missing or invalid
  `BRIDGE_MFA_KEY` / `BRIDGE_AUDIT_KEY`, never encrypt TOTP secrets with
  an invalid key, and agree on one key-validity rule with the installers.
  The gateway's audit trail was silently disabled in the default compose
  deployment; it is now wired up.
- Edge agents (`node_agent`, `rf_scan`, `wifi_scan`,
  `detection_reporter`, `tools/signal_tester`, `lib/shiny/node_agent`)
  verify TLS by default instead of sending their API key over an
  unverified connection; the remote `iq_capture` command is
  bounds-checked.
- wifi-scan and bt-scan containers are no longer `privileged`; they get
  only the capabilities they need.
- Bridge: `X-Forwarded-Proto` and `X-Forwarded-Host` are believed only
  from the gateway (a valid `X-Rust-Proxy`) or a peer listed in
  `BRIDGE_TRUSTED_PROXIES` (loopback always). Before, any client could
  send `X-Forwarded-Proto: https` over plaintext and pass the TLS check
  on `POST /api/admin/keys/{id}/rotate`, which returns the new raw key,
  and could choose the host and scheme of generated links. A TLS
  terminator other than the gateway (nginx) must now be listed in
  `BRIDGE_TRUSTED_PROXIES` unless it connects over loopback.
- Bridge: a session whose `last_active` cannot be read as a timestamp
  (`''`, a blank, garbage, a non-text value) is refused and deleted, like
  an idle one. Before, such a value skipped the idle timeout and the next
  request reset it to now, so an idle session came back with a fresh
  idle clock (in bridge-only deployments, or through direct access to the
  bridge port). A session whose `expires_at` cannot be read is now deleted
  too, not only refused. Both timestamps are read in the gateway's one
  layout: `YYYY-MM-DD`, `T` or a space, `HH:MM:SS`, an optional fraction,
  and an optional `Z` or `±HH:MM` offset (no offset means UTC). Every
  writer of the sessions table produces it. Forms Python's `fromisoformat`
  also reads (`+0000` offsets, a comma fraction, the basic or date-only
  forms) are now refused, as the gateway refuses them. A NULL
  `last_active` (a session from before the column) still means "no idle
  information": only the absolute expiry applies until the first request
  sets it. A row edited by hand or restored from another tool must use
  that layout. The idle time counts whole seconds, as the gateway counts
  it, so a session idle for 30 minutes and half a second is still within
  the default limit in both services.
- Bridge: `POST /api/auth/logout` now ends a session that is past its
  absolute or idle limit, or whose times cannot be read: the row is
  deleted, the answer is 200 and `user_logout` is audited (as `unknown`),
  as the gateway's logout does. Before, the lookup for the audit name
  deleted such a row first, so the logout answered 401 and audited
  nothing.
- Bridge CA: a certificate revocation could silently come undone. Changes
  to `data/ca/registry.json` were serialised only within one process, so
  `scripts/pki_bootstrap.py` run against a live stack, or a second bridge
  worker, could write back a registry it had read before the revocation;
  `POST /api/ca/revoke/{serial}` had returned 200 and the gateway, which
  enforces revocation from that file, accepted the certificate again. The
  same race dropped certificates already handed out (then refused by the
  gateway) and failed changes on each other's temp file. Every issuance,
  revocation and CA creation now holds an advisory lock on
  `data/ca/.ca.lock` (a new, empty `0600` file; a symlink or anything
  other than a regular file there is refused). A change that cannot get
  the lock within 5 seconds (its holder is stopped or hung) fails with a
  503 and changes nothing; it waits on a thread of its own, so the
  bridge's other requests are not held up, and reads never wait for it. Run
  `pki_bootstrap.py` from the same release as the bridge: an older one
  takes no lock (see `PKI_ARCHITECTURE.md`, "Files").
- Gateway: a password reset or change did not stop logins and changes
  already under way with the old password. A pending MFA login (password
  step done, `mfa_token` not yet used) survived the reset, so whoever
  held the password and a second factor could still finish it within its
  5 minutes; a login whose password check (about a second of PBKDF2) was
  running when an admin reset the password still got a full session; and
  a `POST /api/auth/change-password` that was verifying or hashing when
  an admin reset the password committed afterwards, replacing the
  admin's password with its own (from a session the reset had revoked).
  Every password change, the admin reset included, now ends the user's
  pending MFA logins in the same transaction, and the MFA challenge, the
  session and the password change are each committed only while the
  password the request verified is still the stored one (a change also
  needs its session to still exist and the account to be enabled).
  Otherwise the login answers 401 `Invalid username or password` or
  `Invalid credentials`, and the change answers 401 `Current password is
  incorrect` or `Not authenticated` and changes nothing. The transparent
  upgrade of a legacy SHA-256 password hash no longer overwrites a reset
  committed while it was checked; that login is refused, as on the
  bridge.
- Bridge: the same password-reset gaps, in the bridge's own auth routes
  (bridge-only deployments behind a reverse proxy, and direct access to
  the bridge port). An admin reset or a change through the bridge
  (`POST /api/admin/users/{username}/reset-password`,
  `POST /api/auth/change-password`) left the user's pending MFA logins in
  `mfa_tokens`. The gateway shares `detections.db` and redeems those
  tokens, so with a gateway on the same database a login started before
  the reset could still be finished at the gateway's
  `/api/auth/mfa/verify`. A bridge login whose password check had passed
  when an admin reset the password still got a session (or an MFA
  challenge). A bridge change-password that was hashing its new password
  when an admin reset the password committed afterwards, replacing the
  admin's password from a session the reset had revoked. Every password
  write now ends the user's pending MFA logins in its own transaction. The
  session, the MFA challenge and the password change are each committed
  only while the password the request verified is still stored and the
  account is enabled. A change also needs its own session to still exist,
  and its replacement session is refused if a reset lands right after the
  change. Otherwise the login answers 401 `Invalid username or password`,
  and the change answers 401 `Current password is incorrect` or `Not
  authenticated` and changes nothing. A change whose replacement session
  is refused answers 200 with `reauthentication_required: true`, as it
  already did when that session could not be issued. The same binding
  applies to `routers/mfa.py`'s `/api/auth/mfa/verify` (401 `Invalid or
  expired MFA token`), which the shipped bridge does not mount.
- Bridge: `POST /api/auth/change-password` did not count wrong current
  passwords, so a stolen session could guess the account's password
  without limit: no attempt was recorded, nothing was audited, and the
  answer was never 429. Each attempt now counts against the account
  lockout the login uses (the `account_lockout` table the gateway's login
  also counts). A wrong current password is audited as `auth_failure`,
  and once the account has 10 failures in 30 minutes (logins and changes
  together) every login and change for it gets 429 `Account temporarily
  locked due to too many failed attempts.` with `Retry-After: 1800`, even
  with the right password. A correct current password clears the count,
  as a successful login does.
- Gateway: a certificate revocation written to the CA's `registry.json`
  within the same filesystem timestamp tick as the version the gateway
  had loaded (on Linux the mtime advances in ticks of a few
  milliseconds, so revoking right after issuing, or several revocations
  in a row) was never applied: the gateway reloaded the registry only
  when its mtime changed, so the revoked certificate went on
  authenticating, and its open WebSockets passed revalidation, until a
  later write. It now reloads when the mtime, size or inode changes, and
  reads again a version it read within 2 seconds of its mtime until a
  read falls outside that window, so even an in-place rewrite of the same
  size within one tick is seen.
- Bridge: an edge-decoded message's own `tenant_id` was stored as given.
  A sensor key could attach `decoded_messages` that named another tenant
  to its detection batch, and the row went into that tenant's view of a
  shared database (and was missing from the sender's own). Edge-decoded
  messages, and the ADS-B aircraft tracks they feed, are now stored under
  the bridge's own tenant: the decoded-message and aircraft stores ignore
  a record's `tenant_id` (for `POST /api/aircraft/` positions too). An
  ADS-B track is now attributed to the batch's node, not to a node its
  metadata names.
- Bridge: the 10 MB request-body limit checked only `Content-Length`, so
  a chunked body of any size reached the route, which buffered and parsed
  it before authenticating (an unauthenticated client got a 422, not a
  413). The bridge now also counts the bytes of a chunked body as they are
  read and answers 413 `Request body too large` once it passes the limit
  (64 MB for the gateway's `/api/internal/*` ingest hook), whatever the
  route makes of the refused read, as the gateway's limit already did. The
  limit now applies before the upperCrust ingest proxy
  (`/api/detections/batch`, `/batch`) too: that proxy buffered a whole
  body of any size, and forwarded a declared one over 10 MB. This matters
  where the bridge can be reached directly (the bare-metal dev flow); the
  default compose stack and the documented systemd unit put the gateway in
  front. Every 413 of this limit, also for a declared length and on the
  ingest proxy, now carries the security headers (CSP, `nosniff`,
  `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`), as the
  gateway's own body-limit refusal does, and the `X-Correlation-ID`,
  `X-Request-ID` and `X-API-Version` headers, and is logged like any
  other API request. The declared-length 413 had none of them and was not
  logged. A request's logged duration now also counts the middleware's
  own checks.
- Bridge: the generated admin password file (`/tmp/sigrift-admin-pw`,
  written when no users exist and `BRIDGE_ADMIN_PASSWORD` is unset outside
  production) was opened by its fixed name without `O_EXCL`, so a symlink
  or file already there received the password, and the file was created
  with the umask's mode before it was made 0600. It is now created 0600
  with `O_EXCL` and `O_NOFOLLOW`. Whatever is already at that name is
  removed first, never written through. If it cannot be removed, for
  example another user's file in a shared sticky `/tmp`, no file is written
  and a warning is logged, as for any other write failure. The default
  container has its own `/tmp`. The risk was a shared `/tmp` in the
  bare-metal dev flow.
- Bridge: with `BRIDGE_ENV=production`, no users and no
  `BRIDGE_ADMIN_PASSWORD`, the bridge logged `Failed to seed default admin
  user` and started with no users, though the install guide says it
  refuses to start. It now refuses to start, before generating a password.
  The "Forced password change" section of the install guide, its
  "Admin password is never printed" note, the "Admin password lost"
  full reset in the troubleshooting guide and the bridge deployment
  guide's dev/production table now say so too. They described the
  generated password file for a plain `docker compose up -d`, whose
  default `BRIDGE_ENV` is production.
- Shiny dashboard: `viewer` keys, documented as read-only, could write:
  `POST /api/alerts/rules`, `PUT /api/alerts/{id}/ack`, `POST
  /api/jobs/`, `PUT /api/jobs/{id}/priority`, `POST
  /api/jobs/{id}/rerun`, `POST /api/jobs/schedules`, `PUT
  /api/jobs/schedules/{id}` and `POST
  /api/training/models/{id}/evaluate` accepted any valid key, and so did
  `POST /api/spectrum/connect` (an outbound connection from the
  dashboard host to any host and port the key holder named), `GET
  /api/spectrum/disconnect` (stopping every operator's live stream) and
  `PUT /api/spectrum/config` (retuning the receiver). They now need an
  `analyst` key, as the bridge's alert-rule, acknowledge, job and
  spectrum connect / disconnect routes do (see Upgrade notes). The
  dashboard, spectrum panel included, says so when a write is refused
  (403) instead of failing silently, and its API Keys panel shows each
  key's role and lets the master key pick the role of a new key.
- Shiny dashboard: the CSV exports (`GET /api/export/{nodes,alerts,
  training}?format=csv`) wrote cells as stored, so an alert rule named
  `=1+1` or a node host such as `@SUM(1+1)*cmd|' /C calc'!A0` ran as a
  formula in the spreadsheet of whoever opened the export. A cell that
  starts with `=`, `+`, `-`, `@`, TAB or CR is now prefixed with `'`, by
  the bridge export's rule (plain numbers such as `-85.5` are left as
  they are).
- Shiny dashboard and Bridge: the JSON exports HTML-escaped strings in
  dicts but not dict keys or strings inside lists (a node capability
  `{"tags": ["<img ...>"]}` came back raw). Every string is now escaped,
  at any depth, by one rule on both.
- Shiny dashboard and Bridge: ids checked against `[a-zA-Z0-9_-]{1,64}`
  (node ids, key ids, the node a key is bound to) and Shiny job names
  accepted a trailing newline, so `edge-01\n` was registered as a second
  node that looks like `edge-01`; the bridge's `signal_class` and
  `backend` patterns had the same gap. All now refuse it with a 422, as
  the gateway's checks already did. The bridge's backup and learned-state
  bundle downloads (`GET /api/admin/backups/{filename}`, its `/verify`,
  and `GET /api/admin/baselines/exports/{filename}`) likewise let a name
  with one trailing newline through and now answer 400.

### Added
- Learned-state export/import bundles: admin API
  (`/api/admin/baselines/*`, `/api/admin/presets/*`) plus a
  `python -m sigrift.bridge.bundles` CLI for headless
  backup/restore/migration, built on a validated `.sigrift.tar.gz`
  format (spec: `docs/bundle-format.md`). Two kinds: `export`
  (lossless same-site backup — the restore direction the one-way
  `/backup` endpoint lacked) and `preset` (fully synthetic,
  site-transferable, RF-only).
- Four synthetic environment presets shipped in-repo (`urban-dense`,
  `suburban-residential`, `rural-quiet`, `office-commercial`) so a
  fresh install starts warm instead of spending ~300 detections per
  frequency bin in learning mode, plus `SIGRIFT_PRESET` first-boot
  seeding (idempotent, provenance-gated; never overwrites learned
  state, never blocks startup on a bad preset). Timing patterns
  still learn locally.
- Periodic crash-safe baseline autosave: the bridge persists dirty
  anomaly baselines every `BRIDGE_BASELINE_SAVE_INTERVAL` seconds
  (default 900; 0 disables; admin-runtime-configurable), not only at
  graceful shutdown.
- Deterministic preset generator
  (`training/generate_preset_bundles.py`) driven by the signal
  factory — presets contain no real-site data and are reproducible
  from committed profile configs.

### Fixed
- A backup encryption key (`BRIDGE_BACKUP_ENCRYPTION_KEY`) that is set but
  is not a valid Fernet key no longer gives an unencrypted backup.
  `POST /api/admin/backup` now refuses with HTTP 500 and writes nothing (no
  file, no audit entry, no pruning). Its message says how to fix or unset
  the key, without quoting the key. An unset or blank key still writes
  unencrypted backups, and a valid key works as before.
- Bundle imports now check the structure of `wifi_baselines.json` and
  `bt_baselines.json`. A member must be an object with a `baselines`
  object, field types must match what the bridge exports, `alpha` must be
  in (0, 1], and variances and counts must not be negative. A malformed
  member is now refused with the usual 422 validation report, on the dry run
  too, before anything is applied. Before, it passed the dry run, and the
  apply could replace earlier components and then fail with a 500, leaving
  no `bundle_provenance.json` and no import audit entry. RF baselines or a
  signal whitelist of the wrong shape now also get a 422 instead of a 500,
  and an apply decodes every component before it replaces any live state.
- Edge model training no longer replaces the served model with a partial
  file. `POST /api/edge-models/model/train` writes `family_classifier.pth`
  and `family_classifier.onnx` under hidden temporary names in the same
  directory and renames them into place (the ONNX last) only once both are
  complete. Before, a save or export that failed part-way (a full disk, for
  example) left a truncated ONNX that `GET /api/edge-models/model/download`
  served with HTTP 200 and a digest of the truncated bytes, so edges that
  verify the digest accepted it. A failed job still answers 500. The
  previous model, its digest and the in-memory classifier now stay as they
  were.
- Gateway ingest refuses detections dated more than 5 minutes ahead of the
  gateway's clock. Each one is dropped on its own and counted in the batch
  response's `rejected` and `rejected_reasons` under a new key,
  `future_timestamp`; the rest of the batch is stored and still gets 200.
  Before, such detections were stored. The correlation step reads the
  newest detections of the last 10 seconds first, at most 500, so
  future-dated detections from one node kept every other node's detections
  out of cross-node correlation until they were purged.
- The SQLCipher migration of an existing plaintext database
  (`encrypt_existing_db`, run at start-up when `pysqlcipher3` is installed
  and `BRIDGE_DB_ENCRYPTION_KEY` or `BRIDGE_DB_ENCRYPTION_KEY_FILE` is set)
  no longer fails with `no such function: sqlcipher_export`. It ran
  SQLCipher's export through the standard-library `sqlite3` module, which
  does not have that function; it now runs through `pysqlcipher3`. A failed
  migration removes `<db>.encrypted` instead of leaving an empty one, and a
  data directory whose path contains a single quote no longer breaks it.
  SQLCipher at rest still does not work end to end: with `pysqlcipher3` and
  a key, the bridge's start-up fails later with `TypeError: Row() argument 1
  must be sqlite3.Cursor`, because the shared connection uses the standard
  library's row type. The shipped images do not install `pysqlcipher3`.
- A non-finite `BRIDGE_FUZZ_MAX_DURATION` (`nan`, `inf`, `-inf`) is now
  treated as malformed: the bridge logs the existing warning and enforces
  the 60 s default. Before, `nan` switched off the TX duration check, the
  300 s hard cap included. No shipped code path calls the TX safety checks
  yet, so this was latent.
- The Wi-Fi scanner now always logs why a capture round ended when
  `tcpdump` exits by itself. On a slow host the scanner could see
  `tcpdump`'s output end a moment before the exit itself, and then started
  the next round without the `exited unexpectedly` line; the last error
  line `tcpdump` printed could also be lost. Capture itself was not
  affected.
- Scanners now survive a sensor being unplugged, re-plugged or replaced.
  Before, a one-second USB drop of the RTL-SDR stopped RF scanning until an
  operator re-ran `quickstart.sh`: the receiver container kept a dead device
  and still reported healthy, and Docker could not restart it because its
  one mapped device node had gone. The Wi-Fi scanner crash-looped while its
  adapter was away and exited with an error on every stop, and the
  Bluetooth scanner scanned nothing, silently, when its adapter vanished.
  Now every scanner follows one rule set
  ([docs/sensor-lifecycle.md](docs/sensor-lifecycle.md)):
  - **Unplugged:** the scanner waits, logs one line and reports
    `sensor_absent`; it does not crash-loop or flood the log.
  - **Same sensor back:** capture resumes by itself, even if its USB device
    number, interface index or `hciN` number changed. The Wi-Fi scanner
    re-applies monitor mode. One condition for the SDR: the host must let
    the scanner open the returned receiver (see `sensor_unusable` below).
  - **Back, but the host does not let the scanner open it:** reported as
    `sensor_unusable`. This is what a re-plugged RTL-SDR looks like on a
    host that needed `prepare-rtl`, because that preparation is temporary
    and a re-plug or reboot resets the device node. Run `prepare-rtl` again,
    or make it last with the new
    `scanner_setup.py prepare-rtl --usb=<port> --print-udev-rule`, which
    prints one udev rule for that receiver for you to install. The tool
    still writes no system files itself.
  - **Different sensor in its place:** when setup recorded an identity, it
    is not used and is reported as `sensor_changed`; run `quickstart.sh`
    again to select it.
  - **Stopping** a scanner is a clean exit in every state.
  The dashboard shows these states for every scanner kind (`sdr`, `wifi`,
  `bluetooth`, `zigbee`, `adsb`) and shows recovery without a reload.
  **What changes for operators:**
  - The `rtl-tcp` service now runs `sigrift.edge.rtl_tcp_supervisor`, which
    starts `rtl_tcp` and answers the receiver's state on port 1235 inside
    the Compose network. `scan` no longer waits for `rtl-tcp` to be healthy
    before starting.
    `rtl-tcp` shows as unhealthy while the receiver is away; that is
    expected.
  - With managed scanner setup, `rtl-tcp` is given the receiver's USB bus
    directory (`/dev/bus/usb/BBB`), where it was given one device node. It
    can therefore see the other device nodes on that bus; what it can open
    is still limited by each node's permissions. This is what lets a
    re-plugged receiver return without an operator. Because of it, setup
    now refuses a receiver whose device node belongs to group root, or to a
    group that another device on the same bus shares: run the printed
    `prepare-rtl` command first.
  - Setup refreshes a saved sensor whose device number changed (and its
    group, when the new group passes the rule above), and upgrades an
    overlay written by an earlier version, including while the earlier
    `rtl-tcp` container is still running; it still refuses a different
    sensor.
  - Scanner status reports may carry a `reason` (`starting`,
    `sensor_absent`, `sensor_changed`, `sensor_unusable`, `capture_failed`)
    with state `error`. A scanner that meets an older bridge sends its
    report again without it.
  - New variables set by setup: `MLRF_SDR_USB`, `MLRF_SDR_IDENTITY`,
    `MLRF_WIFI_IDENTITY`; `MLRF_RTL_STATUS_PORT` (default 1235);
    `MLRF_BT_ADAPTER` may be a Bluetooth address as well as `hciN`.
  - Not followed: a Wi-Fi adapter that returns under a different interface
    name, or any sensor moved to a different USB port. Both need setup to be
    run again. Bluetooth is still not part of managed scanner setup: a
    replaced Bluetooth adapter is noticed only when `MLRF_BT_ADAPTER` is an
    address, and is selected by changing that setting. The Bluetooth
    scanner no longer counts BlueZ's cached device list as a working scan
    of the selected adapter.
- RF scanner: signal classification now works at real receiver levels. The
  classifier was trained on windows scaled to unit average power, but the
  Compose scanner (`rf_scan`) passed it receiver-scaled samples. On
  synthetic test signals that took accuracy from 92% to 15–35%, and at
  typical receiver levels every window was labelled `ask` with high
  confidence. Each window is now scaled to unit power before inference
  (90–92% on the same test at every level tried). Reported power and SNR
  still describe the raw capture. Detections stored before this fix keep
  the label they were given.
- Signal families: the shipped model's classes `ask`, `psk`, `qam`, `fsk`,
  `msk` and `dsss` were given the family `UNKNOWN` by the gateway and the
  bridge, which raised their anomaly score and could trip the default
  "Novel Signal Detected" alert rule on ordinary signals. They now get
  `ASK`, `PSK`, `QAM`, `FSK`, `FSK` and `SPREAD_SPECTRUM`, and the scanner's
  own family labels cover all 16 classes (its `lora-css` summaries now say
  `SPREAD_SPECTRUM`, as the bridge always did). Rows stored earlier keep
  `UNKNOWN`.
- RF scanner: it no longer runs with class names that do not fit the model.
  If the model's `_metadata.json` is missing or lists a different number of
  classes than the model outputs, the scanner logs the reason and exits
  instead of mislabelling every detection, and it no longer borrows another
  model's metadata file from the same folder. `quickstart.sh` now refuses to
  activate a downloaded model whose metadata file is absent from the
  release, cannot be fetched or fails its checksum. With managed scanner
  setup it also refuses a local model that has no metadata file, changing
  nothing, and scanner setup refuses to start the SDR scanner without
  `models/open-default_metadata.json`; an older installation that starts its
  scanners itself gets a warning instead. **If
  you supply your own model, put its `<name>_metadata.json` (with a
  `classes` list in the model's output order) next to it.**
- RF scanner: the capture length, `edge_inference.py --benchmark` and its
  stdin mode now follow the model's input length (8,192 samples for the
  shipped model) instead of assuming 4,096. `MLRF_INPUT_SAMPLES` is used
  only for a model whose input length is not fixed.
- Docs: the classifier has about 420,000 parameters, not the 525,000 and
  800,000 that `training/README.md` and `edge.py` stated.
- Dashboard: muting alert sounds now silences every alert sound. A browser
  notification for a critical or warning alert was shown without
  `silent`, so the operating system could still play its notification
  sound, and an alarm already playing when the operator muted kept
  playing to its end. Notifications are now silent while muted, muting
  stops a sound in progress, and the mute follows the setting changed in
  another tab. The mute button also reports its state to assistive
  technology (`aria-pressed` and a label that says what it will do).
- Hourly detection aggregates kept only one family per signal class on
  every bridge start after the first. The start-up schema script
  re-created the family-less unique index `idx_agg_unique (hour, node_id,
  signal_class)` that migrations 34 and 37 had dropped, so `INSERT OR
  REPLACE` overwrote one family's row with another's (for example
  `802.11n` and `802.11ac` under `wifi`). The script now creates the
  family-aware `idx_agg_unique_v2` and drops the old index, which repairs a
  database earlier starts re-created it on; later starts change nothing.
  Hours aggregated while the old index was in place are not rebuilt.
- Dashboard edge-onboarding card: it showed "No edge agents are reporting
  yet" on every status poll, even while nodes reported, and never showed
  the "In-stack scanners registered, awaiting heartbeat" state for a
  quick-start stack whose scanner key is already registered. Two versions
  of the card's code were loaded and the older one won. The card now
  hides once any node reports, and Copy command puts only the command
  with the key placeholder turned into a `# REPLACE WITH YOUR KEY`
  comment on the clipboard (a second handler also copied the raw
  `--api-key YOUR_NODE_KEY` command, which runs and fails with 401 in a
  loop instead of failing at once). Hide still lasts until the browser
  tab is closed, reloads included; a browser that blocks site storage
  keeps it hidden until the next reload.
- Dashboard Summary: a Wi-Fi, Bluetooth, Zigbee or SDR source that has
  not answered since the page loaded now turns its group red after two
  poll cycles, as one that stops answering does; before, it never did.
- Dashboard frequency panels: 162.4–162.6 MHz is labelled NOAA Weather
  (it was VHF), and suspicious frequencies list high severity first, then
  medium, then low (high ranked with low, below medium).
- Alert rule builder: the signal-class value field suggests the classes
  seen in the last 24 hours. It read a field `/api/status` does not
  send, so it never suggested anything.
- RF anomaly queue: Purge Resolved now asks before it re-evaluates and
  dismisses every resolved anomaly server-side, as the Wi-Fi Purge
  Resolved does; one stray click dismissed them all. Select all, Dismiss,
  Escalate and Export name anomalies only by their stored row ID: an
  anomaly (or, grouped, a group) without one has a disabled selection
  box, where it was sent by its detection ID (refused, so nothing was
  dismissed) or by its list position (which dismissed whichever anomaly
  had that row ID). The Wi-Fi and Bluetooth queues follow the same rule:
  ticking an anomaly without an ID sent an empty ID (Bluetooth: ID 0)
  to bulk Dismiss and ticked Select all.
- RF, Wi-Fi and Bluetooth anomaly queues: the bulk-action bar (select
  all, "0 selected") now hides once the last anomaly is dismissed or
  gone, and a selection no longer counts anomalies that have left the
  queue.
- RF anomaly scoring legend: its icon opens the legend again (a click
  on it toggled the legend twice).
- RF deep dive: the Multi-Node Correlation step shows the icon of the
  grade it settles on, not the "—" of an unchecked step. View on an IQ
  capture opens the deep dive of that capture (class, node, frequency,
  captured waveform, feedback and Mark as known), not an empty
  "Unknown" one.
- Wi-Fi and Bluetooth: the "Also: ..." badge on an anomaly card now
  links a MAC seen by both panels; the panels called the dashboard's
  entity index with the wrong arguments, so nothing was ever linked.
- RF, Wi-Fi and Bluetooth: a critical or anomalous anomaly reaches the
  threat timeline once, not again on every refresh (each 15 s for RF
  and Bluetooth, 8 s for Wi-Fi). Bluetooth events are now drawn in the
  timeline's Bluetooth colour and row, not as unknown-protocol grey
  "BT observation" marks.
- Wi-Fi and Bluetooth: a whitelisted AP or device shows as Authorized
  as soon as the whitelist has reloaded, not at the next poll.
- Wi-Fi: a network or client without a signal reading (or a client
  without a data rate), or with an empty one, shows "--", not a bare
  " dBm" or " Mbps".
- Bluetooth: a node reported without an RSSI is no longer marked as the
  strongest observer of an anomaly, and a device search with no match
  says "No devices match the search", not "No all devices".
- Gateway image builds could ship a gateway compiled from other sources.
  The builder's cargo `target` cache mount is shared by every build on a
  host's BuildKit, and cargo takes a workspace crate as fresh when none of
  its source files is newer than its cached build; `COPY` keeps the
  checkout's mtimes. So building a checkout made before another
  checkout's build (two clones, a candidate run after another) reused
  that build's binary: cargo printed `Finished` with nothing compiled.
  The build now touches `src/gateway` first, so the workspace crates are
  always compiled from the sources being built (dependencies stay
  cached). A single checkout updated in place (`git pull`, `git checkout`
  rewrite the files they change) was rebuilt correctly before too.
- Dashboard and admin pages served by a bridge without a gateway: the
  documentation ("?") menu never opened, and the spectrogram's Export PNG
  button did nothing. Both ran from inline handlers, which the bridge's
  own policy (`script-src 'self'`) refuses. They are now bound by
  `static/docs_dropdown.js` and `static/spectrogram_viewer.js`, so they
  work under either service's policy. The dashboard's inline copy of
  `static/auth_guard.js` is gone too.
- Removed `static/sweeps.js` and `static/wifi_fingerprint.js`, which no
  page loaded (the former built `onclick=` markup, the latter read a
  session key nothing writes). The `/api/sweeps` and
  `/api/wifi/device-clusters` APIs are unchanged. The WiFi tab's Device
  Clusters panel, which only `wifi_fingerprint.js` would have filled,
  stays empty as before.
- Gateway: a page loaded a few seconds after the previous request could
  lose one of its scripts, or an API call, to a 502 "Proxy error"; when
  the dashboard lost a script it needs, it stayed blank. The gateway kept
  an idle connection to the bridge for reuse for 90 seconds, but the
  bridge (uvicorn) closes one idle for 5 seconds, and a request sent on a
  connection as the bridge closed it failed. The gateway now stops
  reusing a bridge connection idle for 2 seconds
  (`BACKEND_POOL_IDLE_TIMEOUT`), and the bridge image states its 5-second
  keep-alive (`--timeout-keep-alive 5`);
  `tests/bridge/test_gateway_backend_keepalive.py` keeps them apart.
- Dashboard and admin dialogs taller than the window could not be
  scrolled: centred, their top sat above the window and their bottom
  below it, out of reach. On a laptop screen the signal deep-dive with a
  spectrogram lost its close button and the spectrogram's controls,
  Export PNG included, and its investigation checklist. Such a dialog now
  scrolls from its top; one that fits stays centred.
- Node records saved with a value of the wrong type (by an earlier
  heartbeat, or edited by hand) no longer fail their readers: the node
  listings and WebSocket snapshot, `GET /api/status`, the admin node list
  and diagnostics, the bridge start-up and the heartbeat's alert checks
  (bridge and Shiny), and on the bridge the map and geo endpoints
  (`GET /api/geo/map`, `/heatmap`, `/coverage`, `/activity`,
  `GET /api/nodes/locations`, `GET /api/maps/overlay`), the TDOA position
  lookup, the spectrum node list and `POST /api/spectrum/connect`, and the
  SSH deploy of `POST /api/admin/keys/{key_id}/rotate` (whose 500 lost the
  key it had just rotated). A missing or unreadable `last_seen`, or one
  more than 60 s ahead of the server's clock, is status `unknown`; one
  without a UTC offset is read as UTC; a latitude or longitude that is not
  a number in range is no location (the node is left off the map, not
  every node); any other bad field reads as not reported. Of the
  `capabilities` only the monitor fields a heartbeat copies there are
  checked; the admin's other entries are listed as registered, also one
  named like another metric (`status: "lab"`). A non-numeric
  `disk_percent` or `mem_percent` no longer makes the heartbeat answer 500
  after its record was saved, which cost the node its queued commands.
- `POST /api/spectrum/connect`: a node whose stored host is not a valid
  hostname or IP address (also the empty host a registration without one
  stores) is a 409 `Node '<id>' has no valid host registered` instead of a
  500, and a stored `port` or `rtl_tcp_port` that is not a whole number
  from 1 to 65535 (also the `port` 0 a registration without one stores)
  reads as the default, 8080 for the HTTP fallback and 1234 for rtl_tcp,
  instead of a 500 or a connection to port 0.
- Dashboard Summary and admin Nodes tables: one node reporting a value that
  is not a number (for example `cpu_temp: "hot"`) left the table empty for
  every node, the dashboard's on "Loading nodes...". Each number a node
  view formats (CPU, memory, temperature, uptime, latency, detection rate,
  and the fleet overview and diagnostics figures) now shows `--` when it is
  not a finite number, and the other nodes render as before.
- Dashboard: Escalate on selected RF or Wi-Fi anomalies dismissed them
  (`PUT .../anomalies/bulk/dismiss`) and then reported them escalated. It
  now calls the new `POST /api/detections/anomalies/bulk/escalate` and
  `POST /api/wifi/anomalies/bulk/escalate` (analyst role, 1 to 100 IDs),
  which dismiss nothing and raise one critical `anomaly_escalated` or
  `wifi_anomaly_escalated` alert per request (stored, sent to the live
  alert feed, webhooks and syslog). The alert names every anomaly it
  escalates (`anomaly_ids`; the first five described in its message), so
  an escalation of many anomalies adds one alert to the 200-alert store
  instead of pushing older alerts out, and sends one webhook and syslog
  message. An anomaly that an unacknowledged escalation alert already
  names is not alerted again (`already_escalated`); acknowledging that
  alert lets its anomalies be escalated again. Unknown IDs, and those of
  another tenant, are listed in `not_found`. The answer gives the new
  alert's `alert_id` (`null` when none was raised). The dashboard says how
  many anomalies the alert covers and, for a selection of more than 100,
  says so instead of sending a request the server refuses. The gateway
  proxies both endpoints to the bridge.
- Dashboard: the RF Intelligence anomaly queue in its default, ungrouped
  view threw on the first anomaly and showed "Failed to load anomalies",
  so no RF anomaly could be listed or acted on there. It lists them again.
- Dashboard: the Wi-Fi and Bluetooth panels opened no live socket for a
  cookie session (a new tab, or a sign-in that left no stored token). They
  now do, as the status and alert sockets already did.
- Dashboard: an error response lost the server's reason (`detail`): every
  failure became `HTTP <status>`, so MFA, IQ capture, whitelist and bulk
  action errors showed a generic message. The reason is shown again, as
  text.
- Admin console: a failed API key listing showed "No API keys"; it now
  says the listing failed and why. A refused key role change was silent
  and the select kept showing the refused role; it now shows the reason
  and the role still in effect. A role change refused with 403 (a role
  above the admin's own, the keymaster role, the master key) signed the
  admin out; it is now reported like any other refusal, and the admin
  stays signed in. A keymaster key's role select showed "Sensor"; it
  shows Keymaster. The crypto key panel showed `HTTP <status>` instead of
  the server's reason, and a failed crypto key listing could leave "No
  crypto keys" on screen.
- SSIDs and device names showed HTML entities, such as `Joe&#x27;s
  iPhone` or `AT&amp;T`: both Wi-Fi ingest routes,
  `POST /api/bluetooth/ingest`, `POST /api/zigbee/ingest` and the Wi-Fi
  and Bluetooth whitelist forms HTML-escaped them before storing them, and
  the pages escaped them again. They are now stored as received (SSIDs
  still lose control characters and are cut to 32 bytes; Zigbee names to
  64 characters) and escaped where they are shown, as
  `POST /api/bluetooth/ingest-summary` already stored them. Wi-Fi security
  and frame text, and Bluetooth type, class name and manufacturer, follow
  the same rule, and Wi-Fi anomaly frame captures are no longer escaped a
  second time. Alert messages stay HTML-encoded once, as documented.
  The Summary tab's activity log showed every event with entities as well
  (a Wi-Fi auto-alert entry read `Joe&#x27;s &quot;Cafe&quot;`): the bridge
  stores activity events HTML-encoded once, and the dashboard now decodes
  that layer before showing them, as it does for alert messages.
  Saved Wi-Fi baselines (`wifi_baselines.json`, also in exported bundles)
  move to schema 2: a schema 1 file is decoded on load and saved as
  schema 2, so evil-twin matching keeps working for SSIDs with `&`, `<`,
  `>`, `"` or `'`. The decode undoes exactly the five entities the old
  escaping wrote (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&#x27;`), so an SSID
  such as `Bob&copy` is kept as it is. A Bluetooth baseline that learned a
  name escaped matches the same name as heard, and keeps it from then on.
  Rolling back past this release needs the pre-upgrade baseline files:
  see the upgrade notes.
  **Data note:** rows stored before the upgrade (Wi-Fi networks and
  anomalies, Bluetooth devices from `/api/bluetooth/ingest`, Zigbee
  devices, whitelist SSIDs and names) are not rewritten and keep showing
  the entities until retention removes them. Whitelist notes are still
  stored escaped.
- Admin console: a condition rule's hover title showed its conditions
  escaped twice (`&amp;lt;`), and `<em>no conditions</em>` as text.
- `src/sigrift/bridge/UPGRADE.md`, Docker upgrade and rollback: the
  commands used names compose never creates. `docker tag gateway:latest
  gateway:previous` failed (compose builds `<project>-gateway`), retagging
  `bridge:*` did not change what compose runs, and the restore mounted a
  new, empty `bridge_data` volume instead of the stack's
  `<project>_bridge_data`, so it failed and `docker compose up -d` started
  the new release again. No Docker step made the
  `detections.db.pre-upgrade` it restored either. The upgrade now tags the
  running images (`docker compose images -q`) and copies the stopped
  database inside the volume through the bridge service; the rollback
  restores that copy the same way and gives the previous images the names
  compose runs for each service (`image_of`; `docker compose config
  --images gateway` also lists the bridge it depends on), starting nothing
  if a tag fails. Release installs pin the previous release's tag again
  instead.
- Node commands: the bridge (`POST /api/nodes/{id}/command`, `POST
  /api/admin/nodes/{id}/command`) and the Shiny dashboard (`POST
  /api/nodes/{id}/command`) now refuse `capture_start` and `capture_stop`
  with a 422. The edge agent has no handler for either and dropped them
  with an INFO log, while the bridge reported them queued and then
  dispatched. The accepted commands are `restart`, `update`,
  `update_config`, `status` and `ping`; IQ captures go through the
  bridge's `POST /api/nodes/{id}/capture`, as before.
- Bridge admin node routes: `POST /api/admin/nodes/{id}/command` took any
  command name for any node id, and both it and `PUT
  /api/admin/nodes/{id}/config` queued without a limit or a lease. Both now
  apply the checks of `POST /api/nodes/{id}/command`, before anything is
  queued or audited: a command outside the list above is a 422, a node
  that is not registered is a 404 (`Node '<id>' not found`), and a node
  with 100 commands already pending is a 429. Tooling that queued names of
  its own now gets that 422, as do `restart_scanner` and `run_diagnostics`,
  which older admin panels sent and the agent ignored. A command or config
  push that the node has not collected within 5 minutes is dropped, as
  other node commands already were: an admin `restart`, `update` or config
  push for a node offline longer than that no longer runs when the node
  comes back, and the response still reads `queued` (`config_queued:
  true`). Deregistering a node (`DELETE /api/admin/nodes/{id}` or `DELETE
  /api/nodes/{id}`) drops the commands still queued for it, so a node
  registered again under that id does not run them.
- Bridge admin panel: the nodes table's **Restart** button sent
  `restart_scanner`, which the edge agent ignored, so it did nothing. It
  now sends `restart`: the agent restarts every node service, `rf-edge`,
  `mlrf-bt-scanner` and `wifi-scan`, and then the node agent itself
  (`mlrf-agent`), and the node stops scanning and reporting while they
  restart. The confirmation says so. **Diag** queued
  `run_diagnostics`, which the agent cannot run; it now opens the node's
  diagnostics view, built from its heartbeats.
- Bridge: it now refuses to start on a database that a newer bridge has
  migrated (PRE-68), for example after the code alone was rolled back.
  When `schema_version` holds a migration newer than its own newest one,
  it logs CRITICAL and stops with `Database schema has migrations [...]
  newer than this build`, before it runs any schema statement. Before, it
  ran against a schema it did not know. Versions at or below its newest one
  (including the gaps 39 and 44) are accepted, and a database without
  `schema_version` starts as before. Bridges from before this release do
  not check. Rollbacks, and when a pre-upgrade restore is safe:
  `src/sigrift/bridge/UPGRADE.md`.
- Gateway: it now refuses to start on a database that a newer bridge has
  migrated, as the bridge does (PRE-68). When `schema_version` holds a
  migration newer than the bridge release the gateway was built with, it
  exits 1 with an error starting `schema: Database schema has migrations
  [...] newer than this gateway build`, before it changes anything in the
  database. It checks again when its wait for the bridge ends (the bridge
  answered, or 60 s passed), before it listens, so a gateway started
  before a newer bridge migrated the database refuses too when the bridge
  committed its migrations by then. A migration committed later (a bridge
  slower than that to start, or one upgraded on its own while the gateway
  runs) is refused only at the gateway's next start: upgrade and roll back
  the two together. Before, a gateway rolled back on its own (or run with
  `up --no-deps`, or outside compose) kept running against the newer
  schema, after adding its `sessions.scope` column and its `nodes`,
  `pending_commands` and `password_history` tables to it. Versions at or
  below the newest known one (including the gaps 39 and 44) are accepted.
  A database without `schema_version` (fresh, or not migrated by the
  bridge yet) starts as before. A `schema_version` that cannot be read
  refuses too. Gateways from before this release do not check: never
  start one on a database a newer release has migrated. Rollbacks:
  `src/sigrift/bridge/UPGRADE.md`. For crates built on
  `sigrift-gateway-core`: `BuilderError` has a new `Schema` variant for
  this refusal, so an exhaustive `match` on it needs an arm for it.
- The audit log's severity filter (`GET /api/admin/audit?severity=…`)
  failed with a 500, on the bridge and on the gateway, as soon as the log
  held an entry without details (a dismiss, account audits, bulk RF
  actions). Such entries now count as `info`, on both.
- Gateway `GET /api/admin/audit`: `total` was the size of the whole audit
  log whatever the filters (`action`, `operator`, `node_id`, `target_id`,
  `search`, `start`, `end`, `severity`), so a client paginating on it saw
  pages that did not exist. It now counts the entries the filters select,
  as on the bridge, read in the same snapshot as the page, and a failed
  count is a 500 instead of `total: 0`. (The bundled admin UI pages on
  the page size and was not affected.)
- Gateway `GET /api/admin/audit?search=…` treated `%` and `_` in the
  search term as LIKE wildcards, so searching for `%` or `_` listed
  nearly every entry. The term now matches literally (`\`, `%` and `_`
  are escaped), as on the bridge.
- Gateway `GET /api/admin/audit?severity=` (empty) listed nothing: it
  matched entries whose severity is the empty string. An empty severity
  is now no filter, as on the bridge.
- A genuine audit entry written with an integer, `None`, NaN, `-0.0` or
  boolean `freq_hz`, or with `None` as `signal_class`, `node_id`,
  `operator` or `note`, was reported as tampered: it was hashed as passed
  but verified as stored. These values are now stored, hashed and
  returned as they read back (`None` and NaN frequencies as `0.0`, `None`
  text as `""`), and a non-numeric `freq_hz` is refused. Entries written
  that way before this release still fail and need manual triage
  (`src/sigrift/bridge/UPGRADE.md`).
- Bridge CA: opening the CA with a key directory that is the CA
  directory under another name (a symlink, or `BRIDGE_SECRETS_DIR`
  pointing at the data directory) or a key path symlinked to the old
  `data/ca/ca.key` no longer deletes the CA private key. The key
  migration saw the same file twice and removed the "legacy" copy.
- Bridge: a `keys.json` whose `keys` section is not an object, or holds
  entries of which none is valid, is treated as unreadable: it is
  restored from `keys.json.bak` (or startup is refused), and at runtime
  the last good key set is kept. Before, it loaded as an empty key store
  and startup replaced `keys.json.bak` with it, losing every API key.
- Shiny dashboard: the master key can no longer be revoked (`DELETE
  /api/keys/master` is a 400; rotate it instead), and the dashboard no
  longer offers it. On an install that already revoked it, a restart
  writes a new master key to `initial-master-key.txt` (mode 0600) in the
  data directory, as on first start, and keeps every other key.
- Shiny dashboard: the key list flags a key the server rejects as expired
  (`expired`), and shows "Expired" for it, also when its stored expiry
  cannot be parsed (that used to read "Never").
- Bridge: both key lists (`GET /api/keys/`, `GET /api/admin/keys`) flag a
  key that bridge auth rejects as expired (`expired`), also when its stored
  `expires_at` cannot be parsed: `GET /api/keys/` lists that as `null`,
  which read as "never expires". A disabled or revoked key is not flagged.
  `GET /api/keys/` now lists `expires_at` as auth reads it: a stored value
  with surrounding whitespace is no longer listed as `null`, and one
  without a UTC offset is listed as UTC. `GET /api/admin/keys` keeps
  listing the stored value and adds `effective_expires_at`, the instant
  bridge auth applies (`null` when there is none or it cannot be parsed).
  The bridge admin panel's key list shows that instant, with its year, and
  EXPIRED from the flag, not from the browser's clock, date parser or time
  zone: a stored value without a UTC offset is no longer shown as local
  time, and one bridge auth cannot parse is shown as stored and EXPIRED,
  never as "Invalid Date" or as a date the browser guessed. The flag is
  bridge auth's verdict: the gateway reads a hand-edited `expires_at` with
  its own parser, so for example `2999-01-01T00:00` (no seconds) is listed
  as not expired and works on bridge routes but is refused by the
  gateway's own routes.
- Shiny and Bridge: a request body holding `NaN` or `Infinity` anywhere
  now gets a 422 instead of a 500, and an out-of-range key lifetime a 422
  instead of a 500 from the overflowing expiry date.
- Gateway proxy: an HTML page whose links the gateway rewrote (to hide
  `UC_PYTHON_URL`) kept the bridge's `Content-Length`, which no longer
  matched the body. Clients waited for bytes that never came, or misread
  the next response (a debug build panicked). The rewritten page now has
  its own length and a weak `ETag`. The rewrite no longer touches a
  longer port (`:8001` inside `:80010`), compressed bodies or byte
  ranges, or bytes that are not UTF-8. A `HEAD` for such a page has no
  `Content-Length` (it gave the length before the rewrite) and the weak
  `ETag`, and a `304` to a client holding the weak `ETag` sends it back
  weak. A bridge redirect to its own address (`Location` or
  `Content-Location`, e.g. a trailing-slash redirect) now goes out as
  the gateway path, unless that path starts with `//`, which a browser
  would follow to another host.
- Gateway proxy: a header the bridge sent more than once (several
  `Set-Cookie` fields) reached the client with only its last value, and
  a repeated request header reached the bridge with only its last value,
  although the gateway's own checks read the first. Every value is now
  forwarded, in order. Headers a `Connection` field names are no longer
  forwarded in either direction (RFC 9110 §7.6.1).
- Bridge: a `BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS` above 10000000
  (about 1141 years, the ceiling API key lifetimes have) is now logged
  and ignored, and the default of 24 hours applies. From about 7e7 hours
  up, the session expiry overflowed and every login (`POST
  /api/auth/login`) answered 500. A value below 1 is still ignored, and
  now logged too.
- Gateway: `BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS` and
  `BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES` (and their command-line options)
  are read as the bridge reads them. A value of zero or less was used as
  it was, so every session expired as it was created, or was idle at its
  next request, and session logins were locked out; it now gives the
  default (24 hours, 30 minutes), with a warning in the gateway's log. So
  does a value that is not an integer, which stopped the gateway from
  starting, and one of more than 4300 digits, which Python's `int()`
  refuses. Surrounding whitespace, a `+` sign and underscores between
  digits (`1_000`) are accepted, as on the bridge. An absolute timeout
  above 10000000 hours gives the default, with a warning, as on the
  bridge. A value
  written with digits other than 0-9 (`１５`, which the bridge reads as
  15) still stops the gateway from starting, now with a message that
  names the variable: the gateway does not read it, and its default could
  keep sessions the bridge has ended.
- Gateway: a huge absolute session timeout no longer breaks logins. From
  about 2.3e9 hours every login panicked and the client lost its
  connection; from about 7e7 hours the login got a session that its first
  request deleted, because its expiry was past year 9999, which neither
  the gateway nor the bridge reads. A session's expiry is now never later
  than `9999-12-31T23:59:59+00:00`. `PUT /api/admin/settings/security`
  now refuses with 400 a `session_absolute_timeout_hours` above 10000000,
  and a session timeout that is not an integer (it used to ignore one and
  answer 200); a refused request applies and records nothing. A
  `session_idle_timeout_minutes` above 9223372036854775807 is used as
  9223372036854775807 (no idle limit), so a JavaScript client that reads
  that value and writes it back (`9223372036854776000`) is not refused.
- Storage writes that fail now roll back instead of leaving the SQLite
  write lock held, which stalled every other writer for the busy
  timeout and made the write queue drop detection batches.
- ADS-B decoding: altitude (Q-bit position, Gillham for Q=0), airborne
  velocity bit offsets and the CPR longitude-zone function were wrong;
  they now match the Mode S reference vectors.
- Meshtastic: decryption used the wrong AES-CTR nonce layout (real
  traffic never decrypted), accepted wrong keys about half the time,
  parsed Position fields with the wrong wire types, and the LoRa path
  used made-up preset keys. All now follow the firmware.
- Edge nodes relearned their anomaly baselines from zero on every
  restart; they now persist them when `MLRF_DATA_DIR` is set
  (compose sets it via the new `edge_data` volume; the systemd unit
  via `StateDirectory=sigrift-edge`).
- BT baseline prune was defined but never invoked; it now runs on
  the autosave path.
- Learned baselines were only written at graceful shutdown, so an
  ungraceful stop (crash, OOM kill, power loss) lost them; the
  periodic autosave bounds the loss to one save interval.
- Bridge: `PUT /api/admin/detection-config` stored any value it was sent.
  After a string `rf_anomaly_insert_threshold`, every `POST
  /api/detections/batch` answered 500 after storing the batch's
  detections, so edges resent batches already stored; a string weight
  went into the live RF scorer, whose scoring then failed silently. Every
  value is now checked before anything is stored, snapshotted or audited,
  and a request with a refused value is a 422 whose string `detail` names
  each problem (a body that is not a JSON object gets FastAPI's usual 422,
  whose `detail` is a list). Thresholds, scores and
  `rf_min_confidence_floor` must be numbers from 0 to 1; the seen counts,
  `wifi_anomaly_cooldown_seconds` and `rf_min_learning_detections` whole
  numbers from 0 to 1000000000, and the snooze hours whole numbers from 0
  to 87840; each dimension weight a number from 0 to 1; `protocol_detection`
  `true` / `false` for protocols the bridge knows; `auto_rescan` the `POST
  /api/admin/auto-rescan` body; `iq_capture_enabled` `true` / `false`.
  Booleans, strings, `null`, NaN and infinities are not numbers. A weight
  object and `protocol_detection` hold at most 64 entries, counted as
  stored (a partial object merges into the stored one, so `PUT`s that
  each add names cannot grow it past 64), and one object's weights, as
  stored, sum to at most 2.0, as bundle validation already required (an
  export of a configuration `PUT` had accepted could fail to import).
  A key the bridge does not know is refused, unless it is sent with the
  value already stored, so the configuration `GET` returns can always be
  sent back. The 0.1.0 bridge accepted all of these: a client that sent a
  number as a string, or a key of its own, now gets a 422. A partial
  `protocol_detection` now merges into the stored toggles, as the weights
  do; it replaced them, so every protocol it left out went back to its
  default. Bundle import and preset apply check a bundle's
  `detection_config` with the same rules (keys and protocol names of
  another version stay allowed there) and refuse the bundle otherwise;
  a bundle whose weights or toggles, merged into the configuration in
  force, would break those bounds fails a `detection_config merge` check
  (a dry run reports it, `force=true` does not override it) and is
  refused (422) before any of its components is applied.
- Bridge: a stored detection-config value these rules refuse, one a 0.1.0
  bridge stored or one a configuration snapshot taken before this release
  brings back on restore, went to every reader: a restored string
  `rf_anomaly_insert_threshold` made ingest answer 500 again. Such a value
  is now left out when the configuration is read, so its default applies
  (for a weight or a protocol toggle, only that entry: the rest of its
  object is kept); the bridge logs a warning naming each one, and the
  next write drops them from `detection_config.json`.
- Bridge: `PUT /api/admin/protocols` turned a protocol on for any value
  Python counts as true, the string `"false"` included. A value that is not
  `true` / `false` is now a 422 that changes nothing (the rule
  `protocol_detection` has in `PUT /api/admin/detection-config`); a name
  the bridge does not list is still ignored.
- Bridge: `POST /api/admin/auto-rescan`, and the `auto_rescan` key of `PUT
  /api/admin/detection-config` and of bundles, converted strings and
  booleans (`"false"` became `false`, `"0.4"` 0.4, `true` a `max_retries`
  of 1). They are now strict: such a value is a 422, not converted.
- Bridge: `PUT /api/admin/protocols`, before any toggle was saved, wrote
  the toggle into the factory defaults in memory
  (`PersistenceManager.get_detection_config` copied them shallowly), so
  until a restart the defaults `GET /api/admin/detection-config` reported,
  and every other reader in that process, had that protocol toggled.
  `get_detection_config` now returns a deep copy.
- Bridge: with `BRIDGE_BACKGROUND_TASKS=false` (documented in the
  operations guide), shutdown failed with `UnboundLocalError` on the
  periodic tasks that were never started. It stopped before the final
  persistence save, the baseline saves, the write-queue drain and the
  database close, so node, alert and history changes since the last
  auto-save were lost, and learned baselines since the start. It now
  cancels only the tasks that were started and runs to its end.
- Bridge: the deprecated `AppState.create_session()` raised `NameError`
  (its module had no `logger`) instead of logging a warning and
  returning an empty token. Nothing in the bridge calls it.
- Shiny dashboard: queueing a model evaluation (`POST
  /api/training/models/{id}/evaluate`) stored a job without a name, and
  `GET /api/jobs/` and `GET /api/jobs/{id}` then answered 500 for every
  user until the job was deleted. Evaluations are now stored as complete
  jobs, one already stored without a name is listed as
  `evaluate-<model>`, a rerun of an evaluation is an evaluation again,
  and a stored job record that is not a valid job is left out of the
  list instead of failing it.
- Shiny dashboard: a stored job record that is not a valid job (a
  hand-edited `jobs.json`) still made `GET /api/jobs/{id}`, `PUT
  /api/jobs/{id}/priority` (after storing the new priority) and `POST
  /api/jobs/{id}/rerun` answer 500; one that is not an object did the
  same to `DELETE /api/jobs/{id}` and `GET /api/status`, and one with an
  unknown state could not be removed. The three now answer 409 and
  change nothing, the master key can always remove such a record, the
  status leaves it out, and it is logged once per defect instead of on
  every request.
- Shiny dashboard: a job whose stored `job_id` differs from its key in
  `jobs.json` was listed under an id that the job's own routes answered
  404 for; it is listed under its key. Jobs of equal priority are listed
  oldest first by the instant they were created (a time with another UTC
  offset, or none, used to sort as text).
- Shiny dashboard and Bridge: `GET /api/export/training` answered 500
  for CSV, and miscounted the runs in JSON, when `history.json` held an
  entry that is not a run (a hand-edited file). Such an entry is left
  out, as `/api/training/history` does.
- Admin console: a condition rule row whose value was left blank (the
  empty "Signal Class equals" row every new rule starts with) was saved
  as `<field> eq 0`, which no detection matches, so the rule was created
  and never fired. Saving now names the row that has no value and keeps
  the form open until it is filled in or removed, and a rule with no
  conditions (which never fires) is refused with "Add at least one
  condition"; a typed `0` is still kept.
- Admin console: the new or rotated API key dialog closed on Escape or a
  click outside before the admin ticked "I have stored this key
  securely", discarding a key that is never shown again. It now stays
  open until the key is acknowledged.
- Admin console, Config Versions: comparing two snapshots counted a file
  only one of them has as one line longer, with a phantom empty `+` or
  `-` line, so a removed one-line file read "2 changes". It now counts
  only that file's own lines.
- Admin console, ML Advisor: HIGH recommendations were sorted as LOW and
  listed below MEDIUM ones. "Active Nodes" always read 0/N and every
  multi-node fleet was told "N node(s) offline": the advisor counted
  nodes whose status is `online`, which `/api/nodes/` never reports; it
  now counts `active` nodes.
- Admin console, Database: a maintenance task that vacuums showed the
  database size twice, in KB on the first line and again on the VACUUM
  line (`DB size: 3072.0 KB` then `DB size: 3.0 MB`). It is now shown
  once, in B, KB or MB, as the VACUUM line shows it.
- Dashboard, Deployment table: an SSID, interface, firewall policy or
  ONNX model name containing `&`, `<`, `>` or quotes was shown with HTML
  entities (`Ops &amp; Lab`), and a model name with `&` was always
  flagged as drift. They are escaped once and compared as reported. A
  verified node that reports no disk usage showed `--` in green; it is
  now uncolored. After a refused Restart the node's Update button read
  "Restart" (and the reverse after a refused Update); each button keeps
  its own label.
- Shiny dashboard: `GET /api/training/history` and `GET
  /api/training/runs/{run_id}` answered 500 whenever training history
  was stored (`history.json` maps a node to its runs). The history now
  lists every stored run with its `node_id`, and a run is found by its
  `run_id`.
- Shiny dashboard: `GET /api/alerts/history` answered 500 for a `start`
  or `end` without a UTC offset (`2026-03-01`). Such a bound, and a
  stored time without an offset, is now read as UTC, as
  `/api/export/alerts` already read its date bounds.

---

## [0.1.0] — 2026-06-12

Private preview, tagged before the public repository existed and never
published. The public v0.1.0 release includes this section and
everything listed under [Unreleased] above.

### Added
- PKI Phase A: embedded certificate authority in the bridge
  (`/api/ca` routes), gateway mTLS client-certificate verification,
  cert wiring for all five scanners, and the `scripts/pki_bootstrap.py`
  provisioning tool. Additive — API-key auth is unchanged when disabled. See
  `PKI_ARCHITECTURE.md`.
- Spectrum retention: `spectrum_materialized` is now pruned by the
  periodic cleanup loop via `BRIDGE_SPECTRUM_RETENTION_DAYS` (falls back
  to `BRIDGE_RETENTION_DAYS`, default 90). Previously the table grew
  unbounded.
- Playwright end-to-end harness (`tests/e2e/`) and in-repo training
  tooling for the 16-class open-default model.
- Edge summarization: Bluetooth edge summarize, a unified
  `MLRF_SUMMARIZE` env var across the WiFi/BT scanners, replace-per-flush
  semantics for the RF detection reporter, and a runtime
  `MLRF_SUMMARIZE` toggle (flip via the bridge admin `update_config`,
  no node restart).
- Operator docs: `TAILSCALE.md` (remote access), `PRODUCTION_READINESS.md`
  (hardening checklist).

### Changed
- Dashboard/admin UX wave: tab-overflow menu, admin nav grouped into
  five clusters with ARIA tablist semantics, native `alert()` /
  `prompt()` callers replaced with non-blocking toasts and modals,
  severity dual-coding with shape-encoded indicators, viridis spectrum
  colormap, focus/scroll preservation across refreshes, risk-tiered
  admin maintenance buttons, login-page dark theme + caps-lock
  indicator.
- Upgraded FastAPI 0.128.0 → 0.136.3 and Starlette 0.50.0 → 1.2.1; see
  `src/sigrift/bridge/UPGRADE.md` for the migration notes.
- Bridge runs a single uvicorn worker to keep the SQLite WAL bounded;
  WAL checkpoints in `TRUNCATE` mode on a write-locked schedule.
- Cross-correlator queries use indexes plus a per-node throttle.
- Dependency bumps: RustCrypto digest-0.11 stack (sha1/sha2 0.11, hmac
  0.13, pbkdf2 0.13), tokio-tungstenite 0.29, axum-server 0.8,
  torch 2.12.0.

### Fixed
- Bluetooth/WiFi summary ingest rejected the edge scanner's gzipped
  bodies with `400`; the summary routes now decompress them (and
  truncated/corrupt gzip yields `400`, not `500`).
- BLE discovery produced zero devices inside the container: the
  `bluetoothctl`→`hcitool lescan` fallback was unreachable, `lescan` ran
  without `CAP_NET_ADMIN`, and its buffered output was lost on `SIGTERM`
  (now stopped with `SIGINT`).
- Write-queue idle busy-loop that pinned a CPU core; the flush deadline
  now rolls forward when idle.
- SQLite WAL stability batch: `busy_timeout` set before
  `journal_mode=WAL` (worker startup race), checkpoint task actually
  runs in `TRUNCATE` mode under the write lock, migration 53 split +
  orphan backup cleanup, corrupt-DB guard before applying migrations,
  and the spectrum materializer recovers its watermark + chunks inserts
  to stop WAL bursts.
- WebSocket auth: `require_ws_auth` raises `WebSocketException` (not
  `HTTPException`), and the WS connection limiter sees the real client
  IP instead of the gateway's Docker IP.
- BT and Zigbee hourly aggregation wired into the periodic cleanup
  loop.
- Alert ordering: "high" severity sorts between critical and warning.

---

## [0.1.0-rc1] — 2026-05-16

Private preview release candidate; never published.

### Highlights
- Rust gateway (`sigrift-gateway-core` library + `sigrift-gateway`
  binary) with no licence-verification code or crypto keys.
- Python bridge (FastAPI, 46 routers, 35 storage backends in the
  community tree) with plugin-based extension for commercial
  features.
- 82 TSCM threat signatures seeded on first boot.
- Base protocol decoders: ADS-B, UAT, Meshtastic, LoRa PHY, DMR,
  P25.
- Multi-node RF correlation, anomaly scoring, FHSS detection.
- RSS-based geolocation.
- MFA/TOTP authentication, HMAC-SHA256 tamper-evident audit chain.
- Bluetooth vulnerability scanner with CVE match.
- Real-time WebSocket feeds for detections, alerts, spectrum.
- Docker Compose and from-source install paths.
- AGPL-3.0 licensed.

### Added
- `INSTALL.md`, `QUICKSTART.md`, `TROUBLESHOOTING.md` — community
  install and first-run documentation.
- `CHANGELOG.md` (this file).
- **Session binding admin toggle.** New `GET` / `PUT
  /api/admin/session-binding` endpoints + a card in the admin
  dashboard's **System** tab for toggling between `strict` / `ip` /
  `warn` / `none`. Persists to `data/session_binding.json`. Flagged
  with a "restart required" banner when the saved preference drifts
  from the gateway's active env-var value. Ships disabled (`none`);
  see `SECURITY.md` for tradeoffs and enable procedure.
- **Edge-agent onboarding banner.** When zero nodes have checked in,
  the dashboard Summary tab surfaces a first-run card with copy-paste
  install instructions. New public `GET /api/edge/install.sh`
  endpoint serves a host-install script that blacklists the DVB
  kernel modules, installs apt + Python deps, writes a `chmod 600`
  env file, and starts a `sigrift-edge.service` systemd unit. The
  script is idempotent and never embeds secrets — the caller passes
  `--api-key` at runtime.

### Changed
- `ARCHITECTURE.md` rewritten: replaced the 4-tier feature-licensing
  table with a two-column community-vs-commercial editions matrix.
  Added Provider Plugin System rows for `FingerprintProvider`,
  `FuzzProvider`, `OidcProvider`.

### Removed
- `docs/LICENSE_SIGNING.md` — HSM key-management doc relocated to
  the commercial edition; not relevant to community users.

### Security
- Enterprise-feature code (fingerprinting, protocol fuzzing, OIDC
  routers, STIX export, TDOA storage) no longer ships in the
  community source. Community builds fall back to null providers
  that decline those features with 402 / 404 responses. CI enforces
  this via a community-source boundary check.
- Moved the auto-generated admin password temp file from the shared
  `bridge_data` docker volume to `/tmp` inside the bridge container.
  Closes the cross-container read path where a compromised gateway
  could read the plaintext admin password during the 60-second
  auto-delete window (SEC-M18 hardening). Read it now with
  `docker compose exec bridge cat /tmp/sigrift-admin-pw`.
- Bumped transitive `fastrand` dependency from 2.4.0 (yanked) to
  2.4.1 (no CVE; hygiene). `SECURITY.md` now explicitly documents
  the `bridge_data` volume-sharing threat model + the
  `BRIDGE_AUDIT_KEY` dev-mode tradeoff.
