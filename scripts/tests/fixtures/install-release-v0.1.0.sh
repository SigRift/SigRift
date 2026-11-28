#!/usr/bin/env bash
# SigRift community — install from a tagged release.
#
# Pulls pre-built bridge + gateway images from GHCR (linux/amd64 +
# linux/arm64), generates secrets and a self-signed TLS cert, writes a
# pinned docker-compose.yml plus override, and starts the stack in
# production mode (BRIDGE_ENV=production), published on 127.0.0.1 only
# unless SIGRIFT_BIND says otherwise.
#
# Designed to ship in the release tarball (`sigrift-vX.Y.Z.tar.gz`)
# alongside this script — but works standalone too, the only inputs
# it needs are a SIGRIFT_VERSION env var (or VERSION sidecar file) and
# Docker.
#
# Usage:
#   # From the unpacked release tarball (verify the tarball first, as in
#   # README-INSTALL.txt / INSTALL.md "Verifying a release"):
#   bash install-release.sh
#
#   # Standalone (no tarball): download, verify, THEN run — never pipe a
#   # download straight into bash. SHA256SUMS lists install-release.sh
#   # and is signed by the release workflow of this tag:
#   V=v0.1.0; R=https://github.com/SigRift/SigRift/releases/download/$V
#   for f in install-release.sh SHA256SUMS SHA256SUMS.sig SHA256SUMS.pem; do
#       curl -fsSLO "$R/$f"
#   done
#   cosign verify-blob \
#       --certificate-identity "https://github.com/SigRift/SigRift/.github/workflows/release.yml@refs/tags/$V" \
#       --certificate-oidc-issuer https://token.actions.githubusercontent.com \
#       --signature SHA256SUMS.sig --certificate SHA256SUMS.pem SHA256SUMS
#   sha256sum --check --ignore-missing SHA256SUMS
#   SIGRIFT_VERSION=$V bash install-release.sh
#
#   # Reachable from other machines (the LAN, remote edge nodes), not just
#   # this one — recorded in .env as SIGRIFT_BIND:
#   SIGRIFT_BIND=0.0.0.0 bash install-release.sh
#
#   # Extra names/IPs for the self-signed gateway cert (edge nodes on
#   # other hosts verify it against the address they dial):
#   SIGRIFT_TLS_SANS=sigrift.lan,203.0.113.7 bash install-release.sh
#
#   # Only renew the self-signed TLS cert when it expires within 30 days,
#   # keeping its names (for a cron job or systemd timer — see INSTALL.md
#   # "Certificate renewal"; it never adds names, a plain re-run does):
#   bash install-release.sh --renew-tls
#
# Re-runs preserve existing .env and Compose customizations. An explicit
# SIGRIFT_VERSION (or VERSION sidecar) updates only the two managed image
# tags and the known legacy HTTP health probe, after validating Compose,
# with a backup of the original file.
# docker-compose.override.yml is preserved (an invalid BRIDGE_MFA_KEY
# is repaired without losing encrypted TOTP secrets — see
# repair_mfa_key); the self-signed TLS cert is kept unless it lacks a
# required subjectAltName or expires within 30 days; the data volumes'
# ownership is normalised to uid 1500 (the bridge + gateway pinned
# appuser) on every run.

set -euo pipefail
cd "$(dirname "$0")"

RENEW_TLS_ONLY=0
case "${1:-}" in
    "") ;;
    --renew-tls) RENEW_TLS_ONLY=1 ;;
    *)
        echo "usage: $0 [--renew-tls]" >&2
        exit 2
        ;;
esac

# ── Version ──────────────────────────────────────────────────────────
# Priority: SIGRIFT_VERSION env > VERSION file in cwd > "main".
if [ -n "${SIGRIFT_VERSION:-}" ]; then
    VERSION="$SIGRIFT_VERSION"
    VERSION_REQUESTED=1
elif [ -s VERSION ]; then
    VERSION=$(tr -d '[:space:]' < VERSION)
    VERSION_REQUESTED=1
else
    VERSION="main"
    VERSION_REQUESTED=0
fi
if ! [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+)?$ || "$VERSION" =~ ^main(-[a-f0-9]{7,40})?$ ]]; then
    echo "Error: SIGRIFT_VERSION must be vX.Y.Z, vX.Y.Z-rcN, main, or main-<commit>." >&2
    exit 1
fi
echo "==> SigRift release: ${VERSION}"

OWNER="${SIGRIFT_OWNER:-sigrift}"
if ! [[ "$OWNER" =~ ^[a-z0-9]([a-z0-9-]{0,37}[a-z0-9])?$ ]]; then
    echo "Error: SIGRIFT_OWNER must be a lowercase GitHub account or organization name." >&2
    exit 1
fi
PORT="${UC_PORT:-8444}"

# ── Preflight ────────────────────────────────────────────────────────
for cmd in docker python3 openssl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: '$cmd' not found on PATH." >&2
        exit 1
    fi
done

if ! docker compose version >/dev/null 2>&1; then
    echo "Error: docker compose plugin not found." >&2
    echo "See https://docs.docker.com/compose/install/" >&2
    exit 1
fi

randstr() {
    python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
}

# dotenv_password reads a password on stdin, never through process argv.
# Compose's double-quoted dotenv values use JSON-style escapes; $$ prevents
# interpolation. This preserves spaces, quotes, backslashes and literal $/#.
dotenv_password() {
    python3 -c 'import json, sys; print(json.dumps(sys.stdin.read().replace("$", "$$"), ensure_ascii=False))'
}

# >>> shared: mfa-key (keep byte-identical in scripts/quickstart.sh and
#     scripts/install-release.sh; scripts/tests/test_install_scripts.py checks)
#
# BRIDGE_MFA_KEY rule shared with the bridge and the gateway: after
# trimming whitespace, exactly 44 characters — 43 from [A-Za-z0-9-_+/],
# then '=' — decoding (- → +, _ → /) to 32 bytes. Neither service
# encrypts with any other key, and in production both refuse to start
# without a valid one.
#
# fernet_key prints a new key: what cryptography's Fernet.generate_key()
# returns, but stdlib-only (the host's python3 usually has no
# `cryptography` package).
fernet_key() {
    python3 -c 'import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'
}

# repair_mfa_key ENV_FILE makes the BRIDGE_MFA_KEY that docker compose
# reads from ENV_FILE valid without losing TOTP secrets already encrypted
# with it. The value is read as compose reads it: the last assignment
# wins, `export ` and quotes are allowed, and an unquoted value ends at
# " #" (a comment).
#   valid key ......................................... left alone
#   43-character key (secrets.token_urlsafe(32), which older installers
#   wrote and older gateways encrypted with) .......... '=' appended
#   other value an older bridge/gateway could use ..... re-encoded, same bytes
#   missing, empty, or no version could ever use it ... new key
#   anything compose would read differently (multi-line, $, \) ... warning only
# Only that one assignment is rewritten, keeping its `export `, quotes and
# comment; the old file is kept as ENV_FILE.bak.<time>~ (0600).
repair_mfa_key() {
    python3 - "$1" <<'PY'
import base64
import binascii
import os
import re
import sys
import time

path = sys.argv[1]
NAME = "BRIDGE_MFA_KEY"
STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
ASSIGN = re.compile(r"[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*[=:][ \t]*")


def valid(key):
    """The shared rule (see above)."""
    key = key.strip()
    if not re.fullmatch(r"[A-Za-z0-9_+/-]{43}=", key):
        return False
    try:
        raw = base64.b64decode(key.replace("-", "+").replace("_", "/"), validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(raw) == 32


def older_service_keys(key):
    """The 32-byte keys an older bridge or gateway derived from *key*."""
    found = set()
    try:  # bridge: cryptography's Fernet(key) — lenient urlsafe_b64decode
        raw = base64.urlsafe_b64decode(key.encode())
        if len(raw) == 32:
            found.add(raw)
    except (binascii.Error, ValueError, UnicodeError):
        pass
    unpadded = key.strip().rstrip("=")  # gateway: URL-safe, padding ignored
    if re.fullmatch(r"[A-Za-z0-9_-]{43}", unpadded):
        found.add(base64.urlsafe_b64decode(unpadded + "="))
    return found


with open(path, newline="") as f:
    text = f.read()

# Find the assignment compose uses: (value, start, end) in text.
found = unreadable = None
pos, n = 0, len(text)
while pos < n:
    eol = text.find("\n", pos)
    eol = n if eol < 0 else eol
    m = ASSIGN.match(text, pos, eol)
    if not m:
        pos = eol + 1
        continue
    v = m.end()
    if v < eol and text[v] in "'\"":
        quote, k = text[v], v + 1
        while k < n and text[k] != quote:
            k += 2 if text[k] == "\\" else 1
        if k >= n:
            unreadable = "an unterminated quote in the file"
            break
        start, end = v + 1, k
        nxt = text.find("\n", k)
        pos = n if nxt < 0 else nxt + 1
        odd = "\n" in text[start:end] or (
            quote == '"' and ("\\" in text[start:end] or "$" in text[start:end])
        ) or (quote == "'" and "\\" in text[start:end])
    else:
        value = text[v:eol].rstrip("\r")
        cut = value.find(" #")
        value = value[:cut] if cut >= 0 else value
        start, end = v, v + len(value.rstrip(" \t"))
        pos = eol + 1
        odd = "$" in text[start:end]
    if m.group(1) == NAME:
        found = (text[start:end], start, end)
        unreadable = "a value compose would expand, or one spanning lines" if odd else None

if NAME in os.environ:
    print(f"WARNING: {NAME} is also set in this shell's environment; docker "
          f"compose uses that value instead of the one in {path}.", file=sys.stderr)
if unreadable:
    print(f"WARNING: could not check {NAME} in {path} ({unreadable}), so it was "
          "left as it is. The bridge and gateway need a valid Fernet key: if the "
          "key is 43 characters long, append '=' to keep existing encrypted TOTP "
          "secrets readable; otherwise generate a new key with python3 -c 'from "
          "cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'",
          file=sys.stderr)
    sys.exit(0)

old = found[0].strip() if found else ""
if old and valid(old):
    sys.exit(0)
if not old:
    new = base64.urlsafe_b64encode(os.urandom(32)).decode()
    what = (f"set a new {NAME} (there was none, so no TOTP secret was "
            "encrypted with one)")
elif re.fullmatch(r"[A-Za-z0-9_-]{43}", old) and valid(old + "="):
    new = old + "="
    what = (f"repaired {NAME}: appended '=' to the 43-character key. The key "
            "bytes are unchanged, so TOTP secrets encrypted with it stay readable")
else:
    keys = older_service_keys(found[0])
    if len(keys) > 1:
        print(f"WARNING: {NAME} in {path} is not a valid Fernet key, and older "
              "bridge and gateway versions read it differently, so it was left as "
              "it is. Set a valid key by hand (INSTALL.md, \"Upgrade note: "
              "BRIDGE_MFA_KEY\").", file=sys.stderr)
        sys.exit(0)
    if keys:
        new = base64.urlsafe_b64encode(keys.pop()).decode()
        what = (f"rewrote {NAME} as a valid Fernet key with the same 32 bytes an "
                "older version derived from it, so TOTP secrets encrypted with "
                "it stay readable")
    else:
        new = base64.urlsafe_b64encode(os.urandom(32)).decode()
        what = (f"replaced {NAME} with a new key: no bridge or gateway version "
                "could use the old value, so nothing was encrypted with it")

if found:
    _, start, end = found
    updated = text[:start] + new + text[end:]
else:
    sep = "" if not text or text.endswith("\n") else "\n"
    updated = f"{text}{sep}{NAME}={new}\n"

# The backup holds secrets: 0600, and a name ending in "~" (gitignored).
stamp, suffix = time.strftime("%Y%m%d-%H%M%S"), 0
backup = f"{path}.bak.{stamp}~"
while os.path.lexists(backup):
    suffix += 1
    backup = f"{path}.bak.{stamp}.{suffix}~"
for target, data in ((backup, text), (path + ".tmp", updated)):
    if os.path.lexists(target):
        os.unlink(target)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", newline="") as f:
        f.write(data)
os.replace(path + ".tmp", path)
print(f"==> {path}: {what}. Previous file: {backup}")
PY
}
# <<< shared: mfa-key

# >>> shared: tls-cert (keep byte-identical in scripts/quickstart.sh,
#     scripts/install-release.sh and scripts/bootstrap-staging.sh;
#     scripts/tests/test_install_scripts.py checks)
#
# The default self-signed gateway certificate. Its subjectAltName covers
# every name a client may verify it against: localhost, 127.0.0.1 and ::1
# (host-side curl, host-network scanners), gateway and bridge (compose
# DNS), this host's short name, FQDN and addresses (remote edge nodes,
# browsers on the LAN), and SIGRIFT_TLS_SANS: a comma-separated list of
# extra DNS names / IP addresses (a public name, a NAT address, ...).
# Left out of the automatic list: IPv6 link-local and temporary (privacy)
# addresses and Docker's own bridge interfaces, which come and go by
# themselves — add any of them to SIGRIFT_TLS_SANS if clients use them.
#
# tls_ensure_cert CERT KEY CN EXTRA_SANS creates the cert when it is
# missing and regenerates it when it lacks a required name — keeping
# every name the old one had — or expires within TLS_RENEW_DAYS (30)
# days: edge agents verify the gateway and refuse an expired certificate.
# New certificates are valid for TLS_CERT_DAYS (825) days. A certificate
# that is not self-signed (operator-supplied, CA-issued) is never
# replaced; a warning lists what it lacks or says it is about to expire.
# Sets TLS_CERT_CHANGED=1 when it wrote a new cert: containers that mount
# it must then be recreated to see it, and edge nodes on other hosts that
# were given the old one (--ca-cert / MLRF_CA_CERT) need the new one.
#
# TLS_RENEW_ONLY=1 (the unattended --renew-tls / renew-tls mode) renews
# only a certificate that expires within TLS_RENEW_DAYS, with the names
# it already has: a missing name (the host got a new address, a VPN
# came up) is only warned about, because a new certificate breaks every
# remote edge node that pinned the old one until someone copies it over.
# Re-running the installer (or a staging deploy) adds missing names.
#
# Before it replaces the files it creates .recreate-pending next to the
# cert (tls_recreate_marker); the caller removes it once the containers
# that use the cert were recreated: tls_recreate_done when the exit
# status of `up` proves it, tls_recreate_confirm when it cannot (an `up`
# run with `|| true`). While it exists, tls_recreate_pending is true, so
# a recreate that failed (a pull or an `up` that died after the files
# were swapped) is retried on the next run instead of leaving the
# gateway serving the old certificate.
TLS_CERT_CHANGED=0
TLS_RENEW_ONLY=0
TLS_CERT_DAYS=825
TLS_RENEW_DAYS=30

tls_recreate_marker() {
    printf '%s/.recreate-pending' "$(dirname -- "$1")"
}

# tls_recreate_pending CERT — true while the containers that use CERT
# still have to be recreated (a new cert this run, or one an earlier run
# wrote but could not recreate the containers for).
tls_recreate_pending() {
    [ "$TLS_CERT_CHANGED" -eq 1 ] || [ -e "$(tls_recreate_marker "$1")" ]
}

tls_recreate_done() {
    rm -f -- "$(tls_recreate_marker "$1")"
}

# tls_recreate_confirm CERT COMPOSE... — for a recreate whose `up` may
# fail by design (`|| true`), once the gateway is healthy: removes the
# marker only if every running container of the project's services, the
# gateway among them, started after the marker was written, so it reads
# the new certificate (the gateway loads it at start-up, and a bind
# mount is resolved when a container starts). A healthy gateway proves
# nothing on its own: an `up` that failed before compose reached it (a
# full disk while the bridge was recreated) leaves the old gateway
# running, healthy, with the old certificate. Otherwise it names on
# stderr what still runs from before, keeps the marker and returns 1.
# COMPOSE is the compose command line, e.g. `docker compose`.
tls_recreate_confirm() {
    local marker services ids stale
    marker=$(tls_recreate_marker "$1")
    shift
    [ -e "$marker" ] || return 0
    services=$("$@" config --services 2>/dev/null) || services=""
    # One service name per word; none (config failed) lists them all.
    # shellcheck disable=SC2086
    ids=$("$@" ps -q $services 2>/dev/null) || ids=""
    # shellcheck disable=SC2086
    stale=$(
        if [ -n "$ids" ]; then
            docker inspect -f \
                '{{index .Config.Labels "com.docker.compose.service"}} {{.State.StartedAt}}' \
                $ids 2>/dev/null
        fi | python3 -c '
import calendar, os, re, sys
since = os.stat(sys.argv[1]).st_mtime
seen, stale = set(), set()
for line in sys.stdin:
    f = line.split()
    if len(f) != 2:
        continue
    seen.add(f[0])
    m = re.match(r"(\d+)-(\d+)-(\d+)T(\d+):(\d+):(\d+)(\.\d+)?Z$", f[1])
    t = 0.0
    if m:
        t = calendar.timegm(tuple(int(g) for g in m.groups()[:6]))
        t += float(m.group(7) or 0)
    if t < since:
        stale.add(f[0])
if "gateway" not in seen:
    stale.add("gateway(not-running)")
print(" ".join(sorted(stale)))
' "$marker"
    ) || stale="gateway"
    if [ -z "$stale" ]; then
        rm -f -- "$marker"
        return 0
    fi
    echo "ERROR: the recreate for the new certificate in $(dirname -- "$marker")/ did not reach: ${stale}" >&2
    echo "    (they still run from before it changed, with the old certificate)." >&2
    return 1
}

tls_host_names() {
    hostname -s 2>/dev/null || true
    if command -v timeout >/dev/null 2>&1; then
        timeout 5 hostname -f 2>/dev/null || true
    else
        hostname -f 2>/dev/null || true
    fi
}

tls_host_addrs() {
    if command -v ip >/dev/null 2>&1; then
        ip -o addr show 2>/dev/null | awk '{
            ifname = $2; sub(/@.*/, "", ifname)
            if (ifname == "lo" || ifname ~ /^(docker[0-9]+|br-[0-9a-f]+|veth)/) next
            if ($0 ~ / scope host/) next
            if ($3 == "inet6" && ($0 ~ / scope link/ || $0 ~ / temporary/ || $0 ~ / deprecated/)) next
            if ($3 == "inet" || $3 == "inet6") { a = $4; sub(/\/.*/, "", a); print a }
        }'
    else
        hostname -I 2>/dev/null || true
    fi
}

# tls_san_tool required EXTRA NAMES ADDRS | missing CERT_TEXT SANS |
#              merge CERT_TEXT SANS
tls_san_tool() {
    python3 - "$@" <<'PY'
import ipaddress
import re
import sys

LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
HOST = re.compile(rf"{LABEL}(?:\.{LABEL})*")
WILDCARD = re.compile(rf"\*\.{LABEL}(?:\.{LABEL})+")


def as_ip(text):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def dns_name(text, wildcard=False):
    name = text.rstrip(".")
    ok = len(name) <= 253 and (
        HOST.fullmatch(name) or (wildcard and WILDCARD.fullmatch(name))
    )
    return name.lower() if ok and as_ip(name) is None else None


class Sans:
    def __init__(self):
        self.items = []

    def add(self, kind, value):
        if value is not None and (kind, value) not in self.items:
            self.items.append((kind, value))

    def render(self):
        return ",".join(f"{kind}:{value}" for kind, value in self.items)


def parse(text):
    sans = Sans()
    for part in filter(None, (p.strip() for p in text.split(","))):
        kind, _, value = part.partition(":")
        sans.add(kind, as_ip(value) if kind == "IP" else dns_name(value, True))
    return sans


def from_cert(cert_text):
    sans = Sans()
    lines = cert_text.splitlines()
    for i, line in enumerate(lines[:-1]):
        if "X509v3 Subject Alternative Name" in line:
            for part in (p.strip() for p in lines[i + 1].split(",")):
                if part.startswith("DNS:"):
                    sans.add("DNS", dns_name(part[4:], True))
                elif part.startswith("IP Address:"):
                    sans.add("IP", as_ip(part[len("IP Address:"):]))
            break
    return sans


cmd = sys.argv[1]
if cmd == "required":
    extra, names, addrs = sys.argv[2:5]
    sans = Sans()
    for name in ("localhost", "gateway", "bridge"):
        sans.add("DNS", name)
    sans.add("IP", as_ip("127.0.0.1"))
    sans.add("IP", as_ip("::1"))
    for name in names.split():
        if dns_name(name) is None:
            print(f"WARNING: host name {name[:80]!r} is not a valid DNS name; "
                  "left out of the TLS certificate", file=sys.stderr)
        sans.add("DNS", dns_name(name))
    for addr in addrs.split():
        ip = as_ip(addr.split("%")[0])
        if ip is not None and not ip.is_loopback and not (
            ip.version == 6 and ip.is_link_local
        ):
            sans.add("IP", ip)
    bad = []
    for entry in filter(None, (e.strip() for e in extra.split(","))):
        kind, sep, rest = entry.partition(":")
        if sep and kind in ("DNS", "IP"):
            value = as_ip(rest) if kind == "IP" else dns_name(rest, True)
        else:
            kind, value = "IP", as_ip(entry)
            if value is None:
                kind, value = "DNS", dns_name(entry, True)
        if value is None:
            bad.append(entry)
        sans.add(kind, value)
    if bad:
        sys.exit("ERROR: SIGRIFT_TLS_SANS: not a DNS name or IP address: "
                 + ", ".join(repr(b[:80]) for b in bad))
    print(sans.render())
elif cmd == "missing":
    have = from_cert(sys.argv[2]).items
    print(",".join(f"{k}:{v}" for k, v in parse(sys.argv[3]).items
                   if (k, v) not in have))
elif cmd == "merge":
    sans = parse(sys.argv[3])
    for kind, value in from_cert(sys.argv[2]).items:
        sans.add(kind, value)
    print(sans.render())
else:
    sys.exit(f"tls_san_tool: unknown command {cmd!r}")
PY
}

tls_cert_self_signed() {
    local subject issuer
    subject=$(openssl x509 -in "$1" -noout -subject 2>/dev/null) || return 1
    issuer=$(openssl x509 -in "$1" -noout -issuer 2>/dev/null) || return 1
    [ -n "${subject#*=}" ] && [ "${subject#*=}" = "${issuer#*=}" ]
}

tls_ensure_cert() {
    local cert="$1" key="$2" cn="$3" extra="${4:-}" sans text missing expiring kept
    TLS_CERT_CHANGED=0
    sans=$(tls_san_tool required "$extra" "$(tls_host_names)" "$(tls_host_addrs)") || return 1
    if [ ! -s "$cert" ] || [ ! -s "$key" ]; then
        echo "==> Generating self-signed TLS cert ${cert}"
    elif ! text=$(openssl x509 -in "$cert" -noout -text 2>/dev/null); then
        echo "==> ${cert} is not a readable certificate — regenerating it"
    else
        missing=$(tls_san_tool missing "$text" "$sans") || return 1
        expiring=0
        openssl x509 -in "$cert" -noout -checkend $((TLS_RENEW_DAYS * 86400)) >/dev/null 2>&1 \
            || expiring=1
        [ -n "$missing" ] || [ "$expiring" -eq 1 ] || return 0
        if ! tls_cert_self_signed "$cert"; then
            [ -z "$missing" ] || echo "WARNING: ${cert} is not self-signed (operator-supplied?), so it is kept, but its subjectAltName lacks ${missing}; clients that use those names will fail TLS verification." >&2
            [ "$expiring" -eq 0 ] || echo "WARNING: ${cert} is not self-signed (operator-supplied?), so it is kept, but it expires within ${TLS_RENEW_DAYS} days (or has expired): renew it with whoever issued it — edge agents refuse an expired certificate." >&2
            return 0
        fi
        if [ "$TLS_RENEW_ONLY" -eq 1 ] && [ -n "$missing" ]; then
            echo "WARNING: ${cert} lacks subjectAltName ${missing}; clients that use those names fail TLS verification. Renewal never adds names (a new certificate breaks every edge node that pinned this one), so it is not regenerated for them: re-run the installer or a deploy (with SIGRIFT_TLS_SANS for extra names) to add them, then copy the new cert.pem to those edge nodes." >&2
            [ "$expiring" -eq 1 ] || return 0
            # Renew with exactly the names it has.
            kept=$(tls_san_tool merge "$text" "") || return 1
            [ -z "$kept" ] || sans=$kept
            missing=""
        else
            sans=$(tls_san_tool merge "$text" "$sans") || return 1
        fi
        if [ -n "$missing" ]; then
            echo "==> ${cert} lacks subjectAltName ${missing} — regenerating it (keeping its other names)."
        else
            echo "==> ${cert} expires within ${TLS_RENEW_DAYS} days (or has expired) — renewing it (same names)."
        fi
        echo "    Edge nodes that were given the old certificate (--ca-cert / MLRF_CA_CERT) need the new one."
    fi
    echo "    subjectAltName: ${sans}"
    rm -f "${key}.new" "${cert}.new"
    if ! ( umask 077 && openssl req -x509 -newkey rsa:2048 -nodes -days "$TLS_CERT_DAYS" \
            -subj "/CN=${cn}" -addext "subjectAltName=${sans}" \
            -keyout "${key}.new" -out "${cert}.new" 2>/dev/null ); then
        rm -f "${key}.new" "${cert}.new"
        echo "ERROR: openssl could not create the TLS certificate" >&2
        return 1
    fi
    # Recorded before the swap: whatever fails from here on, the next run
    # still recreates the containers.
    : > "$(tls_recreate_marker "$cert")"
    mv -f "${key}.new" "$key"
    mv -f "${cert}.new" "$cert"
    TLS_CERT_CHANGED=1
}
# <<< shared: tls-cert

# >>> shared: tls-key-perms (keep byte-identical in scripts/quickstart.sh and
#     scripts/install-release.sh; scripts/tests/test_install_scripts.py checks)
#
# The gateway container runs as uid/gid 1500 and must read the TLS private
# key; nobody else on this host should. tls_key_perms KEY gives the key
# group 1500 and mode 0640, trying in turn: chown as root; chgrp (works
# when this user is in group 1500); a throwaway container that does the
# chown as root (docker is needed for the stack anyway). It returns 1,
# leaving the key as it was, when none of them works.
HELPER_IMAGE="alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f"

file_gid_mode() {
    stat -c '%g %a' -- "$1" 2>/dev/null || stat -f '%g %Lp' -- "$1" 2>/dev/null
}

tls_key_perms() {
    local key="$1" dir base
    if [ ! -f "$key" ] || [ -L "$key" ]; then
        return 1
    fi
    [ "$(file_gid_mode "$key")" = "1500 640" ] && return 0
    if [ "$(id -u)" -eq 0 ]; then
        chown -- 0:1500 "$key" && chmod -- 0640 "$key" && return 0
    elif chgrp -- 1500 "$key" 2>/dev/null; then
        chmod -- 0640 "$key" && return 0
    fi
    command -v docker >/dev/null 2>&1 || return 1
    dir=$(cd "$(dirname -- "$key")" && pwd -P) || return 1
    base=$(basename -- "$key")
    docker run --rm --network none -v "${dir}:/tls" "$HELPER_IMAGE" \
        sh -c 'chown 0:1500 "/tls/$1" && chmod 0640 "/tls/$1"' sh "$base" \
        >/dev/null 2>&1 || return 1
    [ "$(file_gid_mode "$key")" = "1500 640" ]
}

# secure_tls_files CERT KEY — cert world-readable, key as above. If the
# key cannot be restricted it falls back to 0644 (the gateway must be able
# to read it) and says so.
secure_tls_files() {
    chmod -- 0644 "$1"
    if ! tls_key_perms "$2"; then
        chmod -- 0644 "$2"
        echo "WARNING: could not give $2 group 1500 (the gateway container's) and mode 0640, so it is world-readable (0644). Fix it with: sudo chown root:1500 $2 && sudo chmod 0640 $2" >&2
    fi
}
# <<< shared: tls-key-perms

# >>> shared: exposure (keep byte-identical in scripts/quickstart.sh and
#     scripts/install-release.sh; scripts/tests/test_install_scripts.py checks)
#
# SIGRIFT_BIND is the host address docker publishes the gateway on:
# 127.0.0.1 — the default, this machine only — or 0.0.0.0 — every IPv4
# interface: other browsers on the network, remote edge nodes — or one
# address of this host (an IPv6 one in brackets). Not [::]: docker
# publishes an IPv6 host address on IPv6 only, so IPv4 clients and the
# host-network scanners (https://127.0.0.1) could not connect. The
# compose file reads it from .env.
bind_setting_valid() {
    python3 -c '
import ipaddress, sys
v = sys.argv[1]
bracketed = v[:1] == "[" and v[-1:] == "]"
try:
    ip = ipaddress.ip_address(v[1:-1] if bracketed else v)
except ValueError:
    sys.exit(1)
if (ip.version == 6) != bracketed:
    sys.exit(1)
if ip.version == 6 and ip.is_unspecified:
    print(
        "SIGRIFT_BIND=" + v + " would publish the gateway on IPv6 only: IPv4"
        " clients and the host-network scanners (https://127.0.0.1) could"
        " not connect. Use 0.0.0.0; to serve IPv6 too, add a second ports"
        " entry (INSTALL.md, \"Who can reach the dashboard\").",
        file=sys.stderr,
    )
    sys.exit(1)
' "$1"
}

# persist_bind_setting ENV_FILE — when SIGRIFT_BIND is set in this shell,
# check it and record it in ENV_FILE so later `docker compose` runs keep
# it. An ENV_FILE that already sets a different value is left alone (with
# a note: docker compose prefers the shell's value while it is set).
persist_bind_setting() {
    local env_file="$1" current
    [ -n "${SIGRIFT_BIND:-}" ] || return 0
    if ! bind_setting_valid "$SIGRIFT_BIND"; then
        echo "Error: SIGRIFT_BIND must be an IPv4 address (127.0.0.1, 0.0.0.0, ...) or one IPv6 address in brackets ([fd00::5], ...), not '${SIGRIFT_BIND:0:60}'" >&2
        return 1
    fi
    if ! grep -qE '^[[:space:]]*(export[[:space:]]+)?SIGRIFT_BIND[[:space:]]*=' "$env_file"; then
        printf 'SIGRIFT_BIND=%s\n' "$SIGRIFT_BIND" >> "$env_file"
        echo "==> Recorded SIGRIFT_BIND=${SIGRIFT_BIND} in ${env_file}"
        return 0
    fi
    current=$(sed -n 's/^[[:space:]]*\(export[[:space:]]\{1,\}\)\{0,1\}SIGRIFT_BIND[[:space:]]*=[[:space:]]*//p' "$env_file" | tail -1)
    current=${current%\"}; current=${current#\"}; current=${current%\'}; current=${current#\'}
    if [ "$current" != "$SIGRIFT_BIND" ]; then
        echo "NOTE: ${env_file} sets SIGRIFT_BIND=${current}; this run uses SIGRIFT_BIND=${SIGRIFT_BIND} from your shell. Edit ${env_file} to make that permanent." >&2
    fi
}

# describe_stack — tells the operator where docker actually publishes the
# gateway and which mode the bridge runs in, from `docker compose port` and
# `docker compose config` (what is running, not what we meant to set).
describe_stack() {
    local published mode
    published=$(docker compose port gateway 8444 2>/dev/null | tr '\n' ' ' | sed 's/ *$//') || published=""
    mode=$(docker compose config --format json 2>/dev/null | python3 -c '
import json, sys
try:
    env = json.load(sys.stdin)["services"]["bridge"].get("environment") or {}
except (ValueError, KeyError):
    sys.exit(0)
print(str(env.get("BRIDGE_ENV", "")).strip().lower())
' 2>/dev/null) || mode=""
    case "$published" in
        "")
            echo "Could not ask docker where the gateway is published (docker compose port gateway 8444)." ;;
        127.0.0.1:*)
            echo "The gateway is published on ${published} only: this machine. To reach it"
            echo "from other machines (browsers on your network, remote edge nodes), set"
            echo "SIGRIFT_BIND=0.0.0.0 in .env and run \`docker compose up -d\`." ;;
        *.*)
            echo "The gateway is published on ${published}: other machines on your network"
            echo "can reach it. To keep it to this machine, set SIGRIFT_BIND=127.0.0.1 in .env"
            echo "and run \`docker compose up -d\` (a docker-compose.yml from an older"
            echo "installer has no SIGRIFT_BIND: change the gateway's \`ports:\` entry to"
            echo "\"127.0.0.1:<port>:8444\" instead)." ;;
        *)
            # No IPv4 address at all: docker publishes an IPv6 host address
            # (even [::]) on IPv6 only.
            echo "WARNING: the gateway is published on ${published}: IPv6 only. IPv4 clients"
            echo "and the host-network scanners (wifi-scan, bt-scan: https://127.0.0.1) cannot"
            echo "reach it. Set SIGRIFT_BIND=0.0.0.0 (or 127.0.0.1) in .env and run"
            echo "\`docker compose up -d\`; INSTALL.md (\"Who can reach the dashboard\") shows"
            echo "how to serve IPv6 as well." ;;
    esac
    case "$mode" in
        production|prod)
            echo "The stack runs in production mode (BRIDGE_ENV=${mode})." ;;
        "")
            echo "Could not read the bridge's BRIDGE_ENV from docker compose config." ;;
        *)
            echo "The stack runs in DEVELOPMENT mode (BRIDGE_ENV=${mode}): CSRF protection"
            echo "is off, session cookies are not marked Secure and missing or invalid"
            echo "secrets only log warnings. Fine for a lab box on loopback; for anything"
            echo "else set BRIDGE_ENV=production in .env and run \`docker compose up -d\`." ;;
    esac
}
# <<< shared: exposure

# >>> shared: volumes (keep byte-identical in scripts/quickstart.sh and
#     scripts/install-release.sh; scripts/tests/test_install_scripts.py checks)
#
# fix_volume_ownership — the bridge and gateway run as uid/gid 1500. On a
# fresh install compose creates their volumes with that owner (copied from
# the images); a volume from older images may carry another uid.
# bridge_secrets (the CA private key) is also kept 0700. Only this
# project's volumes are touched — compose labels the volumes it creates.
# Idempotent; a failure is ignored (the containers then report it).
fix_volume_ownership() {
    local project vol name fix
    project=$(docker compose config --format json 2>/dev/null \
        | python3 -c 'import json, sys; print(json.load(sys.stdin).get("name", ""))' 2>/dev/null) \
        || project=""
    for vol in bridge_data bridge_secrets; do
        if [ -n "$project" ]; then
            name=$(docker volume ls -q \
                --filter "label=com.docker.compose.project=${project}" \
                --filter "label=com.docker.compose.volume=${vol}" | head -1)
        else
            name=$(docker volume ls --format '{{.Name}}' | grep -E "_${vol}\$" | head -1) || name=""
        fi
        [ -n "$name" ] || continue
        fix="chown -R 1500:1500 /data"
        if [ "$vol" = bridge_secrets ]; then
            fix="$fix && chmod 0700 /data"
        fi
        docker run --rm --network none -v "${name}:/data" "$HELPER_IMAGE" \
            sh -c "$fix" >/dev/null 2>&1 || true
    done
}
# <<< shared: volumes

# >>> shared: backend-subnet (keep byte-identical in scripts/quickstart.sh,
#     scripts/install-release.sh and scripts/bootstrap-staging.sh;
#     scripts/tests/test_install_scripts.py checks)
#
# The gateway <-> bridge `backend` network has an explicit subnet, so the
# gateway gets the fixed address the bridge trusts (BRIDGE_TRUSTED_PROXIES).
# Docker refuses to create a network whose explicit subnet overlaps an
# existing one ("Pool overlaps with other one on this address space") —
# another SigRift stack on this host, for one — and a subnet that
# overlaps a network the host routes to cuts the host off from part of it.
#
# ensure_backend_subnet ENV_FILE [COMPOSE_ARGS...] takes the subnet that
# `docker compose COMPOSE_ARGS config` gives the backend network and
# compares it with every other docker network and the host's IPv4 routes
# (leaving out this project's own backend network, so a re-run keeps the
# subnet it has, and routes shorter than /8 — VPN catch-alls). On an
# overlap it picks the first free /28 from 10.203.84.0 on (10.203.0.0/16,
# then 172.16.0.0/16) and appends SIGRIFT_BACKEND_SUBNET,
# SIGRIFT_BACKEND_IP_RANGE (its upper half) and SIGRIFT_GATEWAY_BACKEND_IP
# (its .2, outside the range) to ENV_FILE, all three together. If the
# operator set any of them (in ENV_FILE or the shell), or the compose
# file does not take them, it only warns. Best effort: without docker, or
# without a backend network in the compose file, it does nothing.
BACKEND_SUBNET_VARS="SIGRIFT_BACKEND_SUBNET SIGRIFT_BACKEND_IP_RANGE SIGRIFT_GATEWAY_BACKEND_IP"

# backend_subnet_tool check NETWORKS ROUTES | uses SUBNET GW_IP, with the
# `docker compose config --format json` output on stdin (handed to python3
# as fd 3: its own stdin is the script).
backend_subnet_tool() {
    python3 - "$@" 3<&0 <<'PY'
import ipaddress
import json
import os
import sys

ROUTE_TYPES = {"unicast", "local", "broadcast", "blackhole", "unreachable",
               "prohibit", "throw", "nat", "anycast", "multicast"}


def net(text):
    try:
        return ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        return None


def backend(cfg):
    """(network name, subnets, gateway address, trusted proxy entries)."""
    netcfg = (cfg.get("networks") or {}).get("backend") or {}
    pools = (netcfg.get("ipam") or {}).get("config") or []
    subnets = [n for n in (net(str(p.get("subnet", ""))) for p in pools) if n]
    services = cfg.get("services") or {}
    gw_nets = (services.get("gateway") or {}).get("networks") or {}
    gw_ip = str((gw_nets.get("backend") or {}).get("ipv4_address") or "")
    env = (services.get("bridge") or {}).get("environment") or {}
    if isinstance(env, list):
        env = dict(e.split("=", 1) for e in env if "=" in e)
    trusted = str(env.get("BRIDGE_TRUSTED_PROXIES") or "").split(",")
    return netcfg.get("name") or "", subnets, gw_ip, trusted


def free_block(used):
    """[subnet, ip_range, gateway] of the first free /28, or three "-"."""
    for pool, start in (("10.203.0.0/16", "10.203.84.0/28"), ("172.16.0.0/16", None)):
        blocks = list(ipaddress.ip_network(pool).subnets(new_prefix=28))
        if start:
            i = blocks.index(ipaddress.ip_network(start))
            blocks = blocks[i:] + blocks[:i]
        for b in blocks:
            if not any(n.overlaps(b) for n, _ in used):
                return [str(b), str(list(b.subnets(new_prefix=29))[1]),
                        str(b.network_address + 2)]
    return ["-", "-", "-"]


cmd = sys.argv[1]
with os.fdopen(3) as config:
    name, subnets, gw_ip, trusted = backend(json.load(config))
if cmd == "check":
    # Prints "ok", or "clash SUBNET OTHER NEW_SUBNET NEW_RANGE NEW_GW WHAT".
    used, own_devs = [], set()
    for line in sys.argv[2].splitlines():  # docker networks: NAME ID SUBNET...
        parts = line.split()
        if len(parts) < 2:
            continue
        if parts[0] == name:
            own_devs.add("br-" + parts[1][:12])
            continue
        for n in (net(s) for s in parts[2:]):
            if n is not None and n.version == 4:
                used.append((n, "docker network " + parts[0]))
    for line in sys.argv[3].splitlines():  # ip -4 route show table all
        tok = line.split()
        if tok and tok[0] in ROUTE_TYPES:
            tok = tok[1:]
        if not tok or tok[0] == "default":
            continue
        dev = tok[tok.index("dev") + 1] if "dev" in tok[:-1] else ""
        n = net(tok[0])
        if (dev in own_devs or n is None or n.version != 4 or n.prefixlen < 8
                or n.is_loopback):
            continue
        used.append((n, "host route" + (" on " + dev if dev else "")))
    for sub in subnets:
        hits = [(n, what) for n, what in used if n.overlaps(sub)]
        if hits:
            print("clash", sub, hits[0][0], *free_block(used), hits[0][1])
            break
    else:
        print("ok")
elif cmd == "uses":
    # Exit 0 if the backend network is on SUBNET only, the gateway at GW_IP,
    # and BRIDGE_TRUSTED_PROXIES covers GW_IP.
    want, want_gw = net(sys.argv[2]), ipaddress.ip_address(sys.argv[3])
    covered = [n for n in (net(t) for t in trusted) if n is not None]
    sys.exit(0 if subnets == [want] and gw_ip == str(want_gw)
             and any(want_gw in n for n in covered) else 1)
else:
    sys.exit(f"backend_subnet_tool: unknown command {cmd!r}")
PY
}

ensure_backend_subnet() {
    local env_file="$1" cfg id ids=() networks="" routes="" plan verdict subnet
    local other new_subnet new_range new_gw what var explicit="" free=""
    shift
    command -v docker >/dev/null 2>&1 || return 0
    cfg=$(docker compose "$@" config --format json 2>/dev/null) || return 0
    while IFS= read -r id; do
        [ -z "$id" ] || ids+=("$id")
    done < <(docker network ls -q 2>/dev/null)
    if [ "${#ids[@]}" -gt 0 ]; then
        networks=$(docker network inspect \
            --format '{{.Name}} {{.Id}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' \
            "${ids[@]}" 2>/dev/null) || networks=""
    fi
    if command -v ip >/dev/null 2>&1; then
        routes=$(ip -4 route show table all 2>/dev/null) || routes=""
    fi
    plan=$(printf '%s' "$cfg" | backend_subnet_tool check "$networks" "$routes") || return 0
    read -r verdict subnet other new_subnet new_range new_gw what <<<"$plan"
    [ "$verdict" = clash ] || return 0
    [ "$new_subnet" = "-" ] \
        || free=" (${new_subnet} with range ${new_range} and gateway ${new_gw} is free)"
    for var in $BACKEND_SUBNET_VARS; do
        # Exported (what docker compose sees) or in ENV_FILE.
        if printenv "$var" >/dev/null 2>&1 \
            || grep -qE "^[[:space:]]*(export[[:space:]]+)?${var}[[:space:]]*=" "$env_file" 2>/dev/null; then
            explicit="${explicit} ${var}"
        fi
    done
    if [ -n "$explicit" ]; then
        echo "WARNING: the backend network's subnet ${subnet} — from your setting of${explicit} — overlaps ${what} (${other}), so docker cannot create it (\"Pool overlaps with other one on this address space\"). Change SIGRIFT_BACKEND_SUBNET, SIGRIFT_BACKEND_IP_RANGE (inside it) and SIGRIFT_GATEWAY_BACKEND_IP (inside the subnet, outside the range) together${free}." >&2
        return 0
    fi
    if [ "$new_subnet" = "-" ]; then
        echo "WARNING: the backend network's subnet ${subnet} overlaps ${what} (${other}), and no free /28 was found in 10.203.0.0/16 or 172.16.0.0/16. Set SIGRIFT_BACKEND_SUBNET, SIGRIFT_BACKEND_IP_RANGE and SIGRIFT_GATEWAY_BACKEND_IP in ${env_file} to a free subnet." >&2
        return 0
    fi
    if ! SIGRIFT_BACKEND_SUBNET="$new_subnet" SIGRIFT_BACKEND_IP_RANGE="$new_range" \
        SIGRIFT_GATEWAY_BACKEND_IP="$new_gw" docker compose "$@" config --format json 2>/dev/null \
        | backend_subnet_tool uses "$new_subnet" "$new_gw"; then
        echo "WARNING: the backend network's subnet ${subnet} overlaps ${what} (${other}), so docker cannot create it, and this compose file does not take SIGRIFT_BACKEND_SUBNET, SIGRIFT_BACKEND_IP_RANGE and SIGRIFT_GATEWAY_BACKEND_IP (or its BRIDGE_TRUSTED_PROXIES would not cover the gateway's new address). Change the backend network's subnet and ip_range and the gateway's ipv4_address there${free}." >&2
        return 0
    fi
    {
        [ ! -s "$env_file" ] || [ -z "$(tail -c 1 "$env_file")" ] || echo
        echo "# The default backend subnet ${subnet} overlaps ${what} (${other})"
        echo "# on this host, so the installer picked a free one. Change all three together."
        echo "SIGRIFT_BACKEND_SUBNET=${new_subnet}"
        echo "SIGRIFT_BACKEND_IP_RANGE=${new_range}"
        echo "SIGRIFT_GATEWAY_BACKEND_IP=${new_gw}"
    } >> "$env_file"
    echo "==> The backend network's default subnet ${subnet} overlaps ${what} (${other}): using ${new_subnet} (gateway ${new_gw}) instead, recorded in ${env_file}."
}
# <<< shared: backend-subnet

# Existing .env files from older installers may lack BRIDGE_AUDIT_KEY.
# It is not added automatically: that would change the audit-chain HMAC
# key under existing entries.
warn_missing_audit_key() {
    if ! grep -qE '^[[:space:]]*(export[[:space:]]+)?BRIDGE_AUDIT_KEY[[:space:]]*[=:][[:space:]]*[^[:space:]#]' "$1"; then
        cat >&2 <<EOF
WARNING: $1 has no BRIDGE_AUDIT_KEY. In production the bridge and gateway
         refuse to start without one, and without it they do not share the
         audit-chain HMAC key. Add one (entries already in the audit chain
         were signed under the old key and will not verify):
             echo "BRIDGE_AUDIT_KEY=\$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" >> $1
EOF
    fi
}

# An existing docker-compose.yml is never overwritten, so check the
# gateway's environment in it and say loudly what to change. Files from
# older versions of this script passed the shared keys to the bridge
# only; some passed BRIDGE_MASTER_KEY to the gateway, which needs none.
check_compose_gateway_env() {
    local gateway_block bridge_block missing="" k unbound_entry
    local grace_missing="" svc block
    gateway_block=$(awk '/^  gateway:/ { g = 1; next } /^[^ #]/ || /^  [^ #]/ { g = 0 } g' "$1")
    for k in BRIDGE_AUDIT_KEY BRIDGE_MFA_KEY; do
        grep -q "${k}=" <<<"$gateway_block" \
            || missing="${missing}             - ${k}=\${${k}:-}"$'\n'
    done
    if [ -n "$missing" ]; then
        missing=${missing%$'\n'}
        cat >&2 <<EOF
WARNING: the gateway service in $1 does not get the keys it shares with
         the bridge. Without them it cannot decrypt TOTP secrets or extend
         the audit chain, and in production it refuses to start. Add to
         the gateway's \`environment:\` list (same values as the bridge's),
         or move the file aside and re-run this script to regenerate it:
${missing}
EOF
    fi
    if grep -q 'BRIDGE_MASTER_KEY=' <<<"$gateway_block"; then
        cat >&2 <<EOF
WARNING: $1 passes BRIDGE_MASTER_KEY (the admin API key) to the gateway
         service, which does not need it. Remove that line from the
         gateway's \`environment:\` list (keep it for the bridge) so the
         internet-facing container does not hold it.
EOF
    fi
    # Files from before the bridge-secrets volume / proxy-only bridge.
    bridge_block=$(awk '/^  bridge:/ { g = 1; next } /^[^ #]/ || /^  [^ #]/ { g = 0 } g' "$1")
    if ! grep -q 'bridge_secrets:/app/secrets' <<<"$bridge_block"; then
        cat >&2 <<EOF
WARNING: the bridge service in $1 has no \`bridge_secrets\` volume, so the
         bridge CA's private key stays in bridge_data — which the
         internet-facing gateway mounts too. Move the file aside and re-run
         this script to regenerate it (the bridge then moves the key into
         the new volume on start-up), or add to the bridge's \`volumes:\`
             - bridge_secrets:/app/secrets
         and \`bridge_secrets:\` under the top-level \`volumes:\`.
EOF
    fi
    # The environment entry itself (list or mapping form), not a mention
    # of it elsewhere in the block (the healthcheck's message names it).
    if ! grep -qE '^[[:space:]]*(-[[:space:]]*)?"?BRIDGE_REQUIRE_PROXY[=:][[:space:]]*"?true' \
            <<<"$bridge_block"; then
        cat >&2 <<EOF
WARNING: the bridge service in $1 does not set BRIDGE_REQUIRE_PROXY=true,
         so the bridge also answers requests that did not come through the
         gateway. Add to the bridge's \`environment:\` list
             - BRIDGE_REQUIRE_PROXY=true
         (or move the file aside and re-run this script to regenerate it).
EOF
    fi
    # BRIDGE_ALLOW_UNBOUND_NODE_KEYS only means something when both
    # services get it; files from before it existed pass it to neither.
    unbound_entry='^[[:space:]]*(-[[:space:]]*)?"?BRIDGE_ALLOW_UNBOUND_NODE_KEYS[=:]'
    if { [ -n "${BRIDGE_ALLOW_UNBOUND_NODE_KEYS:-}" ] \
            || grep -qE '^[[:space:]]*(export[[:space:]]+)?BRIDGE_ALLOW_UNBOUND_NODE_KEYS[[:space:]]*=[[:space:]]*[^[:space:]#]' .env 2>/dev/null; } \
        && ! { grep -qE "$unbound_entry" <<<"$bridge_block" \
            && grep -qE "$unbound_entry" <<<"$gateway_block"; }; then
        cat >&2 <<EOF
WARNING: BRIDGE_ALLOW_UNBOUND_NODE_KEYS is set, but $1 does not pass it to
         both the bridge and the gateway, so node API keys are still bound
         to the first node they report for. Add to the \`environment:\` list
         of both services
             - BRIDGE_ALLOW_UNBOUND_NODE_KEYS=\${BRIDGE_ALLOW_UNBOUND_NODE_KEYS:-}
EOF
    fi
    # Files from before stop_grace_period: Docker then kills the bridge
    # 10 s after SIGTERM, before its last save, and the gateway may not
    # finish spooling its queued post-ingest hooks.
    for svc in bridge gateway; do
        if [ "$svc" = bridge ]; then block=$bridge_block; else block=$gateway_block; fi
        grep -qE '^[[:space:]]*"?stop_grace_period"?[[:space:]]*:' <<<"$block" \
            || grace_missing="${grace_missing} ${svc}"
    done
    if [ -n "$grace_missing" ]; then
        cat >&2 <<EOF
NOTE: $1 sets no stop_grace_period for:${grace_missing}. Docker kills a
      container 10 s after SIGTERM, which can cut off the bridge's last
      state save at shutdown (after its bounded waits for jobs and the
      write queue) and the gateway's spooling of queued post-ingest
      hooks. Add to each of those services (next to \`restart:\`)
          stop_grace_period: 30s
      (or move the file aside and re-run this script to regenerate it).
EOF
    fi
}

# ── TLS cert + permissions (also the whole of --renew-tls) ───────────
# subjectAltName: localhost, this host's names and addresses (edge nodes
# on other hosts dial https://<this host>:PORT and verify the cert with
# --ca-cert tls/cert.pem) and SIGRIFT_TLS_SANS (extra names/IPs,
# comma-separated). An existing self-signed cert is regenerated only when
# it lacks one of those or expires within 30 days; an operator-supplied
# one is never replaced.
setup_tls() {
    mkdir -p tls
    # The gateway container's uid 1500 must traverse the bind-mounted dir
    # (the `umask 077` below would otherwise leave it 0700).
    chmod 0755 tls
    tls_ensure_cert tls/cert.pem tls/key.pem localhost "${SIGRIFT_TLS_SANS:-}"
    # Cert 0644; key group 1500 (the gateway container's) and 0640.
    secure_tls_files tls/cert.pem tls/key.pem
}

if [ "$RENEW_TLS_ONLY" -eq 1 ]; then
    if [ ! -f docker-compose.yml ] || [ ! -f .env ]; then
        echo "Error: --renew-tls needs an installed stack (docker-compose.yml and .env in $(pwd))." >&2
        exit 1
    fi
    # Unattended: renew an expiring cert with the names it has; never
    # regenerate it for a new name (that is a re-run's job — see
    # tls_ensure_cert).
    TLS_RENEW_ONLY=1
    setup_tls
    if tls_recreate_pending tls/cert.pem; then
        if [ "$TLS_CERT_CHANGED" -eq 1 ]; then
            echo "==> Recreating the gateway so it serves the new certificate"
        else
            echo "==> An earlier run renewed the certificate but did not finish recreating the gateway — recreating it now"
        fi
        # --pull never: the image is already here, and a registry or
        # network outage must not keep the gateway on the old certificate
        # (the generated compose file says pull_policy: always). The
        # marker goes only once the recreate worked; until then every run
        # retries.
        if ! docker compose up -d --pull never --force-recreate gateway; then
            echo "Error: could not recreate the gateway; it may still serve the old certificate. The next run (--renew-tls or a full one) tries again." >&2
            exit 1
        fi
        tls_recreate_done tls/cert.pem
        echo "    Copy $(pwd)/tls/cert.pem to every edge node on another host that"
        echo "    was given the old one (--ca-cert / MLRF_CA_CERT)."
    else
        echo "==> TLS certificate is current — nothing to do"
    fi
    exit 0
fi

# Update literal image tags and the known legacy HTTP health probe in an
# installer-managed Compose file.
# Custom settings and comments are preserved; unfamiliar image sources,
# YAML layouts or overrides are refused instead of being overwritten.
update_release_images() {
    python3 - "$1" "$OWNER" "$VERSION" <<'PY'
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

path = Path(sys.argv[1]).resolve()
owner, version = sys.argv[2:]
if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-rc\d+)?|main(?:-[a-f0-9]{7,40})?", version):
    sys.exit("Error: invalid release tag; Compose was not changed.")
if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?", owner):
    sys.exit("Error: invalid image owner; Compose was not changed.")
expected = {name: f"ghcr.io/{owner}/sigrift-{name}:{version}" for name in ("bridge", "gateway")}
text = path.read_text()
if not text.startswith("# Generated by install-release.sh @ "):
    sys.exit("Error: Compose is not installer-managed. Update its bridge/gateway image tags manually; no files changed.")
if os.environ.get("COMPOSE_FILE"):
    sys.exit("Error: COMPOSE_FILE overrides the installer stack. Update its image tags manually; no files changed.")
if any((path.parent / name).exists() for name in ("compose.yml", "compose.yaml", "docker-compose.yaml")):
    sys.exit("Error: another default Compose file takes precedence over docker-compose.yml; resolve that before upgrading. No files changed.")
# COMPOSE_FILE can also come from .env. Ask Compose rather than parsing
# dotenv ourselves; keep the output private because it includes secrets.
effective = subprocess.run(
    ["docker", "compose", "config", "--environment"], cwd=path.parent,
    capture_output=True, text=True,
)
if effective.returncode:
    sys.exit("Error: cannot resolve the current Compose configuration; no files changed. Check docker compose config --quiet.")
if any(line.partition("=")[0] == "COMPOSE_FILE" and line.partition("=")[2]
       for line in effective.stdout.splitlines()):
    sys.exit("Error: .env sets COMPOSE_FILE and overrides the installer stack. Update its image tags manually; no files changed.")

updated = text
for name, image in expected.items():
    section = re.search(rf"(?ms)^  {name}:[ \t]*(?:#[^\n]*)?\n.*?(?=^  \S|^\S|\Z)", updated)
    if not section:
        sys.exit(f"Error: cannot safely locate the {name} service; update its image tag manually.")
    start, end = section.span()
    body = updated[start:end]
    matches = list(re.finditer(r"(?m)^(    image:[ \t]*)([^\s#]+)([ \t]*(?:#.*)?)$", body))
    if len(matches) != 1:
        sys.exit(f"Error: {name} needs one literal image entry; update its image tag manually.")
    match = matches[0]
    current = match.group(2)
    if not re.fullmatch(rf"ghcr\.io/{re.escape(owner)}/sigrift-{name}:[A-Za-z0-9_][A-Za-z0-9_.-]*", current):
        sys.exit(f"Error: {name} uses a customized image; update it manually. No files changed.")
    body = body[:match.start(2)] + image + body[match.end(2):]
    if name == "gateway":
        body = body.replace(
            '      test: ["CMD", "sh", "-c", "wget -q --spider http://localhost:8444/health || exit 1"]',
            '      test: ["CMD", "/app/healthcheck.sh"]',
        )
    updated = updated[:start] + body + updated[end:]

fd, candidate = tempfile.mkstemp(prefix=".sigrift-compose-", suffix=".yml", dir=path.parent)
try:
    with os.fdopen(fd, "w") as f:
        f.write(updated)
    command = ["docker", "compose", "--project-directory", str(path.parent), "-f", candidate]
    # Explicit -f suppresses Compose's automatic override discovery.
    for filename in ("docker-compose.override.yml", "docker-compose.override.yaml"):
        override = path.parent / filename
        if override.exists():
            command += ["-f", str(override)]
            break
    result = subprocess.run(command + ["config", "--format", "json"], capture_output=True, text=True)
    if result.returncode:
        sys.exit("Error: proposed upgrade does not validate with Compose; no files changed. Check docker compose config --quiet.")
    services = json.loads(result.stdout)["services"]
    if any(services.get(name, {}).get("image") != image for name, image in expected.items()):
        sys.exit("Error: a Compose override changes a requested release image; update it manually. No files changed.")
    if updated != text:
        backup_fd, backup = tempfile.mkstemp(prefix=path.name + ".bak.", suffix="~", dir=path.parent)
        with os.fdopen(backup_fd, "w") as f:
            f.write(text)
        os.chmod(candidate, stat.S_IMODE(path.stat().st_mode))
        os.replace(candidate, path)
        print(f"==> Updated bridge + gateway images to {version}; previous Compose: {backup}")
finally:
    if os.path.exists(candidate):
        os.unlink(candidate)
PY
}

# ── docker-compose.yml (write if absent) ─────────────────────────────
# Existing files retain customizations; explicit version requests update
# the managed images and legacy health probe after validating the result.
if [ ! -f docker-compose.yml ]; then
    cat > docker-compose.yml <<EOF
# Generated by install-release.sh @ ${VERSION}.
# Pinned to the immutable release image tags. Do not edit these tags
# in place — re-run install-release.sh with a different VERSION.
services:
  bridge:
    image: ghcr.io/${OWNER}/sigrift-bridge:${VERSION}
    pull_policy: always
    expose:
      - "8001"
    # Reachable only from the gateway (the only other container on
    # backend).
    networks:
      - backend
    volumes:
      - bridge_data:/app/src/sigrift/bridge/data
      # Bridge-only secrets (the CA private key): never mounted on the
      # gateway, which mounts bridge_data.
      - bridge_secrets:/app/secrets
    environment:
      - BRIDGE_ENV=\${BRIDGE_ENV:-production}
      - BRIDGE_AUDIT_KEY=\${BRIDGE_AUDIT_KEY:-}
      - BRIDGE_MFA_KEY=\${BRIDGE_MFA_KEY:-}
      - BRIDGE_MASTER_KEY=\${BRIDGE_MASTER_KEY:-}
      - BRIDGE_ADMIN_PASSWORD=\${BRIDGE_ADMIN_PASSWORD:-}
      - BRIDGE_SESSION_BINDING=\${BRIDGE_SESSION_BINDING:-none}
      - BRIDGE_SECRETS_DIR=/app/secrets
      # Only requests carrying the gateway's X-Rust-Proxy secret are served.
      - BRIDGE_REQUIRE_PROXY=true
      # Trust X-Forwarded-For from the gateway's fixed backend address only.
      - BRIDGE_TRUSTED_PROXIES=\${BRIDGE_TRUSTED_PROXIES:-\${SIGRIFT_GATEWAY_BACKEND_IP:-10.203.84.2}}
      # Required: without it the bridge refuses everything the gateway
      # proxies, and the healthcheck below keeps it unhealthy.
      - UC_PROXY_SECRET=\${UC_PROXY_SECRET:-}
      # "1" lets node API keys without a node_id act for any node instead
      # of being bound to the first node they report for. Set it for the
      # gateway too (its detection ingest binds them as well).
      - BRIDGE_ALLOW_UNBOUND_NODE_KEYS=\${BRIDGE_ALLOW_UNBOUND_NODE_KEYS:-}
    restart: unless-stopped
    # Docker's default 10 s before SIGKILL is shorter than the bridge's
    # bounded shutdown waits (jobs, write queue, threads; then a last save).
    stop_grace_period: 30s
    healthcheck:
      test: ["CMD", "python3", "-c", "import os, sys, urllib.request; sys.exit('UC_PROXY_SECRET is empty: the bridge refuses every proxied request (BRIDGE_REQUIRE_PROXY=true). Set it in .env, see .env.example') if os.environ.get('UC_PROXY_SECRET', '') in ('', 'uppercrust-internal') else urllib.request.urlopen('http://localhost:8001/api/healthz')"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 15s

  gateway:
    image: ghcr.io/${OWNER}/sigrift-gateway:${VERSION}
    pull_policy: always
    # 127.0.0.1 = this machine only (the default); SIGRIFT_BIND=0.0.0.0 in
    # .env publishes it on every interface (the LAN, remote edge nodes).
    ports:
      - "\${SIGRIFT_BIND:-127.0.0.1}:${PORT}:8444"
    networks:
      default: {}
      backend:
        # Outside backend's ip_range, so docker never gives it to the bridge.
        ipv4_address: \${SIGRIFT_GATEWAY_BACKEND_IP:-10.203.84.2}
    environment:
      - UC_PYTHON_URL=http://bridge:8001
      - UC_HOST=0.0.0.0
      - UC_PORT=8444
      - UC_PROXY_SECRET=\${UC_PROXY_SECRET:-}
      - UC_DB_PATH=/app/data/detections.db
      - UC_KEYS_PATH=/app/data/keys.json
      - BRIDGE_ENV=\${BRIDGE_ENV:-production}
      # Content-Security-Policy: strict unless .env says report-only or
      # disabled, which turn the protection off to diagnose a page.
      - UC_CSP_MODE=\${UC_CSP_MODE:-strict}
      # Same values as the bridge: the audit-chain HMAC key and the
      # Fernet key for stored TOTP secrets. The gateway refuses to start
      # in production without valid ones. BRIDGE_MASTER_KEY (the admin
      # API key) stays with the bridge: the gateway does not need it.
      - BRIDGE_AUDIT_KEY=\${BRIDGE_AUDIT_KEY:-}
      - BRIDGE_MFA_KEY=\${BRIDGE_MFA_KEY:-}
      - UC_TLS_CERT=\${UC_TLS_CERT:-}
      - UC_TLS_KEY=\${UC_TLS_KEY:-}
      # Same value as the bridge's.
      - BRIDGE_ALLOW_UNBOUND_NODE_KEYS=\${BRIDGE_ALLOW_UNBOUND_NODE_KEYS:-}
    volumes:
      - bridge_data:/app/data
    depends_on:
      bridge:
        condition: service_healthy
    restart: unless-stopped
    # Room to deliver queued post-ingest hooks and spool the rest at stop.
    stop_grace_period: 30s
    healthcheck:
      test: ["CMD", "/app/healthcheck.sh"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 10s

# backend (gateway <-> bridge) has a fixed subnet so the gateway has a
# fixed address; docker gives the bridge an address from ip_range only,
# never the gateway's. The default is outside Docker's default address
# pools. If it clashes with a network on this host (another SigRift
# stack, say), install-release.sh writes a free one to .env; by hand, set
# SIGRIFT_BACKEND_SUBNET, SIGRIFT_BACKEND_IP_RANGE (inside it) and
# SIGRIFT_GATEWAY_BACKEND_IP (inside the subnet, outside the range) there.
networks:
  default: {}
  backend:
    ipam:
      config:
        - subnet: \${SIGRIFT_BACKEND_SUBNET:-10.203.84.0/28}
          ip_range: \${SIGRIFT_BACKEND_IP_RANGE:-10.203.84.8/29}

volumes:
  bridge_data:
  bridge_secrets:
EOF
    echo "==> Wrote docker-compose.yml (pinned to ${VERSION})"
else
    if [ "$VERSION_REQUESTED" -eq 1 ]; then
        update_release_images docker-compose.yml
    fi
    check_compose_gateway_env docker-compose.yml
fi

# Remember an explicit upgrade so the next plain re-run cannot read an
# older VERSION sidecar and silently revert the images to that release.
if [ "$VERSION_REQUESTED" -eq 1 ]; then
    version_tmp=$(mktemp .sigrift-version.XXXXXX)
    printf '%s\n' "$VERSION" > "$version_tmp"
    chmod 0644 "$version_tmp"
    mv "$version_tmp" VERSION
fi

# ── .env: prompt for admin password, generate the rest ───────────────
if [ -f .env ] && grep -q '^BRIDGE_ADMIN_PASSWORD=' .env 2>/dev/null; then
    echo "==> Using existing .env (admin password already set)"
    repair_mfa_key .env
    warn_missing_audit_key .env
    persist_bind_setting .env
else
    cat <<'EOF'
This installer will create a local admin account.

The password you type next is written only to a local .env file
(chmod 600) and passed straight to the bridge container as an
environment variable. It is never printed to stdout, never stored
in docker logs, and never written to any other file.

Minimum 12 characters.
EOF
    ADMIN_PASSWORD=""
    while true; do
        read -r -s -p "Admin password: " PW1; echo
        if [ ${#PW1} -lt 12 ]; then
            echo "  too short (min 12 chars), try again" >&2
            continue
        fi
        read -r -s -p "Confirm password: " PW2; echo
        if [ "$PW1" != "$PW2" ]; then
            echo "  passwords did not match, try again" >&2
            continue
        fi
        ADMIN_PASSWORD=$PW1
        unset PW1 PW2
        break
    done

    BIND="${SIGRIFT_BIND:-127.0.0.1}"
    if ! bind_setting_valid "$BIND"; then
        echo "Error: SIGRIFT_BIND must be an IPv4 address (127.0.0.1, 0.0.0.0, ...) or one IPv6 address in brackets ([fd00::5], ...)" >&2
        exit 1
    fi

    # Generate the secrets up front: a failing $(...) inside the heredoc
    # below would not trip `set -e` and would silently write an empty
    # value into .env. These are all the secrets production mode needs.
    MFA_KEY=$(fernet_key)
    AUDIT_KEY=$(randstr)
    MASTER_KEY=$(randstr)
    PROXY_SECRET=$(randstr)
    ADMIN_PASSWORD_ENV=$(printf '%s' "$ADMIN_PASSWORD" | dotenv_password)

    umask 077
    tmp_env=$(mktemp "${TMPDIR:-/tmp}/sigrift-env.XXXXXX")
    trap 'rm -f "$tmp_env"' EXIT
    cat > "$tmp_env" <<EOF
# Generated by scripts/install-release.sh @ ${VERSION}. Do not commit.
BRIDGE_ENV=production
# Host address the gateway is published on: 127.0.0.1 = this machine
# only; 0.0.0.0 = every interface (other machines, remote edge nodes).
SIGRIFT_BIND=${BIND}
BRIDGE_MFA_KEY=${MFA_KEY}
BRIDGE_AUDIT_KEY=${AUDIT_KEY}
BRIDGE_MASTER_KEY=${MASTER_KEY}
UC_PROXY_SECRET=${PROXY_SECRET}
BRIDGE_ADMIN_USER=admin
BRIDGE_ADMIN_PASSWORD=${ADMIN_PASSWORD_ENV}
UC_TLS_CERT=/app/tls/cert.pem
UC_TLS_KEY=/app/tls/key.pem
EOF
    unset MFA_KEY AUDIT_KEY MASTER_KEY PROXY_SECRET
    chmod 600 "$tmp_env"
    mv "$tmp_env" .env
    trap - EXIT
    unset ADMIN_PASSWORD ADMIN_PASSWORD_ENV
    echo "==> Wrote .env (chmod 600)"
fi

# ── Self-signed TLS cert ─────────────────────────────────────────────
setup_tls

# ── Compose override (TLS bind-mount) ────────────────────────────────
if [ ! -f docker-compose.override.yml ]; then
    cat > docker-compose.override.yml <<'EOF'
# Generated by install-release.sh. Mounts the host-generated TLS dir
# into the gateway. docker-compose loads this automatically.
services:
  gateway:
    volumes:
      - ./tls:/app/tls:ro
EOF
    echo "==> Wrote docker-compose.override.yml"
fi

# ── Backend network subnet ───────────────────────────────────────────
# The default may clash with another SigRift stack or a network this
# host uses; then a free one is recorded in .env (ensure_backend_subnet).
ensure_backend_subnet .env

# ── Pull + start ─────────────────────────────────────────────────────
echo "==> Pulling images for ${VERSION}..."
docker compose pull

echo "==> Starting stack..."
# A regenerated cert is a new file the running gateway does not see —
# whether this run wrote it or an earlier one whose pull or `up` failed
# afterwards (tls/.recreate-pending, cleared only once `up` worked).
up_args=(up -d --remove-orphans)
if tls_recreate_pending tls/cert.pem; then
    up_args+=(--force-recreate)
fi
docker compose "${up_args[@]}"
tls_recreate_done tls/cert.pem

# ── Volume ownership migration ───────────────────────────────────────
# Bridge + gateway run as uid/gid 1500. On a fresh install the volumes
# are created with that owner; on an upgrade from older images a volume
# may carry a different uid. bridge_secrets is also kept 0700.
fix_volume_ownership

# ── Wait for health ──────────────────────────────────────────────────
echo "==> Waiting for gateway to report healthy (up to 120s)..."
state=""
deadline=$(( $(date +%s) + 120 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    state=$(docker compose ps --format json 2>/dev/null \
        | python3 -c '
import json, sys
for line in sys.stdin:
    if not line.strip():
        continue
    try:
        row = json.loads(line)
    except json.JSONDecodeError:
        continue
    if row.get("Service") == "gateway":
        print(row.get("Health", ""))
' | head -1)
    if [ "$state" = "healthy" ]; then
        break
    fi
    sleep 3
done

if [ "$state" != "healthy" ]; then
    echo "" >&2
    echo "Gateway did not become healthy within 120s." >&2
    echo "Check logs:" >&2
    echo "    docker compose logs --tail=50 gateway" >&2
    echo "    docker compose logs --tail=50 bridge" >&2
    exit 1
fi

# ── Summary ──────────────────────────────────────────────────────────
cat <<EOF

SigRift ${VERSION} is up.

    Dashboard:  https://localhost:${PORT}/
    Username:   admin
    Password:   (the one you set at prompt)

Accept the self-signed TLS certificate in your browser.
$(describe_stack)

Edge nodes on other hosts verify the gateway against its certificate:
copy $(pwd)/tls/cert.pem to them and pass it with --ca-cert,
using a host name or address of this machine that the certificate
lists (openssl x509 -in tls/cert.pem -noout -ext subjectAltName;
add more with SIGRIFT_TLS_SANS=name,ip and re-run this script).

Next steps:
    View logs:           docker compose logs -f
    Stop everything:     docker compose down
    Reset all data:      docker compose down -v
    Pin a new version:   SIGRIFT_VERSION=vX.Y.Z bash install-release.sh
    Renew the TLS cert:  bash install-release.sh --renew-tls   (cron: see INSTALL.md)
    Add an edge agent:   see https://github.com/SigRift/SigRift/blob/${VERSION}/INSTALL.md

Read LEGAL.md before scanning anything other than your own signals.
EOF
