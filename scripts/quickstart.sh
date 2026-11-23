#!/usr/bin/env bash
# SigRift community — single-host quickstart.
#
# One-command bootstrap for lab / individual-researcher use. Prompts
# for an admin password, generates the remaining secrets + a self-
# signed TLS cert, and builds the selected services. --dashboard-only
# starts bridge + gateway + edge without scanner hardware or a model.
# A plain first run discovers safe local devices and selects only ready
# SDR/Wi-Fi workers. With no ready hardware, only the first three start:
#
#   bridge     — FastAPI app
#   gateway    — Rust TLS + auth proxy
#   edge       — node-heartbeat agent
#   rtl-tcp    — USB SDR → TCP relay
#   scan       — ONNX RF classifier
#   wifi-scan  — 802.11 monitor-mode capture
#   bt-scan    — Bluetooth discovery (not automatically selected)
#
# Use --dashboard-only for a fresh install without hardware. Its mode is
# saved in .env and retained on plain retries; existing overrides are
# never rewritten. See QUICKSTART.md to enable hardware later or change
# an existing installation without losing custom Compose settings.
#
# The admin password you type goes straight into a 0600 .env file
# and the bridge's environment; never printed to stdout or logs.
#
# Fresh installs default to BRIDGE_ENV=development (CSRF protection off,
# warnings instead of refusals for weak secrets) and publish on 127.0.0.1
# only. Set BRIDGE_ENV=production on the first run to save production mode.
# SIGRIFT_BIND=0.0.0.0 publishes the gateway on every interface. Existing
# .env files retain their mode; edit that file to change it permanently.
#
# Usage:
#   scripts/quickstart.sh --dashboard-only
#       (fresh hardware-free dashboard; mode is kept on plain retries)
#   scripts/quickstart.sh
#       (retry saved device choices; a fresh run safely auto-detects)
#   scripts/quickstart.sh --scanners=auto
#       (explicitly discover/select available devices on an existing stack)
#   scripts/quickstart.sh --scanners=wifi --wifi-interface=wlan1
#       (choose one spare Wi-Fi adapter; SSH/default-route radios are refused)
#   scripts/quickstart.sh --scanners=auto --prepare-host
#       (consent up front to the one sudo host-preparation step, for
#       unattended installs; --no-prepare-host never asks or runs it)
#   BRIDGE_ENV=production scripts/quickstart.sh --dashboard-only
#       (fresh production dashboard; saved in the new .env)
#   SIGRIFT_BIND=0.0.0.0 scripts/quickstart.sh
#       (reachable from other machines too; recorded in .env)
#   SIGRIFT_TLS_SANS=sigrift.lan,203.0.113.7 scripts/quickstart.sh
#       (extra names/IPs for the gateway cert, e.g. for remote edge nodes)
#   scripts/quickstart.sh --renew-tls
#       (only renew the self-signed TLS cert when it expires within 30
#       days, keeping its names — for a cron job or systemd timer, see
#       INSTALL.md "Certificate renewal"; a plain re-run adds names)
#
# Re-runs are idempotent: existing .env, model symlinks and override
# file are preserved (an invalid BRIDGE_MFA_KEY is repaired without
# losing encrypted TOTP secrets — see repair_mfa_key); the TLS cert is
# kept unless it lacks a required subjectAltName or expires within 30
# days; the data volumes' ownership is normalised to uid 1500 (the
# containers' pinned appuser).

set -euo pipefail

cd "$(dirname "$0")/.."

RENEW_TLS_ONLY=0
REQUESTED_MODE=""
SCANNER_REQUEST=""
WIFI_INTERFACE=""
SCANNER_ARGUMENT=0
WIFI_ARGUMENT=0
# yes: run the host preparation without asking; no: never ask or run it.
PREPARE_HOST=""
for argument in "$@"; do
    case "$argument" in
        --renew-tls) RENEW_TLS_ONLY=1 ;;
        --prepare-host|--no-prepare-host)
            if [ -n "$PREPARE_HOST" ]; then
                echo "Error: supply one of --prepare-host or --no-prepare-host, once." >&2; exit 2
            fi
            if [ "$argument" = --prepare-host ]; then PREPARE_HOST=yes; else PREPARE_HOST=no; fi
            ;;
        --dashboard-only) REQUESTED_MODE=dashboard-only ;;
        --scanners=*)
            if [ "$SCANNER_ARGUMENT" -eq 1 ] || [ -z "${argument#*=}" ]; then
                echo "Error: supply one nonempty --scanners choice." >&2; exit 2
            fi
            SCANNER_ARGUMENT=1
            SCANNER_REQUEST=${argument#*=}
            ;;
        --wifi-interface=*)
            if [ "$WIFI_ARGUMENT" -eq 1 ] || [ -z "${argument#*=}" ]; then
                echo "Error: supply one nonempty --wifi-interface choice." >&2; exit 2
            fi
            WIFI_ARGUMENT=1
            WIFI_INTERFACE=${argument#*=}
            ;;
        *) echo "usage: $0 [--dashboard-only | --scanners=auto|none|sdr|wifi|sdr,wifi [--wifi-interface=NAME] [--prepare-host | --no-prepare-host] | --renew-tls]" >&2; exit 2 ;;
    esac
done
if [ -n "$PREPARE_HOST" ] && { [ "$RENEW_TLS_ONLY" -eq 1 ] || [ -n "$REQUESTED_MODE" ] \
    || [ "$SCANNER_REQUEST" = none ]; }; then
    echo "Error: --prepare-host and --no-prepare-host prepare the host for scanners; they cannot be combined with --dashboard-only, --renew-tls or --scanners=none." >&2
    exit 2
fi
if { [ "$RENEW_TLS_ONLY" -eq 1 ] && [ "$#" -ne 1 ]; } \
    || { [ -n "$REQUESTED_MODE" ] && [ "$#" -ne 1 ]; } \
    || { [ -n "$WIFI_INTERFACE" ] && [ -z "$SCANNER_REQUEST" ]; }; then
    echo "Error: choose --dashboard-only | --renew-tls | --scanners=...; --wifi-interface requires --scanners." >&2
    exit 2
fi
if [ -n "$WIFI_INTERFACE" ]; then
    case "$SCANNER_REQUEST" in
        auto|wifi|sdr,wifi|wifi,sdr) ;;
        *) echo "Error: --wifi-interface requires a choice including Wi-Fi." >&2; exit 2 ;;
    esac
fi
case "$SCANNER_REQUEST" in
    ""|auto|none|sdr|wifi|sdr,wifi|wifi,sdr) ;;
    *) echo "Error: --scanners must be auto, none, sdr, wifi or sdr,wifi." >&2; exit 2 ;;
esac

# An explicit shell override must be unambiguous before prompts, probes or
# writes. Do not export a default: an existing .env still controls plain retries.
if [ "${BRIDGE_ENV+x}" = x ]; then
    case "$BRIDGE_ENV" in
        production|development) ;;
        *)
            echo "Error: BRIDGE_ENV must be production or development when explicitly set." >&2
            echo "Unset it to use an existing .env, or the development default for a fresh install." >&2
            exit 1
            ;;
    esac
fi

# ── Preflight ────────────────────────────────────────────────────────
if ! command -v docker >/dev/null 2>&1; then
    cat >&2 <<'EOF'
Error: docker not found on PATH.

Install Docker Engine + Compose plugin, then re-run this script:
    https://docs.docker.com/engine/install/
EOF
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: Python 3.11 or newer is required as python3 on PATH." >&2
    echo "Install or activate Python 3.11+, then re-run this script." >&2
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "Error: curl is required for model downloads and startup checks." >&2
    echo "Install curl with your operating system's package manager, then re-run this script." >&2
    exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
    echo "Error: openssl required for TLS cert generation." >&2
    echo "Install OpenSSL with your operating system's package manager, then re-run this script." >&2
    exit 1
fi

# Python keeps these read-only CLI probes bounded on both Linux and macOS.
# Inherit the operator's Docker context/endpoint; never switch it or start a
# daemon. This runs before password prompts or any generated configuration.
python3 - <<'PY'
import os
import signal
import subprocess
import sys

if sys.version_info < (3, 11):
    version = ".".join(map(str, sys.version_info[:3]))
    print(f"Error: Python 3.11 or newer is required; python3 is {version}.", file=sys.stderr)
    print("Install or activate Python 3.11+, then re-run this script.", file=sys.stderr)
    raise SystemExit(1)


def stop_probe(process):
    # A Docker SSH context can spawn a child. Kill this probe's process group
    # too, so a timeout or Ctrl-C cannot leave a background connection behind.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        # macOS can report EPERM for an exited child until it is reaped.
        process.poll()
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait(timeout=2)


def probe(command, label, guidance):
    process = None
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True,
        )
        result = process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        stop_probe(process)
        print(f"Error: {label} probe timed out after 10 seconds.", file=sys.stderr)
    except OSError:
        print(f"Error: {label} is unavailable or not working.", file=sys.stderr)
    except KeyboardInterrupt:
        if process is not None:
            stop_probe(process)
        print("Setup cancelled during prerequisite checks; configuration is unchanged.", file=sys.stderr)
        raise SystemExit(130)
    except BaseException:
        if process is not None:
            stop_probe(process)
        raise
    else:
        if result == 0:
            return
        print(f"Error: {label} is unavailable or not working.", file=sys.stderr)
    print(guidance, file=sys.stderr)
    raise SystemExit(1)


def interrupted(_signum, _frame):
    raise KeyboardInterrupt


signal.signal(signal.SIGTERM, interrupted)
probe(
    ["docker", "compose", "version"], "Docker Compose plugin",
    "Install or repair the Compose plugin: https://docs.docker.com/compose/install/",
)
probe(
    ["docker", "info", "--format", "{{.ServerVersion}}"], "Docker daemon",
    "Start the selected Docker daemon (Docker Desktop or Engine), or select the intended "
    "Docker context. Run `docker info` to check connection and permissions, then re-run this script.",
)
PY

# Resolve only our plain, installer-owned mode assignment; never source .env.
# Dashboard-only also checks Compose's effective inputs, including settings
# from .env. Capture config privately: it contains resolved credentials.
quickstart_mode() {
    python3 - "$1" "$2" <<'PYMODE'
from pathlib import Path
import re
import subprocess
import sys

requested, phase = sys.argv[1:]
env = Path(".env")
override = Path("docker-compose.override.yml")

def fail(message):
    sys.exit("Error: " + message)

assignments = [line for line in env.read_text().splitlines()
               if re.match(r"\s*(?:export\s+)?SIGRIFT_QUICKSTART_MODE\s*[=:]", line)] if env.exists() else []
stored = None
if assignments:
    if len(assignments) != 1 or not re.fullmatch(
        r"SIGRIFT_QUICKSTART_MODE=(dashboard-only|hardware|auto)", assignments[0]
    ):
        fail(".env must contain one plain SIGRIFT_QUICKSTART_MODE=dashboard-only, =auto or =hardware assignment before setup can continue.")
    stored = assignments[0].partition("=")[2]
if requested == "dashboard-only" and stored != "dashboard-only" and not Path(".sigrift-scanners.yml").exists():
    if env.exists() or override.exists() or override.is_symlink():
        fail("--dashboard-only cannot change an existing installation automatically. Existing files are preserved. See QUICKSTART.md 'Change an existing installation to dashboard-only'.")
mode = stored or requested or "hardware"
if mode == "dashboard-only":
    for name in ("compose.yml", "compose.yaml", "docker-compose.yaml",
                 "compose.override.yml", "compose.override.yaml", "docker-compose.override.yaml"):
        if Path(name).exists() or Path(name).is_symlink():
            fail("dashboard-only requires docker-compose.yml and docker-compose.override.yml without alternate Compose filenames. Preserve and reconcile your custom files first; see QUICKSTART.md.")
    if override.is_symlink() or (override.exists() and not override.is_file()):
        fail("dashboard-only requires a regular docker-compose.override.yml; existing overrides are not replaced.")
    def compose(*args):
        try:
            result = subprocess.run(["docker", "compose", "config", *args], capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            fail("Compose configuration did not complete within 10 seconds. Check docker compose config --quiet before retrying.")
        if result.returncode:
            fail("cannot resolve Compose configuration. Run docker compose config --quiet and correct it before retrying.")
        return result.stdout
    effective = dict(line.partition("=")[::2] for line in compose("--environment").splitlines())
    if effective.get("COMPOSE_FILE") or effective.get("COMPOSE_PROFILES"):
        fail("dashboard-only requires COMPOSE_FILE and COMPOSE_PROFILES unset in both the shell and .env. They can change which services start.")
    if override.exists() or phase == "verify":
        active = set(compose("--services").splitlines())
        if active != {"bridge", "gateway", "edge"}:
            fail("dashboard-only must resolve exactly bridge, gateway and edge. Existing override is preserved; disable rtl-tcp, scan, wifi-scan and bt-scan with profiles: [hardware], then retry. See QUICKSTART.md.")
print(mode)
PYMODE
}

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

# ── Self-signed TLS cert (also the whole of --renew-tls) ────────────
# Gateway requires a cert+key to bind 8444. We generate a self-signed
# pair; the cert is mounted into the gateway and every edge agent via
# the override file below. Its subjectAltName covers localhost, the
# in-stack names (gateway, bridge — the agents verify TLS, so edge/scan
# need DNS:gateway), this host's names and addresses (remote edge nodes
# that dial https://<this host>:8444 with --ca-cert) and SIGRIFT_TLS_SANS
# (extra names/IPs, comma-separated). An existing cert is regenerated
# only when it lacks one of those or expires within 30 days — see
# tls_ensure_cert.
setup_tls() {
    mkdir -p tls
    # 0755 on the dir is non-negotiable: the gateway container's appuser
    # (uid 1500) must traverse this dir to read the cert files. A 0700 dir
    # from a restrictive umask makes cert load fail with EACCES regardless
    # of file-level perms. Re-applied every run so existing 0700 dirs from
    # a prior bug get healed without a rerun-from-scratch.
    chmod 0755 tls
    tls_ensure_cert tls/cert.pem tls/key.pem localhost "${SIGRIFT_TLS_SANS:-}"
    # Cert 0644 (every agent reads it); key group 1500 — the gateway
    # container's appuser group — and 0640, so other host users cannot.
    secure_tls_files tls/cert.pem tls/key.pem
}

# wait_gateway_healthy SECS — polls `docker compose ps` until the gateway
# reports healthy (returns 0) or SECS pass (returns 1).
wait_gateway_healthy() {
    local state="" deadline
    deadline=$(( $(date +%s) + $1 ))
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
            return 0
        fi
        sleep 3
    done
    return 1
}

# Optional host checks never undo setup, but explicit cancellation must not
# fall through to a normal completion banner.
report_setup_readiness() {
    local readiness_status=0
    python3 scripts/scanner_readiness.py "$@" || readiness_status=$?
    case "$readiness_status" in
        130|143) exit "$readiness_status" ;;
    esac
}

# ── Host preparation for scanner hardware ───────────────────────────
# One reviewed sudo step (scanner_setup.py prepare) releases the receiver's
# TV driver, installs its udev rule and keeps NetworkManager off the spare
# Wi-Fi adapter. --prepare-host consents up front; otherwise ask once only
# when stdin and stdout are both terminals (unattended installs pipe the
# admin password on stdin). The review and the root run name exactly the
# targets "prepare --check" reported (--usb, --wifi-interface), and the SSH
# client address is passed on because sudo drops SSH_CONNECTION. Returns 0
# only after a successful preparation and a new plan in SCANNER_PLAN;
# anything else keeps the plan as it was. PREPARE_CONTEXT=failed-plan means
# the plan itself failed (an install whose selected receiver lost its
# preparation): the messages then do not promise that the run continues.
prepare_host_step() {
    local after_failure=0
    if [ "${PREPARE_CONTEXT:-}" = failed-plan ]; then after_failure=1; fi
    if [ "${PREPARE_HOST:-}" = no ]; then
        return 1
    fi
    local -a check_args=(--scanners "$SCANNER_REQUEST")
    if [ -n "${WIFI_INTERFACE:-}" ]; then check_args+=(--wifi-interface "$WIFI_INTERFACE"); fi
    if [ "${SCANNER_HONOR_PROFILES:-0}" -eq 1 ]; then check_args+=(--honor-profiles); fi
    local -a ssh_args=()
    if [ -n "${SSH_CONNECTION:-}" ]; then ssh_args=(--ssh-client "${SSH_CONNECTION%% *}"); fi
    local check_error check_output="" check_status=0 reason
    check_error=$(mktemp "${TMPDIR:-/tmp}/sigrift-prepare.XXXXXX") || return 1
    check_output=$(python3 scripts/scanner_setup.py prepare --check "${check_args[@]}" \
        ${ssh_args[@]+"${ssh_args[@]}"} 2>"$check_error") || check_status=$?
    reason=$(tr '\n' ' ' < "$check_error")
    rm -f "$check_error"
    if [ "$check_status" -ne 0 ]; then
        # After a failed plan the check usually fails for the same reason;
        # the plan's error above already says it, so add nothing here.
        if [ "$after_failure" -eq 1 ]; then return 1; fi
        reason=${reason#Error: }
        reason=${reason% }
        echo "    Skipped host preparation: ${reason:-scanner_setup.py prepare --check failed.}" >&2
        echo "    Review it with: python3 scripts/scanner_setup.py prepare --print   then re-run quickstart." >&2
        return 1
    fi
    if [ "${check_output%%$'\n'*}" != needed ]; then
        return 1
    fi
    local line usb="" wifi="" kinds=""
    while IFS= read -r line; do
        case "$line" in
            usb=*) usb=${line#usb=} ;;
            wifi-interface=*) wifi=${line#wifi-interface=} ;;
        esac
    done <<< "$check_output"
    if [ -n "$usb" ] && [ -n "$wifi" ]; then
        kinds=sdr,wifi
    elif [ -n "$usb" ]; then
        kinds=sdr
    elif [ -n "$wifi" ]; then
        kinds=wifi
    else
        echo "    Skipped host preparation: scanner_setup.py prepare --check named no device to prepare." >&2
        echo "    Review it with: python3 scripts/scanner_setup.py prepare --print   then re-run quickstart." >&2
        return 1
    fi
    local -a target_args=(--scanners "$kinds")
    local shown=" --scanners=$kinds"
    if [ -n "$usb" ]; then target_args+=(--usb "$usb"); shown+=" --usb=$usb"; fi
    if [ -n "$wifi" ]; then target_args+=(--wifi-interface "$wifi"); shown+=" --wifi-interface=$wifi"; fi
    target_args+=(${ssh_args[@]+"${ssh_args[@]}"})
    local display="sudo python3 scripts/scanner_setup.py prepare$shown"
    local review="python3 scripts/scanner_setup.py prepare --print$shown"
    local terminal=0
    if [ -t 0 ] && [ -t 1 ]; then terminal=1; fi
    local -a elevate=(sudo)
    if [ "$(id -u)" -eq 0 ]; then
        elevate=()
    elif [ "$terminal" -eq 0 ]; then
        elevate=(sudo -n)  # never hang on a password prompt
    fi
    if [ "${PREPARE_HOST:-}" = yes ]; then
        echo "==> Preparing this host for the scanners (--prepare-host): $display"
    elif [ "$terminal" -eq 1 ]; then
        echo
        echo "==> This host needs a one-time preparation for the scanners:"
        python3 scripts/scanner_setup.py prepare --print "${target_args[@]}" || true
        local answer=""
        read -r -p "Run it now with sudo? [y/N]: " answer || answer=""
        case "$answer" in
            y|Y|yes|Yes|YES) ;;
            *)
                if [ "$after_failure" -eq 1 ]; then
                    echo "    Skipped host preparation."
                else
                    echo "    Skipped host preparation; scanners that need it stay off in this run."
                fi
                echo "    Run it later with: $display   then re-run quickstart."
                return 1
                ;;
        esac
    else
        if [ "$after_failure" -eq 1 ]; then
            echo "==> This host needs a one-time preparation before the selected scanners can start."
        else
            echo "==> This host needs a one-time preparation for the scanners; scanners that need it stay off in this run."
        fi
        echo "    Review it with: $review"
        echo "    Then run: $display   (or re-run quickstart with --prepare-host)"
        return 1
    fi
    if ! ${elevate[@]+"${elevate[@]}"} python3 scripts/scanner_setup.py prepare "${target_args[@]}"; then
        if [ "$after_failure" -eq 1 ]; then
            echo "    Host preparation did not complete." >&2
        else
            echo "    Skipped: host preparation did not complete; scanners that need it stay off in this run." >&2
        fi
        echo "    Review it with: $review, then run: $display" >&2
        return 1
    fi
    local replanned
    if ! replanned=$(python3 scripts/scanner_setup.py "${plan_args[@]}"); then
        if [ "$after_failure" -eq 1 ]; then
            echo "    Planning again after host preparation failed." >&2
        else
            echo "    Planning again after host preparation failed; continuing with the earlier plan." >&2
        fi
        return 1
    fi
    SCANNER_PLAN=$replanned
    return 0
}

# Refuse ambiguous mode/device changes before credentials, certificates or models.
if [ -z "$REQUESTED_MODE" ] && [ ! -e .env ] && [ ! -L .env ]; then
    REQUESTED_MODE=auto
fi
QUICKSTART_MODE=$(quickstart_mode "$REQUESTED_MODE" plan)
SCANNER_MANAGED=0
SCANNER_RF=0
SCANNER_WIFI=0
QUICKSTART_SERVICES=()
SCANNER_COMPOSE_ARGS=()
SCANNER_HONOR_PROFILES=0
if [ "$RENEW_TLS_ONLY" -eq 0 ]; then
    if [ "$REQUESTED_MODE" = "dashboard-only" ]; then
        SCANNER_REQUEST=none
    elif [ -z "$SCANNER_REQUEST" ]; then
        if [ -e .sigrift-scanners.yml ] || [ -L .sigrift-scanners.yml ] \
            || [ -e .sigrift-scanners-pending.json ] || [ -L .sigrift-scanners-pending.json ]; then
            SCANNER_REQUEST=saved
        elif [ "$QUICKSTART_MODE" = "auto" ]; then
            if [ -e .env ]; then
                echo "Error: saved scanner selection is missing. Choose --scanners=auto or =none explicitly; existing settings are preserved." >&2
                exit 1
            fi
            SCANNER_REQUEST=auto
            SCANNER_HONOR_PROFILES=1
        elif [ "$QUICKSTART_MODE" != "dashboard-only" ]; then
            echo "Error: this legacy hardware configuration has no saved device selection." >&2
            echo "Preserve your files and choose scripts/quickstart.sh --scanners=auto (or =none)." >&2
            exit 1
        fi
    fi
    # Existing dashboard-only installs retain their no-hardware/no-probe path.
    # Explicit selection can add hardware through a separate managed overlay;
    # the stored .env and operator override are never rewritten for this.
    if [ -n "$SCANNER_REQUEST" ] && { [ "$SCANNER_REQUEST" != none ] \
        || [ -e .sigrift-scanners.yml ] || [ -L .sigrift-scanners.yml ] \
        || [ -e .sigrift-scanners-pending.json ] || [ -L .sigrift-scanners-pending.json ]; }; then
        SCANNER_MANAGED=1
        plan_args=(plan --scanners "$SCANNER_REQUEST")
        if [ "$SCANNER_HONOR_PROFILES" -eq 1 ]; then plan_args+=(--honor-profiles); fi
        if [ -n "$WIFI_INTERFACE" ]; then plan_args+=(--wifi-interface "$WIFI_INTERFACE"); fi
        if SCANNER_PLAN=$(python3 scripts/scanner_setup.py "${plan_args[@]}"); then
            # After a successful preparation the same run continues with
            # the scanners that are ready now; otherwise nothing changes.
            prepare_host_step || true
        else
            plan_status=$?
            # A plan can fail only because this host is not prepared (for
            # example an install whose selected receiver lost its udev rule,
            # or one made before this step existed). Offer the same one-time
            # preparation; after it the plan runs again in this run.
            if [ "$plan_status" -ne 130 ] && [ "$plan_status" -ne 143 ] \
                && PREPARE_CONTEXT=failed-plan prepare_host_step; then
                echo "==> The host is prepared now; the error above is resolved and setup continues."
            else
                # An unplugged/blocked saved adapter is useful last-check evidence.
                # Only an existing verified installation can receive it; reporting
                # never creates credentials or changes the saved scanner choice.
                if [ "$plan_status" -ne 130 ] && [ "$plan_status" -ne 143 ] && [ -f .env ] && [ -f tls/cert.pem ]; then
                    report_setup_readiness
                fi
                exit "$plan_status"
            fi
        fi
        SCANNER_RF=$(printf '%s' "$SCANNER_PLAN" | python3 -c 'import json,sys; print(int("sdr" in json.load(sys.stdin)))')
        SCANNER_WIFI=$(printf '%s' "$SCANNER_PLAN" | python3 -c 'import json,sys; print(int("wifi" in json.load(sys.stdin)))')
        QUICKSTART_SERVICES=(bridge gateway edge)
    elif [ "$SCANNER_REQUEST" = none ] && [ "$QUICKSTART_MODE" != dashboard-only ]; then
        SCANNER_MANAGED=1
        SCANNER_PLAN=$(python3 scripts/scanner_setup.py plan --scanners none)
        QUICKSTART_SERVICES=(bridge gateway edge)
    fi
fi
echo "==> Quickstart mode: ${QUICKSTART_MODE}"

if [ "$RENEW_TLS_ONLY" -eq 1 ]; then
    if [ -e .sigrift-scanners.yml ] || [ -L .sigrift-scanners.yml ]; then
        python3 scripts/scanner_setup.py check
    elif [ "$QUICKSTART_MODE" != dashboard-only ]; then
        echo "Error: saved scanner selection is missing; run quickstart --scanners=auto or =none before renewing TLS." >&2
        exit 1
    fi
    if [ "$QUICKSTART_MODE" = "dashboard-only" ]; then
        quickstart_mode "$QUICKSTART_MODE" verify >/dev/null
    fi
    if [ ! -f .env ]; then
        echo "Error: --renew-tls needs an installed stack (no .env in $(pwd)); run scripts/quickstart.sh first." >&2
        exit 1
    fi
    # Unattended: renew an expiring cert with the names it has; never
    # regenerate it for a new name (that is a re-run's job — see
    # tls_ensure_cert).
    TLS_RENEW_ONLY=1
    setup_tls
    if tls_recreate_pending tls/cert.pem; then
        # The agents mount cert.pem as a single file, which pins the old
        # inode: recreate everything that runs, not just the gateway.
        if [ "$TLS_CERT_CHANGED" -eq 1 ]; then
            echo "==> Recreating the running services so they use the new certificate"
        else
            echo "==> An earlier run renewed the certificate but did not finish recreating the services — recreating them now"
        fi
        # `|| true` as in a full run: services whose hardware is missing
        # (rtl-tcp, scan, ...) make `up` fail by design. What counts is
        # the gateway coming back healthy and every running service
        # having been recreated (tls_recreate_confirm: an `up` that died
        # before it reached the gateway leaves the old one running and
        # healthy); until then the marker stays and the next run
        # recreates again.
        if [ -e .sigrift-scanners.yml ]; then
            docker compose up -d --no-build --force-recreate bridge gateway edge || true
        else
            docker compose up -d --no-build --force-recreate || true
        fi
        if ! wait_gateway_healthy 240; then
            echo "Error: the gateway did not become healthy within 240s after the recreate; the next run retries it." >&2
            echo "    docker compose logs --tail=50 gateway" >&2
            exit 1
        fi
        if [ -e .sigrift-scanners.yml ]; then
            python3 scripts/scanner_setup.py start --recreate
        fi
        if ! tls_recreate_confirm tls/cert.pem docker compose; then
            echo "Error: the certificate was renewed but not every service was recreated; the next run retries it." >&2
            echo "    docker compose ps; docker compose logs --tail=50" >&2
            exit 1
        fi
        echo "    Copy ${PWD}/tls/cert.pem to every edge node on another host that"
        echo "    was given the old one (--ca-cert / MLRF_CA_CERT)."
    else
        echo "==> TLS certificate is current — nothing to do"
    fi
    exit 0
fi

# ── Admin password: prompt once, never write to logs ─────────────────
if [ -f .env ] && grep -q '^BRIDGE_ADMIN_PASSWORD=' .env 2>/dev/null; then
    echo "==> Using existing .env (admin password already set)"
    # Supplement an existing .env from a pre-7-service quickstart with
    # BRIDGE_LOCAL_NODE_KEY (added when wifi-scan/bt-scan landed). The
    # four scanner services need this to authenticate.
    if ! grep -q '^BRIDGE_LOCAL_NODE_KEY=' .env 2>/dev/null; then
        echo "BRIDGE_LOCAL_NODE_KEY=$(randstr)" >> .env
        echo "==> Added BRIDGE_LOCAL_NODE_KEY to .env (was missing)"
    fi
    repair_mfa_key .env
    warn_missing_audit_key .env
    if [ -z "${SIGRIFT_BIND:-}" ] \
        && ! grep -qE '^[[:space:]]*(export[[:space:]]+)?SIGRIFT_BIND[[:space:]]*=' .env; then
        echo "NOTE: the gateway is now published on 127.0.0.1 only (this machine) unless .env sets SIGRIFT_BIND. To keep it reachable from other machines, re-run with SIGRIFT_BIND=0.0.0.0 (or add SIGRIFT_BIND=0.0.0.0 to .env)." >&2
    fi
    persist_bind_setting .env
else
    cat <<'EOF'
This installer will create a local admin account.

The password you type next is written only to a local .env file
(chmod 600, gitignored) and passed straight to the bridge container
as an environment variable. It is never printed to stdout, never
stored in docker logs, and never written to any other file.

Minimum 12 characters. Mix classes if you want — no rules enforced
here, but the bridge will enforce its own rules on later logins.
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

    # ── Environment preset: pre-warm the anomaly baselines ───────────────
    # Skipped when SIGRIFT_PRESET is already set (env/CI) or stdin is not a TTY.
    SIGRIFT_PRESET="${SIGRIFT_PRESET:-}"
    if [ -z "$SIGRIFT_PRESET" ] && [ -t 0 ]; then
        cat <<'EOF'

==> Environment preset (pre-trains the RF anomaly baselines so scoring starts
    warm instead of spending ~300 detections/bin in learning mode; fully
    synthetic — no site data, and timing patterns still learn locally):
    1) suburban-residential  (default)
    2) urban-dense
    3) rural-quiet
    4) office-commercial
    5) none — learn from scratch
EOF
        read -r -p "Choice [1]: " _preset_choice
        case "${_preset_choice:-1}" in
            1) SIGRIFT_PRESET=suburban-residential ;;
            2) SIGRIFT_PRESET=urban-dense ;;
            3) SIGRIFT_PRESET=rural-quiet ;;
            4) SIGRIFT_PRESET=office-commercial ;;
            5 | none) SIGRIFT_PRESET=none ;;
            *) SIGRIFT_PRESET=suburban-residential ;;
        esac
    fi

    # Write .env atomically with 0600 permissions. Subshell scopes the
    # umask 077 so it doesn't leak into later mkdirs (which would create
    # 0700 dirs that the bridge/gateway containers can't traverse, since
    # their appuser uid 1500 is neither the host owner nor the host gid).
    # Generate the secrets up front: a failing $(...) inside the heredoc
    # below would not trip `set -e` and would silently write an empty
    # value into .env.
    BIND="${SIGRIFT_BIND:-127.0.0.1}"
    if ! bind_setting_valid "$BIND"; then
        echo "Error: SIGRIFT_BIND must be an IPv4 address (127.0.0.1, 0.0.0.0, ...) or one IPv6 address in brackets ([fd00::5], ...)" >&2
        exit 1
    fi
    MFA_KEY=$(fernet_key)
    AUDIT_KEY=$(randstr)
    MASTER_KEY=$(randstr)
    PROXY_SECRET=$(randstr)
    LOCAL_NODE_KEY=$(randstr)
    ADMIN_PASSWORD_ENV=$(printf '%s' "$ADMIN_PASSWORD" | dotenv_password)

    tmp_env=$(mktemp "${TMPDIR:-/tmp}/sigrift-env.XXXXXX")
    trap 'rm -f "$tmp_env"' EXIT
    (
        umask 077
        cat > "$tmp_env" <<EOF
# Generated by scripts/quickstart.sh. Do not commit — this file is
# gitignored and contains the admin password plus server secrets.
# The first run's selected mode is retained. Development relaxes security
# guards; production requires the generated secrets below. Edit this value
# and run docker compose up -d to change the installed mode permanently.
BRIDGE_ENV=${BRIDGE_ENV:-development}
# Retained on plain retries, including when the override needs recreating.
SIGRIFT_QUICKSTART_MODE=${QUICKSTART_MODE:-hardware}
# Host address the gateway is published on: 127.0.0.1 = this machine
# only; 0.0.0.0 = every interface (other machines, remote edge nodes).
SIGRIFT_BIND=${BIND}
UC_PORT=${UC_PORT:-8444}
BRIDGE_MFA_KEY=${MFA_KEY}
BRIDGE_AUDIT_KEY=${AUDIT_KEY}
BRIDGE_MASTER_KEY=${MASTER_KEY}
UC_PROXY_SECRET=${PROXY_SECRET}
# First-boot anomaly-baseline preset (applied only when no learned state
# exists yet). One of urban-dense|suburban-residential|rural-quiet|
# office-commercial, or 'none'/empty to learn from scratch.
SIGRIFT_PRESET=${SIGRIFT_PRESET}
# Pre-seeded NODE-role key the bridge registers for the local-edge
# node on first boot. The four in-stack scanner services (edge,
# scan, wifi-scan, bt-scan) authenticate with this key. Without it
# they crash-loop with "No API key provided".
BRIDGE_LOCAL_NODE_KEY=${LOCAL_NODE_KEY}
BRIDGE_ADMIN_USER=admin
BRIDGE_ADMIN_PASSWORD=${ADMIN_PASSWORD_ENV}
UC_TLS_CERT=/app/tls/cert.pem
UC_TLS_KEY=/app/tls/key.pem
EOF
    )
    chmod 600 "$tmp_env"
    mv "$tmp_env" .env
    trap - EXIT
    unset ADMIN_PASSWORD ADMIN_PASSWORD_ENV MFA_KEY AUDIT_KEY MASTER_KEY PROXY_SECRET LOCAL_NODE_KEY BIND

    echo "==> Wrote .env (chmod 600)"
fi

# Keep nonsecret desired hardware separate from the active overlay. A failed
# TLS/model operation can then be retried plainly without guessing new devices
# or stopping previously active workers. Activation clears this pending record.
if [ "${SCANNER_MANAGED:-0}" -eq 1 ]; then
    printf '%s' "$SCANNER_PLAN" | python3 scripts/scanner_setup.py remember
fi

# ── Self-signed TLS cert ────────────────────────────────────────────
setup_tls

# ── Compose override: preserve every existing file, including old generated ones ─
# Header text cannot prove a file is still unmodified. Never overwrite an
# operator's changes on a retry. The persisted mode controls new files only.
OV_HEADER="# Generated by scripts/quickstart.sh"
if [ ! -e docker-compose.override.yml ] && [ ! -L docker-compose.override.yml ]; then
    HARDWARE_PROFILES='[]'
    if [ "$QUICKSTART_MODE" = "dashboard-only" ] || [ "$QUICKSTART_MODE" = "auto" ]; then
        HARDWARE_PROFILES='["hardware"]'
    fi
    cat > docker-compose.override.yml <<EOF
$OV_HEADER. docker-compose loads this automatically alongside
# docker-compose.yml. Mounts the host TLS dir into gateway, the
# host models dir into scan, and the gateway's self-signed cert into
# every edge agent (edge, scan, wifi-scan, bt-scan). The agents verify
# TLS by default against MLRF_CA_CERT / MLRF_CA_BUNDLE, else the
# system trust store, so they need the cert path to talk to the
# gateway. (MLRF_INSECURE_TLS=1 turns verification off — dev-only.)
# Existing overrides are never rewritten. Hardware profiles, when set,
# stay inactive until explicitly enabled; see QUICKSTART.md.
services:
  gateway:
    volumes:
      - ./tls:/app/tls:ro
  edge:
    volumes:
      - ./tls/cert.pem:/app/tls/cert.pem:ro
    environment:
      - MLRF_CA_CERT=/app/tls/cert.pem
  rtl-tcp:
    profiles: ${HARDWARE_PROFILES:-[]}
  scan:
    profiles: ${HARDWARE_PROFILES:-[]}
    volumes:
      - ./models:/app/models:ro
      - ./tls/cert.pem:/app/tls/cert.pem:ro
    environment:
      - MLRF_CA_CERT=/app/tls/cert.pem
  wifi-scan:
    profiles: ${HARDWARE_PROFILES:-[]}
    volumes:
      - ./tls/cert.pem:/app/tls/cert.pem:ro
    environment:
      - MLRF_CA_CERT=/app/tls/cert.pem
  bt-scan:
    profiles: ${HARDWARE_PROFILES:-[]}
    volumes:
      - ./tls/cert.pem:/app/tls/cert.pem:ro
    environment:
      - MLRF_CA_BUNDLE=/app/tls/cert.pem
      - MLRF_CA_CERT=/app/tls/cert.pem
EOF
    echo "==> Wrote docker-compose.override.yml"
fi

if [ "$QUICKSTART_MODE" = "dashboard-only" ]; then
    quickstart_mode "$QUICKSTART_MODE" verify >/dev/null
fi

# ── Model for the `scan` service ────────────────────────────────────
# Only a selected SDR requires this model. The `scan` container needs an
# ONNX classifier at /app/models/open-default.onnx (via the bind-mount
# below). We auto-source it from, in order:
#   1. Whatever .onnx file is already in ./models/ — newest by mtime
#      wins if multiple are present (matches bootstrap-staging.sh).
#   2. The latest GitHub Release asset, if (1) finds nothing.
#   3. Fail clearly before starting the selected scanner; keep configuration
#      and downloaded files available for a corrected retry.
#
# The active model is exposed under canonical names:
#   ./models/open-default.onnx           → symlink to the chosen file
#   ./models/open-default_metadata.json  → sidecar (class names)
#
# load_metadata() in edge_inference.py finds the sidecar via stem-match
# on the canonical name. To switch models later, drop a newer .onnx
# into ./models/ and re-run quickstart, or delete the
# open-default.onnx symlink and re-run.
MODELS_DIR="${PWD}/models"

# Helper: link a given ONNX basename (and matching metadata sidecar
# if present) to the canonical names the scan service reads. Symlinks
# are relative so they resolve inside the scan container's bind mount.
link_canonical_model() {
    python3 - "$MODELS_DIR" "$1" <<'PY'
import os
from pathlib import Path
import sys
import tempfile

models, picked = Path(sys.argv[1]), sys.argv[2]
links = []
# A release may already use the canonical filename. Preserve its real bytes
# instead of replacing them with a self-referential symlink.
if picked != "open-default.onnx":
    links.append((picked, "open-default.onnx"))
metadata = picked.removesuffix(".onnx") + "_metadata.json"
stale = None
if metadata != "open-default_metadata.json":
    if (models / metadata).is_file():
        links.append((metadata, "open-default_metadata.json"))
    else:
        # An unmanaged install may activate a model that has no sidecar. A
        # leftover alias would make the scanner label it with the previous
        # model's class names, so drop the alias. Only a link to a file is
        # removed, never a real file or a directory.
        alias = models / "open-default_metadata.json"
        if alias.is_symlink() and not alias.is_dir():
            stale = alias

try:
    # Refuse real directories and symlinks to directories before changing
    # either alias. ln -sf would otherwise create a link inside that directory.
    for _, alias in links:
        if (models / alias).is_dir():
            raise IsADirectoryError(f"canonical alias is a directory: {models / alias}")
    if links:
        with tempfile.TemporaryDirectory(prefix=".model-link-", dir=models) as stage:
            for target, alias in links:
                (Path(stage) / alias).symlink_to(target)
            for _, alias in links:
                # Each replacement is atomic and does not follow the old link.
                # The pair is not a multi-file transaction.
                os.replace(Path(stage) / alias, models / alias)
    # Only after the model alias is in place: a failed step keeps the pair.
    if stale is not None:
        stale.unlink()
except OSError as error:
    print(f"Error: cannot activate canonical model aliases: {error}", file=sys.stderr)
    raise SystemExit(1)
PY
}

# Try to fetch the open-default model from the dedicated models release
# as a fallback when ./models/ is empty. Pinned to the models tag rather
# than /releases/latest, which only ever returns the newest code release
# (no .onnx assets there). A failed transfer leaves no partial model.
# The selected-SDR caller fails clearly so the operator can retry; a
# dashboard/Wi-Fi-only selection never calls this helper.
MODELS_RELEASE_TAG="${SIGRIFT_MODELS_TAG:-v0.1.0-models}"
try_download_latest_release_model() (
    # A subshell keeps cleanup traps local to this operation. Staged files are
    # private, on the destination filesystem, and outside the *.onnx discovery
    # set: a failed/interrupted transfer cannot become next run's active model.
    local repo="SigRift/SigRift"
    local rel_json onnx_url meta_url onnx_bn meta_bn meta_status
    local download_dir
    # Bound DNS/TCP/TLS setup, stalled transfers and total request time. The
    # model gets a larger overall budget than the small release/sidecar files.
    # Do not retry here: plain quickstart retries the saved scanner selection.
    model_curl() {
        local maximum_seconds="$1"
        shift
        curl --connect-timeout 10 --max-time "$maximum_seconds" \
            --speed-limit 1024 --speed-time 10 --retry 0 "$@"
    }
    echo "==> No model in ./models/ — checking github.com/${repo} release ${MODELS_RELEASE_TAG}"
    if ! rel_json=$(model_curl 30 -fsSL "https://api.github.com/repos/${repo}/releases/tags/${MODELS_RELEASE_TAG}" 2>/dev/null); then
        echo "    GitHub API request failed or timed out (offline? rate-limited? release not published?). Re-run to retry."
        return 1
    fi
    onnx_url=$(echo "$rel_json" | python3 -c '
import json, sys
data = json.load(sys.stdin)
for a in data.get("assets", []):
    if a["name"].endswith(".onnx"):
        print(a["browser_download_url"]); break
')
    local sums_url
    sums_url=$(echo "$rel_json" | python3 -c '
import json, sys
data = json.load(sys.stdin)
for a in data.get("assets", []):
    if a["name"] == "SHA256SUMS":
        print(a["browser_download_url"]); break
')
    if [ -z "$onnx_url" ]; then
        echo "    Release ${MODELS_RELEASE_TAG} has no .onnx asset. Grab one from"
        echo "    https://github.com/${repo}/releases instead. Skipping."
        return 1
    fi
    # Name the file after the asset, not the URL: a URL may be percent-encoded,
    # and SHA256SUMS and the sidecar asset use the plain name.
    onnx_bn=$(echo "$rel_json" | python3 -c '
import json, os, sys
data = json.load(sys.stdin)
for a in data.get("assets", []):
    if a["name"].endswith(".onnx"):
        print(os.path.basename(a["name"])); break
')
    # The scanner reads class names from <model stem>_metadata.json. Without
    # it every label would come from an older built-in list, so the sidecar
    # for exactly this model is required, not optional.
    meta_bn="${onnx_bn%.onnx}_metadata.json"
    meta_url=$(echo "$rel_json" | python3 -c '
import json, sys
data = json.load(sys.stdin)
for a in data.get("assets", []):
    if a["name"] == sys.argv[1]:
        print(a["browser_download_url"]); break
' "$meta_bn")
    if [ -z "$meta_url" ]; then
        echo "    Release ${MODELS_RELEASE_TAG} has no ${meta_bn} asset. The scanner cannot" >&2
        echo "    label detections without it, so ${onnx_bn} was not downloaded." >&2
        return 1
    fi
    if ! download_dir=$(mktemp -d "${MODELS_DIR}/.model-download.XXXXXX"); then
        echo "    Could not create model download staging directory. Skipping." >&2
        return 1
    fi
    trap 'rm -rf -- "$download_dir"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    # Unlike mv, os.replace refuses an existing directory at the target path.
    # Each completed file replaces its destination atomically; this is not a
    # multi-file transaction. The checksum receipt stays optional.
    publish_downloaded_file() {
        python3 - "${download_dir}/$1" "${MODELS_DIR}/$1" <<'PY'
import os
import sys

os.replace(sys.argv[1], sys.argv[2])
PY
    }
    # Publish the sidecar (when staged) before the model, so a model is never
    # discoverable without it. If the model then fails to publish, the previous
    # sidecar is restored (or the new one removed): no orphan is left behind.
    # An old sidecar that could not be backed up stays replaced by the new one.
    # Exit 2: the sidecar was not published and nothing changed.
    publish_downloaded_model() {
        python3 - "$download_dir" "$MODELS_DIR" "$1" "${2:-}" <<'PY'
import os
from pathlib import Path
import shutil
import sys

stage, models, model, metadata = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4]
backup = stage / ".previous-metadata"
had_previous = False
backup_failed = False
if metadata:
    target = models / metadata
    try:
        if target.is_symlink():
            backup.symlink_to(os.readlink(target))
            had_previous = True
        elif target.is_file():
            shutil.copy2(target, backup)
            had_previous = True
    except OSError as error:
        # The backup only serves the rollback below. An unreadable old
        # sidecar must not keep out the new verified one.
        print(f"    Could not back up {metadata}, replacing it without a rollback copy: {error}", file=sys.stderr)
        backup_failed = True
    try:
        os.replace(stage / metadata, target)
    except OSError as error:
        print(f"    {error}", file=sys.stderr)
        raise SystemExit(2)
try:
    os.replace(stage / model, models / model)
except OSError as error:
    print(f"    {error}", file=sys.stderr)
    # Without a backup the old sidecar cannot come back; keep the new one.
    if metadata and not backup_failed:
        try:
            if had_previous:
                os.replace(backup, target)
            else:
                os.unlink(target)
        except OSError as rollback:
            print(f"    Could not roll back {metadata}: {rollback}", file=sys.stderr)
    raise SystemExit(1)
PY
    }
    # Hash a staged file. Prints nothing and fails if it cannot be read.
    staged_sha256() {
        python3 - "${download_dir}/$1" <<'PY'
import hashlib
import sys

with open(sys.argv[1], "rb") as staged:
    print(hashlib.file_digest(staged, "sha256").hexdigest())
PY
    }
    # A sidecar for exactly this stem from an earlier run (a regular file,
    # not an alias of another model) may stand in for a failed transfer.
    have_previous_metadata() {
        [ -f "${MODELS_DIR}/${meta_bn}" ] && [ ! -L "${MODELS_DIR}/${meta_bn}" ]
    }

    echo "==> Downloading ${onnx_bn}"
    if ! model_curl 900 -fSL --progress-bar -o "${download_dir}/${onnx_bn}" "$onnx_url"; then
        echo "    Download failed or timed out. Discarding partial data; re-run to retry."
        return 1
    fi
    # Verify the download against the release's SHA256SUMS. Fail closed
    # on mismatch. If the release predates SHA256SUMS (older asset set) or the
    # user opts out, warn and continue.
    if [ "${SIGRIFT_SKIP_CHECKSUM:-}" = "1" ]; then
        echo "    SIGRIFT_SKIP_CHECKSUM=1 — skipping checksum verification"
    elif [ -n "$sums_url" ]; then
        echo "==> Verifying ${onnx_bn} against SHA256SUMS"
        if ! model_curl 30 -fsSL -o "${download_dir}/SHA256SUMS" "$sums_url"; then
            echo "    Could not fetch SHA256SUMS (request failed or timed out) — refusing an unverified model. Re-run to retry." >&2
            return 1
        fi
        local want got
        want=$(awk -v f="$onnx_bn" '$2==f || $2=="*"f {print $1}' "${download_dir}/SHA256SUMS" | head -1)
        if ! got=$(staged_sha256 "$onnx_bn"); then
            echo "    Could not hash downloaded model — refusing an unverified model." >&2
            return 1
        fi
        if [ -z "$want" ] || [ "$want" != "$got" ]; then
            echo "    CHECKSUM MISMATCH for ${onnx_bn} (want=${want:-<absent>} got=${got})." >&2
            echo "    Discarding the download. Re-run, or set SIGRIFT_SKIP_CHECKSUM=1 to override." >&2
            return 1
        fi
        echo "    OK (sha256 verified)"
    else
        echo "    Release has no SHA256SUMS asset — model integrity unverified."
    fi
    # Fetch and verify the sidecar before anything is published.
    local meta_staged="$meta_bn"
    echo "==> Downloading ${meta_bn}"
    if ! model_curl 30 -fSL --progress-bar -o "${download_dir}/${meta_bn}" "$meta_url"; then
        if ! have_previous_metadata; then
            echo "    Metadata download failed or timed out. The scanner cannot label detections" >&2
            echo "    without ${meta_bn}, so ${onnx_bn} was not activated. Re-run to retry." >&2
            return 1
        fi
        echo "    Metadata download failed or timed out; using models/${meta_bn} from an earlier run." >&2
        meta_staged=""
    elif [ -f "${download_dir}/SHA256SUMS" ]; then
        # Same fail-closed policy as the model, when SHA256SUMS lists the file.
        local meta_want meta_got
        meta_want=$(awk -v f="$meta_bn" '$2==f || $2=="*"f {print $1}' "${download_dir}/SHA256SUMS" | head -1)
        if [ -z "$meta_want" ]; then
            echo "    SHA256SUMS does not list ${meta_bn} — metadata integrity unverified."
        else
            if ! meta_got=$(staged_sha256 "$meta_bn"); then
                echo "    Could not hash downloaded metadata — refusing unverified metadata." >&2
                return 1
            fi
            if [ "$meta_want" != "$meta_got" ]; then
                echo "    CHECKSUM MISMATCH for ${meta_bn} (want=${meta_want} got=${meta_got})." >&2
                echo "    Discarding the download; ${onnx_bn} was not activated. Re-run, or set SIGRIFT_SKIP_CHECKSUM=1 to override." >&2
                return 1
            fi
            echo "    OK (${meta_bn} sha256 verified)"
        fi
    fi
    meta_status=0
    publish_downloaded_model "$onnx_bn" "$meta_staged" || meta_status=$?
    if [ "$meta_status" -eq 2 ]; then
        if ! have_previous_metadata; then
            echo "    Could not publish ${meta_bn}. The scanner cannot label detections without it," >&2
            echo "    so ${onnx_bn} was not activated. Fix models/${meta_bn} and re-run." >&2
            return 1
        fi
        echo "    Could not publish new metadata; using models/${meta_bn} from an earlier run." >&2
        meta_status=0
        publish_downloaded_model "$onnx_bn" || meta_status=$?
    fi
    if [ "$meta_status" -ne 0 ]; then
        echo "    Could not publish completed model. Skipping." >&2
        return 1
    fi
    if [ -f "${download_dir}/SHA256SUMS" ] && ! publish_downloaded_file SHA256SUMS; then
        echo "    Model verified, but could not save its SHA256SUMS receipt." >&2
    fi
    if ! link_canonical_model "$onnx_bn"; then
        echo "    Model downloaded, but canonical activation failed. Fix the alias paths and re-run." >&2
        return 1
    fi
    echo "==> Active model: ${onnx_bn}"
)

# A local model without its sidecar. Managed scanner setup refuses a model
# without its class names, so a managed install stops here, before any alias
# changes. An unmanaged (legacy) install starts its scanner itself and is
# only warned: the scanner decides. -f accepts a regular file or a symlink
# to one.
check_local_metadata() {
    local meta="${1%.onnx}_metadata.json"
    if [ -f "${MODELS_DIR}/${meta}" ]; then
        return 0
    fi
    if [ "${SCANNER_MANAGED:-0}" -ne 1 ]; then
        echo "WARNING: models/$1 has no models/${meta}. The scanner names its detections" >&2
        echo "         from that file and refuses to start without it, unless the model's" >&2
        echo "         output count matches its built-in class list." >&2
        return 0
    fi
    echo "Error: models/$1 has no models/${meta}; no scanner was started." >&2
    echo "       That JSON file holds the model's class names: a \"classes\" list in the" >&2
    echo "       model's output order. Add it next to the model, or remove models/$1 so" >&2
    echo "       this script downloads the release model with its metadata. Then re-run." >&2
    return 1
}

# Keep the helper definitions above available in every mode. Only hardware
# installs need model discovery, downloads, symlinks and permission changes.
if { [ "${SCANNER_MANAGED:-0}" -eq 1 ] && [ "${SCANNER_RF:-0}" -eq 0 ]; } \
    || { [ "${SCANNER_MANAGED:-0}" -eq 0 ] && [ "$QUICKSTART_MODE" = "dashboard-only" ]; }; then
    echo "==> No selected RF scanner: skipping RF model downloads"
else
    mkdir -p "$MODELS_DIR"
    chmod 0755 "$MODELS_DIR"
# Discover existing model files, excluding the canonical alias from
# the candidate set (so the symlink doesn't count as a "real" model).
shopt -s nullglob
ONNX_FILES=()
for f in "${MODELS_DIR}"/*.onnx; do
    [ "$(basename "$f")" = "open-default.onnx" ] && continue
    ONNX_FILES+=("$f")  # full path so we can sort by mtime
done
shopt -u nullglob

if [ "${#ONNX_FILES[@]}" -eq 0 ]; then
    # No real models in ./models/. Try a release download; if that
    # fails too, fail before starting a selected scanner.
    if [ -f "${MODELS_DIR}/open-default.onnx" ] && [ ! -L "${MODELS_DIR}/open-default.onnx" ]; then
        check_local_metadata open-default.onnx || exit 1
        echo "==> Using model at models/open-default.onnx"
    elif ! try_download_latest_release_model; then
        echo ""
        echo "No RF model is available. Place a verified .onnx and its metadata"
        echo "sidecar in ./models/, then rerun the same setup command."
        echo "         Download both files from the newest *-models-* release at"
        echo "             https://github.com/SigRift/SigRift/releases"
        echo "         The dashboard configuration is preserved for retry."
        echo ""
        echo "Error: selected SDR requires a model; no scanner was started. Add a verified model or retry the download." >&2
        exit 1
    fi
else
    # One or more real models. Pick the newest by mtime — matches
    # bootstrap-staging.sh's first-boot policy, no prompt.
    newest=$(python3 - "${ONNX_FILES[@]}" <<'PY'
from pathlib import Path
import sys

print(max(map(Path, sys.argv[1:]), key=lambda path: (path.stat().st_mtime_ns, path.name)))
PY
)
    newest_bn=$(basename "$newest")
    CURRENT_LINK_TARGET=""
    if [ -L "${MODELS_DIR}/open-default.onnx" ]; then
        CURRENT_LINK_TARGET=$(readlink "${MODELS_DIR}/open-default.onnx")
    fi
    check_local_metadata "$newest_bn" || exit 1
    # Relink even when the model alias is current: a sidecar added since the
    # last run still needs its alias. Relinking is idempotent and atomic.
    if ! link_canonical_model "$newest_bn"; then
        echo "Error: model activation failed. Fix the alias paths in models/ and re-run." >&2
        exit 1
    fi
    if [ "$CURRENT_LINK_TARGET" = "$newest_bn" ]; then
        echo "==> Using model: $newest_bn"
    else
        echo "==> Active model: $newest_bn (newest of ${#ONNX_FILES[@]} in models/)"
    fi
fi

# Normalise file perms on anything in models/. Hosts with a 0077 umask
# (hardened Debian, some Ubuntu LTS) make `cp` produce 0700 files,
# which the scan container (uid 1500) can't read → ONNX load fails
# with EACCES (errno 13). Re-applied every run so files dropped in
# manually after a previous quickstart still become container-
# readable on the next invocation.
shopt -s nullglob
for f in "${MODELS_DIR}"/*; do
    [ -f "$f" ] || continue   # skip the symlinks
    chmod 0644 "$f"
done
shopt -u nullglob

fi

# Publish only our separate scanner overlay after rechecking hardware/model and
# actual Compose merge semantics. Existing .env/override/data are preserved.
if [ "${SCANNER_MANAGED:-0}" -eq 1 ]; then
    printf '%s' "$SCANNER_PLAN" | python3 scripts/scanner_setup.py install
    SCANNER_COMPOSE_ARGS=(-f docker-compose.yml -f docker-compose.override.yml -f .sigrift-scanners.yml)
    if [ "$SCANNER_RF" -eq 1 ]; then QUICKSTART_SERVICES+=(rtl-tcp scan); fi
    if [ "$SCANNER_WIFI" -eq 1 ]; then QUICKSTART_SERVICES+=(wifi-scan); fi
fi

# ── Backend network subnet ───────────────────────────────────────────
# The default may clash with another SigRift stack or a network this
# host uses; then a free one is recorded in .env (ensure_backend_subnet).
ensure_backend_subnet .env

# ── Boot ─────────────────────────────────────────────────────────────
echo "==> Building active service images (first build depends on host and download speed)..."
docker compose "${SCANNER_COMPOSE_ARGS[@]}" build "${QUICKSTART_SERVICES[@]}"

# ── Volume ownership migration ───────────────────────────────────────
# Bridge + gateway containers run as uid/gid 1500. On a fresh install
# the volume is created with the correct owner; on an upgrade from an
# older release the volume may carry a different uid. Idempotent.
# Run before `up` so the very first start finds correctly-owned files.
# Compose creates the volume on first reference, so trigger that:
docker compose create bridge >/dev/null 2>&1 || true
fix_volume_ownership

# Start the stack. `|| true` because compose returns non-zero when a
# service marked `depends_on: service_healthy` doesn't reach healthy
# within compose's internal timeout. On a fresh Pi-class host the
# gateway's schema migration races with the bridge's first-boot
# inserts on the shared SQLite DB — both wait on busy_timeout, so the
# first 'up' can easily take 2-3 minutes before gateway settles. Our
# own wait loop below is patient; trust it rather than compose's gate.
# A regenerated TLS cert is a new file that running containers (gateway
# config, the agents' single-file mounts and SSL contexts) do not see:
# recreate them.
echo "==> Starting services..."
# A cert an earlier run wrote but could not recreate the services for
# (tls/.recreate-pending) counts too; the marker is cleared below once
# the gateway is healthy again and every running service was recreated.
up_args=(up -d --no-build)
if tls_recreate_pending tls/cert.pem; then
    up_args+=(--force-recreate)
fi
if [ "${SCANNER_MANAGED:-0}" -eq 1 ]; then
    docker compose "${up_args[@]}" bridge gateway edge || true
else
    docker compose "${up_args[@]}" || true
fi

# ── Wait for health ──────────────────────────────────────────────────
# Generous deadline — first-boot SQLite contention on Pi-class arm64
# pushes gateway-healthy past 2 minutes routinely. 240s gives margin.
echo "==> Waiting for gateway to report healthy (up to 240s)..."
if ! wait_gateway_healthy 240; then
    echo "" >&2
    echo "Gateway did not become healthy within 240s." >&2
    echo "Check logs:" >&2
    echo "    docker compose logs --tail=50 gateway" >&2
    echo "    docker compose logs --tail=50 bridge" >&2
    exit 1
fi
# A healthy gateway may still be the old one: an `up` that failed before
# compose reached it (a full disk while the bridge was recreated) leaves
# it running with the old certificate.
if [ "${SCANNER_MANAGED:-0}" -eq 1 ] && tls_recreate_pending tls/cert.pem; then
    python3 scripts/scanner_setup.py start --recreate
fi
if ! tls_recreate_confirm tls/cert.pem docker compose; then
    echo "" >&2
    echo "The TLS certificate changed but not every service was recreated." >&2
    echo "Re-run scripts/quickstart.sh to recreate them; check:" >&2
    echo "    docker compose ps; docker compose logs --tail=50" >&2
    exit 1
fi

# ── Start dependent services that bailed during the first-boot race ──
# Compose's internal depends_on:service_healthy gate gives up before the
# first-boot SQLite race settles (see comment above the boot block).
# The `compose up -d --no-build || true` we issued earlier started
# bridge+gateway+rtl-tcp but left edge/scan/wifi-scan/bt-scan in
# "Created" because gateway wasn't healthy in time. Now that gateway
# IS healthy, re-issue `up -d` so the stragglers start. No-op for
# already-running services.
echo "==> Starting active dependent services..."
if [ "${SCANNER_MANAGED:-0}" -eq 1 ]; then
    docker compose up -d --no-build bridge gateway edge || true
else
    docker compose up -d --no-build || true
fi

# ── End-to-end smoke ─────────────────────────────────────────────────
# Confirm the stack is actually usable, not just "up". Catches subtle
# misconfigs (TLS SAN mismatch, .env / compose env drift, admin user
# not seeded) that `docker compose ps` would happily report as healthy.
# Show every check, then return failure unless all checks passed. Existing
# configuration, volumes and logs remain available for diagnosis and retry.
# Use the running gateway's published binding, not a second dotenv parser or
# an assumed localhost address. A specific interface need not serve localhost.
published_gateway_url() {
    python3 - <<'PYENDPOINT'
import ipaddress
import os
import re
import signal
import subprocess
import sys


def fail(message):
    sys.exit("Error: " + message + " Check `docker compose port gateway 8444` and the gateway ports configuration, then retry.")


def stop(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        process.poll()  # macOS may need an exited child reaped first.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait(timeout=2)


def interrupted(_signum, _frame):
    raise KeyboardInterrupt


signal.signal(signal.SIGTERM, interrupted)
process = None
try:
    process = subprocess.Popen(
        ["docker", "compose", "port", "gateway", "8444"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, start_new_session=True,
    )
    output, _ = process.communicate(timeout=10)
except subprocess.TimeoutExpired:
    stop(process)
    fail("Gateway port lookup timed out after 10 seconds.")
except KeyboardInterrupt:
    if process is not None:
        stop(process)
    sys.exit(130)
except OSError:
    fail("Cannot read the gateway's published port.")
if process.returncode:
    fail("Cannot read the gateway's published port.")

candidates = []
for line in output.splitlines():
    if not line.strip():
        continue
    match = re.fullmatch(r"(?:\[([0-9A-Fa-f:.]+)\]|([^:\s]+)):([0-9]+)", line.strip())
    if not match:
        fail("Gateway returned an invalid published IP address or port.")
    try:
        address = ipaddress.ip_address(match[1] or match[2])
        port = int(match[3])
        if not 1 <= port <= 65535 or (address.version == 6) != bool(match[1]):
            raise ValueError
    except ValueError:
        fail("Gateway returned an invalid published IP address or port.")
    if address.is_unspecified:
        address = ipaddress.ip_address("127.0.0.1" if address.version == 4 else "::1")
    host = str(address) if address.version == 4 else f"[{address}]"
    # Prefer IPv4 when dual-published, and loopback within an address family.
    candidates.append(((address.version, not address.is_loopback, host, port), f"https://{host}:{port}"))
if not candidates:
    fail("Gateway has no published HTTPS port.")
print(min(candidates)[1])
PYENDPOINT
}
SMOKE_URL=$(published_gateway_url)
# Private scratch dir for the session cookie jar and verified username.
SMOKE_TMP=$(mktemp -d "${TMPDIR:-/tmp}/sigrift-smoke.XXXXXX")
SMOKE_WAIT_PID=
smoke_cleanup() {
    if [ -n "${SMOKE_WAIT_PID:-}" ]; then
        kill "$SMOKE_WAIT_PID" 2>/dev/null || :
        wait "$SMOKE_WAIT_PID" 2>/dev/null || :
    fi
    rm -rf -- "$SMOKE_TMP"
}
trap smoke_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
COOKIE_JAR="${SMOKE_TMP}/cookies"
# login_body ENV_FILE [USERNAME_FILE] resolves the bridge environment with Compose,
# including shell overrides, dotenv quoting and customized service settings.
# The optional private file carries only the username to the completion banner.
login_body() {
    docker compose --env-file "$1" config --format json | python3 -c '
import json
import os
import sys

values = json.load(sys.stdin)["services"]["bridge"].get("environment", {})
# config re-escapes literal dollars as $$ so its output can be used as a
# Compose input again. Undo that rendering escape for the HTTP request.
def actual(name, default=""):
    return (values.get(name) or default).replace("$$", "$")

body = dict(
    username=actual("BRIDGE_ADMIN_USER", "admin"),
    password=actual("BRIDGE_ADMIN_PASSWORD"),
)
if sys.argv[1]:
    fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        output.write(body["username"])
print(json.dumps(body))
' "${2:-}"
}
smoke_step() {
    local label="$1"; shift
    if "$@" >/dev/null 2>&1; then
        printf '    \033[32mOK\033[0m   %s\n' "$label"
        return 0
    else
        printf '    \033[31mFAIL\033[0m %s\n' "$label"
        return 1
    fi
}
smoke_curl() {
    # A healthy container can still accept TLS and then stall. Bound connection
    # setup (including TLS) and the whole request, without retrying mutations.
    curl --noproxy '*' --connect-timeout 5 --max-time 15 "$@"
}
smoke_login_retry_delay() {
    # Only one short, unambiguous server-directed cooldown is eligible. A long
    # account lockout, missing/duplicate header or HTTP-date fails immediately.
    python3 - "$SMOKE_TMP/login-headers" <<'PYRETRY'
from email.parser import BytesHeaderParser
from pathlib import Path
import re
import sys

with Path(sys.argv[1]).open("rb") as stream:
    data = stream.read(65537)
if len(data) > 65536:
    raise SystemExit(1)
blocks = [part for part in re.split(rb"\r?\n\r?\n", data) if part.startswith(b"HTTP/")]
if not blocks:
    raise SystemExit(1)
status, _, headers = blocks[-1].partition(b"\n")
if len(status.split()) < 2 or status.split()[1] != b"429":
    raise SystemExit(1)
values = BytesHeaderParser().parsebytes(headers).get_all("Retry-After", [])
if len(values) != 1:
    raise SystemExit(1)
value = values[0].strip()
if not value.isascii() or not value.isdecimal() or len(value) > 2:
    raise SystemExit(1)
seconds = int(value)
if not 1 <= seconds <= 60:
    raise SystemExit(1)
# Avoid racing the boundary of the gateway's sliding rate window.
print(seconds + 1)
PYRETRY
}
smoke_login() {
    local status delay attempt wait_status
    # Build once: retries retain identical credentials, and neither passwords
    # nor responses/cookies enter argv or terminal output. EXIT removes them.
    if ! (umask 077
        login_body .env "$SMOKE_TMP/username" > "$SMOKE_TMP/login-body" &&
        : > "$SMOKE_TMP/login-headers" && : > "$SMOKE_TMP/login-response" &&
        : > "$COOKIE_JAR"
    ); then
        return 1
    fi
    for attempt in 1 2; do
        # A truncated/stalled response is a transport failure, even if curl saw
        # 429 headers. Only a fully completed 429 may be retried.
        if ! status=$(smoke_curl -sk -c "$COOKIE_JAR" \
            -D "$SMOKE_TMP/login-headers" -o "$SMOKE_TMP/login-response" \
            -w '%{http_code}' -H "Content-Type: application/json" \
            --data-binary @- "${SMOKE_URL}/api/auth/login" \
            < "$SMOKE_TMP/login-body" 2>/dev/null); then
            echo "Login verification transport failed; no automatic retry." >&2
            return 1
        fi
        if [ "$status" = 200 ]; then
            grep -q '\"success\".*true\|\"role\"\|\"username\"' "$SMOKE_TMP/login-response"
            return $?
        fi
        if [ "$status" != 429 ] || [ "$attempt" -ne 1 ]; then
            printf 'Login verification failed (HTTP %s); no further retry.\n' "$status" >&2
            return 1
        fi
        if ! delay=$(smoke_login_retry_delay); then
            echo "Login rate-limited; cooldown is missing, invalid or longer than 60s. Wait before retrying setup." >&2
            return 1
        fi
        printf 'Login rate-limited; retrying once after %ss (HTTP 429).\n' "$delay" >&2
        sleep "$delay" &
        SMOKE_WAIT_PID=$!
        wait_status=0
        wait "$SMOKE_WAIT_PID" || wait_status=$?
        SMOKE_WAIT_PID=
        [ "$wait_status" -eq 0 ] || return "$wait_status"
    done
    return 1
}
echo "==> Running smoke against ${SMOKE_URL}"
smoke_ok=1
smoke_step "gateway /health" \
    smoke_curl -sk -f "${SMOKE_URL}/health" || smoke_ok=0
smoke_step "bridge /api/version" \
    smoke_curl -sk -f "${SMOKE_URL}/api/version" || smoke_ok=0
# Only login may honor one short Retry-After; other smoke operations never retry.
if smoke_login; then
    printf '    \033[32mOK\033[0m   %s\n' "POST /api/auth/login"
else
    printf '    \033[31mFAIL\033[0m %s\n' "POST /api/auth/login"
    smoke_ok=0
fi
smoke_step "/api/auth/me" \
    smoke_curl -sk -f -b "$COOKIE_JAR" "${SMOKE_URL}/api/auth/me" || smoke_ok=0
smoke_step "/api/detections/recent" \
    smoke_curl -sk -f -b "$COOKIE_JAR" "${SMOKE_URL}/api/detections/recent?limit=1" || smoke_ok=0
if [ "$smoke_ok" -eq 1 ]; then
    ADMIN_USERNAME=$(cat "$SMOKE_TMP/username") || smoke_ok=0
fi
smoke_cleanup
trap - EXIT INT TERM
if [ "$smoke_ok" -ne 1 ]; then
    echo ""
    echo "Error: startup verification failed; SigRift is not ready." >&2
    echo "Configuration and data were preserved. Check the failed step and logs:" >&2
    echo "    docker compose logs --tail=60 gateway bridge" >&2
    echo "After correcting the problem, retry: scripts/quickstart.sh" >&2
    exit 1
fi

# Only now start the chosen workers. A successful dashboard smoke alone is
# not sufficient to claim that selected scanner processes started.
if [ "${SCANNER_MANAGED:-0}" -eq 1 ]; then
    if python3 scripts/scanner_setup.py start; then
        :
    else
        start_status=$?
        if [ "$start_status" -ne 130 ] && [ "$start_status" -ne 143 ]; then report_setup_readiness; fi
        exit "$start_status"
    fi
fi

# Optional host facts use only the installed node key and verified gateway CA.
# Delivery failure never reverses successful setup or claims capture is ready.
if [ "$QUICKSTART_MODE" = dashboard-only ] && [ "${SCANNER_MANAGED:-0}" -eq 0 ]; then
    report_setup_readiness --dashboard-only
else
    report_setup_readiness
fi

# ── Summary ──────────────────────────────────────────────────────────
cat <<EOF

SigRift is up.

    Dashboard:  ${SMOKE_URL}/
    Username:   ${ADMIN_USERNAME}
    Password:   (the one you set at prompt)

Accept the self-signed TLS certificate in your browser.
$(describe_stack)

Edge nodes on other hosts verify the gateway against its certificate:
copy ${PWD}/tls/cert.pem to them and pass it with --ca-cert,
using a host name or address of this machine that the certificate
lists (openssl x509 -in tls/cert.pem -noout -ext subjectAltName;
add more with SIGRIFT_TLS_SANS=name,ip and re-run this script).

Next steps:
    View logs:           docker compose logs -f
    Stop everything:     docker compose down
    Reset all data:      docker compose down -v
    Renew the TLS cert:  scripts/quickstart.sh --renew-tls   (cron: see INSTALL.md)
    Add an edge agent:   see INSTALL.md "Adding an edge agent"

Read LEGAL.md before scanning anything other than your own signals.
EOF
