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
#   UC_PORT=8454 scripts/quickstart.sh --new-instance
#       (a second, separate stack on this host on purpose: without it a
#       checkout beside another SigRift install is refused)
#
# The checkout's Docker Compose project (COMPOSE_PROJECT_NAME, which names
# the volumes) is pinned in .env on the first run. Before anything changes,
# a run refuses (exit 3, "Nothing was changed.") a second stack, a .env
# whose secrets do not match the running bridge or the data, and a
# missing .env beside existing data; --adopt-project NAME takes over the
# data of a checkout renamed before the pin existed.
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
# Which stack this checkout drives (see lc_identity); counted apart, since
# they combine with every other choice except --renew-tls.
LC_NEW_INSTANCE=0
LC_ADOPT_PROJECT=""
LC_KEEP_RUNNING_SECRETS=0
LC_ARGC=0
# --adopt-project NAME (the form the release installer takes) as well as
# --adopt-project=NAME: the name is the next argument.
LC_ADOPT_NEXT=0
for argument in "$@"; do
    if [ "$LC_ADOPT_NEXT" -eq 1 ]; then
        LC_ADOPT_NEXT=0
        case "$argument" in
            ""|-*) echo "Error: supply one nonempty --adopt-project name." >&2; exit 2 ;;
        esac
        LC_ADOPT_PROJECT=$argument
        LC_ARGC=$((LC_ARGC + 1))
        continue
    fi
    case "$argument" in
        --renew-tls) RENEW_TLS_ONLY=1 ;;
        --adopt-project)
            if [ -n "$LC_ADOPT_PROJECT" ]; then
                echo "Error: supply one nonempty --adopt-project name." >&2; exit 2
            fi
            LC_ADOPT_NEXT=1
            LC_ARGC=$((LC_ARGC + 1))
            ;;
        --new-instance) LC_NEW_INSTANCE=1; LC_ARGC=$((LC_ARGC + 1)) ;;
        --keep-running-secrets) LC_KEEP_RUNNING_SECRETS=1; LC_ARGC=$((LC_ARGC + 1)) ;;
        --adopt-project=*)
            if [ -n "$LC_ADOPT_PROJECT" ] || [ -z "${argument#*=}" ]; then
                echo "Error: supply one nonempty --adopt-project name." >&2; exit 2
            fi
            LC_ADOPT_PROJECT=${argument#*=}
            LC_ARGC=$((LC_ARGC + 1))
            ;;
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
        *) echo "usage: $0 [--dashboard-only | --scanners=auto|none|sdr|wifi|sdr,wifi [--wifi-interface=NAME] [--prepare-host | --no-prepare-host] | --renew-tls] [--new-instance | --adopt-project NAME] [--keep-running-secrets]" >&2; exit 2 ;;
    esac
done
if [ "$LC_ADOPT_NEXT" -eq 1 ]; then
    echo "Error: supply one nonempty --adopt-project name." >&2
    exit 2
fi
if { [ "$LC_NEW_INSTANCE" -eq 1 ] && [ -n "$LC_ADOPT_PROJECT" ]; } \
    || { [ "$RENEW_TLS_ONLY" -eq 1 ] && [ "$LC_ARGC" -ne 0 ]; }; then
    echo "Error: choose one of --new-instance and --adopt-project; neither, nor --keep-running-secrets, combines with --renew-tls." >&2
    exit 2
fi
if [ -n "$PREPARE_HOST" ] && { [ "$RENEW_TLS_ONLY" -eq 1 ] || [ -n "$REQUESTED_MODE" ] \
    || [ "$SCANNER_REQUEST" = none ]; }; then
    echo "Error: --prepare-host and --no-prepare-host prepare the host for scanners; they cannot be combined with --dashboard-only, --renew-tls or --scanners=none." >&2
    exit 2
fi
if { [ "$RENEW_TLS_ONLY" -eq 1 ] && [ $(( $# - LC_ARGC )) -ne 1 ]; } \
    || { [ -n "$REQUESTED_MODE" ] && [ $(( $# - LC_ARGC )) -ne 1 ]; } \
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
    python3 -I -c 'import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'
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
    python3 -I - "$1" <<'PY'
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
        fi | python3 -I -c '
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
    python3 -I - "$@" <<'PY'
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
    # A caller that keeps restore points copies the old pair first; its
    # failure only warns (an expiring certificate must still be renewed).
    if declare -F tls_before_swap >/dev/null; then
        tls_before_swap "$cert" "$key" || true
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
    python3 -I -c '
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
    mode=$(docker compose config --format json 2>/dev/null | python3 -I -c '
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
        | python3 -I -c 'import json, sys; print(json.load(sys.stdin).get("name", ""))' 2>/dev/null) \
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
    python3 -I - "$@" 3<&0 <<'PY'
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

# >>> shared: lifecycle-tool (keep byte-identical in scripts/quickstart.sh and
#     scripts/install-release.sh; scripts/tests/test_install_scripts.py checks)
#
# lc_tool SUBCOMMAND ARGS... is the installers' lifecycle tool (python3 on
# the host): which install a run acts on (identity), the .env rules
# (env-merge, pin), the secrets check, the records, and engine-run, which
# starts the engine in the bridge image. It asks Docker through argv that
# never holds a secret; it reads secrets from .env, the shell and `docker
# inspect` in its own process and never prints one. fd 3 is the caller's
# stdin (the engine source, or an admin password, on a pipe). -I: the
# folder it runs in (an install folder) is never on sys.path, so no file
# there is imported. The installers are the source of this block and of
# the ones after it: edit them in install-release.sh and copy them into
# quickstart.sh unchanged.
IFS= read -r -d '' LC_TOOL_SRC <<'PY' || true
"""The installers' lifecycle tool: which stack a run acts on, and .env rules.

Run as `lc_tool SUBCOMMAND ...` from the installers; the tests import this
text as a module. It asks Docker through argv that never holds a secret,
never prints a secret value, and refuses with the installers' format:
"Error: ...", details, "Next: <one command>", "Nothing was changed.",
exit 3.
"""

import base64
import binascii
import errno
import fcntl
import json
import os
import re
import stat
import subprocess
import sys
import time

# hashlib, secrets, shlex, shutil, signal, socket, tempfile and uuid are
# imported where they are used: an installer run starts this tool a
# hundred times, most of them for a journal or facts lookup.

EXIT_REFUSED = 3
EXIT_NEEDS_PASSWORD = 10
DOCKER_TIMEOUT = 60
ENGINE_TIMEOUT = 600

PROJECT_LABEL = "com.docker.compose.project"
VOLUME_LABEL = "com.docker.compose.volume"
SERVICE_LABEL = "com.docker.compose.service"
WORKDIR_LABEL = "com.docker.compose.project.working_dir"
STATE_DIR = ".sigrift"
HOST_RECORD = os.path.join(STATE_DIR, "install.json")
VOLUME_RECORD = ".sigrift-install.json"
RELEASE_HEADER = "# Generated by install-release.sh @ "
HOLD_HEADER = "# SigRift hold stub"
TAG = re.compile(r"v(\d+)\.(\d+)\.(\d+)(?:-rc(\d+))?")
VERSION_RE = re.compile(r"v\d+\.\d+\.\d+(?:-rc\d+)?|main(?:-[a-f0-9]{7,40})?")
PROJECT_RE = re.compile(r"[a-z0-9][a-z0-9_-]*")

# Keys the engine checks against the data (candidate maps hold only these).
CANDIDATE_KEYS = ("BRIDGE_AUDIT_KEY", "BRIDGE_AUDIT_SECRET", "BRIDGE_MASTER_KEY",
                  "BRIDGE_MFA_KEY", "BRIDGE_KEYSTORE_KEY", "BRIDGE_ENV")
AUDIT_KEYS = ("BRIDGE_AUDIT_KEY", "BRIDGE_AUDIT_SECRET")
DATA_BOUND = ("BRIDGE_AUDIT_KEY", "BRIDGE_AUDIT_SECRET", "BRIDGE_MFA_KEY",
              "BRIDGE_KEYSTORE_KEY", "BRIDGE_BACKUP_ENCRYPTION_KEY",
              "BRIDGE_DB_ENCRYPTION_KEY")

# Every key either installer writes, .env.example lists or a compose file
# interpolates has a class; the class says what a run may do with it
# (proposal 3.2, "Inventory"). scripts/tests/test_lifecycle_env.py checks
# that none is missing.
KEY_CLASSES = {
    "COMPOSE_PROJECT_NAME": "identity",
    "BRIDGE_ENV": "setting", "BRIDGE_MODE": "setting",
    "SIGRIFT_QUICKSTART_MODE": "setting", "UC_PORT": "setting",
    "UC_CSP_MODE": "setting", "BRIDGE_SESSION_BINDING": "setting",
    "BRIDGE_ALLOW_UNBOUND_NODE_KEYS": "setting",
    "BRIDGE_TRUSTED_PROXIES": "setting", "SIGRIFT_TLS_SANS": "setting",
    "BRIDGE_ALLOW_MIGRATION_WITHOUT_BACKUP": "setting",
    "SIGRIFT_PRESET": "setting", "UC_TLS_CERT": "setting", "UC_TLS_KEY": "setting",
    "MLRF_NODE_ID": "setting", "MLRF_BT_ADAPTER": "setting",
    "MLRF_BT_SCAN_INTERVAL": "setting", "MLRF_INPUT_SAMPLES": "setting",
    "MLRF_MODEL_PATH": "setting", "MLRF_WIFI_BANDS": "setting",
    "MLRF_WIFI_IFACE": "setting",
    "SIGRIFT_BIND": "host", "SIGRIFT_BACKEND_SUBNET": "host",
    "SIGRIFT_BACKEND_IP_RANGE": "host", "SIGRIFT_GATEWAY_BACKEND_IP": "host",
    "BRIDGE_AUDIT_KEY": "data-bound", "BRIDGE_AUDIT_SECRET": "data-bound",
    "BRIDGE_MFA_KEY": "data-bound", "BRIDGE_KEYSTORE_KEY": "data-bound",
    "BRIDGE_BACKUP_ENCRYPTION_KEY": "data-bound",
    "BRIDGE_DB_ENCRYPTION_KEY": "data-bound",
    "BRIDGE_MASTER_KEY": "regenerable", "UC_PROXY_SECRET": "regenerable",
    "BRIDGE_LOCAL_NODE_KEY": "regenerable",
    "BRIDGE_ADMIN_USER": "bootstrap", "BRIDGE_ADMIN_PASSWORD": "bootstrap",
    "COMPOSE_FILE": "compose", "COMPOSE_PROFILES": "compose",
}

# What env_plan applies, in this order (spec 4.5). Documentation for the
# reader and the tests; env_plan is the implementation.
KEY_RULES = (
    ("R1", "COMPOSE_PROJECT_NAME is written by the pin only"),
    ("R2", "a missing data-bound key is restored from the running bridge or the shell when it matches the data"),
    ("R3", "BRIDGE_MFA_KEY is generated only when no fernet: TOTP secret exists"),
    ("R4", "BRIDGE_AUDIT_KEY is generated only while audit_log is empty"),
    ("R5", "BRIDGE_KEYSTORE_KEY is generated only while crypto_keys is empty"),
    ("R6", "BRIDGE_MASTER_KEY is generated only when an audit key is set"),
    ("R7", "UC_PROXY_SECRET is always generated when missing"),
    ("R8", "BRIDGE_LOCAL_NODE_KEY is always generated when missing (quickstart)"),
    ("R9", "BRIDGE_ADMIN_PASSWORD is asked for only while no user exists"),
    ("R10", "config migrations"),
    ("R11", "unknown keys are kept"),
)

# Config migrations: the .env counterpart of the database migrations.
# Each is idempotent by its own condition and applied, in table order,
# only when the target version is at or above "since" (or is main*).
# Kinds: rename {old, new}; default {key, when, new: literal | "random"};
# note {key, text}. Removing keys is out of scope.
CONFIG_MIGRATIONS = [
    {"id": "cm-0001", "since": "v0.2.0", "kind": "default",
     "key": "UC_PROXY_SECRET", "when": ["uppercrust-internal"], "new": "random",
     "why": "the old public default, which the bridge refuses (it stays unhealthy)"},
]


PIN_COMMENT = ("# Docker Compose project of this install (volume and network names).\n"
               "# Written once by the installer; changing it points this folder at\n"
               "# other or empty volumes.\n")


EXIT_STOPPED = 4


class Refused(SystemExit):
    pass


def refuse(message, details=(), next_cmd=""):
    """The refusal format; exit 3. Inside an upgrade's critical section
    (LC_CRITICAL=1, the stack already stopped) a refusal cannot say that
    nothing changed: it says where the upgrade stopped and exits 4."""
    lines = ["Error: " + message] + ["  " + d for d in details]
    if os.environ.get("LC_CRITICAL") == "1":
        lines += ["  The upgrade stopped at step %s and changed nothing more; fix this, "
                  "then resume it (%s) or undo it (%s)." % (
                      os.environ.get("LC_STEP") or "?", lifecycle_cmd("--resume"),
                      lifecycle_cmd("--abort")),
                  "Next: " + next_cmd]
        sys.stderr.write("\n".join(lines) + "\n")
        sys.stderr.flush()
        raise Refused(EXIT_STOPPED)
    lines += ["Next: " + next_cmd, "Nothing was changed."]
    sys.stderr.write("\n".join(lines) + "\n")
    sys.stderr.flush()
    raise Refused(EXIT_REFUSED)


def note(text):
    sys.stderr.write("NOTE: " + text + "\n")


def say(text):
    sys.stdout.write(text + "\n")


def q(text):
    """TEXT as one shell word, for a path or a name in a printed command:
    a folder like `/srv/x; curl ... #` must not run more when pasted."""
    import shlex
    return shlex.quote(str(text))


def installer_prog(installer):
    """This installer, as the operator runs it from where they typed the
    command: `bash install-release.sh` there, or its path from elsewhere."""
    if installer == "quickstart":
        return "scripts/quickstart.sh"
    caller = os.environ.get("LC_CALLER_DIR") or ""
    self_dir = os.environ.get("LC_SELF_DIR") or ""
    if not caller or not self_dir or same_path(caller, self_dir):
        return "bash install-release.sh"
    return "bash %s/install-release.sh" % q(self_dir)


def installer_cmd(installer):
    """This run again, as the operator types it (with its --upgrade DIR);
    flags are appended to it."""
    cmd = installer_prog(installer)
    target = os.environ.get("LC_UPGRADE_DIR") or ""
    if installer != "quickstart" and target:
        cmd += " --upgrade " + q(os.path.realpath(os.path.expanduser(target)))
    return cmd


def elsewhere():
    """True when this run works in another folder than the one the operator
    typed the command in (the automatic path, --upgrade DIR)."""
    caller = os.environ.get("LC_CALLER_DIR") or ""
    return bool(caller) and not same_path(caller, os.getcwd())


def here(cmd):
    """CMD, which reads this install folder's files, as the operator types it."""
    return "cd %s && %s" % (q(os.getcwd()), cmd) if elsewhere() else cmd


def lifecycle_cmd(args, d=None):
    """--status, --resume or --abort for the install in D (default: this
    folder), with the installer the operator just ran: the install folder
    may still hold an older one that has none of them."""
    d = os.path.realpath(d or os.getcwd())
    caller = os.environ.get("LC_CALLER_DIR") or ""
    if not caller or same_path(caller, d):
        return "bash install-release.sh " + args
    return "%s %s %s" % (installer_prog("release"), args, q(d))


# ── dotenv, read as docker compose reads it ─────────────────────────────

ASSIGN = re.compile(r"[ \t]*(export[ \t]+)?([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*[=:][ \t]*")


class Assign(object):
    """One assignment: value text[start:end] (None when unreadable)."""

    __slots__ = ("name", "value", "start", "end", "name_start", "name_end",
                 "line_start", "line_end", "quote", "export", "odd")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    def __repr__(self):
        return "Assign(%s)" % ", ".join("%s=%r" % (k, getattr(self, k)) for k in self.__slots__)


def parse_dotenv(text):
    """The loop of repair_mfa_key: `export ` allowed, quotes, " #" comments.

    Returns every assignment in order; compose uses the last one of a
    name. An unterminated quote ends the file (value None, odd).
    """
    out = []
    pos, n = 0, len(text)
    while pos < n:
        line_start = pos
        eol = text.find("\n", pos)
        eol = n if eol < 0 else eol
        m = ASSIGN.match(text, pos, eol)
        if not m:
            pos = eol + 1
            continue
        v = m.end()
        common = dict(name=m.group(2), name_start=m.start(2), name_end=m.end(2),
                      line_start=line_start, export=bool(m.group(1)))
        if v < eol and text[v] in "'\"":
            quote, k = text[v], v + 1
            while k < n and text[k] != quote:
                k += 2 if text[k] == "\\" else 1
            if k >= n:
                out.append(Assign(value=None, start=v, end=n, line_end=n, quote=quote,
                                  odd=True, **common))
                break
            start, end = v + 1, k
            nxt = text.find("\n", k)
            line_end = n if nxt < 0 else nxt
            pos = n if nxt < 0 else nxt + 1
            body = text[start:end]
            odd = "\n" in body or (quote == '"' and ("\\" in body or "$" in body)) or (
                quote == "'" and "\\" in body)
        else:
            value = text[v:eol].rstrip("\r")
            cut = value.find(" #")
            value = value[:cut] if cut >= 0 else value
            start, end = v, v + len(value.rstrip(" \t"))
            line_end = eol
            pos = eol + 1
            quote = ""
            odd = "$" in text[start:end]
        out.append(Assign(value=None if odd else text[start:end], start=start, end=end,
                          line_end=line_end, quote=quote, odd=odd, **common))
    return out


def env_effective(text):
    """{name: value} of the last assignments; None for an unreadable one."""
    eff = {}
    for a in parse_dotenv(text or ""):
        eff[a.name] = a.value
    return eff


def last_assign(text, name):
    found = None
    for a in parse_dotenv(text or ""):
        if a.name == name:
            found = a
    return found


def read_text(path):
    try:
        with open(path, newline="") as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        return None


def first_line(path):
    text = read_text(path)
    return text.split("\n", 1)[0] if text else ""


# ── secrets: the shared MFA rule, fingerprints, comparison ───────────────


def mfa_valid(key):
    key = (key or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_+/-]{43}=", key):
        return False
    try:
        raw = base64.b64decode(key.replace("-", "+").replace("_", "/"), validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(raw) == 32


def mfa_bytes(key):
    return base64.b64decode(key.strip().replace("-", "+").replace("_", "/"), validate=True)


def same_secret(name, a, b):
    a, b = (a or "").strip(), (b or "").strip()
    if name in ("BRIDGE_MFA_KEY", "BRIDGE_KEYSTORE_KEY") and mfa_valid(a) and mfa_valid(b):
        return mfa_bytes(a) == mfa_bytes(b)
    return a == b


def fernet_key():
    return base64.urlsafe_b64encode(os.urandom(32)).decode()


def token():
    import secrets
    return secrets.token_urlsafe(32)


def dotenv_value(value):
    """`value` written so that docker compose reads it back unchanged."""
    if re.fullmatch(r"[A-Za-z0-9_+/=.:,@%-]*", value):
        return value
    if "'" not in value and "\n" not in value:
        return "'" + value + "'"
    return json.dumps(value.replace("$", "$$"), ensure_ascii=False)


# ── Docker ──────────────────────────────────────────────────────────────


class DockerError(Exception):
    def __init__(self, what, rc):
        Exception.__init__(self, what)
        self.what, self.rc = what, rc


def docker(*args, **kw):
    """`docker ARGS` with output captured (bytes). Never raises."""
    timeout = kw.pop("timeout", DOCKER_TIMEOUT)
    try:
        return subprocess.run(["docker"] + list(args), capture_output=True,
                              timeout=timeout, **kw)
    except (OSError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(["docker"] + list(args), 125, b"",
                                           str(e).encode())


def docker_lines(what, *args):
    r = docker(*args)
    if r.returncode:
        raise DockerError(what, r.returncode)
    return r.stdout.decode("utf-8", "replace").splitlines()


def derive_project(dir_path):
    """Docker Compose's own rule for a folder's project name."""
    base = os.path.basename(os.path.normpath(dir_path)).lower()
    return "".join(re.findall(r"[a-z0-9_-]", base)).lstrip("_-")


def valid_project(name):
    return bool(name) and bool(PROJECT_RE.fullmatch(name))


def compose_env(without_shell=True):
    env = dict(os.environ)
    if without_shell:
        env.pop("COMPOSE_PROJECT_NAME", None)
    return env


def compose_name(dir_path, without_shell=True):
    """`.name` of `docker compose config` in dir_path, or None."""
    r = docker("compose", "config", "--format", "json", cwd=dir_path,
               env=compose_env(without_shell))
    if r.returncode:
        return None
    try:
        name = json.loads(r.stdout.decode("utf-8", "replace") or "{}").get("name")
    except (ValueError, AttributeError):
        return None
    return name if isinstance(name, str) and valid_project(name) else None


def compose_honours_env_pin(dir_path, name):
    """(ok, got): does Compose take COMPOSE_PROJECT_NAME from an env file?

    Asked in a throwaway folder whose own name gives another project, with
    an env file and a compose file that hold nothing but the name (so no
    secret is involved): only a Compose that reads the env file answers
    NAME. dir_path is where the pin will be written (unused by the probe).
    """
    import tempfile
    tmp = tempfile.mkdtemp(prefix="sigrift-pin-probe-")
    env_file = os.path.join(tmp, "pin.env")
    probe = os.path.join(tmp, "probe.yml")
    try:
        with open(env_file, "w") as f:
            f.write("COMPOSE_PROJECT_NAME=%s\n" % name)
        with open(probe, "w") as f:
            f.write("services:\n  probe:\n    image: scratch\n")
        env = compose_env(True)
        env.pop("COMPOSE_FILE", None)
        r = docker("compose", "--project-directory", tmp, "-f", probe, "--env-file", env_file,
                   "config", "--format", "json", cwd=tmp, env=env)
        got = None
        if r.returncode == 0:
            try:
                got = json.loads(r.stdout.decode("utf-8", "replace") or "{}").get("name")
            except (ValueError, AttributeError):
                got = None
        return got == name, got
    finally:
        for p in (env_file, probe):
            try:
                os.unlink(p)
            except OSError:
                pass
        os.rmdir(tmp)


def list_volumes():
    """[(name, project, compose volume)] of every Compose-made volume."""
    fmt = '{{.Name}}\t{{.Label "%s"}}\t{{.Label "%s"}}' % (PROJECT_LABEL, VOLUME_LABEL)
    rows = []
    for line in docker_lines("docker volume ls", "volume", "ls", "--filter",
                             "label=" + VOLUME_LABEL, "--format", fmt):
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0]:
            rows.append((parts[0], parts[1], parts[2]))
    return rows


class Container(object):
    __slots__ = ("id", "name", "project", "service", "working_dir", "state",
                 "image", "mounts", "ports")

    def __init__(self, parts):
        parts = (parts + [""] * 9)[:9]
        (self.id, self.name, self.project, self.service, self.working_dir,
         self.state, self.image, mounts, self.ports) = parts
        self.mounts = [m.strip() for m in mounts.split(",") if m.strip()]


def list_containers():
    fmt = "\t".join([
        "{{.ID}}", "{{.Names}}", '{{.Label "%s"}}' % PROJECT_LABEL,
        '{{.Label "%s"}}' % SERVICE_LABEL, '{{.Label "%s"}}' % WORKDIR_LABEL,
        "{{.State}}", "{{.Image}}", "{{.Mounts}}", "{{.Ports}}"])
    return [Container(line.split("\t")) for line in docker_lines(
        "docker ps -a", "ps", "-a", "--filter", "label=" + PROJECT_LABEL,
        "--format", fmt) if line.strip()]


# Every container the lifecycle tool starts carries this label, so its own
# short reads of a volume (the engine, the helper) are never taken for
# another writer of the data (stop-project, foreign-mounts).
LIFECYCLE_LABEL = "com.sigrift.lifecycle"
RECORD_MAX = 65536
RECORD_STR = ("install_id", "project", "working_dir", "host_id", "install_type",
              "installer_version", "first_version", "last_version", "updated_at")


def helper_run_args(kind, user=None):
    """`docker run` options of a short helper or engine container: no
    network, no daemon log copy, the lifecycle label, no privilege gain."""
    args = ["run", "--rm", "--log-driver", "none", "--network", "none",
            "--label", "%s=%s" % (LIFECYCLE_LABEL, kind),
            "--security-opt", "no-new-privileges"]
    if user:
        args += ["--user", user, "--cap-drop", "ALL"]
    return args


def valid_record(rec):
    """The volume record, or None. The bridge and the gateway can write
    bridge_data, so its fields are hints: checked for type here, and a
    folder it names is never a target by itself (classify_host)."""
    if not isinstance(rec, dict):
        return None
    for k in RECORD_STR:
        if rec.get(k) is not None and not isinstance(rec[k], str):
            return None
    if rec.get("project") and not valid_project(rec["project"]):
        return None
    if rec.get("working_dir") and not os.path.isabs(rec["working_dir"]):
        return None
    return rec


def read_volume_record(volume, helper):
    """bridge_data/.sigrift-install.json of a volume (no secrets in it),
    read as the bridge's uid with no capabilities, at most RECORD_MAX bytes."""
    if not helper:
        return None
    r = docker(*(helper_run_args("record", "1500:1500") + [
        "-v", volume + ":/v:ro", helper, "head", "-c", str(RECORD_MAX + 1),
        "/v/" + VOLUME_RECORD]))
    if r.returncode or len(r.stdout) > RECORD_MAX:
        return None
    try:
        rec = json.loads(r.stdout.decode("utf-8", "replace"))
    except ValueError:
        return None
    return valid_record(rec)


def container_env(container_id):
    """The environment a container runs with (kept in this process only)."""
    if not container_id:
        return None
    r = docker("inspect", "--format", "{{json .Config.Env}}", container_id)
    if r.returncode:
        return None
    try:
        items = json.loads(r.stdout.decode("utf-8", "replace"))
    except ValueError:
        return None
    env = {}
    for item in items or []:
        k, sep, v = str(item).partition("=")
        if sep:
            env[k] = v
    return env


def image_present(ref):
    if not ref:
        return False
    r = docker("image", "inspect", "--format", "{{.Id}}", ref)
    return r.returncode == 0 and bool(r.stdout.strip())


# ── which installs are on this host ─────────────────────────────────────


def same_path(a, b):
    try:
        return os.path.realpath(a) == os.path.realpath(b)
    except (TypeError, ValueError):
        return False


class Project(object):
    def __init__(self, name):
        self.name = name
        self.valid = valid_project(name)
        self.volumes = {}
        self.containers = []
        self.record = None
        # The folder: from Compose's working_dir labels (set by the daemon),
        # or from the volume record when that folder's own host record has
        # the same install id, or (folder_exists False) one the record names
        # that no longer exists. `hint`: a folder the record names that
        # exists but does not confirm it.
        self.folder = None
        self.folder_how = ""
        self.folder_exists = False
        self.hint = None
        self.kind = "unknown"
        self.version = "unknown"
        self.port = ""

    @property
    def has_data(self):
        return "bridge_data" in self.volumes

    def service(self, name):
        for c in self.containers:
            if c.service == name:
                return c
        return None

    @property
    def state(self):
        if any(c.state == "running" for c in self.containers):
            return "running"
        return "stopped" if self.containers else "down"

    def line(self):
        port = ("port " + self.port) if self.port else "port unknown"
        folder = self.folder or "(folder not known)"
        if self.folder and not self.folder_exists:
            folder += " (gone)"
        if self.hint:
            folder += " (its volume record names %s, which does not confirm it)" % self.hint
        name = self.name if self.valid else "%s (invalid name)" % self.name[:60]
        return "%s  %s, %s, %s  %s" % (name, self.version, self.state, port, folder)

    def owned_by(self, d):
        """Compose labelled one of its containers with folder D."""
        return any(c.working_dir and same_path(c.working_dir, d) for c in self.containers)


def host_record(dir_path):
    text = read_text(os.path.join(dir_path, HOST_RECORD))
    if not text:
        return None
    try:
        rec = json.loads(text)
    except ValueError:
        return None
    return rec if isinstance(rec, dict) else None


def env_pin(dir_path):
    eff = env_effective(read_text(os.path.join(dir_path, ".env")) or "")
    return eff.get("COMPOSE_PROJECT_NAME") or ""


def compose_port(dir_path):
    text = read_text(os.path.join(dir_path, "docker-compose.yml")) or ""
    m = re.search(r"(?m)^\s*-\s*\"?(?:\$\{[^}]*\}|[0-9.\[\]:]+):(\d+):8444\"?", text)
    return m.group(1) if m else ""


def compose_owner(dir_path):
    text = read_text(os.path.join(dir_path, "docker-compose.yml")) or ""
    m = re.search(r"(?m)^\s+image:\s*ghcr\.io/([a-z0-9-]+)/sigrift-bridge:", text)
    return m.group(1) if m else None


def compose_bridge_image(dir_path):
    text = read_text(os.path.join(dir_path, "docker-compose.yml")) or ""
    m = re.search(r"(?m)^\s+image:\s*(ghcr\.io/[a-z0-9-]+/sigrift-bridge:\S+)", text)
    return m.group(1) if m else None


def installed_version(dir_path):
    v = (read_text(os.path.join(dir_path, "VERSION")) or "").strip()
    if VERSION_RE.fullmatch(v):
        return v
    text = read_text(os.path.join(dir_path, "docker-compose.yml")) or ""
    m = re.search(r"ghcr\.io/[a-z0-9-]+/sigrift-bridge:(\S+)", text)
    if m and VERSION_RE.fullmatch(m.group(1)):
        return m.group(1)
    journal = read_text(os.path.join(dir_path, STATE_DIR, "journal.json"))
    if journal:
        try:
            v = json.loads(journal).get("from_version") or ""
        except (ValueError, AttributeError):
            v = ""
        if VERSION_RE.fullmatch(v):
            return v
    return "unknown"


def version_key(v):
    m = TAG.fullmatch(v or "")
    if not m:
        return None
    rc = int(m.group(4)) if m.group(4) is not None else float("inf")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), rc)


def version_cmp(a, b):
    """-1, 0, 1 for vX.Y.Z[-rcN] (an rc before its release); None otherwise."""
    ka, kb = version_key(a), version_key(b)
    if ka is None or kb is None:
        return None
    return (ka > kb) - (ka < kb)


def is_release_tag(v):
    return version_key(v) is not None


def project_kind(p):
    # The folder's own files first; the volume record (writable by the
    # containers) only when there is no folder to look at.
    if p.folder_exists:
        hr = host_record(p.folder) or {}
        if hr.get("install_type") in ("release", "source"):
            return hr["install_type"]
        head = first_line(os.path.join(p.folder, "docker-compose.yml"))
        if head.startswith(RELEASE_HEADER) or head.startswith(HOLD_HEADER):
            return "release"
        if os.path.exists(os.path.join(p.folder, "scripts", "quickstart.sh")) or \
                os.path.exists(os.path.join(p.folder, ".git")):
            return "source"
    rec = p.record or {}
    if rec.get("install_type") in ("release", "source"):
        return rec["install_type"]
    bridge = p.service("bridge")
    if bridge:
        if re.match(r"ghcr\.io/[a-z0-9-]+/sigrift-bridge:", bridge.image):
            return "release"
        if re.match(re.escape(p.name) + r"-bridge(:|$)", bridge.image):
            return "source"
    return "unknown"


def container_port(p):
    gw = p.service("gateway")
    for c in ([gw] if gw else []) + p.containers:
        m = re.search(r":(\d+)->8444/", c.ports or "")
        if m:
            return m.group(1)
    return ""


def classify_host(helper, volumes=None):
    projects = {}
    for name, proj, vol in (list_volumes() if volumes is None else volumes):
        if proj:
            projects.setdefault(proj, Project(proj)).volumes.setdefault(vol, name)
    containers = list_containers()
    for c in containers:
        if c.project:
            projects.setdefault(c.project, Project(c.project)).containers.append(c)
    for p in projects.values():
        if not p.has_data:
            continue
        bridge = p.service("bridge")
        dirs = [c.working_dir for c in p.containers if c.working_dir]
        if bridge and bridge.working_dir:
            p.folder, p.folder_how = bridge.working_dir, "labels"
        elif dirs:
            p.folder, p.folder_how = dirs[0], "labels"
        if not p.containers and p.valid:
            p.record = read_volume_record(p.volumes["bridge_data"], helper)
            hint = (p.record or {}).get("working_dir")
            if hint and not p.folder:
                hr = host_record(hint) if os.path.isdir(hint) else None
                if not os.path.isdir(hint):
                    p.folder, p.folder_how = hint, "record"
                elif hr and hr.get("install_id") and \
                        hr.get("install_id") == p.record.get("install_id"):
                    p.folder, p.folder_how = hint, "record"
                else:
                    p.hint = hint
        p.folder_exists = bool(p.folder) and os.path.isdir(p.folder)
        p.kind = project_kind(p)
        if p.folder_exists:
            p.version = installed_version(p.folder)
            p.port = compose_port(p.folder) or container_port(p)
        else:
            p.port = container_port(p)
        if p.version == "unknown" and p.record:
            p.version = p.record.get("last_version") or "unknown"
        if p.version == "unknown" and bridge and ":" in bridge.image:
            tag = bridge.image.rsplit(":", 1)[1]
            if VERSION_RE.fullmatch(tag):
                p.version = tag
    return projects, containers


# ── ports ───────────────────────────────────────────────────────────────


def port_published(port, containers):
    for c in containers:
        if re.search(r":%s->" % re.escape(str(port)), c.ports or ""):
            return c.name
    return None


def port_bindable(port, bind):
    host = (bind or "127.0.0.1").strip("[]")
    import socket
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    try:
        s.bind((host, int(port)))
        return True
    except OSError as e:
        return e.errno != errno.EADDRINUSE
    finally:
        s.close()


def port_free(port, bind, containers):
    return port_published(port, containers) is None and port_bindable(port, bind)


def suggest_port(port, bind, containers):
    for p in range(int(port) + 1, int(port) + 101):
        if p < 65536 and port_free(p, bind, containers):
            return str(p)
    return "<free port>"


# ── atomic files ────────────────────────────────────────────────────────


def owner_for(path):
    """(uid, gid) for a file or folder this run creates at PATH while it
    runs as root (sudo), else None: the file it replaces, else its folder.
    A root-owned .env or .sigrift/ would lock the operator's own later
    runs (and cron's --renew-tls) out."""
    if os.geteuid() != 0:
        return None
    for ref in (path, os.path.dirname(os.path.abspath(path))):
        try:
            st = os.lstat(ref)
        except OSError:
            continue
        if not stat.S_ISLNK(st.st_mode):
            return st.st_uid, st.st_gid
    return None


def give_owner(target, ids):
    """chown TARGET (a path or an open fd) to IDS from owner_for."""
    if not ids:
        return
    try:
        if isinstance(target, int):
            os.fchown(target, ids[0], ids[1])
        else:
            os.lchown(target, ids[0], ids[1])
    except OSError:
        pass


def fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_write(path, data, mode):
    """temp file, fsync, rename, directory fsync."""
    d = os.path.dirname(os.path.abspath(path))
    ids = owner_for(path)
    import tempfile
    fd, tmp = tempfile.mkstemp(prefix="." + os.path.basename(path) + ".", suffix=".tmp", dir=d)
    try:
        give_owner(fd, ids)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    fsync_dir(d)


def ensure_state_dir(dir_path):
    path = os.path.join(dir_path, STATE_DIR)
    if not os.path.isdir(path):
        os.mkdir(path, 0o700)
        give_owner(path, owner_for(dir_path))
    os.chmod(path, 0o700)
    return path


def write_host_record(dir_path, rec):
    ensure_state_dir(dir_path)
    data = (json.dumps(rec, indent=2, sort_keys=True) + "\n").encode()
    atomic_write(os.path.join(dir_path, HOST_RECORD), data, 0o644)


def now_utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def backup_path(path):
    stamp, n = time.strftime("%Y%m%d-%H%M%S"), 0
    backup = "%s.bak.%s~" % (path, stamp)
    while os.path.lexists(backup):
        n += 1
        backup = "%s.bak.%s.%d~" % (path, stamp, n)
    return backup


def write_new_text(path, old, new):
    """One edit: 0600 backup of the old text, temp file, rename. -> backup."""
    backup = backup_path(path)
    tmp = path + ".tmp"
    ids = owner_for(path)
    for target, data in ((backup, old), (tmp, new)):
        if os.path.lexists(target):
            os.unlink(target)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        give_owner(fd, ids)
        with os.fdopen(fd, "w", newline="") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    os.replace(tmp, path)
    fsync_dir(os.path.dirname(os.path.abspath(path)))
    return backup


# ── the engine, run in the stack's own bridge image ─────────────────────


def project_volumes(project, volumes=None):
    rows = volumes if volumes is not None else list_volumes()
    return {vol: name for name, proj, vol in rows if proj == project}


def engine_record(data):
    return str(len(data)).encode("ascii") + b"\n" + data


def build_candidates(env_file, bridge_id, env_only=False):
    eff = env_effective(read_text(env_file) or "") if env_file else {}
    env_c = dict((k, eff[k]) for k in CANDIDATE_KEYS if eff.get(k))
    cands = {"env": env_c, "container": None, "shell": None}
    if env_only:
        return cands
    cenv = container_env(bridge_id) if bridge_id else None
    if cenv is not None:
        cont = dict((k, cenv[k]) for k in CANDIDATE_KEYS if cenv.get(k))
        cands["container"] = {"same_as": "env"} if cont == env_c else cont
    shell = dict(env_c)
    for k in CANDIDATE_KEYS:
        if k in os.environ:
            if os.environ[k]:
                shell[k] = os.environ[k]
            else:
                shell.pop(k, None)
    if shell != env_c:
        cands["shell"] = shell
    return cands


def run_engine(image, project, op, source, extra=None, volumes=None):
    """Run engine OP in IMAGE with the project's volumes; -> reply dict.

    The request (which may hold secrets) goes in on stdin, as length-
    prefixed records after the engine source; argv and the container's
    environment hold none, and --log-driver none keeps the daemon from
    storing a copy of the output.
    """
    data_dir = os.environ.get("LC_ENGINE_DATA_DIR") or "/app/src/sigrift/bridge/data"
    bootstrap = os.environ.get("LC_ENGINE_BOOTSTRAP") or ""
    if not image or not bootstrap or not source:
        return {"format": 1, "ok": False, "error": "no bridge image or engine to run"}
    args = helper_run_args("engine", "1500:1500") + ["-i", "--entrypoint", "python3"]
    if project:
        vols = project_volumes(project, volumes)
        if "bridge_data" in vols:
            args += ["-v", vols["bridge_data"] + ":" + data_dir]
        if "bridge_secrets" in vols:
            args += ["-v", vols["bridge_secrets"] + ":/app/secrets:ro"]
    args += [image, "-c", bootstrap]
    req = {"format": 1, "op": op, "data_dir": data_dir}
    req.update(extra or {})
    payload = engine_record(source) + engine_record(json.dumps(req).encode())
    r = docker(*args, input=payload, timeout=ENGINE_TIMEOUT)
    try:
        reply = json.loads(r.stdout.decode("utf-8", "replace") or "null")
    except ValueError:
        reply = None
    if not isinstance(reply, dict):
        return {"format": 1, "ok": False,
                "error": "the engine gave no answer (docker run exited %d)" % r.returncode}
    if r.returncode and reply.get("ok"):
        reply = {"format": 1, "ok": False, "error": "docker run exited %d" % r.returncode}
    return reply


def read_fd3():
    try:
        with os.fdopen(3, "rb") as f:
            return f.read()
    except OSError:
        return b""


def facts_for(project, env_file, bridge_id, image, source, volumes=None, env_only=False):
    extra = {"candidates": build_candidates(env_file, bridge_id, env_only)}
    return run_engine(image, project, "facts", source, extra, volumes)


def load_facts(text=None):
    """The engine's facts this run holds in LC_FACTS_JSON, or None."""
    text = os.environ.get("LC_FACTS_JSON", "") if text is None else text
    try:
        facts = json.loads(text) if text else None
    except ValueError:
        return None
    return facts if isinstance(facts, dict) and facts.get("ok") else None


def facts_known(facts):
    """The engine read the database (or found none): its counts hold. An
    encrypted database or a failed query leaves them unknown, which every
    rule treats as "data may depend on it", never as "no rows"."""
    db = (facts or {}).get("db") or {}
    return bool(facts) and not db.get("encrypted") and not db.get("error")


def counts(facts, key):
    if not facts_known(facts):
        return None
    v = (facts.get("counts") or {}).get(key)
    return v if isinstance(v, int) else None


def candidate(facts, source):
    """The engine's verdicts for candidate SOURCE (same_as resolved)."""
    if not facts:
        return None
    cands = facts.get("candidates") or {}
    c = cands.get(source)
    seen = 0
    while isinstance(c, dict) and c.get("same_as") and seen < 3:
        c = cands.get(c["same_as"])
        seen += 1
    return c if isinstance(c, dict) else None


# ── consistency between this folder's .env and a project's data ─────────


def consistency(facts, host_rec, vol_rec):
    """(contradiction or None, proofs) for adopting a project's data."""
    proofs = []
    host_rec, vol_rec = host_rec or {}, vol_rec or (facts or {}).get("record") or {}
    hid, vid = host_rec.get("install_id"), vol_rec.get("install_id")
    if hid and vid:
        if hid != vid:
            return "its volume record names another install", proofs
        proofs.append("same install id")
    env = candidate(facts, "env") or {}
    fps = env.get("fingerprints") or {}
    rec_fps = vol_rec.get("fingerprints") or {}
    for name, var in (("audit", "BRIDGE_AUDIT_KEY"), ("mfa", "BRIDGE_MFA_KEY"),
                      ("keystore", "BRIDGE_KEYSTORE_KEY")):
        want = rec_fps.get(name)
        if isinstance(want, dict):
            want = want.get("fp")
        have = fps.get(name)
        if want and have:
            if want != have:
                return "%s does not match its volume record" % var, proofs
            proofs.append("%s matches its volume record" % var)
    mfa = env.get("mfa")
    if mfa == "fail":
        return "BRIDGE_MFA_KEY does not verify its TOTP secrets", proofs
    if mfa == "ok":
        proofs.append("TOTP secrets verify")
    audit = env.get("audit") or {}
    rows = counts(facts, "audit_rows") or 0
    # Only a key from this folder's .env says anything about this folder:
    # without one the engine checks the volume's own audit.key ("file").
    mine = audit.get("source") in ("env-key", "legacy-secret", "master")
    if audit.get("result") == "fail" and rows > 0 and mine:
        return "BRIDGE_AUDIT_KEY does not verify its audit chain", proofs
    if audit.get("result") == "ok" and mine:
        proofs.append("audit chain verifies")
    return None, proofs


def match_summary(facts):
    env = candidate(facts, "env") or {}
    mfa = {"ok": "yes", "fail": "no"}.get(env.get("mfa"), "n.a.")
    audit = {"ok": "yes", "fail": "no"}.get((env.get("audit") or {}).get("result"), "n.a.")
    return "TOTP key %s, audit key %s" % (mfa, audit)


# ── identity: which folder and project this run acts on ─────────────────


DECISION_KEYS = ("LC_KIND", "LC_TARGET_DIR", "LC_PROJECT", "LC_PROJECT_HOW", "LC_PIN",
                 "LC_AUTO", "LC_HAS_DATA", "LC_FROM_VERSION", "LC_MOVED_FROM",
                 "LC_INSTALL_ID", "LC_BRIDGE_CONTAINER", "LC_GATEWAY_CONTAINER",
                 "LC_WAS_RUNNING", "LC_OTHERS", "LC_PORT", "LC_ADOPTED_FROM",
                 "LC_PROOF")


class Ctx(object):
    pass


def parse_flags(argv, spec):
    """--name VALUE / --name=VALUE / --flag; spec maps name -> takes value."""
    out, i = {}, 0
    while i < len(argv):
        arg = argv[i]
        name, sep, value = arg.partition("=")
        if not name.startswith("--") or name[2:] not in spec:
            sys.exit("lc_tool: unknown argument %r" % arg)
        key = name[2:].replace("-", "_")
        if spec[name[2:]]:
            if not sep:
                i += 1
                if i >= len(argv):
                    sys.exit("lc_tool: %s needs a value" % name)
                value = argv[i]
            out[key] = value
        else:
            out[key] = True
        i += 1
    return out


def folder_kind(d, installer):
    env = os.path.lexists(os.path.join(d, ".env"))
    head = first_line(os.path.join(d, "docker-compose.yml"))
    if head.startswith(HOLD_HEADER):
        return "held"
    if installer == "quickstart":
        return "existing" if env else "new"
    has_compose = os.path.lexists(os.path.join(d, "docker-compose.yml"))
    if not env and not has_compose:
        return "new"
    return "existing" if env else "partial"


def is_checkout(d):
    return os.path.exists(os.path.join(d, ".git")) or \
        os.path.exists(os.path.join(d, "scripts", "quickstart.sh"))


def install_list(projects, exclude=()):
    return [p.line() for p in sorted(projects, key=lambda p: p.name) if p.name not in exclude]


def decision(c, **kw):
    d = dict((k, "") for k in DECISION_KEYS)
    d.update({"LC_PIN": "0", "LC_AUTO": "0", "LC_HAS_DATA": "0", "LC_WAS_RUNNING": "0",
              "LC_FROM_VERSION": "unknown"})
    d.update(kw)
    p = c.projects.get(d["LC_PROJECT"])
    if p is not None:
        bridge, gateway = p.service("bridge"), p.service("gateway")
        d["LC_BRIDGE_CONTAINER"] = bridge.id if bridge else ""
        d["LC_GATEWAY_CONTAINER"] = gateway.id if gateway else ""
        d["LC_WAS_RUNNING"] = "1" if p.state == "running" else "0"
        if p.has_data:
            d["LC_HAS_DATA"] = "1"
    target = d["LC_TARGET_DIR"]
    if target and d["LC_KIND"] != "new":
        d["LC_FROM_VERSION"] = installed_version(target)
        hr = host_record(target) or {}
        d["LC_INSTALL_ID"] = d["LC_INSTALL_ID"] or hr.get("install_id") or ""
        if c.installer == "release":
            d["LC_PORT"] = d["LC_PORT"] or compose_port(target)
    others = [q for q in c.installs if q.name != d["LC_PROJECT"]]
    d["LC_OTHERS"] = "; ".join(install_list(others))
    return d


def check_port(c, port):
    """Refuse M-PORT-BUSY unless PORT is free for a new stack."""
    by = port_published(port, c.containers)
    if by or not port_bindable(port, c.bind):
        free = suggest_port(port, c.bind, c.containers)
        refuse("port %s is already in use%s, so a second stack cannot use it." % (
            port, " (published by container %s)" % by if by else ""),
            next_cmd="UC_PORT=%s %s --new-instance" % (free, c.prog))


def free_port_for(c, port):
    return port if port_free(port, c.bind, c.containers) else suggest_port(port, c.bind, c.containers)


def engine_image(installer, owner, version, bridge_id, folders, project):
    """A local bridge image to read a project's data with, or ''.

    The running (or stopped) bridge's own image first, then the bridge
    image a folder's compose file names, then the one this run installs.
    """
    if bridge_id:
        r = docker("inspect", "--format", "{{.Image}}", bridge_id)
        image = r.stdout.decode("utf-8", "replace").strip() if r.returncode == 0 else ""
        if image:
            return image
    refs = [compose_bridge_image(f) for f in folders if f]
    if installer == "quickstart" and project:
        refs.append(project + "-bridge")
    if installer == "release" and owner and VERSION_RE.fullmatch(version or ""):
        refs.append("ghcr.io/%s/sigrift-bridge:%s" % (owner, version))
    for ref in refs:
        if ref and image_present(ref):
            return ref
    return ""


def candidate_facts(c, p, d):
    """The engine's verdict on this folder's .env against the data of P, a
    project this folder does not own yet: only .env's values go to it (not
    the shell's or a container's), since that data may be anyone's."""
    if c.source is None:
        c.source = read_fd3()
    cache = c.__dict__.setdefault("facts_cache", {})
    if p.name in cache:
        return cache[p.name]
    bridge = p.service("bridge")
    image = engine_image(c.installer, c.owner, c.version, bridge.id if bridge else "",
                         [d, p.folder if p.folder_exists else None], p.name)
    facts = facts_for(p.name, os.path.join(d, ".env"), "", image, c.source, c.volumes,
                      env_only=True)
    cache[p.name] = facts if facts.get("ok") else None
    return cache[p.name]


def docker_root():
    """Docker's own data folder on this host (volumes live under it), or ''."""
    r = docker("info", "--format", "{{.DockerRootDir}}")
    text = r.stdout.decode("utf-8", "replace").strip() if r.returncode == 0 else ""
    return os.path.realpath(text) if text.startswith("/") else ""


def private_group(st):
    """The group of ST is its owner's own primary group and has no other
    member (a user private group: umask 002 makes such folders 0775)."""
    try:
        import grp
        import pwd
        pw = pwd.getpwuid(st.st_uid)
        if pw.pw_gid != st.st_gid:
            return False
        return not [m for m in grp.getgrgid(st.st_gid).gr_mem if m != pw.pw_name]
    except (ImportError, KeyError):
        return False


def folder_unsafe(d):
    """Why folder D is not upgraded without being named, or None. The run
    goes on in D with docker's power (its compose file, its .env), so they
    must belong to whoever runs this (or root), nobody else may be able to
    change them, and no folder inside Docker's own data qualifies: the
    folder came from a label or record, not from the operator."""
    allowed = {os.geteuid(), 0}
    if os.geteuid() == 0 and (os.environ.get("SUDO_UID") or "").isdigit():
        allowed.add(int(os.environ["SUDO_UID"]))
    root = docker_root()
    real = os.path.realpath(d)
    if root and root != "/" and (real == root or real.startswith(root.rstrip("/") + "/")):
        return "it is inside Docker's own data folder (%s)" % root
    for path in (d, os.path.join(d, ".env"), os.path.join(d, "docker-compose.yml")):
        try:
            st = os.stat(path)
        except OSError:
            continue
        if st.st_uid not in allowed:
            return "%s belongs to uid %d, not to the user running this" % (path, st.st_uid)
        if st.st_mode & stat.S_IWOTH:
            return "every user on this host can change %s" % path
        if st.st_mode & stat.S_IWGRP and not private_group(st):
            return "group %d can change %s" % (st.st_gid, path)
    return None


def auto_target(c, p):
    """The one release install P that a run from a newly unpacked folder
    upgrades without being told: this installer must have a release
    version, P's folder must be a release install folder, and safe to run
    docker compose in."""
    if not is_release_tag(c.version):
        refuse("this installer has no release version (it would install the moving "
               ":main images), so it does not upgrade %s by itself." % p.folder,
               next_cmd="SIGRIFT_VERSION=vX.Y.Z %s --upgrade %s" % (c.prog, q(p.folder)))
    validate_target(c, p.folder)
    why = folder_unsafe(p.folder)
    if why:
        refuse("this host has one SigRift release install, in %s, but %s, so this run does "
               "not upgrade it without being told." % (p.folder, why),
               ["Check that folder; to upgrade it anyway, name it with --upgrade."],
               next_cmd="%s --upgrade %s" % (c.prog, q(p.folder)))
    return decide_existing(c, p.folder, auto=True)


def decide_new(c):
    d = c.self_dir
    shell = c.shell_project
    if shell:
        p = c.projects.get(shell)
        if p and p.has_data:
            if c.installer == "release" and p.valid and p.kind == "release" and \
                    p.folder_exists and not same_path(p.folder, d):
                return auto_target(c, p)
            refuse("COMPOSE_PROJECT_NAME=%s in your shell names an existing SigRift install "
                   "whose folder is %s, not this one." % (
                       shell, p.folder if p.folder_exists else "not known"),
                   next_cmd="unset COMPOSE_PROJECT_NAME && " + c.cmd)
        check_port(c, c.port)
        return decision(c, LC_KIND="new", LC_TARGET_DIR=d, LC_PROJECT=shell,
                        LC_PROJECT_HOW="shell", LC_PIN="1", LC_PORT=c.port)
    derived = compose_name(d) or derive_project(d)
    own = c.projects.get(derived)
    if own and own.has_data and not c.new_instance and (
            not own.folder_exists or same_path(own.folder, d)):
        env_missing(c, derived, d)
    if c.new_instance:
        if own and (own.volumes or own.containers):
            refuse("Docker Compose project %s already exists on this host (%s), so a new "
                   "install here would share its volumes." % (
                       derived, own.folder if own.folder_exists else "data only"),
                   next_cmd="COMPOSE_PROJECT_NAME=%s-2 %s --new-instance" % (derived, c.cmd))
        check_port(c, c.port)
        return decision(c, LC_KIND="new", LC_TARGET_DIR=d, LC_PROJECT=derived,
                        LC_PROJECT_HOW="derived", LC_PIN="1", LC_PORT=c.port)
    if not c.installs:
        return decision(c, LC_KIND="new", LC_TARGET_DIR=d, LC_PROJECT=derived,
                        LC_PROJECT_HOW="derived", LC_PIN="1", LC_PORT=c.port)
    if c.installer == "quickstart":
        second_stack_qs(c)
    targets = [p for p in c.installs if p.valid and p.kind == "release" and p.folder_exists
               and not same_path(p.folder, d)]
    if len(targets) == 1:
        return auto_target(c, targets[0])
    if len(targets) > 1:
        refuse("this host runs %d SigRift release installs, so this run cannot tell which "
               "one to upgrade." % len(targets), install_list(targets),
               next_cmd="%s --upgrade <one of the folders above>" % c.prog)
    lost = [p for p in c.installs if not p.folder_exists]
    if lost:
        details = ["%s  volumes %s; %s" % (p.name, ", ".join(sorted(p.volumes.values())),
                                          "folder %s is gone" % p.folder if p.folder else
                                          "no containers" + (
                                              "; its volume record names %s, which does "
                                              "not confirm it" % p.hint if p.hint else ""))
                   for p in sorted(lost, key=lambda p: p.name)]
        details.append("Name its folder (the one holding its .env and docker-compose.yml) "
                       "to upgrade it, or start a separate stack with --new-instance.")
        refuse("this host has SigRift data whose install folder is not known (its "
               "containers were removed, for example with docker compose down).", details,
               next_cmd="%s --upgrade /path/to/that/folder" % c.prog)
    sources = [p for p in c.installs if p.kind == "source"]
    free = free_port_for(c, c.port)
    if sources and len(sources) == len(c.installs):
        details = []
        for p in sorted(sources, key=lambda p: p.name):
            details.append("%s (source install, %s, port %s) in %s" % (
                p.name, p.state, p.port or "unknown", p.folder))
            details.append("A release install cannot upgrade it; update it in its folder: "
                           "cd %s && git pull && scripts/quickstart.sh" % q(p.folder))
        details.append("To run a separate release stack beside it on purpose, give it its own port:")
        refuse("this host already runs SigRift from a source checkout, so a release install "
               "here would be a second stack.", details,
               next_cmd="UC_PORT=%s %s --new-instance" % (free, c.prog))
    second_stack(c, free)


def second_stack(c, free):
    if c.installer == "quickstart":
        refuse("this checkout has no data yet and this host already runs SigRift, so "
               "starting it would make a second stack.", install_list(c.installs) + [
                   "To update an existing source install, run quickstart in its folder."],
               next_cmd="UC_PORT=%s scripts/quickstart.sh --new-instance" % free)
    refuse("this folder has no data yet and this host already runs SigRift, so starting "
           "it would make a second stack.", install_list(c.installs) + [
               "If you meant to upgrade one of them, run this installer with --upgrade and "
               "its folder."],
           next_cmd="UC_PORT=%s %s --new-instance" % (free, c.prog))


def second_stack_qs(c):
    free = free_port_for(c, c.port)
    refuse("this host already runs SigRift, so a fresh quickstart here would start a "
           "second, empty stack (with new secrets).", install_list(c.installs) + [
               "To update an existing source install, run quickstart in its folder."],
           next_cmd="UC_PORT=%s scripts/quickstart.sh --new-instance" % free)


def in_dir(d, cmd):
    """CMD, which reads folder D's files, as the operator types it where
    they ran the installer."""
    base = os.environ.get("LC_CALLER_DIR") or os.getcwd()
    return cmd if same_path(base, d) else "cd %s && %s" % (q(d), cmd)


def env_missing(c, project, d):
    refuse("there is no .env here, but project %s has data, which needs the secrets that "
           "were in it; new secrets would make its TOTP secrets and audit chain "
           "unreadable." % project, next_cmd=in_dir(d, "ls -la .env.bak.*~ .sigrift/snapshots/"))


def copy_refusal(c, orig, install_id=None):
    if install_id:
        msg = ("this folder is a copy of %s (same install id %s...), and both would drive "
               "the same stack and data." % (orig, install_id[:8]))
    else:
        msg = ("this folder and %s address the same Docker Compose project, so both would "
               "drive the same stack and data." % orig)
    refuse(msg, ["Run the installer on the original folder. For a separate install, unpack "
                 "a release into a new folder instead of copying one."],
           next_cmd=("cd %s && scripts/quickstart.sh" % q(orig)) if c.installer == "quickstart"
           else "%s --upgrade %s" % (c.prog, q(orig)))


def pin_ignored(got, nxt="docker compose version"):
    refuse("docker compose ignored COMPOSE_PROJECT_NAME from the env file (it used "
           "project %s), so pinning the project would not work." % (got or "none"),
           next_cmd=nxt)


def check_pin_honoured(c, d, name):
    if not valid_project(name):
        refuse("%s is not a valid Docker Compose project name, so it is not pinned."
               % name[:60], next_cmd="docker volume ls --filter "
               "label=com.docker.compose.volume=bridge_data")
    ok, got = compose_honours_env_pin(d, name)
    if not ok:
        pin_ignored(got)


def other_folder_using(c, p, d):
    """Another existing folder whose .env drives project P, or None."""
    for cont in p.containers:
        wd = cont.working_dir
        if wd and not same_path(wd, d) and os.path.isdir(wd) and \
                os.path.lexists(os.path.join(wd, ".env")):
            return wd
    if p.folder_how == "record" and p.folder_exists and not same_path(p.folder, d):
        return p.folder
    return None


def tied(p, d):
    """Compose labels or a confirmed volume record tie project P to folder D."""
    return p.owned_by(d) or (p.folder_how == "record" and p.folder_exists
                             and same_path(p.folder, d))


def adopt_flag(c, name):
    """--adopt-project NAME as this installer takes it."""
    if c.installer == "quickstart":
        return "--adopt-project=%s" % q(name)
    return "--adopt-project %s" % q(name)


def env_text(path, next_cmd):
    """The text of an install's .env ('' when it has none). Refuses one the
    installer cannot read (permissions, a byte that is not UTF-8): read as
    empty, a run would plan a new .env and drop every setting. Refuses a
    symbolic link too: an edit writes a new file and renames it over the
    link, and a restore point keeps only the link."""
    if not os.path.lexists(path):
        return ""
    if os.path.islink(path):
        refuse("%s is a symbolic link; the installer edits .env by writing a new file and "
               "renaming it, which would replace the link (and a restore point keeps only "
               "the link)." % path,
               ["Replace the link with a copy of the file it points to, then run this again."],
               next_cmd=next_cmd)
    text = read_text(path)
    if text is None:
        refuse("%s exists but cannot be read as UTF-8 text (its permissions, or a byte that "
               "is not UTF-8), so the installer cannot tell which keys it holds." % path,
               next_cmd=next_cmd)
    return text


def orphan_details(c, orphans, d):
    """The M-RENAMED candidates, best first; -> (details, best name)."""
    details = ["candidates (data no other folder uses):"]
    ranked = []
    for q_ in sorted(orphans, key=lambda x: x.name):
        facts = candidate_facts(c, q_, d)
        bad, proofs = consistency(facts, host_record(d), q_.record)
        ranked.append((0 if (not bad and proofs) else 1 if not bad else 2, q_.name))
        last = ("%s (gone)" % q_.folder) if q_.folder else (
            "unknown (its volume record names %s)" % q_.hint if q_.hint else "unknown")
        details.append("%s  last folder %s, %s; .env matches: %s" % (
            q_.name, last, q_.version, match_summary(facts)))
    return details, sorted(ranked)[0][1]


def decide_existing(c, d, auto=False):
    d = os.path.realpath(d)
    kind = folder_kind(d, c.installer)
    auto_flag = "1" if auto else "0"
    if kind == "held":
        project = (journal_load(d) or {}).get("project") or env_pin(d) or derive_project(d)
        return decision(c, LC_KIND="held", LC_TARGET_DIR=d, LC_PROJECT=project,
                        LC_PROJECT_HOW="pinned", LC_AUTO=auto_flag)
    eff = env_effective(env_text(os.path.join(d, ".env"), in_dir(d, "ls -l .env")))
    pin = eff.get("COMPOSE_PROJECT_NAME") or ""
    if "COMPOSE_PROJECT_NAME" in eff and eff["COMPOSE_PROJECT_NAME"] is None:
        refuse("COMPOSE_PROJECT_NAME in %s/.env is written in a way docker compose would "
               "expand (a $ or a backslash), so the installer cannot tell which project it "
               "names." % d, next_cmd="grep -n COMPOSE_PROJECT_NAME %s/.env" % q(d))
    if pin and not valid_project(pin):
        refuse("COMPOSE_PROJECT_NAME=%s in %s/.env is not a valid Docker Compose project "
               "name." % (pin[:60], d), next_cmd="grep -n COMPOSE_PROJECT_NAME %s/.env" % q(d))
    if kind == "partial":
        derived = compose_name(d) or derive_project(d)
        own = c.projects.get(derived)
        if own and own.has_data:
            env_missing(c, derived, d)
        return decision(c, LC_KIND="partial", LC_TARGET_DIR=d, LC_PROJECT=derived,
                        LC_PROJECT_HOW="derived", LC_PIN="1", LC_AUTO=auto_flag)
    if pin:
        if c.shell_project and c.shell_project != pin:
            refuse("COMPOSE_PROJECT_NAME in your shell (%s) differs from the project pinned "
                   "in .env (%s), so docker compose would address another stack." % (
                       c.shell_project, pin),
                   next_cmd="unset COMPOSE_PROJECT_NAME && " + c.cmd)
        hr = host_record(d)
        moved = ""
        if hr and hr.get("working_dir") and not same_path(hr["working_dir"], d):
            old = hr["working_dir"]
            other = host_record(old) if os.path.isdir(old) else None
            if other and other.get("install_id") and other.get("install_id") == hr.get("install_id"):
                copy_refusal(c, old, hr.get("install_id"))
            moved = old
        elif not hr:
            p = c.projects.get(pin)
            if p:
                for cont in p.containers:
                    wd = cont.working_dir
                    if wd and not same_path(wd, d) and os.path.isdir(wd) and env_pin(wd) == pin:
                        copy_refusal(c, wd)
        return decision(c, LC_KIND="existing", LC_TARGET_DIR=d, LC_PROJECT=pin,
                        LC_PROJECT_HOW="pinned", LC_PIN="0", LC_AUTO=auto_flag,
                        LC_MOVED_FROM=moved)
    # No pin yet: a v0.1.x install, a renamed folder, or a new .env. The
    # projects whose containers Compose labelled with this folder ran from
    # it, whatever name they were started under (a shell's
    # COMPOSE_PROJECT_NAME included).
    derived = compose_name(d) or derive_project(d)
    p = c.projects.get(derived)
    own_data = bool(p and p.has_data and (not p.folder_exists or same_path(p.folder, d)))
    owned = [x for x in c.installs if x.valid and x.owned_by(d)]
    shell = c.shell_project
    if shell:
        sp = c.projects.get(shell)
        if sp and sp.has_data:
            if sp.folder_exists and not same_path(sp.folder, d):
                refuse("COMPOSE_PROJECT_NAME=%s in your shell names an existing SigRift "
                       "install whose folder is %s, not this one." % (shell, sp.folder),
                       next_cmd="unset COMPOSE_PROJECT_NAME && " + c.cmd)
            check_pin_honoured(c, d, shell)
            return decision(c, LC_KIND="existing", LC_TARGET_DIR=d, LC_PROJECT=shell,
                            LC_PROJECT_HOW="shell", LC_PIN="1", LC_AUTO=auto_flag)
        # An explicit, unused name is a deliberate new stack only when this
        # folder has no data of its own (or --new-instance says so).
        mine = [x.name for x in owned] + ([derived] if own_data and derived not in
                                          [x.name for x in owned] else [])
        if mine and not c.new_instance:
            refuse("COMPOSE_PROJECT_NAME=%s in your shell names a project with no data, but "
                   "this folder's data is in project %s; pinning %s would start this "
                   "folder's .env on new, empty volumes." % (shell, mine[0], shell),
                   ["To start a separate, empty stack from this folder on purpose, add "
                    "--new-instance (with a free UC_PORT)."],
                   next_cmd="unset COMPOSE_PROJECT_NAME && " + c.cmd)
        check_port(c, folder_port(c, d))
        return decision(c, LC_KIND="existing", LC_TARGET_DIR=d, LC_PROJECT=shell,
                        LC_PROJECT_HOW="shell", LC_PIN="1", LC_AUTO=auto_flag)
    if c.adopt_project:
        return adopt_named(c, d, c.adopt_project, auto_flag, derived if own_data else "")
    if len(owned) > 1 or (owned and own_data and owned[0].name != derived):
        names = sorted(set([x.name for x in owned] + ([derived] if own_data else [])))
        refuse("this folder's data could be in more than one Docker Compose project (%s), "
               "so this run cannot tell which one is its own." % ", ".join(names),
               install_list([c.projects[n] for n in names]),
               next_cmd="%s %s" % (c.cmd, adopt_flag(c, names[0])))
    if owned and owned[0].name != derived:
        x = owned[0]
        check_pin_honoured(c, d, x.name)
        return decision(c, LC_KIND="existing", LC_TARGET_DIR=d, LC_PROJECT=x.name,
                        LC_PROJECT_HOW="labels", LC_PIN="1", LC_AUTO=auto_flag)
    orphans = [x for x in c.installs if x.valid and not x.folder_exists and x.name != derived
               and not c.new_instance]
    if p and p.has_data:
        other = other_folder_using(c, p, d)
        if other:
            copy_refusal(c, other)
        if not tied(p, d):
            # Nothing ties the data to this folder (no container, no volume
            # record): another install may have had this folder's name.
            facts = candidate_facts(c, p, d)
            bad, _ = consistency(facts, host_record(d), p.record)
            if bad:
                details = ["If this folder was renamed, name its own project with "
                           "--adopt-project; otherwise look for the key in older .env copies "
                           "(.env.bak.*~, .sigrift/snapshots/)."]
                nxt = in_dir(d, "ls -la .env.bak.*~ .sigrift/snapshots/")
                others = [x for x in orphans if x.name != derived]
                if others:
                    more, best = orphan_details(c, others, d)
                    details += more
                    nxt = "%s %s" % (c.cmd, adopt_flag(c, best))
                refuse("project %s, the one this folder's name gives, has data that this "
                       "folder's .env does not match (%s): either another install used this "
                       "folder's name, or .env no longer holds the key that data was written "
                       "with." % (derived, bad), details, next_cmd=nxt)
        check_pin_honoured(c, d, derived)
        return decision(c, LC_KIND="existing", LC_TARGET_DIR=d, LC_PROJECT=derived,
                        LC_PROJECT_HOW="derived", LC_PIN="1", LC_AUTO=auto_flag)
    # --new-instance: this folder starts with empty data on purpose, beside
    # whatever orphaned data there is.
    if orphans:
        if len(orphans) == 1:
            x = orphans[0]
            # Taken over without being named only when its last folder is
            # known (a container label, its volume record) and gone: with no
            # folder known, a copy of the folder made after `docker compose
            # down` looks the same as the folder renamed.
            compatible = x.kind in ("unknown", "release" if c.installer == "release" else "source")
            if x.folder and compatible:
                facts = candidate_facts(c, x, d)
                bad, proofs = consistency(facts, host_record(d), x.record)
                if facts and not bad and proofs:
                    check_pin_honoured(c, d, x.name)
                    return decision(c, LC_KIND="existing", LC_TARGET_DIR=d, LC_PROJECT=x.name,
                                    LC_PROJECT_HOW="adopted", LC_PIN="1", LC_AUTO=auto_flag,
                                    LC_ADOPTED_FROM=x.folder, LC_PROOF=", ".join(proofs))
        details, best = orphan_details(c, orphans, d)
        if len(orphans) == 1 and not orphans[0].folder:
            details.append("No container or volume record names its last folder, so this run "
                           "does not take it over by itself: a copy of a folder made after "
                           "`docker compose down` looks the same as a renamed one.")
        details.append("To start this folder with empty data instead, use --new-instance.")
        refuse("this folder's .env is not pinned to a Docker Compose project, and the project "
               "its name gives (%s) has no data; it looks like a folder renamed before this "
               "installer pinned it." % derived, details,
               next_cmd="%s %s" % (c.cmd, adopt_flag(c, best)))
    others = [x for x in c.installs if x.name != derived]
    if others:
        if not c.new_instance:
            second_stack(c, free_port_for(c, folder_port(c, d)))
        check_port(c, folder_port(c, d))
    elif not (p and p.has_data):
        note("no data volumes exist for project %s on this host; the stack starts with "
             "empty data and this folder's .env." % derived)
    return decision(c, LC_KIND="existing", LC_TARGET_DIR=d, LC_PROJECT=derived,
                    LC_PROJECT_HOW="derived", LC_PIN="1", LC_AUTO=auto_flag)


def folder_port(c, d):
    if c.installer == "release":
        return compose_port(d) or c.port
    if os.environ.get("UC_PORT"):
        return os.environ["UC_PORT"]
    return env_effective(read_text(os.path.join(d, ".env")) or "").get("UC_PORT") or c.port


def adopt_named(c, d, name, auto_flag, own=""):
    if not valid_project(name):
        refuse("%s is not a valid Docker Compose project name." % name[:60],
               next_cmd="docker volume ls --filter label=com.docker.compose.volume=bridge_data")
    x = c.projects.get(name)
    if not x or not x.has_data:
        refuse("project %s has no data volumes on this host, so there is nothing to adopt."
               % name, next_cmd="docker volume ls --filter "
               "label=com.docker.compose.volume=bridge_data")
    if x.folder_exists and not same_path(x.folder, d):
        refuse("project %s belongs to %s, which still exists, so this folder cannot take "
               "it over." % (name, x.folder),
               next_cmd=("cd %s && scripts/quickstart.sh" % q(x.folder))
               if c.installer == "quickstart" else "%s --upgrade %s" % (c.prog, q(x.folder)))
    facts = candidate_facts(c, x, d)
    bad, proofs = consistency(facts, host_record(d), x.record)
    if bad:
        refuse("the secrets in this folder's .env do not match the data of project %s (%s)."
               % (name, bad), next_cmd=in_dir(d, "ls -la .env.bak.*~"))
    check_pin_honoured(c, d, name)
    if own and own != name:
        note("project %s, the one this folder's name gives, has data too; it stays as it is "
             "and this folder no longer uses it." % own)
    return decision(c, LC_KIND="existing", LC_TARGET_DIR=d, LC_PROJECT=name,
                    LC_PROJECT_HOW="adopted", LC_PIN="1", LC_AUTO=auto_flag,
                    LC_ADOPTED_FROM=x.folder or "an unknown folder",
                    LC_PROOF=", ".join(proofs) or "no contradiction found")


def validate_target(c, target):
    if not os.path.isdir(target) or not os.path.lexists(os.path.join(target, ".env")) \
            or not os.path.lexists(os.path.join(target, "docker-compose.yml")):
        if os.path.isdir(target) and is_checkout(target):
            source_target(target)
        refuse("%s holds no SigRift install (no .env or docker-compose.yml)." % target,
               next_cmd=c.prog)
    if is_checkout(target):
        source_target(target)
    head = first_line(os.path.join(target, "docker-compose.yml"))
    if not (head.startswith(RELEASE_HEADER) or head.startswith(HOLD_HEADER)):
        refuse("%s/docker-compose.yml was not written by install-release.sh, so this "
               "installer does not upgrade it." % target,
               next_cmd="head -1 %s/docker-compose.yml" % q(target))


def source_target(target):
    refuse("%s is a source checkout (quickstart install); install-release.sh upgrades "
           "release installs only." % target,
           next_cmd="cd %s && git pull && scripts/quickstart.sh" % q(target))


def cmd_identity(argv):
    a = parse_flags(argv, {"installer": True, "self-dir": True, "target": True,
                           "new-instance": False, "adopt-project": True,
                           "keep-running-secrets": False, "version": True, "port": True,
                           "bind": True, "owner": True})
    c = Ctx()
    c.installer = a.get("installer", "release")
    # c.prog runs this installer from where the operator typed the command;
    # c.cmd is this run again (with its --upgrade DIR), flags go after it.
    c.prog = installer_prog(c.installer)
    c.cmd = installer_cmd(c.installer)
    c.self_dir = os.path.realpath(a["self_dir"])
    c.version = a.get("version", "")
    c.port = a.get("port") or "8444"
    c.bind = a.get("bind") or "127.0.0.1"
    c.owner = a.get("owner", "")
    c.new_instance = bool(a.get("new_instance"))
    c.adopt_project = a.get("adopt_project", "")
    c.shell_project = os.environ.get("COMPOSE_PROJECT_NAME", "").strip()
    c.source = None
    if c.shell_project and not valid_project(c.shell_project):
        refuse("COMPOSE_PROJECT_NAME=%s in your shell is not a valid Docker Compose project "
               "name." % c.shell_project[:60], next_cmd="unset COMPOSE_PROJECT_NAME && " + c.cmd)
    # The engine source arrives on fd 3: read it whole now, so the writer
    # never sees a closed pipe.
    c.source = read_fd3()
    try:
        c.volumes = list_volumes()
        projects, c.containers = classify_host(os.environ.get("LC_HELPER_IMAGE", ""), c.volumes)
    except DockerError as e:
        refuse("could not ask Docker which SigRift installs this host has (%s exited %d)."
               % (e.what, e.rc), next_cmd=e.what)
    c.projects = projects
    c.installs = [p for p in projects.values() if p.has_data]
    if a.get("target"):
        target = os.path.realpath(os.path.expanduser(a["target"]))
        validate_target(c, target)
        d = decide_existing(c, target)
    elif folder_kind(c.self_dir, c.installer) == "new":
        d = decide_new(c)
    else:
        d = decide_existing(c, c.self_dir)
    for k in DECISION_KEYS:
        v = str(d.get(k, "")).replace("\n", " ")
        say("%s=%s" % (k, v))


# ── secrets check: container, .env and shell must agree ─────────────────


def compose_would_pass(name, eff):
    if name in os.environ:
        return os.environ[name]
    return eff.get(name)


def audit_fp(facts, source):
    cand = candidate(facts, source) or {}
    return (cand.get("fingerprints") or {}).get("audit")


def depends(name, facts, has_data):
    """Which value the data needs: none | env | container | neither | unknown."""
    if not has_data:
        return "none"
    if name == "BRIDGE_DB_ENCRYPTION_KEY":
        return "unknown" if not facts or (facts.get("db") or {}).get("encrypted") else "none"
    if not facts_known(facts):
        return "unknown"
    env, cont = candidate(facts, "env") or {}, candidate(facts, "container") or {}
    if name == "BRIDGE_MFA_KEY":
        if counts(facts, "totp_fernet") == 0:
            return "none"
        if env.get("mfa") == "ok":
            return "env"
        return "container" if cont.get("mfa") == "ok" else "neither"
    if name in AUDIT_KEYS or name == "BRIDGE_MASTER_KEY":
        if counts(facts, "audit_rows") == 0:
            return "none"
        efp, cfp = audit_fp(facts, "env"), audit_fp(facts, "container")
        if efp and efp == cfp:
            return "none"
        if (env.get("audit") or {}).get("result") == "ok":
            return "env"
        if (cont.get("audit") or {}).get("result") == "ok":
            return "container"
        return "neither"
    if name == "BRIDGE_KEYSTORE_KEY":
        return "none" if counts(facts, "crypto_keys") == 0 else "unknown"
    return "unknown"


def secret_keys(eff):
    keys = list(DATA_BOUND)
    if not (eff.get("BRIDGE_AUDIT_KEY") or eff.get("BRIDGE_AUDIT_SECRET")):
        keys.append("BRIDGE_MASTER_KEY")
    return keys


def secret_conflicts(eff, benv, facts, has_data):
    """[(name, outcome)] where the running bridge differs from .env."""
    out = []
    for name in secret_keys(eff):
        running = (benv or {}).get(name) or ""
        wanted = compose_would_pass(name, eff)
        if not running or not wanted or same_secret(name, running, wanted):
            continue
        out.append((name, depends(name, facts, has_data)))
    return out


PROOF_TEXT = {
    "BRIDGE_MFA_KEY": ("%s TOTP secrets verify with it, none with .env's",
                       "lock those users out of MFA"),
    "audit": ("the audit chain verifies with it, not with .env's", "break the audit chain"),
}


NONE_MATCHES_HELP = ("Look for the value the data was written with in older .env copies; "
                     "TROUBLESHOOTING.md, \"The installer says a key differs from the running "
                     "bridge / no key matches the data\", explains the checks.")


def differs_refusal(name, outcome, facts, cmd):
    if outcome == "neither":
        refuse("neither .env's %s nor the running bridge's verifies this install's data, so "
               "the installer cannot tell which one is right." % name,
               [NONE_MATCHES_HELP], next_cmd=here("ls -la .env.bak.*~ .sigrift/snapshots/"))
    details = ["Values are never shown. .env may have been edited since the stack started, "
               "or the stack was started with a value from a shell."]
    if outcome == "container":
        if name == "BRIDGE_MFA_KEY":
            proof = PROOF_TEXT[name][0] % (counts(facts, "totp_fernet") or 0)
            harm = PROOF_TEXT[name][1]
        else:
            proof, harm = PROOF_TEXT["audit"]
        refuse("the running bridge uses a different %s than .env, and the data needs the "
               "running one (%s). Starting from .env would %s." % (name, proof, harm),
               details, next_cmd=cmd + " --keep-running-secrets")
    refuse("the running bridge uses a different %s than .env, and the installer cannot "
           "check which one this install's data needs (the running bridge's is the one in "
           "use)." % name, details, next_cmd=cmd + " --keep-running-secrets")


def check_secrets(env_file, bridge, gateway, facts, has_data, keep_running, cmd):
    eff = env_effective(read_text(env_file) or "")
    for name in secret_keys(eff):
        if name in os.environ and eff.get(name) and \
                not same_secret(name, os.environ[name], eff.get(name)):
            refuse("%s is set in your shell and differs from .env, and docker compose would "
                   "use the shell's value." % name, next_cmd="unset %s && %s" % (name, cmd))
    benv, genv = container_env(bridge) or {}, container_env(gateway) or {}
    for name in ("BRIDGE_AUDIT_KEY", "BRIDGE_MFA_KEY"):
        if benv.get(name) and genv.get(name) and not same_secret(name, benv[name], genv[name]):
            gateway_differs(name, eff, benv, facts, has_data, keep_running, cmd)
    for name, outcome in secret_conflicts(eff, benv, facts, has_data):
        if outcome == "none":
            note("the running bridge uses another %s than .env; no data depends on it, so "
                 "this run starts the stack with .env's value." % name)
        elif outcome == "env":
            note("the running bridge uses another %s than .env; .env's value verifies the "
                 "data, so this run starts the stack with it." % name)
        elif keep_running and outcome in ("container", "unknown"):
            continue
        else:
            differs_refusal(name, outcome, facts, cmd)
    env_verifies_nothing(eff, benv, facts, has_data, keep_running)
    return benv


def gateway_differs(name, eff, benv, facts, has_data, keep_running, cmd):
    """The bridge and the gateway run with different NAME values. The next
    command depends on which value the data needs: recreating both from
    .env would give the bridge a key the data does not verify with."""
    msg = ("the bridge and the gateway run with different %s values, so the stack is "
           "already inconsistent." % name)
    wanted = compose_would_pass(name, eff)
    if wanted and same_secret(name, benv[name], wanted):
        reason = ".env holds the bridge's value"
    else:
        outcome = depends(name, facts, has_data)
        if outcome in ("container", "unknown"):
            if keep_running:
                return  # .env gets the bridge's value; the start recreates the gateway
            refuse(msg, ["The bridge's value is the one %s; this run can write it into .env "
                         "and start both with it." % (
                             "the data verifies with" if outcome == "container" else "in use")],
                   next_cmd=cmd + " --keep-running-secrets")
        if outcome == "neither":
            refuse(msg, [NONE_MATCHES_HELP],
                   next_cmd=here("ls -la .env.bak.*~ .sigrift/snapshots/"))
        reason = ("the data verifies with .env's value" if outcome == "env"
                  else "no data depends on it")
    refuse(msg, ["Recreate both containers from .env (%s)." % reason],
           next_cmd=here("docker compose up -d --force-recreate"))


def env_verifies_nothing(eff, benv, facts, has_data, keep_running):
    """Refuse when the value this run would start the stack with (.env's,
    or the shell's) does not verify data that needs one, and no running
    bridge has one that does (that case is a differs refusal, or
    --keep-running-secrets). Without this, an install whose stack is down
    would migrate first and fail its checks afterwards."""
    if not has_data or not facts_known(facts):
        return
    env, cont = candidate(facts, "env") or {}, candidate(facts, "container") or {}
    n = counts(facts, "totp_fernet") or 0
    if n > 0 and env.get("mfa") == "fail" and not (keep_running and cont.get("mfa") == "ok"):
        if cont.get("mfa") != "ok":
            refuse(".env's BRIDGE_MFA_KEY does not verify this install's %d TOTP secrets, and "
                   "no running bridge has one that does; starting with it would lock those "
                   "users out of MFA." % n, [NONE_MATCHES_HELP],
                   next_cmd=here("ls -la .env.bak.*~ .sigrift/snapshots/"))
    rows = counts(facts, "audit_rows") or 0
    audit, caudit = env.get("audit") or {}, cont.get("audit") or {}
    if rows > 0 and audit.get("result") == "fail" and \
            audit.get("source") in ("env-key", "legacy-secret", "master") and \
            not (keep_running and caudit.get("result") == "ok"):
        if caudit.get("result") != "ok":
            refuse("the audit key in .env does not verify any of this install's %d audit "
                   "entries, and no running bridge has one that does; new entries would "
                   "break the audit chain." % rows, [NONE_MATCHES_HELP],
                   next_cmd=here("ls -la .env.bak.*~ .sigrift/snapshots/"))


def cmd_secrets_check(argv):
    a = parse_flags(argv, {"env-file": True, "bridge": True, "gateway": True,
                           "has-data": True, "keep-running-secrets": False, "installer": True})
    check_secrets(a.get("env_file", ".env"), a.get("bridge", ""), a.get("gateway", ""),
                  load_facts(), a.get("has_data") == "1",
                  bool(a.get("keep_running_secrets")),
                  installer_cmd(a.get("installer", "release")))


# ── .env merge ──────────────────────────────────────────────────────────


def cm_applies(cm, version):
    if not version or not VERSION_RE.fullmatch(version) or version.startswith("main"):
        return True
    return version_cmp(version, cm["since"]) in (0, 1)


class Plan(object):
    def __init__(self, text):
        self.text = text
        self.eff = env_effective(text)
        self.sets = []       # (name, value, how, raw)  how: replace | append | rename
        self.notes = []      # (to_stdout, text); "{backup}" is filled in after the write
        self.cm = []
        self.needs_password = False

    def renamed_from(self, name):
        """The old name of an assignment this plan renames to NAME, or None."""
        for n, v, how, _ in self.sets:
            if how == "rename" and v == name:
                return n
        return None

    def value(self, name):
        for n, v, how, _ in reversed(self.sets):
            if n == name and how != "rename":
                return v
        old = self.renamed_from(name)
        return self.eff.get(old if old else name)

    def missing(self, name):
        """Absent or empty; an assignment compose would expand is left alone."""
        if any(n == name and how != "rename" for n, _, how, _ in self.sets):
            return not self.value(name).strip()
        key = self.renamed_from(name) or name
        if any(n == key and how == "rename" for n, _, how, _ in self.sets) and key == name:
            return True  # renamed away
        if key in self.eff and self.eff[key] is None:
            return False
        return not (self.eff.get(key) or "").strip()

    def set(self, name, value, how=None, raw=False):
        if how is None:
            target = self.renamed_from(name) or name
            how = "replace" if last_assign(self.text, target) is not None else "append"
        self.sets.append((name, value, how, raw))

    @property
    def changes(self):
        return bool(self.sets)


def value_matches(name, source, facts, has_data):
    """(verdict, proof) for restoring NAME from candidate SOURCE (container
    or shell): "ok", "fail" (the data does not verify with it) or
    "unchecked" (it cannot be checked while data may depend on it)."""
    if not has_data:
        return "ok", "no data depends on it yet"
    unchecked = "unchecked", "the installer could not check it against the data"
    if name == "BRIDGE_DB_ENCRYPTION_KEY":
        db = (facts or {}).get("db") or {}
        return ("ok", "the database is not encrypted") if facts and not db.get("encrypted") \
            else unchecked
    if not facts_known(facts):
        return unchecked
    cand = candidate(facts, source) or {}
    if name == "BRIDGE_MFA_KEY":
        n = counts(facts, "totp_fernet")
        if n == 0:
            return "ok", "no TOTP secret is encrypted with one yet"
        if cand.get("mfa") == "ok":
            return "ok", "%d TOTP secrets verify with it" % n
        return ("fail", "") if cand.get("mfa") == "fail" else unchecked
    if name in AUDIT_KEYS or name == "BRIDGE_MASTER_KEY":
        if counts(facts, "audit_rows") == 0:
            return "ok", "the audit log is empty"
        r = (cand.get("audit") or {}).get("result")
        if r == "ok":
            return "ok", "the audit chain verifies with it"
        return ("fail", "") if r == "fail" else unchecked
    if name == "BRIDGE_KEYSTORE_KEY" and counts(facts, "crypto_keys") == 0:
        return "ok", "no protocol key is stored yet"
    return unchecked


def env_plan(path, installer, facts, container_env_map, shell_env, flags):
    """The edits of one run (spec 4.5); refuses when an edit would harm data."""
    text = env_text(path, here("ls -l %s" % q(path)))
    plan = Plan(text)
    cmd = installer_cmd(installer)
    has_data = bool(flags.get("has_data"))
    version = flags.get("version") or ""
    cenv = container_env_map or {}
    # R1: the pin.
    pin = flags.get("pin")
    if pin and not valid_project(pin):
        sys.exit("lc_tool env-merge: invalid project name")
    if pin:
        cur = plan.eff.get("COMPOSE_PROJECT_NAME")
        if cur and cur != pin:
            refuse("%s already pins COMPOSE_PROJECT_NAME=%s, not %s." % (path, cur, pin),
                   next_cmd=here("grep -n COMPOSE_PROJECT_NAME %s" % q(path)))
        if not cur:
            plan.set("COMPOSE_PROJECT_NAME", pin)
            plan.notes.append((True, flags.get("pin_note") or (
                "==> Pinned COMPOSE_PROJECT_NAME=%s in .env." % pin)))
    # Values that differ from the running bridge.
    for name, outcome in secret_conflicts(plan.eff, cenv, facts, has_data):
        if outcome in ("container", "unknown") and flags.get("keep_running_secrets"):
            plan.set(name, cenv[name])
            plan.notes.append((True, "==> .env: %s now holds the value the running bridge "
                                     "uses (--keep-running-secrets). Previous file: {backup}"
                               % name))
        elif outcome not in ("none", "env"):
            differs_refusal(name, outcome, facts, cmd)
    # R2: restore a missing data-bound key from the running bridge or the shell.
    for name in DATA_BOUND + ("BRIDGE_MASTER_KEY",):
        if not plan.missing(name):
            continue
        running = cenv.get(name) or ""
        shell = shell_env.get(name) or ""
        if running and shell and not same_secret(name, running, shell):
            refuse("the running bridge and your shell have different %s values, and .env has "
                   "none, so the installer cannot tell which one is right." % name,
                   ["Values are never shown."], next_cmd="unset %s && %s" % (name, cmd))
        value = running or shell
        if not value:
            continue
        source = "container" if running else "shell"
        verdict, proof = value_matches(name, source, facts, has_data)
        if verdict == "fail":
            differs_refusal(name, "neither", facts, cmd)
        if verdict == "unchecked" and source == "shell":
            # Only the shell has it, and nothing can check it: written into
            # .env it would stay there for good. The operator writes it.
            refuse(".env has no %s and only your shell sets one, which the installer cannot "
                   "check against this install's data, so it does not write it into .env."
                   % name, ["If it is the value this install's data needs, add it to .env "
                            "yourself, then run this again; otherwise unset it."],
                   next_cmd=here("grep -c '^%s=' .env" % name))
        if verdict == "unchecked":
            proof = "the running bridge uses it; " + proof
        plan.set(name, value)
        plan.notes.append((True, "==> .env had no %s; restored the value the %s uses (%s). "
                                 "Previous file: {backup}" % (
                                     name, "running bridge" if running else "shell", proof)))
    # R3: BRIDGE_MFA_KEY.
    if plan.missing("BRIDGE_MFA_KEY"):
        n = counts(facts, "totp_fernet")
        if not has_data or n == 0:
            plan.set("BRIDGE_MFA_KEY", fernet_key())
        else:
            details = ["Put the old value back (from a .env.bak.*~ backup or your records) "
                       "and re-run."]
            if n is None:
                refuse(".env has no BRIDGE_MFA_KEY, and the installer could not read the "
                       "database to tell whether TOTP secrets are encrypted with one; a new "
                       "key would lock those users out of MFA, so none is generated.",
                       details, next_cmd=here("grep -l '^BRIDGE_MFA_KEY=' .env.bak.*~"))
            refuse(".env has no BRIDGE_MFA_KEY, but %d users' TOTP secrets are encrypted "
                   "with one; a new key would lock them out of MFA, so none is generated."
                   % n, details, next_cmd=here("grep -l '^BRIDGE_MFA_KEY=' .env.bak.*~"))
    # R4: BRIDGE_AUDIT_KEY (otherwise warn_missing_audit_key warns).
    if plan.missing("BRIDGE_AUDIT_KEY") and (not has_data or counts(facts, "audit_rows") == 0):
        plan.set("BRIDGE_AUDIT_KEY", token())
    # R5: BRIDGE_KEYSTORE_KEY.
    if plan.missing("BRIDGE_KEYSTORE_KEY"):
        rows = counts(facts, "crypto_keys")
        if not has_data or rows == 0:
            plan.set("BRIDGE_KEYSTORE_KEY", fernet_key())
            plan.notes.append((True, "==> Added BRIDGE_KEYSTORE_KEY to .env (keeps imported "
                                     "protocol decryption keys across restarts; none is "
                                     "stored yet). Previous file: {backup}"))
        elif rows:
            plan.notes.append((False, "NOTE: .env has no BRIDGE_KEYSTORE_KEY, but the "
                                      "database holds %d stored protocol keys; they stay "
                                      "unreadable until the key that stored them is back in "
                                      ".env." % rows))
        else:
            why = (facts or {}).get("error") if facts else None
            if facts and (facts.get("db") or {}).get("error"):
                why = facts["db"]["error"]
            if facts and (facts.get("db") or {}).get("encrypted"):
                why = "it is encrypted"
            plan.notes.append((False, "NOTE: BRIDGE_KEYSTORE_KEY was not added: the "
                                      "installer could not read the database (%s). Imported "
                                      "protocol keys stay in memory only." % (
                                          why or "no bridge image to read it with")))
    # R6: BRIDGE_MASTER_KEY, only beside an audit key.
    if plan.missing("BRIDGE_MASTER_KEY") and not (
            plan.missing("BRIDGE_AUDIT_KEY") and plan.missing("BRIDGE_AUDIT_SECRET")):
        plan.set("BRIDGE_MASTER_KEY", token())
    # R7, R8.
    if plan.missing("UC_PROXY_SECRET"):
        plan.set("UC_PROXY_SECRET", token())
    if installer == "quickstart" and plan.missing("BRIDGE_LOCAL_NODE_KEY"):
        plan.set("BRIDGE_LOCAL_NODE_KEY", token())
    # R9: the bootstrap admin, only while no user exists.
    users = counts(facts, "users")
    if plan.missing("BRIDGE_ADMIN_PASSWORD") and (not has_data or users == 0):
        plan.needs_password = True
        if flags.get("no_prompt"):
            refuse("this install's data has no users, so the new bridge needs "
                   "BRIDGE_ADMIN_PASSWORD in .env to create the admin, and an upgrade runs "
                   "without a terminal to ask for it.", next_cmd=lifecycle_cmd("--abort"))
        password = flags.get("password")
        if password is not None:
            plan.set("BRIDGE_ADMIN_PASSWORD",
                     json.dumps(password.replace("$", "$$"), ensure_ascii=False), raw=True)
            if plan.missing("BRIDGE_ADMIN_USER"):
                plan.set("BRIDGE_ADMIN_USER", "admin")
    # R10: config migrations.
    for cm in CONFIG_MIGRATIONS:
        if not cm_applies(cm, version):
            continue
        kind = cm["kind"]
        if kind == "rename":
            if not plan.missing(cm["old"]) and plan.missing(cm["new"]):
                plan.set(cm["old"], cm["new"], "rename")
                plan.cm.append(cm["id"])
                plan.notes.append((True, "==> .env: %s: renamed %s to %s. Previous file: "
                                         "{backup}" % (cm["id"], cm["old"], cm["new"])))
        elif kind == "default":
            cur = plan.value(cm["key"])
            if cur is not None and cur.strip() in cm["when"]:
                new = token() if cm["new"] == "random" else cm["new"]
                plan.set(cm["key"], new)
                plan.cm.append(cm["id"])
                plan.notes.append((True, "==> .env: %s: replaced %s=%s (%s) with %s. Previous "
                                         "file: {backup}" % (
                                             cm["id"], cm["key"], cur.strip(), cm["why"],
                                             "a random secret" if cm["new"] == "random"
                                             else cm["new"])))
        elif kind == "note":
            if not plan.missing(cm["key"]):
                plan.notes.append((False, "NOTE: .env: %s: %s" % (cm["id"], cm["text"])))
    # R11: keys this installer does not know are kept.
    unknown = sorted(k for k in plan.eff if k not in KEY_CLASSES)
    if unknown:
        plan.notes.append((False, "NOTE: .env keeps keys this installer does not use: %s."
                           % ", ".join(unknown)))
    return plan


def render_plan(plan, installer, version):
    """The new .env text: values replaced in place, additions appended."""
    text = plan.text
    edits, appends = {}, []
    for name, value, how, raw in plan.sets:
        encoded = value if raw else dotenv_value(value)
        a = last_assign(text, plan.renamed_from(name) or name if how != "rename" else name)
        if how == "rename":
            edits[(a.name_start, a.name_end)] = value
        elif how == "replace" and a is not None and a.value is not None:
            span = (a.start - 1, a.end + 1) if a.quote else (a.start, a.end)
            edits[span] = encoded
        else:
            appends = [(n, v) for n, v in appends if n != name] + [(name, encoded)]
    for (start, end), rep in sorted(edits.items(), reverse=True):
        text = text[:start] + rep + text[end:]
    pin = [v for n, v in appends if n == "COMPOSE_PROJECT_NAME"]
    appends = [(n, v) for n, v in appends if n != "COMPOSE_PROJECT_NAME"]
    if pin:
        if text and not text.endswith("\n"):
            text += "\n"
        text += PIN_COMMENT + "COMPOSE_PROJECT_NAME=%s\n" % pin[0]
    if appends:
        if text and not text.endswith("\n"):
            text += "\n"
        text += "# Added by %s @ %s (%s): %s\n" % (
            "install-release.sh" if installer == "release" else "scripts/quickstart.sh",
            version or "main", time.strftime("%Y-%m-%d"), ", ".join(n for n, _ in appends))
        text += "".join("%s=%s\n" % (n, v) for n, v in appends)
    return text


def env_apply(path, plan, installer, version):
    """Write a plan's edits as one change; -> the backup's path, or None."""
    if not plan.changes:
        return None
    return write_new_text(path, plan.text, render_plan(plan, installer, version))


def read_password_fd3():
    data = read_fd3()
    return data.decode("utf-8") if data else None


def cmd_env_merge(argv):
    a = parse_flags(argv, {"env-file": True, "installer": True, "version": True,
                           "bridge": True, "has-data": True, "pin": True,
                           "pin-note": True, "plan": False, "keep-running-secrets": False,
                           "password-fd3": False, "no-prompt": False})
    path = a.get("env_file", ".env")
    installer = a.get("installer", "release")
    facts = load_facts()
    flags = {"has_data": a.get("has_data") == "1", "version": a.get("version", ""),
             "pin": a.get("pin", ""), "pin_note": a.get("pin_note", ""),
             "keep_running_secrets": bool(a.get("keep_running_secrets")),
             "no_prompt": bool(a.get("no_prompt"))}
    if a.get("password_fd3"):
        password = read_password_fd3()
        if password:
            flags["password"] = password
    cenv = container_env(a.get("bridge", "")) or {}
    plan = env_plan(path, installer, facts, cenv, os.environ, flags)
    result = {"needs_password": plan.needs_password and "password" not in flags,
              "adds": sorted(set(n for n, _, how, _ in plan.sets if how == "append")),
              "replaces": sorted(set(n for n, _, how, _ in plan.sets if how != "append")),
              "cm": plan.cm, "backup": None}
    if a.get("plan") or result["needs_password"]:
        say("LC_ENV_RESULT=" + json.dumps(result, sort_keys=True))
        sys.exit(EXIT_NEEDS_PASSWORD if result["needs_password"] else 0)
    backup = env_apply(path, plan, installer, flags["version"])
    result["backup"] = backup
    for to_stdout, text in plan.notes:
        line = text.replace("{backup}", backup or "(none)")
        if to_stdout:
            say(line)
        else:
            sys.stderr.write(line + "\n")
    say("LC_ENV_RESULT=" + json.dumps(result, sort_keys=True))


def cmd_pin(argv):
    """pin ENV_FILE NAME [--no-backup]: add COMPOSE_PROJECT_NAME once."""
    a = parse_flags(argv[2:], {"no-backup": False, "note": True})
    path, name = argv[0], argv[1]
    if not valid_project(name):
        sys.exit("lc_tool pin: invalid project name")
    text = env_text(path, here("ls -l %s" % q(path)))
    cur = env_effective(text).get("COMPOSE_PROJECT_NAME")
    if cur and cur != name:
        refuse("%s already pins COMPOSE_PROJECT_NAME=%s, not %s." % (path, cur, name),
               next_cmd=here("grep -n COMPOSE_PROJECT_NAME %s" % q(path)))
    if cur == name:
        return
    sep = "" if not text or text.endswith("\n") else "\n"
    new = text + sep + PIN_COMMENT + "COMPOSE_PROJECT_NAME=%s\n" % name
    if a.get("no_backup"):
        tmp = path + ".tmp"
        if os.path.lexists(tmp):
            os.unlink(tmp)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        give_owner(fd, owner_for(path))
        with os.fdopen(fd, "w", newline="") as f:
            f.write(new)
        os.replace(tmp, path)
        backup = None
    else:
        backup = write_new_text(path, text, new)
    if a.get("note"):
        say(a["note"] + ("" if not backup else " Previous file: %s" % backup))


def cmd_compose_name(argv):
    name = compose_name(argv[0] if argv else ".", without_shell=True)
    if name:
        say(name)
    else:
        sys.exit(1)


def cmd_compose_owner(argv):
    owner = compose_owner(argv[0] if argv else ".")
    if owner:
        say(owner)


def cmd_installed_version(argv):
    say(installed_version(argv[0] if argv else "."))


def cmd_version_cmp(argv):
    r = version_cmp(argv[0], argv[1])
    say("none" if r is None else str(r))


def dig(obj, path):
    for part in path.split("."):
        obj = obj.get(part) if isinstance(obj, dict) else None
    if obj is None:
        return ""
    if isinstance(obj, bool):
        return "1" if obj else "0"
    return json.dumps(obj) if isinstance(obj, (dict, list)) else str(obj)


def cmd_facts_get(argv):
    """facts-get KEY.PATH: one value of this run's facts ('' if absent)."""
    say(dig(load_facts(), argv[0]))


def cmd_json_get(argv):
    """json-get KEY.PATH: one value of the JSON object on fd 3."""
    try:
        obj = json.loads(read_fd3().decode("utf-8", "replace") or "{}")
    except ValueError:
        sys.exit(1)
    say(dig(obj, argv[0]))


def cmd_foreign_mounts(argv):
    """Refuse while a container of another project mounts this one's volumes."""
    a = parse_flags(argv, {"project": True, "installer": True})
    project = a["project"]
    for vol, name in sorted(project_volumes(project).items()):
        # Running containers only: a stopped one cannot write. The
        # lifecycle tool's own short reads (another run's --status) are not
        # writers either.
        try:
            lines = docker_lines("docker ps", "ps", "--filter", "volume=" + name, "--format",
                                 '{{.Names}}\t{{.Label "%s"}}\t{{.Label "%s"}}' % (
                                     PROJECT_LABEL, LIFECYCLE_LABEL))
        except DockerError as e:
            refuse("could not ask Docker which containers mount %s (%s exited %d)."
                   % (name, e.what, e.rc), next_cmd="docker ps --filter volume=" + q(name))
        for line in lines:
            cname, other, lifecycle = (line.split("\t") + ["", ""])[:3]
            if cname and other != project and not lifecycle:
                refuse("container %s (project %s) also mounts %s, so the installer could "
                       "not stop everything that writes this install's data." % (
                           cname, other or "none", name), next_cmd="docker stop " + q(cname))


def cmd_engine_image(argv):
    """engine-image: a local bridge image to read the data with, or ''."""
    a = parse_flags(argv, {"installer": True, "project": True, "dir": True, "bridge": True,
                           "owner": True, "version": True})
    say(engine_image(a.get("installer", "release"), a.get("owner", ""), a.get("version", ""),
                     a.get("bridge", ""), [a.get("dir", ".")], a.get("project", "")))


def cmd_engine_run(argv):
    """engine-run --image I --project P --op OP [--env-file F] [--bridge ID]
    [--record-file F]: engine source on fd 3, reply JSON on stdout."""
    a = parse_flags(argv, {"image": True, "project": True, "op": True, "env-file": True,
                           "bridge": True, "record-file": True})
    source = read_fd3()
    op = a.get("op", "facts")
    extra = {}
    if op == "facts":
        extra["candidates"] = build_candidates(a.get("env_file"), a.get("bridge", ""))
    elif op == "write-record":
        rec = json.loads(read_text(a["record_file"]) or "{}")
        extra["record"] = rec
        extra["secrets"] = build_candidates(a.get("env_file"), "")["env"]
    reply = run_engine(a.get("image", ""), a.get("project", "") if op != "image-info" else "",
                       op, source, extra)
    say(json.dumps(reply, sort_keys=True))
    if not reply.get("ok"):
        sys.exit(1)


def host_id():
    r = docker("info", "--format", "{{.Name}}:{{.ID}}")
    if r.returncode:
        return ""
    raw = "sigrift-host-v1:" + r.stdout.decode("utf-8", "replace").strip()
    import hashlib
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def cmd_write_host_record(argv):
    """Host record after a healthy run; prints the volume record to write."""
    a = parse_flags(argv, {"dir": True, "op": True, "project": True, "install-type": True,
                           "from": True, "to": True, "installer": True,
                           "installer-version": True, "env-result": True,
                           "moved-from": True, "schema": True, "snapshot": True,
                           "volume-record": True, "result": True})
    d = os.path.realpath(a.get("dir", "."))
    rec = host_record(d) or {}
    first = not rec.get("install_id")
    now = now_utc()
    if first:
        import uuid
        rec = {"format": 1, "install_id": str(uuid.uuid4()), "created_at": now,
               "first_version": a.get("from") if a.get("op") != "install" and
               a.get("from") not in (None, "", "unknown") else a.get("to"),
               "history": [], "config_migrations": [], "compose_template_sha256": None}
    moved = a.get("moved_from") or ""
    if moved and rec.get("working_dir") and not same_path(rec["working_dir"], d):
        say("==> This install moved from %s to %s; its records were updated." % (
            rec["working_dir"], d))
    rec.update({"format": 1, "install_type": a.get("install_type", "release"),
                "project": a.get("project", ""), "working_dir": d, "host_id": host_id(),
                "version": a.get("to", ""), "updated_at": now,
                "installer": {"version": a.get("installer_version", ""),
                              "sha256": sha256_file(a["installer"]) if a.get("installer")
                              else None}})
    if a.get("schema"):
        try:
            rec["schema"] = int(a["schema"])
        except ValueError:
            pass
    try:
        result = json.loads(a.get("env_result") or "{}")
    except ValueError:
        result = {}
    cms = rec.get("config_migrations") or []
    for cm in result.get("cm") or []:
        if cm not in cms:
            cms.append(cm)
    rec["config_migrations"] = cms
    history = rec.get("history") or []
    history.append({"at": now, "op": a.get("op", "rerun"), "from": a.get("from", ""),
                    "to": a.get("to", ""), "result": a.get("result") or "ok",
                    "snapshot": a.get("snapshot") or None})
    rec["history"] = history[-50:]
    write_host_record(d, rec)
    if a.get("volume_record"):
        vol = {"format": 1, "install_id": rec["install_id"], "project": rec["project"],
               "working_dir": d, "host_id": rec["host_id"],
               "install_type": rec["install_type"],
               "installer_version": a.get("installer_version", ""),
               "first_version": rec.get("first_version"), "last_version": rec["version"],
               "tls_cert_sha256": sha256_file(os.path.join(d, "tls", "cert.pem")),
               "updated_at": now}
        atomic_write(a["volume_record"], json.dumps(vol).encode(), 0o600)


def keys_line(facts):
    """The plan's line on the data-bound keys: what the engine verified."""
    try:
        raw = json.loads(os.environ.get("LC_FACTS_JSON") or "{}")
    except ValueError:
        raw = {}
    if not isinstance(raw, dict) or not raw:
        return "no data to check yet"
    if not facts:
        return "not checked: %s" % (raw.get("error") or "the engine gave no answer")
    db = facts.get("db") or {}
    if db.get("encrypted"):
        return "not checked: the database is encrypted"
    if db.get("error"):
        return "not checked: the database could not be read (%s)" % db["error"]
    env, cont = candidate(facts, "env") or {}, candidate(facts, "container") or {}
    compared = (facts.get("candidates") or {}).get("container") is not None
    who = "running bridge, .env and shell agree" if compared else \
        ".env and shell agree (no bridge container to compare with)"
    n, rows = counts(facts, "totp_fernet") or 0, counts(facts, "audit_rows") or 0
    if n == 0:
        totp = "no TOTP users"
    elif env.get("mfa") == "ok":
        totp = "TOTP: %d rows verify" % n
    elif env.get("mfa") == "fail" and cont.get("mfa") == "ok":
        totp = "TOTP: %d rows verify with the running bridge's key, which goes into .env" % n
    elif env.get("mfa") == "fail":
        totp = "TOTP: .env's key does NOT verify"
    else:
        totp = "TOTP: not verified"
    result = (env.get("audit") or {}).get("result")
    if rows == 0:
        audit = "audit: empty"
    elif result == "ok":
        audit = "audit: chain verifies (%d entries)" % rows
    elif result == "fail" and (cont.get("audit") or {}).get("result") == "ok":
        audit = "audit: the chain verifies with the running bridge's key, which goes into .env"
    elif result == "fail":
        audit = "audit: .env's key does NOT verify"
    else:
        audit = "audit: not verified"
    return "%s; %s; %s" % (who, totp, audit)


def cmd_plan(argv):
    """The plan (spec 6.1), printed by --dry-run and before an automatic
    upgrade; the run has changed nothing when it is printed."""
    a = parse_flags(argv, {"dir": True, "project": True, "pin": True, "from": True,
                           "to": True, "env-result": True, "others": True, "mode": True,
                           "source-dir": True, "newest": True, "tls": True, "owner": True})
    d = os.path.realpath(a.get("dir", "."))
    facts = load_facts()
    try:
        result = json.loads(a.get("env_result") or "{}")
    except ValueError:
        result = {}
    project = a.get("project", "")
    mode = a.get("mode", "upgrade")
    pinned = ("pins COMPOSE_PROJECT_NAME=%s on this first run" % project
              if a.get("pin") == "1" else "pinned")
    say("  target    %s (project %s, %s)" % (d, project, pinned))
    frm, to = a.get("from", "unknown"), a.get("to", "")
    if a.get("owner"):
        say("  images    ghcr.io/%s/sigrift-bridge:%s, ghcr.io/%s/sigrift-gateway:%s" % (
            a["owner"], to, a["owner"], to))
    if mode == "fresh":
        say("  version   %s (a new install; the images are pulled before anything is written)"
            % to)
    elif frm == to:
        say("  version   %s (re-run, same version; the images are pulled first)" % to)
    else:
        say("  version   %s -> %s (images pulled first, while the stack keeps running)"
            % (frm, to))
    live = (facts or {}).get("db", {}).get("schema") if facts else None
    newest = a.get("newest") or ""
    if mode == "fresh":
        say("  schema    none yet (the bridge creates the database)")
    elif newest:
        say("  schema    %s -> %s" % (live if live is not None else "unknown", newest))
    else:
        say("  schema    %s -> read from the %s bridge image after the pull" % (
            live if live is not None else "unknown", to))
    if mode == "fresh":
        say("  compose   written for %s" % to)
    elif frm == to:
        say("  compose   kept")
    else:
        say("  compose   image tags updated in place (old file kept as "
            "docker-compose.yml.bak.*~)")
    adds = result.get("adds") or []
    replaces = [r for r in result.get("replaces") or [] if r != "COMPOSE_PROJECT_NAME"]
    if mode == "fresh":
        say("  .env      written new (you are asked for the admin password)")
    else:
        say("  .env      kept; %s; %d config migrations" % (
            ("adds: " + ", ".join(adds)) if adds else "nothing to add",
            len(result.get("cm") or [])) + (("; replaces: " + ", ".join(replaces))
                                             if replaces else ""))
    say("  keys      %s" % keys_line(facts))
    if a.get("tls"):
        say("  TLS       %s" % a["tls"])
    src = a.get("source_dir") or ""
    if src and not same_path(src, d):
        say("  installer this install-release.sh is copied into %s after the pull (old one "
            "kept as install-release.sh.bak.*~)" % d)
    elif mode != "fresh":
        say("  installer the one in %s" % d)
    if mode == "fresh":
        say("  restore   nothing to keep yet (a new install)")
    else:
        say("  restore   files-only restore point in %s/.sigrift/snapshots/ (.env, compose, "
            "VERSION, tls, installer); the data volumes are not copied by this installer "
            "yet: to keep a copy first, see INSTALL.md \"Upgrading a release install\"" % d)
    if mode == "upgrade":
        say("  downtime  the stack stops from the switch until the new bridge is healthy "
            "(about 1-3 min, plus migration time)")
    elif mode == "rerun":
        say("  downtime  none planned (a re-run recreates only containers whose settings "
            "changed)")
    for line in (a.get("others") or "").split("; "):
        if line:
            say("  also here %s" % line)



# ── the lock: one changing run per install folder ───────────────────────
#
# flock(2) on the install folder's own directory, opened by bash on fd 9:
# taking it creates no file, so a refusal leaves the folder byte-identical,
# and the lock lives as long as any process holds that fd. The detached
# critical section inherits it, so a second run is refused until the
# upgrade has finished, even after the terminal that started it is gone.

LOCK_OWNER = os.path.join(STATE_DIR, "lock-owner.json")
# Reserved for Phase 1b's restore (see LC_RESTORE_MARKER in the identity block).
RESTORE_MARKER = ".sigrift-restore-incomplete"
JOURNAL = os.path.join(STATE_DIR, "journal.json")
SNAPSHOTS = os.path.join(STATE_DIR, "snapshots")
LOGS = os.path.join(STATE_DIR, "logs")
HELD = os.path.join(STATE_DIR, "held")
EXIT_LOCK_DEFERRED = 5
EXIT_LOCK_UNSUPPORTED = 6
ACTIVE_STATES = ("running", "failed", "verify_failed")
OVERRIDES = ("docker-compose.override.yml", "docker-compose.override.yaml")
# What a files-only restore point holds, each when present: everything an
# upgrade, a re-run or a TLS renewal may change outside the volumes.
SNAPSHOT_FILES = (".env", "docker-compose.yml") + OVERRIDES + (
    "VERSION", "install-release.sh", "LICENSE", "NOTICE", "THIRD-PARTY-NOTICES.txt",
    "README-INSTALL.txt", "tls/cert.pem", "tls/key.pem", ".sigrift-scanners.yml",
    ".sigrift/install.json")
# What --upgrade DIR installs into DIR from the newly unpacked release.
RELEASE_FILES = ("install-release.sh", "LICENSE", "NOTICE", "THIRD-PARTY-NOTICES.txt",
                 "README-INSTALL.txt")
SNAPSHOT_KEEP = 10


def read_json(path):
    text = read_text(path)
    if not text:
        return None
    try:
        obj = json.loads(text)
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


def write_json(path, obj, mode=0o600):
    atomic_write(path, (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode(), mode)


def cmd_lock(argv):
    """lock FD DIR OP [--installer I]: exclusive, non-blocking flock on FD.

    Busy: M-LOCKED (exit 3), or exit 5 for renew-tls (the caller defers).
    Exit 6 where the filesystem has no directory locks (the caller falls
    back to a lock file).
    """
    fd, d, op = int(argv[0]), os.path.realpath(argv[1]), argv[2]
    a = parse_flags(argv[3:], {"installer": True, "inherited": False})
    if a.get("inherited"):
        # The lock a parent run took, on the fd it handed down: FD must be
        # open on this folder (or its lock file), and taking the lock again
        # through it succeeds only because this open file holds it already.
        try:
            st = os.fstat(fd)
            mine = any(os.path.exists(x) and os.path.samestat(st, os.stat(x))
                       for x in (d, os.path.join(d, STATE_DIR, "lock")))
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            mine = False
        if not mine:
            sys.stderr.write("lc_tool lock: this run does not hold the lock of %s\n" % d)
            sys.exit(2)
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return
    except OSError as e:
        if e.errno not in (errno.EWOULDBLOCK, errno.EAGAIN):
            if e.errno in (errno.EINVAL, errno.EBADF, errno.ENOLCK, errno.ENOTSUP,
                           errno.EOPNOTSUPP, errno.ENOSYS):
                sys.exit(EXIT_LOCK_UNSUPPORTED)
            raise
    if op == "renew-tls":
        sys.exit(EXIT_LOCK_DEFERRED)
    owner = read_json(os.path.join(d, LOCK_OWNER)) or {}
    what = ""
    if owner.get("op"):
        what = " (%s, pid %s%s)" % (owner["op"], owner.get("pid") or "unknown",
                                    ", log %s" % owner["log"] if owner.get("log") else "")
    if a.get("installer") == "quickstart":
        refuse("another installer run is working on %s%s." % (d, what),
               ["Run it again once the other run has finished."],
               next_cmd="scripts/quickstart.sh")
    log = owner.get("log") or ""
    nxt = ("tail -f %s" % q(os.path.join(d, log))) if log else lifecycle_cmd("--status", d)
    refuse("another installer run is working on %s%s." % (d, what), next_cmd=nxt)


def cmd_lock_owner(argv):
    """lock-owner DIR --op OP --log LOG [--pid PID] | lock-owner DIR --release"""
    d = argv[0]
    a = parse_flags(argv[1:], {"op": True, "log": True, "pid": True, "release": False})
    path = os.path.join(d, LOCK_OWNER)
    if a.get("release"):
        try:
            os.unlink(path)
        except OSError:
            pass
        return
    ensure_state_dir(d)
    write_json(path, {"pid": int(a.get("pid") or os.getppid()), "op": a.get("op", ""),
                      "started_at": now_utc(), "log": a.get("log", "")})


# ── the journal: where an upgrade stands ────────────────────────────────


def journal_load(d):
    return read_json(os.path.join(d, JOURNAL))


def journal_save(d, j):
    j["updated_at"] = now_utc()
    ensure_state_dir(d)
    write_json(os.path.join(d, JOURNAL), j)


def journal_active(j):
    return bool(j) and j.get("state") in ACTIVE_STATES


def journal_pending(j):
    done = set(j.get("done") or [])
    return [s for s in j.get("steps") or [] if s not in done]


def read_kv_fd3():
    out = {}
    for line in read_fd3().decode("utf-8", "replace").splitlines():
        k, sep, v = line.partition("=")
        if sep and re.fullmatch(r"[A-Z_][A-Z0-9_]*", k):
            out[k] = v
    return out


def container_image_id(cid):
    if not cid:
        return ""
    r = docker("inspect", "--format", "{{.Image}}", cid)
    return r.stdout.decode("utf-8", "replace").strip() if r.returncode == 0 else ""


def cmd_journal_new(argv):
    """journal-new --dir D --op OP --steps a,b --done a --from F --to T ...

    Variables to carry into the detached run come as KEY=VALUE lines on
    fd 3 (no secrets: decision values, versions, flags). Prints the id.
    """
    a = parse_flags(argv, {"dir": True, "op": True, "steps": True, "done": True,
                           "from": True, "to": True, "owner": True, "project": True,
                           "source-dir": True, "snapshot": True, "was-running": True,
                           "images": True, "bridge": True, "gateway": True, "pin": True,
                           "project-how": True})
    d = os.path.realpath(a.get("dir", "."))
    ensure_state_dir(d)
    logs = os.path.join(d, LOGS)
    if not os.path.isdir(logs):
        os.mkdir(logs, 0o700)
        give_owner(logs, owner_for(os.path.join(d, STATE_DIR)))
    os.chmod(logs, 0o700)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    jid, n = stamp, 1
    while os.path.lexists(os.path.join(logs, "%s-%s.log" % (a.get("op", "upgrade"), jid))):
        n += 1
        jid = "%s-%d" % (stamp, n)
    log = os.path.join(LOGS, "%s-%s.log" % (a.get("op", "upgrade"), jid))
    fd = os.open(os.path.join(d, log), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    give_owner(fd, owner_for(logs))
    os.close(fd)
    facts = load_facts() or {}
    db, cnt = facts.get("db") or {}, facts.get("counts") or {}
    env = candidate(facts, "env") or {}
    images = {}
    for item in (a.get("images") or "").split():
        svc, _, ref = item.partition("=")
        if svc and ref:
            images[svc] = ref
    steps = [s for s in (a.get("steps") or "").split(",") if s]
    done = [s for s in (a.get("done") or "").split(",") if s]
    j = {"format": 1, "id": jid, "op": a.get("op", "upgrade"), "state": "running",
         "steps": steps, "done": done, "next": "",
         "from_version": a.get("from", ""), "to_version": a.get("to", ""),
         "owner": a.get("owner", ""), "project": a.get("project", ""), "working_dir": d,
         "source_dir": a.get("source_dir") or None, "images": images,
         "previous_images": {"bridge": container_image_id(a.get("bridge", "")),
                             "gateway": container_image_id(a.get("gateway", ""))},
         "was_running": a.get("was_running") == "1",
         "pre": {"schema": db.get("schema"), "db_bytes": db.get("bytes"),
                 "encrypted": db.get("encrypted"),
                 "audit_rows": cnt.get("audit_rows"), "audit_head_id": cnt.get("audit_head_id"),
                 "audit_ok": (env.get("audit") or {}).get("result") == "ok",
                 "totp_fernet": cnt.get("totp_fernet"),
                 "detections_max_id": cnt.get("detections_max_id")},
         "snapshot": a.get("snapshot") or None, "installer_backups": [], "held": [],
         "pin": a.get("pin") == "1", "project_how": a.get("project_how", ""),
         # The daemon the stack runs on: --resume and --abort refuse another.
         "host_id": host_id(),
         "vars": read_kv_fd3(), "bridge_started_at": None, "pid": None, "log": log,
         "started_at": now_utc(), "error": None}
    pending = journal_pending(j)
    j["next"] = pending[0] if pending else ""
    journal_save(d, j)
    say(jid)


def cmd_journal_get(argv):
    """journal-get DIR KEY.PATH: one value ('' when absent)."""
    say(dig(journal_load(argv[0]), argv[1]))


def cmd_journal_vars(argv):
    """journal-vars DIR: the carried variables as KEY=VALUE lines."""
    for k, v in sorted(((journal_load(argv[0]) or {}).get("vars") or {}).items()):
        say("%s=%s" % (k, str(v).replace("\n", " ")))


def cmd_journal_pending(argv):
    """journal-pending DIR: the steps still to run, in order."""
    say(" ".join(journal_pending(journal_load(argv[0]) or {})))


def cmd_journal_step(argv):
    """journal-step DIR NAME: NAME is done; next is the following step."""
    d, name = argv[0], argv[1]
    j = journal_load(d)
    if not j:
        sys.exit("lc_tool: no journal in %s" % d)
    if name not in (j.get("done") or []):
        j.setdefault("done", []).append(name)
    pending = journal_pending(j)
    j["next"] = pending[0] if pending else ""
    journal_save(d, j)


def journal_value(v):
    if v == "null":
        return None
    if v == "@now":
        return now_utc()
    if v in ("true", "false"):
        return v == "true"
    return v


def cmd_journal_set(argv):
    """journal-set DIR KEY=VALUE... (null, true, false, @now are typed)."""
    d = argv[0]
    j = journal_load(d)
    if not j:
        sys.exit("lc_tool: no journal in %s" % d)
    for item in argv[1:]:
        k, _, v = item.partition("=")
        if k in ("installer_backups", "held"):
            j[k] = sorted(set((j.get(k) or []) + [x for x in v.split(",") if x]))
        elif k == "next" and v:
            # Back to an earlier step (resume re-runs it): it is no longer done.
            steps = j.get("steps") or []
            if v in steps:
                j["done"] = [s for s in j.get("done") or [] if steps.index(s) < steps.index(v)
                             or s not in steps]
            j[k] = v
        elif k == "pid" and v.isdigit():
            j[k] = int(v)
        else:
            j[k] = journal_value(v)
    journal_save(d, j)


def cmd_journal_state(argv):
    """journal-state DIR STATE [ERROR]"""
    d, state = argv[0], argv[1]
    j = journal_load(d)
    if not j:
        sys.exit("lc_tool: no journal in %s" % d)
    j["state"] = state
    j["error"] = argv[2] if len(argv) > 2 and argv[2] else None
    if state in ("done", "aborted"):
        j["finished_at"] = now_utc()
    journal_save(d, j)


def resume_cmd(d, j):
    """The one command that goes on with an interrupted upgrade."""
    src = j.get("source_dir")
    if src and "installer" in (j.get("steps") or []) and \
            "installer" not in (j.get("done") or []):
        # The install folder still has its old installer, which knows no
        # --resume: the new release's goes on with it.
        if os.path.isfile(os.path.join(src, "install-release.sh")):
            return "bash %s/install-release.sh --resume %s" % (q(src), q(d))
        return "bash /path/to/the/new/release/install-release.sh --resume %s" % q(d)
    return lifecycle_cmd("--resume", d)


def cmd_journal_check(argv):
    """journal-check DIR --to VERSION --requested 0|1 [--held 0|1]

    What a plain run does with the journal: prints `none` (no upgrade in
    progress), `resume` (an interrupted one to the same version), or
    refuses (M-INTERRUPTED, M-VERIFY-FAILED, a hold without a journal).
    """
    d = argv[0]
    a = parse_flags(argv[1:], {"to": True, "requested": True, "held": True})
    j = journal_load(d)
    if not journal_active(j):
        if a.get("held") == "1":
            refuse("%s/docker-compose.yml is the hold stub of an upgrade, but no upgrade is in "
                   "progress there (.sigrift/journal.json is missing or finished), so this run "
                   "does not guess which files are real." % d,
                   ["The real files are in %s/%s/." % (d, HELD)],
                   next_cmd="ls -la %s/" % q(os.path.join(d, HELD)))
        say("none")
        return
    step = j.get("next") or "?"
    if j.get("state") == "verify_failed":
        refuse("the last upgrade to %s is up but failed its checks (%s), so this run does not "
               "change it further." % (j.get("to_version"), j.get("error") or "see the log"),
               next_cmd=lifecycle_cmd("--status", d))
    to = a.get("to", "")
    if a.get("requested") != "1" or to == j.get("to_version"):
        say("resume")
        return
    refuse("an upgrade to %s was interrupted at step %s, so this run (%s) cannot start "
           "another." % (j.get("to_version"), step, to or "a re-run"),
           next_cmd=resume_cmd(d, j))


def cmd_journal_guard(argv):
    """journal-guard DIR: before --resume, --abort or the detached part act
    on an upgrade's journal, this shell must talk to the Docker daemon the
    upgrade ran on (DOCKER_HOST, DOCKER_CONTEXT). Prints the journal's
    project, which every compose call then uses (a COMPOSE_PROJECT_NAME
    exported in this shell would address another stack)."""
    d = os.path.realpath(argv[0])
    j = journal_load(d) or {}
    want, have = j.get("host_id") or "", host_id()
    if want and have and want != have:
        refuse("this shell's docker talks to another Docker daemon than the one the upgrade "
               "in %s ran on (DOCKER_HOST or DOCKER_CONTEXT differ), so it does not act on "
               "it from here." % d,
               ["Point docker at the daemon that runs this install's stack, then run the "
                "command again."], next_cmd="docker context ls")
    project = j.get("project") or ""
    if not valid_project(project):
        refuse("the journal in %s names no valid Docker Compose project." % d,
               next_cmd="cat %s" % q(os.path.join(d, JOURNAL)))
    shell = os.environ.get("COMPOSE_PROJECT_NAME", "").strip()
    if shell and shell != project:
        note("COMPOSE_PROJECT_NAME=%s in your shell is not used: this upgrade belongs to "
             "project %s." % (shell[:60], project))
    say(project)


def cmd_journal_find(argv):
    """journal-find --source-dir S: the install folder whose upgrade in
    progress was started from S (a newly unpacked release folder), when
    there is exactly one; nothing otherwise."""
    a = parse_flags(argv, {"source-dir": True})
    src = os.path.realpath(a.get("source_dir") or ".")
    try:
        projects, _ = classify_host(helper_image())
    except DockerError:
        return
    found = []
    for p in projects.values():
        if p.has_data and p.folder_exists and p.folder_how == "labels":
            j = journal_load(p.folder)
            if journal_active(j) and j.get("source_dir") and same_path(j["source_dir"], src):
                found.append(os.path.realpath(p.folder))
    if len(set(found)) == 1:
        say(found[0])


def cmd_project_bridge(argv):
    """project-bridge PROJECT: the running bridge container of PROJECT."""
    rows = docker_lines("docker ps", "ps", "--filter", "label=%s=%s" % (PROJECT_LABEL, argv[0]),
                        "--filter", "label=%s=bridge" % SERVICE_LABEL, "--format", "{{.ID}}")
    rows = [r.strip() for r in rows if r.strip()]
    if rows:
        say(rows[0])


def cmd_renew_check(argv):
    """renew-check DIR: may an unattended --renew-tls change tls/ now?
    Prints `proceed`, or `defer REASON`. It waits while an upgrade has the
    stack stopped or is running; a finished one that failed its checks
    (verify_failed), or failed while its stack runs again, does not hold
    the certificate back."""
    d = os.path.realpath(argv[0])
    if is_held(d):
        say("defer an upgrade has the stack stopped")
        return
    j = journal_load(d)
    if not journal_active(j):
        say("proceed")
        return
    state = j.get("state")
    pid = j.get("pid")
    if state == "running" and isinstance(pid, int) and alive(pid):
        say("defer an upgrade is running")
        return
    if state == "verify_failed":
        say("proceed")
        return
    try:
        running = set(x.strip() for x in docker_lines(
            "docker ps", "ps", "--filter", "label=%s=%s" % (PROJECT_LABEL, j.get("project") or ""),
            "--format", '{{.Label "%s"}}' % SERVICE_LABEL))
    except DockerError:
        running = set()
    if {"bridge", "gateway"} <= running:
        say("proceed")
        return
    say("defer an upgrade stopped at step %s with the stack down" % (j.get("next") or "?"))


# ── files-only restore points ───────────────────────────────────────────


def sha256_bytes(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


def helper_image():
    return os.environ.get("LC_HELPER_IMAGE", "")


def tls_key_read(path):
    """The bytes of a TLS key this user cannot read, through the pinned
    helper image (it runs as root), with no log copy kept by the daemon."""
    d, base = os.path.dirname(os.path.abspath(path)), os.path.basename(path)
    if not helper_image():
        raise OSError("no helper image to read %s with" % path)
    # Root in the helper, with only the capability to read a file it does
    # not own (the key may be 0600 for another uid).
    r = docker(*(helper_run_args("tls") + [
        "--cap-drop", "ALL", "--cap-add", "DAC_OVERRIDE",
        "-v", os.path.realpath(d) + ":/tls:ro", helper_image(), "cat", "/tls/" + base]))
    if r.returncode:
        raise OSError("could not read %s through the helper image (docker run exited %d)"
                      % (path, r.returncode))
    return r.stdout


def tls_key_write(path, data):
    """Write a TLS key into a folder this user cannot write, through the
    helper image: a new file, then a rename over the old one."""
    d, base = os.path.dirname(os.path.abspath(path)), os.path.basename(path)
    if not helper_image():
        raise OSError("no helper image to write %s with" % path)
    r = docker(*(helper_run_args("tls") + [
        "-i", "--cap-drop", "ALL", "--cap-add", "DAC_OVERRIDE",
        "-v", os.path.realpath(d) + ":/tls", helper_image(), "sh", "-c",
        'umask 077 && cat > "/tls/$1.sigrift-new" && mv -f "/tls/$1.sigrift-new" "/tls/$1"',
        "sh", base]), input=data)
    if r.returncode:
        raise OSError("could not write %s through the helper image (docker run exited %d)"
                      % (path, r.returncode))


def read_file_bytes(path, rel):
    """(bytes, via_helper) of an install file; the TLS key through the
    helper when this user cannot read it."""
    try:
        with open(path, "rb") as f:
            return f.read(), False
    except PermissionError:
        if rel == "tls/key.pem":
            return tls_key_read(path), True
        raise


def snapshot_complete(path):
    man = os.path.join(path, "manifest.json")
    try:
        with open(man, "rb") as f:
            digest = sha256_bytes(f.read())
        with open(os.path.join(path, "COMPLETE")) as f:
            return f.read().strip() == digest
    except OSError:
        return False


class Snapshot(object):
    def __init__(self, sid, path):
        self.id, self.path = sid, path
        self.manifest = read_json(os.path.join(path, "manifest.json")) or {}
        self.complete = snapshot_complete(path)

    @property
    def kind(self):
        return self.manifest.get("kind", "files")

    @property
    def created(self):
        return self.manifest.get("created_at") or ""

    def bytes(self):
        total = 0
        for root, _, files in os.walk(self.path):
            for name in files:
                try:
                    total += os.lstat(os.path.join(root, name)).st_size
                except OSError:
                    pass
        return total


def list_snapshots(d):
    """Every restore point under DIR/.sigrift/snapshots, newest first."""
    root = os.path.join(d, SNAPSHOTS)
    try:
        names = os.listdir(root)
    except OSError:
        return []
    out = [Snapshot(n, os.path.join(root, n)) for n in names
           if os.path.isdir(os.path.join(root, n)) and not n.startswith(".")]
    return sorted(out, key=lambda s: (s.created, s.id), reverse=True)


# The host record changes on every run (its history), so it does not count
# when deciding whether a restore point would only repeat the newest one.
SIGNATURE_IGNORES = (".sigrift/install.json",)


def snapshot_signature(files, missing):
    return (sorted((f["path"], f.get("sha256"), f.get("symlink")) for f in files
                   if f["path"] not in SIGNATURE_IGNORES),
            sorted(m for m in missing if m not in SIGNATURE_IGNORES))


def make_dirs(path):
    """mkdir -p with mode 0700 for every directory it creates."""
    if os.path.isdir(path):
        return
    make_dirs(os.path.dirname(path))
    os.mkdir(path, 0o700)
    give_owner(path, owner_for(os.path.dirname(path)))


def take_snapshot(d, reason, frm, to, installer_version, project, install_id):
    """A files-only restore point of DIR; -> (id, reused)."""
    files, missing, blobs = [], [], {}
    for rel in SNAPSHOT_FILES:
        p = os.path.join(d, rel)
        if os.path.islink(p):
            files.append({"path": rel, "symlink": os.readlink(p)})
            continue
        if not os.path.lexists(p):
            missing.append(rel)
            continue
        if not os.path.isfile(p):
            continue
        data, via = read_file_bytes(p, rel)
        files.append({"path": rel, "sha256": sha256_bytes(data), "bytes": len(data),
                      "mode": "%04o" % stat.S_IMODE(os.lstat(p).st_mode), "via_helper": via})
        blobs[rel] = data
    for s in list_snapshots(d):
        if s.complete and s.kind == "files":
            m = s.manifest
            if snapshot_signature(m.get("files") or [], m.get("missing") or []) == \
                    snapshot_signature(files, missing):
                return s.id, True
            break
    root = os.path.join(d, SNAPSHOTS)
    ensure_state_dir(d)
    make_dirs(root)
    os.chmod(root, 0o700)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    base = "%s-%s-files" % (stamp, re.sub(r"[^A-Za-z0-9._-]", "_", frm or "unknown"))
    sid, n = base, 1
    while os.path.lexists(os.path.join(root, sid)):
        n += 1
        sid = "%s-%d" % (base, n)
    path = os.path.join(root, sid)
    os.mkdir(path, 0o700)
    give_owner(path, owner_for(root))
    try:
        for rel, data in blobs.items():
            target = os.path.join(path, "files", rel)
            make_dirs(os.path.dirname(target))
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            give_owner(fd, owner_for(os.path.dirname(target)))
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        for root_, dirs, _ in os.walk(path):
            fsync_dir(root_)
        manifest = {"format": 1, "kind": "files", "id": sid, "created_at": now_utc(),
                    "reason": reason, "from_version": frm, "to_version": to,
                    "install_id": install_id or None, "project": project,
                    "installer_version": installer_version, "files": files,
                    "missing": missing}
        write_json(os.path.join(path, "manifest.json"), manifest)
        with open(os.path.join(path, "manifest.json"), "rb") as f:
            digest = sha256_bytes(f.read())
        atomic_write(os.path.join(path, "COMPLETE"), (digest + "\n").encode(), 0o600)
        fsync_dir(root)
    except BaseException:
        import shutil
        shutil.rmtree(path, ignore_errors=True)
        raise
    return sid, False


def cmd_snapshot_files(argv):
    """snapshot-files DIR --reason R --from F --to T: prints the id.

    Deduplicated: when every file equals the newest complete files-only
    restore point, that one's id is printed and nothing is written. On a
    failure the partial restore point is deleted (exit 1).
    """
    d = os.path.realpath(argv[0])
    a = parse_flags(argv[1:], {"reason": True, "from": True, "to": True,
                               "installer-version": True, "project": True})
    hr = host_record(d) or {}
    try:
        sid, reused = take_snapshot(d, a.get("reason", "upgrade"), a.get("from", ""),
                                    a.get("to", ""), a.get("installer_version", ""),
                                    a.get("project", ""), hr.get("install_id"))
    except (OSError, ValueError) as e:
        sys.stderr.write("could not save a restore point of %s (%s)\n" % (d, e))
        sys.exit(1)
    say("%s %s" % (sid, "reused" if reused else "new"))


def snapshot_by_id(d, sid):
    for s in list_snapshots(d):
        if s.id == sid:
            return s
    return None


def cmd_snapshot_restore(argv):
    """snapshot-restore DIR ID [--dry-run]: put every file of a complete
    restore point back (rename over, never in place: a running installer
    keeps reading its old inode) and remove the ones it did not have."""
    d = os.path.realpath(argv[0])
    a = parse_flags(argv[2:], {"dry-run": False})
    s = snapshot_by_id(d, argv[1])
    if s is None or not s.complete:
        refuse("restore point %s is missing or incomplete, so --abort cannot put the files "
               "back." % argv[1], next_cmd="ls -la %s/" % q(os.path.join(d, SNAPSHOTS)))
    restored, removed, key = [], [], False
    plan = []
    for f in s.manifest.get("files") or []:
        rel = f["path"]
        if "symlink" in f:
            continue
        src = os.path.join(s.path, "files", rel)
        with open(src, "rb") as fh:
            data = fh.read()
        if sha256_bytes(data) != f.get("sha256"):
            refuse("restore point %s is damaged (%s does not match its manifest), so --abort "
                   "does not use it." % (s.id, rel), next_cmd="ls -la %s" % q(s.path))
        p = os.path.join(d, rel)
        try:
            cur = read_file_bytes(p, rel)[0] if os.path.lexists(p) else None
        except OSError:
            cur = None
        if cur is not None and sha256_bytes(cur) == f["sha256"]:
            continue
        mode = int(f.get("mode") or "0600", 8)
        if rel == "tls/key.pem":
            # Never wider than 0600 until secure_tls_files gives it group
            # 1500 and 0640 again.
            mode = 0o600
        plan.append((rel, p, data, mode))
    gone = [rel for rel in s.manifest.get("missing") or []
            if os.path.lexists(os.path.join(d, rel)) and
            not os.path.isdir(os.path.join(d, rel))]
    if a.get("dry_run"):
        say("restore   %s" % (", ".join(r for r, _, _, _ in plan) or "nothing (every file "
                                                                   "is as it was)"))
        say("remove    %s" % (", ".join(gone) or "nothing"))
        return
    for rel, p, data, mode in plan:
        make_dirs(os.path.dirname(p))
        if rel == "tls/key.pem" and not os.access(os.path.dirname(p), os.W_OK):
            tls_key_write(p, data)
        else:
            atomic_write(p, data, mode)
        restored.append(rel)
        key = key or rel == "tls/key.pem"
    for rel in gone:
        os.unlink(os.path.join(d, rel))
        removed.append(rel)
    say("restored=%s" % ",".join(restored))
    say("removed=%s" % ",".join(removed))


def prune_snapshots(d, keep, protect):
    """Keep the KEEP newest complete files-only restore points; never the
    newest one, one in PROTECT, or an incomplete one (--status lists it)."""
    snaps = [s for s in list_snapshots(d) if s.complete and s.kind == "files"]
    removed = []
    for i, s in enumerate(snaps):
        if i < keep or i == 0 or s.id in protect:
            continue
        import shutil
        shutil.rmtree(s.path, ignore_errors=True)
        removed.append(s.id)
    return removed


def cmd_prune_snapshots(argv):
    d = argv[0]
    a = parse_flags(argv[1:], {"keep": True, "protect": True})
    protect = set(x for x in (a.get("protect") or "").split(",") if x)
    j = journal_load(d) or {}
    if j.get("snapshot"):
        protect.add(j["snapshot"])
    for sid in prune_snapshots(d, int(a.get("keep") or SNAPSHOT_KEEP), protect):
        say("pruned %s" % sid)


# ── --upgrade DIR: the new release's own installer goes into DIR ────────


def cmd_install_files(argv):
    """install-files --src S --dir D: each release file of S that differs
    goes into D by a copy and a rename (bash reads a running script as it
    goes, so it is never overwritten in place), the old one kept as
    NAME.bak.<time>~. Prints NAME=BACKUP per file replaced."""
    a = parse_flags(argv, {"src": True, "dir": True})
    src, d = os.path.realpath(a["src"]), os.path.realpath(a["dir"])
    if same_path(src, d):
        return
    if not os.path.isfile(os.path.join(src, "install-release.sh")):
        # Reporting "all were current" would leave the old installer here.
        sys.stderr.write("the release folder %s has no install-release.sh (it was moved or "
                         "deleted)\n" % src)
        sys.exit(1)
    for name in RELEASE_FILES:
        sp, dp = os.path.join(src, name), os.path.join(d, name)
        if not os.path.isfile(sp):
            continue
        with open(sp, "rb") as f:
            data = f.read()
        mode = 0o755 if name == "install-release.sh" else 0o644
        backup = ""
        if os.path.lexists(dp):
            try:
                with open(dp, "rb") as f:
                    old = f.read()
            except OSError:
                old = None
            if old == data:
                continue
            if old is not None:
                backup = backup_path(dp)
                fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                             stat.S_IMODE(os.lstat(dp).st_mode))
                give_owner(fd, owner_for(dp))
                with os.fdopen(fd, "wb") as f:
                    f.write(old)
        tmp = os.path.join(d, "." + name + ".sigrift-new")
        if os.path.lexists(tmp):
            os.unlink(tmp)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        give_owner(fd, owner_for(dp))
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, dp)
        say("%s=%s" % (name, os.path.basename(backup)))
    fsync_dir(d)


# ── the hold: a placeholder compose file while the stack is stopped ─────

STUB = """%s: install-release.sh is changing this install.
# The real files are in .sigrift/held/. This placeholder starts nothing
# that touches the data. Run: bash install-release.sh --status
name: %s
services:
  sigrift-held:
    image: %s
    network_mode: none
    restart: "no"
    command: ["sh", "-c", "echo 'SigRift is mid-upgrade: run bash install-release.sh --status' >&2; exit 1"]
"""


def is_held(d):
    return first_line(os.path.join(d, "docker-compose.yml")).startswith(HOLD_HEADER)


def cmd_hold(argv):
    """hold --dir D --project P: docker-compose.yml and the override go to
    .sigrift/held/, a stub that declares no volume takes the compose
    file's place (one rename, so there is no moment without either). A
    plain `docker compose up` or a reboot then starts nothing that touches
    the data; even `down -v` there removes no volume. Idempotent."""
    a = parse_flags(argv, {"dir": True, "project": True})
    d = os.path.realpath(a["dir"])
    held = os.path.join(d, HELD)
    ensure_state_dir(d)
    if not os.path.isdir(held):
        os.mkdir(held, 0o700)
        give_owner(held, owner_for(os.path.join(d, STATE_DIR)))
    os.chmod(held, 0o700)
    compose = os.path.join(d, "docker-compose.yml")
    names = []
    if not is_held(d):
        with open(compose, "rb") as f:
            data = f.read()
        mode = stat.S_IMODE(os.lstat(compose).st_mode)
        atomic_write(os.path.join(held, "docker-compose.yml"), data, mode)
        if not valid_project(a["project"]):
            sys.exit("lc_tool hold: invalid project name")
        stub = STUB % (HOLD_HEADER, a["project"], helper_image() or "alpine")
        atomic_write(compose, stub.encode(), mode)
    if os.path.isfile(os.path.join(held, "docker-compose.yml")):
        names.append("docker-compose.yml")
    for ov in OVERRIDES:
        p = os.path.join(d, ov)
        if os.path.lexists(p):
            os.replace(p, os.path.join(held, ov))
        if os.path.lexists(os.path.join(held, ov)):
            names.append(ov)
    fsync_dir(held)
    fsync_dir(d)
    say(",".join(names))


def cmd_unhold(argv):
    """unhold --dir D: the held files back in place (the compose rename
    replaces the stub in one step). Idempotent, also after a crash between
    two of its renames: a stub beside an override is not a valid project,
    so it starts nothing either."""
    a = parse_flags(argv, {"dir": True})
    d = os.path.realpath(a["dir"])
    held = os.path.join(d, HELD)
    for ov in OVERRIDES:
        if os.path.lexists(os.path.join(held, ov)):
            os.replace(os.path.join(held, ov), os.path.join(d, ov))
    if os.path.lexists(os.path.join(held, "docker-compose.yml")):
        os.replace(os.path.join(held, "docker-compose.yml"), os.path.join(d, "docker-compose.yml"))
    fsync_dir(d)
    try:
        os.rmdir(held)
    except OSError:
        pass


# ── stop: nothing may write the data while it is copied and switched ───


def project_containers(project, running_only):
    fmt = "{{.ID}}\t{{.Names}}\t{{.State}}"
    args = ["ps"] + ([] if running_only else ["-a"]) + [
        "--filter", "label=%s=%s" % (PROJECT_LABEL, project), "--format", fmt]
    rows = []
    for line in docker_lines("docker ps", *args):
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0]:
            rows.append(parts)
    return rows


def cmd_stop_project(argv):
    """stop-project --project P: stop every running container labelled
    with the project (the stub's, a scanner's), then check that no
    running container mounts a project volume. Prints CONTAINER VOLUME and
    exits 1 when one still does."""
    a = parse_flags(argv, {"project": True})
    project = a["project"]
    try:
        ids = [r[0] for r in project_containers(project, True)]
        if ids:
            r = docker("stop", "--time", "30", *ids, timeout=300)
            if r.returncode:
                sys.stderr.write("docker stop exited %d\n" % r.returncode)
        for vol, name in sorted(project_volumes(project).items()):
            for line in docker_lines("docker ps", "ps", "--filter", "volume=" + name,
                                     "--format", '{{.Names}}\t{{.Label "%s"}}'
                                     % LIFECYCLE_LABEL):
                cname, _, lifecycle = line.partition("\t")
                if cname.strip() and not lifecycle.strip():
                    say("%s %s" % (cname.strip(), name))
                    sys.exit(1)
    except DockerError as e:
        say("%s exited %d" % (e.what, e.rc))
        sys.exit(1)


# ── the two-stage start ─────────────────────────────────────────────────


def cmd_ps_row(argv):
    """ps-row SERVICE: `STATE HEALTH` of SERVICE from `docker compose ps
    --format json` on fd 3 (one object per line, or one array from older
    Compose); `- -` when it has no container."""
    svc = argv[0]
    text = read_fd3().decode("utf-8", "replace").strip()
    rows = []
    if text.startswith("["):
        try:
            rows = json.loads(text)
        except ValueError:
            rows = []
    else:
        for line in text.splitlines():
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    for row in rows:
        if isinstance(row, dict) and row.get("Service") == svc:
            say("%s %s" % ((row.get("State") or "-").lower(), (row.get("Health") or "-").lower()))
            return
    say("- -")


def bridge_deadline(db_bytes):
    """Seconds to wait for a bridge that may be migrating its database:
    max(10 min, 3 min + 1 min per 500 MB)."""
    try:
        n = max(0, int(db_bytes or 0))
    except ValueError:
        n = 0
    return max(600, 180 + 60 * -(-n // 500000000))


def cmd_bridge_deadline(argv):
    say(str(bridge_deadline(argv[0] if argv else 0)))


# ── the detached critical section ───────────────────────────────────────

TOOL_ENV = ("LC_ENGINE_BOOTSTRAP", "LC_ENGINE_DATA_DIR", "LC_HELPER_IMAGE", "LC_FACTS_JSON",
            "LC_CRITICAL", "LC_STEP", "LC_CALLER_DIR", "LC_SELF_DIR", "LC_UPGRADE_DIR")


def cmd_setsid_exec(argv):
    """setsid-exec LOG CMD...: CMD in a new session, its stdin /dev/null
    and its output appended to LOG; prints its pid. Writes to a terminal
    that went away (an SSH drop) can then no longer stop it, and it does
    not get the terminal's SIGHUP. fd 9, the install folder's lock, is
    inherited, so the lock is held until CMD ends."""
    log, cmd = argv[0], argv[1:]
    pid = os.fork()
    if pid == 0:
        try:
            os.setsid()
            out = os.open(log, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            null = os.open(os.devnull, os.O_RDONLY)
            os.dup2(null, 0)
            os.dup2(out, 1)
            os.dup2(out, 2)
            for fd in (out, null, 3):
                try:
                    os.close(fd)
                except OSError:
                    pass
            env = dict((k, v) for k, v in os.environ.items() if k not in TOOL_ENV)
            env["LC_LOCK_INHERITED"] = "1"
            os.execvpe(cmd[0], cmd, env)
        finally:
            os._exit(127)
    say(str(pid))


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def cmd_follow(argv):
    """follow LOG PID RCFILE: print LOG as it grows until PID has written
    RCFILE (or is gone); exit with that code (4 when it left none).
    Ctrl-C, a hang-up or a TERM stop only the following."""
    log, pid, rcfile = argv[0], int(argv[1]), argv[2]
    status = argv[3] if len(argv) > 3 else "bash install-release.sh --status"

    def detach(signum, frame):
        try:
            sys.stdout.flush()
        except OSError:
            pass
        try:
            sys.stderr.write("\nStopped following the log; the upgrade goes on. Follow it with: "
                             "tail -f %s\nCheck it with: %s\n" % (q(os.path.abspath(log)), status))
            sys.stderr.flush()
        except OSError:
            pass
        os._exit(130)

    import signal
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, detach)
    out = sys.stdout.buffer

    def pump(f):
        chunk = f.read()
        if chunk:
            try:
                out.write(chunk)
                out.flush()
            except OSError:
                pass
        return chunk

    def rc():
        text = read_text(rcfile)
        if text is None or not text.strip():
            return None
        try:
            return int(text.strip())
        except ValueError:
            return 4

    with open(log, "rb") as f:
        while True:
            pump(f)
            code = rc()
            if code is None and not alive(pid):
                time.sleep(0.2)
                code = rc()
                code = 4 if code is None else code
            if code is not None:
                time.sleep(0.05)
                pump(f)
                # Not sys.exit: a terminal that went away must not turn the
                # final flush into an error after the work is done.
                os._exit(code)
            time.sleep(0.2)


# ── after the start: the upgrade's checks ───────────────────────────────


def cmd_verify_upgrade(argv):
    """verify-upgrade DIR --target-schema N: this run's facts (read with
    the new bridge image) against the journal's from before the stop.
    Prints what it checked; exit 1 with the reason on a regression."""
    d = argv[0]
    a = parse_flags(argv[1:], {"target-schema": True, "project": True, "bridge": True})
    facts = load_facts()
    pre = (journal_load(d) or {}).get("pre") or {}
    if a.get("project") and not a.get("bridge"):
        # The facts were read from the project's volumes; the stack that
        # runs must be that project's too (a shell or another daemon could
        # have started another one).
        say("no running bridge container belongs to project %s" % a["project"])
        sys.exit(1)
    if not facts or not facts_known(facts):
        raw = os.environ.get("LC_FACTS_JSON", "")
        try:
            err = (json.loads(raw) or {}).get("error") if raw else None
        except ValueError:
            err = None
        err = ((facts or {}).get("db") or {}).get("error") or err
        if pre.get("encrypted") or ((facts or {}).get("db") or {}).get("encrypted"):
            say("the database is encrypted, so its checks were not done")
            return
        if pre.get("audit_rows") is None and pre.get("totp_fernet") is None:
            say("the installer could not read the database before the upgrade either (%s), "
                "so its checks were not done" % (err or "no answer"))
            return
        say("the installer could not read the database after the start (%s)"
            % (err or "no answer"))
        sys.exit(1)
    db, cnt = facts.get("db") or {}, facts.get("counts") or {}
    problems, done = [], []
    schema, target = db.get("schema"), a.get("target_schema") or ""
    if target.isdigit() and schema != int(target):
        problems.append("the database is at migration %s, not %s" % (schema, target))
    done.append("schema %s" % schema)
    env = candidate(facts, "env") or {}
    if (cnt.get("totp_fernet") or 0) > 0:
        if env.get("mfa") == "ok":
            done.append("MFA ok")
        else:
            problems.append("BRIDGE_MFA_KEY does not verify the TOTP secrets")
    else:
        done.append("no TOTP users")
    rows, head, pre_head = cnt.get("audit_rows") or 0, cnt.get("audit_head_id"), \
        pre.get("audit_head_id")
    if rows > 0:
        ok = (env.get("audit") or {}).get("result") == "ok"
        if not ok and pre.get("audit_ok"):
            problems.append("the audit chain no longer verifies")
        elif isinstance(head, int) and isinstance(pre_head, int) and head < pre_head:
            problems.append("the audit head fell from %d to %d" % (pre_head, head))
        else:
            done.append("audit chain %s, head %s -> %s" % (
                "valid" if ok else "unchanged (it did not verify before either)",
                pre_head if pre_head is not None else "none", head))
    det, pre_det = cnt.get("detections_max_id"), pre.get("detections_max_id")
    if isinstance(det, int) and isinstance(pre_det, int) and det < pre_det:
        problems.append("the highest detection id fell from %d to %d" % (pre_det, det))
    elif isinstance(pre_det, int):
        done.append("detections max id not lower")
    if problems:
        say("; ".join(problems))
        sys.exit(1)
    say("; ".join(done))


# ── --status ────────────────────────────────────────────────────────────


def openssl_out(*args):
    try:
        r = subprocess.run(["openssl"] + list(args), capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return r.stdout.decode("utf-8", "replace").strip() if r.returncode == 0 else ""


def tls_line(d):
    cert = os.path.join(d, "tls", "cert.pem")
    if not os.path.isfile(cert):
        return "no tls/cert.pem yet"
    end = openssl_out("x509", "-in", cert, "-noout", "-enddate").partition("=")[2]
    subj = openssl_out("x509", "-in", cert, "-noout", "-subject").partition("=")[2]
    iss = openssl_out("x509", "-in", cert, "-noout", "-issuer").partition("=")[2]
    kind = "self-signed" if subj and subj == iss else "operator-supplied"
    return "tls/cert.pem expires %s (%s)" % (end or "unknown", kind)


def health_of(status):
    m = re.search(r"\((healthy|unhealthy|health: starting)\)", status or "")
    return m.group(1).replace("health: ", "") if m else "no healthcheck"


def human_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0


def cmd_status(argv):
    """status DIR [--installer I]: where this install stands (read-only)."""
    d = os.path.realpath(argv[0])
    a = parse_flags(argv[1:], {"installer": True})
    installer = a.get("installer", "release")
    source = read_fd3()
    if not os.path.lexists(os.path.join(d, ".env")) and \
            not os.path.lexists(os.path.join(d, "docker-compose.yml")):
        details = []
        try:
            projects, _ = classify_host(helper_image())
            installs = [p for p in projects.values() if p.has_data]
            if installs:
                details = ["SigRift installs on this host:"] + install_list(installs)
        except DockerError:
            pass
        refuse("%s holds no SigRift install (no .env or docker-compose.yml)." % d, details,
               next_cmd="%s --status <one of the folders above>" % installer_prog("release")
               if details else installer_prog("release"))
    j = journal_load(d)
    hr = host_record(d) or {}
    pin = env_pin(d)
    project = pin or (j or {}).get("project") or compose_name(d) or derive_project(d)
    held = is_held(d)
    kind = hr.get("install_type") or ("source" if is_checkout(d) else "release")
    say("SigRift install in %s" % d)
    say("  identity  project %s (%s), install id %s, %s install" % (
        project, "pinned in .env" if pin else "not pinned yet",
        (hr.get("install_id") or "none yet")[:8] + ("..." if hr.get("install_id") else ""),
        kind))
    try:
        rows = docker_lines("docker ps -a", "ps", "-a", "--filter",
                            "label=%s=%s" % (PROJECT_LABEL, project), "--format",
                            '{{.Label "%s"}}\t{{.State}}\t{{.Status}}\t{{.Image}}\t{{.ID}}'
                            % SERVICE_LABEL)
    except DockerError:
        rows = []
    svcs = {}
    for line in rows:
        parts = (line.split("\t") + [""] * 5)[:5]
        svcs.setdefault(parts[0], parts)
    images = ", ".join("%s %s" % (s, svcs[s][3]) for s in ("bridge", "gateway") if s in svcs)
    say("  version   %s; %s" % (installed_version(d),
                               ("containers: " + images) if images
                               else "no bridge or gateway container"))
    say("  health    %s" % (", ".join(
        ("%s running/%s" % (s, health_of(svcs[s][2]))) if svcs[s][1] == "running"
        else "%s %s" % (s, svcs[s][1]) for s in ("bridge", "gateway") if s in svcs)
        or "nothing runs"))
    schema = "unknown (no bridge image here)"
    bridge = svcs.get("bridge")
    image = engine_image(installer, compose_owner(d) or "", installed_version(d),
                         bridge[4] if bridge else "", [d, os.path.join(d, HELD)], project)
    marker = False
    if image and source:
        facts = facts_for(project, os.path.join(d, ".env"), "", image, source)
        info = run_engine(image, "", "image-info", source)
        if facts.get("ok"):
            marker = bool(facts.get("restore_marker"))
            db = facts.get("db") or {}
            live = "encrypted" if db.get("encrypted") else db.get("schema")
            schema = "%s (the bridge image knows up to %s)" % (
                live if live is not None else "none", info.get("newest_migration", "unknown"))
        else:
            schema = "unknown (%s)" % (facts.get("error") or "the engine gave no answer")
    say("  schema    %s" % schema)
    nxt = "nothing to do"
    if j:
        frm, to, state = j.get("from_version"), j.get("to_version"), j.get("state")
        if state == "done":
            what = "done at %s" % (j.get("finished_at") or j.get("updated_at"))
        elif state == "aborted":
            what = "aborted at %s" % (j.get("finished_at") or j.get("updated_at"))
        elif state == "verify_failed":
            what = "VERIFY FAILED: %s" % (j.get("error") or "see the log")
            nxt = "%s (runs the checks again), or keep it as it is: %s" % (
                lifecycle_cmd("--resume", d), lifecycle_cmd("--resume --accept", d))
        elif state == "failed":
            what = "FAILED at step %s: %s" % (j.get("next") or "?", j.get("error") or "see the log")
            nxt = resume_cmd(d, j)
        else:
            pid = j.get("pid")
            if isinstance(pid, int) and alive(pid):
                what = "RUNNING step %s (pid %d)" % (j.get("next") or "?", pid)
                nxt = "tail -f %s" % q(os.path.join(d, j.get("log") or ""))
            else:
                what = "INTERRUPTED at step %s (pid gone)" % (j.get("next") or "?")
                nxt = resume_cmd(d, j)
        say("  journal   %s %s -> %s %s; log %s" % (j.get("op"), frm, to, what, j.get("log")))
        if journal_active(j) and not j.get("bridge_started_at") and state != "verify_failed":
            nxt += "; or undo it: %s" % lifecycle_cmd("--abort", d)
    else:
        say("  journal   no upgrade has run here yet")
    if held:
        say("  hold      docker-compose.yml is the hold stub; the real files are in %s/" % HELD)
    if marker:
        say("  marker    %s is in the data volume: a restore was interrupted, so no stack may "
            "start on this data" % RESTORE_MARKER)
    say("  next      %s" % nxt)
    snaps = list_snapshots(d)
    complete = [s for s in snaps if s.complete]
    incomplete = [s for s in snaps if not s.complete]
    if complete:
        say("  restore   %d files-only restore points (newest %s, %s); %d incomplete" % (
            len(complete), complete[0].id, human_bytes(complete[0].bytes()), len(incomplete)))
    else:
        say("  restore   no restore points yet%s" % (
            "; %d incomplete" % len(incomplete) if incomplete else ""))
    say("  TLS       %s" % tls_line(d))
    try:
        projects, _ = classify_host(helper_image())
        others = [p for p in projects.values() if p.has_data and p.name != project]
    except DockerError:
        others = []
    for p in sorted(others, key=lambda p: p.name):
        say("  others    %s (%s, %s, %s)" % (p.name, p.kind, p.state, p.folder or "folder not known"))


COMMANDS = {
    "identity": cmd_identity,
    "secrets-check": cmd_secrets_check,
    "env-merge": cmd_env_merge,
    "pin": cmd_pin,
    "compose-name": cmd_compose_name,
    "compose-owner": cmd_compose_owner,
    "installed-version": cmd_installed_version,
    "version-cmp": cmd_version_cmp,
    "facts-get": cmd_facts_get,
    "json-get": cmd_json_get,
    "foreign-mounts": cmd_foreign_mounts,
    "engine-image": cmd_engine_image,
    "engine-run": cmd_engine_run,
    "write-host-record": cmd_write_host_record,
    "plan": cmd_plan,
    "lock": cmd_lock,
    "lock-owner": cmd_lock_owner,
    "journal-new": cmd_journal_new,
    "journal-get": cmd_journal_get,
    "journal-vars": cmd_journal_vars,
    "journal-pending": cmd_journal_pending,
    "journal-step": cmd_journal_step,
    "journal-set": cmd_journal_set,
    "journal-state": cmd_journal_state,
    "journal-check": cmd_journal_check,
    "journal-guard": cmd_journal_guard,
    "journal-find": cmd_journal_find,
    "project-bridge": cmd_project_bridge,
    "renew-check": cmd_renew_check,
    "snapshot-files": cmd_snapshot_files,
    "snapshot-restore": cmd_snapshot_restore,
    "prune-snapshots": cmd_prune_snapshots,
    "install-files": cmd_install_files,
    "hold": cmd_hold,
    "unhold": cmd_unhold,
    "stop-project": cmd_stop_project,
    "ps-row": cmd_ps_row,
    "bridge-deadline": cmd_bridge_deadline,
    "setsid-exec": cmd_setsid_exec,
    "follow": cmd_follow,
    "verify-upgrade": cmd_verify_upgrade,
    "status": cmd_status,
}


def main(argv):
    if not argv or argv[0] not in COMMANDS:
        sys.exit("lc_tool: unknown command %r" % (argv[0] if argv else ""))
    COMMANDS[argv[0]](argv[1:])


if __name__ == "__main__":
    main(sys.argv[1:])
PY

lc_tool() {
    if [ -n "${LC_TOOL_PYC:-}" ] && [ -f "$LC_TOOL_PYC" ] && [ -O "$LC_TOOL_PYC" ]; then
        LC_ENGINE_BOOTSTRAP=${LC_ENGINE_BOOTSTRAP:-} LC_ENGINE_DATA_DIR=${LC_ENGINE_DATA_DIR:-} \
            LC_HELPER_IMAGE=${HELPER_IMAGE:-} LC_FACTS_JSON=${LC_FACTS_JSON:-} \
            LC_CALLER_DIR=${LC_CALLER_DIR:-} LC_SELF_DIR=${LC_SELF_DIR:-} \
            LC_UPGRADE_DIR=${LC_UPGRADE_DIR:-} \
            python3 -I "$LC_TOOL_PYC" "$@" 3<&0 </dev/null
    else
        LC_ENGINE_BOOTSTRAP=${LC_ENGINE_BOOTSTRAP:-} LC_ENGINE_DATA_DIR=${LC_ENGINE_DATA_DIR:-} \
            LC_HELPER_IMAGE=${HELPER_IMAGE:-} LC_FACTS_JSON=${LC_FACTS_JSON:-} \
            LC_CALLER_DIR=${LC_CALLER_DIR:-} LC_SELF_DIR=${LC_SELF_DIR:-} \
            LC_UPGRADE_DIR=${LC_UPGRADE_DIR:-} \
            python3 -I - "$@" 3<&0 <<<"$LC_TOOL_SRC"
    fi
}

# An installer run calls lc_tool a hundred times; compiling its source each
# time costs more than the work. It is compiled once per version into
# $TMPDIR/sigrift-lc-<uid>/ (a 0700 folder this user owns; anything else
# there, or a folder someone else made, means no cache), and run from there.
# Without a cache lc_tool runs the same source from LC_TOOL_SRC.
LC_TOOL_CACHE_PY='import hashlib, importlib.util, marshal, os, stat, sys, tempfile, time
src = sys.stdin.read()
d = os.path.join(os.environ.get("TMPDIR") or "/tmp", "sigrift-lc-%d" % os.geteuid())
try:
    os.mkdir(d, 0o700)
except FileExistsError:
    pass
st = os.lstat(d)
if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
    sys.exit(1)
key = hashlib.sha256(importlib.util.MAGIC_NUMBER + src.encode()).hexdigest()[:32]
path = os.path.join(d, "lc_tool-%s.pyc" % key)
try:
    st = os.lstat(path)
except FileNotFoundError:
    code = compile(src, "<lc_tool>", "exec")
    fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
    with os.fdopen(fd, "wb") as f:
        f.write(importlib.util.MAGIC_NUMBER + bytes(4) + int(time.time()).to_bytes(4, "little")
                + (len(src) & 0xFFFFFFFF).to_bytes(4, "little") + marshal.dumps(code))
    os.replace(tmp, path)
    old = sorted((os.path.join(d, n) for n in os.listdir(d) if n.startswith("lc_tool-")
                  and n.endswith(".pyc") and os.path.join(d, n) != path), key=os.path.getmtime)
    for p in old[:-3]:
        os.unlink(p)
    st = os.lstat(path)
if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
    sys.exit(1)
print(path)'
LC_TOOL_PYC=$(printf '%s' "$LC_TOOL_SRC" | python3 -I -c "$LC_TOOL_CACHE_PY" 2>/dev/null) || LC_TOOL_PYC=""
# <<< shared: lifecycle-tool

# >>> shared: lifecycle-engine (keep byte-identical in scripts/quickstart.sh and
#     scripts/install-release.sh; scripts/tests/test_install_scripts.py checks)
#
# The engine: python run inside the stack's own bridge image (python3,
# cryptography and the bridge's code; the v0.1.x images qualify) with the
# bridge_data volume mounted where the bridge mounts it, so it answers
# questions about the data with the bridge's own code: the schema, the
# counts the .env rules need, whether a key verifies the TOTP secrets and
# the audit chain. LC_ENGINE_BOOTSTRAP is all that goes in argv; the
# engine source and the request, which may hold secrets, follow on stdin
# as length-prefixed records (lc_tool engine-run), so no secret reaches
# argv or the container's environment, and --log-driver none keeps the
# daemon from storing a copy of the output.
LC_ENGINE_DATA_DIR=/app/src/sigrift/bridge/data
LC_ENGINE_BOOTSTRAP='import json, sys
r = sys.stdin.buffer
def rec():
    n = int(r.readline().decode("ascii").strip()); b = r.read(n)
    if len(b) != n: raise SystemExit("engine: short input")
    return b
src = rec(); req = json.loads(rec())
exec(compile(src, "<sigrift-engine>", "exec"), {"__name__": "sigrift_engine", "REQUEST": req})'

lc_engine_source() {
    cat <<'PY'
"""SigRift lifecycle engine: read-only facts about an install's data.

Runs inside the stack's own bridge image (python3 + cryptography + the
bridge's code), started by the installers with the bridge_data volume
at the bridge's own path. The request arrives on stdin after this
source (see LC_ENGINE_BOOTSTRAP) and may hold secrets; they are set in
this process only. The reply on stdout never holds one: fingerprints
are HMACs keyed by the secret.
"""

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import sqlite3
import sys

MARKER = ".sigrift-restore-incomplete"
RECORD = ".sigrift-install.json"
# Where the engine mounts bridge_secrets (read-only), when the project has it.
SECRETS_DIR = "/app/secrets"
FP_DOMAIN = b"sigrift-key-fingerprint-v1:"
AUDIT_VARS = ("BRIDGE_AUDIT_KEY", "BRIDGE_AUDIT_SECRET", "BRIDGE_MASTER_KEY")
SQLITE_MAGIC = b"SQLite format 3\x00"


def mfa_valid(key):
    """The shared BRIDGE_MFA_KEY rule (install-release.sh, repair_mfa_key)."""
    key = (key or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_+/-]{43}=", key):
        return False
    try:
        raw = base64.b64decode(key.replace("-", "+").replace("_", "/"), validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(raw) == 32


def key_bytes(key):
    return base64.b64decode(key.strip().replace("-", "+").replace("_", "/"), validate=True)


def fingerprint(secret, name):
    return hmac.new(secret, FP_DOMAIN + name.encode("ascii"), hashlib.sha256).hexdigest()[:32]


class SavedEnviron(object):
    """Set variables for the bridge's own helpers; put them back after."""

    def __init__(self, values):
        self.values = values
        self.saved = {}

    def __enter__(self):
        for k, v in self.values.items():
            self.saved[k] = os.environ.get(k)
            if v:
                os.environ[k] = v
            else:
                os.environ.pop(k, None)
        return self

    def __exit__(self, *exc):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return False


def open_ro(db):
    """A read-only connection that writes nothing into the volume.

    With a live writer the -wal and -shm exist and a plain read-only
    open shares them; without one (the stack is down) the file is read
    as immutable, so no -wal or -shm is created next to it.
    """
    from pathlib import Path
    uri = Path(db).resolve().as_uri() + "?mode=ro"
    if not os.path.exists(db + "-wal"):
        uri += "&immutable=1"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


class Unreadable(Exception):
    """A query failed for another reason than a table or column an older
    schema does not have: the counts are unknown, not zero."""


def scalar(conn, sql, default=None):
    try:
        row = conn.execute(sql).fetchone()
    except sqlite3.OperationalError as e:
        # A database from before the table (crypto_keys is migration 51)
        # has none of its rows; anything else (a malformed page, a lock, a
        # recovery the read-only open cannot do) leaves the count unknown.
        if re.match(r"no such (table|column)", str(e)):
            return default
        raise Unreadable("%s: %s" % (type(e).__name__, str(e)[:200]))
    except sqlite3.Error as e:
        raise Unreadable("%s: %s" % (type(e).__name__, str(e)[:200]))
    if row is None or row[0] is None:
        return default
    return row[0]


def audit_secret(values, data_dir):
    """(source, 32-byte secret or None) by the bridge's resolution order."""
    present = dict((k, (values.get(k) or "").strip()) for k in AUDIT_VARS)
    if any(present.values()):
        source = ("env-key" if present["BRIDGE_AUDIT_KEY"] else
                  "legacy-secret" if present["BRIDGE_AUDIT_SECRET"] else "master")
        try:
            from sigrift.bridge.storage import audit
            with SavedEnviron(dict((k, present[k]) for k in AUDIT_VARS)):
                return source, audit._get_audit_secret()
        except ImportError:
            pass
        if source == "env-key":
            return source, hashlib.sha256(present["BRIDGE_AUDIT_KEY"].encode()).digest()
        if source == "legacy-secret":
            return source, hashlib.sha256(present["BRIDGE_AUDIT_SECRET"].encode()).digest()
        return source, hashlib.sha256(
            b"bridge-audit-hmac:" + present["BRIDGE_MASTER_KEY"].encode()).digest()
    path = os.path.join(data_dir, "audit.key")
    try:
        if os.path.isfile(path):
            with open(path) as f:
                stored = f.read().strip()
            if stored:
                return "file", hashlib.sha256(stored.encode("utf-8")).digest()
    except OSError:
        pass
    return "none", None


class _Ctx(object):
    tenant_id = "default"

    def __init__(self, conn):
        self._conn = conn

    def get_conn(self):
        return self._conn


def verify_audit(conn, secret):
    """The bridge's own verifier, with this candidate's key."""
    from sigrift.bridge.storage import audit
    original = audit._get_audit_secret
    audit._get_audit_secret = lambda: secret
    try:
        return audit.AuditStore(_Ctx(conn)).verify_chain()
    finally:
        audit._get_audit_secret = original


def check_mfa(conn, key, fernet_rows):
    key = (key or "").strip()
    if not key:
        return "missing"
    if not mfa_valid(key):
        return "invalid-key"
    if not fernet_rows:
        return "n/a"
    from cryptography.fernet import Fernet, InvalidToken
    # As the bridge builds it (users._get_fernet): exactly the 32 bytes the
    # shared rule decodes. extract_timestamp checks the HMAC only; nothing
    # is decrypted.
    f = Fernet(base64.urlsafe_b64encode(key_bytes(key)))
    try:
        rows = conn.execute("SELECT totp_secret FROM users WHERE totp_secret LIKE 'fernet:%' "
                            "ORDER BY id LIMIT 3").fetchall()
    except sqlite3.Error:
        return "unchecked"
    for row in rows:
        try:
            f.extract_timestamp(row[0][len("fernet:"):].encode("utf-8"))
            return "ok"
        except (InvalidToken, ValueError, TypeError):
            continue
    return "fail"


def evaluate(values, conn, counts, data_dir):
    out = {"mfa": "n/a", "audit": {"result": "n/a", "source": "none", "valid": None,
                                   "checked": 0, "mismatches": 0},
           "keystore": {"present": False, "valid": None}, "fingerprints": {}}
    mfa = values.get("BRIDGE_MFA_KEY") or ""
    # Counts are None when the database could not be read (encrypted, or a
    # query failed): nothing can be verified, which is not "nothing to verify".
    unknown = counts.get("users") is None
    out["mfa"] = check_mfa(conn, mfa, counts.get("totp_fernet")) if conn is not None else (
        "missing" if not mfa.strip() else "invalid-key" if not mfa_valid(mfa) else
        "unchecked" if unknown else "n/a")
    source, secret = audit_secret(values, data_dir)
    audit = out["audit"]
    audit["source"] = source
    if unknown:
        audit["result"] = "unchecked"
    elif secret is None:
        audit["result"] = "no-key" if counts.get("audit_rows") else "n/a"
    elif conn is not None and counts.get("audit_rows"):
        try:
            r = verify_audit(conn, secret)
            audit.update(valid=bool(r.get("valid")), checked=int(r.get("checked") or 0),
                         mismatches=len(r.get("errors") or []))
            if audit["checked"] == 0:
                audit["result"] = "n/a"
            elif audit["mismatches"] < audit["checked"]:
                audit["result"] = "ok"
            else:
                audit["result"] = "fail"
        except Exception as e:  # a damaged table, an older bridge: unchecked
            audit["result"] = "unchecked"
            audit["error"] = type(e).__name__
    keystore = values.get("BRIDGE_KEYSTORE_KEY") or ""
    out["keystore"] = {"present": bool(keystore.strip()),
                       "valid": mfa_valid(keystore) if keystore.strip() else None}
    fps = out["fingerprints"]
    fps["audit"] = fingerprint(secret, "audit") if secret is not None else None
    fps["mfa"] = fingerprint(key_bytes(mfa), "mfa") if mfa_valid(mfa) else None
    fps["keystore"] = fingerprint(key_bytes(keystore), "keystore") if mfa_valid(keystore) else None
    return out


def read_record(data_dir):
    try:
        with open(os.path.join(data_dir, RECORD)) as f:
            rec = json.load(f)
        return rec if isinstance(rec, dict) else None
    except (OSError, ValueError):
        return None


UNKNOWN_COUNTS = {"users": None, "totp_fernet": None, "audit_rows": None,
                  "audit_head_id": None, "crypto_keys": None, "detections_max_id": None}


def op_facts(req):
    data_dir = req["data_dir"]
    db = os.path.join(data_dir, "detections.db")
    # A restore (Phase 1b) leaves the marker at the root of each volume it
    # restores: bridge_data, and bridge_secrets when the project has it.
    markers = [where for where, root in (("bridge_data", data_dir),
                                         ("bridge_secrets", SECRETS_DIR))
               if os.path.lexists(os.path.join(root, MARKER))]
    out = {"format": 1, "ok": True, "op": "facts", "data_dir_exists": os.path.isdir(data_dir),
           "db": {"present": False, "encrypted": False, "bytes": 0, "wal_bytes": 0,
                  "schema": None, "error": None},
           "counts": {"users": 0, "totp_fernet": 0, "audit_rows": 0, "audit_head_id": None,
                      "crypto_keys": 0, "detections_max_id": None},
           "restore_marker": bool(markers), "restore_markers": markers,
           "record": read_record(data_dir), "candidates": {}}
    conn = None
    if os.path.isfile(db):
        info = out["db"]
        info["present"] = True
        info["bytes"] = os.path.getsize(db)
        try:
            info["wal_bytes"] = os.path.getsize(db + "-wal")
        except OSError:
            info["wal_bytes"] = 0
        with open(db, "rb") as f:
            head = f.read(16)
        if head and head != SQLITE_MAGIC:
            # SQLCipher (BRIDGE_DB_ENCRYPTION_KEY): nothing can be counted.
            info["encrypted"] = True
            out["counts"] = dict(UNKNOWN_COUNTS)
        elif head:
            try:
                conn = open_ro(db)
                info["schema"] = scalar(conn, "SELECT MAX(version) FROM schema_version")
                c = out["counts"]
                c["users"] = scalar(conn, "SELECT COUNT(*) FROM users", 0)
                c["totp_fernet"] = scalar(
                    conn, "SELECT COUNT(*) FROM users WHERE totp_secret LIKE 'fernet:%'", 0)
                c["audit_rows"] = scalar(conn, "SELECT COUNT(*) FROM audit_log", 0)
                c["audit_head_id"] = scalar(conn, "SELECT MAX(id) FROM audit_log")
                c["crypto_keys"] = scalar(conn, "SELECT COUNT(*) FROM crypto_keys", 0)
                c["detections_max_id"] = scalar(conn, "SELECT MAX(rowid) FROM detections")
            except (sqlite3.Error, Unreadable) as e:
                info["error"] = str(e) if isinstance(e, Unreadable) else "%s: %s" % (
                    type(e).__name__, str(e)[:200])
                # Unknown, never zero: "no rows" would let a run generate a
                # new key under data that needs the old one.
                out["counts"] = dict(UNKNOWN_COUNTS)
                if conn is not None:
                    conn.close()
                conn = None
    try:
        cands = req.get("candidates") or {}
        for source in ("env", "container", "shell"):
            values = cands.get(source)
            if values is None:
                out["candidates"][source] = None
            elif isinstance(values, dict) and values.get("same_as"):
                out["candidates"][source] = {"same_as": values["same_as"]}
            else:
                out["candidates"][source] = evaluate(values, conn, out["counts"], data_dir)
    finally:
        if conn is not None:
            conn.close()
    return out


def op_image_info(req):
    import platform
    from sigrift.bridge.storage.base import _MIGRATIONS
    return {"format": 1, "ok": True, "op": "image-info",
            "newest_migration": max(v for v, _, _ in _MIGRATIONS),
            "python": platform.python_version()}


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def op_write_record(req):
    """bridge_data/.sigrift-install.json, with the fingerprints added."""
    data_dir = req["data_dir"]
    record = dict(req.get("record") or {})
    secrets = req.get("secrets") or {}
    source, secret = audit_secret(secrets, data_dir)
    mfa = secrets.get("BRIDGE_MFA_KEY") or ""
    keystore = secrets.get("BRIDGE_KEYSTORE_KEY") or ""
    record["fingerprints"] = {
        "audit": {"source": source,
                  "fp": fingerprint(secret, "audit") if secret is not None else None},
        "mfa": fingerprint(key_bytes(mfa), "mfa") if mfa_valid(mfa) else None,
        "keystore": fingerprint(key_bytes(keystore), "keystore") if mfa_valid(keystore) else None,
    }
    db = os.path.join(data_dir, "detections.db")
    if os.path.isfile(db) and record.get("schema") is None:
        with open(db, "rb") as f:
            plain = f.read(16) == SQLITE_MAGIC
        if plain:
            conn = open_ro(db)
            try:
                record["schema"] = scalar(conn, "SELECT MAX(version) FROM schema_version")
            except Unreadable:
                record["schema"] = None
            finally:
                conn.close()
    path = os.path.join(data_dir, RECORD)
    tmp = path + ".tmp"
    if os.path.lexists(tmp):
        os.unlink(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    fsync_dir(data_dir)
    return {"format": 1, "ok": True, "op": "write-record"}


OPS = {"facts": op_facts, "image-info": op_image_info, "write-record": op_write_record}


def run(req):
    try:
        reply = OPS[req["op"]](req)
    except Exception as e:  # the type and a short message only: never a value
        sys.stdout.write(json.dumps({"format": 1, "ok": False,
                                     "error": "%s: %s" % (type(e).__name__, str(e)[:200])}))
        sys.stdout.flush()
        return 1
    sys.stdout.write(json.dumps(reply, sort_keys=True))
    sys.stdout.flush()
    return 0


if __name__ == "sigrift_engine":
    sys.exit(run(REQUEST))  # noqa: F821 - set by the bootstrap
PY
}

# lc_engine IMAGE PROJECT OP [ENV_FILE [BRIDGE_CONTAINER]] prints the
# engine's JSON reply (exit 1 when it is not ok).
lc_engine() {
    lc_engine_source | lc_tool engine-run --image "$1" --project "$2" --op "$3" \
        --env-file "${4:-}" --bridge "${5:-}"
}

# lc_engine_image_info IMAGE prints {"newest_migration": N, ...}: the
# newest database migration that bridge image knows.
lc_engine_image_info() {
    lc_engine_source | lc_tool engine-run --image "$1" --op image-info
}
# <<< shared: lifecycle-engine

# >>> shared: identity (keep byte-identical in scripts/quickstart.sh and
#     scripts/install-release.sh; scripts/tests/test_install_scripts.py checks)
#
# Which install a run acts on. Docker Compose names the project (and so
# every volume) after COMPOSE_PROJECT_NAME, else after the folder, so a
# newly unpacked release folder, a renamed or a copied one would address
# another, empty stack and pair new secrets with old data, or old secrets
# with nothing. lc_identity asks lc_tool, which reads the Compose labels
# of every volume and container on this host, and loads its decision into
# the LC_* variables of LC_DECISION_KEYS. It refuses, changing nothing,
# when the run could act on the wrong data; every refusal ends with
# "Nothing was changed." and one next command, and exits 3.
LC_STATE_DIRNAME=.sigrift
# Reserved for the restore of Phase 1b, which writes it at the root of the
# bridge_data volume before it moves restored data into place and removes
# it last: while it exists the data is half restored, so the installers
# never start a stack and the bridge (Phase 3) refuses to start.
LC_RESTORE_MARKER=.sigrift-restore-incomplete
# The first line of the placeholder docker-compose.yml that holds a stack
# while an upgrade has it stopped (lifecycle block).
# shellcheck disable=SC2034
LC_HOLD_HEADER="# SigRift hold stub"
# 1 failed after a change; 2 usage; 3 refused, nothing changed; 4 stopped
# in the middle of an operation (the journal holds its state).
# shellcheck disable=SC2034
LC_EXIT_FAILED=1 LC_EXIT_USAGE=2 LC_EXIT_REFUSED=3 LC_EXIT_STOPPED=4
# Until rollback exists (Phase 1b) the way back is the documented one.
LC_DOWNGRADE_NEXT='see "Going back" in INSTALL.md, "Upgrading a release install"'
SIGRIFT_UPGRADE_PROMPT_SECONDS=${SIGRIFT_UPGRADE_PROMPT_SECONDS:-20}
LC_SNAPSHOTS=${LC_SNAPSHOTS:-0}
LC_DECISION_KEYS="LC_KIND LC_TARGET_DIR LC_PROJECT LC_PROJECT_HOW LC_PIN LC_AUTO LC_HAS_DATA"
LC_DECISION_KEYS+=" LC_FROM_VERSION LC_MOVED_FROM LC_INSTALL_ID LC_BRIDGE_CONTAINER"
LC_DECISION_KEYS+=" LC_GATEWAY_CONTAINER LC_WAS_RUNNING LC_OTHERS LC_PORT LC_ADOPTED_FROM LC_PROOF"

# lc_refuse NEXT MESSAGE [DETAIL...] — the refusal format; exits 3.
# Inside an upgrade's detached part (LC_CRITICAL=1: the stack is already
# stopped) it says where the upgrade stopped instead, and exits 4.
lc_refuse() {
    local next="$1" line
    shift
    printf 'Error: %s\n' "$1" >&2
    shift
    for line in "$@"; do
        printf '  %s\n' "$line" >&2
    done
    if [ "${LC_CRITICAL:-0}" = 1 ]; then
        printf '  The upgrade stopped at step %s and changed nothing more; fix this, then resume it (%s) or undo it (%s).\n' \
            "${LC_STEP:-?}" "$(lc_here_cmd --resume)" "$(lc_here_cmd --abort)" >&2
        printf 'Next: %s\n' "$next" >&2
        exit "$LC_EXIT_STOPPED"
    fi
    printf 'Next: %s\nNothing was changed.\n' "$next" >&2
    exit "$LC_EXIT_REFUSED"
}

lc_note() {
    printf 'NOTE: %s\n' "$*" >&2
}

# lc_identity INSTALLER (release | quickstart) — decide, or refuse.
# Reads LC_SELF_DIR, VERSION, the port (PORT for the release installer,
# which sets it from UC_PORT; UC_PORT for quickstart, where a PORT exported
# for something else must not count), SIGRIFT_BIND, OWNER and the flags
# LC_UPGRADE_DIR, LC_NEW_INSTANCE, LC_ADOPT_PROJECT. The engine source goes
# to lc_tool on stdin: adopting a renamed folder's data needs the engine's
# verdict on this folder's .env against that data.
lc_identity() {
    local decision args port
    LC_INSTALLER=$1
    if [ "$LC_INSTALLER" = release ]; then port=${PORT:-8444}; else port=${UC_PORT:-8444}; fi
    args=(identity --installer "$LC_INSTALLER" --self-dir "$LC_SELF_DIR"
        --version "${VERSION:-main}" --port "$port"
        --bind "${SIGRIFT_BIND:-127.0.0.1}" --owner "${OWNER:-}")
    [ -z "${LC_UPGRADE_DIR:-}" ] || args+=(--target "$LC_UPGRADE_DIR")
    [ "${LC_NEW_INSTANCE:-0}" = 0 ] || args+=(--new-instance)
    [ -z "${LC_ADOPT_PROJECT:-}" ] || args+=(--adopt-project "$LC_ADOPT_PROJECT")
    decision=$(lc_engine_source | lc_tool "${args[@]}") || exit "$?"
    lc_load_decision "$decision"
}

# lc_load_decision TEXT — KEY=VALUE lines; only LC_DECISION_KEYS, no eval.
lc_load_decision() {
    local line key
    while IFS= read -r line; do
        key=${line%%=*}
        case " $LC_DECISION_KEYS " in
            *" $key "*) printf -v "$key" '%s' "${line#*=}" ;;
        esac
    done <<<"$1"
}

# lc_confirm_auto_target — after the plan of an automatic upgrade: when
# stdin is a terminal (stdout may be a pipe: `| tee upgrade.log`), ask once
# with a timeout that means yes; without one, go on. read -p prints its
# prompt on stderr.
lc_confirm_auto_target() {
    local answer="" secs="${SIGRIFT_UPGRADE_PROMPT_SECONDS:-0}"
    [ -t 0 ] || return 0
    case "$secs" in ''|*[!0-9]*) return 0 ;; esac
    [ "$secs" -gt 0 ] || return 0
    if read -r -t "$secs" -p "Upgrade it now? [Y/n] (continues in ${secs} s): " answer; then
        case "$answer" in
            n|N|no|No|NO)
                echo "Not upgraded: you answered no. Nothing was changed." >&2
                exit "$LC_EXIT_REFUSED"
                ;;
        esac
    else
        echo >&2
    fi
}

# lc_pin_note — what the pin line says, by how the project was found.
lc_pin_note() {
    case "${LC_PROJECT_HOW:-}" in
        derived)
            if [ "${LC_HAS_DATA:-0}" = 1 ]; then
                printf '==> Pinned COMPOSE_PROJECT_NAME=%s in .env (the name Docker Compose already used; volume names stay the same).' "$LC_PROJECT"
            else
                printf '==> Pinned COMPOSE_PROJECT_NAME=%s in .env.' "$LC_PROJECT"
            fi
            ;;
        adopted)
            printf '==> Adopted project %s for this folder (renamed from %s; .env matches its data: %s). Pinned it in .env.' \
                "$LC_PROJECT" "${LC_ADOPTED_FROM:-an unknown folder}" "${LC_PROOF:-no contradiction found}"
            ;;
        labels)
            printf '==> Pinned COMPOSE_PROJECT_NAME=%s in .env (the project this folder'"'"'s containers run under; volume names stay the same).' "$LC_PROJECT"
            ;;
        *) printf '==> Pinned COMPOSE_PROJECT_NAME=%s in .env.' "$LC_PROJECT" ;;
    esac
}

# lc_pin_project ENV_FILE [new] — write COMPOSE_PROJECT_NAME=LC_PROJECT
# once (no backup for a .env this run just wrote), then read it back the
# way every later plain `docker compose` in this folder will: a Compose
# that ignored it would address another stack.
lc_pin_project() {
    local env_file="$1" got args
    args=(pin "$env_file" "$LC_PROJECT" --note "$(lc_pin_note)")
    [ "${2:-}" != new ] || args+=(--no-backup)
    lc_tool "${args[@]}" </dev/null
    got=$(lc_tool compose-name . </dev/null) || got=""
    if [ "$got" != "$LC_PROJECT" ]; then
        printf 'Error: docker compose ignored COMPOSE_PROJECT_NAME in %s (it used project %s, not %s), so this run stops before it starts anything.\n' \
            "$env_file" "${got:-none}" "$LC_PROJECT" >&2
        printf '  %s was updated (its previous text is in the newest %s.bak.*~).\n' "$env_file" "$env_file" >&2
        printf 'Next: docker compose version\n' >&2
        exit "$LC_EXIT_FAILED"
    fi
}
# <<< shared: identity

# >>> shared: preflight (keep byte-identical in scripts/quickstart.sh and
#     scripts/install-release.sh; scripts/tests/test_install_scripts.py checks)
#
# Read-only checks that run after lc_identity and before the first file
# change. Facts about the data come from the engine, run in the stack's own
# bridge image; LC_FACTS_JSON holds them for the rest of the run (counts,
# verdicts and fingerprints, never a secret value). Each check refuses
# through lc_refuse (or lc_tool's refuse) and so changes nothing.

# lc_facts — LC_FACTS_JSON and LC_DB_BYTES for the decided project. With
# no bridge image on this host to read the data with, a release run pulls
# the one it installs (a pull changes no file); a source install cannot,
# and its facts stay unknown, which every .env rule treats as "data may
# depend on it".
lc_facts() {
    local image ref rc
    LC_FACTS_JSON='{}'
    LC_DB_BYTES=0
    [ "${LC_HAS_DATA:-0}" = 1 ] || return 0
    image=$(lc_tool engine-image --installer "$LC_INSTALLER" --project "$LC_PROJECT" --dir . \
        --bridge "${LC_BRIDGE_CONTAINER:-}" --owner "${OWNER:-}" --version "${VERSION:-}" </dev/null)
    if [ -z "$image" ] && [ "$LC_INSTALLER" = release ] && [[ "${VERSION:-}" =~ ^v ]]; then
        ref="ghcr.io/${OWNER}/sigrift-bridge:${VERSION}"
        echo "==> Pulling ${ref} to read this install's data with (the stack keeps running)..."
        rc=0
        docker pull "$ref" >/dev/null || rc=$?
        if [ "$rc" -ne 0 ]; then
            lc_refuse "docker pull ${ref}" \
                "could not pull ${ref} (docker pull exited ${rc}). The running stack and every file are as they were."
        fi
        image=$ref
    fi
    if [ -z "$image" ]; then
        LC_FACTS_JSON='{"format": 1, "ok": false, "error": "no bridge image on this host to read the data with"}'
        return 0
    fi
    LC_FACTS_JSON=$(lc_engine "$image" "$LC_PROJECT" facts .env "${LC_BRIDGE_CONTAINER:-}") || true
    [ -n "$LC_FACTS_JSON" ] || LC_FACTS_JSON='{"format": 1, "ok": false, "error": "the engine gave no answer"}'
    LC_DB_BYTES=$(lc_tool facts-get db.bytes </dev/null)
    LC_DB_BYTES=${LC_DB_BYTES:-0}
}

# lc_check_restore_marker — never start on half-restored data. A restore
# leaves the marker at the root of each volume it restores (bridge_data,
# bridge_secrets) until it is complete.
lc_check_restore_marker() {
    local next where
    [ "$(lc_tool facts-get restore_marker </dev/null)" = 1 ] || return 0
    where=$(lc_tool facts-get restore_markers </dev/null | tr -d '[]"' | sed 's/, */ and /g')
    if [ "$LC_INSTALLER" = release ]; then
        next=$(lc_here_cmd --status)
    else
        next="grep -n -A8 'restore-incomplete' TROUBLESHOOTING.md"
    fi
    lc_refuse "$next" \
        "the ${where:-bridge_data} volume of ${LC_PROJECT} holds ${LC_RESTORE_MARKER}, left by an interrupted restore, so the stack must not start."
}

# lc_secrets_check — the running bridge (and gateway), .env and the shell
# must agree on every data-bound secret, or the data must show which one
# is right (lc_tool secrets-check; --keep-running-secrets takes the
# running bridge's values, written by lc_env_merge).
lc_secrets_check() {
    local args
    [ -e .env ] || return 0
    args=(secrets-check --env-file .env --bridge "${LC_BRIDGE_CONTAINER:-}"
        --gateway "${LC_GATEWAY_CONTAINER:-}" --has-data "${LC_HAS_DATA:-0}"
        --installer "$LC_INSTALLER")
    [ "${LC_KEEP_RUNNING_SECRETS:-0}" = 0 ] || args+=(--keep-running-secrets)
    lc_tool "${args[@]}" </dev/null
}

# lc_env_merge ENV_FILE INSTALLER [--plan] — the .env rules: an existing
# .env is never replaced; a missing key is added only where nothing
# depends on it, a missing data-bound one is restored from the running
# bridge when it matches the data; the pin and the config migrations go
# in the same single edit (one ENV_FILE.bak.<time>~). Returns 10, writing
# nothing, while it needs an admin password (no user exists yet): the
# caller asks for one and runs it again with LC_ADMIN_PASSWORD set.
# LC_ENV_RESULT gets what it did (key names and migration ids only).
lc_env_merge() {
    local env_file="$1" installer="$2" mode="${3:-}" out="" rc=0 line args
    args=(env-merge --env-file "$env_file" --installer "$installer" --version "${VERSION:-main}"
        --bridge "${LC_BRIDGE_CONTAINER:-}" --has-data "${LC_HAS_DATA:-0}")
    [ "${LC_PIN:-0}" != 1 ] || args+=(--pin "$LC_PROJECT" --pin-note "$(lc_pin_note)")
    [ "${LC_KEEP_RUNNING_SECRETS:-0}" = 0 ] || args+=(--keep-running-secrets)
    [ "${LC_NO_PROMPT:-0}" = 0 ] || args+=(--no-prompt)
    [ "$mode" != --plan ] || args+=(--plan)
    if [ -n "${LC_ADMIN_PASSWORD+x}" ]; then
        # printf is a builtin: the password reaches lc_tool on a pipe only.
        out=$(printf '%s' "$LC_ADMIN_PASSWORD" | lc_tool "${args[@]}" --password-fd3) || rc=$?
    else
        out=$(lc_tool "${args[@]}" </dev/null) || rc=$?
    fi
    while IFS= read -r line; do
        case "$line" in
            LC_ENV_RESULT=*) LC_ENV_RESULT=${line#LC_ENV_RESULT=} ;;
            "") ;;
            *) printf '%s\n' "$line" ;;
        esac
    done <<<"$out"
    return "$rc"
}

# lc_check_foreign_mounts — a container of another project that mounts
# this project's volumes could write the data while the installer works.
lc_check_foreign_mounts() {
    [ "${LC_HAS_DATA:-0}" = 1 ] || return 0
    lc_tool foreign-mounts --project "$LC_PROJECT" --installer "$LC_INSTALLER" </dev/null
}

# lc_check_versions — never an older release over newer data: by version
# (a release can change data one way without a migration), then by
# schema once the target bridge image is on this host (it knows only the
# migrations up to its newest, and refuses a newer database).
lc_check_versions() {
    local live newest image
    [ "$LC_INSTALLER" = release ] || return 0
    if [ "$(lc_tool version-cmp "${VERSION:-}" "${LC_FROM_VERSION:-unknown}" </dev/null)" = -1 ]; then
        lc_refuse "$LC_DOWNGRADE_NEXT" \
            "${VERSION} is older than the installed ${LC_FROM_VERSION}; newer releases can change the data one way, so the installer never installs an older release over it."
    fi
    [ "${LC_HAS_DATA:-0}" = 1 ] || return 0
    live=$(lc_tool facts-get db.schema </dev/null)
    [ -n "$live" ] || return 0
    image="ghcr.io/${OWNER}/sigrift-bridge:${VERSION}"
    [ -n "$(docker image inspect --format '{{.Id}}' "$image" 2>/dev/null)" ] || return 0
    newest=$(lc_engine_image_info "$image" | lc_tool json-get newest_migration) || newest=""
    # The schema the upgrade's checks expect after the start.
    # shellcheck disable=SC2034
    LC_TARGET_SCHEMA=$newest
    case "$newest" in ''|*[!0-9]*) return 0 ;; esac
    if [ "$newest" -lt "$live" ]; then
        lc_refuse "$(lc_here_cmd --status)" \
            "the ${VERSION} bridge knows database migrations up to ${newest}, but this install's database is at migration ${live} (written by a newer release); the bridge would refuse to start."
    fi
}

# lc_preflight — every check above, in order; nothing is written.
lc_preflight() {
    local rc=0
    lc_facts
    lc_check_restore_marker
    lc_secrets_check
    if [ -e .env ]; then
        lc_env_merge .env "$LC_INSTALLER" --plan || rc=$?
        [ "$rc" -eq 0 ] || [ "$rc" -eq 10 ] || exit "$rc"
    fi
    lc_check_foreign_mounts
    lc_check_versions
}
# <<< shared: preflight

# >>> shared: lifecycle (keep byte-identical in scripts/quickstart.sh and
#     scripts/install-release.sh; scripts/tests/test_install_scripts.py checks)
#
# The guarded upgrade of a release install. Nothing changes before the new
# images are on this host; then a files-only restore point (.env, compose,
# VERSION, tls/, the installer) is taken, and the steps that stop the stack
# run detached from the terminal (an SSH drop cannot stop them halfway),
# journaled in .sigrift/journal.json so --status, --resume and --abort know
# where they stand. While the stack is stopped, docker-compose.yml is a
# placeholder that starts nothing touching the data (the hold). The new
# bridge starts first and may take as long as its migrations need; the
# gateway follows once the bridge is healthy. Records are written only
# after a healthy run. Quickstart uses the lock only (Phase 2 adds the
# rest for source installs).

# The steps of the detached part of an upgrade, in order. The restore point
# ("snapshot") is taken before the journal exists, so a failure there
# changes nothing; "installer" runs only for --upgrade DIR and the
# automatic path.
LC_UPGRADE_STEPS="snapshot installer stop hold switch start-bridge start-rest verify record"
# What the detached run takes over from the run that started it (no
# secrets: versions, the identity decision, flags).
LC_JOURNAL_VARS="VERSION VERSION_REQUESTED OWNER PORT $LC_DECISION_KEYS LC_KEEP_RUNNING_SECRETS"
LC_JOURNAL_VARS+=" LC_TARGET_SCHEMA LC_DB_BYTES LC_SNAPSHOT_ID LC_OP LC_CALLER_DIR"
LC_JOURNAL_VARS+=" SIGRIFT_BIND SIGRIFT_TLS_SANS"
LC_SNAPSHOT_ID=${LC_SNAPSHOT_ID:-}
# Set by lc_lock_acquire in the process that holds the lock; never taken
# from the environment.
LC_LOCK_HELD=0

# lc_lock_acquire DIR OP — one changing run per install folder: flock(2)
# on the folder itself (fd 9, no file created), held by every process
# that inherits fd 9, the detached upgrade too. Busy: M-LOCKED (exit 3);
# for renew-tls it returns 5 so the caller defers. Where the filesystem
# has no directory locks, .sigrift/lock is the lock file instead. The
# detached part (LC_LOCK_INHERITED=1, set by setsid-exec) checks that fd 9
# really is the held lock, and does not pass the claim on.
lc_lock_acquire() {
    local dir="$1" op="$2" rc=0
    [ "$LC_LOCK_HELD" != 1 ] || return 0
    if [ "${LC_LOCK_INHERITED:-0}" = 1 ]; then
        lc_tool lock 9 "$dir" "$op" --inherited </dev/null || exit "$LC_EXIT_USAGE"
        unset LC_LOCK_INHERITED
        LC_LOCK_HELD=1
        return 0
    fi
    exec 9<"$dir"
    lc_tool lock 9 "$dir" "$op" --installer "${LC_INSTALLER:-release}" </dev/null || rc=$?
    if [ "$rc" -eq 6 ]; then
        mkdir -m 0700 "$dir/$LC_STATE_DIRNAME" 2>/dev/null || true
        exec 9>>"$dir/$LC_STATE_DIRNAME/lock"
        rc=0
        lc_tool lock 9 "$dir" "$op" --installer "${LC_INSTALLER:-release}" </dev/null || rc=$?
    fi
    [ "$rc" -eq 0 ] || [ "$rc" -eq 5 ] || exit "$rc"
    [ "$rc" -ne 0 ] || LC_LOCK_HELD=1
    return "$rc"
}

# lc_pull_images — the new images, pulled while the old stack runs and
# before any file changes: a failed pull leaves everything as it was.
# Records each image's digest (LC_IMAGE_REFS, for the journal) and id
# (LC_PULLED_ID_bridge, LC_PULLED_ID_gateway). Every later `up` uses
# --pull never, whatever the compose file's pull_policy says.
lc_pull_images() {
    local svc ref rc digest id
    LC_IMAGE_REFS=""
    for svc in bridge gateway; do
        ref="ghcr.io/${OWNER}/sigrift-${svc}:${VERSION}"
        echo "==> Pulling ${ref} (the running stack is not touched)"
        rc=0
        docker pull --quiet "$ref" >/dev/null || rc=$?
        if [ "$rc" -ne 0 ]; then
            lc_refuse "docker pull ${ref}" \
                "could not pull ${ref} (docker pull exited ${rc}). The running stack and every file are as they were."
        fi
        digest=$(docker image inspect --format '{{index .RepoDigests 0}}' "$ref" 2>/dev/null) || digest=""
        id=$(docker image inspect --format '{{.Id}}' "$ref" 2>/dev/null) || id=""
        LC_IMAGE_REFS+="${svc}=${ref}${digest:+@${digest##*@}} "
        printf -v "LC_PULLED_ID_${svc}" '%s' "$id"
    done
}

# lc_decide_mode — LC_MODE: fresh (no .env), upgrade (another version,
# or a container that runs another image than the one just pulled: a
# moving :main tag), or rerun.
# shellcheck disable=SC2034
lc_decide_mode() {
    local svc cid running pulled
    if [ ! -e .env ]; then
        LC_MODE=fresh
        return 0
    fi
    if [ "${LC_FROM_VERSION:-unknown}" != "$VERSION" ]; then
        LC_MODE=upgrade
        return 0
    fi
    for svc in bridge gateway; do
        if [ "$svc" = bridge ]; then cid=${LC_BRIDGE_CONTAINER:-}; else cid=${LC_GATEWAY_CONTAINER:-}; fi
        [ -n "$cid" ] || continue
        running=$(docker inspect --format '{{.Image}}' "$cid" 2>/dev/null) || running=""
        pulled="LC_PULLED_ID_${svc}"
        pulled=${!pulled:-}
        if [ -n "$running" ] && [ -n "$pulled" ] && [ "$running" != "$pulled" ]; then
            LC_MODE=upgrade
            return 0
        fi
    done
    LC_MODE=rerun
}

# lc_check_target_schema — after the pull: the new bridge must know every
# migration the database already has (it refuses a newer one).
lc_check_target_schema() {
    local live newest
    [ "${LC_HAS_DATA:-0}" = 1 ] || return 0
    newest=$(lc_engine_image_info "ghcr.io/${OWNER}/sigrift-bridge:${VERSION}" \
        | lc_tool json-get newest_migration) || newest=""
    case "$newest" in ''|*[!0-9]*) return 0 ;; esac
    LC_TARGET_SCHEMA=$newest
    live=$(lc_tool facts-get db.schema </dev/null)
    case "$live" in ''|*[!0-9]*) return 0 ;; esac
    if [ "$newest" -lt "$live" ]; then
        lc_refuse "$(lc_here_cmd --status)" \
            "the ${VERSION} bridge knows database migrations up to ${newest}, but this install's database is at migration ${live} (written by a newer release); the bridge would refuse to start."
    fi
}

# lc_snapshot_files REASON — a files-only restore point of this folder in
# .sigrift/snapshots/ (the TLS key through the helper image when this
# user cannot read it); LC_SNAPSHOT_ID names it. One that would equal the
# newest is not written again.
lc_snapshot_files() {
    local out
    out=$(lc_tool snapshot-files . --reason "$1" --from "${LC_FROM_VERSION:-unknown}" \
        --to "${VERSION:-}" --installer-version "${VERSION:-}" --project "${LC_PROJECT:-}" \
        </dev/null) || return 1
    LC_SNAPSHOT_ID=${out%% *}
    if [ "${out#* }" = reused ]; then
        echo "==> Restore point ${LC_SNAPSHOT_ID} (files only) already holds these files"
    else
        echo "==> Restore point ${LC_SNAPSHOT_ID} (files only): ${PWD}/${LC_STATE_DIRNAME}/snapshots/${LC_SNAPSHOT_ID}"
    fi
}

# tls_before_swap CERT KEY — called by tls_ensure_cert just before it
# replaces the certificate and key: an install that keeps restore points
# saves the old pair first, unless this run already took its restore
# point. A failure only warns: an expiring certificate must still be
# renewed.
tls_before_swap() {
    local out from="${LC_FROM_VERSION:-unknown}"
    [ "${LC_SNAPSHOTS:-0}" = 1 ] || return 0
    [ -z "$LC_SNAPSHOT_ID" ] || return 0
    [ -e "$2" ] || [ -e "$1" ] || return 0
    if ! out=$(lc_tool snapshot-files . --reason "${LC_OP:-renew-tls}" --from "$from" \
            --to "${LC_SNAPSHOT_TO:-$from}" --installer-version "${VERSION:-}" \
            --project "${LC_PROJECT:-}" </dev/null 2>&1); then
        echo "WARNING: could not save a restore point of tls/ before renewing (${out:-unknown reason}); renewing anyway." >&2
        LC_SNAPSHOT_ID=-
        return 0
    fi
    LC_SNAPSHOT_ID=${out%% *}
    echo "==> Saved the old certificate and key in restore point ${LC_SNAPSHOT_ID}"
}

# lc_journal_vars — the LC_JOURNAL_VARS as KEY=VALUE lines.
lc_journal_vars() {
    local k
    for k in $LC_JOURNAL_VARS; do
        printf '%s=%s\n' "$k" "${!k:-}"
    done
}

# lc_load_journal_vars — the carried variables of this folder's journal
# (only LC_JOURNAL_VARS; a SIGRIFT_* setting only when the shell has none).
lc_load_journal_vars() {
    local line key value
    while IFS= read -r line; do
        key=${line%%=*}
        value=${line#*=}
        case " $LC_JOURNAL_VARS " in
            *" $key "*) ;;
            *) continue ;;
        esac
        case "$key" in
            SIGRIFT_*)
                [ -n "$value" ] && [ -z "${!key:-}" ] || continue
                export "$key=$value"
                ;;
            *) printf -v "$key" '%s' "$value" ;;
        esac
    done < <(lc_tool journal-vars . </dev/null)
}

# lc_journal_begin OP — after the pull and the restore point: the journal
# (and lock-owner.json, for a second run's M-LOCKED) of the detached part.
lc_journal_begin() {
    local steps="" step done="snapshot"
    for step in $LC_UPGRADE_STEPS; do
        [ "$step" != installer ] || [ "$LC_SELF_DIR" != "$(pwd -P)" ] || continue
        steps+="${steps:+,}${step}"
    done
    lc_journal_vars | lc_tool journal-new --dir . --op "$1" --steps "$steps" \
        --done "$done" --from "${LC_FROM_VERSION:-unknown}" --to "$VERSION" --owner "$OWNER" \
        --project "$LC_PROJECT" --source-dir "$([ "$LC_SELF_DIR" = "$(pwd -P)" ] || echo "$LC_SELF_DIR")" \
        --snapshot "$LC_SNAPSHOT_ID" --was-running "${LC_WAS_RUNNING:-0}" \
        --images "${LC_IMAGE_REFS:-}" --bridge "${LC_BRIDGE_CONTAINER:-}" \
        --gateway "${LC_GATEWAY_CONTAINER:-}" --pin "${LC_PIN:-0}" \
        --project-how "${LC_PROJECT_HOW:-}" >/dev/null
    lc_tool lock-owner . --op "$1" --log "$(lc_tool journal-get . log </dev/null)" --pid "$$" </dev/null
}

lc_journal_step() {
    lc_tool journal-step . "$1" </dev/null
}

lc_journal_state() {
    lc_tool journal-state . "$1" "${2:-}" </dev/null
}

# lc_here_cmd ARGS — --status, --resume or --abort for this install, as
# the operator types it: in place, or, from the folder they ran this from,
# with this installer and the install folder named (the install folder may
# still hold an older installer that knows none of them).
lc_here_cmd() {
    local here
    here=$(pwd -P)
    if [ -z "${LC_CALLER_DIR:-}" ] || [ "$LC_CALLER_DIR" = "$here" ]; then
        printf 'bash install-release.sh %s' "$*"
    elif [ -z "${LC_SELF_DIR:-}" ] || [ "$LC_SELF_DIR" = "$LC_CALLER_DIR" ]; then
        printf 'bash install-release.sh %s %q' "$*" "$here"
    else
        printf 'bash %q/install-release.sh %s %q' "$LC_SELF_DIR" "$*" "$here"
    fi
}

# lc_in_here CMD — CMD, which reads this install folder's files, as the
# operator types it where they ran the installer.
lc_in_here() {
    if [ -n "${LC_CALLER_DIR:-}" ] && [ "$LC_CALLER_DIR" != "$(pwd -P)" ]; then
        printf 'cd %q && %s' "$(pwd -P)" "$*"
    else
        printf '%s' "$*"
    fi
}

# lc_rerun_cmd — this run again, as the operator types it.
lc_rerun_cmd() {
    if [ -z "${LC_CALLER_DIR:-}" ] || [ "$LC_CALLER_DIR" = "$(pwd -P)" ]; then
        printf 'bash install-release.sh'
    elif [ "${LC_SELF_DIR:-}" = "$LC_CALLER_DIR" ]; then
        printf 'bash install-release.sh --upgrade %q' "$(pwd -P)"
    else
        printf 'bash %q/install-release.sh --upgrade %q' "$LC_SELF_DIR" "$(pwd -P)"
    fi
}

# lc_use_journal_project — every compose call of a journaled upgrade
# addresses the journal's project on the daemon it ran on: a shell's
# COMPOSE_PROJECT_NAME or COMPOSE_FILE would make `docker compose` act on
# another stack (start it on empty volumes while the checks read the old
# data), another DOCKER_HOST on another host (lc_tool journal-guard
# refuses that).
lc_use_journal_project() {
    local project
    project=$(lc_tool journal-guard . </dev/null) || exit "$?"
    export COMPOSE_PROJECT_NAME="$project"
    unset COMPOSE_FILE
    LC_PROJECT=$project
}

# lc_goto_install [DIR] — the folder --status, --resume and --abort act on:
# DIR when given; else this one, or, when this folder holds no install (a
# newly unpacked release folder), the install whose upgrade in progress
# was started from here.
lc_goto_install() {
    local dir="${1:-}" found
    if [ -n "$dir" ]; then
        if ! cd "$dir" 2>/dev/null; then
            lc_refuse "ls -ld $(printf %q "$dir")" "${dir} is not a folder this user can enter."
        fi
        return 0
    fi
    if [ -e .env ] || [ -e docker-compose.yml ] || [ -e "${LC_STATE_DIRNAME}/journal.json" ]; then
        return 0
    fi
    found=$(lc_tool journal-find --source-dir "$(pwd -P)" </dev/null) || found=""
    if [ -n "$found" ]; then
        echo "==> The upgrade started from this folder works on ${found}."
        cd "$found"
    fi
}

# lc_run_detached — the rest of the journal's steps in a new session
# (lc_continue in `install-release.sh --lc-continue ID`), its output in
# .sigrift/logs/; this run only follows the log and exits with its code.
lc_run_detached() {
    local id log rcfile child rc=0
    id=$(lc_tool journal-get . id </dev/null)
    log=$(lc_tool journal-get . log </dev/null)
    rcfile=${log%.log}.rc
    rm -f -- "$rcfile"
    child=$(lc_tool setsid-exec "$log" "$BASH" "$LC_RUN_SCRIPT" --lc-continue "$id" </dev/null)
    echo "    log: $(pwd -P)/${log}; the upgrade goes on if this terminal closes (check it with $(lc_here_cmd --status))"
    lc_tool follow "$log" "$child" "$rcfile" "$(lc_here_cmd --status)" </dev/null || rc=$?
    return "$rc"
}

# lc_progress N TEXT — a numbered step line of the upgrade.
lc_progress() {
    echo "==> [$1/${LC_STEPS_TOTAL:-8}] $2"
}

# lc_continue ID — the detached part, run from the journal of this
# folder: each pending step, then records it done. Every step is
# idempotent, so --resume simply runs the pending ones again.
lc_continue() {
    local id="$1" step fn
    if [ "${LC_LOCK_INHERITED:-0}" != 1 ] || [ "$(lc_tool journal-get . id </dev/null)" != "$id" ]; then
        echo "usage: --lc-continue is for the installer's own detached run" >&2
        exit 2
    fi
    lc_lock_acquire . continue
    lc_load_journal_vars
    LC_LOG=$(lc_tool journal-get . log </dev/null)
    LC_RC_FILE=${LC_LOG%.log}.rc
    LC_SOURCE_DIR=$(lc_tool journal-get . source_dir </dev/null)
    LC_STEPS_TOTAL=7
    [ -z "$LC_SOURCE_DIR" ] || LC_STEPS_TOTAL=8
    export LC_CRITICAL=1
    LC_NO_PROMPT=1
    trap lc_child_exit EXIT
    lc_use_journal_project
    lc_tool journal-set . "pid=$$" state=running error=null </dev/null
    lc_tool lock-owner . --op "$(lc_tool journal-get . op </dev/null)" --log "$LC_LOG" --pid "$$" </dev/null
    for step in $(lc_tool journal-pending . </dev/null); do
        export LC_STEP=$step
        fn="lc_step_${step//-/_}"
        "$fn"
        lc_journal_step "$step"
    done
    lc_journal_state "done"
    lc_tool lock-owner . --release </dev/null
}

# lc_child_exit — the detached run's EXIT trap: the journal says where it
# stopped, the follower gets the exit code.
lc_child_exit() {
    local rc=$? state
    trap - EXIT
    set +e
    if [ "$rc" -ne 0 ]; then
        state=$(lc_tool journal-get . state </dev/null 2>/dev/null)
        # A failure after the journal says done (the summary) or after a
        # failed check keeps what the journal says.
        if [ "$state" != verify_failed ] && [ "$state" != "done" ]; then
            lc_journal_state failed "${LC_STEP:-?}: exit ${rc}" >/dev/null 2>&1
        fi
        echo "" >&2
        echo "The upgrade stopped at step ${LC_STEP:-?} (exit ${rc}); the journal keeps where it stands." >&2
        # Exit 4 paths already named what to run next.
        [ "$rc" -eq "$LC_EXIT_STOPPED" ] || echo "Next: $(lc_here_cmd --status)" >&2
    fi
    lc_tool lock-owner . --release </dev/null >/dev/null 2>&1
    printf '%s\n' "$rc" >"${LC_RC_FILE}.tmp" && mv -f "${LC_RC_FILE}.tmp" "$LC_RC_FILE"
    exit "$rc"
}

lc_step_snapshot() {
    # Taken before the journal existed; a resume finds it done.
    :
}

# lc_step_installer — the new release's installer and release files go
# into the install folder. The folder the upgrade was started from may be
# gone by a resume (deleted, or the release unpacked again elsewhere and
# resumed from there): then this installer's own folder holds the same
# release, when its VERSION is the journal's.
lc_step_installer() {
    local line changed="" kept="" src="$LC_SOURCE_DIR" out self_version=""
    if [ ! -f "${src}/install-release.sh" ] && [ -f "${LC_SELF_DIR}/install-release.sh" ] \
        && [ "$LC_SELF_DIR" != "$(pwd -P)" ]; then
        self_version=$(tr -d '[:space:]' <"${LC_SELF_DIR}/VERSION" 2>/dev/null) || self_version=""
        if [ "$self_version" = "$VERSION" ]; then
            src=$LC_SELF_DIR
            lc_tool journal-set . "source_dir=${src}" </dev/null
        fi
    fi
    if ! out=$(lc_tool install-files --src "$src" --dir . </dev/null 2>&1); then
        lc_refuse "bash /path/to/the/${VERSION}/release/install-release.sh --resume $(printf %q "$(pwd -P)")" \
            "the ${VERSION} release files could not be installed into $(pwd -P): ${out}" \
            "Unpack the ${VERSION} release again (anywhere) and resume with its installer."
    fi
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        changed+="${changed:+, }${line%%=*}"
        if [ -n "${line#*=}" ]; then
            kept=" (old ones kept as <name>.bak.*~)"
            lc_tool journal-set . "installer_backups=${line#*=}" </dev/null
        fi
    done <<<"$out"
    lc_progress 4 "installer and release files installed in $(pwd -P): ${changed:-all were current}${kept}"
}

lc_step_stop() {
    lc_stop_stack
}

lc_step_hold() {
    lc_hold
    lc_progress "$((LC_STEPS_TOTAL - 3))" "stack stopped and held  (log: ${LC_LOG}; safe to lose this terminal)"
}

lc_step_switch() {
    "${LC_INSTALLER}_switch"
    # What the .env edit did (key names and migration ids), for the record
    # step, also when a resume runs that step in another process.
    lc_tool journal-set . "env_result=${LC_ENV_RESULT:-}" </dev/null
    lc_progress "$((LC_STEPS_TOTAL - 2))" "compose, VERSION and .env switched"
}

lc_step_start_bridge() {
    lc_tool journal-set . bridge_started_at=@now </dev/null
    lc_start_bridge
}

lc_step_start_rest() {
    lc_start_rest
    lc_progress "$((LC_STEPS_TOTAL - 1))" "bridge healthy${LC_BRIDGE_WAITED:+ after ${LC_BRIDGE_WAITED} s}${LC_MIGRATIONS_SEEN:+ (${LC_MIGRATIONS_SEEN} migrations)}; gateway healthy${LC_GATEWAY_WAITED:+ after ${LC_GATEWAY_WAITED} s}"
}

lc_step_verify() {
    lc_verify_upgrade
}

lc_step_record() {
    local accepted
    [ -n "${LC_ENV_RESULT:-}" ] || LC_ENV_RESULT=$(lc_tool journal-get . env_result </dev/null)
    accepted=$(lc_tool journal-get . accepted_error </dev/null)
    if [ -n "$accepted" ]; then
        # --resume --accept: the operator closed an upgrade whose checks failed.
        LC_RECORD_RESULT=accepted
        LC_VERIFIED="checks failed and were accepted (${accepted})"
    fi
    lc_record_success "${LC_OP:-upgrade}"
    lc_progress "$LC_STEPS_TOTAL" "${LC_VERIFIED:-checks passed}; records written"
}

# lc_stop_stack — every service (the gateway has the database open too),
# then every other running container of the project, then no running
# container may still mount a project volume; otherwise the stack is
# started again and the upgrade stops (exit 1).
lc_stop_stack() {
    local still again
    if ! lc_is_held; then
        docker compose stop
    fi
    if ! still=$(lc_tool stop-project --project "$LC_PROJECT" </dev/null); then
        lc_unhold
        if docker compose start >/dev/null 2>&1; then
            again="the stack was started again"
        else
            again="starting the stack again failed too ($(lc_in_here docker compose start))"
        fi
        echo "Error: ${still% *} still mounts ${still##* } after the stop, so the upgrade did not go on; ${again}. Only the installer files may have changed so far; restore point ${LC_SNAPSHOT_ID:-none} holds them as they were ($(lc_here_cmd --abort) puts them back)." >&2
        exit 1
    fi
}

lc_is_held() {
    head -1 docker-compose.yml 2>/dev/null | grep -q "^${LC_HOLD_HEADER}"
}

# lc_hold / lc_unhold — see the hold stub in lc_tool (hold, unhold).
lc_hold() {
    local held
    held=$(lc_tool hold --dir . --project "$LC_PROJECT" </dev/null)
    lc_tool journal-set . "held=${held}" </dev/null
}

lc_unhold() {
    lc_tool unhold --dir . </dev/null
}

# lc_wait_service_healthy SERVICE SECS [--migrations] — until the
# service's container is running and healthy. A running but unhealthy
# bridge is still starting (its migrations run before it answers its
# healthcheck); with --migrations every new "Migration N applied" line in
# its log moves the deadline to at least 5 minutes later. Returns 1 when
# it exited or the deadline passed (LC_WAIT_FAIL says which).
lc_wait_service_healthy() {
    local svc="$1" secs="$2" migrations="${3:-}" start now deadline last row state health
    local since n seen=0
    start=$(date +%s)
    deadline=$((start + secs))
    last=$start
    since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    LC_WAIT_FAIL=""
    while :; do
        row=$(docker compose ps --all --format json "$svc" 2>/dev/null | lc_tool ps-row "$svc") || row="- -"
        state=${row%% *}
        health=${row#* }
        now=$(date +%s)
        case "$state/$health" in
            running/healthy)
                LC_WAITED=$((now - start))
                return 0
                ;;
            exited/*|dead/*)
                LC_WAIT_FAIL=exited
                return 1
                ;;
        esac
        if [ -n "$migrations" ]; then
            n=$(docker compose logs --no-color --since "$since" "$svc" 2>/dev/null \
                | grep -c 'Migration [0-9][0-9]* applied') || n=0
            if [ "${n:-0}" -gt "$seen" ]; then
                seen=$n
                LC_MIGRATIONS_SEEN=$n
                [ "$deadline" -ge $((now + 300)) ] || deadline=$((now + 300))
                echo "    ${svc}: ${n} migrations applied so far; waiting while they run"
            fi
        fi
        if [ "$now" -ge "$deadline" ]; then
            LC_WAIT_FAIL=timeout
            LC_WAITED=$((now - start))
            return 1
        fi
        if [ $((now - last)) -ge 30 ]; then
            echo "    still waiting for the ${svc} ($((now - start)) s; ${state}/${health})"
            last=$now
        fi
        sleep 3
    done
}

# lc_start_failed SERVICE — M-START-FAILED; exit 4.
lc_start_failed() {
    local svc="$1" next
    echo "" >&2
    if [ "${LC_WAIT_FAIL:-}" = exited ]; then
        echo "The ${svc} did not become healthy: it exited." >&2
    else
        echo "The ${svc} did not become healthy within ${LC_WAITED:-?} s." >&2
    fi
    echo "Check logs:" >&2
    echo "    $(lc_in_here docker compose logs --tail=50 bridge)" >&2
    echo "    $(lc_in_here docker compose logs --tail=50 gateway)" >&2
    if [ "${LC_CRITICAL:-0}" = 1 ]; then
        next="$(lc_here_cmd --resume)"
    else
        next="$(lc_rerun_cmd)"
    fi
    echo "Then: ${next}" >&2
    exit "$LC_EXIT_STOPPED"
}

# lc_start_bridge / lc_start_rest — the two-stage start. The bridge
# first, alone, with a deadline that grows with the database (a long
# migration is not "never healthy"); then the rest, which waits for a
# healthy bridge anyway (depends_on: service_healthy). --pull never: the
# images were pulled before anything changed. --remove-orphans also
# removes a hold stub container someone started.
lc_start_bridge() {
    local secs
    echo "==> Starting the bridge (it applies any database migrations first)"
    docker compose up -d --pull never --remove-orphans bridge
    secs=$(lc_tool bridge-deadline "${LC_DB_BYTES:-0}" </dev/null)
    LC_MIGRATIONS_SEEN=""
    if ! lc_wait_service_healthy bridge "$secs" --migrations; then
        lc_start_failed bridge
    fi
    LC_BRIDGE_WAITED=$LC_WAITED
}

lc_start_rest() {
    echo "==> Starting the gateway"
    if tls_recreate_pending tls/cert.pem; then
        # The certificate is new: recreate the gateway (only it mounts
        # tls/; the bridge just became healthy).
        docker compose up -d --pull never --remove-orphans --force-recreate gateway
    else
        docker compose up -d --pull never --remove-orphans
    fi
    fix_volume_ownership
    if ! lc_wait_service_healthy gateway 180; then
        lc_start_failed gateway
    fi
    LC_GATEWAY_WAITED=$LC_WAITED
    tls_recreate_done tls/cert.pem
}

lc_start_two_stage() {
    lc_start_bridge
    lc_start_rest
}

# lc_verify_upgrade — the data read with the new bridge image against the
# journal's from before the stop: the schema the new bridge knows, the
# TOTP secrets and the audit chain still verify, nothing went backwards.
# A regression keeps the upgrade up (it was healthy) and records
# verify_failed; exit 4.
lc_verify_upgrade() {
    local out rc=0
    # The project's own running bridge, by its Compose labels.
    LC_BRIDGE_CONTAINER=$(lc_tool project-bridge "$LC_PROJECT" </dev/null) || LC_BRIDGE_CONTAINER=""
    LC_HAS_DATA=1
    lc_facts
    out=$(lc_tool verify-upgrade . --target-schema "${LC_TARGET_SCHEMA:-}" \
        --project "$LC_PROJECT" --bridge "$LC_BRIDGE_CONTAINER" </dev/null) || rc=$?
    if [ "$rc" -ne 0 ]; then
        lc_journal_state verify_failed "$out"
        echo "" >&2
        echo "The upgrade to ${VERSION} is up, but a check failed: ${out}. The journal records it; nothing was rolled back." >&2
        echo "Next: $(lc_here_cmd --status)" >&2
        exit "$LC_EXIT_STOPPED"
    fi
    LC_VERIFIED=$out
}

# lc_write_version VERSION — remember an explicit version, so the next
# plain re-run cannot read an older VERSION sidecar and silently revert
# the images to that release.
lc_write_version() {
    local version_tmp
    version_tmp=$(mktemp .sigrift-version.XXXXXX)
    printf '%s\n' "$1" > "$version_tmp"
    chmod 0644 "$version_tmp"
    mv "$version_tmp" VERSION
}

# lc_tls_plan — the TLS line of the plan: what the run will do with the
# certificate (the checks of tls_ensure_cert, read-only).
lc_tls_plan() {
    local cert=tls/cert.pem text sans missing end
    if [ ! -s "$cert" ] || [ ! -s tls/key.pem ]; then
        echo "a new self-signed certificate is made"
        return 0
    fi
    if ! text=$(openssl x509 -in "$cert" -noout -text 2>/dev/null); then
        echo "tls/cert.pem is not a readable certificate: a new one is made"
        return 0
    fi
    if ! tls_cert_self_signed "$cert"; then
        echo "kept (operator-supplied; never replaced)"
        return 0
    fi
    end=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null) || end=""
    end=${end#*=}
    if ! openssl x509 -in "$cert" -noout -checkend $((TLS_RENEW_DAYS * 86400)) >/dev/null 2>&1; then
        echo "renewed: it expires within ${TLS_RENEW_DAYS} days (same names); edge nodes given the old cert.pem need the new one"
        return 0
    fi
    sans=$(tls_san_tool required "${SIGRIFT_TLS_SANS:-}" "$(tls_host_names)" "$(tls_host_addrs)" 2>/dev/null) || sans=""
    missing=$(tls_san_tool missing "$text" "$sans" 2>/dev/null) || missing=""
    if [ -n "$missing" ]; then
        echo "renewed: it lacks ${missing}; edge nodes given the old cert.pem need the new one"
        return 0
    fi
    echo "kept (names complete, expires ${end:-unknown})"
}

# lc_record_success OP — after a healthy run: the host record
# .sigrift/install.json (install id, project, folder, versions, history;
# no secrets) and the volume record bridge_data/.sigrift-install.json,
# which names the folder and carries the key fingerprints, so a later run
# can tell a renamed, copied or moved folder from a new one even after
# `docker compose down` removed the containers and their folder labels.
# Then old files-only restore points are pruned (the newest 10 stay).
# A failure only warns. Source installs keep no records yet.
lc_record_success() {
    local op="$1" volrec image
    [ "${LC_INSTALLER:-}" = release ] || return 0
    volrec=$(mktemp "${TMPDIR:-/tmp}/sigrift-record.XXXXXX")
    if ! lc_tool write-host-record --dir . --op "$op" --project "$LC_PROJECT" \
        --install-type release --from "${LC_FROM_VERSION:-unknown}" --to "$VERSION" \
        --installer "${LC_SELF_DIR}/$(basename -- "$0")" --installer-version "$VERSION" \
        --env-result "${LC_ENV_RESULT:-}" --moved-from "${LC_MOVED_FROM:-}" \
        --schema "${LC_TARGET_SCHEMA:-}" --snapshot "${LC_SNAPSHOT_ID#-}" \
        --result "${LC_RECORD_RESULT:-ok}" --volume-record "$volrec" </dev/null; then
        rm -f -- "$volrec"
        echo "WARNING: could not write ${LC_STATE_DIRNAME}/install.json; the next run checks this install again from its labels and data." >&2
        return 0
    fi
    image=$(lc_tool engine-image --installer release --project "$LC_PROJECT" --dir . \
        --bridge "$(lc_tool project-bridge "$LC_PROJECT" </dev/null)" \
        --owner "${OWNER:-}" --version "$VERSION" </dev/null)
    if ! lc_engine_source | lc_tool engine-run --image "$image" --project "$LC_PROJECT" \
        --op write-record --env-file .env --record-file "$volrec" >/dev/null; then
        echo "WARNING: could not write the volume record (${LC_PROJECT}'s bridge_data/.sigrift-install.json); the next run checks this install again from its labels and data." >&2
    fi
    rm -f -- "$volrec"
    lc_tool prune-snapshots . --keep 10 --protect "${LC_SNAPSHOT_ID#-}" </dev/null >/dev/null || true
}

# lc_status — where the install in this folder stands; read-only, no lock.
lc_status() {
    lc_engine_source | lc_tool status . --installer "${LC_INSTALLER:-release}"
}

# lc_resume — go on with an interrupted upgrade from its journal (after a
# failed check, run the checks again).
# With LC_ACCEPT=1 (--resume --accept) an upgrade that is up but failed its
# checks is closed as it is: the checks' result goes into the journal and
# the host record's history ("accepted"), and the records are written.
lc_resume() {
    local state
    lc_lock_acquire . resume
    state=$(lc_tool journal-get . state </dev/null)
    case "$state" in
        running|failed)
            if [ "${LC_ACCEPT:-0}" = 1 ]; then
                lc_refuse "$(lc_here_cmd --resume)" \
                    "--accept closes an upgrade that is up but failed its checks; the one in $(pwd -P) stopped at step $(lc_tool journal-get . next </dev/null) instead."
            fi
            ;;
        verify_failed) ;;
        *)
            echo "==> Nothing to resume (no upgrade is in progress in $(pwd -P))."
            return 0
            ;;
    esac
    lc_use_journal_project
    if [ "$state" = verify_failed ] && [ "${LC_ACCEPT:-0}" = 1 ]; then
        lc_tool journal-set . "accepted_error=$(lc_tool journal-get . error </dev/null)" \
            accepted_at=@now </dev/null
        lc_journal_step verify
    elif [ "$state" = verify_failed ]; then
        lc_tool journal-set . next=verify </dev/null
    fi
    lc_tool journal-set . state=running </dev/null
    echo "==> Resuming the interrupted upgrade $(lc_tool journal-get . from_version </dev/null) -> $(lc_tool journal-get . to_version </dev/null) (step $(lc_tool journal-get . next </dev/null))."
    lc_run_detached
}

# lc_abort [--dry-run] — undo an upgrade that stopped before the new
# bridge started (afterwards it may have migrated the database, which the
# old release cannot read): the held files back, every file of the
# restore point back, the old stack started again if it ran. Nothing
# changes until the restore point has checked whole and the database is
# still at the schema it had before the upgrade.
lc_abort() {
    local state started snap out from pre image live restored
    [ "${LC_ABORT_DRY_RUN:-0}" = 1 ] || lc_lock_acquire . abort
    state=$(lc_tool journal-get . state </dev/null)
    case "$state" in
        running|failed|verify_failed) ;;
        *)
            echo "==> Nothing to abort (no upgrade is in progress in $(pwd -P))."
            return 0
            ;;
    esac
    lc_use_journal_project
    from=$(lc_tool journal-get . from_version </dev/null)
    started=$(lc_tool journal-get . bridge_started_at </dev/null)
    if [ -n "$started" ]; then
        lc_refuse "$(lc_here_cmd --resume)" \
            "the new bridge started at ${started} and may have migrated the database, which ${from} cannot read; --abort only undoes an upgrade that stopped before that."
    fi
    snap=$(lc_tool journal-get . snapshot </dev/null)
    # Refuses (changing nothing) a restore point that is missing,
    # incomplete or damaged.
    out=$(lc_tool snapshot-restore . "$snap" --dry-run </dev/null) || exit "$?"
    # A new bridge started by hand (docker compose up while the upgrade was
    # stopped) migrates the database without the journal knowing.
    pre=$(lc_tool journal-get . pre.schema </dev/null)
    image=$(lc_tool journal-get . previous_images.bridge </dev/null)
    [ -n "$image" ] || image=$(lc_tool journal-get . images.bridge </dev/null)
    if [[ "$pre" =~ ^[0-9]+$ ]] && [ -n "$image" ]; then
        live=$(LC_FACTS_JSON=$(lc_engine "$image" "$LC_PROJECT" facts) lc_tool facts-get db.schema </dev/null) || live=""
        if [[ "$live" =~ ^[0-9]+$ ]] && [ "$live" -gt "$pre" ]; then
            lc_refuse "$(lc_here_cmd --status)" \
                "the database is at migration ${live} now, not ${pre} as before the upgrade: a newer bridge has migrated it already (started by hand?), so ${from} cannot read it and --abort does not go back."
        fi
    fi
    if [ "${LC_ABORT_DRY_RUN:-0}" = 1 ]; then
        echo "==> --abort would (--dry-run: nothing was changed):"
        echo "  held      put docker-compose.yml and the override back from ${LC_STATE_DIRNAME}/held/"
        printf '%s\n' "$out"
        if [ "$(lc_tool journal-get . was_running </dev/null)" = 1 ]; then
            echo "  start     the old stack again, as it was (docker compose up -d --no-recreate)"
        fi
        return 0
    fi
    lc_unhold
    out=$(lc_tool snapshot-restore . "$snap" </dev/null)
    restored=$(sed -n 's/^restored=//p' <<<"$out")
    echo "==> Restored from ${snap}: ${restored:-nothing}"
    if [ -n "$(sed -n 's/^removed=//p' <<<"$out")" ]; then
        echo "    removed what the restore point did not have: $(sed -n 's/^removed=//p' <<<"$out")"
    fi
    # The restore writes the key 0600; it gets group 1500 and 0640 again.
    if [ -e tls/cert.pem ] && [ -e tls/key.pem ] && [[ ",${restored}," == *,tls/* ]]; then
        secure_tls_files tls/cert.pem tls/key.pem
    fi
    # The restored .env predates the pin. When the folder's name gives
    # another project (adopted, or started under a shell's name), a plain
    # docker compose here would address that one: the pin stays.
    case "$(lc_tool journal-get . project_how </dev/null)" in
        adopted|shell|labels)
            if [ "$(lc_tool journal-get . pin </dev/null)" = 1 ]; then
                lc_tool pin .env "$LC_PROJECT" --no-backup \
                    --note "==> Kept COMPOSE_PROJECT_NAME=${LC_PROJECT} in the restored .env (this install's project; the folder's name gives another)." </dev/null
            fi
            ;;
    esac
    lc_journal_state aborted
    lc_tool lock-owner . --release </dev/null
    # History only in a host record that exists: a new one would get a new
    # install id that the volume record does not know.
    if [ -e "${LC_STATE_DIRNAME}/install.json" ]; then
        lc_tool write-host-record --dir . --op abort --project "$LC_PROJECT" --install-type release \
            --from "$(lc_tool journal-get . to_version </dev/null)" \
            --to "$from" --result aborted \
            --snapshot "$snap" </dev/null >/dev/null 2>&1 || true
    fi
    if [ "$(lc_tool journal-get . was_running </dev/null)" = 1 ]; then
        # --no-recreate: the containers the upgrade stopped start as they
        # were, with the values they ran with (after --keep-running-secrets
        # the restored .env may hold others); only missing ones are made.
        echo "==> Starting the stack as it was"
        if ! docker compose up -d --pull never --no-recreate --remove-orphans; then
            echo "Error: the files are back as they were before the upgrade, but the old stack did not start." >&2
            echo "Next: $(lc_in_here docker compose up -d --no-recreate)" >&2
            exit 1
        fi
    fi
    echo "==> Aborted the upgrade to $(lc_tool journal-get . to_version </dev/null); this install is back at ${from}."
}
# <<< shared: lifecycle

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

# ── Which stack this checkout drives ─────────────────────────────────
# Before host preparation, prompts, certificates or models, and changing
# nothing: a fresh checkout beside another SigRift install, a .env whose
# secrets do not match the running bridge or the data, or a missing .env
# beside existing data is refused (lc_identity, lc_preflight).
# One changing run per checkout: a second quickstart (or a cron
# --renew-tls) waits until this one has finished.
LC_INSTALLER=quickstart
if [ "$RENEW_TLS_ONLY" -eq 0 ]; then
    LC_SELF_DIR=$(pwd -P)
    lc_lock_acquire "$LC_SELF_DIR" quickstart
    lc_identity quickstart
    lc_preflight
fi

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
    # Cron runs this unattended: while another run holds the checkout, the
    # renewal waits for the next run (it renews 30 days before expiry).
    lock_rc=0
    lc_lock_acquire . renew-tls || lock_rc=$?
    if [ "$lock_rc" -eq 5 ]; then
        echo "==> TLS renewal deferred: another installer run holds the lock."
        exit 0
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
# read_admin_password — asks twice, never echoed, into LC_ADMIN_PASSWORD.
# Only asked while no user exists: the bridge creates the admin from it on
# an empty users table only.
read_admin_password() {
    local pw1 pw2
    cat <<'EOF'
This installer will create a local admin account.

The password you type next is written only to a local .env file
(chmod 600, gitignored) and passed straight to the bridge container
as an environment variable. It is never printed to stdout, never
stored in docker logs, and never written to any other file.

Minimum 12 characters. Mix classes if you want — no rules enforced
here, but the bridge will enforce its own rules on later logins.
EOF

    while true; do
        read -r -s -p "Admin password: " pw1; echo
        if [ ${#pw1} -lt 12 ]; then
            echo "  too short (min 12 chars), try again" >&2
            continue
        fi
        read -r -s -p "Confirm password: " pw2; echo
        if [ "$pw1" != "$pw2" ]; then
            echo "  passwords did not match, try again" >&2
            continue
        fi
        LC_ADMIN_PASSWORD=$pw1
        break
    done
}

# An existing .env is never replaced: lc_env_merge adds only what nothing
# depends on (BRIDGE_LOCAL_NODE_KEY, which the four in-stack scanner
# services authenticate with, among them) and asks for an admin password
# only while no user exists.
if [ -e .env ]; then
    echo "==> Using existing .env (kept; missing keys are added only where no data depends on them)"
    env_merge_rc=0
    lc_env_merge .env quickstart || env_merge_rc=$?
    if [ "$env_merge_rc" -eq 10 ]; then
        read_admin_password
        env_merge_rc=0
        lc_env_merge .env quickstart || env_merge_rc=$?
        unset LC_ADMIN_PASSWORD
    fi
    [ "$env_merge_rc" -eq 0 ] || exit "$env_merge_rc"
    repair_mfa_key .env
    warn_missing_audit_key .env
    if [ -z "${SIGRIFT_BIND:-}" ] \
        && ! grep -qE '^[[:space:]]*(export[[:space:]]+)?SIGRIFT_BIND[[:space:]]*=' .env; then
        echo "NOTE: the gateway is now published on 127.0.0.1 only (this machine) unless .env sets SIGRIFT_BIND. To keep it reachable from other machines, re-run with SIGRIFT_BIND=0.0.0.0 (or add SIGRIFT_BIND=0.0.0.0 to .env)." >&2
    fi
    persist_bind_setting .env
else
    read_admin_password

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
    KEYSTORE_KEY=$(fernet_key)
    AUDIT_KEY=$(randstr)
    MASTER_KEY=$(randstr)
    PROXY_SECRET=$(randstr)
    LOCAL_NODE_KEY=$(randstr)
    ADMIN_PASSWORD_ENV=$(printf '%s' "$LC_ADMIN_PASSWORD" | dotenv_password)

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
BRIDGE_KEYSTORE_KEY=${KEYSTORE_KEY}
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
    unset LC_ADMIN_PASSWORD ADMIN_PASSWORD_ENV MFA_KEY KEYSTORE_KEY AUDIT_KEY MASTER_KEY PROXY_SECRET LOCAL_NODE_KEY BIND

    echo "==> Wrote .env (chmod 600)"
    QUICKSTART_NEW_ENV=1
fi
# The project the volumes belong to, pinned once (lc_env_merge wrote it
# together with any other .env edit; a new .env gets it here).
if [ "${LC_PIN:-0}" = 1 ] && [ "${QUICKSTART_NEW_ENV:-0}" = 1 ]; then
    lc_pin_project .env new
elif [ "${LC_PIN:-0}" = 1 ]; then
    lc_pin_project .env
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
