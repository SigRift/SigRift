#!/usr/bin/env bash
# SigRift edge-agent host installer.
#
# Meant to be piped from `curl https://<bridge-host>:<port>/api/edge/install.sh`
# and invoked with an API key + the bridge's URL. Idempotent: re-runs are
# safe and only update what has drifted.
#
# Usage:
#   curl -sfL --cacert gateway-cert.pem https://<bridge>:8444/api/edge/install.sh | \
#     sudo bash -s -- \
#       --api-url https://<bridge>:8444 \
#       --api-key <node-role-api-key> \
#       [--node-id my-edge-01] \
#       [--ca-cert gateway-cert.pem] \
#       [--ref vX.Y.Z]
#
# Re-runs (to upgrade the agent after a server upgrade, or to change a setting).
# Download first, so a failed download runs nothing instead of an empty script
# (drop --cacert for a publicly trusted gateway; the summary prints the exact line):
#   f=$(mktemp) && curl -fsSL --cacert /etc/sigrift-edge/ca.pem -o "$f" \
#     https://<bridge>:8444/api/edge/install.sh && sudo bash "$f"; rm -f "$f"
# keep /etc/sigrift-edge.env (API URL, API key, node ID, gateway trust) and the CA
# certificate; a flag given replaces its value. A new --api-url needs --api-key
# too, and drops the kept gateway trust. The agent's code is checked out at the
# release the server runs (or main, for a development server) unless --ref <tag>
# names another.
#
# TLS: the edge agent verifies the gateway's certificate. If the gateway
# uses a self-signed certificate (the quickstart / install-release
# default: tls/cert.pem next to its docker-compose.yml), copy it here and
# pass it with --ca-cert (and to curl with --cacert). That only works when
# the host name or IP in --api-url is in the certificate's subjectAltName;
# certificates from older installers list only localhost, so regenerate
# the gateway certificate first (see INSTALL.md) or use a publicly trusted
# one, which needs no --ca-cert. The installer checks the gateway's
# certificate before installing anything and stops if it does not verify.
# --insecure-tls turns verification off (sets MLRF_INSECURE_TLS=1) —
# development only.
#
# Target platforms: Ubuntu 22.04 / 24.04, Debian 12, Raspberry Pi OS
# (bookworm). Other apt-based distros probably work but aren't tested.
#
# Everything below is function definitions; the last line runs main, so a
# download cut short runs nothing. (SIGRIFT_EDGE_INSTALL_SOURCE_ONLY=1
# defines the functions without running them, for the tests.)

set -euo pipefail

INSTALL_DIR="/opt/sigrift-edge"
VENV_DIR="${INSTALL_DIR}/venv"
ENV_FILE="/etc/sigrift-edge.env"
CA_DEST="/etc/sigrift-edge/ca.pem"
STATE_DIR="/var/lib/sigrift-edge"
SERVICE_FILE="/etc/systemd/system/sigrift-edge.service"
REPO_URL="https://github.com/SigRift/SigRift.git"
# The release the server runs. GET /api/edge/install.sh fills this in
# (routers/edge.py): the bridge's release tag, or "" for a development build.
SERVER_RELEASE="__SIGRIFT_SERVER_RELEASE__"

API_URL=""
API_KEY=""
NODE_ID=""
CA_CERT=""
INSECURE_TLS=0
REF=""
REF_SET=0
# Read from an earlier install's ${ENV_FILE} (load_existing_env).
OLD_API_URL=""
OLD_API_KEY=""
OLD_NODE_ID=""
OLD_CA_CERT=""
OLD_INSECURE_TLS=""
EXTRA_ENV_LINES=""
TLS_ENV=""

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
SigRift edge-agent host installer (run as root).

First install:
  curl -sfL --cacert gateway-cert.pem https://<bridge>:8444/api/edge/install.sh | \
    sudo bash -s -- --api-url https://<bridge>:8444 --api-key <node-role-api-key> \
      [--node-id my-edge-01] [--ca-cert gateway-cert.pem] [--ref vX.Y.Z]

Upgrade or re-run (keeps /etc/sigrift-edge.env and the CA certificate; download
first, so a failed download runs nothing; drop --cacert for a publicly trusted gateway):
  f=$(mktemp) && curl -fsSL --cacert /etc/sigrift-edge/ca.pem -o "$f" \
    https://<bridge>:8444/api/edge/install.sh && sudo bash "$f"; rm -f "$f"

Options (each replaces the value kept from an earlier install):
  --api-url URL      the gateway, https://<host>:8444 (a new one needs --api-key too,
                     and the kept --ca-cert or --insecure-tls is not reused)
  --api-key KEY      an API key with the node role
  --node-id ID       this node's id (default: <hostname>-<digits>)
  --ca-cert FILE     the gateway's tls/cert.pem (or its CA), for a self-signed gateway
  --insecure-tls     do not verify the gateway certificate (development only)
  --ref REF          the SigRift tag or branch to install (default: the release
                     the server runs, or main for a development server)
  -h, --help         this help
EOF
}

# ── Arguments ────────────────────────────────────────────────────────
need_value() {  # <flag> <number of arguments left, the flag included>
    [ "$2" -ge 2 ] || die "$1 needs a value"
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --api-url)   need_value "$1" $#; API_URL="$2"; shift 2 ;;
            --api-key)   need_value "$1" $#; API_KEY="$2"; shift 2 ;;
            --node-id)   need_value "$1" $#; NODE_ID="$2"; shift 2 ;;
            --ca-cert)   need_value "$1" $#; CA_CERT="$2"; shift 2 ;;
            --ref)       need_value "$1" $#; REF="$2"; REF_SET=1; shift 2 ;;
            --insecure-tls) INSECURE_TLS=1; shift ;;
            -h|--help) usage; exit 0 ;;
            *) die "unknown arg: $1" ;;
        esac
    done
}

# ── Settings kept from an earlier install ────────────────────────────
# The text after the first '=' of a KEY=value line, without one pair of
# matching quotes.
env_value() {
    local value="${1#*=}"
    case "$value" in
        \"*\") value="${value#\"}"; value="${value%\"}" ;;
        \'*\') value="${value#\'}"; value="${value%\'}" ;;
    esac
    printf '%s' "$value"
}

# Reads ${ENV_FILE} line by line (never sources it): the values this
# script manages into OLD_*, every other line (an operator's settings,
# comments) verbatim into EXTRA_ENV_LINES, kept as they are.
load_existing_env() {
    [ -f "$ENV_FILE" ] || return 0
    local line
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            MLRF_API_URL=*) OLD_API_URL=$(env_value "$line") ;;
            MLRF_API_KEY=*) OLD_API_KEY=$(env_value "$line") ;;
            MLRF_NODE_ID=*) OLD_NODE_ID=$(env_value "$line") ;;
            MLRF_CA_CERT=*) OLD_CA_CERT=$(env_value "$line") ;;
            MLRF_INSECURE_TLS=*) OLD_INSECURE_TLS=$(env_value "$line") ;;
            # Written again by write_env_file.
            PYTHONPATH=*|PYTHONUNBUFFERED=*|"") ;;
            "# edge-install.sh:"*) ;;
            # The header of the file older versions of this script wrote.
            "# Generated by edge-install.sh."*|"# overwrite this file. Chmod 600"*) ;;
            *) EXTRA_ENV_LINES+="${line}"$'\n' ;;
        esac
    done < "$ENV_FILE"
}

# A URL as compared for "did --api-url change": lower case, no trailing '/'.
url_key() {
    local url
    url=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    while [ "${url%/}" != "$url" ]; do url=${url%/}; done
    printf '%s' "$url"
}

has_line_break() {
    case "$1" in
        *$'\n'*|*$'\r'*) return 0 ;;
    esac
    return 1
}

# A flag wins; otherwise the value from ${ENV_FILE}.
resolve_settings() {
    local none
    if [ -f "$ENV_FILE" ]; then
        none="${ENV_FILE} names none"
    else
        none="there is no ${ENV_FILE} from an earlier install"
    fi
    if [ -z "$API_URL" ] && [ -n "$OLD_API_URL" ]; then
        API_URL=$OLD_API_URL
        log "keeping the API URL from ${ENV_FILE}: ${API_URL}"
    elif [ -n "$API_URL" ] && [ -n "$OLD_API_URL" ] \
        && [ "$(url_key "$API_URL")" != "$(url_key "$OLD_API_URL")" ]; then
        # Another gateway: the kept key and trust belong to the old one.
        [ -n "$API_KEY" ] \
            || die "--api-key is required when --api-url changes (${ENV_FILE} has ${OLD_API_URL}): the API key kept there belongs to that gateway"
        if [ -z "$CA_CERT" ] && [ "$INSECURE_TLS" -eq 0 ] \
            && { [ -n "$OLD_CA_CERT" ] || [ "$OLD_INSECURE_TLS" = 1 ]; }; then
            log "not keeping the gateway trust from ${ENV_FILE} (--api-url changed): the system trust store is used; pass --ca-cert <the new gateway's tls/cert.pem> for a self-signed gateway"
        fi
        OLD_CA_CERT=""
        OLD_INSECURE_TLS=""
    fi
    if [ -z "$API_KEY" ] && [ -n "$OLD_API_KEY" ]; then
        API_KEY=$OLD_API_KEY
        log "keeping the API key from ${ENV_FILE}"
    fi
    if [ -z "$NODE_ID" ] && [ -n "$OLD_NODE_ID" ]; then
        NODE_ID=$OLD_NODE_ID
        log "keeping node ID ${NODE_ID} from ${ENV_FILE}"
    fi
    if [ -z "$CA_CERT" ] && [ "$INSECURE_TLS" -eq 0 ]; then
        if [ -n "$OLD_CA_CERT" ]; then
            [ -f "$OLD_CA_CERT" ] \
                || die "${ENV_FILE} names MLRF_CA_CERT=${OLD_CA_CERT}, which does not exist: pass --ca-cert <the gateway's tls/cert.pem>"
            CA_CERT=$OLD_CA_CERT
            log "keeping the gateway CA certificate ${CA_CERT}"
        elif [ "$OLD_INSECURE_TLS" = 1 ]; then
            INSECURE_TLS=1
            log "WARN: keeping MLRF_INSECURE_TLS=1 from ${ENV_FILE}: the gateway certificate is NOT verified (pass --ca-cert to fix)"
        fi
    fi
    [ -n "$API_URL" ] || die "--api-url is required (${none})"
    [ -n "$API_KEY" ] || die "--api-key is required (${none})"
    if has_line_break "$API_URL"; then die "--api-url must be a single line"; fi
    if has_line_break "$API_KEY"; then die "--api-key must be a single line"; fi
    if has_line_break "$NODE_ID"; then die "--node-id must be a single line"; fi
    if has_line_break "$CA_CERT"; then die "--ca-cert must be a single line"; fi
}

check_ca_cert() {
    [ -n "$CA_CERT" ] || return 0
    [ -f "$CA_CERT" ] || die "--ca-cert file not found: $CA_CERT"
    grep -q -- "-----BEGIN CERTIFICATE-----" "$CA_CERT" \
        || die "--ca-cert is not a PEM certificate: $CA_CERT"
    [ "$INSECURE_TLS" -eq 0 ] || die "--ca-cert and --insecure-tls are mutually exclusive"
}

# ── Which SigRift to install ─────────────────────────────────────────
valid_ref() {
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$ ]] || return 1
    case "$1" in
        *..*|*//*|*/|*.|*.lock) return 1 ;;
    esac
    return 0
}

resolve_ref() {
    if [ "$REF_SET" -eq 1 ]; then
        valid_ref "$REF" \
            || die "--ref must be a tag or branch name such as v0.2.0 or main (got: ${REF})"
        log "installing ${REF} (--ref)"
    elif [[ "$SERVER_RELEASE" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+)?$ ]]; then
        REF=$SERVER_RELEASE
        log "installing ${REF}, the release the server runs (--ref <tag> installs another)"
    else
        REF=main
        log "the server did not name a release (a development build): installing main (--ref vX.Y.Z pins a release)"
    fi
}

# Check the gateway's certificate the way the agent will, before spending
# minutes on packages: an agent that cannot verify it never heartbeats.
# Only a verification failure stops the install (curl exit 60; 51 on curl
# older than 7.62; 77 for an unusable --ca-cert file). A gateway that is
# merely unreachable right now is reported and the install goes on.
check_gateway_tls() {
    local rc=0
    command -v curl >/dev/null 2>&1 || return 0
    case "$API_URL" in https://*) ;; *) return 0 ;; esac
    if [ -n "$CA_CERT" ]; then
        curl -sS -o /dev/null --max-time 10 --cacert "$CA_CERT" "$API_URL" 2>/dev/null || rc=$?
    else
        curl -sS -o /dev/null --max-time 10 "$API_URL" 2>/dev/null || rc=$?
    fi
    case "$rc" in
        0) ;;
        51|60|77)
            if [ -n "$CA_CERT" ]; then
                die "the gateway at ${API_URL} does not verify against --ca-cert ${CA_CERT}: use the gateway's tls/cert.pem, and a host name or IP in --api-url that the certificate's subjectAltName lists (regenerate older certificates, see INSTALL.md)"
            fi
            die "the gateway at ${API_URL} has a certificate this host does not trust (self-signed?): copy the gateway's tls/cert.pem here and pass --ca-cert <file> (--insecure-tls disables verification, development only)"
            ;;
        *) log "WARN: could not reach ${API_URL} to check its certificate (curl exit ${rc}); continuing" ;;
    esac
}

ensure_node_id() {
    if [ -z "$NODE_ID" ]; then
        NODE_ID="$(hostname -s)-$(date +%s | tail -c 6)"
        log "Auto-generated NODE_ID: ${NODE_ID}"
    fi
}

check_os() {
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-unknown}" in
        ubuntu|debian|raspbian) ;;
        *)
            log "WARN: unsupported distro ${ID:-unknown} — proceeding anyway; may need manual intervention"
            ;;
    esac
}

# ── apt packages ─────────────────────────────────────────────────────
install_packages() {
    log "apt: ensuring base + SDR packages"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
        ca-certificates curl git \
        python3 python3-pip python3-venv \
        rtl-sdr \
        build-essential python3-dev
}

# ── Kernel DVB blacklist ─────────────────────────────────────────────
# The stock DVB drivers claim the RTL2832U chipset and block userspace
# SDR access. Blacklist them persistently so the next boot — or an
# immediate modprobe -r — frees the dongle for rtl_sdr / rtl_tcp.
blacklist_dvb() {
    local blacklist_file=/etc/modprobe.d/blacklist-rtl.conf expected
    expected=$(cat <<'EOF'
blacklist dvb_usb_rtl28xxu
blacklist rtl2832
blacklist rtl2830
EOF
)
    if [ ! -f "$blacklist_file" ] || ! diff -q <(echo "$expected") "$blacklist_file" >/dev/null; then
        log "writing RTL-SDR module blacklist"
        echo "$expected" > "$blacklist_file"
        modprobe -r dvb_usb_rtl28xxu rtl2832 rtl2830 2>/dev/null || true
        udevadm control --reload-rules 2>/dev/null || true
        udevadm trigger --action=add --subsystem-match=usb 2>/dev/null || true
    fi
}

# ── Repo checkout ────────────────────────────────────────────────────
# Always detached at the exact commit of ${REF} (FETCH_HEAD peels an
# annotated tag); --force discards local edits, as a reset did before.
checkout_ref() {
    local hint="check the name, or pass --ref main (or another release tag)"
    if [ ! -d "${INSTALL_DIR}/.git" ]; then
        log "cloning SigRift ${REF} to ${INSTALL_DIR}"
        mkdir -p "$INSTALL_DIR"
        git clone --quiet --depth 1 --branch "$REF" "$REPO_URL" "$INSTALL_DIR" \
            || die "could not clone ${REF} from ${REPO_URL}: ${hint}"
    else
        log "updating the SigRift checkout to ${REF}"
        git -C "$INSTALL_DIR" fetch --quiet --depth 1 origin "$REF" \
            || die "could not fetch ${REF} from ${REPO_URL}: ${hint}"
        git -C "$INSTALL_DIR" checkout --quiet --force --detach FETCH_HEAD
    fi
    log "checked out ${REF} at $(git -C "$INSTALL_DIR" rev-parse --short HEAD)"
}

# ── Python virtualenv ────────────────────────────────────────────────
install_python_deps() {
    if [ ! -d "$VENV_DIR" ]; then
        log "creating venv at ${VENV_DIR}"
        python3 -m venv "$VENV_DIR"
    fi
    log "installing Python deps into venv"
    "${VENV_DIR}/bin/pip" install --quiet --upgrade pip
    "${VENV_DIR}/bin/pip" install --quiet -r "${INSTALL_DIR}/src/sigrift/bridge/requirements.txt"
}

# ── Gateway trust anchor ─────────────────────────────────────────────
install_trust_anchor() {
    TLS_ENV=""
    if [ -n "$CA_CERT" ]; then
        if [ -e "$CA_DEST" ] && [ "$CA_CERT" -ef "$CA_DEST" ]; then
            log "keeping the gateway CA certificate ${CA_DEST}"
        else
            log "installing gateway CA certificate to ${CA_DEST}"
            install -d -m 0755 "$(dirname "$CA_DEST")"
            install -m 0644 "$CA_CERT" "$CA_DEST"
        fi
        TLS_ENV="MLRF_CA_CERT=${CA_DEST}"
    elif [ "$INSECURE_TLS" -eq 1 ]; then
        log "WARN: --insecure-tls — gateway certificate will NOT be verified (development only)"
        TLS_ENV="MLRF_INSECURE_TLS=1"
    else
        log "no --ca-cert given — the agent will verify the gateway against the system trust store"
        log "  (a self-signed gateway needs --ca-cert, or heartbeats will fail TLS verification)"
    fi
}

# ── Environment file (0600, contains the API key) ────────────────────
# Written atomically; the lines this script does not manage are kept
# after its own. A changed file is kept as ${ENV_FILE}.bak (0600); a re-run
# that changes nothing leaves the file byte-identical and makes no .bak.
write_env_file() {
    local tmp
    log "writing ${ENV_FILE}"
    umask 077
    tmp=$(mktemp "${ENV_FILE}.XXXXXX")
    if ! {
        printf '%s\n' "# edge-install.sh: written by the SigRift edge installer; mode 0600, it holds a NODE-role API key."
        printf '%s\n' "# edge-install.sh: a re-run keeps these values unless new ones are given (--api-url, --api-key,"
        printf '%s\n' "# edge-install.sh: --node-id, --ca-cert, --insecure-tls), and keeps every other line as it is."
        printf 'MLRF_API_URL=%s\nMLRF_API_KEY=%s\nMLRF_NODE_ID=%s\n' "$API_URL" "$API_KEY" "$NODE_ID"
        [ -z "$TLS_ENV" ] || printf '%s\n' "$TLS_ENV"
        printf 'PYTHONPATH=%s/src\nPYTHONUNBUFFERED=1\n' "$INSTALL_DIR"
        printf '%s' "$EXTRA_ENV_LINES"
    } > "$tmp" || ! chmod 600 "$tmp"; then
        rm -f "$tmp"
        die "could not write ${ENV_FILE}"
    fi
    if [ -f "$ENV_FILE" ] && ! cmp -s "$tmp" "$ENV_FILE"; then
        # A new file under umask 077, then exactly 0600, whatever mode the
        # old file (or an old .bak) had: it holds the API key.
        if ! { rm -f "${ENV_FILE}.bak" && cp "$ENV_FILE" "${ENV_FILE}.bak" \
            && chmod 600 "${ENV_FILE}.bak"; }; then
            rm -f "$tmp"
            die "could not keep ${ENV_FILE}.bak"
        fi
        log "the previous ${ENV_FILE} is kept as ${ENV_FILE}.bak"
    fi
    mv -f "$tmp" "$ENV_FILE"
}

# ── State directory ──────────────────────────────────────────────────
# scanner-config.json (a runtime update_config from the bridge) goes here,
# for the scanner units to read. Created when missing; an existing one is
# never re-owned or chmodded (systemd re-owns it for the scanner units that
# declare StateDirectory=sigrift-edge and run as pi).
prepare_state_dir() {
    if [ ! -d "$STATE_DIR" ]; then
        log "creating ${STATE_DIR} (scanner-config.json for the scanners)"
        install -d -m 0755 "$STATE_DIR"
    fi
}

# ── systemd unit ─────────────────────────────────────────────────────
write_unit() {
    log "writing ${SERVICE_FILE}"
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=SigRift edge agent (heartbeat + RF ingest)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV_DIR}/bin/python -m sigrift.edge.node_agent
Restart=always
RestartSec=10
WorkingDirectory=${INSTALL_DIR}

# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
# No StateDirectory=: this unit runs as root, and systemd would re-own ${STATE_DIR} to root at every start, locking out the scanner units that run as pi (src/sigrift/edge/README.md, step 5).
ReadWritePaths=/var/log /tmp -${STATE_DIR}

[Install]
WantedBy=multi-user.target
EOF
}

# ── Enable + (re)start ───────────────────────────────────────────────
# A running agent is restarted, so it runs the new checkout and settings
# (enable --now alone leaves a running service as it is).
start_service() {
    systemctl daemon-reload
    if systemctl is-active --quiet sigrift-edge.service; then
        log "restarting sigrift-edge.service (new checkout and settings)"
        systemctl enable sigrift-edge.service
        systemctl restart sigrift-edge.service
    else
        log "enabling + starting sigrift-edge.service"
        systemctl enable --now sigrift-edge.service
    fi
}

# ── Summary ──────────────────────────────────────────────────────────
# The re-run command for the trust this install uses. It downloads first:
# piped into bash, a failed download (an expired CA, a 5xx) would run an
# empty script and exit 0 with nothing upgraded.
upgrade_command() {
    local trust="" url
    if [ -n "$CA_CERT" ]; then
        trust="--cacert ${CA_DEST} "
    elif [ "$INSECURE_TLS" -eq 1 ]; then
        trust="-k "
    fi
    url=$API_URL
    while [ "${url%/}" != "$url" ]; do url=${url%/}; done
    # shellcheck disable=SC2016  # $f is for the operator's shell
    printf 'f=$(mktemp) && curl -fsSL %s-o "$f" %s/api/edge/install.sh && sudo bash "$f"; rm -f "$f"' \
        "$trust" "$url"
}

print_summary() {
    local head
    sleep 2
    if systemctl is-active --quiet sigrift-edge.service; then
        head=$(git -C "$INSTALL_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)
        log "SigRift edge agent is running."
        log "  Node ID:  ${NODE_ID}"
        log "  Gateway:  ${API_URL}"
        log "  Release:  ${REF} (${head})"
        log "  Journal:  journalctl -u sigrift-edge -f"
        log "  Upgrade:  after a server upgrade, run (no flags needed):"
        log "    $(upgrade_command)"
        if [ "$INSECURE_TLS" -eq 1 ]; then
            log "WARN: the gateway certificate is NOT verified (MLRF_INSECURE_TLS=1, which re-runs keep): re-run with --ca-cert <the gateway's tls/cert.pem> to fix"
        fi
        log ""
        log "Dashboard should show this node within ~30 seconds."
    else
        die "sigrift-edge.service failed to start — see: journalctl -u sigrift-edge -n 50"
    fi
}

main() {
    parse_args "$@"
    [ "$(id -u)" -eq 0 ] || die "must run as root (prefix with sudo)"
    load_existing_env
    resolve_settings
    check_ca_cert
    resolve_ref
    if [ "$INSECURE_TLS" -eq 0 ]; then
        check_gateway_tls
    fi
    ensure_node_id
    check_os
    install_packages
    blacklist_dvb
    checkout_ref
    install_python_deps
    install_trust_anchor
    write_env_file
    prepare_state_dir
    write_unit
    start_service
    print_summary
}

[ "${SIGRIFT_EDGE_INSTALL_SOURCE_ONLY:-0}" = 1 ] || main "$@"
