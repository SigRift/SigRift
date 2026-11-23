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
#       [--ca-cert gateway-cert.pem]
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

set -euo pipefail

INSTALL_DIR="/opt/sigrift-edge"
VENV_DIR="${INSTALL_DIR}/venv"
ENV_FILE="/etc/sigrift-edge.env"
CA_DEST="/etc/sigrift-edge/ca.pem"
SERVICE_FILE="/etc/systemd/system/sigrift-edge.service"
REPO_URL="https://github.com/SigRift/SigRift.git"

API_URL=""
API_KEY=""
NODE_ID=""
CA_CERT=""
INSECURE_TLS=0

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# ── Args ─────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --api-url)   API_URL="$2"; shift 2 ;;
        --api-key)   API_KEY="$2"; shift 2 ;;
        --node-id)   NODE_ID="$2"; shift 2 ;;
        --ca-cert)   CA_CERT="$2"; shift 2 ;;
        --insecure-tls) INSECURE_TLS=1; shift ;;
        -h|--help)
            sed -n '2,29p' "$0"
            exit 0
            ;;
        *) die "unknown arg: $1" ;;
    esac
done

# ── Preflight ────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || die "must run as root (prefix with sudo)"
[ -n "$API_URL" ]    || die "--api-url is required"
[ -n "$API_KEY" ]    || die "--api-key is required"
if [ -n "$CA_CERT" ]; then
    [ -f "$CA_CERT" ] || die "--ca-cert file not found: $CA_CERT"
    grep -q -- "-----BEGIN CERTIFICATE-----" "$CA_CERT" \
        || die "--ca-cert is not a PEM certificate: $CA_CERT"
    [ "$INSECURE_TLS" -eq 0 ] || die "--ca-cert and --insecure-tls are mutually exclusive"
fi

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
if [ "$INSECURE_TLS" -eq 0 ]; then
    check_gateway_tls
fi

if [ -z "$NODE_ID" ]; then
    NODE_ID="$(hostname -s)-$(date +%s | tail -c 6)"
    log "Auto-generated NODE_ID: ${NODE_ID}"
fi

. /etc/os-release
case "$ID" in
    ubuntu|debian|raspbian) ;;
    *)
        log "WARN: unsupported distro $ID — proceeding anyway; may need manual intervention"
        ;;
esac

# ── apt packages ─────────────────────────────────────────────────────
log "apt: ensuring base + SDR packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    ca-certificates curl git \
    python3 python3-pip python3-venv \
    rtl-sdr \
    build-essential python3-dev

# ── Kernel DVB blacklist ─────────────────────────────────────────────
# The stock DVB drivers claim the RTL2832U chipset and block userspace
# SDR access. Blacklist them persistently so the next boot — or an
# immediate modprobe -r — frees the dongle for rtl_sdr / rtl_tcp.
BLACKLIST_FILE=/etc/modprobe.d/blacklist-rtl.conf
EXPECTED_BLACKLIST=$(cat <<'EOF'
blacklist dvb_usb_rtl28xxu
blacklist rtl2832
blacklist rtl2830
EOF
)
if [ ! -f "$BLACKLIST_FILE" ] || ! diff -q <(echo "$EXPECTED_BLACKLIST") "$BLACKLIST_FILE" >/dev/null; then
    log "writing RTL-SDR module blacklist"
    echo "$EXPECTED_BLACKLIST" > "$BLACKLIST_FILE"
    modprobe -r dvb_usb_rtl28xxu rtl2832 rtl2830 2>/dev/null || true
    udevadm control --reload-rules 2>/dev/null || true
    udevadm trigger --action=add --subsystem-match=usb 2>/dev/null || true
fi

# ── Repo checkout ────────────────────────────────────────────────────
if [ ! -d "${INSTALL_DIR}/.git" ]; then
    log "cloning SigRift to ${INSTALL_DIR}"
    mkdir -p "$INSTALL_DIR"
    git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
else
    log "updating SigRift checkout"
    git -C "$INSTALL_DIR" fetch --depth 1 origin main
    git -C "$INSTALL_DIR" reset --hard origin/main
fi

# ── Python virtualenv ────────────────────────────────────────────────
if [ ! -d "$VENV_DIR" ]; then
    log "creating venv at ${VENV_DIR}"
    python3 -m venv "$VENV_DIR"
fi
log "installing Python deps into venv"
"${VENV_DIR}/bin/pip" install --quiet --upgrade pip
"${VENV_DIR}/bin/pip" install --quiet -r "${INSTALL_DIR}/src/sigrift/bridge/requirements.txt"

# ── Gateway trust anchor ─────────────────────────────────────────────
TLS_ENV=""
if [ -n "$CA_CERT" ]; then
    log "installing gateway CA certificate to ${CA_DEST}"
    install -d -m 0755 "$(dirname "$CA_DEST")"
    install -m 0644 "$CA_CERT" "$CA_DEST"
    TLS_ENV="MLRF_CA_CERT=${CA_DEST}"
elif [ "$INSECURE_TLS" -eq 1 ]; then
    log "WARN: --insecure-tls — gateway certificate will NOT be verified (development only)"
    TLS_ENV="MLRF_INSECURE_TLS=1"
else
    log "no --ca-cert given — the agent will verify the gateway against the system trust store"
    log "  (a self-signed gateway needs --ca-cert, or heartbeats will fail TLS verification)"
fi

# ── Environment file (0600, contains the API key) ────────────────────
log "writing ${ENV_FILE}"
umask 077
cat > "$ENV_FILE" <<EOF
# Generated by edge-install.sh. Re-running the installer will
# overwrite this file. Chmod 600 — contains a NODE-role API key.
MLRF_API_URL=${API_URL}
MLRF_API_KEY=${API_KEY}
MLRF_NODE_ID=${NODE_ID}
${TLS_ENV}
PYTHONPATH=${INSTALL_DIR}/src
PYTHONUNBUFFERED=1
EOF
chmod 600 "$ENV_FILE"

# ── systemd unit ─────────────────────────────────────────────────────
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
ReadWritePaths=/var/log /tmp

[Install]
WantedBy=multi-user.target
EOF

# ── Enable + start ───────────────────────────────────────────────────
log "enabling + starting sigrift-edge.service"
systemctl daemon-reload
systemctl enable --now sigrift-edge.service

# ── Summary ──────────────────────────────────────────────────────────
sleep 2
if systemctl is-active --quiet sigrift-edge.service; then
    log "SigRift edge agent is running."
    log "  Node ID:  ${NODE_ID}"
    log "  Gateway:  ${API_URL}"
    log "  Journal:  journalctl -u sigrift-edge -f"
    log ""
    log "Dashboard should show this node within ~30 seconds."
else
    die "sigrift-edge.service failed to start — see: journalctl -u sigrift-edge -n 50"
fi
