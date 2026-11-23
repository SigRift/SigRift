#!/bin/sh
# Probe the gateway itself, using the same TLS mode as its environment.
# The address is deliberately fixed to loopback and proxy use is disabled:
# this request carries no credentials, never follows redirects, and only
# checks that the local listener serves /health. Certificate verification
# is left to clients: an operator's valid public certificate need not name
# 127.0.0.1. The TLS exception here does not affect gateway or edge traffic.
set -eu

port=${UC_PORT:-8444}
case "$port" in
    ''|*[!0-9]*) echo "Invalid UC_PORT for healthcheck" >&2; exit 1 ;;
esac
if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    echo "Invalid UC_PORT for healthcheck" >&2
    exit 1
fi

scheme=http
if [ -n "${UC_TLS_CERT:-}" ] || [ -n "${UC_TLS_KEY:-}" ]; then
    if [ -z "${UC_TLS_CERT:-}" ] || [ -z "${UC_TLS_KEY:-}" ]; then
        echo "Healthcheck requires both UC_TLS_CERT and UC_TLS_KEY for TLS" >&2
        exit 1
    fi
    scheme=https
fi

status=$(curl --silent --show-error --fail --insecure --noproxy '*' \
    --connect-timeout 2 --max-time 3 --output /dev/null --write-out '%{http_code}' \
    "${scheme}://127.0.0.1:${port}/health")
[ "$status" = 200 ]
