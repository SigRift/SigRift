#!/usr/bin/env bash
# Post-deploy smoke for the SigRift staging stack.
#
# Invoked by scripts/bootstrap-staging.sh after `docker compose up -d`
# clears the gateway's basic health probe. A green `/health` only means
# the Rust gateway is listening — it doesn't prove the Python bridge
# routers loaded or that auth and storage actually work. This script
# does, in order:
#
#   1. gateway /health          — TCP listener up
#   2. bridge /api/version      — bridge is routing through the gateway
#   3. bridge /api/ready        — DB reachable (kubernetes-style probe)
#   4. POST /api/bluetooth/ingest-summary (gzip) — ingest path + decompress
#   5. POST /api/auth/login     — admin auth succeeds, HttpOnly session cookie set
#   6. /api/auth/me             — auth chain works end-to-end
#   7. /api/detections/recent   — viewer-role read works end-to-end
#
# Each step has a 5s curl timeout. First failure exits 1; bootstrap
# treats that as a deploy failure and rolls back. Exit 0 means all
# seven steps ran and passed — nothing is skipped silently except step 4
# without a node key (local runs).
#
# Auth transport: the cookie jar only, as a browser holds the session.
# Login writes the gateway's cookies to the jar with -c: the HttpOnly
# session_token (every gateway since 0.1.0 sets it; curl writes it as a
# `#HttpOnly_` line) and the csrf_token. Subsequent requests replay the
# jar with -b. The login body's session_token is never read: newer
# gateways stop returning it, and this works with either.
#
# Why only gateway-served endpoints in steps 6–7?
# The Rust gateway has its own routes for /api/auth/* and the
# /api/detections/* read endpoints (gateway/.../builder.rs:345-364).
# Anything else — /api/status, /api/nodes/, etc. — gets reverse-
# proxied to the Python bridge. The bridge then runs its own IP-
# binding check (BRIDGE_SESSION_BINDING=ip default), but the IP
# captured at login is the GATEWAY's view of the client (e.g.
# 127.0.0.1) while the IP the bridge sees on the proxied request is
# the GATEWAY container's IP — guaranteed mismatch → 401. The
# gateway's own proxy/handler.rs:122 comment acknowledges this skew
# ("Rust stores 127.0.0.1, browser comes from real IP"). Until that
# split-brain IP detection is fixed at the deployment layer (e.g.
# gateway sets X-Forwarded-For + bridge trusts it, or
# BRIDGE_SESSION_BINDING=none on staging), bridge-direct authed
# reads are unreachable from any client routed through the gateway.
# We therefore stay on gateway-served endpoints for the auth-gated
# coverage.
#
# The smoke admin must get a full session. A session restricted to
# changing the password (the account is flagged must_change_password) or
# to enrolling MFA (the tenant requires MFA) is a FAILURE: it cannot run
# steps 6-7, so passing it would mark a build last-good without the
# auth-gated checks ever running. Staging seeds its admin from
# BRIDGE_ADMIN_PASSWORD, which never sets must_change_password; if the
# flag is set anyway, log in once by hand and change the password (and
# update staging.env), or reset the account.
#
# Required env (passed through from deploy workflow):
#   BRIDGE_ADMIN_PASSWORD   — admin login password
#
# Optional env:
#   BRIDGE_LOCAL_NODE_KEY   — SENSOR-role API key; enables the step-4
#                             gzipped ingest check (skipped if unset)
#   BRIDGE_LOCAL_NODE_ID    — the node that key is bound to, which step 4
#                             posts for; default MLRF_NODE_ID, then
#                             "local-edge" (the bridge's defaults)
#   BASE_URL                — default https://127.0.0.1:8444
#   BRIDGE_ADMIN_USER       — default "admin"
#   LOG_DIR                 — default /opt/sigrift; falls back to /tmp

set -euo pipefail

BASE_URL="${BASE_URL:-https://127.0.0.1:8444}"
USER_NAME="${BRIDGE_ADMIN_USER:-admin}"
PASS="${BRIDGE_ADMIN_PASSWORD:-}"
LOG_DIR_RAW="${LOG_DIR:-/opt/sigrift}"

if [ -z "$PASS" ]; then
    echo "ERROR: BRIDGE_ADMIN_PASSWORD not set" >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq not installed (required for JSON parsing)" >&2
    exit 1
fi

# Resolve log dir; fall back to /tmp if the requested dir isn't writable.
if [ -d "$LOG_DIR_RAW" ] && [ -w "$LOG_DIR_RAW" ]; then
    LOG_DIR="$LOG_DIR_RAW"
else
    LOG_DIR=/tmp
fi
LOG_FILE="${LOG_DIR}/smoke-$(date -u +%Y%m%dT%H%M%SZ).log"

# Private scratch dir (0700) for the cookie jar and header files; cleaned
# up on exit so the session cookie isn't left readable on disk. Secrets
# (password, node key, session cookie) are handed to curl/jq through
# these files, stdin or the environment — never on the command line,
# which any local user can read from /proc while the process runs.
SMOKE_TMP=$(mktemp -d -t sigrift-smoke.XXXXXX)
trap 'rm -rf "$SMOKE_TMP"' EXIT
COOKIE_JAR="${SMOKE_TMP}/cookies"
: > "$COOKIE_JAR"

# curl(1) options: silent on success, fail on HTTP >=400, show errors,
# accept self-signed cert, hard 5s ceiling per call.
CURL_OPTS=(-fsS -k --max-time 5)

log()  { printf '%s [smoke] %s\n' "$(date -u +%H:%M:%SZ)" "$*" | tee -a "$LOG_FILE" >&2; }
fail() { log "FAIL  $*"; exit 1; }
pass() { log "OK    $*"; }

# Hit an authenticated GET with the cookie jar (the session cookie).
# Echoes "$http_code|$body" so callers can pattern-match on either.
# Doesn't fail on non-2xx — the caller decides whether to fail or
# tolerate (e.g. 403 mfa_setup_required).
auth_get() {
    local path="$1"
    curl -k --max-time 5 -sS \
        -b "$COOKIE_JAR" \
        -w '\n%{http_code}' \
        "${BASE_URL}${path}"
}

# True if the jar holds an HttpOnly session_token cookie with a value.
# curl writes an HttpOnly cookie as a `#HttpOnly_<domain>` line (tab-
# separated: domain, include-subdomains, path, secure, expiry, name,
# value) and drops a cookie the server expired.
jar_has_session() {
    awk -F '\t' '$1 ~ /^#HttpOnly_/ && $6 == "session_token" && $7 != "" { found = 1 }
        END { exit !found }' "$COOKIE_JAR"
}

# Returns 0 if the response is a scoped-session 403 (password change or
# MFA enrolment pending) — reported as such, then failed.
is_scoped_session_403() {
    local body="$1"
    printf '%s' "$body" | grep -qiE 'mfa setup required|password change required'
}

log "starting smoke against ${BASE_URL} (log: ${LOG_FILE})"

# ── Step 1 — gateway listener ──────────────────────────────────────────
curl "${CURL_OPTS[@]}" "${BASE_URL}/health" >/dev/null \
    || fail "step 1: GET /health (gateway not responding)"
pass "step 1: gateway /health"

# ── Step 2 — bridge alive via /api/version ─────────────────────────────
version_body=$(curl "${CURL_OPTS[@]}" "${BASE_URL}/api/version") \
    || fail "step 2: GET /api/version (bridge not routing through gateway)"
server_version=$(printf '%s' "$version_body" | jq -r '.server_version // empty')
[ -n "$server_version" ] || fail "step 2: /api/version missing server_version (body: $version_body)"
pass "step 2: bridge /api/version (server_version=${server_version})"

# ── Step 3 — bridge DB reachable ───────────────────────────────────────
ready_body=$(curl "${CURL_OPTS[@]}" "${BASE_URL}/api/ready") \
    || fail "step 3: GET /api/ready (bridge DB not ready)"
ready_status=$(printf '%s' "$ready_body" | jq -r '.status // empty')
[ "$ready_status" = "ready" ] || fail "step 3: /api/ready returned status='${ready_status}' (body: $ready_body)"
pass "step 3: bridge /api/ready"

# ── Step 4 — gzipped ingest path (the BLE-incident regression guard) ──
# Edge scanners authenticate with an API key (X-API-Key), NOT a session,
# so the IP-binding skew that limits steps 6-7 to gateway-served routes
# does not apply here — this is the exact path the BT scanner uses.
# The body is gzipped with Content-Encoding: gzip; a summary route that
# fails to decompress it returns 400. On 2026-06-10, 283 consecutive
# such 400s rode through a "healthy" deploy because smoke never touched
# an ingest path. An empty devices list writes no rows. Skipped (not
# failed) when BRIDGE_LOCAL_NODE_KEY is absent so local runs still work.
# The bridge binds that key to its node (BRIDGE_LOCAL_NODE_ID) and refuses
# it for any other node (403), so the summary is posted for that node.
if [ -n "${BRIDGE_LOCAL_NODE_KEY:-}" ]; then
    printf 'X-API-Key: %s\n' "$BRIDGE_LOCAL_NODE_KEY" > "${SMOKE_TMP}/node-headers"
    ingest_node="${BRIDGE_LOCAL_NODE_ID:-${MLRF_NODE_ID:-local-edge}}"
    ingest_payload=$(jq -nc --arg n "$ingest_node" \
        '{node_id: $n, scan_period_s: 1.0, total_observations: 0, devices: []}')
    ingest_code=$(printf '%s' "$ingest_payload" | gzip \
        | curl -k --max-time 5 -sS -o /dev/null -w '%{http_code}' \
            -X POST "${BASE_URL}/api/bluetooth/ingest-summary" \
            -H @"${SMOKE_TMP}/node-headers" \
            -H 'Content-Type: application/json' \
            -H 'Content-Encoding: gzip' \
            --data-binary @-) \
        || fail "step 4: POST /api/bluetooth/ingest-summary (network failure)"
    [ "$ingest_code" = "201" ] \
        || fail "step 4: gzipped BT ingest-summary for node ${ingest_node} HTTP ${ingest_code} (expected 201 — gzip ingest-path regression? 403: BRIDGE_LOCAL_NODE_ID is not the node the key is bound to)"
    pass "step 4: gzipped BT ingest-summary for node ${ingest_node} (201)"
else
    log "SKIP  step 4: gzipped ingest check (BRIDGE_LOCAL_NODE_KEY not set)"
fi

# ── Step 4 — admin login (capture the session and CSRF cookies) ────────
# Password reaches jq via its environment and curl via stdin.
login_body=$(SMOKE_PASS="$PASS" jq -nc --arg u "$USER_NAME" '{username: $u, password: env.SMOKE_PASS}' \
    | curl "${CURL_OPTS[@]}" -X POST "${BASE_URL}/api/auth/login" \
        -c "$COOKIE_JAR" \
        -H 'Content-Type: application/json' \
        --data-binary @-) \
    || fail "step 5: POST /api/auth/login (network/auth failure)"

mfa_required=$(printf '%s' "$login_body" | jq -r '.mfa_required // false')
if [ "$mfa_required" = "true" ]; then
    fail "step 5: login returned mfa_required=true (smoke admin must not have MFA)"
fi
if [ "$(printf '%s' "$login_body" | jq -r '.password_change_required // false')" = "true" ]; then
    fail "step 5: the admin session is restricted to changing the password (must_change_password is set) — steps 6-7 cannot run; change the password or reset the account (see the header of this script)"
fi
if [ "$(printf '%s' "$login_body" | jq -r '.mfa_setup_required // false')" = "true" ]; then
    fail "step 5: the admin session is restricted to MFA enrolment (the tenant requires MFA) — steps 6-7 cannot run; the smoke admin needs a full session"
fi
# The session is the HttpOnly cookie the gateway set; steps 6-7 send
# only the jar, so they prove the cookie authenticates.
jar_has_session \
    || fail "step 5: login set no HttpOnly session_token cookie (the gateway issues the session only as that cookie)"
pass "step 5: POST /api/auth/login"

# ── Step 5 — auth chain works end-to-end via /api/auth/me ─────────────
# Cheapest authenticated check (no role gating beyond require_api_key).
# If this fails the auth chain itself is broken; subsequent role-
# gated steps would fail with no extra signal. Body echo helps
# diagnose IP-binding mismatches and scope rejections.
me_resp=$(auth_get /api/auth/me)
me_code=$(printf '%s' "$me_resp" | tail -n1)
me_body=$(printf '%s' "$me_resp" | sed '$d')
case "$me_code" in
    200)
        me_user=$(printf '%s' "$me_body" | jq -r '.username // empty')
        pass "step 6: /api/auth/me (user=${me_user})"
        ;;
    403)
        if is_scoped_session_403 "$me_body"; then
            fail "step 6: /api/auth/me 403 — the admin session is scoped (${me_body}); steps 6-7 cannot run, so this deploy is not verified"
        fi
        fail "step 6: /api/auth/me 403 (body: $me_body)"
        ;;
    *)
        fail "step 6: /api/auth/me HTTP ${me_code} (body: $me_body)"
        ;;
esac

# ── Step 6 — /api/detections/recent (viewer role, gateway-served) ──────
# Gateway has its own native handler for this path (no proxy to bridge),
# so the IP-binding skew doesn't bite. Validates that role-gated reads
# actually return data shaped as expected.
det_resp=$(auth_get '/api/detections/recent?limit=1')
det_code=$(printf '%s' "$det_resp" | tail -n1)
det_body=$(printf '%s' "$det_resp" | sed '$d')
if [ "$det_code" = "403" ] && is_scoped_session_403 "$det_body"; then
    fail "step 7: /api/detections/recent 403 — the admin session is scoped (${det_body}); this deploy is not verified"
fi
[ "$det_code" = "200" ] || fail "step 7: /api/detections/recent HTTP ${det_code} (body: $det_body)"
# Gateway and bridge both serve this endpoint with the same shape, but
# accept either an array (gateway) or {detections: [...]} (bridge) for
# robustness.
printf '%s' "$det_body" \
    | jq -e 'type == "array" or (.detections | type == "array")' >/dev/null \
    || fail "step 7: /api/detections/recent unexpected body (body: $det_body)"
pass "step 7: /api/detections/recent"

log "ALL 7 smoke steps passed (${BASE_URL})"
