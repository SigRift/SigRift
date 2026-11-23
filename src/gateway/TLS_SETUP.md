# TLS Certificate Setup for the Gateway

## Production: Let's Encrypt (recommended)

### Prerequisites
- A domain name pointing to your server (e.g., `bridge.yourdomain.com`)
- Port 80 accessible for ACME challenge (or use DNS challenge)

### Install certbot
```bash
sudo apt install certbot
```

### Obtain certificate
```bash
# Standalone mode (stops any service on port 80 briefly)
sudo certbot certonly --standalone -d bridge.yourdomain.com

# Or DNS challenge (no port 80 needed)
sudo certbot certonly --manual --preferred-challenges dns -d bridge.yourdomain.com
```

### Certificate locations
```
/etc/letsencrypt/live/bridge.yourdomain.com/fullchain.pem  # cert
/etc/letsencrypt/live/bridge.yourdomain.com/privkey.pem    # key
```

### Configure the gateway
```bash
UC_TLS_CERT=/etc/letsencrypt/live/bridge.yourdomain.com/fullchain.pem
UC_TLS_KEY=/etc/letsencrypt/live/bridge.yourdomain.com/privkey.pem
```

### Auto-renewal
```bash
# Test renewal
sudo certbot renew --dry-run

# Cron (certbot installs this automatically)
# Renews every 60 days, cert valid for 90 days
0 0 1 */2 * certbot renew --post-hook "systemctl restart sigrift-gateway"
```

### systemd service
```ini
[Service]
Environment=UC_TLS_CERT=/etc/letsencrypt/live/bridge.yourdomain.com/fullchain.pem
Environment=UC_TLS_KEY=/etc/letsencrypt/live/bridge.yourdomain.com/privkey.pem
```

## Self-signed certificate (default installs)

`scripts/quickstart.sh` and `install-release.sh` generate the gateway's
self-signed certificate themselves, with every name the stack needs: the
in-stack agents dial `gateway` and `127.0.0.1`, so the certificate must
list them, and the installers add the host's names and addresses. Do not
replace it with a hand-made certificate. To add names (`SIGRIFT_TLS_SANS`),
renew it, or give it to remote edge nodes, see INSTALL.md
["Gateway certificate for remote edge nodes"](../../INSTALL.md#gateway-certificate-for-remote-edge-nodes)
and ["Certificate renewal"](../../INSTALL.md#certificate-renewal); for
certificate errors see [TROUBLESHOOTING.md](../../TROUBLESHOOTING.md).
Production mode (`BRIDGE_ENV=production`, the release installer's and the
compose file's default) works with this certificate; do not lower
`BRIDGE_ENV` to work around a certificate problem.

### Browser setup
1. First visit shows certificate warning — accept it. Two options:
   - **Per-session click-through (preferred):** in Chrome, type `thisisunsafe` anywhere on the cert error page to proceed once; in Firefox, click "Advanced → Accept the Risk and Continue". This keeps the rest of the browser's safety checks intact.
   - **Suppress the warning globally for localhost:** in Chrome, enable `chrome://flags/#allow-insecure-localhost`. This turns the warning off for *all* localhost cert errors in that browser profile — convenient but blunt. Use only on a dev workstation.
2. Firefox: Settings → Privacy → Certificates → View → delete old exceptions if regenerating cert.

### Mitigations for self-signed quirks

Self-signed certs trigger some browser hardening that the gateway works around as a first-party feature, not a hack:

- `sessionStorage` may not persist across page navigations on cert-warning pages.
- The session survives a lost `sessionStorage` through the HttpOnly `session_token` cookie, which the browser sends with every same-origin request. Scripts cannot read it.

Older gateways also set a JS-readable `bridge_token` cookie that held a copy of the session token. Any injected script could read that copy, so the gateway no longer sets it and expires any stale copy at login and logout. Dashboard code must rely on the `session_token` cookie being sent automatically (`fetch` with `credentials: "same-origin"`). It must not read the token from a cookie.

## No TLS (HTTP only)

> **Warning:** Disabling TLS also disables the `Secure` cookie flag, HSTS, and the CSRF + session-binding chain that assume HTTPS end-to-end. This mode is acceptable **only** for an isolated local development loop on the same host. Do not run the gateway over plain HTTP on any interface reachable from another machine, container network, or VPN — credentials, session tokens, and detection payloads would all travel in clear text, and the browser will silently weaken or refuse cookies, session storage, and `fetch()` calls that the dashboard depends on.

For local development without TLS:
```bash
# Simply omit UC_TLS_CERT and UC_TLS_KEY
UC_HOST=0.0.0.0 UC_PORT=8444 ./target/release/sigrift-gateway
```

Access via `http://localhost:8444`. No certificate issues, all browser features work normally — but only on the loopback interface, and only for development.

## Verifying TLS

```bash
# Check certificate details
openssl s_client -connect localhost:8444 -showcerts </dev/null 2>/dev/null | openssl x509 -text -noout | head -20

# Test HTTPS
curl -v https://localhost:8444/health 2>&1 | grep "SSL\|TLS\|subject"

# Test with self-signed (skip verify)
curl -k https://localhost:8444/health
```

## Certificate Rotation

the gateway loads TLS certs at startup. To rotate certificates:

1. Replace cert/key files
2. Restart the gateway: `systemctl restart sigrift-gateway`

For zero-downtime rotation, use a reverse proxy (nginx/caddy) in front of the gateway that handles TLS termination and cert rotation independently.
