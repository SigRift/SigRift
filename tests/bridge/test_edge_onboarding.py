"""Tests for the edge-agent onboarding endpoint.

Covers GET /api/edge/install.sh — an unauthenticated endpoint that
returns the host-install shell script. No secrets are embedded in the
script; the operator must supply --api-key at invocation.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from fastapi.testclient import TestClient


class TestEdgeInstallScript:
    """GET /api/edge/install.sh"""

    def test_returns_200(self, client: TestClient):
        resp = client.get("/api/edge/install.sh")
        assert resp.status_code == 200

    def test_is_public(self, bridge_app):
        """Explicitly no auth — `curl | bash` must work without a
        dashboard cookie or API key."""
        unauth = TestClient(bridge_app)
        resp = unauth.get("/api/edge/install.sh")
        assert resp.status_code == 200

    def test_content_type(self, client: TestClient):
        resp = client.get("/api/edge/install.sh")
        assert resp.headers["content-type"].startswith("text/x-shellscript")

    def test_script_has_shebang(self, client: TestClient):
        resp = client.get("/api/edge/install.sh")
        assert resp.text.startswith("#!/usr/bin/env bash"), (
            "script must be identifiable to `sudo bash` as a shell script"
        )

    def test_script_contains_required_args(self, client: TestClient):
        """Sanity: the script must accept the two args the dashboard's
        one-liner passes, otherwise the install flow breaks silently."""
        resp = client.get("/api/edge/install.sh")
        body = resp.text
        assert "--api-url" in body
        assert "--api-key" in body

    def test_script_never_embeds_secrets(self, client: TestClient):
        """Script is served unauthenticated; any embedded secret would
        leak. Caller-supplied API key is the only sensitive value in
        the flow, and it arrives at `sudo bash -s --` runtime."""
        resp = client.get("/api/edge/install.sh")
        body = resp.text
        # Common env-var-style secret names that would indicate a leak
        forbidden = [
            "BRIDGE_MFA_KEY=",
            "BRIDGE_AUDIT_KEY=",
            "UC_PROXY_SECRET=",
            "BRIDGE_ADMIN_PASSWORD=",
        ]
        for needle in forbidden:
            assert needle not in body, f"install.sh leaks {needle}"

    def test_script_blacklists_dvb_modules(self, client: TestClient):
        """Scripts that don't blacklist the kernel DVB drivers produce
        'usb_claim_interface error -6' on every RTL-SDR install; guard
        against a regression where the blacklist block gets removed."""
        body = client.get("/api/edge/install.sh").text
        for module in ("dvb_usb_rtl28xxu", "rtl2832", "rtl2830"):
            assert f"blacklist {module}" in body

    def test_script_installs_required_deps(self, client: TestClient):
        body = client.get("/api/edge/install.sh").text
        # These three packages are the host-side minimum. If any is
        # dropped the agent won't start.
        for pkg in ("python3", "python3-venv", "rtl-sdr"):
            assert pkg in body, f"install.sh missing {pkg}"

    def test_script_writes_env_file_with_0600(self, client: TestClient):
        """The env file holds the NODE API key; chmod must be 600."""
        body = client.get("/api/edge/install.sh").text
        assert "chmod 600" in body
        assert "/etc/sigrift-edge.env" in body

    def test_script_creates_systemd_unit(self, client: TestClient):
        body = client.get("/api/edge/install.sh").text
        assert "sigrift-edge.service" in body
        assert "systemctl enable --now" in body

    def test_script_is_idempotent_on_clone(self, client: TestClient):
        """Re-running must update an existing checkout, not fail or
        duplicate."""
        body = client.get("/api/edge/install.sh").text
        assert "git -C" in body and "reset --hard" in body


class TestEdgeInstallScriptFilePresent:
    """The served script must physically exist on disk (otherwise the
    endpoint 500s and the onboarding flow silently breaks)."""

    def test_script_file_exists(self):
        from sigrift.bridge.routers import edge as edge_router
        assert edge_router._INSTALL_SCRIPT_PATH.is_file(), (
            f"expected install script at {edge_router._INSTALL_SCRIPT_PATH}"
        )

    def test_script_is_executable_in_repo(self):
        """Convenience for local testing (`./scripts/edge-install.sh
        --help`); not load-bearing for the actual `curl | bash` flow,
        which doesn't care about the exec bit. CI runners sometimes
        check out without preserving filemode (`core.fileMode=false`),
        so this is informational only — pass even if the bit is missing.
        """
        from sigrift.bridge.routers import edge as edge_router
        import os
        path = edge_router._INSTALL_SCRIPT_PATH
        if not os.access(path, os.X_OK):
            import warnings
            warnings.warn(
                f"{path} not chmod +x — fine for `curl | bash`, but local "
                f"`./scripts/edge-install.sh` won't work without `bash` prefix",
                UserWarning,
                stacklevel=2,
            )


# ---------------------------------------------------------------------------
# Self-signed gateways: the onboarding command and the installer's TLS check
# ---------------------------------------------------------------------------

_BRIDGE_DIR = Path(__file__).resolve().parents[2] / "src" / "sigrift" / "bridge"


class TestOnboardingCommandTrustsGatewayCert:
    """The agent verifies TLS, so the copy-paste command must carry the
    gateway certificate (both for curl and for the agent) — otherwise, on
    a default self-signed install, the node installs but never heartbeats."""

    @staticmethod
    def _check(command: str) -> None:
        assert "--cacert gateway-cert.pem" in command
        assert "--ca-cert gateway-cert.pem" in command
        # The copy button turns YOUR_NODE_KEY into a "# REPLACE ..." shell
        # comment, so nothing may follow the key on the line.
        assert command.rstrip().endswith("--api-key YOUR_NODE_KEY"), command

    def test_dashboard_one_liner(self):
        js = (_BRIDGE_DIR / "static" / "dashboard.js").read_text()
        start = js.index("pre.textContent =")
        statement = js[start : js.index(";", start)]
        # Join the JS string literals back into the command line.
        import re

        self._check("".join(re.findall(r'"([^"]*)"', statement)))

    def test_template_placeholder(self):
        import html as html_mod

        html = (_BRIDGE_DIR / "templates" / "index.html").read_text()
        start = html.index('id="edge-install-oneliner"')
        code = html[html.index(">", start) + 1 : html.index("</code>", start)]
        self._check(html_mod.unescape(code))
        # The step before it says where the certificate comes from.
        assert "tls/cert.pem" in html[html.index("edge-onboarding-installer") : start]


class TestInstallerTLSPreflight:
    """edge-install.sh checks the gateway certificate before installing."""

    _BASE = ("--api-url", "https://gw.example:8444", "--api-key", "k")

    @staticmethod
    def _run(tmp_path: Path, curl_rc: int, *args: str):
        stubs = tmp_path / "stubs"
        stubs.mkdir(exist_ok=True)
        calls = tmp_path / "calls.log"
        for name, body in {
            "id": "echo 0",
            "curl": f'echo "curl $*" >> "{calls}"; exit {curl_rc}',
            # Stop right after preflight: the first install step.
            "apt-get": f'echo "apt-get $*" >> "{calls}"; exit 97',
        }.items():
            stub = stubs / name
            stub.write_text(f"#!/bin/sh\n{body}\n")
            stub.chmod(0o755)
        script = _BRIDGE_DIR / "scripts" / "edge-install.sh"
        proc = subprocess.run(
            ["bash", str(script), *args],
            capture_output=True,
            text=True,
            timeout=60,
            env={"PATH": f"{stubs}:{os.environ.get('PATH', '/usr/bin:/bin')}"},
        )
        log = calls.read_text() if calls.exists() else ""
        return proc, log

    def test_untrusted_gateway_stops_before_installing(self, tmp_path):
        proc, log = self._run(tmp_path, 60, *self._BASE)
        assert proc.returncode == 1
        assert "--ca-cert" in proc.stderr
        assert "apt-get" not in log

    def test_ca_cert_that_does_not_verify_stops(self, tmp_path):
        cert = tmp_path / "gateway-cert.pem"
        cert.write_text(
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        )
        proc, log = self._run(tmp_path, 60, *self._BASE, "--ca-cert", str(cert))
        assert proc.returncode == 1
        assert "subjectAltName" in proc.stderr
        assert f"--cacert {cert}" in log
        assert "apt-get" not in log

    def test_unreachable_gateway_does_not_block(self, tmp_path):
        proc, log = self._run(tmp_path, 7, *self._BASE)
        assert "could not reach" in proc.stdout
        assert proc.returncode == 97  # reached the apt-get stub
        assert "apt-get" in log

    def test_verified_gateway_proceeds(self, tmp_path):
        proc, log = self._run(tmp_path, 0, *self._BASE)
        assert proc.returncode == 97
        assert "apt-get" in log

    def test_insecure_tls_skips_the_check(self, tmp_path):
        proc, log = self._run(tmp_path, 60, *self._BASE, "--insecure-tls")
        assert proc.returncode == 97
        assert "curl" not in log
