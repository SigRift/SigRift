"""The staging smoke's ingest step posts for the node its key is bound to.

The bridge seeds BRIDGE_LOCAL_NODE_KEY bound to BRIDGE_LOCAL_NODE_ID
(contract K4) and refuses it for any other node with 403. Step 4 of
scripts/staging-smoke.sh posts a BT ingest summary with that key, and
a refused post fails the smoke, so the step must post for exactly the
node the bridge bound the key to — a fixed node id ("smoke-probe")
failed every run.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SMOKE = ROOT / "scripts" / "staging-smoke.sh"
COMPOSE = ROOT / "docker-compose.yml"
BASH = shutil.which("bash") or "/bin/bash"

needs_tools = pytest.mark.skipif(
    not (shutil.which("jq") and shutil.which("gzip")),
    reason="jq and gzip are needed to run the smoke script",
)

# A curl stand-in: steps 1-3 succeed, step 4's gzipped body is saved and
# answered with 201, and the login (step 5) fails, which ends the run.
FAKE_CURL = textwrap.dedent("""\
    #!/bin/bash
    url=""
    for arg in "$@"; do
        case "$arg" in http://*|https://*) url="$arg" ;; esac
    done
    case "$url" in
        */health) exit 0 ;;
        */api/version) printf '{"server_version":"test"}' ;;
        */api/ready) printf '{"status":"ready"}' ;;
        */api/bluetooth/ingest-summary)
            cat > "$SMOKE_CAPTURE"
            printf '201' ;;
        *) exit 22 ;;
    esac
    """)


def run_smoke(
    tmp_path: Path, ingest_status: str = "201", **env: str
) -> tuple[subprocess.CompletedProcess, dict]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    curl = bin_dir / "curl"
    curl.write_text(FAKE_CURL.replace("printf '201'", f"printf '{ingest_status}'"))
    curl.chmod(0o755)
    capture = tmp_path / "ingest-body.gz"
    full = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "TMPDIR": str(tmp_path),
        "LC_ALL": "C",
        "BASE_URL": "https://127.0.0.1:8444",
        "BRIDGE_ADMIN_PASSWORD": "not-used-here",
        "BRIDGE_LOCAL_NODE_KEY": "node-key-123456",
        "LOG_DIR": str(tmp_path),
        "SMOKE_CAPTURE": str(capture),
    }
    full.update(env)
    r = subprocess.run(
        [BASH, str(SMOKE)],
        capture_output=True,
        text=True,
        env=full,
        stdin=subprocess.DEVNULL,
        timeout=60,
    )
    body = json.loads(gzip.decompress(capture.read_bytes())) if capture.exists() else {}
    return r, body


@needs_tools
@pytest.mark.parametrize(
    ("env", "node"),
    [
        ({"BRIDGE_LOCAL_NODE_ID": "sensor-7"}, "sensor-7"),
        ({"BRIDGE_LOCAL_NODE_ID": "sensor-7", "MLRF_NODE_ID": "other"}, "sensor-7"),
        # The bridge's own default chain: ${MLRF_NODE_ID:-local-edge}.
        ({"MLRF_NODE_ID": "edge-b"}, "edge-b"),
        ({}, "local-edge"),
    ],
)
def test_ingest_step_posts_for_the_bound_node(tmp_path, env, node):
    r, body = run_smoke(tmp_path, **env)
    assert "OK    step 4" in r.stderr, r.stderr
    assert body["node_id"] == node
    # Still the empty summary that writes no rows.
    assert body["devices"] == [] and body["total_observations"] == 0
    # The run went on to the login step (which the fake curl fails).
    assert "FAIL  step 5" in r.stderr and r.returncode == 1


@needs_tools
def test_ingest_step_failure_names_the_node(tmp_path):
    r, body = run_smoke(tmp_path, ingest_status="403", BRIDGE_LOCAL_NODE_ID="sensor-7")
    assert body["node_id"] == "sensor-7"
    assert r.returncode == 1
    assert "FAIL  step 4" in r.stderr and "node sensor-7 HTTP 403" in r.stderr
    assert "step 5" not in r.stderr


def test_compose_binds_the_scanner_key_to_mlrf_node_id():
    """local_node_id() mirrors this compose line; keep the two in step."""
    text = COMPOSE.read_text()
    bridge = re.search(r"^  bridge:\n(.*?)(?=^  \S)", text, re.S | re.M)
    assert bridge, "bridge service missing in docker-compose.yml"
    assert "- BRIDGE_LOCAL_NODE_ID=${MLRF_NODE_ID:-local-edge}" in bridge.group(1)
