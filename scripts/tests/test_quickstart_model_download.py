"""Exercise quickstart's shipped model selection against real HTTP transfers.

Only the fixed GitHub API URL is redirected to the disposable loopback server.
The shipped model block, real curl, checksum verification and retry discovery
run unchanged; no installer, Docker command, or external endpoint is executed.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import shutil
import signal
import subprocess
import threading
import urllib.parse
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
BASH = shutil.which("bash")
CURL = shutil.which("curl")
MODEL_NAME = "release-model.onnx"
META_NAME = "release-model_metadata.json"
OTHER_META_NAME = "other-model_metadata.json"
OTHER_METADATA = b'{"classes": ["another model"]}\n'
MODEL = b"disposable transport fixture; not an ONNX inference claim\n" * 128
METADATA = b'{"classes": ["fixture"]}\n'

pytestmark = pytest.mark.skipif(not (BASH and CURL), reason="requires bash and curl")


@pytest.fixture
def release_server():
    state = SimpleNamespace(
        truncate_model=0,
        truncate_sums=0,
        truncate_metadata=0,
        checksum=True,
        mismatch=False,
        metadata=True,
        sums_list_metadata=False,
        metadata_mismatch=False,
        decoys=False,
        requests=Counter(),
        pause_model=False,
        model_started=threading.Event(),
        release_model=threading.Event(),
        stall_path=None,
        stall_before_headers=False,
        stream_path=None,
        release_stall=threading.Event(),
        stalled=threading.Event(),
    )

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            # Asset URLs are percent-encoded, as a real server may do.
            path = urllib.parse.unquote(self.path)
            state.requests[path] += 1

            def asset(name):
                return {
                    "name": name,
                    "browser_download_url": state.base + "/" + urllib.parse.quote(name),
                }

            if path == "/release":
                assets = [asset(MODEL_NAME)]
                if state.decoys:
                    # Another model and its sidecar, listed before this one's.
                    assets += [asset(OTHER_META_NAME), asset("other-model.onnx")]
                if state.metadata:
                    assets.append(asset(META_NAME))
                if state.checksum:
                    assets.append(
                        {
                            "name": "SHA256SUMS",
                            "browser_download_url": state.base + "/SHA256SUMS",
                        }
                    )
                data = json.dumps({"assets": assets}).encode()
                truncate = False
            elif path == "/" + OTHER_META_NAME:
                data = OTHER_METADATA
                truncate = False
            elif path == "/" + MODEL_NAME:
                data = MODEL
                truncate = state.truncate_model > 0
                state.truncate_model = max(0, state.truncate_model - 1)
            elif path == "/" + META_NAME:
                data = METADATA
                truncate = state.truncate_metadata > 0
                state.truncate_metadata = max(0, state.truncate_metadata - 1)
            elif path == "/SHA256SUMS":
                digest = (
                    "0" * 64 if state.mismatch else hashlib.sha256(MODEL).hexdigest()
                )
                data = f"{digest}  {MODEL_NAME}\n".encode()
                if state.sums_list_metadata:
                    meta_digest = (
                        "0" * 64
                        if state.metadata_mismatch
                        else hashlib.sha256(METADATA).hexdigest()
                    )
                    data += f"{meta_digest}  {META_NAME}\n".encode()
                truncate = state.truncate_sums > 0
                state.truncate_sums = max(0, state.truncate_sums - 1)
            else:
                self.send_error(404)
                return
            if path == state.stall_path and state.stall_before_headers:
                state.stalled.set()
                state.release_stall.wait(timeout=50)
                return
            self.send_response(200)
            self.send_header(
                "Content-Length",
                str(1_000_000 if path == state.stream_path else len(data)),
            )
            self.end_headers()
            try:
                if path == state.stall_path:
                    self.wfile.write(data[:1])
                    self.wfile.flush()
                    state.stalled.set()
                    state.release_stall.wait(timeout=50)
                elif path == state.stream_path:
                    # Above the shipped low-speed floor: only the overall
                    # request deadline should end this incomplete response.
                    while not state.release_stall.is_set():
                        self.wfile.write(b" " * 4096)
                        self.wfile.flush()
                        state.stalled.set()
                        state.release_stall.wait(timeout=0.25)
                elif path == "/" + MODEL_NAME and state.pause_model:
                    self.wfile.write(data[: len(data) // 2])
                    self.wfile.flush()
                    state.model_started.set()
                    if state.release_model.wait(timeout=10):
                        self.wfile.write(data[len(data) // 2 :])
                else:
                    self.wfile.write(data[: len(data) // 2] if truncate else data)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                # The interruption test deliberately closes the real client.
                pass
            self.close_connection = True

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    # Join every request handler after releasing its real stall barrier.
    server.daemon_threads = False
    state.base = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        state.release_model.set()
        state.release_stall.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def model_command(
    tmp_path,
    server,
    *,
    skip_checksum=False,
    discover=True,
    stage_as_directory=None,
    managed=False,
):
    source = (ROOT / "scripts/quickstart.sh").read_text()
    start = source.index('MODELS_DIR="${PWD}/models"\n')
    end = source.index(
        "\n# ── Backend network subnet"
        if discover
        else "# Keep the helper definitions above available in every mode.",
        start,
    )
    # Run the complete production model-selection block, including discovery
    # on the next invocation and permissions, under the production shell flags.
    harness = """set -euo pipefail
QUICKSTART_MODE=hardware
trap 'printf preserved > "${TEST_OUTER_EXIT}"' EXIT
curl() {
    local arg
    local args=()
    for arg in "$@"; do
        case "$arg" in
            https://api.github.com/repos/SigRift/SigRift/releases/tags/*)
                args+=("${TEST_RELEASE_URL}") ;;
            *) args+=("$arg") ;;
        esac
    done
    python3 -c 'import json,sys; open(sys.argv[1], "a").write(json.dumps(sys.argv[2:])+"\\n")' "${TEST_CURL_CALLS}" "${args[@]}"
    local status=0 previous=""
    "${TEST_REAL_CURL}" -q --noproxy '*' "${args[@]}" || status=$?
    # A test may turn one completed staged file into a directory, so that
    # only hashing or publishing that file fails.
    if [ "$status" -eq 0 ] && [ -n "${TEST_STAGE_AS_DIRECTORY:-}" ]; then
        for arg in "${args[@]}"; do
            if [ "$previous" = "-o" ] && [ "${arg##*/}" = "${TEST_STAGE_AS_DIRECTORY}" ]; then
                rm -f -- "$arg"
                mkdir -- "$arg"
            fi
            previous="$arg"
        done
    fi
    return "$status"
}
""" + source[start:end]
    if managed:
        # Managed scanner setup, with an SDR selected: quickstart sets both
        # before this block. The default here is an unmanaged legacy install.
        harness = harness.replace(
            "QUICKSTART_MODE=hardware\n",
            "QUICKSTART_MODE=hardware\nSCANNER_MANAGED=1\nSCANNER_RF=1\n",
            1,
        )
    if not discover:
        # The caller now prepares models/ only in hardware mode. Direct helper
        # tests supply that same directory prerequisite without slicing into
        # the mode branch or running discovery first.
        harness += '\nmkdir -p "$MODELS_DIR"\nchmod 0755 "$MODELS_DIR"\n'
        harness += "try_download_latest_release_model\n"
    env = dict(os.environ)
    env.pop("SIGRIFT_SKIP_CHECKSUM", None)
    env.pop("SIGRIFT_MODELS_TAG", None)
    env.pop("TEST_STAGE_AS_DIRECTORY", None)
    if stage_as_directory:
        env["TEST_STAGE_AS_DIRECTORY"] = stage_as_directory
    env.update(
        TEST_RELEASE_URL=server.base + "/release",
        TEST_REAL_CURL=CURL,
        TEST_CURL_CALLS=str(tmp_path / "curl-calls.jsonl"),
        TEST_OUTER_EXIT=str(tmp_path / "outer-exit"),
    )
    if skip_checksum:
        env["SIGRIFT_SKIP_CHECKSUM"] = "1"
    return [BASH, "-c", harness], env


def run_model_block(tmp_path, server, **options):
    command, env = model_command(tmp_path, server, **options)
    return subprocess.run(
        command,
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )


@pytest.mark.parametrize("skip_checksum", [False, True])
def test_truncated_transfer_never_becomes_a_discoverable_model(
    tmp_path, release_server, skip_checksum
):
    release_server.truncate_model = 1
    result = run_model_block(tmp_path, release_server, skip_checksum=skip_checksum)
    assert result.returncode == 1  # A selected SDR cannot start without its model.
    assert "selected SDR requires a model; no scanner was started" in result.stderr
    assert "Download failed" in result.stdout
    assert not list((tmp_path / "models").glob("*.onnx"))
    assert not list((tmp_path / "models").glob(".model-download.*"))
    assert release_server.requests["/" + MODEL_NAME] == 1


def test_second_invocation_retries_transfer_then_links_verified_complete_bytes(
    tmp_path, release_server
):
    release_server.truncate_model = 1
    first = run_model_block(tmp_path, release_server)
    second = run_model_block(tmp_path, release_server)
    assert first.returncode == 1
    assert "selected SDR requires a model; no scanner was started" in first.stderr
    assert second.returncode == 0
    assert release_server.requests["/release"] == 2
    assert release_server.requests["/" + MODEL_NAME] == 2
    assert release_server.requests["/SHA256SUMS"] == 1
    model = tmp_path / "models" / MODEL_NAME
    assert model.read_bytes() == MODEL
    assert (model.parent / "open-default.onnx").readlink() == Path(MODEL_NAME)
    assert (model.parent / "open-default_metadata.json").read_bytes() == METADATA
    assert "OK (sha256 verified)" in second.stdout
    assert not list(model.parent.glob(".model-download.*"))


@pytest.mark.parametrize("failure", ["truncate_sums", "mismatch"])
def test_unverifiable_model_is_not_published_and_can_be_retried(
    tmp_path, release_server, failure
):
    setattr(release_server, failure, 1)
    first = run_model_block(tmp_path, release_server)
    assert first.returncode == 1
    assert "selected SDR requires a model; no scanner was started" in first.stderr
    assert not list((tmp_path / "models").glob("*.onnx"))
    assert not list((tmp_path / "models").glob(".model-download.*"))
    release_server.mismatch = False
    second = run_model_block(tmp_path, release_server)
    assert second.returncode == 0
    assert (tmp_path / "models" / "open-default.onnx").read_bytes() == MODEL
    assert release_server.requests["/" + MODEL_NAME] == 2


def test_truncated_sidecar_blocks_activation_and_leaves_no_partial_files(
    tmp_path, release_server
):
    release_server.truncate_metadata = 1
    result = run_model_block(tmp_path, release_server)
    assert result.returncode == 1
    assert "Metadata download failed" in result.stderr
    assert "was not activated. Re-run to retry." in result.stderr
    models = tmp_path / "models"
    assert not list(models.glob("*.onnx"))
    assert not (models / META_NAME).exists()
    assert not (models / "open-default_metadata.json").is_symlink()
    assert not (models / "SHA256SUMS").exists()
    assert not list(models.glob(".model-download.*"))


@pytest.mark.parametrize("policy", ["no-checksum-asset", "explicit-opt-out"])
def test_existing_checksum_opt_out_policies_are_preserved(
    tmp_path, release_server, policy
):
    if policy == "no-checksum-asset":
        release_server.checksum = False
    else:
        release_server.mismatch = True
    result = run_model_block(
        tmp_path, release_server, skip_checksum=policy == "explicit-opt-out"
    )
    assert result.returncode == 0
    assert (tmp_path / "models" / "open-default.onnx").read_bytes() == MODEL
    assert release_server.requests["/SHA256SUMS"] == 0
    assert "sha256 verified" not in result.stdout
    assert (
        "integrity unverified" if policy == "no-checksum-asset" else "skipping checksum"
    ) in result.stdout


@pytest.mark.parametrize("failure", ["truncate_model", "truncate_sums", "mismatch"])
def test_failed_direct_download_preserves_existing_artifacts(
    tmp_path, release_server, failure
):
    models = tmp_path / "models"
    models.mkdir()
    previous = {
        MODEL_NAME: b"previous complete operator-supplied model",
        META_NAME: b'{"classes": ["previous"]}\n',
        "SHA256SUMS": b"previous verification receipt\n",
    }
    for name, data in previous.items():
        (models / name).write_bytes(data)
    (models / "open-default.onnx").symlink_to(MODEL_NAME)
    setattr(release_server, failure, 1)
    result = run_model_block(tmp_path, release_server, discover=False)
    assert result.returncode == 1
    assert {name: (models / name).read_bytes() for name in previous} == previous
    assert (models / "open-default.onnx").readlink() == Path(MODEL_NAME)
    assert (tmp_path / "outer-exit").read_text() == "preserved"
    assert not list(models.glob(".model-download.*"))


def test_failed_sidecar_transfer_keeps_existing_complete_metadata(
    tmp_path, release_server
):
    models = tmp_path / "models"
    models.mkdir()
    previous_metadata = b'{"classes": ["previous complete sidecar"]}\n'
    (models / META_NAME).write_bytes(previous_metadata)
    release_server.truncate_metadata = 1
    result = run_model_block(tmp_path, release_server)
    assert result.returncode == 0
    assert (models / "open-default.onnx").read_bytes() == MODEL
    assert (models / "open-default_metadata.json").read_bytes() == previous_metadata
    assert not list(models.glob(".model-download.*"))


def test_model_publication_refuses_existing_directory_and_preserves_other_files(
    tmp_path, release_server
):
    models = tmp_path / "models"
    (models / MODEL_NAME).mkdir(parents=True)
    (models / META_NAME).write_bytes(METADATA)
    (models / "SHA256SUMS").write_bytes(b"previous receipt")
    result = run_model_block(tmp_path, release_server, discover=False)
    assert result.returncode == 1
    assert "Could not publish completed model" in result.stderr
    assert list((models / MODEL_NAME).iterdir()) == []
    assert (models / META_NAME).read_bytes() == METADATA
    assert (models / "SHA256SUMS").read_bytes() == b"previous receipt"
    assert not (models / "open-default.onnx").is_symlink()
    assert not list(models.glob(".model-download.*"))


def test_optional_receipt_publication_failure_keeps_verified_model_and_destination(
    tmp_path, release_server
):
    models = tmp_path / "models"
    destination = models / "SHA256SUMS"
    destination.mkdir(parents=True)
    (destination / "operator-owned").write_bytes(b"preserved")
    result = run_model_block(tmp_path, release_server)
    assert result.returncode == 0
    assert (models / "open-default.onnx").read_bytes() == MODEL
    assert "OK (sha256 verified)" in result.stdout
    assert (destination / "operator-owned").read_bytes() == b"preserved"
    assert len(list(destination.iterdir())) == 1
    assert not list(models.glob(".model-download.*"))
    assert "could not save its SHA256SUMS receipt" in result.stderr


def test_interrupted_transfer_cleans_staging_and_next_run_downloads_again(
    tmp_path, release_server
):
    release_server.pause_model = True
    command, env = model_command(tmp_path, release_server)
    child = subprocess.Popen(
        command,
        cwd=tmp_path,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        assert release_server.model_started.wait(timeout=5)
        models = tmp_path / "models"
        assert not list(models.glob("*.onnx"))
        staged = list(models.glob(".model-download.*"))
        assert len(staged) == 1
        assert staged[0].stat().st_mode & 0o777 == 0o700
        os.killpg(child.pid, signal.SIGTERM)
        child.communicate(timeout=5)
        assert child.returncode != 0
        # The function runs in a subshell, whose cleanup can finish just after
        # the parent has been reaped. Its pipes close only once that work exits.
        assert not list(models.glob(".model-download.*"))
        assert not list(models.glob("*.onnx"))
    finally:
        release_server.release_model.set()
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.communicate(timeout=5)
    release_server.pause_model = False
    result = run_model_block(tmp_path, release_server)
    assert result.returncode == 0
    assert (models / "open-default.onnx").read_bytes() == MODEL
    assert release_server.requests["/" + MODEL_NAME] == 2
    assert (tmp_path / "outer-exit").read_text() == "preserved"
