"""Real urllib diagnostics must carry decisions, never HTTP content/secrets."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import runpy
import ssl
import subprocess
import sys
from threading import Thread
from types import SimpleNamespace
import urllib.error

import pytest
import yaml

from tests.e2e import conftest as e2e
from tests.e2e import diagnostics as diag


SECRET = "secret-password-token-cookie-header-body-query"


@contextmanager
def server(code=200, raw=b"{}", reply=None):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def reply(self):
            calls.append((self.command, self.path))
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            response_code, response_raw = (
                reply(self.command, self.path) if reply else (code, raw)
            )
            self.send_response(response_code)
            self.send_header("X-Secret", SECRET)
            self.end_headers()
            self.wfile.write(response_raw)

        do_GET = do_POST = do_DELETE = reply

    http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=http.serve_forever, daemon=True)
    worker.start()
    try:
        settings = e2e.Settings(
            f"http://127.0.0.1:{http.server_port}",
            SECRET,
            SECRET,
            ssl.create_default_context(),
        )
        yield e2e.Client(settings), calls
    finally:
        http.shutdown()
        http.server_close()
        worker.join(5)
        assert not worker.is_alive()


@pytest.mark.parametrize(
    "code,raw,category",
    [
        (200, b'{"secret":"' + SECRET.encode() + b'"}', "ok"),
        (403, SECRET.encode(), "unexpected_status"),
        (200, SECRET.encode(), "invalid_json"),
    ],
)
def test_real_client_records_safe_decision_before_failure(
    tmp_path, monkeypatch, code, raw, category
):
    output = tmp_path / "events.jsonl"
    monkeypatch.setenv("SIGRIFT_E2E_DIAGNOSTICS", str(output))
    with server(code, raw) as (client, calls):
        try:
            client.request(
                "DELETE",
                f"/api/admin/keys/{SECRET}?key={SECRET}",
                {"password": SECRET},
                key=SECRET,
            )
        except (AssertionError, json.JSONDecodeError):
            assert category != "ok"
        assert len(calls) == 1
    assert output.exists(), "No safe operation diagnostics were recorded"
    text = output.read_text()
    assert SECRET not in text
    events = [json.loads(line) for line in text.splitlines()]
    assert events[-1] == {
        "method": "DELETE",
        "route": "/api/admin/keys/{key_id}",
        "status": code,
        "expected": [200],
        "stage": "request",
        "category": category,
    }


@pytest.fixture
def sink(tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    monkeypatch.setenv("SIGRIFT_E2E_DIAGNOSTICS", str(path))
    yield path
    diag.finish()


def events(path):
    text = path.read_text()
    assert SECRET not in text
    return [json.loads(line) for line in text.splitlines()]


@pytest.mark.parametrize("failure", ["transport", "request_contract"])
def test_client_failure_categories_preserve_original_exception(
    sink, monkeypatch, failure
):
    client = e2e.Client(
        e2e.Settings(
            "https://invalid.test", SECRET, SECRET, ssl.create_default_context()
        )
    )

    def fail(*_args, **_kwargs):
        raise urllib.error.URLError(SECRET)

    monkeypatch.setattr(client.opener, "open", fail)
    with pytest.raises(urllib.error.URLError if failure == "transport" else TypeError):
        client.request(
            "POST",
            "/api/auth/login",
            object() if failure == "request_contract" else {"secret": SECRET},
        )
    assert events(sink)[-1]["category"] == failure
    assert events(sink)[-1]["status"] is None


@pytest.mark.parametrize(
    "phase",
    [
        None,
        "scanner_register",
        "scanner_key",
        "scanner_key_contract",
        "scanner_key_missing_credential",
        "scanner_detection",
        "scanner_wifi",
    ],
)
def test_real_scanner_fixture_phases_are_private_and_cleanup_is_preserved(sink, phase):
    state = {"revoked": False}

    def reply(method, path):
        if method == "DELETE":
            state["revoked"] = True
            return 200, b"{}"
        if path == "/api/nodes/register":
            return (
                (429, SECRET.encode()) if phase == "scanner_register" else (200, b"{}")
            )
        if path == "/api/admin/keys":
            if phase == "scanner_key":
                return 429, SECRET.encode()
            if phase == "scanner_key_missing_credential":
                return 201, b'{"key_id":"owned_key"}'
            return 201, json.dumps(
                {"bad": SECRET}
                if phase == "scanner_key_contract"
                else {"key_id": "owned_key", "raw_key": SECRET}
            ).encode()
        if path == "/api/detections/batch":
            if state["revoked"]:
                return 401, b"{}"
            return 200, json.dumps(
                {
                    "inserted": SECRET if phase == "scanner_detection" else 1,
                    "rejected": 0,
                }
            ).encode()
        if path.startswith("/api/nodes/") and path.endswith("/scanner-status"):
            assert state["revoked"]
            return 401, b"{}"
        assert path == "/api/wifi/ingest"
        return 201, json.dumps(
            [] if phase == "scanner_wifi" else {"inserted": 1}
        ).encode()

    with server(reply=reply) as (admin, calls):
        fixture = e2e.synthetic_scanner.__wrapped__(None, admin, admin.settings)
        if phase:
            with pytest.raises((AssertionError, TypeError, KeyError)):
                next(fixture)
        else:
            scanner = next(fixture)
            assert set(scanner) == {
                "node_id",
                "detection_id",
                "ssid",
                "report",
                "observe_rf",
                "upload_iq",
            }
            assert callable(scanner["observe_rf"])
            assert callable(scanner["upload_iq"])
            fixture.close()
        assert len([c for c in calls if c == ("POST", "/api/admin/keys")]) == (
            0 if phase == "scanner_register" else 1
        )
        assert state["revoked"] is (
            phase
            in {
                None,
                "scanner_detection",
                "scanner_wifi",
                "scanner_key_missing_credential",
            }
        )
    records = events(sink)
    if phase:
        wanted = (
            "scanner_key"
            if phase in {"scanner_key_contract", "scanner_key_missing_credential"}
            else phase
        )
        assert any(
            row["stage"] == wanted
            and row["category"] in {"unexpected_status", "fixture_contract"}
            for row in records
        )
    else:
        assert [row["stage"] for row in records if row["category"] == "ok"] == [
            "scanner_register",
            "scanner_key",
            "scanner_detection",
            "scanner_wifi",
            "scanner_cleanup",
            "scanner_revocation",
            "scanner_revocation",
        ]


def test_fixture_unexpected_setup_error_keeps_original_and_fixed_category(sink):
    with pytest.raises(RuntimeError, match=SECRET):
        with diag.fixture_stage("scanner_client"):
            raise RuntimeError(SECRET)
    assert events(sink)[-1]["category"] == "fixture_error"


def test_sink_failure_never_masks_real_http_failure(tmp_path, monkeypatch, capsys):
    path = tmp_path / SECRET / "missing-parent" / "events.jsonl"
    monkeypatch.setenv("SIGRIFT_E2E_DIAGNOSTICS", str(path))
    with server(403, SECRET.encode()) as (client, _calls):
        with pytest.raises(AssertionError, match="HTTP 403"):
            client.request("POST", "/api/admin/keys")
    assert diag.finish() is False
    assert diag.summarize(path) == 1
    assert SECRET not in capsys.readouterr().out


@pytest.mark.parametrize("symlink", [False, True])
def test_recorder_never_overwrites_existing_file_or_symlink(tmp_path, symlink):
    original = tmp_path / "original"
    original.write_text(SECRET)
    path = tmp_path / "events.jsonl"
    if symlink:
        path.symlink_to(original)
    else:
        path.write_text(SECRET)
    recorder = diag.Recorder(str(path))
    assert recorder.failed
    assert path.read_text() == SECRET and original.read_text() == SECRET


def test_fresh_log_is_private_and_summary_is_sealed(sink, capsys):
    diag.record("GET", "/api/auth/me", status=200, expected=[200], category="ok")
    assert sink.stat().st_mode & 0o777 == 0o600
    assert diag.summarize(sink) == 1  # Process has not sealed the log yet.
    assert diag.finish()
    assert diag.summarize(sink) == 0
    assert SECRET not in capsys.readouterr().out


@pytest.mark.parametrize(
    "field,value",
    [
        ("method", SECRET),
        ("method", 42),
        ("route", "/api/admin/keys/" + SECRET),
        ("stage", SECRET),
        ("category", SECRET),
        ("status", SECRET),
        ("status", True),
        ("status", 999),
        ("expected", [True]),
        ("expected", [SECRET]),
        ("extra", SECRET),
    ],
)
def test_summary_validates_all_fields_before_emitting_any_input(
    tmp_path, capsys, field, value
):
    row = diag.event("GET", "/api/auth/me", status=200, expected=[200], category="ok")
    row[field] = value
    path = tmp_path / "events.jsonl"
    path.write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                diag.event(stage="session", category="begin"),
                diag.event(category="ok"),
                row,
                diag.event(stage="session", category="complete"),
            ]
        )
    )
    assert diag.summarize(path) == 1
    output = capsys.readouterr().out
    assert SECRET not in output and '"category": "ok"' not in output


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not json",
        b"\xff",
        b"[]\n",
        b"x" * (1024 * 1024 + 1),
        b"[" * 10000 + b"]" * 10000,
    ],
)
def test_invalid_summary_input_has_only_fixed_error(tmp_path, capsys, raw):
    path = tmp_path / "events.jsonl"
    path.write_bytes(raw)
    assert diag.summarize(path) == 1
    assert (
        capsys.readouterr().out
        == "E2E diagnostics unavailable, incomplete, or invalid; raw output remains private.\n"
    )


def test_unknown_producer_values_never_escape_allowlist():
    result = diag.event(
        SECRET,
        "/" + SECRET,
        status=SECRET,
        expected=[SECRET],
        stage=[SECRET],
        category={SECRET: SECRET},
    )
    assert result == {
        "method": "OTHER",
        "route": "unknown",
        "status": None,
        "expected": [],
        "stage": "unknown",
        "category": "internal",
    }
    assert diag.route_template("x" * 2049) == "unknown"
    assert diag.route_template(None) == "unknown"


def test_session_hook_preserves_failure_and_rejects_incomplete_success(
    tmp_path, monkeypatch
):
    monkeypatch.setenv(
        "SIGRIFT_E2E_DIAGNOSTICS", str(tmp_path / "absent" / "events.jsonl")
    )
    failed = SimpleNamespace(exitstatus=2)
    e2e.pytest_sessionfinish(failed, 2)
    assert failed.exitstatus == 2
    success = SimpleNamespace(exitstatus=0)
    e2e.pytest_sessionfinish(success, 0)
    assert success.exitstatus == 1


def test_actual_workflow_uses_unique_private_paths_and_always_safe_summary(tmp_path):
    root = Path(__file__).resolve().parents[2]
    workflow = yaml.safe_load(
        (root / ".github/workflows/quickstart-smoke.yml").read_text()
    )
    steps = next(
        job["steps"]
        for job in workflow["jobs"].values()
        if any(
            step.get("name") == "Prepare private browser diagnostics"
            for step in job.get("steps", [])
        )
    )
    prepare = next(
        step
        for step in steps
        if step.get("name") == "Prepare private browser diagnostics"
    )
    summary = next(
        step
        for step in steps
        if step.get("name") == "Diagnostics — safe browser operations"
    )
    assert summary["if"] == "always()"
    envfile = tmp_path / "github-env"
    env = dict(os.environ, RUNNER_TEMP=str(tmp_path), GITHUB_ENV=str(envfile))
    paths = []
    for _ in range(2):
        subprocess.run(
            ["bash", "-eo", "pipefail", "-c", prepare["run"]],
            cwd=root,
            env=env,
            check=True,
            capture_output=True,
        )
        paths.append(envfile.read_text().splitlines()[-1].split("=", 1)[1])
    assert paths[0] != paths[1]
    assert all(Path(path).parent.stat().st_mode & 0o777 == 0o700 for path in paths)
    recorder = diag.Recorder(paths[1])
    recorder.write(
        diag.event(
            "DELETE",
            f"/api/admin/keys/{SECRET}?token={SECRET}",
            status=403,
            expected=[200],
            stage="scanner_cleanup",
            category="unexpected_status",
        )
    )
    recorder.write(diag.event(stage="session", category="complete"))
    recorder.close()
    env["SIGRIFT_E2E_DIAGNOSTICS"] = paths[1]
    result = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", summary["run"]],
        cwd=root,
        env=env,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0 and '"status": 403' in result.stdout
    assert SECRET not in result.stdout + result.stderr
    Path(paths[1]).write_text(SECRET)
    result = subprocess.run(
        [sys.executable, "tests/e2e/diagnostics.py", paths[1]],
        cwd=root,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 1 and SECRET not in result.stdout + result.stderr


def test_recorder_limit_and_write_close_failures_are_visible(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(diag, "MAX_EVENTS", 2)
    limited = diag.Recorder(str(tmp_path / "limited"))
    limited.write(diag.event(category="ok"))
    limited.write(diag.event(category="ok"))
    assert limited.failed
    limited.close()
    assert diag.summarize(tmp_path / "limited") == 1
    broken = diag.Recorder(str(tmp_path / "broken"))
    os.close(broken.stream.fileno())  # Actual descriptor failure, not fake error text.
    broken.write(diag.event(category="ok"))
    broken.close()
    assert broken.failed
    assert SECRET not in capsys.readouterr().out


def test_disabled_recorder_and_cli_entrypoint(tmp_path, monkeypatch, capsys):
    diag.finish()
    monkeypatch.delenv("SIGRIFT_E2E_DIAGNOSTICS", raising=False)
    assert diag.finish()
    path = tmp_path / "sealed"
    recorder = diag.Recorder(str(path))
    recorder.write(diag.event(stage="session", category="complete"))
    recorder.close()
    monkeypatch.setattr(sys, "argv", [str(Path(diag.__file__)), str(path)])
    with pytest.raises(SystemExit) as result:
        runpy.run_path(diag.__file__, run_name="__main__")
    assert result.value.code == 0
    assert SECRET not in capsys.readouterr().out


@pytest.mark.parametrize("phase", ["setup", "call", "teardown"])
def test_actual_pytest_hook_records_only_failure_phase(tmp_path, phase):
    package = tmp_path / "probe"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "conftest.py").write_text(Path(e2e.__file__).read_text())
    (package / "diagnostics.py").write_text(Path(diag.__file__).read_text())
    fail = f"    raise RuntimeError({SECRET!r})\n"
    fixture = "@pytest.fixture(autouse=True)\ndef no_uncaught_browser_errors():\n"
    fixture += (
        fail
        if phase == "setup"
        else "    yield\n" + (fail if phase == "teardown" else "")
    )
    body = (
        "import pytest\n"
        + fixture
        + "def test_probe():\n"
        + (fail if phase == "call" else "    pass\n")
    )
    (package / "test_probe.py").write_text(body)
    log = tmp_path / "events.jsonl"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(package),
            "--confcutdir",
            str(package),
            "-c",
            os.devnull,
            "-q",
        ],
        env={
            "PATH": os.environ["PATH"],
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "SIGRIFT_E2E_DIAGNOSTICS": str(log),
        },
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    rows = events(log)
    diag.validate(rows)
    assert any(
        row["stage"] == "test_" + phase and row["category"] == "test_failure"
        for row in rows
    )


def test_scanner_status_path_hides_node_identity(sink, capsys):
    diag.record(
        "POST",
        "/api/nodes/" + SECRET + "/scanner-status",
        status=200,
        expected=[200],
        stage="scanner_status",
        category="ok",
    )
    assert diag.finish()
    assert diag.summarize(sink) == 0
    content = sink.read_text() + capsys.readouterr().out
    assert SECRET not in content
    assert "/api/nodes/{node_id}/scanner-status" in content
