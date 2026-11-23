"""Software process recovery with real pipes/signals; never operate a radio."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

import pytest


# These tests drive real worker and stand-in processes. The project default of
# 30 s per test (pyproject.toml) is too short for them on a loaded CI runner.
pytestmark = pytest.mark.timeout(180)

ROOT = Path(__file__).resolve().parents[2]
# Capture rounds in which the tcpdump stand-in sends one complete frame.
FRAME_ROUNDS = 2
# Limits for a state the worker must REACH or for its exit. Generous on purpose:
# on a loaded CI runner the worker and every stand-in command are separate
# Python processes that can each take seconds to start. The polls return as
# soon as the state is reached; a worker that hangs is still caught.
READY = 60.0
STOP = 30.0
# Waits for a helper process or thread to end; return as soon as it has.
REAP = 30.0
# Runs the worker against a fake sysfs with short lifecycle waits. The wait for
# the error-output reader is lengthened: these tests assert the child's last
# line, and a loaded runner can outlast the product's 1 s (the wait returns as
# soon as the reader has finished).
LAUNCH = (
    "import os, sys; from pathlib import Path; import sigrift.edge.wifi_scan as w; "
    "w.NET_SYSFS = Path(sys.argv[1]); w.RETRY_INTERVAL = w.WATCH_INTERVAL = 0.1; "
    "w.WifiScanner.STDERR_JOIN_TIMEOUT = 30.0; "
    "grace = os.environ.get('RECOVERY_EXIT_GRACE'); "
    "w.WifiScanner.EXIT_GRACE = float(grace) if grace else w.WifiScanner.EXIT_GRACE; "
    "sys.exit(w.main())"
)


@contextmanager
def bridge_endpoint():
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(
                (
                    self.path,
                    json.loads(self.rfile.read(int(self.headers["Content-Length"]))),
                )
            )
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", received
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=REAP)
        assert not thread.is_alive()


def command_standins(tmp_path):
    """Real executable boundaries record intent instead of touching interfaces."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    commands = tmp_path / "commands.jsonl"
    capture_pid = tmp_path / "capture-pid"
    script = (
        f"#!{sys.executable}\n"
        + r"""
import json,os,signal,struct,sys,time
from pathlib import Path
name=Path(sys.argv[0]).name
fd=os.open(os.environ['RECOVERY_COMMANDS'],os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
try: os.write(fd,(json.dumps([name,*sys.argv[1:]])+'\n').encode())
finally: os.close(fd)
if name=='tcpdump':
    header=struct.pack('<IHHIIII',0xA1B2C3D4,2,4,0,0,512,127)
    frame=bytes.fromhex('000008000000000080000000ffffffffffff02aabbccddee02aabbccddee1000'
                        '080706050403020164000100000c746573742d6e6574776f726b030106')
    packet=struct.pack('<IIII',1700000000,123456,len(frame),len(frame))
    phase=os.environ.get('RECOVERY_PHASE','quiet')
    with open(os.environ['RECOVERY_COMMANDS']) as recorded:
        started=sum(json.loads(line)[0]=='tcpdump' for line in recorded)
    # Only the first rounds send a frame; later ones stay live and quiet, so
    # the number of frames sent is exact when the worker is stopped.
    if phase in ('complete','late-exit') and started>int(os.environ['RECOVERY_FRAME_ROUNDS']): phase='quiet'
    if phase=='ignore-term': signal.signal(signal.SIGTERM,signal.SIG_IGN)
    if phase=='global-header': stream=header[:7]
    elif phase=='packet-header': stream=header+packet[:7]
    elif phase=='payload': stream=header+packet+frame[:7]
    elif phase=='complete': stream=header+packet+frame
    else: stream=header
    for byte in stream:
        sys.stdout.buffer.write(bytes((byte,)));sys.stdout.buffer.flush()
        if phase=='complete': time.sleep(.002)
    # Atomic: a stand-in stopped mid-write must not leave an empty pid file.
    pid_file=Path(os.environ['RECOVERY_CAPTURE_PID'])
    pid_file.with_name(f'{pid_file.name}.{os.getpid()}').write_text(str(os.getpid()))
    os.replace(f'{pid_file}.{os.getpid()}',pid_file)
    if phase=='complete': sys.stderr.write('tcpdump: synthetic end\n'); sys.exit(0)
    if phase=='late-exit':
        # Ends its output first and exits a moment later: the worker sees the
        # closed stream before the exit can be collected.
        sys.stderr.write('tcpdump: synthetic end\n'); sys.stderr.flush()
        os.close(1); time.sleep(.4); os._exit(0)
    while True: time.sleep(1)
if name=='iw' and sys.argv[3:5]==['set','type']:
    # Same effect on the fake sysfs as on a real radio.
    kind=Path(os.environ['RECOVERY_SYSFS'])/sys.argv[2]/'type'
    kind.write_text('803\n' if sys.argv[5]=='monitor' else '1\n')
if name=='ip' and sys.argv[-1]=='down' and os.environ.get('RECOVERY_PHASE')=='startup':
    Path(os.environ['RECOVERY_STARTUP_READY']).touch()
    # Released once the worker logged the signal (up to STOP s); never hangs.
    deadline=time.monotonic()+120
    while not Path(os.environ['RECOVERY_STARTUP_RELEASE']).exists():
        if time.monotonic()>deadline: sys.exit(2)
        time.sleep(.01)
"""
    )
    for name in ("ip", "iw", "tcpdump"):
        path = bindir / name
        path.write_text(script)
        path.chmod(0o700)
    return bindir, commands, capture_pid


def fake_sysfs(tmp_path):
    netdir = tmp_path / "sys/class/net"
    radio = netdir / "owned-fixture0"
    radio.mkdir(parents=True)
    (radio / "ifindex").write_text("7\n")
    (radio / "type").write_text("1\n")
    return netdir


def clean_environment(tmp_path, bindir, commands, capture_pid, url):
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("MLRF_", "BRIDGE_", "SIGRIFT_", "PYTHON"))
        and key.upper()
        not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "SSLKEYLOGFILE"}
    }
    env.update(
        {
            "HOME": str(tmp_path),
            "PATH": str(bindir) + os.pathsep + env["PATH"],
            "PYTHONPATH": str(ROOT / "src"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "MLRF_BRIDGE_URL": url,
            "MLRF_BRIDGE_KEY": "software-fixture-key",
            "MLRF_NODE_ID": "software-recovery-node",
            "MLRF_WIFI_IFACE": "owned-fixture0",
            "MLRF_WIFI_BANDS": "2.4",
            "MLRF_CHANNEL_DWELL": "0.05",
            "MLRF_FLUSH_INTERVAL": "0.05",
            "MLRF_SUMMARIZE": "false",
            "RECOVERY_COMMANDS": str(commands),
            "RECOVERY_CAPTURE_PID": str(capture_pid),
            "RECOVERY_SYSFS": str(tmp_path / "sys/class/net"),
            "RECOVERY_FRAME_ROUNDS": str(FRAME_ROUNDS),
        }
    )
    return env


@pytest.mark.parametrize("sent", [signal.SIGTERM, signal.SIGINT])
@pytest.mark.parametrize(
    "phase", ["quiet", "global-header", "packet-header", "payload", "startup"]
)
def test_quiet_capture_signal_finishes_restoration_and_stopped_lease(
    tmp_path, sent, phase
):
    run_capture(tmp_path, phase, sent)


def test_unresponsive_capture_child_is_killed_and_reaped(tmp_path):
    run_capture(tmp_path, "ignore-term", signal.SIGTERM)


def test_fragmented_packet_is_uploaded_once_per_round_and_eof_restarts_capture(
    tmp_path,
):
    # Contract change: EOF from tcpdump no longer ends the worker with a final
    # "error"; it logs why, cleans up and starts a new capture round. Stopped
    # once a quiet round follows the rounds that each sent the frame once.
    # The stand-in closes its output as it exits; on a loaded runner the exit
    # can be collected later than the product's 1 s EXIT_GRACE, so that wait
    # is lengthened here (it ends as soon as the exit is collected).
    log = run_capture(
        tmp_path,
        "complete",
        signal.SIGTERM,
        rounds=FRAME_ROUNDS + 1,
        exit_grace=20,
    )
    assert (
        "tcpdump on owned-fixture0 exited unexpectedly (code 0): tcpdump: synthetic end"
        in log
    )


def test_child_that_ends_its_output_before_it_exits_is_still_reported(tmp_path):
    # On a slow machine the closed stream is seen before the exit can be
    # collected. That round's end must still be logged with the exit code and
    # the child's last error line, not stopped silently. The wait for the exit
    # is lengthened here so that a loaded runner cannot outlast it: the
    # stand-in exits 0.4 s after it closes its output.
    log = run_capture(tmp_path, "late-exit", signal.SIGTERM, rounds=2, exit_grace=20)
    assert (
        "tcpdump on owned-fixture0 exited unexpectedly (code 0): tcpdump: synthetic end"
        in log
    )


def test_error_output_written_just_before_the_stop_is_kept():
    # The reader thread may be told to stop before it has read the child's
    # last line; what is already in the pipe must still reach the exit log.
    import sigrift.edge.wifi_scan as wifi

    scanner = wifi.WifiScanner("unused-test-interface")
    read_end, write_end = os.pipe()
    try:
        os.write(write_end, b"tcpdump: last words\n")
        stop = threading.Event()
        stop.set()
        scanner._drain_stderr(os.fdopen(read_end, "rb", buffering=0), stop)
    finally:
        os.close(write_end)
    assert list(scanner._stderr_tail) == ["tcpdump: last words"]


def run_capture(tmp_path, phase, sent, rounds=1, exit_grace=None):
    bindir, commands, capture_pid = command_standins(tmp_path)
    netdir = fake_sysfs(tmp_path)
    startup_ready = tmp_path / "startup-ready"
    startup_release = tmp_path / "startup-release"
    with bridge_endpoint() as (url, received):
        env = clean_environment(tmp_path, bindir, commands, capture_pid, url)
        if exit_grace is not None:
            env["RECOVERY_EXIT_GRACE"] = str(exit_grace)
        env.update(
            RECOVERY_PHASE=phase,
            RECOVERY_STARTUP_READY=str(startup_ready),
            RECOVERY_STARTUP_RELEASE=str(startup_release),
        )
        with (tmp_path / "worker.log").open("w") as log:
            worker = subprocess.Popen(
                [sys.executable, "-c", LAUNCH, str(netdir)],
                cwd=tmp_path,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                deadline = time.monotonic() + READY
                reached = False
                while time.monotonic() < deadline and worker.poll() is None:
                    calls = (
                        [json.loads(line) for line in commands.read_text().splitlines()]
                        if commands.exists()
                        else []
                    )
                    if phase == "startup" and startup_ready.exists():
                        reached = True
                        break
                    if (
                        capture_pid.exists()
                        and any(
                            call[:5]
                            == ["iw", "dev", "owned-fixture0", "set", "channel"]
                            for call in calls
                        )
                        and [call[0] for call in calls].count("tcpdump") >= rounds
                    ):
                        reached = True
                        break
                    time.sleep(0.01)
                if sent is not None:
                    assert worker.poll() is None, (tmp_path / "worker.log").read_text()
                    # Signalling earlier would test a different moment.
                    assert reached, (
                        "worker did not reach the expected capture state:\n"
                        + (tmp_path / "worker.log").read_text()
                    )
                    assert (
                        startup_ready.exists()
                        if phase == "startup"
                        else capture_pid.exists()
                    )
                    worker.send_signal(sent)
                if phase == "startup":
                    # Establish that cancellation occurred before start() resumes;
                    # otherwise scheduler timing could conceal lost cancellation.
                    deadline = time.monotonic() + STOP
                    while (
                        "Shutting down (signal"
                        not in (tmp_path / "worker.log").read_text()
                    ):
                        assert time.monotonic() < deadline
                        time.sleep(0.01)
                    startup_release.touch()
                try:
                    result = worker.wait(timeout=STOP)
                except subprocess.TimeoutExpired:
                    pytest.fail(
                        "Quiet capture ignored shutdown while waiting for another frame"
                    )
                assert result == 0, (tmp_path / "worker.log").read_text()
                calls = [json.loads(line) for line in commands.read_text().splitlines()]
                assert [
                    "iw",
                    "dev",
                    "owned-fixture0",
                    "set",
                    "type",
                    "managed",
                ] in calls
                assert calls[-1] == ["ip", "link", "set", "owned-fixture0", "up"]
                statuses = [
                    entry for entry in received if entry[0].endswith("/scanner-status")
                ]
                assert statuses[-1] == (
                    "/api/nodes/software-recovery-node/scanner-status",
                    {"protocol": "wifi", "state": "stopped"},
                )
                if capture_pid.exists():
                    with pytest.raises(ProcessLookupError):
                        os.kill(int(capture_pid.read_text()), 0)
                uploads = [
                    body for path, body in received if path == "/api/wifi/ingest"
                ]
                records = [row for body in uploads for row in body["records"]]
                if phase == "complete":
                    # Exactly once per round that sent the fragmented frame.
                    assert len(records) == FRAME_ROUNDS
                    for record in records:
                        assert record["ssid"] == "test-network"
                        assert record["bssid"] == "02:aa:bb:cc:dd:ee"
                        assert record["channel"] == 6
                else:
                    assert not records
                return (tmp_path / "worker.log").read_text()
            finally:
                try:
                    os.killpg(worker.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                worker.wait(timeout=REAP)
