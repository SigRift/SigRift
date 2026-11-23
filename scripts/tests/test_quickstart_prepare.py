"""quickstart's one host-preparation step: flag, terminal question, no terminal.

The real quickstart function and scanner-plan block run in bash. python3 and
sudo are recording fakes on PATH, so nothing here needs root, prompts for a
password or changes this machine.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import subprocess
import time

import pytest

from test_quickstart_modes import QUICKSTART, clean_env, function

PREPARE = "python3 scripts/scanner_setup.py prepare"
# What the root run gets: exactly the targets prepare --check named.
TARGETED = "--scanners sdr,wifi --usb 1-1.3 --wifi-interface wlan1"
READY_PLAN = {"wifi": {"identity": "b" * 64, "interface": "wlan1", "phy": "phy1"}}

FAKE_PYTHON = r"""#!/bin/sh
# Recording stand-in for: python3 scripts/scanner_setup.py ...
echo "python3 $*" >> "$TEST_LOG"
[ "$1" = scripts/scanner_setup.py ] || exit 97
shift
case "$1" in
    plan)
        if [ -e "$TEST_STATE/prepared" ]; then
            echo "$TEST_PLAN_AFTER"
        elif [ -n "${TEST_PLAN_FAILS:-}" ]; then
            echo "Error: Selected sdr is unavailable or ambiguous." >&2
            exit "${TEST_PLAN_STATUS:-1}"
        else
            echo '{}'
        fi
        ;;
    prepare)
        case "${2:-}" in
            --check)
                if [ -n "${TEST_CHECK_FAILS:-}" ]; then
                    echo "Error: $TEST_CHECK_FAILS" >&2
                    exit 1
                fi
                if [ -e "$TEST_STATE/prepared" ] || [ -n "${TEST_CHECK_NOT_NEEDED:-}" ]; then
                    echo not-needed
                else
                    echo needed
                    printf '%s\n' "$TEST_TARGETS"
                fi ;;
            --print)
                echo "PREVIEW: would write /etc/udev/rules.d/70-sigrift-sdr.rules" ;;
            *)
                if [ "${TEST_PREPARE_STATUS:-0}" -ne 0 ]; then
                    echo "Error: simulated preparation failure" >&2
                    exit "$TEST_PREPARE_STATUS"
                fi
                touch "$TEST_STATE/prepared"
                echo "Prepared this host." ;;
        esac
        ;;
    *) exit 98 ;;
esac
"""

FAKE_SUDO = r"""#!/bin/sh
echo "sudo $*" >> "$TEST_LOG"
if [ "$1" = -n ]; then shift; fi
exec "$@"
"""


@pytest.fixture
def fakes(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, text in (("python3", FAKE_PYTHON), ("sudo", FAKE_SUDO)):
        (bindir / name).write_text(text)
        (bindir / name).chmod(0o700)
    state = tmp_path / "state"
    state.mkdir()
    log = tmp_path / "log"
    log.write_text("")
    env = clean_env() | {
        "PATH": str(bindir) + os.pathsep + os.environ["PATH"],
        "TEST_LOG": str(log),
        "TEST_STATE": str(state),
        "TEST_PLAN_AFTER": json.dumps(READY_PLAN),
        "TEST_TARGETS": "usb=1-1.3\nwifi-interface=wlan1",
    }
    env.pop("SSH_CONNECTION", None)
    return SimpleFakes(tmp_path, env, log, state)


class SimpleFakes:
    def __init__(self, root, env, log, state):
        self.root, self.env, self.log, self.state = root, env, log, state

    def calls(self):
        return self.log.read_text().splitlines()


def step_script(prepare_host="", request="auto", wifi=""):
    return (
        "set -euo pipefail\n"
        + function("prepare_host_step")
        + f"PREPARE_HOST={prepare_host}\nSCANNER_REQUEST={request}\n"
        + f"WIFI_INTERFACE={wifi}\n"
        + 'plan_args=(plan --scanners "$SCANNER_REQUEST")\n'
        + "SCANNER_PLAN='{}'\n"
        + 'if prepare_host_step; then echo "RESULT=replanned"; '
        + 'else echo "RESULT=unchanged"; fi\n'
        + 'echo "PLAN=$SCANNER_PLAN"\n'
    )


def run_piped(fakes, script, *, stdin="admin-password\nadmin-password\n"):
    return subprocess.run(
        ["bash", "-c", script],
        cwd=fakes.root,
        env=fakes.env,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=30,
    )


def run_on_terminal(fakes, script, answer, *, stdout_tty=True):
    """Run with stdin (and stdout) on a pseudo-terminal; type `answer`."""
    master, slave = pty.openpty()
    process = subprocess.Popen(
        ["bash", "-c", script],
        cwd=fakes.root,
        env=fakes.env,
        stdin=slave,
        stdout=slave if stdout_tty else subprocess.PIPE,
        stderr=slave,
    )
    os.close(slave)
    output = b""
    sent = False
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 0.2)
        if ready:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            output += chunk
            if not sent and b"[y/N]" in output:
                os.write(master, answer.encode() + b"\n")
                sent = True
        elif process.poll() is not None:
            break
    if process.poll() is None and not sent and not stdout_tty:
        os.write(master, answer.encode() + b"\n")
    process.wait(timeout=30)
    if not stdout_tty:
        output += process.stdout.read()
    os.close(master)
    return process.returncode, output.decode(errors="replace").replace("\r", "")


# ── The three paths ──────────────────────────────────────────────────


def test_flag_runs_prepare_with_non_interactive_sudo_and_replans(fakes):
    result = run_piped(fakes, step_script("yes"))
    assert result.returncode == 0, result.stderr
    assert "RESULT=replanned" in result.stdout
    assert "PLAN=" + json.dumps(READY_PLAN) in result.stdout
    calls = fakes.calls()
    assert calls[0] == f"{PREPARE} --check --scanners auto"
    assert f"sudo -n {PREPARE} {TARGETED}" in calls
    assert "[y/N]" not in result.stdout + result.stderr
    # The plan runs again after the preparation, with the same arguments.
    assert calls.index(f"sudo -n {PREPARE} {TARGETED}") < len(calls) - 1
    assert calls[-1] == "python3 scripts/scanner_setup.py plan --scanners auto"


def test_terminal_yes_shows_the_review_then_runs_and_replans(fakes):
    code, output = run_on_terminal(fakes, step_script(), "y")
    assert code == 0, output
    assert "PREVIEW: would write" in output
    assert output.index("PREVIEW") < output.index("[y/N]")
    assert "RESULT=replanned" in output
    calls = fakes.calls()
    # The review and the root run name the same targets.
    assert f"{PREPARE} --print {TARGETED}" in calls
    assert f"sudo {PREPARE} {TARGETED}" in calls
    assert not any(call.startswith("sudo -n") for call in calls)


@pytest.mark.parametrize("answer", ["", "n", "no", "whatever"])
def test_terminal_default_and_no_skip_and_continue(fakes, answer):
    code, output = run_on_terminal(fakes, step_script(), answer)
    assert code == 0, output
    assert "RESULT=unchanged" in output and "PLAN={}" in output
    assert not any(call.startswith("sudo") for call in fakes.calls())
    assert "Skipped" in output
    assert (
        f"sudo {PREPARE} --scanners=sdr,wifi --usb=1-1.3 --wifi-interface=wlan1"
        in output
    )


def test_no_terminal_prints_the_single_command_and_never_prompts(fakes):
    result = run_piped(fakes, step_script())
    assert result.returncode == 0, result.stderr
    out = result.stdout + result.stderr
    assert "[y/N]" not in out
    assert f"sudo {PREPARE}" in out
    assert "RESULT=unchanged" in result.stdout
    assert not any(call.startswith("sudo") for call in fakes.calls())
    assert not any("--print" in call for call in fakes.calls())


def test_terminal_stdin_but_redirected_stdout_never_prompts(fakes):
    code, output = run_on_terminal(fakes, step_script(), "y", stdout_tty=False)
    assert code == 0, output
    assert "[y/N]" not in output
    assert "RESULT=unchanged" in output
    assert not any(call.startswith("sudo") for call in fakes.calls())


def test_no_prepare_host_never_asks_or_runs(fakes):
    code, output = run_on_terminal(fakes, step_script("no"), "y")
    assert code == 0, output
    assert "[y/N]" not in output and "RESULT=unchanged" in output
    assert fakes.calls() == []


def test_nothing_needed_means_no_question(fakes):
    (fakes.state / "prepared").touch()
    code, output = run_on_terminal(fakes, step_script(), "y")
    assert code == 0 and "[y/N]" not in output
    assert "RESULT=unchanged" in output
    assert fakes.calls() == [
        "python3 scripts/scanner_setup.py prepare --check --scanners auto"
    ]


def test_failed_prepare_continues_and_says_what_was_skipped(fakes):
    fakes.env["TEST_PREPARE_STATUS"] = "1"
    result = run_piped(fakes, step_script("yes"))
    assert result.returncode == 0, result.stderr
    assert "RESULT=unchanged" in result.stdout and "PLAN={}" in result.stdout
    assert "Skipped" in result.stdout + result.stderr
    assert not any(" plan " in f" {call} " for call in fakes.calls())


def test_wifi_interface_and_request_are_passed_through(fakes):
    fakes.env["TEST_TARGETS"] = "wifi-interface=wlan1"
    result = run_piped(fakes, step_script("yes", "wifi", "wlan1"))
    assert result.returncode == 0, result.stderr
    calls = fakes.calls()
    assert calls[0] == f"{PREPARE} --check --scanners wifi --wifi-interface wlan1"
    assert f"sudo -n {PREPARE} --scanners wifi --wifi-interface wlan1" in calls


def test_only_the_receiver_is_targeted_when_check_names_only_it(fakes):
    fakes.env["TEST_TARGETS"] = "usb=1-1.3"
    result = run_piped(fakes, step_script("yes"))
    assert result.returncode == 0, result.stderr
    assert f"sudo -n {PREPARE} --scanners sdr --usb 1-1.3" in fakes.calls()


def test_ssh_client_address_is_passed_to_every_prepare_call(fakes):
    fakes.env["SSH_CONNECTION"] = "192.0.2.10 50000 192.0.2.1 22"
    code, output = run_on_terminal(fakes, step_script(), "y")
    assert code == 0, output
    prepares = [call for call in fakes.calls() if call.startswith(PREPARE)]
    assert len(prepares) == 3  # check, review and the root run
    assert all(call.endswith(" --ssh-client 192.0.2.10") for call in prepares)


def test_check_naming_no_target_is_skipped(fakes):
    fakes.env["TEST_TARGETS"] = ""
    result = run_piped(fakes, step_script("yes"))
    assert result.returncode == 0, result.stderr
    assert "RESULT=unchanged" in result.stdout
    assert "Skipped host preparation:" in result.stdout + result.stderr
    assert not any(call.startswith("sudo") for call in fakes.calls())


REFUSAL = (
    "/etc/udev/rules.d/70-sigrift-sdr.rules holds SigRift settings for a "
    "different receiver; it is left untouched."
)


@pytest.mark.parametrize("prepare_host", ["", "yes"])
def test_refused_check_is_reported_and_the_install_continues(fakes, prepare_host):
    fakes.env["TEST_CHECK_FAILS"] = REFUSAL
    result = run_piped(fakes, step_script(prepare_host))
    assert result.returncode == 0, result.stderr
    out = result.stdout + result.stderr
    assert f"Skipped host preparation: {REFUSAL}" in out
    assert "python3 scripts/scanner_setup.py prepare --print" in out
    assert "RESULT=unchanged" in result.stdout and "PLAN={}" in result.stdout
    assert not any(call.startswith("sudo") for call in fakes.calls())


def test_refused_check_on_a_terminal_is_reported_without_a_question(fakes):
    fakes.env["TEST_CHECK_FAILS"] = REFUSAL
    code, output = run_on_terminal(fakes, step_script(), "y")
    assert code == 0, output
    assert "[y/N]" not in output
    assert f"Skipped host preparation: {REFUSAL}" in output


# ── The real scanner-plan block ──────────────────────────────────────


def plan_block():
    text = QUICKSTART.read_text()
    start = text.index("        plan_args=(plan --scanners")
    end = text.index("        SCANNER_RF=", start)
    return text[start:end]


def block_script(prepare_host=""):
    return (
        "set -euo pipefail\n"
        + function("prepare_host_step")
        + "report_setup_readiness() { echo READINESS; }\n"
        + f"PREPARE_HOST={prepare_host}\nSCANNER_REQUEST=auto\nWIFI_INTERFACE=\n"
        + "SCANNER_HONOR_PROFILES=0\n"
        + plan_block()
        + 'echo "PLAN=$SCANNER_PLAN"\n'
    )


def test_plan_block_prepares_then_continues_with_the_ready_scanners(fakes):
    result = run_piped(fakes, block_script("yes"))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("PLAN=" + json.dumps(READY_PLAN))
    plans = [call for call in fakes.calls() if " plan " in f" {call} "]
    assert len(plans) == 2


def test_plan_block_failed_prepare_keeps_the_dashboard_plan(fakes):
    fakes.env["TEST_PREPARE_STATUS"] = "1"
    result = run_piped(fakes, block_script("yes"))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("PLAN={}")


# A plan that fails because the host is not prepared (an install whose
# selected receiver lost its preparation, or one made before this step).
# Measured on a Pi: quickstart then exited in 2 s even with --prepare-host.

PLAN_CALL = "python3 scripts/scanner_setup.py plan --scanners auto"
CHECK_CALL = f"{PREPARE} --check --scanners auto"


def test_failed_plan_with_the_flag_prepares_then_continues(fakes):
    fakes.env["TEST_PLAN_FAILS"] = "1"
    result = run_piped(fakes, block_script("yes"))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("PLAN=" + json.dumps(READY_PLAN))
    calls = fakes.calls()
    assert calls[:2] == [PLAN_CALL, CHECK_CALL]
    assert f"sudo -n {PREPARE} {TARGETED}" in calls
    assert calls[-1] == PLAN_CALL  # planned again in the same run
    assert "the error above is resolved" in result.stdout


def test_failed_plan_on_a_terminal_asks_then_continues(fakes):
    fakes.env["TEST_PLAN_FAILS"] = "1"
    code, output = run_on_terminal(fakes, block_script(), "y")
    assert code == 0, output
    assert output.index("PREVIEW") < output.index("[y/N]")
    assert "PLAN=" + json.dumps(READY_PLAN) in output
    assert f"sudo {PREPARE} {TARGETED}" in fakes.calls()


def test_failed_plan_declined_on_a_terminal_exits_as_before(fakes):
    fakes.env["TEST_PLAN_FAILS"] = "1"
    code, output = run_on_terminal(fakes, block_script(), "n")
    assert code == 1
    assert "PLAN=" not in output
    assert "Skipped host preparation." in output
    assert "stay off in this run" not in output
    assert not any(call.startswith("sudo") for call in fakes.calls())


def test_failed_plan_without_a_terminal_names_the_step_and_exits(fakes):
    fakes.env["TEST_PLAN_FAILS"] = "1"
    result = run_piped(fakes, block_script())
    assert result.returncode == 1
    out = result.stdout + result.stderr
    assert "PLAN=" not in result.stdout
    assert "before the selected scanners can start" in out
    assert "stay off in this run" not in out
    assert "--prepare-host" in out
    assert "[y/N]" not in out
    assert fakes.calls() == [PLAN_CALL, CHECK_CALL]


def test_failed_plan_that_preparation_cannot_fix_exits_as_before(fakes):
    fakes.env["TEST_PLAN_FAILS"] = "1"
    fakes.env["TEST_CHECK_NOT_NEEDED"] = "1"
    result = run_piped(fakes, block_script("yes"))
    assert result.returncode == 1
    assert "PLAN=" not in result.stdout
    assert fakes.calls() == [PLAN_CALL, CHECK_CALL]


def test_failed_preparation_after_a_failed_plan_exits_with_the_plan_status(fakes):
    fakes.env["TEST_PLAN_FAILS"] = "1"
    fakes.env["TEST_PLAN_STATUS"] = "3"
    fakes.env["TEST_PREPARE_STATUS"] = "1"
    result = run_piped(fakes, block_script("yes"))
    assert result.returncode == 3
    assert "Host preparation did not complete." in result.stderr
    assert "stay off in this run" not in result.stdout + result.stderr
    calls = fakes.calls()
    assert f"sudo -n {PREPARE} {TARGETED}" in calls
    assert calls.count(PLAN_CALL) == 1  # no second plan after a failed step


@pytest.mark.parametrize("status", ["130", "143"])
def test_interrupted_plan_is_never_followed_by_preparation(fakes, status):
    fakes.env["TEST_PLAN_FAILS"] = "1"
    fakes.env["TEST_PLAN_STATUS"] = status
    result = run_piped(fakes, block_script("yes"))
    assert result.returncode == int(status)
    assert fakes.calls() == [PLAN_CALL]


def test_failed_plan_with_no_prepare_host_exits_as_before(fakes):
    fakes.env["TEST_PLAN_FAILS"] = "1"
    result = run_piped(fakes, block_script("no"))
    assert result.returncode == 1
    assert fakes.calls() == [PLAN_CALL]


# ── Arguments ────────────────────────────────────────────────────────


@pytest.mark.parametrize("flag", ["--prepare-host", "--no-prepare-host"])
@pytest.mark.parametrize(
    "mode", [["--dashboard-only"], ["--renew-tls"], ["--scanners=none"]]
)
def test_flags_are_refused_with_modes_that_never_use_scanners(tmp_path, flag, mode):
    script = tmp_path / "scripts/quickstart.sh"
    script.parent.mkdir()
    shutil.copyfile(QUICKSTART, script)
    for arguments in ([flag, *mode], [*mode, flag]):
        result = subprocess.run(
            ["bash", str(script), *arguments],
            capture_output=True,
            text=True,
            timeout=10,
            env=clean_env(),
        )
        assert result.returncode == 2, arguments
        assert "--prepare-host" in result.stderr and "scanners" in result.stderr
        assert not (tmp_path / ".env").exists()


@pytest.mark.parametrize(
    "arguments",
    [
        ["--prepare-host", "--no-prepare-host"],
        ["--prepare-host", "--prepare-host"],
    ],
)
def test_conflicting_or_repeated_flags_are_refused(tmp_path, arguments):
    script = tmp_path / "scripts/quickstart.sh"
    script.parent.mkdir()
    shutil.copyfile(QUICKSTART, script)
    result = subprocess.run(
        ["bash", str(script), *arguments],
        capture_output=True,
        text=True,
        timeout=10,
        env=clean_env(),
    )
    assert result.returncode == 2
    assert "--prepare-host" in result.stderr


def test_flags_are_documented_in_usage_and_quickstart_md():
    text = QUICKSTART.read_text()
    usage = next(line for line in text.splitlines() if 'echo "usage: $0' in line)
    assert "--prepare-host" in usage and "--no-prepare-host" in usage
    guide = (Path(QUICKSTART).parents[1] / "QUICKSTART.md").read_text()
    assert "--prepare-host" in guide
    assert "sudo python3 scripts/scanner_setup.py prepare" in guide
    assert "prepare --print" in guide and "unprepare" in guide


def test_quickstart_md_states_the_measured_network_manager_effect():
    guide = (Path(QUICKSTART).parents[1] / "QUICKSTART.md").read_text()
    section = re.search(
        r"^#### Preparing the host\n.*?(?=^#{2,4} )", guide, re.M | re.S
    )
    flat = " ".join(section.group().split())
    assert "17 seconds" in flat
    assert "recommended, not required" in flat
    assert "wlan1 left monitor mode" in flat
    assert "56 minutes" in flat
    # Which existing files are replaced, said precisely.
    assert "with other content is left as it is" not in flat
    assert "is replaced" in flat
