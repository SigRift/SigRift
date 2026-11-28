"""A journal or lock pid that now belongs to another process is not alive.

The journal records the detached child's pid. After the child ends, or after
a reboot in the middle of an upgrade, the same pid can belong to an unrelated
process. --status, --resume, --renew-tls and the lock must not read that as an
operation still running. The pid is recorded with its start identity (the boot
id and start time on Linux, ps's start time elsewhere) and checked against it.
"""

import os
import time

from lifecycle_fakes import load_lifecycle_tool  # noqa: E402

TOOL = load_lifecycle_tool()


def test_a_live_pid_with_its_recorded_start_is_alive():
    me = os.getpid()
    start = TOOL.proc_start(me)
    assert start
    assert TOOL.alive(me, start) is True
    assert TOOL.alive(me) is True  # journals written before pid_start existed


def test_a_reused_pid_is_not_alive():
    me = os.getpid()
    other = "linux:another-boot:1" if TOOL.proc_start(me).startswith("linux:") \
        else "ps:Thu Jan  1 00:00:00 1970"
    assert TOOL.alive(me, other) is False


def test_journal_set_records_the_start_with_the_pid(tmp_path):
    os.makedirs(tmp_path / TOOL.STATE_DIR, exist_ok=True)
    TOOL.journal_save(str(tmp_path), {"op": "upgrade", "state": "running", "pid": None})
    TOOL.cmd_journal_set([str(tmp_path), "pid=%d" % os.getpid()])
    j = TOOL.journal_load(str(tmp_path))
    assert j["pid"] == os.getpid()
    assert j["pid_start"] == TOOL.proc_start(os.getpid())


def test_an_ended_child_not_yet_reaped_is_not_alive():
    # A zombie still answers kill(pid, 0); the detached child becomes one when
    # its new parent (a container's PID 1, a CI runner) does not reap it.
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    try:
        for _ in range(200):
            if TOOL.proc_zombie(pid):
                break
            time.sleep(0.01)
        assert TOOL.proc_zombie(pid) is True
        assert TOOL.alive(pid) is False
    finally:
        os.waitpid(pid, 0)
