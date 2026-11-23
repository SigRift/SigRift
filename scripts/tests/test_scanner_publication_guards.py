"""Saved choices, overlay publication, startup and the command line refuse safely.

Saved files are real files under tmp_path. Docker/Compose answers are fixtures:
these tests check what is written or kept when an answer is wrong, changes
mid-run, or another run writes at the same time, and that nothing is started
or overwritten then.
"""

from __future__ import annotations

import copy
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import test_scanner_setup as planner

setup = planner.setup
clean = planner.clean
SDR, WIFI = planner.SDR, planner.WIFI
ROOT = planner.ROOT
GENERIC = (
    "Error: scanner configuration could not be validated; "
    "existing files are preserved where possible.\n"
)


# ── Saved selection and intent ───────────────────────────────────────


@pytest.mark.parametrize(
    "selection,message",
    [
        (["sdr"], "Invalid saved scanner selection"),
        ({"bluetooth": {}}, "Invalid saved scanner selection"),
        ({"sdr": "1-2"}, "Invalid saved scanner identity"),
        ({"sdr": SDR | {"device": "/dev/sda"}}, "Invalid saved SDR identity"),
        ({"sdr": SDR | {"device": "/dev/bus/usb/001/../sda"}}, "Invalid saved SDR"),
        ({"sdr": SDR | {"usb": "1-2;reboot"}}, "Invalid saved SDR identity"),
        ({"sdr": SDR | {"identity": "A" * 64}}, "Invalid saved SDR identity"),
        ({"sdr": SDR | {"gid": True}}, "Invalid saved SDR identity"),
        ({"sdr": SDR | {"gid": -1}}, "Invalid saved SDR identity"),
        ({"sdr": SDR | {"gid": 2**32 - 1}}, "Invalid saved SDR identity"),
        ({"sdr": SDR | {"privileged": True}}, "Invalid saved SDR identity"),
        ({"sdr": {"usb": "1-2", "identity": "a" * 64}}, "Invalid saved SDR identity"),
    ],
)
def test_saved_selection_that_could_map_another_device_is_refused(
    tmp_path, selection, message
):
    with pytest.raises(setup.SetupError, match=message):
        setup.validate_selection(selection)
    # The same selection in the managed overlay is refused and left as it is.
    lines = setup.render({"sdr": SDR}).splitlines(keepends=True)
    metadata = {"version": 3, "selection": selection}
    lines[1] = "x-sigrift-scanner-setup: " + json.dumps(metadata) + "\n"
    path = tmp_path / setup.STATE
    path.write_text("".join(lines))
    before = path.read_bytes()
    with pytest.raises(setup.SetupError, match=message):
        setup.saved_selection(tmp_path)
    assert path.read_bytes() == before


def test_largest_valid_group_id_is_accepted():
    selection = {"sdr": SDR | {"gid": 2**32 - 2}}
    assert setup.validate_selection(selection) is selection


@pytest.mark.parametrize(
    "metadata",
    [
        {"version": 4, "selection": {"wifi": WIFI}, "note": "operator"},
        {"version": "4", "selection": {"wifi": WIFI}},
    ],
)
def test_overlay_metadata_edits_are_refused_and_preserved(tmp_path, metadata):
    lines = setup.render({"wifi": WIFI}).splitlines(keepends=True)
    lines[1] = "x-sigrift-scanner-setup: " + json.dumps(metadata) + "\n"
    path = tmp_path / setup.STATE
    path.write_text("".join(lines))
    before = path.read_bytes()
    with pytest.raises(setup.SetupError, match="edited or is invalid"):
        setup.saved_selection(tmp_path)
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "record",
    [
        {"version": 2, "stage": "active", "selection": {"wifi": WIFI}},
        {"version": "2", "stage": "pending", "selection": {"wifi": WIFI}},
        {"version": 2, "stage": "pending", "selection": {"wifi": WIFI}, "by": "x"},
    ],
)
def test_intent_record_with_another_role_is_refused_and_preserved(tmp_path, record):
    path = tmp_path / setup.PENDING
    path.write_text(json.dumps(record, sort_keys=True) + "\n")
    before = path.read_bytes()
    with pytest.raises(setup.SetupError, match="Pending scanner intent was edited"):
        setup.pending_selection(tmp_path)
    assert path.read_bytes() == before


def test_intent_is_not_saved_when_the_device_changed_meanwhile(tmp_path, monkeypatch):
    monkeypatch.setattr(setup, "compose_inputs", Mock())
    replugged = {"sdr": [SDR | {"gid": 99, "reasons": []}], "wifi": [], "reasons": []}
    monkeypatch.setattr(setup, "managed_discovery", lambda root: replugged)
    ownership = Mock()
    monkeypatch.setattr(setup, "verify_ownership", ownership)
    with pytest.raises(setup.SetupError, match="changed before saving intent"):
        setup.remember(tmp_path, {"sdr": SDR})
    assert list(tmp_path.iterdir()) == []
    ownership.assert_not_called()


def test_intent_written_by_another_run_meanwhile_is_kept(tmp_path, monkeypatch):
    monkeypatch.setattr(setup, "compose_inputs", Mock())
    theirs = setup.pending_text({"wifi": WIFI})

    def concurrent_run(root, selection):
        (root / setup.PENDING).write_text(theirs)

    monkeypatch.setattr(setup, "verify_ownership", concurrent_run)
    with pytest.raises(setup.SetupError, match="changed during setup; retry without"):
        setup.remember(tmp_path, {})
    assert (tmp_path / setup.PENDING).read_text() == theirs
    assert [path.name for path in tmp_path.iterdir()] == [setup.PENDING]


# ── Compose inputs and ownership ─────────────────────────────────────


@pytest.fixture
def compose_inputs(tmp_path, monkeypatch, clean):
    monkeypatch.setattr(setup, "compose_override_capability", Mock())
    answers = SimpleNamespace(environment="", calls=[])

    def run(args, **kwargs):
        answers.calls.append(args)
        return answers.environment

    monkeypatch.setattr(setup, "run", run)
    monkeypatch.setattr(setup, "json_command", Mock(side_effect=AssertionError))
    return answers


@pytest.mark.parametrize(
    "name", ["compose.yaml", "compose.override.yml", "docker-compose.yaml"]
)
def test_custom_compose_file_names_are_refused_and_kept(tmp_path, compose_inputs, name):
    (tmp_path / name).write_text("services: {}\n")
    with pytest.raises(setup.SetupError, match="standard docker-compose.yml"):
        setup.compose_inputs(tmp_path)
    assert compose_inputs.calls == []
    assert (tmp_path / name).read_text() == "services: {}\n"


def test_symlinked_override_is_refused(tmp_path, compose_inputs):
    (tmp_path / "operator.yml").write_text("services: {}\n")
    (tmp_path / "docker-compose.override.yml").symlink_to(tmp_path / "operator.yml")
    with pytest.raises(setup.SetupError, match="must be regular files"):
        setup.compose_inputs(tmp_path)
    assert compose_inputs.calls == []


@pytest.mark.parametrize(
    "variable", ["COMPOSE_PROFILES=hardware", "COMPOSE_FILE=a.yml"]
)
def test_compose_selection_variables_must_be_unset(tmp_path, compose_inputs, variable):
    compose_inputs.environment = f"COMPOSE_PROJECT_NAME=sigrift\n{variable}\n"
    with pytest.raises(
        setup.SetupError, match="Unset COMPOSE_FILE and COMPOSE_PROFILES"
    ):
        setup.compose_inputs(tmp_path)
    assert compose_inputs.calls == [["docker", "compose", "config", "--environment"]]


def test_unnamed_compose_project_blocks_the_ownership_check(tmp_path, monkeypatch):
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return json.dumps({"services": {}})

    monkeypatch.setattr(setup, "run", run)
    with pytest.raises(setup.SetupError, match="Cannot identify the Compose project"):
        setup.verify_ownership(tmp_path, {"sdr": SDR})
    assert calls == [["docker", "compose", "config", "--format", "json"]]


@pytest.mark.parametrize(
    "containers", ["not-a-container-id\n", "\n".join(["a" * 64] * 257) + "\n"]
)
def test_unbounded_or_odd_container_list_blocks_selection(
    tmp_path, monkeypatch, containers
):
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        if args[1] == "compose":
            return json.dumps({"name": "this-checkout"})
        return containers

    monkeypatch.setattr(setup, "run", run)
    with pytest.raises(setup.SetupError, match="Cannot bound/validate"):
        setup.verify_ownership(tmp_path, {"wifi": WIFI})
    assert not any(call[1] == "inspect" for call in calls)


@pytest.mark.parametrize(
    "devices",
    [
        [{"PathOnHost": "dev/bus/usb/001"}],
        ["/dev/bus/usb/001"],
        [{"PathInContainer": "/dev/bus/usb/001"}],
    ],
)
def test_unreadable_device_mappings_block_selection(tmp_path, monkeypatch, devices):
    planner.ownership_boundary(monkeypatch, [planner.container_owner(devices=devices)])
    with pytest.raises(setup.SetupError, match="ownership data is incomplete"):
        setup.verify_ownership(tmp_path, {"sdr": SDR})


def usbfs_receiver(tmp_path, monkeypatch, *, mode, rdev, kernel):
    usb = tmp_path / "sys/bus/usb/devices"
    interface = usb / "1-2:1.0"
    interface.mkdir(parents=True)
    (usb / "1-2").mkdir()
    (usb / "1-2/dev").write_text(kernel + "\n")
    driver = usb.parent / "drivers/usbfs"
    driver.mkdir(parents=True)
    (interface / "driver").symlink_to(driver)
    monkeypatch.setattr(setup, "USB_SYSFS", usb)
    monkeypatch.setattr(
        setup, "os", SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
    )
    monkeypatch.setattr(setup.os, "major", lambda _: rdev[0])
    monkeypatch.setattr(setup.os, "minor", lambda _: rdev[1])
    node = SimpleNamespace(st_mode=mode | 0o660, st_rdev=4242, st_ino=77)
    real = Path.lstat
    monkeypatch.setattr(
        Path, "lstat", lambda path: node if str(path) == SDR["device"] else real(path)
    )


@pytest.mark.parametrize(
    "mode,rdev,kernel",
    [
        (stat.S_IFCHR, (189, 3), "189:4"),
        (stat.S_IFREG, (189, 3), "189:3"),
        (stat.S_IFCHR, (1, 3), "1:3"),
    ],
)
def test_managed_receiver_with_another_identity_is_refused(
    tmp_path, monkeypatch, mode, rdev, kernel
):
    usbfs_receiver(tmp_path, monkeypatch, mode=mode, rdev=rdev, kernel=kernel)
    with pytest.raises(setup.SetupError, match="device identity changed"):
        setup.usbfs_device_state(SDR)


def test_managed_receiver_identity_is_the_kernel_device(tmp_path, monkeypatch):
    usbfs_receiver(
        tmp_path, monkeypatch, mode=stat.S_IFCHR, rdev=(189, 3), kernel="189:3"
    )
    assert setup.usbfs_device_state(SDR) == ((189, 3), 77)


# ── Plan, publication and check ──────────────────────────────────────


@pytest.mark.parametrize(
    "reasons,detail",
    [
        (
            ["sdr: Hardware metadata is unreadable; discovery is incomplete."],
            "sdr: Hardware metadata is unreadable; discovery is incomplete.",
        ),
        ([], "Check connected devices and rerun discovery."),
    ],
)
def test_explicit_choice_with_nothing_discovered_says_why(reasons, detail):
    discovery = {"sdr": [], "wifi": [], "reasons": reasons}
    with pytest.raises(setup.SetupError) as raised:
        setup.selection_from(discovery, "sdr")
    assert str(raised.value) == f"Selected sdr is unavailable or ambiguous. {detail}"


def test_plan_refuses_while_unmanaged_scanners_run(
    tmp_path, monkeypatch, clean, capsys
):
    monkeypatch.setattr(setup, "compose_inputs", Mock())
    discovery = {
        "sdr": [],
        "wifi": [],
        "reasons": ["wifi: iw is unavailable or returned invalid text."],
    }
    monkeypatch.setattr(setup, "discover", lambda: copy.deepcopy(discovery))
    ownership = Mock()
    monkeypatch.setattr(setup, "verify_ownership", ownership)
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return "bridge\ngateway\nwifi-scan\n"

    monkeypatch.setattr(setup, "run", run)
    host = {"sysfs": tmp_path / "sys", "etc": tmp_path / "etc", "runner": calls.append}
    with pytest.raises(setup.SetupError, match="services are running.*: wifi-scan$"):
        setup.plan(tmp_path, "auto", host=host)
    err = capsys.readouterr().err
    assert "    wifi: iw is unavailable or returned invalid text.\n" in err
    assert "==> Selected scanners: none (dashboard only)\n" in err
    assert "Prepare this host" not in err
    assert calls == [["docker", "compose", "ps", "--services", "--status", "running"]]
    ownership.assert_not_called()
    assert list(tmp_path.iterdir()) == []


class Compose:
    """Compose answers for install(); hooks run while the overlay is validated."""

    def __init__(self, root, monkeypatch):
        self.root = root
        self.discovery = {"sdr": [], "wifi": [], "reasons": []}
        self.baseline = {"services": {name: {"image": name} for name in setup.CORE}}
        self.config = copy.deepcopy(self.baseline)
        self.while_validating = []
        self.while_stopping = []
        self.commands = []
        monkeypatch.setattr(setup, "compose_inputs", Mock())
        monkeypatch.setattr(setup, "verify_ownership", Mock(return_value=[]))
        monkeypatch.setattr(
            setup, "managed_discovery", lambda root: copy.deepcopy(self.discovery)
        )
        monkeypatch.setattr(setup, "json_command", self.json_command)
        monkeypatch.setattr(setup, "run", self.run)

    def json_command(self, args):
        self.commands.append(args)
        if "-f" in args:
            for hook in self.while_validating:
                hook()
            return copy.deepcopy(self.config)
        return copy.deepcopy(self.baseline)

    def run(self, args, **kwargs):
        self.commands.append(args)
        for hook in self.while_stopping:
            hook()
        return ""

    def models(self):
        (self.root / "models").mkdir()
        (self.root / "models/open-default.onnx").write_bytes(b"onnx")
        (self.root / "models/open-default_metadata.json").write_text("{}")

    def files(self):
        return sorted(path.name for path in self.root.iterdir())


@pytest.fixture
def compose(tmp_path, monkeypatch, clean):
    return Compose(tmp_path, monkeypatch)


def test_receiver_that_changed_during_publication_is_not_published(compose):
    compose.discovery["sdr"] = [SDR | {"gid": 99, "reasons": []}]
    with pytest.raises(setup.SetupError, match="Device metadata changed during setup"):
        setup.install(compose.root, {"sdr": SDR})
    assert compose.files() == []
    assert compose.commands == []


def test_overlay_that_changes_a_core_service_is_not_published(compose):
    compose.config["services"]["gateway"]["ports"] = [
        {"target": 8444, "published": "0"}
    ]
    with pytest.raises(setup.SetupError, match="unexpectedly changes a core service"):
        setup.install(compose.root, {})
    assert compose.files() == []  # no overlay, no temporary file


def test_receiver_with_a_custom_model_path_is_not_published(compose):
    compose.models()
    compose.discovery["sdr"] = [SDR | {"reasons": []}]
    compose.config["services"]["scan"] = {
        "environment": {"MLRF_MODEL_PATH": "/app/models/custom.onnx"}
    }
    with pytest.raises(
        setup.SetupError, match="MLRF_MODEL_PATH=/app/models/open-default"
    ):
        setup.install(compose.root, {"sdr": SDR})
    assert compose.files() == ["models"]


@pytest.mark.parametrize(
    "url", ["https://bridge.example:9444", "https://127.0.0.1:8444", ""]
)
def test_wifi_bridge_url_must_be_the_gateway_loopback_publication(compose, url):
    gateway = {"ports": [{"target": 8444, "published": "9444", "host_ip": "127.0.0.1"}]}
    for config in (compose.baseline, compose.config):
        config["services"]["gateway"] = copy.deepcopy(gateway)
    compose.discovery["wifi"] = [WIFI | {"reasons": []}]
    compose.config["services"]["wifi-scan"] = {"environment": {"MLRF_BRIDGE_URL": url}}
    with pytest.raises(
        setup.SetupError, match="does not match the gateway publication"
    ):
        setup.install(compose.root, {"wifi": WIFI})
    assert compose.files() == []


def test_overlay_activated_by_another_run_meanwhile_is_kept(compose):
    theirs = setup.render({"wifi": WIFI})
    compose.while_validating.append(
        lambda: (compose.root / setup.STATE).write_text(theirs)
    )
    with pytest.raises(
        setup.SetupError, match="Scanner selection changed during setup"
    ):
        setup.install(compose.root, {})
    assert (compose.root / setup.STATE).read_text() == theirs
    assert compose.files() == [setup.STATE]


def test_intent_saved_by_another_run_before_activation_is_kept(compose):
    theirs = setup.pending_text({"wifi": WIFI})
    compose.while_validating.append(
        lambda: (compose.root / setup.PENDING).write_text(theirs)
    )
    with pytest.raises(setup.SetupError, match="changed before activation"):
        setup.install(compose.root, {})
    assert (compose.root / setup.PENDING).read_text() == theirs
    assert compose.files() == [setup.PENDING]


def test_intent_changed_right_after_activation_is_kept_for_reconciling(compose):
    root = compose.root
    (root / setup.STATE).write_text(setup.render({"sdr": SDR}))
    (root / setup.PENDING).write_text(setup.pending_text({}))
    theirs = setup.pending_text({"wifi": WIFI})
    compose.while_stopping.append(lambda: (root / setup.PENDING).write_text(theirs))
    with pytest.raises(
        setup.SetupError, match="Selection activated but pending intent"
    ):
        setup.install(root, {})
    # The new selection is active; the other run's intent is not deleted.
    assert (root / setup.STATE).read_text() == setup.render({})
    assert (root / setup.PENDING).read_text() == theirs
    assert compose.files() == sorted([setup.STATE, setup.PENDING])
    stop = setup.compose_command(root, root / setup.STATE) + [
        "stop",
        "rtl-tcp",
        "scan",
    ]
    assert stop in compose.commands


def test_check_of_a_dashboard_only_selection_never_probes_hardware(
    tmp_path, monkeypatch
):
    (tmp_path / setup.STATE).write_text(setup.render({}))
    discovery, inputs = Mock(), Mock()
    ownership = Mock(return_value=[])
    monkeypatch.setattr(setup, "managed_discovery", discovery)
    monkeypatch.setattr(setup, "compose_inputs", inputs)
    monkeypatch.setattr(setup, "verify_ownership", ownership)
    assert setup.check(tmp_path) == {}
    discovery.assert_not_called()
    inputs.assert_called_once_with(tmp_path)
    ownership.assert_called_once_with(tmp_path, {})


# ── Startup ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "output",
    [
        "not json",
        '[{"Name": "sigrift-scan-1"}]',
        '{"Service": "scan"}\n{"State": "x"}\n',
    ],
)
def test_unreadable_container_states_are_an_error(monkeypatch, output):
    monkeypatch.setattr(setup, "run", lambda args: output)
    with pytest.raises(
        setup.SetupError, match="Cannot verify selected scanner containers"
    ):
        setup.service_states(["docker", "compose"])
    # The pre-start staleness check recreates nothing it cannot read.
    assert setup.stale_scanners(["docker", "compose"], ["scan"]) == []


def test_dashboard_only_selection_starts_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(setup, "check", lambda root: {})
    run = Mock()
    monkeypatch.setattr(setup, "run", run)
    assert setup.start(tmp_path) is None
    run.assert_not_called()


def test_startup_that_never_becomes_healthy_stops_at_its_deadline(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(setup, "check", lambda root: {"wifi": WIFI})
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        if args[-3:] == ["ps", "--format", "json"]:
            return json.dumps(
                [{"Service": "wifi-scan", "State": "running", "Health": "starting"}]
            )
        return ""

    clock = SimpleNamespace(now=1000.0, sleeps=[])

    def sleep(seconds):
        clock.sleeps.append(seconds)
        clock.now += seconds

    monkeypatch.setattr(setup, "run", run)
    monkeypatch.setattr(
        setup, "time", SimpleNamespace(monotonic=lambda: clock.now, sleep=sleep)
    )
    with pytest.raises(setup.SetupError, match="did not complete within 30 seconds"):
        setup.start(tmp_path)
    assert clock.sleeps == [1] * 30
    command = setup.compose_command(tmp_path, tmp_path / setup.STATE)
    assert [call for call in calls if "up" in call] == [
        command + ["up", "-d", "--no-build", "--no-deps", "wifi-scan"]
    ]
    assert "Selected scanner processes started" not in capsys.readouterr().out


# ── Command line ─────────────────────────────────────────────────────


def cli(monkeypatch, *argv):
    monkeypatch.setattr(setup.signal, "signal", lambda *_: None)
    monkeypatch.setattr(sys, "argv", ["scanner_setup.py", *argv])
    return setup.main()


def test_check_flag_outside_prepare_is_refused(monkeypatch, capsys):
    assert cli(monkeypatch, "unprepare", "--check") == 1
    assert capsys.readouterr().err == "Error: --check works only with prepare.\n"


def test_plan_command_validates_the_interface_and_prints_the_selection(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.chdir(tmp_path)
    seen = []

    def plan(root, request, wifi_interface, *, honor_profiles):
        seen.append((root, request, wifi_interface, honor_profiles))
        return {"wifi": WIFI}

    monkeypatch.setattr(setup, "plan", plan)
    assert cli(monkeypatch, "plan", "--wifi-interface", "wlan1;reboot") == 1
    assert capsys.readouterr().err == "Error: Invalid Wi-Fi interface name.\n"
    assert seen == []
    assert cli(monkeypatch, "plan") == 0
    assert capsys.readouterr().out == json.dumps({"wifi": WIFI}, sort_keys=True) + "\n"
    argv = ("plan", "--scanners=wifi", "--wifi-interface=wlan1", "--honor-profiles")
    assert cli(monkeypatch, *argv) == 0
    assert seen == [
        (Path.cwd(), "saved", None, False),
        (Path.cwd(), "wifi", "wlan1", True),
    ]


@pytest.mark.parametrize("action", ["remember", "install"])
def test_selection_from_stdin_reaches_the_action(tmp_path, monkeypatch, action):
    monkeypatch.chdir(tmp_path)
    seen = []
    monkeypatch.setattr(setup, action, lambda root, selection: seen.append(selection))
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"wifi": WIFI})))
    assert cli(monkeypatch, action) == 0
    assert seen == [{"wifi": WIFI}]


@pytest.mark.parametrize("action", ["remember", "install"])
def test_malformed_selection_on_stdin_is_a_plain_error(
    tmp_path, monkeypatch, capsys, action
):
    monkeypatch.chdir(tmp_path)
    called = Mock()
    monkeypatch.setattr(setup, action, called)
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"wifi": BRIDGE_ADMIN_PASSWORD'))
    assert cli(monkeypatch, action) == 1
    err = capsys.readouterr().err
    assert err == GENERIC and "BRIDGE_ADMIN_PASSWORD" not in err
    called.assert_not_called()
    assert list(tmp_path.iterdir()) == []


def test_prepare_rtl_command_without_root_changes_nothing(monkeypatch, capsys):
    monkeypatch.setattr(setup.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        setup, "os", SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
    )
    monkeypatch.setattr(setup.os, "geteuid", lambda: 1000)
    release = Mock()
    monkeypatch.setattr(setup, "release_rtl", release)
    assert cli(monkeypatch, "prepare-rtl", "--usb", "1-2") == 1
    assert "requires native Linux root" in capsys.readouterr().err
    release.assert_not_called()


@pytest.mark.parametrize("action", ["check", "start"])
def test_check_and_start_need_a_saved_selection(tmp_path, monkeypatch, capsys, action):
    monkeypatch.chdir(tmp_path)
    run = Mock()
    monkeypatch.setattr(setup, "run", run)
    assert cli(monkeypatch, action) == 1
    assert capsys.readouterr().err == (
        "Error: No managed scanner selection exists; run quickstart first.\n"
    )
    run.assert_not_called()
    assert list(tmp_path.iterdir()) == []


def test_sigterm_during_a_run_cancels_with_status_130(monkeypatch, capsys):
    handlers = []
    monkeypatch.setattr(
        setup.signal,
        "signal",
        lambda signum, handler: handlers.append((signum, handler)),
    )

    def terminated(**options):
        ((signum, handler),) = handlers
        handler(signum, None)

    monkeypatch.setattr(setup, "unprepare", terminated)
    monkeypatch.setattr(sys, "argv", ["scanner_setup.py", "unprepare", "--print"])
    assert setup.main() == 130
    assert handlers[0][0] == signal.SIGTERM
    assert capsys.readouterr().err == (
        "Scanner setup cancelled; existing data is preserved.\n"
    )


def test_script_exits_with_the_status_main_returns(tmp_path):
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/scanner_setup.py"), "plan", "--print"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 1
    # endswith: a measuring coverage run may print its own warnings first.
    assert result.stderr.endswith(
        "Error: --print works only with prepare and unprepare.\n"
    )
    assert result.stdout == ""
    assert not (tmp_path / setup.STATE).exists()
