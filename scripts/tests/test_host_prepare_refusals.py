"""Host preparation: what it refuses, what it leaves alone, and what it targets.

Uses the fake host of test_host_prepare (real files under a temporary /etc,
fixture nmcli/udevadm and receiver release), so nothing here needs root or
touches this machine's devices or configuration.
"""

from __future__ import annotations

import copy

import pytest
import test_host_prepare as prepared
import test_scanner_setup as planner

setup = planner.setup
clean = planner.clean
host = prepared.host
UDEV, DROPIN = prepared.UDEV, prepared.DROPIN
SPARE, RECEIVER = prepared.SPARE, prepared.RECEIVER


# ── NetworkManager state ─────────────────────────────────────────────


def test_network_manager_that_is_not_running_counts_as_absent():
    calls = []

    def stopped(args, **kwargs):
        calls.append(args)
        return "stopped\n"

    assert setup.nm_device_states(stopped) is None
    assert calls == [["nmcli", "-t", "-f", "RUNNING", "general"]]


def test_only_plain_interface_names_are_read_from_nmcli():
    answers = {
        "general": "running\n",
        "device": "wlan1:disconnected\nbr\\:0:connected\nno-separator\n:unmanaged\n"
        "wlan2:unavailable \n",
    }

    def nmcli(args, **kwargs):
        return answers[args[-1]]

    assert setup.nm_device_states(nmcli) == {
        "wlan1": "disconnected",
        "wlan2": "unavailable",
    }


def test_no_ready_adapter_means_no_network_manager_query():
    items = [{"interface": "wlan0", "phy": "phy0", "reasons": [prepared.PROTECTED]}]
    before = copy.deepcopy(items)
    calls = []
    setup.annotate_network_manager(items, runner=calls.append)
    assert calls == [] and items == before


# ── Permanent addresses ──────────────────────────────────────────────


def test_unreadable_address_files_read_as_no_address(tmp_path):
    (tmp_path / "good").write_text("02:AA:bb:CC:dd:EE\n")
    (tmp_path / "binary").write_bytes(b"\xff\xfe\x00\n")
    assert setup.read_address(tmp_path / "good") == "02:aa:bb:cc:dd:ee"
    assert setup.read_address(tmp_path / "binary") is None
    assert setup.read_address(tmp_path / "missing") is None


def test_address_shared_with_another_radio_is_refused(host):
    # The management radio reports the spare adapter's permanent address too.
    (host.sysfs / "devices/radio0/ieee80211/phy0/macaddress").write_text(
        prepared.SPARE_ADDRESS + "\n"
    )
    with pytest.raises(setup.SetupError, match="also used by another network device"):
        host.prepare(scanners="wifi")
    assert host.files() == {} and host.mutations() == []


def test_uniqueness_of_an_unknown_radio_cannot_be_shown(host):
    assert (
        setup.wifi_address_is_unique(host.sysfs, "phy9", prepared.SPARE_ADDRESS)
        is False
    )


# ── Files at the target paths ────────────────────────────────────────


def test_undecodable_file_at_the_rule_path_is_not_treated_as_ours(host):
    path = host.etc / UDEV
    path.write_bytes(setup.UDEV_MARKER.encode() + b"\xff\xfe\n")
    before = host.files()
    for mode in ("print", "apply"):
        with pytest.raises(setup.SetupError, match="was not written by this tool"):
            host.prepare(scanners="sdr", mode=mode)
    assert host.files() == before
    assert host.released == [] and host.mutations() == []


def test_file_written_between_review_and_apply_stops_the_run(host):
    prep = setup.host_preparation(
        copy.deepcopy(host.discovery),
        kinds=("sdr",),
        sysfs=host.sysfs,
        etc=host.etc,
        runner=host.run,
    )
    assert [step["action"] for step in prep["steps"]] == [
        "release",
        "write",
        "run",
        "run",
    ]
    (host.etc / UDEV).write_text("# operator rule written meanwhile\n")
    with pytest.raises(setup.SetupError) as raised:
        setup.apply_preparation(
            prep,
            runner=host.run,
            release=host.release,
            sysfs=host.sysfs,
            dev=host.dev,
            owner=None,
            sleep=None,
        )
    message = str(raised.value)
    assert message.startswith(
        f"Host preparation stopped at: Receiver 1-1.3: write {host.etc / UDEV}"
    )
    assert "already exists and was not written by this tool" in message
    assert "Completed before it: Receiver 1-1.3: release its TV driver" in message
    assert setup.UNPREPARE_COMMAND in message
    assert host.files() == {UDEV: b"# operator rule written meanwhile\n"}
    assert host.mutations() == []  # udev was not reloaded for a rule it did not write


def test_identical_rule_written_meanwhile_is_kept_not_rewritten(host):
    prep = setup.host_preparation(
        copy.deepcopy(host.discovery),
        kinds=("sdr",),
        sysfs=host.sysfs,
        etc=host.etc,
        runner=host.run,
    )
    path = host.etc / UDEV
    path.write_text(prep["steps"][1]["text"])
    inode = path.stat().st_ino
    done = setup.apply_preparation(
        prep,
        runner=host.run,
        release=host.release,
        sysfs=host.sysfs,
        dev=host.dev,
        owner=None,
        sleep=None,
    )
    assert len(done) == 4
    assert path.stat().st_ino == inode
    assert sorted(p.name for p in path.parent.iterdir()) == [path.name]
    assert host.mutations() == [list(argv) for argv in setup.UDEV_COMMANDS]


# ── What a run targets ───────────────────────────────────────────────


def test_none_prepares_nothing_and_discovers_nothing(host, capsys):
    host.root_user = False
    host.prepare(scanners="none", mode="check")
    assert capsys.readouterr().out == "not-needed\n"
    assert host.discover_options == []


def test_saved_choice_targets_the_saved_kind_and_pending_intent_wins(host, capsys):
    host.root_user = False
    host.prepare(scanners="saved", mode="check")
    assert capsys.readouterr().out == "not-needed\n"
    assert host.discover_options == []
    (host.root / setup.STATE).write_text(setup.render({"wifi": SPARE}))
    host.prepare(scanners="saved", mode="check")
    assert capsys.readouterr().out == "needed\nwifi-interface=wlan1\n"
    (host.root / setup.PENDING).write_text(setup.pending_text({"sdr": RECEIVER}))
    host.prepare(scanners="saved", mode="check")
    assert capsys.readouterr().out == "needed\nusb=1-1.3\n"


@pytest.mark.parametrize("scanners", ["bluetooth", "sdr,", "sdr,wifi,bt", ""])
def test_unknown_scanner_kind_is_refused_before_discovery(host, scanners):
    with pytest.raises(setup.SetupError, match="Choose --scanners="):
        host.prepare(scanners=scanners, mode="print")
    assert host.discover_options == [] and host.files() == {}


@pytest.mark.parametrize(
    "choice,interface,suffix",
    [
        (None, None, ""),
        ("auto", "wlan1", " --wifi-interface=wlan1"),
        ("sdr,wifi", None, " --scanners=sdr,wifi"),
        ("wifi", "wlan2", " --scanners=wifi --wifi-interface=wlan2"),
    ],
)
def test_suggested_command_targets_exactly_the_request(choice, interface, suffix):
    assert setup.prepare_command(choice, interface) == setup.PREPARE_COMMAND + suffix


def test_discovery_problems_are_listed_except_the_bluetooth_notice(host, capsys):
    host.discovery["sdr"] = []
    host.discovery["reasons"] = [
        "Bluetooth is not enabled automatically; its readiness probe is not yet implemented.",
        "sdr: Hardware metadata is unreadable; discovery is incomplete.",
    ]
    host.prepare(mode="print")
    out = capsys.readouterr().out
    assert (
        "  Not prepared: discovery: sdr: Hardware metadata is unreadable; discovery is incomplete.\n"
        in out
    )
    assert "Bluetooth" not in out and "Receiver" not in out
    assert host.files() == {} and host.mutations() == []


def test_hardware_disabled_override_is_honoured_only_when_it_disables(
    host, monkeypatch, capsys
):
    services = []
    compose = []

    def run(args, **kwargs):
        compose.append(args)
        return "\n".join(services) + "\n"

    monkeypatch.setattr(setup, "run", run)
    host.root_user = False
    # No override file: nothing to ask Compose, discovery runs.
    host.prepare(mode="check", honor_profiles=True)
    assert capsys.readouterr().out.startswith("needed\n")
    assert compose == [] and len(host.discover_options) == 1
    (host.root / "docker-compose.override.yml").write_text("services: {}\n")
    services[:] = [*setup.CORE, "scan"]
    host.prepare(mode="check", honor_profiles=True)
    assert capsys.readouterr().out.startswith("needed\n")
    assert len(host.discover_options) == 2
    services[:] = setup.CORE
    host.prepare(mode="check", honor_profiles=True)
    assert capsys.readouterr().out == "not-needed\n"
    assert len(host.discover_options) == 2
    assert compose == [["docker", "compose", "config", "--services"]] * 2


def test_refused_plan_still_points_at_the_reviewed_prepare(host):
    (host.etc / UDEV).write_text("# operator rule\n")
    options = {"sysfs": host.sysfs, "etc": host.etc, "runner": host.run}
    assert (
        setup.host_needs_preparation(
            copy.deepcopy(host.discovery), "sdr", None, options
        )
        is True
    )
    assert host.files() == {UDEV: b"# operator rule\n"}
    assert host.released == [] and host.mutations() == []


# ── Root ─────────────────────────────────────────────────────────────


def test_apply_and_undo_need_native_root_by_default(host, monkeypatch):
    monkeypatch.setattr(setup.platform, "system", lambda: "Darwin")
    (host.etc / UDEV).write_text(setup.udev_rule("1-1.3", sysfs=host.sysfs) + "\n")
    before = host.files()
    with pytest.raises(setup.SetupError, match="needs root"):
        setup.prepare(
            host.root,
            sysfs=host.sysfs,
            dev=host.dev,
            etc=host.etc,
            runner=host.run,
            release=host.release,
        )
    with pytest.raises(setup.SetupError, match="needs root"):
        setup.unprepare(etc=host.etc, runner=host.run)
    assert host.files() == before
    assert host.discover_options == [] and host.calls == []


# ── Undo ─────────────────────────────────────────────────────────────


def test_undo_never_follows_a_symlink_even_to_a_marked_file(host, capsys):
    target = host.etc / "elsewhere.rules"
    target.write_text(setup.udev_rule("1-1.3", sysfs=host.sysfs) + "\n")
    path = host.etc / UDEV
    path.symlink_to(target)
    host.unprepare()
    out = capsys.readouterr().out
    assert path.is_symlink() and target.is_file()
    assert f"Left untouched (not written by this tool): {path}" in out
    assert "Nothing to undo" in out
    assert host.mutations() == []


def test_undo_keeps_a_dropin_whose_first_line_does_not_decode(host, capsys):
    path = host.etc / DROPIN
    content = setup.NM_MARKER.encode() + b" \xff\xfe\n[keyfile]\n"
    path.write_bytes(content)
    host.unprepare()
    assert path.read_bytes() == content
    assert (
        f"Left untouched (not written by this tool): {path}" in capsys.readouterr().out
    )
    assert host.mutations() == []
