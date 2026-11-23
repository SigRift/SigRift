"""Re-plugged, swapped and older-format scanner selections in setup.

Saved files, sysfs-like trees, /proc layouts and the Compose parser are real.
Hardware discovery and the Docker daemon are explicit fixtures; nothing here
starts, stops or changes a container or a device.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest
import test_scanner_setup as planner
import test_scanner_usbfs_owner as usbfs

setup = planner.setup
# Several tests run the real `docker compose config` through setup.run, whose
# 10 s default a starved CI runner can outlast; it is lengthened below. The
# project default of 30 s per test (pyproject.toml) is then too short.
pytestmark = pytest.mark.timeout(180)
COMMAND_TIMEOUT = 60
SDR = planner.SDR
WIFI = planner.WIFI
clean = planner.clean
project = planner.project
owned = usbfs.owned
# The same receiver after a one-second USB drop: same port and identity, new
# kernel device number and (here) a new group from the host's udev rule.
REPLUGGED = SDR | {"device": "/dev/bus/usb/001/007", "gid": 47}
SUPERVISOR = ["python3", "-m", "sigrift.edge.rtl_tcp_supervisor"]
A64, B64, C64 = SDR["identity"], WIFI["identity"], "c" * 64

# What the previous version wrote for {"sdr": SDR, "wifi": WIFI}, verbatim.
LEGACY_TEXT = (
    "# Managed by scripts/scanner_setup.py; edit choices with quickstart --scanners=...\n"
    'x-sigrift-scanner-setup: {"selection": {"sdr": {"device": "/dev/bus/usb/001/004", '
    '"gid": 46, "identity": "'
    + A64
    + '", "usb": "1-2"}, "wifi": {"identity": "'
    + B64
    + '", "interface": "wlan1", "phy": "phy1"}}, "version": 2}\n'
    "services:\n"
    "  rtl-tcp:\n"
    "    profiles: !override [hardware]\n"
    '    devices: !override ["/dev/bus/usb/001/004:/dev/bus/usb/001/004:rw"]\n'
    '    group_add: !override ["46"]\n'
    '    command: ["rtl_tcp", "-a", "0.0.0.0", "-d", "0"]\n'
    "  scan:\n"
    "    profiles: !override [hardware]\n"
    "    volumes:\n"
    "      - ./models:/app/models:ro\n"
    "      - ./tls/cert.pem:/app/tls/cert.pem:ro\n"
    "    environment:\n"
    "      MLRF_CA_CERT: /app/tls/cert.pem\n"
    "  wifi-scan:\n"
    "    profiles: !override [hardware]\n"
    "    volumes:\n"
    "      - ./tls/cert.pem:/app/tls/cert.pem:ro\n"
    "    environment:\n"
    "      MLRF_CA_CERT: /app/tls/cert.pem\n"
    '      MLRF_WIFI_IFACE: "wlan1"\n'
    "  bt-scan:\n"
    "    profiles: !override [hardware]\n"
)


@pytest.fixture(autouse=True)
def patient_compose(monkeypatch):
    """Give the real Compose parser time on a loaded runner.

    Autouse, so it is in place before the fixtures that wrap setup.run: they
    and the tests still see the timeouts setup asks for. Only the real
    subprocess gets the longer limit; it returns as soon as Compose exits.
    """
    real = setup.run

    def run(args, **kwargs):
        if args[:2] == ["docker", "compose"]:
            kwargs["timeout"] = max(kwargs.get("timeout", 0), COMMAND_TIMEOUT)
        return real(args, **kwargs)

    monkeypatch.setattr(setup, "run", run)


def inventory(*sdr, wifi=()):
    return lambda: {
        "sdr": [item | {"reasons": []} for item in sdr],
        "wifi": [item | {"reasons": []} for item in wifi],
        "reasons": [],
    }


def with_model(root):
    models = root / "models"
    models.mkdir()
    (models / "open-default.onnx").write_bytes(b"synthetic nonempty model")
    (models / "open-default_metadata.json").write_text('{"classes": ["noise"]}')


def compose_config(root):
    return setup.json_command(
        setup.compose_command(root, root / setup.STATE)
        + ["--profile", "hardware", "config", "--format", "json"]
    )


# ── Rendered overlay ─────────────────────────────────────────────────


def test_sdr_overlay_maps_only_the_bus_and_runs_the_supervisor():
    assert setup.render({"sdr": SDR}) == (
        "# Managed by scripts/scanner_setup.py; edit choices with quickstart --scanners=...\n"
        'x-sigrift-scanner-setup: {"selection": {"sdr": {"device": "/dev/bus/usb/001/004", '
        '"gid": 46, "identity": "' + A64 + '", "usb": "1-2"}}, "version": 3}\n'
        "services:\n"
        "  rtl-tcp:\n"
        "    profiles: !override [hardware]\n"
        '    devices: !override ["/dev/bus/usb/001:/dev/bus/usb/001:rw"]\n'
        '    group_add: !override ["46"]\n'
        '    command: ["python3", "-m", "sigrift.edge.rtl_tcp_supervisor"]\n'
        "    environment:\n"
        '      MLRF_SDR_USB: "1-2"\n'
        '      MLRF_SDR_IDENTITY: "' + A64 + '"\n'
        "  scan:\n"
        "    profiles: !override [hardware]\n"
        "    volumes:\n"
        "      - ./models:/app/models:ro\n"
        "      - ./tls/cert.pem:/app/tls/cert.pem:ro\n"
        "    environment:\n"
        "      MLRF_CA_CERT: /app/tls/cert.pem\n"
        "  wifi-scan:\n"
        "    profiles: !override [hardware]\n"
        "  bt-scan:\n"
        "    profiles: !override [hardware]\n"
    )


def test_wifi_overlay_passes_the_identity_only_when_one_was_recorded():
    expected = (
        "# Managed by scripts/scanner_setup.py; edit choices with quickstart --scanners=...\n"
        'x-sigrift-scanner-setup: {"selection": {"wifi": {"identity": "'
        + B64
        + '", "interface": "wlan1", "phy": "phy1"}}, "version": 4}\n'
        "services:\n"
        "  rtl-tcp:\n"
        "    profiles: !override [hardware]\n"
        "  scan:\n"
        "    profiles: !override [hardware]\n"
        "  wifi-scan:\n"
        "    profiles: !override [hardware]\n"
        "    volumes:\n"
        "      - ./tls/cert.pem:/app/tls/cert.pem:ro\n"
        "    environment:\n"
        "      MLRF_CA_CERT: /app/tls/cert.pem\n"
        '      MLRF_WIFI_IFACE: "wlan1"\n'
        '      MLRF_WIFI_IDENTITY: "' + B64 + '"\n'
        "  bt-scan:\n"
        "    profiles: !override [hardware]\n"
    )
    assert setup.render({"wifi": WIFI}) == expected
    # An older selection without an identity cannot pin one.
    legacy = {"wifi": {"interface": "wlan1", "phy": "phy1"}}
    assert "MLRF_WIFI_IDENTITY" not in setup.render(legacy)
    assert '"version": 3}' in setup.render(legacy)


def test_base_compose_runs_the_supervisor_with_its_healthcheck_and_status_port(
    project,
):
    config = setup.json_command(
        ["docker", "compose", "--profile", "hardware", "config", "--format", "json"]
    )
    rtl = config["services"]["rtl-tcp"]
    assert rtl["command"] == SUPERVISOR
    assert rtl["healthcheck"]["test"] == ["CMD", *SUPERVISOR, "--check"]
    assert rtl["expose"] == ["1234", "1235"]
    assert rtl["restart"] == "unless-stopped"
    # Legacy unmanaged installs keep their mapping until setup selects one.
    assert [item["source"] for item in rtl["devices"]] == ["/dev/bus/usb"]
    scan = config["services"]["scan"]["environment"]
    assert scan["MLRF_RTL_PORT"] == "1234"
    assert scan["MLRF_RTL_STATUS_PORT"] == "1235"
    wifi = config["services"]["wifi-scan"]
    assert wifi["cap_drop"] == ["ALL"]
    assert wifi["security_opt"] == ["no-new-privileges:true"]


def test_managed_compose_config_maps_the_bus_and_passes_identities(
    project, monkeypatch
):
    monkeypatch.setattr(setup, "discover", inventory(SDR, wifi=[WIFI]))
    with_model(project)
    setup.install(project, {"sdr": SDR, "wifi": WIFI})
    config = compose_config(project)
    rtl = config["services"]["rtl-tcp"]
    assert [(item["source"], item["target"]) for item in rtl["devices"]] == [
        ("/dev/bus/usb/001", "/dev/bus/usb/001")
    ]
    assert rtl["devices"][0].get("permissions") == "rw"
    assert rtl["command"] == SUPERVISOR
    assert rtl["healthcheck"]["test"] == ["CMD", *SUPERVISOR, "--check"]
    assert rtl["environment"] == {
        "MLRF_SDR_USB": "1-2",
        "MLRF_SDR_IDENTITY": A64,
    }
    assert rtl["restart"] == "unless-stopped"
    wifi = config["services"]["wifi-scan"]["environment"]
    assert wifi["MLRF_WIFI_IFACE"] == "wlan1"
    assert wifi["MLRF_WIFI_IDENTITY"] == B64
    assert config["services"]["scan"]["environment"]["MLRF_RTL_STATUS_PORT"] == "1235"


# ── Re-plug: same identity, new kernel numbers ───────────────────────


def test_check_refreshes_a_replugged_receiver_through_publication(project, monkeypatch):
    (project / setup.STATE).write_text(setup.render({"sdr": SDR}))
    with_model(project)
    monkeypatch.setattr(setup, "discover", inventory(REPLUGGED))
    assert setup.check(project) == {"sdr": REPLUGGED}
    assert setup.saved_selection(project) == {"sdr": REPLUGGED}
    assert (project / setup.STATE).read_text() == setup.render({"sdr": REPLUGGED})
    assert stat.S_IMODE((project / setup.STATE).stat().st_mode) == 0o600
    assert list(project.glob(".sigrift-scanners-*.yml")) == []
    rtl = compose_config(project)["services"]["rtl-tcp"]
    assert rtl["group_add"] == ["47"]
    assert rtl["devices"][0]["source"] == "/dev/bus/usb/001"
    # A second check finds nothing to refresh and changes nothing.
    before = (project / setup.STATE).read_bytes()
    assert setup.check(project) == {"sdr": REPLUGGED}
    assert (project / setup.STATE).read_bytes() == before


@pytest.mark.parametrize("recreate", [False, True])
def test_start_refreshes_then_starts_only_the_selected_services(
    project, monkeypatch, recreate
):
    (project / setup.STATE).write_text(setup.render({"sdr": SDR}))
    with_model(project)
    monkeypatch.setattr(setup, "discover", inventory(REPLUGGED))
    real = setup.run
    started = []

    def command(args, **kwargs):
        if "up" in args:
            started.append(args)
            # The overlay is already refreshed when the services start.
            assert setup.saved_selection(project) == {"sdr": REPLUGGED}
            return ""
        if args[-3:] == ["ps", "--format", "json"]:
            return json.dumps(
                [
                    {"Service": name, "State": "running", "Health": "healthy"}
                    for name in ("rtl-tcp", "scan")
                ]
            )
        return real(args, **kwargs)

    monkeypatch.setattr(setup, "run", command)
    setup.start(project, recreate=recreate)
    assert len(started) == 1
    assert started[0][-2:] == ["rtl-tcp", "scan"]
    assert ("--force-recreate" in started[0]) is recreate


def test_start_recreates_a_running_scanner_that_is_unhealthy(
    project, monkeypatch, capsys
):
    # Measured on a Pi: after prepare changed the receiver's node on the host,
    # the running rtl-tcp container still saw its old copy (root:root 0664),
    # stayed unhealthy, and quickstart's start timed out after 30 seconds.
    (project / setup.STATE).write_text(setup.render({"sdr": SDR}))
    with_model(project)
    monkeypatch.setattr(setup, "discover", inventory(REPLUGGED))
    real = setup.run
    ups = []

    def command(args, **kwargs):
        if "up" in args:
            ups.append(args)
            return ""
        if args[-3:] == ["ps", "--format", "json"]:
            recreated = any("--force-recreate" in up for up in ups)
            health = "healthy" if recreated else "unhealthy"
            return json.dumps(
                [
                    {"Service": "rtl-tcp", "State": "running", "Health": health},
                    {"Service": "scan", "State": "running", "Health": ""},
                ]
            )
        return real(args, **kwargs)

    monkeypatch.setattr(setup, "run", command)
    setup.start(project)
    assert len(ups) == 2
    assert "--force-recreate" in ups[0] and ups[0][-1] == "rtl-tcp"
    assert "scan" not in ups[0]  # only the stale container is recreated
    assert "--force-recreate" not in ups[1] and ups[1][-2:] == ["rtl-tcp", "scan"]
    assert "Recreating rtl-tcp" in capsys.readouterr().out


def test_start_leaves_healthy_and_absent_scanners_alone(project, monkeypatch):
    (project / setup.STATE).write_text(setup.render({"sdr": SDR}))
    with_model(project)
    monkeypatch.setattr(setup, "discover", inventory(REPLUGGED))
    real = setup.run
    ups = []
    answers = iter(
        [
            "[]",
            json.dumps(
                [
                    {"Service": n, "State": "running", "Health": "healthy"}
                    for n in ("rtl-tcp", "scan")
                ]
            ),
        ]
    )

    def command(args, **kwargs):
        if "up" in args:
            ups.append(args)
            return ""
        if args[-3:] == ["ps", "--format", "json"]:
            return next(answers)
        return real(args, **kwargs)

    monkeypatch.setattr(setup, "run", command)
    setup.start(project)  # nothing running yet: a fresh install
    assert len(ups) == 1 and "--force-recreate" not in ups[0]


def test_wifi_with_a_new_phy_is_refreshed_by_check(project, monkeypatch):
    (project / setup.STATE).write_text(setup.render({"wifi": WIFI}))
    moved = WIFI | {"phy": "phy4"}
    monkeypatch.setattr(setup, "discover", inventory(wifi=[moved]))
    assert setup.check(project) == {"wifi": moved}
    assert (project / setup.STATE).read_text() == setup.render({"wifi": moved})


def test_refresh_keeps_a_differing_pending_intent_and_the_overlay(project, monkeypatch):
    (project / setup.STATE).write_text(setup.render({"sdr": SDR}))
    (project / setup.PENDING).write_text(setup.pending_text({"wifi": WIFI}))
    with_model(project)
    before = {
        name: (project / name).read_bytes() for name in (setup.STATE, setup.PENDING)
    }
    monkeypatch.setattr(setup, "discover", inventory(REPLUGGED, wifi=[WIFI]))
    with pytest.raises(setup.SetupError, match="Pending scanner intent differs"):
        setup.check(project)
    assert {name: (project / name).read_bytes() for name in before} == before


def test_running_supervisor_on_the_replugged_receiver_is_adopted(owned, monkeypatch):
    # rtl_tcp already reopened the receiver under its new number; usbfs owns
    # it. Setup must recognise its own container instead of refusing.
    actual = Path.lstat
    status = SimpleNamespace(st_mode=stat.S_IFCHR | 0o660, st_rdev=123, st_ino=123)
    monkeypatch.setattr(
        Path,
        "lstat",
        lambda path: status if str(path) == REPLUGGED["device"] else actual(path),
    )
    owned.device = REPLUGGED["device"]
    owned.inventory["sdr"][0].update(device=REPLUGGED["device"], gid=47)
    found = copy.deepcopy(owned.inventory["sdr"])
    assert setup.managed_rtl_devices(owned.root, found) == [REPLUGGED | {"reasons": []}]
    assert setup.plan(owned.root, "saved") == {"sdr": REPLUGGED}
    assert setup.saved_selection(owned.root) == {"sdr": SDR}
    assert all(call[1] not in {"stop", "restart", "start"} for call in owned.calls)


@pytest.mark.parametrize(
    "change",
    [
        {"usb": "1-3"},
        {"identity": C64},
        {"device": "/dev/bus/usb/002/007"},
    ],
)
def test_usbfs_exception_still_needs_the_same_port_identity_and_bus(owned, change):
    owned.inventory["sdr"][0].update(change)
    found = copy.deepcopy(owned.inventory["sdr"])
    assert setup.managed_rtl_devices(owned.root, found) == found
    assert not any(call[:2] == ["docker", "exec"] for call in owned.calls)


# ── Swap: a different identity is refused ───────────────────────────


def test_swapped_receiver_is_refused_with_reselection_guidance(project, monkeypatch):
    (project / setup.STATE).write_text(setup.render({"sdr": SDR}))
    with_model(project)
    before = (project / setup.STATE).read_bytes()
    other = REPLUGGED | {"identity": C64}
    monkeypatch.setattr(setup, "discover", inventory(other))
    with pytest.raises(setup.SetupError) as error:
        setup.check(project)
    message = str(error.value)
    assert "unavailable or ambiguous" in message
    assert "different sdr device is now at the saved USB port 1-2" in message
    assert "re-run: bash scripts/quickstart.sh --scanners=sdr" in message
    assert C64 not in message and A64 not in message
    assert "/dev/bus/usb" not in message
    assert (project / setup.STATE).read_bytes() == before


def test_swapped_wifi_adapter_is_refused_with_reselection_guidance(
    project, monkeypatch
):
    (project / setup.STATE).write_text(setup.render({"sdr": SDR, "wifi": WIFI}))
    with_model(project)
    before = (project / setup.STATE).read_bytes()
    other = WIFI | {"identity": C64, "phy": "phy2"}
    monkeypatch.setattr(setup, "discover", inventory(SDR, wifi=[other]))
    with pytest.raises(setup.SetupError) as error:
        setup.check(project)
    message = str(error.value)
    assert "different wifi device is now at the saved interface wlan1" in message
    assert "--scanners=sdr,wifi --wifi-interface=wlan1" in message
    assert C64 not in message and B64 not in message
    assert (project / setup.STATE).read_bytes() == before
    # The plain retry quickstart runs refuses it the same way.
    with pytest.raises(setup.SetupError, match="different wifi device"):
        setup.selection_from(
            inventory(SDR, wifi=[other])(), "sdr,wifi", {"sdr": SDR, "wifi": WIFI}
        )


def test_absent_hardware_keeps_the_previous_refusal():
    with pytest.raises(setup.SetupError) as error:
        setup.selection_from(inventory()(), "sdr", {"sdr": SDR})
    assert "different" not in str(error.value)
    assert "Check connected devices" in str(error.value)


# ── Older overlay format ─────────────────────────────────────────────


def test_previous_format_is_recognised_and_only_exact_text_counts(tmp_path):
    target = tmp_path / setup.STATE
    target.write_text(LEGACY_TEXT)
    assert setup.render_format({"sdr": SDR, "wifi": WIFI}, legacy=True) == LEGACY_TEXT
    assert setup.saved_overlay(tmp_path) == ({"sdr": SDR, "wifi": WIFI}, False)
    assert setup.saved_selection(tmp_path) == {"sdr": SDR, "wifi": WIFI}
    for edited in (
        LEGACY_TEXT + "# operator customization\n",
        # Old text claiming the new version, and new text claiming the old one.
        LEGACY_TEXT.replace('"version": 2}', '"version": 4}'),
        setup.render({"sdr": SDR, "wifi": WIFI}).replace(
            '"version": 4}', '"version": 2}'
        ),
        LEGACY_TEXT.replace('"version": 2}', '"version": 5}'),
    ):
        target.write_text(edited)
        with pytest.raises(setup.SetupError, match="edited"):
            setup.saved_selection(tmp_path)
        assert target.read_text() == edited


def test_quickstart_install_upgrades_the_previous_format(project, monkeypatch):
    (project / setup.STATE).write_text(LEGACY_TEXT)
    with_model(project)
    monkeypatch.setattr(setup, "discover", inventory(SDR, wifi=[WIFI]))
    real = setup.run
    monkeypatch.setattr(
        setup,
        "run",
        lambda args, **kwargs: "" if "ps" in args else real(args, **kwargs),
    )
    selection = setup.plan(project, "saved")
    assert selection == {"sdr": SDR, "wifi": WIFI}
    setup.remember(project, selection)
    setup.install(project, selection)
    assert setup.saved_overlay(project) == (selection, True)
    assert (project / setup.STATE).read_text() == setup.render(selection)


def test_check_upgrades_the_previous_format_for_unattended_restarts(
    project, monkeypatch
):
    (project / setup.STATE).write_text(LEGACY_TEXT)
    with_model(project)
    monkeypatch.setattr(setup, "discover", inventory(SDR, wifi=[WIFI]))
    assert setup.check(project) == {"sdr": SDR, "wifi": WIFI}
    assert setup.saved_overlay(project) == ({"sdr": SDR, "wifi": WIFI}, True)
    assert compose_config(project)["services"]["rtl-tcp"]["command"] == SUPERVISOR


def legacy_owner(owned):
    (owned.root / setup.STATE).write_text(
        setup.render_format({"sdr": SDR}, legacy=True)
    )
    owned.owner["devices"] = [
        {
            "PathOnHost": SDR["device"],
            "PathInContainer": SDR["device"],
            "CgroupPermissions": "rw",
        }
    ]
    owned.state.update(path="rtl_tcp", args=["-a", "0.0.0.0", "-d", "0"])
    owned.mode = "legacy"


def test_running_previous_format_container_is_still_recognised(owned):
    legacy_owner(owned)
    found = copy.deepcopy(owned.inventory["sdr"])
    assert setup.managed_rtl_devices(owned.root, found) == [SDR | {"reasons": []}]
    assert sum(call[:2] == ["docker", "exec"] for call in owned.calls) == 1


@pytest.mark.parametrize("change", ["bus-mapping", "supervisor", "new-device"])
def test_previous_format_keeps_its_exact_single_node_checks(owned, change):
    legacy_owner(owned)
    if change == "bus-mapping":
        owned.owner["devices"] = [
            {
                "PathOnHost": usbfs.BUS,
                "PathInContainer": usbfs.BUS,
                "CgroupPermissions": "rw",
            }
        ]
    elif change == "supervisor":
        owned.state.update(path=SUPERVISOR[0], args=SUPERVISOR[1:])
    else:
        # The old container mapped one node; it cannot hold a new one.
        owned.inventory["sdr"][0]["device"] = REPLUGGED["device"]
        found = copy.deepcopy(owned.inventory["sdr"])
        assert setup.managed_rtl_devices(owned.root, found) == found
        return
    found = copy.deepcopy(owned.inventory["sdr"])
    with pytest.raises(setup.SetupError, match="Cannot verify the saved rtl-tcp"):
        setup.managed_rtl_devices(owned.root, found)
    assert not any(call[:2] == ["docker", "exec"] for call in owned.calls)


def compose_configs(owned):
    """Answer install's two Compose merges; core services are unchanged."""
    strict = setup.run

    def command(args, **kwargs):
        if args[:2] == ["docker", "compose"] and args[-5:] == [
            "--profile",
            "hardware",
            "config",
            "--format",
            "json",
        ]:
            env = {"MLRF_MODEL_PATH": "/app/models/open-default.onnx"}
            return json.dumps(
                {
                    "services": {name: {} for name in setup.CORE}
                    | {"scan": {"environment": env}}
                }
            )
        return strict(args, **kwargs)

    return command


def test_upgrade_while_the_previous_container_runs_then_start_succeeds(
    owned, monkeypatch
):
    # Quickstart writes the new overlay while the previous rtl-tcp (rtl_tcp as
    # PID 1, one mapped node) still holds the receiver; nothing recreates it
    # before the next start, which must still recognise it.
    legacy_owner(owned)
    with_model(owned.root)
    monkeypatch.setattr(setup, "run", compose_configs(owned))
    selection = setup.plan(owned.root, "saved")
    assert selection == {"sdr": SDR}
    setup.remember(owned.root, selection)
    setup.install(owned.root, selection)
    assert setup.saved_overlay(owned.root) == ({"sdr": SDR}, True)
    owned.calls.clear()
    setup.start(owned.root)
    assert setup.saved_overlay(owned.root) == ({"sdr": SDR}, True)
    probes = [call for call in owned.calls if call[:2] == ["docker", "exec"]]
    assert len(probes) == 1 and probes[0][-1] == "legacy"
    # The `up` then recreates rtl-tcp under the new overlay.
    assert sum("up" in call for call in owned.calls) == 1


def test_previous_format_overlay_adopts_a_supervised_container(owned):
    (owned.root / setup.STATE).write_text(
        setup.render_format({"sdr": SDR}, legacy=True)
    )
    found = copy.deepcopy(owned.inventory["sdr"])
    assert setup.managed_rtl_devices(owned.root, found) == [SDR | {"reasons": []}]


@pytest.mark.parametrize(
    "change",
    ["other-node", "node-with-supervisor", "bus-with-rtl-tcp", "replugged-node"],
)
def test_a_container_matching_neither_shape_is_refused_after_upgrade(
    owned, monkeypatch, change
):
    def node(path):
        return {"PathOnHost": path, "PathInContainer": path, "CgroupPermissions": "rw"}

    if change in {"other-node", "replugged-node"}:
        legacy_owner(owned)
        # The upgrade already saved the new-format overlay.
        (owned.root / setup.STATE).write_text(setup.render({"sdr": SDR}))
    if change == "other-node":
        owned.owner["devices"] = [node("/dev/bus/usb/001/005")]
    elif change == "node-with-supervisor":
        owned.owner["devices"] = [node(SDR["device"])]
    elif change == "bus-with-rtl-tcp":
        owned.state.update(path="rtl_tcp", args=["-a", "0.0.0.0", "-d", "0"])
    else:
        # The old container mapped the old node; it cannot own a new one,
        # even though usbfs holds the receiver under its new number.
        actual = Path.lstat
        status = SimpleNamespace(st_mode=stat.S_IFCHR | 0o660, st_rdev=123, st_ino=123)
        monkeypatch.setattr(
            Path,
            "lstat",
            lambda path: status if str(path) == REPLUGGED["device"] else actual(path),
        )
        owned.inventory["sdr"][0]["device"] = REPLUGGED["device"]
    found = copy.deepcopy(owned.inventory["sdr"])
    with pytest.raises(setup.SetupError, match="Cannot verify the saved rtl-tcp"):
        setup.managed_rtl_devices(owned.root, found)
    assert not any(call[:2] == ["docker", "exec"] for call in owned.calls)


# ── Receiver group with a bus mapping ────────────────────────────────

SERIAL = "synthetic-serial"
REAL_ID = hashlib.sha256(f"0bda:2838:{SERIAL}".encode()).hexdigest()


def usb_bus(tmp_path, monkeypatch, gid, *, others=(), devnum=7):
    """Real sysfs/dev files; only character-device metadata is injected.

    others: (name, gid, mode) of further nodes on bus 001.
    """
    entry = tmp_path / "sys/bus/usb/devices/1-2"
    entry.mkdir(parents=True)
    for name, value in {
        "idVendor": "0bda",
        "idProduct": "2838",
        "busnum": "1",
        "devnum": str(devnum),
        "dev": f"189:{devnum}",
        "serial": SERIAL,
    }.items():
        (entry / name).write_text(value)
    bus = tmp_path / "dev/bus/usb/001"
    bus.mkdir(parents=True)
    fakes = {}
    for name, group, mode, minor in [(f"{devnum:03d}", gid, 0o660, devnum)] + [
        (name, group, mode, 100 + index)
        for index, (name, group, mode) in enumerate(others)
    ]:
        (bus / name).write_bytes(b"")
        fakes[str(bus / name)] = SimpleNamespace(
            st_mode=stat.S_IFCHR | mode,
            st_uid=0,
            st_gid=group,
            st_rdev=(189 << 8) | minor,
        )
    actual = Path.lstat
    monkeypatch.setattr(
        Path, "lstat", lambda path: fakes.get(str(path)) or actual(path)
    )
    monkeypatch.setattr(
        setup, "os", SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
    )
    monkeypatch.setattr(setup.os, "major", lambda value: value >> 8)
    monkeypatch.setattr(setup.os, "minor", lambda value: value & 0xFF)
    return tmp_path / "sys", tmp_path / "dev"


@pytest.mark.parametrize(
    "gid,others,ready",
    [
        (0, [("001", 0, 0o664)], False),  # stock udev: root:root 0664
        (0, [], False),
        (47, [("001", 0, 0o664), ("003", 47, 0o660)], False),
        (47, [("003", 47, 0o640)], False),
        (47, [("003", 47, 0o620)], False),
        # plugdev on the receiver only; the root hub stays root:root.
        (47, [("001", 0, 0o664), ("002", 48, 0o660)], True),
        (47, [("003", 47, 0o600)], True),
    ],
)
def test_receiver_group_must_belong_to_the_receiver_alone(
    tmp_path, monkeypatch, gid, others, ready
):
    sysfs, dev = usb_bus(tmp_path, monkeypatch, gid, others=others)
    [item] = setup.rtl_devices(sysfs, dev)
    assert item["gid"] == gid
    assert (item["reasons"] == []) is ready
    if ready:
        return
    assert item["reasons"] == [setup.SHARED_GROUP]
    with pytest.raises(setup.SetupError) as error:
        setup.selection_from({"sdr": [item], "wifi": [], "reasons": []}, "sdr", None)
    assert "sudo python3 scripts/scanner_setup.py prepare-rtl --usb=1-2" in str(
        error.value
    )
    assert SERIAL not in str(error.value) and REAL_ID not in str(error.value)


def test_unreadable_bus_directory_is_not_assumed_safe(tmp_path, monkeypatch):
    sysfs, dev = usb_bus(tmp_path, monkeypatch, 47)
    monkeypatch.setattr(
        Path,
        "iterdir",
        lambda path: (_ for _ in ()).throw(PermissionError("synthetic")),
    )
    assert setup.rtl_devices(sysfs, dev)[0]["reasons"] == [setup.SHARED_GROUP]


def replug_project(project, monkeypatch, gid, others=()):
    saved = {
        "usb": "1-2",
        "identity": REAL_ID,
        "device": "/dev/bus/usb/001/004",
        "gid": 46,
    }
    (project / setup.STATE).write_text(setup.render({"sdr": saved}))
    with_model(project)
    sysfs, dev = usb_bus(project / "host", monkeypatch, gid, others=others)

    def discover():
        # Saved selections name the host's /dev; the tree lives under tmp.
        found = setup.rtl_devices(sysfs, dev)
        for item in found:
            item["device"] = item["device"].replace(str(dev), "/dev")
        return {"sdr": found, "wifi": [], "reasons": []}

    monkeypatch.setattr(setup, "discover", discover)
    return saved


@pytest.mark.parametrize(
    "gid,others", [(0, [("001", 0, 0o664)]), (47, [("003", 47, 0o660)])]
)
def test_check_refuses_a_changed_group_that_is_not_the_receivers_alone(
    project, monkeypatch, gid, others
):
    replug_project(project, monkeypatch, gid, others)
    before = (project / setup.STATE).read_bytes()
    with pytest.raises(setup.SetupError) as error:
        setup.check(project)
    assert "prepare-rtl --usb=1-2" in str(error.value)
    assert (project / setup.STATE).read_bytes() == before


def test_check_still_refreshes_a_new_device_number_and_own_group(project, monkeypatch):
    saved = replug_project(project, monkeypatch, 47, [("001", 0, 0o664)])
    refreshed = saved | {"device": "/dev/bus/usb/001/007", "gid": 47}
    assert setup.check(project) == {"sdr": refreshed}
    assert setup.saved_selection(project) == {"sdr": refreshed}


# ── Printed udev rule ────────────────────────────────────────────────


def udev_tree(tmp_path, monkeypatch, *, serial=SERIAL, vendor="0bda"):
    import grp

    entry = tmp_path / "sys/bus/usb/devices/1-1.3"
    entry.mkdir(parents=True)
    (entry / "idVendor").write_text(vendor + "\n")
    (entry / "idProduct").write_text("2838\n")
    if serial is not None:
        (entry / "serial").write_text(serial + "\n")
    monkeypatch.setattr(grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=46))
    return tmp_path / "sys"


def test_printed_udev_rule_matches_exactly_that_receiver(tmp_path, monkeypatch):
    sysfs = udev_tree(tmp_path, monkeypatch)
    before = sorted(path for path in tmp_path.rglob("*"))
    rule = setup.udev_rule("1-1.3", sysfs=sysfs)
    lines = rule.splitlines()
    assert all(line.startswith("#") for line in lines[:-1])
    assert lines[-1] == (
        'SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_device", KERNEL=="1-1.3", '
        'ATTR{idVendor}=="0bda", ATTR{idProduct}=="2838", '
        'ATTR{serial}=="synthetic-serial", GROUP="plugdev", MODE="0660"'
    )
    comments = "\n".join(lines[:-1])
    assert "/etc/udev/rules.d/70-sigrift-sdr.rules" in comments
    assert "udevadm control --reload-rules" in comments
    assert "re-plug" in comments and "udevadm trigger" in comments
    assert "To undo: delete that file" in comments
    assert sorted(path for path in tmp_path.rglob("*")) == before


@pytest.mark.parametrize(
    "usb,serial,vendor,match",
    [
        ("1-1.3", 'abc"def', "0bda", "escaped"),
        ("1-1.3", "abc*", "0bda", "escaped"),
        ("1-1.3", "abc def", "0bda", "escaped"),
        ("1-1.3", "abc\\x", "0bda", "escaped"),
        ("1-1.3", "", "0bda", "no serial"),
        ("1-1.3", None, "0bda", "no serial"),
        ("1-1.3", SERIAL, "1234", "No supported RTL receiver"),
        ("1-9", SERIAL, "0bda", "No supported RTL receiver"),
        ('1-1.3"', SERIAL, "0bda", "--usb"),
        ("1-1.3*", SERIAL, "0bda", "--usb"),
    ],
)
def test_udev_rule_refuses_instead_of_escaping(
    tmp_path, monkeypatch, usb, serial, vendor, match
):
    sysfs = udev_tree(tmp_path, monkeypatch, serial=serial, vendor=vendor)
    with pytest.raises(setup.SetupError, match=match) as error:
        setup.udev_rule(usb, sysfs=sysfs)
    if serial:
        assert serial not in str(error.value)


def test_udev_rule_refuses_without_plugdev(tmp_path, monkeypatch):
    import grp

    sysfs = udev_tree(tmp_path, monkeypatch)
    monkeypatch.setattr(grp, "getgrnam", lambda _: (_ for _ in ()).throw(KeyError()))
    with pytest.raises(setup.SetupError, match="plugdev group is missing"):
        setup.udev_rule("1-1.3", sysfs=sysfs)


def test_cli_prints_the_rule_without_root_or_preparation(tmp_path, monkeypatch, capsys):
    sysfs = udev_tree(tmp_path, monkeypatch)
    real = setup.udev_rule
    monkeypatch.setattr(setup, "udev_rule", lambda usb: real(usb, sysfs=sysfs))
    monkeypatch.setattr(
        setup,
        "prepare_rtl",
        lambda *_: pytest.fail("prepare-rtl must not run for --print-udev-rule"),
    )
    monkeypatch.setattr(setup.signal, "signal", lambda *_: None)
    monkeypatch.setattr(
        sys,
        "argv",
        ["scanner_setup.py", "prepare-rtl", "--usb=1-1.3", "--print-udev-rule"],
    )
    assert setup.main() == 0
    assert capsys.readouterr().out.splitlines()[-1].startswith('SUBSYSTEM=="usb"')
    monkeypatch.setattr(sys, "argv", ["scanner_setup.py", "check", "--print-udev-rule"])
    assert setup.main() == 1
    assert "works only with prepare-rtl" in capsys.readouterr().err


# ── Ownership boundaries with a bus mapping ──────────────────────────


@pytest.mark.parametrize(
    "devices,exposed",
    [
        ([{"PathOnHost": "/dev/bus/usb/001"}], True),
        ([{"PathOnHost": "/dev/bus/usb"}], True),
        ([{"PathOnHost": REPLUGGED["device"]}], False),
        ([{"PathOnHost": "/dev/bus/usb/002"}], False),
    ],
)
def test_foreign_bus_mapping_still_blocks_and_other_buses_do_not(
    tmp_path, monkeypatch, devices, exposed
):
    planner.ownership_boundary(monkeypatch, [planner.container_owner(devices=devices)])
    if exposed:
        with pytest.raises(setup.SetupError, match="another running container"):
            setup.verify_ownership(tmp_path, {"sdr": SDR})
    else:
        assert setup.verify_ownership(tmp_path, {"sdr": SDR}) == []


def test_own_bus_mapped_rtl_tcp_is_the_owner_of_a_replugged_node(tmp_path, monkeypatch):
    row = planner.container_owner(
        project="this-checkout",
        service="rtl-tcp",
        devices=[{"PathOnHost": "/dev/bus/usb/001"}],
    )
    planner.ownership_boundary(monkeypatch, [row])
    assert setup.verify_ownership(tmp_path, {"sdr": REPLUGGED}) == [row]


# ── Embedded process probe ───────────────────────────────────────────


def fake_proc(root, *, supervisor=True, ppid=1, exe="/usr/bin/rtl_tcp", argv=None):
    """A /proc layout of real files and symlinks; /dev/null is the receiver."""
    first = root / "1"
    (first / "fd").mkdir(parents=True)
    (first / "cmdline").write_bytes(
        b"\0".join(
            [part.encode() for part in SUPERVISOR] + [b""]
            if supervisor
            else [b"rtl_tcp", b"-a", b"0.0.0.0", b"-d", b"0", b""]
        )
    )
    child = root / "7"
    (child / "fd").mkdir(parents=True)
    (child / "status").write_text(f"Name:\trtl_tcp\nPid:\t7\nPPid:\t{ppid}\n")
    (child / "comm").write_text("rtl_tcp\n")
    (child / "exe").symlink_to(exe)
    (child / "cmdline").write_bytes(
        b"\0".join(argv or [b"rtl_tcp", b"-a", b"0.0.0.0", b"-d", b"0", b""])
    )
    (child / "fd/5").symlink_to("/dev/null")
    (root / "self").mkdir()
    return child


def probe_namespace():
    namespace = {"__name__": "probe_test"}
    exec(compile(setup.RTL_FD_PROBE, "<shipped RTL FD probe>", "exec"), namespace)
    node = Path("/dev/null").stat()
    return namespace, (os.major(node.st_rdev), os.minor(node.st_rdev))


@pytest.mark.parametrize(
    "change",
    [
        None,
        "legacy-pid1",
        "orphan",
        "wrong-executable",
        "wrong-command",
        "closed",
        "only-pid1-holds",
        "other-device",
    ],
)
def test_supervised_probe_requires_the_supervisors_rtl_tcp_child(tmp_path, change):
    namespace, expected = probe_namespace()
    child = fake_proc(
        tmp_path,
        supervisor=change != "legacy-pid1",
        ppid=0 if change == "orphan" else 1,
        exe="/bin/sh" if change == "wrong-executable" else "/usr/bin/rtl_tcp",
        argv=[b"sh", b"-c", b"rtl_tcp", b""] if change == "wrong-command" else None,
    )
    if change in {"closed", "only-pid1-holds"}:
        (child / "fd/5").unlink()
    if change == "only-pid1-holds":
        (tmp_path / "1/fd/5").symlink_to("/dev/null")
    if change == "other-device":
        (child / "fd/5").unlink()
        (child / "fd/5").symlink_to("/dev/zero")
    owned = namespace["supervised_owns_device"](tmp_path, Path("/dev/null"), expected)
    assert owned is (change is None)


def test_probe_without_a_known_mode_reports_not_owned(tmp_path):
    for mode in ([], ["bogus"]):
        result = subprocess.run(
            [sys.executable, "-c", setup.RTL_FD_PROBE, "/dev/null", "1", "3", *mode],
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT,
        )
        assert result.stdout == "not-owned\n"
