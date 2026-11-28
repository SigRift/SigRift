"""Safe scanner planning with real filesystem and Compose merge boundaries.

Hardware command responses are fixtures, not a physical capture claim. Compose
configuration is the real CLI; daemon-changing calls are never made here.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time

import pytest
import test_quickstart_model_download as model_transfers

release_server = model_transfers.release_server

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "scanner_setup_tested", ROOT / "scripts/scanner_setup.py"
)
setup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(setup)
WIFI = {"interface": "wlan1", "phy": "phy1", "identity": "b" * 64}
SDR = {"usb": "1-2", "identity": "a" * 64, "device": "/dev/bus/usb/001/004", "gid": 46}


def found(*, wifi=True, sdr=True):
    return {
        "sdr": [SDR | {"reasons": []}] if sdr else [],
        "wifi": [WIFI | {"reasons": []}] if wifi else [],
        "reasons": [],
    }


@pytest.fixture
def clean(monkeypatch):
    for name in list(os.environ):
        if (
            name.startswith(("COMPOSE_", "DOCKER_", "SIGRIFT_", "BRIDGE_", "UC_"))
            or name == "SSH_CONNECTION"
        ):
            monkeypatch.delenv(name)


@pytest.fixture
def project(tmp_path, monkeypatch, clean):
    shutil.copyfile(ROOT / "docker-compose.yml", tmp_path / "docker-compose.yml")
    # Private unrelated configuration must stay byte-for-byte unchanged.
    (tmp_path / ".env").write_text(
        "BRIDGE_ADMIN_PASSWORD=operator-secret\nUC_PORT=9444\n"
    )
    (tmp_path / "docker-compose.override.yml").write_text(
        "services:\n  edge:\n    environment:\n      OPERATOR_SETTING: keep-me\n"
    )
    monkeypatch.chdir(tmp_path)
    actual_run = setup.run

    def command(args, **kwargs):
        # Inventory of running containers is a daemon boundary; Compose merges
        # below still execute the installed, real configuration parser.
        if args == ["docker", "ps", "--quiet", "--no-trunc"]:
            return ""
        return actual_run(args, **kwargs)

    monkeypatch.setattr(setup, "run", command)
    return tmp_path


def test_auto_only_selects_unambiguous_ready_hardware():
    inventory = found()
    assert setup.selection_from(inventory, "auto") == {"sdr": SDR, "wifi": WIFI}
    inventory["wifi"][0]["reasons"] = ["radio carries SSH"]
    assert setup.selection_from(inventory, "auto") == {"sdr": SDR}
    inventory["sdr"].append(SDR | {"usb": "1-3", "reasons": []})
    assert setup.selection_from(inventory, "auto") == {}
    with pytest.raises(setup.SetupError, match="unavailable or ambiguous"):
        setup.selection_from(inventory, "sdr")


def test_explicit_wifi_choice_and_saved_identity_cannot_silently_switch():
    inventory = found(sdr=False)
    inventory["wifi"].append(
        {"interface": "wlan2", "phy": "phy2", "identity": "c" * 64, "reasons": []}
    )
    assert setup.selection_from(inventory, "wifi", wifi_interface="wlan1") == {
        "wifi": WIFI
    }
    assert setup.selection_from(inventory, "wifi", {"wifi": WIFI}) == {"wifi": WIFI}
    inventory["wifi"] = inventory["wifi"][1:]
    with pytest.raises(setup.SetupError):
        setup.selection_from(inventory, "wifi", {"wifi": WIFI})


@pytest.mark.parametrize(
    "choice", ["bluetooth", "sdr,", "wifi;touch /tmp/unwanted", "all"]
)
def test_unknown_scanner_choice_is_rejected(choice):
    with pytest.raises(setup.SetupError):
        setup.selection_from(found(), choice)


def wifi_commands(
    monkeypatch, *, sysfs, routed="wlan0", ssh="wlan0", malformed=False, monitor=False
):
    # Real stable-identity metadata; ip/iw remain explicit command boundaries.
    for index, interfaces in ((0, ("wlan0", "sibling")), (1, ("wlan1",))):
        device = sysfs / "devices" / f"radio{index}"
        phy = device / "ieee80211" / f"phy{index}"
        phy.mkdir(parents=True, exist_ok=True)
        (phy / "macaddress").write_text(f"02:11:22:33:44:{index:02x}\n")
        for link, target in [
            (phy / "device", device),
            (sysfs / "class/ieee80211" / f"phy{index}", phy),
            *((sysfs / "class/net" / name / "phy80211", phy) for name in interfaces),
        ]:
            link.parent.mkdir(parents=True, exist_ok=True)
            link.unlink(missing_ok=True)
            link.symlink_to(target, target_is_directory=True)
    calls = []

    def command(args):
        calls.append(args)
        if args[:3] == ["ip", "-j", "address"]:
            return json.dumps([{"ifname": "wlan0", "addr_info": []}])
        if args[:3] == ["ip", "-j", "route"]:
            return json.dumps([{"dev": ssh}])
        if args[:2] == ["ip", "-j"]:
            if malformed:
                return "{}"
            return (
                json.dumps([{"dst": "default", "nexthops": [{"dev": routed}]}])
                if routed
                else "[]"
            )
        if args == ["iw", "dev"]:
            return (
                "phy#0\n\tInterface wlan0\n\t\ttype managed\n\tInterface sibling\n\t\ttype managed\nphy#1\n\tInterface wlan1\n\t\ttype "
                + ("monitor" if monitor else "managed")
                + "\n"
            )
        if args[:2] == ["iw", "phy"]:
            return "Supported interface modes:\n\t * managed\n\t * monitor\nBand 1:\n"
        if args[-1] == "link":
            assert not (monitor and args[2] == "wlan1"), (
                "monitor retries must not query unsupported link state"
            )
            return "Not connected.\n"
        raise AssertionError(args)

    monkeypatch.setattr(setup, "run", command)
    return calls


def test_route_and_ssh_protect_entire_phy_not_only_named_interface(
    tmp_path, monkeypatch, clean
):
    calls = wifi_commands(monkeypatch, sysfs=tmp_path, routed="eth0", ssh="wlan0")
    monkeypatch.setenv("SSH_CONNECTION", "192.0.2.5 50123 192.0.2.6 22")
    result = setup.wifi_devices(tmp_path)
    assert [item["interface"] for item in result if not item["reasons"]] == ["wlan1"]
    assert all(item["reasons"] for item in result if item["phy"] == "phy0")
    assert ["ip", "-j", "route", "get", "192.0.2.5"] in calls
    assert not any("set" in call or "down" in call for call in calls)


def test_default_multipath_protects_sibling_and_monitor_retry_is_read_only(
    tmp_path, monkeypatch, clean
):
    wifi_commands(monkeypatch, sysfs=tmp_path, monitor=True)
    result = setup.wifi_devices(tmp_path)
    assert [item["interface"] for item in result if not item["reasons"]] == ["wlan1"]


def test_incomplete_network_probes_fail_closed(tmp_path, monkeypatch, clean):
    wifi_commands(monkeypatch, sysfs=tmp_path, malformed=True)
    with pytest.raises(setup.SetupError, match="routes"):
        setup.wifi_devices(tmp_path)
    wifi_commands(monkeypatch, sysfs=tmp_path)
    monkeypatch.setenv("SSH_CONNECTION", "malformed")
    with pytest.raises(setup.SetupError, match="SSH client route"):
        setup.wifi_devices(tmp_path)


def test_rfkill_and_no_monitor_driver_are_not_ready(tmp_path, monkeypatch, clean):
    wifi_commands(monkeypatch, sysfs=tmp_path)
    flag = tmp_path / "class/ieee80211/phy1/rfkill7/soft"
    flag.parent.mkdir(parents=True)
    flag.write_text("1\n")
    result = setup.wifi_devices(tmp_path)
    assert "radio is blocked by rfkill" in result[-1]["reasons"]


def usb_tree(tmp_path):
    entry = tmp_path / "sys/bus/usb/devices/1-2"
    entry.mkdir(parents=True)
    for name, value in {
        "idVendor": "0bda",
        "idProduct": "2838",
        "busnum": "1",
        "devnum": "4",
        "dev": "189:3",
        "serial": "synthetic-serial",
    }.items():
        (entry / name).write_text(value)
    node = tmp_path / "dev/bus/usb/001/004"
    node.parent.mkdir(parents=True)
    node.write_bytes(b"regular file is deliberately not a USB device")
    return entry, node


def test_real_sysfs_files_identify_driver_and_refuse_non_device_node(tmp_path):
    entry, node = usb_tree(tmp_path)
    interface = entry.parent / "1-2:1.0"
    interface.mkdir()
    (interface / "driver").symlink_to("/sys/bus/usb/drivers/dvb_usb_rtl28xxu")
    before = {p: p.read_bytes() for p in entry.iterdir()}
    result = setup.rtl_devices(tmp_path / "sys", tmp_path / "dev")
    assert len(result) == 1
    assert result[0]["usb"] == "1-2"
    assert "kernel driver owns this receiver" in result[0]["reasons"]
    assert "USB path is not a character device" in result[0]["reasons"]
    assert {p: p.read_bytes() for p in entry.iterdir()} == before
    assert node.read_bytes().startswith(b"regular file")


def test_usb_permissions_use_numeric_device_group_without_chmod(tmp_path, monkeypatch):
    _, node = usb_tree(tmp_path)
    real_stat = Path.stat
    calls = []
    from types import SimpleNamespace

    monkeypatch.setattr(
        setup, "os", SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
    )
    monkeypatch.setattr(setup.os, "major", lambda _: 189)
    monkeypatch.setattr(setup.os, "minor", lambda _: 3)

    def device_stat(path, *args, **kwargs):
        calls.append(path)
        if path == node:
            # Character-device metadata is a syscall boundary; no host device
            # is manufactured, opened, chmodded or claimed by this test.
            from types import SimpleNamespace

            return SimpleNamespace(
                st_mode=stat.S_IFCHR | 0o660,
                st_uid=0,
                st_gid=876,
                st_rdev=123456789,
            )
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", device_stat)
    result = setup.rtl_devices(tmp_path / "sys", tmp_path / "dev")
    assert result[0]["reasons"] == []
    assert result[0]["gid"] == 876
    assert node in calls


@pytest.mark.parametrize(
    "endpoint", ["ssh://operator@host", "tcp://127.0.0.1:2375", "https://host"]
)
def test_remote_docker_endpoint_never_implies_local_hardware(
    monkeypatch, clean, endpoint
):
    monkeypatch.setattr(setup.platform, "system", lambda: "Linux")
    monkeypatch.setenv("DOCKER_HOST", endpoint)
    monkeypatch.setattr(
        setup, "json_command", lambda _: pytest.fail("must reject before daemon info")
    )
    with pytest.raises(setup.SetupError, match="local Unix"):
        setup.native_docker()


def test_docker_context_precedence_and_native_identity(monkeypatch, clean):
    monkeypatch.setattr(setup.platform, "system", lambda: "Linux")
    monkeypatch.setenv("DOCKER_CONTEXT", "selected")
    monkeypatch.setenv("DOCKER_HOST", "ssh://ignored")
    calls = []

    def command(args):
        calls.append(args)
        if "context" in args:
            return "unix:///var/run/docker.sock"
        return {
            "OSType": "linux",
            "KernelVersion": setup.platform.release(),
            "Name": setup.socket.gethostname(),
            "SecurityOptions": [],
            "OperatingSystem": "Debian",
        }

    monkeypatch.setattr(setup, "json_command", command)
    setup.native_docker()
    assert calls[0][1] == "context"

    def rootless(args):
        result = command(args)
        if isinstance(result, dict):
            result["SecurityOptions"] = ["name=rootless"]
        return result

    monkeypatch.setattr(setup, "json_command", rootless)
    with pytest.raises(setup.SetupError, match="native, rootful"):
        setup.native_docker()


def test_managed_file_roundtrip_rejects_operator_changes_and_symlinks(tmp_path):
    target = tmp_path / setup.STATE
    target.write_text(setup.render({"wifi": WIFI}))
    assert setup.saved_selection(tmp_path) == {"wifi": WIFI}
    original = target.read_bytes()
    target.write_bytes(original + b"# operator customization\n")
    with pytest.raises(setup.SetupError, match="edited"):
        setup.saved_selection(tmp_path)
    assert target.read_bytes() == original + b"# operator customization\n"
    target.unlink()
    operator = tmp_path / "operator.yml"
    operator.write_bytes(original)
    target.symlink_to(operator)
    with pytest.raises(setup.SetupError, match="regular"):
        setup.saved_selection(tmp_path)
    assert operator.read_bytes() == original


def test_real_compose_overlay_narrows_usb_and_preserves_all_core_config(
    project, monkeypatch
):
    monkeypatch.setattr(setup, "discover", found)
    models = project / "models"
    models.mkdir()
    (models / "open-default.onnx").write_bytes(
        b"synthetic nonempty model; no inference claim"
    )
    (models / "open-default_metadata.json").write_text('{"classes": ["noise"]}')
    before = {
        name: (project / name).read_bytes()
        for name in (".env", "docker-compose.override.yml")
    }
    setup.install(project, {"sdr": SDR, "wifi": WIFI})
    assert setup.saved_selection(project) == {"sdr": SDR, "wifi": WIFI}
    assert stat.S_IMODE((project / setup.STATE).stat().st_mode) == 0o600
    config = setup.json_command(
        setup.compose_command(project, project / setup.STATE)
        + ["--profile", "hardware", "config", "--format", "json"]
    )
    rtl = config["services"]["rtl-tcp"]
    # Only the receiver's own bus directory, so a re-plug can come back.
    assert len(rtl["devices"]) == 1
    assert rtl["devices"][0]["source"] == "/dev/bus/usb/001"
    assert rtl["devices"][0]["target"] == "/dev/bus/usb/001"
    assert rtl["group_add"] == ["46"]
    assert rtl["command"] == ["python3", "-m", "sigrift.edge.rtl_tcp_supervisor"]
    assert rtl["environment"] == {
        "MLRF_SDR_USB": SDR["usb"],
        "MLRF_SDR_IDENTITY": SDR["identity"],
    }
    assert config["services"]["wifi-scan"]["environment"]["MLRF_WIFI_IFACE"] == "wlan1"
    assert (
        config["services"]["wifi-scan"]["environment"]["MLRF_WIFI_IDENTITY"]
        == WIFI["identity"]
    )
    assert config["services"]["gateway"]["ports"][0]["published"] == "9444"
    assert {name: (project / name).read_bytes() for name in before} == before
    # Ordinary Compose never enables hardware solely by loading the managed
    # overlay; quickstart must explicitly name the selected services.
    active = setup.run(
        setup.compose_command(project, project / setup.STATE) + ["config", "--services"]
    )
    assert set(active.splitlines()) == set(setup.CORE)


def test_missing_model_and_failed_publish_keep_previous_selection(project, monkeypatch):
    monkeypatch.setattr(setup, "discover", found)
    target = project / setup.STATE
    target.write_text(setup.render({"wifi": WIFI}))
    before = target.read_bytes()
    with pytest.raises(setup.SetupError, match="model is missing"):
        setup.install(project, {"sdr": SDR})
    assert target.read_bytes() == before
    # A model without its class-name metadata is refused the same way: the
    # scanner would not start with it.
    models = project / "models"
    models.mkdir()
    (models / "open-default.onnx").write_bytes(b"synthetic nonempty model")
    for sidecar in (None, b""):
        if sidecar is not None:
            (models / "open-default_metadata.json").write_bytes(sidecar)
        with pytest.raises(setup.SetupError, match="model metadata .* is missing or empty"):
            setup.install(project, {"sdr": SDR})
        assert target.read_bytes() == before
    (models / "open-default_metadata.json").unlink()
    (models / "open-default.onnx").unlink()
    models.rmdir()
    monkeypatch.setattr(
        setup.os,
        "replace",
        lambda *_: (_ for _ in ()).throw(OSError("synthetic publication failure")),
    )
    with pytest.raises(OSError):
        setup.install(project, {"wifi": WIFI})
    assert target.read_bytes() == before
    assert list(project.glob(".sigrift-scanners-*.yml")) == []


def test_custom_exposure_is_preserved_and_incompatible_wifi_fails(project, monkeypatch):
    monkeypatch.setattr(setup, "discover", found)
    with (project / ".env").open("a") as output:
        output.write("SIGRIFT_BIND=192.0.2.4\n")
    before = (project / ".env").read_bytes()
    with pytest.raises(setup.SetupError, match="never changes exposure"):
        setup.install(project, {"wifi": WIFI})
    assert (project / ".env").read_bytes() == before
    assert not (project / setup.STATE).exists()


def test_explicit_new_wifi_choice_replaces_only_managed_selection(project, monkeypatch):
    (project / setup.STATE).write_text(setup.render({"wifi": WIFI}))
    alternative = {"interface": "wlan2", "phy": "phy2", "identity": "c" * 64}
    monkeypatch.setattr(
        setup,
        "discover",
        lambda: {"sdr": [], "wifi": [alternative | {"reasons": []}], "reasons": []},
    )
    real_run = setup.run
    monkeypatch.setattr(
        setup,
        "run",
        lambda args, **kwargs: "" if "ps" in args else real_run(args, **kwargs),
    )
    assert setup.plan(project, "wifi", "wlan2") == {"wifi": alternative}
    with pytest.raises(setup.SetupError):
        setup.plan(project, "saved")


def test_start_checks_failure_and_uses_only_selected_services(tmp_path, monkeypatch):
    (tmp_path / setup.STATE).write_text(setup.render({"wifi": WIFI}))
    monkeypatch.setattr(setup, "discover", found)
    calls = []

    def command(args, **kwargs):
        calls.append(args)
        if "ps" in args:
            return json.dumps(
                {"Service": "wifi-scan", "State": "restarting", "Health": ""}
            )
        return ""

    monkeypatch.setattr(setup, "run", command)
    monkeypatch.setattr(setup, "compose_inputs", lambda _: None)
    monkeypatch.setattr(setup, "verify_ownership", lambda *_: None)
    with pytest.raises(setup.SetupError, match="failed to stay running"):
        setup.start(tmp_path)
    started = next(call for call in calls if "up" in call)
    assert started[-1] == "wifi-scan"
    assert "--no-deps" in started and "--no-build" in started
    assert not any(
        item in started
        for item in ("scan", "rtl-tcp", "bt-scan", "privileged", "chmod")
    )


def test_real_timed_out_command_and_its_child_are_killed(tmp_path):
    marker = tmp_path / "escaped"
    program = tmp_path / "spawn.py"
    program.write_text(
        "import subprocess,sys,time\nsubprocess.Popen([sys.executable,'-c',"
        + repr(
            "import time,pathlib; time.sleep(1); pathlib.Path("
            + repr(str(marker))
            + ").write_text('bad')"
        )
        + "])\ntime.sleep(10)\n"
    )
    with pytest.raises(setup.SetupError, match="deadline"):
        setup.run([sys.executable, str(program)], timeout=0.1)
    time.sleep(1.2)
    assert not marker.exists()


def test_existing_disabled_override_constrains_implicit_auto(project, monkeypatch):
    override = project / "docker-compose.override.yml"
    override.write_text(
        "services:\n"
        + "".join(
            f"  {name}:\n    profiles: [hardware]\n"
            for name in ("rtl-tcp", "scan", "wifi-scan", "bt-scan")
        )
    )
    before = override.read_bytes()
    monkeypatch.setattr(
        setup,
        "discover",
        lambda: pytest.fail("an explicit disabled override forbids hardware probing"),
    )
    real_run = setup.run
    monkeypatch.setattr(
        setup,
        "run",
        lambda args, **kwargs: "" if "ps" in args else real_run(args, **kwargs),
    )
    assert setup.plan(project, "auto", honor_profiles=True) == {}
    assert override.read_bytes() == before


def test_selected_removal_failure_preserves_saved_state(project, monkeypatch):
    target = project / setup.STATE
    target.write_text(setup.render({"wifi": WIFI}))
    before = target.read_bytes()
    real_run = setup.run

    def command(args, **kwargs):
        if "stop" in args:
            raise setup.SetupError("owned stop failed")
        return real_run(args, **kwargs)

    monkeypatch.setattr(setup, "run", command)
    with pytest.raises(setup.SetupError, match="owned stop failed"):
        setup.install(project, {})
    assert target.read_bytes() == before
    assert not list(project.glob(".sigrift-scanners-*.yml"))


def test_custom_dependency_cannot_start_unselected_scanners(project):
    (project / "docker-compose.override.yml").write_text(
        "services:\n  edge:\n    depends_on:\n      wifi-scan:\n        condition: service_started\n"
    )
    with pytest.raises(setup.SetupError, match="depends on a scanner"):
        setup.compose_inputs(project)


def test_real_cli_auto_core_build_then_retry_preserves_config(tmp_path, clean):
    checkout = tmp_path / "checkout"
    (checkout / "scripts").mkdir(parents=True)
    for name in ("quickstart.sh", "scanner_setup.py"):
        shutil.copyfile(ROOT / "scripts" / name, checkout / "scripts" / name)
    shutil.copyfile(ROOT / "docker-compose.yml", checkout / "docker-compose.yml")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "commands.jsonl"
    real_docker = shutil.which("docker")
    script = bindir / "docker"
    script.write_text(
        f"#!{sys.executable}\n"
        + f"real={real_docker!r}\nlog={str(log)!r}\n"
        + """
import json,os,sys
args=sys.argv[1:]
with open(log,'a') as output:
    output.write(json.dumps(args)+'\\n')
if args[:2]==['compose','version'] or ('compose' in args and 'config' in args):
    os.execv(real,[real,*args])
if args[:2]==['info','--format'] or args==['network','ls','-q'] or ('compose' in args and 'ps' in args):
    sys.exit(0)
if args[:2]==['volume','ls'] or (args[:1]==['ps'] and any(a in ('-a','-q') for a in args)):
    sys.exit(0)  # lc_identity's read-only queries: an empty host
# No daemon-changing command is permitted. Build is the deliberate boundary.
sys.exit(77 if 'build' in args else 97)
"""
    )
    script.chmod(0o700)
    (bindir / "curl").write_text("#!/bin/sh\necho unexpected-network >&2\nexit 96\n")
    (bindir / "curl").chmod(0o700)
    env = dict(
        os.environ,
        PATH=str(bindir) + os.pathsep + os.environ["PATH"],
        SIGRIFT_PRESET="none",
    )
    original = None
    for flags in (["--scanners=none"], []):
        result = subprocess.run(
            ["bash", str(checkout / "scripts/quickstart.sh"), *flags],
            input="disposable-scanner-password\ndisposable-scanner-password\n",
            text=True,
            capture_output=True,
            env=env,
            timeout=30,
        )
        assert result.returncode == 77, result.stderr
        assert "unexpected-network" not in result.stderr
        assert "disposable-scanner-password" not in result.stdout + result.stderr
        assert not (checkout / "models").exists()
        snapshot = {
            name: (checkout / name).read_bytes()
            for name in (".env", "docker-compose.override.yml", setup.STATE)
        }
        if original is None:
            original = snapshot
        else:
            assert snapshot == original
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    builds = [call for call in calls if "build" in call]
    assert len(builds) == 2
    assert all(call[call.index("build") + 1 :] == setup.CORE for call in builds)
    assert not any("up" in call or "stop" in call for call in calls)
    assert not any("--privileged" in call or "/dev/bus/usb" in call for call in calls)


def test_disposable_harnesses_and_ci_explicitly_disable_physical_scanners():
    import ast

    for name in ("scripts/test-candidate.py", "scripts/soak-candidate.py"):
        tree = ast.parse((ROOT / name).read_text())
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.List)
            and any(
                isinstance(value, ast.Constant)
                and value.value == "scripts/quickstart.sh"
                for value in node.elts
            )
        ]
        assert calls, name
        assert all(
            any(
                isinstance(value, ast.Constant) and value.value == "--scanners=none"
                for value in node.elts
            )
            for node in calls
        ), name
    workflow = (ROOT / ".github/workflows/quickstart-smoke.yml").read_text()
    assert "| scripts/quickstart.sh --scanners=none\n" in workflow


def preparation_fixture(tmp_path, monkeypatch, *, other_driver=False):
    import grp
    from types import SimpleNamespace

    entry, node = usb_tree(tmp_path)
    driver_root = tmp_path / "sys/bus/usb/drivers/dvb_usb_rtl28xxu"
    driver_root.mkdir(parents=True)
    unbind = driver_root / "unbind"
    unbind.write_text("")
    interface = entry.parent / "1-2:1.0"
    interface.mkdir()
    (interface / "driver").symlink_to(
        driver_root if not other_driver else driver_root.parent / "unexpected"
    )
    monkeypatch.setattr(setup.platform, "system", lambda: "Linux")
    # Keep injected character-device/ownership syscalls local to the tested
    # module: pytest's own file descriptors and process identity stay real.
    monkeypatch.setattr(
        setup, "os", SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
    )
    monkeypatch.setattr(setup.os, "geteuid", lambda: 0)
    monkeypatch.setattr(grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=876))
    real_stat = os.fstat

    def hardware_metadata(fd):
        original = real_stat(fd)
        return SimpleNamespace(
            st_mode=stat.S_IFCHR | stat.S_IMODE(original.st_mode),
            st_uid=0,
            st_rdev=123456789,
        )

    monkeypatch.setattr(setup.os, "fstat", hardware_metadata)
    monkeypatch.setattr(
        setup.os, "major", lambda value: 189 if value == 123456789 else os.major(value)
    )
    monkeypatch.setattr(
        setup.os, "minor", lambda value: 3 if value == 123456789 else os.minor(value)
    )
    changes = []
    monkeypatch.setattr(
        setup.os, "fchown", lambda fd, uid, gid: changes.append(("owner", uid, gid))
    )
    real_chmod = os.fchmod

    def permissions(fd, mode):
        changes.append(("mode", mode))
        real_chmod(fd, mode)

    monkeypatch.setattr(setup.os, "fchmod", permissions)
    return node, unbind, changes


def test_explicit_preparation_writes_only_selected_unbind_and_open_device(
    tmp_path, monkeypatch
):
    node, unbind, changes = preparation_fixture(tmp_path, monkeypatch)
    content = node.read_bytes()
    setup.prepare_rtl("1-2", sysfs=tmp_path / "sys", dev=tmp_path / "dev")
    assert unbind.read_text() == "1-2:1.0"
    assert changes == [("owner", -1, 876), ("mode", 0o660)]
    assert stat.S_IMODE(node.stat().st_mode) == 0o660
    assert node.read_bytes() == content
    # Emulate the kernel removing the interface's driver link after unbind:
    # repeat preparation is safe and never writes a global driver policy.
    (tmp_path / "sys/bus/usb/devices/1-2:1.0/driver").unlink()
    unbind.write_text("no second unbind")
    setup.prepare_rtl("1-2", sysfs=tmp_path / "sys", dev=tmp_path / "dev")
    assert unbind.read_text() == "no second unbind"


def test_preparation_refuses_unknown_driver_and_no_root_before_changes(
    tmp_path, monkeypatch
):
    _, unbind, changes = preparation_fixture(tmp_path, monkeypatch, other_driver=True)
    with pytest.raises(setup.SetupError, match="unexpected driver"):
        setup.prepare_rtl("1-2", sysfs=tmp_path / "sys", dev=tmp_path / "dev")
    assert unbind.read_text() == "" and changes == []
    monkeypatch.setattr(setup.os, "geteuid", lambda: 1000)
    with pytest.raises(setup.SetupError, match="requires native Linux root"):
        setup.prepare_rtl("1-2", sysfs=tmp_path / "sys", dev=tmp_path / "dev")
    assert unbind.read_text() == "" and changes == []


def test_preparation_partial_failure_is_explicit_and_retryable(tmp_path, monkeypatch):
    node, unbind, _ = preparation_fixture(tmp_path, monkeypatch)
    before = stat.S_IMODE(node.stat().st_mode)
    monkeypatch.setattr(
        setup.os,
        "fchown",
        lambda *_: (_ for _ in ()).throw(
            PermissionError("simulated device ownership failure")
        ),
    )
    with pytest.raises(setup.SetupError, match="may already have changed"):
        setup.prepare_rtl("1-2", sysfs=tmp_path / "sys", dev=tmp_path / "dev")
    assert unbind.read_text() == "1-2:1.0"
    assert stat.S_IMODE(node.stat().st_mode) == before


def test_preparation_refuses_a_symlinked_device_without_unbinding(
    tmp_path, monkeypatch
):
    node, unbind, changes = preparation_fixture(tmp_path, monkeypatch)
    target = node.with_name("operator-file")
    node.rename(target)
    node.symlink_to(target)
    with pytest.raises(OSError):
        setup.prepare_rtl("1-2", sysfs=tmp_path / "sys", dev=tmp_path / "dev")
    assert unbind.read_text() == "" and changes == []
    assert target.read_bytes().startswith(b"regular file")


def ownership_boundary(monkeypatch, rows, *, raw=None):
    calls = []
    ids = [str(index + 1).zfill(64) for index in range(len(rows))]
    for identity, row in zip(ids, rows):
        row.setdefault("id", identity)

    def command(args, **kwargs):
        calls.append(args)
        if args == ["docker", "compose", "config", "--format", "json"]:
            return json.dumps({"name": "this-checkout"})
        if args == ["docker", "ps", "--quiet", "--no-trunc"]:
            return "\n".join(ids)
        if args[:2] == ["docker", "inspect"]:
            assert args[2:4] == ["--format", setup.OWNER_FORMAT]
            assert args[4:] == ids
            return raw if raw is not None else "\n".join(map(json.dumps, rows))
        raise AssertionError(args)

    monkeypatch.setattr(setup, "run", command)
    return calls


def container_owner(**changes):
    return {
        "project": "other-checkout",
        "service": "unrelated",
        "devices": [],
        "rules": [],
        "privileged": False,
        "network": "bridge",
        "caps": [],
        "wifi": [],
    } | changes


@pytest.mark.parametrize(
    "changes",
    [
        {"devices": [{"PathOnHost": SDR["device"]}]},
        {"devices": [{"PathOnHost": "/dev/bus/usb"}]},
        {"rules": ["c 189:* rwm"]},
        {"privileged": True},
    ],
)
def test_another_container_with_usb_access_is_not_disrupted(
    tmp_path, monkeypatch, changes
):
    calls = ownership_boundary(monkeypatch, [container_owner(**changes)])
    with pytest.raises(setup.SetupError, match="another running container"):
        setup.verify_ownership(tmp_path, {"sdr": SDR})
    assert all(call[1] in {"compose", "ps", "inspect"} for call in calls)
    assert not any("stop" in call or "rm" in call or "up" in call for call in calls)


@pytest.mark.parametrize(
    "changes",
    [
        {"caps": ["NET_ADMIN"]},
        {"caps": ["CAP_NET_RAW"]},
        {"privileged": True},
        {"wifi": ["MLRF_WIFI_IFACE=wlan1"]},
        {
            "project": "this-checkout",
            "service": "wifi-scan",
            "wifi": ["MLRF_WIFI_IFACE=wlan2"],
        },
    ],
)
def test_existing_or_ambiguous_host_radio_owner_blocks_second_wifi_worker(
    tmp_path, monkeypatch, changes
):
    ownership_boundary(monkeypatch, [container_owner(network="host", **changes)])
    with pytest.raises(setup.SetupError, match="host-network container"):
        setup.verify_ownership(tmp_path, {"wifi": WIFI})


def test_same_project_selected_workers_allow_idempotent_retry(tmp_path, monkeypatch):
    ownership_boundary(
        monkeypatch,
        [
            container_owner(
                project="this-checkout",
                service="rtl-tcp",
                devices=[{"PathOnHost": SDR["device"]}],
            ),
            container_owner(
                project="this-checkout",
                service="wifi-scan",
                network="host",
                caps=["NET_ADMIN", "NET_RAW"],
                wifi=["MLRF_WIFI_IFACE=wlan1"],
            ),
            container_owner(network="host"),
            container_owner(devices=[{"PathOnHost": "/dev/dri/renderD128"}]),
        ],
    )
    setup.verify_ownership(tmp_path, {"sdr": SDR, "wifi": WIFI})


@pytest.mark.parametrize(
    "raw", ["", "{}", "invalid-json", '{"id":"wrong","privileged":false}', "[]"]
)
def test_incomplete_ownership_results_fail_closed(tmp_path, monkeypatch, raw):
    ownership_boundary(monkeypatch, [container_owner()], raw=raw)
    with pytest.raises(setup.SetupError, match="ownership data is incomplete"):
        setup.verify_ownership(tmp_path, {"sdr": SDR})


def test_container_inspection_never_requests_raw_environment_or_mutations(
    tmp_path, monkeypatch
):
    calls = ownership_boundary(monkeypatch, [container_owner()])
    setup.verify_ownership(tmp_path, {"sdr": SDR})
    template = next(call[3] for call in calls if call[1] == "inspect")
    assert "json .Config.Env" not in template
    assert "MLRF_WIFI_IFACE" in template
    assert "BRIDGE_ADMIN_PASSWORD" not in template and "MLRF_BRIDGE_KEY" not in template
    monkeypatch.setattr(
        setup,
        "run",
        lambda _: pytest.fail("none selection must not inspect other containers"),
    )
    setup.verify_ownership(tmp_path, {})


@pytest.mark.parametrize(
    "sibling_type,link",
    [
        ("managed", "Connected to 02:00:00:00:00:01\n"),
        ("AP", "Not connected.\n"),
        ("P2P-client", "Not connected.\n"),
    ],
)
def test_active_or_unknown_sibling_protects_entire_radio(
    tmp_path, monkeypatch, clean, sibling_type, link
):
    wifi_commands(monkeypatch, sysfs=tmp_path, routed="eth0", ssh="eth0")
    sibling = tmp_path / "class/net/sibling/phy80211"
    sibling.unlink()
    sibling.symlink_to(
        tmp_path / "devices/radio1/ieee80211/phy1", target_is_directory=True
    )
    boundary = setup.run

    def command(args):
        if args == ["iw", "dev"]:
            return f"phy#1\n\tInterface wlan1\n\t\ttype monitor\n\tInterface sibling\n\t\ttype {sibling_type}\n"
        if args == ["iw", "dev", "sibling", "link"]:
            return link
        return boundary(args)

    monkeypatch.setattr(setup, "run", command)
    result = setup.wifi_devices(tmp_path)
    assert len(result) == 2
    assert all(item["reasons"] for item in result)
    assert (
        setup.selection_from({"wifi": result, "sdr": [], "reasons": []}, "auto") == {}
    )


def test_usb_discovery_refuses_symlink_even_when_target_is_readable(tmp_path):
    _, node = usb_tree(tmp_path)
    target = node.with_name("target")
    node.rename(target)
    node.symlink_to(target)
    before = target.read_bytes()
    result = setup.rtl_devices(tmp_path / "sys", tmp_path / "dev")
    assert "USB path is not a character device" in result[0]["reasons"]
    assert target.read_bytes() == before


@pytest.mark.parametrize("device_identity", ["189:4", "1:3"])
def test_preparation_verifies_exact_kernel_device_before_unbind(
    tmp_path, monkeypatch, device_identity
):
    node, unbind, changes = preparation_fixture(tmp_path, monkeypatch)
    (tmp_path / "sys/bus/usb/devices/1-2/dev").write_text(device_identity)
    before = node.read_bytes()
    with pytest.raises(setup.SetupError, match="root-owned USB character device"):
        setup.prepare_rtl("1-2", sysfs=tmp_path / "sys", dev=tmp_path / "dev")
    assert unbind.read_text() == "" and changes == []
    assert node.read_bytes() == before


@pytest.mark.parametrize(
    "flags",
    [
        ["--scanners="],
        ["--scanners=none", "--scanners=sdr"],
        ["--wifi-interface="],
        ["--scanners=wifi", "--wifi-interface=wlan1", "--wifi-interface=wlan2"],
        ["--scanners=none", "--wifi-interface=wlan1"],
    ],
)
def test_ambiguous_options_fail_before_any_probe_or_file_change(tmp_path, flags):
    (tmp_path / "scripts").mkdir()
    script = tmp_path / "scripts/quickstart.sh"
    shutil.copyfile(ROOT / "scripts/quickstart.sh", script)
    before = script.read_bytes()
    result = subprocess.run(
        ["bash", str(script), *flags], capture_output=True, text=True, timeout=5
    )
    assert result.returncode == 2
    assert "Error:" in result.stderr
    assert sorted(path.name for path in tmp_path.iterdir()) == ["scripts"]
    assert script.read_bytes() == before


@pytest.mark.parametrize("state", ["missing", "edited", "legacy"])
def test_managed_tls_renewal_refuses_incomplete_selection_before_mutation(
    tmp_path, state
):
    # Real CLI and real mode/helper logic; only Docker prerequisite/config
    # commands are intercepted before the test reaches any TLS operation.
    from test_quickstart_preflight import Checkout

    checkout = Checkout(tmp_path)
    shutil.copyfile(
        ROOT / "scripts/scanner_setup.py", checkout.root / "scripts/scanner_setup.py"
    )
    checkout.existing_configuration()
    if state != "legacy":
        with (checkout.root / ".env").open("a") as output:
            output.write("SIGRIFT_QUICKSTART_MODE=auto\n")
    if state == "edited":
        (checkout.root / setup.STATE).write_text(setup.render({}) + "# edited\n")
    before = checkout.snapshot()
    result = checkout.run("--renew-tls")
    assert result.returncode == 1
    assert (
        "was edited" if state == "edited" else "selection is missing"
    ) in result.stderr
    assert checkout.snapshot() == before
    assert all(
        call["tool"] == "docker"
        and call["args"]
        in (
            ["compose", "version"],
            ["info", "--format", "{{.ServerVersion}}"],
            ["compose", "config", "--environment"],
        )
        for call in checkout.calls()
    )


@pytest.mark.parametrize(
    "missing", ["project", "service", "devices", "rules", "network", "caps", "wifi"]
)
def test_correct_id_with_missing_ownership_field_is_not_treated_as_unowned(
    tmp_path, monkeypatch, missing
):
    row = container_owner()
    del row[missing]
    ownership_boundary(monkeypatch, [row])
    with pytest.raises(setup.SetupError, match="ownership data is incomplete"):
        setup.verify_ownership(tmp_path, {"sdr": SDR, "wifi": WIFI})


def test_legitimate_null_docker_arrays_and_labels_are_accepted(tmp_path, monkeypatch):
    ownership_boundary(
        monkeypatch,
        [
            container_owner(
                project=None, service=None, devices=None, rules=None, caps=None
            )
        ],
    )
    setup.verify_ownership(tmp_path, {"sdr": SDR, "wifi": WIFI})


@pytest.mark.parametrize(
    "response", ["unsupported", "{}", '{"services":{"probe":{"profiles":[]}}}']
)
def test_unsupported_compose_override_is_actionable_before_planning(
    project, monkeypatch, response
):
    real_run = setup.run
    calls = []

    def command(args, **kwargs):
        calls.append((args, kwargs))
        if "-f" in args and args[args.index("-f") + 1] == "-":
            assert "!override" in kwargs["input"]
            if response == "unsupported":
                raise setup.SetupError("simulated older Compose rejects the YAML tag")
            return response
        if "ps" in args:
            return ""
        return real_run(args, **kwargs)

    monkeypatch.setattr(setup, "run", command)
    before = {path.name: path.read_bytes() for path in project.iterdir()}
    with pytest.raises(setup.SetupError, match=r"Compose 2\.24\.4\+.*!override"):
        setup.plan(project, "none")
    assert {path.name: path.read_bytes() for path in project.iterdir()} == before
    assert all("build" not in args and "up" not in args for args, _ in calls)


def test_real_cli_unsupported_compose_stops_before_password_and_files(tmp_path):
    from test_quickstart_preflight import Checkout

    checkout = Checkout(tmp_path)
    shutil.copyfile(
        ROOT / "scripts/scanner_setup.py", checkout.root / "scripts/scanner_setup.py"
    )
    shutil.copyfile(ROOT / "docker-compose.yml", checkout.root / "docker-compose.yml")
    checkout.command(
        "docker",
        """
        import json, os, sys
        args=sys.argv[1:]
        with open(os.environ['PREFLIGHT_COMMAND_LOG'],'a') as output:
            output.write(json.dumps({'tool':'docker','args':args})+'\\n')
        if args == ['compose','version'] or args == ['info','--format','{{.ServerVersion}}']:
            sys.exit(0)
        if args[:2] == ['volume','ls'] or (args[:1] == ['ps'] and any(a in ('-a','-q') for a in args)):
            sys.exit(0)  # lc_identity's read-only queries: an empty host
        if '-f' in args and args[args.index('-f')+1] == '-':
            assert '!override' in sys.stdin.read()
            sys.exit(3)
        sys.exit(97)
    """,
    )
    before = checkout.snapshot()
    result = checkout.run("--scanners=none")
    assert result.returncode == 1
    assert "Compose 2.24.4+" in result.stderr and "!override" in result.stderr
    assert "Admin password:" not in result.stderr
    assert checkout.snapshot() == before
    assert not any(
        "build" in call["args"] or "up" in call["args"] for call in checkout.calls()
    )


def test_real_subprocess_input_remains_bounded_and_is_not_a_shell(tmp_path):
    token = "literal input with $(false); newline\n"
    output = setup.run(
        [sys.executable, "-c", "import sys; print(repr(sys.stdin.read()))"], input=token
    )
    assert output.strip() == repr(token)


@pytest.mark.parametrize("retry", ["plain", "none"])
@pytest.mark.parametrize("failure", ["truncated", "stalled"])
def test_real_failed_model_transfer_preserves_intent_for_safe_retry(
    tmp_path, clean, release_server, retry, failure
):
    checkout = tmp_path / "checkout"
    (checkout / "scripts").mkdir(parents=True)
    for name in ("quickstart.sh", "scanner_setup.py"):
        shutil.copyfile(ROOT / "scripts" / name, checkout / "scripts" / name)
    shutil.copyfile(ROOT / "docker-compose.yml", checkout / "docker-compose.yml")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "commands.jsonl"
    real_docker = shutil.which("docker")
    real_curl = shutil.which("curl")
    docker = bindir / "docker"
    docker.write_text(
        f"#!{sys.executable}\nreal={real_docker!r}\nlog={str(log)!r}\n"
        + """
import json,os,sys
args=sys.argv[1:]
with open(log,'a') as output: output.write(json.dumps(args)+'\\n')
if args[:2]==['compose','version'] or ('compose' in args and 'config' in args):
    os.execv(real,[real,*args])
if args[:2]==['info','--format'] or args[:2]==['ps','--quiet'] or args==['network','ls','-q'] or ('compose' in args and 'ps' in args):
    sys.exit(0)
if args[:2]==['volume','ls'] or (args[:1]==['ps'] and any(a in ('-a','-q') for a in args)):
    sys.exit(0)  # lc_identity's read-only queries: an empty host
sys.exit(77 if 'build' in args else 97)
"""
    )
    docker.chmod(0o700)
    python = bindir / "python3"
    python.write_text(
        f"#!{sys.executable}\nSDR={SDR!r}\n"
        + """
import importlib.util,os,pathlib,sys
if len(sys.argv)>1 and pathlib.Path(sys.argv[1]).name=='scanner_setup.py':
    spec=importlib.util.spec_from_file_location('actual_scanner_setup',sys.argv[1])
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    # Only physical discovery is injected. Selection/storage/ownership guard/
    # actual Compose parsing and the shipped CLI all execute unchanged.
    SDR['identity']=os.environ.get('TEST_SDR_IDENTITY',SDR['identity'])
    module.discover=lambda: {'sdr':[dict(SDR,reasons=[])],'wifi':[],'reasons':[]}
    sys.argv=sys.argv[1:]
    raise SystemExit(module.main())
os.execv(sys.executable,[sys.executable,*sys.argv[1:]])
"""
    )
    python.chmod(0o700)
    curl = bindir / "curl"
    curl.write_text(
        f"#!{sys.executable}\nreal={real_curl!r}\nurl={release_server.base + '/release'!r}\n"
        + """
import os,sys
args=[url if x.startswith('https://api.github.com/repos/SigRift/SigRift/releases/tags/') else x for x in sys.argv[1:]]
os.execv(real,[real,'-q','--noproxy','*',*args])
"""
    )
    curl.chmod(0o700)
    env = dict(
        os.environ,
        PATH=str(bindir) + os.pathsep + os.environ["PATH"],
        SIGRIFT_PRESET="none",
    )
    release_server.truncate_model = 1
    if failure == "stalled":
        release_server.stall_path = "/" + model_transfers.MODEL_NAME

    def invoke(flags=(), *, identity=None):
        chosen = env if identity is None else env | {"TEST_SDR_IDENTITY": identity}
        return subprocess.run(
            ["bash", str(checkout / "scripts/quickstart.sh"), *flags],
            input="disposable-model-retry-password\ndisposable-model-retry-password\n",
            text=True,
            capture_output=True,
            env=chosen,
            timeout=45,
        )

    first = invoke()
    assert first.returncode == 1
    assert "selected SDR requires a model; no scanner was started" in first.stderr
    pending = checkout / ".sigrift-scanners-pending.json"
    assert pending.is_file(), (
        "Model failure must retain the same desired radio for plain retry"
    )
    before = {
        name: (checkout / name).read_bytes()
        for name in (".env", "docker-compose.override.yml", pending.name)
    }
    assert stat.S_IMODE(pending.stat().st_mode) == 0o600
    assert not (checkout / setup.STATE).exists()
    assert not list((checkout / "models").glob("*.onnx"))
    assert not any(
        "build" in call or "up" in call or "stop" in call
        for call in map(json.loads, log.read_text().splitlines())
    )
    assert release_server.requests["/" + model_transfers.MODEL_NAME] == 1

    release_server.stall_path = None
    release_server.release_stall.set()
    if retry == "plain":
        moved = invoke(identity="b" * 64)
        assert moved.returncode == 1 and "unavailable or ambiguous" in moved.stderr
        assert {name: (checkout / name).read_bytes() for name in before} == before
        assert release_server.requests["/" + model_transfers.MODEL_NAME] == 1
    second = invoke(() if retry == "plain" else ("--scanners=none",))
    assert second.returncode == 77, second.stderr
    assert not pending.exists()
    assert (checkout / ".env").read_bytes() == before[".env"]
    assert (checkout / "docker-compose.override.yml").read_bytes() == before[
        "docker-compose.override.yml"
    ]
    expected = {"sdr": SDR} if retry == "plain" else {}
    assert setup.saved_selection(checkout) == expected
    builds = [
        call
        for call in map(json.loads, log.read_text().splitlines())
        if "build" in call
    ]
    assert len(builds) == 1
    assert builds[0][builds[0].index("build") + 1 :] == setup.CORE + (
        ["rtl-tcp", "scan"] if retry == "plain" else []
    )
    assert release_server.requests["/" + model_transfers.MODEL_NAME] == (
        2 if retry == "plain" else 1
    )
    if retry == "plain":
        assert (
            checkout / "models/open-default.onnx"
        ).read_bytes() == model_transfers.MODEL
    assert (
        "disposable-model-retry-password"
        not in first.stdout + first.stderr + second.stdout + second.stderr
    )


@pytest.mark.parametrize("corruption", ["edited", "symlink", "active-format"])
def test_pending_intent_rejects_edited_or_wrong_role_files(
    project, monkeypatch, corruption
):
    target = project / setup.PENDING
    original = setup.pending_text({"sdr": SDR})
    if corruption == "symlink":
        other = project / "operator.json"
        other.write_text(original)
        target.symlink_to(other)
    else:
        target.write_text(
            original + " " if corruption == "edited" else setup.render({"sdr": SDR})
        )
    before = target.read_bytes()
    monkeypatch.setattr(
        setup,
        "discover",
        lambda: pytest.fail("invalid intent must fail before hardware discovery"),
    )
    with pytest.raises(setup.SetupError, match="Pending scanner intent"):
        setup.plan(project, "saved")
    assert target.read_bytes() == before
    assert not (project / setup.STATE).exists()


def test_failed_model_keeps_previous_active_selection_and_workers(project, monkeypatch):
    (project / setup.STATE).write_text(setup.render({"wifi": WIFI}))
    active = (project / setup.STATE).read_bytes()
    monkeypatch.setattr(setup, "discover", found)
    actual = setup.run
    mutations = []

    def command(args, **kwargs):
        if any(operation in args for operation in ("stop", "up", "build")):
            mutations.append(args)
            return ""
        return actual(args, **kwargs)

    monkeypatch.setattr(setup, "run", command)
    setup.remember(project, {"sdr": SDR})
    assert setup.pending_selection(project) == {"sdr": SDR}
    with pytest.raises(setup.SetupError, match="model is missing"):
        setup.install(project, {"sdr": SDR})
    assert (project / setup.STATE).read_bytes() == active
    assert setup.pending_selection(project) == {"sdr": SDR}
    assert mutations == []


def test_none_cancels_pending_and_stops_only_previously_active_workers(
    project, monkeypatch
):
    (project / setup.STATE).write_text(setup.render({"wifi": WIFI}))
    (project / setup.PENDING).write_text(setup.pending_text({"sdr": SDR}))
    monkeypatch.setattr(
        setup,
        "discover",
        lambda: pytest.fail("none must not rediscover physical hardware"),
    )
    actual = setup.run
    stopped = []

    def command(args, **kwargs):
        if "stop" in args:
            stopped.append(args[args.index("stop") + 1 :])
            return ""
        if "ps" in args:
            return "wifi-scan\n"
        return actual(args, **kwargs)

    monkeypatch.setattr(setup, "run", command)
    selection = setup.plan(project, "none")
    setup.remember(project, selection)
    setup.install(project, selection)
    assert stopped == [["wifi-scan"]]
    assert setup.saved_selection(project) == {}
    assert not (project / setup.PENDING).exists()
    assert not (project / "models").exists()


def test_failed_pending_publication_preserves_prior_intent_and_active_config(
    project, monkeypatch
):
    (project / setup.STATE).write_text(setup.render({"wifi": WIFI}))
    (project / setup.PENDING).write_text(setup.pending_text({"wifi": WIFI}))
    before = {
        name: (project / name).read_bytes() for name in (setup.STATE, setup.PENDING)
    }
    monkeypatch.setattr(setup, "discover", found)
    monkeypatch.setattr(
        setup.os,
        "replace",
        lambda *_: (_ for _ in ()).throw(
            PermissionError("injected atomic publication failure")
        ),
    )
    with pytest.raises(PermissionError):
        setup.remember(project, {"sdr": SDR})
    assert {name: (project / name).read_bytes() for name in before} == before
    assert not list(project.glob(".sigrift-scanners-pending-*.json"))
