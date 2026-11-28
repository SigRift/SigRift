"""Retry the same Wi-Fi radio across PHY renumbering, never a name-only match.

The filesystem layout and symlinks are real. ip/iw/Docker discovery responses
are explicit process boundaries; no host interface or Docker daemon is changed.
"""

import hashlib
import importlib.util
import json
import sys
from unittest.mock import patch

import pytest
import test_scanner_setup as planner

setup = planner.setup
REAL_RUN = setup.run
clean = planner.clean
ROOT = planner.ROOT
spec = importlib.util.spec_from_file_location(
    "wifi_identity_readiness", ROOT / "scripts/scanner_readiness.py"
)
readiness = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"scanner_setup": setup}):
    spec.loader.exec_module(readiness)


class RadioHost:
    def __init__(self, root):
        self.root = root
        self.sysfs = root / "sys"
        self.project = root / "project"
        self.project.mkdir()
        self.phy = "phy1"
        self.calls = []
        self.protected = "wlan0"
        self.device = self.sysfs / "devices/pci0000:00/0000:00:14.0/usb3/3-1/3-1:1.0"
        self.device.mkdir(parents=True)
        self.wiphy = self.device / "ieee80211" / self.phy
        self.wiphy.mkdir(parents=True)
        (self.wiphy / "macaddress").write_text("02:11:22:33:44:55\n")
        (self.wiphy / "device").symlink_to(self.device, target_is_directory=True)
        self.class_phy = self.sysfs / "class/ieee80211"
        self.class_phy.mkdir(parents=True)
        (self.class_phy / self.phy).symlink_to(self.wiphy, target_is_directory=True)
        self.net = self.device / "net/wlan1"
        self.net.mkdir(parents=True)
        (self.net / "phy80211").symlink_to(self.wiphy, target_is_directory=True)
        # This mutable interface address must not be used as physical identity.
        (self.net / "address").write_text("02:99:99:99:99:99\n")
        netclass = self.sysfs / "class/net"
        netclass.mkdir(parents=True)
        (netclass / "wlan1").symlink_to(self.net, target_is_directory=True)
        self.usb = root / "empty-usb-inventory"
        self.usb.mkdir()

    def command(self, args, **kwargs):
        self.calls.append(args)
        if args[:3] == ["ip", "-j", "address"]:
            return json.dumps(
                [{"ifname": self.protected, "addr_info": [{"scope": "global"}]}]
            )
        if args[:2] == ["ip", "-j"]:
            return json.dumps([{"dev": self.protected, "dst": "default"}])
        if args == ["iw", "dev"]:
            return f"phy#{self.phy[3:]}\n\tInterface wlan1\n\t\ttype monitor\n"
        if args[:2] == ["iw", "phy"]:
            return "Supported interface modes:\n\t * managed\n\t * monitor\nBand 1:\n"
        raise AssertionError(f"Unexpected external command: {args}")

    def inventory(self):
        return {"sdr": [], "wifi": setup.wifi_devices(self.sysfs), "reasons": []}

    def save(self):
        selected = setup.selection_from(
            self.inventory(), "wifi", wifi_interface="wlan1"
        )
        (self.project / setup.STATE).write_text(setup.render(selected))
        return selected

    def renumber(self):
        (self.class_phy / self.phy).unlink()
        next_phy = "phy2"
        moved = self.wiphy.with_name(next_phy)
        self.wiphy.rename(moved)
        self.wiphy = moved
        self.phy = next_phy
        (self.class_phy / self.phy).symlink_to(self.wiphy, target_is_directory=True)
        (self.net / "phy80211").unlink()
        (self.net / "phy80211").symlink_to(self.wiphy, target_is_directory=True)


@pytest.fixture
def radio(tmp_path, monkeypatch):
    host = RadioHost(tmp_path)
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.setattr(setup, "run", host.command)
    monkeypatch.setattr(setup, "native_docker", lambda: None)
    monkeypatch.setattr(setup, "rtl_devices", lambda: [])
    original_wifi = setup.wifi_devices
    monkeypatch.setattr(
        setup, "wifi_devices", lambda sysfs=host.sysfs: original_wifi(sysfs)
    )
    monkeypatch.setattr(readiness, "USB_INVENTORY", host.usb)
    yield host
    assert not any(
        "set" in call or "down" in call or "docker" in call for call in host.calls
    )


def test_saved_radio_retries_after_phy_renumber_and_receipt_stays_ready(radio):
    original = radio.save()
    saved = radio.project / setup.STATE
    before = saved.read_bytes()
    radio.renumber()
    selected = setup.selection_from(
        radio.inventory(), "wifi", setup.saved_selection(radio.project)
    )
    assert selected["wifi"]["phy"] == "phy2"
    assert selected["wifi"]["identity"] == original["wifi"]["identity"]
    assert readiness.host_receipt(radio.project)["wifi"] == {
        "adapter": "ready",
        "selection": "selected",
        "reason": "checked",
    }
    assert saved.read_bytes() == before
    assert not (radio.project / setup.PENDING).exists()


def test_fingerprint_uses_permanent_address_and_not_phy_or_mutable_mac(radio):
    first = radio.save()["wifi"]["identity"]
    assert len(first) == 64 and set(first) <= set("0123456789abcdef")
    (radio.net / "address").write_text("02:88:88:88:88:88\n")
    radio.renumber()
    assert radio.inventory()["wifi"][0]["identity"] == first
    text = (radio.project / setup.STATE).read_text()
    assert "02:11:22:33:44:55" not in text and str(radio.device) not in text


@pytest.mark.parametrize("change", ["permanent_address", "physical_path"])
def test_same_interface_with_changed_hardware_is_never_adopted(radio, change):
    original = radio.save()
    before = (radio.project / setup.STATE).read_bytes()
    if change == "permanent_address":
        (radio.wiphy / "macaddress").write_text("02:aa:bb:cc:dd:ee\n")
    else:
        other = radio.sysfs / "devices/another-physical-device"
        radio.device.rename(other)
        radio.device = other
        radio.wiphy = other / "ieee80211" / radio.phy
        radio.net = other / "net/wlan1"
        for link, target in (
            (radio.class_phy / radio.phy, radio.wiphy),
            (radio.sysfs / "class/net/wlan1", radio.net),
            (radio.wiphy / "device", other),
            (radio.net / "phy80211", radio.wiphy),
        ):
            link.unlink()
            link.symlink_to(target, target_is_directory=True)
    with pytest.raises(setup.SetupError, match="unavailable|ambiguous"):
        setup.selection_from(radio.inventory(), "wifi", original)
    assert readiness.host_receipt(radio.project)["wifi"]["reason"] == "selected_absent"
    assert (radio.project / setup.STATE).read_bytes() == before


@pytest.mark.parametrize(
    "address",
    [
        "é",
        "",
        "00:00:00:00:00:00",
        "ff:ff:ff:ff:ff:ff",
        "01:11:22:33:44:55",
        "not-a-mac",
        "02:11:22:33:44",
        "02:11:22:33:44:55 extra",
    ],
)
def test_unusable_permanent_identity_blocks_selection_without_claiming_absence(
    radio, address
):
    radio.save()
    (radio.wiphy / "macaddress").write_text(address)
    with pytest.raises(setup.SetupError, match="identity"):
        setup.selection_from(
            radio.inventory(), "wifi", setup.saved_selection(radio.project)
        )
    assert readiness.host_receipt(radio.project)["wifi"] == {
        "adapter": "unknown",
        "selection": "selected",
        "reason": "probe_failed",
    }


@pytest.mark.parametrize(
    "fault", ["missing_mac", "outside_devices", "wrong_interface_binding"]
)
def test_unverifiable_sysfs_identity_is_not_an_absent_adapter(radio, fault):
    radio.save()
    if fault == "missing_mac":
        (radio.wiphy / "macaddress").unlink()
    elif fault == "outside_devices":
        (radio.wiphy / "device").unlink()
        (radio.wiphy / "device").symlink_to(radio.root, target_is_directory=True)
    else:
        (radio.net / "phy80211").unlink()
        (radio.net / "phy80211").symlink_to(radio.device, target_is_directory=True)
    with pytest.raises(setup.SetupError, match="identity"):
        setup.selection_from(
            radio.inventory(), "wifi", setup.saved_selection(radio.project)
        )
    assert readiness.host_receipt(radio.project)["wifi"]["adapter"] == "unknown"


def test_matching_identity_cannot_override_current_management_or_rfkill_protection(
    radio,
):
    original = radio.save()
    radio.renumber()
    radio.protected = "wlan1"
    with pytest.raises(setup.SetupError, match="SSH|routed"):
        setup.selection_from(radio.inventory(), "wifi", original)
    radio.protected = "wlan0"
    flag = radio.wiphy / "rfkill7/soft"
    flag.parent.mkdir()
    flag.write_text("1\n")
    with pytest.raises(setup.SetupError, match="rfkill"):
        setup.selection_from(radio.inventory(), "wifi", original)


@pytest.mark.parametrize("pending", [False, True])
def test_legacy_selection_requires_explicit_reselection_and_is_preserved(
    radio, pending
):
    legacy = {"wifi": {"interface": "wlan1", "phy": "phy1"}}
    active = radio.project / setup.STATE
    active.write_text(setup.render(legacy))
    if pending:
        (radio.project / setup.PENDING).write_text(setup.pending_text(legacy))
    before = {p.name: p.read_bytes() for p in radio.project.iterdir()}
    with pytest.raises(
        setup.SetupError, match="--scanners=wifi --wifi-interface=wlan1"
    ):
        setup.selection_from(
            radio.inventory(), "wifi", setup.saved_selection(radio.project)
        )
    assert readiness.host_receipt(radio.project)["wifi"] == {
        "adapter": "unknown",
        "selection": "selected",
        "reason": "selection_unavailable",
    }
    assert {p.name: p.read_bytes() for p in radio.project.iterdir()} == before
    # Explicit selection is the only path that enrolls the observed identity.
    new = setup.selection_from(radio.inventory(), "wifi", wifi_interface="wlan1")
    assert new["wifi"]["identity"]


def test_sdr_legacy_selection_still_refreshes_usb_address():
    old = {
        "usb": "3-1",
        "identity": hashlib.sha256(b"receiver").hexdigest(),
        "device": "/dev/bus/usb/003/002",
        "gid": 46,
    }
    current = old | {"device": "/dev/bus/usb/003/003"}
    assert setup.selection_from(
        {"sdr": [current | {"reasons": []}], "wifi": [], "reasons": []},
        "sdr",
        {"sdr": old},
    ) == {"sdr": current}


def test_duplicate_matching_identity_is_not_reported_ready(radio, monkeypatch):
    selected = radio.save()
    duplicate = radio.inventory()["wifi"][0]
    rows = [duplicate, dict(duplicate)]
    with pytest.raises(setup.SetupError, match="ambiguous"):
        setup.selection_from({"sdr": [], "wifi": rows, "reasons": []}, "wifi", selected)
    monkeypatch.setattr(setup, "wifi_devices", lambda: rows)
    assert readiness.host_receipt(radio.project)["wifi"]["adapter"] == "unknown"


def test_legacy_reselection_guidance_keeps_all_selected_scanners(radio):
    legacy = {"sdr": planner.SDR, "wifi": {"interface": "wlan1", "phy": "phy1"}}
    found = radio.inventory() | {"sdr": [planner.SDR | {"reasons": []}]}
    with pytest.raises(
        setup.SetupError, match="--scanners=sdr,wifi --wifi-interface=wlan1"
    ):
        setup.selection_from(found, "sdr,wifi", legacy)


@pytest.mark.parametrize("location", ["active", "pending"])
@pytest.mark.parametrize("alteration", ["bad_fingerprint", "wrong_version", "symlink"])
def test_new_identity_state_refuses_tampering(radio, location, alteration):
    selected = radio.save()
    path = radio.project / (setup.STATE if location == "active" else setup.PENDING)
    if location == "pending":
        path.write_text(setup.pending_text(selected))
    if alteration == "bad_fingerprint":
        path.write_text(
            path.read_text().replace(selected["wifi"]["identity"], "not-a-fingerprint")
        )
    elif alteration == "wrong_version":
        # Active overlays carry the format offset; pending records do not.
        version = setup.selection_version(selected) + (
            setup.OVERLAY_FORMAT if location == "active" else 0
        )
        text = path.read_text()
        assert f'"version": {version}' in text
        path.write_text(text.replace(f'"version": {version}', '"version": 1'))
    else:
        original = path.with_suffix(".original")
        path.rename(original)
        path.symlink_to(original)
    before = path.read_bytes()
    reader = setup.saved_selection if location == "active" else setup.pending_selection
    with pytest.raises(setup.SetupError):
        reader(radio.project)
    assert path.read_bytes() == before


def test_retry_refresh_rechecks_docker_ownership_before_state_publication(
    radio, monkeypatch
):
    selected = radio.save()
    radio.renumber()
    desired = setup.selection_from(radio.inventory(), "wifi", selected)
    before = (radio.project / setup.STATE).read_bytes()
    calls = []
    owner = planner.container_owner(
        project="another-project",
        service="wifi-scan",
        network="host",
        wifi=["MLRF_WIFI_IFACE=wlan1"],
        caps=["NET_ADMIN", "NET_RAW"],
    )
    owner["id"] = "a" * 64

    def boundary(args, **kwargs):
        calls.append(args)
        if args == ["docker", "compose", "config", "--format", "json"]:
            return json.dumps({"name": "owned-project"})
        if args == ["docker", "ps", "--quiet", "--no-trunc"]:
            return owner["id"] + "\n"
        if args[:2] == ["docker", "inspect"]:
            return json.dumps(owner) + "\n"
        raise AssertionError(args)

    monkeypatch.setattr(setup, "run", boundary)
    monkeypatch.setattr(setup, "compose_inputs", lambda _: None)
    monkeypatch.setattr(
        setup,
        "discover",
        lambda: {"sdr": [], "wifi": [desired["wifi"] | {"reasons": []}], "reasons": []},
    )
    with pytest.raises(setup.SetupError, match="different or ambiguous host-network"):
        setup.remember(radio.project, desired)
    assert any(call[1] == "inspect" for call in calls)
    assert (radio.project / setup.STATE).read_bytes() == before
    assert not (radio.project / setup.PENDING).exists()


def test_none_cancels_legacy_or_new_pending_without_hardware_probe(radio, monkeypatch):
    legacy = {"wifi": {"interface": "wlan1", "phy": "phy1"}}
    (radio.project / setup.PENDING).write_text(setup.pending_text(legacy))
    monkeypatch.setattr(setup, "compose_inputs", lambda _: None)
    monkeypatch.setattr(setup, "run", lambda args, **kwargs: "")
    monkeypatch.setattr(
        setup, "discover", lambda: pytest.fail("none must not probe hardware")
    )
    assert setup.plan(radio.project, "none") == {}
    setup.remember(radio.project, {})
    assert setup.pending_selection(radio.project) == {}


def test_real_quickstart_plain_retry_refreshes_only_verified_wifi_choice(
    radio, monkeypatch
):
    import os
    import shutil
    import subprocess

    # All hardware and daemon boundaries are explicit. The actual shipped CLI,
    # stable sysfs identity, saved state and installed Compose config parser run.
    for name in list(os.environ):
        if name.startswith(("COMPOSE_", "DOCKER_", "SIGRIFT_", "BRIDGE_", "UC_")):
            monkeypatch.delenv(name)
    project = radio.project
    (project / "scripts").mkdir()
    for name in ("quickstart.sh", "scanner_setup.py"):
        shutil.copyfile(ROOT / "scripts" / name, project / "scripts" / name)
    shutil.copyfile(ROOT / "docker-compose.yml", project / "docker-compose.yml")
    bindir = radio.root / "bin"
    bindir.mkdir()
    log = radio.root / "cli-commands.jsonl"
    docker = bindir / "docker"
    docker.write_text(
        f"#!{sys.executable}\nreal={shutil.which('docker')!r}\nlog={str(log)!r}\n"
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
        f"#!{sys.executable}\n"
        + """
import importlib.util,json,os,pathlib,sys
if len(sys.argv)>1 and pathlib.Path(sys.argv[1]).name=='scanner_setup.py':
    spec=importlib.util.spec_from_file_location('actual_setup',sys.argv[1])
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    external=m.run
    def command(args,**kwargs):
        if args[:3]==['ip','-j','address']:
            return json.dumps([{'ifname':'wlan0','addr_info':[{'scope':'global'}]}])
        if args[:2]==['ip','-j']:
            return json.dumps([{'dev':'wlan0','dst':'default'}])
        if args==['iw','dev']:
            return 'phy#'+os.environ['TEST_PHY']+'\\n\\tInterface wlan1\\n\\t\\ttype monitor\\n'
        if args[:2]==['iw','phy']:
            return 'Supported interface modes:\\n\\t * managed\\n\\t * monitor\\nBand 1:\\n'
        return external(args,**kwargs)
    m.run=command
    m.native_docker=lambda:None
    m.rtl_devices=lambda:[]
    actual_wifi=m.wifi_devices
    m.wifi_devices=lambda:actual_wifi(pathlib.Path(os.environ['TEST_SYSFS']))
    sys.argv=sys.argv[1:]
    raise SystemExit(m.main())
os.execv(sys.executable,[sys.executable,*sys.argv[1:]])
"""
    )
    python.chmod(0o700)
    (bindir / "curl").write_text("#!/bin/sh\necho unexpected-network >&2\nexit 96\n")
    (bindir / "curl").chmod(0o700)
    env = dict(
        os.environ,
        PATH=str(bindir) + os.pathsep + os.environ["PATH"],
        SIGRIFT_PRESET="none",
        TEST_SYSFS=str(radio.sysfs),
        TEST_PHY="1",
    )

    def invoke(flags):
        return subprocess.run(
            ["bash", str(project / "scripts/quickstart.sh"), *flags],
            cwd=project,
            input="disposable-identity-password\ndisposable-identity-password\n",
            text=True,
            capture_output=True,
            env=env,
            timeout=30,
        )

    first = invoke(["--scanners=wifi", "--wifi-interface=wlan1"])
    assert first.returncode == 77, first.stderr
    selected = setup.saved_selection(project)
    assert selected["wifi"]["identity"]
    assert selected["wifi"]["phy"] == "phy1"
    assert not (project / "models").exists()
    assert not (project / setup.PENDING).exists()
    preserved = {
        name: (project / name).read_bytes()
        for name in (
            ".env",
            "docker-compose.override.yml",
            "tls/cert.pem",
            "tls/key.pem",
        )
    }
    radio.renumber()
    env["TEST_PHY"] = "2"
    second = invoke([])
    assert second.returncode == 77, second.stderr
    assert setup.saved_selection(project) == {
        "wifi": selected["wifi"] | {"phy": "phy2"}
    }
    assert {name: (project / name).read_bytes() for name in preserved} == preserved
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    builds = [call for call in calls if "build" in call]
    assert len(builds) == 2
    assert all(
        call[call.index("build") + 1 :] == setup.CORE + ["wifi-scan"] for call in builds
    )
    assert not any("up" in call or "stop" in call for call in calls)
    assert (
        "disposable-identity-password"
        not in first.stdout + first.stderr + second.stdout + second.stderr
    )
    assert "unexpected-network" not in first.stderr + second.stderr


@pytest.mark.parametrize("change_before_activation", [False, True])
def test_pending_retry_revalidates_identity_before_atomic_activation(
    radio, monkeypatch, clean, change_before_activation
):
    import shutil
    import stat

    project = radio.project
    shutil.copyfile(ROOT / "docker-compose.yml", project / "docker-compose.yml")
    (project / ".env").write_text("BRIDGE_ADMIN_PASSWORD=disposable-wifi-retry\n")
    (project / "docker-compose.override.yml").write_text(
        "services:\n  edge:\n    environment:\n      OPERATOR_SETTING: keep-me\n"
    )
    monkeypatch.chdir(project)
    selected = radio.save()
    (project / setup.PENDING).write_text(setup.pending_text(selected))
    preserved = {
        name: (project / name).read_bytes()
        for name in (".env", "docker-compose.override.yml")
    }
    active = (project / setup.STATE).read_bytes()
    radio.renumber()
    external_calls = []

    def command(args, **kwargs):
        if args and args[0] in {"ip", "iw"}:
            return radio.command(args, **kwargs)
        if args and args[0] == "nmcli":
            # Host-preparation probe (read-only): no NetworkManager here.
            raise setup.SetupError("nmcli is unavailable")
        external_calls.append(args)
        if args == ["docker", "ps", "--quiet", "--no-trunc"] or "ps" in args:
            return ""
        assert "config" in args, args
        return REAL_RUN(args, **kwargs)

    monkeypatch.setattr(setup, "run", command)
    monkeypatch.setattr(setup, "discover", radio.inventory)
    refreshed = setup.plan(project, "saved")
    assert refreshed["wifi"] == selected["wifi"] | {"phy": "phy2"}
    assert (project / setup.STATE).read_bytes() == active
    setup.remember(project, refreshed)
    assert setup.pending_selection(project) == refreshed
    assert stat.S_IMODE((project / setup.PENDING).stat().st_mode) == 0o600
    pending = (project / setup.PENDING).read_bytes()
    if change_before_activation:
        (radio.wiphy / "macaddress").write_text("02:66:66:66:66:66\n")
        with pytest.raises(setup.SetupError, match="unavailable"):
            setup.install(project, refreshed)
        assert (project / setup.STATE).read_bytes() == active
        assert (project / setup.PENDING).read_bytes() == pending
    else:
        setup.install(project, refreshed)
        assert setup.saved_selection(project) == refreshed
        assert not (project / setup.PENDING).exists()
    assert {name: (project / name).read_bytes() for name in preserved} == preserved
    assert not any("up" in c or "stop" in c or "build" in c for c in external_calls)
