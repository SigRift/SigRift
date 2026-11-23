"""Real sysfs identity with explicit ip/iw boundaries, never host radio changes.

The first fixture preserves the sanitized ordered headings from the actual
2026-11-08 host diagnostic. Addresses below are synthetic. The unnamed heading
is emitted by upstream iw's print_iface_handler when IFNAME is absent.
"""

import json

import pytest
import test_scanner_setup as planner

setup = planner.setup
clean = planner.clean
MONITOR = "\tInterface wlan1\n\t\ttype monitor\n"
MANAGED = "\tInterface wlan0\n\t\ttype managed\n"
UNNAMED = "\tUnnamed/non-netdev interface\n\t\ttype P2P-device\n"
NATIVE_HEADINGS = "phy#2\n" + MONITOR + "phy#1\n" + UNNAMED + MANAGED


def inventory(tmp_path, monkeypatch, output=NATIVE_HEADINGS, *, safeguard=None):
    for name, index in (("wlan0", 1), ("wlan1", 2)):
        device = tmp_path / "devices" / f"radio{index}"
        phy = device / "ieee80211" / f"phy{index}"
        phy.mkdir(parents=True)
        (phy / "macaddress").write_text(f"02:11:22:33:44:{index:02x}\n")
        for link, target in (
            (phy / "device", device),
            (tmp_path / "class/ieee80211" / f"phy{index}", phy),
            (tmp_path / "class/net" / name / "phy80211", phy),
        ):
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(target, target_is_directory=True)
    if safeguard == "rfkill":
        flag = tmp_path / "class/ieee80211/phy2/rfkill7/soft"
        flag.parent.mkdir()
        flag.write_text("1\n")
    if safeguard == "identity":
        (tmp_path / "class/net/wlan1/phy80211").unlink()
    if safeguard == "ssh":
        monkeypatch.setenv("SSH_CONNECTION", "192.0.2.5 50123 192.0.2.6 22")
    calls = []

    def command(args):
        calls.append(args)
        if args == ["iw", "dev"]:
            return output
        if args[:2] == ["iw", "phy"]:
            monitor = "" if safeguard == "capability" else "\t * monitor\n"
            return "Supported interface modes:\n\t * managed\n" + monitor + "Band 1:\n"
        if args == ["iw", "dev", "wlan0", "link"]:
            return "Not connected.\n"
        if args == ["ip", "-j", "route", "get", "192.0.2.5"]:
            return json.dumps([{"dev": "wlan1"}])
        if args[:3] == ["ip", "-j", "address"]:
            return json.dumps(
                [
                    {"ifname": "wlan0", "addr_info": []},
                    {
                        "ifname": "wlan1",
                        "addr_info": [{"scope": "global"}]
                        if safeguard == "address"
                        else [],
                    },
                ]
            )
        if args in [
            ["ip", "-j", family, "route", "show", "table", "all"]
            for family in ("-4", "-6")
        ]:
            return json.dumps(
                [
                    {
                        "dev": "wlan1" if safeguard == "route" else "wlan0",
                        "dst": "default",
                    }
                ]
            )
        pytest.fail("Unexpected command: " + repr(args))

    monkeypatch.setattr(setup, "run", command)
    values = setup.wifi_devices(tmp_path)
    assert all(not any(word in cmd for word in ("set", "down", "del")) for cmd in calls)
    assert ["iw", "dev", "wlan1", "link"] not in calls
    return {row["interface"]: row for row in values}


def test_actual_heading_order_does_not_assign_other_radio_p2p_to_monitor(
    tmp_path, monkeypatch, clean
):
    rows = inventory(tmp_path, monkeypatch)
    assert rows["wlan1"]["reasons"] == []
    assert rows["wlan0"]["reasons"]
    selected = setup.selection_from(
        {"wifi": list(rows.values()), "sdr": [], "reasons": []},
        "wifi",
        wifi_interface="wlan1",
    )
    assert selected == {
        "wifi": {k: v for k, v in rows["wlan1"].items() if k != "reasons"}
    }


@pytest.mark.parametrize(
    "blocks",
    [
        UNNAMED + MONITOR,
        MONITOR + UNNAMED,
        MONITOR + "\tUnnamed/non-netdev interface\n",
    ],
)
def test_same_radio_unnamed_entry_protects_named_radio_regardless_of_order_or_type(
    tmp_path, monkeypatch, clean, blocks
):
    rows = inventory(tmp_path, monkeypatch, "phy#2\n" + blocks)
    assert rows["wlan1"]["reasons"] == [
        "radio carries SSH, routed/addressed traffic or an active/unknown sibling"
    ]
    with pytest.raises(setup.SetupError, match="unavailable or ambiguous"):
        setup.selection_from(
            {"wifi": list(rows.values()), "sdr": [], "reasons": []}, "wifi"
        )


def test_other_radio_unnamed_before_monitor_remains_separate(
    tmp_path, monkeypatch, clean
):
    rows = inventory(
        tmp_path, monkeypatch, "phy#1\n" + UNNAMED + MANAGED + "phy#2\n" + MONITOR
    )
    assert rows["wlan1"]["reasons"] == []
    assert rows["wlan0"]["reasons"]


@pytest.mark.parametrize(
    "output",
    [
        MONITOR,
        UNNAMED + "phy#2\n" + MONITOR,
        "phy#2\n\ttype monitor\n" + MONITOR,
        "phy#2\n" + MONITOR + "phy#1\n\ttype monitor\n",
        "phy#2\n" + MONITOR + "phy#bad\n" + UNNAMED,
        "phy#2\n" + MONITOR + "\tInterface invalid name\n\t\ttype monitor\n",
        "phy#2\n" + MONITOR + MONITOR,
        "phy#2\n" + MONITOR + "\t\ttype managed\n",
        "phy#2\n" + MONITOR + "\tUnnamed/non-netdev interface extra\n",
    ],
)
def test_malformed_or_unscoped_interface_metadata_fails_closed(
    tmp_path, monkeypatch, clean, output
):
    with pytest.raises(setup.SetupError, match="Unrecognized Wi-Fi interface metadata"):
        inventory(tmp_path, monkeypatch, output)


@pytest.mark.parametrize(
    "safeguard,reason",
    [
        ("route", "radio carries SSH"),
        ("address", "radio carries SSH"),
        ("ssh", "radio carries SSH"),
        ("rfkill", "radio is blocked by rfkill"),
        ("identity", "permanent Wi-Fi hardware identity is unavailable"),
        ("capability", "driver does not advertise monitor mode"),
    ],
)
def test_other_radio_parser_correction_never_bypasses_existing_interface_guards(
    tmp_path, monkeypatch, clean, safeguard, reason
):
    rows = inventory(tmp_path, monkeypatch, safeguard=safeguard)
    assert any(reason in value for value in rows["wlan1"]["reasons"])
    assert rows["wlan0"]["reasons"]
    assert (
        setup.selection_from(
            {"wifi": list(rows.values()), "sdr": [], "reasons": []}, "auto"
        )
        == {}
    )
