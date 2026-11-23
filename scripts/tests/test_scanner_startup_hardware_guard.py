"""Startup's second hardware guard and the summary of a no-op preparation.

`check` matches the saved receiver or adapter by port/interface and identity
twice: once while selecting it, and again before it republishes the overlay.
The second guard only matters if the first one ever lets a different device
through, so these tests replace the first matcher with one that accepts every
candidate and check that startup still refuses, changes no file and never
reaches Docker. Discovery is an explicit fixture; nothing touches a device.
"""

from __future__ import annotations

from unittest.mock import Mock

import pytest
import test_scanner_setup as planner

setup = planner.setup
clean = planner.clean
SDR, WIFI = planner.SDR, planner.WIFI


def accept_every_candidate(_kind, candidates, _previous):
    return candidates


@pytest.mark.parametrize(
    "saved,found",
    [
        # Same receiver identity, now on another USB port.
        ({"sdr": SDR}, {"sdr": [SDR | {"usb": "1-3"}], "wifi": []}),
        # Another receiver on the saved USB port.
        ({"sdr": SDR}, {"sdr": [SDR | {"identity": "c" * 64}], "wifi": []}),
        # The saved adapter's identity under another interface name.
        ({"wifi": WIFI}, {"sdr": [], "wifi": [WIFI | {"interface": "wlan2"}]}),
        # Another adapter under the saved interface name.
        ({"wifi": WIFI}, {"sdr": [], "wifi": [WIFI | {"identity": "d" * 64}]}),
    ],
)
def test_startup_refuses_other_hardware_even_if_the_first_match_lets_it_through(
    tmp_path, monkeypatch, clean, saved, found
):
    (tmp_path / setup.STATE).write_text(setup.render(saved))
    before = (tmp_path / setup.STATE).read_bytes()
    inventory = {
        kind: [item | {"reasons": []} for item in items]
        for kind, items in found.items()
    } | {"reasons": []}
    monkeypatch.setattr(setup, "discover", lambda: inventory)
    monkeypatch.setattr(setup, "matching_devices", accept_every_candidate)
    docker = Mock(side_effect=AssertionError("Docker must not be reached"))
    monkeypatch.setattr(setup, "run", docker)
    with pytest.raises(setup.SetupError) as error:
        setup.check(tmp_path)
    assert str(error.value) == (
        "Selected hardware changed before startup; run ordinary quickstart to refresh it."
    )
    # The saved choice is kept byte for byte; nothing was published or started.
    assert (tmp_path / setup.STATE).read_bytes() == before
    assert setup.saved_selection(tmp_path) == saved
    assert sorted(path.name for path in tmp_path.iterdir()) == [setup.STATE]
    docker.assert_not_called()


def test_summary_of_an_apply_that_changed_nothing_claims_no_change(capsys):
    prep = {
        "steps": [],
        "in_place": ["udev rule for the receiver on USB port 1-2"],
        "skipped": ["wifi: no spare adapter"],
    }
    setup.print_preparation(prep, done=[])
    assert capsys.readouterr().out == (
        "Host preparation: nothing to change.\n"
        "  Already in place: udev rule for the receiver on USB port 1-2\n"
        "  Not prepared: wifi: no spare adapter\n"
        f"Undo with: {setup.UNPREPARE_COMMAND}\n"
    )
