"""Restore a real configuration snapshot through the authenticated admin UI."""

import secrets
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from .conftest import expect, expect_admin_ready, navigate


def matches(response, method, path):
    return response.request.method == method and urlsplit(response.url).path == path


@pytest.mark.disposable
@pytest.mark.timeout(300)
def test_admin_snapshot_restore_updates_saved_config_and_visible_fields(
    page, settings, admin_api, disposable, output_path
):
    config_path = "/api/admin/detection-config"
    snapshots_path = "/api/admin/config-snapshots"
    description = "E2E synthetic restore rehearsal " + secrets.token_hex(5)
    snapshot_id = None
    owned_snapshots = []
    original = None

    # Every config/snapshot request shares the admin's sensitive 10/minute
    # bucket. Start with a quiet window, independent of earlier test cases.
    # Then allow exactly ten requests in this phase; never retry mutations.
    # The explicit 300s budget includes all three 61s windows and cleanup.
    time.sleep(61)
    try:
        original = admin_api.request("GET", config_path)["config"]
        original_value = original["rf_min_learning_detections"]
        assert type(original_value) is int and original_value >= 0
        changed_value = 350 if original_value != 350 else 400

        # A fresh stack can return defaults without a config file on disk.
        # Persist the same values first, so the snapshot must contain them.
        persisted = admin_api.request("PUT", config_path, original)
        assert bool(persisted["config"] == original), "Setup changed original config"
        page.context.add_cookies(admin_api.browser_cookies())
        with page.expect_response(
            lambda response: matches(response, "GET", snapshots_path)
        ) as listed:
            navigate(page, settings.base_url + "/admin#version")
            expect_admin_ready(page, settings)
        assert listed.value.status == 200

        page.locator("#config-snap-create-btn").click()
        dialog = page.get_by_role("dialog", name="Create config snapshot")
        dialog.locator("#admin-modal-snap-desc").fill(description)
        with page.expect_response(
            lambda response: matches(response, "GET", snapshots_path)
        ) as refreshed:
            with page.expect_response(
                lambda response: matches(response, "POST", snapshots_path)
            ) as created:
                dialog.get_by_role("button", name="Create", exact=True).click()
            assert created.value.status == 201
            snapshot_id = created.value.json()["snapshot_id"]
            assert type(snapshot_id) is int and snapshot_id > 0
            owned_snapshots.append(snapshot_id)
        assert refreshed.value.status == 200
        expect(page.locator("#config-snap-tbody")).to_contain_text(description)
        expect(page.locator("#config-snap-result")).to_contain_text(
            f"Snapshot #{snapshot_id} created."
        )
        saved = admin_api.request("GET", f"{snapshots_path}/{snapshot_id}")["snapshot"]
        assert saved["description"] == description
        assert bool(saved["files"]["detection_config.json"]["config"] == original), (
            "Snapshot omitted or changed the persisted configuration"
        )

        with page.expect_response(
            lambda response: matches(response, "GET", config_path)
        ) as loaded:
            page.locator("#advanced-link").click()
        assert loaded.value.status == 200
        learning = page.locator("#sdr-rf-learning-detections")
        expect(learning).to_have_value(str(original_value))
        learning.fill(str(changed_value))
        with page.expect_response(
            lambda response: matches(response, "PUT", config_path)
        ) as changed:
            page.locator("#sdr-config-save-btn").click()
        assert changed.value.status == 200
        expect(page.locator("#sdr-config-result")).to_have_text(
            "SDR scoring config saved."
        )
        assert (
            admin_api.request("GET", config_path)["config"][
                "rf_min_learning_detections"
            ]
            == changed_value
        )

        # Ten sensitive requests have completed. Let that real server window
        # expire before the restore phase (eight requests, including UI refreshes).
        page.wait_for_timeout(61_000)
        with page.expect_response(
            lambda response: matches(response, "GET", snapshots_path)
        ) as listed:
            page.locator("#version-link").click()
        assert listed.value.status == 200
        page.locator(f'[data-snap-restore="{snapshot_id}"]').click()
        dialog = page.get_by_role("dialog", name="Restore config snapshot")
        with page.expect_response(
            lambda response: matches(response, "GET", snapshots_path)
        ) as refreshed:
            with page.expect_response(
                lambda response: matches(
                    response, "POST", f"{snapshots_path}/{snapshot_id}/restore"
                )
            ) as restored:
                dialog.get_by_role("button", name="Restore", exact=True).click()
            assert restored.value.status == 200
            result = restored.value.json()
            assert result["status"] == "restored"
            assert result["snapshot_id"] == snapshot_id
            assert "detection_config.json" in result["restored_files"]
        assert refreshed.value.status == 200
        expect(page.locator("#config-snap-result")).to_contain_text(
            f"files from snapshot #{snapshot_id}:"
        )
        assert bool(admin_api.request("GET", config_path)["config"] == original), (
            "Restore did not recover all saved configuration values"
        )

        # Snapshot creation reads the JSON files from disk. This second,
        # explicitly synthetic snapshot proves durable values independently
        # of the API's live in-memory configuration and the original snapshot.
        verification = admin_api.request(
            "POST",
            snapshots_path,
            {"description": description + " - restored disk verification"},
            status=201,
        )["snapshot_id"]
        assert type(verification) is int and verification > 0
        assert verification != snapshot_id
        owned_snapshots.append(verification)
        disk = admin_api.request("GET", f"{snapshots_path}/{verification}")["snapshot"]
        assert bool(disk["files"]["detection_config.json"]["config"] == original), (
            "Restored on-disk configuration differs from the saved values"
        )

        # This tab fetches again from the server, rather than showing the
        # pre-restore controller cache. Assert both HTTP and visible readback.
        with page.expect_response(
            lambda response: matches(response, "GET", config_path)
        ) as reloaded:
            page.locator("#advanced-link").click()
        assert reloaded.value.status == 200
        expect(learning).to_have_value(str(original_value))
        with page.expect_response(
            lambda response: matches(response, "GET", snapshots_path)
        ) as listed:
            page.locator("#version-link").click()
        assert listed.value.status == 200
        expect(page.locator("#config-snap-tbody")).to_contain_text(description)
        expect(page.locator("#config-snap-result")).to_contain_text(
            "detection_config.json"
        )
        # Only the restored configuration panel is captured: no keys, login
        # forms, session information or API responses. The caller already owns
        # the private pytest --output directory; no new artifact flag is needed.
        image_dir = Path(output_path)
        image_dir.mkdir(parents=True, exist_ok=True)
        # Fit the panel below the sticky account bar so it cannot cover the
        # restore result or appear inside the documentation capture.
        page.set_viewport_size({"width": 1280, "height": 1200})
        page.locator("#tab-version").evaluate(
            "el => window.scrollTo(0, Math.max(0, window.scrollY + "
            "el.getBoundingClientRect().top - 180))"
        )
        page.locator("#tab-version").screenshot(
            path=str(image_dir / "synthetic-config-snapshot-restored.png")
        )
    finally:
        if original is not None:
            # Independent of a working browser: even a failed/closed page must
            # not prevent reverting the real config. Preserve the recovery
            # snapshot if cleanup or its independent readback fails.
            time.sleep(61)
            admin_api.request("PUT", config_path, original)
            assert bool(admin_api.request("GET", config_path)["config"] == original), (
                "Cleanup did not recover the original configuration"
            )
            for owned_id in owned_snapshots:
                admin_api.request("DELETE", f"{snapshots_path}/{owned_id}")
                admin_api.request("GET", f"{snapshots_path}/{owned_id}", status=404)
            # Automatic pre-change/pre-restore backups remain recovery/audit
            # evidence until this explicitly disposable stack is destroyed.
