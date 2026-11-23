"""Tests for protocol admin configuration, license gating, and dashboard tabs."""
import pathlib

import pytest
from fastapi.testclient import TestClient


class TestProtocolConfig:
    """Protocol detection config API endpoints."""

    def test_get_protocols_returns_all(self, client: TestClient):
        """GET /api/admin/protocols returns all protocol toggles."""
        resp = client.get("/api/admin/protocols")
        assert resp.status_code == 200
        data = resp.json()
        assert "protocols" in data
        assert "adsb" in data["protocols"]
        assert "dji_ofdm" in data["protocols"]
        assert "wireless_hart" in data["protocols"]
        assert "lora_meshtastic" in data["protocols"]

    def test_get_protocols_structure(self, client: TestClient):
        """Each protocol entry has enabled and licensed fields."""
        resp = client.get("/api/admin/protocols")
        protos = resp.json()["protocols"]
        for proto, info in protos.items():
            assert "enabled" in info, f"{proto} missing 'enabled'"
            assert "licensed" in info, f"{proto} missing 'licensed'"
            assert isinstance(info["enabled"], bool)
            assert isinstance(info["licensed"], bool)

    def test_put_protocols_toggles(self, client: TestClient):
        """PUT /api/admin/protocols can disable a protocol."""
        resp = client.put(
            "/api/admin/protocols",
            json={"adsb": False},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

        # Verify it persisted
        resp2 = client.get("/api/admin/protocols")
        assert resp2.json()["protocols"]["adsb"]["enabled"] is False

    def test_put_protocols_enable(self, client: TestClient):
        """PUT can re-enable a previously disabled protocol."""
        client.put("/api/admin/protocols", json={"adsb": False})
        client.put("/api/admin/protocols", json={"adsb": True})
        resp = client.get("/api/admin/protocols")
        assert resp.json()["protocols"]["adsb"]["enabled"] is True

    def test_put_unknown_protocol_ignored(self, client: TestClient):
        """Unknown protocol names in PUT body are silently ignored."""
        resp = client.put(
            "/api/admin/protocols",
            json={"nonexistent_proto": True},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_protocols_count(self, client: TestClient):
        """Config should have 20 protocol entries."""
        resp = client.get("/api/admin/protocols")
        protos = resp.json()["protocols"]
        assert len(protos) == 20


class TestDashboardTabs:
    """Verify template includes conditional tab elements."""

    @pytest.fixture(autouse=True)
    def _load_template(self):
        path = pathlib.Path(__file__).parent.parent.parent / "src" / "sigrift" / "bridge" / "templates" / "index.html"
        self.template = path.read_text()

    def test_tab_buttons_present(self):
        for tab in ["adsb", "drone", "iot"]:
            assert f'data-tab="{tab}"' in self.template, \
                f'Tab button for "{tab}" not found in template'

    def test_tab_content_panels_present(self):
        for tab_id in ["tab-adsb", "tab-drone", "tab-iot"]:
            assert f'id="{tab_id}"' in self.template, \
                f'Tab panel "{tab_id}" not found in template'

class TestAdminProtocolPanel:
    """Verify admin template includes protocol panel."""

    @pytest.fixture(autouse=True)
    def _load_template(self):
        path = pathlib.Path(__file__).parent.parent.parent / "src" / "sigrift" / "bridge" / "templates" / "admin.html"
        self.template = path.read_text()

    def test_protocol_nav_item(self):
        assert 'data-tab="protocols"' in self.template

    def test_protocol_panel(self):
        assert 'id="tab-protocols"' in self.template

    def test_protocol_toggles_container(self):
        assert 'id="protocol-toggles"' in self.template

    def test_save_button(self):
        assert 'id="save-protocols"' in self.template


class TestDetectionConfigJSON:
    """Verify detection_config.json has protocol_detection section.

    The detection_config.json file is a runtime-generated artifact that is
    written by PersistenceManager.set_detection_config on first admin save.
    When absent, defaults come from PersistenceManager._DETECTION_CONFIG_DEFAULTS
    in code. These tests skip when the seed file is not checked in.
    """

    _CFG_PATH = pathlib.Path(__file__).parent.parent.parent / "src" / "sigrift" / "bridge" / "data" / "detection_config.json"

    def test_protocol_detection_section(self):
        import json

        if not self._CFG_PATH.is_file():
            pytest.skip("detection_config.json is runtime-generated; not checked in")
        config = json.loads(self._CFG_PATH.read_text())
        proto = config["config"]["protocol_detection"]
        assert isinstance(proto, dict)
        assert len(proto) == 20

    def test_all_protocols_default_enabled(self):
        import json

        if not self._CFG_PATH.is_file():
            pytest.skip("detection_config.json is runtime-generated; not checked in")
        config = json.loads(self._CFG_PATH.read_text())
        proto = config["config"]["protocol_detection"]
        for name, enabled in proto.items():
            assert enabled is True, f"Protocol {name} should default to enabled"


class TestStaticJSFiles:
    """Verify JS files exist for each new tab."""

    @pytest.mark.parametrize("filename", [
        "adsb.js", "drone.js", "iot.js",
        "protocol_admin.js",
    ])
    def test_js_file_exists(self, filename):
        path = pathlib.Path(__file__).parent.parent.parent / "src" / "sigrift" / "bridge" / "static" / filename
        assert path.is_file(), f"Static JS file {filename} not found"

    @pytest.mark.parametrize("filename", [
        "adsb.js", "drone.js", "iot.js",
    ])
    def test_js_file_not_empty(self, filename):
        path = pathlib.Path(__file__).parent.parent.parent / "src" / "sigrift" / "bridge" / "static" / filename
        content = path.read_text()
        assert len(content) > 50, f"{filename} appears to be empty or trivial"
