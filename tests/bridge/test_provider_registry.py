"""Registry contracts exercised through real distribution metadata and imports.

The isolated search path contains only temporary, local distributions. No entry
point discovery, loading, provider construction, or configuration is mocked.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import logging
from pathlib import Path
import sys
import textwrap
import uuid

import pytest

from sigrift.providers import null, registry


KINDS = ("geo", "alert", "report", "ingest", "fingerprint", "fuzz", "oidc")
GETTERS = {
    kind: getattr(registry, f"get_{kind}_provider")
    for kind in KINDS
    if kind != "ingest"
}
CONFIGURABLE = {"geo", "fingerprint", "fuzz", "oidc"}
NULL_TYPES = {
    "geo": null.NullGeoProvider,
    "alert": null.NullAlertProvider,
    "report": null.NullReportProvider,
    "fingerprint": null.NullFingerprintProvider,
    "fuzz": null.NullFuzzProvider,
    "oidc": null.NullOidcProvider,
}

PLUGIN_SOURCE = """
from sigrift.providers.null import (
    NullGeoProvider, NullAlertProvider, NullReportProvider, NullIngestProvider,
    NullFingerprintProvider, NullFuzzProvider, NullOidcProvider,
)

class Configuration:
    def __init__(self):
        self.configuration = None

    def configure(self, config):
        if config.get("reject"):
            raise ValueError("unsupported fixture configuration")
        self.configuration = dict(config)

class Geo(Configuration, NullGeoProvider):
    pass
class Alert(Configuration, NullAlertProvider):
    pass
class Report(Configuration, NullReportProvider):
    pass
class Ingest(Configuration, NullIngestProvider):
    def decode(self, raw_bytes, metadata):
        return {"payload_hex": raw_bytes.hex(), "node_id": metadata["node_id"]}
class Fingerprint(Configuration, NullFingerprintProvider):
    pass
class Fuzz(Configuration, NullFuzzProvider):
    pass
class Oidc(Configuration, NullOidcProvider):
    pass
class BrokenConstructor:
    def __init__(self):
        raise RuntimeError("fixture provider initialization failed")
"""


class PluginDirectory:
    def __init__(self, root: Path):
        self.root = root
        self.module_name = "registry_fixture_" + uuid.uuid4().hex
        (root / f"{self.module_name}.py").write_text(textwrap.dedent(PLUGIN_SOURCE))
        self.distributions = 0

    def target(self, kind):
        return f"{self.module_name}:{kind.capitalize()}"

    def install(self, groups):
        """Write actual dist-info metadata, without pip or global installation."""
        self.distributions += 1
        name = f"registry_fixture_{self.distributions}"
        distribution = self.root / f"{name}-1.0.dist-info"
        distribution.mkdir()
        (distribution / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n"
        )
        entries = distribution / "entry_points.txt"
        entries.write_text(
            "\n".join(
                f"[sigrift.{kind}_providers]\n"
                + "\n".join(f"{name} = {target}" for name, target in providers.items())
                for kind, providers in groups.items()
            )
        )
        importlib.invalidate_caches()
        return entries

    def provider_type(self, kind):
        return getattr(importlib.import_module(self.module_name), kind.capitalize())


@pytest.fixture
def plugins(tmp_path, monkeypatch):
    # The public metadata API scans sys.path. Restrict that actual scan instead
    # of substituting entry_points(), EntryPoint.load(), or registry internals.
    # Runtime dependencies above are imported before narrowing the path.
    root = tmp_path / "plugins"
    root.mkdir()
    directory = PluginDirectory(root)
    monkeypatch.setattr(sys, "path", [str(root)])
    monkeypatch.setattr(registry, "_cache", {})
    try:
        yield directory
    finally:
        sys.modules.pop(directory.module_name, None)
        importlib.invalidate_caches()


@pytest.mark.parametrize("kind", tuple(GETTERS))
def test_missing_plugin_returns_fresh_typed_null_provider(plugins, kind):
    first = GETTERS[kind]()
    second = GETTERS[kind]("not-installed")
    assert type(first) is NULL_TYPES[kind]
    assert type(second) is NULL_TYPES[kind]
    assert first is not second
    assert registry.list_all_providers() == {name: [] for name in KINDS}


@pytest.mark.parametrize("kind", tuple(GETTERS))
def test_named_provider_uses_real_entry_point_class_and_new_instance(plugins, kind):
    plugins.install(
        {
            kind: {
                "first": f"{plugins.module_name}:BrokenConstructor",
                "selected": plugins.target(kind),
            }
        }
    )
    provider = GETTERS[kind]("selected")
    again = GETTERS[kind]("selected")
    assert type(provider) is plugins.provider_type(kind)
    assert provider is not again
    assert provider.configuration is None
    assert list(getattr(registry, f"get_{kind}_providers")()) == ["first", "selected"]


@pytest.mark.parametrize("kind", tuple(GETTERS))
@pytest.mark.parametrize("name", (None, "", "unregistered"))
def test_default_or_unregistered_name_selects_first_loaded_provider(
    plugins, kind, name
):
    # The second class must not be constructed when choosing the first entry.
    plugins.install(
        {
            kind: {
                "preferred": plugins.target(kind),
                "second": f"{plugins.module_name}:BrokenConstructor",
            }
        }
    )
    provider = GETTERS[kind](name)
    assert type(provider) is plugins.provider_type(kind)


@pytest.mark.parametrize("kind", sorted(CONFIGURABLE))
def test_configuration_reaches_only_the_new_instance(plugins, kind):
    plugins.install({kind: {"configured": plugins.target(kind)}})
    config = {"coordinate_mode": "fixture", "threshold": 0.75}
    configured = GETTERS[kind]("configured", config=config)
    assert configured.configuration == config
    assert GETTERS[kind](config={}).configuration is None


@pytest.mark.parametrize("kind", sorted(CONFIGURABLE))
def test_plugin_configuration_failure_is_not_disguised_as_null_success(plugins, kind):
    plugins.install({kind: {"configured": plugins.target(kind)}})
    with pytest.raises(ValueError, match="unsupported fixture configuration"):
        GETTERS[kind]("configured", config={"reject": True})
    # A failed instance does not poison the cached class or later configuration.
    assert GETTERS[kind](config={"valid": True}).configuration == {"valid": True}


@pytest.mark.parametrize("kind", tuple(GETTERS))
def test_selected_constructor_failure_propagates_without_trying_other_plugins(
    plugins, kind
):
    plugins.install(
        {
            kind: {
                "broken": f"{plugins.module_name}:BrokenConstructor",
                "healthy": plugins.target(kind),
            }
        }
    )
    with pytest.raises(RuntimeError, match="fixture provider initialization failed"):
        GETTERS[kind]("broken")
    assert type(GETTERS[kind]("healthy")) is plugins.provider_type(kind)


def test_all_seven_group_inventories_include_real_ingest_plugin(plugins):
    plugins.install({kind: {f"local-{kind}": plugins.target(kind)} for kind in KINDS})
    assert registry.list_all_providers() == {kind: [f"local-{kind}"] for kind in KINDS}
    decoder = registry.get_ingest_providers()["local-ingest"]()
    assert decoder.decode(b"\x00\xff", {"node_id": "sensor-fixture"}) == {
        "payload_hex": "00ff",
        "node_id": "sensor-fixture",
    }


def test_broken_import_and_missing_class_do_not_hide_healthy_plugins(plugins, caplog):
    plugins.install(
        {
            "geo": {
                "missing-module": "not_installed_registry_fixture:Provider",
                "missing-class": f"{plugins.module_name}:NotDefined",
                "healthy": plugins.target("geo"),
            }
        }
    )
    with caplog.at_level(logging.WARNING, logger=registry.__name__):
        providers = registry.get_geo_providers()
    assert providers == {"healthy": plugins.provider_type("geo")}
    assert len(caplog.records) == 2
    assert all(record.levelno == logging.WARNING for record in caplog.records)
    assert "Failed to load provider sigrift.geo_providers.missing-module" in caplog.text
    assert "Failed to load provider sigrift.geo_providers.missing-class" in caplog.text


def test_discovery_cache_keeps_registered_class_after_metadata_is_removed(plugins):
    metadata = plugins.install({"geo": {"retained": plugins.target("geo")}})
    original = registry.get_geo_providers()
    metadata.unlink()
    # Independently prove the package metadata no longer advertises the entry.
    assert not importlib.metadata.entry_points(group="sigrift.geo_providers")
    assert registry.get_geo_providers() is original
    assert type(registry.get_geo_provider("retained")) is plugins.provider_type("geo")


def test_empty_group_is_cached_until_explicit_refresh_and_other_groups_are_independent(
    plugins,
):
    assert registry.get_geo_providers() == {}
    plugins.install(
        {
            "geo": {"new-geo": plugins.target("geo")},
            "alert": {"new-alert": plugins.target("alert")},
        }
    )
    assert [
        ep.name for ep in importlib.metadata.entry_points(group="sigrift.geo_providers")
    ] == ["new-geo"]
    assert registry.get_geo_providers() == {}
    assert type(registry.get_alert_provider()) is plugins.provider_type("alert")
    registry._cache.clear()
    assert type(registry.get_geo_provider()) is plugins.provider_type("geo")


def test_invalid_utf8_distribution_metadata_fails_safely_and_logs_once(plugins, caplog):
    metadata = plugins.install({"geo": {"repaired": plugins.target("geo")}})
    valid = metadata.read_bytes()
    metadata.write_bytes(b"\xff")
    # This is an actual corrupt installed metadata file, not a fabricated
    # exception from a substitute entry-point scanner.
    with pytest.raises(UnicodeDecodeError):
        importlib.metadata.entry_points(group="sigrift.geo_providers")
    with caplog.at_level(logging.WARNING, logger=registry.__name__):
        assert type(registry.get_geo_provider()) is null.NullGeoProvider
        metadata.write_bytes(valid)
        assert type(registry.get_geo_provider()) is null.NullGeoProvider
    assert len(caplog.records) == 1
    assert "Entry point discovery failed for sigrift.geo_providers" in caplog.text
    registry._cache.clear()
    assert type(registry.get_geo_provider()) is plugins.provider_type("geo")
