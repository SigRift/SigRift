"""Signal browser endpoint tests."""

from __future__ import annotations

import httpx
import pytest

from sigrift.lib.taxonomy import CLASSES, CLASS_TO_SF, FAMILY_TO_CLASSES

pytestmark = pytest.mark.asyncio

# Counts are derived from the taxonomy itself rather than hard-coded so
# the assertions track the source of truth — the previous literals (41
# classes / 10 families / 7 super-families) silently rotted when the
# taxonomy grew to 76/16/9 because this suite is not in `testpaths` and
# never ran in CI. It is now a dedicated CI job (see .github/workflows/ci.yml).
_N_CLASSES = len(CLASSES)
_N_FAMILIES = len(FAMILY_TO_CLASSES)
_N_SUPER_FAMILIES = len(set(CLASS_TO_SF.values()))


async def test_list_classes_matches_taxonomy(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/signals/classes", headers=api_key_header)
    assert resp.status_code == 200
    classes = resp.json()
    assert isinstance(classes, list)
    assert len(classes) == _N_CLASSES
    # Verify structure
    first = classes[0]
    assert "name" in first
    assert "mod_type" in first
    assert "family" in first
    assert "super_family" in first


async def test_list_families(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/signals/families", headers=api_key_header)
    assert resp.status_code == 200
    families = resp.json()
    assert isinstance(families, list)
    assert len(families) == _N_FAMILIES
    for fam in families:
        assert "family" in fam
        assert "classes" in fam
        assert isinstance(fam["classes"], list)


async def test_list_super_families(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/signals/super-families", headers=api_key_header)
    assert resp.status_code == 200
    sfs = resp.json()
    assert isinstance(sfs, list)
    assert len(sfs) == _N_SUPER_FAMILIES
    for sf in sfs:
        assert "super_family" in sf
        assert "families" in sf


async def test_generate_waveform(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get(
        "/api/signals/generate",
        headers=api_key_header,
        params={"class": "bpsk", "snr": 15.0, "n": 256},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["signal_class"] == "bpsk"
    assert len(body["iq_real"]) == 256


async def test_generate_unknown_class(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get(
        "/api/signals/generate",
        headers=api_key_header,
        params={"class": "not-a-real-signal"},
    )
    assert resp.status_code == 400


async def test_dsp_features(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get(
        "/api/signals/dsp-features",
        headers=api_key_header,
        params={"class": "qpsk", "snr": 10.0},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "features" in body
    assert body["signal_class"] == "qpsk"
