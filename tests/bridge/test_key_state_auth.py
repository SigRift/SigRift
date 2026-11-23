"""Bridge auth must reject key states the gateway refuses.

Gateway fallback routes forward X-API-Key even after gateway authentication
fails. Exercise the bridge's real HTTP/WebSocket dependencies and persisted
key metadata, including an earlier successful verification cached in memory.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi import Depends, FastAPI, WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import sigrift.bridge.dependencies as deps
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
)


@pytest.fixture(autouse=True)
def fresh_auth_cache():
    deps._verified_key_cache.clear()
    yield
    deps._verified_key_cache.clear()


@pytest.mark.parametrize("cached", [False, True])
@pytest.mark.parametrize(
    "inactive",
    [{"enabled": False}, {"revoked": True}, {"expires_at": "not-a-date"}],
    ids=["disabled", "revoked", "malformed-expiry"],
)
def test_persisted_inactive_key_is_refused_by_http_and_ws(
    persistence, inactive, cached
):
    raw = generate_api_key(32)
    hash_hex, salt = hash_credential(raw)
    persistence.add_key(
        "operator",
        hash_hex,
        salt,
        lookup_hash=compute_lookup_hash(raw),
        meta={"role": "viewer"},
    )
    app = FastAPI()
    app.state.persistence = persistence
    app.state.detection_store = None

    @app.get("/guard")
    async def guard(principal: str = Depends(deps.require_api_key)):
        return {"principal": principal}

    @app.websocket("/guard/ws")
    async def guard_ws(ws: WebSocket):
        principal, _, protocol = await deps._authenticate_ws(ws)
        await ws.accept(subprotocol=protocol)
        await ws.send_json({"principal": principal})
        await ws.close()

    with TestClient(app) as client:
        if cached:
            assert client.get("/guard", headers={"X-API-Key": raw}).status_code == 200
            with client.websocket_connect(
                "/guard/ws", subprotocols=["bridge-v1", raw]
            ) as ws:
                assert ws.receive_json()["principal"] == "operator"

        persistence.set_key_meta("operator", {"role": "viewer", **inactive})
        # Both a cold lookup and an existing successful cache entry must
        # refuse the new state without doing another PBKDF2 verification.
        with patch.object(deps, "verify_credential") as verify:
            response = client.get("/guard", headers={"X-API-Key": raw})
            assert response.status_code == 401, response.text
            for headers, protocols in (
                ({"X-API-Key": raw}, []),
                ({}, ["bridge-v1", raw]),
            ):
                with pytest.raises(WebSocketDisconnect) as exc:
                    with client.websocket_connect(
                        "/guard/ws", headers=headers, subprotocols=protocols
                    ):
                        pytest.fail("Inactive key opened a WebSocket")
                assert exc.value.code == 4001
            verify.assert_not_called()


@pytest.mark.parametrize(
    "inactive",
    [{"enabled": False}, {"revoked": True}, {"expires_at": "not-a-date"}],
)
def test_legacy_scans_skip_inactive_keys(inactive):
    # No lookup hash: the legacy scan used to PBKDF2-check these entries
    # and accept their roles even when persisted revocation was set.
    store = {"legacy": ("unused-hash", b"unused-salt")}
    meta = {"legacy": {"role": "admin", **inactive}}
    with patch.object(deps, "verify_credential", return_value=True) as verify:
        assert deps._lookup_key("credential", store, meta) == (None, None)
        assert asyncio.run(deps._lookup_key_async("credential", store, meta)) == (
            None,
            None,
        )
        verify.assert_not_called()


@pytest.mark.parametrize("expiry", [None, "", "  "])
def test_legacy_empty_expiry_remains_non_expiring(expiry):
    assert deps._key_usable({"expires_at": expiry})


def test_missing_state_fields_and_valid_expiry_keep_their_policy():
    assert deps._key_usable({})
    future = datetime.now(timezone.utc) + timedelta(days=1)
    past = datetime.now(timezone.utc) - timedelta(days=1)
    assert deps._key_usable({"expires_at": future.isoformat()})
    assert not deps._key_usable({"expires_at": past.isoformat()})


_UTC_2999 = datetime(2999, 1, 1, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("stored", "expiry"),
    [
        (None, None),
        ("", None),
        ("  ", None),
        ("2999-01-01T00:00:00+00:00", _UTC_2999),
        ("2999-01-01T00:00:00", _UTC_2999),
        (" 2999-01-01T00:00:00Z ", _UTC_2999),
        ("2999-01-01T02:00:00+02:00", _UTC_2999),
    ],
)
@pytest.mark.usefixtures("local_time_not_utc")
def test_key_expiry_is_the_instant_auth_applies(stored, expiry):
    """The one parser auth and the key listings share: blank is none,
    padding is ignored and a naive value is UTC (not the host's local time,
    which the fixture moves off UTC so this holds on a UTC host too)."""
    parsed = deps.key_expiry({"expires_at": stored})
    assert parsed == expiry
    if parsed is not None:
        assert parsed.tzinfo is not None
    assert deps.key_expired({"expires_at": stored}) is False


@pytest.mark.usefixtures("local_time_not_utc")
def test_a_naive_expiry_that_passed_in_utc_is_refused_whatever_the_local_time():
    """Read as local time (7 hours west of UTC here), a naive expiry 3 hours
    ago in UTC would still be 4 hours away, and auth would accept the key."""
    passed = (datetime.now(timezone.utc) - timedelta(hours=3)).replace(tzinfo=None)
    meta = {"expires_at": passed.isoformat()}
    assert deps.key_expired(meta) is True
    assert not deps._key_usable(meta)


@pytest.mark.parametrize(
    "stored",
    ["2030-01-01T00:00:00+00:00", "2030-01-01T00:00:00", "2030-01-01T02:00:00+02:00"],
    ids=["aware", "naive", "offset"],
)
def test_a_key_is_usable_up_to_and_including_its_expiry_instant(stored):
    """As on the gateway (``now <= expires_at`` is usable): the key expires
    once the clock is past its instant, not at the instant itself."""
    at = datetime(2030, 1, 1, tzinfo=timezone.utc)
    meta = {"expires_at": stored}
    assert deps.key_expired(meta, now=at - timedelta(microseconds=1)) is False
    assert deps.key_expired(meta, now=at) is False
    assert deps.key_expired(meta, now=at + timedelta(microseconds=1)) is True


@pytest.mark.parametrize("stored", ["soon", 12345, True, ["2999-01-01"], {"a": 1}])
def test_a_malformed_expiry_has_no_instant_and_counts_as_expired(stored):
    with pytest.raises(ValueError):
        deps.key_expiry({"expires_at": stored})
    assert deps.key_expired({"expires_at": stored}) is True
    assert not deps._key_usable({"expires_at": stored})


@pytest.mark.parametrize("inactive", [{"enabled": False}, {"revoked": True}])
def test_inactive_key_does_not_hold_a_node_claim(inactive):
    assert not deps._holds_node("node-a")("old-key", {"node_id": "node-a", **inactive})
