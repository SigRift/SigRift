"""Security-path tests for the Shiny dashboard key router (``/api/keys``).

Integration tests: the real router on the conftest app, real keys hashed
into a real ``PersistenceManager`` (``keys.json`` in ``tmp_path``) and
authenticated by the real dependencies.

``test_keys.py`` has the happy paths; ``test_roles_and_ws_auth.py`` covers
roles, purposes, expiry and ``PATCH``. This file adds: every endpoint
without a key, the non-master refusals for create / revoke / rotate,
rotation and revocation taking effect (also after a reload from disk),
raw keys, hashes and salts never leaving the server or reaching the
logs, HTML escaping of user strings and path ids, unknown stored roles,
unparseable stored timestamps (and the ``expired`` flag they list with),
the master key refusing revocation, the bounds on ``expires_in_hours``,
and a non-finite number anywhere in a create body being a 422, not a 500.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.lib.shiny.dependencies import clear_fast_hash_index
from sigrift.lib.shiny.models import MAX_KEY_EXPIRES_IN_HOURS
from sigrift.lib.shiny.persistence import PersistenceManager
from sigrift.lib.shiny.state import AppState

pytestmark = pytest.mark.asyncio

_XSS = '<img src=x onerror="alert(1)">'


@pytest.fixture(autouse=True)
def _fresh_index():
    clear_fast_hash_index()
    yield
    clear_fast_hash_index()


def _h(raw: str) -> dict[str, str]:
    return {"X-API-Key": raw}


def _add_key(pm: PersistenceManager, key_id: str, **meta: Any) -> str:
    raw = generate_api_key()
    hash_hex, salt = hash_credential(raw)
    pm.set_key(key_id, hash_hex, salt, meta=meta or None)
    return raw


def _reloaded(pm: PersistenceManager) -> PersistenceManager:
    fresh = PersistenceManager(data_dir=pm.data_dir, auto_save_interval=0)
    fresh.load_all()
    return fresh


async def _create(
    client: httpx.AsyncClient, master: dict[str, str], **body: Any
) -> dict[str, Any]:
    resp = await client.post("/api/keys/", headers=master, json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _endpoints(key_id: str) -> list[tuple[str, str, dict | None]]:
    return [
        ("POST", "/api/keys/", {"key_id": "intruder", "role": "admin"}),
        ("GET", "/api/keys/", None),
        ("PATCH", f"/api/keys/{key_id}", {"node_id": "edge-01"}),
        ("DELETE", f"/api/keys/{key_id}", None),
        ("PUT", f"/api/keys/{key_id}/rotate", None),
    ]


# ---------------------------------------------------------------------------
# Authentication and authorization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", [None, "", "not-a-real-key"])
async def test_every_endpoint_needs_a_valid_key(
    test_client: httpx.AsyncClient, mock_persistence: PersistenceManager, key
) -> None:
    _add_key(mock_persistence, "target", role="viewer")
    before = mock_persistence.get_key_store()
    headers = {} if key is None else {"X-API-Key": key}
    for method, path, body in _endpoints("target"):
        resp = await test_client.request(method, path, headers=headers, json=body)
        assert resp.status_code == 401, (method, path)
    assert mock_persistence.get_key_store() == before


@pytest.mark.parametrize("who", ["admin", "node", "viewer"])
async def test_only_the_master_key_creates_revokes_or_rotates(
    test_client: httpx.AsyncClient,
    mock_persistence: PersistenceManager,
    mock_app_state: AppState,
    admin_key_header: dict[str, str],
    node_key_header: dict[str, str],
    api_key_header: dict[str, str],
    who: str,
) -> None:
    headers = {
        "admin": admin_key_header,
        "node": node_key_header,
        "viewer": api_key_header,
    }[who]
    target = _add_key(mock_persistence, "target", role="analyst")
    before = mock_persistence.get_key_store()
    for method, path, body in _endpoints("target"):
        if method == "GET":
            continue
        resp = await test_client.request(method, path, headers=headers, json=body)
        assert resp.status_code == 403, (method, path)
        assert "raw_key" not in resp.text
    assert mock_persistence.get_key_store() == before
    assert "intruder" not in mock_persistence.get_key_store()
    assert (await test_client.get("/api/keys/", headers=_h(target))).status_code == 200
    assert not [e for e in mock_app_state.activity_log if "key_" in e["event_type"]]


async def test_any_valid_key_may_list_but_sees_no_secrets(
    test_client: httpx.AsyncClient,
    mock_persistence: PersistenceManager,
    master_key_header: dict[str, str],
    node_key_header: dict[str, str],
) -> None:
    created = await _create(test_client, master_key_header, key_id="listed")
    resp = await test_client.get("/api/keys/", headers=node_key_header)
    assert resp.status_code == 200
    assert {"listed", "master", "test-node"} <= {k["key_id"] for k in resp.json()}
    assert created["raw_key"] not in resp.text
    for hash_hex, salt in mock_persistence.get_key_store().values():
        assert hash_hex not in resp.text
        assert salt.hex() not in resp.text
    for row in resp.json():
        assert not {"raw_key", "hash", "salt"} & set(row)


# ---------------------------------------------------------------------------
# Rotation and revocation take effect
# ---------------------------------------------------------------------------


async def test_rotation_invalidates_the_old_key(
    test_client: httpx.AsyncClient,
    mock_persistence: PersistenceManager,
    mock_app_state: AppState,
    master_key_header: dict[str, str],
) -> None:
    created = await _create(
        test_client, master_key_header, key_id="rot", role="analyst", node_id="edge-01"
    )
    old = created["raw_key"]
    assert (await test_client.get("/api/keys/", headers=_h(old))).status_code == 200

    resp = await test_client.put("/api/keys/rot/rotate", headers=master_key_header)
    assert resp.status_code == 200
    new = resp.json()["raw_key"]
    assert new != old

    assert (await test_client.get("/api/keys/", headers=_h(old))).status_code == 401
    assert (await test_client.get("/api/keys/", headers=_h(new))).status_code == 200
    meta = _reloaded(mock_persistence).get_key_meta("rot")
    assert meta["role"] == "analyst" and meta["node_id"] == "edge-01"
    assert "rotated_at" in meta
    assert mock_app_state.activity_log[-1]["event_type"] == "key_rotated"


async def test_the_master_key_can_rotate_itself(
    test_client: httpx.AsyncClient,
    master_key: str,
    master_key_header: dict[str, str],
) -> None:
    resp = await test_client.put("/api/keys/master/rotate", headers=master_key_header)
    assert resp.status_code == 200
    new = resp.json()["raw_key"]
    probe = {"key_id": "after-rotation"}
    stale = await test_client.post("/api/keys/", headers=master_key_header, json=probe)
    assert stale.status_code == 401
    fresh = await test_client.post("/api/keys/", headers=_h(new), json=probe)
    assert fresh.status_code == 201


async def test_revocation_takes_effect_and_persists(
    test_client: httpx.AsyncClient,
    mock_persistence: PersistenceManager,
    master_key_header: dict[str, str],
) -> None:
    raw = (await _create(test_client, master_key_header, key_id="doomed"))["raw_key"]
    assert (await test_client.get("/api/keys/", headers=_h(raw))).status_code == 200

    resp = await test_client.delete("/api/keys/doomed", headers=master_key_header)
    assert resp.status_code == 200

    assert (await test_client.get("/api/keys/", headers=_h(raw))).status_code == 401
    assert "doomed" not in _reloaded(mock_persistence).get_key_store()
    resp = await test_client.put("/api/keys/doomed/rotate", headers=master_key_header)
    assert resp.status_code == 404  # cannot be resurrected by rotation
    assert "doomed" not in mock_persistence.get_key_store()


async def test_the_master_key_cannot_be_revoked(
    test_client: httpx.AsyncClient,
    mock_persistence: PersistenceManager,
    mock_app_state: AppState,
    master_key_header: dict[str, str],
    api_key_header: dict[str, str],  # another key exists
) -> None:
    # Revoking it would remove the only key that can manage keys until a
    # restart generates a new one.
    resp = await test_client.delete("/api/keys/master", headers=master_key_header)
    assert resp.status_code == 400
    assert "cannot be revoked" in resp.json()["detail"]
    assert "master" in mock_persistence.get_key_store()
    assert "master" in _reloaded(mock_persistence).get_key_store()
    assert not [e for e in mock_app_state.activity_log if "key_" in e["event_type"]]
    # ... and it still manages keys.
    await _create(test_client, master_key_header, key_id="after-refusal")


# ---------------------------------------------------------------------------
# Secrets never leave the server or reach the logs
# ---------------------------------------------------------------------------


async def test_raw_keys_are_shown_once_and_never_logged_or_stored(
    test_client: httpx.AsyncClient,
    mock_persistence: PersistenceManager,
    mock_app_state: AppState,
    master_key_header: dict[str, str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG):
        created = await _create(test_client, master_key_header, key_id="secret")
        rotated = (
            await test_client.put("/api/keys/secret/rotate", headers=master_key_header)
        ).json()
        listed = await test_client.get("/api/keys/", headers=master_key_header)
    raws = [created["raw_key"], rotated["raw_key"]]

    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "API key created: secret" in logged and "API key rotated: secret" in logged
    activity = json.dumps(list(mock_app_state.activity_log))
    on_disk = (mock_persistence.data_dir / "keys.json").read_text(encoding="utf-8")
    assert (mock_persistence.data_dir / "keys.json").stat().st_mode & 0o077 == 0
    for raw in raws:
        for text in (logged, activity, on_disk, listed.text):
            assert raw not in text
    # What is stored is a salted hash of the current key only.
    stored = json.loads(on_disk)["keys"]["secret"]
    assert (stored["hash"], bytes.fromhex(stored["salt"])) == (
        mock_persistence.get_key_store()["secret"]
    )


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------


async def test_description_is_html_escaped_everywhere(
    test_client: httpx.AsyncClient,
    mock_persistence: PersistenceManager,
    master_key_header: dict[str, str],
) -> None:
    created = await _create(
        test_client, master_key_header, key_id="xss", description=_XSS
    )
    escaped = "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;"
    assert created["description"] == escaped
    assert mock_persistence.get_key_meta("xss")["description"] == escaped
    assert _reloaded(mock_persistence).get_key_meta("xss")["description"] == escaped
    listed = await test_client.get("/api/keys/", headers=master_key_header)
    (row,) = [k for k in listed.json() if k["key_id"] == "xss"]
    assert row["description"] == escaped
    assert "<img" not in listed.text


@pytest.mark.parametrize(
    ("method", "suffix", "body"),
    [
        ("DELETE", "", None),
        ("PUT", "/rotate", None),
        ("PATCH", "", {"node_id": None}),
    ],
)
async def test_unknown_path_ids_are_escaped_in_errors(
    test_client: httpx.AsyncClient,
    master_key_header: dict[str, str],
    method: str,
    suffix: str,
    body: dict | None,
) -> None:
    # No "/" in the id, so the request still reaches the key routes.
    resp = await test_client.request(
        method,
        '/api/keys/<svg onload="alert(1)">' + suffix,
        headers=master_key_header,
        json=body,
    )
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert detail == "Key &lt;svg onload=&quot;alert(1)&quot;&gt; not found"


@pytest.mark.parametrize(
    "body",
    [
        {"key_id": "../master"},
        {"key_id": "master; rm"},
        {"key_id": "a" * 65},
        {"key_id": ""},
        {"key_id": "ok", "raw_key": "chosen-by-attacker"},
        {"key_id": "ok", "role": "keymaster"},
    ],
)
async def test_create_rejects_bad_ids_and_extra_fields(
    test_client: httpx.AsyncClient,
    mock_persistence: PersistenceManager,
    master_key_header: dict[str, str],
    body: dict,
) -> None:
    before = set(mock_persistence.get_key_store())
    resp = await test_client.post("/api/keys/", headers=master_key_header, json=body)
    assert resp.status_code == 422
    assert set(mock_persistence.get_key_store()) == before


async def test_unknown_stored_role_is_shown_as_invalid_and_cannot_authenticate(
    test_client: httpx.AsyncClient,
    mock_persistence: PersistenceManager,
    master_key_header: dict[str, str],
) -> None:
    raw = _add_key(mock_persistence, "odd", role="superuser")
    listed = await test_client.get("/api/keys/", headers=master_key_header)
    (row,) = [k for k in listed.json() if k["key_id"] == "odd"]
    assert row["role"] == "invalid:superuser"  # not silently a viewer or admin
    resp = await test_client.get("/api/keys/", headers=_h(raw))
    assert resp.status_code == 401
    assert "unknown role" in resp.json()["detail"]


async def test_unparseable_stored_timestamps_do_not_break_the_listing(
    test_client: httpx.AsyncClient,
    mock_persistence: PersistenceManager,
    master_key_header: dict[str, str],
) -> None:
    _add_key(mock_persistence, "garbled", created_at="yesterday-ish", last_used="?")
    listed = await test_client.get("/api/keys/", headers=master_key_header)
    assert listed.status_code == 200
    (row,) = [k for k in listed.json() if k["key_id"] == "garbled"]
    assert row["created_at"]  # falls back to "now" rather than failing
    assert row["last_used"] is None


async def test_an_out_of_range_expiry_is_a_validation_error(
    test_app: FastAPI,
    mock_persistence: PersistenceManager,
    master_key_header: dict[str, str],
) -> None:
    transport = httpx.ASGITransport(app=test_app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/keys/",
            headers=master_key_header,
            json={"key_id": "forever", "expires_in_hours": 1e9},
        )
    assert resp.status_code == 422
    assert "forever" not in mock_persistence.get_key_store()


# Sent as raw JSON text: Starlette's json.loads accepts the bare NaN and
# Infinity tokens, which ``json=`` would refuse to encode.
@pytest.mark.parametrize(
    ("hours", "message"),
    [
        (
            f"{MAX_KEY_EXPIRES_IN_HOURS + 1}",
            f"less than or equal to {MAX_KEY_EXPIRES_IN_HOURS}",
        ),
        ("1e308", f"less than or equal to {MAX_KEY_EXPIRES_IN_HOURS}"),
        ("Infinity", "finite number"),
        ("-Infinity", "finite number"),
        ("NaN", "finite number"),
    ],
)
async def test_a_too_long_or_non_finite_expiry_is_refused(
    test_app: FastAPI,
    mock_persistence: PersistenceManager,
    mock_app_state: AppState,
    master_key_header: dict[str, str],
    hours: str,
    message: str,
) -> None:
    transport = httpx.ASGITransport(app=test_app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/keys/",
            headers={**master_key_header, "Content-Type": "application/json"},
            content=f'{{"key_id": "forever", "expires_in_hours": {hours}}}',
        )
    assert resp.status_code == 422, resp.text
    (error,) = resp.json()["detail"]
    assert error["loc"] == ["body", "expires_in_hours"]
    assert message in error["msg"]
    assert "forever" not in mock_persistence.get_key_store()
    assert not [e for e in mock_app_state.activity_log if "key_" in e["event_type"]]


async def test_the_longest_documented_expiry_is_accepted(
    test_client: httpx.AsyncClient,
    mock_persistence: PersistenceManager,
    master_key_header: dict[str, str],
) -> None:
    created = await _create(
        test_client,
        master_key_header,
        key_id="long",
        expires_in_hours=MAX_KEY_EXPIRES_IN_HOURS,
    )
    expected = datetime.now(timezone.utc) + timedelta(hours=MAX_KEY_EXPIRES_IN_HOURS)
    stored = datetime.fromisoformat(mock_persistence.get_key_meta("long")["expires_at"])
    assert abs((stored - expected).total_seconds()) < 60
    assert created["expires_at"] == stored.isoformat()


@pytest.mark.parametrize(
    ("stored", "expired"),
    [
        (None, False),
        ("2999-01-01T00:00:00+00:00", False),
        ("2000-01-01T00:00:00+00:00", True),
        ("2000-01-01T00:00:00", True),  # naive: read as UTC
        ("next tuesday", True),
        (12345, True),
        (0, True),
        (False, True),
        ([], True),
        ("  ", True),
    ],
)
async def test_the_listing_flags_keys_that_are_rejected_as_expired(
    test_client: httpx.AsyncClient,
    mock_persistence: PersistenceManager,
    master_key_header: dict[str, str],
    stored: Any,
    expired: bool,
) -> None:
    # An unparseable stored expiry is listed as expires_at null (the
    # dashboard would show "Never"), yet the auth layer rejects the key:
    # "expired" says which it is.
    raw = _add_key(mock_persistence, "dated", expires_at=stored)
    listed = await test_client.get("/api/keys/", headers=master_key_header)
    assert listed.status_code == 200
    rows = {k["key_id"]: k for k in listed.json()}
    assert rows["dated"]["expired"] is expired
    assert rows["master"]["expired"] is False
    resp = await test_client.get("/api/keys/", headers=_h(raw))
    assert resp.status_code == (401 if expired else 200)


# Raw JSON text, as above.  The 422 echoes the rejected input, and a
# non-finite float in it used to fail to encode: the 422 became a 500.
@pytest.mark.parametrize(
    ("body", "loc", "echoed"),
    [
        ('{"key_id": NaN}', ["body", "key_id"], "NaN"),
        (
            '{"key_id": "k", "description": Infinity}',
            ["body", "description"],
            "Infinity",
        ),
        ('{"key_id": "k", "node_id": NaN}', ["body", "node_id"], "NaN"),
        ('{"key_id": "k", "role": -Infinity}', ["body", "role"], "-Infinity"),
        ('{"key_id": "k", "surplus": NaN}', ["body", "surplus"], "NaN"),
        (
            '{"key_id": "k", "expires_in_hours": [NaN]}',
            ["body", "expires_in_hours"],
            ["NaN"],
        ),
    ],
)
async def test_a_non_finite_number_anywhere_is_a_422_not_a_500(
    test_app: FastAPI,
    mock_persistence: PersistenceManager,
    mock_app_state: AppState,
    master_key_header: dict[str, str],
    body: str,
    loc: list[str],
    echoed: Any,
) -> None:
    before = sorted(mock_persistence.get_key_store())
    transport = httpx.ASGITransport(app=test_app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/keys/",
            headers={**master_key_header, "Content-Type": "application/json"},
            content=body,
        )
    assert resp.status_code == 422, resp.text
    (error,) = resp.json()["detail"]
    assert error["loc"] == loc
    assert error["input"] == echoed
    assert sorted(mock_persistence.get_key_store()) == before
    assert not [e for e in mock_app_state.activity_log if "key_" in e["event_type"]]


async def test_the_production_app_answers_validation_errors_json_safely() -> None:
    # The test_app fixture installs the handler as the production app does.
    from fastapi.exceptions import RequestValidationError

    from sigrift.lib.shiny.app import app
    from sigrift.lib.validation_errors import request_validation_handler

    assert app.exception_handlers[RequestValidationError] is request_validation_handler
