"""Security-path tests for ``routers/keys.py`` (``/api/keys``) over HTTP.

Real test app, real ``PersistenceManager`` (keys.json on disk). Basic CRUD
is in test_keys_router.py and master-key / keymaster ceilings in
test_round3_bridge_auth.py; these tests add the end-to-end lifecycles and
the refusals around them:

* create -> use -> revoke -> the key is rejected at once (even though its
  last verification was cached) and is gone from keys.json;
* create -> use -> rotate -> only the new raw key works, metadata kept;
* expiry is capped at the maximum lifetime and defaults to it, and a
  lifetime past the absolute ceiling or not finite is a 422;
* a key created for a node may act only for that node;
* every mutating endpoint refuses sensor / viewer / analyst keys and a
  foreign tenant's admin key, without changing the key store;
* a non-finite number anywhere in a create body is a 422, not a 500;
* list survives malformed (also non-string) stored dates and never leaks
  credentials, and both key lists (also ``/api/admin/keys``) flag exactly
  the keys auth rejects as expired;
* rotate / rotate-master on a missing key, a master entry removed or
  replaced concurrently, and rotation without an audit store.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import sigrift.bridge.dependencies as deps
import sigrift.bridge.routers.keys as keys_mod
from sigrift.bridge.persistence import PersistenceManager
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
)
from sigrift.lib.shiny.models import MAX_KEY_EXPIRES_IN_HOURS


@pytest.fixture(autouse=True)
def _fresh_cache():
    deps._verified_key_cache.clear()
    yield
    deps._verified_key_cache.clear()


def _add_key(persistence: PersistenceManager, key_id: str, role: str, **meta) -> str:
    raw = generate_api_key(32)
    hash_hex, salt = hash_credential(raw)
    full = {"role": role, "description": "", "created_at": "", "expires_at": None}
    full.update(meta)
    assert persistence.add_key(
        key_id, hash_hex, salt, lookup_hash=compute_lookup_hash(raw), meta=full
    )
    return raw


def _as(app: FastAPI, raw: str) -> TestClient:
    return TestClient(app, headers={"X-API-Key": raw})


def _keys_json(persistence: PersistenceManager) -> dict:
    return json.loads((persistence._data_dir / "keys.json").read_text())


def _activity(app_state, event_type: str) -> list[dict]:
    return [e for e in app_state.activity_log if e["event_type"] == event_type]


_SECRET_FIELDS = {"hash", "hash_hex", "salt", "lookup_hash", "raw_key", "key_hash"}


# ---------------------------------------------------------------------------
# Lifecycles
# ---------------------------------------------------------------------------


class TestKeyLifecycle:
    def test_create_use_revoke_then_rejected(
        self, bridge_app, client, persistence, app_state
    ) -> None:
        created = client.post(
            "/api/keys/", json={"key_id": "ops-tool", "description": "<b>ops</b>"}
        )
        assert created.status_code == 201, created.text
        body = created.json()
        raw = body["raw_key"]
        assert body["key_id"] == "ops-tool"
        assert body["description"] == "&lt;b&gt;ops&lt;/b&gt;"
        assert "hash" not in json.dumps(body).lower()

        # Stored hashed only: the raw key appears nowhere on disk.
        on_disk = (persistence._data_dir / "keys.json").read_text()
        assert raw not in on_disk
        assert _keys_json(persistence)["keys"]["ops-tool"]["role"] == "analyst"

        tool = _as(bridge_app, raw)
        me = tool.get("/api/auth/me")
        assert me.json() == {
            "auth_type": "api_key",
            "key_id": "ops-tool",
            "role": "analyst",
        }
        assert tool.get("/api/keys/").status_code == 200
        # An analyst key may not manage keys itself.
        assert tool.post("/api/keys/", json={"key_id": "sneaky"}).status_code == 403
        assert tool.delete("/api/keys/master").status_code == 403

        revoked = client.delete("/api/keys/ops-tool")
        assert revoked.json() == {"status": "ok", "revoked": "ops-tool"}
        # Rejected immediately, although the last check was cached.
        assert tool.get("/api/auth/me").status_code == 401
        assert tool.get("/api/keys/").status_code == 401
        assert "ops-tool" not in _keys_json(persistence)["keys"]
        listed = [k["key_id"] for k in client.get("/api/keys/").json()]
        assert "ops-tool" not in listed
        assert client.delete("/api/keys/ops-tool").status_code == 404
        assert len(_activity(app_state, "key_created")) == 1
        assert len(_activity(app_state, "key_revoked")) == 1

    def test_create_use_rotate_only_new_key_works(
        self, bridge_app, client, persistence, app_state
    ) -> None:
        raw = client.post(
            "/api/keys/",
            json={"key_id": "rotor", "description": "d", "node_id": "edge-1"},
        ).json()["raw_key"]
        old = _as(bridge_app, raw)
        assert old.get("/api/auth/me").status_code == 200  # cache the old key

        rotated = client.put("/api/keys/rotor/rotate")
        assert rotated.status_code == 200, rotated.text
        new_raw = rotated.json()["raw_key"]
        assert new_raw != raw

        assert old.get("/api/auth/me").status_code == 401
        me = _as(bridge_app, new_raw).get("/api/auth/me")
        assert me.json() == {
            "auth_type": "api_key",
            "key_id": "rotor",
            "role": "analyst",
        }
        meta = persistence.get_key_meta()["rotor"]
        assert meta["description"] == "d"
        assert meta["node_id"] == "edge-1"
        assert meta["role"] == "analyst"
        assert meta["rotated_at"] == rotated.json()["rotated_at"]
        assert len(_activity(app_state, "key_rotated")) == 1

    def test_master_key_cannot_revoke_itself(self, client) -> None:
        resp = client.delete("/api/keys/master")
        assert resp.status_code == 403
        assert resp.json() == {"detail": "Cannot revoke master key"}
        assert client.get("/api/keys/").status_code == 200

    def test_rotate_master_flow(
        self, bridge_app, client, master_key, detection_store
    ) -> None:
        assert client.get("/api/auth/me").status_code == 200
        resp = client.post("/api/keys/rotate-master")
        assert resp.status_code == 200, resp.text
        new_master = resp.json()["raw_key"]
        assert client.get("/api/auth/me").status_code == 401
        me = _as(bridge_app, new_master).get("/api/auth/me").json()
        assert me == {"auth_type": "api_key", "key_id": "master", "role": "admin"}
        assert (
            detection_store.count_audit_log(
                action="master_key_rotated", target_id="master"
            )
            == 1
        )


class TestExpiry:
    def _expires(self, persistence, key_id: str) -> datetime:
        return datetime.fromisoformat(persistence.get_key_meta()[key_id]["expires_at"])

    @pytest.mark.parametrize("hours", [10**7, 365 * 24 + 1])
    def test_requested_lifetime_is_capped(self, client, persistence, hours) -> None:
        resp = client.post(
            "/api/keys/", json={"key_id": "long", "expires_in_hours": hours}
        )
        assert resp.status_code == 201
        cap = datetime.now(timezone.utc) + timedelta(
            days=keys_mod._MAX_KEY_LIFETIME_DAYS
        )
        expires = self._expires(persistence, "long")
        assert abs((expires - cap).total_seconds()) < 60
        assert resp.json()["expires_at"] == expires.isoformat()

    @pytest.mark.parametrize("hours", [None, 0, -5])
    def test_no_or_non_positive_lifetime_gets_the_default(
        self, client, persistence, hours
    ) -> None:
        body = {"key_id": "dflt"}
        if hours is not None:
            body["expires_in_hours"] = hours
        assert client.post("/api/keys/", json=body).status_code == 201
        cap = datetime.now(timezone.utc) + timedelta(
            days=keys_mod._MAX_KEY_LIFETIME_DAYS
        )
        assert abs((self._expires(persistence, "dflt") - cap).total_seconds()) < 60

    # Raw JSON text: the server's json.loads accepts bare NaN / Infinity.
    @pytest.mark.parametrize(
        ("hours", "message"),
        [
            (f"{MAX_KEY_EXPIRES_IN_HOURS + 1}", "less than or equal to"),
            ("1e9", "less than or equal to"),
            ("1e308", "less than or equal to"),
            ("Infinity", "finite number"),
            ("-Infinity", "finite number"),
            ("NaN", "finite number"),
        ],
    )
    def test_an_out_of_range_or_non_finite_lifetime_is_refused(
        self, bridge_app, master_key, persistence, app_state, hours, message
    ) -> None:
        # 1e9 hours used to overflow the expiry datetime (500) before the
        # cap could apply; NaN and -Infinity silently got the default.
        client = TestClient(
            bridge_app,
            headers={"X-API-Key": master_key, "Content-Type": "application/json"},
            raise_server_exceptions=False,
        )
        resp = client.post(
            "/api/keys/",
            content=f'{{"key_id": "forever", "expires_in_hours": {hours}}}',
        )
        assert resp.status_code == 422, resp.text
        (error,) = resp.json()["detail"]
        assert error["loc"] == ["body", "expires_in_hours"]
        assert message in error["msg"]
        assert "forever" not in persistence.get_key_store()
        assert not _activity(app_state, "key_created")

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
            ('{"key_id": "k", "surplus": -Infinity}', ["body", "surplus"], "-Infinity"),
            (
                '{"key_id": "k", "expires_in_hours": [NaN]}',
                ["body", "expires_in_hours"],
                ["NaN"],
            ),
        ],
    )
    def test_a_non_finite_number_anywhere_is_a_422_not_a_500(
        self, bridge_app, master_key, persistence, app_state, body, loc, echoed
    ) -> None:
        # The 422 echoes the rejected input, which used to fail to encode.
        client = TestClient(
            bridge_app,
            headers={"X-API-Key": master_key, "Content-Type": "application/json"},
            raise_server_exceptions=False,
        )
        before = sorted(persistence.get_key_store())
        resp = client.post("/api/keys/", content=body)
        assert resp.status_code == 422, resp.text
        (error,) = resp.json()["detail"]
        assert error["loc"] == loc
        assert error["input"] == echoed
        assert sorted(persistence.get_key_store()) == before
        assert not _activity(app_state, "key_created")

    def test_the_production_app_answers_validation_errors_json_safely(
        self,
    ) -> None:
        # create_test_app installs the handler the same way; this pins the
        # module-level production app too.
        from fastapi.exceptions import RequestValidationError

        from sigrift.bridge.app import app
        from sigrift.lib.validation_errors import request_validation_handler

        assert app.exception_handlers[RequestValidationError] is (
            request_validation_handler
        )

    def test_a_huge_configured_maximum_falls_back_to_the_ceiling(
        self, client, persistence, monkeypatch
    ) -> None:
        # timedelta(days=10**9) overflows, so every create used to fail.
        monkeypatch.setattr(keys_mod, "_MAX_KEY_LIFETIME_DAYS", 10**9)
        resp = client.post("/api/keys/", json={"key_id": "dflt"})
        assert resp.status_code == 201, resp.text
        cap = datetime.now(timezone.utc) + timedelta(hours=MAX_KEY_EXPIRES_IN_HOURS)
        assert abs((self._expires(persistence, "dflt") - cap).total_seconds()) < 60

    def test_short_lived_key_stops_working_when_it_expires(
        self, bridge_app, client, persistence
    ) -> None:
        raw = client.post(
            "/api/keys/", json={"key_id": "brief", "expires_in_hours": 1}
        ).json()["raw_key"]
        assert _as(bridge_app, raw).get("/api/auth/me").status_code == 200
        meta = persistence.get_key_meta()["brief"]
        meta["expires_at"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat()
        persistence.set_key_meta("brief", meta)
        assert _as(bridge_app, raw).get("/api/auth/me").status_code == 401


class TestNodeScopedKey:
    def test_key_created_for_a_node_acts_only_for_it(self, bridge_app, client) -> None:
        for node in ("edge-1", "edge-2"):
            assert (
                client.post("/api/nodes/register", json={"node_id": node}).status_code
                == 200
            )
        raw = client.post(
            "/api/keys/", json={"key_id": "edge-1-key", "node_id": "edge-1"}
        ).json()["raw_key"]
        node = _as(bridge_app, raw)
        assert (
            node.post("/api/nodes/heartbeat", json={"node_id": "edge-1"}).status_code
            == 200
        )
        other = node.post("/api/nodes/heartbeat", json={"node_id": "edge-2"})
        assert other.status_code == 403
        assert "bound to node 'edge-1'" in other.json()["detail"]


# ---------------------------------------------------------------------------
# Who may call the mutating endpoints
# ---------------------------------------------------------------------------

_MUTATIONS = [
    ("post", "/api/keys/", {"key_id": "evil"}),
    ("delete", "/api/keys/victim", None),
    ("put", "/api/keys/victim/rotate", None),
    ("post", "/api/keys/rotate-master", None),
]


class TestMutationsRefuseNonAdmins:
    @pytest.fixture
    def victim(self, persistence) -> dict:
        _add_key(persistence, "victim", "sensor")
        return dict(persistence.get_key_store())

    @pytest.mark.parametrize("method, path, body", _MUTATIONS)
    @pytest.mark.parametrize("role", ["sensor", "node", "viewer", "analyst"])
    def test_below_admin_is_403(
        self, bridge_app, persistence, victim, role, method, path, body
    ) -> None:
        c = _as(bridge_app, _add_key(persistence, f"{role}-caller", role))
        before = dict(persistence.get_key_store())
        kwargs = {"json": body} if body is not None else {}
        resp = getattr(c, method)(path, **kwargs)
        assert resp.status_code == 403, resp.text
        assert resp.json() == {"detail": "Admin role required"}
        assert persistence.get_key_store() == before
        assert "evil" not in persistence.get_key_store()

    @pytest.mark.parametrize("method, path, body", _MUTATIONS)
    def test_foreign_tenant_admin_is_403(
        self, bridge_app, persistence, victim, method, path, body
    ) -> None:
        raw = _add_key(persistence, "foreign-admin", "admin", tenant_id="other")
        before = dict(persistence.get_key_store())
        kwargs = {"json": body} if body is not None else {}
        resp = getattr(_as(bridge_app, raw), method)(path, **kwargs)
        assert resp.status_code == 403
        assert resp.json() == {"detail": "Credential belongs to another tenant"}
        assert persistence.get_key_store() == before

    @pytest.mark.parametrize("method, path, body", _MUTATIONS)
    def test_no_credential_is_401(self, bridge_app, victim, method, path, body):
        kwargs = {"json": body} if body is not None else {}
        assert (
            getattr(TestClient(bridge_app), method)(path, **kwargs).status_code == 401
        )

    def test_sensor_key_cannot_list_keys(self, bridge_app, persistence) -> None:
        resp = _as(bridge_app, _add_key(persistence, "s", "sensor")).get("/api/keys/")
        assert resp.status_code == 403
        assert resp.json() == {"detail": "Viewer role required"}

    @pytest.mark.parametrize("key_id", ["a b", "../x", "<script>", "", "k" * 65])
    def test_malformed_key_ids_are_422(self, client, persistence, key_id) -> None:
        before = set(persistence.get_key_store())
        resp = client.post("/api/keys/", json={"key_id": key_id})
        assert resp.status_code == 422
        assert set(persistence.get_key_store()) == before

    def test_role_cannot_be_chosen_by_the_caller(self, client, persistence) -> None:
        resp = client.post("/api/keys/", json={"key_id": "x", "role": "keymaster"})
        assert resp.status_code == 422
        assert "x" not in persistence.get_key_store()


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------


class TestListing:
    def test_malformed_dates_do_not_break_the_list(
        self, bridge_app, persistence
    ) -> None:
        _add_key(
            persistence,
            "odd-dates",
            "viewer",
            created_at="yesterday",
            expires_at="soon",
            last_used="sometime",
        )
        raw = _add_key(
            persistence,
            "good-dates",
            "viewer",
            created_at="2026-01-01T00:00:00+00:00",
            expires_at="2999-01-01T00:00:00+00:00",
            last_used="2026-02-01T00:00:00+00:00",
        )
        resp = _as(bridge_app, raw).get("/api/keys/")
        assert resp.status_code == 200, resp.text
        by_id = {k["key_id"]: k for k in resp.json()}
        assert by_id["odd-dates"]["expires_at"] is None
        assert by_id["odd-dates"]["last_used"] is None
        assert by_id["odd-dates"]["created_at"]  # fell back to "now"
        assert by_id["good-dates"]["last_used"].startswith("2026-02-01")
        for entry in resp.json():
            assert not _SECRET_FIELDS & set(entry)

    @pytest.mark.parametrize("stored", [12345, ["2026-01-01"], {"at": 1}, True])
    def test_dates_that_are_not_strings_do_not_break_the_list(
        self, bridge_app, persistence, stored
    ) -> None:
        # fromisoformat raises TypeError (not ValueError) for these: 500.
        _add_key(
            persistence,
            "typed-dates",
            "viewer",
            created_at=stored,
            expires_at=stored,
            last_used=stored,
        )
        raw = _add_key(persistence, "reader", "viewer")
        resp = _as(bridge_app, raw).get("/api/keys/")
        assert resp.status_code == 200, resp.text
        row = {k["key_id"]: k for k in resp.json()}["typed-dates"]
        assert row["expires_at"] is None
        assert row["last_used"] is None
        assert row["created_at"]  # fell back to "now"

    def test_the_listing_flags_a_key_rejected_as_expired(
        self, bridge_app, persistence
    ) -> None:
        # An unparseable expiry lists as null, which alone would read as
        # "never expires", while bridge auth and the gateway reject the key.
        odd = _add_key(persistence, "odd-expiry", "viewer", expires_at="soon")
        raw = _add_key(persistence, "reader", "viewer")
        assert _as(bridge_app, odd).get("/api/auth/me").status_code == 401
        row = {k["key_id"]: k for k in _as(bridge_app, raw).get("/api/keys/").json()}
        assert row["odd-expiry"]["expires_at"] is None
        assert row["odd-expiry"].get("expired") is True
        assert row["reader"]["expired"] is False

    @pytest.mark.parametrize(
        ("stored", "rejected"),
        [
            (None, False),
            ("", False),
            ("   ", False),
            ("2999-01-01T00:00:00+00:00", False),
            ("2999-01-01T00:00:00", False),
            (" 2999-01-01T00:00:00+00:00 ", False),
            ("2020-01-01T00:00:00+00:00", True),
            ("2020-01-01T00:00:00", True),
            (" 2020-01-01T00:00:00+00:00 ", True),
            ("2020-01-01T00:00:00Z", True),
            ("20200101T000000+0000", True),
            ("soon", True),
            (12345, True),
            (True, True),
            (["2999-01-01"], True),
            ({"at": "2999-01-01"}, True),
        ],
        ids=[
            "none",
            "empty",
            "blank",
            "future",
            "future-naive",
            "future-padded",
            "past",
            "past-naive",
            "past-padded",
            "past-zulu",
            "past-basic-iso",
            "unparseable",
            "number",
            "bool",
            "list",
            "object",
        ],
    )
    def test_both_listings_flag_exactly_the_keys_auth_rejects_as_expired(
        self, bridge_app, client, persistence, stored, rejected
    ) -> None:
        """``expired`` in ``GET /api/keys/`` and ``GET /api/admin/keys`` is
        the auth layer's verdict for every stored ``expires_at`` shape."""
        probe = _add_key(persistence, "probe", "viewer", expires_at=stored)
        reader = _add_key(persistence, "reader", "viewer")
        me = _as(bridge_app, probe).get("/api/auth/me")
        assert me.status_code == (401 if rejected else 200), me.text

        listed = _as(bridge_app, reader).get("/api/keys/")
        assert listed.status_code == 200, listed.text
        rows = {k["key_id"]: k for k in listed.json()}
        assert rows["probe"]["expired"] is rejected
        assert rows["reader"]["expired"] is False

        admin = client.get("/api/admin/keys")
        assert admin.status_code == 200, admin.text
        admin_rows = {k["key_id"]: k for k in admin.json()}
        assert admin_rows["probe"]["expired"] is rejected
        assert admin_rows["reader"]["expired"] is False
        assert admin_rows["master"]["expired"] is False
        # The admin listing keeps keys.json's value as stored, so an
        # operator can see (and fix) what the flag is about.
        assert admin_rows["probe"]["expires_at"] == stored

    @pytest.mark.parametrize(
        "stored",
        [
            "2999-01-01T00:00:00+00:00",
            "2999-01-01T00:00:00",
            " 2999-01-01T00:00:00+00:00 ",
            "2999-01-01T02:00:00+02:00",
        ],
        ids=["aware", "naive", "padded", "offset"],
    )
    @pytest.mark.usefixtures("local_time_not_utc")
    def test_the_listing_reports_the_expiry_auth_applies(
        self, bridge_app, client, persistence, stored
    ) -> None:
        """``expires_at`` is the instant auth stops accepting the key: a
        padded value is not listed as null ("never expires") and a naive one
        is UTC, as auth reads it, not a local time left to the client (nor
        the server's: the fixture moves it off UTC).  The admin listing
        reports the same instant as ``effective_expires_at``."""
        raw = _add_key(persistence, "dated", "viewer", expires_at=stored)
        assert _as(bridge_app, raw).get("/api/auth/me").status_code == 200
        row = {k["key_id"]: k for k in _as(bridge_app, raw).get("/api/keys/").json()}
        admin_row = {k["key_id"]: k for k in client.get("/api/admin/keys").json()}
        for listed in (
            row["dated"]["expires_at"],
            admin_row["dated"]["effective_expires_at"],
        ):
            assert listed is not None
            listed_dt = datetime.fromisoformat(listed)
            assert listed_dt.tzinfo is not None, listed
            assert listed_dt == datetime(2999, 1, 1, tzinfo=timezone.utc)
        assert row["dated"]["expired"] is False
        assert admin_row["dated"]["expires_at"] == stored

    @pytest.mark.parametrize(
        ("stored", "effective"),
        [
            (None, None),
            ("", None),
            ("   ", None),
            ("2020-01-01T00:00:00Z", datetime(2020, 1, 1, tzinfo=timezone.utc)),
            (" 2020-01-01T00:00:00 ", datetime(2020, 1, 1, tzinfo=timezone.utc)),
            (
                "0001-01-01T00:00:00+14:00",
                datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=14))),
            ),
            ("soon", None),
            ("Jan 1 2999", None),
            (12345, None),
            (["2999-01-01"], None),
        ],
        ids=[
            "none",
            "empty",
            "blank",
            "past-zulu",
            "past-naive-padded",
            "extreme-offset",
            "unparseable",
            "browser-readable-only",
            "number",
            "list",
        ],
    )
    @pytest.mark.usefixtures("local_time_not_utc")
    def test_the_admin_listing_reports_the_instant_auth_applies(
        self, client, persistence, stored, effective
    ) -> None:
        """``effective_expires_at`` is what the admin UI shows: the instant
        bridge auth applies, with an offset (never naive, so the browser
        cannot read it as its local time), null for none and for a value
        auth cannot parse.  An instant UTC cannot hold does not break the
        list: it is listed with its own offset, not converted."""
        _add_key(persistence, "probe", "viewer", expires_at=stored)
        resp = client.get("/api/admin/keys")
        assert resp.status_code == 200, resp.text
        row = {k["key_id"]: k for k in resp.json()}["probe"]
        assert row["expires_at"] == stored
        listed = row["effective_expires_at"]
        if effective is None:
            assert listed is None
        else:
            listed_dt = datetime.fromisoformat(listed)
            assert listed_dt.utcoffset() == effective.utcoffset(), listed
            assert listed_dt == effective
        # No instant but rejected: the stored value cannot be parsed.
        assert row["expired"] is (stored not in (None, "", "   "))

    @pytest.mark.parametrize(
        "stored", [None, "2999-01-01T00:00:00+00:00"], ids=["no-expiry", "future"]
    )
    @pytest.mark.parametrize(
        "inactive", [{"enabled": False}, {"revoked": True}], ids=["disabled", "revoked"]
    )
    def test_a_key_refused_for_another_reason_is_not_listed_as_expired(
        self, bridge_app, client, persistence, stored, inactive
    ) -> None:
        """``expired`` is the expiry verdict alone, not "unusable": a disabled
        or revoked key that has not expired is not EXPIRED in either list,
        so an operator does not re-create a key that only needs enabling."""
        off = _add_key(persistence, "off", "viewer", expires_at=stored, **inactive)
        reader = _add_key(persistence, "reader", "viewer")
        assert _as(bridge_app, off).get("/api/auth/me").status_code == 401

        listed = _as(bridge_app, reader).get("/api/keys/")
        assert listed.status_code == 200, listed.text
        rows = {k["key_id"]: k for k in listed.json()}
        assert rows["off"]["expired"] is False

        admin = client.get("/api/admin/keys")
        assert admin.status_code == 200, admin.text
        admin_rows = {k["key_id"]: k for k in admin.json()}
        assert admin_rows["off"]["expired"] is False
        assert admin_rows["off"]["effective_expires_at"] == (
            None if stored is None else "2999-01-01T00:00:00+00:00"
        )


# ---------------------------------------------------------------------------
# Rotation edge cases
# ---------------------------------------------------------------------------


class TestRotationEdges:
    def test_rotating_an_unknown_key_is_404(self, client, persistence) -> None:
        resp = client.put("/api/keys/ghost/rotate")
        assert resp.status_code == 404
        assert "ghost" not in persistence.get_key_store()

    def test_rotate_master_without_a_master_entry_is_404(
        self, bridge_app, persistence
    ) -> None:
        km = _as(bridge_app, _add_key(persistence, "km", "keymaster"))
        assert persistence.remove_key("master")
        resp = km.post("/api/keys/rotate-master")
        assert resp.status_code == 404
        assert "master" not in persistence.get_key_store()

    def test_master_removed_while_hashing_is_404(
        self, client, persistence, monkeypatch
    ) -> None:
        # The test app stores master without a lookup hash; its first use
        # upgrades the credential, so take the snapshot after that.
        assert client.get("/api/auth/me").status_code == 200
        before = persistence.get_key_store()["master"]

        async def _gone(*args, **kwargs):
            return None

        monkeypatch.setattr(persistence, "async_replace_key_credential", _gone)
        resp = client.post("/api/keys/rotate-master")
        assert resp.status_code == 404
        assert persistence.get_key_store()["master"] == before
        assert client.get("/api/auth/me").status_code == 200

    def test_rotate_master_without_an_audit_store(
        self, bridge_app, client, app_state
    ) -> None:
        bridge_app.state.detection_store = None
        resp = client.post("/api/keys/rotate-master")
        assert resp.status_code == 200
        assert len(_activity(app_state, "master_key_rotated")) == 1
        assert (
            _as(bridge_app, resp.json()["raw_key"]).get("/api/keys/").status_code == 200
        )

    def test_admin_session_cannot_rotate_master(
        self, bridge_app, client, detection_store, master_key
    ) -> None:
        detection_store.create_user(
            username="adm", password="Password123!", role="admin"
        )
        uid = detection_store.users.get_user("adm")["id"]
        token = detection_store.create_session(user_id=uid)["session_token"]
        c = TestClient(bridge_app, headers={"Authorization": f"Bearer {token}"})
        assert c.post("/api/keys/rotate-master").status_code == 403
        assert c.put("/api/keys/master/rotate").status_code == 403
        assert client.get("/api/auth/me").status_code == 200  # master unchanged
