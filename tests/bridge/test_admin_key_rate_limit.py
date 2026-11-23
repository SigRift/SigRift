"""The admin limiter rejects creation before key/audit persistence changes."""

from types import SimpleNamespace

from sigrift.bridge import dependencies


def test_key_creation_cooldown_precedes_side_effects(
    client, persistence, detection_store, monkeypatch
):
    # Advance only this dependency's clock: real authentication, public routes,
    # persistence and hashing execute, without sleeping through a minute window.
    now = [1000.0]
    monkeypatch.setattr(dependencies, "time", SimpleNamespace(monotonic=lambda: now[0]))
    limiter = dependencies.RateLimiter(max_requests=300, window_seconds=60.0)
    monkeypatch.setattr(dependencies, "_rate_limiter", limiter)
    for _ in range(10):
        assert client.get("/api/admin/keys").status_code == 200
    before_keys = persistence.get_key_store().copy()
    before_meta = persistence.get_key_meta().copy()
    before_audit = detection_store.get_audit_log()
    assert len(before_audit) == 10
    body = {"description": "disposable synthetic scanner", "role": "sensor"}
    now[0] += 0.5
    for _ in range(2):
        rejected = client.post("/api/admin/keys", json=body)
        assert rejected.status_code == 429
        assert rejected.headers["retry-after"] == "60"
        assert persistence.get_key_store() == before_keys
        assert persistence.get_key_meta() == before_meta
        assert detection_store.get_audit_log() == before_audit
    now[0] += int(rejected.headers["retry-after"])
    accepted = client.post("/api/admin/keys", json=body)
    assert accepted.status_code == 201
    key = accepted.json()
    assert isinstance(key["raw_key"], str) and key["raw_key"]
    assert set(persistence.get_key_store()) == set(before_keys) | {key["key_id"]}
    assert persistence.get_key_meta()[key["key_id"]]["role"] == "sensor"
    created = detection_store.get_audit_log(action="admin_create_key")
    assert len(created) == 1
    assert created[0]["target_id"] == key["key_id"]
