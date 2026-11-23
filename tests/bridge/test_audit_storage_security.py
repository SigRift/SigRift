"""Security paths of the audit sub-store, against a real SQLite file.

Covers what the existing audit suites leave out: the transactional-append
guard, hostile values in every field, LIKE-wildcard escaping on both the
list and the count query, the severity filter, malformed JSON columns,
per-field tamper detection, forged/re-keyed/reordered rows, v1, v2 and legacy
rows chained with v3 ones, unsigned rows after signed ones (reported, as on
the gateway), values normalised to what reads back, verification
errors that hand out no digest, and the HMAC encoding itself (the v3 golden
vectors are shared with the Rust gateway's ``audit/chain.rs``).  End-to-end
checks go through the real admin HTTP routes (``/api/admin/audit`` and
``/api/admin/audit/verify``).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest

from sigrift.bridge.storage.audit import (
    _HMAC_MISMATCH,
    _HMAC_MISSING,
    AuditStore,
    _compute_hmac,
    _compute_hmac_v2,
    _compute_hmac_v3,
    _get_audit_secret,
    _hmac_v3_payload,
)
from sigrift.bridge.storage.base import SharedContext

AUDIT_KEY = "audit-test-key-not-a-secret"


@pytest.fixture(autouse=True)
def _audit_key(monkeypatch):
    # Pin the chain key so no development key file is read or written.
    monkeypatch.setenv("BRIDGE_AUDIT_KEY", AUDIT_KEY)
    monkeypatch.delenv("BRIDGE_AUDIT_SECRET", raising=False)
    monkeypatch.delenv("BRIDGE_MASTER_KEY", raising=False)
    monkeypatch.delenv("BRIDGE_DB_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("BRIDGE_DB_ENCRYPTION_KEY_FILE", raising=False)


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "audit.db"


@pytest.fixture
def ctx(db_path):
    context = SharedContext(db_path)
    yield context
    context.close()


@pytest.fixture
def audit(ctx):
    return AuditStore(ctx)


def persist(ctx, statement, values=()):
    with ctx.write_transaction() as conn:
        conn.execute(statement, values)


def rows(ctx):
    return ctx.get_conn().execute("SELECT * FROM audit_log ORDER BY id").fetchall()


def error_ids(result):
    return [e["id"] for e in result["errors"]]


# ---------------------------------------------------------------------------
# Appends only ride on this context's own open transaction
# ---------------------------------------------------------------------------


def test_append_without_an_open_transaction_is_refused(ctx, audit):
    with pytest.raises(RuntimeError, match="active transaction"):
        audit._log_audit_in_transaction(ctx.get_conn(), "user_update", "alice")
    assert rows(ctx) == []


def test_append_on_another_contexts_transaction_is_refused(tmp_path, ctx, audit):
    other = SharedContext(tmp_path / "other.db")
    try:
        with other.write_transaction(immediate=True) as conn:
            with pytest.raises(RuntimeError, match="active transaction"):
                audit._log_audit_in_transaction(conn, "user_update", "alice")
        assert rows(ctx) == []
        assert (
            other.get_conn().execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
            == 0
        )
    finally:
        other.close()


def test_in_transaction_append_rolls_back_with_its_caller(ctx, audit):
    with pytest.raises(ZeroDivisionError):
        with ctx.write_transaction(immediate=True) as conn:
            audit._log_audit_in_transaction(conn, "user_update", "alice")
            1 / 0
    assert rows(ctx) == []

    with ctx.write_transaction(immediate=True) as conn:
        entry = audit._log_audit_in_transaction(
            conn, "user_update", "alice", operator="root"
        )
    assert [r["action"] for r in rows(ctx)] == ["user_update"]
    assert entry["operator"] == "root"
    assert audit.verify_chain()["valid"] is True


# ---------------------------------------------------------------------------
# Hostile values are bound parameters, stored verbatim and authenticated
# ---------------------------------------------------------------------------

HOSTILE = [
    "o'brien",
    "x' OR '1'='1",
    "'); DELETE FROM audit_log; --",
    'q"uote',
    "back\\slash",
    "100%_done",
    "名前-Ωμέγα-🙂",
    "nul\x00byte",
    "z" * 20_000,
]


@pytest.mark.parametrize("value", HOSTILE, ids=range(len(HOSTILE)))
def test_hostile_values_round_trip_and_verify(ctx, audit, value):
    audit.log_audit("baseline", "det-0", operator="ops", note="first")
    audit.log_audit(
        action=value,
        target_id=value,
        signal_class=value,
        node_id=value,
        operator=value,
        note=value,
        details={"k": value, value: [value]},
        target_ids=[value, "det-0"],
    )
    audit.log_audit("dismiss", "det-2", operator="ops")

    stored = rows(ctx)
    assert len(stored) == 3
    entry = audit.get_audit_log(operator=value)
    assert len(entry) == 1
    entry = entry[0]
    for field in ("action", "target_id", "signal_class", "node_id", "note"):
        assert entry[field] == value
    assert entry["details"] == {"k": value, value: [value]}
    assert entry["target_ids"] == [value, "det-0"]

    assert audit.get_audit_log(action=value, target_id=value, node_id=value) == [entry]
    assert audit.count_audit_log(operator=value) == 1
    assert audit.count_audit_log(search=value) == 1
    assert value in audit.get_audit_actions()
    assert value in audit.get_audit_operators()
    assert value in audit.get_audit_node_ids()
    assert audit.verify_chain() == {
        "valid": True,
        "total": 3,
        "checked": 3,
        "errors": [],
        "gaps": [],
    }


@pytest.mark.parametrize(
    ("search", "expected"),
    [
        ("%", {"pct"}),
        ("_", {"under"}),
        ("\\", {"slash"}),
        ("100%", {"pct"}),
        ("a_b", {"under"}),
        ("' OR '1'='1", set()),
        ("%' OR 1=1 --", set()),
        ("", {"pct", "plain", "under", "axb", "slash", "noslash"}),
    ],
)
def test_search_treats_like_metacharacters_literally(audit, search, expected):
    for target, note in [
        ("pct", "100% done"),
        ("plain", "100 done"),
        ("under", "a_b"),
        ("axb", "axb"),
        ("slash", "back\\slash"),
        ("noslash", "backslash"),
    ]:
        audit.log_audit("feedback", target, note=note)
    found = {e["target_id"] for e in audit.get_audit_log(search=search)}
    assert found == expected
    assert audit.count_audit_log(search=search) == len(expected)


def test_count_and_list_apply_the_same_filters(ctx, audit):
    audit.log_audit("dismiss", "det-1", operator="alice", node_id="n1")
    audit.log_audit("dismiss", "det-2", operator="bob", node_id="n2")
    audit.log_audit("baseline", "det-1", operator="alice", node_id="n1")
    stamps = [r["timestamp"] for r in rows(ctx)]

    cases = [
        {"action": "dismiss"},
        {"target_id": "det-1"},
        {"operator": "alice"},
        {"node_id": "n2"},
        {"start": stamps[1]},
        {"end": stamps[1]},
        {"start": stamps[1], "end": stamps[1]},
        {"action": "dismiss", "operator": "alice", "node_id": "n1"},
        {"operator": "alice' OR '1'='1"},
    ]
    for filters in cases:
        listed = audit.get_audit_log(**filters)
        assert audit.count_audit_log(**filters) == len(listed), filters
    assert audit.count_audit_log(start=stamps[1]) == 2
    assert audit.count_audit_log(end=stamps[1]) == 2
    assert audit.count_audit_log(operator="alice' OR '1'='1") == 0


def test_severity_filter_when_every_entry_has_details(audit):
    audit.log_audit("a1", "t1", details={"severity": "critical"})
    audit.log_audit("a2", "t2", details={"severity": "warning"})
    audit.log_audit("a3", "t3", details={"severity": "info"})
    audit.log_audit("a4", "t4", details={"reason": "no severity key"})
    audit.log_audit("a5", "t5", details={"severity": "critical' OR '1'='1"})

    assert [e["action"] for e in audit.get_audit_log(severity="critical")] == ["a1"]
    assert audit.count_audit_log(severity="critical") == 1
    assert audit.count_audit_log(severity="warning") == 1
    assert {e["action"] for e in audit.get_audit_log(severity="info")} == {"a3", "a4"}
    assert audit.count_audit_log(severity="info") == 2
    assert audit.get_audit_log(severity="' OR '1'='1") == []
    assert audit.count_audit_log(severity="critical' OR '1'='1") == 1


def test_severity_filter_tolerates_entries_without_details(audit):
    audit.log_audit("dismiss", "plain-entry")
    audit.log_audit("flag", "t1", details={"severity": "critical"})

    assert [e["action"] for e in audit.get_audit_log(severity="critical")] == ["flag"]
    assert audit.count_audit_log(severity="critical") == 1
    assert [e["action"] for e in audit.get_audit_log(severity="info")] == ["dismiss"]


@pytest.mark.parametrize(
    "stored", [None, "", "{broken", "[1, 2]", '"text"', "5", '{"severity": null}']
)
def test_severity_filter_reads_details_without_a_severity_as_info(ctx, audit, stored):
    audit.log_audit("odd", "t0", details={"severity": "warning"})
    audit.log_audit("flag", "t1", details={"severity": "critical"})
    persist(ctx, "UPDATE audit_log SET details = ? WHERE action = 'odd'", (stored,))

    assert [e["action"] for e in audit.get_audit_log(severity="critical")] == ["flag"]
    assert audit.count_audit_log(severity="critical") == 1
    assert audit.get_audit_log(severity="warning") == []
    assert audit.count_audit_log(severity="warning") == 0
    info = audit.get_audit_log(severity="info")
    assert [(e["action"], e["details"]) for e in info] == [
        ("odd", {} if stored in (None, "", "{broken") else json.loads(stored))
    ]
    assert audit.count_audit_log(severity="info") == 1


def test_malformed_json_columns_read_as_empty_and_are_flagged(ctx, audit):
    audit.log_audit("bulk_dismiss", "det-1", target_ids=["det-1", "det-2"])
    audit.log_audit("dismiss", "det-3", details={"why": "fp"})
    first, second = rows(ctx)
    persist(
        ctx, "UPDATE audit_log SET target_ids = 'not json' WHERE id = ?", (first["id"],)
    )
    persist(
        ctx, "UPDATE audit_log SET details = '{broken' WHERE id = ?", (second["id"],)
    )

    by_target = {e["target_id"]: e for e in audit.get_audit_log()}
    assert by_target["det-1"]["target_ids"] == []
    assert by_target["det-3"]["details"] == {}
    # Rewriting details is tampering with an authenticated field.
    assert second["id"] in error_ids(audit.verify_chain())


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------

TAMPER = {
    "action": "'dismiss'",
    "target_id": "'det-other'",
    "operator": "'mallory'",
    "timestamp": "'2020-01-01T00:00:00+00:00'",
    "details": '\'{"severity": "info"}\'',
    "note": "'nothing to see'",
    "signal_class": "'wifi'",
    "freq_hz": "1.0",
    "node_id": "'node-x'",
}


@pytest.mark.parametrize("column", sorted(TAMPER))
def test_rewriting_any_authenticated_field_is_detected(ctx, audit, column):
    audit.log_audit("baseline", "det-0")
    audit.log_audit(
        "feedback",
        "det-1",
        signal_class="lora",
        freq_hz=868.1e6,
        node_id="node-1",
        operator="alice",
        note="real note",
        details={"severity": "critical"},
    )
    audit.log_audit("dismiss", "det-2")
    target = rows(ctx)[1]["id"]
    persist(
        ctx, f"UPDATE audit_log SET {column} = {TAMPER[column]} WHERE id = ?", (target,)
    )

    result = audit.verify_chain()
    assert result["valid"] is False
    assert error_ids(result) == [target]
    assert result["gaps"] == []


def test_rewriting_bulk_target_ids_is_detected(ctx, audit):
    audit.log_audit("bulk_dismiss", "det-1", target_ids=["det-1", "det-2", "det-3"])
    persist(ctx, "UPDATE audit_log SET target_ids = ?", (json.dumps(["det-9"]),))
    assert audit.verify_chain()["valid"] is False


def test_shifting_text_between_adjacent_fields_is_detected(ctx, audit):
    audit.log_audit("dismiss", "det-1", note="approved|signed-off", signal_class="wifi")
    persist(
        ctx, "UPDATE audit_log SET note = 'approved', signal_class = 'signed-off|wifi'"
    )
    assert audit.verify_chain()["valid"] is False


SHIFTS = [
    # (column, original, rewritten) pairs: the bytes are only re-split.
    (("target_id", "det-1", "det-1|x"), ("operator", "x|y", "y")),
    (("details", '{"a": "b|c"}', '{"a": "b'), ("note", "n", 'c"}|n')),
    (("signal_class", "lora|", "lora"), ("freq_hz", 0.0, "|0.0")),
    (("node_id", "n|", "n"), ("target_ids", '["d"]', '|["d"]')),
]


@pytest.mark.parametrize("shift", SHIFTS, ids=[f"{a[0]}-{b[0]}" for a, b in SHIFTS])
def test_shifting_text_between_any_adjacent_fields_is_detected(ctx, audit, shift):
    (col_a, a, new_a), (col_b, b, new_b) = shift
    audit.log_audit("dismiss", "det-0")
    fields = {"target_id": "det-1", col_a: a, col_b: b}
    if "details" in fields:
        fields["details"] = json.loads(fields["details"])
    if "target_ids" in fields:
        fields["target_ids"] = json.loads(fields["target_ids"])
    audit.log_audit("dismiss", **fields)
    target = rows(ctx)[-1]
    assert (target[col_a], target[col_b]) == (a, b)
    assert audit.verify_chain()["valid"] is True
    persist(
        ctx,
        f"UPDATE audit_log SET {col_a} = ?, {col_b} = ? WHERE id = ?",
        (new_a, new_b, target["id"]),
    )
    assert error_ids(audit.verify_chain()) == [target["id"]]


@pytest.mark.parametrize("freq", [0, 433_920_000])
def test_integer_frequency_entry_verifies(audit, freq):
    audit.log_audit("feedback", "det-1", freq_hz=freq)
    assert audit.verify_chain()["valid"] is True


@pytest.mark.parametrize(
    ("freq", "stored"),
    [
        (None, 0.0),
        (-0.0, 0.0),
        (float("nan"), 0.0),
        (True, 1.0),
        (433_920_000, 433_920_000.0),
        (float("inf"), float("inf")),
        ("433", 433.0),
    ],
    ids=["none", "negative-zero", "nan", "bool", "int", "inf", "numeric-string"],
)
def test_frequency_is_hashed_as_it_is_stored(ctx, audit, freq, stored):
    entry = audit.log_audit("feedback", "det-1", freq_hz=freq)
    assert type(entry["freq_hz"]) is float and entry["freq_hz"] == stored
    assert rows(ctx)[0]["freq_hz"] == stored
    assert audit.verify_chain()["valid"] is True


@pytest.mark.parametrize("freq", ["abc", "", [433.92e6], object()])
def test_non_numeric_frequency_fails_closed(ctx, audit, freq):
    audit.log_audit("dismiss", "det-0")
    with pytest.raises(ValueError, match="freq_hz must be a number"):
        audit.log_audit("feedback", "det-1", freq_hz=freq)
    # A caller's surrounding write transaction is rolled back with it.
    with pytest.raises(ValueError, match="freq_hz must be a number"):
        with ctx.write_transaction(immediate=True) as conn:
            audit._log_audit_in_transaction(conn, "user_update", "alice")
            audit._log_audit_in_transaction(conn, "feedback", "det-1", freq_hz=freq)
    assert [r["target_id"] for r in rows(ctx)] == ["det-0"]
    assert audit.verify_chain()["valid"] is True


@pytest.mark.parametrize("field", ["signal_class", "node_id", "operator", "note"])
def test_none_text_field_is_stored_as_empty_and_verifies(ctx, audit, field):
    # NULL text verifies as "", so None must not be hashed as "None".
    entry = audit.log_audit("feedback", "det-1", **{field: None})
    assert entry[field] == ""
    assert rows(ctx)[0][field] == ""
    assert audit.verify_chain()["valid"] is True


def test_numpy_frequencies_are_stored_as_real_and_verify(ctx, audit):
    np = pytest.importorskip("numpy")
    # sqlite3 stores numpy scalars as BLOBs unless they are converted.
    freqs = (np.float32(433.92e6), np.int64(868_000_000), np.float64(2.4e9))
    for i, freq in enumerate(freqs):
        audit.log_audit("feedback", f"det-{i}", freq_hz=freq)
    assert [r["freq_hz"] for r in rows(ctx)] == [float(f) for f in freqs]
    assert audit.verify_chain()["valid"] is True


def test_float_frequencies_verify_exactly(audit):
    for freq in (0.0, 433.92e6, 2.4e9, 1e-300, 123456789.123456):
        audit.log_audit("feedback", f"det-{freq}", freq_hz=freq)
    assert audit.verify_chain()["valid"] is True


def test_swapping_two_rows_is_detected(ctx, audit):
    for i in range(4):
        audit.log_audit("dismiss", f"det-{i}", operator=f"op{i}")
    a, b = rows(ctx)[1], rows(ctx)[2]
    columns = ("timestamp", "action", "target_id", "operator", "hmac_chain")
    for src, dst in ((a, b), (b, a)):
        persist(
            ctx,
            f"UPDATE audit_log SET {', '.join(c + ' = ?' for c in columns)} WHERE id = ?",
            [src[c] for c in columns] + [dst["id"]],
        )
    result = audit.verify_chain()
    assert result["valid"] is False
    assert set(error_ids(result)) >= {a["id"], b["id"]}


def test_appended_forgery_without_the_key_is_detected(ctx, audit, monkeypatch):
    audit.log_audit("dismiss", "det-1")
    head = rows(ctx)[-1]["hmac_chain"]
    now = datetime.now(timezone.utc).isoformat()
    forged = _compute_hmac_v2(
        b"attacker-guess",
        head,
        "baseline",
        "det-2",
        "admin",
        now,
        "",
        "",
        "",
        "0.0",
        "",
    )
    persist(
        ctx,
        "INSERT INTO audit_log (timestamp, action, target_id, operator, tenant_id, "
        "hmac_chain) VALUES (?, 'baseline', 'det-2', 'admin', 'default', ?)",
        (now, forged),
    )
    forged_id = rows(ctx)[-1]["id"]
    assert error_ids(audit.verify_chain()) == [forged_id]

    # The real key makes the same row valid: the check is key-dependent.
    real = _compute_hmac_v2(
        _get_audit_secret(),
        head,
        "baseline",
        "det-2",
        "admin",
        now,
        "",
        "",
        "",
        "0.0",
        "",
    )
    persist(ctx, "UPDATE audit_log SET hmac_chain = ? WHERE id = ?", (real, forged_id))
    assert audit.verify_chain()["valid"] is True


def test_verify_does_not_report_the_digest_that_would_re_sign_a_tampered_row(
    ctx, audit
):
    for i in range(3):
        audit.log_audit("dismiss", f"det-{i}", note="real")
    first = rows(ctx)[0]
    persist(ctx, "UPDATE audit_log SET note = 'forged' WHERE id = ?", (first["id"],))
    resigned = _compute_hmac_v3(
        _get_audit_secret(), "", "dismiss", "det-0", "", first["timestamp"],
        "", "forged", "", "0.0", "", "", "default",
    )  # fmt: skip

    result = audit.verify_chain()
    assert result["errors"] == [
        {
            "id": first["id"],
            "expected": "HMAC of the entry's fields chained from its predecessor",
            "actual": first["hmac_chain"],
        }
    ]
    assert resigned not in json.dumps(result)

    # Storing each reported "expected" as the HMAC, entry by entry, does not
    # launder the tampering.
    for _ in range(3):
        for error in audit.verify_chain()["errors"]:
            persist(
                ctx,
                "UPDATE audit_log SET hmac_chain = ? WHERE id = ?",
                (error["expected"], error["id"]),
            )
    assert audit.verify_chain()["valid"] is False


def test_chain_written_under_one_key_fails_under_another(audit, monkeypatch):
    audit.log_audit("dismiss", "det-1")
    audit.log_audit("dismiss", "det-2")
    assert audit.verify_chain()["valid"] is True
    monkeypatch.setenv("BRIDGE_AUDIT_KEY", AUDIT_KEY + "-rotated")
    result = audit.verify_chain()
    assert result["valid"] is False
    assert result["checked"] == 2
    assert len(result["errors"]) == 2


def test_v1_entry_verifies_but_its_v1_fields_are_still_protected(ctx, audit):
    now = datetime.now(timezone.utc).isoformat()
    v1 = _compute_hmac(_get_audit_secret(), "", "dismiss", "det-1", "alice", now)
    persist(
        ctx,
        "INSERT INTO audit_log (timestamp, action, target_id, operator, tenant_id, "
        "hmac_chain) VALUES (?, 'dismiss', 'det-1', 'alice', 'default', ?)",
        (now, v1),
    )
    audit.log_audit("baseline", "det-2")
    assert audit.verify_chain()["valid"] is True

    persist(ctx, "UPDATE audit_log SET operator = 'mallory' WHERE target_id = 'det-1'")
    result = audit.verify_chain()
    assert result["valid"] is False
    assert error_ids(result) == [rows(ctx)[0]["id"]]


def insert_signed(ctx, compute, **fields):
    """Append a row signed with an older record version, chained to the head."""
    row = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": "dismiss",
        "target_id": "",
        "target_ids": "",
        "signal_class": "",
        "freq_hz": 0.0,
        "node_id": "",
        "operator": "",
        "note": "",
        "details": "",
        **fields,
    }
    head = (
        ctx.get_conn()
        .execute("SELECT hmac_chain FROM audit_log ORDER BY id DESC LIMIT 1")
        .fetchone()
    )
    previous = "" if head is None else (head[0] or "LEGACY_NO_HMAC")
    common = (row["action"], row["target_id"], row["operator"], row["timestamp"])
    if compute is _compute_hmac:
        digest = _compute_hmac(_get_audit_secret(), previous, *common)
    else:
        digest = _compute_hmac_v2(
            _get_audit_secret(),
            previous,
            *common,
            row["details"],
            row["note"],
            row["signal_class"],
            str(row["freq_hz"]),
            row["node_id"],
        )
    columns = ", ".join(row)
    persist(
        ctx,
        f"INSERT INTO audit_log ({columns}, tenant_id, hmac_chain) "
        f"VALUES ({', '.join('?' * len(row))}, 'default', ?)",
        [*row.values(), digest],
    )
    return rows(ctx)[-1]["id"]


def insert_unsigned(ctx, timestamp=None, target_id="det-legacy"):
    """Append a row without an HMAC, as written before the chain existed."""
    persist(
        ctx,
        "INSERT INTO audit_log (timestamp, action, target_id, tenant_id, hmac_chain) "
        "VALUES (?, 'legacy', ?, 'default', '')",
        (timestamp or datetime.now(timezone.utc).isoformat(), target_id),
    )
    return rows(ctx)[-1]["id"]


def test_v1_v2_and_legacy_rows_chain_into_v3_rows(ctx, audit):
    # Rows that predate the chain come before its first signed row.
    insert_unsigned(ctx)
    v2_after_legacy = insert_signed(ctx, _compute_hmac_v2, target_id="det-v2b")
    v1 = insert_signed(ctx, _compute_hmac, target_id="det-v1", operator="alice")
    v2 = insert_signed(
        ctx,
        _compute_hmac_v2,
        action="bulk_dismiss",
        target_id="det-v2",
        target_ids='["det-v2", "det-x"]',
        note="v2 note",
        details='{"severity": "warning"}',
        freq_hz=433.92e6,
    )
    audit.log_audit("baseline", "det-v3", target_ids=["det-v3", "det-y"])
    audit.log_audit("dismiss", "det-last", note="after the old rows")
    result = audit.verify_chain()
    assert result["valid"] is True, result
    assert (result["total"], result["checked"]) == (6, 5)

    # Older rows keep exactly the protection their version gives.
    persist(ctx, "UPDATE audit_log SET note = 'rewritten' WHERE id = ?", (v2,))
    persist(ctx, "UPDATE audit_log SET note = 'unprotected' WHERE id = ?", (v1,))
    assert error_ids(audit.verify_chain()) == [v2]
    persist(ctx, "UPDATE audit_log SET note = 'v2 note' WHERE id = ?", (v2,))
    persist(ctx, "UPDATE audit_log SET operator = 'x' WHERE id = ?", (v2_after_legacy,))
    assert error_ids(audit.verify_chain()) == [v2_after_legacy]


def test_new_rows_are_v3_over_the_stored_target_ids(ctx, audit):
    audit.log_audit("bulk_dismiss", "det-1", target_ids=["det-1"], freq_hz=1.5)
    entry = rows(ctx)[0]
    assert entry["hmac_chain"] == _compute_hmac_v3(
        _get_audit_secret(),
        "",
        "bulk_dismiss",
        "det-1",
        "",
        entry["timestamp"],
        "",
        "",
        "",
        "1.5",
        "",
        '["det-1"]',
        "default",
    )


def test_moving_an_entry_to_another_tenant_is_detected(db_path, ctx, audit):
    other = SharedContext(db_path, tenant_id="tenant-b")
    try:
        audit.log_audit("dismiss", "det-1")
        # Both chains start from "", so only tenant_id in the HMAC reveals it.
        persist(ctx, "UPDATE audit_log SET tenant_id = 'tenant-b'")
        result = AuditStore(other).verify_chain()
        assert result["valid"] is False
        assert error_ids(result) == [rows(ctx)[0]["id"]]
    finally:
        other.close()


# Shared with the Rust gateway (sigrift-gateway-core/src/audit/chain.rs):
# key SHA-256("test_audit_key").
GATEWAY_SECRET = hashlib.sha256(b"test_audit_key").digest()
V3_EMPTY = "dd117c1f04cef5294841277d1f9ca81eb8ca2c4fe056d8b7ccd22691924d81ad"


def test_v3_golden_vectors_match_the_gateway():
    ts = "2024-01-01T00:0{}:00+00:00"
    first = _compute_hmac_v3(
        GATEWAY_SECRET, "", "user_login", "testuser", "testuser", ts.format(0),
        "", "", "", "0.0", "", "", "default",
    )  # fmt: skip
    assert first == V3_EMPTY
    assert _compute_hmac_v3(
        GATEWAY_SECRET, first, "user_logout", "testuser", "testuser", ts.format(1),
        "", "", "", "0.0", "", "", "default",
    ) == "e8cc81b36b1321c4b843aecfa270d730efa616f802092fc8eed4680a6473ce8a"  # fmt: skip
    assert _compute_hmac_v3(
        GATEWAY_SECRET, first, "bulk_dismiss_rf", "1", "alice", ts.format(2),
        '{"ip":"10.0.0.1","who":"名前|Ω"}', "approved|signed-off\x00ok", "wifi",
        "2400000000.0", "node1", '["1","2","3"]', "tenant-b",
    ) == "95fbc262b9f5c8ec7b7965cea3c5b41b36b544227cb35792b157a9c5f662a0ec"  # fmt: skip
    # The v2 vector the gateway pins is unchanged.
    assert _compute_hmac_v2(
        GATEWAY_SECRET, "", "user_login", "testuser", "testuser", ts.format(0),
        "", "", "", "0.0", "",
    ) == "b091ad4c6e113e653c51eb3064bac1e899eff07f8fc0f30cf5ecfcb4bf070e9a"  # fmt: skip


def test_v3_payload_length_prefixes_count_utf8_bytes():
    assert _hmac_v3_payload("", "é|x", "a") == b"v3|0:|4:\xc3\xa9|x|1:a"
    assert _hmac_v3_payload("a|1:b") != _hmac_v3_payload("a", "b")
    assert _hmac_v3_payload("nul\x00") == b"v3|4:nul\x00"


def test_v3_payload_cannot_be_a_v1_or_v2_payload():
    # v1 starts with the previous HMAC ("", 64 hex digits or the sentinel),
    # v2 with "v2|"; neither can start with "v3|".
    for previous in ("", "0" * 64, "LEGACY_NO_HMAC"):
        v3 = _hmac_v3_payload(previous, "dismiss")
        assert v3.startswith(b"v3|")
        assert not v3.startswith(f"{previous}|".encode())
        assert not v3.startswith(b"v2|")


def test_legacy_row_without_hmac_is_chained_through_a_sentinel(ctx, audit):
    first_legacy = insert_unsigned(ctx, target_id="det-legacy-1")
    insert_unsigned(ctx, target_id="det-legacy-2")
    audit.log_audit("dismiss", "det-1")
    after_legacy = rows(ctx)[-1]
    expected = _compute_hmac_v3(
        _get_audit_secret(),
        "LEGACY_NO_HMAC",
        "dismiss",
        "det-1",
        "",
        after_legacy["timestamp"],
        "",
        "",
        "",
        "0.0",
        "",
        "",
        "default",
    )
    assert after_legacy["hmac_chain"] == expected
    audit.log_audit("dismiss", "det-2")
    result = audit.verify_chain()
    assert result["valid"] is True
    assert (result["total"], result["checked"]) == (4, 2)

    # Removing a legacy row is still visible as a gap.
    persist(ctx, "DELETE FROM audit_log WHERE target_id = 'det-legacy-2'")
    result = audit.verify_chain()
    assert result["valid"] is False
    assert result["errors"] == []
    assert result["gaps"] == [
        {"after_id": first_legacy, "before_id": after_legacy["id"], "missing": 1}
    ]


def missing_hmac_ids(result):
    """Ids reported as unsigned entries after a signed one."""
    missing = [e for e in result["errors"] if e["expected"] == _HMAC_MISSING]
    assert all(e["actual"] == "" for e in missing), missing
    return [e["id"] for e in missing]


def test_an_unsigned_entry_after_signed_entries_is_reported(ctx, audit):
    # Both writers sign every entry, so an unsigned one after a signed one was
    # written without the key: a forged append, or the newest entries
    # rewritten and their HMACs blanked (blanking every HMAC from an entry on
    # hides a rewrite of any of them).  The gateway reports the same rows.
    for target in ("det-1", "det-2", "det-3"):
        audit.log_audit("dismiss", target)
    second, newest = (r["id"] for r in rows(ctx)[1:])
    forged = insert_unsigned(ctx, target_id="det-forged")
    result = audit.verify_chain()
    assert result["valid"] is False
    assert result["errors"] == [{"id": forged, "expected": _HMAC_MISSING, "actual": ""}]
    assert (result["total"], result["checked"]) == (4, 4)
    persist(ctx, "DELETE FROM audit_log WHERE id = ?", (forged,))
    assert audit.verify_chain()["valid"] is True

    for rewritten in (newest, second):
        persist(
            ctx, "UPDATE audit_log SET note = 'rewritten' WHERE id = ?", (rewritten,)
        )
        persist(ctx, "UPDATE audit_log SET hmac_chain = '' WHERE id >= ?", (rewritten,))
        result = audit.verify_chain()
        assert result["valid"] is False, rewritten
        assert missing_hmac_ids(result) == list(range(rewritten, newest + 1))


def test_each_unsigned_entry_after_a_signed_one_is_reported_and_chained_past(
    ctx, audit
):
    for target in ("det-1", "det-2", "det-3"):
        audit.log_audit("dismiss", target)
    blanked, third = (r["id"] for r in rows(ctx)[1:])
    persist(ctx, "UPDATE audit_log SET hmac_chain = '' WHERE id = ?", (blanked,))
    forged = insert_unsigned(ctx, target_id="det-forged")
    # log_audit chains the next entry from the sentinel, and so does the walk.
    audit.log_audit("dismiss", "det-after")
    result = audit.verify_chain()
    assert result["valid"] is False
    assert result["errors"] == [
        {"id": blanked, "expected": _HMAC_MISSING, "actual": ""},
        # Chained from the blanked HMAC.
        {"id": third, "expected": _HMAC_MISMATCH, "actual": rows(ctx)[2]["hmac_chain"]},
        {"id": forged, "expected": _HMAC_MISSING, "actual": ""},
    ]
    assert (result["total"], result["checked"]) == (5, 5)


def test_unsigned_entries_after_an_archived_signed_prefix_are_reported(ctx, audit):
    # The archived prefix ended with a signed entry (the marker's terminal
    # HMAC), so blanking the HMAC of every live entry, the marker's included,
    # is reported although the walk meets no signed entry.
    old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
    for target in ("det-old-1", "det-old-2"):
        audit.log_audit("dismiss", target)
    persist(ctx, "UPDATE audit_log SET timestamp = ?", (old,))
    # Re-sign the old rows at their new timestamp, as if written then.
    previous = ""
    for row in rows(ctx):
        digest = _compute_hmac_v3(
            _get_audit_secret(), previous, "dismiss", row["target_id"], "", old,
            "", "", "", "0.0", "", "", "default",
        )  # fmt: skip
        persist(
            ctx, "UPDATE audit_log SET hmac_chain = ? WHERE id = ?", (digest, row["id"])
        )
        previous = digest
    audit.log_audit("dismiss", "det-live")
    archived = audit.archive_audit_log(max_age_days=90)
    assert (archived["archived_count"], archived["terminal_hmac"]) == (2, previous)
    assert audit.verify_chain()["valid"] is True

    persist(ctx, "UPDATE audit_log SET hmac_chain = ''")
    live = [r["id"] for r in rows(ctx)]
    result = audit.verify_chain()
    assert result["valid"] is False
    assert missing_hmac_ids(result) == live


def test_unsigned_rows_before_the_first_signed_one_survive_an_archive(ctx, audit):
    # An archived prefix of unsigned rows leaves an empty terminal HMAC: the
    # unsigned rows still before the first signed one keep verifying.
    old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
    insert_unsigned(ctx, timestamp=old, target_id="det-old")
    insert_unsigned(ctx, target_id="det-recent")
    audit.log_audit("dismiss", "det-1")
    archived = audit.archive_audit_log(max_age_days=90)
    assert (archived["archived_count"], archived["terminal_hmac"]) == (1, "")
    result = audit.verify_chain()
    assert result["valid"] is True, result
    assert (result["total"], result["checked"]) == (3, 2)


def test_a_gateway_archive_of_unsigned_rows_does_not_make_the_chain_signed(ctx, audit):
    # The gateway's marker for an archived prefix that ended unsigned carries
    # the sentinel as its terminal HMAC (its walk's predecessor after them).
    insert_unsigned(ctx, target_id="det-recent")
    audit.log_audit("dismiss", "det-1")
    audit.log_audit(
        "archive_marker",
        "",
        details={"terminal_hmac": "LEGACY_NO_HMAC", "last_archived_id": 1},
    )
    result = audit.verify_chain()
    assert result["valid"] is True, result
    assert (result["total"], result["checked"]) == (3, 2)


def test_missing_hmac_text_matches_the_gateway():
    # Same text as HMAC_MISSING in sigrift-gateway-core/src/audit/store.rs.
    assert _HMAC_MISSING == (
        "an HMAC: only entries before the chain's first signed entry may have none"
    )


def test_archive_after_a_legacy_head_chains_marker_through_sentinel(ctx, audit):
    old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
    persist(
        ctx,
        "INSERT INTO audit_log (timestamp, action, target_id, tenant_id, hmac_chain) "
        "VALUES (?, 'legacy', 'det-old', 'default', '')",
        (old,),
    )
    persist(
        ctx,
        "INSERT INTO audit_log (timestamp, action, target_id, tenant_id, hmac_chain) "
        "VALUES (?, 'legacy', 'det-recent', 'default', '')",
        (datetime.now(timezone.utc).isoformat(),),
    )
    result = audit.archive_audit_log(max_age_days=90)
    assert result["archived_count"] == 1
    assert result["terminal_hmac"] == ""
    marker = rows(ctx)[-1]
    assert marker["action"] == "archive_marker"
    expected = _compute_hmac_v3(
        _get_audit_secret(),
        "LEGACY_NO_HMAC",
        "archive_marker",
        "",
        "",
        marker["timestamp"],
        marker["details"],
        "",
        "",
        "0.0",
        "",
        "",
        "default",
    )
    assert marker["hmac_chain"] == expected
    assert [r["target_id"] for r in rows(ctx)] == ["det-recent", ""]


def test_archive_never_touches_another_tenant(db_path, ctx, audit):
    other = SharedContext(db_path, tenant_id="tenant-b")
    try:
        foreign = AuditStore(other)
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        foreign.log_audit("dismiss", "b-1")
        persist(
            other,
            "UPDATE audit_log SET timestamp = ? WHERE tenant_id = 'tenant-b'",
            (old,),
        )
        audit.log_audit("dismiss", "a-1")

        assert audit.archive_audit_log(max_age_days=90)["archived_count"] == 0
        assert [r["target_id"] for r in rows(ctx)] == ["b-1", "a-1"]
        assert audit.get_audit_log()[0]["target_id"] == "a-1"
        assert foreign.get_audit_log()[0]["target_id"] == "b-1"
        assert foreign.is_dismissed("a-1") is False
        assert audit.is_dismissed("b-1") is False
        assert audit.verify_chain()["valid"] is True
    finally:
        other.close()


def test_forged_archive_marker_cannot_vouch_for_a_tampered_row(ctx, audit):
    audit.log_audit("dismiss", "det-1")
    audit.log_audit("dismiss", "det-2")
    first = rows(ctx)[0]
    # Delete the first row and plant a marker claiming it was archived.
    persist(ctx, "DELETE FROM audit_log WHERE id = ?", (first["id"],))
    persist(
        ctx,
        "INSERT INTO audit_log (timestamp, action, target_id, details, tenant_id, "
        "hmac_chain) VALUES (?, 'archive_marker', '', ?, 'default', ?)",
        (
            datetime.now(timezone.utc).isoformat(),
            json.dumps({"terminal_hmac": first["hmac_chain"], "archived_count": 1}),
            "f" * 64,
        ),
    )
    marker_id = rows(ctx)[-1]["id"]
    result = audit.verify_chain()
    assert result["valid"] is False
    assert marker_id in error_ids(result)


def test_marker_with_unparseable_details_is_reported(ctx, audit):
    audit.log_audit("dismiss", "det-1")
    persist(
        ctx,
        "INSERT INTO audit_log (timestamp, action, target_id, details, tenant_id, "
        "hmac_chain) VALUES (?, 'archive_marker', '', '{not json', 'default', ?)",
        (datetime.now(timezone.utc).isoformat(), "0" * 64),
    )
    result = audit.verify_chain()
    assert result["valid"] is False
    assert error_ids(result) == [rows(ctx)[-1]["id"]]


# ---------------------------------------------------------------------------
# End to end through the admin HTTP routes
# ---------------------------------------------------------------------------


def _seed_http_audit(detection_store):
    detection_store.log_audit(action="dismiss", target_id="pct", note="100% done")
    detection_store.log_audit(action="dismiss", target_id="plain", note="100 done")
    detection_store.log_audit(
        action="flag", target_id="crit", details={"severity": "critical"}
    )


def test_http_audit_search_is_literal_and_chain_verifies(client, detection_store):
    _seed_http_audit(detection_store)
    resp = client.get("/api/admin/audit", params={"search": "%"})
    assert resp.status_code == 200
    body = resp.json()
    assert [e["target_id"] for e in body["entries"]] == ["pct"]
    assert body["total"] == 1

    resp = client.get("/api/admin/audit", params={"operator": "' OR '1'='1"})
    assert resp.status_code == 200
    assert resp.json()["entries"] == []

    verified = client.get("/api/admin/audit/verify").json()
    assert verified["valid"] is True
    assert verified["errors"] == [] and verified["gaps"] == []


def test_http_audit_verify_reports_a_tampered_row(client, detection_store):
    _seed_http_audit(detection_store)
    conn = detection_store.get_connection()
    with detection_store._ctx.write_transaction() as wconn:
        wconn.execute("UPDATE audit_log SET note = 'rewritten' WHERE target_id = 'pct'")
    tampered, stored = conn.execute(
        "SELECT id, hmac_chain FROM audit_log WHERE target_id = 'pct'"
    ).fetchone()
    body = client.get("/api/admin/audit/verify").json()
    assert body["valid"] is False
    # No computed digest is handed out (it would re-sign the tampered row).
    assert body["errors"] == [
        {
            "id": tampered,
            "expected": "HMAC of the entry's fields chained from its predecessor",
            "actual": stored,
        }
    ]


def test_http_audit_severity_filter(client, detection_store):
    _seed_http_audit(detection_store)
    resp = client.get("/api/admin/audit", params={"severity": "critical"})
    assert resp.status_code == 200
    assert [e["target_id"] for e in resp.json()["entries"]] == ["crit"]
    assert resp.json()["total"] == 1
