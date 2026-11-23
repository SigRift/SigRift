"""get_ingest_claims: the claim store an app without one gets on first use.

Claims must hold across processes, so the store always works on the shared
detections database: a second store over the same database finds a claim
taken, whether or not the first one could be cached on the app state.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.storage.ingest_claims import IngestClaimStore, get_ingest_claims


class _SealedState:
    """App state that cannot take new attributes (setattr raises)."""

    __slots__ = ("detection_store",)

    def __init__(self, store):
        self.detection_store = store


def test_first_use_creates_one_store_on_the_shared_database(detection_store):
    state = SimpleNamespace(detection_store=detection_store)
    claims = get_ingest_claims(state)
    assert isinstance(claims, IngestClaimStore)
    assert state.ingest_claims is claims
    assert get_ingest_claims(state) is claims
    assert claims.claim_decode("det-1", now=1_000.0, source="iq-upload") is True
    # Another process opens its own connection to the same file: the claim is
    # already taken there, so the decode job is queued only once.
    other = DetectionStore(detection_store.db_path)
    try:
        assert IngestClaimStore(other._ctx).claim_decode("det-1", now=1_001.0) is False
        assert IngestClaimStore(other._ctx).decode_claimed("det-1") is True
    finally:
        other.close()


@pytest.mark.parametrize(
    "state",
    [
        SimpleNamespace(),
        SimpleNamespace(detection_store=None),
        SimpleNamespace(detection_store=SimpleNamespace(_ctx="not-a-shared-context")),
    ],
)
def test_without_a_shared_detection_database_there_is_no_store(state):
    assert get_ingest_claims(state) is None
    assert not hasattr(state, "ingest_claims")


def test_an_existing_store_is_returned_without_touching_the_database():
    sentinel = object()
    assert get_ingest_claims(SimpleNamespace(ingest_claims=sentinel)) is sentinel


def test_state_that_refuses_the_cache_still_deduplicates(detection_store):
    state = _SealedState(detection_store)
    first = get_ingest_claims(state)
    second = get_ingest_claims(state)
    assert isinstance(first, IngestClaimStore) and isinstance(second, IngestClaimStore)
    assert first is not second  # nothing could be cached on this state
    claimed = first.claim_hook_detections(
        "node-a", ["d1", "d2"], now=100.0, ttl=60.0, max_rows=100
    )
    assert claimed == {"d1", "d2"}
    # The claims live in the database, not in the first store's memory.
    again = second.claim_hook_detections(
        "node-a", ["d2", "d3"], now=101.0, ttl=60.0, max_rows=100
    )
    assert again == {"d3"}
    assert second.hook_claim_count() == 3
