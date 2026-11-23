"""Account lockout holds under concurrent logins.

``login()`` checks the per-account failure count, then awaits the PBKDF2
password check in a worker thread.  The failure used to be recorded only
after that await, so every attempt that arrived while earlier checks were
still running passed the lockout check: N parallel wrong guesses (each from
its own client IP, so the per-IP limit does not apply) were all checked
against the password instead of LOCKOUT_MAX of them.  The attempt is now
reserved — counted as a failure — in the same atomic step as the check.
"""

from __future__ import annotations

import asyncio
import threading

import httpx
import pytest

from sigrift.bridge.storage.security_state import SecurityStateStore

_USER = "lockme"
_PASSWORD = "CorrectHorse123!"


async def _login_burst(app, n: int, password: str) -> list[int]:
    # ASGITransport's client address is 127.0.0.1 — a trusted proxy — so
    # each request's X-Forwarded-For becomes its client IP.
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:

        async def one(i: int) -> int:
            resp = await client.post(
                "/api/auth/login",
                json={"username": _USER, "password": password},
                headers={"X-Forwarded-For": f"10.9.{i // 250}.{i % 250 + 1}"},
            )
            return resp.status_code

        return list(await asyncio.gather(*(one(i) for i in range(n))))


@pytest.fixture
def user(detection_store):
    detection_store.create_user(_USER, _PASSWORD, role="viewer")
    return _USER


def test_parallel_wrong_logins_stop_at_lockout_max(bridge_app, detection_store, user):
    lockout_max = detection_store.security_state.LOCKOUT_MAX
    attempts = lockout_max * 3
    codes = asyncio.run(_login_burst(bridge_app, attempts, "wrong-password"))
    assert codes.count(401) == lockout_max, codes
    assert codes.count(429) == attempts - lockout_max, codes
    assert detection_store.security_state.count_recent_failures(user) == lockout_max


def test_correct_password_clears_the_reservation(bridge_app, detection_store, user):
    codes = asyncio.run(_login_burst(bridge_app, 1, _PASSWORD))
    assert codes == [200]
    assert detection_store.security_state.count_recent_failures(user) == 0


def test_locked_account_rejects_even_the_right_password(
    bridge_app, detection_store, user
):
    sec = detection_store.security_state
    for _ in range(sec.LOCKOUT_MAX):
        sec.record_account_failure(user)
    codes = asyncio.run(_login_burst(bridge_app, 1, _PASSWORD))
    assert codes == [429]


class TestReserveAccountAttempt:
    def test_reserves_until_limit(self, detection_store):
        sec: SecurityStateStore = detection_store.security_state
        results = [sec.reserve_account_attempt("u") for _ in range(sec.LOCKOUT_MAX + 3)]
        assert results == [True] * sec.LOCKOUT_MAX + [False] * 3
        assert sec.count_recent_failures("u") == sec.LOCKOUT_MAX

    def test_atomic_across_threads(self, detection_store):
        sec: SecurityStateStore = detection_store.security_state
        results: list[bool] = []
        lock = threading.Lock()
        start = threading.Barrier(12)

        def worker():
            start.wait()
            for _ in range(3):
                ok = sec.reserve_account_attempt("racer")
                with lock:
                    results.append(ok)

        threads = [threading.Thread(target=worker) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert results.count(True) == sec.LOCKOUT_MAX
        assert sec.count_recent_failures("racer") == sec.LOCKOUT_MAX

    def test_other_accounts_unaffected(self, detection_store):
        sec: SecurityStateStore = detection_store.security_state
        for _ in range(sec.LOCKOUT_MAX):
            assert sec.reserve_account_attempt("busy")
        assert sec.reserve_account_attempt("other")
