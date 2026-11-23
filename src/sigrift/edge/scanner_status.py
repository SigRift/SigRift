"""Best-effort leases backed by scanner work, never generic agent liveness.

A lost status request expires at the bridge; it must not stop radio capture.
Only fixed protocol/state/reason/status categories are logged, never
credentials, URLs, device observations or response bodies. Each report is a
single request, except one resend without "reason" to a bridge too old to know it.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from ssl import SSLContext

logger = logging.getLogger(__name__)
_STATES = frozenset({"running", "stopped", "error"})
_PROTOCOLS = frozenset({"sdr", "wifi", "bluetooth", "zigbee", "adsb"})
# Same closed list as sensor_presence.REASONS, repeated so this module still
# imports on its own in legacy standalone installs.
_REASONS = frozenset(
    {"starting", "sensor_absent", "sensor_changed", "sensor_unusable", "capture_failed"}
)
# How a bridge without the "reason" field refuses one: its strict model answers
# 422. Not 400, which other causes can produce.
_REASON_REFUSED = frozenset({422})
# Per request. stop() waits for an in-flight report, its one resend and the
# final report: 3 x 3 s stays inside Docker's default 10 s stop window.
_REQUEST_TIMEOUT = 3.0


def _reason_for(state: str, reason: str | None) -> str | None:
    if reason is not None and reason not in _REASONS:
        raise ValueError("Invalid scanner status reason")
    # The bridge accepts a reason only together with "error".
    return reason if state == "error" else None


class CaptureActivity:
    """Recent completed RF capture/classification, independent of detections.

    ``status`` is a ready ``capture_state`` callable that also says why
    capture is not running; ``state`` keeps returning the state alone.
    """

    def __init__(self) -> None:
        self._last_success: float | None = None
        self._ever_succeeded = False
        self._reason: str | None = None
        self._lock = threading.Lock()

    def succeeded(self) -> None:
        with self._lock:
            self._last_success = time.monotonic()
            self._ever_succeeded = True
            self._reason = None

    def failed(self, reason: str = "capture_failed") -> None:
        if reason not in _REASONS:
            raise ValueError("Invalid scanner status reason")
        with self._lock:
            self._last_success = None
            self._reason = reason

    def state(self) -> str:
        return self.status()[0]

    def status(self) -> tuple[str, str | None]:
        with self._lock:
            recent = self._last_success
            reason = self._reason
            ever = self._ever_succeeded
        if recent is not None and time.monotonic() - recent < 60:
            return "running", None
        if reason is None:
            # Never captured yet is start-up; captured once then went quiet
            # without an explicit failure is a stalled capture.
            reason = "capture_failed" if ever else "starting"
        return "error", reason


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # A status endpoint must never forward sensor credentials elsewhere.
        return None


class ScannerStatusReporter:
    """Report actual capture state every 30s against the bridge's 120s lease.

    TLS and authentication factories are the same ones the worker uses for
    uploads. Build the context first, because loading mTLS can change headers.
    The callback must observe real capture health, including a valid idle
    Wi-Fi capture; merely starting this reporter is never evidence of work.
    It returns a state, or ``(state, reason)`` with a reason from the closed
    list; a reason is sent only with "error".
    """

    def __init__(
        self,
        server_url: str,
        node_id: str,
        protocol: str,
        tls_context: Callable[[], SSLContext],
        auth_headers: Callable[[], dict[str, str]],
        capture_state: Callable[[], str | tuple[str, str | None]],
        *,
        interval: float = 30.0,
    ) -> None:
        if protocol not in _PROTOCOLS or not 0 < interval <= 30:
            raise ValueError("Invalid scanner status configuration")
        base = urllib.parse.urlsplit(server_url)
        if (
            base.scheme not in {"http", "https"}
            or not base.hostname
            or base.username is not None
            or base.password is not None
            or base.query
            or base.fragment
            or not node_id
        ):
            raise ValueError("Invalid scanner status destination")
        self._url = (
            server_url.rstrip("/")
            + "/api/nodes/"
            + urllib.parse.quote(node_id, safe="")
            + "/scanner-status"
        )
        self._protocol = protocol
        self._tls_context = tls_context
        self._auth_headers = auth_headers
        self._capture_state = capture_state
        self._interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._final_state = "stopped"
        self._final_reason: str | None = None
        self._send_reasons = True

    def report(self, state: str, reason: str | None = None) -> bool:
        if state not in _STATES:
            raise ValueError("Invalid scanner status state")
        reason = _reason_for(state, reason)
        body = {"protocol": self._protocol, "state": state}
        if reason is not None and self._send_reasons:
            body["reason"] = reason
            status = self._post(body, quiet=_REASON_REFUSED)
            if status not in _REASON_REFUSED:
                return status == 200
            # A bridge from before reasons forbids unknown fields. Fall back
            # to the state alone for the rest of this process.
            self._send_reasons = False
            logger.info(
                "Bridge does not accept scanner status reasons; sending state only"
            )
            del body["reason"]
        return self._post(body) == 200

    def _post(
        self, body: dict[str, str], quiet: frozenset[int] = frozenset()
    ) -> int | None:
        """Send one request; return the HTTP status, or None without one."""
        try:
            context = self._tls_context()
            headers = {**self._auth_headers(), "Content-Type": "application/json"}
            request = urllib.request.Request(
                self._url,
                data=json.dumps(body).encode(),
                headers=headers,
                method="POST",
            )
            opener = urllib.request.build_opener(
                _NoRedirect(), urllib.request.HTTPSHandler(context=context)
            )
            with opener.open(request, timeout=_REQUEST_TIMEOUT) as response:
                status = response.status
            if status != 200:
                logger.warning("Scanner status rejected: HTTP %d", status)
            return status
        except urllib.error.HTTPError as exc:
            if exc.code not in quiet:
                logger.warning("Scanner status rejected: HTTP %d", exc.code)
            exc.close()
            return exc.code
        except Exception:
            logger.warning("Scanner status transport/configuration failure")
        return None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run, name="scanner-status", daemon=True
        )
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                value = self._capture_state()
                state, reason = value if isinstance(value, tuple) else (value, None)
                if state not in _STATES:
                    raise ValueError("Invalid capture state")
                reason = _reason_for(state, reason)
            except Exception:
                logger.warning("Scanner capture-state inspection failed")
                state, reason = "error", None
            started = time.monotonic()
            self.report(state, reason)
            self._stop.wait(max(0.0, self._interval - (time.monotonic() - started)))
        self.report(self._final_state, self._final_reason)

    def stop(self, state: str = "stopped", reason: str | None = None) -> None:
        if state not in {"stopped", "error"}:
            raise ValueError("Invalid final scanner status")
        self._final_reason = _reason_for(state, reason)
        self._final_state = state
        self._stop.set()
        if self._thread is not None:
            # An in-flight report, its one resend and the final report, each
            # bounded by _REQUEST_TIMEOUT; no unbounded join.
            self._thread.join(timeout=3 * _REQUEST_TIMEOUT + 0.5)
            if self._thread.is_alive():
                logger.warning("Scanner status shutdown did not finish")
