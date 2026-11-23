/**
 * The Bridge — Main Dashboard JavaScript
 * Manages API communication, WebSocket connections, panel updates,
 * card collapse/expand, theme toggle, auth flow, and orchestrates
 * DetectionDashboard, SpectrumViewer, and SignalBrowser.
 * Security: All dynamic content is HTML-escaped. No eval(), no innerHTML with untrusted data.
 */
"use strict";

/* -- Utilities -------------------------------------------------- */

/* HTML-escape text (& < > " ') for element content and for quoted attribute
 * values. Not for unquoted attributes, URLs, inline handlers, script elements or style. */
function esc(str) {
    if (str == null) return "";
    return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function fmtTime(iso) {
    if (!iso) return "--";
    try { return new Date(iso).toLocaleString(undefined, { hour12: false, month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" }); }
    catch (_) { return esc(iso); }
}
/* A node-reported value as a finite number, or null. Heartbeat metrics
   reach the node table through free-form fields, so a string, object or
   NaN reads as not reported instead of throwing: one bad node must never
   blank the table for every node. */
function finiteNumber(v) {
    return typeof v === "number" && isFinite(v) ? v : null;
}
/* finiteNumber(v) with toFixed(digits) and *suffix*, or "--". */
function fixedOr(v, digits, suffix) {
    var n = finiteNumber(v);
    return n == null ? "--" : n.toFixed(digits) + (suffix || "");
}
function fmtUptime(s) {
    if (s == null || s < 0) return "";
    return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m";
}
function setText(id, t) { var el = document.getElementById(id); if (el) el.textContent = t; }
function setHTML(id, h) { var el = document.getElementById(id); if (el) el.innerHTML = h; }

// Preferences remain usable in this tab when browser storage is denied/full.
var _browserPreferenceFallback = Object.create(null);
function readBrowserPreference(key) {
    if (Object.prototype.hasOwnProperty.call(_browserPreferenceFallback, key)) return _browserPreferenceFallback[key];
    try { return localStorage.getItem(key); } catch (_) { return null; }
}
function writeBrowserPreference(key, value) {
    try { localStorage.setItem(key, value); delete _browserPreferenceFallback[key]; return true; }
    catch (_) { _browserPreferenceFallback[key] = String(value); return false; }
}

/* -- Page visibility: pause polling when tab is hidden ---------- */
var _pageVisible = true;
document.addEventListener("visibilitychange", function() {
    _pageVisible = !document.hidden;
});
function isPageActive() { return _pageVisible; }

/* -- Toast notification system ---------------------------------- */
var _toastContainer = null;
function showToast(msg, type) {
    if (!_toastContainer) _toastContainer = document.getElementById("toast-container");
    if (!_toastContainer) return;
    var el = document.createElement("div");
    el.className = "toast" + (type ? " toast-" + type : "");
    el.textContent = msg;
    _toastContainer.appendChild(el);
    setTimeout(function() {
        el.classList.add("toast-out");
        setTimeout(function() { if (el.parentNode) el.parentNode.removeChild(el); }, 250);
    }, 4000);
    // Limit visible toasts
    while (_toastContainer.children.length > 5) _toastContainer.removeChild(_toastContainer.firstChild);
}

/* The most anomalies one escalation request may name (the server's limit). */
var ESCALATION_MAX_IDS = 100;

/* What a bulk escalation (POST .../anomalies/bulk/escalate) did, for a toast:
   the one critical alert it raised for the anomalies it escalated, and the
   selected anomalies it skipped. */
function escalationSummary(result) {
    result = result || {};
    var raised = Number(result.escalated_count) || 0;
    var open = Array.isArray(result.already_escalated) ? result.already_escalated.length : 0;
    var gone = Array.isArray(result.not_found) ? result.not_found.length : 0;
    var msg = raised
        ? "Critical alert raised for " + raised + " anomal" + (raised === 1 ? "y" : "ies")
        : "No new alert";
    if (open) msg += "; " + open + " already escalated";
    if (gone) msg += "; " + gone + " not found";
    return msg;
}

/* Whether an escalation of `count` selected anomalies may be sent; when it
   names more than the server accepts, says so and sends nothing. */
function escalationFits(count) {
    if (count <= ESCALATION_MAX_IDS) return true;
    showToast("Escalate at most " + ESCALATION_MAX_IDS + " anomalies at a time (" + count + " selected)", "error");
    return false;
}

/* -- Error-tracking fetch wrapper ------------------------------- */
var _fetchErrors = {};
function trackFetchError(name, err) {
    // Don't track errors while auth overlay is visible (401s are expected)
    var authOverlay = document.getElementById("auth-overlay");
    if (authOverlay && authOverlay.style.display !== "none") return;
    // Don't track auth errors
    if (err && err.message === "Unauthorized") return;
    // Don't spam toasts for rate limiting — it's transient
    if (err && (err.detail === "Rate limit exceeded" || (err.message && err.message.indexOf("429") !== -1))) return;
    _fetchErrors[name] = (_fetchErrors[name] || 0) + 1;
    if (_fetchErrors[name] === 3) showToast("Connection issue: " + name + " failing", "error");
}
function clearFetchError(name) { _fetchErrors[name] = 0; }

/* -- Node hardware lookup (fallback when capabilities not reported) -- */
/* Hardware info should come from node capabilities reported via heartbeat.
   This empty table serves as a fallback; populate from /api/nodes if needed. */
var _NODE_HW = {};

/* -- BridgeDashboard Class -------------------------------------- */

function BridgeDashboard() {
    // Read auth from cookies via auth_guard.js (sessionStorage unreliable with self-signed TLS)
    var _auth = window.__bridge_auth || {};
    this.apiKey = _auth.apiKey || sessionStorage.getItem("bridge_api_key") || "";
    this.sessionToken = _auth.sessionToken || sessionStorage.getItem("bridge_session_token") || "";
    this._cookieAuth = !this.sessionToken && !this.apiKey && document.cookie.indexOf("csrf_token=") !== -1;
    this.sessionUser = null;
    this.wsConns = {};
    this.wsRetries = {};
    this.wsMaxRetries = 5;
    this.pollTimers = {};
    this.collapsed = {};
    this.wifiNodeIds = [];
    this.activeFreqHours = 1;

    this.detectionDashboard = null;
    this.spectrumViewer = null;
    this.signalBrowser = null;
    this.geoMap = null;
    var dashboard = this;
    this.scannerAvailability = new ScannerAvailability(function() {
        dashboard._updateScannerTabs();
        dashboard._renderNodes(dashboard.scannerAvailability.nodes);
    });

    this._loadCollapsed();
    this._initTheme();
    this._initAlertSound();
    this._initBrowserNotifications();
    this._initTabs();
    this._initCards();
    this._initFreqRange();
    this._initAuthGuard();
    this._initModal();
    this._initWideModal();
    this._initAlerts();
    this._initNodeSearch();
    this._initNodeDetails();
    this._initFloorPlan();
    this._initGeoMap();
    this._initIQCaptureDialog();
    this._initThreatTimeline();
    this._initStaleTracking();
    this._initTrends();
    this._initShortcutOverlay();
    this._initEntityIndex();
    this._initMFASettings();
    this._initFreshnessStripes();
    this._initEdgeOnboarding();

    this.setupChecklist = window.SetupChecklist ? new window.SetupChecklist(this) : null;
    this._startPolling();
    this._connectWebSockets();
    this._loadActivity();
}

/* -- API Fetch -------------------------------------------------- */

/* A failed response as an Error("HTTP <status>") (Error("Unauthorized") for
   a 401) that keeps the status and, from a JSON body, the server's string
   `detail` for the caller to show as text. A body that is not JSON, or has
   no string detail, leaves just the status. */
function apiResponseError(r, message) {
    var error = new Error(message);
    error.status = r.status;
    return r.json().then(function(body) {
        if (body && typeof body.detail === "string") error.detail = body.detail;
        return Promise.reject(error);
    }, function() { return Promise.reject(error); });
}

/* opts.keepSessionOn401: the request checks a code the operator typed (MFA),
   whose 401 means "wrong code", not "session ended". Every other 401 means
   the credential is no longer accepted, so the page returns to sign-in. */
BridgeDashboard.prototype.apiFetch = function(path, opts) {
    var self = this;
    opts = opts || {};
    var keepSession = !!opts.keepSessionOn401;
    delete opts.keepSessionOn401;
    var h = opts.headers || {};
    h["Accept"] = "application/json";
    h["Cache-Control"] = "no-cache";
    if (opts.body && typeof opts.body === "object" && !(opts.body instanceof FormData)) {
        h["Content-Type"] = "application/json";
        opts.body = JSON.stringify(opts.body);
    }
    if (self.sessionToken) h["Authorization"] = "Bearer " + self.sessionToken;
    else if (self.apiKey) h["X-API-Key"] = self.apiKey;
    // If neither sessionStorage token is set, cookies will be sent via credentials:"same-origin"
    opts.headers = h;
    opts.credentials = "same-origin";
    // Cache-bust: append timestamp to prevent stale browser cache on GET requests
    if (!opts.method || opts.method === "GET") {
        var sep = path.indexOf("?") === -1 ? "?" : "&";
        path = path + sep + "_t=" + Date.now();
    }
    return fetch(path, opts).then(function(r) {
        // Never log the credential, or any part of it: the console is
        // readable by anyone at the screen and by injected script.
        if (r.status === 401) { console.warn("401 on " + path); if (!keepSession) self._showAuth(); return apiResponseError(r, "Unauthorized"); }
        if (!r.ok) return apiResponseError(r, "HTTP " + r.status);
        if (r.status === 204) return null;
        return (r.headers.get("content-type") || "").indexOf("json") !== -1 ? r.json() : r;
    });
};

/* -- WebSocket Manager ------------------------------------------ */

BridgeDashboard.prototype._wsUrl = function(path) {
    var p = location.protocol === "https:" ? "wss:" : "ws:";
    var u = p + "//" + location.host + path;
    // No longer append query params - use Sec-WebSocket-Protocol header instead
    return u;
};

/* Sub-protocols for a WebSocket: ["bridge-v1", <credential>] when the
   dashboard holds an API key or session token; none in cookie mode, where
   the browser sends the (HttpOnly) session cookie with the upgrade. */
BridgeDashboard.prototype._wsProtocols = function() {
    var authKey = this.apiKey || this.sessionToken;
    return authKey ? ["bridge-v1", authKey] : [];
};

BridgeDashboard.prototype._connectWS = function(name, path, onMsg) {
    var self = this;
    if (!self.apiKey && !self.sessionToken && !self._cookieAuth) return;
    if (self.wsConns[name] && self.wsConns[name].readyState <= 1) return;
    if ((self.wsRetries[name] || 0) >= self.wsMaxRetries) return;
    var ws;
    try {
        // SECURITY: Use Sec-WebSocket-Protocol header for auth instead of query params
        // This prevents API keys from leaking to server logs, proxy logs, and browser history
        ws = new WebSocket(self._wsUrl(path), self._wsProtocols());
    } catch (_) { return; }
    self.wsConns[name] = ws;
    ws.onopen = function() { self.wsRetries[name] = 0; self._updateConn(); };
    ws.onmessage = function(ev) { try { onMsg(JSON.parse(ev.data)); } catch (_) {} };
    ws.onclose = function() {
        self.wsConns[name] = null;
        self._updateConn();
        self.wsRetries[name] = (self.wsRetries[name] || 0) + 1;
        setTimeout(function() { self._connectWS(name, path, onMsg); }, Math.min(1000 * Math.pow(2, self.wsRetries[name]), 30000));
    };
    ws.onerror = function() { ws.close(); };
};

BridgeDashboard.prototype._connectWebSockets = function() {
    var s = this;
    s._connectWS("status", "/api/nodes/ws/status", function(d) { s._onStatusWS(d); });
    s._connectWS("alerts", "/api/alerts/ws/alerts", function(d) { s._onAlertWS(d); });
};

BridgeDashboard.prototype._updateConn = function() {
    var el = document.getElementById("connection-status");
    if (!el) return;
    var open = false;
    for (var k in this.wsConns) {
        if (this.wsConns[k] && this.wsConns[k].readyState === 1) { open = true; break; }
    }
    el.className = "connection-indicator " + (open ? "connected" : "disconnected");
    var st = el.querySelector(".status-text");
    if (st) st.textContent = open ? "Connected" : "Disconnected";
    // R6: Mark fresh on reconnect
    if (open) this._markDataFresh();
};

/* -- Polling ---------------------------------------------------- */

BridgeDashboard.prototype._stopPolling = function() {
    for (var k in this.pollTimers) {
        if (this.pollTimers[k]) clearInterval(this.pollTimers[k]);
    }
    this.pollTimers = {};
};

BridgeDashboard.prototype._startPolling = function() {
    var s = this;
    s._stopPolling();
    s._pollStatus();
    s._pollNodes();
    s._pollSummaryStats();
    s._pollIngestStatus();
    if (s.setupChecklist) s.setupChecklist.refresh();
    s.pollTimers.setup = setInterval(function() { if (isPageActive() && s.setupChecklist) s.setupChecklist.refresh(); }, 20000);
    s.pollTimers.st = setInterval(function() { if (isPageActive()) s._pollStatus(); }, 15000);
    s.pollTimers.nd = setInterval(function() { if (isPageActive()) s._pollNodes(); }, 10000);
    s.pollTimers.ss = setInterval(function() { if (isPageActive()) s._pollSummaryStats(); }, 30000);
    s.pollTimers.is = setInterval(function() { if (isPageActive()) s._pollIngestStatus(); }, 30000);
};

BridgeDashboard.prototype._pollStatus = function() {
    var s = this;
    s.apiFetch("/api/status?freq_hours=" + s.activeFreqHours).then(function(d) {
        // PR-22 (dashboard §1.2): mark SDR-source data as freshly fetched.
        // /api/status powers the SDR summary-group (nodes, detection rate,
        // RF anomalies, active freqs). When the SDR ingest path dies, this
        // call stops succeeding and the per-source stripe goes red within
        // 2x cadence — instead of the panel silently displaying "0".
        s._markSourceFresh("sdr");
        // Nodes
        setText("stat-node-count", d.node_count);
        setText("stat-node-detail", (d.active_nodes || 0) + " active");
        // Detections/sec
        var dps = d.detections_per_second != null ? d.detections_per_second : 0;
        setText("stat-det-rate", dps.toFixed(1) + "/sec");
        setText("stat-det-detail", (d.total_detections_24h || 0) + " total (24h)");
        // Anomalies
        setText("stat-anomaly-count", d.active_anomalies != null ? d.active_anomalies : "--");
        setText("stat-anomaly-detail", (d.active_anomalies || 0) + " active");
        // Alerts
        setText("stat-alert-count", d.alert_count != null ? d.alert_count : "--");
        setText("stat-alert-detail", (d.unacked_alerts || 0) + " unacked");
        // Active Freqs
        setText("stat-freq-count", d.active_frequencies != null ? d.active_frequencies : "--");
        var freqLabel = s.activeFreqHours >= 168 ? "last 7d" : s.activeFreqHours >= 24 ? "last 24h" : "last " + s.activeFreqHours + "h";
        setText("stat-freq-detail", freqLabel);
        // Active Frequency list
        s._renderActiveFreqs(d.active_frequency_list || []);
        s._renderUniqueFreqs(d.active_frequency_list || []);
        s._renderSuspiciousFreqs(d.active_frequency_list || []);
        // Uptime
        setText("uptime-display", "Uptime: " + fmtUptime(d.uptime_seconds));
        // R2: Update tab badges
        var anomCount = d.active_anomalies || 0;
        s._updateTabBadge("rf", anomCount, anomCount > 0 ? "warning" : "");
        var alertCount = d.unacked_alerts || 0;
        s._updateTabBadge("alerts", alertCount, alertCount > 0 ? "critical" : "");
        // Incidents tab badge (fetch open incident count)
        s.apiFetch("/api/incidents/metrics").then(function(m) {
            var incOpen = (m.open || 0) + (m.investigating || 0);
            s._updateTabBadge("incidents", incOpen, incOpen > 0 ? "warning" : "");
        }).catch(function() {});
        // PR-16 (cog review §1.1): populate the canonical
        // "UNACKED CRITICAL" lead stat-card. /api/status only
        // exposes the unacked total (all severities); to split out
        // the critical slice we issue a filtered alerts list call.
        // limit=500 is the API max and well above any realistic
        // critical backlog. Cheap enough to ride the same 15s
        // status cadence.
        s._updateUnackedCritical();
        // R7: Track trends and render indicators
        s._trackStat("det_rate", dps);
        s._trackStat("anomalies", d.active_anomalies || 0);
        s._trackStat("alerts", d.alert_count || 0);
        s._trackStat("freqs", d.active_frequencies || 0);
        s._renderTrendIndicator("stat-det-rate", "det_rate");
        s._renderTrendIndicator("stat-anomaly-count", "anomalies");
        s._renderTrendIndicator("stat-alert-count", "alerts");
        s._renderTrendIndicator("stat-freq-count", "freqs");
        // R6: Mark data fresh
        s._markDataFresh();
        // PR-6 (cog review §1.3): tri-state edge-onboarding banner.
        // Drives display of the first-run installer card based on
        // both node_count and the new local_scanner_key_registered
        // signal so quickstart-path users aren't told to mint keys
        // that docker-compose already minted.
        s._toggleEdgeOnboarding(d);
    }).then(function() { clearFetchError("status"); }).catch(function(e) { trackFetchError("status", e); });
};

/* -- PR-6: Edge-onboarding banner state machine (cog review §1.3) -- *
 *
 * Three states, picked from /api/status fields:
 *
 *   1. node_count > 0
 *      -> hide the banner entirely (operator is past first-run)
 *
 *   2. node_count == 0 AND local_scanner_key_registered == true
 *      -> show "registered, waiting for heartbeat" sub-state.
 *         The docker-compose stack pre-registered a NODE key for
 *         the bundled wifi-scan/bt-scan containers, so the work
 *         the full installer card describes is already done.
 *         Pointing the operator at "Admin -> mint a NODE key"
 *         here would be misleading (cognitive review §1.3, §8.1).
 *
 *   3. node_count == 0 AND local_scanner_key_registered == false
 *      -> show the full installer one-liner card (legacy behavior).
 *
 * Backwards compatibility: when the field is absent from the
 * response (older bridge serving an updated dashboard, or vice
 * versa), we treat it as `false` and fall back to state 3 /
 * state 1 — i.e. the pre-PR-6 behavior. Operators on stale
 * servers see no regression.
 *
 * The user-banner dismiss lasts for the browser-tab session: once
 * the operator hits Hide we don't re-show the card on the next
 * poll or after a reload of the same tab (sessionStorage key
 * "edge-onboarding-dismissed"). A new tab or browser session
 * re-prompts. Storage that throws (private mode, blocked site
 * data) falls back to the in-memory flag.
 */
var EDGE_ONBOARDING_DISMISS_KEY = "edge-onboarding-dismissed";

function _edgeOnboardingDismissStored() {
    try { return window.sessionStorage.getItem(EDGE_ONBOARDING_DISMISS_KEY) === "1"; }
    catch (e) { return false; }
}

BridgeDashboard.prototype._toggleEdgeOnboarding = function(status) {
    var s = this;
    var card = document.getElementById("edge-onboarding-card");
    if (!card) return;
    if (s._edgeOnboardingDismissed || _edgeOnboardingDismissStored()) {
        card.style.display = "none";
        return;
    }
    // node_count is every registered node, not just the active ones;
    // active_nodes covers a payload that only reports the live count.
    var nodeCount = 0;
    if (status && typeof status.node_count === "number") nodeCount = status.node_count;
    if (status && typeof status.active_nodes === "number" && status.active_nodes > nodeCount) nodeCount = status.active_nodes;
    // Treat missing flag as false (back-compat with older /api/status payloads).
    var keyRegistered = !!(status && status.local_scanner_key_registered);

    if (nodeCount > 0) {
        // State 1: nodes are checking in. Suppress the banner.
        card.style.display = "none";
        return;
    }

    var installer = document.getElementById("edge-onboarding-installer");
    var waiting = document.getElementById("edge-onboarding-waiting");
    var heading = document.getElementById("edge-onboarding-heading");
    var subline = document.getElementById("edge-onboarding-sub");

    if (keyRegistered) {
        // State 2: in-stack scanner key present, awaiting first heartbeat.
        if (installer) installer.style.display = "none";
        if (waiting) waiting.style.display = "";
        if (heading) heading.textContent = "In-stack scanners registered, awaiting heartbeat";
        if (subline) {
            subline.textContent =
                "The bundled wifi-scan and bt-scan containers have an API " +
                "key pre-registered. They should check in within ~30 seconds " +
                "of container startup.";
        }
    } else {
        // State 3: no scanners anywhere. Show the original installer card.
        if (installer) installer.style.display = "";
        if (waiting) waiting.style.display = "none";
        if (heading) heading.textContent = "No edge agents are reporting yet";
        if (subline) {
            subline.textContent =
                "Attach an RTL-SDR (or other supported SDR) to a host on " +
                "your network, then run the installer below on that host. " +
                "A node typically appears here within 30 seconds of install.";
        }
    }
    s._fillEdgeOneliner();
    card.style.display = "block";
};

/* Fill the one-liner with the live dashboard origin so the operator
 * doesn't have to edit <bridge-url> by hand. The edge agent verifies
 * the gateway's TLS certificate, so the command trusts the gateway's
 * (by default self-signed) cert explicitly: curl fetches the script
 * with --cacert and the agent gets --ca-cert. --api-key stays last:
 * the copy handler turns YOUR_NODE_KEY into a "# REPLACE ..." comment,
 * which swallows the rest of the line. */
BridgeDashboard.prototype._fillEdgeOneliner = function() {
    var pre = document.getElementById("edge-install-oneliner");
    if (!pre) return;
    var origin = window.location.origin;
    pre.textContent =
        "curl -sfL --cacert gateway-cert.pem " + origin +
        "/api/edge/install.sh | " +
        "sudo bash -s -- --api-url " + origin +
        " --ca-cert gateway-cert.pem --api-key YOUR_NODE_KEY";
};

/* PR-6: one-time wiring for the banner dismiss button + copy button.
 * Called from init(). Idempotent — guards against being attached
 * twice if init() runs more than once. */
BridgeDashboard.prototype._initEdgeOnboarding = function() {
    var s = this;
    if (s._edgeOnboardingWired) return;
    s._edgeOnboardingWired = true;

    var dismiss = document.getElementById("edge-onboarding-dismiss");
    if (dismiss) {
        dismiss.addEventListener("click", function() {
            s._edgeOnboardingDismissed = true;
            try { window.sessionStorage.setItem(EDGE_ONBOARDING_DISMISS_KEY, "1"); } catch (e) { /* in-memory only */ }
            var card = document.getElementById("edge-onboarding-card");
            if (card) card.style.display = "none";
        });
    }

    var copyBtn = document.getElementById("edge-oneliner-copy");
    var copied = document.getElementById("edge-oneliner-copied");
    if (copyBtn) {
        copyBtn.addEventListener("click", function() {
            var codeEl = document.getElementById("edge-install-oneliner");
            if (!codeEl) return;
            // PR-6 (cog review §1.3 / plan line 90): the literal
            // "YOUR_NODE_KEY" placeholder paste-and-run would silently
            // produce a 401-loop for the operator. Replace it in the
            // clipboard payload with a hash-prefixed REPLACE marker so
            // the shell rejects the command outright — fail loud, not
            // fail silent.
            var raw = codeEl.textContent || "";
            var safe = raw.replace(
                /YOUR_NODE_KEY/g,
                "# REPLACE WITH YOUR KEY"
            );
            var ok = function() {
                if (!copied) return;
                copied.style.display = "";
                setTimeout(function() { copied.style.display = "none"; }, 2000);
            };
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(safe).then(ok).catch(function() {
                    // Fall back to the old textarea trick if the
                    // Clipboard API rejects (HTTP context, permissions).
                    var ta = document.createElement("textarea");
                    ta.value = safe;
                    document.body.appendChild(ta);
                    ta.select();
                    try { document.execCommand("copy"); ok(); } catch (_) { /* noop */ }
                    document.body.removeChild(ta);
                });
            } else {
                var ta2 = document.createElement("textarea");
                ta2.value = safe;
                document.body.appendChild(ta2);
                ta2.select();
                try { document.execCommand("copy"); ok(); } catch (_) { /* noop */ }
                document.body.removeChild(ta2);
            }
        });
    }
};

/* -- PR-16: Canonical "Unacked Critical" lead stat-card --------- */

BridgeDashboard.prototype._updateUnackedCritical = function() {
    var s = this;
    s.apiFetch("/api/alerts/?severity=critical&acknowledged=false&limit=500").then(function(alerts) {
        if (!Array.isArray(alerts)) alerts = [];
        var count = alerts.length;
        var card = document.getElementById("stat-unacked-critical-card");
        var sub;
        if (count === 0) {
            sub = "no open criticals";
            if (card) card.setAttribute("data-state", "zero");
        } else {
            // Count distinct nodes touched by the open criticals so
            // the operator gets blast-radius at a glance, not just
            // a raw alert count.
            var nodeSet = {};
            for (var i = 0; i < alerts.length; i++) {
                var nid = alerts[i].node_id;
                if (nid) nodeSet[nid] = 1;
            }
            var nodes = Object.keys(nodeSet).length;
            sub = count + " open" + (nodes > 0 ? " — " + nodes + " node" + (nodes === 1 ? "" : "s") : "");
            if (card) card.setAttribute("data-state", "nonzero");
        }
        setText("stat-unacked-critical", count);
        setText("stat-unacked-critical-sub", sub);
    }).catch(function() { /* leave previous value rather than flap to 0 */ });
};

/* -- Summary Tab Stats (lightweight fetch for inactive panels) --- */

BridgeDashboard.prototype._pollSummaryStats = function() {
    var s = this;
    // Fetch basic stats for WiFi/BT/Zigbee so summary tab shows counts
    // even when those panels are inactive
    s.apiFetch("/api/wifi/stats").then(function(d) {
        // PR-22 (dashboard §1.2): mark Wi-Fi-source fresh on success.
        s._markSourceFresh("wifi");
        setText("sum-wifi-networks", d.total_networks != null ? d.total_networks : "--");
        setText("sum-wifi-clients", d.total_clients != null ? d.total_clients : "--");
        setText("sum-wifi-anomalies", d.anomaly_count != null ? d.anomaly_count : "--");
        // R2: WiFi anomaly badge
        var wac = d.anomaly_count || 0;
        s._updateTabBadge("wifi", wac, wac > 0 ? "warning" : "");
    }).catch(function() {});
    s.apiFetch("/api/bluetooth/stats").then(function(d) {
        // PR-22 (dashboard §1.2): mark Bluetooth-source fresh on success.
        s._markSourceFresh("bluetooth");
        setText("sum-bt-devices", d.total_devices != null ? d.total_devices : "--");
        setText("sum-bt-anomalies", d.anomaly_count != null ? d.anomaly_count : "--");
        // R2: BT anomaly badge
        var bac = d.anomaly_count || 0;
        s._updateTabBadge("bluetooth", bac, bac > 0 ? "warning" : "");
    }).catch(function() {});
    s.apiFetch("/api/zigbee/stats").then(function(d) {
        // PR-22 (dashboard §1.2): mark Zigbee-source fresh on success.
        s._markSourceFresh("zigbee");
        var total = 0, panIds = 0;
        if (d.total_devices != null) total = d.total_devices;
        if (d.pan_ids != null) panIds = Array.isArray(d.pan_ids) ? d.pan_ids.length : d.pan_ids;
        setText("sum-zb-devices", total);
        setText("sum-zb-pan-ids", panIds);
    }).catch(function() {});
};

/* -- PR-22: Per-source freshness stripes (dashboard §1.2) -------- *
 * When a backend scanner dies (wifi-scan, bluetooth-scan, zigbee-
 * scan, or the SDR ingest path), the corresponding /api/<source>/
 * stats endpoint stops returning fresh data — the dashboard then
 * silently displays "0" with no anomaly signal. This module tracks
 * the last-successful fetch timestamp per source and tints the
 * matching summary-group header red once age exceeds 2x the
 * expected poll cadence.
 *
 * Falsifiable validation: stop the wifi-scan service operator-side;
 * the Wi-Fi summary-group should turn red within ~60s (poll cadence
 * is 30s for /api/wifi/stats, threshold 2x = 60s).
 *
 * NOTE: CSS class `.summary-group.freshness-stale` is requested
 * upstream (no rule exists yet — PR #120 added .threshold-* but not
 * freshness-*). Inline border-left provides the visual until then.
 */

// Map source key -> { groupLabel, expectedCadenceMs }
// groupLabel matches the .summary-group-label textContent in
// index.html:162,187,212,227 — used to locate the cluster by DOM
// scan rather than fragile nth-child indexing (resilient to layout
// reshuffles).
BridgeDashboard.prototype._freshnessSources = {
    sdr:       { label: "SDR",              cadenceMs: 15000 }, // /api/status @ 15s
    wifi:      { label: "Wi-Fi",            cadenceMs: 30000 }, // /api/wifi/stats @ 30s
    bluetooth: { label: "Bluetooth SIGINT", cadenceMs: 30000 }, // /api/bluetooth/stats @ 30s
    zigbee:    { label: "Zigbee",           cadenceMs: 30000 }, // /api/zigbee/stats @ 30s
};

BridgeDashboard.prototype._sourceTimestamps = {};

BridgeDashboard.prototype._markSourceFresh = function(source) {
    this._sourceTimestamps[source] = Date.now();
    // Defer the stripe update to the next paint so we don't thrash
    // the DOM mid-render. updateFreshnessStripes is also on a 5s
    // wall-clock timer so a fetch that fails outright still flips
    // the stripe.
    this._updateFreshnessStripes();
};

BridgeDashboard.prototype._findSummaryGroup = function(labelText) {
    // Locate the .summary-group whose .summary-group-label matches.
    var labels = document.querySelectorAll(".summary-group .summary-group-label");
    for (var i = 0; i < labels.length; i++) {
        if (labels[i].textContent.trim() === labelText) {
            return labels[i].closest(".summary-group");
        }
    }
    return null;
};

BridgeDashboard.prototype._updateFreshnessStripes = function() {
    var now = Date.now();
    if (this._freshnessStart == null) this._freshnessStart = now;
    var sources = this._freshnessSources;
    for (var key in sources) {
        if (!sources.hasOwnProperty(key)) continue;
        var meta = sources[key];
        var group = this._findSummaryGroup(meta.label);
        if (!group) continue;
        var ts = this._sourceTimestamps[key];
        // No timestamp yet means we have never seen a successful
        // fetch for this source: it ages from page load, so a scanner
        // that is down from the start turns red after the same 2x
        // cadence instead of looking healthy forever.
        var threshold = 2 * meta.cadenceMs;
        var age = now - (ts || this._freshnessStart);
        var stale = age > threshold;
        if (stale) {
            if (!group.classList.contains("freshness-stale")) {
                group.classList.add("freshness-stale");
                // Inline fallback until CSS rule lands upstream.
                group.style.borderLeft = "4px solid var(--accent-red, #e5534b)";
                group.setAttribute("data-freshness-stale", "true");
                group.setAttribute(
                    "title",
                    meta.label + " data stale (no successful fetch in " +
                    Math.round(age / 1000) + "s; backend scanner may be down)"
                );
            }
        } else {
            if (group.classList.contains("freshness-stale")) {
                group.classList.remove("freshness-stale");
                group.style.borderLeft = "";
                group.removeAttribute("data-freshness-stale");
                group.removeAttribute("title");
            }
        }
    }
};

BridgeDashboard.prototype._initFreshnessStripes = function() {
    var s = this;
    // Separate 5s tick so even a completely-failing source flips
    // red without waiting for the next poll to even attempt.
    if (s._freshnessTimer) clearInterval(s._freshnessTimer);
    s._freshnessTimer = setInterval(function() {
        if (isPageActive()) s._updateFreshnessStripes();
    }, 5000);
};

/* -- Raw Ingest Warning Panel ----------------------------------- */

BridgeDashboard.prototype._pollIngestStatus = function() {
    var s = this;
    s.apiFetch("/api/detections/ingest-status").then(function(d) {
        var panel = document.getElementById("panel-raw-ingest-warning");
        var tbody = document.getElementById("raw-ingest-tbody");
        var badge = document.getElementById("raw-ingest-badge");
        if (!panel || !tbody) return;

        var rawNodes = d.raw_ingest_nodes || {};
        var summaryNodes = d.summary_ingest_nodes || {};

        // Filter to nodes that are ONLY using raw ingest (not also using summary)
        var offenders = [];
        for (var nodeId in rawNodes) {
            if (!rawNodes.hasOwnProperty(nodeId)) continue;
            // Skip nodes that have migrated (summary timestamp is newer)
            if (summaryNodes[nodeId] && summaryNodes[nodeId] >= rawNodes[nodeId]) continue;
            offenders.push({ id: nodeId, ts: rawNodes[nodeId] });
        }

        if (offenders.length === 0) {
            panel.style.display = "none";
            return;
        }

        // Sort by most recent first
        offenders.sort(function(a, b) { return b.ts - a.ts; });

        panel.style.display = "";
        if (badge) badge.textContent = offenders.length;

        var html = "";
        for (var i = 0; i < offenders.length; i++) {
            var ts = new Date(offenders[i].ts * 1000);
            html += "<tr><td>" + esc(offenders[i].id) + "</td>"
                  + "<td>" + esc(ts.toLocaleString(undefined, { hour12: false, month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" })) + "</td></tr>";
        }
        tbody.innerHTML = html;
    }).catch(function() {});
};

/* -- Active Frequencies Panel ----------------------------------- */

BridgeDashboard.prototype._freqBand = function(mhz) {
    if (mhz >= 87.5 && mhz <= 108) return "FM Broadcast";
    if (mhz >= 118 && mhz <= 137) return "Airband";
    if (mhz >= 144 && mhz <= 148) return "2m Amateur";
    // NOAA Weather sits inside the VHF range, so it is tested first.
    if (mhz >= 162.4 && mhz <= 162.6) return "NOAA Weather";
    if (mhz >= 150 && mhz <= 174) return "VHF";
    if (mhz >= 225 && mhz <= 400) return "UHF Mil";
    if (mhz >= 420 && mhz <= 450) return "70cm / ISM 433";
    if (mhz >= 460 && mhz <= 470) return "FRS/GMRS";
    if (mhz >= 470 && mhz <= 698) return "UHF TV";
    if (mhz >= 698 && mhz <= 960 && mhz < 862) return "LTE";
    if (mhz >= 862 && mhz <= 870) return "ISM 868";
    if (mhz >= 902 && mhz <= 928) return "ISM 915";
    if (mhz >= 1164 && mhz <= 1189) return "GPS L5";
    if (mhz >= 1217 && mhz <= 1237) return "GPS L2";
    if (mhz >= 1559 && mhz <= 1591) return "GPS L1";
    if (mhz >= 1710 && mhz <= 2170) return "LTE/AWS";
    if (mhz >= 2400 && mhz <= 2500) return "ISM 2.4G / WiFi";
    if (mhz >= 5150 && mhz <= 5850) return "WiFi 5G";
    if (mhz >= 5925 && mhz <= 7125) return "WiFi 6E";
    return "Other";
};

BridgeDashboard.prototype._renderActiveFreqs = function(freqList) {
    var tb = document.getElementById("active-freqs-tbody");
    var badge = document.getElementById("active-freqs-badge");
    if (!tb) return;
    if (badge) badge.textContent = freqList.length;
    if (!freqList.length) {
        tb.innerHTML = '<tr><td colspan="6" class="empty-state">No active frequencies</td></tr>';
        return;
    }
    var html = "";
    for (var i = 0; i < freqList.length; i++) {
        var f = freqList[i];
        var band = this._freqBand(f.freq_mhz);
        var classes = (f.classes || "").split(",").filter(function(c) { return c; });
        var classTags = "";
        for (var j = 0; j < classes.length; j++) {
            classTags += '<span class="class-tag">' + esc(classes[j]) + '</span> ';
        }
        var nodes = (f.nodes || "").split(",").filter(function(n) { return n; });
        var nodeTags = "";
        for (var k = 0; k < nodes.length; k++) {
            nodeTags += '<span class="class-tag">' + esc(nodes[k]) + '</span> ';
        }
        var power = f.avg_power_dbm != null ? f.avg_power_dbm.toFixed(1) + " dBm" : "--";
        var freqHz = f.freq_mhz * 1e6;
        // Make class tags drill-down links
        var classTagsDrilldown = "";
        for (var j2 = 0; j2 < classes.length; j2++) {
            classTagsDrilldown += '<span class="class-tag drilldown-link" data-drilldown-summary-class="' + esc(classes[j2]) + '" title="View in RF Intelligence">' + esc(classes[j2]) + '</span> ';
        }
        // PR-17 (cog review §7.1): Signal Classes column moved from
        // position 6 to position 3 — co-locates the "what is this
        // signal?" with the frequency/band identity. Remaining
        // columns shift right; colspan stays at 6.
        html += "<tr>";
        html += "<td><strong><span class=\"drilldown-link\" data-drilldown-summary-freq=\"" + freqHz + "\" title=\"View in Spectrum Analysis\">" + esc(String(f.freq_mhz)) + "</span></strong></td>";
        html += "<td>" + esc(band) + "</td>";
        html += "<td>" + (classTagsDrilldown || "--") + "</td>";
        html += "<td>" + esc(f.count) + "</td>";
        html += "<td>" + esc(power) + "</td>";
        html += "<td>" + (nodeTags || "--") + "</td>";
        html += "</tr>";
    }
    tb.innerHTML = html;

    // Drill-down: frequency -> Spectrum Analysis
    tb.querySelectorAll("[data-drilldown-summary-freq]").forEach(function(link) {
        link.addEventListener("click", function(e) {
            e.stopPropagation();
            var hz = parseFloat(this.getAttribute("data-drilldown-summary-freq"));
            if (hz && window.drillDown) window.drillDown.toSpectrum(hz);
        });
    });

    // Drill-down: signal class -> RF Intelligence
    tb.querySelectorAll("[data-drilldown-summary-class]").forEach(function(link) {
        link.addEventListener("click", function(e) {
            e.stopPropagation();
            var cls = this.getAttribute("data-drilldown-summary-class");
            if (cls && window.drillDown) window.drillDown.toSignalClass(cls);
        });
    });
};

/* -- Unique Frequencies Panel ----------------------------------- */

BridgeDashboard.prototype._renderUniqueFreqs = function(freqList) {
    var grid = document.getElementById("unique-freqs-grid");
    var badge = document.getElementById("unique-freqs-badge");
    var empty = document.getElementById("unique-freqs-empty");
    if (!grid) return;

    if (!freqList || !freqList.length) {
        grid.innerHTML = "";
        if (badge) badge.textContent = "0 bands";
        if (empty) empty.style.display = "";
        return;
    }
    if (empty) empty.style.display = "none";

    // Group by band
    var bands = {};
    var bandOrder = [];
    for (var i = 0; i < freqList.length; i++) {
        var f = freqList[i];
        var band = this._freqBand(f.freq_mhz);
        if (!bands[band]) {
            bands[band] = { count: 0, detections: 0, freqs: [], power: [] };
            bandOrder.push(band);
        }
        bands[band].count++;
        bands[band].detections += f.count || 0;
        bands[band].freqs.push(f.freq_mhz);
        if (f.avg_power_dbm != null) bands[band].power.push(f.avg_power_dbm);
    }

    // Sort by detection count descending
    bandOrder.sort(function(a, b) { return bands[b].detections - bands[a].detections; });

    if (badge) badge.textContent = bandOrder.length + " band" + (bandOrder.length !== 1 ? "s" : "");

    var html = "";
    for (var j = 0; j < bandOrder.length; j++) {
        var name = bandOrder[j];
        var b = bands[name];
        var avgPwr = "--";
        if (b.power.length) {
            var sum = 0;
            for (var k = 0; k < b.power.length; k++) sum += b.power[k];
            avgPwr = (sum / b.power.length).toFixed(1) + " dBm";
        }
        var freqStr = b.freqs.slice(0, 5).join(", ") + (b.freqs.length > 5 ? " +" + (b.freqs.length - 5) + " more" : "");
        html += '<div class="freq-band-card">';
        html += '<div class="freq-band-name">' + esc(name) + '</div>';
        html += '<div class="freq-band-value">' + esc(b.count) + ' <span style="font-size:12px;font-weight:400;color:var(--text-secondary)">freq' + (b.count !== 1 ? 's' : '') + '</span></div>';
        html += '<div class="freq-band-stats"><span>' + esc(b.detections) + ' det</span><span>' + esc(avgPwr) + '</span></div>';
        html += '<div class="freq-band-freqs" title="' + esc(b.freqs.join(", ")) + '">' + esc(freqStr) + ' MHz</div>';
        html += '</div>';
    }
    grid.innerHTML = html;
};

/* -- Suspicious Frequencies Panel ------------------------------- */

BridgeDashboard.prototype._renderSuspiciousFreqs = function(freqList) {
    var list = document.getElementById("suspicious-freqs-list");
    var badge = document.getElementById("suspicious-freqs-badge");
    var empty = document.getElementById("suspicious-freqs-empty");
    if (!list) return;

    if (!freqList || !freqList.length) {
        list.innerHTML = "";
        if (badge) badge.textContent = "0";
        if (empty) empty.style.display = "";
        return;
    }

    // Compute stats for heuristics
    var powers = [], counts = [];
    for (var i = 0; i < freqList.length; i++) {
        if (freqList[i].avg_power_dbm != null) powers.push(freqList[i].avg_power_dbm);
        counts.push(freqList[i].count || 0);
    }
    var avgPower = 0, stdPower = 0, avgCount = 0;
    if (powers.length) {
        for (var p = 0; p < powers.length; p++) avgPower += powers[p];
        avgPower /= powers.length;
        for (var q = 0; q < powers.length; q++) stdPower += (powers[q] - avgPower) * (powers[q] - avgPower);
        stdPower = Math.sqrt(stdPower / powers.length);
    }
    if (counts.length) {
        for (var c = 0; c < counts.length; c++) avgCount += counts[c];
        avgCount /= counts.length;
    }

    var suspicious = [];
    for (var j = 0; j < freqList.length; j++) {
        var f = freqList[j];
        var reasons = [];
        var severity = "low";
        var nodes = (f.nodes || "").split(",").filter(function(n) { return n; });
        var band = this._freqBand(f.freq_mhz);

        // High power outlier (>1.5 std above mean)
        if (f.avg_power_dbm != null && stdPower > 0 && f.avg_power_dbm > avgPower + 1.5 * stdPower) {
            reasons.push("Power outlier: " + f.avg_power_dbm.toFixed(1) + " dBm (avg " + avgPower.toFixed(1) + ")");
            severity = "high";
        }

        // Transient/rare signal (very low count relative to average)
        if (f.count <= 3 && avgCount > 10) {
            reasons.push("Transient signal: only " + f.count + " detection" + (f.count !== 1 ? "s" : ""));
            if (severity !== "high") severity = "med";
        }

        // Single-node sighting (not corroborated)
        if (nodes.length === 1 && freqList.length > 3) {
            reasons.push("Single-node sighting (" + nodes[0] + ")");
        }

        // Unexpected band
        if (band === "Other") {
            reasons.push("Unregistered band (" + f.freq_mhz + " MHz)");
            if (severity !== "high") severity = "med";
        }

        // Military band activity
        if (band === "UHF Mil") {
            reasons.push("Military band activity");
            if (severity !== "high") severity = "med";
        }

        if (reasons.length) {
            suspicious.push({ freq: f, reasons: reasons, severity: severity, band: band, nodes: nodes });
        }
    }

    // Sort: high severity first, then med, then low
    var sevOrder = { high: 0, med: 1, low: 2 };
    var rank = function(item) { return sevOrder.hasOwnProperty(item.severity) ? sevOrder[item.severity] : 2; };
    suspicious.sort(function(a, b) { return rank(a) - rank(b); });

    if (badge) badge.textContent = suspicious.length;
    if (empty) empty.style.display = suspicious.length ? "none" : "";

    if (!suspicious.length) {
        list.innerHTML = "";
        return;
    }

    var html = "";
    var icons = { high: "&#9888;", med: "&#9670;", low: "&#9679;" };
    for (var k = 0; k < suspicious.length; k++) {
        var s = suspicious[k];
        var sevClass = s.severity === "high" ? "severity-high" : s.severity === "low" ? "severity-low" : "";
        html += '<div class="suspicious-freq-item ' + sevClass + '">';
        html += '<div class="suspicious-freq-icon">' + (icons[s.severity] || "&#9679;") + '</div>';
        html += '<div class="suspicious-freq-body">';
        html += '<div class="suspicious-freq-header">';
        html += '<span class="suspicious-freq-title">' + esc(String(s.freq.freq_mhz)) + ' MHz — ' + esc(s.band) + '</span>';
        html += '</div>';
        for (var r = 0; r < s.reasons.length; r++) {
            html += '<div class="suspicious-freq-reason">' + esc(s.reasons[r]) + '</div>';
        }
        var power = s.freq.avg_power_dbm != null ? s.freq.avg_power_dbm.toFixed(1) + " dBm" : "--";
        html += '<div class="suspicious-freq-meta">';
        html += '<span>' + esc(s.freq.count) + ' det</span>';
        html += '<span>' + esc(power) + '</span>';
        html += '<span>' + s.nodes.length + ' node' + (s.nodes.length !== 1 ? 's' : '') + '</span>';
        html += '</div>';
        html += '</div></div>';
    }
    list.innerHTML = html;
};

/* -- Node Panel ------------------------------------------------- */

BridgeDashboard.prototype._pollNodes = function() {
    var s = this;
    var observedAt = performance.now();
    var tb = document.getElementById("nodes-tbody");
    if (tb && !tb.innerHTML) {
        tb.innerHTML = '<tr><td colspan="19"><div class="loading-container"><div class="loading-spinner"></div>Loading nodes...</div></td></tr>';
    }
    s.apiFetch("/api/nodes/").then(function(n) { clearFetchError("nodes"); s.scannerAvailability.update(n, observedAt); }).catch(function(e) { trackFetchError("nodes", e); });
};

BridgeDashboard.prototype._renderNodes = function(nodes) {
    var tb = document.getElementById("nodes-tbody");
    var em = document.getElementById("nodes-empty");
    if (!tb) return;
    setText("node-count-badge", nodes.length);
    if (!nodes.length) { tb.innerHTML = ""; if (em) em.style.display = ""; return; }
    if (em) em.style.display = "none";

    var self = this;
    var h = "";
    for (var i = 0; i < nodes.length; i++) {
        var n = nodes[i], st = esc(n.status || "unknown");
        var cap = n.capabilities || {};
        var hw = _NODE_HW[n.node_id] || {};
        var radio = cap.hardware || cap.device_type || hw.hardware || "Not reported";
        var runningProtocols = self.scannerAvailability.protocolsFor(n.node_id);
        var scanning = runningProtocols.map(function(protocol) { return ScannerAvailability.LABELS[protocol]; });
        var captureMode = cap.capture_mode || "";
        var capModeBadge = captureMode === "dual" ? " <span class=\"capture-badge dual\">DUAL</span>"
            : captureMode === "hackrf" ? " <span class=\"capture-badge hackrf\">HackRF</span>"
            : "";
        var aiHwRaw = cap.gpu || cap.accelerator || hw.accelerator || null;
        var aiHw = aiHwRaw || "<span class=\"no-ai-hw\">\u2716</span>";
        var agentVer = cap.agent_version || "";
        var monCls = agentVer ? (st === "active" ? "mon-active" : st === "stale" ? "mon-stale" : "mon-offline") : "mon-none";
        var monTxt = agentVer ? "v" + esc(agentVer) : "--";
        var cpuTempVal = finiteNumber(cap.cpu_temp);
        var cpuTemp = fixedOr(cpuTempVal, 0, "\u00b0C");

        // Detection rate (from detection_summary)
        var detSum = n.detection_summary || {};
        var detTotal = finiteNumber(detSum.total_detections) || 0;
        var detPeriod = finiteNumber(detSum.period_seconds) || 0;
        var detRateMin = detPeriod > 0 ? (detTotal / detPeriod * 60) : 0;
        var clsRate = finiteNumber(n.classifications_per_sec);
        var detRateStr = detPeriod > 0 ? detRateMin.toFixed(1) : (clsRate != null ? (clsRate * 60).toFixed(1) : "--");

        // Top signal classes mini-bar
        var classCounts = detSum.class_counts || {};
        var classKeys = Object.keys(classCounts);
        var topClassHtml = "";
        if (classKeys.length > 0) {
            // Sort by count descending, take top 3
            classKeys.sort(function(a, b) { return classCounts[b] - classCounts[a]; });
            var topN = Math.min(classKeys.length, 3);
            var maxCnt = classCounts[classKeys[0]] || 1;
            for (var ci = 0; ci < topN; ci++) {
                var cls = classKeys[ci];
                var cnt = classCounts[cls];
                var pct = Math.round((cnt / maxCnt) * 100);
                topClassHtml += "<div class=\"node-class-bar\" title=\"" + esc(cls) + ": " + esc(cnt) + "\">"
                    + "<div class=\"node-class-bar-fill\" style=\"width:" + pct + "%\"></div>"
                    + "<span class=\"node-class-bar-label\">" + esc(cls.length > 12 ? cls.substring(0, 10) + ".." : cls)
                    + " <em>" + esc(cnt) + "</em></span></div>";
            }
            if (classKeys.length > 3) {
                topClassHtml += "<span class=\"node-class-more\">+" + (classKeys.length - 3) + " more</span>";
            }
        } else {
            topClassHtml = "<span style=\"color:var(--text-secondary);font-size:11px;\">--</span>";
        }

        // Uptime
        var uptimeSec = finiteNumber(cap.uptime_seconds);
        var uptimeStr = uptimeSec != null ? fmtUptime(uptimeSec) : "--";

        // Latency
        var latencyMs = finiteNumber(cap.heartbeat_latency_ms);
        var latencyStr = fixedOr(latencyMs, 0, "ms");
        var latencyCls = "";
        if (latencyMs != null) {
            latencyCls = latencyMs > 500 ? " node-latency-high" : latencyMs > 200 ? " node-latency-med" : "";
        }

        // WiFi monitoring badge
        var wifiBadge = (self.wifiNodeIds && self.wifiNodeIds.indexOf(n.node_id) !== -1)
            ? " <span class=\"capture-badge wifi\">WiFi</span>" : "";

        // Health indicator (green/yellow/red)
        var healthColor = "green";
        var healthTitle = "Online";
        var cpuPct = finiteNumber(n.cpu_percent);
        if (st !== "active") {
            healthColor = st === "offline" ? "red" : "yellow";
            healthTitle = st === "offline" ? "Offline" : "Stale";
        } else {
            if ((cpuPct != null && cpuPct > 90) || (cpuTempVal != null && cpuTempVal > 80)) {
                healthColor = "red";
                healthTitle = "Critical";
            } else if ((cpuPct != null && cpuPct > 75) || (cpuTempVal != null && cpuTempVal > 70) || (latencyMs != null && latencyMs > 500)) {
                healthColor = "yellow";
                healthTitle = "Degraded";
            }
        }
        var healthHtml = "<span class=\"node-health node-health-" + healthColor + "\" title=\"" + esc(healthTitle) + "\"><span class=\"health-dot\"></span> " + esc(healthTitle) + "</span>";

        // Last error (from capabilities if node reports it)
        var errorSuffix = {sensor_absent: " sensor not connected", sensor_changed: " sensor changed",
            sensor_unusable: " sensor cannot be opened"};
        var scannerErrors = [], scannerStarting = [];
        Object.keys(ScannerAvailability.LABELS).forEach(function(protocol) {
            var report = n.scanner_status && n.scanner_status[protocol];
            if (!report || report.state !== "error") return;
            var reason = ScannerAvailability.reason(report), label = ScannerAvailability.LABELS[protocol];
            // Starting capture is not an issue; it is listed with the scanners.
            if (reason === "starting") scannerStarting.push(label + " starting capture");
            else scannerErrors.push(label + (errorSuffix[reason] || " scanner error"));
        });
        var lastError = cap.last_error ? String(cap.last_error) : scannerErrors.join(", ");
        var lastErrorHtml = lastError
            ? "<span class=\"node-last-error\" title=\"" + esc(lastError) + "\">" + esc(lastError.length > 30 ? lastError.substring(0, 28) + ".." : lastError) + "</span>"
            : "<span style=\"color:var(--text-secondary);font-size:11px;\">--</span>";

        // R5: "Top Issue" — single prioritized column combining error, anomaly, resource alerts
        var topIssueHtml;
        if (lastError) {
            topIssueHtml = "<div class=\"node-top-issue issue-error\"><span class=\"issue-icon\">\u2716</span>" + esc(lastError.length > 35 ? lastError.substring(0, 33) + ".." : lastError) + "</div>";
        } else if (healthColor === "red") {
            var reason = (cpuPct != null && cpuPct > 90) ? "CPU " + cpuPct.toFixed(0) + "%" : (cpuTempVal != null && cpuTempVal > 80) ? "Temp " + cpuTempVal.toFixed(0) + "\u00b0C" : st;
            topIssueHtml = "<div class=\"node-top-issue issue-error\"><span class=\"issue-icon\">\u26a0</span>" + esc(reason) + "</div>";
        } else if (healthColor === "yellow") {
            var reason2 = (cpuPct != null && cpuPct > 75) ? "CPU " + cpuPct.toFixed(0) + "%" : (cpuTempVal != null && cpuTempVal > 70) ? "Temp " + cpuTempVal.toFixed(0) + "\u00b0C" : (latencyMs != null && latencyMs > 500) ? "Latency " + latencyMs.toFixed(0) + "ms" : st;
            topIssueHtml = "<div class=\"node-top-issue issue-warning\"><span class=\"issue-icon\">\u26a0</span>" + esc(reason2) + "</div>";
        } else {
            topIssueHtml = "<div class=\"node-top-issue issue-ok\">No issues reported</div>";
        }

        // R5: Compact "Status" column (radio + capabilities as tooltip)
        var scannerText = (scanning.length ? [scanning.join(", ") + " scanning"] : []).concat(scannerStarting).join(", ")
            || "No active scanner reported";
        var statusCompact = "<div class=\"node-status-compact\" title=\"Hardware: " + esc(radio) + "\"><span class=\"status-radio\">" + esc(scannerText) + "</span></div>";

        // PR-17 (cog review §7.2): Actions cell relocated to column
        // 2 (between Health and Node ID) — keeps Ping/Capture-IQ
        // controls in the operator's primary scan path. Remaining
        // column order is unchanged so the existing column count
        // and any positional callers (search, expand toggle) stay
        // valid.
        h += "<tr>"
            + "<td>" + healthHtml + "</td>"
            + "<td><button class=\"btn btn-sm btn-secondary\" data-cmd-node=\"" + esc(n.node_id) + "\">Ping</button>"
            + " <button class=\"btn btn-sm\" data-capture-node=\"" + esc(n.node_id) + "\" title=\"Trigger manual IQ capture\">Capture IQ</button></td>"
            + "<td>" + esc(n.node_id) + "</td>"
            + "<td class=\"node-col-compact\">" + statusCompact + "</td>"
            + "<td>" + esc(detRateStr) + "</td>"
            + "<td>" + topIssueHtml + "</td>"
            + "<td>" + fmtTime(n.last_seen) + "</td>"
            + "<td class=\"node-col-detail\"><span class=\"monitor-badge " + monCls + "\"><span class=\"dot\"></span> " + monTxt + "</span></td>"
            + "<td class=\"node-col-detail\">" + esc(hw.platform || "--") + "</td>"
            + "<td class=\"node-col-detail\"><span style=\"font-family:var(--font-mono);font-size:11px;\">" + esc(hw.cpu || "--") + "</span></td>"
            + "<td class=\"node-col-detail\">" + esc(n.host) + "</td>"
            + "<td class=\"node-col-detail\">" + esc(radio) + capModeBadge + wifiBadge + "</td>"
            + "<td class=\"node-col-detail\">" + (aiHwRaw ? esc(aiHwRaw) : aiHw) + "</td>"
            + "<td class=\"node-col-detail\"><div class=\"node-class-bars\">" + topClassHtml + "</div></td>"
            + "<td class=\"node-col-detail\">" + esc(uptimeStr) + "</td>"
            + "<td class=\"node-col-detail\">" + esc(fixedOr(cpuPct, 1)) + "</td>"
            + "<td class=\"node-col-detail\">" + esc(fixedOr(n.memory_mb, 0)) + "</td>"
            + "<td class=\"node-col-detail\">" + esc(cpuTemp) + "</td>"
            + "<td class=\"node-col-detail" + latencyCls + "\">" + esc(latencyStr) + "</td></tr>";
    }
    tb.innerHTML = h;
    tb.querySelectorAll("[data-cmd-node]").forEach(function(b) {
        b.addEventListener("click", function() {
            self.apiFetch("/api/nodes/" + encodeURIComponent(this.getAttribute("data-cmd-node")) + "/command",
                { method: "POST", body: { command: "ping", params: {} } }).catch(function() {});
        });
    });
    tb.querySelectorAll("[data-capture-node]").forEach(function(b) {
        b.addEventListener("click", function(e) {
            e.stopPropagation();
            self._openIQCaptureDialog(this.getAttribute("data-capture-node"));
        });
    });
    // Apply search filter if active
    this._filterNodes();
    // Update floor plan
    this._drawFloorPlan(nodes);
};

BridgeDashboard.prototype._initNodeSearch = function() {
    var s = this;
    var searchInput = document.getElementById("node-search");
    if (searchInput) {
        searchInput.addEventListener("input", function() {
            s._filterNodes();
        });
    }
};

BridgeDashboard.prototype._filterNodes = function() {
    var searchInput = document.getElementById("node-search");
    var tb = document.getElementById("nodes-tbody");
    var noMatchMsg = document.getElementById("nodes-no-match");

    if (!searchInput || !tb) return;

    var searchText = searchInput.value.toLowerCase().trim();
    var rows = tb.querySelectorAll("tr");
    var visibleCount = 0;

    rows.forEach(function(row) {
        if (!searchText) {
            row.style.display = "";
            visibleCount++;
            return;
        }

        // Get text content from the row, searching across all visible columns
        var rowText = row.textContent.toLowerCase();

        if (rowText.indexOf(searchText) !== -1) {
            row.style.display = "";
            visibleCount++;
        } else {
            row.style.display = "none";
        }
    });

    // Show/hide "no match" message
    if (noMatchMsg) {
        noMatchMsg.style.display = (visibleCount === 0 && rows.length > 0) ? "" : "none";
    }
};

BridgeDashboard.prototype._onStatusWS = function(d) {
    if (d.type === "snapshot" && Array.isArray(d.nodes)) this.scannerAvailability.update(d.nodes, performance.now());
    // R6: Mark data fresh on WS updates
    this._markDataFresh();
};

/* -- Floor Plan ------------------------------------------------- */

BridgeDashboard.prototype._drawFloorPlan = function(nodes) {
    var canvas = document.getElementById("floorplan-canvas");
    if (!canvas) return;
    var ctx = canvas.getContext("2d");
    var W = canvas.width, H = canvas.height;
    var PAD = 30;

    ctx.clearRect(0, 0, W, H);

    // Draw grid
    var theme = document.documentElement.getAttribute("data-theme") || "dark";
    var themeColors = {
        dark:  { grid: "rgba(255,255,255,0.06)", text: "rgba(255,255,255,0.3)", border: "rgba(255,255,255,0.15)", nodeBorder: "rgba(255,255,255,0.4)", label: "#c9d1d9" },
        light: { grid: "rgba(0,0,0,0.06)",       text: "rgba(0,0,0,0.3)",       border: "rgba(0,0,0,0.15)",       nodeBorder: "rgba(0,0,0,0.3)",       label: "#24292f" },
        command: { grid: "rgba(255,153,0,0.08)",    text: "rgba(255,153,0,0.4)",   border: "rgba(204,102,51,0.5)",   nodeBorder: "rgba(255,153,0,0.6)",   label: "#ff9900" },
        tactical:{ grid: "rgba(91,127,170,0.1)",    text: "rgba(138,154,181,0.5)", border: "rgba(61,74,110,0.6)",    nodeBorder: "rgba(138,154,181,0.5)", label: "#e8dcc8" },
        bladerunner:{ grid: "rgba(212,160,80,0.06)", text: "rgba(138,112,88,0.5)",  border: "rgba(58,48,32,0.6)",     nodeBorder: "rgba(212,160,80,0.5)",  label: "#d4a050" },
        br2049:  { grid: "rgba(40,176,184,0.08)",   text: "rgba(96,120,112,0.5)",  border: "rgba(40,56,48,0.6)",     nodeBorder: "rgba(224,160,80,0.5)",  label: "#e0a050" },
        cyberpunk:{ grid: "rgba(192,64,255,0.08)",  text: "rgba(128,128,176,0.5)", border: "rgba(48,32,96,0.5)",     nodeBorder: "rgba(0,168,255,0.5)",   label: "#e0e8ff" },
        sentinel:{ grid: "rgba(200,192,176,0.06)", text: "rgba(138,128,112,0.5)", border: "rgba(58,54,48,0.6)",     nodeBorder: "rgba(200,192,176,0.4)", label: "#c8c0b0" },
        gateway:{ grid: "rgba(60,168,232,0.08)",   text: "rgba(110,126,148,0.5)", border: "rgba(56,68,88,0.6)",     nodeBorder: "rgba(60,168,232,0.5)",  label: "#c8d0dc" },
        explorer:{ grid: "rgba(68,136,204,0.08)",   text: "rgba(104,130,168,0.5)", border: "rgba(42,58,90,0.6)",     nodeBorder: "rgba(68,136,204,0.5)",  label: "#b8cce0" },
        matrix:  { grid: "rgba(0,255,65,0.06)",    text: "rgba(0,255,65,0.3)",    border: "rgba(0,51,0,0.8)",       nodeBorder: "rgba(0,255,65,0.5)",   label: "#00ff41" }
    };
    var tc = themeColors[theme] || themeColors.dark;
    var gridColor = tc.grid;
    var textColor = tc.text;
    ctx.strokeStyle = gridColor;
    ctx.lineWidth = 1;
    for (var gx = 0; gx <= 10; gx++) {
        var x = PAD + (gx / 10) * (W - 2 * PAD);
        ctx.beginPath(); ctx.moveTo(x, PAD); ctx.lineTo(x, H - PAD); ctx.stroke();
    }
    for (var gy = 0; gy <= 10; gy++) {
        var y = PAD + (gy / 10) * (H - 2 * PAD);
        ctx.beginPath(); ctx.moveTo(PAD, y); ctx.lineTo(W - PAD, y); ctx.stroke();
    }

    // Border
    ctx.strokeStyle = tc.border;
    ctx.lineWidth = 2;
    ctx.strokeRect(PAD, PAD, W - 2 * PAD, H - 2 * PAD);

    // Scale labels
    ctx.fillStyle = textColor;
    ctx.font = "10px monospace";
    ctx.textAlign = "center";
    for (var lx = 0; lx <= 10; lx += 2) {
        ctx.fillText(lx * 10, PAD + (lx / 10) * (W - 2 * PAD), H - PAD + 14);
    }
    ctx.textAlign = "right";
    for (var ly = 0; ly <= 10; ly += 2) {
        ctx.fillText(ly * 10, PAD - 6, PAD + (ly / 10) * (H - 2 * PAD) + 3);
    }

    // Draw nodes
    var placed = 0;
    this._floorplanNodes = [];
    for (var i = 0; i < nodes.length; i++) {
        var n = nodes[i];
        if (n.position_x == null || n.position_y == null) continue;
        placed++;
        var px = PAD + (n.position_x / 100) * (W - 2 * PAD);
        var py = PAD + (n.position_y / 100) * (H - 2 * PAD);
        var isOnline = n.status === "active";
        var dotColor = isOnline ? "#3fb950" : "#8b949e";
        var radius = 8;

        // Glow for active nodes
        if (isOnline) {
            ctx.save();
            ctx.shadowColor = "#3fb950";
            ctx.shadowBlur = 10;
            ctx.beginPath();
            ctx.arc(px, py, radius, 0, Math.PI * 2);
            ctx.fillStyle = dotColor;
            ctx.fill();
            ctx.restore();
        } else {
            ctx.beginPath();
            ctx.arc(px, py, radius, 0, Math.PI * 2);
            ctx.fillStyle = dotColor;
            ctx.fill();
        }

        // Border
        ctx.beginPath();
        ctx.arc(px, py, radius, 0, Math.PI * 2);
        ctx.strokeStyle = tc.nodeBorder;
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // Label
        ctx.fillStyle = tc.label;
        ctx.font = "10px sans-serif";
        ctx.textAlign = "center";
        var label = n.node_id.length > 14 ? n.node_id.substring(0, 12) + ".." : n.node_id;
        ctx.fillText(label, px, py - radius - 4);

        this._floorplanNodes.push({ x: px, y: py, radius: radius, node: n });
    }

    // "No nodes placed" message
    if (placed === 0) {
        ctx.fillStyle = textColor;
        ctx.font = "14px sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("No nodes placed yet. Set positions in Admin > Nodes.", W / 2, H / 2);
    }

    setText("floorplan-badge", placed + " placed");
};

BridgeDashboard.prototype._initFloorPlan = function() {
    var self = this;
    var canvas = document.getElementById("floorplan-canvas");
    if (!canvas) return;

    canvas.addEventListener("click", function(e) {
        var rect = canvas.getBoundingClientRect();
        var scaleX = canvas.width / rect.width;
        var mx = (e.clientX - rect.left) * scaleX;
        var my = (e.clientY - rect.top) * (canvas.height / rect.height);

        if (!self._floorplanNodes) return;
        for (var i = 0; i < self._floorplanNodes.length; i++) {
            var fn = self._floorplanNodes[i];
            var dx = mx - fn.x, dy = my - fn.y;
            if (dx * dx + dy * dy <= (fn.radius + 4) * (fn.radius + 4)) {
                // Open node comparison modal focused on this node
                if (self.nodeComparison && typeof self.nodeComparison.openForNode === "function") {
                    self.nodeComparison.openForNode(fn.node.node_id);
                }
                return;
            }
        }
    });

    canvas.addEventListener("mousemove", function(e) {
        var rect = canvas.getBoundingClientRect();
        var scaleX = canvas.width / rect.width;
        var mx = (e.clientX - rect.left) * scaleX;
        var my = (e.clientY - rect.top) * (canvas.height / rect.height);
        var tooltip = document.getElementById("floorplan-tooltip");
        if (!tooltip || !self._floorplanNodes) return;

        var hit = null;
        for (var i = 0; i < self._floorplanNodes.length; i++) {
            var fn = self._floorplanNodes[i];
            var dx = mx - fn.x, dy = my - fn.y;
            if (dx * dx + dy * dy <= (fn.radius + 4) * (fn.radius + 4)) { hit = fn; break; }
        }

        if (hit) {
            canvas.style.cursor = "pointer";
            var n = hit.node;
            tooltip.innerHTML = "<strong>" + esc(n.node_id) + "</strong><br>"
                + "Status: " + esc(n.status) + "<br>"
                + "Host: " + esc(n.host) + "<br>"
                + (n.floor_label ? "Floor: " + esc(n.floor_label) + "<br>" : "")
                + "Position: (" + n.position_x.toFixed(0) + ", " + n.position_y.toFixed(0) + ")";
            tooltip.style.display = "";
            tooltip.style.left = (e.clientX + 12) + "px";
            tooltip.style.top = (e.clientY - 10) + "px";
        } else {
            canvas.style.cursor = "default";
            tooltip.style.display = "none";
        }
    });

    canvas.addEventListener("mouseleave", function() {
        var tooltip = document.getElementById("floorplan-tooltip");
        if (tooltip) tooltip.style.display = "none";
        canvas.style.cursor = "default";
    });
};

/* -- Alert Panel ------------------------------------------------ */

BridgeDashboard.prototype._initAlerts = function() {
    var s = this;
    s._loadAlerts();
    var fs = document.getElementById("alert-severity-filter");
    var fa = document.getElementById("alert-hide-acked");
    if (fs) fs.addEventListener("change", function() { s._loadAlerts(); });
    if (fa) fa.addEventListener("change", function() { s._loadAlerts(); });
    var cb = document.getElementById("create-rule-btn");
    if (cb) cb.addEventListener("click", function() { s._createRule(); });
    s._initConditionBuilder();
};

BridgeDashboard.prototype._loadAlerts = function() {
    var s = this, p = [];
    var sv = document.getElementById("alert-severity-filter");
    if (sv && sv.value) p.push("severity=" + sv.value);
    var c = document.getElementById("alerts-list");
    if (c && !c.innerHTML) {
        c.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div>Loading alerts...</div>';
    }
    s.apiFetch("/api/alerts/" + (p.length ? "?" + p.join("&") : ""))
        .then(function(a) { clearFetchError("alerts"); s._renderAlerts(a); })
        .catch(function(e) { trackFetchError("alerts", e); });
};

BridgeDashboard.prototype._renderAlerts = function(alerts) {
    var c = document.getElementById("alerts-list");
    var em = document.getElementById("alerts-empty");
    if (!c) return;
    var ha = document.getElementById("alert-hide-acked"), f = alerts;
    if (ha && ha.checked) f = alerts.filter(function(a) { return !a.acknowledged; });
    setText("alert-count-badge", f.length);
    if (!f.length) { c.innerHTML = ""; if (em) em.style.display = ""; return; }
    if (em) em.style.display = "none";

    var self = this;
    var h = "";
    for (var i = 0; i < f.length; i++) {
        var a = f[i], sv = esc(a.severity || "warning"), ak = a.acknowledged ? " acknowledged" : "";
        var escState = a.escalated ? " escalated" : "";
        // PR-14: dual-code severity via window.severityIcon() shape glyph
        // (defined in severity.js, loaded before dashboard.js). Falls back
        // to text-only if the helper is missing.
        var sevIcon = (typeof window.severityIcon === "function") ? window.severityIcon(sv) : "";
        h += "<div class=\"alert-item " + sv + ak + escState + "\">"
            + "<span class=\"severity-badge " + sv + "\">" + sevIcon + sv + "</span>"
            + "<span class=\"alert-msg\">" + esc(decodeHtmlEscapedText(a.message)) + "</span>"
            + "<span class=\"alert-time\">" + fmtTime(a.triggered_at) + "</span>";
        if (a.acknowledged) {
            // R13: Show ack details
            var ackInfo = "<div class=\"alert-ack-info\">";
            if (a.acknowledged_by) ackInfo += "<span class=\"ack-user\">" + esc(a.acknowledged_by) + "</span> ";
            if (a.acknowledged_at) {
                var tta = self._calcTTA(a.triggered_at, a.acknowledged_at);
                ackInfo += "<span class=\"ack-time\">acked " + fmtTime(a.acknowledged_at) + "</span>";
                if (tta) ackInfo += " <span class=\"ack-tta\">(TTA: " + esc(tta) + ")</span>";
            }
            if (a.ack_note) ackInfo += " <span class=\"ack-note\">\"" + esc(decodeHtmlEscapedText(a.ack_note)) + "\"</span>";
            ackInfo += "</div>";
            h += ackInfo;
        } else {
            // R13: Ack with note + escalate
            h += "<div class=\"alert-ack-form\">"
                + "<input class=\"alert-ack-note\" data-ack-note-for=\"" + esc(a.alert_id) + "\" placeholder=\"Note (optional)\" maxlength=\"200\">"
                + "<button class=\"btn btn-sm\" data-ack-alert=\"" + esc(a.alert_id) + "\">Ack</button>"
                + "<button class=\"btn btn-sm btn-escalate\" data-escalate-alert=\"" + esc(a.alert_id) + "\" title=\"Escalate this alert\">Escalate</button>"
                + "</div>";
        }
        if (a.rf_detection_id) h += '<button class="btn btn-sm" data-known-detection="' + esc(a.rf_detection_id) + '">Mark as known…</button>';
        h += "</div>";
    }
    c.innerHTML = h;
    if (window.KnownSignals) window.KnownSignals.bind(c, self);
    c.querySelectorAll("[data-ack-alert]").forEach(function(b) {
        b.addEventListener("click", function() {
            var aid = this.getAttribute("data-ack-alert");
            // Matched as text: an alert ID is never built into a selector.
            var noteInput = null;
            c.querySelectorAll("[data-ack-note-for]").forEach(function(input) {
                if (input.getAttribute("data-ack-note-for") === aid) noteInput = input;
            });
            var note = noteInput ? noteInput.value.trim() : "";
            // R13: Send note with ack
            self.apiFetch("/api/alerts/" + encodeURIComponent(aid) + "/ack", {
                method: "PUT",
                body: note ? { note: note } : undefined
            }).then(function() { showToast("Alert acknowledged", "success"); self._loadAlerts(); })
              .catch(function() { showToast("Failed to acknowledge alert", "error"); });
        });
    });
    c.querySelectorAll("[data-escalate-alert]").forEach(function(b) {
        b.addEventListener("click", function() {
            var aid = this.getAttribute("data-escalate-alert");
            self.apiFetch("/api/alerts/" + encodeURIComponent(aid) + "/ack", {
                method: "PUT",
                body: { note: "ESCALATED", escalated: true }
            }).then(function() { showToast("Alert escalated", "warning"); self._loadAlerts(); })
              .catch(function() { showToast("Failed to escalate alert", "error"); });
        });
    });
};

BridgeDashboard.prototype._createRule = function() {
    // Legacy simple rule creation (kept for backward compat)
    var n = document.getElementById("rule-name"), sv = document.getElementById("rule-severity");
    if (!n || !n.value.trim()) return;
    var s = this;
    s.apiFetch("/api/alerts/rules", { method: "POST", body: { name: n.value.trim(), severity: sv ? sv.value : "warning", thresholds: {} } })
        .then(function() { n.value = ""; showToast("Alert rule created", "success"); s._loadAlerts(); }).catch(function() { showToast("Failed to create rule", "error"); });
};

/* ================================================================
   Condition Builder — visual alert rule builder
   ================================================================ */

BridgeDashboard.prototype._CB_FIELDS = [
    { value: "freq_hz",       label: "Frequency (Hz)",    type: "number" },
    { value: "signal_class",  label: "Signal Class",      type: "text"   },
    { value: "power_dbm",     label: "Power (dBm)",       type: "number" },
    { value: "snr_db",        label: "SNR (dB)",          type: "number" },
    { value: "anomaly_score", label: "Anomaly Score",     type: "number" },
    { value: "node_id",       label: "Node ID",           type: "text"   },
    { value: "confidence",    label: "Confidence",        type: "number" },
    { value: "family",        label: "Family",            type: "text"   },
    { value: "bandwidth_hz",  label: "Bandwidth (Hz)",    type: "number" },
];

BridgeDashboard.prototype._CB_OPERATORS = [
    { value: "eq",      label: "equals" },
    { value: "ne",      label: "not equals" },
    { value: "gt",      label: "greater than" },
    { value: "gte",     label: "greater or equal" },
    { value: "lt",      label: "less than" },
    { value: "lte",     label: "less or equal" },
    { value: "between", label: "between" },
    { value: "in",      label: "in list" },
    { value: "not_in",  label: "not in list" },
];

BridgeDashboard.prototype._initConditionBuilder = function() {
    var s = this;
    var addBtn = document.getElementById("cb-add-condition");
    var saveBtn = document.getElementById("cb-save-rule");
    var testBtn = document.getElementById("cb-test-rule");
    var cancelBtn = document.getElementById("cb-cancel");
    var logicSel = document.getElementById("cb-rule-logic");

    if (addBtn) addBtn.addEventListener("click", function() { s._cbAddConditionRow(); s._cbEnhanceLastRow(); });
    if (saveBtn) saveBtn.addEventListener("click", function() { s._cbSaveRule(); });
    if (testBtn) testBtn.addEventListener("click", function() { s._cbTestRule(); });
    if (cancelBtn) cancelBtn.addEventListener("click", function() { s._cbResetForm(); });
    if (logicSel) logicSel.addEventListener("change", function() { s._cbUpdateLogicBadges(); });

    s._loadConditionRules();
};

BridgeDashboard.prototype._cbAddConditionRow = function(data) {
    var container = document.getElementById("cb-conditions");
    var noCondMsg = document.getElementById("cb-no-conditions");
    if (!container) return;
    if (noCondMsg) noCondMsg.style.display = "none";

    var s = this;
    var row = document.createElement("div");
    row.className = "cb-condition-row";

    // Logic badge (shown for 2nd+ conditions)
    var existingRows = container.querySelectorAll(".cb-condition-row");
    if (existingRows.length > 0) {
        var logicSel = document.getElementById("cb-rule-logic");
        var logicText = (logicSel && logicSel.value) || "AND";
        var badge = document.createElement("span");
        badge.className = "cb-logic-badge";
        badge.textContent = logicText;
        row.appendChild(badge);
    }

    // Field select
    var fieldSel = document.createElement("select");
    fieldSel.className = "form-input cb-field-select";
    for (var i = 0; i < s._CB_FIELDS.length; i++) {
        var opt = document.createElement("option");
        opt.value = s._CB_FIELDS[i].value;
        opt.textContent = s._CB_FIELDS[i].label;
        fieldSel.appendChild(opt);
    }
    if (data && data.field) fieldSel.value = data.field;
    row.appendChild(fieldSel);

    // Operator select
    var opSel = document.createElement("select");
    opSel.className = "form-input cb-op-select";
    for (var j = 0; j < s._CB_OPERATORS.length; j++) {
        var opt2 = document.createElement("option");
        opt2.value = s._CB_OPERATORS[j].value;
        opt2.textContent = s._CB_OPERATORS[j].label;
        opSel.appendChild(opt2);
    }
    if (data && data.operator) opSel.value = data.operator;
    row.appendChild(opSel);

    // Value input
    var valInput = document.createElement("input");
    valInput.type = "text";
    valInput.className = "form-input cb-value-input";
    valInput.placeholder = "value";
    if (data && data.value !== undefined && data.value !== null) {
        if (data.operator === "between" && Array.isArray(data.value)) {
            valInput.value = String(data.value[0]);
        } else if ((data.operator === "in" || data.operator === "not_in") && Array.isArray(data.value)) {
            valInput.value = data.value.join(", ");
        } else {
            valInput.value = String(data.value);
        }
    }
    row.appendChild(valInput);

    // Value2 input (for between)
    var val2Input = document.createElement("input");
    val2Input.type = "text";
    val2Input.className = "form-input cb-value2-input";
    val2Input.placeholder = "max";
    val2Input.style.display = (data && data.operator === "between") ? "" : "none";
    if (data && data.operator === "between" && Array.isArray(data.value) && data.value.length === 2) {
        val2Input.value = String(data.value[1]);
    }
    row.appendChild(val2Input);

    // Show/hide value2 on operator change
    opSel.addEventListener("change", function() {
        val2Input.style.display = opSel.value === "between" ? "" : "none";
        if (opSel.value === "in" || opSel.value === "not_in") {
            valInput.placeholder = "val1, val2, ...";
        } else if (opSel.value === "between") {
            valInput.placeholder = "min";
        } else {
            valInput.placeholder = "value";
        }
    });
    // Trigger to set placeholder
    if (opSel.value === "in" || opSel.value === "not_in") valInput.placeholder = "val1, val2, ...";
    else if (opSel.value === "between") valInput.placeholder = "min";

    // Remove button
    var removeBtn = document.createElement("button");
    removeBtn.className = "cb-remove-btn";
    removeBtn.innerHTML = "&#x2715;";
    removeBtn.title = "Remove condition";
    removeBtn.addEventListener("click", function() {
        row.remove();
        s._cbUpdateLogicBadges();
        var remaining = container.querySelectorAll(".cb-condition-row");
        if (remaining.length === 0 && noCondMsg) noCondMsg.style.display = "";
    });
    row.appendChild(removeBtn);

    container.appendChild(row);
};

BridgeDashboard.prototype._cbUpdateLogicBadges = function() {
    var container = document.getElementById("cb-conditions");
    if (!container) return;
    var logicSel = document.getElementById("cb-rule-logic");
    var logicText = (logicSel && logicSel.value) || "AND";
    var rows = container.querySelectorAll(".cb-condition-row");
    for (var i = 0; i < rows.length; i++) {
        var badge = rows[i].querySelector(".cb-logic-badge");
        if (i === 0) {
            if (badge) badge.remove();
        } else {
            if (badge) {
                badge.textContent = logicText;
            } else {
                var newBadge = document.createElement("span");
                newBadge.className = "cb-logic-badge";
                newBadge.textContent = logicText;
                rows[i].insertBefore(newBadge, rows[i].firstChild);
            }
        }
    }
};

BridgeDashboard.prototype._cbCollectConditions = function() {
    var container = document.getElementById("cb-conditions");
    if (!container) return [];
    var rows = container.querySelectorAll(".cb-condition-row");
    var conditions = [];
    for (var i = 0; i < rows.length; i++) {
        var field = rows[i].querySelector(".cb-field-select").value;
        var op = rows[i].querySelector(".cb-op-select").value;
        var rawVal = rows[i].querySelector(".cb-value-input").value.trim();
        var val;

        // Determine field type
        var fieldMeta = null;
        for (var f = 0; f < this._CB_FIELDS.length; f++) {
            if (this._CB_FIELDS[f].value === field) { fieldMeta = this._CB_FIELDS[f]; break; }
        }
        var isNum = fieldMeta && fieldMeta.type === "number";

        if (op === "between") {
            var raw2 = rows[i].querySelector(".cb-value2-input").value.trim();
            val = isNum ? [parseFloat(rawVal) || 0, parseFloat(raw2) || 0] : [rawVal, raw2];
        } else if (op === "in" || op === "not_in") {
            var parts = rawVal.split(",").map(function(s) { return s.trim(); }).filter(Boolean);
            val = isNum ? parts.map(function(p) { return parseFloat(p) || 0; }) : parts;
        } else {
            val = isNum ? (parseFloat(rawVal) || 0) : rawVal;
        }
        conditions.push({ field: field, operator: op, value: val });
    }
    return conditions;
};

BridgeDashboard.prototype._cbSaveRule = function() {
    var nameEl = document.getElementById("cb-rule-name");
    var sevEl = document.getElementById("cb-rule-severity");
    var logicEl = document.getElementById("cb-rule-logic");
    var cooldownEl = document.getElementById("cb-cooldown");
    var enabledEl = document.getElementById("cb-enabled");
    var editingId = document.getElementById("cb-editing-rule-id");

    var name = nameEl ? nameEl.value.trim() : "";
    if (!name) { showToast("Rule name is required", "error"); return; }

    var conditions = this._cbCollectConditions();
    if (conditions.length === 0) { showToast("Add at least one condition", "error"); return; }

    var payload = {
        name: name,
        severity: sevEl ? sevEl.value : "warning",
        conditions: conditions,
        logic: logicEl ? logicEl.value : "AND",
        cooldown_seconds: cooldownEl ? parseInt(cooldownEl.value, 10) || 300 : 300,
        enabled: enabledEl ? enabledEl.checked : true,
        notify_webhook: true,
    };

    var s = this;
    var ruleId = editingId ? editingId.value : "";

    if (ruleId) {
        // Update existing rule
        s.apiFetch("/api/alerts/rules/conditions/" + encodeURIComponent(ruleId), {
            method: "PUT", body: payload,
        }).then(function() {
            showToast("Rule updated", "success");
            s._cbResetForm();
            s._loadConditionRules();
        }).catch(function() { showToast("Failed to update rule", "error"); });
    } else {
        // Create new rule
        s.apiFetch("/api/alerts/rules/conditions", {
            method: "POST", body: payload,
        }).then(function() {
            showToast("Rule created", "success");
            s._cbResetForm();
            s._loadConditionRules();
        }).catch(function() { showToast("Failed to create rule", "error"); });
    }
};

BridgeDashboard.prototype._cbTestRule = function() {
    var editingId = document.getElementById("cb-editing-rule-id");
    var ruleId = editingId ? editingId.value : "";
    var resultEl = document.getElementById("cb-test-result");

    if (!ruleId) {
        showToast("Save the rule first, then test it", "warning");
        return;
    }

    var s = this;
    if (resultEl) resultEl.textContent = "Testing...";

    s.apiFetch("/api/alerts/rules/conditions/" + encodeURIComponent(ruleId) + "/test", {
        method: "POST", body: { minutes: 60, limit: 1000 },
    }).then(function(data) {
        if (resultEl) {
            resultEl.textContent = "Scanned " + data.detections_scanned + " detections, " + data.matches + " matches";
            resultEl.style.color = data.matches > 0 ? "var(--accent-green)" : "var(--text-secondary)";
        }
    }).catch(function() {
        if (resultEl) { resultEl.textContent = "Test failed"; resultEl.style.color = "var(--accent-red)"; }
    });
};

BridgeDashboard.prototype._cbResetForm = function() {
    var nameEl = document.getElementById("cb-rule-name");
    var sevEl = document.getElementById("cb-rule-severity");
    var logicEl = document.getElementById("cb-rule-logic");
    var cooldownEl = document.getElementById("cb-cooldown");
    var enabledEl = document.getElementById("cb-enabled");
    var editingId = document.getElementById("cb-editing-rule-id");
    var condContainer = document.getElementById("cb-conditions");
    var noCondMsg = document.getElementById("cb-no-conditions");
    var resultEl = document.getElementById("cb-test-result");
    var titleEl = document.getElementById("cb-title");

    if (nameEl) nameEl.value = "";
    if (sevEl) sevEl.value = "warning";
    if (logicEl) logicEl.value = "AND";
    if (cooldownEl) cooldownEl.value = "300";
    if (enabledEl) enabledEl.checked = true;
    if (editingId) editingId.value = "";
    if (condContainer) condContainer.innerHTML = "";
    if (noCondMsg) noCondMsg.style.display = "";
    if (resultEl) resultEl.textContent = "";
    if (titleEl) titleEl.textContent = "New Alert Rule";
};

BridgeDashboard.prototype._cbEditRule = function(rule) {
    var titleEl = document.getElementById("cb-title");
    var nameEl = document.getElementById("cb-rule-name");
    var sevEl = document.getElementById("cb-rule-severity");
    var logicEl = document.getElementById("cb-rule-logic");
    var cooldownEl = document.getElementById("cb-cooldown");
    var enabledEl = document.getElementById("cb-enabled");
    var editingId = document.getElementById("cb-editing-rule-id");
    var condContainer = document.getElementById("cb-conditions");
    var noCondMsg = document.getElementById("cb-no-conditions");

    if (titleEl) titleEl.textContent = "Edit Rule: " + decodeHtmlEscapedText(rule.name);
    if (nameEl) nameEl.value = decodeHtmlEscapedText(rule.name);
    if (sevEl) sevEl.value = rule.severity || "warning";
    if (logicEl) logicEl.value = rule.logic || "AND";
    if (cooldownEl) cooldownEl.value = String(rule.cooldown_seconds || 300);
    if (enabledEl) enabledEl.checked = rule.enabled !== false;
    if (editingId) editingId.value = rule.rule_id || "";
    if (condContainer) condContainer.innerHTML = "";

    var conds = rule.conditions || [];
    for (var i = 0; i < conds.length; i++) {
        this._cbAddConditionRow(conds[i]);
    }
    if (noCondMsg) noCondMsg.style.display = conds.length > 0 ? "none" : "";

    // Scroll to builder
    var builder = document.getElementById("condition-builder");
    if (builder) builder.scrollIntoView({ behavior: "smooth", block: "nearest" });
};

BridgeDashboard.prototype._loadConditionRules = function() {
    var s = this;
    s.apiFetch("/api/alerts/rules/conditions")
        .then(function(rules) {
            s._renderConditionRules(rules);
        }).catch(function() {});
};

BridgeDashboard.prototype._renderConditionRules = function(rules) {
    var container = document.getElementById("condition-rules-list");
    var emptyEl = document.getElementById("condition-rules-empty");
    if (!container) return;

    if (!rules || rules.length === 0) {
        container.innerHTML = "";
        if (emptyEl) emptyEl.style.display = "";
        return;
    }
    if (emptyEl) emptyEl.style.display = "none";

    var s = this;
    var h = "";
    for (var i = 0; i < rules.length; i++) {
        var r = rules[i];
        var sev = esc(r.severity || "warning");
        var dis = r.enabled === false ? " cr-disabled" : "";
        var condSummary = s._cbConditionSummary(r.conditions || [], r.logic || "AND");

        // PR-14: dual-code severity via window.severityIcon() shape glyph.
        var crSevIcon = (typeof window.severityIcon === "function") ? window.severityIcon(sev) : "";
        h += '<div class="cr-item cr-' + sev + dis + '" data-rule-id="' + esc(r.rule_id) + '">'
           + '<div class="cr-info-col">'
           + '<div class="cr-name">' + esc(decodeHtmlEscapedText(r.name)) + '</div>'
           + '<div class="cr-meta">'
           + '<span class="severity-badge ' + sev + '">' + crSevIcon + sev + '</span> '
           + (r.enabled === false ? '<span style="color:var(--text-secondary)">[disabled]</span> ' : '')
           + 'Cooldown: ' + esc(r.cooldown_seconds) + 's'
           + (r.trigger_count ? ' | Triggered: ' + esc(r.trigger_count) + 'x' : '')
           + '</div>'
           + '<div class="cr-conditions-summary">' + condSummary + '</div>'
           + '</div>'
           + '<div class="cr-actions">'
           + '<button class="btn btn-sm" data-cr-edit="' + esc(r.rule_id) + '">Edit</button>'
           + '<button class="btn btn-sm" data-cr-delete="' + esc(r.rule_id) + '" style="color:var(--accent-red)">Del</button>'
           + '</div>'
           + '</div>';
    }
    container.innerHTML = h;

    // Bind edit/delete
    container.querySelectorAll("[data-cr-edit]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var id = this.getAttribute("data-cr-edit");
            var rule = rules.find(function(r) { return r.rule_id === id; });
            if (rule) s._cbEditRule(rule);
        });
    });
    container.querySelectorAll("[data-cr-delete]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var id = this.getAttribute("data-cr-delete");
            if (!confirm("Delete this alert rule?")) return;
            s.apiFetch("/api/alerts/rules/conditions/" + encodeURIComponent(id), { method: "DELETE" })
                .then(function() { showToast("Rule deleted", "success"); s._loadConditionRules(); })
                .catch(function() { showToast("Failed to delete rule", "error"); });
        });
    });
};

BridgeDashboard.prototype._cbConditionSummary = function(conditions, logic) {
    if (!conditions || conditions.length === 0) return "<em>No conditions</em>";
    var opLabels = { eq: "=", ne: "!=", gt: ">", gte: ">=", lt: "<", lte: "<=", between: "between", "in": "in", not_in: "not in" };
    var parts = [];
    for (var i = 0; i < conditions.length; i++) {
        var c = conditions[i];
        var opLabel = opLabels[c.operator] || c.operator;
        var valStr;
        if (c.operator === "between" && Array.isArray(c.value)) {
            valStr = c.value[0] + " .. " + c.value[1];
        } else if ((c.operator === "in" || c.operator === "not_in") && Array.isArray(c.value)) {
            valStr = "[" + c.value.join(", ") + "]";
        } else {
            valStr = String(c.value);
        }
        parts.push(esc(c.field) + " " + esc(opLabel) + " " + esc(valStr));
    }
    var sep = ' <span class="cb-logic-badge">' + esc(logic) + '</span> ';
    return parts.join(sep);
};

BridgeDashboard.prototype._onAlertWS = function(alert) {
    this._loadAlerts();
    // Also refresh the dedicated Alerts tab if active
    if (this.alertsDashboard && this.alertsDashboard._active) {
        this.alertsDashboard._fetchAlerts();
    }

    // Visual toast notification
    var severity = (alert && alert.severity) || "info";
    var name = (alert && alert.name) || "alert";
    var message = decodeHtmlEscapedText((alert && alert.message) || "New alert received");
    var toastType = severity === "critical" ? "error" : severity === "warning" ? "warning" : "info";
    showToast(message, toastType);

    // R1: Push to threat timeline
    this._pushThreatEvent("alert", severity, message, alert && alert.alert_id);

    // Browser Notification API (requires user permission)
    if (severity === "critical" || severity === "warning") {
        this._browserNotify(severity, message);
    }

    // R3: Severity-differentiated audio. Silent while the operator is already
    // looking at the Alerts tab; the toast and banner still appear.
    if (this._alertSoundEnabled() && !this._viewingAlertsTab()) {
        this._playAlertTone(severity);
    }

    // Critical alert banner (PR-7: pass structured object so the banner
    // can coalesce repeats by name/node within a 60s window).
    if (severity === "critical") {
        showCriticalBanner({
            id: (alert && (alert.alert_id || alert.id || alert.rule_id)) || null,
            name: name,
            nodeId: (alert && (alert.node_id || alert.nodeId)) || null,
            message: message
        });
    }
};

BridgeDashboard.prototype._viewingAlertsTab = function() {
    return Boolean(this.alertsDashboard && this.alertsDashboard._active) &&
        document.visibilityState !== "hidden";
};

BridgeDashboard.prototype._alertSoundEnabled = function() {
    return readBrowserPreference("bridge_alert_sound") !== "off";
};

// Browser delivery is independent of dashboard alerts and audio. Permission is
// requested only by the explicit topbar button, never at startup/on an alert.
BridgeDashboard.prototype._browserNotify = function(severity, message) {
    this._updateNotificationButton();
    if (!this._browserNotificationsOn || !("Notification" in window) || Notification.permission !== "granted") return;
    try {
        new Notification("Bridge Alert — " + severity.toUpperCase(), {
            body: message, icon: "/static/favicon.ico", tag: "bridge-alert",
            requireInteraction: severity === "critical",
            silent: !this._alertSoundEnabled()
        });
    } catch (_) {}
};

BridgeDashboard.prototype._initBrowserNotifications = function() {
    var s = this;
    s._browserNotificationsOn = readBrowserPreference("bridge_browser_notifications") !== "off";
    s._notificationIntentVersion = 0;
    var btn = document.getElementById("browser-notification-toggle");
    if (btn) btn.addEventListener("click", function() {
        if (s._notificationPending || !("Notification" in window)) return;
        if (s._browserNotificationsOn && Notification.permission === "granted") {
            s._saveBrowserNotifications(false);
        } else if (Notification.permission === "denied") {
            showToast("Browser notifications are blocked. Change this site's permission in your browser settings to enable them.", "info");
        } else if (Notification.permission === "granted") {
            s._saveBrowserNotifications(true);
        } else {
            s._notificationPending = true;
            s._updateNotificationButton();
            // Call synchronously inside the user gesture, then settle either API failure form.
            var request, intentVersion = s._notificationIntentVersion;
            try { request = Notification.requestPermission(); }
            catch (_) { request = Promise.reject(new Error("Notification permission unavailable")); }
            Promise.resolve(request).then(function(permission) {
                if (intentVersion === s._notificationIntentVersion) s._saveBrowserNotifications(permission === "granted");
                if (permission !== "granted") showToast("Browser notification permission was not granted. Dashboard alerts remain available.", "info");
            }).catch(function() {
                showToast("Could not request browser notification permission. Check your browser settings.", "error");
            }).finally(function() {
                s._notificationPending = false;
                s._updateNotificationButton();
            });
        }
    });
    window.addEventListener("storage", function(event) {
        if (event.key !== "bridge_browser_notifications" && event.key !== null) return;
        s._notificationIntentVersion++;
        s._browserNotificationsOn = readBrowserPreference("bridge_browser_notifications") !== "off";
        s._updateNotificationButton();
    });
    window.addEventListener("focus", function() { s._updateNotificationButton(); });
    s._updateNotificationButton();
};

BridgeDashboard.prototype._saveBrowserNotifications = function(enabled) {
    this._browserNotificationsOn = enabled;
    var saved = writeBrowserPreference("bridge_browser_notifications", enabled ? "on" : "off");
    this._updateNotificationButton();
    showToast("Browser notifications " + (enabled ? "enabled" : "disabled") +
        (saved ? "." : " for this tab only; this browser could not save the preference."), "info");
};

BridgeDashboard.prototype._updateNotificationButton = function() {
    var btn = document.getElementById("browser-notification-toggle");
    if (!btn) return;
    var supported = "Notification" in window;
    var on = supported && Notification.permission === "granted" && this._browserNotificationsOn;
    var state = !supported ? "Unavailable" : this._notificationPending ? "Waiting…" :
        Notification.permission === "denied" ? "Blocked" : on ? "On" : "Off";
    btn.disabled = !supported || !!this._notificationPending;
    btn.setAttribute("aria-pressed", on ? "true" : "false");
    btn.setAttribute("aria-label", "Browser notifications: " + state);
    btn.title = "Browser notifications: " + state + ". Dashboard alerts and audio are independent.";
    setText("browser-notification-state", state);
};

BridgeDashboard.prototype._closeAlertAudio = function(ctx) {
    var contexts = this._alertAudioContexts || [];
    var index = contexts.indexOf(ctx);
    if (index < 0) return;
    contexts.splice(index, 1);
    try {
        var closing = ctx.close();
        if (closing && closing.catch) closing.catch(function() {});
    } catch (_) {}
};

BridgeDashboard.prototype._syncAlertSound = function() {
    var s = this;
    if (!s._alertSoundEnabled()) {
        (s._alertAudioContexts || []).slice().forEach(function(ctx) { s._closeAlertAudio(ctx); });
    }
    s._updateSoundIcon();
};

BridgeDashboard.prototype._playAlertTone = function(severity) {
    if (!this._alertSoundEnabled()) return;
    var s = this, ctx;
    // R3: Severity-differentiated audio alerts
    // Critical: sustained alarm (3 high-pitched beep sets)
    // Warning: rising two-tone
    // Info: short double-beep
    try {
        ctx = new (window.AudioContext || window.webkitAudioContext)();
        (s._alertAudioContexts || (s._alertAudioContexts = [])).push(ctx);
        var profiles = {
            critical: { freqs: [[880, 1100, 880], [880, 1100, 880], [880, 1100, 880]], dur: 0.15, gap: 0.05, setGap: 0.4, vol: 0.18, wave: "square" },
            warning:  { freqs: [[600, 900]],     dur: 0.2,  gap: 0.05, setGap: 0, vol: 0.12, wave: "triangle" },
            info:     { freqs: [[660, 660]],      dur: 0.08, gap: 0.06, setGap: 0, vol: 0.08, wave: "sine" },
        };
        var p = profiles[severity] || profiles.info;

        var t = ctx.currentTime;
        for (var si = 0; si < p.freqs.length; si++) {
            var set = p.freqs[si];
            for (var i = 0; i < set.length; i++) {
                var osc = ctx.createOscillator();
                var gain = ctx.createGain();
                osc.connect(gain);
                gain.connect(ctx.destination);
                osc.frequency.value = set[i];
                osc.type = p.wave;
                gain.gain.value = p.vol;
                osc.start(t);
                t += p.dur;
                osc.stop(t);
                t += p.gap;
            }
            t += p.setGap;
        }
        setTimeout(function() { s._closeAlertAudio(ctx); }, (t - ctx.currentTime + 0.5) * 1000);
    } catch (_) { if (ctx) s._closeAlertAudio(ctx); }
};

/* -- Activity Log ----------------------------------------------- */

BridgeDashboard.prototype._loadActivity = function() {
    var s = this;
    var c = document.getElementById("activity-log");
    if (c && !c.innerHTML) {
        c.innerHTML = '<tr><td colspan="4" class="loading-container"><div class="loading-spinner"></div>Loading activity log...</td></tr>';
    }
    s.apiFetch("/api/nodes/activity?limit=200").then(function(e) { clearFetchError("activity"); s._renderActivity(e); }).catch(function(e) { trackFetchError("activity", e); });
};

BridgeDashboard.prototype._renderActivity = function(entries) {
    var c = document.getElementById("activity-log");
    var em = document.getElementById("activity-empty");
    if (!c) return;
    if (!entries || !entries.length) { c.innerHTML = ""; if (em) em.style.display = ""; return; }
    if (em) em.style.display = "none";
    var h = "";
    // The bridge stores each activity event's type, node and message
    // HTML-encoded once (state.log_activity): decode that layer, then escape.
    for (var i = entries.length - 1; i >= 0; i--) {
        var e = entries[i];
        h += "<tr class=\"activity-entry\"><td class=\"activity-ts\">" + fmtTime(e.timestamp) + "</td>"
            + "<td class=\"activity-node\">" + esc(decodeHtmlEscapedText(e.node_id || "")) + "</td>"
            + "<td class=\"activity-type\">" + esc(decodeHtmlEscapedText(e.event_type)) + "</td>"
            + "<td class=\"activity-msg\">" + esc(decodeHtmlEscapedText(e.message)) + "</td></tr>";
    }
    c.innerHTML = h;
    var wrap = document.getElementById("activity-log-wrapper");
    if (wrap) wrap.scrollTop = wrap.scrollHeight;
};

/* -- Theme Toggle ----------------------------------------------- */

BridgeDashboard.prototype._initTheme = function() {
    var saved = readBrowserPreference("bridge_theme") || "dark";
    document.documentElement.setAttribute("data-theme", saved);
    var sel = document.getElementById("theme-select");
    var s = this;
    if (sel) {
        sel.value = saved;
        sel.addEventListener("change", function() {
            document.documentElement.setAttribute("data-theme", sel.value);
            writeBrowserPreference("bridge_theme", sel.value);
            // R12: Theme warning
            s._checkThemeWarning();
        });
    }
    // R12: Initial check
    s._checkThemeWarning();
};

/* -- Alert Sound Toggle ----------------------------------------- */

BridgeDashboard.prototype._initAlertSound = function() {
    var s = this;
    s._syncAlertSound();
    var btn = document.getElementById("alert-sound-toggle");
    if (btn) btn.addEventListener("click", function() {
        var on = s._alertSoundEnabled();
        writeBrowserPreference("bridge_alert_sound", on ? "off" : "on");
        s._syncAlertSound();
        showToast("Alert sounds " + (on ? "disabled" : "enabled"), "info");
    });
    window.addEventListener("storage", function(event) {
        if (event.key === null || event.key === "bridge_alert_sound") s._syncAlertSound();
    });
    window.addEventListener("focus", function() { s._syncAlertSound(); });
};

BridgeDashboard.prototype._updateSoundIcon = function() {
    var on = this._alertSoundEnabled();
    var icon = document.getElementById("alert-sound-icon");
    if (icon) icon.textContent = on ? "\uD83D\uDD0A" : "\uD83D\uDD07";
    var btn = document.getElementById("alert-sound-toggle");
    if (btn) {
        btn.setAttribute("aria-pressed", String(on));
        btn.setAttribute("aria-label", on ? "Disable alert sounds" : "Enable alert sounds");
        btn.title = on ? "Disable alert sounds" : "Enable alert sounds";
    }
};

/* ================================================================
   R1: Unified Cross-Protocol Threat Timeline
   ================================================================ */

BridgeDashboard.prototype._initThreatTimeline = function() {
    this._tlEvents = [];      // [{ts, protocol, severity, label, alertId?}]
    this._tlPoints = [];
    this._tlSelected = null;
    this._tlProtoColors = {
        sdr: "#58a6ff", wifi: "#3fb950", bluetooth: "#d29922", zigbee: "#bc8cff", alert: "#f85149"
    };
    var legend = document.getElementById("threat-timeline-legend");
    if (legend) {
        var h = "";
        var labels = { sdr: "SDR", wifi: "Wi-Fi", bluetooth: "Bluetooth", zigbee: "Zigbee", alert: "Alert" };
        for (var k in labels) {
            h += "<span><span class=\"tl-swatch\" style=\"background:" + this._tlProtoColors[k] + "\"></span>" + labels[k] + "</span>";
        }
        legend.innerHTML = h;
    }
    var s = this;
    var canvas = document.getElementById("threat-timeline-canvas");
    if (canvas) {
        canvas.addEventListener("mousemove", function(event) { s._showTimelineEvent(s._timelineHit(event)); });
        canvas.addEventListener("mouseleave", function() { s._showTimelineEvent(null); });
        canvas.addEventListener("click", function(event) {
            var point = s._timelineHit(event);
            s._showTimelineEvent(point);
            if (point && point.event.protocol === "alert") s._openTimelineAlert(point.event);
        });
        canvas.addEventListener("focus", function() { s._tlSelected = null; s._stepTimelineAlert(0); });
        canvas.addEventListener("blur", function() { s._showTimelineEvent(null); });
        canvas.addEventListener("keydown", function(event) {
            if (event.key === "ArrowRight" || event.key === "ArrowLeft") {
                event.preventDefault(); event.stopPropagation(); s._stepTimelineAlert(event.key === "ArrowRight" ? 1 : -1);
            } else if (event.key === "Enter" || event.key === " ") {
                event.preventDefault(); event.stopPropagation();
                if (s._tlSelected && s._tlSelected.event.protocol === "alert") s._openTimelineAlert(s._tlSelected.event);
            } else if (event.key === "Escape") { event.stopPropagation(); s._showTimelineEvent(null); }
        });
    }
    var open = document.getElementById("threat-timeline-open");
    if (open) open.addEventListener("click", function() { s._openTimelineAlert(null); });
    window.addEventListener("resize", function() { s._renderThreatTimeline(); });
    // Seed timeline from recent alerts
    this._seedThreatTimeline();
};

BridgeDashboard.prototype._seedThreatTimeline = function() {
    var s = this;
    s.apiFetch("/api/alerts/?limit=50").then(function(alerts) {
        if (!Array.isArray(alerts)) return;
        var now = Date.now();
        var cutoff = now - 30 * 60 * 1000;
        for (var i = alerts.length - 1; i >= 0; i--) {
            var a = alerts[i];
            var ts = a.triggered_at ? new Date(a.triggered_at).getTime() : 0;
            if (!Number.isFinite(ts) || ts < cutoff || ts > now) continue;
            s._tlEvents.push({ ts: ts, protocol: "alert", severity: a.severity || "info", label: decodeHtmlEscapedText(a.message || ""), alertId: a.alert_id || null });
        }
        // Also seed from recent RF anomalies
        return s.apiFetch("/api/detections/anomalies?min_score=0.5&limit=50");
    }).then(function(data) {
        if (!data) return;
        var anomalies = data.anomalies || data;
        if (!Array.isArray(anomalies)) return;
        var now2 = Date.now();
        var cutoff2 = now2 - 30 * 60 * 1000;
        for (var j = anomalies.length - 1; j >= 0; j--) {
            var an = anomalies[j];
            var ts2 = an.timestamp ? new Date(an.timestamp).getTime() : (an.detected_at ? new Date(an.detected_at).getTime() : 0);
            if (!Number.isFinite(ts2) || ts2 < cutoff2 || ts2 > now2) continue;
            var score = an.anomaly_score || 0;
            var sev = score >= 0.7 ? "critical" : score >= 0.5 ? "warning" : "info";
            s._tlEvents.push({ ts: ts2, protocol: "sdr", severity: sev, label: (an.signal_class || "RF") + " anomaly" });
        }
        s._renderThreatTimeline();
    }).catch(function() {});
};

BridgeDashboard.prototype._pushThreatEvent = function(proto, severity, label, alertId) {
    var now = Date.now();
    this._tlEvents.push({ ts: now, protocol: proto, severity: severity, label: label, alertId: alertId || null });
    // Keep 30 minutes of events
    var cutoff = now - 30 * 60 * 1000;
    this._tlEvents = this._tlEvents.filter(function(event) { return event.ts >= cutoff; });
    this._renderThreatTimeline();
};

BridgeDashboard.prototype._renderThreatTimeline = function() {
    var canvas = document.getElementById("threat-timeline-canvas");
    if (!canvas) return;
    var ctx = canvas.getContext("2d");
    var W = Math.max(1, canvas.parentElement.clientWidth - 48);
    canvas.width = W;
    var H = canvas.height;
    ctx.clearRect(0, 0, W, H);

    var now = Date.now();
    var span = 30 * 60 * 1000;  // 30 minutes
    var start = now - span;

    // Draw time axis
    ctx.strokeStyle = "rgba(139,148,158,0.2)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(0, H - 1);
    ctx.lineTo(W, H - 1);
    ctx.stroke();

    // Time labels
    ctx.fillStyle = "rgba(139,148,158,0.4)";
    ctx.font = "9px monospace";
    ctx.textAlign = "center";
    for (var m = 5; m <= 30; m += 5) {
        var x = ((span - m * 60000) / span) * W;
        ctx.fillText("-" + m + "m", x, H - 2);
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, H - 10);
        ctx.strokeStyle = "rgba(139,148,158,0.08)";
        ctx.stroke();
    }

    // Plot events.
    // PR-18 (dashboard §1.5): decouple protocol from severity.
    //   - Protocol = hue (existing color map).
    //   - Severity = SHAPE (info: small dot, warning: hollow ring,
    //     critical: large filled, high: filled + halo).
    // Previously severity rode on globalAlpha+radius alone, which
    // collided with the protocol hue (e.g. Bluetooth yellow ≈ severity
    // yellow). Color is NOT used for severity in this rendering.
    var colors = this._tlProtoColors;
    this._tlPoints = [];
    for (var i = 0; i < this._tlEvents.length; i++) {
        var e = this._tlEvents[i];
        var ex = ((e.ts - start) / span) * W;
        if (!Number.isFinite(ex) || ex < 0 || ex > W) continue;
        var y = H * 0.4;  // center area
        // Protocol row offset
        var protos = ["alert", "sdr", "wifi", "bluetooth", "zigbee"];
        var pi = protos.indexOf(e.protocol);
        if (pi >= 0) y = 6 + (pi / protos.length) * (H - 20);

        var color = colors[e.protocol] || "#8b949e";
        this._drawTimelineEvent(ctx, ex, y, color, e.severity);
        this._tlPoints.push({x: ex, y: y, event: e});
    }
    if (this._tlSelected) {
        var selected = this._tlSelected.event;
        this._showTimelineEvent(this._tlPoints.find(function(point) { return point.event === selected; }) || null);
    }
};

BridgeDashboard.prototype._timelineHit = function(event) {
    var canvas = document.getElementById("threat-timeline-canvas");
    var rect = canvas.getBoundingClientRect();
    if (!rect.width || !rect.height) return null;
    var best = null, distance = 100; // A ten CSS-pixel hit radius, including scaled canvases.
    for (var i = 0; i < this._tlPoints.length; i++) {
        var point = this._tlPoints[i];
        var dx = event.clientX - rect.left - point.x * rect.width / canvas.width;
        var dy = event.clientY - rect.top - point.y * rect.height / canvas.height;
        var squared = dx * dx + dy * dy;
        if (squared < distance) { best = point; distance = squared; }
    }
    return best;
};

BridgeDashboard.prototype._showTimelineEvent = function(point) {
    this._tlSelected = point;
    var summary = document.getElementById("threat-timeline-summary");
    if (!summary) return;
    summary.hidden = !point;
    if (!point) { summary.textContent = ""; return; }
    var event = point.event;
    summary.textContent = (event.protocol === "alert" ? "Alert" : event.protocol.toUpperCase() + " observation (no linked alert)") +
        " · " + event.severity + " · " + new Date(event.ts).toLocaleTimeString() + " · " + event.label +
        (event.protocol === "alert" ? " — Click or press Enter to open Alerts." : "");
};

BridgeDashboard.prototype._stepTimelineAlert = function(direction) {
    var alerts = this._tlPoints.filter(function(point) { return point.event.protocol === "alert"; }).sort(function(a, b) { return a.event.ts - b.event.ts; });
    if (!alerts.length) { this._showTimelineEvent(null); return; }
    var index = alerts.indexOf(this._tlSelected);
    index = index < 0 ? 0 : (index + direction + alerts.length) % alerts.length;
    this._showTimelineEvent(alerts[index]);
};

BridgeDashboard.prototype._openTimelineAlert = function(event) {
    this.activateTab("alerts");
    if (event && event.alertId && this.alertsDashboard) this.alertsDashboard.focusAlert(event.alertId);
};

BridgeDashboard.prototype._drawTimelineEvent = function(ctx, x, y, color, severity) {
    ctx.globalAlpha = 1.0;
    if (severity === "critical") {
        // Large filled circle.
        ctx.beginPath();
        ctx.fillStyle = color;
        ctx.arc(x, y, 6, 0, 2 * Math.PI);
        ctx.fill();
    } else if (severity === "high") {
        // Filled circle with halo (two-tone outline).
        ctx.beginPath();
        ctx.fillStyle = color;
        ctx.arc(x, y, 5, 0, 2 * Math.PI);
        ctx.fill();
        ctx.beginPath();
        ctx.strokeStyle = color;
        ctx.lineWidth = 1.5;
        ctx.globalAlpha = 0.4;
        ctx.arc(x, y, 9, 0, 2 * Math.PI);
        ctx.stroke();
        ctx.globalAlpha = 1.0;
    } else if (severity === "warning") {
        // Hollow ring (stroke only).
        ctx.beginPath();
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        ctx.arc(x, y, 5, 0, 2 * Math.PI);
        ctx.stroke();
    } else {
        // info / unknown — small filled dot.
        ctx.beginPath();
        ctx.fillStyle = color;
        ctx.arc(x, y, 3, 0, 2 * Math.PI);
        ctx.fill();
    }
    ctx.globalAlpha = 1.0;
};

/* ================================================================
   R2: Tab Badge Updates
   ================================================================ */

BridgeDashboard.prototype._updateTabBadge = function(tabId, count, severity) {
    var el = document.getElementById("tab-badge-" + tabId);
    if (!el) return;
    if (count > 0) {
        el.textContent = count > 99 ? "99+" : String(count);
        el.className = "tab-badge badge-visible" + (severity ? " badge-" + severity : "");
    } else {
        el.className = "tab-badge";
        el.textContent = "";
    }
};

/* ================================================================
   R6: Stale Data Indication
   ================================================================ */

BridgeDashboard.prototype._initStaleTracking = function() {
    this._lastDataTs = Date.now();
    this._staleCheckTimer = null;
    var s = this;
    this._staleCheckTimer = setInterval(function() { s._checkStale(); }, 5000);
};

BridgeDashboard.prototype._markDataFresh = function() {
    this._lastDataTs = Date.now();
    document.body.classList.remove("data-stale");
};

BridgeDashboard.prototype._checkStale = function() {
    var elapsed = Math.round((Date.now() - this._lastDataTs) / 1000);
    if (elapsed > 30) {
        document.body.classList.add("data-stale");
        setText("stale-data-ago", String(elapsed));
    } else {
        document.body.classList.remove("data-stale");
    }
};

/* ================================================================
   R5: Node Table Progressive Disclosure
   ================================================================ */

BridgeDashboard.prototype._initNodeDetails = function() {
    var cb = document.getElementById("nodes-show-details");
    var table = document.getElementById("nodes-table");
    if (!cb || !table) return;
    var saved = readBrowserPreference("bridge_nodes_detail") === "true";
    cb.checked = saved;
    if (saved) table.classList.add("nodes-detail-mode");
    cb.addEventListener("change", function() {
        table.classList.toggle("nodes-detail-mode", cb.checked);
        writeBrowserPreference("bridge_nodes_detail", cb.checked ? "true" : "false");
    });
};

/* ================================================================
   R7: Trend Indicators on Summary Stats
   ================================================================ */

BridgeDashboard.prototype._initTrends = function() {
    // Circular buffers for 12 polls (3 min at 15s intervals)
    this._trendBuf = {};
    this._TREND_SIZE = 12;
};

BridgeDashboard.prototype._trackStat = function(key, value) {
    var num = parseFloat(value);
    if (isNaN(num)) return;
    if (!this._trendBuf[key]) this._trendBuf[key] = [];
    var buf = this._trendBuf[key];
    buf.push(num);
    if (buf.length > this._TREND_SIZE) buf.shift();
};

BridgeDashboard.prototype._renderTrendIndicator = function(elementId, key) {
    var el = document.getElementById(elementId);
    if (!el) return;
    var buf = this._trendBuf[key];
    if (!buf || buf.length < 3) {
        // Remove any existing trend span
        var old = el.parentElement && el.parentElement.querySelector(".stat-trend");
        if (old) old.remove();
        return;
    }
    var latest = buf[buf.length - 1];
    var avg = 0;
    for (var i = 0; i < buf.length - 1; i++) avg += buf[i];
    avg /= (buf.length - 1);

    var pctChange = avg !== 0 ? ((latest - avg) / Math.abs(avg)) * 100 : 0;
    var arrow, cls;
    if (pctChange > 10) { arrow = "\u2191"; cls = "trend-up"; }
    else if (pctChange < -10) { arrow = "\u2193"; cls = "trend-down"; }
    else { arrow = "\u2192"; cls = "trend-flat"; }

    // Draw inline sparkline
    var sparkSvg = "<svg class=\"stat-sparkline\" width=\"40\" height=\"12\" viewBox=\"0 0 40 12\">";
    var minV = Math.min.apply(null, buf), maxV = Math.max.apply(null, buf);
    var range = maxV - minV || 1;
    var pts = [];
    for (var j = 0; j < buf.length; j++) {
        var x = (j / (buf.length - 1)) * 40;
        var y = 11 - ((buf[j] - minV) / range) * 10;
        pts.push(x.toFixed(1) + "," + y.toFixed(1));
    }
    var color = cls === "trend-up" ? "var(--accent-red)" : cls === "trend-down" ? "var(--accent-green)" : "var(--text-secondary)";
    sparkSvg += "<polyline points=\"" + pts.join(" ") + "\" fill=\"none\" stroke=\"" + color + "\" stroke-width=\"1.5\" opacity=\"0.7\"/></svg>";

    var trendEl = el.parentElement && el.parentElement.querySelector(".stat-trend");
    if (!trendEl) {
        trendEl = document.createElement("span");
        trendEl.className = "stat-trend";
        el.parentElement.appendChild(trendEl);
    }
    trendEl.className = "stat-trend " + cls;
    var absPct = Math.abs(pctChange).toFixed(0);
    trendEl.innerHTML = arrow + (absPct > 0 ? " " + absPct + "%" : "") + " " + sparkSvg;
};

/* ================================================================
   R8: Contextual Rule Builder Enhancements
   ================================================================ */

BridgeDashboard.prototype._cbEnhanceLastRow = function() {
    var container = document.getElementById("cb-conditions");
    if (!container) return;
    var rows = container.querySelectorAll(".cb-condition-row");
    if (rows.length) this._cbEnhanceRow(rows[rows.length - 1]);
};

BridgeDashboard.prototype._CB_FIELD_HINTS = {
    freq_hz: "Typical: 88M-6G. Use band picker below.",
    signal_class: "e.g. fm, qpsk, wifi, bluetooth-le",
    power_dbm: "Typical range: -80 to -10",
    snr_db: "Typical range: 0 to 40",
    anomaly_score: "Range: 0.0 to 1.0 (0.7+ = critical)",
    node_id: "e.g. rtlsdr_186, hackrf_57",
    confidence: "Range: 0.0 to 1.0",
    family: "e.g. ask, fsk, psk, ofdm",
    bandwidth_hz: "Typical: 10K-20M"
};

BridgeDashboard.prototype._CB_FREQ_BANDS = [
    { label: "FM Broadcast", min: 88e6, max: 108e6 },
    { label: "VHF Air", min: 108e6, max: 137e6 },
    { label: "ISM 433", min: 433.05e6, max: 434.79e6 },
    { label: "ISM 868", min: 863e6, max: 870e6 },
    { label: "ISM 915", min: 902e6, max: 928e6 },
    { label: "GSM 900", min: 880e6, max: 960e6 },
    { label: "WiFi 2.4G", min: 2.4e9, max: 2.5e9 },
    { label: "WiFi 5G", min: 5.15e9, max: 5.85e9 },
];

BridgeDashboard.prototype._cbEnhanceRow = function(row) {
    var s = this;
    var fieldSel = row.querySelector(".cb-field-select");
    var valInput = row.querySelector(".cb-value-input");
    var val2Input = row.querySelector(".cb-value2-input");
    var opSel = row.querySelector(".cb-op-select");
    if (!fieldSel || !valInput) return;

    // Hint element
    var hint = document.createElement("div");
    hint.className = "cb-field-hint";
    row.appendChild(hint);

    // Band picker (shown for freq_hz)
    var bandPicker = document.createElement("div");
    bandPicker.className = "cb-band-picker";
    bandPicker.style.display = "none";
    for (var i = 0; i < s._CB_FREQ_BANDS.length; i++) {
        var b = s._CB_FREQ_BANDS[i];
        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = "cb-band-btn";
        btn.textContent = b.label;
        btn.setAttribute("data-min", String(b.min));
        btn.setAttribute("data-max", String(b.max));
        btn.addEventListener("click", function() {
            valInput.value = this.getAttribute("data-min");
            if (opSel) opSel.value = "between";
            if (val2Input) { val2Input.value = this.getAttribute("data-max"); val2Input.style.display = ""; }
            s._cbUpdatePreview();
        });
        bandPicker.appendChild(btn);
    }
    row.appendChild(bandPicker);

    function updateHint() {
        var field = fieldSel.value;
        hint.textContent = s._CB_FIELD_HINTS[field] || "";
        bandPicker.style.display = field === "freq_hz" ? "flex" : "none";
        s._cbUpdatePreview();
    }
    fieldSel.addEventListener("change", updateHint);
    if (opSel) opSel.addEventListener("change", function() { s._cbUpdatePreview(); });
    valInput.addEventListener("input", function() { s._cbUpdatePreview(); });
    if (val2Input) val2Input.addEventListener("input", function() { s._cbUpdatePreview(); });
    updateHint();

    // Signal class autocomplete
    if (fieldSel.value === "signal_class") s._cbAttachAutocomplete(valInput);
    fieldSel.addEventListener("change", function() {
        if (fieldSel.value === "signal_class") s._cbAttachAutocomplete(valInput);
    });
};

BridgeDashboard.prototype._observedClasses = [];

BridgeDashboard.prototype._cbAttachAutocomplete = function(input) {
    if (input._acAttached) return;
    input._acAttached = true;
    var s = this;
    // Fetch observed classes if empty
    if (!s._observedClasses.length) {
        s.apiFetch("/api/status?freq_hours=24").then(function(d) {
            var fl = d.active_frequency_list || [];
            var seen = {};
            // Rows carry a comma-joined "classes" field
            // (detection_analytics.get_active_frequencies); a single
            // signal_class is accepted too.
            for (var i = 0; i < fl.length; i++) {
                var raw = fl[i].classes != null ? fl[i].classes : fl[i].signal_class;
                var names = String(raw == null ? "" : raw).split(",");
                for (var j = 0; j < names.length; j++) {
                    var name = names[j].trim();
                    if (name && !seen.hasOwnProperty(name)) {
                        seen[name] = true;
                        s._observedClasses.push(name);
                    }
                }
            }
        }).catch(function() {});
    }
    input.addEventListener("input", function() {
        var val = input.value.toLowerCase();
        var existing = input.parentElement.querySelector(".cb-autocomplete-list");
        if (existing) existing.remove();
        if (!val) return;
        var matches = s._observedClasses.filter(function(c) { return c.toLowerCase().indexOf(val) !== -1; });
        if (!matches.length) return;
        var list = document.createElement("div");
        list.className = "cb-autocomplete-list";
        for (var i = 0; i < Math.min(8, matches.length); i++) {
            var item = document.createElement("div");
            item.className = "cb-autocomplete-item";
            item.textContent = matches[i];
            item.addEventListener("click", function() {
                input.value = this.textContent;
                list.remove();
                s._cbUpdatePreview();
            });
            list.appendChild(item);
        }
        input.parentElement.style.position = "relative";
        input.parentElement.appendChild(list);
    });
};

BridgeDashboard.prototype._cbUpdatePreview = function() {
    var preview = document.getElementById("cb-rule-preview");
    if (!preview) return;
    var container = document.getElementById("cb-conditions");
    if (!container) return;
    var rows = container.querySelectorAll(".cb-condition-row");
    var logicSel = document.getElementById("cb-rule-logic");
    var logic = (logicSel && logicSel.value) || "AND";

    if (!rows.length) { preview.textContent = "Rule preview will appear here..."; return; }

    var parts = [];
    var fieldLabels = {};
    for (var k = 0; k < this._CB_FIELDS.length; k++) fieldLabels[this._CB_FIELDS[k].value] = this._CB_FIELDS[k].label;
    var opLabels = {};
    for (var m = 0; m < this._CB_OPERATORS.length; m++) opLabels[this._CB_OPERATORS[m].value] = this._CB_OPERATORS[m].label;

    for (var i = 0; i < rows.length; i++) {
        var fs = rows[i].querySelector(".cb-field-select");
        var os = rows[i].querySelector(".cb-op-select");
        var vi = rows[i].querySelector(".cb-value-input");
        var v2 = rows[i].querySelector(".cb-value2-input");
        if (!fs || !os || !vi) continue;

        var fld = fieldLabels[fs.value] || fs.value;
        var op = opLabels[os.value] || os.value;
        var val = vi.value || "?";

        // Humanize frequency values
        if (fs.value === "freq_hz" && !isNaN(parseFloat(val))) {
            val = (parseFloat(val) / 1e6).toFixed(1) + " MHz";
        }

        var part = fld + " " + op + " " + val;
        if (os.value === "between" && v2 && v2.value) {
            var val2 = v2.value;
            if (fs.value === "freq_hz" && !isNaN(parseFloat(val2))) val2 = (parseFloat(val2) / 1e6).toFixed(1) + " MHz";
            part += " and " + val2;
        }
        parts.push(part);
    }
    preview.textContent = "Alert when " + parts.join(" " + logic + " ");
};

/* ================================================================
   R12: Theme Operational Warning
   ================================================================ */

/* ================================================================
   R14: Keyboard Shortcut Overlay + Tab Number Shortcuts
   ================================================================ */

BridgeDashboard.prototype._initShortcutOverlay = function() {
    var s = this;
    var overlay = document.getElementById("shortcut-overlay");
    if (!overlay) return;

    // Show onboarding tooltip on first visit
    if (!readBrowserPreference("bridge_shortcuts_seen")) {
        setTimeout(function() {
            showToast("Press ? for keyboard shortcuts", "info");
            writeBrowserPreference("bridge_shortcuts_seen", "true");
        }, 3000);
    }

    // Global keyboard handler for overlay + tab numbers
    document.addEventListener("keydown", function(e) {
        var tag = (e.target.tagName || "").toLowerCase();
        if (tag === "input" || tag === "textarea" || tag === "select") return;

        // "?" toggles overlay
        if (e.key === "?" && !e.ctrlKey && !e.metaKey) {
            overlay.classList.toggle("visible");
            e.preventDefault();
            return;
        }
        // Escape closes overlay
        if (e.key === "Escape" && overlay.classList.contains("visible")) {
            overlay.classList.remove("visible");
            e.preventDefault();
            return;
        }
        // Number keys 1-0 switch tabs
        var tabMap = { "1": "summary", "2": "rf", "3": "wifi", "4": "map", "5": "spectrum-analysis", "6": "bluetooth", "7": "zigbee", "8": "alerts", "9": "training", "0": "deployment" };
        if (tabMap[e.key] && !e.ctrlKey && !e.metaKey && !e.altKey) {
            s.activateTab(tabMap[e.key]);
            e.preventDefault();
        }
    });

    // Click overlay background to close
    overlay.addEventListener("click", function(e) {
        if (e.target === overlay) overlay.classList.remove("visible");
    });
};

/* ================================================================
   R11: Cross-Protocol Entity Linking
   ================================================================ */

BridgeDashboard.prototype._initEntityIndex = function() {
    // Stores known MACs/freqs/node_ids seen per protocol
    this._entityIndex = { wifi: {}, bluetooth: {}, sdr: {} };
};

BridgeDashboard.prototype.indexEntity = function(protocol, type, value) {
    if (!value || !this._entityIndex) return;
    var key = type + ":" + String(value).toLowerCase();
    if (!this._entityIndex[protocol]) this._entityIndex[protocol] = {};
    this._entityIndex[protocol][key] = Date.now();
};

BridgeDashboard.prototype.getEntityLinks = function(protocol, type, value) {
    if (!value || !this._entityIndex) return "";
    var key = type + ":" + String(value).toLowerCase();
    var cutoff = Date.now() - 60 * 60 * 1000; // 1 hour
    var others = [];
    for (var p in this._entityIndex) {
        if (p === protocol) continue;
        if (this._entityIndex[p][key] && this._entityIndex[p][key] > cutoff) {
            others.push(p === "sdr" ? "SDR" : p === "wifi" ? "WiFi" : "BT");
        }
    }
    if (!others.length) return "";
    return " <span class=\"entity-link-badge\" title=\"Also seen in " + others.join(", ") + "\">Also: " + others.join(", ") + "</span>";
};

BridgeDashboard.prototype._RECREATIONAL_THEMES = ["matrix", "cyberpunk", "bladerunner", "br2049"];

BridgeDashboard.prototype._checkThemeWarning = function() {
    var sel = document.getElementById("theme-select");
    var warn = document.getElementById("theme-warning");
    if (!sel || !warn) return;
    var isRec = this._RECREATIONAL_THEMES.indexOf(sel.value) !== -1;
    warn.style.display = isRec ? "" : "none";
};

/* ================================================================
   R13: Alert Acknowledgment Enrichment
   ================================================================ */

BridgeDashboard.prototype._calcTTA = function(triggeredAt, ackedAt) {
    if (!triggeredAt || !ackedAt) return null;
    try {
        var diff = (new Date(ackedAt).getTime() - new Date(triggeredAt).getTime()) / 1000;
        if (diff < 60) return diff.toFixed(0) + "s";
        if (diff < 3600) return (diff / 60).toFixed(0) + "m";
        return (diff / 3600).toFixed(1) + "h";
    } catch (_) { return null; }
};

/* -- Geo Map ---------------------------------------------------- */

BridgeDashboard.prototype._initGeoMap = function() {
    if (typeof GeoMap === "function") {
        this.geoMap = new GeoMap(this);
        // If Map tab was already active before geoMap was created, initialize now
        var mapTab = document.getElementById("tab-map");
        if (mapTab && mapTab.classList.contains("active")) {
            this.geoMap.init();
            this.geoMap.invalidateSize();
        }
    }
};

/* -- Tab Navigation --------------------------------------------- */

// PR-34 (cog review §7.1): per-tab scroll-position persistence.
// Operators frequently jump deep into the Bluetooth / Nodes / Alerts
// tables and ack/inspect entries by hopping to a sibling tab — the
// pre-fix behaviour was that returning lands at the top, forcing a
// rescroll. We checkpoint the scroll offset of the leaving tab into
// localStorage and restore it on re-entry via rAF (DOM needs a tick
// to layout the newly-activated panel before scrollTop is honoured).
//
// Resilience: tab-content panels themselves are usually not the
// scrolling container — the page scrolls. We probe a panel-local
// scroll first (in case CSS later moves it inside) and fall back to
// document.documentElement.scrollTop. localStorage I/O is wrapped
// in try/catch — private/incognito modes reject writes and we must
// not let that break tab switching.
BridgeDashboard.prototype._tabScrollKey = function(tabName) {
    return "bridge_tab_scroll_" + tabName;
};

BridgeDashboard.prototype._getTabScrollContainer = function(tabEl) {
    if (tabEl && tabEl.scrollHeight > tabEl.clientHeight + 4) return tabEl;
    return document.scrollingElement || document.documentElement;
};

BridgeDashboard.prototype._saveTabScroll = function(tabName) {
    if (!tabName) return;
    try {
        var prev = document.getElementById("tab-" + tabName);
        if (!prev) return;
        var container = this._getTabScrollContainer(prev);
        var offset = container ? (container.scrollTop || 0) : 0;
        localStorage.setItem(this._tabScrollKey(tabName), String(offset));
    } catch (_) { /* private-mode storage refusal — ignore */ }
};

BridgeDashboard.prototype._restoreTabScroll = function(tabName) {
    var s = this;
    if (!tabName) return;
    var raw;
    try { raw = localStorage.getItem(this._tabScrollKey(tabName)); } catch (_) { return; }
    if (raw == null) return;
    var target = parseInt(raw, 10);
    if (!isFinite(target) || target <= 0) return;
    // Wait one frame so the new tab's contents have been laid out;
    // honour the offset only if there is enough scrollable height
    // (avoids snapping to a useless 0 on a near-empty tab).
    requestAnimationFrame(function() {
        var next = document.getElementById("tab-" + tabName);
        if (!next) return;
        var container = s._getTabScrollContainer(next);
        if (!container) return;
        var maxScroll = (container.scrollHeight || 0) - (container.clientHeight || 0);
        if (maxScroll <= 0) return;
        container.scrollTop = Math.min(target, maxScroll);
    });
};

BridgeDashboard.prototype.activateTab = function(tabName) {
    var s = this;
    var knownTab = Array.from(document.querySelectorAll("#dashboard-tabs .tab-btn")).some(function(button) { return button.getAttribute("data-tab") === tabName; });
    if (!knownTab || !s.isTabAvailable(tabName)) tabName = "summary";
    // PR-34: checkpoint scroll of the tab we are leaving before its
    // .active class is stripped (active=display:none would zero the
    // scrollTop on the next read).
    var prevTab = readBrowserPreference("bridge_active_tab");
    if (prevTab && prevTab !== tabName) s._saveTabScroll(prevTab);
    var btns = document.querySelectorAll("#dashboard-tabs .tab-btn");
    var tabs = document.querySelectorAll(".tab-content");

    btns.forEach(function(b) {
        var isActive = b.getAttribute("data-tab") === tabName;
        b.classList.toggle("active", isActive);
        b.setAttribute("aria-selected", isActive ? "true" : "false");
    });
    tabs.forEach(function(t) {
        t.classList.toggle("active", t.id === "tab-" + tabName);
    });
    try { writeBrowserPreference("bridge_active_tab", tabName); } catch (_) {}
    // PR-34: restore scroll for the just-activated tab.
    s._restoreTabScroll(tabName);

    // Activate/deactivate panels based on active tab to avoid rate-limit saturation
    if (s.detectionDashboard) {
        if (tabName === "rf") s.detectionDashboard.activate(); else s.detectionDashboard.deactivate();
    }
    if (s.wifiPanel) {
        if (tabName === "wifi") s.wifiPanel.activate(); else s.wifiPanel.deactivate();
    }
    if (s.btPanel) {
        if (tabName === "bluetooth") s.btPanel.activate(); else s.btPanel.deactivate();
    }
    if (s.zigbeePanel) {
        if (tabName === "zigbee") s.zigbeePanel.activate(); else s.zigbeePanel.deactivate();
    }
    if (s.tdoaView) {
        if (tabName === "rf") s.tdoaView.start(); else s.tdoaView.stop();
    }
    if (s.alertsDashboard) {
        if (tabName === "alerts") s.alertsDashboard.activate(); else if (s.alertsDashboard._active) s.alertsDashboard.deactivate();
    }
    if (tabName === "map" && s.geoMap) {
        s.geoMap.init();
        s.geoMap.invalidateSize();
    }
    if (tabName === "map" && typeof activateMapPanel === "function") {
        activateMapPanel();
    }
    if (tabName !== "map" && typeof deactivateMapPanel === "function") {
        deactivateMapPanel();
    }
    if (tabName === "adsb" && window._adsbMapInvalidate) {
        window._adsbMapInvalidate();
    }
};

BridgeDashboard.prototype.isTabAvailable = function(tabName) {
    return this.scannerAvailability.available(tabName);
};

BridgeDashboard.prototype._updateScannerTabs = function() {
    var self = this;
    document.querySelectorAll("#dashboard-tabs .tab-btn").forEach(function(button) {
        var available = self.isTabAvailable(button.getAttribute("data-tab"));
        button.hidden = !available;
        button.disabled = !available;
        button.setAttribute("aria-disabled", available ? "false" : "true");
    });
    // The same server-issued leases govern protocol metrics and navigation.
    // Generic health and stored history remain accessible without a scanner.
    var protocols = self.scannerAvailability.protocolsFor();
    document.querySelectorAll("[data-scanner-section]").forEach(function(section) {
        section.hidden = protocols.indexOf(section.getAttribute("data-scanner-section")) === -1;
    });
    var current = document.querySelector("#dashboard-tabs .tab-btn.active");
    if (current && !self.isTabAvailable(current.getAttribute("data-tab"))) self.activateTab("summary");
    self._renderScannerWarnings();
};

BridgeDashboard.prototype._renderScannerWarnings = function() {
    var region = document.getElementById("scanner-warning"), list = document.getElementById("scanner-warning-list");
    if (!region || !list) return;
    // A scanner that has just started is not a problem yet.
    var problems = this.scannerAvailability.problems().filter(function(problem) { return problem.reason !== "starting"; });
    var labels = {error: "Capture error reported", stopped: "Scanner stopped", expired: "Scanner not reporting",
        sensor_absent: "Sensor not connected", sensor_changed: "Different sensor connected", sensor_unusable: "Sensor cannot be opened"};
    var guidance = {
        error: "Check scanner logs, adapter connection and device permissions. Retry only this scanner after the cause is fixed.",
        stopped: "If capture is intended, start this scanner using its saved configuration.",
        expired: "Check the scanner service and its connection to the dashboard. A node heartbeat alone does not confirm capture."
    };
    var items = problems.map(function(problem) {
        var name = ScannerAvailability.LABELS[problem.protocol];
        // A sensor reason has its own advice; any other keeps the state's.
        var advice = ScannerAvailability.guidance(problem.reason, problem.protocol);
        var kind = advice ? problem.reason : problem.state;
        // An expired scanner sent nothing since; a failing one keeps reporting
        // the same status, and this is the report the warning was shown from.
        return {text: '<li><strong>' + esc(problem.node) + ' · ' + esc(name) + ' — ' + labels[kind] + '</strong>. ' +
            esc(advice || guidance[kind]) + (problem.state === "expired" ? ' Last status report: ' : ' Status reported at: '),
            time: esc(new Date(problem.timestamp).toISOString())};
    });
    // Avoid repeating a screen-reader announcement for unchanged poll results.
    // A failing scanner reports again every 30 seconds, so the report time is
    // left out of the comparison: the list is rewritten only when a warning
    // itself changes. Compared with the markup last written, not
    // list.innerHTML: the browser serialises an escaped quote back as a
    // literal one, so that never matches.
    var key = items.map(function(item) { return item.text; }).join("");
    if (this._scannerWarningsKey !== key) {
        list.innerHTML = items.map(function(item) { return item.text + item.time + '.</li>'; }).join("");
        this._scannerWarningsKey = key;
    }
    region.hidden = problems.length === 0;
};

BridgeDashboard.prototype._initTabs = function() {
    var s = this;
    var saved = readBrowserPreference("bridge_active_tab") || "summary";
    var btns = document.querySelectorAll("#dashboard-tabs .tab-btn");
    var setupLink = document.getElementById("scanner-warning-setup");
    if (setupLink) setupLink.addEventListener("click", function() { s.activateTab("summary"); });

    btns.forEach(function(btn) {
        btn.addEventListener("click", function() {
            s.activateTab(btn.getAttribute("data-tab"));
        });
    });

    // Set initial tab visibility (panels will be activated in boot sequence after construction)
    s._updateScannerTabs();
    s.activateTab(saved);
};

/* -- Card Collapse/Expand --------------------------------------- */

BridgeDashboard.prototype._loadCollapsed = function() {
    try { var s = localStorage.getItem("bridge_collapsed"); this.collapsed = s ? JSON.parse(s) : {}; } catch (_) { this.collapsed = {}; }
};

BridgeDashboard.prototype._saveCollapsed = function() {
    try { localStorage.setItem("bridge_collapsed", JSON.stringify(this.collapsed)); } catch (_) {}
};

BridgeDashboard.prototype._initCards = function() {
    var s = this;
    document.querySelectorAll("[data-collapse]").forEach(function(hdr) {
        var key = hdr.getAttribute("data-collapse"), card = hdr.closest(".card");
        if (!card) return;
        if (s.collapsed[key]) card.classList.add("collapsed");
        hdr.addEventListener("click", function() {
            var is = card.classList.toggle("collapsed");
            s.collapsed[key] = is;
            s._saveCollapsed();
        });
    });
};

/* -- Active Freq Time Range ------------------------------------- */

BridgeDashboard.prototype._initFreqRange = function() {
    var s = this;
    var btns = document.querySelectorAll("[data-freq-range]");
    btns.forEach(function(btn) {
        btn.addEventListener("click", function(e) {
            e.stopPropagation();
            btns.forEach(function(b) { b.classList.remove("active"); });
            btn.classList.add("active");
            s.activeFreqHours = parseInt(btn.getAttribute("data-freq-range"), 10) || 1;
            s._pollStatus();
        });
    });
};

/* -- Auth Guard ------------------------------------------------- */

BridgeDashboard.prototype._initAuthGuard = function() {
    var s = this;
    var logoutBtn = document.getElementById("logout-btn");
    if (logoutBtn) logoutBtn.addEventListener("click", function() { s._logout(); });

    // Show app content — the inline guard script already redirected if no creds
    var appContent = document.getElementById("app-content");
    if (appContent) appContent.style.display = "";

    // New tabs can have a valid HttpOnly session without a JS-readable
    // token. Show the same account controls for that cookie session.
    if (s.sessionToken || s._cookieAuth) {
        s._fetchUserInfo();
        var lb = document.getElementById("logout-btn");
        if (lb) lb.style.display = "";
    }
    if (s.apiKey) {
        var lb = document.getElementById("logout-btn");
        if (lb) lb.style.display = "";
    }
};

/* The server no longer accepts this page's credential (a 401: the session
   expired or was signed out in another tab, or the key was revoked). Forget
   the stored credential and go to sign-in once, coming back to this page
   afterwards, as the admin page does. Never throws: apiFetch still rejects
   with "Unauthorized" for its caller. */
BridgeDashboard.prototype._showAuth = function() {
    if (this._signInPending) return;
    this._signInPending = true;
    try {
        sessionStorage.removeItem("bridge_session_token");
        sessionStorage.removeItem("bridge_api_key");
    } catch (_) {}
    try {
        window.location.replace("/login?next=" + encodeURIComponent(window.location.pathname || "/"));
    } catch (_) {}
};

BridgeDashboard.prototype._logout = function() {
    var self = this;
    if (self._logoutPending) return;
    var button = document.getElementById("logout-btn");
    function finish() {
        self.sessionToken = "";
        self.sessionUser = null;
        self.apiKey = "";
        self._cookieAuth = false;
        sessionStorage.removeItem("bridge_session_token");
        sessionStorage.removeItem("bridge_api_key");
        // Close WS connections only after the server session is revoked.
        for (var k in self.wsConns) {
            if (self.wsConns[k]) { try { self.wsConns[k].close(); } catch(_) {} }
            self.wsConns[k] = null;
        }
        window.location.replace("/login");
    }
    if (!self.sessionToken && !self._cookieAuth) { finish(); return; }

    self._logoutPending = true;
    if (button) button.disabled = true;
    var headers = { "Accept": "application/json" };
    if (self.sessionToken) headers["Authorization"] = "Bearer " + self.sessionToken;
    var csrf = (document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/) || [])[1];
    if (csrf) headers["X-CSRF-Token"] = csrf;
    return fetch("/api/auth/logout", {
        method: "POST", headers: headers, credentials: "same-origin"
    }).then(function(response) {
        // An expired session is already signed out. Every other failure must
        // remain visible instead of pretending that the cookie was revoked.
        if (!response.ok && response.status !== 401) throw new Error("Logout failed");
        finish();
    }).catch(function() {
        self._logoutPending = false;
        if (button) button.disabled = false;
        showToast("Could not sign out. Please try again.", "error");
    });
};

BridgeDashboard.prototype._fetchUserInfo = function() {
    var self = this;
    self.apiFetch("/api/auth/me").then(function(data) {
        if (data && data.username) {
            self.sessionUser = data;
            self._showUserInfo(data);
        }
    }).catch(function() {});
};

BridgeDashboard.prototype._showUserInfo = function(user) {
    var info = document.getElementById("user-info");
    var nameEl = document.getElementById("user-display-name");
    var roleEl = document.getElementById("user-role");
    var logoutBtn = document.getElementById("logout-btn");
    var settingsBtn = document.getElementById("settings-btn");
    if (info) info.style.display = "";
    if (nameEl) nameEl.textContent = user.display_name || user.username || "";
    if (roleEl) roleEl.textContent = "(" + (user.role || "") + ")";
    if (logoutBtn) logoutBtn.style.display = "";
    if (settingsBtn) settingsBtn.style.display = "";
};

BridgeDashboard.prototype._hideUserInfo = function() {
    var info = document.getElementById("user-info");
    var logoutBtn = document.getElementById("logout-btn");
    var settingsBtn = document.getElementById("settings-btn");
    if (info) info.style.display = "none";
    if (logoutBtn) logoutBtn.style.display = "none";
    if (settingsBtn) settingsBtn.style.display = "none";
};

/* -- MFA Settings ----------------------------------------------- */

BridgeDashboard.prototype._initMFASettings = function() {
    var s = this;
    var btn = document.getElementById("settings-btn");
    var closeBtn = document.getElementById("mfa-settings-close");
    var overlay = document.getElementById("mfa-settings-overlay");
    if (btn) btn.addEventListener("click", function() { s._openMFASettings(); });
    if (closeBtn) closeBtn.addEventListener("click", function() { s._closeMFASettings(); });
    if (overlay) overlay.addEventListener("click", function(e) { if (e.target === this) s._closeMFASettings(); });
};

BridgeDashboard.prototype._openMFASettings = function() {
    var overlay = document.getElementById("mfa-settings-overlay");
    // PR-23: focus trap + scroll lock + return focus to settings btn.
    if (overlay) _openModal(overlay);
    this._loadMFAStatus();
};

BridgeDashboard.prototype._closeMFASettings = function() {
    var overlay = document.getElementById("mfa-settings-overlay");
    if (overlay) {
        if (_modalState.activeModal === overlay) {
            _closeActiveModal();
        } else {
            overlay.style.display = "none";
        }
    }
    // Reset UI state
    var setupSection = document.getElementById("mfa-setup-section");
    if (setupSection) setupSection.style.display = "none";
    var regenDisplay = document.getElementById("mfa-regen-codes-display");
    if (regenDisplay) regenDisplay.style.display = "none";
};

BridgeDashboard.prototype._loadMFAStatus = function() {
    var s = this;
    var loading = document.getElementById("mfa-loading");
    var content = document.getElementById("mfa-content");
    if (loading) loading.style.display = "";
    if (content) content.style.display = "none";

    s.apiFetch("/api/auth/me").then(function(data) {
        if (loading) loading.style.display = "none";
        if (content) content.style.display = "";
        s._renderMFAStatus(data);
    }).catch(function(err) {
        if (loading) loading.textContent = "Failed to load user info.";
    });
};

BridgeDashboard.prototype._renderMFAStatus = function(user) {
    var badge = document.getElementById("mfa-status-badge");
    var enableSection = document.getElementById("mfa-enable-section");
    var enabledSection = document.getElementById("mfa-enabled-section");
    var setupSection = document.getElementById("mfa-setup-section");
    var backupCount = document.getElementById("mfa-backup-count");
    var s = this;

    var mfaOn = user.mfa_enabled;

    if (badge) {
        badge.textContent = mfaOn ? "Enabled" : "Disabled";
        badge.style.background = mfaOn ? "rgba(0,200,100,0.2)" : "rgba(255,100,60,0.2)";
        badge.style.color = mfaOn ? "#00c864" : "#ff6b6b";
    }

    if (enableSection) enableSection.style.display = mfaOn ? "none" : "";
    if (enabledSection) enabledSection.style.display = mfaOn ? "" : "none";
    if (setupSection) setupSection.style.display = "none";
    if (backupCount) backupCount.textContent = (user.backup_codes_remaining != null) ? user.backup_codes_remaining : "--";

    // Wire enable button
    var enableBtn = document.getElementById("mfa-enable-btn");
    if (enableBtn) {
        enableBtn.onclick = function() { s._startMFASetup(); };
    }

    // Wire disable button
    var disableBtn = document.getElementById("mfa-disable-btn");
    if (disableBtn) {
        disableBtn.onclick = function() { s._disableMFA(); };
    }

    // Wire verify setup button
    var verifyBtn = document.getElementById("mfa-verify-setup-btn");
    if (verifyBtn) {
        verifyBtn.onclick = function() { s._verifyMFASetup(); };
    }

    // Wire regenerate button
    var regenBtn = document.getElementById("mfa-regen-codes-btn");
    if (regenBtn) {
        regenBtn.onclick = function() { s._regenBackupCodes(); };
    }

    // Enter key on verify input
    var verifyInput = document.getElementById("mfa-verify-code");
    if (verifyInput) {
        verifyInput.onkeydown = function(e) { if (e.key === "Enter") s._verifyMFASetup(); };
    }

    // Enter key on disable input
    var disableInput = document.getElementById("mfa-disable-code");
    if (disableInput) {
        disableInput.onkeydown = function(e) { if (e.key === "Enter") s._disableMFA(); };
    }

    // Clear error messages and inputs
    var setupErr = document.getElementById("mfa-setup-error");
    if (setupErr) setupErr.style.display = "none";
    var disableErr = document.getElementById("mfa-disable-error");
    if (disableErr) disableErr.style.display = "none";
    var regenDisplay = document.getElementById("mfa-regen-codes-display");
    if (regenDisplay) regenDisplay.style.display = "none";
    if (verifyInput) verifyInput.value = "";
    var disableCode = document.getElementById("mfa-disable-code");
    if (disableCode) disableCode.value = "";
};

BridgeDashboard.prototype._startMFASetup = function() {
    var s = this;
    var enableBtn = document.getElementById("mfa-enable-btn");
    if (enableBtn) enableBtn.disabled = true;

    s.apiFetch("/api/auth/mfa/setup", { method: "POST" }).then(function(data) {
        if (enableBtn) enableBtn.disabled = false;
        var enableSection = document.getElementById("mfa-enable-section");
        var setupSection = document.getElementById("mfa-setup-section");
        if (enableSection) enableSection.style.display = "none";
        if (setupSection) setupSection.style.display = "";

        var uriEl = document.getElementById("mfa-provisioning-uri");
        if (uriEl) uriEl.textContent = data.provisioning_uri;

        var secretEl = document.getElementById("mfa-secret-display");
        if (secretEl) secretEl.textContent = data.secret;

        var codesEl = document.getElementById("mfa-backup-codes-display");
        if (codesEl) {
            codesEl.innerHTML = "";
            for (var i = 0; i < data.backup_codes.length; i++) {
                var div = document.createElement("div");
                div.textContent = data.backup_codes[i];
                div.style.padding = "2px 0";
                codesEl.appendChild(div);
            }
        }

        var verifyInput = document.getElementById("mfa-verify-code");
        if (verifyInput) { verifyInput.value = ""; verifyInput.focus(); }
    }).catch(function(err) {
        if (enableBtn) enableBtn.disabled = false;
        var msg = (err && err.detail) ? err.detail : "Failed to start MFA setup.";
        alert(msg);
    });
};

BridgeDashboard.prototype._verifyMFASetup = function() {
    var s = this;
    var codeInput = document.getElementById("mfa-verify-code");
    var code = codeInput ? codeInput.value.trim() : "";
    if (code.length !== 6) {
        s._showMFAError("mfa-setup-error", "Enter a 6-digit code.");
        return;
    }

    var btn = document.getElementById("mfa-verify-setup-btn");
    if (btn) btn.disabled = true;

    s.apiFetch("/api/auth/mfa/verify-setup", {
        method: "POST",
        body: { totp_code: code },
        keepSessionOn401: true  // a 401 here is a wrong or reused code
    }).then(function(data) {
        if (btn) btn.disabled = false;
        // Refresh status to show enabled state
        s._loadMFAStatus();
    }).catch(function(err) {
        if (btn) btn.disabled = false;
        var msg = (err && err.detail) ? err.detail : "Verification failed. Try again.";
        s._showMFAError("mfa-setup-error", msg);
    });
};

BridgeDashboard.prototype._disableMFA = function() {
    var s = this;
    var codeInput = document.getElementById("mfa-disable-code");
    var code = codeInput ? codeInput.value.trim() : "";
    if (code.length === 0) {
        s._showMFAError("mfa-disable-error", "Enter a TOTP code to confirm.");
        return;
    }

    if (!confirm("Are you sure you want to disable MFA?")) return;

    var btn = document.getElementById("mfa-disable-btn");
    if (btn) btn.disabled = true;

    s.apiFetch("/api/auth/mfa/disable", {
        method: "POST",
        body: { totp_code: code },
        keepSessionOn401: true  // a 401 here is a wrong or reused code
    }).then(function(data) {
        if (btn) btn.disabled = false;
        s._loadMFAStatus();
    }).catch(function(err) {
        if (btn) btn.disabled = false;
        var msg = (err && err.detail) ? err.detail : "Failed to disable MFA.";
        s._showMFAError("mfa-disable-error", msg);
    });
};

BridgeDashboard.prototype._regenBackupCodes = function() {
    var s = this;
    if (!confirm("This will invalidate all existing backup codes and generate new ones. Continue?")) return;

    var code = prompt("Enter your current 6-digit TOTP code to regenerate backup codes:");
    if (!code || code.trim().length === 0) return;
    code = code.trim();

    var btn = document.getElementById("mfa-regen-codes-btn");
    if (btn) btn.disabled = true;

    s.apiFetch("/api/auth/mfa/regenerate-backup-codes", {
        method: "POST",
        body: { totp_code: code },
        keepSessionOn401: true  // a 401 here is a wrong or reused code
    }).then(function(data) {
        if (btn) btn.disabled = false;
        var regenDisplay = document.getElementById("mfa-regen-codes-display");
        if (regenDisplay) {
            regenDisplay.style.display = "";
            regenDisplay.innerHTML = "";
            for (var i = 0; i < data.backup_codes.length; i++) {
                var div = document.createElement("div");
                div.textContent = data.backup_codes[i];
                div.style.padding = "2px 0";
                regenDisplay.appendChild(div);
            }
        }
        var countEl = document.getElementById("mfa-backup-count");
        if (countEl) countEl.textContent = data.backup_codes_remaining;
    }).catch(function(err) {
        if (btn) btn.disabled = false;
        var msg = (err && err.detail) ? err.detail : "Failed to regenerate backup codes.";
        s._showMFAError("mfa-disable-error", msg);
    });
};

BridgeDashboard.prototype._showMFAError = function(elemId, msg) {
    var el = document.getElementById(elemId);
    if (el) {
        el.textContent = msg;
        el.style.display = "";
    }
};

/* -- PR-23: Modal a11y helpers (ux P0-5) ------------------------ *
 * Focus trap + scroll lock + return-focus for all dashboard.js
 * modals. HTML already has role="dialog"/aria-modal="true"/
 * aria-labelledby per index.html:2357,2369,2381,2482,2501,2530,
 * 2567 (prior review). What was missing: focus capture on open,
 * Tab-cycle handler so focus doesn't leak to the underlying page,
 * body.overflow lock so the page doesn't scroll behind the modal,
 * and focus return on close.
 *
 * Stacking: _openModal closes any currently-open modal first, so
 * we only need to track a single active modal. The Escape handler
 * routes through _closeActiveModal() so it correctly returns focus
 * and unlocks scroll (previously it just set display:none).
 *
 * NOTE: external panels (detections.js deep-dive, node_compare.js)
 * own their own overlays. This helper is wired into the modals
 * defined and managed inside dashboard.js: modal-overlay, modal-
 * wide-overlay, mfa-settings-overlay, iq-capture-overlay.
 */

var _modalState = {
    activeModal: null,
    previousFocus: null,
    previousBodyOverflow: "",
};

function _modalFocusables(el) {
    // Visible, enabled, tabbable elements within the modal.
    var sel = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';
    var nodes = Array.prototype.slice.call(el.querySelectorAll(sel));
    return nodes.filter(function(n) {
        if (n.disabled) return false;
        // offsetParent is null for display:none/hidden subtrees (and
        // for position:fixed, but our modal buttons aren't fixed).
        if (n.offsetParent === null) return false;
        return true;
    });
}

function _openModal(el) {
    if (!el) return;
    // Stack guard: if another modal is open, close it first so we
    // only ever have one focus trap active. previousFocus is
    // captured from the still-current activeElement, which for a
    // chained open is the just-closed modal's trigger — not ideal
    // but better than dangling state.
    if (_modalState.activeModal && _modalState.activeModal !== el) {
        _closeActiveModal();
    }
    _modalState.previousFocus = document.activeElement;
    _modalState.previousBodyOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    el.style.display = "";
    el.removeAttribute("aria-hidden");
    _modalState.activeModal = el;

    // Focus first focusable element (or the modal itself as a
    // fallback so AT users land somewhere meaningful).
    var items = _modalFocusables(el);
    if (items.length) {
        items[0].focus();
    } else if (typeof el.focus === "function") {
        // Make the dialog focusable transiently so screen readers
        // anchor their cursor inside the modal.
        if (!el.hasAttribute("tabindex")) el.setAttribute("tabindex", "-1");
        el.focus();
    }

    var tabHandler = function(e) {
        if (e.key !== "Tab" || _modalState.activeModal !== el) return;
        var f = _modalFocusables(el);
        if (!f.length) { e.preventDefault(); return; }
        var first = f[0], last = f[f.length - 1];
        var ae = document.activeElement;
        if (e.shiftKey) {
            if (ae === first || !el.contains(ae)) {
                e.preventDefault();
                last.focus();
            }
        } else {
            if (ae === last || !el.contains(ae)) {
                e.preventDefault();
                first.focus();
            }
        }
    };
    document.addEventListener("keydown", tabHandler);
    el._modalCleanup = function() {
        document.removeEventListener("keydown", tabHandler);
    };
}

function _closeActiveModal() {
    var el = _modalState.activeModal;
    if (!el) return;
    if (el._modalCleanup) { el._modalCleanup(); delete el._modalCleanup; }
    el.style.display = "none";
    el.setAttribute("aria-hidden", "true");
    document.body.style.overflow = _modalState.previousBodyOverflow;
    var prev = _modalState.previousFocus;
    if (prev && typeof prev.focus === "function") {
        try { prev.focus(); } catch (_) { /* element detached */ }
    }
    _modalState.activeModal = null;
    _modalState.previousFocus = null;
    _modalState.previousBodyOverflow = "";
}

/* -- Modal ------------------------------------------------------ */

BridgeDashboard.prototype._initModal = function() {
    var s = this;
    var closeBtn = document.getElementById("modal-close");
    var overlay = document.getElementById("modal-overlay");
    if (closeBtn) closeBtn.addEventListener("click", function() { s._closeModal(); });
    if (overlay) overlay.addEventListener("click", function(e) { if (e.target === this) s._closeModal(); });

    // Global Escape key handler. Route through _closeActiveModal so
    // focus return + scroll-unlock happen for dashboard.js modals.
    // External overlays (deep-dive, node-compare) still fall back
    // to the legacy display:none toggle since they manage their
    // own a11y lifecycle.
    document.addEventListener("keydown", function(e) {
        if (e.key !== "Escape") return;
        if (_modalState.activeModal && _modalState.activeModal.style.display !== "none") {
            e.preventDefault();
            _closeActiveModal();
            return;
        }
        var overlays = ["mfa-settings-overlay", "deep-dive-overlay", "node-compare-overlay", "modal-wide-overlay", "modal-overlay", "iq-capture-overlay"];
        for (var i = 0; i < overlays.length; i++) {
            var ol = document.getElementById(overlays[i]);
            if (ol && ol.style.display !== "none") {
                ol.style.display = "none";
                return;
            }
        }
    });
};

BridgeDashboard.prototype._showModal = function(title, body) {
    setText("modal-title", title);
    var b = document.getElementById("modal-body");
    if (b) b.innerHTML = body;
    var o = document.getElementById("modal-overlay");
    if (o) _openModal(o);
};

BridgeDashboard.prototype._closeModal = function() {
    var o = document.getElementById("modal-overlay");
    if (!o) return;
    if (_modalState.activeModal === o) {
        _closeActiveModal();
    } else {
        // Defensive: modal was opened by legacy direct display
        // toggle. Just hide without triggering focus return.
        o.style.display = "none";
    }
};

/* -- Wide Modal ------------------------------------------------- */

BridgeDashboard.prototype._initWideModal = function() {
    var s = this;
    var closeBtn = document.getElementById("modal-wide-close");
    var overlay = document.getElementById("modal-wide-overlay");
    if (closeBtn) closeBtn.addEventListener("click", function() { s._closeWideModal(); });
    if (overlay) overlay.addEventListener("click", function(e) { if (e.target === this) s._closeWideModal(); });
};

BridgeDashboard.prototype._closeWideModal = function() {
    var o = document.getElementById("modal-wide-overlay");
    if (!o) return;
    // PR-23: route through _closeActiveModal when this modal is the
    // active one so focus return + scroll-unlock + tab handler
    // cleanup all fire. Other callers that opened it via direct
    // display toggle still get a clean hide.
    if (_modalState.activeModal === o) {
        _closeActiveModal();
    } else {
        o.style.display = "none";
    }
};

BridgeDashboard.prototype._showWideModal = function() {
    // PR-23 helper for callers that want focus-trap semantics.
    // (No existing dashboard.js opener — kept as a thin entry point
    // for future migrations and to expose the trap to external
    // panels that currently set display directly.)
    var o = document.getElementById("modal-wide-overlay");
    if (o) _openModal(o);
};

/* -- Critical Banner -------------------------------------------- */
/* PR-7 (dashboard §5.2, §9.1, §9.2): coalesce bursts of critical
   alerts by (name, node_id) within a 60s window so we render
   "<name> × 5 (5 nodes)" instead of clobbering with the latest
   message. Persist seen IDs in localStorage for 30 min so a repeat
   fire is rendered with a muted "(seen 10m ago)" hint.            */

var _originalTitle = document.title;
var _criticalAlertCount = 0;
var _bannerCoalesceWindow = 60000;          // 60s coalescing window
var _bannerSeenWindow = 30 * 60 * 1000;     // 30 min "seen" memory
var _activeBannerEvents = [];               // [{id, name, nodeId, message, ts}]

var _seenCriticalIds = (function() {
    try {
        var raw = localStorage.getItem('bridge_seen_critical_ids');
        if (!raw) return new Map();
        return new Map(JSON.parse(raw));
    } catch (_) {
        return new Map();
    }
})();

function _persistSeenCriticalIds() {
    try {
        // Cap to last 100 entries to avoid unbounded growth.
        var entries = Array.from(_seenCriticalIds.entries()).slice(-100);
        localStorage.setItem('bridge_seen_critical_ids', JSON.stringify(entries));
    } catch (_) { /* private-browsing or quota; ignore */ }
}

function _pruneSeenCriticalIds() {
    var now = Date.now();
    var changed = false;
    _seenCriticalIds.forEach(function(ts, id) {
        if (now - ts > _bannerSeenWindow) {
            _seenCriticalIds.delete(id);
            changed = true;
        }
    });
    if (changed) _persistSeenCriticalIds();
}

function _humanAgo(ms) {
    var s = Math.max(1, Math.floor(ms / 1000));
    if (s < 60) return s + 's ago';
    var m = Math.floor(s / 60);
    if (m < 60) return m + 'm ago';
    var h = Math.floor(m / 60);
    return h + 'h ago';
}

function _composeBannerText() {
    if (_activeBannerEvents.length === 0) return '';
    // Group by (name) — count events, count distinct nodes.
    var groups = {};
    var order = [];
    for (var i = 0; i < _activeBannerEvents.length; i++) {
        var ev = _activeBannerEvents[i];
        var key = ev.name || ev.message || 'alert';
        if (!groups[key]) {
            groups[key] = { name: key, count: 0, nodes: {}, lastMessage: ev.message };
            order.push(key);
        }
        groups[key].count += 1;
        if (ev.nodeId) groups[key].nodes[ev.nodeId] = true;
        groups[key].lastMessage = ev.message;
    }
    var parts = [];
    for (var j = 0; j < order.length; j++) {
        var g = groups[order[j]];
        var nNodes = Object.keys(g.nodes).length;
        if (g.count > 1) {
            var nodeSuffix = nNodes > 0 ? ' (' + nNodes + ' node' + (nNodes === 1 ? '' : 's') + ')' : '';
            parts.push(g.name + ' × ' + g.count + nodeSuffix);
        } else {
            parts.push(g.lastMessage || g.name);
        }
    }
    return parts.join(' — ');
}

function showCriticalBanner(arg) {
    // Backward-compat: a bare-string call still works.
    var ev;
    if (typeof arg === 'string') {
        ev = { id: null, name: null, nodeId: null, message: arg };
    } else if (arg && typeof arg === 'object') {
        ev = {
            id: arg.id || null,
            name: arg.name || null,
            nodeId: arg.nodeId || arg.node_id || null,
            message: arg.message || ''
        };
    } else {
        return;
    }

    var banner = document.getElementById('critical-banner');
    var msg = document.getElementById('critical-banner-msg');
    if (!banner || !msg) return;

    var now = Date.now();

    // Prune older entries outside the coalesce window before appending.
    _activeBannerEvents = _activeBannerEvents.filter(function(e) {
        return (now - e.ts) <= _bannerCoalesceWindow;
    });

    ev.ts = now;
    _activeBannerEvents.push(ev);

    // Check repeat-seen status.
    _pruneSeenCriticalIds();
    var repeatHint = '';
    var isRepeat = false;
    if (ev.id && _seenCriticalIds.has(ev.id)) {
        var prevTs = _seenCriticalIds.get(ev.id);
        var ago = now - prevTs;
        if (ago <= _bannerSeenWindow) {
            repeatHint = ' (seen ' + _humanAgo(ago) + ')';
            isRepeat = true;
        }
    }
    if (ev.id) {
        _seenCriticalIds.set(ev.id, now);
        _persistSeenCriticalIds();
    }

    var text = _composeBannerText() + repeatHint;
    msg.textContent = text;
    banner.classList.remove('hidden');

    // Muted styling cue for repeat fires; CSS rule may not exist yet,
    // but adding the class is harmless and lets a future stylesheet hook in.
    if (isRepeat) {
        banner.classList.add('critical-banner-repeat');
    } else {
        banner.classList.remove('critical-banner-repeat');
    }

    _criticalAlertCount = (_criticalAlertCount || 0) + 1;
    updateTitleBadge();
}

function dismissCriticalBanner() {
    var banner = document.getElementById('critical-banner');
    if (banner) {
        banner.classList.add('hidden');
        banner.classList.remove('critical-banner-repeat');
    }
    _criticalAlertCount = 0;
    _activeBannerEvents = [];
    updateTitleBadge();
}

function updateTitleBadge() {
    if (_criticalAlertCount > 0) {
        document.title = '(' + _criticalAlertCount + ') ' + _originalTitle + ' — Critical Alert';
    } else {
        document.title = _originalTitle;
    }
}

/* Intentionally NOT resetting _criticalAlertCount on window focus
   (PR-7 / dashboard §9.2): the count is reset only by explicit
   acknowledgement via dismissCriticalBanner().                      */

/* -- IQ Capture Dialog ------------------------------------------ */

BridgeDashboard.prototype._initIQCaptureDialog = function() {
    var s = this;
    var closeBtn = document.getElementById("iq-capture-close");
    var cancelBtn = document.getElementById("iq-capture-cancel");
    var submitBtn = document.getElementById("iq-capture-submit");
    var overlay = document.getElementById("iq-capture-overlay");

    // PR-23: route close through the focus-trap helper when the
    // helper owns this modal; fall back to direct hide otherwise.
    var closeFn = function() {
        if (!overlay) return;
        if (_modalState.activeModal === overlay) {
            _closeActiveModal();
        } else {
            overlay.style.display = "none";
        }
    };
    if (closeBtn) closeBtn.addEventListener("click", closeFn);
    if (cancelBtn) cancelBtn.addEventListener("click", closeFn);
    if (overlay) overlay.addEventListener("click", function(e) { if (e.target === overlay) closeFn(); });
    if (submitBtn) submitBtn.addEventListener("click", function() { s._submitIQCapture(); });
};

BridgeDashboard.prototype._openIQCaptureDialog = function(nodeId, freqMhz, signalClass) {
    var overlay = document.getElementById("iq-capture-overlay");
    if (!overlay) return;
    // The class of the detection being captured, if any: the bridge tags
    // the capture with it, so a DMR / P25 / LoRa capture gets decoded.
    overlay.setAttribute("data-signal-class", signalClass || "");

    var nodeSelect = document.getElementById("iq-capture-node-id");
    var freqInput = document.getElementById("iq-capture-freq");
    var statusEl = document.getElementById("iq-capture-status");

    // Populate node dropdown from API
    var self = this;
    self.apiFetch("/api/nodes/").then(function(nodes) {
        if (!nodeSelect) return;
        var prev = nodeSelect.value;
        nodeSelect.innerHTML = "";
        (nodes || []).forEach(function(n) {
            if (n.status !== "active") return;
            var opt = document.createElement("option");
            opt.value = n.node_id;
            opt.textContent = n.node_id + " (" + n.host + ")";
            nodeSelect.appendChild(opt);
        });
        if (nodeId) nodeSelect.value = nodeId;
        else if (prev) nodeSelect.value = prev;
    }).catch(function() {
        // Fallback: add the provided nodeId if API fails (built as text)
        if (nodeSelect && nodeId) {
            nodeSelect.innerHTML = "";
            var fallback = document.createElement("option");
            fallback.value = nodeId;
            fallback.textContent = nodeId;
            nodeSelect.appendChild(fallback);
        }
    });

    if (freqMhz != null && freqInput) freqInput.value = freqMhz;
    if (statusEl) { statusEl.style.display = "none"; statusEl.textContent = ""; }

    // PR-23: open with focus trap + scroll lock + return focus.
    _openModal(overlay);
    // Override default first-focusable when no freq is preset, so
    // the user lands in the freq input rather than the close button.
    if (freqInput && freqMhz == null) freqInput.focus();
};

BridgeDashboard.prototype._submitIQCapture = function() {
    var nodeId = (document.getElementById("iq-capture-node-id") || {}).value;
    var freqMhz = parseFloat((document.getElementById("iq-capture-freq") || {}).value);
    var durationMs = parseInt((document.getElementById("iq-capture-duration") || {}).value, 10);
    var sampleRateMhz = parseFloat((document.getElementById("iq-capture-samplerate") || {}).value);
    var gainDb = parseFloat((document.getElementById("iq-capture-gain") || {}).value);
    var statusEl = document.getElementById("iq-capture-status");
    var overlay = document.getElementById("iq-capture-overlay");

    if (!nodeId) {
        if (statusEl) { statusEl.textContent = "Select a target node"; statusEl.style.display = ""; statusEl.style.color = "var(--accent-red)"; }
        return;
    }
    if (isNaN(freqMhz) || freqMhz <= 0) {
        if (statusEl) { statusEl.textContent = "Invalid frequency"; statusEl.style.display = ""; statusEl.style.color = "var(--accent-red)"; }
        return;
    }

    var payload = {
        freq_hz: freqMhz * 1e6,
        duration_ms: durationMs || 1000,
        sample_rate: (sampleRateMhz || 2.4) * 1e6
    };
    // Only send a gain when the operator typed one; an empty field means
    // "use the node's scan gain" (sending a fixed 40 cut HackRF ~48 dB low).
    if (gainDb != null && !isNaN(gainDb)) payload.gain_db = gainDb;
    var signalClass = overlay ? overlay.getAttribute("data-signal-class") : "";
    if (signalClass && /^[a-zA-Z0-9_\/.-]{1,128}$/.test(signalClass)) {
        payload.signal_class = signalClass;
    }

    var self = this;
    if (statusEl) { statusEl.textContent = "Queuing capture..."; statusEl.style.display = ""; statusEl.style.color = "var(--text-secondary)"; }

    self.apiFetch("/api/nodes/" + encodeURIComponent(nodeId) + "/capture", {
        method: "POST",
        body: payload
    }).then(function(data) {
        showToast("IQ capture queued for " + nodeId + " at " + freqMhz + " MHz", "success");
        // PR-23: dismiss through the helper to release focus trap.
        if (overlay) {
            if (_modalState.activeModal === overlay) {
                _closeActiveModal();
            } else {
                overlay.style.display = "none";
            }
        }
    }).catch(function(err) {
        var msg = (err && (err.detail || err.message)) || "Failed to queue capture";
        if (statusEl) { statusEl.textContent = msg; statusEl.style.color = "var(--accent-red)"; }
        showToast("IQ capture failed: " + msg, "error");
    });
};

/* -- Loading/Error State Helper --------------------------------- */

function setLoadingState(containerId, loading, error, retryFn) {
    var el = document.getElementById(containerId);
    if (!el) return;
    if (loading) {
        el.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div>Loading...</div>';
    } else if (error) {
        el.innerHTML = '<div class="error-state"><span class="error-icon">⚠</span><p>' + esc(error) + '</p>' + (retryFn ? '<button class="retry-btn">Retry</button>' : '') + '</div>';
        if (retryFn) {
            var btn = el.querySelector(".retry-btn");
            if (btn) {
                var fn = typeof retryFn === "function" ? retryFn : window[retryFn];
                if (fn) btn.addEventListener("click", function() { fn(); });
            }
        }
    }
}

/* ================================================================
   Cross-Panel Drill-Down Navigation
   ================================================================ */

window.drillDown = {
    /**
     * Switch to a tab by its data-tab name, using the same mechanism
     * as _initTabs.  Returns a promise that resolves after the tab
     * has rendered (150ms settle).
     */
    _switchTab: function(tabName) {
        var dashboard = window.dashboard;
        if (!dashboard || !dashboard.isTabAvailable(tabName)) {
            if (dashboard) dashboard.activateTab("summary");
            return Promise.resolve(false);
        }
        dashboard.activateTab(tabName);
        return new Promise(function(resolve) {
            // Let the permitted tab render before follow-up actions.
            setTimeout(function() { resolve(dashboard.isTabAvailable(tabName)); }, 180);
        });
    },

    /**
     * Briefly apply the drilldown-highlight class to an element,
     * scroll it into view, then remove the class when the animation ends.
     */
    _highlight: function(el) {
        if (!el) return;
        el.scrollIntoView({ block: "center", behavior: "smooth" });
        el.classList.add("drilldown-highlight");
        setTimeout(function() { el.classList.remove("drilldown-highlight"); }, 1800);
    },

    /**
     * Navigate to the Spectrum Analysis tab.  If freqHz is provided,
     * scroll to and highlight the band occupancy row whose frequency
     * range contains that frequency.
     */
    toSpectrum: function(freqHz) {
        var self = this;
        self._switchTab("spectrum-analysis").then(function(allowed) {
            if (!allowed) return;
            if (freqHz == null) return;
            var freqMhz = freqHz / 1e6;
            // Try to find and highlight the matching band row
            var tbody = document.getElementById("sa-bands-tbody");
            if (!tbody) return;
            var rows = tbody.querySelectorAll("tr");
            for (var i = 0; i < rows.length; i++) {
                var cells = rows[i].querySelectorAll("td");
                if (cells.length < 2) continue;
                // The Range column (index 1) has format "MIN - MAX MHz"
                var rangeText = cells[1].textContent || "";
                var match = rangeText.match(/([\d.]+)\s*-\s*([\d.]+)/);
                if (match) {
                    var minMhz = parseFloat(match[1]);
                    var maxMhz = parseFloat(match[2]);
                    if (freqMhz >= minMhz && freqMhz <= maxMhz) {
                        self._highlight(rows[i]);
                        return;
                    }
                }
            }
            // If no band row matched, highlight the band occupancy panel itself
            var panel = document.getElementById("panel-band-occupancy");
            if (panel) self._highlight(panel);
        });
    },

    /**
     * Navigate to the RF Intelligence tab, open the deep-dive overlay
     * for a specific detection ID.  Falls back to scrolling to the
     * anomaly queue if no matching detection is found.
     */
    toDetection: function(detectionId) {
        var self = this;
        self._switchTab("rf").then(function(allowed) {
            if (!allowed) return;
            if (!detectionId) return;
            // Look for the detection in the anomaly queue
            var dd = window.dashboard && window.dashboard.detectionDashboard;
            if (dd && dd.anomalies) {
                for (var i = 0; i < dd.anomalies.length; i++) {
                    var a = dd.anomalies[i];
                    if (String(a.detection_id) === String(detectionId) || String(a.id) === String(detectionId)) {
                        dd._showDeepDive(a);
                        return;
                    }
                }
            }
            // Fallback: scroll to anomaly queue
            var aq = document.getElementById("anomaly-queue");
            if (aq) self._highlight(aq);
        });
    },

    /**
     * Navigate to the RF Intelligence tab and filter the anomaly queue
     * to show only anomalies matching the given signal class.  Then
     * scroll to and highlight the first matching card.
     */
    toSignalClass: function(signalClass) {
        var self = this;
        self._switchTab("rf").then(function(allowed) {
            if (!allowed) return;
            if (!signalClass) return;
            var dd = window.dashboard && window.dashboard.detectionDashboard;
            if (dd) {
                // Apply client-side filter by signal_class
                var filterKeySel = document.getElementById("rf-anomaly-filter-key");
                var filterValSel = document.getElementById("rf-anomaly-filter-val");
                if (filterKeySel && filterValSel) {
                    filterKeySel.value = "signal_class";
                    filterKeySel.dispatchEvent(new Event("change"));
                    // Short delay to let the value dropdown populate
                    setTimeout(function() {
                        filterValSel.value = signalClass;
                        filterValSel.dispatchEvent(new Event("change"));
                        // Highlight the first anomaly card after re-render
                        setTimeout(function() {
                            var firstCard = document.querySelector("#anomaly-queue .anomaly-card");
                            if (firstCard) self._highlight(firstCard);
                        }, 100);
                    }, 80);
                    return;
                }
            }
            // Fallback: look for the signal class in the signal browser
            var sb = window.dashboard && window.dashboard.signalBrowser;
            if (sb && sb.classes) {
                var cls = sb.classes.find(function(c) { return c.class_name === signalClass; });
                if (cls) {
                    sb.selCls = signalClass;
                    sb._showViewer(signalClass);
                    return;
                }
            }
            var aq = document.getElementById("anomaly-queue");
            if (aq) self._highlight(aq);
        });
    },

    /**
     * Navigate to the Bluetooth tab and filter the device table
     * to show the device with the given MAC address.
     */
    toBluetooth: function(macAddr) {
        var self = this;
        self._switchTab("bluetooth").then(function(allowed) {
            if (!allowed) return;
            if (!macAddr) return;
            var bt = window.dashboard && window.dashboard.btPanel;
            // Use the manufacturer search input to filter to this MAC
            var searchInput = document.getElementById("bt-manufacturer-search");
            if (searchInput && bt) {
                searchInput.value = macAddr;
                bt.manufacturerSearch = macAddr.toLowerCase().trim();
                bt._renderDeviceTable(bt.devices);
            }
            // Highlight the matching row if found
            setTimeout(function() {
                var tbody = document.getElementById("bt-device-tbody");
                if (!tbody) return;
                var rows = tbody.querySelectorAll("tr");
                for (var i = 0; i < rows.length; i++) {
                    var text = rows[i].textContent || "";
                    if (text.toLowerCase().indexOf(macAddr.toLowerCase()) !== -1) {
                        self._highlight(rows[i]);
                        return;
                    }
                }
                // Fallback: highlight the entire table
                if (rows.length > 0) self._highlight(rows[0]);
            }, 100);
        });
    },

    /**
     * Navigate to the Summary tab and scroll to the Alerts panel,
     * optionally filtering by priority/severity.
     */
    toAlerts: function(priority) {
        var self = this;
        self._switchTab("summary").then(function(allowed) {
            if (!allowed) return;
            // Set the severity filter dropdown if a priority is given
            if (priority) {
                var filterSel = document.getElementById("alert-severity-filter");
                if (filterSel) {
                    filterSel.value = priority;
                    filterSel.dispatchEvent(new Event("change"));
                }
            }
            // Scroll to and highlight the alerts panel
            setTimeout(function() {
                var panel = document.getElementById("panel-alerts");
                if (panel) self._highlight(panel);
            }, 100);
        });
    }
};

/* -- Boot ------------------------------------------------------- */

document.addEventListener("DOMContentLoaded", function() {
    var dismissBtn = document.getElementById("critical-banner-dismiss");
    if (dismissBtn) dismissBtn.addEventListener("click", dismissCriticalBanner);

    window.dashboard = new BridgeDashboard();
    window._bridgeDashboard = window.dashboard;  // R1: expose for cross-module timeline events
    if (typeof DetectionDashboard === "function") {
        window.dashboard.detectionDashboard = new DetectionDashboard(window.dashboard);
    }
    if (typeof NodeComparison === "function") {
        window.dashboard.nodeComparison = new NodeComparison(window.dashboard);
    }
    if (typeof SpectrumViewer === "function") {
        window.dashboard.spectrumViewer = new SpectrumViewer(window.dashboard);
    }
    if (typeof SignalBrowser === "function") {
        window.dashboard.signalBrowser = new SignalBrowser(window.dashboard);
    }
    if (typeof WifiPanel === "function") {
        window.dashboard.wifiPanel = new WifiPanel(window.dashboard);
    }
    if (typeof BluetoothPanel === "function") {
        window.dashboard.btPanel = new BluetoothPanel(window.dashboard);
    }
    if (typeof ZigbeePanel === "function") {
        window.dashboard.zigbeePanel = new ZigbeePanel(window.dashboard);
    }
    if (typeof DeploymentPanel === "function") {
        window.dashboard.deploymentPanel = new DeploymentPanel(window.dashboard);
    }
    if (typeof AlertsDashboard === "function") {
        window.dashboard.alertsDashboard = new AlertsDashboard(window.dashboard);
    }

    // Activate the saved tab's panel now that all panels are constructed
    window.dashboard.activateTab(readBrowserPreference("bridge_active_tab") || "summary");
});
