/**
 * Admin Panel — Key, Node, Alert, Audit, and System Management
 *
 * Master-key-only admin interface with tab navigation and CRUD operations.
 * Security: All dynamic content is HTML-escaped. API key stored in sessionStorage.
 */
"use strict";

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

/* A /api/admin/keys row's Expires cell, from the server's reading of the
   stored expires_at, never this browser's date parser or time zone:
   effective_expires_at is the instant bridge auth applies (always with an
   offset, so a naive stored value is not read as local time), shown with its
   year; without one, a key bridge auth still rejects as `expired` has a
   stored value auth cannot parse, shown as stored (escaped); else "--".
   Whether the key is expired is also the server's verdict (`expired`). */
function fmtKeyExpiry(k) {
    var at = k.effective_expires_at;
    var when = typeof at === "string" ? new Date(at) : null;
    if (when && !isNaN(when.getTime())) {
        return esc(when.toLocaleString(undefined, { hour12: false, year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" }));
    }
    if (at == null && k.expired !== true) return "--";
    var stored = k.expires_at;
    return "<code>" + esc(typeof stored === "string" ? stored : JSON.stringify(stored)) + "</code>";
}

function fmtNum(n) {
    if (n == null) return "--";
    if (n >= 1000000) return (n / 1000000).toFixed(1) + "M";
    if (n >= 1000) return (n / 1000).toFixed(1) + "K";
    return esc(n);
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

function fmtUptime(seconds) {
    if (seconds == null || seconds < 0) return "--";
    var d = Math.floor(seconds / 86400);
    var h = Math.floor((seconds % 86400) / 3600);
    var m = Math.floor((seconds % 3600) / 60);
    var parts = [];
    if (d > 0) parts.push(d + "d");
    if (h > 0 || d > 0) parts.push(h + "h");
    parts.push(m + "m");
    return parts.join(" ");
}

/* -- Toast / notify shim ---------------------------------------- */
/* Non-blocking feedback also works on the standalone admin page, which
 * does not load dashboard.js. Use textContent for untrusted server details.
 */
function notify(msg, type) {
    if (typeof window.showToast === "function") {
        window.showToast(msg, type || "info");
        return;
    }
    var container = document.getElementById("toast-container");
    if (container) {
        var el = document.createElement("div");
        el.className = "toast toast-" + (type || "info");
        el.setAttribute("role", type === "error" ? "alert" : "status");
        el.textContent = msg;
        container.appendChild(el);
        setTimeout(function() {
            el.classList.add("toast-out");
            setTimeout(function() { if (el.parentNode) el.parentNode.removeChild(el); }, 250);
        }, 4000);
        while (container.children.length > 5) container.removeChild(container.firstChild);
        return;
    }
    if (type === "error") console.error(msg);
    else console.log(msg);
}

/* -- Modal Helper ----------------------------------------------- */
/* Reusable modal pattern for admin dialogs.
 * Replaces native prompt()/confirm() with accessible, themed modals.
 * See dashboard cognitive-review §2.4, §2.5, §11.1.
 */

var _adminModalStyleInjected = false;
function _injectAdminModalStyle() {
    if (_adminModalStyleInjected) return;
    _adminModalStyleInjected = true;
    var css = ""
        + ".admin-modal-backdrop { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 10001; display: flex; align-items: center; justify-content: center; }"
        + ".admin-modal { background: var(--bg-card, #1f1f1f); border: 1px solid var(--border, #444); border-radius: 8px; padding: 20px; max-width: 90vw; max-height: 90vh; overflow: auto; color: var(--text-primary, #eee); min-width: 320px; }"
        + ".admin-modal-title { font-size: 1.1em; font-weight: 600; margin-bottom: 12px; }"
        + ".admin-modal-body { margin-bottom: 16px; }"
        + ".admin-modal-buttons { display: flex; gap: 8px; justify-content: flex-end; }"
        + ".admin-modal-buttons button { padding: 8px 16px; min-height: 36px; border-radius: 4px; cursor: pointer; font: inherit; }"
        + ".admin-modal-buttons button.primary { background: var(--accent-blue, #4493f8); color: #fff; border: 1px solid var(--accent-blue, #4493f8); }"
        + ".admin-modal-buttons button.cancel { background: transparent; color: var(--text-primary, #eee); border: 1px solid var(--border, #444); }"
        + ".admin-modal-buttons button.destructive { background: var(--accent-red, #e5534b); color: #fff; border: 1px solid var(--accent-red, #e5534b); }"
        + ".admin-modal-buttons button:focus { outline: 2px solid var(--accent-blue, #4493f8); outline-offset: 2px; }"
        + ".admin-modal-buttons button[disabled] { opacity: 0.5; cursor: not-allowed; }"
        + ".admin-modal label { display: block; margin-bottom: 6px; font-weight: 500; }"
        + ".admin-modal input, .admin-modal select, .admin-modal textarea { width: 100%; padding: 8px; border-radius: 4px; border: 1px solid var(--border, #444); background: var(--bg-input, #0d1117); color: var(--text-primary, #eee); margin-bottom: 12px; font: inherit; box-sizing: border-box; }"
        + ".admin-modal textarea { font-family: monospace; resize: vertical; }"
        + ".admin-modal-error { color: var(--accent-red, #e5534b); font-size: 0.9em; margin-top: -8px; margin-bottom: 12px; white-space: pre-wrap; }"
        + ".admin-modal-hint { color: var(--text-secondary, #aaa); font-size: 0.85em; margin-top: -8px; margin-bottom: 12px; }";
    var style = document.createElement("style");
    style.setAttribute("data-admin-modal-style", "1");
    style.textContent = css;
    document.head.appendChild(style);
}

var _adminModalSeq = 0;

/**
 * Show a modal dialog.
 *
 * @param {Object} opts
 * @param {string} opts.title              Modal header text.
 * @param {string|Element} opts.body       HTML string OR a DOM element for the body.
 * @param {Array}  opts.buttons            [{ label, kind: 'primary'|'cancel'|'destructive', onClick: (close) => void }]
 * @param {Function} [opts.onShow]         Called with (bodyEl, closeFn) after mount.
 * @returns {Function} closeFn — call to dismiss programmatically.
 */
function showModal(opts) {
    _injectAdminModalStyle();
    opts = opts || {};
    var titleId = "admin-modal-title-" + (++_adminModalSeq);

    var prevFocus = document.activeElement;
    var prevOverflow = document.body.style.overflow;

    var backdrop = document.createElement("div");
    backdrop.className = "admin-modal-backdrop";

    var modal = document.createElement("div");
    modal.className = "admin-modal";
    modal.setAttribute("role", "dialog");
    modal.setAttribute("aria-modal", "true");
    modal.setAttribute("aria-labelledby", titleId);

    var titleEl = document.createElement("div");
    titleEl.className = "admin-modal-title";
    titleEl.id = titleId;
    titleEl.textContent = opts.title || "";
    modal.appendChild(titleEl);

    var bodyEl = document.createElement("div");
    bodyEl.className = "admin-modal-body";
    if (opts.body instanceof Element) {
        bodyEl.appendChild(opts.body);
    } else if (typeof opts.body === "string") {
        bodyEl.innerHTML = opts.body;
    }
    modal.appendChild(bodyEl);

    var btnRow = document.createElement("div");
    btnRow.className = "admin-modal-buttons";
    modal.appendChild(btnRow);

    backdrop.appendChild(modal);

    var closed = false;
    function close() {
        if (closed) return;
        closed = true;
        document.removeEventListener("keydown", onKeyDown, true);
        if (backdrop.parentNode) backdrop.parentNode.removeChild(backdrop);
        document.body.style.overflow = prevOverflow;
        try { if (prevFocus && typeof prevFocus.focus === "function") prevFocus.focus(); } catch (_) {}
    }

    var buttons = opts.buttons || [{ label: "OK", kind: "primary", onClick: function(c) { c(); } }];
    buttons.forEach(function(b) {
        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = b.kind || "cancel";
        btn.textContent = b.label;
        btn.addEventListener("click", function() {
            try { (b.onClick || function(c) { c(); })(close); }
            catch (err) { close(); throw err; }
        });
        btnRow.appendChild(btn);
    });

    function getFocusable() {
        return modal.querySelectorAll(
            'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
        );
    }

    // Escape and a click outside dismiss the dialog unless opts.canDismiss()
    // says no (e.g. a one-time secret not yet acknowledged).
    function dismiss() {
        if (typeof opts.canDismiss === "function" && !opts.canDismiss()) return;
        close();
    }

    function onKeyDown(e) {
        if (e.key === "Escape") {
            e.preventDefault();
            dismiss();
            return;
        }
        if (e.key === "Tab") {
            var f = getFocusable();
            if (!f.length) { e.preventDefault(); return; }
            var first = f[0], last = f[f.length - 1];
            if (e.shiftKey && document.activeElement === first) {
                e.preventDefault();
                last.focus();
            } else if (!e.shiftKey && document.activeElement === last) {
                e.preventDefault();
                first.focus();
            }
        }
    }

    backdrop.addEventListener("mousedown", function(e) {
        if (e.target === backdrop) dismiss();
    });
    document.addEventListener("keydown", onKeyDown, true);

    document.body.style.overflow = "hidden";
    document.body.appendChild(backdrop);

    // Default focus: first focusable element in body, else first button.
    var focusables = getFocusable();
    var bodyFocusables = bodyEl.querySelectorAll(
        'input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled])'
    );
    if (bodyFocusables.length) {
        try { bodyFocusables[0].focus(); } catch (_) {}
    } else if (focusables.length) {
        try { focusables[0].focus(); } catch (_) {}
    }

    if (typeof opts.onShow === "function") {
        try { opts.onShow(bodyEl, close); } catch (_) {}
    }

    return close;
}

/**
 * Promise-returning confirm dialog built on showModal().
 * Resolves with true if the primary/destructive button was clicked, false otherwise
 * (including backdrop click and Escape).
 *
 * @param {Object} opts
 * @param {string} opts.title
 * @param {string} opts.message
 * @param {string} [opts.confirmLabel="OK"]
 * @param {string} [opts.cancelLabel="Cancel"]
 * @param {boolean} [opts.destructive=false]   Use destructive (red) styling for the confirm button.
 * @returns {Promise<boolean>}
 */
function confirmModal(opts) {
    opts = opts || {};
    return new Promise(function(resolve) {
        var resolved = false;
        function done(v) { if (!resolved) { resolved = true; resolve(v); } }

        var body = document.createElement("div");
        body.style.whiteSpace = "pre-wrap";
        body.textContent = opts.message || "";

        var close = showModal({
            title: opts.title || "Confirm",
            body: body,
            buttons: [
                { label: opts.cancelLabel || "Cancel", kind: "cancel", onClick: function(c) { done(false); c(); } },
                {
                    label: opts.confirmLabel || "OK",
                    kind: opts.destructive ? "destructive" : "primary",
                    onClick: function(c) { done(true); c(); }
                }
            ]
        });
        // Wrap close so backdrop/Escape dismissals also resolve false.
        var origClose = close;
        var wrapper = function() { done(false); origClose(); };
        // Hook into the backdrop: showModal's own backdrop/Escape calls origClose directly;
        // those resolve false because the buttons never ran. We just need to ensure resolve fires.
        // To do that, we observe the backdrop element by polling once via a MutationObserver alternative:
        var obs = new MutationObserver(function(records, observer) {
            // When the backdrop is removed from the DOM, resolve(false) if not yet resolved.
            for (var i = 0; i < records.length; i++) {
                var r = records[i];
                for (var j = 0; j < r.removedNodes.length; j++) {
                    var n = r.removedNodes[j];
                    if (n && n.classList && n.classList.contains("admin-modal-backdrop")) {
                        done(false);
                        observer.disconnect();
                        return;
                    }
                }
            }
        });
        obs.observe(document.body, { childList: true });
        // Safety: also resolve after a long timeout if observer somehow misses.
        // (Not strictly needed — modals always remove their backdrop.)
        void wrapper;
    });
}

function AdminPanel() {
    this.apiKey = sessionStorage.getItem("bridge_admin_key") || sessionStorage.getItem("bridge_api_key") || "";
    this.authenticated = false;
    this.auditOffset = 0;
    this.auditLimit = 50;
    this._metricsInterval = null;
    this._logAutoInterval = null;

    // Show app content — the inline guard script already redirected if no creds
    var appContent = document.getElementById("app-content");
    if (appContent) appContent.style.display = "";

    this._initTabs();
    this._tryAuth();
}

/* -- API Fetch -------------------------------------------------- */

/* opts.keepSessionOn403: the server refuses this one action with 403 for a
   reason of its own (the role ceiling, the master key), not because the
   session ended, so the page reports it instead of signing out. Every
   other 401 or 403 sends the operator to sign-in. */
AdminPanel.prototype.apiFetch = function(path, opts) {
    var self = this;
    opts = opts || {};
    var keepSessionOn403 = !!opts.keepSessionOn403;
    delete opts.keepSessionOn403;
    var h = opts.headers || {};
    h["Accept"] = "application/json";
    if (opts.body && typeof opts.body === "object" && !(opts.body instanceof FormData)) {
        h["Content-Type"] = "application/json";
        opts.body = JSON.stringify(opts.body);
    }
    if (self.apiKey) h["X-API-Key"] = self.apiKey;
    var sessionToken = sessionStorage.getItem("bridge_session_token");
    if (sessionToken && !self.apiKey) h["X-Session-Token"] = sessionToken;
    opts.headers = h;
    opts.credentials = "same-origin";
    return fetch(path, opts).then(function(r) {
        // PR-32 (dashboard cog review §11.5): capture session expiry from any
        // authenticated response so we can render "expires in N min" without
        // an extra round-trip. dependencies.py:498 sets this header.
        try {
            var expHdr = r.headers.get("X-Session-Expires-In");
            if (expHdr != null) {
                var remaining = parseInt(expHdr, 10);
                if (!isNaN(remaining)) {
                    self._sessionExpiresAtMs = Date.now() + (remaining * 1000);
                    if (typeof self._updateAdminSessionInfo === "function") {
                        self._updateAdminSessionInfo();
                    }
                }
            }
        } catch (_) {}
        if (r.status === 401 || (r.status === 403 && !keepSessionOn403)) {
            // PR-32: flag the session as expired before the redirect so any
            // pending UI tick reflects the terminal state.
            self._sessionExpiresAtMs = 0;
            if (typeof self._renderSessionExpired === "function") {
                try { self._renderSessionExpired(); } catch (_) {}
            }
            sessionStorage.removeItem("bridge_admin_key");
            sessionStorage.removeItem("bridge_api_key");
            sessionStorage.removeItem("bridge_session_token");
            window.location.replace("/login?next=%2Fadmin");
            var denied = new Error("Unauthorized");
            denied.status = r.status;
            return Promise.reject(denied);
        }
        if (!r.ok) {
            // Preserve response metadata even when an error body is not JSON.
            // Only the read-only bootstrap decides whether to retry a request.
            var error = new Error("HTTP " + r.status);
            error.status = r.status;
            var retryAfter = r.headers.get("Retry-After") || "";
            if (r.status === 429 && /^[0-9]{1,2}$/.test(retryAfter)) {
                var seconds = Number(retryAfter);
                if (seconds >= 1 && seconds <= 60) error.retryAfter = seconds;
            }
            // Preserve actionable API explanations (for example, an incomplete
            // configuration restore). Callers render detail through esc/text;
            // malformed/non-JSON bodies retain the original HTTP failure.
            if ((r.headers.get("content-type") || "").indexOf("json") !== -1) {
                return r.json().then(function(body) {
                    if (body && typeof body.detail === "string") error.detail = body.detail;
                    return Promise.reject(error);
                }, function() { return Promise.reject(error); });
            }
            return Promise.reject(error);
        }
        if (r.status === 204) return null;
        return (r.headers.get("content-type") || "").indexOf("json") !== -1 ? r.json() : r;
    });
};

/* -- Auth ------------------------------------------------------- */

AdminPanel.prototype._setAuthStatus = function(message, canRetry) {
    var s = this;
    var status = document.getElementById("admin-status");
    if (status) {
        status.className = "connection-indicator " + (s.authenticated ? "connected" : "disconnected");
        var text = status.querySelector(".status-text");
        if (text) text.textContent = message;
    }
    var retry = document.getElementById("admin-auth-retry");
    if (retry) {
        retry.hidden = !canRetry;
        // .btn has an explicit display value, so the UA's [hidden] rule alone
        // does not hide it. Keep the visual and accessibility states aligned.
        retry.style.display = canRetry ? "" : "none";
        // Assignment avoids accumulating handlers after repeated failures.
        retry.onclick = function() { s._tryAuth(false); };
    }
};

AdminPanel.prototype._tryAuth = function(retried) {
    var s = this;
    if (s.authenticated || s._authBusy || s._authRetryTimer) return s._authPromise;
    s._authBusy = true;
    s._setAuthStatus("Connecting to admin services...", false);
    s._authPromise = s.apiFetch("/api/admin/stats")
        .then(function() {
            s.authenticated = true;
            s._setAuthStatus("Authenticated", false);
            // PR-32 (dashboard cog review §11.5): fetch user info once
            // for the "Logged in as <user>" prefix, then start the 60s tick.
            s._fetchAdminUserInfo();
            s._startAdminSessionInfoTick();
            s._loadCurrentTab();
        })
        .catch(function(error) {
            // apiFetch already handles actual authentication/authorization
            // failures. Transient failures do not invalidate a session.
            if (error && (error.status === 401 || error.status === 403)) return;
            s.authenticated = false;
            if (error && error.status === 429 && error.retryAfter && !retried) {
                var seconds = error.retryAfter;
                s._setAuthStatus("Admin requests are rate limited. Retrying in " + seconds + " second" + (seconds === 1 ? "." : "s."), false);
                s._authRetryTimer = setTimeout(function() {
                    s._authRetryTimer = null;
                    s._tryAuth(true);
                }, seconds * 1000);
                return;
            }
            s._setAuthStatus("Admin connection unavailable. Please try again.", true);
        })
        .finally(function() {
            s._authBusy = false;
        });
    return s._authPromise;
};

/* -- Session Info (PR-32) --------------------------------------- */
/* Renders "Logged in as <user> — expires in N min" with a 60s tick.
 * Mirrors index.html's pattern; reads X-Session-Expires-In captured by
 * apiFetch (dependencies.py:498). When N < 5 the expiry text uses the
 * --accent-yellow warning color; on 401 (handled in apiFetch) the
 * session is marked expired and admin actions are disabled before the
 * login redirect. See dashboard cog review §11.5.
 */

AdminPanel.prototype._fetchAdminUserInfo = function() {
    var s = this;
    s.apiFetch("/api/auth/me").then(function(data) {
        if (data && (data.username || data.key_id)) {
            s._adminUser = data;
            s._updateAdminSessionInfo();
        }
    }).catch(function() {});
};

AdminPanel.prototype._startAdminSessionInfoTick = function() {
    var s = this;
    if (s._sessionInfoInterval) return;
    // 60s tick: recompute the "expires in N min" display from the
    // cached expiry timestamp. apiFetch refreshes the cache on every
    // authenticated response, so a separate /api/auth/me poll is only
    // needed when the user is idle. We poll /api/auth/me at most once
    // per 60s as a fallback to detect server-side invalidation.
    s._sessionInfoInterval = setInterval(function() {
        s._updateAdminSessionInfo();
        // Cheap fallback poll: if no apiFetch has refreshed the cache in
        // > 50s, ping /api/auth/me. This catches idle-tab session expiry.
        var stale = !s._sessionExpiresAtMs
            || (Date.now() - (s._sessionInfoLastRefresh || 0)) > 50000;
        if (stale && s.authenticated) {
            s._sessionInfoLastRefresh = Date.now();
            s.apiFetch("/api/auth/me").then(function(data) {
                if (data && (data.username || data.key_id)) {
                    s._adminUser = data;
                }
                s._updateAdminSessionInfo();
            }).catch(function() {});
        }
    }, 60000);
};

AdminPanel.prototype._updateAdminSessionInfo = function() {
    var s = this;
    var wrap = document.getElementById("admin-session-info");
    var userEl = document.getElementById("admin-session-user");
    var expEl = document.getElementById("admin-session-expiry");
    if (!wrap || !userEl || !expEl) return;

    // Build user label
    var userLabel = "";
    if (s._adminUser) {
        if (s._adminUser.auth_type === "session" && s._adminUser.username) {
            userLabel = "Logged in as " + s._adminUser.username;
        } else if (s._adminUser.auth_type === "api_key" && s._adminUser.key_id) {
            userLabel = "API key " + s._adminUser.key_id;
        }
    }
    userEl.textContent = userLabel;

    // Expiry countdown (session auth only; api_key has no expiry header)
    expEl.textContent = "";
    expEl.style.color = "";
    if (s._sessionExpiresAtMs) {
        var remainingSec = Math.floor((s._sessionExpiresAtMs - Date.now()) / 1000);
        if (remainingSec <= 0) {
            s._renderSessionExpired();
            return;
        }
        var minutes = Math.max(1, Math.round(remainingSec / 60));
        var label = "expires in " + minutes + " min";
        if (userLabel) expEl.textContent = "— " + label;
        else expEl.textContent = label;
        if (minutes < 5) {
            expEl.style.color = "var(--accent-yellow, #d4a72c)";
        }
    }

    wrap.style.display = (userLabel || expEl.textContent) ? "" : "none";
};

AdminPanel.prototype._renderSessionExpired = function() {
    var s = this;
    var wrap = document.getElementById("admin-session-info");
    var userEl = document.getElementById("admin-session-user");
    var expEl = document.getElementById("admin-session-expiry");
    if (wrap) wrap.style.display = "";
    if (userEl) userEl.textContent = "";
    if (expEl) {
        expEl.textContent = "Session expired — please log in again";
        expEl.style.color = "var(--accent-red, #e5534b)";
    }
    s.authenticated = false;
    // Disable admin action buttons during the brief window before redirect.
    var buttons = document.querySelectorAll(
        ".admin-tab-panel button, #system-maintenance button, .maint-task-btn"
    );
    for (var i = 0; i < buttons.length; i++) {
        try { buttons[i].disabled = true; } catch (_) {}
    }
};

/* -- Tab Navigation --------------------------------------------- */

AdminPanel.prototype._initTabs = function() {
    var s = this;
    document.querySelectorAll("[data-tab]").forEach(function(link) {
        link.addEventListener("click", function(e) {
            e.preventDefault();
            document.querySelectorAll("[data-tab]").forEach(function(l) { l.classList.remove("active"); });
            link.classList.add("active");
            document.querySelectorAll(".admin-tab-panel").forEach(function(p) { p.style.display = "none"; });
            var panel = document.getElementById("tab-" + link.getAttribute("data-tab"));
            if (panel) panel.style.display = "";
            window.location.hash = link.getAttribute("data-tab");
            s._loadCurrentTab();
        });
    });

    // Check URL hash: compared as text, never built into a selector.
    var hash = window.location.hash.replace("#", "");
    if (hash) {
        var links = document.querySelectorAll("[data-tab]");
        for (var i = 0; i < links.length; i++) {
            if (links[i].getAttribute("data-tab") === hash) { links[i].click(); break; }
        }
    }
};

AdminPanel.prototype._loadCurrentTab = function() {
    if (!this.authenticated) return;
    var active = document.querySelector("[data-tab].active");
    if (!active) return;
    var tab = active.getAttribute("data-tab");
    switch (tab) {
        case "keys": this._loadKeys(); this._loadCerts(); break;
        case "nodes": this._loadNodes(); break;
        case "alerts": this._loadAlerts(); break;
        case "training": this._loadTraining(); break;
        case "audit": this._loadAudit(); break;
        case "logs": this._loadLogs(); break;
        case "database": this._loadDatabase(); break;
        case "notifications": this._loadNotifications(); break;
        case "wifi-security": this._loadWifiSecurity(); break;
        case "system": this._loadSystem(); break;
        case "advanced": this._loadAdvanced(); break;
        case "reports": this._loadReports(); break;
        case "ml-advisor": this._loadMLAdvisor(); break;
        case "version": this._loadVersion(); break;
    }
};

/* -- Key Management --------------------------------------------- */

AdminPanel.prototype._loadKeys = function() {
    var s = this;
    var btn = document.getElementById("create-key-btn");
    if (btn && !btn._bound) {
        btn._bound = true;
        btn.addEventListener("click", function() { s._createKey(); });
    }

    return s.apiFetch("/api/admin/keys").then(function(keys) {
        s._renderKeys(keys);
    }).catch(function(e) {
        // A failed listing is not an empty key store: hide "No API keys" and
        // say why. 401/403 already sent the operator to the login page.
        var em = document.getElementById("keys-empty");
        if (em) em.style.display = "none";
        if (e && (e.status === 401 || e.status === 403)) return;
        notify("Could not load API keys: " + ((e && (e.detail || e.message)) || "Unknown error"), "error");
    });
};

/* -- Client Certificates (mTLS / PKI) --------------------------- */

AdminPanel.prototype._loadCerts = function() {
    var s = this;
    var btn = document.getElementById("mint-cert-btn");
    if (btn && !btn._bound) {
        btn._bound = true;
        btn.addEventListener("click", function() { s._mintCert(); });
    }

    return s.apiFetch("/api/ca/certs").then(function(certs) {
        s._renderCerts(certs);
    }).catch(function(e) {
        // 401/403 already sent the operator to the login page. Anything else
        // (e.g. a 503 for CA files that need an operator) is shown, not
        // presented as an empty certificate list.
        if (e && (e.status === 401 || e.status === 403)) return;
        notify("Could not load client certificates: " + ((e && (e.detail || e.message)) || "Unknown error"), "error");
    });
};

AdminPanel.prototype._renderCerts = function(certs) {
    var tb = document.getElementById("certs-tbody");
    var em = document.getElementById("certs-empty");
    if (!tb) return;
    if (!certs || !certs.length) { tb.innerHTML = ""; if (em) em.style.display = ""; return; }
    if (em) em.style.display = "none";

    var s = this, h = "";
    for (var i = 0; i < certs.length; i++) {
        var c = certs[i];
        var role = c.role || "node";
        var badge = "<span class=\"admin-badge " + esc(role) + "\">" + esc(role.toUpperCase()) + "</span>";
        var status, actions;
        if (c.revoked) {
            status = "<span class=\"admin-badge expired\">REVOKED</span>";
            actions = "--";
        } else if (c.not_after && new Date(c.not_after) < new Date()) {
            status = "<span class=\"admin-badge expired\">EXPIRED</span>";
            actions = "<button class=\"btn btn-sm btn-danger\" data-revoke-cert=\"" + esc(c.serial) + "\">Revoke</button>";
        } else {
            status = "<span class=\"admin-badge\">VALID</span>";
            actions = "<button class=\"btn btn-sm btn-danger\" data-revoke-cert=\"" + esc(c.serial) + "\">Revoke</button>";
        }
        h += "<tr><td data-label=\"Identity\"><code>" + esc(c.identity || "--") + "</code></td>"
            + "<td data-label=\"Role\">" + badge + "</td>"
            + "<td data-label=\"Serial\"><code>" + esc(String(c.serial || "").slice(0, 16)) + "</code></td>"
            + "<td data-label=\"Issued\">" + fmtTime(c.issued_at) + "</td>"
            + "<td data-label=\"Expires\">" + fmtTime(c.not_after) + "</td>"
            + "<td data-label=\"Status\">" + status + "</td>"
            + "<td data-label=\"Actions\">" + actions + "</td></tr>";
    }
    tb.innerHTML = h;

    tb.querySelectorAll("[data-revoke-cert]").forEach(function(b) {
        b.addEventListener("click", function() {
            var serial = this.getAttribute("data-revoke-cert");
            confirmModal({
                title: "Revoke client certificate",
                message: "Revoke certificate " + serial + "?\n\nThe agent using it loses access once the gateway refreshes its registry.",
                confirmLabel: "Revoke",
                destructive: true
            }).then(function(ok) {
                if (!ok) return;
                s.apiFetch("/api/ca/revoke/" + encodeURIComponent(serial), { method: "POST" })
                    .then(function() { s._loadCerts(); notify("Certificate revoked", "success"); })
                    .catch(function(e) { notify("Failed to revoke: " + (e.detail || e.message || "Unknown error"), "error"); });
            });
        });
    });
};

AdminPanel.prototype._mintCert = function() {
    var s = this;
    var idEl = document.getElementById("new-cert-identity");
    var roleEl = document.getElementById("new-cert-role");
    var ttlEl = document.getElementById("new-cert-ttl");
    var displayEl = document.getElementById("cert-minted-display");

    var identity = idEl ? idEl.value.trim() : "";
    if (!identity) { notify("Enter a certificate identity", "error"); return; }
    var role = roleEl ? roleEl.value : "node";
    var ttl = ttlEl ? parseInt(ttlEl.value, 10) : 90;
    if (!ttl || ttl < 1) ttl = 90;

    s.apiFetch("/api/ca/issue", {
        method: "POST",
        body: { identity: identity, role: role, ttl_days: ttl }
    }).then(function(d) {
        if (idEl) idEl.value = "";
        s._loadCerts();
        if (!displayEl) return;
        displayEl.style.display = "";
        displayEl.innerHTML =
            "<strong style=\"color:var(--accent-green);\">Certificate issued for "
            + esc(d.identity) + ".</strong> Download all three files now — "
            + "the private key is shown only once and is not stored by the bridge.<br>";
        // The cert, its key, and the CA cert — the agent needs all three.
        var files = [
            { label: "certificate", name: d.identity + ".crt", text: d.cert_pem },
            { label: "private key", name: d.identity + ".key", text: d.key_pem },
            { label: "CA certificate", name: "ca.crt", text: d.ca_pem }
        ];
        files.forEach(function(f) {
            var a = document.createElement("a");
            a.className = "btn btn-sm";
            a.style.marginRight = "8px";
            a.style.marginTop = "8px";
            a.textContent = "Download " + f.label;
            a.href = URL.createObjectURL(new Blob([f.text || ""], { type: "application/x-pem-file" }));
            a.download = f.name;
            displayEl.appendChild(a);
        });
        notify("Certificate issued for " + d.identity, "success");
    }).catch(function(e) {
        notify("Mint failed: " + (e.detail || e.message || "Unknown error"), "error");
    });
};

AdminPanel.prototype._renderKeys = function(keys) {
    var tb = document.getElementById("keys-tbody");
    var em = document.getElementById("keys-empty");
    if (!tb) return;
    if (!keys || !keys.length) { tb.innerHTML = ""; if (em) em.style.display = ""; return; }
    if (em) em.style.display = "none";

    var s = this, h = "";
    for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        var role = k.role || (k.is_master ? "admin" : "viewer");
        var roleCls = k.is_master ? "master" : role;
        var roleLabel = k.is_master ? "MASTER" : role.toUpperCase();
        var badge = "<span class=\"admin-badge " + esc(roleCls) + "\">" + esc(roleLabel) + "</span>";

        // EXPIRED when bridge auth rejects the key as expired: the server's
        // verdict, also for a stored expiry it cannot parse, and not this
        // browser's clock.
        var expiresStr = fmtKeyExpiry(k);
        if (k.expired === true) {
            expiresStr += " <span class=\"admin-badge expired\">EXPIRED</span>";
        }

        var actions = "";
        if (k.is_master) {
            actions = "--";
        } else {
            // Role change dropdown. A keymaster key (only a keymaster may
            // assign that role) shows its role too, not the first option.
            actions = "<select class=\"role-select-inline\" data-role-change=\"" + esc(k.key_id) + "\">"
                + (role === "keymaster" ? "<option value=\"keymaster\" selected>Keymaster</option>" : "")
                + "<option value=\"sensor\"" + (role === "sensor" ? " selected" : "") + ">Sensor</option>"
                + "<option value=\"node\"" + (role === "node" ? " selected" : "") + ">Node</option>"
                + "<option value=\"viewer\"" + (role === "viewer" ? " selected" : "") + ">Viewer</option>"
                + "<option value=\"analyst\"" + (role === "analyst" ? " selected" : "") + ">Analyst</option>"
                + "<option value=\"admin\"" + (role === "admin" ? " selected" : "") + ">Admin</option>"
                + "</select> "
                + "<button class=\"btn btn-sm\" data-rotate=\"" + esc(k.key_id) + "\" data-node=\"" + esc(k.node_id || "") + "\">Rotate</button> "
                + "<button class=\"btn btn-sm btn-danger\" data-revoke=\"" + esc(k.key_id) + "\">Revoke</button>";
        }

        var nodeCell = k.node_id ? "<code>" + esc(k.node_id) + "</code>" : "<span style=\"color:var(--text-secondary);\">--</span>";

        h += "<tr><td data-label=\"Key ID\"><code>" + esc(k.key_id) + "</code></td>"
            + "<td data-label=\"Role\">" + badge + "</td>"
            + "<td data-label=\"Node\">" + nodeCell + "</td>"
            + "<td data-label=\"Desc\">" + esc(k.description || "--") + "</td>"
            + "<td data-label=\"Created\">" + fmtTime(k.created_at) + "</td>"
            + "<td data-label=\"Expires\">" + expiresStr + "</td>"
            + "<td data-label=\"Actions\">" + actions + "</td></tr>";
    }
    tb.innerHTML = h;

    // Bind revoke buttons
    tb.querySelectorAll("[data-revoke]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var kid = this.getAttribute("data-revoke");
            confirmModal({
                title: "Revoke API key",
                message: "Revoke key " + kid + "?\n\nAny client using this key will immediately lose access.",
                confirmLabel: "Revoke",
                destructive: true
            }).then(function(ok) {
                if (!ok) return;
                s.apiFetch("/api/admin/keys/" + encodeURIComponent(kid), { method: "DELETE" })
                    .then(function() { s._loadKeys(); notify("Key " + kid + " revoked", "success"); })
                    .catch(function(e) { notify("Failed to revoke key: " + (e.detail || e.message || "Unknown error"), "error"); });
            });
        });
    });

    // Bind rotate buttons
    tb.querySelectorAll("[data-rotate]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var kid = this.getAttribute("data-rotate");
            var nodeId = this.getAttribute("data-node");
            s._rotateKey(kid, nodeId);
        });
    });

    // Bind role change dropdowns. A refused change is reported (a 403 here
    // is the server refusing that role or key, as the K5 role ceiling does,
    // not an ended session), and the select goes back to the role the
    // server still applies.
    tb.querySelectorAll("[data-role-change]").forEach(function(sel) {
        var applied = sel.value;
        sel.addEventListener("change", function() {
            var kid = this.getAttribute("data-role-change");
            var newRole = this.value;
            s.apiFetch("/api/admin/keys/" + encodeURIComponent(kid) + "/permissions", {
                method: "PUT",
                body: { role: newRole },
                keepSessionOn403: true
            }).then(function() {
                applied = newRole;
                s._loadKeys();
            }).catch(function(e) {
                sel.value = applied;
                if (e && e.status === 401) return;
                notify("Role change for " + kid + " failed: " + ((e && (e.detail || e.message)) || "Unknown error"), "error");
                s._loadKeys();
            });
        });
    });
};

AdminPanel.prototype._createKey = function() {
    var s = this;
    var descEl = document.getElementById("new-key-desc");
    var roleEl = document.getElementById("new-key-role");
    var expiresEl = document.getElementById("new-key-expires");
    var displayEl = document.getElementById("key-created-display");

    var desc = descEl ? descEl.value.trim() : "";
    var role = roleEl ? roleEl.value : "analyst";

    var body = { description: desc, role: role };
    // A blank expiry sends no expires_days: the key gets the server's
    // default lifetime (BRIDGE_MAX_KEY_LIFETIME_DAYS, which also caps a
    // longer request).  Anything else must be a whole number of days from 1
    // to the field's max (the API's limit): a typo such as -30 or 0 is
    // refused here, never sent as the default.  A number field reads "" for
    // text it cannot parse, so badInput tells such a typo from a blank field.
    var expiresRaw = expiresEl ? String(expiresEl.value == null ? "" : expiresEl.value).trim() : "";
    var unreadable = !!(expiresEl && expiresEl.validity && expiresEl.validity.badInput);
    if (expiresRaw !== "" || unreadable) {
        var maxDays = parseInt(expiresEl.getAttribute("max"), 10);
        var expiresDays = /^\d+$/.test(expiresRaw) ? parseInt(expiresRaw, 10) : 0;
        if (expiresDays < 1 || (maxDays > 0 && expiresDays > maxDays)) {
            notify("Key not created: expiry must be a whole number of days"
                + (maxDays > 0 ? " from 1 to " + maxDays : " of at least 1")
                + ", or blank for the default lifetime", "error");
            if (typeof expiresEl.focus === "function") expiresEl.focus();
            return;
        }
        body.expires_days = expiresDays;
    }

    s.apiFetch("/api/admin/keys", { method: "POST", body: body })
        .then(function(d) {
            // PR-12 (dashboard §4.2): reveal the raw key in a modal with copy +
            // acknowledgement gate. The inline displayEl now only shows a
            // confirmation that the key was created — the raw value is never
            // injected into the page DOM so it cannot linger after refresh.
            if (displayEl) {
                displayEl.style.display = "";
                displayEl.innerHTML = "<strong style=\"color:var(--accent-green);\">Key created.</strong>"
                    + " Key ID: <code>" + esc(d.key_id) + "</code>";
            }
            if (descEl) descEl.value = "";
            if (expiresEl) expiresEl.value = "";
            s._loadKeys();
            s._showRawKeyReveal({
                title: "API key created — save it now",
                keyId: d.key_id,
                rawKey: d.raw_key
            });
        })
        .catch(function(e) {
            notify("Key creation failed: " + (e.detail || e.message || "Unknown error"), "error");
        });
};

AdminPanel.prototype._rotateKey = function(keyId, nodeId) {
    var s = this;
    var resultEl = document.getElementById("key-rotate-result");

    // PR-11 (dashboard cog-review §4.1): tri-state rotate-key dialog.
    // Replaces a two-prompt confirm() chain whose Cancel-Cancel path silently
    // rotated without deploying — easy to land in by reflex, leaving the node
    // dead 30-60s later. The new flow uses one modal with three explicit
    // verbs so there is no implicit destructive default.
    s._chooseRotateAction(keyId, nodeId).then(function(action) {
        if (action === "cancel") return;
        var deployToNode = (action === "rotate-deploy");

        if (resultEl) {
            resultEl.style.display = "";
            resultEl.innerHTML = "<span style=\"color:var(--text-secondary);\">Rotating key"
                + (deployToNode ? " and deploying to " + esc(nodeId) : "") + "...</span>";
        }

        s.apiFetch("/api/admin/keys/" + encodeURIComponent(keyId) + "/rotate", {
            method: "POST",
            body: { deploy_to_node: deployToNode }
        }).then(function(d) {
            // PR-12 raw-key reveal (dashboard §4.2): show the new raw key in a
            // modal with copy + acknowledgement gate so it can be hidden after
            // confirmation. The dashboard table never displays the raw key —
            // the user must capture it now.
            s._showRawKeyReveal({
                title: "Key rotated — save the new key now",
                keyId: d.key_id,
                rawKey: d.raw_key,
                extraHtml: (function() {
                    if (d.deployed) {
                        return "<div style=\"margin-top:8px;color:var(--accent-green);\">Deployed to node <strong>"
                            + esc(d.deploy_node_id) + "</strong> (" + esc(d.deploy_host) + ")</div>";
                    }
                    if (d.deploy_error) {
                        return "<div style=\"margin-top:8px;color:var(--accent-red);\">Deploy failed: "
                            + esc(d.deploy_error) + "</div>"
                            + "<div style=\"margin-top:4px;\"><em>Update the node manually with the new key above.</em></div>";
                    }
                    return "";
                })()
            });
            // Inline result panel now only shows status, never the raw key.
            if (resultEl) {
                resultEl.style.display = "";
                var statusHtml = "<strong style=\"color:var(--accent-green);\">Key rotated.</strong>"
                    + " Key ID: <code>" + esc(d.key_id) + "</code>";
                if (d.deployed) {
                    statusHtml += " — deployed to <strong>" + esc(d.deploy_node_id) + "</strong>.";
                } else if (d.deploy_error) {
                    statusHtml += " — <span style=\"color:var(--accent-red);\">deploy failed: "
                        + esc(d.deploy_error) + "</span>";
                }
                resultEl.innerHTML = statusHtml;
            }
            s._loadKeys();
        }).catch(function(e) {
            var msg = e.detail || e.message || "Unknown error";
            if (resultEl) {
                resultEl.style.display = "";
                resultEl.innerHTML = "<strong style=\"color:var(--accent-red);\">Rotation failed:</strong> " + esc(msg);
            }
            notify("Key rotation failed: " + msg, "error");
        });
    });
};

/**
 * Tri-state rotate-key chooser. Resolves with one of:
 *   "rotate-deploy" | "rotate-only" | "cancel"
 *
 * No implicit destructive default — Escape/backdrop resolve to "cancel".
 */
AdminPanel.prototype._chooseRotateAction = function(keyId, nodeId) {
    return new Promise(function(resolve) {
        var resolved = false;
        function done(v) { if (!resolved) { resolved = true; resolve(v); } }

        var body = document.createElement("div");
        if (nodeId) {
            body.innerHTML = ""
                + "<div>Rotating key <code>" + esc(keyId) + "</code> linked to node <code>"
                + esc(nodeId) + "</code>. Choose how the new key reaches the node.</div>"
                + "<div style=\"margin-top:10px;\"><strong>Rotate &amp; Deploy</strong> — push the new key to the node over SSH. "
                + "The node keeps reporting.</div>"
                + "<div style=\"margin-top:6px;\"><strong>Rotate Only</strong> — invalidate the old key now and update the node manually later. "
                + "<span style=\"color:var(--accent-red);\">The node will stop reporting until you SSH in and update its config.</span></div>";
        } else {
            body.innerHTML = ""
                + "<div>Rotating key <code>" + esc(keyId) + "</code>. The current key will be invalidated immediately.</div>"
                + "<div style=\"margin-top:6px;color:var(--text-secondary);\">"
                + "No node is linked to this key, so nothing will be deployed automatically.</div>";
        }

        var buttons;
        if (nodeId) {
            buttons = [
                { label: "Cancel", kind: "cancel", onClick: function(c) { done("cancel"); c(); } },
                { label: "Rotate Only (deploy manually)", kind: "destructive",
                    onClick: function(c) { done("rotate-only"); c(); } },
                { label: "Rotate & Deploy via SSH", kind: "destructive",
                    onClick: function(c) { done("rotate-deploy"); c(); } }
            ];
        } else {
            buttons = [
                { label: "Cancel", kind: "cancel", onClick: function(c) { done("cancel"); c(); } },
                { label: "Rotate Key", kind: "destructive",
                    onClick: function(c) { done("rotate-only"); c(); } }
            ];
        }

        showModal({
            title: "Rotate API key",
            body: body,
            buttons: buttons
        });

        // Backdrop / Escape dismissal: resolve "cancel" when modal element is removed.
        var obs = new MutationObserver(function(records, observer) {
            for (var i = 0; i < records.length; i++) {
                var r = records[i];
                for (var j = 0; j < r.removedNodes.length; j++) {
                    var n = r.removedNodes[j];
                    if (n && n.classList && n.classList.contains("admin-modal-backdrop")) {
                        done("cancel");
                        observer.disconnect();
                        return;
                    }
                }
            }
        });
        obs.observe(document.body, { childList: true });
    });
};

/**
 * Raw-key reveal modal (PR-12, dashboard §4.2).
 * Shows the freshly generated raw key with a Copy button and an
 * acknowledgement checkbox. The Done button is disabled until the user
 * confirms they have stored it; checking the box replaces the visible key
 * with bullets. The raw key is never persisted anywhere (no localStorage,
 * no DOM after Done click) — it is captured into a local variable inside
 * this function and the reference is dropped on close.
 */
AdminPanel.prototype._showRawKeyReveal = function(opts) {
    opts = opts || {};
    var keyId = opts.keyId || "";
    var rawKey = opts.rawKey || "";
    var extraHtml = opts.extraHtml || "";

    var body = document.createElement("div");
    body.innerHTML = ""
        + "<div style=\"margin-bottom:10px;\">"
        + "  <strong>This key will not be shown again.</strong> Copy it now and store it somewhere safe."
        + "</div>"
        + "<div style=\"margin-bottom:8px;\"><strong>Key ID:</strong> <code>" + esc(keyId) + "</code></div>"
        + "<div style=\"display:flex;gap:8px;align-items:center;margin-bottom:10px;\">"
        + "  <code id=\"admin-rawkey-code\" style=\"flex:1;padding:8px;background:var(--bg-input,#0d1117);"
        + "border:1px solid var(--border,#444);border-radius:4px;word-break:break-all;font-family:monospace;\">"
        + esc(rawKey) + "</code>"
        + "  <button type=\"button\" id=\"admin-rawkey-copy\" class=\"btn btn-sm\" style=\"min-height:36px;\">Copy</button>"
        + "</div>"
        + "<label style=\"display:flex;gap:8px;align-items:flex-start;font-weight:normal;\">"
        + "  <input type=\"checkbox\" id=\"admin-rawkey-ack\" style=\"width:auto;margin-top:3px;\">"
        + "  <span>I have stored this key securely &mdash; hide it now.</span>"
        + "</label>"
        + extraHtml;

    var codeEl = body.querySelector("#admin-rawkey-code");
    var copyBtn = body.querySelector("#admin-rawkey-copy");
    var ackCb = body.querySelector("#admin-rawkey-ack");

    // Hold the raw key only in this closure. When the modal closes, the
    // reference is dropped and the DOM no longer carries it.
    var pendingKey = rawKey;

    copyBtn.addEventListener("click", function() {
        var orig = copyBtn.textContent;
        function flash(label) {
            copyBtn.textContent = label;
            setTimeout(function() { copyBtn.textContent = orig; }, 1500);
        }
        if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
            navigator.clipboard.writeText(pendingKey).then(
                function() { flash("Copied!"); },
                function() { flash("Copy failed"); }
            );
        } else {
            // Fallback for browsers without clipboard API
            try {
                var ta = document.createElement("textarea");
                ta.value = pendingKey;
                ta.style.position = "fixed"; ta.style.opacity = "0";
                document.body.appendChild(ta);
                ta.select();
                var ok = document.execCommand("copy");
                document.body.removeChild(ta);
                flash(ok ? "Copied!" : "Copy failed");
            } catch (_) { flash("Copy failed"); }
        }
    });

    var doneBtnRef = null;
    ackCb.addEventListener("change", function() {
        if (ackCb.checked) {
            codeEl.textContent = rawKey.replace(/./g, "•");
            if (doneBtnRef) doneBtnRef.disabled = false;
        } else {
            codeEl.textContent = rawKey;
            if (doneBtnRef) doneBtnRef.disabled = true;
        }
    });

    showModal({
        title: opts.title || "API key created — save it now",
        body: body,
        // The key is never shown again: Escape or a click outside closes the
        // reveal only once the admin has acknowledged storing it.
        canDismiss: function() {
            if (ackCb.checked) { pendingKey = null; codeEl.textContent = ""; return true; }
            try { ackCb.focus(); } catch (_) {}
            return false;
        },
        buttons: [
            {
                label: "Done",
                kind: "primary",
                onClick: function(close) {
                    if (!ackCb.checked) {
                        try { ackCb.focus(); } catch (_) {}
                        return;
                    }
                    // Scrub references before close.
                    pendingKey = null;
                    codeEl.textContent = "";
                    close();
                }
            }
        ],
        onShow: function(bodyEl) {
            // Locate the Done button in the rendered modal so we can toggle its
            // disabled state from the checkbox handler.
            var btns = bodyEl.parentNode.querySelectorAll(".admin-modal-buttons button.primary");
            if (btns.length) {
                doneBtnRef = btns[btns.length - 1];
                doneBtnRef.disabled = true;
            }
            try { copyBtn.focus(); } catch (_) {}
        }
    });
};

/* -- Node Management -------------------------------------------- */

AdminPanel.prototype._loadNodes = function() {
    var s = this;
    s._initFloorPlanEditor();
    s._initNodeDetailModal();
    s.apiFetch("/api/admin/nodes").then(function(nodes) {
        s._renderNodes(nodes);
        s._renderFleetOverview(nodes);
    }).catch(function() {});

    var fleetRefresh = document.getElementById("admin-fleet-refresh");
    if (fleetRefresh && !fleetRefresh._bound) {
        fleetRefresh._bound = true;
        fleetRefresh.addEventListener("click", function() { s._loadNodes(); });
    }
};

AdminPanel.prototype._renderFleetOverview = function(nodes) {
    if (!nodes) return;
    var total = nodes.length;
    var online = 0, stale = 0, offline = 0, degraded = 0;
    var cpuSum = 0, cpuCount = 0, memSum = 0, memCount = 0;
    var totalDetRate = 0;
    var problemNodes = [];

    for (var i = 0; i < nodes.length; i++) {
        var n = nodes[i];
        var st = n.status || "unknown";
        if (st === "active") online++;
        else if (st === "stale") stale++;
        else if (st === "offline") offline++;
        else offline++;

        var cpu = finiteNumber(n.cpu_percent), mem = finiteNumber(n.memory_mb);
        if (cpu != null) { cpuSum += cpu; cpuCount++; }
        if (mem != null) { memSum += mem; memCount++; }

        // Detection rate from detection_summary
        var ds = n.detection_summary || {};
        var dTotal = finiteNumber(ds.total_detections) || 0;
        var dPeriod = finiteNumber(ds.period_seconds) || 0;
        var clsRate = finiteNumber(n.classifications_per_sec);
        if (dPeriod > 0) totalDetRate += (dTotal / dPeriod * 60);
        else if (clsRate != null) totalDetRate += clsRate * 60;

        // Check for degraded nodes (high CPU, high temp, or errors)
        var caps = n.capabilities || {};
        var temp = finiteNumber(caps.cpu_temp);
        var isDegraded = false;
        if (cpu != null && cpu > 85) { isDegraded = true; }
        if (temp != null && temp > 75) { isDegraded = true; }
        if (caps.last_error) { isDegraded = true; }
        if (isDegraded && st === "active") {
            degraded++;
            problemNodes.push(n);
        }
    }

    var setText = function(id, v) { var el = document.getElementById(id); if (el) el.textContent = v; };
    setText("fleet-total", total);
    setText("fleet-online", online);
    setText("fleet-stale", stale);
    setText("fleet-offline", offline);
    setText("fleet-degraded", degraded);
    setText("fleet-det-rate", totalDetRate.toFixed(1));
    setText("fleet-avg-cpu", cpuCount > 0 ? (cpuSum / cpuCount).toFixed(1) : "--");
    setText("fleet-avg-mem", memCount > 0 ? Math.round(memSum / memCount) : "--");

    // Fleet alerts
    var alertsContainer = document.getElementById("fleet-alerts-container");
    if (alertsContainer) {
        var alertHtml = "";
        if (offline > 0) {
            alertHtml += "<div class=\"fleet-alert\">" + offline + " node(s) offline</div>";
        }
        for (var j = 0; j < problemNodes.length; j++) {
            var pn = problemNodes[j];
            var reasons = [];
            var pcpu = finiteNumber(pn.cpu_percent);
            if (pcpu != null && pcpu > 85) reasons.push("CPU " + pcpu.toFixed(1) + "%");
            var pcaps = pn.capabilities || {};
            var ptemp = finiteNumber(pcaps.cpu_temp);
            if (ptemp != null && ptemp > 75) reasons.push("Temp " + ptemp.toFixed(0) + "\u00b0C");
            if (pcaps.last_error) reasons.push(String(pcaps.last_error).substring(0, 60));
            alertHtml += "<div class=\"fleet-alert\">" + esc(pn.node_id) + ": " + esc(reasons.join(", ")) + "</div>";
        }
        alertsContainer.innerHTML = alertHtml;
    }
};

AdminPanel.prototype._renderNodes = function(nodes) {
    var tb = document.getElementById("admin-nodes-tbody");
    var em = document.getElementById("admin-nodes-empty");
    if (!tb) return;
    this._adminNodes = nodes || [];
    if (!nodes || !nodes.length) { tb.innerHTML = ""; if (em) em.style.display = ""; return; }
    if (em) em.style.display = "none";

    // Update node selector dropdown
    var sel = document.getElementById("admin-fp-node-select");
    if (sel) {
        var curVal = sel.value;
        sel.innerHTML = "<option value=\"\">-- select node to place --</option>";
        for (var k = 0; k < nodes.length; k++) {
            var opt = document.createElement("option");
            opt.value = nodes[k].node_id;
            opt.textContent = nodes[k].node_id;
            sel.appendChild(opt);
        }
        if (curVal) sel.value = curVal;
    }

    var s = this, h = "";
    for (var i = 0; i < nodes.length; i++) {
        var n = nodes[i], st = esc(n.status || "unknown");
        var nid = esc(n.node_id);
        var caps = n.capabilities || {};
        var cpu = finiteNumber(n.cpu_percent), temp = finiteNumber(caps.cpu_temp);
        var cpuTemp = fixedOr(temp, 0, "\u00b0C");
        var uptimeSec = finiteNumber(caps.uptime_seconds);
        var uptimeStr = uptimeSec != null ? fmtUptime(uptimeSec) : "--";

        // Detection rate
        var ds = n.detection_summary || {};
        var dTotal = finiteNumber(ds.total_detections) || 0;
        var dPeriod = finiteNumber(ds.period_seconds) || 0;
        var clsRate = finiteNumber(n.classifications_per_sec);
        var detRateMin = dPeriod > 0 ? (dTotal / dPeriod * 60).toFixed(1)
            : (clsRate != null ? (clsRate * 60).toFixed(1) : "--");

        // Health indicator (a stale node's critical metric stays red, as in
        // the diagnostics view)
        var healthColor = "green", healthTitle = "Healthy";
        var critical = (cpu != null && cpu > 90) || (temp != null && temp > 80);
        if (st === "offline") {
            healthColor = "red"; healthTitle = "Offline";
        } else if (st !== "active") {
            healthColor = critical ? "red" : "yellow";
            healthTitle = critical ? "Stale, critical" : "Stale";
        } else if (critical) {
            healthColor = "red"; healthTitle = "Critical";
        } else if ((cpu != null && cpu > 75) || (temp != null && temp > 70)) {
            healthColor = "yellow"; healthTitle = "Degraded";
        }
        var healthHtml = "<span class=\"node-health node-health-" + healthColor + "\" title=\"" + esc(healthTitle) + "\"><span class=\"health-dot\"></span> " + esc(healthTitle) + "</span>";

        h += "<tr class=\"node-main-row\" data-node-detail=\"" + nid + "\" style=\"cursor:pointer;\" title=\"Click for detailed diagnostics\">"
            + "<td>" + healthHtml + "</td>"
            + "<td data-label=\"Node\"><code>" + nid + "</code></td>"
            + "<td data-label=\"Host\">" + esc(n.host) + "</td>"
            + "<td data-label=\"Status\"><span class=\"node-status " + st + "\"><span class=\"dot\"></span> " + st + "</span></td>"
            + "<td data-label=\"Det/min\">" + esc(detRateMin) + "</td>"
            + "<td data-label=\"CPU\">" + esc(fixedOr(cpu, 1)) + "</td>"
            + "<td data-label=\"Mem\">" + esc(fixedOr(n.memory_mb, 0)) + "</td>"
            + "<td data-label=\"Temp\">" + esc(cpuTemp) + "</td>"
            + "<td data-label=\"Uptime\">" + esc(uptimeStr) + "</td>"
            + "<td data-label=\"Seen\">" + fmtTime(n.last_seen) + "</td>"
            + "<td data-label=\"Actions\">"
            + "<button class=\"btn btn-sm\" data-restart-scanner=\"" + nid + "\" title=\"Restart every service on this node, including its agent\">Restart</button> "
            + "<button class=\"btn btn-sm\" data-update-config=\"" + nid + "\" title=\"Push config update\">Config</button> "
            + "<button class=\"btn btn-sm\" data-run-diag=\"" + nid + "\" title=\"Show node diagnostics\">Diag</button> "
            + "<button class=\"btn btn-sm btn-danger\" data-dereg=\"" + nid + "\">Deregister</button>"
            + "</td></tr>";
    }
    tb.innerHTML = h;

    // Row click opens node detail modal
    tb.querySelectorAll("[data-node-detail]").forEach(function(row) {
        row.addEventListener("click", function(e) {
            if (e.target.closest("button")) return;
            var nid = this.getAttribute("data-node-detail");
            s._openNodeDetail(nid);
        });
    });

    // Restart: the node agent restarts every node service, itself last
    tb.querySelectorAll("[data-restart-scanner]").forEach(function(btn) {
        btn.addEventListener("click", function(e) {
            e.stopPropagation();
            var nid = this.getAttribute("data-restart-scanner");
            confirmModal({
                title: "Restart node services",
                message: "Restart every service on " + nid + ", including its agent?\n\n"
                    + "The node stops scanning and reporting while they restart. It runs the "
                    + "command at its next heartbeat; if it has not collected it within 5 minutes, "
                    + "the command is dropped.",
                confirmLabel: "Restart",
                destructive: true
            }).then(function(ok) {
                if (!ok) return;
                s.apiFetch("/api/admin/nodes/" + encodeURIComponent(nid) + "/command",
                    { method: "POST", body: { command: "restart", params: {} } })
                    .then(function() { notify("Restart command queued for " + nid, "success"); })
                    .catch(function() { notify("Failed to queue restart command for " + nid, "error"); });
            });
        });
    });

    // Update Config
    tb.querySelectorAll("[data-update-config]").forEach(function(btn) {
        btn.addEventListener("click", function(e) {
            e.stopPropagation();
            var nid = this.getAttribute("data-update-config");
            var form = document.createElement("div");
            form.innerHTML = ""
                + '<label for="admin-modal-cfg-json">JSON config</label>'
                + '<textarea id="admin-modal-cfg-json" rows="20" cols="80" spellcheck="false" autocomplete="off">{}</textarea>'
                + '<div class="admin-modal-error" id="admin-modal-cfg-err" style="display:none;"></div>'
                + '<div class="admin-modal-hint">Live-parsed as JSON. Submit is allowed even with parse errors so the server can respond.</div>';
            var ta = form.querySelector("#admin-modal-cfg-json");
            var errEl = form.querySelector("#admin-modal-cfg-err");

            function liveParse() {
                var raw = ta.value;
                if (raw.trim() === "") {
                    errEl.style.display = "";
                    errEl.textContent = "Empty input — provide a JSON object (e.g. {}).";
                    return;
                }
                try {
                    JSON.parse(raw);
                    errEl.style.display = "none";
                    errEl.textContent = "";
                } catch (parseErr) {
                    errEl.style.display = "";
                    errEl.textContent = "Invalid JSON: " + (parseErr && parseErr.message ? parseErr.message : String(parseErr));
                }
            }
            ta.addEventListener("input", liveParse);

            showModal({
                title: "Push config to " + nid,
                body: form,
                buttons: [
                    { label: "Cancel", kind: "cancel", onClick: function(close) { close(); } },
                    {
                        label: "Submit",
                        kind: "primary",
                        onClick: function(close) {
                            var config;
                            try {
                                config = JSON.parse(ta.value);
                            } catch (parseErr) {
                                errEl.style.display = "";
                                errEl.textContent = "Invalid JSON: " + (parseErr && parseErr.message ? parseErr.message : String(parseErr));
                                try { ta.focus(); } catch (_) {}
                                return;
                            }
                            close();
                            s.apiFetch("/api/admin/nodes/" + encodeURIComponent(nid) + "/config",
                                { method: "PUT", body: { config: config } })
                                .then(function() { notify("Config update queued for " + nid, "success"); })
                                .catch(function() { notify("Failed to queue config update for " + nid, "error"); });
                        }
                    }
                ],
                onShow: function() {
                    liveParse();
                    try { ta.focus(); ta.select(); } catch (_) {}
                }
            });
        });
    });

    // Diagnostics: the bridge's view from heartbeats (the node agent has no
    // self-test command to queue)
    tb.querySelectorAll("[data-run-diag]").forEach(function(btn) {
        btn.addEventListener("click", function(e) {
            e.stopPropagation();
            s._openNodeDetail(this.getAttribute("data-run-diag"));
        });
    });

    // Deregister
    tb.querySelectorAll("[data-dereg]").forEach(function(btn) {
        btn.addEventListener("click", function(e) {
            e.stopPropagation();
            var nid = this.getAttribute("data-dereg");
            confirmModal({
                title: "Deregister node",
                message: "Deregister node " + nid + "?\n\nThis cannot be undone. The node will need to re-enroll with a new key to rejoin.",
                confirmLabel: "Deregister",
                destructive: true
            }).then(function(ok) {
                if (!ok) return;
                s.apiFetch("/api/admin/nodes/" + encodeURIComponent(nid), { method: "DELETE" })
                    .then(function() { s._loadNodes(); notify("Node " + nid + " deregistered", "success"); })
                    .catch(function(e) { notify("Failed to deregister node: " + (e.detail || e.message || "Unknown error"), "error"); });
            });
        });
    });

    // Draw admin floor plan
    this._drawAdminFloorPlan();
};

/* -- Node Detail Modal ------------------------------------------ */

AdminPanel.prototype._initNodeDetailModal = function() {
    if (this._nodeDetailBound) return;
    this._nodeDetailBound = true;
    var s = this;
    var modal = document.getElementById("node-detail-modal");
    var closeBtn = document.getElementById("node-detail-close");
    var dismissBtn = document.getElementById("node-detail-dismiss");

    var closeFn = function() { if (modal) modal.style.display = "none"; };
    if (closeBtn) closeBtn.addEventListener("click", closeFn);
    if (dismissBtn) dismissBtn.addEventListener("click", closeFn);
    if (modal) modal.addEventListener("click", function(e) { if (e.target === modal) closeFn(); });

    document.addEventListener("keydown", function(e) {
        if (e.key === "Escape" && modal && modal.style.display !== "none") {
            modal.style.display = "none";
        }
    });
};

AdminPanel.prototype._openNodeDetail = function(nodeId) {
    var modal = document.getElementById("node-detail-modal");
    var titleEl = document.getElementById("node-detail-title");
    var bodyEl = document.getElementById("node-detail-body");
    if (!modal || !bodyEl) return;

    if (titleEl) titleEl.textContent = "Node Diagnostics: " + nodeId;
    bodyEl.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div>Loading diagnostics...</div>';
    modal.style.display = "";

    var s = this;
    s.apiFetch("/api/admin/nodes/" + encodeURIComponent(nodeId) + "/diagnostics")
        .then(function(data) { s._renderNodeDetail(data, bodyEl); })
        .catch(function(err) {
            bodyEl.innerHTML = '<div style="color:var(--accent-red);padding:20px;">Failed to load diagnostics: '
                + esc((err && err.detail) || (err && err.message) || "Unknown error") + '</div>';
        });
};

AdminPanel.prototype._renderNodeDetail = function(data, container) {
    var html = "";

    // Health banner
    var healthBg = data.health === "red" ? "rgba(248,81,73,0.1)" : data.health === "yellow" ? "rgba(210,169,34,0.1)" : "rgba(63,185,80,0.1)";
    var healthBorder = data.health === "red" ? "rgba(248,81,73,0.4)" : data.health === "yellow" ? "rgba(210,169,34,0.4)" : "rgba(63,185,80,0.4)";
    var healthTextColor = data.health === "red" ? "var(--accent-red)" : data.health === "yellow" ? "var(--accent-yellow)" : "var(--accent-green)";
    html += '<div style="padding:8px 16px;margin-bottom:16px;border-radius:6px;background:' + healthBg + ';border:1px solid ' + healthBorder + ';">'
        + '<strong style="color:' + healthTextColor + ';">Health: ' + esc(data.health.toUpperCase()) + '</strong>';
    if (data.health_issues && data.health_issues.length) {
        html += '<ul style="margin:4px 0 0 16px;font-size:12px;color:var(--text-secondary);">';
        for (var hi = 0; hi < data.health_issues.length; hi++) {
            html += '<li>' + esc(data.health_issues[hi]) + '</li>';
        }
        html += '</ul>';
    }
    html += '</div>';

    // System Info
    var sys = data.system_info || {};
    html += '<div class="node-detail-section"><h4>System Information</h4><div class="node-detail-grid">';
    var sysItems = [
        ["CPU", esc(fixedOr(sys.cpu_percent, 1, "%"))],
        ["Memory", esc(fixedOr(sys.memory_mb, 0, " MB"))],
        ["Disk", esc(fixedOr(sys.disk_percent, 1, "%"))],
        ["Temperature", esc(fixedOr(sys.cpu_temp, 0, "\u00b0C"))],
        ["Load 1m", esc(fixedOr(sys.load_1m, 2))],
        ["OS", esc(sys.os || "--")],
        ["Platform", esc(sys.platform || "--")],
        ["Python", esc(sys.python_version || "--")],
        ["Agent", esc(sys.agent_version || "--")],
        ["Model", esc(sys.model || "--")],
        ["Accelerator", esc(sys.accelerator || "None")],
        ["Uptime", esc(finiteNumber(data.uptime_seconds) != null ? fmtUptime(data.uptime_seconds) : "--")],
    ];
    for (var si = 0; si < sysItems.length; si++) {
        html += '<div class="node-detail-item"><span class="ndl">' + sysItems[si][0] + '</span><span class="ndv">' + sysItems[si][1] + '</span></div>';
    }
    html += '</div></div>';

    // SDR Device Details
    var sdr = data.sdr_info || {};
    html += '<div class="node-detail-section"><h4>SDR Device</h4><div class="node-detail-grid">';
    var sdrItems = [
        ["Type", esc(sdr.type || "--")],
        ["Capture Mode", esc(sdr.capture_mode || "--")],
        ["Serial", esc(sdr.serial || "--")],
        ["Firmware", esc(sdr.firmware || "--")],
        ["Sample Rate", esc(sdr.sample_rate ? (sdr.sample_rate / 1e6).toFixed(1) + " MHz" : "--")],
        ["Freq Min", esc(sdr.freq_range_min ? (sdr.freq_range_min / 1e6).toFixed(1) + " MHz" : "--")],
        ["Freq Max", esc(sdr.freq_range_max ? (sdr.freq_range_max / 1e6).toFixed(1) + " MHz" : "--")],
    ];
    for (var sdi = 0; sdi < sdrItems.length; sdi++) {
        html += '<div class="node-detail-item"><span class="ndl">' + sdrItems[sdi][0] + '</span><span class="ndv">' + sdrItems[sdi][1] + '</span></div>';
    }
    html += '</div></div>';

    // Detection Statistics
    var det = data.detection_stats || {};
    html += '<div class="node-detail-section"><h4>Detection Statistics</h4><div class="node-detail-grid">';
    var detItems = [
        ["Total Detections", esc(det.total_detections != null ? det.total_detections : "--")],
        ["Rate", esc(fixedOr(det.rate_per_min, 1, "/min"))],
        ["Avg Confidence", esc(finiteNumber(det.avg_confidence) != null ? (det.avg_confidence * 100).toFixed(1) + "%" : "--")],
        ["Dominant Class", esc(det.dominant_class || "--")],
        ["Dominant Family", esc(det.dominant_family || "--")],
        ["Period", esc(fixedOr(det.period_seconds, 0, "s"))],
    ];
    for (var di = 0; di < detItems.length; di++) {
        html += '<div class="node-detail-item"><span class="ndl">' + detItems[di][0] + '</span><span class="ndv">' + detItems[di][1] + '</span></div>';
    }
    html += '</div>';

    // Per-class counts table
    var topClasses = det.top_classes || [];
    if (topClasses.length > 0) {
        html += '<div style="margin-top:8px;"><table class="data-table" style="font-size:12px;"><thead><tr><th>Class</th><th>Count</th><th>Distribution</th></tr></thead><tbody>';
        var maxClassCnt = topClasses[0].count || 1;
        for (var ci = 0; ci < topClasses.length; ci++) {
            var tc = topClasses[ci];
            var barPct = Math.round((tc.count / maxClassCnt) * 100);
            html += '<tr><td>' + esc(tc["class"]) + '</td><td>' + esc(tc.count) + '</td>'
                + '<td><div style="background:rgba(88,166,255,0.15);border-radius:2px;height:12px;width:' + barPct + '%;min-width:2px;"></div></td></tr>';
        }
        html += '</tbody></table></div>';
    }
    html += '</div>';

    // Active Scanners
    var scanners = data.scanners || [];
    html += '<div class="node-detail-section"><h4>Active Scanners</h4>';
    if (scanners.length > 0) {
        html += '<div class="node-scanner-list">';
        for (var sci = 0; sci < scanners.length; sci++) {
            var sc = scanners[sci];
            html += '<div class="node-scanner-badge"><span class="scanner-dot"></span> '
                + esc(sc.name) + ' — ' + esc(sc.status)
                + (sc.count != null ? ' (' + esc(sc.count) + ')' : '') + '</div>';
        }
        html += '</div>';
    } else {
        html += '<span style="color:var(--text-secondary);font-size:12px;">No active scanners</span>';
    }
    html += '</div>';

    // Recent Errors/Audit entries
    var errors = data.recent_errors || [];
    html += '<div class="node-detail-section"><h4>Recent Audit/Log Entries (' + errors.length + ')</h4>';
    if (errors.length > 0) {
        html += '<div class="node-error-list">';
        for (var ei = 0; ei < Math.min(errors.length, 20); ei++) {
            var err = errors[ei];
            html += '<div class="node-error-entry">'
                + '<span class="node-error-ts">' + fmtTime(err.timestamp) + '</span>'
                + '<span class="node-error-msg">' + esc(err.action || "") + ': ' + esc(err.note || err.message || "") + '</span>'
                + '</div>';
        }
        html += '</div>';
    } else {
        html += '<span style="color:var(--text-secondary);font-size:12px;">No recent entries</span>';
    }
    html += '</div>';

    // Pending Commands
    var pending = data.pending_commands || [];
    if (pending.length > 0) {
        html += '<div class="node-detail-section"><h4>Pending Commands (' + pending.length + ')</h4>';
        html += '<div style="font-size:12px;">';
        for (var pi = 0; pi < pending.length; pi++) {
            var pc = pending[pi];
            html += '<div style="padding:4px 0;border-bottom:1px solid var(--border-color);">'
                + '<strong>' + esc(pc.command) + '</strong> queued at ' + fmtTime(pc.queued_at)
                + '</div>';
        }
        html += '</div></div>';
    }

    // Latency
    if (finiteNumber(data.latency_ms) != null) {
        html += '<div class="node-detail-section"><h4>Network</h4>'
            + '<div class="node-detail-item"><span class="ndl">Heartbeat Latency</span><span class="ndv">'
            + esc(fixedOr(data.latency_ms, 0, " ms")) + '</span></div></div>';
    }

    container.innerHTML = html;
};

/* -- Admin Floor Plan (click-to-place) -------------------------- */

AdminPanel.prototype._initFloorPlanEditor = function() {
    var s = this;
    var canvas = document.getElementById("admin-floorplan-canvas");
    if (!canvas || canvas._bound) return;
    canvas._bound = true;

    canvas.addEventListener("click", function(e) {
        var sel = document.getElementById("admin-fp-node-select");
        var nodeId = sel ? sel.value : "";
        if (!nodeId) { notify("Select a node from the dropdown first.", "warning"); return; }

        var rect = canvas.getBoundingClientRect();
        var scaleX = canvas.width / rect.width;
        var scaleY = canvas.height / rect.height;
        var mx = (e.clientX - rect.left) * scaleX;
        var my = (e.clientY - rect.top) * scaleY;

        var PAD = 30, W = canvas.width, H = canvas.height;
        var pctX = Math.max(0, Math.min(100, ((mx - PAD) / (W - 2 * PAD)) * 100));
        var pctY = Math.max(0, Math.min(100, ((my - PAD) / (H - 2 * PAD)) * 100));

        var floorLabel = (document.getElementById("admin-fp-floor-label") || {}).value || "";

        s.apiFetch("/api/nodes/" + encodeURIComponent(nodeId) + "/position", {
            method: "PATCH",
            body: { x: Math.round(pctX * 10) / 10, y: Math.round(pctY * 10) / 10, floor_label: floorLabel }
        }).then(function() {
            s._loadNodes();
        }).catch(function(err) {
            notify("Failed to set position: " + (err.detail || err.message || "Unknown error"), "error");
        });
    });

    canvas.addEventListener("mousemove", function(e) {
        var rect = canvas.getBoundingClientRect();
        var scaleX = canvas.width / rect.width;
        var scaleY = canvas.height / rect.height;
        var mx = (e.clientX - rect.left) * scaleX;
        var my = (e.clientY - rect.top) * scaleY;
        var PAD = 30, W = canvas.width, H = canvas.height;
        var pctX = Math.max(0, Math.min(100, ((mx - PAD) / (W - 2 * PAD)) * 100));
        var pctY = Math.max(0, Math.min(100, ((my - PAD) / (H - 2 * PAD)) * 100));
        var el = document.getElementById("admin-fp-coords");
        if (el) el.textContent = "(" + pctX.toFixed(0) + ", " + pctY.toFixed(0) + ")";
    });
};

AdminPanel.prototype._drawAdminFloorPlan = function() {
    var canvas = document.getElementById("admin-floorplan-canvas");
    if (!canvas) return;
    var ctx = canvas.getContext("2d");
    var W = canvas.width, H = canvas.height, PAD = 30;
    var nodes = this._adminNodes || [];

    ctx.clearRect(0, 0, W, H);

    // Grid
    var gridColor = "rgba(255,255,255,0.06)";
    var textColor = "rgba(255,255,255,0.3)";
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
    ctx.strokeStyle = "rgba(255,255,255,0.15)";
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

    // Nodes
    for (var i = 0; i < nodes.length; i++) {
        var n = nodes[i];
        if (n.position_x == null || n.position_y == null) continue;
        var px = PAD + (n.position_x / 100) * (W - 2 * PAD);
        var py = PAD + (n.position_y / 100) * (H - 2 * PAD);
        var isOnline = n.status === "active";
        var dotColor = isOnline ? "#3fb950" : "#8b949e";

        ctx.beginPath();
        ctx.arc(px, py, 8, 0, Math.PI * 2);
        ctx.fillStyle = dotColor;
        ctx.fill();
        ctx.strokeStyle = "rgba(255,255,255,0.4)";
        ctx.lineWidth = 1.5;
        ctx.stroke();

        ctx.fillStyle = "#c9d1d9";
        ctx.font = "10px sans-serif";
        ctx.textAlign = "center";
        var label = n.node_id.length > 14 ? n.node_id.substring(0, 12) + ".." : n.node_id;
        ctx.fillText(label, px, py - 12);
    }

    // Hint if no placed nodes
    var placed = nodes.filter(function(n) { return n.position_x != null; }).length;
    if (placed === 0) {
        ctx.fillStyle = textColor;
        ctx.font = "14px sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("Select a node above, then click to place it.", W / 2, H / 2);
    }
};

/* -- Alert Management ------------------------------------------- */

AdminPanel.prototype._loadAlerts = function() {
    var s = this;
    s.apiFetch("/api/admin/alerts").then(function(alerts) {
        s._renderAlerts(alerts);
    }).catch(function() {});

    // Load condition-based rules
    s.apiFetch("/api/alerts/rules/conditions").then(function(rules) {
        s._renderConditionRules(rules);
    }).catch(function() {});

    var btn = document.getElementById("admin-create-alert-btn");
    if (btn && !btn._bound) {
        btn._bound = true;
        btn.addEventListener("click", function() { s._createAlert(); });
    }

    // Bind condition rule builder buttons
    var crBtn = document.getElementById("admin-create-condition-rule-btn");
    if (crBtn && !crBtn._bound) {
        crBtn._bound = true;
        crBtn.addEventListener("click", function() { s._showConditionRuleForm(); });
    }
    var addRow = document.getElementById("add-condition-row-btn");
    if (addRow && !addRow._bound) {
        addRow._bound = true;
        addRow.addEventListener("click", function() { s._addConditionRow(); });
    }
    var saveBtn = document.getElementById("condition-rule-save-btn");
    if (saveBtn && !saveBtn._bound) {
        saveBtn._bound = true;
        saveBtn.addEventListener("click", function() { s._saveConditionRule(); });
    }
    var cancelBtn = document.getElementById("condition-rule-cancel-btn");
    if (cancelBtn && !cancelBtn._bound) {
        cancelBtn._bound = true;
        cancelBtn.addEventListener("click", function() { s._hideConditionRuleForm(); });
    }
};

AdminPanel.prototype._renderAlerts = function(alerts) {
    var tb = document.getElementById("admin-alerts-tbody");
    var em = document.getElementById("admin-alerts-empty");
    if (!tb) return;
    if (!alerts || !alerts.length) { tb.innerHTML = ""; if (em) em.style.display = ""; return; }
    if (em) em.style.display = "none";

    var s = this, h = "";
    for (var i = 0; i < alerts.length; i++) {
        var a = alerts[i];
        var sv = esc(a.severity || "info");
        // PR-14: dual-code severity via window.severityIcon() shape glyph
        // (defined in severity.js, loaded before admin.js).
        var sevIcon = (typeof window.severityIcon === "function") ? window.severityIcon(sv) : "";
        h += "<tr><td data-label=\"Alert ID\"><code>" + esc(a.alert_id) + "</code></td>"
            + "<td data-label=\"Name\">" + esc(a.name) + "</td>"
            + "<td data-label=\"Severity\"><span class=\"severity-badge " + sv + "\">" + sevIcon + sv + "</span></td>"
            + "<td data-label=\"Message\">" + esc(decodeHtmlEscapedText(a.message || "--")) + "</td>"
            + "<td data-label=\"Triggered\">" + fmtTime(a.triggered_at) + "</td>"
            + "<td data-label=\"Ack\">" + (a.acknowledged ? "Yes" : "No") + "</td>"
            + "<td data-label=\"Actions\"><button class=\"btn btn-sm btn-danger\" data-del-alert=\"" + esc(a.alert_id) + "\">Delete</button></td></tr>";
    }
    tb.innerHTML = h;

    tb.querySelectorAll("[data-del-alert]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var aid = this.getAttribute("data-del-alert");
            confirmModal({
                title: "Delete alert",
                message: "Delete alert " + aid + "?",
                confirmLabel: "Delete",
                destructive: true
            }).then(function(ok) {
                if (!ok) return;
                s.apiFetch("/api/admin/alerts/" + encodeURIComponent(aid), { method: "DELETE" })
                    .then(function() { s._loadAlerts(); notify("Alert deleted", "success"); })
                    .catch(function(e) { notify("Failed to delete alert: " + (e.detail || e.message || "Unknown error"), "error"); });
            });
        });
    });
};

AdminPanel.prototype._createAlert = function() {
    var s = this;
    var form = document.createElement("div");
    form.innerHTML = ""
        + '<label for="admin-modal-alert-name">Rule name <span aria-hidden="true">*</span></label>'
        + '<input type="text" id="admin-modal-alert-name" autocomplete="off" required />'
        + '<label for="admin-modal-alert-severity">Severity</label>'
        + '<select id="admin-modal-alert-severity">'
        +   '<option value="critical">critical</option>'
        +   '<option value="high">high</option>'
        +   '<option value="warning" selected>warning</option>'
        +   '<option value="info">info</option>'
        + '</select>';
    var nameInput = form.querySelector("#admin-modal-alert-name");
    var sevSelect = form.querySelector("#admin-modal-alert-severity");

    var createBtnRef = null;
    function syncCreateEnabled() {
        if (!createBtnRef) return;
        var ok = nameInput.value.trim().length > 0;
        createBtnRef.disabled = !ok;
    }
    nameInput.addEventListener("input", syncCreateEnabled);

    showModal({
        title: "Create alert rule",
        body: form,
        buttons: [
            { label: "Cancel", kind: "cancel", onClick: function(close) { close(); } },
            {
                label: "Create",
                kind: "primary",
                onClick: function(close) {
                    var name = nameInput.value.trim();
                    if (!name) { nameInput.focus(); return; }
                    var severity = sevSelect.value || "warning";
                    close();
                    s.apiFetch("/api/admin/alerts",
                        { method: "POST", body: { name: name, severity: severity, thresholds: {} } })
                        .then(function() { s._loadAlerts(); })
                        .catch(function() {});
                }
            }
        ],
        onShow: function() {
            // Resolve the Create button (last in row) so we can toggle its disabled state.
            var btns = form.parentNode.parentNode.querySelectorAll(".admin-modal-buttons button.primary");
            if (btns.length) createBtnRef = btns[btns.length - 1];
            syncCreateEnabled();
            try { nameInput.focus(); } catch (_) {}
        }
    });
};

/* -- Condition Rule Builder ------------------------------------- */

var CONDITION_FIELDS = [
    { value: "signal_class", label: "Signal Class" },
    { value: "freq_hz", label: "Frequency (Hz)" },
    { value: "snr_db", label: "SNR (dB)" },
    { value: "power_dbm", label: "Power (dBm)" },
    { value: "anomaly_score", label: "Anomaly Score" },
    { value: "node_id", label: "Node ID" },
    { value: "family", label: "Family" },
    { value: "bandwidth_hz", label: "Bandwidth (Hz)" },
    { value: "confidence", label: "Confidence" }
];

var CONDITION_OPERATORS = [
    { value: "eq", label: "equals" },
    { value: "ne", label: "not equals" },
    { value: "gt", label: ">" },
    { value: "gte", label: ">=" },
    { value: "lt", label: "<" },
    { value: "lte", label: "<=" },
    { value: "in", label: "in (comma-sep)" },
    { value: "not_in", label: "not in (comma-sep)" },
    { value: "between", label: "between (lo,hi)" }
];

AdminPanel.prototype._showConditionRuleForm = function(editRule) {
    var form = document.getElementById("condition-rule-form");
    if (!form) return;
    form.style.display = "";
    document.getElementById("condition-rule-edit-id").value = "";
    document.getElementById("condition-rule-name").value = "";
    document.getElementById("condition-rule-severity").value = "warning";
    document.getElementById("condition-rule-cooldown").value = "300";
    document.getElementById("condition-rule-enabled").checked = true;
    document.getElementById("condition-rule-webhook").checked = true;
    document.getElementById("condition-rows").innerHTML = "";

    if (editRule) {
        document.getElementById("condition-rule-edit-id").value = editRule.rule_id || "";
        document.getElementById("condition-rule-name").value = decodeHtmlEscapedText(editRule.name);
        document.getElementById("condition-rule-severity").value = editRule.severity || "warning";
        document.getElementById("condition-rule-cooldown").value = String(editRule.cooldown_seconds || 300);
        document.getElementById("condition-rule-enabled").checked = editRule.enabled !== false;
        document.getElementById("condition-rule-webhook").checked = editRule.notify_webhook !== false;
        var conds = editRule.conditions || [];
        for (var i = 0; i < conds.length; i++) {
            this._addConditionRow(conds[i]);
        }
    }
    if (!document.getElementById("condition-rows").children.length) {
        this._addConditionRow();
    }
};

AdminPanel.prototype._hideConditionRuleForm = function() {
    var form = document.getElementById("condition-rule-form");
    if (form) form.style.display = "none";
};

AdminPanel.prototype._addConditionRow = function(cond) {
    var container = document.getElementById("condition-rows");
    if (!container) return;
    var row = document.createElement("div");
    row.style.cssText = "display:flex;gap:6px;margin-bottom:4px;flex-wrap:wrap;align-items:center;";

    var fieldSel = "<select class=\"form-input cond-field\" style=\"flex:1;min-width:120px;\">";
    for (var i = 0; i < CONDITION_FIELDS.length; i++) {
        var f = CONDITION_FIELDS[i];
        var sel = (cond && cond.field === f.value) ? " selected" : "";
        fieldSel += "<option value=\"" + esc(f.value) + "\"" + sel + ">" + esc(f.label) + "</option>";
    }
    fieldSel += "</select>";

    var opSel = "<select class=\"form-input cond-op\" style=\"flex:1;min-width:100px;\">";
    for (var j = 0; j < CONDITION_OPERATORS.length; j++) {
        var o = CONDITION_OPERATORS[j];
        var osel = (cond && cond.operator === o.value) ? " selected" : "";
        opSel += "<option value=\"" + esc(o.value) + "\"" + osel + ">" + esc(o.label) + "</option>";
    }
    opSel += "</select>";

    var val = cond ? (Array.isArray(cond.value) ? cond.value.join(",") : String(cond.value)) : "";
    var valInput = "<input type=\"text\" class=\"form-input cond-val\" placeholder=\"value\" value=\"" + esc(val) + "\" style=\"flex:2;min-width:140px;\">";

    row.innerHTML = fieldSel + opSel + valInput + "<button class=\"btn btn-sm btn-danger cond-remove\" title=\"Remove\">&times;</button>";
    container.appendChild(row);

    row.querySelector(".cond-remove").addEventListener("click", function() {
        row.remove();
    });
};

AdminPanel.prototype._collectConditions = function() {
    var rows = document.querySelectorAll("#condition-rows > div");
    var conditions = [];
    for (var i = 0; i < rows.length; i++) {
        var field = rows[i].querySelector(".cond-field").value;
        var op = rows[i].querySelector(".cond-op").value;
        var rawVal = rows[i].querySelector(".cond-val").value.trim();
        var value;
        if (op === "in" || op === "not_in") {
            value = rawVal.split(",").map(function(v) { return v.trim(); });
        } else if (op === "between") {
            var parts = rawVal.split(",").map(function(v) { return parseFloat(v.trim()); });
            value = parts;
        } else {
            // Try to parse as number if it looks numeric
            value = isNaN(Number(rawVal)) ? rawVal : Number(rawVal);
        }
        conditions.push({ field: field, operator: op, value: value });
    }
    return conditions;
};

AdminPanel.prototype._saveConditionRule = function() {
    var s = this;
    var editId = document.getElementById("condition-rule-edit-id").value;
    var name = document.getElementById("condition-rule-name").value.trim();
    if (!name) {
        notify("Rule name is required", "error");
        var nameInput = document.getElementById("condition-rule-name");
        if (nameInput) try { nameInput.focus(); } catch (_) {}
        return;
    }

    // Every row needs a value: Number("") is 0, so a blank row used to be
    // saved as "<field> eq 0", which no detection matches, and dropping it
    // quietly would save a rule that never fires (no conditions) or a
    // broader one (one AND condition fewer). Say so and keep the form open.
    var rows = document.querySelectorAll("#condition-rows > div");
    if (!rows.length) {
        notify("Add at least one condition", "error");
        return;
    }
    for (var i = 0; i < rows.length; i++) {
        var valInput = rows[i].querySelector(".cond-val");
        if (valInput.value.trim() === "") {
            notify("Condition " + (i + 1) + " has no value: enter one or remove the row", "error");
            try { valInput.focus(); } catch (_) {}
            return;
        }
    }

    var payload = {
        name: name,
        severity: document.getElementById("condition-rule-severity").value,
        conditions: s._collectConditions(),
        enabled: document.getElementById("condition-rule-enabled").checked,
        cooldown_seconds: parseInt(document.getElementById("condition-rule-cooldown").value, 10) || 300,
        notify_webhook: document.getElementById("condition-rule-webhook").checked
    };

    if (editId) {
        // Update
        s.apiFetch("/api/alerts/rules/conditions/" + encodeURIComponent(editId), { method: "PUT", body: payload })
            .then(function() { s._hideConditionRuleForm(); s._loadAlerts(); notify("Rule updated", "success"); })
            .catch(function(e) { notify("Failed to update rule: " + (e.detail || e.message || e), "error"); });
    } else {
        // Create
        s.apiFetch("/api/alerts/rules/conditions", { method: "POST", body: payload })
            .then(function() { s._hideConditionRuleForm(); s._loadAlerts(); notify("Rule created", "success"); })
            .catch(function(e) { notify("Failed to create rule: " + (e.detail || e.message || e), "error"); });
    }
};

AdminPanel.prototype._renderConditionRules = function(rules) {
    var tb = document.getElementById("condition-rules-tbody");
    var em = document.getElementById("condition-rules-empty");
    if (!tb) return;
    if (!rules || !rules.length) { tb.innerHTML = ""; if (em) em.style.display = ""; return; }
    if (em) em.style.display = "none";

    var s = this, h = "";
    for (var i = 0; i < rules.length; i++) {
        var r = rules[i];
        var sv = esc(r.severity || "warning");
        var conds = r.conditions || [];
        // Plain text first: escaped once for the cell and once for its title.
        var condText = "";
        for (var c = 0; c < conds.length; c++) {
            if (c > 0) condText += " AND ";
            var cv = conds[c];
            condText += (cv.field == null ? "" : cv.field) + " " + (cv.operator == null ? "" : cv.operator) + " "
                + (Array.isArray(cv.value) ? cv.value.join(",") : String(cv.value));
        }
        var condStr = condText ? esc(condText) : "<em>no conditions</em>";
        // PR-14: dual-code severity via window.severityIcon() shape glyph.
        var sevIcon = (typeof window.severityIcon === "function") ? window.severityIcon(sv) : "";
        h += "<tr>"
            + "<td data-label=\"Rule ID\"><code>" + esc(r.rule_id) + "</code></td>"
            + "<td data-label=\"Name\">" + esc(decodeHtmlEscapedText(r.name)) + "</td>"
            + "<td data-label=\"Severity\"><span class=\"severity-badge " + sv + "\">" + sevIcon + sv + "</span></td>"
            + "<td data-label=\"Conditions\" style=\"max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;\" title=\"" + esc(condText || "no conditions") + "\">" + condStr + "</td>"
            + "<td data-label=\"Enabled\">" + (r.enabled ? "Yes" : "No") + "</td>"
            + "<td data-label=\"Cooldown\">" + esc(r.cooldown_seconds || 300) + "s</td>"
            + "<td data-label=\"Triggers\">" + esc(r.trigger_count || 0) + "</td>"
            + "<td data-label=\"Last Triggered\">" + fmtTime(r.last_triggered_at) + "</td>"
            + "<td data-label=\"Actions\">"
            + "<button class=\"btn btn-sm\" data-edit-crule=\"" + esc(r.rule_id) + "\">Edit</button> "
            + "<button class=\"btn btn-sm\" data-test-crule=\"" + esc(r.rule_id) + "\">Test</button> "
            + "<button class=\"btn btn-sm btn-danger\" data-del-crule=\"" + esc(r.rule_id) + "\">Delete</button>"
            + "</td></tr>";
    }
    tb.innerHTML = h;

    // Store rules for edit lookup
    s._conditionRulesCache = rules;

    tb.querySelectorAll("[data-del-crule]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var rid = this.getAttribute("data-del-crule");
            confirmModal({
                title: "Delete condition rule",
                message: "Delete condition rule " + rid + "?",
                confirmLabel: "Delete",
                destructive: true
            }).then(function(ok) {
                if (!ok) return;
                s.apiFetch("/api/alerts/rules/conditions/" + encodeURIComponent(rid), { method: "DELETE" })
                    .then(function() { s._loadAlerts(); notify("Rule deleted", "success"); })
                    .catch(function(e) { notify("Failed to delete rule: " + (e.detail || e.message || "Unknown error"), "error"); });
            });
        });
    });

    tb.querySelectorAll("[data-edit-crule]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var rid = this.getAttribute("data-edit-crule");
            var rule = null;
            for (var k = 0; k < (s._conditionRulesCache || []).length; k++) {
                if (s._conditionRulesCache[k].rule_id === rid) { rule = s._conditionRulesCache[k]; break; }
            }
            if (rule) s._showConditionRuleForm(rule);
        });
    });

    tb.querySelectorAll("[data-test-crule]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var rid = this.getAttribute("data-test-crule");
            s.apiFetch("/api/alerts/rules/conditions/" + encodeURIComponent(rid) + "/test", { method: "POST", body: { minutes: 60, limit: 1000 } })
                .then(function(result) {
                    var body = document.createElement("div");
                    body.innerHTML = ""
                        + "<div style=\"margin-bottom:6px;\"><strong>Detections scanned:</strong> "
                        + esc(String(result.detections_scanned)) + "</div>"
                        + "<div><strong>Matches:</strong> " + esc(String(result.matches)) + "</div>";
                    showModal({
                        title: "Dry-run results — rule " + rid,
                        body: body,
                        buttons: [{ label: "Close", kind: "primary", onClick: function(c) { c(); } }]
                    });
                }).catch(function(e) { notify("Test failed: " + (e.detail || e.message || e), "error"); });
        });
    });
};

/* -- Audit Log -------------------------------------------------- */

AdminPanel.prototype._loadAuditFilters = function() {
    var s = this;
    var actionSel = document.getElementById("audit-action-filter");
    if (!actionSel || actionSel._filtersLoaded) return;
    actionSel._filtersLoaded = true;

    s.apiFetch("/api/admin/audit/filters").then(function(data) {
        if (!data) return;

        // Populate action dropdown
        var actions = data.actions || [];
        for (var i = 0; i < actions.length; i++) {
            var a = actions[i];
            var exists = false;
            for (var j = 0; j < actionSel.options.length; j++) {
                if (actionSel.options[j].value === a) { exists = true; break; }
            }
            if (!exists) {
                var opt = document.createElement("option");
                opt.value = a;
                opt.textContent = a;
                actionSel.appendChild(opt);
            }
        }

        // Populate operator dropdown
        var opSel = document.getElementById("audit-operator-filter");
        if (opSel) {
            var operators = data.operators || [];
            for (var oi = 0; oi < operators.length; oi++) {
                var oopt = document.createElement("option");
                oopt.value = operators[oi];
                oopt.textContent = operators[oi];
                opSel.appendChild(oopt);
            }
        }

        // Populate node dropdown
        var nodeSel = document.getElementById("audit-node-filter");
        if (nodeSel) {
            var nodes = data.node_ids || [];
            for (var ni = 0; ni < nodes.length; ni++) {
                var nopt = document.createElement("option");
                nopt.value = nodes[ni];
                nopt.textContent = nodes[ni];
                nodeSel.appendChild(nopt);
            }
        }
    }).catch(function() {});
};

AdminPanel.prototype._loadAudit = function() {
    var s = this;
    s._loadAuditFilters();

    var action = (document.getElementById("audit-action-filter") || {}).value || "";
    var operator = (document.getElementById("audit-operator-filter") || {}).value || "";
    var nodeId = (document.getElementById("audit-node-filter") || {}).value || "";
    var search = (document.getElementById("audit-search-filter") || {}).value || "";
    var startDt = (document.getElementById("audit-start-filter") || {}).value || "";
    var endDt = (document.getElementById("audit-end-filter") || {}).value || "";
    var severity = (document.getElementById("audit-severity-filter") || {}).value || "";

    if (action === "training") {
        s.apiFetch("/api/training/operations?limit=" + s.auditLimit).then(function(entries) {
            s._renderAudit(entries || []);
            var prev = document.getElementById("audit-prev-btn");
            var next = document.getElementById("audit-next-btn");
            if (prev) prev.disabled = true;
            if (next) next.disabled = true;
        }).catch(function() {});
    } else {
        var params = "?limit=" + s.auditLimit + "&offset=" + s.auditOffset;
        if (action) params += "&action=" + encodeURIComponent(action);
        if (operator) params += "&operator=" + encodeURIComponent(operator);
        if (nodeId) params += "&node_id=" + encodeURIComponent(nodeId);
        if (search) params += "&search=" + encodeURIComponent(search);
        if (startDt) params += "&start=" + encodeURIComponent(new Date(startDt).toISOString());
        if (endDt) params += "&end=" + encodeURIComponent(new Date(endDt).toISOString());
        if (severity) params += "&severity=" + encodeURIComponent(severity);

        s.apiFetch("/api/admin/audit" + params).then(function(d) {
            s._renderAudit(d.entries || []);
            var prev = document.getElementById("audit-prev-btn");
            var next = document.getElementById("audit-next-btn");
            if (prev) prev.disabled = s.auditOffset === 0;
            if (next) next.disabled = (d.entries || []).length < s.auditLimit;
        }).catch(function() {});
    }

    // Bind filter/pagination
    var af = document.getElementById("audit-action-filter");
    if (af && !af._bound) {
        af._bound = true;
        af.addEventListener("change", function() { s.auditOffset = 0; s._loadAudit(); });
    }
    var fb = document.getElementById("audit-filter-btn");
    if (fb && !fb._bound) {
        fb._bound = true;
        fb.addEventListener("click", function() { s.auditOffset = 0; s._loadAudit(); });
    }
    var cb = document.getElementById("audit-clear-btn");
    if (cb && !cb._bound) {
        cb._bound = true;
        cb.addEventListener("click", function() {
            var ids = ["audit-action-filter","audit-operator-filter","audit-node-filter",
                       "audit-severity-filter","audit-search-filter","audit-start-filter","audit-end-filter"];
            for (var i = 0; i < ids.length; i++) {
                var el = document.getElementById(ids[i]);
                if (el) el.value = "";
            }
            s.auditOffset = 0;
            s._loadAudit();
        });
    }
    // Bind severity filter
    var sevF = document.getElementById("audit-severity-filter");
    if (sevF && !sevF._bound) {
        sevF._bound = true;
        sevF.addEventListener("change", function() { s.auditOffset = 0; s._loadAudit(); });
    }
    // Bind dropdowns to auto-filter on change
    var dropdowns = ["audit-operator-filter","audit-node-filter"];
    for (var di = 0; di < dropdowns.length; di++) {
        var dd = document.getElementById(dropdowns[di]);
        if (dd && !dd._bound) {
            dd._bound = true;
            dd.addEventListener("change", function() { s.auditOffset = 0; s._loadAudit(); });
        }
    }
    // Enter key triggers filter on search input
    var searchInp = document.getElementById("audit-search-filter");
    if (searchInp && !searchInp._bound) {
        searchInp._bound = true;
        searchInp.addEventListener("keydown", function(ev) {
            if (ev.key === "Enter") { s.auditOffset = 0; s._loadAudit(); }
        });
    }
    var pb = document.getElementById("audit-prev-btn");
    if (pb && !pb._bound) {
        pb._bound = true;
        pb.addEventListener("click", function() {
            s.auditOffset = Math.max(0, s.auditOffset - s.auditLimit);
            s._loadAudit();
        });
    }
    var nb = document.getElementById("audit-next-btn");
    if (nb && !nb._bound) {
        nb._bound = true;
        nb.addEventListener("click", function() {
            s.auditOffset += s.auditLimit;
            s._loadAudit();
        });
    }
    // Modal close bindings
    s._bindAuditModal();
};

AdminPanel.prototype._bindAuditModal = function() {
    var s = this;
    var modal = document.getElementById("audit-detail-modal");
    if (!modal || modal._bound) return;
    modal._bound = true;

    var closeBtn = document.getElementById("audit-detail-close");
    var dismissBtn = document.getElementById("audit-detail-dismiss");
    var copyBtn = document.getElementById("audit-detail-copy");

    function closeModal() { modal.style.display = "none"; }

    if (closeBtn) closeBtn.addEventListener("click", closeModal);
    if (dismissBtn) dismissBtn.addEventListener("click", closeModal);
    modal.addEventListener("click", function(ev) {
        if (ev.target === modal) closeModal();
    });
    document.addEventListener("keydown", function(ev) {
        if (ev.key === "Escape" && modal.style.display !== "none") closeModal();
    });
    if (copyBtn) copyBtn.addEventListener("click", function() {
        var json = modal.getAttribute("data-json") || "{}";
        navigator.clipboard.writeText(json).then(function() {
            copyBtn.textContent = "Copied!";
            setTimeout(function() { copyBtn.textContent = "Copy JSON"; }, 1500);
        }).catch(function() {});
    });
};

AdminPanel.prototype._showAuditDetail = function(entry) {
    this._bindAuditModal();
    var modal = document.getElementById("audit-detail-modal");
    var title = document.getElementById("audit-detail-title");
    var body = document.getElementById("audit-detail-body");
    if (!modal || !body) return;

    var fullJson = JSON.stringify(entry, null, 2);
    modal.setAttribute("data-json", fullJson);

    title.textContent = "Audit: " + (entry.action || "unknown");

    var h = '<table style="width:100%;border-collapse:collapse;">';
    var fields = [
        ["Timestamp", entry.timestamp],
        ["Action", entry.action],
        ["Target ID", entry.target_id],
        ["Operator", entry.operator || "--"],
        ["Node ID", entry.node_id || "--"],
        ["Signal Class", entry.signal_class || "--"],
        ["Frequency", entry.freq_hz ? (entry.freq_hz / 1e6).toFixed(3) + " MHz" : "--"],
        ["Note", entry.note || "--"]
    ];
    for (var i = 0; i < fields.length; i++) {
        h += '<tr style="border-bottom:1px solid var(--border-color);">'
            + '<td style="padding:6px 8px;font-weight:600;white-space:nowrap;width:120px;color:var(--text-dim);">' + esc(fields[i][0]) + '</td>'
            + '<td style="padding:6px 8px;">' + esc(String(fields[i][1])) + '</td></tr>';
    }

    // Bulk target IDs
    if (entry.target_ids && entry.target_ids.length) {
        h += '<tr style="border-bottom:1px solid var(--border-color);">'
            + '<td style="padding:6px 8px;font-weight:600;white-space:nowrap;color:var(--text-dim);">Targets (' + entry.target_ids.length + ')</td>'
            + '<td style="padding:6px 8px;font-size:12px;word-break:break-all;">' + esc(entry.target_ids.join(", ")) + '</td></tr>';
    }
    h += '</table>';

    // Details section
    if (entry.details && Object.keys(entry.details).length) {
        h += '<div style="margin-top:12px;"><strong style="color:var(--text-dim);">Details:</strong></div>';

        var changes = entry.details.changes;
        if (changes && changes.length) {
            h += '<table style="width:100%;border-collapse:collapse;margin-top:6px;">'
                + '<thead><tr style="border-bottom:1px solid var(--border-color);">'
                + '<th style="padding:4px 8px;text-align:left;font-size:12px;">Key</th>'
                + '<th style="padding:4px 8px;text-align:left;font-size:12px;">Old</th>'
                + '<th style="padding:4px 8px;text-align:left;font-size:12px;">New</th>'
                + '</tr></thead><tbody>';
            for (var j = 0; j < changes.length; j++) {
                var c = changes[j];
                h += '<tr style="border-bottom:1px solid var(--border-color);">'
                    + '<td style="padding:4px 8px;font-size:12px;"><code>' + esc(c.key) + '</code></td>'
                    + '<td style="padding:4px 8px;font-size:12px;color:var(--accent-red);">' + esc(String(c.old != null ? c.old : "null")) + '</td>'
                    + '<td style="padding:4px 8px;font-size:12px;color:var(--accent-green);">' + esc(String(c.new != null ? c.new : "null")) + '</td>'
                    + '</tr>';
            }
            h += '</tbody></table>';
        } else {
            h += '<pre style="margin-top:6px;padding:10px;background:var(--bg-primary);border:1px solid var(--border-color);border-radius:var(--radius-sm);font-size:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;">'
                + esc(JSON.stringify(entry.details, null, 2)) + '</pre>';
        }
    }

    body.innerHTML = h;
    modal.style.display = "";
    modal.focus();
};

AdminPanel.prototype._renderAudit = function(entries, tbodyId, emptyId) {
    var s = this;
    var tb = document.getElementById(tbodyId || "audit-tbody");
    var em = document.getElementById(emptyId || "audit-empty");
    if (!tb) return;
    if (!entries || !entries.length) { tb.innerHTML = ""; if (em) em.style.display = ""; return; }
    if (em) em.style.display = "none";

    // Store entries for detail modal
    s._auditEntries = entries;

    var h = "";
    for (var i = 0; i < entries.length; i++) {
        var e = entries[i];
        var detailsPreview = "";
        var hasDetails = e.details && Object.keys(e.details).length > 0;

        if (hasDetails) {
            var changes = e.details.changes;
            if (changes && changes.length) {
                detailsPreview = changes.length + " change" + (changes.length > 1 ? "s" : "");
            } else {
                var dKeys = Object.keys(e.details);
                var dParts = [];
                for (var k = 0; k < Math.min(dKeys.length, 3); k++) {
                    var dv = e.details[dKeys[k]];
                    var val = typeof dv === "object" ? JSON.stringify(dv) : String(dv);
                    if (val.length > 40) val = val.substring(0, 37) + "...";
                    dParts.push(esc(dKeys[k]) + ": " + esc(val));
                }
                detailsPreview = dParts.join("; ");
                if (dKeys.length > 3) detailsPreview += " +" + (dKeys.length - 3) + " more";
            }
        }

        var viewBtn = hasDetails
            ? ' <button class="btn btn-sm" style="font-size:11px;padding:1px 6px;" data-audit-idx="' + i + '">View</button>'
            : "";

        var sev = (e.details && e.details.severity) ? e.details.severity : "";
        var sevCls = sev === "critical" ? " audit-sev-critical" : sev === "warning" ? " audit-sev-warning" : "";

        var sevBadge = sev === "critical" ? "<span class=\"audit-sev-badge critical\">critical</span>"
            : sev === "warning" ? "<span class=\"audit-sev-badge warning\">warning</span>"
            : "<span class=\"audit-sev-badge info\">info</span>";

        h += "<tr class=\"" + sevCls + "\">"
            + "<td data-label=\"Time\">" + fmtTime(e.timestamp) + "</td>"
            + "<td data-label=\"Sev\">" + sevBadge + "</td>"
            + "<td data-label=\"Action\"><code>" + esc(e.action) + "</code></td>"
            + "<td data-label=\"Target\">" + esc(e.target_id) + "</td>"
            + "<td data-label=\"Operator\">" + esc(e.operator || "--") + "</td>"
            + "<td data-label=\"Note\">" + esc(e.note || "--") + "</td>"
            + "<td data-label=\"Details\">" + (detailsPreview || "--") + viewBtn + "</td>"
            + "</tr>";
    }
    tb.innerHTML = h;

    // Bind view buttons
    var viewBtns = tb.querySelectorAll("[data-audit-idx]");
    for (var v = 0; v < viewBtns.length; v++) {
        viewBtns[v].addEventListener("click", function() {
            var idx = parseInt(this.getAttribute("data-audit-idx"), 10);
            if (s._auditEntries && s._auditEntries[idx]) {
                s._showAuditDetail(s._auditEntries[idx]);
            }
        });
    }
};

/* -- Training Tab ----------------------------------------------- */

AdminPanel.prototype._loadTraining = function() {
    var s = this;
    s._loadTrainingHealth();
    s._loadTrainingOps();

    var btn = document.getElementById("training-health-refresh");
    if (btn && !btn._bound) {
        btn._bound = true;
        btn.addEventListener("click", function() { s._loadTrainingHealth(); });
    }
};

AdminPanel.prototype._loadTrainingHealth = function() {
    var s = this;
    var el = document.getElementById("training-health-cards");
    var em = document.getElementById("training-health-empty");
    if (!el) return;

    s.apiFetch("/api/training/health").then(function(d) {
        var runs = d.runs || [];
        if (!runs.length) {
            el.innerHTML = "";
            if (em) em.style.display = "";
            return;
        }
        if (em) em.style.display = "none";

        var h = "";
        for (var i = 0; i < runs.length; i++) {
            var r = runs[i];
            var st = r.status || "unknown";
            var badgeCls = st === "active" ? "color:var(--accent-green);"
                : st === "stalled" ? "color:var(--accent-yellow);"
                : st === "failed" ? "color:var(--accent-red);"
                : st === "completed" ? "color:var(--accent-cyan);"
                : "color:var(--text-secondary);";
            var epoch = r.current_epoch != null ? r.current_epoch : "--";
            var acc = r.best_val_acc != null ? (r.best_val_acc * 100).toFixed(1) + "%" : "--";
            var age = r.last_activity_s != null ? fmtUptime(r.last_activity_s) + " ago" : "--";

            h += "<div class=\"metric-card\">"
                + "<div class=\"metric-value\" style=\"" + badgeCls + "font-size:14px;text-transform:uppercase;\">" + esc(st) + "</div>"
                + "<div class=\"metric-label\" style=\"font-size:11px;\">" + esc(r.run_id) + "</div>"
                + "<div style=\"font-size:11px;color:var(--text-secondary);margin-top:4px;\">"
                + "Epoch " + esc(String(epoch)) + " | Acc " + esc(acc)
                + "<br>Last: " + esc(age)
                + "</div></div>";
        }
        el.innerHTML = h;
    }).catch(function() {
        el.innerHTML = "<p class=\"empty-state\">Failed to load training health</p>";
    });
};

AdminPanel.prototype._loadTrainingOps = function() {
    var s = this;
    var tb = document.getElementById("training-ops-tbody");
    var em = document.getElementById("training-ops-empty");
    if (!tb) return;

    s.apiFetch("/api/training/operations?limit=50").then(function(entries) {
        if (!entries || !entries.length) {
            tb.innerHTML = "";
            if (em) em.style.display = "";
            return;
        }
        if (em) em.style.display = "none";
        s._renderAudit(entries, "training-ops-tbody", "training-ops-empty");
    }).catch(function() {});
};

/* -- Database Tab ----------------------------------------------- */

AdminPanel.prototype._loadDatabase = function() {
    var s = this;

    // Init maintenance controls
    s._initMaintenance();

    // Init backup controls
    s._initBackup();

    // DB stats period selector
    var periodSel = document.getElementById("db-stats-period");
    if (periodSel && !periodSel._bound) {
        periodSel._bound = true;
        periodSel.addEventListener("change", function() { s._loadDbStats(); });
    }
    s._loadDbStats();

    // Jobs refresh button
    var jobsBtn = document.getElementById("jobs-refresh-btn");
    if (jobsBtn && !jobsBtn._bound) {
        jobsBtn._bound = true;
        jobsBtn.addEventListener("click", function() { s._loadJobs(); });
    }
    s._loadJobs();
};

AdminPanel.prototype._loadJobs = function() {
    var s = this;
    var el = document.getElementById("db-jobs");
    if (!el) return;

    s.apiFetch("/api/admin/jobs").then(function(d) {
        var jobs = d.jobs || [];
        var nextCleanup = d.next_scheduled_cleanup;

        var h = "";
        // Scheduled cleanup info
        if (nextCleanup) {
            h += "<div style=\"margin-bottom:8px;padding:6px 10px;background:var(--bg-primary);border:1px solid var(--border-color);border-radius:4px;font-size:12px;\">"
                + "<span style=\"color:var(--text-secondary);\">Next scheduled cleanup:</span> "
                + "<strong>" + fmtTime(nextCleanup) + "</strong></div>";
        }

        if (!jobs.length) {
            h += "<p class=\"empty-state\">No recent jobs</p>";
            el.innerHTML = h;
            return;
        }

        h += "<table class=\"data-table admin-table\"><thead><tr>"
            + "<th>Task</th><th>Trigger</th><th>Status</th>"
            + "<th>Started</th><th>Duration</th><th>Details</th>"
            + "</tr></thead><tbody>";

        for (var i = 0; i < jobs.length; i++) {
            var j = jobs[i];
            var statusCls = j.status === "running" ? "color:var(--accent-cyan);"
                : j.status === "failed" ? "color:var(--accent-red);"
                : j.status === "completed" ? "color:var(--accent-green);" : "";
            var dur = j.duration_s != null ? j.duration_s + "s" : "--";
            var triggerBadge = j.trigger === "scheduled"
                ? "<span class=\"admin-badge\">scheduled</span>"
                : "<span class=\"admin-badge master\">manual</span>";

            // Build details string
            var details = "";
            if (j.error) {
                details = "<span style=\"color:var(--accent-red);\">" + esc(j.error) + "</span>";
            } else if (j.result) {
                var parts = [];
                var r = j.result;
                if (r.deleted != null) {
                    if (typeof r.deleted === "object") {
                        for (var k in r.deleted) {
                            if (r.deleted[k] > 0) parts.push(esc(k) + ": " + fmtNum(r.deleted[k]));
                        }
                    } else if (r.deleted > 0) {
                        parts.push(fmtNum(r.deleted) + " deleted");
                    }
                }
                if (r.aggregated > 0) parts.push(fmtNum(r.aggregated) + " aggregated");
                if (r.aggregated_wifi_hourly > 0) parts.push("wifi: " + fmtNum(r.aggregated_wifi_hourly) + " agg");
                if (r.dismissed > 0) parts.push(fmtNum(r.dismissed) + " dismissed");
                if (r.vacuumed) parts.push("vacuumed");
                if (r.reclaimed_bytes > 0) {
                    var rb = r.reclaimed_bytes;
                    parts.push("reclaimed " + (rb >= 1048576 ? (rb/1048576).toFixed(1)+"MB" : rb >= 1024 ? (rb/1024).toFixed(1)+"KB" : rb+"B"));
                }
                // Scheduled cleanup result keys
                if (r.deleted_detections > 0) parts.push("det: " + fmtNum(r.deleted_detections));
                if (r.deleted_wifi_metadata > 0) parts.push("wifi: " + fmtNum(r.deleted_wifi_metadata));
                if (r.deleted_rf_anomalies > 0) parts.push("rf_anom: " + fmtNum(r.deleted_rf_anomalies));
                if (r.deleted_wifi_anomalies > 0) parts.push("wifi_anom: " + fmtNum(r.deleted_wifi_anomalies));
                if (r.deleted_wifi_hourly > 0) parts.push("hourly: " + fmtNum(r.deleted_wifi_hourly));
                details = parts.length ? parts.join(", ") : "ok";
            } else if (j.note) {
                // Historical job from audit log
                details = esc(j.note);
            } else if (j.status === "running") {
                details = "<span style=\"" + statusCls + "\">in progress...</span>";
            }
            // Append operator for historical entries
            if (j.operator && j.operator !== "system") {
                details += " <small style=\"color:var(--text-secondary);\">[" + esc(j.operator.substring(0, 8)) + "]</small>";
            }

            h += "<tr>"
                + "<td data-label=\"Task\"><code>" + esc(j.task) + "</code></td>"
                + "<td data-label=\"Trigger\">" + triggerBadge + "</td>"
                + "<td data-label=\"Status\" style=\"" + statusCls + "\">" + esc(j.status) + "</td>"
                + "<td data-label=\"Started\">" + fmtTime(j.started_at) + "</td>"
                + "<td data-label=\"Duration\" style=\"text-align:right;font-family:var(--font-mono);\">" + esc(dur) + "</td>"
                + "<td data-label=\"Details\" style=\"font-size:12px;\">" + details + "</td>"
                + "</tr>";
        }
        h += "</tbody></table>";
        el.innerHTML = h;
    }).catch(function() {
        el.innerHTML = "<p class=\"empty-state\">Failed to load jobs</p>";
    });
};

/* -- Notifications ---------------------------------------------- */

AdminPanel.prototype._loadNotifications = function() {
    var s = this;
    s.apiFetch("/api/admin/webhooks").then(function(d) {
        s._renderWebhooks(d.webhooks || []);
        s._renderDeliveryLog(d.delivery_log || []);
    }).catch(function(e) {
        notify("Failed to load webhooks: " + (e.detail || e.message || "Unknown error"), "error");
    });

    // Load syslog targets
    s._loadSyslog();

    // Bind controls (once)
    var addBtn = document.getElementById("admin-add-webhook-btn");
    if (addBtn && !addBtn._bound) {
        addBtn._bound = true;
        addBtn.addEventListener("click", function() {
            s._editingWebhookId = null;
            var form = document.getElementById("admin-webhook-form");
            if (form) form.style.display = "";
            var urlEl = document.getElementById("webhook-url-input");
            var nameEl = document.getElementById("webhook-name-input");
            var sevEl = document.getElementById("webhook-severity-input");
            if (urlEl) { urlEl.value = ""; urlEl.focus(); }
            if (nameEl) nameEl.value = "";
            if (sevEl) {
                for (var i = 0; i < sevEl.options.length; i++) sevEl.options[i].selected = true;
            }
        });
    }

    var saveBtn = document.getElementById("webhook-save-btn");
    if (saveBtn && !saveBtn._bound) {
        saveBtn._bound = true;
        saveBtn.addEventListener("click", function() { s._saveWebhook(); });
    }

    var cancelBtn = document.getElementById("webhook-cancel-btn");
    if (cancelBtn && !cancelBtn._bound) {
        cancelBtn._bound = true;
        cancelBtn.addEventListener("click", function() {
            var form = document.getElementById("admin-webhook-form");
            if (form) form.style.display = "none";
            s._editingWebhookId = null;
        });
    }
};

AdminPanel.prototype._saveWebhook = function() {
    var s = this;
    var urlEl = document.getElementById("webhook-url-input");
    var nameEl = document.getElementById("webhook-name-input");
    var sevEl = document.getElementById("webhook-severity-input");

    var url = urlEl ? urlEl.value.trim() : "";
    var name = nameEl ? nameEl.value.trim() : "";
    if (!url) {
        notify("URL is required.", "error");
        if (urlEl) try { urlEl.focus(); } catch (_) {}
        return;
    }

    var sevFilter = [];
    if (sevEl) {
        for (var i = 0; i < sevEl.options.length; i++) {
            if (sevEl.options[i].selected) sevFilter.push(sevEl.options[i].value);
        }
    }
    if (!sevFilter.length) sevFilter = ["critical", "warning"];

    var body = { url: url, name: name, severity_filter: sevFilter };

    if (s._editingWebhookId) {
        s.apiFetch("/api/admin/webhooks/" + encodeURIComponent(s._editingWebhookId), {
            method: "PUT", body: body
        }).then(function() {
            var form = document.getElementById("admin-webhook-form");
            if (form) form.style.display = "none";
            s._editingWebhookId = null;
            s._loadNotifications();
            notify("Webhook updated", "success");
        }).catch(function(e) {
            notify("Failed to update webhook: " + (e.detail || e.message || "Unknown error"), "error");
        });
    } else {
        s.apiFetch("/api/admin/webhooks", {
            method: "POST", body: body
        }).then(function() {
            var form = document.getElementById("admin-webhook-form");
            if (form) form.style.display = "none";
            s._loadNotifications();
            notify("Webhook created", "success");
        }).catch(function(e) {
            notify("Failed to create webhook: " + (e.detail || e.message || "Unknown error"), "error");
        });
    }
};

AdminPanel.prototype._renderWebhooks = function(webhooks) {
    var tb = document.getElementById("admin-webhooks-tbody");
    var em = document.getElementById("admin-webhooks-empty");
    var tbl = document.getElementById("admin-webhooks-table");
    if (!tb) return;
    if (!webhooks || !webhooks.length) {
        tb.innerHTML = "";
        if (em) em.style.display = "";
        if (tbl) tbl.style.display = "none";
        return;
    }
    if (em) em.style.display = "none";
    if (tbl) tbl.style.display = "";

    var s = this, h = "";
    for (var i = 0; i < webhooks.length; i++) {
        var w = webhooks[i];
        var sevBadges = "";
        var sevs = w.severity_filter || [];
        for (var j = 0; j < sevs.length; j++) {
            // PR-14: dual-code severity via window.severityIcon() shape glyph.
            var sevIconJ = (typeof window.severityIcon === "function") ? window.severityIcon(sevs[j]) : "";
            sevBadges += "<span class=\"severity-badge " + esc(sevs[j]) + "\">" + sevIconJ + esc(sevs[j]) + "</span> ";
        }
        var enabledLabel = w.enabled
            ? "<span style=\"color:var(--accent-green);\">On</span>"
            : "<span style=\"color:var(--text-secondary);\">Off</span>";
        var toggleLabel = w.enabled ? "Disable" : "Enable";

        h += "<tr>"
            + "<td data-label=\"Name\">" + esc(w.name) + "</td>"
            + "<td data-label=\"URL\"><code style=\"font-size:11px;\">" + esc(w.url) + "</code></td>"
            + "<td data-label=\"Severity\">" + sevBadges + "</td>"
            + "<td data-label=\"Enabled\">" + enabledLabel + "</td>"
            + "<td data-label=\"Sent\" style=\"text-align:right;\">" + fmtNum(w.delivery_count || 0) + "</td>"
            + "<td data-label=\"Fails\" style=\"text-align:right;\">" + fmtNum(w.failure_count || 0) + "</td>"
            + "<td data-label=\"Last\">" + fmtTime(w.last_delivery) + "</td>"
            + "<td data-label=\"Actions\">"
            + "<button class=\"btn btn-sm\" data-wh-toggle=\"" + esc(w.id) + "\" data-wh-enabled=\"" + (w.enabled ? "1" : "0") + "\">" + esc(toggleLabel) + "</button> "
            + "<button class=\"btn btn-sm\" data-wh-test=\"" + esc(w.id) + "\">Test</button> "
            + "<button class=\"btn btn-sm\" data-wh-edit=\"" + esc(w.id) + "\">Edit</button> "
            + "<button class=\"btn btn-sm btn-danger\" data-wh-delete=\"" + esc(w.id) + "\">Delete</button>"
            + "</td></tr>";
    }
    tb.innerHTML = h;

    // Toggle enable/disable
    tb.querySelectorAll("[data-wh-toggle]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            if (this.disabled) return;
            var self = this;
            self.disabled = true;
            var wid = this.getAttribute("data-wh-toggle");
            var nowEnabled = this.getAttribute("data-wh-enabled") === "1";
            s.apiFetch("/api/admin/webhooks/" + encodeURIComponent(wid), {
                method: "PUT", body: { enabled: !nowEnabled }
            }).then(function() { s._loadNotifications(); }).catch(function(e) {
                notify("Failed to update webhook: " + (e.detail || e.message || "Unknown error"), "error");
            }).finally(function() { self.disabled = false; });
        });
    });

    // Test webhook
    tb.querySelectorAll("[data-wh-test]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var wid = this.getAttribute("data-wh-test");
            this.disabled = true;
            this.textContent = "...";
            var self = this;
            s.apiFetch("/api/admin/webhooks/" + encodeURIComponent(wid) + "/test", { method: "POST" })
                .then(function(d) {
                    self.textContent = d.status === "delivered" ? "OK" : "Fail";
                    setTimeout(function() { self.textContent = "Test"; self.disabled = false; }, 2000);
                    s._loadNotifications();
                })
                .catch(function() {
                    self.textContent = "Err";
                    setTimeout(function() { self.textContent = "Test"; self.disabled = false; }, 2000);
                });
        });
    });

    // Edit webhook
    tb.querySelectorAll("[data-wh-edit]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var wid = this.getAttribute("data-wh-edit");
            var webhook = null;
            for (var k = 0; k < webhooks.length; k++) {
                if (webhooks[k].id === wid) { webhook = webhooks[k]; break; }
            }
            if (!webhook) return;
            s._editingWebhookId = wid;
            var form = document.getElementById("admin-webhook-form");
            if (form) form.style.display = "";
            var urlEl = document.getElementById("webhook-url-input");
            var nameEl = document.getElementById("webhook-name-input");
            var sevEl = document.getElementById("webhook-severity-input");
            if (urlEl) urlEl.value = webhook.url || "";
            if (nameEl) nameEl.value = webhook.name || "";
            if (sevEl) {
                var sf = webhook.severity_filter || [];
                for (var m = 0; m < sevEl.options.length; m++) {
                    sevEl.options[m].selected = sf.indexOf(sevEl.options[m].value) !== -1;
                }
            }
        });
    });

    // Delete webhook
    tb.querySelectorAll("[data-wh-delete]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var wid = this.getAttribute("data-wh-delete");
            confirmModal({
                title: "Delete webhook",
                message: "Delete this webhook?\n\nAny pending deliveries will be dropped.",
                confirmLabel: "Delete",
                destructive: true
            }).then(function(ok) {
                if (!ok) return;
                s.apiFetch("/api/admin/webhooks/" + encodeURIComponent(wid), { method: "DELETE" })
                    .then(function() { s._loadNotifications(); notify("Webhook deleted", "success"); })
                    .catch(function(e) { notify("Failed to delete webhook: " + (e.detail || e.message || "Unknown error"), "error"); });
            });
        });
    });
};

AdminPanel.prototype._renderDeliveryLog = function(entries) {
    var tb = document.getElementById("admin-delivery-log-tbody");
    var em = document.getElementById("admin-delivery-empty");
    var tbl = document.getElementById("admin-delivery-log-table");
    if (!tb) return;
    if (!entries || !entries.length) {
        tb.innerHTML = "";
        if (em) em.style.display = "";
        if (tbl) tbl.style.display = "none";
        return;
    }
    if (em) em.style.display = "none";
    if (tbl) tbl.style.display = "";

    var h = "";
    // Show newest first
    for (var i = entries.length - 1; i >= 0; i--) {
        var e = entries[i];
        var statusCls = e.success ? "color:var(--accent-green);" : "color:var(--accent-red);";
        var statusTxt = e.success ? "delivered" : "failed";
        // PR-14: dual-code severity via window.severityIcon() shape glyph.
        var sevIcon = (typeof window.severityIcon === "function") ? window.severityIcon(e.severity) : "";
        h += "<tr>"
            + "<td data-label=\"Time\">" + fmtTime(e.timestamp) + "</td>"
            + "<td data-label=\"Webhook\">" + esc(e.webhook_name || e.webhook_id) + "</td>"
            + "<td data-label=\"Alert\"><code>" + esc(e.alert_id || "--") + "</code></td>"
            + "<td data-label=\"Severity\"><span class=\"severity-badge " + esc(e.severity || "") + "\">" + sevIcon + esc(e.severity || "--") + "</span></td>"
            + "<td data-label=\"Status\" style=\"" + statusCls + "\">" + esc(statusTxt) + "</td>"
            + "<td data-label=\"Error\" style=\"font-size:11px;\">" + esc(e.error || "--") + "</td>"
            + "</tr>";
    }
    tb.innerHTML = h;
};

/* -- Syslog Forwarding ------------------------------------------ */

AdminPanel.prototype._loadSyslog = function() {
    var s = this;
    s.apiFetch("/api/admin/syslog").then(function(d) {
        s._renderSyslog(d.targets || []);
    }).catch(function() {});

    // Bind controls (once)
    var addBtn = document.getElementById("admin-add-syslog-btn");
    if (addBtn && !addBtn._bound) {
        addBtn._bound = true;
        addBtn.addEventListener("click", function() {
            s._syslogResetForm();
            var form = document.getElementById("admin-syslog-form");
            if (form) form.style.display = "";
            var hostEl = document.getElementById("syslog-host-input");
            if (hostEl) hostEl.focus();
        });
    }

    var saveBtn = document.getElementById("syslog-save-btn");
    if (saveBtn && !saveBtn._bound) {
        saveBtn._bound = true;
        saveBtn.addEventListener("click", function() { s._saveSyslog(); });
    }

    var cancelBtn = document.getElementById("syslog-cancel-btn");
    if (cancelBtn && !cancelBtn._bound) {
        cancelBtn._bound = true;
        cancelBtn.addEventListener("click", function() {
            var form = document.getElementById("admin-syslog-form");
            if (form) form.style.display = "none";
        });
    }

    // Show/hide TLS fields based on protocol selection
    var protoEl = document.getElementById("syslog-protocol-input");
    if (protoEl && !protoEl._bound) {
        protoEl._bound = true;
        protoEl.addEventListener("change", function() {
            var tlsFields = document.getElementById("syslog-tls-fields");
            if (tlsFields) tlsFields.style.display = this.value === "tls" ? "" : "none";
        });
    }
};

AdminPanel.prototype._syslogResetForm = function() {
    var editId = document.getElementById("syslog-edit-id");
    if (editId) editId.value = "";
    var hostEl = document.getElementById("syslog-host-input");
    if (hostEl) hostEl.value = "";
    var portEl = document.getElementById("syslog-port-input");
    if (portEl) portEl.value = "514";
    var protoEl = document.getElementById("syslog-protocol-input");
    if (protoEl) protoEl.value = "udp";
    var facEl = document.getElementById("syslog-facility-input");
    if (facEl) facEl.value = "local0";
    var sevEl = document.getElementById("syslog-severity-input");
    if (sevEl) {
        for (var i = 0; i < sevEl.options.length; i++) {
            sevEl.options[i].selected = sevEl.options[i].value !== "info";
        }
    }
    var classEl = document.getElementById("syslog-class-input");
    if (classEl) classEl.value = "";
    var nodeEl = document.getElementById("syslog-node-input");
    if (nodeEl) nodeEl.value = "";
    var caEl = document.getElementById("syslog-ca-input");
    if (caEl) caEl.value = "";
    var certEl = document.getElementById("syslog-cert-input");
    if (certEl) certEl.value = "";
    var keyEl = document.getElementById("syslog-key-input");
    if (keyEl) keyEl.value = "";
    var tlsFields = document.getElementById("syslog-tls-fields");
    if (tlsFields) tlsFields.style.display = "none";
};

AdminPanel.prototype._saveSyslog = function() {
    var s = this;
    var hostEl = document.getElementById("syslog-host-input");
    var portEl = document.getElementById("syslog-port-input");
    var protoEl = document.getElementById("syslog-protocol-input");
    var facEl = document.getElementById("syslog-facility-input");
    var sevEl = document.getElementById("syslog-severity-input");
    var classEl = document.getElementById("syslog-class-input");
    var nodeEl = document.getElementById("syslog-node-input");
    var editId = document.getElementById("syslog-edit-id");

    var host = hostEl ? hostEl.value.trim() : "";
    if (!host) {
        notify("Host is required.", "error");
        if (hostEl) try { hostEl.focus(); } catch (_) {}
        return;
    }

    var port = portEl ? parseInt(portEl.value, 10) : 514;
    if (isNaN(port) || port < 1 || port > 65535) {
        notify("Port must be 1-65535.", "error");
        if (portEl) try { portEl.focus(); } catch (_) {}
        return;
    }

    var protocol = protoEl ? protoEl.value : "udp";
    var facility = facEl ? facEl.value : "local0";

    var sevFilter = [];
    if (sevEl) {
        for (var i = 0; i < sevEl.options.length; i++) {
            if (sevEl.options[i].selected) sevFilter.push(sevEl.options[i].value);
        }
    }
    if (!sevFilter.length) sevFilter = ["critical", "warning"];

    var signalClassFilter = [];
    if (classEl && classEl.value.trim()) {
        signalClassFilter = classEl.value.split(",").map(function(v) { return v.trim(); }).filter(function(v) { return v; });
    }

    var nodeFilter = [];
    if (nodeEl && nodeEl.value.trim()) {
        nodeFilter = nodeEl.value.split(",").map(function(v) { return v.trim(); }).filter(function(v) { return v; });
    }

    var body = {
        host: host,
        port: port,
        protocol: protocol,
        facility: facility,
        severity_filter: sevFilter,
        signal_class_filter: signalClassFilter,
        node_filter: nodeFilter
    };

    // TLS fields
    if (protocol === "tls") {
        var caEl = document.getElementById("syslog-ca-input");
        var certBundleEl = document.getElementById("syslog-cert-input");
        var keyPathEl = document.getElementById("syslog-key-input");
        if (caEl && caEl.value.trim()) body.tls_ca_bundle = caEl.value.trim();
        if (certBundleEl && certBundleEl.value.trim()) body.tls_client_cert = certBundleEl.value.trim();
        if (keyPathEl && keyPathEl.value.trim()) body.tls_client_key = keyPathEl.value.trim();
    }

    var targetId = editId ? editId.value : "";

    if (targetId) {
        s.apiFetch("/api/admin/syslog/" + encodeURIComponent(targetId), {
            method: "PUT", body: body
        }).then(function() {
            var form = document.getElementById("admin-syslog-form");
            if (form) form.style.display = "none";
            s._loadSyslog();
            notify("Syslog target updated", "success");
        }).catch(function(e) {
            notify("Failed to update syslog target: " + (e.detail || e.message || "Unknown error"), "error");
        });
    } else {
        s.apiFetch("/api/admin/syslog", {
            method: "POST", body: body
        }).then(function() {
            var form = document.getElementById("admin-syslog-form");
            if (form) form.style.display = "none";
            s._loadSyslog();
            notify("Syslog target created", "success");
        }).catch(function(e) {
            notify("Failed to create syslog target: " + (e.detail || e.message || "Unknown error"), "error");
        });
    }
};

AdminPanel.prototype._deleteSyslog = function(targetId) {
    var s = this;
    confirmModal({
        title: "Delete syslog target",
        message: "Delete this syslog target?\n\nForwarding to it will stop immediately.",
        confirmLabel: "Delete",
        destructive: true
    }).then(function(ok) {
        if (!ok) return;
        s.apiFetch("/api/admin/syslog/" + encodeURIComponent(targetId), { method: "DELETE" })
            .then(function() { s._loadSyslog(); notify("Syslog target deleted", "success"); })
            .catch(function(e) { notify("Failed to delete syslog target: " + (e.detail || e.message || "Unknown error"), "error"); });
    });
};

AdminPanel.prototype._testSyslog = function(targetId, btn) {
    var s = this;
    btn.disabled = true;
    btn.textContent = "...";
    s.apiFetch("/api/admin/syslog/" + encodeURIComponent(targetId) + "/test", { method: "POST" })
        .then(function(d) {
            btn.textContent = d.status === "delivered" ? "OK" : "Fail";
            setTimeout(function() { btn.textContent = "Test"; btn.disabled = false; }, 2000);
            s._loadSyslog();
        })
        .catch(function() {
            btn.textContent = "Err";
            setTimeout(function() { btn.textContent = "Test"; btn.disabled = false; }, 2000);
        });
};

AdminPanel.prototype._renderSyslog = function(targets) {
    var tb = document.getElementById("admin-syslog-tbody");
    var em = document.getElementById("admin-syslog-empty");
    var tbl = document.getElementById("admin-syslog-table");
    if (!tb) return;
    if (!targets || !targets.length) {
        tb.innerHTML = "";
        if (em) em.style.display = "";
        if (tbl) tbl.style.display = "none";
        return;
    }
    if (em) em.style.display = "none";
    if (tbl) tbl.style.display = "";

    var s = this, h = "";
    for (var i = 0; i < targets.length; i++) {
        var t = targets[i];
        var sevBadges = "";
        var sevs = t.severity_filter || [];
        for (var j = 0; j < sevs.length; j++) {
            // PR-14: dual-code severity via window.severityIcon() shape glyph.
            var sevIconJ = (typeof window.severityIcon === "function") ? window.severityIcon(sevs[j]) : "";
            sevBadges += "<span class=\"severity-badge " + esc(sevs[j]) + "\">" + sevIconJ + esc(sevs[j]) + "</span> ";
        }
        var enabledLabel = t.enabled
            ? "<span style=\"color:var(--accent-green);\">On</span>"
            : "<span style=\"color:var(--text-secondary);\">Off</span>";
        var toggleLabel = t.enabled ? "Disable" : "Enable";

        h += "<tr>"
            + "<td data-label=\"Host\">" + esc(t.host) + "</td>"
            + "<td data-label=\"Port\">" + esc(t.port) + "</td>"
            + "<td data-label=\"Protocol\"><code>" + esc((t.protocol || "udp").toUpperCase()) + "</code></td>"
            + "<td data-label=\"Facility\">" + esc(t.facility || "local0") + "</td>"
            + "<td data-label=\"Severity\">" + sevBadges + "</td>"
            + "<td data-label=\"Enabled\">" + enabledLabel + "</td>"
            + "<td data-label=\"Sent\" style=\"text-align:right;\">" + fmtNum(t.delivery_count || 0) + "</td>"
            + "<td data-label=\"Fails\" style=\"text-align:right;\">" + fmtNum(t.failure_count || 0) + "</td>"
            + "<td data-label=\"Last\">" + fmtTime(t.last_delivery) + "</td>"
            + "<td data-label=\"Actions\">"
            + "<button class=\"btn btn-sm\" data-sl-toggle=\"" + esc(t.id) + "\" data-sl-enabled=\"" + (t.enabled ? "1" : "0") + "\">" + esc(toggleLabel) + "</button> "
            + "<button class=\"btn btn-sm\" data-sl-test=\"" + esc(t.id) + "\">Test</button> "
            + "<button class=\"btn btn-sm\" data-sl-edit=\"" + esc(t.id) + "\">Edit</button> "
            + "<button class=\"btn btn-sm btn-danger\" data-sl-delete=\"" + esc(t.id) + "\">Delete</button>"
            + "</td></tr>";
    }
    tb.innerHTML = h;

    // Toggle enable/disable
    tb.querySelectorAll("[data-sl-toggle]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var tid = this.getAttribute("data-sl-toggle");
            var nowEnabled = this.getAttribute("data-sl-enabled") === "1";
            s.apiFetch("/api/admin/syslog/" + encodeURIComponent(tid), {
                method: "PUT", body: { enabled: !nowEnabled }
            }).then(function() { s._loadSyslog(); }).catch(function() {});
        });
    });

    // Test
    tb.querySelectorAll("[data-sl-test]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var tid = this.getAttribute("data-sl-test");
            s._testSyslog(tid, this);
        });
    });

    // Edit
    tb.querySelectorAll("[data-sl-edit]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var tid = this.getAttribute("data-sl-edit");
            var target = null;
            for (var k = 0; k < targets.length; k++) {
                if (targets[k].id === tid) { target = targets[k]; break; }
            }
            if (!target) return;

            var editId = document.getElementById("syslog-edit-id");
            if (editId) editId.value = tid;
            var form = document.getElementById("admin-syslog-form");
            if (form) form.style.display = "";

            var hostEl = document.getElementById("syslog-host-input");
            if (hostEl) hostEl.value = target.host || "";
            var portEl = document.getElementById("syslog-port-input");
            if (portEl) portEl.value = target.port || 514;
            var protoEl = document.getElementById("syslog-protocol-input");
            if (protoEl) protoEl.value = target.protocol || "udp";
            var facEl = document.getElementById("syslog-facility-input");
            if (facEl) facEl.value = target.facility || "local0";
            var sevEl = document.getElementById("syslog-severity-input");
            if (sevEl) {
                var sf = target.severity_filter || [];
                for (var m = 0; m < sevEl.options.length; m++) {
                    sevEl.options[m].selected = sf.indexOf(sevEl.options[m].value) !== -1;
                }
            }
            var classEl = document.getElementById("syslog-class-input");
            if (classEl) classEl.value = (target.signal_class_filter || []).join(", ");
            var nodeEl = document.getElementById("syslog-node-input");
            if (nodeEl) nodeEl.value = (target.node_filter || []).join(", ");

            // TLS fields
            var tlsFields = document.getElementById("syslog-tls-fields");
            if (tlsFields) tlsFields.style.display = (target.protocol === "tls") ? "" : "none";
            var caEl = document.getElementById("syslog-ca-input");
            if (caEl) caEl.value = target.tls_ca_bundle || "";
            var certEl = document.getElementById("syslog-cert-input");
            if (certEl) certEl.value = target.tls_client_cert || "";
            var keyPathEl = document.getElementById("syslog-key-input");
            if (keyPathEl) keyPathEl.value = target.tls_client_key || "";
            // TLS verification is always enabled; CA bundle path is set via tls_ca_bundle
        });
    });

    // Delete
    tb.querySelectorAll("[data-sl-delete]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var tid = this.getAttribute("data-sl-delete");
            s._deleteSyslog(tid);
        });
    });
};

/* -- WiFi Security (AP Whitelist) ------------------------------- */

AdminPanel.prototype._loadWifiSecurity = function() {
    var s = this;
    s.apiFetch("/api/admin/wifi-whitelist").then(function(d) {
        s._renderWhitelist(d.whitelist || []);
    }).catch(function() {});

    var addBtn = document.getElementById("admin-add-ap-btn");
    if (addBtn && !addBtn._bound) {
        addBtn._bound = true;
        addBtn.addEventListener("click", function() {
            var form = document.getElementById("admin-ap-form");
            if (form) form.style.display = "";
            var bssidEl = document.getElementById("ap-bssid-input");
            var ssidEl = document.getElementById("ap-ssid-input");
            var notesEl = document.getElementById("ap-notes-input");
            if (bssidEl) { bssidEl.value = ""; bssidEl.focus(); }
            if (ssidEl) ssidEl.value = "";
            if (notesEl) notesEl.value = "";
        });
    }

    var saveBtn = document.getElementById("ap-save-btn");
    if (saveBtn && !saveBtn._bound) {
        saveBtn._bound = true;
        saveBtn.addEventListener("click", function() { s._addWhitelistAP(); });
    }

    var cancelBtn = document.getElementById("ap-cancel-btn");
    if (cancelBtn && !cancelBtn._bound) {
        cancelBtn._bound = true;
        cancelBtn.addEventListener("click", function() {
            var form = document.getElementById("admin-ap-form");
            if (form) form.style.display = "none";
        });
    }
};

AdminPanel.prototype._addWhitelistAP = function() {
    var s = this;
    var bssidEl = document.getElementById("ap-bssid-input");
    var ssidEl = document.getElementById("ap-ssid-input");
    var notesEl = document.getElementById("ap-notes-input");

    var bssid = bssidEl ? bssidEl.value.trim() : "";
    if (!bssid) {
        notify("BSSID is required.", "error");
        if (bssidEl) try { bssidEl.focus(); } catch (_) {}
        return;
    }

    var body = {
        bssid: bssid,
        ssid: ssidEl ? ssidEl.value.trim() : "",
        notes: notesEl ? notesEl.value.trim() : ""
    };

    s.apiFetch("/api/admin/wifi-whitelist", {
        method: "POST", body: body
    }).then(function() {
        var form = document.getElementById("admin-ap-form");
        if (form) form.style.display = "none";
        s._loadWifiSecurity();
        notify("AP added to whitelist", "success");
    }).catch(function(e) {
        notify("Failed to add AP to whitelist: " + (e.detail || e.message || "Unknown error"), "error");
    });
};

AdminPanel.prototype._renderWhitelist = function(whitelist) {
    var tb = document.getElementById("admin-whitelist-tbody");
    var em = document.getElementById("admin-whitelist-empty");
    var tbl = document.getElementById("admin-whitelist-table");
    if (!tb) return;
    if (!whitelist || !whitelist.length) {
        tb.innerHTML = "";
        if (em) em.style.display = "";
        if (tbl) tbl.style.display = "none";
        return;
    }
    if (em) em.style.display = "none";
    if (tbl) tbl.style.display = "";

    var s = this, h = "";
    for (var i = 0; i < whitelist.length; i++) {
        var w = whitelist[i];
        h += "<tr>"
            + "<td data-label=\"BSSID\"><code>" + esc(w.bssid) + "</code></td>"
            + "<td data-label=\"SSID\">" + esc(w.ssid || "--") + "</td>"
            + "<td data-label=\"Notes\">" + esc(w.notes || "--") + "</td>"
            + "<td data-label=\"Added\">" + fmtTime(w.added_at) + "</td>"
            + "<td data-label=\"Actions\"><button class=\"btn btn-sm btn-danger\" data-wl-delete=\"" + esc(w.id) + "\">Remove</button></td>"
            + "</tr>";
    }
    tb.innerHTML = h;

    tb.querySelectorAll("[data-wl-delete]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var eid = this.getAttribute("data-wl-delete");
            confirmModal({
                title: "Remove AP from whitelist",
                message: "Remove this AP from the whitelist?\n\nIt will be eligible to trigger rogue-AP detections again.",
                confirmLabel: "Remove",
                destructive: true
            }).then(function(ok) {
                if (!ok) return;
                s.apiFetch("/api/admin/wifi-whitelist/" + encodeURIComponent(eid), { method: "DELETE" })
                    .then(function() { s._loadWifiSecurity(); notify("AP removed from whitelist", "success"); })
                    .catch(function(e) { notify("Failed to remove AP: " + (e.detail || e.message || "Unknown error"), "error"); });
            });
        });
    });
};

/* -- System Info ------------------------------------------------ */

AdminPanel.prototype._loadSystem = function() {
    var s = this;

    // Load metrics
    s._loadMetrics();

    // Session binding panel
    s._loadSessionBinding();

    // Bind auto-refresh toggle
    var arCb = document.getElementById("metrics-auto-refresh");
    if (arCb && !arCb._bound) {
        arCb._bound = true;
        arCb.addEventListener("change", function() {
            if (this.checked) {
                s._metricsInterval = setInterval(function() { s._loadMetrics(); }, 10000);
            } else {
                if (s._metricsInterval) { clearInterval(s._metricsInterval); s._metricsInterval = null; }
            }
        });
    }

    s.apiFetch("/api/admin/config").then(function(d) {
        var el = document.getElementById("system-config");
        if (!el) return;
        el.innerHTML = "<pre style=\"background:var(--bg-primary);padding:12px;border-radius:4px;border:1px solid var(--border-color);font-size:12px;\">"
            + esc(JSON.stringify(d, null, 2)) + "</pre>";

        // Populate retention policy card
        if (d.retention) {
            var daysEl = document.getElementById("retention-days-value");
            var srcEl = document.getElementById("retention-source-badge");
            if (daysEl) daysEl.textContent = String(d.retention.retention_days);
            if (srcEl) {
                var src = d.retention.source === "env" ? "ENV" : "DEFAULT";
                srcEl.textContent = src;
                srcEl.style.background = d.retention.source === "env" ? "var(--accent-green)" : "var(--accent-blue)";
                srcEl.style.color = "var(--bg-primary)";
            }
        }
    }).catch(function() {});

    s.apiFetch("/api/admin/sessions").then(function(d) {
        var el = document.getElementById("system-sessions");
        if (!el) return;
        var sessions = d.sessions || [];
        if (!sessions.length) {
            el.innerHTML = "<p class=\"empty-state\">No active sessions</p>";
            return;
        }
        var h = "<table class=\"data-table admin-table\"><thead><tr><th>Token</th><th>Key ID</th><th>Created</th><th>Expires</th></tr></thead><tbody>";
        for (var i = 0; i < sessions.length; i++) {
            var ss = sessions[i];
            h += "<tr><td data-label=\"Token\"><code>" + esc(ss.token_prefix) + "</code></td>"
                + "<td data-label=\"Key ID\">" + esc(ss.key_id) + "</td>"
                + "<td data-label=\"Created\">" + fmtTime(ss.created) + "</td>"
                + "<td data-label=\"Expires\">" + fmtTime(ss.expires) + "</td></tr>";
        }
        h += "</tbody></table>";
        el.innerHTML = h;
    }).catch(function() {});
};

AdminPanel.prototype._loadDbStats = function() {
    var s = this;
    var periodSel = document.getElementById("db-stats-period");
    var periodHours = periodSel ? parseInt(periodSel.value, 10) || 0 : 0;
    var url = "/api/admin/stats" + (periodHours > 0 ? "?period_hours=" + periodHours : "");

    s.apiFetch(url).then(function(d) {
        var el = document.getElementById("system-db-stats");
        if (!el) return;

        var stats = d.table_stats || [];
        var tableLabels = {
            "detections": "RF Detections",
            "detection_aggregates": "Detection Hourly Aggregates",
            "detection_feedback": "Operator Feedback",
            "audit_log": "Audit Log",
            "wifi_metadata": "WiFi Metadata (raw)",
            "wifi_metadata_hourly": "WiFi Metadata (hourly)",
            "wifi_anomalies": "WiFi Anomalies",
            "rf_anomalies": "RF Anomalies",
            "bt_devices": "Bluetooth Devices",
            "bt_anomalies": "Bluetooth Anomalies",
            "bt_devices_hourly": "Bluetooth Devices (hourly)",
            "fhss_events": "FHSS Events",
            "emitters": "Emitters",
            "tdoa_estimates": "TDoA Estimates",
            "spectrum_snapshots": "Spectrum Snapshots",
            "users": "Users",
            "sessions": "Sessions",
            "mfa_tokens": "MFA Tokens",
            "mfa_backup_codes": "MFA Backup Codes",
            "tenant_settings": "Tenant Settings",
            "schema_version": "Schema Migrations"
        };
        function fmtSz(b) {
            if (b >= 1073741824) return (b / 1073741824).toFixed(1) + " GB";
            if (b >= 1048576) return (b / 1048576).toFixed(1) + " MB";
            if (b >= 1024) return (b / 1024).toFixed(1) + " KB";
            return esc(b) + " B";
        }
        var showPeriod = periodHours > 0;
        var periodLabel = periodHours >= 168 ? "7d" : periodHours >= 48 ? "48h" : periodHours + "h";

        if (!stats.length) {
            var tables = d.tables || {};
            var h = "<table class=\"data-table admin-table\"><thead><tr><th>Table</th><th>Rows</th></tr></thead><tbody>";
            for (var t in tables) {
                h += "<tr><td data-label=\"Table\"><code>" + esc(t) + "</code></td><td data-label=\"Rows\">" + esc(tables[t]) + "</td></tr>";
            }
            h += "</tbody></table>";
            el.innerHTML = h;
        } else {
            var h = "<table class=\"data-table admin-table\"><thead><tr>"
                + "<th>Table</th><th>Rows</th><th>Size</th>"
                + "<th>1h</th><th>24h</th>";
            if (showPeriod) h += "<th>" + esc(periodLabel) + "</th>";
            h += "<th>Oldest</th><th>Newest</th>"
                + "</tr></thead><tbody>";
            for (var i = 0; i < stats.length; i++) {
                var t = stats[i];
                var label = tableLabels[t.name] || t.name;
                var szStr = fmtSz(t.size_bytes || 0);
                var rows1h = t.rows_1h != null ? fmtNum(t.rows_1h) : "--";
                var rows24h = t.rows_24h != null ? fmtNum(t.rows_24h) : "--";
                var oldest = t.oldest ? fmtTime(t.oldest) : "--";
                var newest = t.newest ? fmtTime(t.newest) : "--";

                h += "<tr>"
                    + "<td data-label=\"Table\"><code>" + esc(label) + "</code>"
                    + "<br><small style=\"color:var(--text-secondary);\">" + esc(t.name) + "</small></td>"
                    + "<td data-label=\"Rows\" style=\"text-align:right;font-family:var(--font-mono);\">" + fmtNum(t.rows) + "</td>"
                    + "<td data-label=\"Size\" style=\"text-align:right;font-family:var(--font-mono);\">" + esc(szStr) + "</td>"
                    + "<td data-label=\"1h\" style=\"text-align:right;font-family:var(--font-mono);\">" + rows1h + "</td>"
                    + "<td data-label=\"24h\" style=\"text-align:right;font-family:var(--font-mono);\">" + rows24h + "</td>";
                if (showPeriod) {
                    var rp = t.rows_period;
                    var rpStr = rp != null ? fmtNum(rp) : "--";
                    var rpColor = "";
                    if (rp != null && rp > 0) rpColor = "color:var(--accent-green);";
                    h += "<td style=\"text-align:right;font-family:var(--font-mono);" + rpColor + "\">"
                        + (rp != null && rp > 0 ? "+" : "") + rpStr + "</td>";
                }
                h += "<td data-label=\"Oldest\">" + oldest + "</td>"
                    + "<td data-label=\"Newest\">" + newest + "</td>"
                    + "</tr>";
            }
            h += "</tbody></table>";
            el.innerHTML = h;
        }

        // DB totals summary
        var totalRows = 0;
        for (var j = 0; j < stats.length; j++) totalRows += (stats[j].rows || 0);
        el.innerHTML += "<p style=\"margin-top:8px;color:var(--text-secondary);font-size:12px;\">"
            + "Total rows: <strong>" + fmtNum(totalRows) + "</strong>"
            + " | DB: " + esc(d.db_path) + " (" + fmtSz(d.db_size_bytes || 0) + ")"
            + " | WAL: " + fmtSz(d.wal_size_bytes || 0) + "</p>";
    }).catch(function() {});
};

AdminPanel.prototype._initMaintenance = function() {
    // PR-20 (dashboard cog review §3.1): risk-tiered maintenance surface.
    // Destructive purge tasks require type-to-confirm; low-risk DB ops use
    // a single confirmModal. Backend task identifiers are unchanged.
    var s = this;
    var buttons = document.querySelectorAll(".maint-task-btn");
    for (var i = 0; i < buttons.length; i++) {
        var b = buttons[i];
        if (b._bound) continue;
        b._bound = true;
        (function(btn) {
            btn.addEventListener("click", function() {
                s._runMaintenanceTask(btn);
            });
        })(b);
    }
};

AdminPanel.prototype._runMaintenanceTask = function(btn) {
    var s = this;
    var task = btn.getAttribute("data-task");
    var label = btn.getAttribute("data-label") || task;
    var destructive = btn.getAttribute("data-destructive") === "1";
    var usesRetention = btn.getAttribute("data-uses-retention") === "1";
    var phrase = btn.getAttribute("data-confirm-phrase") || "delete";
    var retEl = document.getElementById("maint-retention");
    var resultEl = document.getElementById("maint-result");

    var days = 7;
    if (usesRetention && retEl) {
        var n = parseInt(retEl.value, 10);
        if (!isNaN(n) && n >= 1) days = n;
    }

    if (!task) return;

    if (destructive) {
        s._confirmDestructiveMaintenance(task, label, phrase, days, usesRetention, resultEl, btn);
    } else {
        confirmModal({
            title: "Run maintenance task",
            message: "Run \"" + label + "\"?",
            confirmLabel: "Run",
            destructive: false
        }).then(function(ok) {
            if (!ok) return;
            s._executeMaintenance(task, days, label, resultEl, btn);
        });
    }
};

AdminPanel.prototype._confirmDestructiveMaintenance = function(task, label, phrase, days, usesRetention, resultEl, btn) {
    var s = this;
    // Type-to-confirm modal: submit enabled only when input matches phrase
    // exactly (case-insensitive, trimmed). Phrase is the dataset name so
    // it stays short and obvious (e.g. "iq captures", "audit log").
    var body = document.createElement("div");
    var retentionLine = usesRetention
        ? '<p style="margin:0 0 10px 0;font-size:13px;color:var(--text-secondary);">'
            + 'Retention window: <strong>' + esc(String(days)) + ' day' + (days === 1 ? '' : 's') + '</strong>. '
            + 'Rows older than this will be removed.</p>'
        : '';
    body.innerHTML = ''
        + '<p style="margin:0 0 8px 0;">'
        + 'This will <strong>permanently delete</strong> data for: <strong>' + esc(label) + '</strong>.'
        + '</p>'
        + retentionLine
        + '<p style="margin:12px 0 6px 0;font-size:13px;">'
        + 'To confirm, type <code style="background:var(--bg-input,#0d1117);padding:2px 6px;border-radius:3px;">' + esc(phrase) + '</code> below:'
        + '</p>'
        + '<input type="text" id="maint-confirm-input" autocomplete="off" spellcheck="false" placeholder="' + esc(phrase) + '">';

    var confirmBtnRef = null;
    var inputRef = null;
    function matches(val) {
        return (val || "").trim().toLowerCase() === phrase.toLowerCase();
    }

    var close = showModal({
        title: "Confirm destructive cleanup",
        body: body,
        buttons: [
            { label: "Cancel", kind: "cancel", onClick: function(c) { c(); } },
            {
                label: "Delete",
                kind: "destructive",
                onClick: function(c) {
                    if (!inputRef || !matches(inputRef.value)) return;
                    c();
                    s._executeMaintenance(task, days, label, resultEl, btn);
                }
            }
        ],
        onShow: function(bodyEl, closeFn) {
            inputRef = bodyEl.querySelector("#maint-confirm-input");
            // Find the destructive button in the modal's button row.
            var modalButtons = bodyEl.parentNode.querySelectorAll(".admin-modal-buttons button");
            for (var i = 0; i < modalButtons.length; i++) {
                if (modalButtons[i].classList.contains("destructive")) {
                    confirmBtnRef = modalButtons[i];
                    break;
                }
            }
            if (confirmBtnRef) confirmBtnRef.disabled = true;
            if (inputRef) {
                inputRef.focus();
                inputRef.addEventListener("input", function() {
                    if (confirmBtnRef) confirmBtnRef.disabled = !matches(inputRef.value);
                });
                inputRef.addEventListener("keydown", function(e) {
                    if (e.key === "Enter" && matches(inputRef.value)) {
                        e.preventDefault();
                        closeFn();
                        s._executeMaintenance(task, days, label, resultEl, btn);
                    }
                });
            }
        }
    });
    void close;
};

AdminPanel.prototype._executeMaintenance = function(task, days, label, resultEl, btn) {
    var s = this;
    var origLabel = null;
    if (btn) {
        origLabel = btn.textContent;
        btn.disabled = true;
        btn.textContent = "Running...";
    }

    s.apiFetch("/api/admin/maintenance", {
        method: "POST",
        body: { task: task, retention_days: days }
    }).then(function(d) {
        if (resultEl) {
            resultEl.style.display = "";
            var h = "<strong>" + esc(label) + "</strong> completed.";
            if (d.deleted != null) {
                if (typeof d.deleted === "object") {
                    h += "<br><br>";
                    for (var k in d.deleted) {
                        h += "<code>" + esc(k) + "</code>: " + esc(d.deleted[k]) + " removed<br>";
                    }
                } else {
                    h += " <strong>" + esc(d.deleted) + "</strong> rows/files removed.";
                }
            }
            function fmtBytes(b) {
                return b >= 1048576 ? (b / 1048576).toFixed(1) + " MB"
                    : b >= 1024 ? (b / 1024).toFixed(1) + " KB" : b + " B";
            }
            // A task that vacuums states the size once, on its VACUUM line.
            if (d.db_size_bytes != null && !d.vacuumed) {
                h += " DB size: " + esc(fmtBytes(d.db_size_bytes));
            }
            if (d.wal_pages != null) {
                h += " WAL pages: " + esc(d.wal_pages) + ", checkpointed: " + esc(d.checkpointed);
            }
            if (d.aggregated != null) h += " <strong>" + esc(d.aggregated) + "</strong> hourly buckets aggregated.";
            if (d.aggregated_wifi_hourly != null) h += "<br>WiFi hourly: <strong>" + esc(d.aggregated_wifi_hourly) + "</strong> buckets aggregated.";
            if (d.processed != null) {
                h += "<br>Processed: <strong>" + esc(d.processed) + "</strong>";
                if (d.dismissed != null) h += ", dismissed: <strong>" + esc(d.dismissed) + "</strong>";
                if (d.still_active != null) h += ", still active: <strong>" + esc(d.still_active) + "</strong>";
            }
            if (d.vacuumed) {
                h += "<br>VACUUM completed.";
                if (d.reclaimed_bytes != null) {
                    h += " Reclaimed: <strong>" + esc(fmtBytes(d.reclaimed_bytes)) + "</strong>";
                }
                if (d.db_size_bytes != null) {
                    h += " | DB size: <strong>" + esc(fmtBytes(d.db_size_bytes)) + "</strong>";
                }
            }
            if (d.note) h += "<br><small>" + esc(d.note) + "</small>";
            resultEl.innerHTML = h;
        }
        // Refresh DB stats and jobs
        s._loadDbStats();
        s._loadJobs();
    }).catch(function(e) {
        if (resultEl) {
            resultEl.style.display = "";
            resultEl.innerHTML = "<strong style=\"color:var(--accent-red);\">Failed:</strong> " + esc(e.detail || e.message || "Unknown error");
        }
    }).finally(function() {
        if (btn) {
            btn.disabled = false;
            if (origLabel != null) btn.textContent = origLabel;
        }
    });
};

AdminPanel.prototype._loadMetrics = function() {
    var s = this;
    s.apiFetch("/api/metrics").then(function(d) {
        var el = document.getElementById("system-metrics");
        if (!el) return;

        var uptime = d.uptime_seconds != null ? fmtUptime(d.uptime_seconds) : "--";
        var ingest = d.ingest || {};
        var ingestRate = ingest.detections_per_second != null ? ingest.detections_per_second.toFixed(1) + "/s" : "--";
        var db = d.database || {};
        var dbSize = db.db_size_mb != null ? db.db_size_mb.toFixed(1) + " MB" : "--";

        var ws = d.ws_clients || {};
        var wsDet = ws.detections != null ? ws.detections : "--";
        var wsAnom = ws.anomalies != null ? ws.anomalies : "--";
        var wsSpec = ws.spectrum != null ? ws.spectrum : "--";
        var wsWifi = ws.wifi != null ? ws.wifi : "--";

        el.innerHTML = ""
            + "<div class=\"metric-card\"><div class=\"metric-value\">" + esc(uptime) + "</div><div class=\"metric-label\">Uptime</div></div>"
            + "<div class=\"metric-card\"><div class=\"metric-value\">" + esc(ingestRate) + "</div><div class=\"metric-label\">Ingest Rate</div></div>"
            + "<div class=\"metric-card\"><div class=\"metric-value\">" + esc(dbSize) + "</div><div class=\"metric-label\">DB Size</div></div>"
            + "<div class=\"metric-card\"><div class=\"metric-value\">" + esc(wsDet) + "</div><div class=\"metric-label\">WS Detections</div></div>"
            + "<div class=\"metric-card\"><div class=\"metric-value\">" + esc(wsAnom) + "</div><div class=\"metric-label\">WS Anomalies</div></div>"
            + "<div class=\"metric-card\"><div class=\"metric-value\">" + esc(wsSpec) + "</div><div class=\"metric-label\">WS Spectrum</div></div>"
            + "<div class=\"metric-card\"><div class=\"metric-value\">" + esc(wsWifi) + "</div><div class=\"metric-label\">WS WiFi</div></div>";
    }).catch(function() {
        var el = document.getElementById("system-metrics");
        if (el) el.innerHTML = "<p class=\"empty-state\">Metrics unavailable</p>";
    });
};

/* -- Session Binding (admin toggle) ----------------------------- */

AdminPanel.prototype._loadSessionBinding = function() {
    var s = this;
    s.apiFetch("/api/admin/session-binding").then(function(d) {
        var sel = document.getElementById("session-binding-mode");
        var status = document.getElementById("session-binding-status");
        var banner = document.getElementById("session-binding-restart-banner");
        var gwEl = document.getElementById("session-binding-gateway-value");
        var savedEl = document.getElementById("session-binding-saved-value");
        if (!sel) return;
        sel.value = d.saved || "none";
        if (status) {
            status.textContent = "Saved preference: " + d.saved
                + " • Gateway active: " + d.gateway_active
                + (d.restart_required ? " • restart required ⚠" : "");
        }
        if (banner) {
            banner.style.display = d.restart_required ? "block" : "none";
            if (gwEl) gwEl.textContent = d.gateway_active;
            if (savedEl) savedEl.textContent = d.saved;
        }
    }).catch(function(e) {
        console.error("Failed to load session binding:", e);
        var status = document.getElementById("session-binding-status");
        if (status) status.textContent = "Failed to load: " + (e.message || e);
    });

    var btn = document.getElementById("session-binding-save-btn");
    if (btn && !btn._bound) {
        btn._bound = true;
        btn.addEventListener("click", function() { s._saveSessionBinding(); });
    }
};

AdminPanel.prototype._saveSessionBinding = function() {
    var s = this;
    var sel = document.getElementById("session-binding-mode");
    var status = document.getElementById("session-binding-status");
    if (!sel) return;
    var mode = sel.value;
    s.apiFetch("/api/admin/session-binding", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: mode })
    }).then(function(d) {
        if (status) {
            status.textContent = "Saved: " + d.saved
                + " • Gateway active: " + d.gateway_active
                + (d.restart_required ? " • restart required ⚠" : " • applied");
        }
        // Re-render the banner
        s._loadSessionBinding();
    }).catch(function(e) {
        if (status) status.textContent = "Save failed: " + (e.message || e);
    });
};

/* -- Log Viewer ------------------------------------------------- */

AdminPanel.prototype._loadLogs = function() {
    var s = this;
    var level = (document.getElementById("log-level-filter") || {}).value || "";
    var loggerName = (document.getElementById("log-logger-filter") || {}).value || "";
    var search = (document.getElementById("log-search") || {}).value || "";

    var params = "?limit=300";
    if (level) params += "&level=" + encodeURIComponent(level);
    if (loggerName) params += "&logger=" + encodeURIComponent(loggerName);
    if (search) params += "&search=" + encodeURIComponent(search);

    s.apiFetch("/api/admin/logs" + params).then(function(d) {
        s._renderLogs(d.entries || []);
        // Populate logger dropdown
        var sel = document.getElementById("log-logger-filter");
        if (sel && d.loggers) {
            var cur = sel.value;
            sel.innerHTML = "<option value=\"\">All Loggers</option>";
            for (var i = 0; i < d.loggers.length; i++) {
                sel.innerHTML += "<option value=\"" + esc(d.loggers[i]) + "\">" + esc(d.loggers[i]) + "</option>";
            }
            if (cur) sel.value = cur;
        }
    }).catch(function() {});

    // Bind controls (once)
    var rb = document.getElementById("log-refresh-btn");
    if (rb && !rb._bound) {
        rb._bound = true;
        rb.addEventListener("click", function() { s._loadLogs(); });
    }

    var si = document.getElementById("log-search");
    if (si && !si._bound) {
        si._bound = true;
        si.addEventListener("keydown", function(e) {
            if (e.key === "Enter") s._loadLogs();
        });
    }

    var lf = document.getElementById("log-level-filter");
    if (lf && !lf._bound) {
        lf._bound = true;
        lf.addEventListener("change", function() { s._loadLogs(); });
    }

    var lgf = document.getElementById("log-logger-filter");
    if (lgf && !lgf._bound) {
        lgf._bound = true;
        lgf.addEventListener("change", function() { s._loadLogs(); });
    }

    var ar = document.getElementById("log-auto-refresh");
    if (ar && !ar._bound) {
        ar._bound = true;
        ar.addEventListener("change", function() {
            if (this.checked) {
                s._logAutoInterval = setInterval(function() { s._loadLogs(); }, 5000);
            } else {
                if (s._logAutoInterval) { clearInterval(s._logAutoInterval); s._logAutoInterval = null; }
            }
        });
    }
};

AdminPanel.prototype._renderLogs = function(entries) {
    var el = document.getElementById("log-entries");
    var em = document.getElementById("log-empty");
    if (!el) return;
    if (!entries || !entries.length) { el.innerHTML = ""; if (em) em.style.display = ""; return; }
    if (em) em.style.display = "none";

    var h = "";
    for (var i = 0; i < entries.length; i++) {
        var e = entries[i];
        var ts = e.timestamp || "";
        // Show just HH:MM:SS from ISO timestamp
        var tsParts = ts.split("T");
        var timeStr = tsParts.length > 1 ? tsParts[1].substring(0, 8) : ts;

        h += "<div class=\"log-entry\">"
            + "<span class=\"log-ts\">" + esc(timeStr) + "</span>"
            + "<span class=\"log-level " + esc(e.level) + "\">" + esc(e.level) + "</span>"
            + "<span class=\"log-logger\">" + esc(e.logger) + "</span>"
            + "<span class=\"log-msg\">" + esc(e.message);
        if (e.exception) {
            h += "<span class=\"log-exc\">" + esc(e.exception) + "</span>";
        }
        h += "</span></div>";
    }
    el.innerHTML = h;
};

/* -- Database Backup -------------------------------------------- */

AdminPanel.prototype._initBackup = function() {
    var s = this;
    var createBtn = document.getElementById("backup-create-btn");
    if (createBtn && !createBtn._bound) {
        createBtn._bound = true;
        createBtn.addEventListener("click", function() { s._createBackup(); });
    }
    var refreshBtn = document.getElementById("backup-refresh-btn");
    if (refreshBtn && !refreshBtn._bound) {
        refreshBtn._bound = true;
        refreshBtn.addEventListener("click", function() { s._loadBackups(); });
    }
    s._loadBackups();
};

AdminPanel.prototype._createBackup = function() {
    var s = this;
    var resultEl = document.getElementById("backup-result");
    var btn = document.getElementById("backup-create-btn");

    if (btn) { btn.disabled = true; btn.textContent = "Creating..."; }

    s.apiFetch("/api/admin/backup", { method: "POST" })
        .then(function(d) {
            if (resultEl) {
                resultEl.style.display = "";
                resultEl.innerHTML = "<strong>Backup created!</strong> "
                    + esc(d.backup_file) + " (" + ((d.size_bytes || 0) / 1024).toFixed(1) + " KB)";
            }
            s._loadBackups();
        })
        .catch(function(e) {
            if (resultEl) {
                resultEl.style.display = "";
                resultEl.innerHTML = "<strong style=\"color:var(--accent-red);\">Failed:</strong> "
                    + esc(e.detail || e.message || "Unknown error");
            }
        })
        .finally(function() {
            if (btn) { btn.disabled = false; btn.textContent = "Create Backup"; }
        });
};

AdminPanel.prototype._loadBackups = function() {
    var s = this;
    var el = document.getElementById("backup-list");
    if (!el) return;

    s.apiFetch("/api/admin/backups").then(function(d) {
        var backups = d.backups || [];
        if (!backups.length) {
            el.innerHTML = "<p class=\"empty-state\">No backups</p>";
            return;
        }
        var h = "";
        for (var i = 0; i < backups.length; i++) {
            var b = backups[i];
            var sz = b.size_bytes || 0;
            var szStr = sz >= 1048576 ? (sz / 1048576).toFixed(1) + " MB"
                : sz >= 1024 ? (sz / 1024).toFixed(1) + " KB"
                : sz + " B";
            h += "<div class=\"backup-item\">"
                + "<span class=\"backup-name\">" + esc(b.name) + "</span>"
                + "<span class=\"backup-size\">" + esc(szStr) + "</span>"
                + "<span class=\"backup-date\">" + fmtTime(b.created) + "</span>"
                + "<button class=\"btn btn-sm\" data-dl-backup=\"" + esc(b.name) + "\">Download</button>"
                + "</div>";
        }
        el.innerHTML = h;

        // Bind download buttons (use fetch to include auth header)
        el.querySelectorAll("[data-dl-backup]").forEach(function(btn) {
            btn.addEventListener("click", function() {
                var fname = this.getAttribute("data-dl-backup");
                var headers = {};
                if (s.apiKey) headers["X-API-Key"] = s.apiKey;
                var _st = sessionStorage.getItem("bridge_session_token");
                if (_st && !s.apiKey) headers["X-Session-Token"] = _st;
                fetch("/api/admin/backups/" + encodeURIComponent(fname), {
                    headers: headers, credentials: "same-origin"
                }).then(function(r) {
                    if (!r.ok) throw new Error("HTTP " + r.status);
                    return r.blob();
                }).then(function(blob) {
                    var url = URL.createObjectURL(blob);
                    var a = document.createElement("a");
                    a.href = url; a.download = fname;
                    document.body.appendChild(a); a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                }).catch(function(e) {
                    notify("Download failed: " + (e.message || "Unknown error"), "error");
                });
            });
        });
    }).catch(function() {
        el.innerHTML = "<p class=\"empty-state\">Failed to load backups</p>";
    });
};

/* -- Advanced (Detection Config) -------------------------------- */

AdminPanel.prototype._loadAdvanced = function() {
    var s = this;
    var loadingEl = document.getElementById("det-config-loading");
    var fieldsEl = document.getElementById("det-config-fields");

    if (loadingEl) loadingEl.style.display = "";
    if (fieldsEl) fieldsEl.style.display = "none";

    s.apiFetch("/api/admin/detection-config").then(function(d) {
        s._detectionConfig = d.config || {};
        s._detectionDefaults = d.defaults || {};
        s._renderDetectionConfig();
        s._initSdrConfig();
        if (loadingEl) loadingEl.style.display = "none";
        if (fieldsEl) fieldsEl.style.display = "";
    }).catch(function(e) {
        console.error("Failed to load detection config:", e);
        if (loadingEl) loadingEl.innerHTML = "<span style=\"color:var(--accent-red);\">Failed to load detection config: " + esc(e.message || String(e)) + "</span>";
    });

    // Bind save/reset (once)
    var saveBtn = document.getElementById("det-config-save-btn");
    if (saveBtn && !saveBtn._bound) {
        saveBtn._bound = true;
        saveBtn.addEventListener("click", function() { s._saveDetectionConfig(); });
    }
    var resetBtn = document.getElementById("det-config-reset-btn");
    if (resetBtn && !resetBtn._bound) {
        resetBtn._bound = true;
        resetBtn.addEventListener("click", function() { s._resetDetectionConfig(); });
    }
};

AdminPanel.prototype._renderDetectionConfig = function() {
    var cfg = this._detectionConfig || {};
    var defs = this._detectionDefaults || {};

    // Field mapping: [inputId, defaultSpanId, configKey] — WiFi only
    var fields = [
        ["det-wifi-insert-threshold", "def-wifi-insert", "wifi_anomaly_insert_threshold"],
        ["det-wifi-alert-threshold", "def-wifi-alert", "wifi_anomaly_alert_threshold"],
        ["det-wifi-critical-threshold", "def-wifi-critical", "wifi_anomaly_critical_threshold"],
        ["det-wifi-cooldown", "def-wifi-cooldown", "wifi_anomaly_cooldown_seconds"],
        ["det-wifi-snooze-count", "def-wifi-snooze-count", "wifi_auto_snooze_seen_count"],
        ["det-wifi-snooze-score", "def-wifi-snooze-score", "wifi_auto_snooze_max_score"],
        ["det-wifi-snooze-hours", "def-wifi-snooze-hours", "wifi_auto_snooze_hours"]
    ];

    for (var i = 0; i < fields.length; i++) {
        var inputId = fields[i][0], defSpanId = fields[i][1], key = fields[i][2];
        var inp = document.getElementById(inputId);
        var defSpan = document.getElementById(defSpanId);
        var val = cfg[key] != null ? cfg[key] : defs[key];
        if (inp) inp.value = val != null ? val : "";
        if (defSpan) defSpan.textContent = defs[key] != null ? "(default: " + defs[key] + ")" : "";
    }

    // WiFi weight sliders only
    var wifiW = cfg.wifi_dimension_weights || defs.wifi_dimension_weights || {};
    var wifiDefW = defs.wifi_dimension_weights || {};
    this._renderWeightSliders("wifi-weights-container", "wifi-weight-sum", wifiW, wifiDefW, "wifi-w-");
};

AdminPanel.prototype._renderWeightSliders = function(containerId, sumId, weights, defaults, prefix) {
    var container = document.getElementById(containerId);
    if (!container) return;

    var keys = Object.keys(weights).sort();
    var h = "";
    for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        var v = parseFloat(weights[k]) || 0;
        var defV = defaults[k] != null ? defaults[k] : "?";
        var label = k.replace(/_/g, " ");
        h += "<div style=\"min-width:200px;flex:1;\">"
            + "<label style=\"font-size:12px;color:var(--text-secondary);display:flex;justify-content:space-between;\">"
            + "<span>" + esc(label) + "</span>"
            + "<span style=\"opacity:0.6;\">(default: " + esc(String(defV)) + ")</span></label>"
            + "<div style=\"display:flex;align-items:center;gap:6px;\">"
            + "<input type=\"range\" id=\"" + esc(prefix + k) + "\" min=\"0\" max=\"1\" step=\"0.01\" value=\"" + v.toFixed(2) + "\" "
            + "style=\"flex:1;\" data-weight-group=\"" + esc(prefix) + "\">"
            + "<span id=\"" + esc(prefix + k) + "-val\" style=\"font-family:var(--font-mono);font-size:12px;min-width:36px;text-align:right;\">"
            + v.toFixed(2) + "</span>"
            + "</div></div>";
    }
    container.innerHTML = h;

    // Bind range input updates
    var self = this;
    container.querySelectorAll("input[type=range]").forEach(function(inp) {
        inp.addEventListener("input", function() {
            var valEl = document.getElementById(this.id + "-val");
            if (valEl) valEl.textContent = parseFloat(this.value).toFixed(2);
            self._updateWeightSum(prefix, sumId, keys);
        });
    });
    this._updateWeightSum(prefix, sumId, keys);
};

AdminPanel.prototype._updateWeightSum = function(prefix, sumId, keys) {
    var sum = 0;
    for (var i = 0; i < keys.length; i++) {
        var inp = document.getElementById(prefix + keys[i]);
        if (inp) sum += parseFloat(inp.value) || 0;
    }
    var el = document.getElementById(sumId);
    if (el) {
        var color = Math.abs(sum - 1.0) < 0.01 ? "var(--accent-green)" : "var(--accent-red)";
        el.innerHTML = "(sum: <span style=\"color:" + color + ";\">" + sum.toFixed(2) + "</span>)";
    }
};

AdminPanel.prototype._collectWeights = function(prefix, keys) {
    var w = {};
    for (var i = 0; i < keys.length; i++) {
        var inp = document.getElementById(prefix + keys[i]);
        if (inp) w[keys[i]] = parseFloat(inp.value) || 0;
    }
    return w;
};

/* -- N1: Weight Preset Definitions -------------------------------- */

AdminPanel.prototype._weightPresets = {
    balanced: {
        novel_class:0.22, rare_class:0.12, low_confidence:0.14,
        power_zscore:0.13, snr_zscore:0.10,
        timing_anomaly:0.05, quiet_frequency:0.04,
        iq_quality:0.08, spectral_anomaly:0.07, modulation_anomaly:0.05
    },
    low_noise: {
        novel_class:0.18, rare_class:0.06, low_confidence:0.10,
        power_zscore:0.16, snr_zscore:0.14,
        timing_anomaly:0.03, quiet_frequency:0.03,
        iq_quality:0.12, spectral_anomaly:0.10, modulation_anomaly:0.08
    },
    novel_signal: {
        novel_class:0.30, rare_class:0.18, low_confidence:0.16,
        power_zscore:0.08, snr_zscore:0.06,
        timing_anomaly:0.04, quiet_frequency:0.05,
        iq_quality:0.05, spectral_anomaly:0.05, modulation_anomaly:0.03
    },
    power_anomaly: {
        novel_class:0.12, rare_class:0.06, low_confidence:0.08,
        power_zscore:0.22, snr_zscore:0.18,
        timing_anomaly:0.06, quiet_frequency:0.03,
        iq_quality:0.10, spectral_anomaly:0.10, modulation_anomaly:0.05
    }
};

/* -- N3: Semantic Weight Grouping --------------------------------- */

AdminPanel.prototype._weightGroups = [
    { name: "Signal Identity", keys: ["novel_class", "rare_class", "low_confidence"] },
    { name: "Signal Characteristics", keys: ["power_zscore", "snr_zscore"] },
    { name: "Behavioral Pattern", keys: ["timing_anomaly", "quiet_frequency"] },
    { name: "Signal Quality", keys: ["iq_quality", "spectral_anomaly", "modulation_anomaly"] }
];

AdminPanel.prototype._renderGroupedWeightSliders = function(containerId, sumId, weights, defaults, prefix) {
    var container = document.getElementById(containerId);
    if (!container) return;

    var allKeys = [];
    var groups = this._weightGroups;
    var h = "";

    for (var g = 0; g < groups.length; g++) {
        var grp = groups[g];
        var groupId = prefix + "group-" + g;
        h += "<div class=\"weight-group\" id=\"" + esc(groupId) + "\">";
        h += "<div class=\"weight-group-header\" data-group=\"" + esc(groupId) + "\">";
        h += "<span><span class=\"group-chevron\">&#9660;</span> " + esc(grp.name) + "</span>";
        h += "<span class=\"group-sum\" id=\"" + esc(groupId) + "-sum\"></span>";
        h += "</div>";
        h += "<div class=\"weight-group-sliders\">";

        for (var i = 0; i < grp.keys.length; i++) {
            var k = grp.keys[i];
            allKeys.push(k);
            var v = parseFloat(weights[k]) || 0;
            var defV = defaults[k] != null ? defaults[k] : "?";
            var label = k.replace(/_/g, " ");
            h += "<div style=\"min-width:200px;flex:1;\">"
                + "<label style=\"font-size:12px;color:var(--text-secondary);display:flex;justify-content:space-between;\">"
                + "<span>" + esc(label) + "</span>"
                + "<span style=\"opacity:0.6;\">(default: " + esc(String(defV)) + ")</span></label>"
                + "<div style=\"display:flex;align-items:center;gap:6px;\">"
                + "<input type=\"range\" id=\"" + esc(prefix + k) + "\" min=\"0\" max=\"1\" step=\"0.01\" value=\"" + v.toFixed(2) + "\" "
                + "style=\"flex:1;\" data-weight-group=\"" + esc(prefix) + "\">"
                + "<span id=\"" + esc(prefix + k) + "-val\" style=\"font-family:var(--font-mono);font-size:12px;min-width:36px;text-align:right;\">"
                + v.toFixed(2) + "</span>"
                + "</div></div>";
        }

        h += "</div></div>";
    }

    container.innerHTML = h;

    // Store all keys for sum calculation
    this._sdrRfWeightKeys = allKeys;

    var self = this;

    // Bind collapse/expand
    container.querySelectorAll(".weight-group-header").forEach(function(hdr) {
        hdr.addEventListener("click", function() {
            var grpEl = document.getElementById(this.getAttribute("data-group"));
            if (grpEl) grpEl.classList.toggle("collapsed");
        });
    });

    // Bind range input updates
    container.querySelectorAll("input[type=range]").forEach(function(inp) {
        inp.addEventListener("input", function() {
            var valEl = document.getElementById(this.id + "-val");
            if (valEl) valEl.textContent = parseFloat(this.value).toFixed(2);
            self._updateWeightSum(prefix, sumId, allKeys);
            self._updateGroupSums(prefix);
            self._syncWeightPreset();
            self._disableRescoreBtn();
        });
    });

    this._updateWeightSum(prefix, sumId, allKeys);
    this._updateGroupSums(prefix);
};

AdminPanel.prototype._updateGroupSums = function(prefix) {
    var groups = this._weightGroups;
    for (var g = 0; g < groups.length; g++) {
        var grp = groups[g];
        var sum = 0;
        for (var i = 0; i < grp.keys.length; i++) {
            var inp = document.getElementById(prefix + grp.keys[i]);
            if (inp) sum += parseFloat(inp.value) || 0;
        }
        var sumEl = document.getElementById(prefix + "group-" + g + "-sum");
        if (sumEl) sumEl.textContent = "(" + sum.toFixed(2) + ")";
    }
};

/* -- N1: Preset Selection ----------------------------------------- */

AdminPanel.prototype._syncWeightPreset = function() {
    var sel = document.getElementById("sdr-weight-preset");
    if (!sel) return;
    var presets = this._weightPresets;
    var prefix = "sdr-rf-w-";
    var matched = "custom";

    for (var name in presets) {
        var p = presets[name];
        var match = true;
        for (var k in p) {
            var inp = document.getElementById(prefix + k);
            if (!inp || Math.abs(parseFloat(inp.value) - p[k]) > 0.005) {
                match = false;
                break;
            }
        }
        if (match) { matched = name; break; }
    }
    sel.value = matched;
};

AdminPanel.prototype._applyWeightPreset = function(presetName) {
    var presets = this._weightPresets;
    var p = presets[presetName];
    if (!p) return;
    var prefix = "sdr-rf-w-";
    for (var k in p) {
        var inp = document.getElementById(prefix + k);
        if (inp) {
            inp.value = p[k].toFixed(2);
            var valEl = document.getElementById(prefix + k + "-val");
            if (valEl) valEl.textContent = p[k].toFixed(2);
        }
    }
    var keys = this._sdrRfWeightKeys || Object.keys(p);
    this._updateWeightSum(prefix, "sdr-rf-weight-sum", keys);
    this._updateGroupSums(prefix);
    this._disableRescoreBtn();
};

/* -- N5: Rescore Safety Gate -------------------------------------- */

AdminPanel.prototype._disableRescoreBtn = function() {
    var btn = document.getElementById("sdr-rescore-btn");
    if (btn) {
        btn.disabled = true;
        btn.title = "Run simulation first";
    }
    // Hide stale simulation results
    var simResults = document.getElementById("sdr-simulate-results");
    if (simResults) simResults.style.display = "none";
};

AdminPanel.prototype._enableRescoreBtn = function() {
    var btn = document.getElementById("sdr-rescore-btn");
    if (btn) {
        btn.disabled = false;
        btn.title = "";
    }
};

AdminPanel.prototype._saveDetectionConfig = function() {
    var s = this;
    var resultEl = document.getElementById("det-config-result");
    var btn = document.getElementById("det-config-save-btn");

    var body = {};

    // Scalar fields — WiFi only
    var fields = [
        ["det-wifi-insert-threshold", "wifi_anomaly_insert_threshold", parseFloat],
        ["det-wifi-alert-threshold", "wifi_anomaly_alert_threshold", parseFloat],
        ["det-wifi-critical-threshold", "wifi_anomaly_critical_threshold", parseFloat],
        ["det-wifi-cooldown", "wifi_anomaly_cooldown_seconds", parseInt],
        ["det-wifi-snooze-count", "wifi_auto_snooze_seen_count", parseInt],
        ["det-wifi-snooze-score", "wifi_auto_snooze_max_score", parseFloat],
        ["det-wifi-snooze-hours", "wifi_auto_snooze_hours", parseInt]
    ];
    for (var i = 0; i < fields.length; i++) {
        var inp = document.getElementById(fields[i][0]);
        if (inp && inp.value !== "") body[fields[i][1]] = fields[i][2](inp.value);
    }

    // WiFi weights only
    var wifiWeightKeys = Object.keys(s._detectionDefaults.wifi_dimension_weights || {});
    if (wifiWeightKeys.length) body.wifi_dimension_weights = s._collectWeights("wifi-w-", wifiWeightKeys);

    if (btn) { btn.disabled = true; btn.textContent = "Saving..."; }

    s.apiFetch("/api/admin/detection-config", {
        method: "PUT", body: body
    }).then(function(d) {
        s._detectionConfig = d.config || {};
        if (resultEl) {
            resultEl.style.display = "";
            resultEl.innerHTML = "<strong style=\"color:var(--accent-green);\">Detection config saved.</strong>";
            setTimeout(function() { resultEl.style.display = "none"; }, 4000);
        }
    }).catch(function(e) {
        if (resultEl) {
            resultEl.style.display = "";
            resultEl.innerHTML = "<strong style=\"color:var(--accent-red);\">Failed:</strong> " + esc(e.detail || e.message || "Unknown error");
        }
    }).finally(function() {
        if (btn) { btn.disabled = false; btn.textContent = "Save WiFi Config"; }
    });
};

AdminPanel.prototype._resetDetectionConfig = function() {
    var s = this;
    confirmModal({
        title: "Reset WiFi scoring",
        message: "Reset WiFi scoring to factory defaults?\n\nAlert thresholds, snooze windows, and dimension weights will all revert.",
        confirmLabel: "Reset",
        destructive: true
    }).then(function(ok) {
        if (!ok) return;
        var resultEl = document.getElementById("det-config-result");
        var defs = s._detectionDefaults;
        var body = {
            wifi_anomaly_insert_threshold: defs.wifi_anomaly_insert_threshold,
            wifi_anomaly_alert_threshold: defs.wifi_anomaly_alert_threshold,
            wifi_anomaly_critical_threshold: defs.wifi_anomaly_critical_threshold,
            wifi_anomaly_cooldown_seconds: defs.wifi_anomaly_cooldown_seconds,
            wifi_auto_snooze_seen_count: defs.wifi_auto_snooze_seen_count,
            wifi_auto_snooze_max_score: defs.wifi_auto_snooze_max_score,
            wifi_auto_snooze_hours: defs.wifi_auto_snooze_hours,
            wifi_dimension_weights: defs.wifi_dimension_weights
        };

        s.apiFetch("/api/admin/detection-config", {
            method: "PUT", body: body
        }).then(function(d) {
            s._detectionConfig = d.config || {};
            s._renderDetectionConfig();
            if (resultEl) {
                resultEl.style.display = "";
                resultEl.innerHTML = "<strong style=\"color:var(--accent-green);\">WiFi config reset to defaults.</strong>";
                setTimeout(function() { resultEl.style.display = "none"; }, 4000);
            }
        }).catch(function(e) {
            if (resultEl) {
                resultEl.style.display = "";
                resultEl.innerHTML = "<strong style=\"color:var(--accent-red);\">Failed:</strong> " + esc(e.detail || e.message || "Unknown error");
            }
            notify("Reset failed: " + (e.detail || e.message || "Unknown error"), "error");
        });
    });
};

/* -- SDR Scoring Panel ------------------------------------------ */

AdminPanel.prototype._initSdrConfig = function() {
    var s = this;
    // Reuse detection config data (same endpoint)
    var cfg = s._detectionConfig || {};
    var defs = s._detectionDefaults || {};

    var loading = document.getElementById("sdr-config-loading");
    var fields = document.getElementById("sdr-config-fields");
    if (loading) loading.style.display = "none";
    if (fields) fields.style.display = "";

    s._renderSdrConfig();

    // Bind save/reset
    var saveBtn = document.getElementById("sdr-config-save-btn");
    if (saveBtn && !saveBtn._bound) {
        saveBtn._bound = true;
        saveBtn.addEventListener("click", function() { s._saveSdrConfig(); });
    }
    var resetBtn = document.getElementById("sdr-config-reset-btn");
    if (resetBtn && !resetBtn._bound) {
        resetBtn._bound = true;
        resetBtn.addEventListener("click", function() { s._resetSdrConfig(); });
    }
    var simBtn = document.getElementById("sdr-simulate-btn");
    if (simBtn && !simBtn._bound) {
        simBtn._bound = true;
        simBtn.addEventListener("click", function() { s._simulateRescore(); });
    }
    var rescoreBtn = document.getElementById("sdr-rescore-btn");
    if (rescoreBtn && !rescoreBtn._bound) {
        rescoreBtn._bound = true;
        rescoreBtn.addEventListener("click", function() { s._rescoreRfAnomalies(); });
    }

    // N1: Bind preset dropdown
    var presetSel = document.getElementById("sdr-weight-preset");
    if (presetSel && !presetSel._bound) {
        presetSel._bound = true;
        presetSel.addEventListener("change", function() {
            if (this.value !== "custom") s._applyWeightPreset(this.value);
        });
    }

    // N5: Disable rescore on load
    s._disableRescoreBtn();
};

AdminPanel.prototype._renderSdrConfig = function() {
    var cfg = this._detectionConfig || {};
    var defs = this._detectionDefaults || {};

    var scalarFields = [
        ["sdr-rf-insert-threshold", "sdr-def-insert", "rf_anomaly_insert_threshold"],
        ["sdr-rf-alert-threshold", "sdr-def-alert", "rf_anomaly_alert_threshold"],
        ["sdr-rf-critical-threshold", "sdr-def-critical", "rf_anomaly_critical_threshold"],
        ["sdr-rf-confidence-floor", "sdr-def-conf-floor", "rf_min_confidence_floor"],
        ["sdr-rf-learning-detections", "sdr-def-learning", "rf_min_learning_detections"],
        ["sdr-rf-snooze-count", "sdr-def-rf-snooze-count", "rf_auto_snooze_seen_count"],
        ["sdr-rf-snooze-score", "sdr-def-rf-snooze-score", "rf_auto_snooze_max_score"],
        ["sdr-rf-snooze-hours", "sdr-def-rf-snooze-hours", "rf_auto_snooze_hours"]
    ];

    for (var i = 0; i < scalarFields.length; i++) {
        var inputId = scalarFields[i][0], defSpanId = scalarFields[i][1], key = scalarFields[i][2];
        var inp = document.getElementById(inputId);
        var defSpan = document.getElementById(defSpanId);
        var val = cfg[key] != null ? cfg[key] : defs[key];
        if (inp) inp.value = val != null ? val : "";
        if (defSpan) defSpan.textContent = defs[key] != null ? "(default: " + defs[key] + ")" : "";
    }

    // RF dimension weights — grouped
    var rfW = cfg.rf_dimension_weights || defs.rf_dimension_weights || {};
    var rfDefW = defs.rf_dimension_weights || {};
    this._renderGroupedWeightSliders("sdr-rf-weights-container", "sdr-rf-weight-sum", rfW, rfDefW, "sdr-rf-w-");
    this._syncWeightPreset();
};

AdminPanel.prototype._saveSdrConfig = function() {
    var s = this;
    var resultEl = document.getElementById("sdr-config-result");
    var btn = document.getElementById("sdr-config-save-btn");

    var body = {};

    var scalarFields = [
        ["sdr-rf-insert-threshold", "rf_anomaly_insert_threshold", parseFloat],
        ["sdr-rf-alert-threshold", "rf_anomaly_alert_threshold", parseFloat],
        ["sdr-rf-critical-threshold", "rf_anomaly_critical_threshold", parseFloat],
        ["sdr-rf-confidence-floor", "rf_min_confidence_floor", parseFloat],
        ["sdr-rf-learning-detections", "rf_min_learning_detections", parseInt],
        ["sdr-rf-snooze-count", "rf_auto_snooze_seen_count", parseInt],
        ["sdr-rf-snooze-score", "rf_auto_snooze_max_score", parseFloat],
        ["sdr-rf-snooze-hours", "rf_auto_snooze_hours", parseInt]
    ];
    for (var i = 0; i < scalarFields.length; i++) {
        var inp = document.getElementById(scalarFields[i][0]);
        if (inp && inp.value !== "") body[scalarFields[i][1]] = scalarFields[i][2](inp.value);
    }

    // RF weights from sliders
    var rfDefWeights = s._detectionDefaults.rf_dimension_weights || {};
    var rfWeightKeys = Object.keys(rfDefWeights);
    if (rfWeightKeys.length) body.rf_dimension_weights = s._collectWeights("sdr-rf-w-", rfWeightKeys);

    if (btn) { btn.disabled = true; btn.textContent = "Saving..."; }

    s.apiFetch("/api/admin/detection-config", {
        method: "PUT", body: body
    }).then(function(d) {
        s._detectionConfig = d.config || {};
        // Also refresh the Detection Logic panel if it was loaded
        s._renderDetectionConfig();
        // N5: Config changed — invalidate simulation
        s._disableRescoreBtn();
        if (resultEl) {
            resultEl.style.display = "";
            resultEl.innerHTML = "<strong style=\"color:var(--accent-green);\">SDR scoring config saved.</strong>";
            setTimeout(function() { resultEl.style.display = "none"; }, 4000);
        }
    }).catch(function(e) {
        if (resultEl) {
            resultEl.style.display = "";
            resultEl.innerHTML = "<strong style=\"color:var(--accent-red);\">Failed:</strong> " + esc(e.detail || e.message || "Unknown error");
        }
    }).finally(function() {
        if (btn) { btn.disabled = false; btn.textContent = "Save SDR Config"; }
    });
};

AdminPanel.prototype._resetSdrConfig = function() {
    var s = this;
    confirmModal({
        title: "Reset SDR scoring",
        message: "Reset SDR scoring to factory defaults?\n\nThis will change alert thresholds, confidence floor, learning detections, and all RF dimension weights.",
        confirmLabel: "Reset",
        destructive: true
    }).then(function(ok) {
        if (!ok) return;
        var resultEl = document.getElementById("sdr-config-result");
        var defs = s._detectionDefaults;

        var body = {
            rf_anomaly_insert_threshold: defs.rf_anomaly_insert_threshold,
            rf_anomaly_alert_threshold: defs.rf_anomaly_alert_threshold,
            rf_anomaly_critical_threshold: defs.rf_anomaly_critical_threshold,
            rf_min_confidence_floor: defs.rf_min_confidence_floor,
            rf_min_learning_detections: defs.rf_min_learning_detections,
            rf_auto_snooze_seen_count: defs.rf_auto_snooze_seen_count,
            rf_auto_snooze_max_score: defs.rf_auto_snooze_max_score,
            rf_auto_snooze_hours: defs.rf_auto_snooze_hours,
            rf_dimension_weights: defs.rf_dimension_weights
        };

        s.apiFetch("/api/admin/detection-config", {
            method: "PUT", body: body
        }).then(function(d) {
            s._detectionConfig = d.config || {};
            s._renderSdrConfig();
            s._renderDetectionConfig();
            // N5: Config changed — invalidate simulation
            s._disableRescoreBtn();
            if (resultEl) {
                resultEl.style.display = "";
                resultEl.innerHTML = "<strong style=\"color:var(--accent-green);\">SDR scoring reset to defaults.</strong>";
                setTimeout(function() { resultEl.style.display = "none"; }, 4000);
            }
        }).catch(function(e) {
            if (resultEl) {
                resultEl.style.display = "";
                resultEl.innerHTML = "<strong style=\"color:var(--accent-red);\">Failed:</strong> " + esc(e.detail || e.message || "Unknown error");
            }
            notify("Reset failed: " + (e.detail || e.message || "Unknown error"), "error");
        });
    });
};

AdminPanel.prototype._simulateRescore = function() {
    var btn = document.getElementById("sdr-simulate-btn");
    var statusEl = document.getElementById("sdr-rescore-status");
    var simPanel = document.getElementById("sdr-simulate-results");
    if (btn) { btn.disabled = true; btn.textContent = "Simulating..."; }
    if (statusEl) { statusEl.textContent = "Calculating..."; statusEl.style.color = "var(--text-secondary)"; }
    if (simPanel) simPanel.style.display = "none";

    var s = this;
    s.apiFetch("/api/admin/simulate-rescore-rf", { method: "POST" })
        .then(function(d) {
            if (statusEl) statusEl.textContent = "";

            // Build in-page results
            if (simPanel) {
                var pb = d.priority_before || {};
                var pa = d.priority_after || {};
                var allPriorities = {};
                var k;
                for (k in pb) allPriorities[k] = true;
                for (k in pa) allPriorities[k] = true;
                var prioKeys = Object.keys(allPriorities).sort();

                var h = "<h4>Rescore Simulation (dry run)</h4>";
                h += "<div class=\"sim-stats\">";
                h += "<span class=\"sim-stat\">Current: <strong>" + esc(String(d.total)) + "</strong></span>";
                h += "<span class=\"sim-stat\">Would remove: <strong>" + esc(String(d.would_remove)) + "</strong></span>";
                h += "<span class=\"sim-stat\">Would update: <strong>" + esc(String(d.would_update)) + "</strong></span>";
                h += "<span class=\"sim-stat\">Unchanged: <strong>" + esc(String(d.unchanged)) + "</strong></span>";
                h += "<span class=\"sim-stat\">Remaining: <strong>" + esc(String(d.remaining)) + "</strong></span>";
                h += "</div>";

                h += "<table><thead><tr><th>Priority</th><th>Before</th><th>After</th></tr></thead><tbody>";
                for (var i = 0; i < prioKeys.length; i++) {
                    var pk = prioKeys[i];
                    h += "<tr><td>" + esc(pk) + "</td><td>" + esc(String(pb[pk] || 0)) + "</td><td>" + esc(String(pa[pk] || 0)) + "</td></tr>";
                }
                h += "</tbody></table>";

                h += "<button class=\"sim-copy-btn\" id=\"sdr-sim-copy-btn\">Copy Results</button>";
                simPanel.innerHTML = h;
                simPanel.style.display = "";

                // Copy button
                var copyBtn = document.getElementById("sdr-sim-copy-btn");
                if (copyBtn) {
                    copyBtn.addEventListener("click", function() {
                        var lines = [];
                        lines.push("Rescore Simulation (dry run)");
                        lines.push("Current: " + d.total + " | Remove: " + d.would_remove + " | Update: " + d.would_update + " | Unchanged: " + d.unchanged + " | Remaining: " + d.remaining);
                        lines.push("");
                        lines.push("Priority\tBefore\tAfter");
                        for (var j = 0; j < prioKeys.length; j++) {
                            lines.push(prioKeys[j] + "\t" + (pb[prioKeys[j]] || 0) + "\t" + (pa[prioKeys[j]] || 0));
                        }
                        navigator.clipboard.writeText(lines.join("\n")).then(function() {
                            copyBtn.textContent = "Copied!";
                            setTimeout(function() { copyBtn.textContent = "Copy Results"; }, 2000);
                        });
                    });
                }
            }

            // N5: Enable rescore after successful simulation
            s._enableRescoreBtn();
        })
        .catch(function(e) {
            if (statusEl) {
                statusEl.style.color = "var(--accent-red)";
                statusEl.textContent = "Simulation failed: " + (e.detail || e.message || "Unknown error");
            }
        })
        .finally(function() {
            if (btn) { btn.disabled = false; btn.textContent = "Simulate Rescore"; }
        });
};

AdminPanel.prototype._rescoreRfAnomalies = function() {
    var s = this;
    confirmModal({
        title: "Rescore RF anomalies",
        message: "Re-evaluate all RF anomalies with the current scoring engine?\n\nAnomalies below the insert threshold or confidence floor will be removed.",
        confirmLabel: "Rescore",
        destructive: true
    }).then(function(ok) {
        if (!ok) return;
        var btn = document.getElementById("sdr-rescore-btn");
        var statusEl = document.getElementById("sdr-rescore-status");
        var simPanel = document.getElementById("sdr-simulate-results");
        if (btn) { btn.disabled = true; btn.textContent = "Rescoring..."; }
        if (statusEl) { statusEl.textContent = "Processing..."; statusEl.style.color = "var(--text-secondary)"; }

        s.apiFetch("/api/admin/rescore-rf-anomalies", { method: "POST" })
            .then(function(d) {
                if (statusEl) {
                    statusEl.style.color = "var(--accent-green)";
                    statusEl.textContent = d.updated + " updated, " + d.removed + " removed (of " + d.total + " total)";
                }
                // Hide simulation results after rescore
                if (simPanel) simPanel.style.display = "none";
            })
            .catch(function(e) {
                if (statusEl) {
                    statusEl.style.color = "var(--accent-red)";
                    statusEl.textContent = "Failed: " + (e.detail || e.message || "Unknown error");
                }
                notify("Rescore failed: " + (e.detail || e.message || "Unknown error"), "error");
            })
            .finally(function() {
                // N5: Disable rescore after completion
                s._disableRescoreBtn();
                if (btn) { btn.textContent = "Rescore Anomalies"; }
            });
    });
};

/* -- Report Generation ------------------------------------------ */

AdminPanel.prototype._loadReports = function() {
    var s = this;
    var btn = document.getElementById("generate-report-btn");
    if (btn && !btn._bound) {
        btn._bound = true;
        btn.addEventListener("click", function() { s._generateReport(); });
    }
};

AdminPanel.prototype._generateReport = function() {
    var s = this;
    var hoursEl = document.getElementById("report-hours");
    var formatEl = document.getElementById("report-format");
    var statusEl = document.getElementById("report-status");
    var statusText = document.getElementById("report-status-text");

    var hours = hoursEl ? hoursEl.value : "24";
    var fmt = formatEl ? formatEl.value : "html";

    // Collect selected sections
    var checks = document.querySelectorAll(".report-section:checked");
    var secs = [];
    checks.forEach(function(cb) { secs.push(cb.value); });
    if (secs.length === 0) secs = ["detections", "anomalies", "spectrum", "nodes", "alerts"];

    if (statusEl) { statusEl.style.display = ""; }
    if (statusText) { statusText.textContent = "Generating report..."; }

    var url = "/api/reports/generate?hours=" + encodeURIComponent(hours)
            + "&format=" + encodeURIComponent(fmt)
            + "&sections=" + encodeURIComponent(secs.join(","));

    var rh = {};
    if (s.apiKey) rh["X-API-Key"] = s.apiKey;
    var st = sessionStorage.getItem("bridge_session_token");
    if (st && !s.apiKey) rh["X-Session-Token"] = st;

    fetch(url, {
        headers: rh,
        credentials: "same-origin"
    }).then(function(resp) {
        if (!resp.ok) return resp.json().then(function(e) { return Promise.reject(e); });
        var disposition = resp.headers.get("content-disposition") || "";
        var match = disposition.match(/filename="?([^"]+)"?/);
        var filename = match ? match[1] : "report." + fmt;
        return resp.blob().then(function(blob) { return { blob: blob, filename: filename }; });
    }).then(function(result) {
        var a = document.createElement("a");
        a.href = URL.createObjectURL(result.blob);
        a.download = result.filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(a.href);
        if (statusText) { statusText.textContent = "Report downloaded: " + result.filename; }
    }).catch(function(e) {
        if (statusText) {
            statusText.innerHTML = "<strong style=\"color:var(--accent-red);\">Failed:</strong> " + esc(e.detail || e.message || "Report generation failed");
        }
    });
};

/* -- ML Advisor ------------------------------------------------- */

AdminPanel.prototype._loadMLAdvisor = function() {
    var s = this;
    var btn = document.getElementById("ml-advisor-refresh");
    if (btn && !btn._bound) {
        btn._bound = true;
        btn.addEventListener("click", function() { s._runMLAnalysis(); });
    }
};

AdminPanel.prototype._runMLAnalysis = function() {
    var s = this;
    var btn = document.getElementById("ml-advisor-refresh");
    if (btn) { btn.disabled = true; btn.textContent = "Analyzing..."; }

    // Fetch all needed data in parallel
    Promise.all([
        s.apiFetch("/api/detections/distribution?hours=24").catch(function() { return {}; }),
        s.apiFetch("/api/detections/anomalies/summary").catch(function() { return {}; }),
        s.apiFetch("/api/training/runs").catch(function() { return { runs: [] }; }),
        s.apiFetch("/api/nodes/").catch(function() { return []; }),
        s.apiFetch("/api/spectrum/monitor/peaks?hours=24").catch(function() { return { peaks: [] }; }),
        s.apiFetch("/api/metrics").catch(function() { return {}; }),
        s.apiFetch("/api/detections/correlations/summary?hours=24").catch(function() { return {}; }),
        s.apiFetch("/api/bluetooth/stats").catch(function() { return {}; }),
    ]).then(function(results) {
        var dist = results[0] || {};
        var anomSummary = results[1] || {};
        var training = results[2] || {};
        var nodes = results[3] || [];
        var peaks = results[4] || {};
        var metrics = results[5] || {};
        var corr = results[6] || {};
        var bt = results[7] || {};

        s._renderMLMetrics(dist, anomSummary, training, nodes, metrics);
        s._renderClassificationAdvice(dist, training);
        s._renderAnomalyAdvice(anomSummary, corr, nodes);
        s._renderDataAdvice(dist, nodes, peaks, bt, metrics);
        s._renderExpansionAdvice(dist, training, nodes, bt, peaks);

        document.getElementById("ml-advisor-empty").style.display = "none";
    }).catch(function(e) {
        console.error("ML analysis failed:", e);
    }).finally(function() {
        if (btn) { btn.disabled = false; btn.textContent = "Analyze Platform"; }
    });
};

AdminPanel.prototype._renderMLMetrics = function(dist, anomSummary, training, nodes, metrics) {
    var el = document.getElementById("ml-advisor-metrics");
    if (!el) return;

    var classes = dist.classes ? Object.keys(dist.classes).length : 0;
    var totalDet = dist.total || 0;
    var anomCount = anomSummary.total_rf || anomSummary.total || 0;
    var runs = training.runs ? training.runs.length : 0;
    var activeNodes = Array.isArray(nodes) ? nodes.filter(function(n) { return n && n.status === "active"; }).length : 0;
    var ingestRate = metrics.ingest ? (metrics.ingest.detections_per_second || 0).toFixed(1) + "/s" : "--";

    el.innerHTML = ""
        + "<div class=\"metric-card\"><div class=\"metric-value\">" + classes + "</div><div class=\"metric-label\">Signal Classes (24h)</div></div>"
        + "<div class=\"metric-card\"><div class=\"metric-value\">" + fmtNum(totalDet) + "</div><div class=\"metric-label\">Detections (24h)</div></div>"
        + "<div class=\"metric-card\"><div class=\"metric-value\">" + fmtNum(anomCount) + "</div><div class=\"metric-label\">RF Anomalies</div></div>"
        + "<div class=\"metric-card\"><div class=\"metric-value\">" + runs + "</div><div class=\"metric-label\">Training Runs</div></div>"
        + "<div class=\"metric-card\"><div class=\"metric-value\">" + activeNodes + "/" + (Array.isArray(nodes) ? nodes.length : 0) + "</div><div class=\"metric-label\">Active Nodes</div></div>"
        + "<div class=\"metric-card\"><div class=\"metric-value\">" + esc(ingestRate) + "</div><div class=\"metric-label\">Ingest Rate</div></div>";
};

AdminPanel.prototype._renderClassificationAdvice = function(dist, training) {
    var body = document.getElementById("ml-cls-body");
    var badge = document.getElementById("ml-cls-badge");
    if (!body) return;

    var recs = [];
    var classes = dist.classes || {};
    var classNames = Object.keys(classes);
    var total = dist.total || 1;

    // Check class imbalance
    var counts = classNames.map(function(c) { return classes[c]; });
    if (counts.length > 0) {
        var maxC = Math.max.apply(null, counts);
        var minC = Math.min.apply(null, counts);
        var ratio = maxC / Math.max(minC, 1);
        if (ratio > 20) {
            recs.push({ priority: "high", title: "Severe class imbalance detected",
                desc: "Ratio " + ratio.toFixed(0) + ":1 between most and least common classes. Apply oversampling (SMOTE), class-weighted loss, or focal loss to prevent minority class neglect.",
                impact: "Minority signals will be misclassified as dominant classes" });
        } else if (ratio > 5) {
            recs.push({ priority: "medium", title: "Moderate class imbalance",
                desc: "Ratio " + ratio.toFixed(0) + ":1. Consider class-weighted cross-entropy loss or data augmentation for underrepresented classes.",
                impact: "Some signal types may have lower recall" });
        }
    }

    // Check number of classes vs taxonomy
    if (classNames.length < 15) {
        recs.push({ priority: "medium", title: "Expand signal taxonomy",
            desc: "Only " + classNames.length + " classes active (taxonomy supports 30). Add training data for missing modulations to improve coverage.",
            impact: "Unrecognized signals default to 'unknown' increasing false negatives" });
    }

    // Training data recommendations
    var runs = training.runs || [];
    var bestAcc = 0;
    var usesHardware = false;
    for (var i = 0; i < runs.length; i++) {
        var r = runs[i];
        if (r.best_val_accuracy && r.best_val_accuracy > bestAcc) bestAcc = r.best_val_accuracy;
        if (r.data_source && r.data_source.indexOf("hardware") >= 0) usesHardware = true;
    }

    if (bestAcc > 0 && bestAcc < 0.80) {
        recs.push({ priority: "high", title: "Model accuracy below 80%",
            desc: "Best validation accuracy: " + (bestAcc * 100).toFixed(1) + "%. Consider: (1) curriculum learning starting with easy classes, (2) larger FFT window for better frequency resolution, (3) mixup/cutmix augmentation, (4) ensemble of CNN + transformer models.",
            impact: "Low accuracy means high misclassification rate in production" });
    } else if (bestAcc >= 0.80 && bestAcc < 0.92) {
        recs.push({ priority: "medium", title: "Model accuracy good but improvable",
            desc: "Best accuracy: " + (bestAcc * 100).toFixed(1) + "%. Try: knowledge distillation from larger model, test-time augmentation, or confidence calibration with temperature scaling.",
            impact: "Marginal gains compound across thousands of daily classifications" });
    }

    if (!usesHardware) {
        recs.push({ priority: "high", title: "No hardware-captured training data",
            desc: "All training appears synthetic. Collect real SDR captures across your deployment RF environment. Even 100 samples per class from actual hardware dramatically improves real-world accuracy.",
            impact: "Synthetic-only models suffer 10-20% accuracy drop on real signals" });
    }

    // Low-confidence detection analysis
    var lowConfClasses = [];
    for (var c in classes) {
        if (classes[c] < total * 0.01) lowConfClasses.push(c);
    }
    if (lowConfClasses.length > 0) {
        recs.push({ priority: "low", title: "Rare signal classes: " + lowConfClasses.slice(0, 5).join(", "),
            desc: "These classes account for <1% of detections. Verify they're being correctly identified and not confused with similar modulations. Consider few-shot learning or prototype networks for rare classes.",
            impact: "Rare classes may have unstable detection performance" });
    }

    if (badge) badge.textContent = String(recs.length);
    body.innerHTML = this._renderRecommendations(recs);
};

AdminPanel.prototype._renderAnomalyAdvice = function(anomSummary, corr, nodes) {
    var body = document.getElementById("ml-anom-body");
    var badge = document.getElementById("ml-anom-badge");
    if (!body) return;

    var recs = [];
    var totalRf = anomSummary.total_rf || 0;
    var dismissed = anomSummary.dismissed_rf || 0;
    var activeAnom = anomSummary.active_rf || totalRf - dismissed;

    // Check anomaly volume
    if (activeAnom > 500) {
        recs.push({ priority: "high", title: "High anomaly volume (" + activeAnom + " active)",
            desc: "Too many anomalies cause alert fatigue. Raise RF insert threshold (currently in Advanced config), enable auto-snooze for recurring benign anomalies, or increase the minimum SNR filter on edge nodes.",
            impact: "Operators will miss genuine threats in noise" });
    }

    // Check dismiss ratio
    if (totalRf > 100 && dismissed / totalRf > 0.8) {
        recs.push({ priority: "medium", title: "80%+ anomalies dismissed — thresholds too sensitive",
            desc: "Most anomalies are being dismissed as false positives. The anomaly scorer's baseline may need retraining, or dimension weights should be rebalanced. Consider raising the insert threshold by 0.1.",
            impact: "Wasted analyst time reviewing false positives" });
    } else if (totalRf > 0 && totalRf < 10) {
        recs.push({ priority: "low", title: "Very few anomalies — thresholds may be too high",
            desc: "Only " + totalRf + " RF anomalies detected. Verify anomaly scoring is enabled on all edge nodes (--anomaly-detection flag). Consider lowering the insert threshold.",
            impact: "Real anomalies may go undetected" });
    }

    // Cross-node correlation
    var corrTotal = corr.total_correlations_24h || 0;
    var avgNodes = corr.avg_nodes_per_correlation || 0;
    var nodeCount = Array.isArray(nodes) ? nodes.length : 0;

    if (nodeCount >= 3 && corrTotal > 0) {
        recs.push({ priority: "low", title: "Multi-node correlation active",
            desc: corrTotal + " correlations (avg " + avgNodes.toFixed(1) + " nodes/event). Consider adding TDOA (time-difference-of-arrival) geolocation when 3+ nodes detect the same signal within 100ms.",
            impact: "TDOA can localize emitters to within meters" });
    }

    if (nodeCount >= 2 && corrTotal === 0) {
        recs.push({ priority: "medium", title: "No cross-node correlations detected",
            desc: "With " + nodeCount + " nodes, you should see correlated detections. Verify nodes have overlapping frequency coverage and synchronized clocks (NTP). Check that the correlator time window isn't too narrow.",
            impact: "Missing multi-node events reduces threat detection capability" });
    }

    // Anomaly scoring dimensions
    recs.push({ priority: "low", title: "Review 7-dimension anomaly scoring weights",
        desc: "The anomaly scorer uses: frequency, temporal, power, modulation, bandwidth, spatial, behavioral dimensions. Tune weights in the Advanced tab based on your threat model. E.g., increase spatial weight for perimeter security, temporal weight for detecting scheduled transmissions.",
        impact: "Proper weight tuning reduces FP rate by 30-50%" });

    if (badge) badge.textContent = String(recs.length);
    body.innerHTML = this._renderRecommendations(recs);
};

AdminPanel.prototype._renderDataAdvice = function(dist, nodes, peaks, bt, metrics) {
    var body = document.getElementById("ml-data-body");
    var badge = document.getElementById("ml-data-badge");
    if (!body) return;

    var recs = [];
    var nodeCount = Array.isArray(nodes) ? nodes.length : 0;
    var onlineNodes = Array.isArray(nodes) ? nodes.filter(function(n) { return n && n.status === "active"; }).length : 0;
    var peakCount = peaks.count || 0;
    var btDevices = bt.total_devices || 0;

    // Node coverage
    if (nodeCount === 1) {
        recs.push({ priority: "high", title: "Single-node deployment",
            desc: "Deploy at least 3 nodes for reliable coverage: enables cross-node correlation, eliminates single-point-of-failure, and provides triangulation capability for emitter localization.",
            impact: "No redundancy, no correlation, no geolocation" });
    } else if (nodeCount > 1 && onlineNodes < nodeCount) {
        recs.push({ priority: "medium", title: (nodeCount - onlineNodes) + " node(s) offline",
            desc: "Offline nodes create coverage gaps. Check node health, network connectivity, and SDR hardware status. Consider adding monitoring alerts for node disconnections.",
            impact: "Coverage gaps during outages" });
    }

    // Spectrum coverage
    if (peakCount === 0) {
        recs.push({ priority: "medium", title: "No spectrum sweep data",
            desc: "Enable wideband spectrum sweeping on edge nodes (--spectrum-sweep flag) to detect unclassified signals, measure band occupancy, and identify interference sources outside your classifier's training set.",
            impact: "Missing signals that fall outside classification model's training" });
    } else if (peakCount < 20) {
        recs.push({ priority: "low", title: "Limited spectrum peak data (" + peakCount + " peaks)",
            desc: "Increase sweep frequency or lower peak detection threshold to capture more spectral features. Consider narrower bin sizes for better resolution in congested bands.",
            impact: "Sparse spectrum data limits occupancy analysis accuracy" });
    }

    // Bluetooth coverage
    if (btDevices === 0) {
        recs.push({ priority: "low", title: "Bluetooth scanning not active",
            desc: "Enable BT scanning on edge nodes with Bluetooth adapters (--bluetooth flag). BT/BLE device tracking adds another layer of RF awareness — useful for detecting unauthorized wireless peripherals, rogue IoT devices, and BLE beacons.",
            impact: "Blind spot in 2.4 GHz ISM band device-level awareness" });
    }

    // Data retention and volume
    var db = metrics.database || {};
    var dbSize = db.db_size_mb || 0;
    if (dbSize > 1000) {
        recs.push({ priority: "medium", title: "Large database (" + dbSize.toFixed(0) + " MB)",
            desc: "Consider: (1) PostgreSQL migration for better concurrent access, (2) time-series partitioning by month, (3) reducing retention period, (4) archiving old detections to cold storage for model retraining.",
            impact: "SQLite performance degrades above 1-2 GB" });
    }

    // Frequency band coverage
    var classes = dist.classes || {};
    var hasSubGHz = false, has2_4 = false, has5 = false;
    var classNames = Object.keys(classes);
    // Check if we're seeing diverse frequency detections by class types
    if (classNames.indexOf("lora-css") >= 0) hasSubGHz = true;
    if (classNames.indexOf("zigbee") >= 0) has2_4 = true;
    if (classNames.indexOf("wifi-ofdm") >= 0) { has2_4 = true; has5 = true; }

    if (!hasSubGHz && !has2_4) {
        recs.push({ priority: "medium", title: "Limited frequency band coverage",
            desc: "Detections don't span multiple RF bands. Ensure SDR nodes are configured to sweep: Sub-GHz (315-915 MHz for IoT/SCADA), 2.4 GHz (WiFi/BT/Zigbee), 5 GHz (WiFi/radar). Different antennas may be needed per band.",
            impact: "Threats in uncovered bands go undetected" });
    }

    if (badge) badge.textContent = String(recs.length);
    body.innerHTML = this._renderRecommendations(recs);
};

AdminPanel.prototype._renderExpansionAdvice = function(dist, training, nodes, bt, peaks) {
    var body = document.getElementById("ml-expand-body");
    var badge = document.getElementById("ml-expand-badge");
    if (!body) return;

    var recs = [];

    // Transfer learning
    recs.push({ priority: "medium", title: "Transfer learning from RadioML 2018.01A",
        desc: "Pre-train on the RadioML dataset (24 modulations, 2M samples) and fine-tune on your hardware data. This bootstraps the model with strong modulation recognition features before domain adaptation.",
        impact: "Typically 5-15% accuracy improvement over training from scratch" });

    // Online learning
    recs.push({ priority: "medium", title: "Implement online/continual learning",
        desc: "Add a feedback loop where analysts can label detections as correct/incorrect from the dashboard. Use this feedback to fine-tune the model periodically without full retraining. Techniques: experience replay, elastic weight consolidation.",
        impact: "Model adapts to evolving RF environment automatically" });

    // Autoencoder for unknown signals
    recs.push({ priority: "high", title: "Deploy autoencoder for unknown signal detection",
        desc: "Train a variational autoencoder (VAE) on known signal types. High reconstruction error indicates unknown/novel signals. This catches threats your classifier was never trained on — critical for zero-day RF attacks.",
        impact: "Detects novel signal types not in the 30-class taxonomy" });

    // GAN augmentation
    recs.push({ priority: "low", title: "GAN-based synthetic data augmentation",
        desc: "Use a conditional GAN to generate realistic IQ samples for underrepresented classes. Especially valuable for signals you rarely see (military, experimental) where hardware captures are difficult to obtain.",
        impact: "Addresses class imbalance without hardware collection campaigns" });

    // Edge inference optimization
    var nodeCount = Array.isArray(nodes) ? nodes.length : 0;
    if (nodeCount > 0) {
        recs.push({ priority: "medium", title: "Quantize model for edge inference",
            desc: "Apply INT8 quantization or knowledge distillation to create a lightweight model for edge nodes. Target: <5ms inference on Raspberry Pi 5. Use ONNX Runtime for optimized CPU inference.",
            impact: "2-4x throughput improvement on edge hardware" });
    }

    // FHSS/spread spectrum
    recs.push({ priority: "medium", title: "Enhance FHSS detection with sequence prediction",
        desc: "Current FHSS detection identifies hopping patterns. Add an LSTM/transformer model to predict hop sequences — enables: (1) protocol identification from hop patterns, (2) tracking specific emitters across frequency changes, (3) detecting coordinated FHSS networks.",
        impact: "Turns FHSS from detection-only to full characterization" });

    // Emitter fingerprinting
    recs.push({ priority: "high", title: "RF fingerprinting for emitter identification",
        desc: "Train a Siamese/triplet network on IQ-level features (carrier frequency offset, I/Q imbalance, phase noise) to uniquely identify individual transmitters regardless of protocol. This enables tracking specific devices even when they change frequency or identity.",
        impact: "Distinguish individual transmitters — critical for threat tracking" });

    // Federated learning
    if (nodeCount >= 3) {
        recs.push({ priority: "low", title: "Federated learning across edge nodes",
            desc: "With " + nodeCount + " nodes, each sees different RF environments. Implement federated averaging to train a global model from local gradients without centralizing raw IQ data. Preserves data privacy and reduces bandwidth.",
            impact: "Better generalization from diverse RF environments" });
    }

    if (badge) badge.textContent = String(recs.length);
    body.innerHTML = this._renderRecommendations(recs);
};

AdminPanel.prototype._renderRecommendations = function(recs) {
    if (!recs || recs.length === 0) return "<p class=\"empty-state\">No recommendations</p>";

    var priorityOrder = { high: 0, medium: 1, low: 2 };
    // high ranks 0, so "|| 2" would sort it as low; only an unknown priority ranks last.
    function rank(r) { return Object.prototype.hasOwnProperty.call(priorityOrder, r.priority) ? priorityOrder[r.priority] : 2; }
    recs.sort(function(a, b) { return rank(a) - rank(b); });

    var h = "";
    for (var i = 0; i < recs.length; i++) {
        var r = recs[i];
        var color = r.priority === "high" ? "var(--accent-red)"
            : r.priority === "medium" ? "var(--accent-orange, #d29922)"
            : "var(--accent-blue)";
        var label = r.priority === "high" ? "HIGH" : r.priority === "medium" ? "MEDIUM" : "LOW";

        h += "<div style=\"padding:12px 16px;margin-bottom:8px;border-left:3px solid " + color + ";background:var(--bg-secondary);border-radius:0 6px 6px 0;\">"
            + "<div style=\"display:flex;align-items:center;gap:8px;margin-bottom:4px;\">"
            + "<span style=\"font-size:10px;font-weight:700;color:" + color + ";background:" + color + "20;padding:2px 6px;border-radius:3px;\">" + label + "</span>"
            + "<strong style=\"font-size:14px;\">" + esc(r.title) + "</strong>"
            + "</div>"
            + "<p style=\"font-size:13px;color:var(--text-secondary);margin:4px 0;line-height:1.5;\">" + esc(r.desc) + "</p>"
            + "<p style=\"font-size:12px;color:var(--text-tertiary);margin:0;\"><em>Impact: " + esc(r.impact) + "</em></p>"
            + "</div>";
    }
    return h;
};

/* -- Config Versions -------------------------------------------- */

AdminPanel.prototype._loadVersion = function() {
    var s = this;
    s._cmpSelected = [];
    s._listSnapshots();

    var createBtn = document.getElementById("config-snap-create-btn");
    if (createBtn && !createBtn._bound) {
        createBtn._bound = true;
        createBtn.addEventListener("click", function() { s._createSnapshot(); });
    }

    var cmpBtn = document.getElementById("config-cmp-btn");
    if (cmpBtn && !cmpBtn._bound) {
        cmpBtn._bound = true;
        cmpBtn.addEventListener("click", function() { s._compareSnapshots(); });
    }
    var cmpCurBtn = document.getElementById("config-cmp-current-btn");
    if (cmpCurBtn && !cmpCurBtn._bound) {
        cmpCurBtn._bound = true;
        cmpCurBtn.addEventListener("click", function() { s._compareVsCurrent(); });
    }
    var cmpClrBtn = document.getElementById("config-cmp-clear-btn");
    if (cmpClrBtn && !cmpClrBtn._bound) {
        cmpClrBtn._bound = true;
        cmpClrBtn.addEventListener("click", function() { s._clearCompare(); });
    }
};

AdminPanel.prototype._listSnapshots = function() {
    var s = this;
    s.apiFetch("/api/admin/config-snapshots?limit=50").then(function(d) {
        s._renderSnapshots(d.snapshots || []);
    }).catch(function() {});
};

AdminPanel.prototype._renderSnapshots = function(snapshots) {
    var tb = document.getElementById("config-snap-tbody");
    var em = document.getElementById("config-snap-empty");
    var tbl = document.getElementById("config-snap-table");
    if (!tb) return;
    if (!snapshots || !snapshots.length) {
        tb.innerHTML = "";
        if (em) em.style.display = "";
        if (tbl) tbl.style.display = "none";
        return;
    }
    if (em) em.style.display = "none";
    if (tbl) tbl.style.display = "";

    var s = this, h = "";
    for (var i = 0; i < snapshots.length; i++) {
        var snap = snapshots[i];
        var triggerColor = snap.trigger === "manual" ? "var(--accent-blue)"
            : snap.trigger === "daily" ? "var(--accent-green)"
            : "var(--accent-orange, #d29922)";
        var checked = s._cmpSelected && s._cmpSelected.indexOf(snap.id) !== -1;
        h += "<tr>"
            + "<td><input type=\"checkbox\" data-snap-cmp=\"" + esc(snap.id) + "\"" + (checked ? " checked" : "") + " title=\"Select for compare\"></td>"
            + "<td data-label=\"ID\">" + esc(snap.id) + "</td>"
            + "<td data-label=\"Timestamp\">" + fmtTime(snap.timestamp) + "</td>"
            + "<td data-label=\"Trigger\"><span style=\"color:" + triggerColor + ";font-weight:600;\">" + esc(snap.trigger) + "</span></td>"
            + "<td data-label=\"Description\">" + esc(snap.description || "--") + "</td>"
            + "<td data-label=\"Files\">" + esc(snap.file_count) + "</td>"
            + "<td data-label=\"Actions\">"
            + "<button class=\"btn btn-sm\" data-snap-view=\"" + esc(snap.id) + "\">View</button> "
            + "<button class=\"btn btn-sm btn-primary\" data-snap-restore=\"" + esc(snap.id) + "\">Restore</button> "
            + "<button class=\"btn btn-sm btn-danger\" data-snap-delete=\"" + esc(snap.id) + "\">Delete</button>"
            + "</td></tr>";
    }
    tb.innerHTML = h;

    tb.querySelectorAll("[data-snap-cmp]").forEach(function(cb) {
        cb.addEventListener("change", function() {
            var id = parseInt(this.getAttribute("data-snap-cmp"), 10);
            if (this.checked) {
                if (!s._cmpSelected) s._cmpSelected = [];
                if (s._cmpSelected.length >= 2) {
                    s._cmpSelected.shift();
                    // uncheck the one that was bumped
                    tb.querySelectorAll("[data-snap-cmp]").forEach(function(c2) {
                        var cid = parseInt(c2.getAttribute("data-snap-cmp"), 10);
                        c2.checked = s._cmpSelected.indexOf(cid) !== -1;
                    });
                }
                if (s._cmpSelected.indexOf(id) === -1) s._cmpSelected.push(id);
            } else {
                s._cmpSelected = (s._cmpSelected || []).filter(function(x) { return x !== id; });
            }
            this.checked = s._cmpSelected.indexOf(id) !== -1;
            s._updateCmpUI();
        });
    });
    tb.querySelectorAll("[data-snap-view]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            s._viewSnapshot(parseInt(this.getAttribute("data-snap-view"), 10));
        });
    });
    tb.querySelectorAll("[data-snap-restore]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            s._restoreSnapshot(parseInt(this.getAttribute("data-snap-restore"), 10));
        });
    });
    tb.querySelectorAll("[data-snap-delete]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            s._deleteSnapshot(parseInt(this.getAttribute("data-snap-delete"), 10));
        });
    });
};

AdminPanel.prototype._createSnapshot = function() {
    var s = this;
    var form = document.createElement("div");
    form.innerHTML = ""
        + '<label for="admin-modal-snap-desc">Description <span class="admin-modal-hint" style="display:inline; margin:0; font-weight:normal;">(optional)</span></label>'
        + '<input type="text" id="admin-modal-snap-desc" autocomplete="off" placeholder="e.g. pre-deploy baseline" />';
    var input = form.querySelector("#admin-modal-snap-desc");

    function submit(desc) {
        var resultEl = document.getElementById("config-snap-result");
        s.apiFetch("/api/admin/config-snapshots", {
            method: "POST", body: { description: desc }
        }).then(function(d) {
            if (resultEl) {
                resultEl.style.display = "";
                resultEl.innerHTML = "<strong style=\"color:var(--accent-green);\">Snapshot #" + esc(d.snapshot_id) + " created.</strong>";
                setTimeout(function() { resultEl.style.display = "none"; }, 4000);
            }
            s._listSnapshots();
        }).catch(function(e) {
            if (resultEl) {
                resultEl.style.display = "";
                resultEl.innerHTML = "<strong style=\"color:var(--accent-red);\">Failed:</strong> " + esc(e.detail || e.message || "Unknown error");
            }
        });
    }

    showModal({
        title: "Create config snapshot",
        body: form,
        buttons: [
            { label: "Cancel", kind: "cancel", onClick: function(close) { close(); } },
            {
                label: "Create",
                kind: "primary",
                onClick: function(close) {
                    var desc = input.value;
                    close();
                    submit(desc);
                }
            }
        ],
        onShow: function() { try { input.focus(); } catch (_) {} }
    });
};

AdminPanel.prototype._restoreSnapshot = function(id) {
    var s = this;
    confirmModal({
        title: "Restore config snapshot",
        message: "Restore config from snapshot #" + id + "?\n\nThis will overwrite current config files. A pre-restore backup will be created automatically.",
        confirmLabel: "Restore",
        destructive: true
    }).then(function(ok) {
        if (!ok) return;
        var resultEl = document.getElementById("config-snap-result");
        s.apiFetch("/api/admin/config-snapshots/" + id + "/restore", { method: "POST" })
            .then(function(d) {
                var files = d.restored_files || [];
                if (resultEl) {
                    resultEl.style.display = "";
                    resultEl.innerHTML = "<strong style=\"color:var(--accent-green);\">Restored " + files.length + " files from snapshot #" + esc(id) + ":</strong> " + esc(files.join(", "));
                }
                s._listSnapshots();
            })
            .catch(function(e) {
                if (resultEl) {
                    resultEl.style.display = "";
                    resultEl.innerHTML = "<strong style=\"color:var(--accent-red);\">Restore failed:</strong> " + esc(e.detail || e.message || "Unknown error");
                }
                notify("Restore failed: " + (e.detail || e.message || "Unknown error"), "error");
            });
    });
};

AdminPanel.prototype._deleteSnapshot = function(id) {
    var s = this;
    confirmModal({
        title: "Delete config snapshot",
        message: "Delete snapshot #" + id + "?",
        confirmLabel: "Delete",
        destructive: true
    }).then(function(ok) {
        if (!ok) return;
        s.apiFetch("/api/admin/config-snapshots/" + id, { method: "DELETE" })
            .then(function() { s._listSnapshots(); notify("Snapshot #" + id + " deleted", "success"); })
            .catch(function(e) {
                notify("Delete failed: " + (e.detail || e.message || "Unknown error"), "error");
            });
    });
};

AdminPanel.prototype._viewSnapshot = function(id) {
    var s = this;
    var detailEl = document.getElementById("config-snap-detail");
    if (!detailEl) return;
    detailEl.innerHTML = "<p style=\"color:var(--text-secondary);\">Loading snapshot #" + esc(id) + "...</p>";

    s.apiFetch("/api/admin/config-snapshots/" + id).then(function(d) {
        var snap = d.snapshot;
        if (!snap) { detailEl.innerHTML = "<p class=\"empty-state\">Snapshot not found</p>"; return; }
        var files = snap.files || {};
        var fileNames = Object.keys(files).sort();

        var h = "<div style=\"margin-bottom:12px;\">"
            + "<strong>Snapshot #" + esc(snap.id) + "</strong> &mdash; "
            + fmtTime(snap.timestamp) + " &mdash; "
            + "<span style=\"font-weight:600;\">" + esc(snap.trigger) + "</span>";
        if (snap.description) h += " &mdash; " + esc(snap.description);
        h += "</div>";

        if (!fileNames.length) {
            h += "<p class=\"empty-state\">No files in this snapshot</p>";
        } else {
            for (var i = 0; i < fileNames.length; i++) {
                var fname = fileNames[i];
                var content = files[fname];
                var json_str = typeof content === "string" ? content : JSON.stringify(content, null, 2);
                // Truncate display for very large files
                var display = json_str.length > 2000 ? json_str.substring(0, 2000) + "\n... (truncated)" : json_str;
                h += "<details style=\"margin-bottom:8px;\">"
                    + "<summary style=\"cursor:pointer;font-weight:600;padding:6px 0;\">"
                    + "<code>" + esc(fname) + "</code>"
                    + " <span style=\"font-weight:400;color:var(--text-secondary);font-size:12px;\">(" + json_str.length + " chars)</span>"
                    + "</summary>"
                    + "<pre style=\"background:var(--bg-primary);padding:12px;border-radius:4px;border:1px solid var(--border-color);font-size:11px;max-height:300px;overflow:auto;white-space:pre-wrap;word-break:break-all;\">"
                    + esc(display) + "</pre>"
                    + "</details>";
            }
        }
        detailEl.innerHTML = h;
    }).catch(function(e) {
        detailEl.innerHTML = "<p style=\"color:var(--accent-red);\">Failed to load snapshot: " + esc(e.message || "Unknown error") + "</p>";
    });
};

/* -- Compare ---------------------------------------------------- */

AdminPanel.prototype._updateCmpUI = function() {
    var sel = this._cmpSelected || [];
    var selEl = document.getElementById("config-cmp-sel");
    var cmpBtn = document.getElementById("config-cmp-btn");
    var curBtn = document.getElementById("config-cmp-current-btn");
    if (cmpBtn) cmpBtn.disabled = sel.length < 2;
    if (curBtn) curBtn.disabled = sel.length < 1;
    if (selEl) {
        if (sel.length === 0) selEl.textContent = "Select up to two snapshots using the checkboxes in the table above.";
        else if (sel.length === 1) selEl.innerHTML = "Selected: <strong>#" + esc(sel[0]) + "</strong> — select one more to compare, or compare vs current config.";
        else selEl.innerHTML = "Selected: <strong>#" + esc(sel[0]) + "</strong> vs <strong>#" + esc(sel[1]) + "</strong>";
    }
};

AdminPanel.prototype._clearCompare = function() {
    this._cmpSelected = [];
    var tb = document.getElementById("config-snap-tbody");
    if (tb) tb.querySelectorAll("[data-snap-cmp]").forEach(function(cb) { cb.checked = false; });
    this._updateCmpUI();
    var r = document.getElementById("config-cmp-result");
    if (r) r.innerHTML = "";
};

AdminPanel.prototype._compareSnapshots = function() {
    var s = this, sel = s._cmpSelected || [];
    if (sel.length < 2) return;
    var resultEl = document.getElementById("config-cmp-result");
    if (resultEl) resultEl.innerHTML = "<p style=\"color:var(--text-secondary);\">Loading snapshots #" + esc(sel[0]) + " and #" + esc(sel[1]) + "...</p>";

    Promise.all([
        s.apiFetch("/api/admin/config-snapshots/" + sel[0]).catch(function() { return null; }),
        s.apiFetch("/api/admin/config-snapshots/" + sel[1]).catch(function() { return null; })
    ]).then(function(results) {
        var missing = [];
        if (!results[0] || !results[0].snapshot) missing.push("#" + sel[0]);
        if (!results[1] || !results[1].snapshot) missing.push("#" + sel[1]);
        if (missing.length) {
            if (resultEl) resultEl.innerHTML = "<p style=\"color:var(--accent-red);\">Snapshot " + esc(missing.join(" and ")) + " no longer exists. It may have been deleted or auto-purged.</p>";
            s._listSnapshots();
            return;
        }
        s._renderDiff(resultEl, results[0].snapshot, results[1].snapshot);
    });
};

AdminPanel.prototype._compareVsCurrent = function() {
    var s = this, sel = s._cmpSelected || [];
    if (sel.length < 1) return;
    var snapId = sel[sel.length - 1]; // use last selected
    var resultEl = document.getElementById("config-cmp-result");
    if (resultEl) resultEl.innerHTML = "<p style=\"color:var(--text-secondary);\">Loading snapshot #" + esc(snapId) + " and current config...</p>";

    // Create a temp snapshot of current state, fetch it, then fetch the selected one
    var currentId = null;
    s.apiFetch("/api/admin/config-snapshots", {
        method: "POST", body: { description: "(temp compare)" }
    }).then(function(d) {
        currentId = d.snapshot_id;
        return Promise.all([
            s.apiFetch("/api/admin/config-snapshots/" + snapId).catch(function() { return null; }),
            s.apiFetch("/api/admin/config-snapshots/" + currentId).catch(function() { return null; })
        ]);
    }).then(function(results) {
        if (!results[0] || !results[0].snapshot) {
            if (resultEl) resultEl.innerHTML = "<p style=\"color:var(--accent-red);\">Snapshot #" + esc(snapId) + " no longer exists. It may have been deleted or auto-purged.</p>";
            s._listSnapshots();
        } else if (!results[1] || !results[1].snapshot) {
            if (resultEl) resultEl.innerHTML = "<p style=\"color:var(--accent-red);\">Failed to read current config snapshot.</p>";
        } else {
            var snapB = results[1].snapshot;
            snapB.id = "current";
            snapB.trigger = "live";
            snapB.description = "Current live config";
            s._renderDiff(resultEl, results[0].snapshot, snapB);
        }
        // Clean up temp snapshot
        if (currentId) {
            s.apiFetch("/api/admin/config-snapshots/" + currentId, { method: "DELETE" }).catch(function(){});
            s._listSnapshots();
        }
    }).catch(function(e) {
        if (resultEl) resultEl.innerHTML = "<p style=\"color:var(--accent-red);\">Failed to create current config snapshot: " + esc(e.message || "Unknown error") + "</p>";
    });
};

AdminPanel.prototype._stripTimestamps = function(obj) {
    if (Array.isArray(obj)) return obj.map(this._stripTimestamps.bind(this));
    if (obj && typeof obj === "object") {
        var out = {};
        for (var k in obj) {
            if (!obj.hasOwnProperty(k)) continue;
            if (/^(saved_at|created_at|updated_at|modified_at|timestamp|last_updated|exported_at)$/i.test(k)) continue;
            out[k] = this._stripTimestamps(obj[k]);
        }
        return out;
    }
    return obj;
};

AdminPanel.prototype._stripMetrics = function(obj) {
    if (Array.isArray(obj)) return obj.map(this._stripMetrics.bind(this));
    if (obj && typeof obj === "object") {
        var out = {};
        for (var k in obj) {
            if (!obj.hasOwnProperty(k)) continue;
            if (/^(load_1m|load_5m|load_15m|uptime_seconds|cpu_percent|memory_mb|disk_percent|last_seen)$/i.test(k)) continue;
            out[k] = this._stripMetrics(obj[k]);
        }
        return out;
    }
    return obj;
};

AdminPanel.prototype._renderDiff = function(el, snapA, snapB) {
    var filesA = snapA.files || {}, filesB = snapB.files || {};
    var ignoreTs = document.getElementById("config-cmp-ignore-ts");
    var stripTs = ignoreTs && ignoreTs.checked;
    var ignoreMetrics = document.getElementById("config-cmp-ignore-metrics");
    var stripMetrics = ignoreMetrics && ignoreMetrics.checked;
    var allFiles = {};
    Object.keys(filesA).forEach(function(f) { allFiles[f] = true; });
    Object.keys(filesB).forEach(function(f) { allFiles[f] = true; });
    var fileNames = Object.keys(allFiles).sort();

    var h = "<div style=\"margin-bottom:12px;display:flex;gap:16px;flex-wrap:wrap;\">"
        + "<div><span style=\"display:inline-block;width:12px;height:12px;background:var(--accent-red);opacity:0.15;border:1px solid var(--accent-red);border-radius:2px;vertical-align:middle;\"></span>"
        + " <strong>#" + esc(snapA.id) + "</strong> <span style=\"color:var(--text-secondary);\">" + fmtTime(snapA.timestamp) + "</span></div>"
        + "<div><span style=\"display:inline-block;width:12px;height:12px;background:var(--accent-green);opacity:0.15;border:1px solid var(--accent-green);border-radius:2px;vertical-align:middle;\"></span>"
        + " <strong>#" + esc(snapB.id) + "</strong> <span style=\"color:var(--text-secondary);\">" + fmtTime(snapB.timestamp) + "</span></div>"
        + "</div>";

    var totalChanges = 0;

    if (!fileNames.length) {
        h += "<p class=\"empty-state\">No files in either snapshot</p>";
    } else {
        for (var i = 0; i < fileNames.length; i++) {
            var fname = fileNames[i];
            var contentA = filesA[fname];
            var contentB = filesB[fname];
            if (stripTs && contentA !== undefined && typeof contentA === "object") contentA = this._stripTimestamps(contentA);
            if (stripTs && contentB !== undefined && typeof contentB === "object") contentB = this._stripTimestamps(contentB);
            if (stripMetrics && contentA !== undefined && typeof contentA === "object") contentA = this._stripMetrics(contentA);
            if (stripMetrics && contentB !== undefined && typeof contentB === "object") contentB = this._stripMetrics(contentB);
            var strA = contentA !== undefined ? (typeof contentA === "string" ? contentA : JSON.stringify(contentA, null, 2)) : "";
            var strB = contentB !== undefined ? (typeof contentB === "string" ? contentB : JSON.stringify(contentB, null, 2)) : "";

            // A file missing from one snapshot has no lines there, not one empty line.
            var linesA = contentA !== undefined ? strA.split("\n") : [];
            var linesB = contentB !== undefined ? strB.split("\n") : [];
            var diffLines = this._diffLines(linesA, linesB);
            var changes = diffLines.filter(function(d) { return d.type !== "same"; }).length;
            totalChanges += changes;

            var statusLabel = "", statusColor = "";
            if (contentA === undefined) { statusLabel = "added"; statusColor = "var(--accent-green)"; }
            else if (contentB === undefined) { statusLabel = "removed"; statusColor = "var(--accent-red)"; }
            else if (changes === 0) { statusLabel = "unchanged"; statusColor = "var(--text-tertiary, var(--text-secondary))"; }
            else { statusLabel = changes + " change" + (changes !== 1 ? "s" : ""); statusColor = "var(--accent-orange, #d29922)"; }

            var open = changes > 0 ? " open" : "";
            h += "<details style=\"margin-bottom:8px;\"" + open + ">"
                + "<summary style=\"cursor:pointer;font-weight:600;padding:6px 0;\">"
                + "<code>" + esc(fname) + "</code>"
                + " <span style=\"font-weight:400;font-size:12px;color:" + statusColor + ";\">" + statusLabel + "</span>"
                + "</summary>"
                + "<div style=\"background:var(--bg-primary);border:1px solid var(--border-color);border-radius:4px;overflow:auto;max-height:400px;font-size:11px;font-family:var(--font-mono, monospace);\">";

            // Render diff lines
            for (var j = 0; j < diffLines.length; j++) {
                var dl = diffLines[j];
                var bg = "", prefix = " ", color = "";
                if (dl.type === "del") { bg = "rgba(248,81,73,0.1)"; prefix = "-"; color = "var(--accent-red)"; }
                else if (dl.type === "add") { bg = "rgba(63,185,80,0.1)"; prefix = "+"; color = "var(--accent-green)"; }
                var lineNum = dl.type === "del" ? dl.lineA : (dl.type === "add" ? dl.lineB : dl.lineA);
                h += "<div style=\"padding:0 8px;white-space:pre-wrap;word-break:break-all;"
                    + (bg ? "background:" + bg + ";" : "")
                    + (color ? "color:" + color + ";" : "")
                    + "\">"
                    + "<span style=\"display:inline-block;width:36px;text-align:right;color:var(--text-secondary);opacity:0.5;user-select:none;margin-right:8px;\">" + lineNum + "</span>"
                    + prefix + " " + esc(dl.text)
                    + "</div>";
            }

            h += "</div></details>";
        }
    }

    h = "<div style=\"margin-bottom:12px;\"><strong>" + totalChanges + " change" + (totalChanges !== 1 ? "s" : "") + "</strong> across " + fileNames.length + " file" + (fileNames.length !== 1 ? "s" : "") + "</div>" + h;
    el.innerHTML = h;
};

AdminPanel.prototype._diffLines = function(a, b) {
    // Myers-like LCS diff for line-level comparison
    var m = a.length, n = b.length;
    // For very large files, fall back to simple comparison
    if (m + n > 5000) return this._simpleDiff(a, b);

    // Build LCS table
    var dp = [];
    for (var i = 0; i <= m; i++) {
        dp[i] = new Array(n + 1);
        dp[i][0] = 0;
    }
    for (var j = 0; j <= n; j++) dp[0][j] = 0;
    for (var i = 1; i <= m; i++) {
        for (var j = 1; j <= n; j++) {
            if (a[i-1] === b[j-1]) dp[i][j] = dp[i-1][j-1] + 1;
            else dp[i][j] = Math.max(dp[i-1][j], dp[i][j-1]);
        }
    }

    // Backtrack to produce diff
    var result = [];
    var i = m, j = n;
    while (i > 0 || j > 0) {
        if (i > 0 && j > 0 && a[i-1] === b[j-1]) {
            result.push({ type: "same", text: a[i-1], lineA: i, lineB: j });
            i--; j--;
        } else if (j > 0 && (i === 0 || dp[i][j-1] >= dp[i-1][j])) {
            result.push({ type: "add", text: b[j-1], lineA: i, lineB: j });
            j--;
        } else {
            result.push({ type: "del", text: a[i-1], lineA: i, lineB: j });
            i--;
        }
    }
    result.reverse();
    return result;
};

AdminPanel.prototype._simpleDiff = function(a, b) {
    var result = [], max = Math.max(a.length, b.length);
    for (var i = 0; i < max; i++) {
        if (i < a.length && i < b.length && a[i] === b[i]) {
            result.push({ type: "same", text: a[i], lineA: i+1, lineB: i+1 });
        } else {
            if (i < a.length) result.push({ type: "del", text: a[i], lineA: i+1, lineB: i+1 });
            if (i < b.length) result.push({ type: "add", text: b[i], lineA: i+1, lineB: i+1 });
        }
    }
    return result;
};

/* -- Boot ------------------------------------------------------- */

document.addEventListener("DOMContentLoaded", function() {
    window.adminPanel = new AdminPanel();
});
