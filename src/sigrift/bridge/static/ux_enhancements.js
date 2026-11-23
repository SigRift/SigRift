/**
 * UX Enhancements for The Bridge TSCM Dashboard
 *
 * Quick wins:
 * A) Ack All button for alerts
 * B) Audio alert on critical threat
 * C) Last-updated timestamps on panels
 * D) Toast confirmations with undo (replace confirm())
 * E) High Alert mode (fast polling)
 * F) Command palette (Ctrl+K)
 */
"use strict";

/* ================================================================
   A) ACK ALL — bulk acknowledge unacknowledged alerts
   ================================================================ */

(function() {
    // Inject "Ack All" button next to alerts filter controls
    function injectAckAll() {
        var container = document.getElementById("alerts-tab-controls") ||
                        document.querySelector(".alerts-tab-header") ||
                        document.querySelector("#tab-alerts .card-header");
        if (!container || container.querySelector("#ack-all-btn")) return;

        var btn = document.createElement("button");
        btn.id = "ack-all-btn";
        btn.className = "btn btn-sm btn-warning";
        btn.textContent = "Ack All";
        btn.style.marginLeft = "8px";
        btn.addEventListener("click", function() {
            var unacked = document.querySelectorAll("[data-ack-alert-tab]");
            if (!unacked.length) { showToast("No unacknowledged alerts", "info"); return; }
            var count = unacked.length;
            showToast("Acknowledging " + count + " alerts...", "info");
            var promises = [];
            unacked.forEach(function(b) {
                var id = b.getAttribute("data-ack-alert-tab");
                promises.push(
                    fetch("/api/alerts/" + encodeURIComponent(id) + "/ack", {
                        method: "PUT",
                        headers: window.__bridge_auth && window.__bridge_auth.sessionToken
                            ? {"Authorization": "Bearer " + window.__bridge_auth.sessionToken}
                            : {},
                        credentials: "same-origin"
                    })
                );
            });
            Promise.all(promises).then(function() {
                showToast(count + " alerts acknowledged", "success");
                // Trigger refresh
                if (window._bridgeAlertsDashboard) window._bridgeAlertsDashboard._fetchAlerts();
            }).catch(function() {
                showToast("Failed to acknowledge some alerts", "error");
            });
        });
        container.appendChild(btn);
    }

    // Retry injection until tab is rendered
    var _ackInterval = setInterval(function() {
        if (document.getElementById("alerts-tab-controls") || document.querySelector("#tab-alerts")) {
            injectAckAll();
            clearInterval(_ackInterval);
        }
    }, 2000);
})();


/* ================================================================
   B) AUDIO ALERT — play tone on critical WebSocket message
   ================================================================ */

(function() {
    // All alert sources share the topbar audio preference and cancellation.
    window._playAlertTone = function(severity) {
        if (severity !== "critical" && severity !== "warning") return;
        if (window.dashboard) window.dashboard._playAlertTone(severity);
    };

    // No DOM polling here: dashboard.js plays one tone per alert received
    // over the WebSocket, honouring the mute setting and the active tab.
})();


/* ================================================================
   C) LAST-UPDATED TIMESTAMPS — per panel freshness indicators
   ================================================================ */

(function() {
    window._panelTimestamps = {};

    window._markPanelUpdated = function(panelId) {
        window._panelTimestamps[panelId] = Date.now();
    };

    // Inject timestamp badges into panel headers
    function updateTimestamps() {
        var panels = ["summary", "rf", "wifi", "bluetooth", "alerts", "incidents"];
        panels.forEach(function(p) {
            var header = document.querySelector("#tab-" + p + " .card-header, #tab-" + p + " h2");
            if (!header) return;
            var badge = header.querySelector(".freshness-badge");
            if (!badge) {
                badge = document.createElement("span");
                badge.className = "freshness-badge";
                badge.style.cssText = "font-size:11px;opacity:0.6;margin-left:8px;font-weight:normal;";
                header.appendChild(badge);
            }
            var ts = window._panelTimestamps[p];
            if (ts) {
                var ago = Math.round((Date.now() - ts) / 1000);
                badge.textContent = ago < 5 ? "just now" : ago + "s ago";
                badge.style.color = ago > 60 ? "#ff6b6b" : ago > 30 ? "#ffa94d" : "";
            }
        });
    }
    setInterval(updateTimestamps, 3000);

    // Hook into apiFetch to track panel updates
    var _origFetch = window.fetch;
    window.fetch = function(url) {
        var result = _origFetch.apply(this, arguments);
        result.then(function(r) {
            if (r.ok) {
                if (url.indexOf("/api/status") !== -1) window._markPanelUpdated("summary");
                if (url.indexOf("/api/wifi") !== -1) window._markPanelUpdated("wifi");
                if (url.indexOf("/api/bluetooth") !== -1) window._markPanelUpdated("bluetooth");
                if (url.indexOf("/api/alerts") !== -1) window._markPanelUpdated("alerts");
                if (url.indexOf("/api/detections") !== -1) window._markPanelUpdated("rf");
                if (url.indexOf("/api/incidents") !== -1) window._markPanelUpdated("incidents");
            }
        }).catch(function(){});
        return result;
    };
})();


/* ================================================================
   D) TOAST CONFIRMATIONS WITH UNDO — replace browser confirm()
   ================================================================ */

(function() {
    // Intercept confirm() calls and replace with async toast + undo
    // Note: can't truly override confirm() synchronously, but we provide
    // a helper that new code should use instead.
    window._confirmWithUndo = function(message, onConfirm, undoTimeout) {
        undoTimeout = undoTimeout || 5000;
        var undone = false;
        var toastEl = document.createElement("div");
        toastEl.className = "toast-undo";
        toastEl.style.cssText = "position:fixed;bottom:20px;right:20px;background:#333;color:#fff;padding:12px 20px;border-radius:8px;z-index:10000;display:flex;align-items:center;gap:12px;box-shadow:0 4px 12px rgba(0,0,0,0.3);";
        toastEl.innerHTML = '<span></span><button style="background:#ff6b6b;border:none;color:#fff;padding:4px 12px;border-radius:4px;cursor:pointer;">Undo</button>';
        toastEl.querySelector("span").textContent = message == null ? "" : String(message);
        toastEl.querySelector("button").addEventListener("click", function() {
            undone = true;
            toastEl.remove();
            showToast("Action undone", "info");
        });
        document.body.appendChild(toastEl);

        setTimeout(function() {
            if (!undone) {
                onConfirm();
                toastEl.remove();
            }
        }, undoTimeout);
    };
})();


/* ================================================================
   E) HIGH ALERT MODE — faster polling, auto-expand criticals
   ================================================================ */

(function() {
    var _highAlert = false;
    var _normalIntervals = {};

    window._toggleHighAlert = function() {
        _highAlert = !_highAlert;
        var btn = document.getElementById("high-alert-btn");
        if (btn) {
            btn.classList.toggle("active", _highAlert);
            var label = _highAlert ? "HIGH ALERT ON" : "High Alert";
            // a11y: keep the polite live-region span so AT announces label
            // flips. Mirror the label in aria-label for AT that doesn't
            // re-read child text on attribute change. aria-pressed reflects
            // toggle state (P0-4 in the cognitive UX review).
            btn.innerHTML = '<span aria-live="polite">' + label + '</span>';
            btn.setAttribute("aria-pressed", _highAlert ? "true" : "false");
            btn.setAttribute("aria-label", label);
            btn.style.background = _highAlert ? "#ff6b6b" : "";
        }
        if (_highAlert) {
            // NOTE: Toast text intentionally avoids any "faster polling"
            // claim. dashboard.js::_startPolling has no HA branch — cadences
            // remain 15s/30s regardless of HA state. HA mode is currently a
            // visual cue only (pulsing border, button glow). See cognitive
            // review dashboard §1.1 for the audit; wiring real fast-poll is
            // a separate product decision tracked elsewhere.
            showToast("HIGH ALERT MODE — visual cue active", "warning");
            document.body.classList.add("high-alert-mode");
        } else {
            showToast("HIGH ALERT MODE OFF", "info");
            document.body.classList.remove("high-alert-mode");
        }
    };

    window._isHighAlert = function() { return _highAlert; };

    // Inject button in header
    function injectHighAlertBtn() {
        var header = document.querySelector(".dashboard-header .header-right, .dashboard-header .header-top");
        if (!header || document.getElementById("high-alert-btn")) return;
        var btn = document.createElement("button");
        btn.id = "high-alert-btn";
        btn.className = "btn btn-sm";
        // a11y (P0-4): this is a toggle button. aria-pressed reflects current
        // state; the inner <span aria-live="polite"> lets AT announce label
        // flips (High Alert <-> HIGH ALERT ON). Mirror label in aria-label
        // for AT that doesn't re-read child text on attribute change.
        btn.setAttribute("type", "button");
        btn.setAttribute("aria-pressed", "false");
        btn.setAttribute("aria-label", "High Alert");
        btn.innerHTML = '<span aria-live="polite">High Alert</span>';
        btn.style.cssText = "margin-left:8px;border:1px solid #ff6b6b;color:#ff6b6b;";
        btn.addEventListener("click", window._toggleHighAlert);
        header.appendChild(btn);
    }

    var _haInterval = setInterval(function() {
        if (document.querySelector(".dashboard-header")) {
            injectHighAlertBtn();
            clearInterval(_haInterval);
        }
    }, 1000);
})();


/* ================================================================
   F) COMMAND PALETTE — Ctrl+K quick action menu
   ================================================================ */

(function() {
    var _paletteEl = null;

    var commands = [
        { name: "Switch to Summary", action: function() { _clickTab("summary"); } },
        { name: "Switch to SDR/RF", action: function() { _clickTab("rf"); } },
        { name: "Switch to WiFi", action: function() { _clickTab("wifi"); } },
        { name: "Switch to Bluetooth", action: function() { _clickTab("bluetooth"); } },
        { name: "Switch to Alerts", action: function() { _clickTab("alerts"); } },
        { name: "Switch to Incidents", action: function() { _clickTab("incidents"); } },
        { name: "Switch to Spectrum", action: function() { _clickTab("spectrum-analysis"); } },
        { name: "Switch to Map", action: function() { _clickTab("map"); } },
        { name: "Toggle High Alert Mode", action: function() { window._toggleHighAlert(); } },
        { name: "Ack All Alerts", action: function() { var b = document.getElementById("ack-all-btn"); if (b) b.click(); } },
        { name: "Refresh Dashboard", action: function() { location.reload(); } },
        { name: "Logout", action: function() { if (window._bridgeDashboard) window._bridgeDashboard._logout(); } },
    ];

    function _clickTab(name) {
        var tab = document.querySelector('[data-tab="' + name + '"]');
        if (tab) tab.click();
        _closePalette();
    }

    function _showPalette() {
        if (_paletteEl) { _closePalette(); return; }
        _paletteEl = document.createElement("div");
        _paletteEl.id = "command-palette";
        _paletteEl.style.cssText = "position:fixed;top:15%;left:50%;transform:translateX(-50%);width:400px;max-height:60vh;background:var(--bg-card,#1e1e2e);border:1px solid var(--border,#333);border-radius:12px;z-index:10001;box-shadow:0 8px 32px rgba(0,0,0,0.5);overflow:hidden;";

        var input = document.createElement("input");
        input.type = "text";
        input.placeholder = "Type a command...";
        input.style.cssText = "width:100%;padding:12px 16px;background:transparent;border:none;border-bottom:1px solid var(--border,#333);color:var(--text,#fff);font-size:16px;outline:none;";
        _paletteEl.appendChild(input);

        var list = document.createElement("div");
        list.style.cssText = "max-height:50vh;overflow-y:auto;";
        _paletteEl.appendChild(list);

        function render(filter) {
            var h = "";
            var f = (filter || "").toLowerCase();
            commands.forEach(function(cmd, i) {
                if (f && cmd.name.toLowerCase().indexOf(f) === -1) return;
                h += '<div class="cmd-item" data-cmd-idx="' + i + '" style="padding:10px 16px;cursor:pointer;border-bottom:1px solid var(--border,#222);">' + esc(cmd.name) + '</div>';
            });
            list.innerHTML = h || '<div style="padding:10px 16px;opacity:0.5;">No matching commands</div>';
            list.querySelectorAll(".cmd-item").forEach(function(el) {
                el.addEventListener("click", function() {
                    var idx = parseInt(this.getAttribute("data-cmd-idx"));
                    commands[idx].action();
                    _closePalette();
                });
                el.addEventListener("mouseenter", function() { this.style.background = "var(--bg-hover,#333)"; });
                el.addEventListener("mouseleave", function() { this.style.background = ""; });
            });
        }

        input.addEventListener("input", function() { render(input.value); });
        input.addEventListener("keydown", function(e) {
            if (e.key === "Escape") _closePalette();
            if (e.key === "Enter") {
                var first = list.querySelector(".cmd-item");
                if (first) first.click();
            }
        });

        document.body.appendChild(_paletteEl);
        render("");
        input.focus();

        // Close on outside click
        setTimeout(function() {
            document.addEventListener("click", _outsideClick);
        }, 100);
    }

    function _outsideClick(e) {
        if (_paletteEl && !_paletteEl.contains(e.target)) _closePalette();
    }

    function _closePalette() {
        if (_paletteEl) { _paletteEl.remove(); _paletteEl = null; }
        document.removeEventListener("click", _outsideClick);
    }

    document.addEventListener("keydown", function(e) {
        if ((e.ctrlKey || e.metaKey) && e.key === "k") {
            // P1-4: don't steal Ctrl+K when the user is typing in an input,
            // textarea, select, or any contenteditable surface. Let the
            // editor / form field handle it (browser default for inputs is
            // a no-op so the user just keeps typing, but contenteditable
            // surfaces may have their own bindings).
            var ae = document.activeElement;
            if (ae && (/^(INPUT|TEXTAREA|SELECT)$/.test(ae.tagName) || ae.isContentEditable)) {
                return;
            }
            e.preventDefault();
            _showPalette();
        }
    });
})();


/* ================================================================
   CSS for High Alert mode
   ================================================================ */

(function() {
    var style = document.createElement("style");
    style.textContent = [
        ".high-alert-mode { animation: pulse-border 2s infinite; }",
        "@keyframes pulse-border { 0%,100% { border-color: transparent; } 50% { border-color: #ff6b6b; } }",
        ".high-alert-mode .dashboard-header { border-bottom: 2px solid #ff6b6b; }",
        "#high-alert-btn.active { animation: pulse-btn 1s infinite; }",
        "@keyframes pulse-btn { 0%,100% { opacity:1; } 50% { opacity:0.6; } }",
        "#command-palette input::placeholder { color: var(--text-muted, #666); }",
    ].join("\n");
    document.head.appendChild(style);
})();


/* ================================================================
   G) ANIMATION BUDGET ARBITER — cog-review §3.1 (PR-35)

   In a worst case (critical alert + High Alert + stale data) the
   operator sees five elements pulsing at three different cadences:
   the critical banner (2s), the critical tab badge (1.5s), an
   alert row (1.5s), the High Alert button (1s), and the connection
   status dot (1s). The ICU literature calls this alarm fatigue —
   too many competing motions and the eye can't localize the one
   that actually demands attention.

   This arbiter implements a single boolean budget: when a
   higher-priority animation source is present (critical banner
   visible OR a critical tab badge visible), set
   body.suppress-lower-pulses, and the CSS rules in style.css
   freeze the lower-priority pulses. Companion CSS lives at the
   end of style.css (search "PR-35").

   Visibility check for .critical-banner is deliberately tolerant:
   the banner uses .hidden in markup but may also be hidden via
   inline style="display: none" or the [hidden] attribute. We
   treat all three as "not visible."
   ================================================================ */

(function() {
    var _scheduled = false;

    function _isVisible(el) {
        if (!el) return false;
        if (el.hasAttribute("hidden")) return false;
        if (el.classList && el.classList.contains("hidden")) return false;
        // Inline style display:none. Don't run getComputedStyle on every
        // node — it forces layout. Cheap string check is good enough for
        // the elements we care about (banner / tab badge).
        var s = el.getAttribute("style") || "";
        if (s.indexOf("display: none") !== -1 || s.indexOf("display:none") !== -1) {
            return false;
        }
        return true;
    }

    function _updateAnimationBudget() {
        _scheduled = false;
        if (!document.body) return;
        var banner = document.querySelector(".critical-banner");
        var badge = document.querySelector(".tab-badge.badge-critical.badge-visible") ||
                    document.querySelector(".tab-badge.badge-critical");
        var shouldSuppress = _isVisible(banner) || _isVisible(badge);
        document.body.classList.toggle("suppress-lower-pulses", shouldSuppress);
    }

    // Coalesce bursts of DOM mutations into one budget evaluation per
    // animation frame. Without this, a render that touches 50 nodes
    // would trigger 50 evaluations.
    function _scheduleUpdate() {
        if (_scheduled) return;
        _scheduled = true;
        if (window.requestAnimationFrame) {
            window.requestAnimationFrame(_updateAnimationBudget);
        } else {
            setTimeout(_updateAnimationBudget, 16);
        }
    }

    function _initArbiter() {
        _updateAnimationBudget();

        // Scope to body subtree; filter to the attributes that can flip
        // visibility of the banner or critical tab badge. We don't need
        // characterData or attributeOldValue, which keeps the observer
        // payload small.
        var observer = new MutationObserver(_scheduleUpdate);
        observer.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ["class", "hidden", "style"]
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", _initArbiter);
    } else {
        _initArbiter();
    }
})();
