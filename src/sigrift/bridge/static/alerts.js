/**
 * The Bridge — Alerts Dashboard
 * Dedicated tab for alert management with filtering, sorting,
 * auto-refresh, and summary stats.
 * Security: All dynamic content is HTML-escaped via esc().
 */
"use strict";

/* ================================================================
   AlertsDashboard Class
   ================================================================ */

function AlertsDashboard(dashboard) {
    this.db = dashboard;
    this.alerts = [];
    this.sortField = "triggered_at";
    this.sortDir = "desc";
    this.autoRefresh = true;
    this._refreshTimer = null;
    this._active = false;
    this._nodeIds = [];

    this._initControls();
}

/* -- Controls --------------------------------------------------- */

AlertsDashboard.prototype._initControls = function() {
    var s = this;

    // Filter controls
    var priority = document.getElementById("alerts-tab-priority");
    var time = document.getElementById("alerts-tab-time");
    var node = document.getElementById("alerts-tab-node");
    var hideAcked = document.getElementById("alerts-tab-hide-acked");

    if (priority) priority.addEventListener("change", function() { s._fetchAlerts(); });
    if (time) time.addEventListener("change", function() { s._fetchAlerts(); });
    if (node) node.addEventListener("change", function() { s._fetchAlerts(); });
    if (hideAcked) hideAcked.addEventListener("change", function() { s._fetchAlerts(); });

    // Auto-refresh toggle
    var autoRefreshCb = document.getElementById("alerts-tab-autorefresh");
    if (autoRefreshCb) {
        autoRefreshCb.addEventListener("change", function() {
            s.autoRefresh = autoRefreshCb.checked;
            if (s.autoRefresh && s._active) {
                s._startAutoRefresh();
            } else {
                s._stopAutoRefresh();
            }
        });
    }

    // Manual refresh button
    var refreshBtn = document.getElementById("alerts-tab-refresh-btn");
    if (refreshBtn) refreshBtn.addEventListener("click", function() { s._fetchAlerts(); });

    // Sortable columns
    var ths = document.querySelectorAll("#alerts-tab-table th.sortable");
    ths.forEach(function(th) {
        th.addEventListener("click", function() {
            var field = th.getAttribute("data-sort");
            if (!field) return;
            if (s.sortField === field) {
                s.sortDir = s.sortDir === "asc" ? "desc" : "asc";
            } else {
                s.sortField = field;
                s.sortDir = field === "triggered_at" ? "desc" : "asc";
            }
            s._renderAlerts();
        });
    });
};

/* -- Activation (called from tab switch) ----------------------- */

AlertsDashboard.prototype.activate = function() {
    this._active = true;
    this._fetchAlerts();
    this._populateNodeFilter();
    if (this.autoRefresh) this._startAutoRefresh();
};

AlertsDashboard.prototype.deactivate = function() {
    this._active = false;
    this._stopAutoRefresh();
};

/* -- Auto-refresh ----------------------------------------------- */

AlertsDashboard.prototype._startAutoRefresh = function() {
    var s = this;
    s._stopAutoRefresh();
    s._refreshTimer = setInterval(function() {
        if (isPageActive() && s._active) s._fetchAlerts();
    }, 10000);
};

AlertsDashboard.prototype._stopAutoRefresh = function() {
    if (this._refreshTimer) {
        clearInterval(this._refreshTimer);
        this._refreshTimer = null;
    }
};

/* -- Node filter population ------------------------------------- */

AlertsDashboard.prototype._populateNodeFilter = function() {
    var s = this;
    s.db.apiFetch("/api/nodes/").then(function(nodes) {
        var sel = document.getElementById("alerts-tab-node");
        if (!sel) return;
        // Preserve current selection
        var current = sel.value;
        // Remove old dynamic options
        while (sel.options.length > 1) sel.remove(1);
        var ids = [];
        for (var i = 0; i < nodes.length; i++) {
            ids.push(nodes[i].node_id);
            var opt = document.createElement("option");
            opt.value = nodes[i].node_id;
            opt.textContent = nodes[i].node_id;
            sel.appendChild(opt);
        }
        s._nodeIds = ids;
        if (current) sel.value = current;
    }).catch(function() {});
};

/* -- Fetch alerts ----------------------------------------------- */

AlertsDashboard.prototype._fetchAlerts = function() {
    var s = this;
    var params = [];

    var prioritySel = document.getElementById("alerts-tab-priority");
    if (prioritySel && prioritySel.value) params.push("severity=" + prioritySel.value);

    var nodeSel = document.getElementById("alerts-tab-node");
    if (nodeSel && nodeSel.value) params.push("node_id=" + encodeURIComponent(nodeSel.value));

    var qs = params.length ? "?" + params.join("&") : "";

    // Show loading on first load
    var tbody = document.getElementById("alerts-tab-tbody");
    if (tbody && !tbody.innerHTML) {
        tbody.innerHTML = '<tr><td colspan="6"><div class="loading-container"><div class="loading-spinner"></div>Loading alerts...</div></td></tr>';
    }

    s.db.apiFetch("/api/alerts/" + qs).then(function(data) {
        clearFetchError("alerts-tab");
        s.alerts = data || [];
        s._renderAlerts();
        if (window.AlertAnalysis) window.AlertAnalysis.refresh(s.db, function() { s._fetchAlerts(); });
    }).catch(function(e) {
        trackFetchError("alerts-tab", e);
    });
};

/* -- Render ----------------------------------------------------- */

AlertsDashboard.prototype._renderAlerts = function() {
    var s = this;
    var filtered = s.alerts.slice();
    var timelineFocus = s._timelineFocusAlert;
    s._timelineFocusAlert = null;

    // Client-side time filter
    var timeSel = document.getElementById("alerts-tab-time");
    if (timeSel && timeSel.value) {
        var hours = parseInt(timeSel.value, 10);
        if (hours > 0) {
            var cutoff = Date.now() - hours * 3600000;
            filtered = filtered.filter(function(a) {
                return new Date(a.triggered_at).getTime() >= cutoff;
            });
        }
    }

    // Client-side hide acknowledged
    var hideAcked = document.getElementById("alerts-tab-hide-acked");
    if (hideAcked && hideAcked.checked) {
        filtered = filtered.filter(function(a) { return !a.acknowledged; });
    }

    // Sort
    var field = s.sortField;
    var dir = s.sortDir === "asc" ? 1 : -1;
    filtered.sort(function(a, b) {
        var va = a[field] || "", vb = b[field] || "";
        if (field === "triggered_at") {
            va = new Date(va).getTime() || 0;
            vb = new Date(vb).getTime() || 0;
        } else if (field === "severity") {
            var order = { critical: 0, high: 0.5, warning: 1, info: 2 };
            va = order[va] != null ? order[va] : 3;
            vb = order[vb] != null ? order[vb] : 3;
        } else {
            va = String(va).toLowerCase();
            vb = String(vb).toLowerCase();
        }
        return va < vb ? -dir : va > vb ? dir : 0;
    });

    // Update summary stats
    s._updateStats(filtered);

    // Update badge
    setText("alerts-tab-badge", filtered.length);

    // Render table
    var tbody = document.getElementById("alerts-tab-tbody");
    var empty = document.getElementById("alerts-tab-empty");
    if (!tbody) return;

    if (!filtered.length) {
        tbody.innerHTML = "";
        if (empty) empty.style.display = "";
        return;
    }
    if (empty) empty.style.display = "none";

    var h = "";
    for (var i = 0; i < filtered.length; i++) {
        var a = filtered[i];
        var sev = esc(a.severity || "info");
        var acked = a.acknowledged ? " acknowledged" : "";
        var priorityBadge = '<span class="alerts-priority-badge ' + sev + '">' + sev + '</span>';

        h += '<tr class="alerts-tab-row ' + sev + acked + '" data-alert-id="' + esc(a.alert_id) + '">';
        h += '<td class="alert-ts-cell">' + fmtTime(a.triggered_at) + '</td>';
        h += '<td>' + priorityBadge + '</td>';
        h += '<td>' + esc(a.name || "--") + '</td>';
        h += '<td class="alert-msg-cell">' + esc(decodeHtmlEscapedText(a.message || "--")) + '</td>';
        h += '<td><span class="alerts-node-tag">' + esc(a.node_id || "--") + '</span></td>';
        h += '<td>';
        if (!a.acknowledged) {
            h += '<button class="btn btn-sm" data-ack-alert-tab="' + esc(a.alert_id) + '">Ack</button>';
        } else {
            h += '<span class="alerts-acked-label">Acked</span>';
        }
        if (a.rf_detection_id) h += '<button class="btn btn-sm" data-known-detection="' + esc(a.rf_detection_id) + '">Mark as known…</button>';
        h += '</td>';
        h += '</tr>';
    }
    tbody.innerHTML = h;
    if (window.KnownSignals) window.KnownSignals.bind(tbody, s.db);

    // Bind ack buttons
    tbody.querySelectorAll("[data-ack-alert-tab]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var alertId = this.getAttribute("data-ack-alert-tab");
            s.db.apiFetch("/api/alerts/" + encodeURIComponent(alertId) + "/ack", { method: "PUT" })
                .then(function() {
                    showToast("Alert acknowledged", "success");
                    s._fetchAlerts();
                    // Also refresh the summary tab alerts
                    if (s.db._loadAlerts) s.db._loadAlerts();
                })
                .catch(function() {
                    showToast("Failed to acknowledge alert", "error");
                });
        });
    });

    // Keep an explicitly selected loaded alert focused across the activation fetch.
    if (timelineFocus) s.focusAlert(timelineFocus, false);

    // Update sort indicators
    var ths = document.querySelectorAll("#alerts-tab-table th.sortable");
    ths.forEach(function(th) {
        th.classList.remove("sort-asc", "sort-desc");
        if (th.getAttribute("data-sort") === s.sortField) {
            th.classList.add(s.sortDir === "asc" ? "sort-asc" : "sort-desc");
        }
    });
};

// Timeline navigation only focuses an exact row already loaded under current filters.
AlertsDashboard.prototype.focusAlert = function(alertId, followRefresh) {
    var tbody = document.getElementById("alerts-tab-tbody");
    if (!tbody) return;
    var rows = tbody.querySelectorAll("[data-alert-id]");
    for (var i = 0; i < rows.length; i++) {
        if (rows[i].getAttribute("data-alert-id") === alertId) {
            if (followRefresh !== false) this._timelineFocusAlert = alertId;
            rows[i].setAttribute("tabindex", "-1");
            rows[i].focus({preventScroll: true});
            rows[i].scrollIntoView({block: "center", behavior: "smooth"});
            return;
        }
    }
};

/* -- Stats ------------------------------------------------------ */

AlertsDashboard.prototype._updateStats = function(filtered) {
    var counts = { critical: 0, warning: 0, info: 0 };
    var unacked = 0;
    for (var i = 0; i < filtered.length; i++) {
        var sev = filtered[i].severity || "info";
        if (counts[sev] != null) counts[sev]++;
        if (!filtered[i].acknowledged) unacked++;
    }
    setText("alerts-count-critical", counts.critical);
    setText("alerts-count-warning", counts.warning);
    setText("alerts-count-info", counts.info);
    setText("alerts-count-total", unacked);
};
