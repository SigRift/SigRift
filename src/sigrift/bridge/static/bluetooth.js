/**
 * Bluetooth SIGINT Panel -- Device Discovery, Anomaly Detection
 *
 * Follows the DetectionDashboard pattern. Polls Bluetooth API endpoints and
 * renders device table, stats summary, anomaly cards, and real-time updates
 * via WebSocket.
 *
 * Security: All dynamic content is HTML-escaped via esc().
 */
"use strict";

/* A key that names the same anomaly across polls, or "" when it has none. */
function _btTimelineKey(a) {
    if (a.id != null) return "id:" + a.id;
    if (a.anomaly_id != null) return "aid:" + a.anomaly_id;
    if (a.device_addr || a.timestamp) return "k:" + (a.device_addr || "") + "|" + (a.anomaly_type || "") + "|" + (a.timestamp || "");
    return "";
}

function BluetoothPanel(dashboard) {
    this.dashboard = dashboard;
    this.devices = [];
    this.stats = {};
    this.btAnomalies = [];
    this.btAnomalyTotal = 0;
    this.selectedDeviceAddr = null;
    this.selectedDeviceType = "all";
    this.manufacturerSearch = "";
    this.showFilter = "all";
    this.whitelistedAddrs = {};
    this.sortCol = "rssi";
    this.sortAsc = false;
    this.pollTimers = {};
    this.tableCollapsed = true;
    this.tableVisibleRows = 20;
    this._selectedBtIds = {};

    this._active = false;

    this._initDeviceTypeToggle();
    this._initManufacturerSearch();
    this._initShowFilter();
    this._initBtBulkSelection();
    this._initWebSocket();
}

/* -- Polling ---------------------------------------------------- */

BluetoothPanel.prototype._loadWhitelist = function() {
    var s = this;
    return s.dashboard.apiFetch("/api/admin/bt-whitelist")
        .then(function(d) {
            var wl = d.whitelist || [];
            s.whitelistedAddrs = {};
            for (var i = 0; i < wl.length; i++) {
                s.whitelistedAddrs[wl[i].device_addr.toUpperCase()] = wl[i].id;
            }
        })
        .catch(function() {});
};

BluetoothPanel.prototype._whitelistDevice = function(addr, name) {
    var s = this;
    s.dashboard.apiFetch("/api/admin/bt-whitelist", {
        method: "POST",
        body: { device_addr: addr, device_name: name || "" }
    }).then(function() {
        showToast("Whitelisted " + (name || addr), "success");
        // Redraw once the reloaded whitelist is in, so the device shows as
        // authorized at once (a failed reload is swallowed and redraws as is).
        s._loadWhitelist().then(function() { s._renderDeviceTable(s.devices); });
    }).catch(function(e) {
        var msg = (e && e.detail) || (e && e.message) || "Failed";
        showToast("Whitelist failed: " + msg, "error");
    });
};

BluetoothPanel.prototype._stopPolling = function() {
    for (var k in this.pollTimers) {
        if (this.pollTimers[k]) clearInterval(this.pollTimers[k]);
    }
    this.pollTimers = {};
};

BluetoothPanel.prototype.activate = function() {
    if (this._active) return;
    this._active = true;
    this._startPolling();
};

BluetoothPanel.prototype.deactivate = function() {
    this._active = false;
    this._stopPolling();
};

BluetoothPanel.prototype._startPolling = function() {
    var s = this;
    s._stopPolling();
    s._loadWhitelist();
    s._pollDevices();
    setTimeout(function() { if (s._active) s._pollStats(); }, 500);
    setTimeout(function() { if (s._active) s._pollAnomalies(); }, 1000);
    s.pollTimers.dev = setInterval(function() { if (s._active) s._pollDevices(); }, 15000);
    s.pollTimers.st = setInterval(function() { if (s._active) s._pollStats(); }, 20000);
    s.pollTimers.anom = setInterval(function() { if (s._active) s._pollAnomalies(); }, 15000);
};

BluetoothPanel.prototype._pollDevices = function() {
    var s = this;
    var tb = document.getElementById("bt-device-tbody");
    if (tb && !tb.innerHTML) {
        tb.innerHTML = '<tr><td colspan="9"><div class="loading-container"><div class="loading-spinner"></div>Loading Bluetooth devices...</div></td></tr>';
    }
    var params = "?limit=200";
    if (s.selectedDeviceType !== "all") params += "&device_type=" + encodeURIComponent(s.selectedDeviceType);
    s.dashboard.apiFetch("/api/bluetooth/devices" + params)
        .then(function(d) {
            s.devices = d.devices || [];
            s._renderDeviceTable(s.devices);
            setText("bt-device-count-badge", s.devices.length);
            clearFetchError("bt-devices");
        })
        .catch(function(e) {
            trackFetchError("bt-devices", e);
            if (tb) {
                tb.innerHTML = '<tr><td colspan="9"><div class="error-state"><span class="error-icon">!</span><p>Failed to load Bluetooth devices</p><button class="retry-btn">Retry</button></div></td></tr>';
                var rb = tb.querySelector(".retry-btn");
                if (rb) rb.addEventListener("click", function() { if (window.dashboard && window.dashboard.btPanel) window.dashboard.btPanel._pollDevices(); });
            }
        });
};

BluetoothPanel.prototype._pollStats = function() {
    var s = this;
    s.dashboard.apiFetch("/api/bluetooth/stats")
        .then(function(d) {
            clearFetchError("bt-stats");
            s.stats = d;
            s._renderStats(d);
        })
        .catch(function(e) {
            trackFetchError("bt-stats", e);
        });
};

BluetoothPanel.prototype._pollAnomalies = function() {
    var s = this;
    var c = document.getElementById("bt-anomaly-queue");
    if (c && !c.innerHTML) {
        c.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div>Loading Bluetooth anomalies...</div>';
    }
    s.dashboard.apiFetch("/api/bluetooth/anomalies?min_score=0.3&limit=50")
        .then(function(d) {
            s.btAnomalies = d.anomalies || [];
            s.btAnomalyTotal = d.total != null ? d.total : s.btAnomalies.length;
            s._renderAnomalyQueue();
            var badge = s.btAnomalyTotal > s.btAnomalies.length
                ? s.btAnomalies.length + " / " + s.btAnomalyTotal
                : String(s.btAnomalyTotal);
            setText("bt-anomaly-count-badge", badge);
            setText("sum-bt-anomalies", s.btAnomalyTotal);
            clearFetchError("bt-anomalies");
        })
        .catch(function(e) {
            trackFetchError("bt-anomalies", e);
            if (c) {
                c.innerHTML = '<div class="error-state"><span class="error-icon">!</span><p>Failed to load Bluetooth anomalies</p><button class="retry-btn">Retry</button></div>';
                var rb = c.querySelector(".retry-btn");
                if (rb) rb.addEventListener("click", function() { if (window.dashboard && window.dashboard.btPanel) window.dashboard.btPanel._pollAnomalies(); });
            }
        });
};

/* -- Device Type Toggle ----------------------------------------- */

BluetoothPanel.prototype._initDeviceTypeToggle = function() {
    var s = this;
    var wrap = document.getElementById("bt-type-toggle");
    if (!wrap) return;
    wrap.querySelectorAll("[data-bt-type]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            wrap.querySelectorAll("[data-bt-type]").forEach(function(b) { b.classList.remove("active"); });
            btn.classList.add("active");
            s.selectedDeviceType = btn.getAttribute("data-bt-type");
            s._pollDevices();
        });
    });
};

/* -- Manufacturer Search ---------------------------------------- */

BluetoothPanel.prototype._initManufacturerSearch = function() {
    var s = this;
    var input = document.getElementById("bt-manufacturer-search");
    if (!input) return;
    input.addEventListener("input", function() {
        s.manufacturerSearch = this.value.toLowerCase().trim();
        s._renderDeviceTable(s.devices);
    });
};

/* -- Show Filter (Authorized / Unauthorized) -------------------- */

BluetoothPanel.prototype._initShowFilter = function() {
    var s = this;
    var sel = document.getElementById("bt-device-show-select");
    if (sel) {
        sel.addEventListener("change", function() {
            s.showFilter = this.value;
            s._renderDeviceTable(s.devices);
        });
    }
};

/* -- Device Table ----------------------------------------------- */

BluetoothPanel.prototype._renderDeviceTable = function(devices) {
    var s = this;
    var tb = document.getElementById("bt-device-tbody");
    var em = document.getElementById("bt-device-empty");
    if (!tb) return;
    if (!devices || !devices.length) {
        tb.innerHTML = "";
        if (em) em.style.display = "";
        return;
    }
    if (em) em.style.display = "none";

    // Filter by manufacturer search
    var filtered = devices;
    if (s.manufacturerSearch) {
        filtered = filtered.filter(function(d) {
            return (d.manufacturer || "").toLowerCase().indexOf(s.manufacturerSearch) !== -1
                || (d.device_name || "").toLowerCase().indexOf(s.manufacturerSearch) !== -1;
        });
    }

    // Filter by authorization status
    if (s.showFilter === "authorized") {
        filtered = filtered.filter(function(d) {
            return s.whitelistedAddrs[(d.device_addr || "").toUpperCase()] != null;
        });
    } else if (s.showFilter === "unauthorized") {
        filtered = filtered.filter(function(d) {
            return s.whitelistedAddrs[(d.device_addr || "").toUpperCase()] == null;
        });
    }

    if (!filtered.length) {
        // "all" is no qualifier: name the search instead ("No all devices" read wrong).
        var emptyText = s.showFilter === "authorized" || s.showFilter === "unauthorized"
            ? "No " + s.showFilter + " devices"
            : (s.manufacturerSearch ? "No devices match the search" : "No devices");
        tb.innerHTML = "<tr><td colspan=\"9\" class=\"empty-state\">" + esc(emptyText) + "</td></tr>";
        return;
    }

    // Sort
    var col = s.sortCol, asc = s.sortAsc;
    var sorted = filtered.slice().sort(function(a, b) {
        var va, vb;
        switch (col) {
            case "addr": va = a.device_addr || ""; vb = b.device_addr || ""; break;
            case "name": va = (a.device_name || "").toLowerCase(); vb = (b.device_name || "").toLowerCase(); break;
            case "type": va = a.device_type || ""; vb = b.device_type || ""; break;
            case "manufacturer": va = (a.manufacturer || "").toLowerCase(); vb = (b.manufacturer || "").toLowerCase(); break;
            case "rssi": va = a.rssi_dbm || -100; vb = b.rssi_dbm || -100; break;
            case "node": va = (a.node_ids || []).join(","); vb = (b.node_ids || []).join(","); break;
            case "services": va = (a.service_uuids || []).length; vb = (b.service_uuids || []).length; break;
            case "last_seen": va = a.last_seen || a.timestamp || ""; vb = b.last_seen || b.timestamp || ""; break;
            default: va = 0; vb = 0;
        }
        if (va < vb) return asc ? -1 : 1;
        if (va > vb) return asc ? 1 : -1;
        return 0;
    });

    var showCount = s.tableCollapsed ? s.tableVisibleRows : sorted.length;
    var displayRows = sorted.slice(0, showCount);
    var h = "";
    for (var i = 0; i < displayRows.length; i++) {
        var d = displayRows[i];
        var sigCls = (d.rssi_dbm || -100) > -50 ? "accent-green"
            : (d.rssi_dbm || -100) > -70 ? "accent-yellow" : "accent-red";
        var svcCount = (d.service_uuids || []).length;
        var typeBadge = d.device_type === "ble" ? "BLE"
            : d.device_type === "classic" ? "Classic"
            : d.device_type === "dual" ? "Dual" : "Unknown";
        // Node badges
        var nodeList = d.node_ids || (d.node_id ? [d.node_id] : []);
        var nodeHtml = "";
        if (nodeList.length > 0) {
            for (var ni = 0; ni < nodeList.length; ni++) {
                nodeHtml += "<span class=\"node-tag\">" + esc(nodeList[ni]) + "</span> ";
            }
        } else {
            nodeHtml = "--";
        }

        var isWl = s.whitelistedAddrs[(d.device_addr || "").toUpperCase()] != null;
        var actionHtml = isWl
            ? "<span class=\"admin-badge\" style=\"font-size:10px;\">Authorized</span>"
            : "<button class=\"btn btn-sm\" data-bt-wl-addr=\"" + esc(d.device_addr) + "\" data-bt-wl-name=\"" + esc(d.device_name || "") + "\">Whitelist</button>";

        h += "<tr data-addr=\"" + esc(d.device_addr) + "\" class=\"bt-dev-row\">"
            + "<td><code>" + esc(d.device_addr) + "</code></td>"
            + "<td>" + esc(d.device_name || "(unnamed)") + "</td>"
            + "<td><span class=\"admin-badge\">" + esc(typeBadge) + "</span></td>"
            + "<td>" + esc(d.manufacturer || "--") + "</td>"
            + "<td style=\"color:var(--" + sigCls + ")\">" + esc(d.rssi_dbm != null ? d.rssi_dbm.toFixed(1) : "--") + " dBm</td>"
            + "<td>" + nodeHtml + "</td>"
            + "<td>" + esc(svcCount > 0 ? svcCount + " svc" : "--") + "</td>"
            + "<td>" + fmtTime(d.last_seen || d.timestamp) + "</td>"
            + "<td>" + actionHtml + "</td>"
            + "</tr>";
    }
    tb.innerHTML = h;

    // Show all / collapse toggle
    var toggleWrap = document.getElementById("bt-table-toggle");
    if (!toggleWrap) {
        toggleWrap = document.createElement("div");
        toggleWrap.id = "bt-table-toggle";
        toggleWrap.style.textAlign = "center";
        toggleWrap.style.padding = "6px 0";
        var tableEl = document.getElementById("bt-device-table");
        if (tableEl && tableEl.parentNode) tableEl.parentNode.appendChild(toggleWrap);
    }
    if (sorted.length > s.tableVisibleRows) {
        var remaining = sorted.length - s.tableVisibleRows;
        toggleWrap.innerHTML = s.tableCollapsed
            ? "<button class=\"btn btn-sm btn-secondary\" id=\"bt-table-expand\">Show all " + sorted.length + " devices (" + remaining + " more)</button>"
            : "<button class=\"btn btn-sm btn-secondary\" id=\"bt-table-expand\">Collapse to " + s.tableVisibleRows + "</button>";
        toggleWrap.style.display = "";
        var expandBtn = document.getElementById("bt-table-expand");
        if (expandBtn) {
            expandBtn.addEventListener("click", function() {
                s.tableCollapsed = !s.tableCollapsed;
                s._renderDeviceTable(s.devices);
            });
        }
    } else {
        toggleWrap.style.display = "none";
    }

    // Row click for detail
    tb.querySelectorAll(".bt-dev-row").forEach(function(row) {
        row.addEventListener("click", function(e) {
            if (e.target.closest("button")) return;
            var addr = this.getAttribute("data-addr");
            s.selectedDeviceAddr = addr;
            tb.querySelectorAll(".bt-dev-row").forEach(function(r) { r.style.background = ""; });
            this.style.background = "var(--bg-hover)";
        });
    });

    // Whitelist buttons
    tb.querySelectorAll("[data-bt-wl-addr]").forEach(function(btn) {
        btn.addEventListener("click", function(e) {
            e.stopPropagation();
            var addr = this.getAttribute("data-bt-wl-addr");
            var name = this.getAttribute("data-bt-wl-name");
            if (confirm("Whitelist BT device " + addr + (name ? " (" + name + ")" : "") + "?")) {
                s._whitelistDevice(addr, name);
            }
        });
    });
};

/* -- Stats Bar -------------------------------------------------- */

BluetoothPanel.prototype._renderStats = function(stats) {
    var total = stats.total_devices != null ? stats.total_devices : "--";
    var ble = stats.ble_count != null ? stats.ble_count : "--";
    var classic = stats.classic_count != null ? stats.classic_count : "--";
    var anomalies = stats.anomaly_count != null ? stats.anomaly_count : "--";
    setText("bt-stat-total", total);
    setText("bt-stat-ble", ble);
    setText("bt-stat-classic", classic);
    setText("bt-stat-anomalies", anomalies);

    // Update summary tab BT stats
    setText("sum-bt-devices", total);
};

/* -- Anomaly Queue ---------------------------------------------- */

BluetoothPanel.prototype._renderAnomalyQueue = function() {
    var c = document.getElementById("bt-anomaly-queue");
    var em = document.getElementById("bt-anomaly-empty");
    if (!c) return;

    var anomalies = this.btAnomalies;

    // Forget selections and timeline pushes of anomalies no longer loaded.
    var present = {}, presentKeys = {};
    for (var pi = 0; pi < anomalies.length; pi++) {
        if (anomalies[pi].id != null) present[String(anomalies[pi].id)] = true;
        var pk = _btTimelineKey(anomalies[pi]);
        if (pk) presentKeys[pk] = true;
    }
    for (var sid in this._selectedBtIds) {
        if (!present[sid]) delete this._selectedBtIds[sid];
    }
    for (var tk in (this._tlPushedKeys || {})) {
        if (!presentKeys[tk]) delete this._tlPushedKeys[tk];
    }

    if (!anomalies.length) {
        c.innerHTML = "";
        if (em) em.style.display = "";
        // No cards are bound below, so refresh the bulk bar here: it hides
        // once the queue is empty.
        this._updateBtBulkBar();
        return;
    }
    if (em) em.style.display = "none";

    var s = this;
    var h = "";
    for (var i = 0; i < anomalies.length; i++) {
        h += s._renderAnomalyCard(anomalies[i]);
    }
    c.innerHTML = h;
    s._bindAnomalyEvents(c);
};

BluetoothPanel.prototype._renderAnomalyCard = function(a) {
    var score = a.anomaly_score != null ? a.anomaly_score : 0;
    var priority = score >= 0.7 ? "critical" : score >= 0.5 ? "anomalous" : score >= 0.3 ? "interesting" : "normal";
    var scoreCls = "score-" + priority;

    var cardId = a.id != null ? String(a.id) : "";
    var isChecked = !!this._selectedBtIds[cardId];

    var h = "<div class=\"anomaly-card priority-" + esc(priority) + (isChecked ? " bulk-selected" : "") + "\" role=\"listitem\">"
        // Bulk actions name anomaly row IDs, so an anomaly without one gets
        // a disabled box (as in the RF queue).
        + (cardId
            ? "<input type=\"checkbox\" class=\"bulk-checkbox\" data-bt-bulk-id=\"" + esc(cardId) + "\"" + (isChecked ? " checked" : "") + " aria-label=\"Select " + esc(a.device_name || a.device_addr || "Unknown") + " anomaly\">"
            : "<input type=\"checkbox\" class=\"bulk-checkbox\" disabled title=\"No stored anomaly ID\" aria-label=\"" + esc(a.device_name || a.device_addr || "Unknown") + " anomaly cannot be selected\">")
        + "<div class=\"anomaly-card-header\">"
        + "<span class=\"anomaly-score-badge " + scoreCls + "\">" + score.toFixed(2) + "</span>"
        + "<strong>" + esc(a.device_name || "(unnamed)") + "</strong>"
        + " <code>" + esc(a.device_addr) + "</code>";

    if (a.device_type) {
        var typeBadge = a.device_type === "ble" ? "BLE"
            : a.device_type === "classic" ? "Classic"
            : a.device_type === "dual" ? "Dual" : "Unknown";
        h += " <span class=\"admin-badge\">" + esc(typeBadge) + "</span>";
    }

    h += "</div>"
        + "<div class=\"anomaly-card-body\">"
        + "<span>RSSI: " + esc(a.rssi_dbm != null ? a.rssi_dbm.toFixed(1) + " dBm" : "--") + "</span>"
        + "<span>Manufacturer: " + esc(a.manufacturer || "--") + "</span>"
        + "<span>" + esc(a.baseline_status || "--") + "</span>"
        + "<span>" + fmtTime(a.timestamp) + "</span>";
    if (a.seen_count > 1) {
        h += "<span class=\"seen-count\">seen " + esc(a.seen_count) + "x</span>";
    }
    h += "</div>";

    // Node observations — show which nodes saw this device
    var nodeIds = a.node_ids || {};
    var nodeKeys = Object.keys(nodeIds);
    if (nodeKeys.length > 0) {
        // Find strongest RSSI among nodes; a node without a numeric reading
        // ("? dBm") is never the strongest (null would compare as 0 dBm).
        var strongest = null;
        for (var ni = 0; ni < nodeKeys.length; ni++) {
            var rv = nodeIds[nodeKeys[ni]];
            if (typeof rv !== "number" || !isFinite(rv)) continue;
            if (strongest === null || rv > nodeIds[strongest]) strongest = nodeKeys[ni];
        }
        h += "<div class=\"anomaly-card-nodes\">"
            + "<span style=\"color:var(--text-secondary);font-size:11px;margin-right:4px;\">Nodes:</span>";
        for (var ni = 0; ni < nodeKeys.length; ni++) {
            var nk = nodeKeys[ni];
            var nRssi = nodeIds[nk];
            var isStrongest = nk === strongest && nodeKeys.length > 1;
            var nodeCls = isStrongest ? "node-tag node-strongest" : "node-tag";
            h += "<span class=\"" + nodeCls + "\">"
                + esc(nk) + " <small>(" + (typeof nRssi === "number" && isFinite(nRssi) ? nRssi.toFixed(1) : "?") + " dBm)</small>"
                + "</span>";
        }
        h += "</div>";
    } else if (a.node_id) {
        h += "<div class=\"anomaly-card-nodes\">"
            + "<span style=\"color:var(--text-secondary);font-size:11px;margin-right:4px;\">Node:</span>"
            + "<span class=\"node-tag node-strongest\">" + esc(a.node_id) + "</span>"
            + "</div>";
    }

    // Dimensions
    h += "<div class=\"anomaly-card-dims\">";
    if (a.dimensions) {
        var dims = a.dimensions;
        var dimKeys = Object.keys(dims);
        dimKeys.sort(function(x, y) { return (dims[y] || 0) - (dims[x] || 0); });
        var dimLabels = {
            spoofed_identity: "Spoofed Identity",
            rogue_device: "Rogue Device",
            rssi_anomaly: "RSSI Anomaly",
            service_change: "Service Change",
            ble_beacon_spoof: "BLE Beacon Spoof",
            device_surge: "Device Surge",
            new_device: "New Device",
            manufacturer_change: "Manufacturer Change",
            name_change: "Name Change",
            type_change: "Type Change",
            adv_anomaly: "Adv Anomaly"
        };
        for (var d = 0; d < Math.min(4, dimKeys.length); d++) {
            if (dims[dimKeys[d]] > 0) {
                var dLabel = dimLabels[dimKeys[d]] || dimKeys[d];
                h += "<span class=\"dim-tag\">"
                    + esc(dLabel) + ": " + dims[dimKeys[d]].toFixed(2) + "</span>";
            }
        }
    }

    if (a.reasons && a.reasons.length) {
        h += "<div class=\"anomaly-reasons\">";
        for (var r = 0; r < Math.min(3, a.reasons.length); r++) {
            h += "<small>" + esc(a.reasons[r]) + "</small> ";
        }
        h += "</div>";
    }
    h += "</div>";

    // R11: Cross-protocol entity links
    // dashboard.js: indexEntity(protocol, type, value) and getEntityLinks(
    // protocol, type, value), which returns ready badge markup (or "").
    // A Bluetooth address and a BSSID are both indexed as type "mac".
    var bd = window._bridgeDashboard;
    if (bd && bd.indexEntity && bd.getEntityLinks) {
        if (a.device_addr) bd.indexEntity("bluetooth", "mac", a.device_addr);
        if (a.node_id) bd.indexEntity("bluetooth", "node", a.node_id);
        var links = a.device_addr ? bd.getEntityLinks("bluetooth", "mac", a.device_addr) : "";
        if (links) h += "<div class=\"anomaly-card-links\">" + links + "</div>";
    }

    // Actions
    h += "<div class=\"anomaly-card-actions\">"
        + "<button class=\"btn btn-sm\" data-bt-dismiss=\"" + esc(a.id) + "\">Dismiss</button>"
        + "<button class=\"btn btn-sm\" data-bt-snooze=\"" + esc(a.id) + "\">Snooze 24h</button>"
        + "</div>"
        + "</div>";

    // N4: Push anomalous/critical BT events to cross-protocol threat timeline
    // Each poll replaces the anomaly objects, so remember what was pushed by
    // a stable key on the panel, not by a flag on the object. The timeline
    // draws, places and names events by protocol "bluetooth".
    var tlKey = _btTimelineKey(a);
    var pushed = this._tlPushedKeys || (this._tlPushedKeys = {});
    var already = tlKey ? !!pushed[tlKey] : !!a._tlPushed;
    if (score >= 0.5 && !already && window._bridgeDashboard && window._bridgeDashboard._pushThreatEvent) {
        if (tlKey) pushed[tlKey] = true;
        a._tlPushed = true;
        var tlSev = score >= 0.7 ? "critical" : "anomalous";
        var tlLabel = (a.device_name || a.device_addr || "Unknown BT");
        window._bridgeDashboard._pushThreatEvent("bluetooth", tlSev, tlLabel);
    }

    return h;
};

BluetoothPanel.prototype._bindAnomalyEvents = function(c) {
    var s = this;

    // Single dismiss
    c.querySelectorAll("[data-bt-dismiss]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var aid = this.getAttribute("data-bt-dismiss");
            s.dashboard.apiFetch("/api/bluetooth/anomalies/" + encodeURIComponent(aid) + "/dismiss", { method: "PUT" })
                .then(function() { showToast("BT anomaly dismissed", "success"); s._pollAnomalies(); })
                .catch(function() { showToast("Failed to dismiss anomaly", "error"); });
        });
    });

    // Single snooze (24h)
    c.querySelectorAll("[data-bt-snooze]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var aid = this.getAttribute("data-bt-snooze");
            s.dashboard.apiFetch("/api/bluetooth/anomalies/" + encodeURIComponent(aid) + "/snooze", {
                method: "PUT",
                body: { hours: 24 }
            })
                .then(function() { showToast("BT anomaly snoozed for 24h", "success"); s._pollAnomalies(); })
                .catch(function() { showToast("Failed to snooze anomaly", "error"); });
        });
    });

    // Bulk checkboxes
    s._bindBtBulkCheckboxes(c);
};

/* -- Bulk Selection --------------------------------------------- */

BluetoothPanel.prototype._initBtBulkSelection = function() {
    var s = this;
    var selectAllCb = document.getElementById("bt-select-all");
    var dismissBtn = document.getElementById("bt-bulk-dismiss");
    var snoozeBtn = document.getElementById("bt-bulk-snooze");

    if (selectAllCb) {
        selectAllCb.addEventListener("change", function() {
            var checked = selectAllCb.checked;
            s._selectedBtIds = {};
            if (checked) {
                for (var i = 0; i < s.btAnomalies.length; i++) {
                    var aid = s.btAnomalies[i].id != null ? String(s.btAnomalies[i].id) : "";
                    if (aid) s._selectedBtIds[aid] = true;
                }
            }
            s._renderAnomalyQueue();
            s._updateBtBulkBar();
        });
    }

    if (dismissBtn) {
        dismissBtn.addEventListener("click", function() {
            var ids = Object.keys(s._selectedBtIds).map(Number);
            if (!ids.length) return;
            if (ids.length > 1 && !confirm("Dismiss " + ids.length + " selected BT anomalies?")) return;
            s.dashboard.apiFetch("/api/bluetooth/anomalies/bulk/dismiss", {
                method: "PUT",
                body: { ids: ids }
            }).then(function() {
                showToast("Dismissed " + ids.length + " BT anomalies", "success");
                s._selectedBtIds = {};
                s._updateBtBulkBar();
                s._pollAnomalies();
            }).catch(function() {
                showToast("Bulk dismiss failed", "error");
            });
        });
    }

    if (snoozeBtn) {
        snoozeBtn.addEventListener("click", function() {
            var ids = Object.keys(s._selectedBtIds).map(Number);
            if (!ids.length) return;
            s.dashboard.apiFetch("/api/bluetooth/anomalies/bulk/snooze", {
                method: "PUT",
                body: { ids: ids, hours: 24 }
            }).then(function() {
                showToast("Snoozed " + ids.length + " BT anomalies for 24h", "success");
                s._selectedBtIds = {};
                s._updateBtBulkBar();
                s._pollAnomalies();
            }).catch(function() {
                showToast("Bulk snooze failed", "error");
            });
        });
    }
};

BluetoothPanel.prototype._bindBtBulkCheckboxes = function(c) {
    var s = this;
    c.querySelectorAll("[data-bt-bulk-id]").forEach(function(cb) {
        cb.addEventListener("change", function(e) {
            e.stopPropagation();
            var aid = this.getAttribute("data-bt-bulk-id");
            if (this.checked) {
                s._selectedBtIds[aid] = true;
            } else {
                delete s._selectedBtIds[aid];
            }
            var card = this.closest(".anomaly-card");
            if (card) card.classList.toggle("bulk-selected", this.checked);
            s._updateBtBulkBar();
        });
    });

    s._updateBtBulkBar();
};

BluetoothPanel.prototype._updateBtBulkBar = function() {
    var bar = document.getElementById("bt-bulk-bar");
    var countEl = document.getElementById("bt-bulk-count");
    var selectAllCb = document.getElementById("bt-select-all");
    var dismissBtn = document.getElementById("bt-bulk-dismiss");
    var snoozeBtn = document.getElementById("bt-bulk-snooze");

    if (!bar) return;

    var count = Object.keys(this._selectedBtIds).length;
    bar.style.display = this.btAnomalies.length > 0 ? "" : "none";
    if (countEl) countEl.textContent = count + " selected";
    if (dismissBtn) dismissBtn.disabled = count === 0;
    if (snoozeBtn) snoozeBtn.disabled = count === 0;

    if (selectAllCb) {
        // Only anomalies with an ID can be selected.
        var sel = this._selectedBtIds;
        var selectable = this.btAnomalies.filter(function(a) { return a.id != null; });
        selectAllCb.checked = selectable.length > 0 && selectable.every(function(a) { return !!sel[String(a.id)]; });
    }
};

/* -- WebSocket -------------------------------------------------- */

BluetoothPanel.prototype._initWebSocket = function() {
    var s = this;
    // An API key, a session token or a cookie session (whose HttpOnly cookie
    // authenticates the upgrade) opens the socket, as in dashboard._connectWS.
    if (!s.dashboard.apiKey && !s.dashboard.sessionToken && !s.dashboard._cookieAuth) return;
    s.dashboard._connectWS("bluetooth", "/api/bluetooth/ws/bluetooth", function(d) {
        if (!s._active) return;
        if (d.type === "bt_ingest") {
            s._pollDevices();
            s._pollStats();
        }
        if (d.type === "bt_anomaly") {
            s._pollAnomalies();
        }
    });
};
