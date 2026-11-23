/**
 * Zigbee Panel -- Device Discovery, Network Topology, Channel Energy
 *
 * Follows the BluetoothPanel pattern. Polls Zigbee API endpoints and
 * renders device table, topology tree, channel energy heatmap, stats
 * summary, and real-time updates via WebSocket.
 *
 * Security: All dynamic content is HTML-escaped via esc().
 */
"use strict";

function ZigbeePanel(dashboard) {
    this.dashboard = dashboard;
    this.devices = [];
    this.stats = {};
    this.topology = [];
    this.selectedDeviceType = "all";
    this.searchQuery = "";
    this.sortCol = "rssi";
    this.sortAsc = false;
    this.pollTimers = {};
    this.tableVisibleRows = 20;
    this.activeSubView = "table"; // table | topology | energy

    this._active = false;

    this._initTypeToggle();
    this._initSearch();
    this._initSubViewToggle();
    this._initWebSocket();
}

/* -- Polling ---------------------------------------------------- */

ZigbeePanel.prototype._stopPolling = function() {
    for (var k in this.pollTimers) {
        if (this.pollTimers[k]) clearInterval(this.pollTimers[k]);
    }
    this.pollTimers = {};
};

ZigbeePanel.prototype.activate = function() {
    if (this._active) return;
    this._active = true;
    this._startPolling();
};

ZigbeePanel.prototype.deactivate = function() {
    this._active = false;
    this._stopPolling();
};

ZigbeePanel.prototype._startPolling = function() {
    var s = this;
    s._stopPolling();
    s._pollDevices();
    setTimeout(function() { if (s._active) s._pollStats(); }, 500);
    setTimeout(function() { if (s._active) s._pollTopology(); }, 1000);
    s.pollTimers.dev = setInterval(function() { if (s._active) s._pollDevices(); }, 15000);
    s.pollTimers.st = setInterval(function() { if (s._active) s._pollStats(); }, 20000);
    s.pollTimers.topo = setInterval(function() { if (s._active) s._pollTopology(); }, 30000);
};

ZigbeePanel.prototype._pollDevices = function() {
    var s = this;
    var url = "/api/zigbee/devices?limit=500";
    if (s.selectedDeviceType !== "all") url += "&device_type=" + s.selectedDeviceType;
    s.dashboard.apiFetch(url).then(function(d) {
        s.devices = d.devices || [];
        if (s.activeSubView === "table") s._renderDeviceTable(s.devices);
        var badge = document.getElementById("zb-device-count-badge");
        if (badge) badge.textContent = s.devices.length;
    }).catch(function() {});
};

ZigbeePanel.prototype._pollStats = function() {
    var s = this;
    s.dashboard.apiFetch("/api/zigbee/stats").then(function(d) {
        s.stats = d;
        s._renderStats(d);
        if (s.activeSubView === "energy") s._renderEnergyHeatmap(d.channel_energy || []);
    }).catch(function() {});
};

ZigbeePanel.prototype._pollTopology = function() {
    var s = this;
    s.dashboard.apiFetch("/api/zigbee/topology").then(function(d) {
        s.topology = d.networks || [];
        if (s.activeSubView === "topology") s._renderTopology(s.topology);
    }).catch(function() {});
};

/* -- Render stats ------------------------------------------------ */

ZigbeePanel.prototype._renderStats = function(st) {
    var el = function(id) { return document.getElementById(id); };
    var total = st.total_devices || 0;
    var panIds = st.total_pan_ids || 0;
    var tb = st.type_breakdown || {};

    if (el("zb-stat-total")) el("zb-stat-total").textContent = total;
    if (el("zb-stat-pan-ids")) el("zb-stat-pan-ids").textContent = panIds;
    if (el("zb-stat-coordinators")) el("zb-stat-coordinators").textContent = tb.coordinator || 0;
    if (el("zb-stat-routers")) el("zb-stat-routers").textContent = tb.router || 0;
    if (el("zb-stat-end-devices")) el("zb-stat-end-devices").textContent = tb.end_device || 0;

    // Summary tab stats
    if (el("sum-zb-devices")) el("sum-zb-devices").textContent = total;
    if (el("sum-zb-pan-ids")) el("sum-zb-pan-ids").textContent = panIds;

    // Channel energy mini-bar in stats
    var energyEl = el("zb-energy-mini");
    if (energyEl && st.channel_energy && st.channel_energy.length) {
        this._renderEnergyMini(energyEl, st.channel_energy);
    }
};

/* -- Sub-view toggle --------------------------------------------- */

ZigbeePanel.prototype._initSubViewToggle = function() {
    var s = this;
    var toggle = document.getElementById("zb-subview-toggle");
    if (!toggle) return;
    toggle.addEventListener("click", function(e) {
        var btn = e.target.closest("[data-zb-subview]");
        if (!btn) return;
        toggle.querySelectorAll("button").forEach(function(b) { b.classList.remove("active"); });
        btn.classList.add("active");
        s.activeSubView = btn.dataset.zbSubview;
        s._showSubView(s.activeSubView);
    });
};

ZigbeePanel.prototype._showSubView = function(view) {
    var views = ["zb-view-table", "zb-view-topology", "zb-view-energy"];
    views.forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.style.display = "none";
    });
    var active = document.getElementById("zb-view-" + view);
    if (active) active.style.display = "block";

    if (view === "table") this._renderDeviceTable(this.devices);
    else if (view === "topology") this._renderTopology(this.topology);
    else if (view === "energy") this._renderEnergyHeatmap(
        (this.stats && this.stats.channel_energy) ? this.stats.channel_energy : []);
};

/* -- Render device table ----------------------------------------- */

ZigbeePanel.prototype._renderDeviceTable = function(devices) {
    var tbody = document.getElementById("zb-device-tbody");
    var emptyEl = document.getElementById("zb-device-empty");
    if (!tbody) return;

    var query = this.searchQuery.toLowerCase();
    var filtered = devices;
    if (query) {
        filtered = devices.filter(function(d) {
            return (d.manufacturer || "").toLowerCase().indexOf(query) >= 0 ||
                   (d.device_name || "").toLowerCase().indexOf(query) >= 0 ||
                   (d.pan_id || "").toLowerCase().indexOf(query) >= 0 ||
                   (d.ieee_addr || "").toLowerCase().indexOf(query) >= 0;
        });
    }

    if (emptyEl) emptyEl.style.display = filtered.length ? "none" : "block";
    if (!filtered.length) { tbody.innerHTML = ""; return; }

    var html = "";
    var limit = Math.min(filtered.length, this.tableVisibleRows);
    for (var i = 0; i < limit; i++) {
        var d = filtered[i];
        var typeClass = d.device_type === "coordinator" ? "style=\"color:var(--accent-yellow)\"" :
                        d.device_type === "router" ? "style=\"color:var(--accent-blue)\"" :
                        d.device_type === "end_device" ? "style=\"color:var(--accent-green)\"" : "";
        var secIcon = d.security_enabled ? "&#x1f512;" : "";
        html += "<tr>" +
            "<td>" + esc(d.ieee_addr || "--") + "</td>" +
            "<td>" + esc(d.short_addr || "--") + "</td>" +
            "<td>" + esc(d.device_name || "--") + "</td>" +
            "<td " + typeClass + ">" + esc(d.device_type || "unknown") + "</td>" +
            "<td>" + esc(d.pan_id || "--") + "</td>" +
            "<td>" + esc(d.channel || "--") + "</td>" +
            "<td>" + esc(d.manufacturer || "--") + "</td>" +
            "<td>" + (d.rssi_dbm ? d.rssi_dbm.toFixed(0) + " dBm" : "--") + "</td>" +
            "<td>" + esc(d.lqi || "--") + "</td>" +
            "<td>" + esc(d.power_source || "--") + "</td>" +
            "<td>" + secIcon + "</td>" +
            "<td>" + esc(d.node_id || "--") + "</td>" +
            "<td>" + esc(d.timestamp ? d.timestamp.substring(11, 19) : "--") + "</td>" +
            "</tr>";
    }
    if (filtered.length > limit) {
        html += "<tr><td colspan=\"13\" style=\"text-align:center;color:var(--text-secondary);\">" +
                "..." + (filtered.length - limit) + " more devices</td></tr>";
    }
    tbody.innerHTML = html;
};

/* -- Topology view ----------------------------------------------- */

ZigbeePanel.prototype._renderTopology = function(networks) {
    var container = document.getElementById("zb-topology-container");
    if (!container) return;

    if (!networks || !networks.length) {
        container.innerHTML = "<p style='color:var(--text-secondary);text-align:center;'>No Zigbee networks discovered</p>";
        return;
    }

    var html = "";
    for (var n = 0; n < networks.length; n++) {
        var net = networks[n];
        var secBadge = net.security_enabled ? " &#x1f512;" : "";
        var profileBadge = net.stack_profile ? " <span style='color:var(--text-secondary);font-size:0.85em;'>(" + esc(net.stack_profile) + ")</span>" : "";

        html += "<div class='zb-network-card'>";
        html += "<div class='zb-net-header'>";
        html += "<span class='zb-net-pan'>PAN " + esc(net.pan_id || "?") + "</span>";
        if (net.extended_pan_id) html += " <span class='zb-net-epan' title='Extended PAN ID'>" + esc(net.extended_pan_id) + "</span>";
        html += " <span class='zb-net-ch'>Ch " + esc(net.channel || "?") + "</span>";
        html += secBadge + profileBadge;
        html += " <span class='zb-net-count'>" + (net.devices ? net.devices.length : 0) + " device" + ((net.devices && net.devices.length !== 1) ? "s" : "") + "</span>";
        html += "</div>";

        // Group devices by type
        var devs = net.devices || [];
        var coordinators = devs.filter(function(d) { return d.device_type === "coordinator"; });
        var routers = devs.filter(function(d) { return d.device_type === "router"; });
        var endDevices = devs.filter(function(d) { return d.device_type === "end_device"; });
        var unknown = devs.filter(function(d) { return d.device_type !== "coordinator" && d.device_type !== "router" && d.device_type !== "end_device"; });

        html += "<div class='zb-tree'>";
        // Coordinators
        for (var c = 0; c < coordinators.length; c++) {
            html += this._renderTopoNode(coordinators[c], "coordinator", 0);
        }
        // Routers (children of coordinator)
        for (var r = 0; r < routers.length; r++) {
            html += this._renderTopoNode(routers[r], "router", 1);
        }
        // End devices (children of routers or coordinator)
        for (var e = 0; e < endDevices.length; e++) {
            html += this._renderTopoNode(endDevices[e], "end_device", 2);
        }
        for (var u = 0; u < unknown.length; u++) {
            html += this._renderTopoNode(unknown[u], "unknown", 1);
        }
        html += "</div></div>";
    }
    container.innerHTML = html;
};

ZigbeePanel.prototype._renderTopoNode = function(d, type, indent) {
    var colors = { coordinator: "var(--accent-yellow)", router: "var(--accent-blue)", end_device: "var(--accent-green)" };
    var icons = { coordinator: "&#9733;", router: "&#9670;", end_device: "&#9679;" };
    var color = colors[type] || "var(--text-secondary)";
    var icon = icons[type] || "&#9675;";
    var pad = indent * 24;

    var rssiStr = d.rssi_dbm ? d.rssi_dbm.toFixed(0) + " dBm" : "";
    var nameStr = d.device_name ? " " + esc(d.device_name) : "";
    var mfgStr = d.manufacturer ? " <span style='color:var(--text-secondary);'>" + esc(d.manufacturer) + "</span>" : "";
    var parentStr = d.parent_addr ? " <span style='color:var(--text-secondary);font-size:0.8em;'>via " + esc(d.parent_addr) + "</span>" : "";

    return "<div class='zb-topo-node' style='padding-left:" + pad + "px;'>" +
        "<span style='color:" + color + ";'>" + icon + "</span> " +
        "<span class='zb-topo-addr'>" + esc(d.ieee_addr || d.short_addr || "?") + "</span>" +
        nameStr + mfgStr + parentStr +
        (rssiStr ? " <span class='zb-topo-rssi'>" + rssiStr + "</span>" : "") +
        "</div>";
};

/* -- Channel energy heatmap -------------------------------------- */

ZigbeePanel.prototype._renderEnergyHeatmap = function(channels) {
    var container = document.getElementById("zb-energy-container");
    if (!container) return;

    if (!channels || !channels.length) {
        container.innerHTML = "<p style='color:var(--text-secondary);text-align:center;'>No channel energy data available. Energy scanning requires bellows.</p>";
        return;
    }

    // Find min/max for color scaling
    var minRssi = 0, maxRssi = -120;
    for (var i = 0; i < channels.length; i++) {
        var r = channels[i].avg_rssi;
        if (r < minRssi) minRssi = r;
        if (r > maxRssi) maxRssi = r;
    }
    var range = maxRssi - minRssi || 1;

    var html = "<div class='zb-energy-grid'>";
    for (var ch = 11; ch <= 26; ch++) {
        var entry = null;
        for (var j = 0; j < channels.length; j++) {
            if (channels[j].channel === ch) { entry = channels[j]; break; }
        }
        var avg = entry ? entry.avg_rssi : null;
        var intensity = avg !== null ? Math.max(0, Math.min(1, (avg - minRssi) / range)) : 0;
        // Green (quiet) → Yellow → Red (noisy)
        var hue = Math.round(120 * (1 - intensity));
        var bgColor = avg !== null ? "hsl(" + hue + ",70%,30%)" : "var(--bg-tertiary)";
        var freqMhz = 2405 + (ch - 11) * 5;
        html += "<div class='zb-energy-cell' style='background:" + bgColor + ";' title='Ch " + ch + " (" + freqMhz + " MHz): " + (avg !== null ? avg.toFixed(1) + " dBm" : "no data") + "'>";
        html += "<div class='zb-energy-ch'>" + ch + "</div>";
        html += "<div class='zb-energy-val'>" + (avg !== null ? avg.toFixed(0) : "--") + "</div>";
        html += "<div class='zb-energy-freq'>" + freqMhz + "</div>";
        html += "</div>";
    }
    html += "</div>";

    // Channel distribution bar chart
    if (this.devices.length) {
        html += "<div class='zb-ch-dist-title'>Device Distribution by Channel</div>";
        html += "<div class='zb-ch-dist'>";
        var chCounts = {};
        for (var k = 0; k < this.devices.length; k++) {
            var dch = this.devices[k].channel;
            if (dch >= 11 && dch <= 26) chCounts[dch] = (chCounts[dch] || 0) + 1;
        }
        var maxCount = 1;
        for (var cc in chCounts) { if (chCounts[cc] > maxCount) maxCount = chCounts[cc]; }
        for (var ch2 = 11; ch2 <= 26; ch2++) {
            var cnt = chCounts[ch2] || 0;
            var pct = Math.round(cnt / maxCount * 100);
            html += "<div class='zb-ch-bar-wrap'>";
            html += "<div class='zb-ch-bar' style='height:" + pct + "%;'></div>";
            html += "<div class='zb-ch-label'>" + ch2 + "</div>";
            html += "<div class='zb-ch-count'>" + cnt + "</div>";
            html += "</div>";
        }
        html += "</div>";
    }

    container.innerHTML = html;
};

ZigbeePanel.prototype._renderEnergyMini = function(el, channels) {
    var html = "";
    var minR = 0, maxR = -120;
    for (var i = 0; i < channels.length; i++) {
        var r = channels[i].avg_rssi;
        if (r < minR) minR = r;
        if (r > maxR) maxR = r;
    }
    var range = maxR - minR || 1;
    for (var ch = 11; ch <= 26; ch++) {
        var entry = null;
        for (var j = 0; j < channels.length; j++) {
            if (channels[j].channel === ch) { entry = channels[j]; break; }
        }
        var avg = entry ? entry.avg_rssi : null;
        var intensity = avg !== null ? Math.max(0, Math.min(1, (avg - minR) / range)) : 0;
        var hue = Math.round(120 * (1 - intensity));
        var bg = avg !== null ? "hsl(" + hue + ",70%,35%)" : "var(--bg-tertiary)";
        html += "<span class='zb-energy-dot' style='background:" + bg + ";' title='Ch " + ch + ": " + (avg !== null ? avg.toFixed(0) + " dBm" : "--") + "'></span>";
    }
    el.innerHTML = html;
};

/* -- Type toggle ------------------------------------------------- */

ZigbeePanel.prototype._initTypeToggle = function() {
    var s = this;
    var toggle = document.getElementById("zb-type-toggle");
    if (!toggle) return;
    toggle.addEventListener("click", function(e) {
        var btn = e.target.closest("[data-zb-type]");
        if (!btn) return;
        toggle.querySelectorAll("button").forEach(function(b) { b.classList.remove("active"); });
        btn.classList.add("active");
        s.selectedDeviceType = btn.dataset.zbType;
        s._pollDevices();
    });
};

/* -- Search ------------------------------------------------------ */

ZigbeePanel.prototype._initSearch = function() {
    var s = this;
    var input = document.getElementById("zb-search");
    if (!input) return;
    var timer = null;
    input.addEventListener("input", function() {
        clearTimeout(timer);
        timer = setTimeout(function() {
            s.searchQuery = input.value.trim();
            s._renderDeviceTable(s.devices);
        }, 300);
    });
};

/* -- WebSocket --------------------------------------------------- */

ZigbeePanel.prototype._initWebSocket = function() {
    var s = this;
    var proto = location.protocol === "https:" ? "wss:" : "ws:";
    var url = proto + "//" + location.host + "/api/zigbee/ws/zigbee";
    // Credential in the sub-protocol (never the query string, which the
    // bridge refuses by default); in cookie mode the session cookie
    // authenticates the upgrade.
    var authKey = s.dashboard.apiKey || s.dashboard.sessionToken || "";
    var protocols = authKey ? ["bridge-v1", authKey] : [];

    function connect() {
        var ws = new WebSocket(url, protocols);
        ws.onmessage = function(ev) {
            try {
                var msg = JSON.parse(ev.data);
                if (msg.type === "zigbee_ingest" && s._active) {
                    s._pollDevices();
                    s._pollStats();
                    s._pollTopology();
                }
            } catch(e) {}
        };
        ws.onclose = function() {
            setTimeout(connect, 5000);
        };
        ws.onerror = function() {};
    }
    connect();
};

/* -- Init on dashboard ready ------------------------------------- */

/* Zigbee panel is initialized by BridgeDashboard boot sequence in dashboard.js */
