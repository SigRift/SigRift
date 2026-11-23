/**
 * WiFi SIGINT Panel — Network Discovery, Channel Heatmap, Client Tracking
 *
 * Follows the DetectionDashboard pattern. Polls WiFi API endpoints and
 * renders network table, channel utilization heatmap, client list, and
 * signal strength timeline using ChartUtils.
 *
 * Security: All dynamic content is HTML-escaped via esc().
 */
"use strict";

/* A measured value with its unit, escaped once; "--" when the radio sent none. */
function _wifiMeasure(value, unit) {
    if (value == null || value === "") return "--";
    return esc(value) + " " + unit;
}

/* A key that names the same anomaly across polls, or "" when it has none. */
function _wifiTimelineKey(a) {
    if (a.id != null) return "id:" + a.id;
    if (a.anomaly_id != null) return "aid:" + a.anomaly_id;
    if (a.bssid || a.timestamp) return "k:" + (a.bssid || "") + "|" + (a.anomaly_type || "") + "|" + (a.timestamp || "");
    return "";
}

function WifiPanel(dashboard) {
    this.dashboard = dashboard;
    this.networks = [];
    this.channels = [];
    this.stats = {};
    this.wifiAnomalies = [];
    this.selectedBssid = null;
    this.selectedBand = "all";
    this.sortCol = "signal";
    this.sortAsc = false;
    this.pollTimers = {};
    this.tableCollapsed = true;
    this.tableVisibleRows = 20;
    this.groupByKey = "";
    this.netGroupKey = "";
    this.whitelistedBssids = {};
    this.showFilter = "all";
    this.filterKey = "";
    this.filterVal = "";
    this._selectedWifiIds = {};  // map of anomaly id -> true for bulk selection

    this._active = false;

    this._initBandToggle();
    this._initTableSort();
    this._initNetGrouping();
    this._initShowFilter();
    this._initAnomalyControls();
    this._initWifiBulkSelection();
    this._initWebSocket();
}

/* -- Polling ---------------------------------------------------- */

WifiPanel.prototype._loadWhitelist = function() {
    var s = this;
    return s.dashboard.apiFetch("/api/admin/wifi-whitelist")
        .then(function(d) {
            var wl = d.whitelist || [];
            s.whitelistedBssids = {};
            for (var i = 0; i < wl.length; i++) {
                s.whitelistedBssids[wl[i].bssid.toUpperCase()] = wl[i].id;
            }
        })
        .catch(function() {});
};

WifiPanel.prototype._whitelistAP = function(bssid, ssid) {
    var s = this;
    s.dashboard.apiFetch("/api/admin/wifi-whitelist", {
        method: "POST",
        body: { bssid: bssid, ssid: ssid || "" }
    }).then(function() {
        showToast("Whitelisted " + (ssid || bssid), "success");
        // Redraw once the reloaded whitelist is in, so the AP shows as
        // authorized at once (a failed reload is swallowed and redraws as is).
        s._loadWhitelist().then(function() { s._renderNetworkTable(s.networks); });
    }).catch(function(e) {
        var msg = (e && e.detail) || (e && e.message) || "Failed";
        showToast("Whitelist failed: " + msg, "error");
    });
};

WifiPanel.prototype._stopPolling = function() {
    for (var k in this.pollTimers) {
        if (this.pollTimers[k]) clearInterval(this.pollTimers[k]);
    }
    this.pollTimers = {};
};

WifiPanel.prototype.activate = function() {
    if (this._active) return;
    this._active = true;
    this._startPolling();
};

WifiPanel.prototype.deactivate = function() {
    this._active = false;
    this._stopPolling();
};

WifiPanel.prototype._startPolling = function() {
    var s = this;
    s._stopPolling();
    s._loadWhitelist();
    s._pollNetworks();
    setTimeout(function() { if (s._active) s._pollChannels(); }, 500);
    setTimeout(function() { if (s._active) s._pollStats(); }, 1000);
    setTimeout(function() { if (s._active) s._pollWifiAnomalies(); }, 1500);
    s.pollTimers.net = setInterval(function() { if (isPageActive() && s._active) s._pollNetworks(); }, 8000);
    s.pollTimers.ch = setInterval(function() { if (isPageActive() && s._active) s._pollChannels(); }, 15000);
    s.pollTimers.st = setInterval(function() { if (isPageActive() && s._active) s._pollStats(); }, 20000);
    s.pollTimers.anom = setInterval(function() { if (isPageActive() && s._active) s._pollWifiAnomalies(); }, 8000);
};

WifiPanel.prototype._pollNetworks = function() {
    var s = this;
    var tb = document.getElementById("wifi-network-tbody");
    if (tb && !tb.innerHTML) {
        tb.innerHTML = '<tr><td colspan="9"><div class="loading-container"><div class="loading-spinner"></div>Loading WiFi networks...</div></td></tr>';
    }
    var params = "?limit=100";
    if (s.selectedBand !== "all") params += "&band=" + encodeURIComponent(s.selectedBand);
    s.dashboard.apiFetch("/api/wifi/networks" + params)
        .then(function(d) {
            s.networks = d.networks || [];
            s._renderNetworkTable(s.networks);
            setText("wifi-net-count-badge", s.networks.length);
            clearFetchError("wifi-networks");
        })
        .catch(function(e) {
            trackFetchError("wifi-networks", e);
            var tb = document.getElementById("wifi-network-tbody");
            if (tb) {
                tb.innerHTML = '<tr><td colspan="9"><div class="error-state"><span class="error-icon">⚠</span><p>Failed to load WiFi networks</p><button class="retry-btn">Retry</button></div></td></tr>';
                var rb = tb.querySelector(".retry-btn");
                if (rb) rb.addEventListener("click", function() { if (window.dashboard && window.dashboard.wifiPanel) window.dashboard.wifiPanel._pollNetworks(); });
            }
        });
};

WifiPanel.prototype._pollChannels = function() {
    var s = this;
    var cv = document.getElementById("wifi-channel-canvas");
    if (cv) {
        var ctx = cv.getContext("2d");
        var bgColor = getComputedStyle(document.documentElement).getPropertyValue("--bg-primary").trim() || "#0d1117";
        ctx.fillStyle = bgColor;
        ctx.fillRect(0, 0, cv.width, cv.height);
        ctx.fillStyle = "#8b949e";
        ctx.font = "12px sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("Loading channel data...", cv.width / 2, cv.height / 2);
    }
    if (s.selectedBand === "all") {
        // Fetch each band independently so one failure doesn't block all
        var ok = function(d) { return d.channels || []; };
        var fail = function() { return []; };
        Promise.all([
            s.dashboard.apiFetch("/api/wifi/channels?band=2.4GHz").then(ok, fail),
            s.dashboard.apiFetch("/api/wifi/channels?band=5GHz").then(ok, fail),
            s.dashboard.apiFetch("/api/wifi/channels?band=6GHz").then(ok, fail)
        ]).then(function(results) {
            s.channels = results[0].concat(results[1]).concat(results[2]);
            s._renderChannelHeatmap(s.channels);
        });
    } else {
        s.dashboard.apiFetch("/api/wifi/channels?band=" + encodeURIComponent(s.selectedBand))
            .then(function(d) {
                s.channels = d.channels || [];
                s._renderChannelHeatmap(s.channels);
            })
            .catch(function() { s._renderChannelHeatmap([]); });
    }
};

WifiPanel.prototype._pollStats = function() {
    var s = this;
    s.dashboard.apiFetch("/api/wifi/stats")
        .then(function(d) { clearFetchError("wifi-stats"); s._renderStats(d); })
        .catch(function(e) {
            trackFetchError("wifi-stats", e);
            if (typeof setLoadingState === "function") {
                setLoadingState("wifi-stats-bar", false, "Failed to load WiFi stats", "window.dashboard.wifiPanel._pollStats.bind(window.dashboard.wifiPanel)");
            }
        });
};

/* -- Band Toggle ------------------------------------------------ */

WifiPanel.prototype._initBandToggle = function() {
    var s = this;
    var wrap = document.getElementById("wifi-band-toggle");
    if (!wrap) return;
    wrap.querySelectorAll("[data-wifi-band]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            wrap.querySelectorAll("[data-wifi-band]").forEach(function(b) { b.classList.remove("active"); });
            btn.classList.add("active");
            s.selectedBand = btn.getAttribute("data-wifi-band");
            s._pollNetworks();
            s._pollChannels();
        });
    });
};

/* -- Table Sorting ---------------------------------------------- */

WifiPanel.prototype._initTableSort = function() {
    var s = this;
    var sortSel = document.getElementById("wifi-net-sort-select");
    var dirBtn = document.getElementById("wifi-net-sort-dir");

    // Sync dropdown with initial state
    if (sortSel) sortSel.value = s.sortCol;

    function syncDirBtn() {
        if (dirBtn) {
            dirBtn.innerHTML = s.sortAsc ? "&#9650;" : "&#9660;";
            dirBtn.title = s.sortAsc ? "Ascending" : "Descending";
        }
    }
    syncDirBtn();

    if (sortSel) {
        sortSel.addEventListener("change", function() {
            s.sortCol = this.value;
            s._renderNetworkTable(s.networks);
        });
    }
    if (dirBtn) {
        dirBtn.addEventListener("click", function() {
            s.sortAsc = !s.sortAsc;
            syncDirBtn();
            s._renderNetworkTable(s.networks);
        });
    }

    // Column header clicks still work
    var ths = document.querySelectorAll("#wifi-network-table th[data-sort]");
    ths.forEach(function(th) {
        th.style.cursor = "pointer";
        th.addEventListener("click", function() {
            var col = th.getAttribute("data-sort");
            if (s.sortCol === col) { s.sortAsc = !s.sortAsc; }
            else { s.sortCol = col; s.sortAsc = true; }
            if (sortSel) sortSel.value = s.sortCol;
            syncDirBtn();
            s._renderNetworkTable(s.networks);
        });
    });
};

WifiPanel.prototype._initNetGrouping = function() {
    var s = this;
    var sel = document.getElementById("wifi-net-group-select");
    if (sel) {
        sel.addEventListener("change", function() {
            s.netGroupKey = this.value;
            s._collapsedNetGroups = {};
            s._renderNetworkTable(s.networks);
        });
    }
};

/* -- Show Filter (Authorized / Unauthorized) -------------------- */

WifiPanel.prototype._initShowFilter = function() {
    var s = this;
    var sel = document.getElementById("wifi-net-show-select");
    if (sel) {
        sel.addEventListener("change", function() {
            s.showFilter = this.value;
            s._renderNetworkTable(s.networks);
        });
    }
};

/* -- Network Table ---------------------------------------------- */

WifiPanel.prototype._renderNetworkTable = function(networks) {
    var s = this;
    var tb = document.getElementById("wifi-network-tbody");
    var em = document.getElementById("wifi-network-empty");
    if (!tb) return;
    if (!networks || !networks.length) {
        tb.innerHTML = "";
        if (em) em.style.display = "";
        return;
    }
    if (em) em.style.display = "none";

    // Filter by authorization status
    if (s.showFilter === "authorized") {
        networks = networks.filter(function(n) {
            return s.whitelistedBssids[(n.bssid || "").toUpperCase()] != null;
        });
    } else if (s.showFilter === "unauthorized") {
        networks = networks.filter(function(n) {
            return s.whitelistedBssids[(n.bssid || "").toUpperCase()] == null;
        });
    }

    if (!networks.length) {
        tb.innerHTML = "<tr><td colspan=\"10\" class=\"empty-state\">No " + esc(s.showFilter) + " networks</td></tr>";
        return;
    }

    // Sort
    var col = s.sortCol, asc = s.sortAsc;
    var sorted = networks.slice().sort(function(a, b) {
        var va, vb;
        switch (col) {
            case "ssid": va = (a.ssid || "").toLowerCase(); vb = (b.ssid || "").toLowerCase(); break;
            case "bssid": va = a.bssid || ""; vb = b.bssid || ""; break;
            case "vendor": va = (a.vendor || "").toLowerCase(); vb = (b.vendor || "").toLowerCase(); break;
            case "channel": va = a.channel || 0; vb = b.channel || 0; break;
            case "band": va = a.band || ""; vb = b.band || ""; break;
            case "security": va = a.security || ""; vb = b.security || ""; break;
            case "signal": va = a.avg_signal_dbm || -100; vb = b.avg_signal_dbm || -100; break;
            case "clients": va = a.client_count || 0; vb = b.client_count || 0; break;
            case "last_seen": va = a.last_seen || ""; vb = b.last_seen || ""; break;
            default: va = 0; vb = 0;
        }
        if (va < vb) return asc ? -1 : 1;
        if (va > vb) return asc ? 1 : -1;
        return 0;
    });

    var h = "";
    var colSpan = 10;

    // Helper: build a single network row HTML
    function netRow(n) {
        var sigCls = (n.avg_signal_dbm || -100) > -50 ? "accent-green"
            : (n.avg_signal_dbm || -100) > -70 ? "accent-yellow" : "accent-red";
        var isWl = s.whitelistedBssids[(n.bssid || "").toUpperCase()] != null;
        var actionHtml = isWl
            ? "<span class=\"admin-badge\" style=\"font-size:10px;\">Authorized</span>"
            : "<button class=\"btn btn-sm\" data-wl-bssid=\"" + esc(n.bssid) + "\" data-wl-ssid=\"" + esc(n.ssid || "") + "\">Whitelist</button>";
        return "<tr data-bssid=\"" + esc(n.bssid) + "\" class=\"wifi-net-row\">"
            + "<td>" + esc(n.ssid || "(hidden)") + "</td>"
            + "<td><code>" + esc(n.bssid) + "</code></td>"
            + "<td>" + esc(n.vendor || "") + "</td>"
            + "<td>" + esc(n.channel) + "</td>"
            + "<td>" + esc(n.band) + "</td>"
            + "<td>" + esc(n.security || "Unknown") + "</td>"
            + "<td style=\"color:var(--" + sigCls + ")\">" + _wifiMeasure(n.avg_signal_dbm, "dBm") + "</td>"
            + "<td>" + esc(n.client_count) + "</td>"
            + "<td>" + fmtTime(n.last_seen) + "</td>"
            + "<td>" + actionHtml + "</td>"
            + "</tr>";
    }

    if (s.netGroupKey) {
        // Initialize collapsed groups tracker
        if (!s._collapsedNetGroups) s._collapsedNetGroups = {};

        // Group networks by selected key
        var groups = {};
        var groupOrder = [];
        for (var gi = 0; gi < sorted.length; gi++) {
            var gn = sorted[gi];
            var gv;
            switch (s.netGroupKey) {
                case "ssid": gv = gn.ssid || "(hidden)"; break;
                case "vendor": gv = gn.vendor || "Unknown"; break;
                case "security": gv = gn.security || "Unknown"; break;
                case "band": gv = gn.band || "Unknown"; break;
                case "channel": gv = String(gn.channel || "?"); break;
                default: gv = "Other";
            }
            if (!groups[gv]) { groups[gv] = []; groupOrder.push(gv); }
            groups[gv].push(gn);
        }
        // Sort groups: largest first
        groupOrder.sort(function(a, b) { return groups[b].length - groups[a].length; });

        var keyLabel = s.netGroupKey.charAt(0).toUpperCase() + s.netGroupKey.slice(1);
        for (var gk = 0; gk < groupOrder.length; gk++) {
            var gLabel = groupOrder[gk];
            var gItems = groups[gLabel];
            var isCollapsed = !!s._collapsedNetGroups[gLabel];
            var arrow = isCollapsed ? "&#9654;" : "&#9660;";
            h += "<tr class=\"wifi-net-group-header\" data-net-group=\"" + esc(gLabel) + "\" style=\"cursor:pointer;background:var(--bg-secondary);\">"
                + "<td colspan=\"" + colSpan + "\" style=\"padding:8px 12px;font-weight:600;border-bottom:1px solid var(--border-primary);\">"
                + "<span style=\"display:inline-block;width:16px;font-size:10px;\">" + arrow + "</span> "
                + esc(keyLabel) + ": " + esc(gLabel)
                + " <span style=\"color:var(--text-secondary);font-weight:normal;\">(" + gItems.length + ")</span>"
                + "</td></tr>";
            if (!isCollapsed) {
                for (var ri = 0; ri < gItems.length; ri++) {
                    h += netRow(gItems[ri]);
                }
            }
        }
    } else {
        var showCount = s.tableCollapsed ? s.tableVisibleRows : sorted.length;
        var displayRows = sorted.slice(0, showCount);
        for (var i = 0; i < displayRows.length; i++) {
            h += netRow(displayRows[i]);
        }
    }
    tb.innerHTML = h;

    // Show all / collapse toggle button (flat mode only)
    var toggleWrap = document.getElementById("wifi-table-toggle");
    if (!toggleWrap) {
        toggleWrap = document.createElement("div");
        toggleWrap.id = "wifi-table-toggle";
        toggleWrap.style.textAlign = "center";
        toggleWrap.style.padding = "6px 0";
        var tableEl = document.getElementById("wifi-network-table");
        if (tableEl && tableEl.parentNode) tableEl.parentNode.appendChild(toggleWrap);
    }
    if (!s.netGroupKey && sorted.length > s.tableVisibleRows) {
        var remaining = sorted.length - s.tableVisibleRows;
        toggleWrap.innerHTML = s.tableCollapsed
            ? "<button class=\"btn btn-sm btn-secondary\" id=\"wifi-table-expand\">Show all " + sorted.length + " networks (" + remaining + " more)</button>"
            : "<button class=\"btn btn-sm btn-secondary\" id=\"wifi-table-expand\">Collapse to " + s.tableVisibleRows + "</button>";
        toggleWrap.style.display = "";
        var expandBtn = document.getElementById("wifi-table-expand");
        if (expandBtn) {
            expandBtn.addEventListener("click", function() {
                s.tableCollapsed = !s.tableCollapsed;
                s._renderNetworkTable(s.networks);
            });
        }
    } else {
        toggleWrap.style.display = "none";
    }

    // Apply scrollable max-height when many rows visible
    var tableWrap = tb.closest(".table-wrap");
    if (tableWrap) {
        var visibleRows = tb.querySelectorAll(".wifi-net-row").length;
        if (visibleRows > s.tableVisibleRows) {
            tableWrap.style.maxHeight = "600px";
            tableWrap.style.overflowY = "auto";
        } else {
            tableWrap.style.maxHeight = "";
            tableWrap.style.overflowY = "";
        }
    }

    // Group header click to collapse/expand
    tb.querySelectorAll(".wifi-net-group-header").forEach(function(hdr) {
        hdr.addEventListener("click", function() {
            var gl = this.getAttribute("data-net-group");
            s._collapsedNetGroups[gl] = !s._collapsedNetGroups[gl];
            s._renderNetworkTable(s.networks);
        });
    });

    // Row click to select network
    tb.querySelectorAll(".wifi-net-row").forEach(function(row) {
        row.addEventListener("click", function(e) {
            if (e.target.closest("button")) return;
            var bssid = this.getAttribute("data-bssid");
            s.selectedBssid = bssid;
            s._renderClientList(bssid);
            s._renderSignalTimeline(bssid);
            tb.querySelectorAll(".wifi-net-row").forEach(function(r) { r.style.background = ""; });
            this.style.background = "var(--bg-hover)";
        });
    });

    // Whitelist buttons
    tb.querySelectorAll("[data-wl-bssid]").forEach(function(btn) {
        btn.addEventListener("click", function(e) {
            e.stopPropagation();
            var bssid = this.getAttribute("data-wl-bssid");
            var ssid = this.getAttribute("data-wl-ssid");
            if (confirm("Whitelist AP " + bssid + (ssid ? " (" + ssid + ")" : "") + "?\n\nThis will reduce anomaly sensitivity for this access point.")) {
                s._whitelistAP(bssid, ssid);
            }
        });
    });
};

/* -- Channel Heatmap -------------------------------------------- */

WifiPanel.prototype._renderChannelHeatmap = function(channels) {
    var cv = document.getElementById("wifi-channel-canvas");
    if (!cv) return;

    // Responsive width
    if (typeof ChartUtils !== "undefined" && ChartUtils.resizeCanvas) {
        ChartUtils.resizeCanvas(cv);
    }

    var ctx = cv.getContext("2d");
    var w = cv.width, h = cv.height;

    // Clear
    var bgColor = getComputedStyle(document.documentElement).getPropertyValue("--bg-primary").trim() || "#0d1117";
    ctx.fillStyle = bgColor;
    ctx.fillRect(0, 0, w, h);

    if (!channels || !channels.length) {
        ctx.fillStyle = "#8b949e";
        ctx.font = "12px sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("No channel data", w / 2, h / 2);
        return;
    }

    // Sort channels: 2.4 GHz first (by channel), then 5 GHz (by channel), then 6 GHz
    var bandOrder = { "2.4GHz": 0, "5GHz": 1, "6GHz": 2, "unknown": 3 };
    channels = channels.slice().sort(function(a, b) {
        var ba = bandOrder[a.band] != null ? bandOrder[a.band] : 3;
        var bb = bandOrder[b.band] != null ? bandOrder[b.band] : 3;
        if (ba !== bb) return ba - bb;
        return (a.channel || 0) - (b.channel || 0);
    });

    var maxFrames = 1;
    for (var i = 0; i < channels.length; i++) {
        if (channels[i].frame_count > maxFrames) maxFrames = channels[i].frame_count;
    }

    // Detect band transitions for separator lines
    var bandBreaks = [];
    for (var bi = 1; bi < channels.length; bi++) {
        if (channels[bi].band !== channels[bi - 1].band) bandBreaks.push(bi);
    }

    var padL = 6, padR = 6, padTop = 16, padBot = 18;
    var nBars = channels.length;
    var barW = Math.max(14, Math.min(36, (w - padL - padR) / nBars));
    var totalBarsW = barW * nBars;
    var startX = padL + Math.max(0, (w - padL - padR - totalBarsW) / 2);
    var maxBarH = h - padTop - padBot;

    ctx.textAlign = "center";

    for (var j = 0; j < nBars; j++) {
        var ch = channels[j];
        var x = startX + j * barW;
        var barH = Math.max(1, (ch.frame_count / maxFrames) * maxBarH);
        var y = h - padBot - barH;

        // Color by utilization percentage
        var pct = ch.utilization_pct || 0;
        var cr = Math.min(255, Math.floor(pct * 5.1));
        var cg = Math.min(255, Math.floor((100 - pct) * 2.55));
        ctx.fillStyle = "rgb(" + cr + "," + cg + ",80)";
        ctx.fillRect(x + 1, y, barW - 2, barH);

        // Channel label
        ctx.fillStyle = "#8b949e";
        ctx.font = nBars > 20 ? "8px monospace" : "10px monospace";
        ctx.fillText(ch.channel, x + barW / 2, h - 4);

        // Network count on top of bar
        if (ch.network_count > 0 && barH > 8) {
            ctx.fillStyle = "#e6edf3";
            ctx.font = nBars > 25 ? "7px monospace" : "9px monospace";
            ctx.fillText(ch.network_count, x + barW / 2, y - 3);
        }
    }

    // Band separator lines and labels
    ctx.strokeStyle = "#484f58";
    ctx.lineWidth = 1;
    ctx.setLineDash([3, 3]);
    ctx.font = "9px monospace";
    ctx.fillStyle = "#8b949e";

    for (var si = 0; si < bandBreaks.length; si++) {
        var sepX = startX + bandBreaks[si] * barW;
        ctx.beginPath();
        ctx.moveTo(sepX, padTop - 10);
        ctx.lineTo(sepX, h - padBot);
        ctx.stroke();
    }
    ctx.setLineDash([]);

    // Band labels at top
    var bandRanges = [];
    var prevIdx = 0;
    for (var ri = 0; ri < bandBreaks.length; ri++) {
        bandRanges.push({ band: channels[prevIdx].band, start: prevIdx, end: bandBreaks[ri] });
        prevIdx = bandBreaks[ri];
    }
    bandRanges.push({ band: channels[prevIdx].band, start: prevIdx, end: nBars });

    ctx.fillStyle = "#58a6ff";
    ctx.font = "9px monospace";
    ctx.textAlign = "center";
    for (var li = 0; li < bandRanges.length; li++) {
        var range = bandRanges[li];
        var labelX = startX + (range.start + range.end) / 2 * barW;
        ctx.fillText(range.band, labelX, 10);
    }
};

/* -- Signal Timeline -------------------------------------------- */

WifiPanel.prototype._renderSignalTimeline = function(bssid) {
    var s = this;
    s.dashboard.apiFetch("/api/wifi/timeline?bssid=" + encodeURIComponent(bssid) + "&hours=24")
        .then(function(d) {
            var cv = document.getElementById("wifi-signal-canvas");
            if (!cv || !d.timeline || !d.timeline.length) return;
            var values = d.timeline.map(function(t) { return t.avg_signal_dbm; });
            if (typeof ChartUtils !== "undefined" && ChartUtils.drawSparkline) {
                var ctx = cv.getContext("2d");
                ChartUtils.drawSparkline(ctx, cv, values, "#58a6ff", "rgba(88,166,255,0.15)");
            }
        })
        .catch(function(e) {
            trackFetchError("wifi-signal", e);
            var cv = document.getElementById("wifi-signal-canvas");
            if (cv) {
                var ctx = cv.getContext("2d");
                ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--bg-primary").trim() || "#0d1117";
                ctx.fillRect(0, 0, cv.width, cv.height);
                ctx.fillStyle = "#f85149";
                ctx.font = "12px sans-serif";
                ctx.textAlign = "center";
                ctx.fillText("Failed to load signal timeline", cv.width / 2, cv.height / 2);
            }
        });
};

/* -- Client List ------------------------------------------------ */

WifiPanel.prototype._renderClientList = function(bssid) {
    var s = this;
    s.dashboard.apiFetch("/api/wifi/clients?bssid=" + encodeURIComponent(bssid))
        .then(function(d) {
            var wrap = document.getElementById("wifi-client-list");
            var em = document.getElementById("wifi-client-empty");
            if (!wrap) return;
            var clients = d.clients || [];
            if (!clients.length) {
                wrap.innerHTML = "";
                if (em) em.style.display = "";
                return;
            }
            if (em) em.style.display = "none";

            var h = "<table class=\"data-table\"><thead><tr>"
                + "<th>Client MAC</th><th>SSID</th><th>Avg Signal</th>"
                + "<th>Data Rate</th><th>Frames</th><th>Last Seen</th></tr></thead><tbody>";
            for (var i = 0; i < clients.length; i++) {
                var c = clients[i];
                h += "<tr><td><code>" + esc(c.client_mac) + "</code></td>"
                    + "<td>" + esc(c.ssid || "--") + "</td>"
                    + "<td>" + _wifiMeasure(c.avg_signal_dbm, "dBm") + "</td>"
                    + "<td>" + _wifiMeasure(c.avg_data_rate, "Mbps") + "</td>"
                    + "<td>" + esc(c.frame_count) + "</td>"
                    + "<td>" + fmtTime(c.last_seen) + "</td></tr>";
            }
            h += "</tbody></table>";
            wrap.innerHTML = h;
        })
        .catch(function(e) {
            trackFetchError("wifi-clients", e);
            var wrap = document.getElementById("wifi-client-list");
            if (wrap) {
                wrap.innerHTML = '<div class="error-state"><span class="error-icon">⚠</span><p>Failed to load client data</p><button class="retry-btn">Retry</button></div>';
                var rb = wrap.querySelector(".retry-btn");
                if (rb) rb.addEventListener("click", function() { if (window.dashboard && window.dashboard.wifiPanel) window.dashboard.wifiPanel._renderClientList(bssid); });
            }
        });
};

/* -- Stats Bar -------------------------------------------------- */

WifiPanel.prototype._renderStats = function(stats) {
    var networks = stats.total_networks != null ? stats.total_networks : "--";
    var clients = stats.total_clients != null ? stats.total_clients : "--";
    setText("wifi-stat-networks", networks);
    setText("wifi-stat-clients", clients);
    setText("wifi-stat-channel", stats.busiest_channel || "--");

    var bd = stats.band_breakdown || {};
    var g24 = bd["2.4GHz"] ? bd["2.4GHz"].network_count : 0;
    var g5 = bd["5GHz"] ? bd["5GHz"].network_count : 0;
    setText("wifi-stat-24g", g24);
    setText("wifi-stat-5g", g5);

    // Update summary tab WiFi stats
    setText("sum-wifi-networks", networks);
    setText("sum-wifi-clients", clients);

    // Share WiFi node IDs with dashboard for node badges
    if (stats.wifi_node_ids) {
        this.dashboard.wifiNodeIds = stats.wifi_node_ids;
    }
};

/* -- WiFi Anomaly Grouping / Filtering Controls -------------------- */

WifiPanel.prototype._initAnomalyControls = function() {
    var s = this;

    // Group-by dropdown
    var groupSel = document.getElementById("wifi-anomaly-group-select");
    if (groupSel) {
        groupSel.addEventListener("change", function() {
            s.groupByKey = this.value;
            s._renderWifiAnomalyQueue();
        });
    }

    // Filter key dropdown — populates value dropdown on change
    var filterKeySel = document.getElementById("wifi-anomaly-filter-key");
    var filterValSel = document.getElementById("wifi-anomaly-filter-val");
    if (filterKeySel && filterValSel) {
        filterKeySel.addEventListener("change", function() {
            s.filterKey = this.value;
            s.filterVal = "";
            if (!s.filterKey) {
                filterValSel.style.display = "none";
                s._renderWifiAnomalyQueue();
                return;
            }
            // Build unique values from current anomalies
            var vals = s._getUniqueFilterValues(s.filterKey);
            var h = "<option value=\"\">All</option>";
            for (var i = 0; i < vals.length; i++) {
                h += "<option value=\"" + esc(vals[i]) + "\">" + esc(vals[i]) + "</option>";
            }
            filterValSel.innerHTML = h;
            filterValSel.style.display = "";
            s._renderWifiAnomalyQueue();
        });
        filterValSel.addEventListener("change", function() {
            s.filterVal = this.value;
            s._renderWifiAnomalyQueue();
        });
    }

    // Re-evaluate All button
    var reevalBtn = document.getElementById("wifi-reeval-all-btn");
    if (reevalBtn) {
        reevalBtn.addEventListener("click", function() {
            s._reevaluateAll();
        });
    }

    // Dismiss Resolved button
    var dismissResBtn = document.getElementById("wifi-dismiss-resolved-btn");
    if (dismissResBtn) {
        dismissResBtn.addEventListener("click", function() {
            s._dismissResolved();
        });
    }
    var purgeBtn = document.getElementById("wifi-reeval-dismiss-all-btn");
    if (purgeBtn) {
        purgeBtn.addEventListener("click", function() {
            s._reevalDismissAll();
        });
    }
};

WifiPanel.prototype._getUniqueFilterValues = function(key) {
    var vals = {};
    for (var i = 0; i < this.wifiAnomalies.length; i++) {
        var a = this.wifiAnomalies[i];
        if (key === "attack") {
            // Collect all active dimensions (score > 0) across all anomalies
            var dims = a.dimensions;
            if (dims && typeof dims === "object") {
                var dk = Object.keys(dims);
                for (var j = 0; j < dk.length; j++) {
                    if (dims[dk[j]] > 0) vals[dk[j]] = true;
                }
            }
        } else {
            var v = this._getAnomalyField(a, key);
            if (v !== "" && v != null) vals[v] = true;
        }
    }
    return Object.keys(vals).sort();
};

WifiPanel.prototype._getAnomalyField = function(a, key) {
    if (key === "attack") {
        // Use server-provided attack_type label if available
        if (a.attack_type) return a.attack_type;
        var dims = a.dimensions;
        if (!dims || typeof dims !== "object") return "";
        var best = "", bestV = 0;
        var dk = Object.keys(dims);
        for (var i = 0; i < dk.length; i++) {
            if (dims[dk[i]] > bestV) { bestV = dims[dk[i]]; best = dk[i]; }
        }
        return best;
    }
    if (key === "priority") {
        var sc = a.anomaly_score || 0;
        return sc >= 0.7 ? "critical" : sc >= 0.5 ? "anomalous" : sc >= 0.3 ? "interesting" : "normal";
    }
    return String(a[key] || "");
};

WifiPanel.prototype._matchesFilter = function(a, key, val) {
    if (!key || !val) return true;
    if (key === "attack") {
        // Match any anomaly where this dimension is active (score > 0)
        var dims = a.dimensions;
        if (!dims || typeof dims !== "object") return false;
        return (dims[val] || 0) > 0;
    }
    return this._getAnomalyField(a, key) === val;
};

/* -- WiFi Anomalies --------------------------------------------- */

WifiPanel.prototype._pollWifiAnomalies = function() {
    var s = this;
    var c = document.getElementById("wifi-anomaly-queue");
    if (c && !c.innerHTML) {
        c.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div>Loading WiFi anomalies...</div>';
    }
    s.dashboard.apiFetch("/api/wifi/anomalies?min_score=0.3&limit=50")
        .then(function(d) {
            s.wifiAnomalies = d.anomalies || [];
            s.wifiAnomalyTotal = d.total != null ? d.total : s.wifiAnomalies.length;
            s.reevalSummary = null;
            s._updateReevalSummary(null);
            s._renderWifiAnomalyQueue();
            var badge = s.wifiAnomalyTotal > s.wifiAnomalies.length
                ? s.wifiAnomalies.length + " / " + s.wifiAnomalyTotal
                : String(s.wifiAnomalyTotal);
            setText("wifi-anomaly-count-badge", badge);
            setText("sum-wifi-anomalies", s.wifiAnomalyTotal);
            clearFetchError("wifi-anomalies");
        })
        .catch(function(e) {
            trackFetchError("wifi-anomalies", e);
            var c = document.getElementById("wifi-anomaly-queue");
            if (c) {
                c.innerHTML = '<div class="error-state"><span class="error-icon">⚠</span><p>Failed to load WiFi anomalies</p><button class="retry-btn">Retry</button></div>';
                var rb = c.querySelector(".retry-btn");
                if (rb) rb.addEventListener("click", function() { if (window.dashboard && window.dashboard.wifiPanel) window.dashboard.wifiPanel._pollWifiAnomalies(); });
            }
        });
};

WifiPanel.prototype._reevaluateAll = function() {
    var s = this;
    var btn = document.getElementById("wifi-reeval-all-btn");
    if (btn) { btn.disabled = true; btn.textContent = "Evaluating..."; }

    s.dashboard.apiFetch("/api/wifi/anomalies?min_score=0.3&limit=50&reevaluate=true")
        .then(function(d) {
            s.wifiAnomalies = d.anomalies || [];
            s.wifiAnomalyTotal = d.total != null ? d.total : s.wifiAnomalies.length;
            s.reevalSummary = d.reeval_summary || null;
            s._updateReevalSummary(d.reeval_summary);
            // Sort: still-anomalous first, resolved last
            s.wifiAnomalies.sort(function(a, b) {
                var aRes = a.reeval && !a.reeval.still_anomalous ? 1 : 0;
                var bRes = b.reeval && !b.reeval.still_anomalous ? 1 : 0;
                if (aRes !== bRes) return aRes - bRes;
                // Within same group, sort by score descending
                return (b.anomaly_score || 0) - (a.anomaly_score || 0);
            });
            s._renderWifiAnomalyQueue();
            var badge = s.wifiAnomalyTotal > s.wifiAnomalies.length
                ? s.wifiAnomalies.length + " / " + s.wifiAnomalyTotal
                : String(s.wifiAnomalyTotal);
            setText("wifi-anomaly-count-badge", badge);
            clearFetchError("wifi-anomalies");
            if (btn) { btn.disabled = false; btn.textContent = "Re-evaluate All"; }
        })
        .catch(function(e) {
            trackFetchError("wifi-anomalies", e);
            if (btn) { btn.disabled = false; btn.textContent = "Re-evaluate All"; }
            showToast("Re-evaluation failed", "error");
        });
};

WifiPanel.prototype._updateReevalSummary = function(summary) {
    var bar = document.getElementById("wifi-reeval-summary");
    var dismissBtn = document.getElementById("wifi-dismiss-resolved-btn");
    if (!bar) return;
    if (!summary) {
        bar.style.display = "none";
        if (dismissBtn) dismissBtn.style.display = "none";
        return;
    }
    var h = "<span class=\"reeval-badge still-anomalous\">" + esc(summary.still_anomalous) + " still anomalous</span>"
        + "<span class=\"reeval-badge now-normal\">" + esc(summary.resolved) + " resolved</span>";
    bar.innerHTML = h;
    bar.style.display = "";
    if (dismissBtn) {
        dismissBtn.style.display = summary.resolved > 0 ? "" : "none";
    }
};

WifiPanel.prototype._dismissResolved = function() {
    var s = this;
    // Collect IDs of anomalies that re-evaluated as no longer anomalous
    var resolvedIds = [];
    for (var i = 0; i < s.wifiAnomalies.length; i++) {
        var a = s.wifiAnomalies[i];
        if (a.reeval && !a.reeval.still_anomalous && a.id) {
            resolvedIds.push(a.id);
        }
    }
    if (!resolvedIds.length) {
        showToast("No resolved anomalies to dismiss", "info");
        return;
    }
    if (!confirm("Dismiss " + resolvedIds.length + " resolved anomalies?")) return;
    s.dashboard.apiFetch("/api/wifi/anomalies/bulk/dismiss", {
        method: "PUT",
        body: { ids: resolvedIds },
    }).then(function() {
        showToast("Dismissed " + resolvedIds.length + " resolved anomalies", "success");
        // Re-evaluate the next batch so user sees updated state
        s._reevaluateAll();
    }).catch(function(e) {
        var msg = e && e.detail ? e.detail : "Bulk dismiss failed";
        showToast(msg, "error");
    });
};

WifiPanel.prototype._reevalDismissAll = function() {
    var s = this;
    var total = s.wifiAnomalyTotal || s.wifiAnomalies.length;
    if (!confirm("Re-evaluate and dismiss all resolved anomalies?\n\nThis will process all " + total + " anomalies server-side.")) return;
    var btn = document.getElementById("wifi-reeval-dismiss-all-btn");
    if (btn) { btn.disabled = true; btn.textContent = "Processing..."; }
    s.dashboard.apiFetch("/api/wifi/anomalies/bulk/reeval-dismiss", {
        method: "POST",
    }).then(function(d) {
        if (btn) { btn.disabled = false; btn.textContent = "Purge Resolved"; }
        var msg = d.processed + " evaluated: " + d.dismissed + " dismissed, " + d.still_anomalous + " remain";
        if (d.errors > 0) msg += " (" + d.errors + " errors)";
        showToast(msg, "success");
        // Update summary bar inline
        s._updateReevalSummary({
            still_anomalous: d.still_anomalous,
            resolved: d.dismissed,
        });
        s._pollWifiAnomalies();
    }).catch(function(e) {
        if (btn) { btn.disabled = false; btn.textContent = "Purge Resolved"; }
        var msg = e && e.detail ? e.detail : "Purge failed";
        showToast(msg, "error");
    });
};

WifiPanel.prototype._renderWifiAnomalyQueue = function() {
    var c = document.getElementById("wifi-anomaly-queue");
    var em = document.getElementById("wifi-anomaly-empty");
    if (!c) return;

    // Apply filter
    var filtered = this.wifiAnomalies;
    var s = this;
    if (s.filterKey && s.filterVal) {
        filtered = filtered.filter(function(a) {
            return s._matchesFilter(a, s.filterKey, s.filterVal);
        });
    }

    // Forget selections and timeline pushes of anomalies no longer loaded.
    var present = {}, presentKeys = {};
    for (var pi = 0; pi < s.wifiAnomalies.length; pi++) {
        var pa = s.wifiAnomalies[pi];
        if (pa.id != null) present[String(pa.id)] = true;
        var pk = _wifiTimelineKey(pa);
        if (pk) presentKeys[pk] = true;
    }
    for (var sid in s._selectedWifiIds) {
        if (!present[sid]) delete s._selectedWifiIds[sid];
    }
    for (var tk in (s._tlPushedKeys || {})) {
        if (!presentKeys[tk]) delete s._tlPushedKeys[tk];
    }

    if (!filtered.length) {
        c.innerHTML = "";
        if (em) em.style.display = s.wifiAnomalies.length ? "none" : "";
        if (!filtered.length && s.filterVal) {
            c.innerHTML = "<p class=\"empty-state\">No anomalies match filter</p>";
        }
        // No cards are bound below, so refresh the bulk bar here: it hides
        // once the queue is empty.
        s._updateWifiBulkBar();
        return;
    }
    if (em) em.style.display = "none";

    var h = "";

    if (s.groupByKey) {
        // Group anomalies by selected key
        var groups = {};
        var groupOrder = [];
        for (var gi = 0; gi < filtered.length; gi++) {
            var ga = filtered[gi];
            var key = s._getAnomalyField(ga, s.groupByKey) || "unknown";
            if (!groups[key]) {
                groups[key] = [];
                groupOrder.push(key);
            }
            groups[key].push(ga);
        }
        // Sort groups by max score descending
        groupOrder.sort(function(a, b) {
            var ma = 0, mb = 0;
            for (var x = 0; x < groups[a].length; x++) { ma = Math.max(ma, groups[a][x].anomaly_score || 0); }
            for (var y = 0; y < groups[b].length; y++) { mb = Math.max(mb, groups[b][y].anomaly_score || 0); }
            return mb - ma;
        });

        for (var gk = 0; gk < groupOrder.length; gk++) {
            var gLabel = groupOrder[gk];
            var items = groups[gLabel];
            var maxScore = 0, totalFrames = 0, totalDeauths = 0;
            var latestTs = "", bestSsid = "";
            var allIds = [];
            for (var mi = 0; mi < items.length; mi++) {
                var item = items[mi];
                var sc = item.anomaly_score || 0;
                if (sc > maxScore) { maxScore = sc; bestSsid = item.ssid || ""; }
                totalFrames += item.frame_count || 0;
                totalDeauths += item.deauth_count || 0;
                if (!latestTs || (item.timestamp && item.timestamp > latestTs)) latestTs = item.timestamp;
                allIds.push(item.id);
            }
            var gPriority = maxScore >= 0.7 ? "critical" : maxScore >= 0.5 ? "anomalous" : maxScore >= 0.3 ? "interesting" : "normal";
            var gScoreCls = "score-" + gPriority;
            var groupId = "wifi-grp-" + gLabel.replace(/[^a-zA-Z0-9]/g, "_") + "-" + gk;

            h += "<div class=\"anomaly-card priority-" + esc(gPriority) + " wifi-mac-group\">"
                + "<div class=\"anomaly-card-header\" style=\"cursor:pointer\" data-wifi-mac-toggle=\"" + esc(groupId) + "\">"
                + "<span class=\"anomaly-score-badge " + gScoreCls + "\">" + maxScore.toFixed(2) + "</span>"
                + "<strong>" + esc(s.groupByKey) + ": " + esc(gLabel) + "</strong>"
                + "<span class=\"anomaly-group-badge\">" + items.length + "</span>"
                + "</div>"
                + "<div class=\"anomaly-card-body\">"
                + "<span>Events: " + items.length + "</span>"
                + "<span>Frames: " + esc(totalFrames) + "</span>";
            if (totalDeauths > 0) h += "<span class=\"deauth-highlight\">Deauth: " + esc(totalDeauths) + "</span>";
            h += "<span>" + fmtTime(latestTs) + "</span>"
                + "</div>"
                + "<div class=\"anomaly-card-actions\">"
                + "<button class=\"btn btn-sm\" data-wifi-dismiss-bulk='" + esc(JSON.stringify(allIds)) + "'>Dismiss All</button>"
                + "<button class=\"btn btn-sm\" data-wifi-reeval-bulk='" + esc(JSON.stringify(allIds)) + "'>Re-evaluate All</button>"
                + "</div>"
                + "<div id=\"wifi-reeval-group-" + esc(groupId) + "\"></div>"
                + "<div class=\"wifi-mac-group-items\" id=\"" + esc(groupId) + "\" style=\"display:none\">";

            for (var mj = 0; mj < items.length; mj++) {
                h += s._renderAnomalyCard(items[mj]);
            }

            h += "</div></div>";
        }
    } else {
        for (var i = 0; i < filtered.length; i++) {
            h += s._renderAnomalyCard(filtered[i]);
        }
    }

    c.innerHTML = h;
    s._bindAnomalyEvents(c);
};

WifiPanel.prototype._bindAnomalyEvents = function(c) {
    var s = this;

    // Group expand/collapse toggles
    c.querySelectorAll("[data-wifi-mac-toggle]").forEach(function(hdr) {
        hdr.addEventListener("click", function() {
            var targetId = this.getAttribute("data-wifi-mac-toggle");
            var target = document.getElementById(targetId);
            if (!target) return;
            target.style.display = target.style.display === "none" ? "" : "none";
        });
    });

    // Bulk dismiss
    c.querySelectorAll("[data-wifi-dismiss-bulk]").forEach(function(btn) {
        btn.addEventListener("click", function(e) {
            e.stopPropagation();
            var ids;
            try { ids = JSON.parse(this.getAttribute("data-wifi-dismiss-bulk")); } catch(_) { return; }
            if (ids.length > 1 && !confirm("Dismiss " + ids.length + " WiFi anomalies?")) return;
            s.dashboard.apiFetch("/api/wifi/anomalies/bulk/dismiss", {
                method: "PUT",
                body: { ids: ids },
            }).then(function() { showToast("Dismissed " + ids.length + " WiFi anomalies", "success"); s._pollWifiAnomalies(); }).catch(function() { showToast("Bulk dismiss failed", "error"); });
        });
    });

    // Bulk re-evaluate
    c.querySelectorAll("[data-wifi-reeval-bulk]").forEach(function(btn) {
        btn.addEventListener("click", function(e) {
            e.stopPropagation();
            var ids;
            try { ids = JSON.parse(this.getAttribute("data-wifi-reeval-bulk")); } catch(_) { return; }
            btn.disabled = true;
            btn.textContent = "Evaluating...";
            s.dashboard.apiFetch("/api/wifi/anomalies/bulk/reevaluate", {
                method: "POST",
                body: { ids: ids },
            }).then(function(d) {
                btn.textContent = "Re-evaluate All";
                btn.disabled = false;
                s._showBulkReevalResults(btn, d.results || {});
            }).catch(function(e) {
                btn.textContent = "Re-evaluate All";
                btn.disabled = false;
                var msg = e && e.detail ? e.detail : "Re-evaluation failed";
                showToast(msg, "error");
            });
        });
    });

    // Investigate
    c.querySelectorAll("[data-wifi-investigate]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var aid = this.getAttribute("data-wifi-investigate");
            for (var i = 0; i < s.wifiAnomalies.length; i++) {
                if (String(s.wifiAnomalies[i].id) === aid) {
                    s._showWifiInvestigation(s.wifiAnomalies[i]);
                    return;
                }
            }
        });
    });

    // Single dismiss
    c.querySelectorAll("[data-wifi-dismiss]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var aid = this.getAttribute("data-wifi-dismiss");
            s.dashboard.apiFetch("/api/wifi/anomalies/" + encodeURIComponent(aid) + "/dismiss", { method: "PUT" })
                .then(function() { showToast("WiFi anomaly dismissed", "success"); s._pollWifiAnomalies(); })
                .catch(function() { showToast("Failed to dismiss anomaly", "error"); });
        });
    });

    // Single re-evaluate
    c.querySelectorAll("[data-wifi-reeval]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var aid = this.getAttribute("data-wifi-reeval");
            btn.disabled = true;
            btn.textContent = "Evaluating...";
            s.dashboard.apiFetch("/api/wifi/anomalies/" + encodeURIComponent(aid) + "/reevaluate", {
                method: "POST",
            }).then(function(d) {
                btn.textContent = "Re-evaluate";
                btn.disabled = false;
                s._showSingleReevalResult(aid, d);
            }).catch(function(e) {
                btn.textContent = "Re-evaluate";
                btn.disabled = false;
                var msg = e && e.detail ? e.detail : "Re-evaluation failed";
                showToast(msg, "error");
            });
        });
    });

    // Pcap summary expand
    c.querySelectorAll("[data-pcap-summary]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var aid = this.getAttribute("data-pcap-summary");
            var panel = document.getElementById("pcap-summary-" + aid);
            if (!panel) return;
            if (panel.style.display !== "none") {
                panel.style.display = "none";
                return;
            }
            if (!panel.dataset.loaded) {
                panel.innerHTML = "<small>Loading pcap summary...</small>";
                panel.style.display = "";
                s.dashboard.apiFetch("/api/wifi/anomalies/" + encodeURIComponent(aid) + "/pcap/summary")
                    .then(function(d) {
                        s._renderPcapSummary(panel, d);
                        panel.dataset.loaded = "1";
                    })
                    .catch(function() {
                        panel.innerHTML = "<small>Failed to load pcap summary</small>";
                    });
            } else {
                panel.style.display = "";
            }
        });
    });

    // Bulk checkbox binding
    s._bindWifiBulkCheckboxes(c);

    // Lazy frame capture expand
    c.querySelectorAll("[data-wifi-frames]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var aid = this.getAttribute("data-wifi-frames");
            var wrap = document.getElementById("pcap-wrap-" + aid);
            if (!wrap) return;
            var content = wrap.querySelector(".pcap-content");
            if (!content) return;
            if (content.style.display !== "none") {
                content.style.display = "none";
                return;
            }
            if (!content.dataset.loaded) {
                s.dashboard.apiFetch("/api/wifi/anomalies?include_frames=true&min_score=0.0&limit=200")
                    .then(function(d) {
                        var anomalies = d.anomalies || [];
                        var match = null;
                        for (var k = 0; k < anomalies.length; k++) {
                            if (String(anomalies[k].id) === String(aid)) { match = anomalies[k]; break; }
                        }
                        if (match && match.frame_capture && match.frame_capture.length) {
                            s._renderFrameTable(content, match.frame_capture);
                        } else {
                            content.innerHTML = "<small>No frames captured</small>";
                        }
                        content.dataset.loaded = "1";
                        content.style.display = "";
                    })
                    .catch(function() { content.innerHTML = "<small>Failed to load</small>"; content.style.display = ""; });
            } else {
                content.style.display = "";
            }
        });
    });
};

/* -- Attack type descriptions ---------------------------------------- */

WifiPanel.prototype.ATTACK_DESCRIPTIONS = {
    evil_twin: "Rogue AP impersonating a legitimate network by cloning its SSID on a different BSSID",
    security_downgrade: "Network security protocol downgraded from expected level (e.g. WPA2 to Open/WEP)",
    signal_anomaly: "Signal strength deviates significantly from the established EWMA baseline for this BSSID",
    new_network: "Previously unseen BSSID appeared in the monitored environment",
    channel_change: "BSSID observed on a channel never seen before in its baseline history",
    client_surge: "Client association count exceeds 2x the expected baseline average",
    deauth_indicator: "Deauthentication/disassociation frames detected or abnormally high retry rate"
};

/* -- Single anomaly card renderer (shared by flat + grouped views) -- */

WifiPanel.prototype._renderAnomalyCard = function(a) {
    var score = a.anomaly_score != null ? a.anomaly_score : 0;
    var priority = score >= 0.7 ? "critical" : score >= 0.5 ? "anomalous" : score >= 0.3 ? "interesting" : "normal";
    var scoreCls = "score-" + priority;
    var isResolved = a.reeval && !a.reeval.still_anomalous;
    var resolvedCls = isResolved ? " anomaly-resolved" : "";

    var wifiCardId = a.id != null ? String(a.id) : "";
    var wIsChecked = !!this._selectedWifiIds[wifiCardId];

    var h = "<div class=\"anomaly-card priority-" + esc(priority) + resolvedCls + (wIsChecked ? " bulk-selected" : "") + "\" role=\"listitem\">"
        // Bulk actions name anomaly row IDs, so an anomaly without one gets
        // a disabled box (as in the RF queue).
        + (wifiCardId
            ? "<input type=\"checkbox\" class=\"bulk-checkbox\" data-wifi-bulk-id=\"" + esc(wifiCardId) + "\"" + (wIsChecked ? " checked" : "") + " aria-label=\"Select " + esc(a.ssid || a.bssid || "Unknown") + " anomaly\">"
            : "<input type=\"checkbox\" class=\"bulk-checkbox\" disabled title=\"No stored anomaly ID\" aria-label=\"" + esc(a.ssid || a.bssid || "Unknown") + " anomaly cannot be selected\">")
        + "<div class=\"anomaly-card-header\">"
        + "<span class=\"anomaly-score-badge " + scoreCls + "\">" + score.toFixed(2) + "</span>"
        + "<strong>" + esc(a.ssid || "(hidden)") + "</strong>"
        + " <code>" + esc(a.bssid) + "</code>";

    // Inline re-eval badge when reeval data is present
    if (a.reeval) {
        var rvCls = a.reeval.still_anomalous ? "still-anomalous" : "now-normal";
        var rvLabel = a.reeval.still_anomalous ? "Active" : "Resolved";
        var rvDelta = a.reeval.score_delta || 0;
        var rvDeltaCls = rvDelta < 0 ? "decreased" : rvDelta > 0 ? "increased" : "same";
        var rvDeltaStr = rvDelta > 0 ? "+" + rvDelta.toFixed(3) : rvDelta.toFixed(3);
        h += "<span class=\"reeval-badge " + rvCls + "\">" + rvLabel + "</span>"
            + "<span class=\"reeval-inline-score\">now " + a.reeval.new_score.toFixed(2)
            + " (<span class=\"score-change " + rvDeltaCls + "\">" + rvDeltaStr + "</span>)</span>";
    }

    h += "</div>"
        + "<div class=\"anomaly-card-body\">"
        + "<span>Ch " + esc(a.channel) + " " + esc(a.band) + "</span>"
        + "<span>" + esc(a.security || "Unknown") + "</span>"
        + "<span>" + esc(a.signal_dbm != null ? a.signal_dbm.toFixed(1) + " dBm" : "--") + "</span>"
        + "<span>" + esc(a.baseline_status || "--") + "</span>"
        + "<span>" + fmtTime(a.timestamp) + "</span>";
    if (a.vendor) {
        h += "<span>Vendor: " + esc(a.vendor) + "</span>";
    }
    if (a.seen_count > 1) {
        h += "<span class=\"seen-count\">seen " + esc(a.seen_count) + "x</span>";
    }
    h += "</div>";

    // Forensic context row
    h += "<div class=\"anomaly-card-forensic\">";
    h += "<span>Clients: " + esc(a.client_count != null ? a.client_count : "--") + "</span>";
    h += "<span>Retry: " + (a.retry_rate != null ? (a.retry_rate * 100).toFixed(1) + "%" : "--") + "</span>";
    if (a.noise_dbm_max) h += "<span>Noise: " + esc(a.noise_dbm_max) + " dBm</span>";
    h += "<span>Frames: " + esc(a.frame_count != null ? a.frame_count : "--") + "</span>";
    if (a.deauth_count > 0) {
        h += "<span class=\"deauth-highlight\">Deauth: " + esc(a.deauth_count) + "</span>";
    }
    if (a.expected_signal != null) {
        h += "<span>Exp sig: " + a.expected_signal.toFixed(1) + " dBm"
            + " (z=" + (a.signal_zscore != null ? a.signal_zscore.toFixed(1) : "--") + ")</span>";
    }
    if (a.expected_channel != null) {
        h += "<span>Exp ch: " + esc(a.expected_channel) + "</span>";
    }
    if (a.baseline_observations > 0) {
        h += "<span>Baseline: " + esc(a.baseline_observations) + " obs</span>";
    }
    h += "</div>";

    // Frame type distribution bar
    if (a.frame_type_counts && Object.keys(a.frame_type_counts).length) {
        var ftc = a.frame_type_counts;
        var ftTotal = 0;
        var ftKeys = Object.keys(ftc);
        for (var fi = 0; fi < ftKeys.length; fi++) ftTotal += ftc[ftKeys[fi]];
        if (ftTotal > 0) {
            h += "<div class=\"frame-type-bar\">";
            var ftColors = { beacon: "var(--accent-blue)", data: "var(--accent-green)",
                deauth: "var(--accent-red)", disassociation: "var(--accent-red)",
                authentication: "var(--accent-yellow)", association: "var(--accent-yellow)",
                probe_response: "var(--accent-cyan)" };
            for (var fj = 0; fj < ftKeys.length; fj++) {
                var pct = (ftc[ftKeys[fj]] / ftTotal * 100).toFixed(1);
                var ftColor = ftColors[ftKeys[fj]] || "var(--text-secondary)";
                h += "<div style=\"width:" + pct + "%;background:" + ftColor
                    + "\" title=\"" + esc(ftKeys[fj]) + ": " + esc(ftc[ftKeys[fj]]) + "\"></div>";
            }
            h += "</div>";
        }
    }

    // Lazy frame capture toggle
    if (a.frame_count > 0) {
        h += "<div class=\"anomaly-card-pcap\" id=\"pcap-wrap-" + esc(a.id) + "\">"
            + "<button class=\"btn btn-sm\" data-wifi-frames=\"" + esc(a.id) + "\">Frames (" + esc(a.frame_count) + ")</button>"
            + "<div class=\"pcap-content\" style=\"display:none\"></div>"
            + "</div>";
    }

    h += "<div class=\"anomaly-card-dims\">";

    if (a.dimensions) {
        var dims = a.dimensions;
        var dimKeys = Object.keys(dims);
        dimKeys.sort(function(x, y) { return (dims[y] || 0) - (dims[x] || 0); });
        var dimLabels = {
            evil_twin: "Evil Twin",
            security_downgrade: "Security Downgrade",
            signal_anomaly: "Signal Anomaly",
            new_network: "New Network",
            channel_change: "Channel Change",
            client_surge: "Client Surge",
            deauth_indicator: "Deauth/Disruption"
        };
        for (var d = 0; d < Math.min(4, dimKeys.length); d++) {
            if (dims[dimKeys[d]] > 0) {
                var dName = dimKeys[d];
                var dLabel = dimLabels[dName] || dName;
                var dDesc = this.ATTACK_DESCRIPTIONS[dName] || "";
                h += "<span class=\"dim-tag\" title=\"" + esc(dDesc) + "\">"
                    + esc(dLabel) + ": " + dims[dName].toFixed(2) + "</span>";
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
    // A BSSID and a Bluetooth address are both indexed as type "mac".
    var bd = window._bridgeDashboard;
    if (bd && bd.indexEntity && bd.getEntityLinks) {
        if (a.bssid) bd.indexEntity("wifi", "mac", a.bssid);
        if (a.node_id) bd.indexEntity("wifi", "node", a.node_id);
        var links = a.bssid ? bd.getEntityLinks("wifi", "mac", a.bssid) : "";
        if (links) h += "<div class=\"anomaly-card-links\">" + links + "</div>";
    }

    h += "<div class=\"anomaly-card-actions\">"
        + "<button class=\"btn btn-sm btn-primary\" data-wifi-investigate=\"" + esc(a.id) + "\">Investigate</button>"
        + "<button class=\"btn btn-sm\" data-wifi-dismiss=\"" + esc(a.id) + "\">Dismiss</button>"
        + "<button class=\"btn btn-sm\" data-wifi-reeval=\"" + esc(a.id) + "\">Re-evaluate</button>";

    // Pcap capture controls
    if (a.has_pcap_capture) {
        // The session cookie authenticates the download; a credential never
        // goes in a URL (browser history, proxy logs).
        var pcapUrl = "/api/wifi/anomalies/" + esc(a.id) + "/pcap";
        h += "<a class=\"btn btn-sm btn-pcap\" href=\"" + pcapUrl
            + "\" download=\"anomaly_" + esc(a.id) + ".pcap.gz\" title=\"Download pcap for Wireshark\">"
            + "pcap";
        if (a.pcap_frame_count > 0) h += " (" + esc(a.pcap_frame_count) + ")";
        h += "</a>"
            + "<button class=\"btn btn-sm\" data-pcap-summary=\"" + esc(a.id) + "\" title=\"View pcap frame summary\">Frames</button>";
    }

    h += "</div>"
        + "<div class=\"reeval-result\" id=\"wifi-reeval-" + esc(a.id) + "\" style=\"display:none\"></div>"
        + "<div class=\"pcap-summary-panel\" id=\"pcap-summary-" + esc(a.id) + "\" style=\"display:none\"></div>"
        + "</div>";

    // N4: Push anomalous/critical WiFi events to cross-protocol threat timeline
    // Each poll replaces the anomaly objects, so remember what was pushed by
    // a stable key on the panel, not by a flag on the object.
    var tlKey = _wifiTimelineKey(a);
    var pushed = this._tlPushedKeys || (this._tlPushedKeys = {});
    var already = tlKey ? !!pushed[tlKey] : !!a._tlPushed;
    if (score >= 0.5 && !already && window._bridgeDashboard && window._bridgeDashboard._pushThreatEvent) {
        if (tlKey) pushed[tlKey] = true;
        a._tlPushed = true;
        var tlSev = score >= 0.7 ? "critical" : "anomalous";
        var tlLabel = (a.ssid || a.bssid || "Unknown WiFi");
        window._bridgeDashboard._pushThreatEvent("wifi", tlSev, tlLabel);
    }

    return h;
};

WifiPanel.prototype._showSingleReevalResult = function(aid, d) {
    var panel = document.getElementById("wifi-reeval-" + aid);
    if (!panel) return;
    panel.style.display = "";
    var cls = d.still_anomalous ? "still-anomalous" : "now-normal";
    var label = d.still_anomalous ? "Still Anomalous" : "Now Normal";
    var deltaCls = d.score_delta < 0 ? "decreased" : d.score_delta > 0 ? "increased" : "same";
    var deltaStr = d.score_delta > 0 ? "+" + d.score_delta.toFixed(3) : d.score_delta.toFixed(3);
    var h = "<span class=\"reeval-badge " + cls + "\">" + esc(label) + "</span> "
        + "New score: <strong>" + d.new_score.toFixed(3) + "</strong> "
        + "(was " + d.original_score.toFixed(3) + ", "
        + "<span class=\"score-change " + deltaCls + "\">" + deltaStr + "</span>) "
        + "Baseline: " + esc(d.baseline_status) + " (" + esc(d.baseline_observations) + " obs)";
    if (d.normal_since) {
        h += " — normal since " + fmtTime(d.normal_since);
    }
    if (d.new_reasons && d.new_reasons.length) {
        h += "<br>Reasons: " + esc(d.new_reasons.join("; "));
    }
    panel.innerHTML = h;
};

WifiPanel.prototype._showBulkReevalResults = function(btn, results) {
    // Find the group container's reeval panel
    var card = btn.closest(".wifi-mac-group");
    if (!card) return;
    var panel = card.querySelector("[id^='wifi-reeval-group-']");
    if (!panel) return;

    var keys = Object.keys(results);
    var stillCount = 0, normalCount = 0;
    for (var i = 0; i < keys.length; i++) {
        if (results[keys[i]].still_anomalous) stillCount++;
        else normalCount++;
    }

    var h = "<div class=\"reeval-result\">"
        + "<strong>" + keys.length + " re-evaluated:</strong> "
        + "<span class=\"reeval-badge now-normal\">" + normalCount + " normal</span> "
        + "<span class=\"reeval-badge still-anomalous\">" + stillCount + " anomalous</span>"
        + "</div>";
    panel.innerHTML = h;
    panel.style.display = "";

    // Also update individual cards within the group
    for (var j = 0; j < keys.length; j++) {
        var aid = keys[j];
        var indPanel = document.getElementById("wifi-reeval-" + aid);
        if (indPanel) {
            var d = results[aid];
            var cls = d.still_anomalous ? "still-anomalous" : "now-normal";
            var label = d.still_anomalous ? "Still Anomalous" : "Now Normal";
            var deltaCls = d.score_delta < 0 ? "decreased" : d.score_delta > 0 ? "increased" : "same";
            var deltaStr = d.score_delta > 0 ? "+" + d.score_delta.toFixed(3) : d.score_delta.toFixed(3);
            indPanel.innerHTML = "<span class=\"reeval-badge " + cls + "\">" + esc(label) + "</span> "
                + d.new_score.toFixed(3) + " (<span class=\"score-change " + deltaCls + "\">" + deltaStr + "</span>)";
            indPanel.style.display = "";
        }
    }
};

WifiPanel.prototype._renderFrameTable = function(container, frames) {
    var maxRows = 20;
    var show = frames.slice(0, maxRows);
    var h = "<table class=\"data-table data-table-sm\"><thead><tr>"
        + "<th>Type</th><th>Client</th><th>Signal</th><th>Rate</th><th>Retry</th>"
        + "</tr></thead><tbody>";
    for (var i = 0; i < show.length; i++) {
        var f = show[i];
        var mac = f.client_mac || "--";
        if (mac.length > 8) mac = "..." + mac.slice(-5);
        h += "<tr>"
            + "<td>" + esc(f.frame_type || "--") + "</td>"
            + "<td><code>" + esc(mac) + "</code></td>"
            + "<td>" + esc(f.signal_dbm != null ? f.signal_dbm : "--") + "</td>"
            + "<td>" + esc(f.data_rate_mbps != null ? f.data_rate_mbps : "--") + "</td>"
            + "<td>" + esc(f.retry_flag != null ? f.retry_flag : "--") + "</td>"
            + "</tr>";
    }
    h += "</tbody></table>";
    if (frames.length > maxRows) {
        h += "<small class=\"pcap-more\">and " + (frames.length - maxRows) + " more...</small>";
    }
    container.innerHTML = h;
};

/* -- Pcap Summary Renderer -------------------------------------- */

WifiPanel.prototype._renderPcapSummary = function(container, summary) {
    var h = "<div class=\"pcap-summary\">"
        + "<div class=\"pcap-summary-stats\">"
        + "<span>Frames: <strong>" + esc(summary.total_frames) + "</strong></span>"
        + "<span>Duration: <strong>" + esc(summary.duration_ms) + " ms</strong></span>"
        + "<span>Size: <strong>" + esc(Math.round((summary.size_bytes || 0) / 1024)) + " KB</strong></span>"
        + "</div>";

    // Frame type breakdown
    var ftc = summary.frame_types || {};
    var ftKeys = Object.keys(ftc);
    if (ftKeys.length) {
        var ftTotal = 0;
        for (var fi = 0; fi < ftKeys.length; fi++) ftTotal += ftc[ftKeys[fi]];
        h += "<div class=\"frame-type-bar\">";
        var ftColors = { beacon: "var(--accent-blue)", data: "var(--accent-green)",
            deauth: "var(--accent-red)", disassociation: "var(--accent-red)",
            authentication: "var(--accent-yellow)", qos_data: "var(--accent-green)",
            probe_response: "var(--accent-cyan)", probe_request: "var(--accent-cyan)" };
        for (var fj = 0; fj < ftKeys.length; fj++) {
            var pct = (ftc[ftKeys[fj]] / ftTotal * 100).toFixed(1);
            var ftColor = ftColors[ftKeys[fj]] || "var(--text-secondary)";
            h += "<div style=\"width:" + pct + "%;background:" + ftColor
                + "\" title=\"" + esc(ftKeys[fj]) + ": " + esc(ftc[ftKeys[fj]]) + " (" + pct + "%)\"></div>";
        }
        h += "</div>";
        h += "<div class=\"pcap-ft-legend\">";
        for (var fl = 0; fl < ftKeys.length; fl++) {
            var color = ftColors[ftKeys[fl]] || "var(--text-secondary)";
            h += "<span><span class=\"ft-dot\" style=\"background:" + color + "\"></span>"
                + esc(ftKeys[fl]) + ": " + esc(ftc[ftKeys[fl]]) + "</span>";
        }
        h += "</div>";
    }

    // Frame timeline table
    var frames = summary.frames || [];
    if (frames.length) {
        h += "<table class=\"data-table data-table-sm\"><thead><tr>"
            + "<th>#</th><th>Type</th><th>Length</th>"
            + "</tr></thead><tbody>";
        var maxRows = 30;
        var show = frames.slice(0, maxRows);
        for (var i = 0; i < show.length; i++) {
            var f = show[i];
            h += "<tr>"
                + "<td>" + (i + 1) + "</td>"
                + "<td>" + esc(f.frame_type || "unknown") + "</td>"
                + "<td>" + esc(f.length || "--") + "</td>"
                + "</tr>";
        }
        h += "</tbody></table>";
        if (frames.length > maxRows) {
            h += "<small class=\"pcap-more\">and " + (frames.length - maxRows) + " more frames...</small>";
        }
    }

    h += "</div>";
    container.innerHTML = h;
};

/* -- WebSocket -------------------------------------------------- */

WifiPanel.prototype._initWebSocket = function() {
    var s = this;
    // An API key, a session token or a cookie session (whose HttpOnly cookie
    // authenticates the upgrade) opens the socket, as in dashboard._connectWS.
    if (!s.dashboard.apiKey && !s.dashboard.sessionToken && !s.dashboard._cookieAuth) return;
    s.dashboard._connectWS("wifi", "/api/wifi/ws/wifi", function(d) {
        if (!s._active) return;
        if (d.type === "wifi_ingest") {
            s._pollNetworks();
            s._pollStats();
        }
        if (d.type === "wifi_anomaly") {
            s._pollWifiAnomalies();
        }
    });
};

/* ================================================================
   WiFi Investigation Workflow
   ================================================================ */

WifiPanel.prototype._showWifiInvestigation = function(anomaly) {
    var s = this;
    var overlay = document.getElementById("wifi-investigate-overlay");
    if (!overlay) return;

    setText("wifi-investigate-title", "WiFi Investigation: " + (anomaly.ssid || anomaly.bssid || "Unknown"));
    overlay.style.display = "";

    // Render context
    s._renderWifiInvContext(anomaly);

    // Render checklist
    s._renderWifiInvChecklist(anomaly);

    // Bind close
    var closeBtn = document.getElementById("wifi-investigate-close");
    var closeBtn2 = document.getElementById("wifi-investigate-close-btn");
    var closeFn = function() { overlay.style.display = "none"; };
    if (closeBtn) closeBtn.onclick = closeFn;
    if (closeBtn2) closeBtn2.onclick = closeFn;
    overlay.onclick = function(e) { if (e.target === overlay) closeFn(); };
};

WifiPanel.prototype._renderWifiInvContext = function(a) {
    var c = document.getElementById("wifi-inv-context");
    if (!c) return;

    var fields = [
        { label: "SSID", value: a.ssid || "(hidden)" },
        { label: "BSSID", value: a.bssid || "--" },
        { label: "Channel", value: (a.channel || "--") + " " + (a.band || "") },
        { label: "Security", value: a.security || "Unknown" },
        { label: "Signal", value: a.signal_dbm != null ? a.signal_dbm.toFixed(1) + " dBm" : "--" },
        { label: "Anomaly Score", value: a.anomaly_score != null ? a.anomaly_score.toFixed(2) : "--" },
        { label: "Clients", value: a.client_count != null ? String(a.client_count) : "--" },
        { label: "Frames", value: a.frame_count != null ? String(a.frame_count) : "--" },
        { label: "Time", value: fmtTime(a.timestamp) }
    ];

    var h = "";
    for (var i = 0; i < fields.length; i++) {
        h += "<div class=\"dd-field\">"
            + "<span class=\"dd-field-label\">" + esc(fields[i].label) + "</span>"
            + "<span class=\"dd-field-value\">" + esc(fields[i].value) + "</span>"
            + "</div>";
    }
    c.innerHTML = h;
};

WifiPanel.prototype._renderWifiInvChecklist = function(a) {
    var c = document.getElementById("wifi-inv-checklist");
    var rec = document.getElementById("wifi-inv-recommendation");
    if (!c) return;

    var steps = [];
    var passCount = 0, warnCount = 0, failCount = 0;
    var score = a.anomaly_score != null ? a.anomaly_score : 0;

    // Step 1: Anomaly Score & Priority
    var scoreStatus, scoreDetail;
    if (score >= 0.7) {
        scoreStatus = "fail"; scoreDetail = "Score " + score.toFixed(2) + " — critical anomaly, requires attention";
    } else if (score >= 0.5) {
        scoreStatus = "warn"; scoreDetail = "Score " + score.toFixed(2) + " — elevated anomaly level";
    } else if (score >= 0.3) {
        scoreStatus = "warn"; scoreDetail = "Score " + score.toFixed(2) + " — minor anomaly";
    } else {
        scoreStatus = "pass"; scoreDetail = "Score " + score.toFixed(2) + " — within normal range";
    }
    steps.push({ label: "Anomaly Score", status: scoreStatus, detail: scoreDetail });

    // Step 2: Detection Dimensions
    var dims = a.dimensions || {};
    var dimKeys = Object.keys(dims);
    var activeDims = [];
    for (var di = 0; di < dimKeys.length; di++) {
        if (dims[dimKeys[di]] > 0) activeDims.push(dimKeys[di]);
    }
    var dimLabels = {
        evil_twin: "Evil Twin", security_downgrade: "Security Downgrade",
        signal_anomaly: "Signal Anomaly", new_network: "New Network",
        channel_change: "Channel Change", client_surge: "Client Surge",
        deauth_indicator: "Deauth/Disruption"
    };
    var dimStatus, dimDetail;
    if (activeDims.length === 0) {
        dimStatus = "pass"; dimDetail = "No anomaly dimensions triggered";
    } else {
        var criticalDims = ["evil_twin", "security_downgrade", "deauth_indicator"];
        var hasCritical = false;
        for (var cd = 0; cd < criticalDims.length; cd++) {
            if (activeDims.indexOf(criticalDims[cd]) !== -1) { hasCritical = true; break; }
        }
        var dimNames = [];
        for (var dn = 0; dn < activeDims.length; dn++) {
            dimNames.push(dimLabels[activeDims[dn]] || activeDims[dn]);
        }
        if (hasCritical) {
            dimStatus = "fail"; dimDetail = "Critical dimension triggered: " + dimNames.join(", ");
        } else {
            dimStatus = "warn"; dimDetail = activeDims.length + " dimension(s) triggered: " + dimNames.join(", ");
        }
    }
    steps.push({ label: "Detection Dimensions", status: dimStatus, detail: dimDetail });

    // Step 3: Deauth activity
    var deauthStatus, deauthDetail;
    var deauths = a.deauth_count || 0;
    if (deauths === 0) {
        deauthStatus = "pass"; deauthDetail = "No deauthentication frames observed";
    } else if (deauths < 10) {
        deauthStatus = "warn"; deauthDetail = deauths + " deauth frames — could be normal roaming";
    } else {
        deauthStatus = "fail"; deauthDetail = deauths + " deauth frames — potential deauth attack";
    }
    steps.push({ label: "Deauth Activity", status: deauthStatus, detail: deauthDetail });

    // Step 4: Signal strength anomaly
    var sigStatus, sigDetail;
    if (a.signal_zscore != null) {
        var zs = Math.abs(a.signal_zscore);
        if (zs < 2) {
            sigStatus = "pass"; sigDetail = "Signal z-score " + a.signal_zscore.toFixed(1) + " — within baseline";
        } else if (zs < 3) {
            sigStatus = "warn"; sigDetail = "Signal z-score " + a.signal_zscore.toFixed(1) + " — moderate deviation";
        } else {
            sigStatus = "fail"; sigDetail = "Signal z-score " + a.signal_zscore.toFixed(1) + " — significant deviation, possible rogue AP";
        }
    } else {
        sigStatus = "unknown"; sigDetail = "Signal baseline data not available";
    }
    steps.push({ label: "Signal Strength Analysis", status: sigStatus, detail: sigDetail });

    // Step 5: Pcap availability
    var pcapStatus, pcapDetail;
    if (a.has_pcap_capture) {
        pcapStatus = "pass"; pcapDetail = "Pcap capture available" + (a.pcap_frame_count ? " (" + a.pcap_frame_count + " frames)" : "") + " — download for Wireshark analysis";
    } else if (a.frame_count > 0) {
        pcapStatus = "warn"; pcapDetail = "Frame metadata available but no raw pcap capture";
    } else {
        pcapStatus = "warn"; pcapDetail = "No packet capture data available";
    }
    steps.push({ label: "Packet Capture", status: pcapStatus, detail: pcapDetail });

    // Step 6: Threat Assessment
    for (var si = 0; si < steps.length; si++) {
        if (steps[si].status === "pass") passCount++;
        else if (steps[si].status === "warn") warnCount++;
        else if (steps[si].status === "fail") failCount++;
    }

    var threatStatus, threatDetail;
    if (failCount >= 2) {
        threatStatus = "fail"; threatDetail = "Multiple critical indicators — potential active attack";
    } else if (failCount >= 1) {
        threatStatus = "warn"; threatDetail = "One critical indicator — investigate before dismissing";
    } else if (warnCount >= 2) {
        threatStatus = "warn"; threatDetail = "Multiple warnings — monitor closely";
    } else {
        threatStatus = "pass"; threatDetail = "All checks nominal — likely benign network activity";
    }
    steps.push({ label: "Threat Assessment", status: threatStatus, detail: threatDetail });

    // Render steps
    var statusIcons = { pass: "\u2714", warn: "\u26A0", fail: "\u2716", unknown: "\u2014" };
    var h = "";
    for (var i = 0; i < steps.length; i++) {
        var st = steps[i];
        h += "<div class=\"inv-step inv-" + esc(st.status) + "\">"
            + "<span class=\"inv-step-icon\">" + (statusIcons[st.status] || "\u2014") + "</span>"
            + "<div class=\"inv-step-content\">"
            + "<span class=\"inv-step-label\">" + esc(st.label) + "</span>"
            + "<span class=\"inv-step-detail\">" + esc(st.detail) + "</span>"
            + "</div></div>";
    }
    c.innerHTML = h;

    // Render recommendation
    if (rec) {
        var recAction, recCls;
        if (failCount >= 2 || (failCount >= 1 && score > 0.7)) {
            recAction = "Escalate"; recCls = "rec-escalate";
        } else if (failCount >= 1 || warnCount >= 2) {
            recAction = "Investigate further"; recCls = "rec-investigate";
        } else if (warnCount >= 1) {
            recAction = "Add to baseline"; recCls = "rec-baseline";
        } else {
            recAction = "Dismiss"; recCls = "rec-dismiss";
        }
        rec.innerHTML = "<div class=\"inv-recommendation " + recCls + "\">"
            + "<span class=\"inv-rec-label\">Recommended Action:</span>"
            + "<span class=\"inv-rec-action\">" + esc(recAction) + "</span>"
            + "</div>";
    }
};

/* ================================================================
   Bulk Selection (WiFi Anomalies)
   ================================================================ */

WifiPanel.prototype._initWifiBulkSelection = function() {
    var s = this;
    var selectAllCb = document.getElementById("wifi-select-all");
    var dismissBtn = document.getElementById("wifi-bulk-dismiss");
    var escalateBtn = document.getElementById("wifi-bulk-escalate");
    var exportBtn = document.getElementById("wifi-bulk-export");

    if (selectAllCb) {
        selectAllCb.addEventListener("change", function() {
            var checked = selectAllCb.checked;
            s._selectedWifiIds = {};
            if (checked) {
                for (var i = 0; i < s.wifiAnomalies.length; i++) {
                    var aid = s.wifiAnomalies[i].id != null ? String(s.wifiAnomalies[i].id) : "";
                    if (aid) s._selectedWifiIds[aid] = true;
                }
            }
            s._renderWifiAnomalyQueue();
            s._updateWifiBulkBar();
        });
    }

    if (dismissBtn) {
        dismissBtn.addEventListener("click", function() {
            var ids = Object.keys(s._selectedWifiIds);
            if (!ids.length) return;
            if (ids.length > 1 && !confirm("Dismiss " + ids.length + " selected WiFi anomalies?")) return;
            s.dashboard.apiFetch("/api/wifi/anomalies/bulk/dismiss", {
                method: "PUT",
                body: { ids: ids }
            }).then(function() {
                showToast("Dismissed " + ids.length + " WiFi anomalies", "success");
                s._selectedWifiIds = {};
                s._updateWifiBulkBar();
                s._pollWifiAnomalies();
            }).catch(function() {
                showToast("Bulk dismiss failed", "error");
            });
        });
    }

    if (escalateBtn) {
        escalateBtn.addEventListener("click", function() {
            var ids = Object.keys(s._selectedWifiIds);
            if (!ids.length || !escalationFits(ids.length)) return;
            if (!confirm("Escalate " + ids.length + " selected WiFi anomalies? One critical alert names them; none is dismissed.")) return;
            // Escalation raises an alert and leaves the anomalies in the queue.
            s.dashboard.apiFetch("/api/wifi/anomalies/bulk/escalate", {
                method: "POST",
                body: { ids: ids }
            }).then(function(d) {
                showToast(escalationSummary(d), "warning");
                s._selectedWifiIds = {};
                s._updateWifiBulkBar();
                s._pollWifiAnomalies();
            }).catch(function(e) {
                showToast("Bulk escalation failed: " + ((e && (e.detail || e.message)) || "unknown error"), "error");
            });
        });
    }

    if (exportBtn) {
        exportBtn.addEventListener("click", function() {
            var ids = Object.keys(s._selectedWifiIds);
            if (!ids.length) return;
            var params = "?format=json&ids=" + ids.map(encodeURIComponent).join(",");
            window.open("/api/export/wifi_anomalies" + params, "_blank");
            showToast("Exporting " + ids.length + " WiFi anomalies", "info");
        });
    }
};

WifiPanel.prototype._bindWifiBulkCheckboxes = function(c) {
    var s = this;
    c.querySelectorAll("[data-wifi-bulk-id]").forEach(function(cb) {
        cb.addEventListener("change", function(e) {
            e.stopPropagation();
            var aid = this.getAttribute("data-wifi-bulk-id");
            if (this.checked) {
                s._selectedWifiIds[aid] = true;
            } else {
                delete s._selectedWifiIds[aid];
            }
            var card = this.closest(".anomaly-card");
            if (card) card.classList.toggle("bulk-selected", this.checked);
            s._updateWifiBulkBar();
        });
    });

    s._updateWifiBulkBar();
};

WifiPanel.prototype._updateWifiBulkBar = function() {
    var bar = document.getElementById("wifi-bulk-bar");
    var countEl = document.getElementById("wifi-bulk-count");
    var selectAllCb = document.getElementById("wifi-select-all");
    var dismissBtn = document.getElementById("wifi-bulk-dismiss");
    var escalateBtn = document.getElementById("wifi-bulk-escalate");
    var exportBtn = document.getElementById("wifi-bulk-export");

    if (!bar) return;

    var count = Object.keys(this._selectedWifiIds).length;
    bar.style.display = this.wifiAnomalies.length > 0 ? "" : "none";
    if (countEl) countEl.textContent = count + " selected";
    if (dismissBtn) dismissBtn.disabled = count === 0;
    if (escalateBtn) escalateBtn.disabled = count === 0;
    if (exportBtn) exportBtn.disabled = count === 0;

    if (selectAllCb) {
        // Only anomalies with an ID can be selected.
        var sel = this._selectedWifiIds;
        var selectable = this.wifiAnomalies.filter(function(a) { return a.id != null; });
        selectAllCb.checked = selectable.length > 0 && selectable.every(function(a) { return !!sel[String(a.id)]; });
    }
};
