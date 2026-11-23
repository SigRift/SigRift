/**
 * MLRF Gen4 Dashboard - Spectrum Occupancy Analysis
 *
 * Provides band occupancy table, canvas waterfall display, and
 * activity timeline scatter plot.  Auto-refreshes when the
 * Spectrum tab is active.
 */
"use strict";

/* ================================================================
   SpectrumAnalysis Class
   ================================================================ */

function SpectrumAnalysis(dashboard) {
    this.dashboard = dashboard;
    this._refreshTimer = null;
    this._active = false;

    this._waterfallCanvas = document.getElementById("sa-waterfall-canvas");
    this._waterfallCtx = this._waterfallCanvas ? this._waterfallCanvas.getContext("2d") : null;

    this._activityCanvas = document.getElementById("sa-activity-canvas");
    this._activityCtx = this._activityCanvas ? this._activityCanvas.getContext("2d") : null;

    this._initControls();
}

/* ----------------------------------------------------------------
   Controls & Refresh
   ---------------------------------------------------------------- */

SpectrumAnalysis.prototype._initControls = function() {
    var self = this;
    var refreshBtn = document.getElementById("sa-refresh");
    if (refreshBtn) {
        refreshBtn.addEventListener("click", function() { self.refreshAll(); });
    }

    // Time picker change refreshes all panels including wideband
    var hoursEl = document.getElementById("sa-hours");
    if (hoursEl) {
        hoursEl.addEventListener("change", function() {
            if (self._active) self.refreshAll();
        });
    }

    // Watch for tab activation
    var observer = new MutationObserver(function() {
        var tab = document.getElementById("tab-spectrum-analysis");
        var isActive = tab && tab.classList.contains("active");
        if (isActive && !self._active) {
            self._active = true;
            self.refreshAll();
            self._startAutoRefresh();
            // Activate wideband monitor if present
            var wb = self.dashboard && self.dashboard.widebandMonitor;
            if (wb) wb.activate();
        } else if (!isActive && self._active) {
            self._active = false;
            self._stopAutoRefresh();
            var wb2 = self.dashboard && self.dashboard.widebandMonitor;
            if (wb2) wb2.deactivate();
        }
    });
    var tab = document.getElementById("tab-spectrum-analysis");
    if (tab) {
        observer.observe(tab, { attributes: true, attributeFilter: ["class"] });
    }
};

SpectrumAnalysis.prototype._startAutoRefresh = function() {
    var self = this;
    this._stopAutoRefresh();
    this._refreshTimer = setInterval(function() {
        if (self._active) self.refreshAll();
    }, 30000);
};

SpectrumAnalysis.prototype._stopAutoRefresh = function() {
    if (this._refreshTimer) {
        clearInterval(this._refreshTimer);
        this._refreshTimer = null;
    }
};

/** Return the user-selected hours from the shared time picker. */
SpectrumAnalysis.prototype._getHours = function() {
    var hoursEl = document.getElementById("sa-hours");
    return hoursEl ? parseInt(hoursEl.value) || 24 : 24;
};

SpectrumAnalysis.prototype.refresh = function() {
    this._loadBands();
    this._loadWaterfall();
    this._loadActivity();
};

/** Refresh all spectrum panels including wideband monitor. */
SpectrumAnalysis.prototype.refreshAll = function() {
    this.refresh();
    var wb = this.dashboard && this.dashboard.widebandMonitor;
    if (wb) wb.refresh();
};

/* ----------------------------------------------------------------
   Band Occupancy Table
   ---------------------------------------------------------------- */

SpectrumAnalysis.prototype._loadBands = function() {
    var self = this;
    var hours = self._getHours();

    self.dashboard.apiFetch("/api/spectrum/bands?hours=" + hours)
        .then(function(data) {
            self._renderBandsTable(data.bands || []);
        })
        .catch(function(e) {
            trackFetchError("sa-bands", e);
            self._renderBandsTable([]);
        });
};

SpectrumAnalysis.prototype._renderBandsTable = function(bands) {
    var tbody = document.getElementById("sa-bands-tbody");
    var empty = document.getElementById("sa-bands-empty");
    if (!tbody) return;

    var activeBands = bands.filter(function(b) { return b.signal_count > 0; });

    if (activeBands.length === 0 && bands.length > 0) {
        // Show all bands even if empty
        activeBands = bands;
    }

    if (bands.length === 0) {
        tbody.innerHTML = "";
        if (empty) empty.style.display = "";
        return;
    }
    if (empty) empty.style.display = "none";

    var html = "";
    for (var i = 0; i < bands.length; i++) {
        var b = bands[i];
        var minMhz = (b.min_hz / 1e6).toFixed(1);
        var maxMhz = (b.max_hz / 1e6).toFixed(1);
        var occPct = b.occupancy_pct != null ? b.occupancy_pct.toFixed(1) + "%" : "--";
        var avgPwr = b.avg_power_dbm != null ? b.avg_power_dbm.toFixed(1) + " dBm" : "--";
        var peakPwr = b.peak_power_dbm != null ? b.peak_power_dbm.toFixed(1) + " dBm" : "--";
        var domClass = b.dominant_class || "--";
        var lastSeen = b.last_seen ? _saFmtTime(b.last_seen) : "--";

        // Occupancy bar
        var barPct = Math.min(b.occupancy_pct || 0, 100);
        var barColor = barPct > 50 ? "var(--accent-red)" : barPct > 20 ? "var(--accent-yellow)" : "var(--accent-green)";
        var barHtml = '<div style="display:flex;align-items:center;gap:6px;">'
            + '<div style="flex:1;height:8px;background:var(--bg-secondary);border-radius:4px;overflow:hidden;">'
            + '<div style="width:' + barPct + '%;height:100%;background:' + barColor + ';border-radius:4px;"></div>'
            + '</div>'
            + '<span style="min-width:40px;text-align:right;">' + _saEsc(occPct) + '</span>'
            + '</div>';

        var rowClass = b.signal_count > 0 ? "" : ' style="opacity:0.5;"';

        // Dominant class — drill-down link to RF Intelligence
        var domClassHtml = domClass !== "--"
            ? "<span class=\"drilldown-link\" data-drilldown-band-class=\"" + _saEsc(domClass) + "\" title=\"View " + _saEsc(domClass) + " in RF Intelligence\">" + _saEsc(domClass) + "</span>"
            : _saEsc(domClass);

        html += "<tr" + rowClass + ">"
            + "<td>" + _saEsc(b.band) + "</td>"
            + "<td>" + _saEsc(minMhz) + " - " + _saEsc(maxMhz) + " MHz</td>"
            + "<td>" + barHtml + "</td>"
            + "<td>" + _saEsc(String(b.signal_count)) + "</td>"
            + "<td>" + _saEsc(avgPwr) + "</td>"
            + "<td>" + _saEsc(peakPwr) + "</td>"
            + "<td>" + domClassHtml + "</td>"
            + "<td>" + _saEsc(lastSeen) + "</td>"
            + "</tr>";
    }
    tbody.innerHTML = html;

    // Drill-down: dominant class in band table -> RF Intelligence
    tbody.querySelectorAll("[data-drilldown-band-class]").forEach(function(link) {
        link.addEventListener("click", function(e) {
            e.stopPropagation();
            var cls = this.getAttribute("data-drilldown-band-class");
            if (cls && window.drillDown) window.drillDown.toSignalClass(cls);
        });
    });
};

/* ----------------------------------------------------------------
   Waterfall Display (canvas)
   ---------------------------------------------------------------- */

SpectrumAnalysis.prototype._loadWaterfall = function() {
    var self = this;
    var hours = self._getHours();
    // Scale time resolution with window size for manageable matrix
    var resSec = hours <= 4 ? 60 : hours <= 24 ? 300 : hours <= 48 ? 900 : 3600;

    self.dashboard.apiFetch("/api/spectrum/waterfall?hours=" + hours + "&time_resolution_sec=" + resSec)
        .then(function(data) {
            self._renderWaterfall(data);
            var badge = document.getElementById("sa-waterfall-badge");
            if (badge) {
                var nTime = (data.time_bins || []).length;
                var nFreq = (data.freq_bins || []).length;
                badge.textContent = nTime + " x " + nFreq;
            }
        })
        .catch(function(e) {
            trackFetchError("sa-waterfall", e);
            self._renderWaterfall({ time_bins: [], freq_bins: [], power_matrix: [] });
        });
};

SpectrumAnalysis.prototype._renderWaterfall = function(data) {
    var canvas = this._waterfallCanvas;
    var ctx = this._waterfallCtx;
    if (!ctx || !canvas) return;

    var w = canvas.width;
    var h = canvas.height;

    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--bg-primary").trim() || "#0d1117";
    ctx.fillRect(0, 0, w, h);

    var timeBins = data.time_bins || [];
    var freqBins = data.freq_bins || [];
    var matrix = data.power_matrix || [];

    if (timeBins.length === 0 || freqBins.length === 0) {
        ctx.fillStyle = "#8b949e";
        ctx.font = "14px sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("No waterfall data available", w / 2, h / 2);
        return;
    }

    var margin = { top: 10, right: 10, bottom: 30, left: 60 };
    var plotW = w - margin.left - margin.right;
    var plotH = h - margin.top - margin.bottom;

    var nTime = timeBins.length;
    var nFreq = freqBins.length;
    var cellW = plotW / nFreq;
    var cellH = plotH / nTime;

    // Find power range
    var minPwr = -100, maxPwr = -20;
    for (var ti = 0; ti < nTime; ti++) {
        for (var fi = 0; fi < nFreq; fi++) {
            var v = matrix[ti] ? matrix[ti][fi] : null;
            if (v != null) {
                if (v < minPwr) minPwr = v;
                if (v > maxPwr) maxPwr = v;
            }
        }
    }

    var cmap = _saGetColormap();

    for (var ti2 = 0; ti2 < nTime; ti2++) {
        for (var fi2 = 0; fi2 < nFreq; fi2++) {
            var pwr = matrix[ti2] ? matrix[ti2][fi2] : null;
            if (pwr == null) continue;

            var norm = (pwr - minPwr) / (maxPwr - minPwr || 1);
            if (norm < 0) norm = 0;
            if (norm > 1) norm = 1;
            var ci = Math.floor(norm * (cmap.length - 1));
            var c = cmap[ci];

            ctx.fillStyle = "rgb(" + c[0] + "," + c[1] + "," + c[2] + ")";
            ctx.fillRect(
                margin.left + fi2 * cellW,
                margin.top + ti2 * cellH,
                Math.ceil(cellW) + 1,
                Math.ceil(cellH) + 1
            );
        }
    }

    // Axes
    ctx.fillStyle = "#8b949e";
    ctx.font = "10px monospace";

    // Frequency axis (bottom)
    ctx.textAlign = "center";
    var freqStep = Math.max(1, Math.floor(nFreq / 8));
    for (var f = 0; f < nFreq; f += freqStep) {
        var fx = margin.left + f * cellW + cellW / 2;
        var freqMhz = (freqBins[f] / 1e6).toFixed(0);
        ctx.fillText(freqMhz + " MHz", fx, h - margin.bottom + 15);
    }

    // Time axis (left)
    ctx.textAlign = "right";
    var timeStep = Math.max(1, Math.floor(nTime / 6));
    for (var t = 0; t < nTime; t += timeStep) {
        var ty = margin.top + t * cellH + cellH / 2;
        var tLabel = _saFmtTimeShort(timeBins[t]);
        ctx.fillText(tLabel, margin.left - 4, ty + 3);
    }
};

/* ----------------------------------------------------------------
   Activity Timeline (scatter plot)
   ---------------------------------------------------------------- */

SpectrumAnalysis.prototype._loadActivity = function() {
    var self = this;
    var hours = self._getHours();

    self.dashboard.apiFetch("/api/spectrum/activity?hours=" + hours + "&limit=1000")
        .then(function(data) {
            self._renderActivity(data.activity || [], hours);
            var badge = document.getElementById("sa-activity-badge");
            if (badge) badge.textContent = (data.count || 0) + " signals";
        })
        .catch(function(e) {
            trackFetchError("sa-activity", e);
            self._renderActivity([], hours);
        });
};

SpectrumAnalysis.prototype._renderActivity = function(activity, hours) {
    var canvas = this._activityCanvas;
    var ctx = this._activityCtx;
    if (!ctx || !canvas) return;

    var w = canvas.width;
    var h = canvas.height;

    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--bg-primary").trim() || "#0d1117";
    ctx.fillRect(0, 0, w, h);

    if (activity.length === 0) {
        ctx.fillStyle = "#8b949e";
        ctx.font = "14px sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("No activity data available", w / 2, h / 2);
        return;
    }

    var margin = { top: 10, right: 10, bottom: 30, left: 70 };
    var plotW = w - margin.left - margin.right;
    var plotH = h - margin.top - margin.bottom;

    // Time axis anchored to requested window
    var now = Date.now();
    var maxTime = now;
    var minTime = now - (hours || 4) * 3600 * 1000;

    // Find freq/power ranges from data
    var minFreq = Infinity, maxFreq = -Infinity;
    var minPwr = Infinity, maxPwr = -Infinity;

    for (var i = 0; i < activity.length; i++) {
        var a = activity[i];
        if (a.freq_hz < minFreq) minFreq = a.freq_hz;
        if (a.freq_hz > maxFreq) maxFreq = a.freq_hz;
        var p = a.power_dbm || -80;
        if (p < minPwr) minPwr = p;
        if (p > maxPwr) maxPwr = p;
    }

    var timeRange = maxTime - minTime || 1;
    var freqRange = maxFreq - minFreq || 1;
    var pwrRange = maxPwr - minPwr || 1;

    // Grid
    ctx.strokeStyle = "#30363d";
    ctx.lineWidth = 0.5;
    for (var g = 0; g <= 4; g++) {
        var gy = margin.top + plotH * g / 4;
        ctx.beginPath(); ctx.moveTo(margin.left, gy); ctx.lineTo(w - margin.right, gy); ctx.stroke();
        var gx = margin.left + plotW * g / 4;
        ctx.beginPath(); ctx.moveTo(gx, margin.top); ctx.lineTo(gx, h - margin.bottom); ctx.stroke();
    }

    // Class color map
    var classColors = {};
    var colorPalette = [
        "#58a6ff", "#3fb950", "#f0883e", "#a371f7", "#f85149",
        "#79c0ff", "#56d364", "#d29922", "#bc8cff", "#ff7b72",
    ];
    var colorIdx = 0;

    // Plot dots
    for (var j = 0; j < activity.length; j++) {
        var act = activity[j];
        var ts = new Date(act.timestamp).getTime();
        var x = margin.left + ((ts - minTime) / timeRange) * plotW;
        var y = margin.top + plotH - ((act.freq_hz - minFreq) / freqRange) * plotH;

        var pNorm = ((act.power_dbm || -80) - minPwr) / pwrRange;
        var radius = 2 + pNorm * 5;

        var cls = act.signal_class || "unknown";
        if (!classColors[cls]) {
            classColors[cls] = colorPalette[colorIdx % colorPalette.length];
            colorIdx++;
        }

        ctx.beginPath();
        ctx.arc(x, y, radius, 0, Math.PI * 2);
        ctx.fillStyle = classColors[cls];
        ctx.globalAlpha = 0.7;
        ctx.fill();
        ctx.globalAlpha = 1.0;
    }

    // Frequency axis labels (left)
    ctx.fillStyle = "#8b949e";
    ctx.font = "10px monospace";
    ctx.textAlign = "right";
    for (var fl = 0; fl <= 4; fl++) {
        var fy = margin.top + plotH - plotH * fl / 4;
        var fLabel = ((minFreq + freqRange * fl / 4) / 1e6).toFixed(1);
        ctx.fillText(fLabel + " MHz", margin.left - 4, fy + 3);
    }

    // Time axis labels (bottom)
    ctx.textAlign = "center";
    for (var tl = 0; tl <= 4; tl++) {
        var tx = margin.left + plotW * tl / 4;
        var tMs = minTime + timeRange * tl / 4;
        ctx.fillText(_saFmtTimeShort(new Date(tMs).toISOString()), tx, h - margin.bottom + 15);
    }

    // Legend
    var legendX = margin.left + 8;
    var legendY = margin.top + 14;
    ctx.font = "10px sans-serif";
    ctx.textAlign = "left";
    var classKeys = Object.keys(classColors);
    for (var li = 0; li < Math.min(classKeys.length, 8); li++) {
        var lk = classKeys[li];
        ctx.fillStyle = classColors[lk];
        ctx.fillRect(legendX, legendY + li * 14 - 8, 10, 10);
        ctx.fillStyle = "#c9d1d9";
        ctx.fillText(lk, legendX + 14, legendY + li * 14);
    }
};

/* ----------------------------------------------------------------
   Utility functions
   ---------------------------------------------------------------- */

/* HTML-escape text (& < > " ') for element content and for quoted attribute
 * values. Not for unquoted attributes, URLs, inline handlers, script elements or style. */
function _saEsc(str) {
    if (str == null) return "";
    return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function _saFmtTime(iso) {
    if (!iso) return "--";
    try {
        return new Date(iso).toLocaleString(undefined, {
            hour12: false, month: "short", day: "numeric",
            hour: "2-digit", minute: "2-digit"
        });
    } catch (_) { return _saEsc(iso); }
}

function _saFmtTimeShort(iso) {
    if (!iso) return "--";
    try {
        return new Date(iso).toLocaleTimeString(undefined, {
            hour12: false, hour: "2-digit", minute: "2-digit"
        });
    } catch (_) { return "--"; }
}

var _saColormap = null;
function _saGetColormap() {
    if (_saColormap) return _saColormap;
    _saColormap = [];
    for (var i = 0; i < 256; i++) {
        var t = i / 255;
        var r, g, b;
        if (t < 0.125) {
            r = 0; g = 0; b = Math.round(128 + 127 * (t / 0.125));
        } else if (t < 0.375) {
            r = 0; g = Math.round(255 * ((t - 0.125) / 0.25)); b = 255;
        } else if (t < 0.625) {
            r = Math.round(255 * ((t - 0.375) / 0.25)); g = 255; b = Math.round(255 * (1 - (t - 0.375) / 0.25));
        } else if (t < 0.875) {
            r = 255; g = Math.round(255 * (1 - (t - 0.625) / 0.25)); b = 0;
        } else {
            r = Math.round(255 * (1 - (t - 0.875) / 0.125 * 0.5)); g = 0; b = 0;
        }
        _saColormap.push([r, g, b]);
    }
    return _saColormap;
}

/* ================================================================
   WidebandMonitor — real-time PSD plot with peak overlay
   ================================================================ */

function WidebandMonitor(dashboard) {
    this.dashboard = dashboard;
    this._ws = null;
    this._psdCanvas = document.getElementById("wb-psd-canvas");
    this._psdCtx = this._psdCanvas ? this._psdCanvas.getContext("2d") : null;
    this._latestSnapshot = null;
    this._peaks = [];
    this._comparison = null;  // Historical PSD comparison data
    this._showComparison = false;
    this._peaksGroupBy = "frequency";
    this._expandedGroups = {};  // tracks which groups the user has expanded

    this._initControls();
}

WidebandMonitor.prototype._initControls = function() {
    var self = this;
    var refreshBtn = document.getElementById("wb-refresh");
    if (refreshBtn) {
        refreshBtn.addEventListener("click", function() { self.refresh(); });
    }

    var nodeSelect = document.getElementById("wb-node-select");
    if (nodeSelect) {
        nodeSelect.addEventListener("change", function() { self.refresh(); });
    }

    var compareToggle = document.getElementById("wb-compare-toggle");
    if (compareToggle) {
        compareToggle.addEventListener("change", function() {
            self._showComparison = compareToggle.checked;
            if (self._showComparison && !self._comparison) {
                self._loadComparison();
            } else if (self._latestSnapshot) {
                self._renderPSD(self._latestSnapshot);
            }
        });
    }

    var stitchBtn = document.getElementById("wb-stitch-btn");
    if (stitchBtn) {
        stitchBtn.addEventListener("click", function() { self._loadStitched(); });
    }

    var groupSelect = document.getElementById("wb-peaks-group");
    if (groupSelect) {
        groupSelect.addEventListener("change", function() {
            self._peaksGroupBy = this.value;
            self._expandedGroups = {};
            self._renderPeaksTable(self._peaks);
        });
    }
};

WidebandMonitor.prototype.activate = function() {
    this.refresh();
    this._connectWS();
};

WidebandMonitor.prototype.deactivate = function() {
    this._disconnectWS();
};

WidebandMonitor.prototype.refresh = function() {
    this._loadMonitor();
    this._loadPeaks();
    this._loadNodes();
    if (this._showComparison) {
        this._loadComparison();
    }
};

WidebandMonitor.prototype._loadNodes = function() {
    var select = document.getElementById("wb-node-select");
    if (!select || select.options.length > 1) return;

    this.dashboard.apiFetch("/api/nodes/")
        .then(function(data) {
            var nodes = data.nodes || [];
            for (var i = 0; i < nodes.length; i++) {
                var opt = document.createElement("option");
                opt.value = nodes[i].node_id;
                opt.textContent = nodes[i].node_id;
                select.appendChild(opt);
            }
        })
        .catch(function() {});
};

WidebandMonitor.prototype._loadMonitor = function() {
    var self = this;
    var nodeSelect = document.getElementById("wb-node-select");
    var nodeId = nodeSelect ? nodeSelect.value : "";
    var url = "/api/spectrum/monitor";
    if (nodeId) url += "?node_id=" + encodeURIComponent(nodeId);

    self.dashboard.apiFetch(url)
        .then(function(data) {
            var snaps = data.snapshots || [];
            var badge = document.getElementById("wb-status-badge");
            if (badge) {
                badge.textContent = snaps.length > 0
                    ? snaps.length + " node" + (snaps.length !== 1 ? "s" : "")
                    : "No data";
            }
            if (snaps.length > 0) {
                self._latestSnapshot = snaps[0];
                self._renderPSD(snaps[0]);
            } else {
                self._renderEmpty();
            }
        })
        .catch(function() {});
};

WidebandMonitor.prototype._getHours = function() {
    var hoursEl = document.getElementById("sa-hours");
    return hoursEl ? parseInt(hoursEl.value) || 24 : 24;
};

WidebandMonitor.prototype._loadPeaks = function() {
    var self = this;
    var hours = self._getHours();
    self.dashboard.apiFetch("/api/spectrum/monitor/peaks?hours=" + hours)
        .then(function(data) {
            self._peaks = data.peaks || [];
            self._renderPeaksTable(self._peaks);
            // Re-render PSD with peak overlay if we have snapshot
            if (self._latestSnapshot) {
                self._renderPSD(self._latestSnapshot);
            }
        })
        .catch(function() {});
};

WidebandMonitor.prototype._renderEmpty = function() {
    var ctx = this._psdCtx;
    var canvas = this._psdCanvas;
    if (!ctx || !canvas) return;
    var w = canvas.width, h = canvas.height;
    ctx.fillStyle = "#0d1117";
    ctx.fillRect(0, 0, w, h);
    ctx.fillStyle = "#8b949e";
    ctx.font = "14px sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("No wideband data available. Edge nodes must POST to /api/spectrum/snapshots.", w / 2, h / 2);
};

WidebandMonitor.prototype._renderPSD = function(snapshot) {
    var ctx = this._psdCtx;
    var canvas = this._psdCanvas;
    if (!ctx || !canvas) return;

    var w = canvas.width, h = canvas.height;
    ctx.fillStyle = "#0d1117";
    ctx.fillRect(0, 0, w, h);

    var psd = snapshot.psd_dbm;
    if (!psd || psd.length === 0) {
        this._renderEmpty();
        return;
    }

    var margin = { top: 15, right: 15, bottom: 35, left: 60 };
    var plotW = w - margin.left - margin.right;
    var plotH = h - margin.top - margin.bottom;

    var centerFreq = snapshot.center_freq_hz;
    var bandwidth = snapshot.bandwidth_hz;
    var startFreq = centerFreq - bandwidth / 2;
    var binWidth = bandwidth / psd.length;

    // Power range
    var minPwr = Infinity, maxPwr = -Infinity;
    for (var i = 0; i < psd.length; i++) {
        if (psd[i] != null) {
            if (psd[i] < minPwr) minPwr = psd[i];
            if (psd[i] > maxPwr) maxPwr = psd[i];
        }
    }
    if (minPwr === Infinity) { minPwr = -120; maxPwr = -20; }
    var pwrPad = (maxPwr - minPwr) * 0.1;
    minPwr -= pwrPad;
    maxPwr += pwrPad;
    var pwrRange = maxPwr - minPwr || 1;

    // Grid
    ctx.strokeStyle = "#30363d";
    ctx.lineWidth = 0.5;
    for (var g = 0; g <= 5; g++) {
        var gy = margin.top + plotH * g / 5;
        ctx.beginPath(); ctx.moveTo(margin.left, gy); ctx.lineTo(w - margin.right, gy); ctx.stroke();
    }
    for (var gx = 0; gx <= 8; gx++) {
        var gxPos = margin.left + plotW * gx / 8;
        ctx.beginPath(); ctx.moveTo(gxPos, margin.top); ctx.lineTo(gxPos, h - margin.bottom); ctx.stroke();
    }

    // Noise floor line
    var noiseFloor = snapshot.noise_floor_dbm;
    if (noiseFloor != null) {
        var nfY = margin.top + plotH - ((noiseFloor - minPwr) / pwrRange) * plotH;
        ctx.strokeStyle = "#f0883e";
        ctx.lineWidth = 1;
        ctx.setLineDash([6, 4]);
        ctx.beginPath();
        ctx.moveTo(margin.left, nfY);
        ctx.lineTo(w - margin.right, nfY);
        ctx.stroke();
        ctx.setLineDash([]);
    }

    // PSD trace
    ctx.strokeStyle = "#58a6ff";
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    var started = false;
    for (var j = 0; j < psd.length; j++) {
        if (psd[j] == null) continue;
        var px = margin.left + (j / psd.length) * plotW;
        var py = margin.top + plotH - ((psd[j] - minPwr) / pwrRange) * plotH;
        if (!started) { ctx.moveTo(px, py); started = true; }
        else { ctx.lineTo(px, py); }
    }
    ctx.stroke();

    // Historical average overlay (dashed line) when comparison is active
    if (this._showComparison && this._comparison && this._comparison.avg_psd) {
        var avgPsd = this._comparison.avg_psd;
        ctx.strokeStyle = "#a371f7";
        ctx.lineWidth = 1.2;
        ctx.setLineDash([6, 4]);
        ctx.beginPath();
        var avgStarted = false;
        for (var ai = 0; ai < avgPsd.length && ai < psd.length; ai++) {
            if (avgPsd[ai] == null) continue;
            var ax = margin.left + (ai / psd.length) * plotW;
            var ay = margin.top + plotH - ((avgPsd[ai] - minPwr) / pwrRange) * plotH;
            if (!avgStarted) { ctx.moveTo(ax, ay); avgStarted = true; }
            else { ctx.lineTo(ax, ay); }
        }
        ctx.stroke();
        ctx.setLineDash([]);
    }

    // Peak markers overlay with signal class annotations
    var nodeId = snapshot.node_id;
    for (var pk = 0; pk < this._peaks.length; pk++) {
        var peak = this._peaks[pk];
        if (peak.node_id !== nodeId) continue;
        var peakFreq = peak.freq_hz;
        if (peakFreq < startFreq || peakFreq > startFreq + bandwidth) continue;

        var peakBin = (peakFreq - startFreq) / binWidth;
        var pkX = margin.left + (peakBin / psd.length) * plotW;
        var pkY = margin.top + plotH - ((peak.power_dbm - minPwr) / pwrRange) * plotH;

        ctx.beginPath();
        ctx.arc(pkX, pkY, 5, 0, Math.PI * 2);
        ctx.fillStyle = peak.classified ? "#3fb950" : "#f85149";
        ctx.fill();
        ctx.strokeStyle = peak.classified ? "#3fb950" : "#f85149";
        ctx.lineWidth = 1;
        ctx.stroke();

        // Signal class label for classified peaks
        if (peak.classified && peak.signal_class) {
            ctx.fillStyle = "#3fb950";
            ctx.font = "9px sans-serif";
            ctx.textAlign = "center";
            ctx.fillText(peak.signal_class, pkX, pkY - 8);
        }
    }

    // Frequency axis labels (bottom)
    ctx.fillStyle = "#8b949e";
    ctx.font = "10px monospace";
    ctx.textAlign = "center";
    for (var fl = 0; fl <= 8; fl++) {
        var fxp = margin.left + plotW * fl / 8;
        var fVal = startFreq + bandwidth * fl / 8;
        ctx.fillText((fVal / 1e6).toFixed(1) + " MHz", fxp, h - margin.bottom + 15);
    }

    // Power axis labels (left)
    ctx.textAlign = "right";
    for (var pl = 0; pl <= 5; pl++) {
        var pYL = margin.top + plotH * pl / 5;
        var pVal = maxPwr - (maxPwr - minPwr) * pl / 5;
        ctx.fillText(pVal.toFixed(0) + " dBm", margin.left - 4, pYL + 3);
    }

    // Title
    ctx.fillStyle = "#c9d1d9";
    ctx.font = "11px sans-serif";
    ctx.textAlign = "left";
    ctx.fillText(
        snapshot.node_id + " | " + (centerFreq / 1e6).toFixed(1) + " MHz | BW: " + (bandwidth / 1e6).toFixed(1) + " MHz",
        margin.left + 4, margin.top + 12
    );
};

WidebandMonitor.prototype._peakGroupKey = function(p) {
    var key = this._peaksGroupBy;
    if (key === "frequency") {
        // Group by frequency rounded to 100 kHz
        var mhz = ((p.freq_hz || 0) / 1e6);
        return mhz.toFixed(1) + " MHz";
    }
    if (key === "node_id") return p.node_id || "unknown";
    if (key === "signal_class") return p.signal_class || "unclassified";
    return "";
};

WidebandMonitor.prototype._renderPeakRow = function(p) {
    var freqMhz = (p.freq_hz / 1e6).toFixed(3) + " MHz";
    var power = p.power_dbm != null ? p.power_dbm.toFixed(1) + " dBm" : "--";
    var nf = p.noise_floor_dbm != null ? p.noise_floor_dbm.toFixed(1) + " dBm" : "--";
    var ts = p.timestamp ? _saFmtTime(p.timestamp) : "--";
    var statusLabel = p.classified
        ? '<span style="color:var(--accent-green);">Classified</span>'
        : '<span style="color:var(--accent-red);font-weight:600;">UNCLASSIFIED</span>';

    var peakClass = p.signal_class ? _saEsc(p.signal_class) : "";
    var peakFreqHz = _saEsc(p.freq_hz || 0);

    return "<tr class=\"wb-peak-row\" data-peak-freq=\"" + peakFreqHz + "\" data-peak-class=\"" + peakClass + "\">"
        + "<td><span class=\"drilldown-link\" data-drilldown-peak-freq=\"" + peakFreqHz + "\" title=\"View in Spectrum band occupancy\">" + _saEsc(freqMhz) + "</span></td>"
        + "<td>" + _saEsc(power) + "</td>"
        + "<td>" + _saEsc(nf) + "</td>"
        + "<td>" + _saEsc(p.node_id || "--") + "</td>"
        + "<td>" + _saEsc(ts) + "</td>"
        + "<td>" + statusLabel + (peakClass ? " <span class=\"drilldown-link\" data-drilldown-peak-class=\"" + peakClass + "\" title=\"View " + peakClass + " in RF Intelligence\">" + peakClass + "</span>" : "") + "</td>"
        + "</tr>";
};

WidebandMonitor.prototype._renderPeaksTable = function(peaks) {
    var self = this;
    var tbody = document.getElementById("wb-peaks-tbody");
    var empty = document.getElementById("wb-peaks-empty");
    var badge = document.getElementById("wb-peaks-badge");
    if (!tbody) return;

    if (badge) badge.textContent = String(peaks.length);

    if (peaks.length === 0) {
        tbody.innerHTML = "";
        if (empty) empty.style.display = "";
        return;
    }
    if (empty) empty.style.display = "none";

    var html = "";
    var shown = peaks.slice(0, 200);

    if (self._peaksGroupBy) {
        // Build groups
        var groups = {};
        var groupOrder = [];
        for (var i = 0; i < shown.length; i++) {
            var gk = self._peakGroupKey(shown[i]);
            if (!groups[gk]) { groups[gk] = []; groupOrder.push(gk); }
            groups[gk].push(shown[i]);
        }

        // Sort groups: by count descending
        groupOrder.sort(function(a, b) { return groups[b].length - groups[a].length; });

        for (var gi = 0; gi < groupOrder.length; gi++) {
            var label = groupOrder[gi];
            var items = groups[label];
            var isExpanded = !!self._expandedGroups[label];
            var arrowStyle = isExpanded ? "" : "transform:rotate(-90deg);";

            // Find highest power peak in group
            var best = items[0];
            for (var bi = 1; bi < items.length; bi++) {
                if ((items[bi].power_dbm || -999) > (best.power_dbm || -999)) best = items[bi];
            }
            var bestFreq = (best.freq_hz / 1e6).toFixed(3) + " MHz";
            var bestPwr = best.power_dbm != null ? best.power_dbm.toFixed(1) + " dBm" : "--";
            var bestStatus = best.classified
                ? '<span style="color:var(--accent-green);">Classified</span>'
                : '<span style="color:var(--accent-red);font-weight:600;">UNCLASSIFIED</span>';
            var bestClass = best.signal_class ? " " + _saEsc(best.signal_class) : "";

            html += "<tr class=\"wb-peaks-group-header" + (isExpanded ? "" : " collapsed") + "\" data-peaks-group=\"" + _saEsc(label) + "\" style=\"cursor:pointer;background:var(--bg-secondary);\">"
                + "<td style=\"font-weight:600;padding:6px 10px;white-space:nowrap;\">"
                + "<span style=\"display:inline-block;width:12px;transition:transform .15s;" + arrowStyle + "\">&#9660;</span> "
                + _saEsc(label) + " <span style=\"color:var(--text-secondary);font-weight:400;\">(" + items.length + ")</span>"
                + "</td>"
                + "<td style=\"font-weight:600;\">" + _saEsc(bestPwr) + "</td>"
                + "<td></td>"
                + "<td style=\"color:var(--text-secondary);font-size:11px;\">" + _saEsc(best.node_id || "") + "</td>"
                + "<td style=\"color:var(--text-secondary);font-size:11px;\">" + _saEsc(bestFreq) + "</td>"
                + "<td>" + bestStatus + bestClass + "</td>"
                + "</tr>";
            var rowDisplay = isExpanded ? "" : "none";
            for (var j = 0; j < items.length; j++) {
                html += self._renderPeakRow(items[j]).replace("<tr ", "<tr style=\"display:" + rowDisplay + ";\" ");
            }
        }
    } else {
        for (var k = 0; k < shown.length; k++) {
            html += self._renderPeakRow(shown[k]);
        }
    }

    tbody.innerHTML = html;

    // Group collapse/expand — persists across async refreshes
    tbody.querySelectorAll(".wb-peaks-group-header").forEach(function(hdr) {
        hdr.addEventListener("click", function() {
            var label = this.getAttribute("data-peaks-group");
            var arrow = this.querySelector("span");
            var isCollapsed = this.classList.toggle("collapsed");
            if (isCollapsed) {
                delete self._expandedGroups[label];
            } else {
                self._expandedGroups[label] = true;
            }
            if (arrow) arrow.style.transform = isCollapsed ? "rotate(-90deg)" : "";
            var row = this.nextElementSibling;
            while (row && !row.classList.contains("wb-peaks-group-header")) {
                row.style.display = isCollapsed ? "none" : "";
                row = row.nextElementSibling;
            }
        });
    });

    // Drill-down: peak frequency -> scroll to band in this tab
    tbody.querySelectorAll("[data-drilldown-peak-freq]").forEach(function(link) {
        link.addEventListener("click", function(e) {
            e.stopPropagation();
            var freqHz = parseFloat(this.getAttribute("data-drilldown-peak-freq"));
            if (!freqHz || !window.drillDown) return;
            var bandTbody = document.getElementById("sa-bands-tbody");
            if (!bandTbody) return;
            var freqMhz = freqHz / 1e6;
            var rows = bandTbody.querySelectorAll("tr");
            for (var r = 0; r < rows.length; r++) {
                var cells = rows[r].querySelectorAll("td");
                if (cells.length < 2) continue;
                var rangeText = cells[1].textContent || "";
                var match = rangeText.match(/([\d.]+)\s*-\s*([\d.]+)/);
                if (match) {
                    var minMhz = parseFloat(match[1]);
                    var maxMhz = parseFloat(match[2]);
                    if (freqMhz >= minMhz && freqMhz <= maxMhz) {
                        window.drillDown._highlight(rows[r]);
                        return;
                    }
                }
            }
        });
    });

    // Drill-down: peak signal class -> RF Intelligence tab
    tbody.querySelectorAll("[data-drilldown-peak-class]").forEach(function(link) {
        link.addEventListener("click", function(e) {
            e.stopPropagation();
            var cls = this.getAttribute("data-drilldown-peak-class");
            if (cls && window.drillDown) window.drillDown.toSignalClass(cls);
        });
    });
};

WidebandMonitor.prototype._loadStitched = function() {
    var self = this;
    var nodeSelect = document.getElementById("wb-node-select");
    var nodeId = nodeSelect ? nodeSelect.value : "";
    if (!nodeId) {
        // Need a specific node for stitching
        return;
    }

    self.dashboard.apiFetch("/api/spectrum/monitor/stitch?node_id=" + encodeURIComponent(nodeId) + "&minutes=5")
        .then(function(data) {
            if (!data.stitched) return;
            // Convert stitched data to snapshot-like format for rendering
            var stitchedSnap = {
                node_id: data.node_id,
                timestamp: data.timestamp,
                center_freq_hz: (data.start_freq_hz + data.end_freq_hz) / 2,
                bandwidth_hz: data.end_freq_hz - data.start_freq_hz,
                psd_dbm: data.psd_dbm,
                noise_floor_dbm: data.noise_floor_dbm,
                fft_size: data.total_bins,
                _stitched: true,
                _segment_count: data.segment_count
            };
            self._latestSnapshot = stitchedSnap;
            self._renderPSD(stitchedSnap);
            var badge = document.getElementById("wb-status-badge");
            if (badge) {
                badge.textContent = "Stitched (" + data.segment_count + " segs)";
            }
        })
        .catch(function() {});
};

WidebandMonitor.prototype._loadComparison = function() {
    var self = this;
    var nodeSelect = document.getElementById("wb-node-select");
    var nodeId = nodeSelect ? nodeSelect.value : "";
    if (!nodeId) return;

    var hours = self._getHours();
    self.dashboard.apiFetch("/api/spectrum/monitor/compare?node_id=" + encodeURIComponent(nodeId) + "&hours=" + hours)
        .then(function(data) {
            if (!data.available) {
                self._comparison = null;
                return;
            }
            self._comparison = data;
            if (self._latestSnapshot) {
                self._renderPSD(self._latestSnapshot);
            }
        })
        .catch(function() { self._comparison = null; });
};

WidebandMonitor.prototype._connectWS = function() {
    if (this._ws) return;
    var self = this;
    var proto = location.protocol === "https:" ? "wss:" : "ws:";
    var key = this.dashboard.apiKey || this.dashboard.sessionToken || "";
    var url = proto + "//" + location.host + "/api/spectrum/ws/spectrum-monitor";
    try {
        // Cookie mode: no sub-protocol, the session cookie authenticates.
        this._ws = new WebSocket(url, key ? ["bridge-v1", key] : []);
        this._ws.onmessage = function(evt) {
            try {
                var data = JSON.parse(evt.data);
                if (data.type === "snapshot") {
                    self.refresh();
                }
            } catch (_) {}
        };
        this._ws.onclose = function() { self._ws = null; };
        this._ws.onerror = function() { self._ws = null; };
    } catch (_) {}
};

WidebandMonitor.prototype._disconnectWS = function() {
    if (this._ws) {
        try { this._ws.close(); } catch (_) {}
        this._ws = null;
    }
};


/* ----------------------------------------------------------------
   Initialization — hook into BridgeDashboard
   ---------------------------------------------------------------- */

(function() {
    var _origInit = BridgeDashboard.prototype._initTabs;
    BridgeDashboard.prototype._initTabs = function() {
        _origInit.call(this);
        this.spectrumAnalysis = new SpectrumAnalysis(this);
        this.widebandMonitor = new WidebandMonitor(this);

        // If Spectrum tab was already active before observer started, trigger refresh
        var tab = document.getElementById("tab-spectrum-analysis");
        if (tab && tab.classList.contains("active")) {
            this.spectrumAnalysis._active = true;
            this.spectrumAnalysis.refreshAll();
            this.spectrumAnalysis._startAutoRefresh();
            if (this.widebandMonitor) this.widebandMonitor.activate();
        }
    };
})();
