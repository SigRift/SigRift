/**
 * The Bridge — Detection Dashboard
 * Real-time detection feed, timeline, treemap, heatmap, anomaly queue,
 * and sparkline. Connects via WebSocket and REST polling.
 * Security: All dynamic content is HTML-escaped via esc().
 */
"use strict";

/* ================================================================
   DetectionDashboard Class
   ================================================================ */

function DetectionDashboard(dashboard) {
    this.db = dashboard;
    this.timeRange = 1;      // hours
    this.paused = false;
    this.autoRefresh = true;
    this.feed = [];
    this.anomalies = [];
    this.anomalyHistory = [];  // sparkline values
    this.rfGroupByKey = readBrowserPreference("bridge_rf_group_by") || "";
    this.rfFilterKey = "";
    this.rfFilterVal = "";
    this.rfSortBy = readBrowserPreference("bridge_rf_sort_by") || "score";
    this.rfSummary = null;

    // Debounce timers for WS-triggered renders
    this._feedRenderTimer = null;
    this._kpiThrottleTimer = null;
    this._kpiThrottleMs = 3000;    // max 1 KPI fetch per 3s from WS events

    this.reevalSummary = null;
    this._focusedCardIdx = -1;
    this._selectedRfIds = {};   // map of anomaly id -> true for bulk selection

    this._active = false;

    this._initControls();
    this._initLegendToggle();
    this._initAnomalyFilterControls();
    this._initReevalControls();
    this._initBulkSelection();
    this._initKeyboardShortcuts();
    this._connectWS();
}

/* -- Keyboard shortcuts ----------------------------------------- */

DetectionDashboard.prototype._initKeyboardShortcuts = function() {
    var s = this;
    document.addEventListener("keydown", function(e) {
        // Skip if user is typing in an input/textarea or a modal is open
        var tag = (e.target.tagName || "").toLowerCase();
        if (tag === "input" || tag === "textarea" || tag === "select") return;
        var deepDive = document.getElementById("deep-dive-overlay");
        if (deepDive && deepDive.style.display !== "none") return;

        var cards = document.querySelectorAll("#anomaly-queue .anomaly-card");
        if (!cards.length) return;

        switch (e.key) {
            case "j": // next anomaly
            case "ArrowDown":
                e.preventDefault();
                s._focusedCardIdx = Math.min(s._focusedCardIdx + 1, cards.length - 1);
                s._highlightCard(cards);
                break;
            case "k": // previous anomaly
            case "ArrowUp":
                e.preventDefault();
                s._focusedCardIdx = Math.max(s._focusedCardIdx - 1, 0);
                s._highlightCard(cards);
                break;
            case "d": // dismiss focused
                if (s._focusedCardIdx < 0 || s._focusedCardIdx >= cards.length) return;
                e.preventDefault();
                var dismissBtn = cards[s._focusedCardIdx].querySelector("[data-dismiss-rf],[data-dismiss-group]");
                if (dismissBtn) dismissBtn.click();
                break;
            case "i": // investigate focused
            case "Enter":
                if (s._focusedCardIdx < 0 || s._focusedCardIdx >= cards.length) return;
                e.preventDefault();
                var invBtn = cards[s._focusedCardIdx].querySelector("[data-investigate-idx],[data-investigate-group]");
                if (invBtn) invBtn.click();
                break;
            case "b": // baseline focused
                if (s._focusedCardIdx < 0 || s._focusedCardIdx >= cards.length) return;
                e.preventDefault();
                var baseBtn = cards[s._focusedCardIdx].querySelector("[data-baseline-anomaly],[data-baseline-group]");
                if (baseBtn) baseBtn.click();
                break;
            case "?": // R14: toggle shortcut overlay (handled by dashboard.js)
                break;
        }
    });
};

DetectionDashboard.prototype._highlightCard = function(cards) {
    for (var i = 0; i < cards.length; i++) {
        cards[i].classList.remove("focused");
    }
    if (this._focusedCardIdx >= 0 && this._focusedCardIdx < cards.length) {
        cards[this._focusedCardIdx].classList.add("focused");
        cards[this._focusedCardIdx].scrollIntoView({ block: "nearest", behavior: "smooth" });
    }
};

DetectionDashboard.prototype._initLegendToggle = function() {
    var toggle = document.getElementById("anomaly-legend-toggle");
    var body = document.getElementById("anomaly-legend-body");
    var title = document.querySelector(".anomaly-legend-title");
    if (toggle && body) {
        var handler = function() {
            body.style.display = body.style.display === "none" ? "" : "none";
        };
        // The icon sits inside the title in index.html: bind one listener
        // so a click on the icon does not bubble into a second toggle.
        if (title && title.contains(toggle)) {
            title.addEventListener("click", handler);
        } else {
            toggle.addEventListener("click", handler);
            if (title) title.addEventListener("click", handler);
        }
    }
};

/* -- Group toggle ----------------------------------------------- */

DetectionDashboard.prototype._initAnomalyFilterControls = function() {
    var s = this;

    // Group-by dropdown
    var groupSel = document.getElementById("rf-anomaly-group-select");
    if (groupSel) {
        groupSel.value = s.rfGroupByKey;
        groupSel.addEventListener("change", function() {
            s.rfGroupByKey = groupSel.value;
            writeBrowserPreference("bridge_rf_group_by", groupSel.value);
            s._renderAnomalyQueue();
        });
    }

    // Filter key dropdown
    var filterKeySel = document.getElementById("rf-anomaly-filter-key");
    var filterValSel = document.getElementById("rf-anomaly-filter-val");
    if (filterKeySel && filterValSel) {
        filterKeySel.addEventListener("change", function() {
            s.rfFilterKey = filterKeySel.value;
            s.rfFilterVal = "";
            if (!s.rfFilterKey) {
                filterValSel.style.display = "none";
                s._renderAnomalyQueue();
                return;
            }
            // Populate value dropdown from current anomalies
            var vals = s._getRfUniqueFilterValues(s.rfFilterKey);
            var h = "<option value=\"\">All</option>";
            for (var i = 0; i < vals.length; i++) {
                h += "<option value=\"" + esc(vals[i]) + "\">" + esc(vals[i]) + "</option>";
            }
            filterValSel.innerHTML = h;
            filterValSel.style.display = "";
            s._renderAnomalyQueue();
        });

        filterValSel.addEventListener("change", function() {
            s.rfFilterVal = filterValSel.value;
            s._renderAnomalyQueue();
        });
    }

    // Sort dropdown
    var sortSel = document.getElementById("rf-anomaly-sort-select");
    if (sortSel) {
        sortSel.value = s.rfSortBy;
        sortSel.addEventListener("change", function() {
            s.rfSortBy = sortSel.value;
            writeBrowserPreference("bridge_rf_sort_by", sortSel.value);
            s._fetchAnomalies();
        });
    }
};

/* -- RF Anomaly filter helpers ---------------------------------- */

DetectionDashboard.prototype._getRfAnomalyField = function(a, key) {
    switch (key) {
        case "signal_class": return a.signal_class || "Unknown";
        case "family": return a.family || "Unknown";
        case "node_id": return a.node_id || "Unknown";
        case "priority": return a.priority || _anomalyPriority(a.anomaly_score || 0);
        case "band": return _rfBandDescription(a.freq_hz) || "Unknown";
        case "dimension":
            var dims = a.dimensions;
            if (!dims || typeof dims !== "object") return "Unknown";
            var topKey = "", topVal = 0;
            for (var k in dims) {
                if (dims[k] > topVal) { topVal = dims[k]; topKey = k; }
            }
            return topKey || "Unknown";
        default: return "Unknown";
    }
};

DetectionDashboard.prototype._getRfUniqueFilterValues = function(key) {
    var seen = {};
    var vals = [];
    for (var i = 0; i < this.anomalies.length; i++) {
        var v = this._getRfAnomalyField(this.anomalies[i], key);
        if (v && !seen[v]) {
            seen[v] = true;
            vals.push(v);
        }
    }
    vals.sort();
    return vals;
};

DetectionDashboard.prototype._matchesRfFilter = function(a, key, val) {
    if (!key || !val) return true;
    return this._getRfAnomalyField(a, key) === val;
};

/* -- Super-family accent colors --------------------------------- */

DetectionDashboard.SF_COLORS = {
    "CONSTANT_ENVELOPE": "#58a6ff",
    "LINEAR_DIGITAL":    "#3fb950",
    "MULTI_CARRIER":     "#a371f7",
    "AMPLITUDE_ONLY":    "#d29922",
    "ANALOG":            "#f85149",
    "SPREAD_SPECTRUM":   "#79c0ff"
};

DetectionDashboard.CLASS_COLORS = [
    "#58a6ff", "#3fb950", "#a371f7", "#d29922", "#f85149",
    "#79c0ff", "#7ee787", "#d2a8ff", "#e3b341", "#f778ba"
];

/* -- Controls --------------------------------------------------- */

DetectionDashboard.prototype._initControls = function() {
    var s = this;

    // Time range buttons — scoped to detection panel only
    var detPanel = document.getElementById("panel-detections");
    var detBtns = detPanel ? detPanel.querySelectorAll(".det-timeline-btn[data-range]") : [];
    detBtns.forEach(function(btn) {
        btn.addEventListener("click", function() {
            detBtns.forEach(function(b) { b.classList.remove("active"); });
            btn.classList.add("active");
            s.timeRange = parseInt(btn.getAttribute("data-range")) || 1;
            s._fetchAll();
        });
    });

    // Pause button
    var pauseBtn = document.getElementById("det-pause-btn");
    if (pauseBtn) {
        pauseBtn.addEventListener("click", function() {
            s.paused = !s.paused;
            pauseBtn.textContent = s.paused ? "Resume" : "Pause";
        });
    }

    // Auto-refresh checkbox
    var arCb = document.getElementById("det-auto-refresh");
    if (arCb) {
        arCb.addEventListener("change", function() {
            s.autoRefresh = arCb.checked;
        });
    }
};

/* -- Polling ---------------------------------------------------- */

DetectionDashboard.prototype._stopPolling = function() {
    if (this._pollCharts) { clearInterval(this._pollCharts); this._pollCharts = null; }
    if (this._pollFeed) { clearInterval(this._pollFeed); this._pollFeed = null; }
    if (this._pollAnomalies) { clearInterval(this._pollAnomalies); this._pollAnomalies = null; }
    if (this._pollSummary) { clearInterval(this._pollSummary); this._pollSummary = null; }
    if (this._pollIQCommands) { clearInterval(this._pollIQCommands); this._pollIQCommands = null; }
};

DetectionDashboard.prototype.activate = function() {
    if (this._active) return;
    this._active = true;
    this._startPolling();
};

DetectionDashboard.prototype.deactivate = function() {
    this._active = false;
    this._stopPolling();
};

DetectionDashboard.prototype._startPolling = function() {
    var s = this;
    s._stopPolling();
    s._fetchKPIs();
    s._fetchFeed();
    setTimeout(function() { if (s._active) s._fetchCharts(); }, 1000);
    setTimeout(function() { if (s._active) s._fetchAnomalies(); }, 2000);
    setTimeout(function() { if (s._active) s._fetchAnomalySummary(); }, 3000);
    setTimeout(function() { if (s._active) s._initIQCaptures(); }, 4000);
    s._pollCharts = setInterval(function() {
        if (!s.paused && s.autoRefresh && isPageActive() && s._active) {
            s._fetchKPIs();
            s._fetchCharts();
        }
    }, 15000);
    s._pollFeed = setInterval(function() {
        if (!s.paused && s.autoRefresh && isPageActive() && s._active) s._fetchFeed();
    }, 8000);
    s._pollAnomalies = setInterval(function() {
        if (!s.paused && s.autoRefresh && isPageActive() && s._active) s._fetchAnomalies();
    }, 8000);
    s._pollSummary = setInterval(function() {
        if (!s.paused && s.autoRefresh && isPageActive() && s._active) s._fetchAnomalySummary();
    }, 15000);
};

DetectionDashboard.prototype._fetchAll = function() {
    this._fetchKPIs();
    this._fetchCharts();
    this._fetchFeed();
    this._fetchAnomalies();
};

DetectionDashboard.prototype._fetchCharts = function() {
    this._fetchTimeline();
    this._fetchDistribution();
    this._fetchHeatmap();
};

/* -- KPIs ------------------------------------------------------- */

DetectionDashboard.prototype._fetchKPIs = function() {
    var s = this;
    s.db.apiFetch("/api/detections/stats?hours=" + s.timeRange)
        .then(function(d) {
            var dps = d.detections_per_second != null ? d.detections_per_second : 0;
            setText("det-kpi-rate", dps.toFixed(1) + "/sec");
            setText("det-kpi-classes", d.unique_classes != null ? d.unique_classes : "--");
            setText("det-kpi-confidence", d.avg_confidence != null ? (d.avg_confidence * 100).toFixed(0) + "%" : "--");
            // Server count: raw positive 100 kHz bins in the last hour.
            // The recent feed is a limited sample, not the statistics source.
            var freqCount = d.active_frequencies;
            setText("det-kpi-freqs", Number.isSafeInteger(freqCount) && freqCount >= 0 ? freqCount : "--");
        })
        .catch(function(e) {
            trackFetchError("det-kpis", e);
            if (typeof setLoadingState === "function") {
                setLoadingState("det-kpi-row", false, "Failed to load KPIs", "window.dashboard.detectionDashboard._fetchKPIs.bind(window.dashboard.detectionDashboard)");
            }
        });
    // Anomaly count for this time range
    s.db.apiFetch("/api/detections/anomalies?min_score=0.3&limit=1000")
        .then(function(d) {
            var cnt = d.count != null ? d.count : (d.anomalies ? d.anomalies.length : 0);
            setText("det-kpi-anomalies", cnt);
        })
        .catch(function(e) { trackFetchError("det-anomaly-count", e); });
};

/* -- Detection Rate Timeline ------------------------------------ */

DetectionDashboard.prototype._fetchTimeline = function() {
    var s = this;
    var cv = document.getElementById("det-timeline-canvas");
    if (cv) {
        var ctx = cv.getContext("2d");
        ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--bg-primary").trim() || "#0d1117";
        ctx.fillRect(0, 0, cv.width, cv.height);
        ctx.fillStyle = "#8b949e";
        ctx.font = "12px sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("Loading timeline...", cv.width / 2, cv.height / 2);
    }
    s.db.apiFetch("/api/detections/timeline?hours=" + s.timeRange)
        .then(function(d) {
            // API returns [{bucket, count, avg_confidence, classes}, ...]
            // Renderer expects {series: [{values, super_family}], timestamps: []}
            if (!d || !d.length) { s._renderTimeline(null); return; }
            var timestamps = [];
            var values = [];
            for (var i = 0; i < d.length; i++) {
                timestamps.push(d[i].bucket);
                values.push(d[i].count || 0);
            }
            s._renderTimeline({
                series: [{ values: values, super_family: "LINEAR_DIGITAL" }],
                timestamps: timestamps
            });
        })
        .catch(function(e) {
            trackFetchError("det-timeline", e);
            var cv = document.getElementById("det-timeline-canvas");
            if (cv) {
                var ctx = cv.getContext("2d");
                ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--bg-primary").trim() || "#0d1117";
                ctx.fillRect(0, 0, cv.width, cv.height);
                ctx.fillStyle = "#f85149";
                ctx.font = "12px sans-serif";
                ctx.textAlign = "center";
                ctx.fillText("Failed to load timeline", cv.width / 2, cv.height / 2);
            }
        });
};

DetectionDashboard.prototype._renderTimeline = function(data) {
    var cv = document.getElementById("det-timeline-canvas");
    if (!cv) return;
    ChartUtils.resizeCanvas(cv);
    var ctx = cv.getContext("2d");

    if (!data || !data.series || !data.series.length || !data.timestamps || !data.timestamps.length) {
        ChartUtils.clearCanvas(ctx, cv);
        ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--text-secondary").trim() || "#8b949e";
        ctx.font = "12px sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("No timeline data", cv.width / 2, cv.height / 2);
        return;
    }

    // Build stacked area data: array of series, each an array of values
    var seriesData = [];
    var colors = [];
    for (var i = 0; i < data.series.length; i++) {
        seriesData.push(data.series[i].values || []);
        var sfColor = DetectionDashboard.SF_COLORS[data.series[i].super_family];
        colors.push(sfColor || DetectionDashboard.CLASS_COLORS[i % DetectionDashboard.CLASS_COLORS.length]);
    }

    // Time labels
    var timeLabels = [];
    for (var t = 0; t < data.timestamps.length; t++) {
        timeLabels.push(ChartUtils.formatTime(data.timestamps[t]));
    }

    ChartUtils.drawStackedArea(ctx, cv, seriesData, colors, timeLabels, "Detections");
};

/* -- Class Distribution Treemap --------------------------------- */

DetectionDashboard.prototype._fetchDistribution = function() {
    var s = this;
    var cv = document.getElementById("det-treemap-canvas");
    if (cv) {
        var ctx = cv.getContext("2d");
        ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--bg-primary").trim() || "#0d1117";
        ctx.fillRect(0, 0, cv.width, cv.height);
        ctx.fillStyle = "#8b949e";
        ctx.font = "12px sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("Loading class distribution...", cv.width / 2, cv.height / 2);
    }
    s.db.apiFetch("/api/detections/distribution?hours=" + s.timeRange)
        .then(function(d) {
            // API returns [{signal_class, family, count, avg_confidence}, ...]
            // Renderer expects {classes: [{name, count, super_family}, ...]}
            if (!d || !d.length) { s._renderTreemap(null); return; }
            var classes = [];
            for (var i = 0; i < d.length; i++) {
                classes.push({
                    name: d[i].signal_class,
                    count: d[i].count || 0,
                    super_family: _familyToSuperFamily(d[i].family)
                });
            }
            s._renderTreemap({ classes: classes });
        })
        .catch(function(e) {
            trackFetchError("det-distribution", e);
            s._renderTreemap(null);
        });
};

DetectionDashboard.prototype._renderTreemap = function(data) {
    var cv = document.getElementById("det-treemap-canvas");
    if (!cv) return;
    ChartUtils.resizeCanvas(cv);
    var ctx = cv.getContext("2d");

    if (!data || !data.classes || !data.classes.length) {
        ChartUtils.clearCanvas(ctx, cv);
        ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--text-secondary").trim() || "#8b949e";
        ctx.font = "12px sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("No class data", cv.width / 2, cv.height / 2);
        return;
    }

    var items = [];
    for (var i = 0; i < data.classes.length; i++) {
        var c = data.classes[i];
        items.push({ label: c.name || c.class_name, value: c.count || 0, super_family: c.super_family });
    }

    ChartUtils.drawTreemap(ctx, cv, items, function(item, idx) {
        if (item.super_family && DetectionDashboard.SF_COLORS[item.super_family]) {
            return DetectionDashboard.SF_COLORS[item.super_family];
        }
        return DetectionDashboard.CLASS_COLORS[idx % DetectionDashboard.CLASS_COLORS.length];
    });
};

/* -- Frequency x Time Heatmap ----------------------------------- */

DetectionDashboard.prototype._fetchHeatmap = function() {
    var s = this;
    var cv = document.getElementById("det-heatmap-canvas");
    if (cv) {
        var ctx = cv.getContext("2d");
        ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--bg-primary").trim() || "#0d1117";
        ctx.fillRect(0, 0, cv.width, cv.height);
        ctx.fillStyle = "#8b949e";
        ctx.font = "12px sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("Loading frequency heatmap...", cv.width / 2, cv.height / 2);
    }
    // Pick resolution to match the time range — shorter ranges get finer buckets
    var res = s.timeRange <= 1 ? 5 : (s.timeRange <= 6 ? 10 : (s.timeRange <= 24 ? 15 : 60));
    s.db.apiFetch("/api/detections/heatmap?hours=" + s.timeRange + "&resolution=" + res)
        .then(function(d) {
            // API returns [{time_bucket, freq_bucket_mhz, count, dominant_class}, ...]
            // Renderer expects {matrix: [[...]], time_labels: [...], freq_labels: [...]}
            if (!d || !d.length) { s._renderHeatmap(null); return; }

            // Collect unique time and freq buckets
            var timeSet = {}, freqSet = {};
            for (var i = 0; i < d.length; i++) {
                timeSet[d[i].time_bucket] = true;
                freqSet[d[i].freq_bucket_mhz] = true;
            }
            var timeBuckets = Object.keys(timeSet).map(Number).sort(function(a, b) { return a - b; });
            var freqBuckets = Object.keys(freqSet).map(Number).sort(function(a, b) { return a - b; });

            // Fill frequency gaps to prevent solid horizontal bars when
            // few frequencies are active (e.g., 10 freq rows → thick bars).
            // Insert intermediate empty rows so active bands appear as thin
            // colored lines with dark gaps between them.
            if (freqBuckets.length > 1 && freqBuckets.length < 40) {
                var minF = freqBuckets[0], maxF = freqBuckets[freqBuckets.length - 1];
                var freqRange = maxF - minF;
                if (freqRange > 0) {
                    var step = Math.max(1, Math.ceil(freqRange / 80));
                    var expanded = {};
                    for (var ff = minF; ff <= maxF; ff += step) expanded[ff] = true;
                    for (var ef = 0; ef < freqBuckets.length; ef++) expanded[freqBuckets[ef]] = true;
                    freqBuckets = Object.keys(expanded).map(Number).sort(function(a, b) { return a - b; });
                }
            }

            // Build index maps
            var timeIdx = {}, freqIdx = {};
            for (var t = 0; t < timeBuckets.length; t++) timeIdx[timeBuckets[t]] = t;
            for (var f = 0; f < freqBuckets.length; f++) freqIdx[freqBuckets[f]] = f;

            // Build matrix[freq_row][time_col] = count
            var matrix = [];
            for (var r = 0; r < freqBuckets.length; r++) {
                matrix.push(new Array(timeBuckets.length).fill(0));
            }
            for (var j = 0; j < d.length; j++) {
                var ri = freqIdx[d[j].freq_bucket_mhz];
                var ci = timeIdx[d[j].time_bucket];
                matrix[ri][ci] = d[j].count;
            }

            // Time labels — compute from (now - timeRange) + bucket * resolution
            var startMs = Date.now() - s.timeRange * 3600000;
            var timeLabels = timeBuckets.map(function(tb) {
                return new Date(startMs + tb * res * 60000).toISOString();
            });
            // Freq labels as Hz values (formatFreq will add MHz suffix)
            var freqLabels = freqBuckets.map(function(fb) { return fb * 1e6; });

            s._renderHeatmap({ matrix: matrix, time_labels: timeLabels, freq_labels: freqLabels });
        })
        .catch(function(e) {
            trackFetchError("det-heatmap", e);
            var cv = document.getElementById("det-heatmap-canvas");
            if (cv) {
                var ctx = cv.getContext("2d");
                ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--bg-primary").trim() || "#0d1117";
                ctx.fillRect(0, 0, cv.width, cv.height);
                ctx.fillStyle = "#f85149";
                ctx.font = "12px sans-serif";
                ctx.textAlign = "center";
                ctx.fillText("Failed to load heatmap", cv.width / 2, cv.height / 2);
            }
        });
};

DetectionDashboard.prototype._renderHeatmap = function(data) {
    var cv = document.getElementById("det-heatmap-canvas");
    if (!cv) return;
    ChartUtils.resizeCanvas(cv);
    var ctx = cv.getContext("2d");

    if (!data || !data.matrix || !data.matrix.length) {
        ChartUtils.clearCanvas(ctx, cv);
        ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--text-secondary").trim() || "#8b949e";
        ctx.font = "12px sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("No heatmap data", cv.width / 2, cv.height / 2);
        return;
    }

    // X labels = time, Y labels = frequency bands
    var xLabels = [];
    if (data.time_labels) {
        for (var t = 0; t < data.time_labels.length; t++) {
            xLabels.push(ChartUtils.formatTime(data.time_labels[t]));
        }
    }
    var yLabels = [];
    if (data.freq_labels) {
        for (var f = 0; f < data.freq_labels.length; f++) {
            yLabels.push(ChartUtils.formatFreq(data.freq_labels[f]));
        }
    }

    ChartUtils.drawHeatmap(ctx, cv, data.matrix, xLabels, yLabels);

    // Heatmap legend
    var legend = document.getElementById("heatmap-legend");
    if (legend && !legend.hasChildNodes()) {
        var cmap = ChartUtils.buildColormap();
        var bar = document.createElement("canvas");
        bar.width = 200; bar.height = 12;
        var bCtx = bar.getContext("2d");
        for (var px = 0; px < 200; px++) {
            var ci = Math.floor((px / 199) * (cmap.length - 1));
            var rgb = cmap[ci];
            bCtx.fillStyle = "rgb(" + rgb[0] + "," + rgb[1] + "," + rgb[2] + ")";
            bCtx.fillRect(px, 0, 1, 12);
        }
        var low = document.createElement("span");
        low.className = "legend-label"; low.textContent = "Low";
        var high = document.createElement("span");
        high.className = "legend-label"; high.textContent = "High";
        legend.appendChild(low);
        legend.appendChild(bar);
        legend.appendChild(high);
    }
};

/* -- Detection Feed --------------------------------------------- */

DetectionDashboard.prototype._fetchFeed = function() {
    var s = this;
    var tb = document.getElementById("det-feed-tbody");
    if (tb && !tb.innerHTML) {
        tb.innerHTML = '<tr><td colspan="8"><div class="loading-container"><div class="loading-spinner"></div>Loading detection feed...</div></td></tr>';
    }
    s.db.apiFetch("/api/detections/recent?minutes=" + (s.timeRange * 60) + "&limit=50")
        .then(function(d) {
            clearFetchError("det-feed");
            // API returns {count, minutes, detections: [...]}
            var dets = (d && d.detections) ? d.detections : (Array.isArray(d) ? d : []);
            // Add freq_band from freq_hz for display grouping
            for (var i = 0; i < dets.length; i++) {
                if (!dets[i].freq_band && dets[i].freq_hz) {
                    dets[i].freq_band = ChartUtils.formatFreq(dets[i].freq_hz);
                }
            }
            s.feed = dets;
            s._renderFeed();
        })
        .catch(function(e) {
            trackFetchError("det-feed", e);
            if (tb) {
                tb.innerHTML = '<tr><td colspan="8"><div class="error-state"><span class="error-icon">⚠</span><p>Failed to load detection feed</p><button class="retry-btn">Retry</button></div></td></tr>';
                var rb = tb.querySelector(".retry-btn");
                if (rb) rb.addEventListener("click", function() { if (window.dashboard && window.dashboard.detectionDashboard) window.dashboard.detectionDashboard._fetchFeed(); });
            }
        });
};

DetectionDashboard.prototype._renderFeed = function() {
    var tb = document.getElementById("det-feed-tbody");
    var em = document.getElementById("det-feed-empty");
    if (!tb) return;

    setText("det-count-badge", this.feed.length);

    if (!this.feed.length) {
        tb.innerHTML = "";
        if (em) em.style.display = "";
        return;
    }
    if (em) em.style.display = "none";

    // Group detections by class + freq band
    var groups = {};
    for (var i = 0; i < this.feed.length; i++) {
        var det = this.feed[i];
        var key = (det.signal_class || "unknown") + "|" + (det.freq_band || "--");
        if (!groups[key]) {
            groups[key] = {
                representative: det,
                signal_class: det.signal_class || "unknown",
                freq_band: det.freq_band || "--",
                nodes: {},
                count: 0,
                totalConf: 0,
                totalSNR: 0,
                snrCount: 0,
                anomaly: false,
                totalAnomalyScore: 0,
                anomalyScoreCount: 0,
                baselineStatuses: {}
            };
        }
        var g = groups[key];
        g.count++;
        if (det.node_id) g.nodes[det.node_id] = true;
        if (det.confidence != null) g.totalConf += det.confidence;
        if (det.snr_db != null) { g.totalSNR += det.snr_db; g.snrCount++; }
        if (det.is_anomaly) g.anomaly = true;
        if (det.anomaly_score != null) { g.totalAnomalyScore += det.anomaly_score; g.anomalyScoreCount++; }
        if (det.baseline_status) g.baselineStatuses[det.baseline_status] = (g.baselineStatuses[det.baseline_status] || 0) + 1;
    }

    var keys = Object.keys(groups);
    keys.sort(function(a, b) { return groups[b].count - groups[a].count; });

    var h = "";
    for (var j = 0; j < keys.length; j++) {
        var gr = groups[keys[j]];
        var nodeList = Object.keys(gr.nodes);
        var avgConf = gr.count > 0 ? (gr.totalConf / gr.count) : 0;
        var avgSNR = gr.snrCount > 0 ? (gr.totalSNR / gr.snrCount) : 0;
        var anomCls = gr.anomaly ? " anomaly-row" : "";

        // Baseline status: pick the dominant one
        var bsKeys = Object.keys(gr.baselineStatuses);
        var baselineStatus = bsKeys.length > 0 ? bsKeys.sort(function(a, b) { return gr.baselineStatuses[b] - gr.baselineStatuses[a]; })[0] : "";
        var baselineHtml = baselineStatus ? "<span class=\"baseline-badge " + esc(baselineStatus) + "\">" + esc(baselineStatus) + "</span>" : "--";

        // Anomaly score
        var avgAnomalyScore = gr.anomalyScoreCount > 0 ? gr.totalAnomalyScore / gr.anomalyScoreCount : -1;
        var scorePri = avgAnomalyScore >= 0 ? _anomalyPriority(avgAnomalyScore) : "";
        var scoreHtml = avgAnomalyScore >= 0
            ? "<span class=\"feed-anomaly-score score-" + scorePri + "\">" + avgAnomalyScore.toFixed(2) + "</span>"
            : "--";

        h += "<tr class=\"det-feed-row" + anomCls + "\" data-dd-class=\"" + esc(gr.signal_class) + "\" data-dd-freq=\"" + esc(gr.freq_band) + "\">"
            + "<td><span class=\"drilldown-link\" data-drilldown-class=\"" + esc(gr.signal_class) + "\" title=\"View in RF Intelligence\">" + esc(gr.signal_class) + "</span></td>"
            + "<td><span class=\"drilldown-link\" data-drilldown-freq=\"" + esc(gr.freq_band) + "\" title=\"View in Spectrum Analysis\">" + esc(gr.freq_band) + "</span></td>"
            + "<td>" + esc(nodeList.join(", ") || "--") + "</td>"
            + "<td>" + gr.count + "</td>"
            + "<td>" + (avgConf * 100).toFixed(0) + "%</td>"
            + "<td>" + (gr.snrCount > 0 ? avgSNR.toFixed(1) + " dB" : "--") + "</td>"
            + "<td>" + baselineHtml + "</td>"
            + "<td>" + scoreHtml + "</td>"
            + "</tr>";
    }
    tb.innerHTML = h;

    // Click feed rows to deep-dive
    var s = this;
    tb.querySelectorAll(".det-feed-row").forEach(function(row) {
        row.style.cursor = "pointer";
        row.addEventListener("click", function(e) {
            // Skip if user clicked a drill-down link (handled separately)
            if (e.target.closest && e.target.closest(".drilldown-link")) return;
            var cls = this.getAttribute("data-dd-class");
            var freq = this.getAttribute("data-dd-freq");
            var group = groups[cls + "|" + freq];
            s._showDeepDive(group ? group.representative : { signal_class: cls, freq_band: freq });
        });
    });

    // Drill-down: signal class -> RF Intelligence filtered by that class
    tb.querySelectorAll("[data-drilldown-class]").forEach(function(link) {
        link.addEventListener("click", function(e) {
            e.stopPropagation();
            var cls = this.getAttribute("data-drilldown-class");
            if (cls && window.drillDown) window.drillDown.toSignalClass(cls);
        });
    });

    // Drill-down: frequency -> Spectrum Analysis filtered to that band
    tb.querySelectorAll("[data-drilldown-freq]").forEach(function(link) {
        link.addEventListener("click", function(e) {
            e.stopPropagation();
            var freqText = this.getAttribute("data-drilldown-freq");
            // Parse frequency text like "433.920 MHz" to Hz
            var freqHz = null;
            var m = freqText.match(/([\d.]+)\s*MHz/i);
            if (m) freqHz = parseFloat(m[1]) * 1e6;
            else {
                m = freqText.match(/([\d.]+)\s*GHz/i);
                if (m) freqHz = parseFloat(m[1]) * 1e9;
            }
            if (freqHz && window.drillDown) window.drillDown.toSpectrum(freqHz);
        });
    });
};

/* -- Anomaly Queue ---------------------------------------------- */

DetectionDashboard.prototype._fetchAnomalies = function() {
    var s = this;
    var c = document.getElementById("anomaly-queue");
    if (c && !c.innerHTML) {
        c.innerHTML = '<div class="loading-container"><div class="loading-spinner"></div>Loading anomalies...</div>';
    }
    var qs = "?limit=50&sort=" + encodeURIComponent(s.rfSortBy);
    s.db.apiFetch("/api/detections/anomalies" + qs)
        .then(function(d) {
            clearFetchError("anomalies");
            s.anomalies = d.anomalies || d || [];
            s.anomalyTotal = d.total || s.anomalies.length;
            if (d.timeline) s.anomalyHistory = d.timeline;
            s.reevalSummary = null;
            s._updateRfReevalSummary(null);
            s._renderAnomalyQueue();
            s._renderAnomalySparkline();
            // Refresh filter value dropdown if filter is active
            if (s.rfFilterKey) {
                var filterValSel = document.getElementById("rf-anomaly-filter-val");
                if (filterValSel) {
                    var curVal = s.rfFilterVal;
                    var vals = s._getRfUniqueFilterValues(s.rfFilterKey);
                    var h = "<option value=\"\">All</option>";
                    for (var i = 0; i < vals.length; i++) {
                        h += "<option value=\"" + esc(vals[i]) + "\"" + (vals[i] === curVal ? " selected" : "") + ">" + esc(vals[i]) + "</option>";
                    }
                    filterValSel.innerHTML = h;
                }
            }
        })
        .catch(function(e) {
            trackFetchError("anomalies", e);
            var c = document.getElementById("anomaly-queue");
            if (c) {
                c.innerHTML = '<div class="error-state"><span class="error-icon">⚠</span><p>Failed to load anomalies</p><button class="retry-btn">Retry</button></div>';
                var rb = c.querySelector(".retry-btn");
                if (rb) rb.addEventListener("click", function() { if (window.dashboard && window.dashboard.detectionDashboard) window.dashboard.detectionDashboard._fetchAnomalies(); });
            }
        });
};

DetectionDashboard.prototype._renderAnomalyQueue = function() {
    var c = document.getElementById("anomaly-queue");
    var em = document.getElementById("anomaly-empty");
    if (!c) return;

    // Apply client-side filter
    var filtered = this.anomalies;
    var s = this;
    if (this.rfFilterKey && this.rfFilterVal) {
        filtered = this.anomalies.filter(function(a) {
            return s._matchesRfFilter(a, s.rfFilterKey, s.rfFilterVal);
        });
    }

    var total = this.anomalyTotal || this.anomalies.length;
    var shownText = filtered.length < this.anomalies.length
        ? filtered.length + " / " + total
        : (total > this.anomalies.length ? this.anomalies.length + " / " + total : String(this.anomalies.length));
    setText("anomaly-count-badge", shownText);
    setText("stat-anomaly-detail", total + " active");

    // Forget selected anomalies that are no longer in the queue.
    var present = {};
    var selectable = this._rfSelectableIds();
    for (var p = 0; p < selectable.length; p++) present[selectable[p]] = true;
    for (var sid in this._selectedRfIds) {
        if (!present[sid]) delete this._selectedRfIds[sid];
    }
    // Forget timeline pushes of anomalies no longer loaded, so one that
    // comes back later is pushed again.
    var presentKeys = {};
    for (var pk = 0; pk < this.anomalies.length; pk++) {
        var tkey = _rfTimelineKey(this.anomalies[pk]);
        if (tkey) presentKeys[tkey] = true;
    }
    for (var tk in (this._tlPushedKeys || {})) {
        if (!presentKeys[tk]) delete this._tlPushedKeys[tk];
    }

    if (!filtered.length) {
        c.innerHTML = "";
        if (em) em.style.display = "";
        // No cards are bound below, so refresh the bulk bar here: it hides
        // once the queue is empty.
        this._updateRfBulkBar();
        return;
    }
    if (em) em.style.display = "none";

    if (this.rfGroupByKey) {
        this._renderAnomalyQueueGrouped(c, filtered);
    } else {
        // R4: Severity-separated sections
        this._renderAnomalyQueueSeveritySections(c, filtered);
    }
};

DetectionDashboard.prototype._renderAnomalyQueueSeveritySections = function(c, items) {
    var buckets = { critical: [], anomalous: [], interesting: [] };
    for (var i = 0; i < items.length; i++) {
        var score = items[i].anomaly_score != null ? items[i].anomaly_score : 0;
        var pri = items[i].priority || _anomalyPriority(score);
        if (pri === "critical") buckets.critical.push(items[i]);
        else if (pri === "anomalous") buckets.anomalous.push(items[i]);
        else buckets.interesting.push(items[i]);
    }

    var h = "";
    var sections = [
        { key: "critical", label: "Critical", items: buckets.critical },
        { key: "anomalous", label: "Anomalous", items: buckets.anomalous },
        { key: "interesting", label: "Interesting", items: buckets.interesting },
    ];

    for (var si = 0; si < sections.length; si++) {
        var sec = sections[si];
        var expanded = sec.key !== "interesting" || sec.items.length === items.length;
        h += "<div class=\"anomaly-severity-section severity-section-" + sec.key + (expanded ? " section-expanded" : "") + "\">"
            + "<div class=\"anomaly-severity-header\" data-severity-toggle=\"" + sec.key + "\">"
            + sec.label
            + " <span class=\"section-count\">(" + sec.items.length + ")</span>"
            + "<span class=\"section-toggle\">" + (sec.key === "interesting" && !expanded ? "\u25b6" : "\u25bc") + "</span>"
            + "</div>"
            + "<div class=\"anomaly-severity-items\">";

        if (sec.items.length === 0) {
            h += "<div style=\"padding:4px 8px;font-size:11px;color:var(--text-secondary);\">None</div>";
        }
        h += "</div></div>";
    }
    c.innerHTML = h;

    // Render actual cards into each section
    var sectionEls = c.querySelectorAll(".anomaly-severity-items");
    var sectionItems = [buckets.critical, buckets.anomalous, buckets.interesting];
    var s = this;
    for (var si2 = 0; si2 < sectionEls.length; si2++) {
        if (sectionItems[si2].length > 0) {
            this._renderAnomalyQueueFlat(sectionEls[si2], sectionItems[si2]);
        }
    }

    // Toggle expand/collapse for sections
    c.querySelectorAll("[data-severity-toggle]").forEach(function(hdr) {
        hdr.addEventListener("click", function() {
            var section = this.closest(".anomaly-severity-section");
            if (section) {
                section.classList.toggle("section-expanded");
                var toggle = this.querySelector(".section-toggle");
                if (toggle) toggle.textContent = section.classList.contains("section-expanded") ? "\u25bc" : "\u25b6";
            }
        });
    });

    // R1: Push critical/anomalous events to threat timeline
    if (window._bridgeDashboard) {
        for (var ti = 0; ti < buckets.critical.length; ti++) {
            var ca = buckets.critical[ti];
            // Each poll replaces the anomaly objects, so remember what was
            // pushed by a stable key on the panel, not by a flag on the object.
            var caKey = _rfTimelineKey(ca);
            var pushed = this._tlPushedKeys || (this._tlPushedKeys = {});
            if (caKey ? pushed[caKey] : ca._tlPushed) continue;
            if (caKey) pushed[caKey] = true;
            ca._tlPushed = true;
            window._bridgeDashboard._pushThreatEvent("sdr", "critical", (ca.signal_class || "RF") + " @ " + (ca.freq_band || ""));
        }
    }
};

DetectionDashboard.prototype._renderAnomalyQueueFlat = function(c, filtered) {
    var s = this;
    var items = filtered || this.anomalies;
    var h = "";
    for (var i = 0; i < items.length; i++) {
        var a = items[i];
        var score = a.anomaly_score != null ? a.anomaly_score : 0;
        var priority = a.priority || _anomalyPriority(score);
        var scoreCls = "score-" + priority;

        var iqBadgeHtml = a.has_iq_capture ? " <span class=\"iq-badge\">IQ</span>" : "";
        var resolvedCls = (a.reeval && !a.reeval.still_anomalous) ? " anomaly-resolved" : "";

        // R9: Age decay — calculate age in minutes
        var ageMs = 0, ageCls = "", ageBadge = "";
        var aTs = a.timestamp || a.detected_at;
        if (aTs) {
            ageMs = Date.now() - new Date(aTs).getTime();
            var ageMins = ageMs / 60000;
            if (ageMins > 30) ageCls = " anomaly-stale";
            else if (ageMins > 15) ageCls = " anomaly-aging";
            // Age label
            if (ageMins >= 60) ageBadge = " <span class=\"anomaly-age-badge\">" + Math.floor(ageMins / 60) + "h ago</span>";
            else if (ageMins >= 5) ageBadge = " <span class=\"anomaly-age-badge\">" + Math.floor(ageMins) + "m ago</span>";
        }

        // Bulk actions name rf_anomalies row IDs, so an anomaly without one
        // gets no selection box (never its detection_id or list position).
        var hasRowId = a.id != null;
        var isChecked = hasRowId && !!s._selectedRfIds[a.id];

        h += "<div class=\"anomaly-card priority-" + esc(priority) + resolvedCls + ageCls + (isChecked ? " bulk-selected" : "") + "\" role=\"listitem\">"
            + (hasRowId
                ? "<input type=\"checkbox\" class=\"bulk-checkbox\" data-rf-bulk-id=\"" + esc(a.id) + "\"" + (isChecked ? " checked" : "") + " aria-label=\"Select " + esc(a.signal_class || "Unknown") + " anomaly\">"
                : "<input type=\"checkbox\" class=\"bulk-checkbox\" disabled title=\"No stored anomaly ID\" aria-label=\"" + esc(a.signal_class || "Unknown") + " anomaly cannot be selected\">")
            + "<div class=\"anomaly-card-header\">"
            + "<span class=\"anomaly-score-badge " + scoreCls + "\">" + score.toFixed(2) + "</span>"
            + "<strong>" + esc(a.signal_class || "Unknown") + "</strong>" + iqBadgeHtml + ageBadge;

        // Seen count badge
        if (a.seen_count > 1) {
            h += " <span class=\"seen-count\">seen " + esc(a.seen_count) + "x</span>";
        }

        // Inline re-eval badge
        if (a.reeval) {
            var rvCls = a.reeval.still_anomalous ? "still-anomalous" : "now-normal";
            var rvLabel = a.reeval.still_anomalous ? "Active" : "Resolved";
            var rvDelta = a.reeval.score_delta || 0;
            var rvDeltaStr = rvDelta > 0 ? "+" + rvDelta.toFixed(3) : rvDelta.toFixed(3);
            var rvDeltaCls = rvDelta < 0 ? "decreased" : rvDelta > 0 ? "increased" : "same";
            h += " <span class=\"reeval-badge " + rvCls + "\">" + rvLabel + "</span>"
                + "<span class=\"reeval-inline-score\">now " + a.reeval.new_score.toFixed(2)
                + " (<span class=\"score-change " + rvDeltaCls + "\">" + rvDeltaStr + "</span>)</span>";
        }

        h += "</div>"
            + "<div class=\"anomaly-card-body\">";

        // Frequency with band context — drill-down to Spectrum
        var freqDisplay = a.freq_band || (a.freq_hz ? ChartUtils.formatFreq(a.freq_hz) : "--");
        var bandDesc = _rfBandDescription(a.freq_hz);
        var freqHzVal = a.freq_hz || 0;
        h += "<span title=\"" + esc(bandDesc) + "\">"
            + "<span class=\"drilldown-link\" data-drilldown-anomaly-freq=\"" + esc(freqHzVal) + "\" title=\"View in Spectrum Analysis\">" + esc(freqDisplay) + "</span>";
        if (bandDesc) h += " <span class=\"rf-band-label\">" + esc(bandDesc) + "</span>";
        h += "</span>";

        // Signal class description — drill-down to filter by class
        var classDesc = _rfClassDescription(a.signal_class, a.family);
        if (classDesc) {
            h += "<span class=\"rf-class-desc drilldown-link\" data-drilldown-anomaly-class=\"" + esc(a.signal_class || "") + "\" title=\"Filter by " + esc(a.signal_class || "") + "\">" + esc(classDesc) + "</span>";
        }

        // Confidence + SNR + Power context
        var ctxParts = [];
        if (a.confidence != null) ctxParts.push("Conf: " + (a.confidence * 100).toFixed(0) + "%");
        if (a.snr_db != null) ctxParts.push("SNR: " + a.snr_db.toFixed(1) + " dB");
        if (a.power_dbm != null) ctxParts.push("Pwr: " + a.power_dbm.toFixed(1) + " dBm");
        if (ctxParts.length) h += "<span>" + esc(ctxParts.join(" | ")) + "</span>";

        h += "<span>Node: " + esc(a.node_id || "--") + "</span>"
            + "<span>" + ChartUtils.formatTime(a.timestamp || a.detected_at) + "</span>";

        // Baseline status badge
        if (a.baseline_status && a.baseline_status !== "stable") {
            h += "<span class=\"baseline-badge " + esc(a.baseline_status) + "\">" + esc(a.baseline_status) + "</span>";
        }

        h += "</div>"
            + "<div class=\"anomaly-card-dims\">";

        // Reasons (human-readable)
        var reasons = (a.reeval && a.reeval.new_reasons) ? a.reeval.new_reasons : a.reasons;
        if (reasons && reasons.length) {
            for (var r = 0; r < Math.min(3, reasons.length); r++) {
                h += "<span class=\"reason-tag\">" + esc(reasons[r]) + "</span>";
            }
        }

        // Show dimensions
        var dims = (a.reeval && a.reeval.new_dimensions) ? a.reeval.new_dimensions : a.dimensions;
        if (dims) {
            var dimKeys = Object.keys(dims);
            dimKeys.sort(function(x, y) { return (dims[y] || 0) - (dims[x] || 0); });
            for (var d = 0; d < Math.min(3, dimKeys.length); d++) {
                if (dims[dimKeys[d]] > 0) {
                    h += "<span class=\"dim-tag\">" + esc(dimKeys[d]) + ": " + dims[dimKeys[d]].toFixed(2) + "</span>";
                }
            }
        }

        // Use rf_anomalies row ID for dismiss, detection_id for investigate/baseline
        var dismissId = a.id != null ? a.id : (a.detection_id || i);
        var detId = a.detection_id || "";

        h += "</div>"
            + "<div class=\"anomaly-card-actions\">"
            + "<button class=\"btn btn-sm btn-primary\" data-investigate-idx=\"" + i + "\">Investigate</button>"
            + "<button class=\"btn btn-sm\" data-dismiss-rf=\"" + esc(dismissId) + "\">Dismiss</button>"
            + "<button class=\"btn btn-sm btn-secondary\" data-baseline-anomaly=\"" + esc(detId) + "\">Mark as known…</button>"
            + "</div>"
            + "</div>";
    }
    c.innerHTML = h;

    var itemsRef = items;
    c.querySelectorAll("[data-investigate-idx]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var idx = parseInt(this.getAttribute("data-investigate-idx"));
            if (idx >= 0 && idx < itemsRef.length) s._showDeepDive(itemsRef[idx]);
        });
    });
    c.querySelectorAll("[data-dismiss-rf]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var aid = this.getAttribute("data-dismiss-rf");
            s.db.apiFetch("/api/detections/anomalies/" + encodeURIComponent(aid) + "/dismiss", { method: "PUT" })
                .then(function() { showToast("Anomaly dismissed", "success"); s._fetchAnomalies(); })
                .catch(function() { showToast("Failed to dismiss anomaly", "error"); });
        });
    });
    c.querySelectorAll("[data-baseline-anomaly]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var aid = this.getAttribute("data-baseline-anomaly");
            if (!aid) return;
            if (window.KnownSignals) window.KnownSignals.open(s.db, aid);
        });
    });

    // Drill-down: anomaly frequency -> Spectrum Analysis
    c.querySelectorAll("[data-drilldown-anomaly-freq]").forEach(function(link) {
        link.addEventListener("click", function(e) {
            e.stopPropagation();
            var freqHz = parseFloat(this.getAttribute("data-drilldown-anomaly-freq"));
            if (freqHz && window.drillDown) window.drillDown.toSpectrum(freqHz);
        });
    });

    // Drill-down: anomaly signal class -> RF Intelligence filtered
    c.querySelectorAll("[data-drilldown-anomaly-class]").forEach(function(link) {
        link.addEventListener("click", function(e) {
            e.stopPropagation();
            var cls = this.getAttribute("data-drilldown-anomaly-class");
            if (cls && window.drillDown) window.drillDown.toSignalClass(cls);
        });
    });

    // Bulk checkbox binding
    s._bindRfBulkCheckboxes(c);
};

DetectionDashboard.prototype._renderAnomalyQueueGrouped = function(c, filtered) {
    // Group anomalies by the selected group key
    var items = filtered || this.anomalies;
    var s = this;
    var groups = {};
    var groupOrder = [];
    for (var i = 0; i < items.length; i++) {
        var a = items[i];
        var key = s._getRfAnomalyField(a, s.rfGroupByKey);
        if (!groups[key]) {
            groups[key] = {
                label: key,
                signal_class: a.signal_class || "Unknown",
                family: a.family || "",
                freq_hz: a.freq_hz || a.center_freq_hz || 0,
                items: [],
                ids: [],
                detection_ids: [],
                max_score: 0,
                max_score_idx: -1,
                total_seen: 0,
                nodes: {},
                first_ts: a.timestamp || a.detected_at,
                last_ts: a.timestamp || a.detected_at,
                has_iq: false
            };
            groupOrder.push(key);
        }
        var g = groups[key];
        g.items.push(a);
        if (a.id != null) g.ids.push(a.id);
        if (a.detection_id) g.detection_ids.push(a.detection_id);
        g.total_seen += (a.seen_count || 1);
        var sc = a.anomaly_score != null ? a.anomaly_score : 0;
        if (sc > g.max_score) {
            g.max_score = sc;
            g.max_score_idx = g.items.length - 1;
        }
        if (a.node_id) g.nodes[a.node_id] = true;
        if (a.has_iq_capture) g.has_iq = true;
        var ts = a.timestamp || a.detected_at;
        if (ts && ts < g.first_ts) g.first_ts = ts;
        if (ts && ts > g.last_ts) g.last_ts = ts;
    }

    var keys = groupOrder;
    // Sort groups by max score descending
    keys.sort(function(a, b) { return groups[b].max_score - groups[a].max_score; });

    var h = "";
    for (var j = 0; j < keys.length; j++) {
        var gr = groups[keys[j]];
        var priority = _anomalyPriority(gr.max_score);
        var scoreCls = "score-" + priority;
        var nodeList = Object.keys(gr.nodes);
        var freqDisplay = gr.freq_hz > 0 ? ChartUtils.formatFreq(gr.freq_hz) : "--";
        var bandDesc = _rfBandDescription(gr.freq_hz);
        var classDesc = _rfClassDescription(gr.signal_class, gr.family);
        var iqBadgeHtml = gr.has_iq ? " <span class=\"iq-badge\">IQ</span>" : "";
        var groupLabel = gr.label || keys[j];

        // For grouped view, use all IDs in the group for bulk selection
        var grpBulkIds = gr.ids.join(",");
        var grpChecked = gr.ids.length > 0 && gr.ids.every(function(gid) { return !!s._selectedRfIds[gid]; });

        h += "<div class=\"anomaly-card grouped priority-" + esc(priority) + (grpChecked ? " bulk-selected" : "") + "\" role=\"listitem\">"
            // A group with no stored row IDs has nothing to act on: disable
            // its box, as the flat view does for a single card.
            + (gr.ids.length > 0
                ? "<input type=\"checkbox\" class=\"bulk-checkbox\" data-rf-bulk-group=\"" + esc(grpBulkIds) + "\"" + (grpChecked ? " checked" : "") + " aria-label=\"Select " + esc(groupLabel) + " group\">"
                : "<input type=\"checkbox\" class=\"bulk-checkbox\" disabled title=\"No stored anomaly ID\" aria-label=\"" + esc(groupLabel) + " group cannot be selected\">")
            + "<div class=\"anomaly-card-header\">"
            + "<span class=\"anomaly-score-badge " + scoreCls + "\">" + gr.max_score.toFixed(2) + "</span>"
            + "<strong>" + esc(groupLabel) + "</strong>"
            + "<span class=\"anomaly-group-badge\">" + gr.items.length + "</span>"
            + iqBadgeHtml;
        if (gr.total_seen > gr.items.length) {
            h += " <span class=\"seen-count\">seen " + esc(gr.total_seen) + "x</span>";
        }
        h += "</div>"
            + "<div class=\"anomaly-card-body\">"
            + "<span><span class=\"drilldown-link\" data-drilldown-anomaly-freq=\"" + esc(gr.freq_hz) + "\" title=\"View in Spectrum Analysis\">" + esc(freqDisplay) + "</span>";
        if (bandDesc) h += " <span class=\"rf-band-label\">" + esc(bandDesc) + "</span>";
        h += "</span>";
        if (classDesc) h += "<span class=\"rf-class-desc drilldown-link\" data-drilldown-anomaly-class=\"" + esc(gr.signal_class) + "\" title=\"Filter by " + esc(gr.signal_class) + "\">" + esc(classDesc) + "</span>";
        h += "<span>Nodes: " + esc(nodeList.join(", ") || "--") + "</span>"
            + "<span>" + ChartUtils.formatTime(gr.first_ts) + " — " + ChartUtils.formatTime(gr.last_ts) + "</span>"
            + "</div>"
            + "<div class=\"anomaly-card-actions\">"
            + "<button class=\"btn btn-sm btn-primary\" data-investigate-group=\"" + j + "\">Investigate</button>"
            + "<button class=\"btn btn-sm\" data-dismiss-group=\"" + j + "\">Dismiss Group</button>"
            + "<button class=\"btn btn-sm btn-secondary\" data-baseline-group=\"" + j + "\">Review known signal…</button>"
            + "</div>"
            + "</div>";
    }
    c.innerHTML = h;

    // Build array mapping group index to group data for event handlers
    var groupArr = [];
    for (var k = 0; k < keys.length; k++) groupArr.push(groups[keys[k]]);

    var s = this;
    c.querySelectorAll("[data-investigate-group]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var gi = parseInt(this.getAttribute("data-investigate-group"));
            var gr = groupArr[gi];
            if (gr && gr.max_score_idx >= 0) s._showDeepDive(gr.items[gr.max_score_idx]);
        });
    });
    c.querySelectorAll("[data-dismiss-group]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var gi = parseInt(this.getAttribute("data-dismiss-group"));
            var gr = groupArr[gi];
            if (gr) s._dismissGroup(gr.ids);
        });
    });
    c.querySelectorAll("[data-baseline-group]").forEach(function(btn) {
        btn.addEventListener("click", function() {
            var gi = parseInt(this.getAttribute("data-baseline-group"));
            var gr = groupArr[gi];
            if (gr) s._baselineGroup(gr.detection_ids);
        });
    });

    // Drill-down: anomaly frequency -> Spectrum Analysis (grouped view)
    c.querySelectorAll("[data-drilldown-anomaly-freq]").forEach(function(link) {
        link.addEventListener("click", function(e) {
            e.stopPropagation();
            var freqHz = parseFloat(this.getAttribute("data-drilldown-anomaly-freq"));
            if (freqHz && window.drillDown) window.drillDown.toSpectrum(freqHz);
        });
    });

    // Drill-down: anomaly signal class -> RF Intelligence filtered (grouped view)
    c.querySelectorAll("[data-drilldown-anomaly-class]").forEach(function(link) {
        link.addEventListener("click", function(e) {
            e.stopPropagation();
            var cls = this.getAttribute("data-drilldown-anomaly-class");
            if (cls && window.drillDown) window.drillDown.toSignalClass(cls);
        });
    });

    // Bulk checkbox binding
    s._bindRfBulkCheckboxes(c);
};

/* -- Bulk actions ----------------------------------------------- */

DetectionDashboard.prototype._dismissGroup = function(ids) {
    var s = this;
    if (!ids || !ids.length) return;
    var cnt = ids.length;
    if (cnt > 1 && !confirm("Dismiss " + cnt + " anomalies?")) return;
    s.db.apiFetch("/api/detections/anomalies/bulk/dismiss", {
        method: "PUT",
        body: { ids: ids }
    })
        .then(function() { showToast("Dismissed " + cnt + " anomalies", "success"); s._fetchAnomalies(); })
        .catch(function() { showToast("Bulk dismiss failed", "error"); });
};

DetectionDashboard.prototype._baselineGroup = function(detectionIds) {
    if (detectionIds && detectionIds.length && window.KnownSignals) {
        // Review one actual member's exact class/range/node; never silently
        // suppress an entire aggregate spanning several nodes or frequencies.
        window.KnownSignals.open(this.db, detectionIds[0]);
    }
};

/* -- RF Re-evaluate --------------------------------------------- */

DetectionDashboard.prototype._initReevalControls = function() {
    var s = this;
    var reevalBtn = document.getElementById("rf-reeval-all-btn");
    if (reevalBtn) {
        reevalBtn.addEventListener("click", function() { s._reevaluateAll(); });
    }
    var dismissResBtn = document.getElementById("rf-dismiss-resolved-btn");
    if (dismissResBtn) {
        dismissResBtn.addEventListener("click", function() { s._dismissResolved(); });
    }
    var purgeBtn = document.getElementById("rf-purge-resolved-btn");
    if (purgeBtn) {
        purgeBtn.addEventListener("click", function() { s._reevalDismissAll(); });
    }
};

DetectionDashboard.prototype._reevaluateAll = function() {
    var s = this;
    var btn = document.getElementById("rf-reeval-all-btn");
    if (btn) { btn.disabled = true; btn.textContent = "Evaluating..."; }

    s.db.apiFetch("/api/detections/anomalies?limit=50&reevaluate=true")
        .then(function(d) {
            // Filter dismissed
            var anomalies = d.anomalies || [];
            s.anomalies = anomalies;
            s.reevalSummary = d.reeval_summary || null;
            s._updateRfReevalSummary(d.reeval_summary);
            // Sort: still-anomalous first, resolved last
            s.anomalies.sort(function(a, b) {
                var aRes = a.reeval && !a.reeval.still_anomalous ? 1 : 0;
                var bRes = b.reeval && !b.reeval.still_anomalous ? 1 : 0;
                if (aRes !== bRes) return aRes - bRes;
                return (b.anomaly_score || 0) - (a.anomaly_score || 0);
            });
            s._renderAnomalyQueue();
            s._renderAnomalySparkline();
            if (btn) { btn.disabled = false; btn.textContent = "Re-evaluate All"; }
        })
        .catch(function(e) {
            if (btn) { btn.disabled = false; btn.textContent = "Re-evaluate All"; }
            var msg = e && e.detail ? e.detail : "Re-evaluation failed";
            showToast(msg, "error");
        });
};

DetectionDashboard.prototype._updateRfReevalSummary = function(summary) {
    var bar = document.getElementById("rf-reeval-summary");
    var dismissBtn = document.getElementById("rf-dismiss-resolved-btn");
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

DetectionDashboard.prototype._dismissResolved = function() {
    var s = this;
    var resolvedIds = [];
    for (var i = 0; i < s.anomalies.length; i++) {
        var a = s.anomalies[i];
        if (a.reeval && !a.reeval.still_anomalous) {
            var rid = a.id;
            if (rid != null) resolvedIds.push(rid);
        }
    }
    if (!resolvedIds.length) {
        showToast("No resolved anomalies to dismiss", "info");
        return;
    }
    if (!confirm("Dismiss " + resolvedIds.length + " resolved anomalies?")) return;
    s.db.apiFetch("/api/detections/anomalies/bulk/dismiss", {
        method: "PUT",
        body: { ids: resolvedIds },
    }).then(function() {
        showToast("Dismissed " + resolvedIds.length + " resolved anomalies", "success");
        s._reevaluateAll();
    }).catch(function(e) {
        var msg = e && e.detail ? e.detail : "Bulk dismiss failed";
        showToast(msg, "error");
    });
};

/* -- Purge Resolved (server-side reeval + auto-dismiss) --------- */

DetectionDashboard.prototype._reevalDismissAll = function() {
    var s = this;
    var total = s.anomalyTotal || (s.anomalies || []).length;
    if (!confirm("Re-evaluate and dismiss all resolved anomalies?\n\nThis will process all " + total + " anomalies server-side.")) return;
    var btn = document.getElementById("rf-purge-resolved-btn");
    if (btn) { btn.disabled = true; btn.textContent = "Purging..."; }

    s.db.apiFetch("/api/detections/anomalies/bulk/reeval-dismiss", { method: "POST" })
        .then(function(d) {
            var msg = (d.dismissed || 0) + " resolved dismissed, " + (d.still_anomalous || 0) + " still active";
            showToast(msg, "success");
            if (btn) { btn.disabled = false; btn.textContent = "Purge Resolved"; }
            s._fetchAnomalies();
        })
        .catch(function(e) {
            if (btn) { btn.disabled = false; btn.textContent = "Purge Resolved"; }
            var msg = (e && e.detail) ? e.detail : (e && e.message) ? e.message : "Purge failed";
            showToast(msg, "error");
            console.error("Purge failed:", e);
        });
};

/* -- Anomaly Sparkline ------------------------------------------ */

DetectionDashboard.prototype._renderAnomalySparkline = function() {
    var cv = document.getElementById("anomaly-sparkline");
    if (!cv || !this.anomalyHistory || this.anomalyHistory.length < 2) return;
    var ctx = cv.getContext("2d");
    ChartUtils.drawSparkline(ctx, cv, this.anomalyHistory, "#f85149", "rgba(248,81,73,0.15)");
};

/* -- Anomaly Summary Bar ---------------------------------------- */

DetectionDashboard.prototype._fetchAnomalySummary = function() {
    var s = this;
    s.db.apiFetch("/api/detections/anomalies/summary")
        .then(function(d) {
            s.rfSummary = d;
            s._renderAnomalySummary(d);
        })
        .catch(function() {});
};

DetectionDashboard.prototype._renderAnomalySummary = function(d) {
    var bar = document.getElementById("rf-anomaly-summary");
    if (!bar || !d) return;

    var crit = (d.by_priority && d.by_priority.critical) || 0;
    var anom = (d.by_priority && d.by_priority.anomalous) || 0;
    var inter = (d.by_priority && d.by_priority.interesting) || 0;
    var families = d.unique_families ? d.unique_families.length : 0;
    var nodes = d.unique_nodes ? d.unique_nodes.length : 0;

    setText("rf-sum-critical", crit + " critical");
    setText("rf-sum-anomalous", anom + " anomalous");
    setText("rf-sum-interesting", inter + " interesting");
    setText("rf-sum-families", families + " families");
    setText("rf-sum-nodes", nodes + " nodes");

    // Apply priority coloring
    var critEl = document.getElementById("rf-sum-critical");
    var anomEl = document.getElementById("rf-sum-anomalous");
    var interEl = document.getElementById("rf-sum-interesting");
    if (critEl) critEl.className = "rf-sum-item rf-sum-critical-badge";
    if (anomEl) anomEl.className = "rf-sum-item rf-sum-anomalous-badge";
    if (interEl) interEl.className = "rf-sum-item rf-sum-interesting-badge";

    bar.style.display = (d.total > 0) ? "" : "none";
};

/* -- WebSocket -------------------------------------------------- */

DetectionDashboard.prototype._connectWS = function() {
    var s = this;
    if (!s.db || !s.db._connectWS) return;

    s.db._connectWS("detections", "/api/detections/ws/feed", function(d) {
        if (s.paused || !s._active) return;
        if (d.type === "detection" && d.detection) {
            s.feed.unshift(d.detection);
            if (s.feed.length > 200) s.feed.length = 200;
            // Debounce feed renders — batch rapid WS events into one render
            if (!s._feedRenderTimer) {
                s._feedRenderTimer = setTimeout(function() {
                    s._feedRenderTimer = null;
                    if (s._active) s._renderFeed();
                }, 500);
            }
            // Throttle KPI fetches — max once per 3s from WS events
            if (!s._kpiThrottleTimer) {
                s._kpiThrottleTimer = setTimeout(function() {
                    s._kpiThrottleTimer = null;
                    if (s._active) s._fetchKPIs();
                }, s._kpiThrottleMs);
            }
        }
        if (d.type === "anomaly" && d.anomaly) {
            s.anomalies.unshift(d.anomaly);
            if (s.anomalies.length > 50) s.anomalies.length = 50;
            s._renderAnomalyQueue();
        }
        if (d.type === "iq_available" && d.detection_id) {
            // Update matching anomaly in local array
            for (var ai = 0; ai < s.anomalies.length; ai++) {
                if (s.anomalies[ai].detection_id === d.detection_id) {
                    s.anomalies[ai].has_iq_capture = true;
                    break;
                }
            }
            s._renderAnomalyQueue();
        }
    });
};

/* -- Signal Deep-Dive Modal -------------------------------------- */

DetectionDashboard.prototype._showDeepDive = function(detection) {
    var s = this;
    var overlay = document.getElementById("deep-dive-overlay");
    if (!overlay) return;

    var cls = detection.signal_class || "Unknown";
    var snr = detection.snr_db != null ? detection.snr_db : 15;
    var detId = detection.detection_id || detection.id || null;
    var hasIQ = detection.has_iq_capture;
    setText("deep-dive-title", "Deep-Dive: " + cls);
    overlay.style.display = "";
    s._currentDeepDiveDetectionId = detId;
    var known = document.getElementById("dd-mark-known");
    if (known) {
        known.style.display = detId ? "" : "none";
        known.onclick = function () { if (detId && window.KnownSignals) window.KnownSignals.open(s.db, detId); };
    }


    // Render detection context
    s._renderDeepDiveContext(detection);

    // Clear time-domain canvas
    var tdCv = document.getElementById("dd-timedomain");
    if (tdCv) { var tdCtx = tdCv.getContext("2d"); tdCtx.fillStyle = "#0d1117"; tdCtx.fillRect(0, 0, tdCv.width, tdCv.height); }

    // Download IQ button — hide by default
    var dlBtn = document.getElementById("dd-download-iq");
    if (dlBtn) dlBtn.style.display = "none";

    // Fetch IQ data: prefer real captured, fall back to synthetic
    if (hasIQ && detId) {
        s._setIQSourceBadge("captured", detId);
        s.db.apiFetch("/api/detections/" + encodeURIComponent(detId) + "/iq?format=json")
            .then(function(d) {
                s._drawDDConstellation(d.constellation_x, d.constellation_y);
                s._drawDDPSD(d.psd_db, d.psd_freq_hz);
                s._drawDDFeatures(d.dsp_features);
                // Draw time-domain from constellation data (I = x, Q = y)
                if (d.constellation_x && d.constellation_y) {
                    s._drawDDTimeDomain(d.constellation_x, d.constellation_y);
                }
                // Show download button
                if (dlBtn) {
                    dlBtn.style.display = "";
                    dlBtn.onclick = function() {
                        // The session cookie authenticates the download; a
                        // credential never goes in a URL (history, proxy logs).
                        window.open("/api/detections/" + encodeURIComponent(detId) + "/iq?format=raw", "_blank");
                    };
                }
            })
            .catch(function() {
                // Fallback to synthetic on fetch failure
                s._setIQSourceBadge("synthetic");
                s._fetchSyntheticViz(cls, snr);
            });
    } else {
        s._setIQSourceBadge("synthetic");
        s._fetchSyntheticViz(cls, snr);
    }

    // Show spectrogram viewer for detections with IQ captures
    if (hasIQ && detId && window.showSpectrogramForDetection) {
        window.showSpectrogramForDetection(detId);
    } else if (window.hideSpectrogramCard) {
        window.hideSpectrogramCard();
    }

    // Fetch baseline comparison
    s._fetchDeepDiveBaseline(detection);

    // Fetch historical activity sparkline
    s._fetchDeepDiveHistory(detection);

    // Render investigation checklist
    s._renderInvestigationChecklist(detection);

    // Bind close
    var closeBtn = document.getElementById("deep-dive-close");
    var closeBtn2 = document.getElementById("dd-close-btn");
    var closeFn = function() { overlay.style.display = "none"; s._currentDeepDiveDetectionId = null; if (window.hideSpectrogramCard) window.hideSpectrogramCard(); };
    if (closeBtn) closeBtn.onclick = closeFn;
    if (closeBtn2) closeBtn2.onclick = closeFn;
    overlay.onclick = function(e) { if (e.target === overlay) closeFn(); };

    // Bind action buttons
    var genRef = document.getElementById("dd-gen-ref");
    if (genRef) genRef.onclick = function() {
        s._setIQSourceBadge("synthetic");
        s._fetchSyntheticViz(cls, 20);
    };

    var viewNodes = document.getElementById("dd-view-nodes");
    if (viewNodes) viewNodes.onclick = function() {
        s.db.apiFetch("/api/detections/recent?minutes=60&limit=100")
            .then(function(d) {
                var dets = (d && d.detections) ? d.detections : (Array.isArray(d) ? d : []);
                var nodeSet = {};
                for (var i = 0; i < dets.length; i++) { if (dets[i].node_id) nodeSet[dets[i].node_id] = true; }
                var nodes = Object.keys(nodeSet);
                if (window.dashboard && window.dashboard.nodeComparison && nodes.length >= 2) {
                    overlay.style.display = "none";
                    window.dashboard.nodeComparison.show(nodes);
                } else {
                    alert("Detected on nodes: " + (nodes.join(", ") || "none"));
                }
            })
            .catch(function() { showToast("Failed to load node data", "error"); });
    };

    var exportBtn = document.getElementById("dd-export");
    if (exportBtn) exportBtn.onclick = function() {
        window.open("/api/export/detections?class=" + encodeURIComponent(cls) + "&hours=" + s.timeRange, "_blank");
    };

    // Capture IQ button — open dialog pre-filled with detection freq and node
    // (and its class, so a capture of a DMR / P25 / LoRa channel is decoded)
    var captureBtn = document.getElementById("dd-capture-iq");
    if (captureBtn) captureBtn.onclick = function() {
        var nodeId = detection.node_id || "";
        var freqMhz = detection.freq_hz ? detection.freq_hz / 1e6 : null;
        if (nodeId && window.dashboard) {
            window.dashboard._openIQCaptureDialog(nodeId, freqMhz, detection.signal_class);
        } else {
            showToast("No node ID available for capture", "error");
        }
    };

    // Feedback buttons — show only if we have a detection_id
    var fbGroup = document.getElementById("dd-feedback-group");
    if (fbGroup) {
        fbGroup.style.display = detId ? "" : "none";
        fbGroup.querySelectorAll("[data-feedback]").forEach(function(btn) {
            btn.onclick = function() {
                var label = this.getAttribute("data-feedback");
                s.db.apiFetch("/api/detections/anomalies/" + encodeURIComponent(detId) + "/feedback", {
                    method: "POST",
                    body: { label: label }
                })
                    .then(function(r) {
                        showToast("Feedback: " + label.replace("_", " "), "success");
                        if (r && r.auto_dismissed) s._fetchAnomalies();
                    })
                    .catch(function() { showToast("Failed to submit feedback", "error"); });
            };
        });
    }
};

/* -- Synthetic visualization fetch helper ----------------------------- */

DetectionDashboard.prototype._fetchSyntheticViz = function(cls, snr) {
    var s = this;
    s.db.apiFetch("/api/signals/generate?class=" + encodeURIComponent(cls) + "&snr=" + snr + "&n=4096")
        .then(function(d) {
            s._drawDDConstellation(d.constellation_x, d.constellation_y);
            s._drawDDPSD(d.psd_db, d.psd_freq_hz);
            s._drawDDFeatures(d.dsp_features);
            if (d.constellation_x && d.constellation_y) {
                s._drawDDTimeDomain(d.constellation_x, d.constellation_y);
            }
        })
        .catch(function() { /* signals router may not be mounted */ });
};

DetectionDashboard.prototype._renderDeepDiveContext = function(det) {
    var c = document.getElementById("dd-context");
    if (!c) return;

    var score = det.anomaly_score != null ? det.anomaly_score : 0;
    var priority = _anomalyPriority(score);
    var scoreCls = "score-" + priority;

    var fields = [
        { label: "Class", value: det.signal_class || "--" },
        { label: "Confidence", value: det.confidence != null ? (det.confidence * 100).toFixed(1) + "%" : "--" },
        { label: "SNR", value: det.snr_db != null ? det.snr_db.toFixed(1) + " dB" : "--" },
        { label: "Power", value: det.power_db != null ? det.power_db.toFixed(1) + " dB" : "--" },
        { label: "Family", value: det.family || "--" },
        { label: "Super-Family", value: det.super_family || "--" },
        { label: "Frequency", value: det.freq_band || (det.center_freq_hz ? ChartUtils.formatFreq(det.center_freq_hz) : "--") },
        { label: "Node", value: det.node_id || "--" },
        { label: "Time", value: ChartUtils.formatTime(det.timestamp || det.detected_at) },
        { label: "Anomaly Score", value: "<span class=\"anomaly-score-badge " + scoreCls + "\">" + score.toFixed(2) + "</span>" }
    ];
    // AGC gain tracking fields (from backend-agent)
    if (det.gain_db != null) fields.push({ label: "Gain", value: det.gain_db.toFixed(1) + " dB" });
    if (det.lna_state) fields.push({ label: "LNA", value: det.lna_state });

    var h = "";
    for (var i = 0; i < fields.length; i++) {
        h += "<div class=\"dd-field\">"
            + "<span class=\"dd-field-label\">" + esc(fields[i].label) + "</span>"
            + "<span class=\"dd-field-value\">" + (fields[i].label === "Anomaly Score" ? fields[i].value : esc(fields[i].value)) + "</span>"
            + "</div>";
    }
    c.innerHTML = h;
};

DetectionDashboard.prototype._fetchDeepDiveBaseline = function(det) {
    var c = document.getElementById("dd-baseline");
    if (!c) return;
    var s = this;
    var freq = det.freq_band || "";
    var cls = det.signal_class || "";

    s.db.apiFetch("/api/detections/distribution?hours=24")
        .then(function(d) {
            // API returns [{signal_class, family, count, avg_confidence}, ...]
            var classes = Array.isArray(d) ? d : (d && d.classes ? d.classes : []);
            if (!classes.length) {
                c.innerHTML = "<span class=\"baseline-unknown\">No baseline data for this frequency band</span>";
                return;
            }
            var expectedNames = [];
            for (var i = 0; i < classes.length; i++) {
                expectedNames.push(classes[i].name || classes[i].signal_class || classes[i].class_name);
            }
            var isMatch = expectedNames.indexOf(cls) !== -1;
            var h = "<span class=\"" + (isMatch ? "baseline-match" : "baseline-mismatch") + "\">"
                + (isMatch ? "Match — " + esc(cls) + " is expected at this frequency" : "Mismatch — " + esc(cls) + " is NOT expected at this frequency")
                + "</span>";
            h += "<div class=\"baseline-class-list\">";
            for (var j = 0; j < expectedNames.length; j++) {
                var m = expectedNames[j] === cls ? " match" : "";
                h += "<span class=\"baseline-class-tag" + m + "\">" + esc(expectedNames[j]) + "</span>";
            }
            h += "</div>";
            c.innerHTML = h;
        })
        .catch(function() {
            c.innerHTML = "<span class=\"baseline-unknown\">Could not load baseline data</span>";
        });
};

DetectionDashboard.prototype._fetchDeepDiveHistory = function(det) {
    var cv = document.getElementById("dd-history-sparkline");
    if (!cv) return;
    var s = this;
    var cls = det.signal_class || "";

    s.db.apiFetch("/api/detections/timeline?hours=48")
        .then(function(d) {
            // API returns [{bucket, count, ...}, ...]
            if (!d || !d.length) {
                ChartUtils.clearCanvas(cv.getContext("2d"), cv);
                return;
            }
            var vals = [];
            for (var i = 0; i < d.length; i++) vals.push(d[i].count || 0);
            ChartUtils.drawSparkline(cv.getContext("2d"), cv, vals, "#58a6ff", "rgba(88,166,255,0.15)");
        })
        .catch(function(e) { trackFetchError("det-48h", e); });
};

/* -- Deep-Dive Canvas Renderers (adapted from signals.js) ------- */

DetectionDashboard.prototype._drawDDConstellation = function(cx, cy) {
    var cv = document.getElementById("dd-constellation");
    if (!cv || !cx || !cx.length) return;
    var ctx = cv.getContext("2d");
    var w = cv.width, h = cv.height, p = 30;
    ctx.fillStyle = "#0d1117"; ctx.fillRect(0, 0, w, h);

    // Find max absolute
    var ma = 0;
    for (var i = 0; i < cx.length; i++) {
        var a = Math.max(Math.abs(cx[i]), Math.abs(cy[i]));
        if (a > ma) ma = a;
    }
    if (ma === 0) ma = 1;
    ma *= 1.2;

    // Grid
    ctx.strokeStyle = "#30363d"; ctx.lineWidth = 0.5;
    ctx.beginPath(); ctx.moveTo(p, h / 2); ctx.lineTo(w - p, h / 2);
    ctx.moveTo(w / 2, p); ctx.lineTo(w / 2, h - p); ctx.stroke();

    // Unit circle
    ctx.beginPath(); ctx.strokeStyle = "#30363d";
    ctx.arc(w / 2, h / 2, ((w - 2 * p) / 2) * (1 / ma), 0, 2 * Math.PI); ctx.stroke();

    // Points
    ctx.fillStyle = "rgba(88,166,255,0.6)";
    for (var j = 0; j < cx.length; j++) {
        var px = w / 2 + (cx[j] / ma) * (w / 2 - p);
        var py = h / 2 - (cy[j] / ma) * (h / 2 - p);
        ctx.beginPath(); ctx.arc(px, py, 1.5, 0, 2 * Math.PI); ctx.fill();
    }

    ctx.fillStyle = "#8b949e"; ctx.font = "10px monospace"; ctx.textAlign = "center";
    ctx.fillText("I", w - 12, h / 2 - 6); ctx.fillText("Q", w / 2 + 10, p - 6);
};

DetectionDashboard.prototype._drawDDPSD = function(psd, freqs) {
    var cv = document.getElementById("dd-psd");
    if (!cv || !psd || !psd.length) return;
    var ctx = cv.getContext("2d");
    var w = cv.width, h = cv.height, p = 30;
    ctx.fillStyle = "#0d1117"; ctx.fillRect(0, 0, w, h);

    var mn = psd[0], mx = psd[0];
    for (var i = 1; i < psd.length; i++) {
        if (psd[i] < mn) mn = psd[i];
        if (psd[i] > mx) mx = psd[i];
    }
    if (mx === mn) mx = mn + 1;

    // Grid lines
    ctx.strokeStyle = "#30363d"; ctx.lineWidth = 0.5;
    for (var g = 1; g < 4; g++) {
        var gy = p + (h - 2 * p) * g / 4;
        ctx.beginPath(); ctx.moveTo(p, gy); ctx.lineTo(w - p, gy); ctx.stroke();
    }

    // PSD line
    ctx.beginPath(); ctx.strokeStyle = "#3fb950"; ctx.lineWidth = 1.5;
    var n = psd.length;
    for (var j = 0; j < n; j++) {
        var x = p + (j / n) * (w - 2 * p);
        var y = p + (1 - (psd[j] - mn) / (mx - mn)) * (h - 2 * p);
        j === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    }
    ctx.stroke();

    ctx.fillStyle = "#8b949e"; ctx.font = "10px monospace";
    ctx.textAlign = "left";
    ctx.fillText(mx.toFixed(0) + " dB", 2, p + 10);
    ctx.fillText(mn.toFixed(0) + " dB", 2, h - p);
    ctx.textAlign = "center";
    ctx.fillText("Frequency (normalized)", w / 2, h - 4);
};

DetectionDashboard.prototype._drawDDFeatures = function(feat) {
    var cv = document.getElementById("dd-features");
    if (!cv || !feat || !feat.length) return;
    var ctx = cv.getContext("2d");
    var w = cv.width, h = cv.height, p = 30;
    ctx.fillStyle = "#0d1117"; ctx.fillRect(0, 0, w, h);

    var LABELS = ["N2pk", "N4pk", "N8pk", "CP64", "CP256", "CP512", "CP1K", "CP2K", "|C20|", "aC20", "|C40|", "aC40", "|C41|", "C42", "rC40", "rC41"];
    var n = feat.length, mx = 0;
    for (var i = 0; i < n; i++) { var a = Math.abs(feat[i]); if (a > mx) mx = a; }
    if (mx === 0) mx = 1;

    var sp = (w - 2 * p) / n, bw = Math.max(4, sp - 2);
    for (var j = 0; j < n; j++) {
        var bh = (Math.abs(feat[j]) / mx) * (h - 2 * p);
        var x = p + j * sp;
        ctx.fillStyle = j < 3 ? "#58a6ff" : j < 8 ? "#a371f7" : "#d29922";
        ctx.fillRect(x, h - p - bh, bw, bh);

        ctx.fillStyle = "#8b949e"; ctx.font = "8px monospace"; ctx.textAlign = "center";
        ctx.fillText(j < LABELS.length ? LABELS[j] : "F" + j, x + bw / 2, h - p + 12);
    }

    ctx.fillStyle = "#8b949e"; ctx.font = "10px monospace"; ctx.textAlign = "left";
    ctx.fillText(mx.toFixed(2), 2, p + 10); ctx.fillText("0", 2, h - p);
};

/* -- Time-Domain I/Q Renderer ----------------------------------- */

DetectionDashboard.prototype._drawDDTimeDomain = function(iVals, qVals) {
    var cv = document.getElementById("dd-timedomain");
    if (!cv || !iVals || !iVals.length) return;
    var ctx = cv.getContext("2d");
    var w = cv.width, h = cv.height, p = 30;
    ctx.fillStyle = "#0d1117"; ctx.fillRect(0, 0, w, h);

    // Show first 512 samples
    var n = Math.min(512, iVals.length);
    var mn = Infinity, mx = -Infinity;
    for (var i = 0; i < n; i++) {
        var vi = iVals[i], vq = qVals[i];
        if (vi < mn) mn = vi; if (vi > mx) mx = vi;
        if (vq < mn) mn = vq; if (vq > mx) mx = vq;
    }
    if (mx === mn) mx = mn + 1;
    var range = mx - mn;

    // Grid
    ctx.strokeStyle = "#30363d"; ctx.lineWidth = 0.5;
    ctx.beginPath(); ctx.moveTo(p, h / 2); ctx.lineTo(w - p, h / 2); ctx.stroke();

    // I trace (blue)
    ctx.beginPath(); ctx.strokeStyle = "#58a6ff"; ctx.lineWidth = 1;
    for (var j = 0; j < n; j++) {
        var x = p + (j / n) * (w - 2 * p);
        var y = p + (1 - (iVals[j] - mn) / range) * (h - 2 * p);
        j === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    }
    ctx.stroke();

    // Q trace (green)
    ctx.beginPath(); ctx.strokeStyle = "#3fb950"; ctx.lineWidth = 1;
    for (var k = 0; k < n; k++) {
        var x2 = p + (k / n) * (w - 2 * p);
        var y2 = p + (1 - (qVals[k] - mn) / range) * (h - 2 * p);
        k === 0 ? ctx.moveTo(x2, y2) : ctx.lineTo(x2, y2);
    }
    ctx.stroke();

    // Labels
    ctx.fillStyle = "#8b949e"; ctx.font = "10px monospace"; ctx.textAlign = "center";
    ctx.fillText("Sample Index", w / 2, h - 4);
    ctx.textAlign = "left";
    ctx.fillText("I", w - p + 4, p + 10);
    ctx.fillStyle = "#58a6ff"; ctx.fillRect(w - p + 4, p + 14, 12, 2);
    ctx.fillStyle = "#8b949e"; ctx.fillText("Q", w - p + 4, p + 30);
    ctx.fillStyle = "#3fb950"; ctx.fillRect(w - p + 4, p + 34, 12, 2);
};

/* -- IQ Source Badge ---------------------------------------------- */

DetectionDashboard.prototype._setIQSourceBadge = function(source, detId) {
    var el = document.getElementById("dd-iq-source");
    if (!el) return;
    if (source === "captured") {
        el.innerHTML = "<span class=\"iq-source-badge captured\">Real Captured Waveform</span>";
        // Fetch IQ quality metadata if available
        if (detId) {
            var s = this;
            s.db.apiFetch("/api/detections/" + encodeURIComponent(detId) + "/iq/quality")
                .then(function(q) {
                    if (!q || q.score == null) return;
                    var qCls = q.score >= 0.8 ? "iq-quality-good" : q.score >= 0.5 ? "iq-quality-fair" : "iq-quality-poor";
                    var warnings = [];
                    if (q.clipped) warnings.push("ADC clipped");
                    if (q.dc_offset) warnings.push("DC offset");
                    if (!q.phase_coherent) warnings.push("Phase incoherent");
                    var warnHtml = warnings.length ? " <span class=\"iq-quality-warn\">" + esc(warnings.join(", ")) + "</span>" : "";
                    el.innerHTML += " <span class=\"iq-quality-badge " + qCls + "\">Quality: " + (q.score * 100).toFixed(0) + "%" + warnHtml + "</span>";
                })
                .catch(function() { /* quality endpoint may not exist yet */ });
        }
    } else {
        el.innerHTML = "<span class=\"iq-source-badge synthetic\">Synthetic Reference</span>";
    }
};

/* -- Helpers ---------------------------------------------------- */

/* A key that names the same RF anomaly across polls, or "" when it has none. */
function _rfTimelineKey(a) {
    if (a.id != null) return "id:" + a.id;
    if (a.detection_id) return "det:" + a.detection_id;
    if (a.timestamp) return "k:" + (a.signal_class || "") + "|" + (a.freq_band || "") + "|" + a.timestamp;
    return "";
}

function _anomalyPriority(score) {
    if (score >= 0.7) return "critical";
    if (score >= 0.5) return "anomalous";
    if (score >= 0.3) return "interesting";
    return "normal";
}

function _rfBandDescription(freqHz) {
    if (!freqHz || freqHz <= 0) return "";
    var mhz = freqHz / 1e6;
    // Order: narrow/specific bands BEFORE wide generic ranges they overlap
    if (mhz >= 0.003 && mhz < 0.03) return "VLF";
    if (mhz >= 0.03 && mhz < 0.3) return "LF";
    if (mhz >= 0.3 && mhz < 3) return "MF";
    if (mhz >= 27 && mhz <= 28) return "CB 27 MHz";
    if (mhz >= 3 && mhz < 30) return "HF";
    if (mhz >= 30 && mhz < 88) return "VHF Low";
    if (mhz >= 88 && mhz <= 108) return "FM Broadcast";
    if (mhz >= 108 && mhz <= 137) return "Aviation VHF";
    if (mhz >= 144 && mhz <= 148) return "2m Amateur";
    if (mhz >= 150 && mhz <= 174) return "VHF Business";
    if (mhz >= 137 && mhz <= 174) return "VHF High";
    if (mhz >= 315 && mhz <= 315.1) return "ISM 315 MHz";
    if (mhz >= 225 && mhz <= 400) return "Military UHF";
    if (mhz >= 400 && mhz <= 410) return "UHF SATCOM";
    if (mhz >= 430 && mhz <= 440) return "ISM 433 MHz";
    if (mhz >= 420 && mhz <= 450) return "70cm Amateur";
    if (mhz >= 450 && mhz <= 470) return "UHF Business";
    if (mhz >= 470 && mhz <= 698) return "UHF TV";
    if (mhz >= 860 && mhz <= 870) return "ISM 868 MHz";
    if (mhz >= 902 && mhz <= 928) return "ISM 915 MHz";
    if (mhz >= 698 && mhz <= 960) return "Cellular 700-900";
    if (mhz >= 1090 && mhz <= 1090.1) return "ADS-B 1090";
    if (mhz >= 960 && mhz <= 1215) return "L-Band Aero";
    if (mhz >= 1200 && mhz <= 1300) return "23cm Amateur";
    if (mhz >= 1525 && mhz <= 1559) return "L-Band SATCOM";
    if (mhz >= 1559 && mhz <= 1610) return "GPS/GNSS L1";
    if (mhz >= 1710 && mhz <= 2170) return "Cellular AWS/PCS";
    if (mhz >= 2400 && mhz <= 2500) return "ISM 2.4 GHz";
    if (mhz >= 2500 && mhz <= 2700) return "BRS/EBS 2.5 GHz";
    if (mhz >= 3300 && mhz <= 3700) return "5G C-Band";
    if (mhz >= 5150 && mhz <= 5850) return "ISM 5 GHz";
    if (mhz >= 5925 && mhz <= 7125) return "WiFi 6E / 6 GHz";
    if (mhz < 30) return "HF";
    if (mhz < 300) return "VHF";
    if (mhz < 3000) return "UHF";
    if (mhz < 30000) return "SHF";
    return "EHF";
}

function _rfClassDescription(signalClass, family) {
    if (!signalClass) return "";
    var sc = signalClass.toLowerCase().replace(/[-_]/g, "");
    var desc = {
        "bpsk": "Binary Phase Shift Keying",
        "qpsk": "Quadrature PSK",
        "8psk": "8-Phase Shift Keying",
        "16psk": "16-Phase Shift Keying",
        "32psk": "32-Phase Shift Keying",
        "16qam": "16-Quadrature Amplitude Mod",
        "32qam": "32-QAM Cross Constellation",
        "64qam": "64-Quadrature Amplitude Mod",
        "128qam": "128-QAM",
        "256qam": "256-QAM",
        "16apsk": "16-Amplitude Phase Shift Keying",
        "32apsk": "32-APSK",
        "64apsk": "64-APSK",
        "128apsk": "128-APSK",
        "ook": "On-Off Keying (2-ASK)",
        "4ask": "4-Amplitude Shift Keying",
        "8ask": "8-ASK",
        "16ask": "16-ASK",
        "4pam": "4-Pulse Amplitude Mod",
        "8pam": "8-PAM",
        "16pam": "16-PAM",
        "2fsk": "Binary Freq Shift Keying",
        "4fsk": "4-FSK",
        "2gfsk": "Gaussian 2-FSK",
        "4gfsk": "Gaussian 4-FSK (BT, DECT)",
        "4msk": "4-Minimum Shift Keying",
        "4gmsk": "Gaussian MSK (GSM)",
        "8msk": "8-MSK",
        "8gmsk": "8-GMSK",
        "amdsb": "AM Double Sideband",
        "amssb": "AM Single Sideband",
        "fm": "Frequency Modulation",
        "tone": "Continuous Wave / Tone",
        "ofdm64": "OFDM 64 Subcarriers (WiFi)",
        "ofdm128": "OFDM 128 Subcarriers",
        "ofdm256": "OFDM 256 Subcarriers (WiMAX)",
        "ofdm512": "OFDM 512 Subcarriers",
        "ofdm1024": "OFDM 1024 Subcarriers",
        "ofdm2048": "OFDM 2048 Subcarriers (LTE)",
        "loracss": "LoRa Chirp Spread Spectrum",
    };
    if (desc[sc]) return desc[sc];
    // Fallback: format family if available
    if (family) {
        var familyDescs = {
            "psk": "Phase Shift Keying",
            "qam": "Quadrature Amplitude Mod",
            "apsk": "Amplitude Phase Shift Keying",
            "ask": "Amplitude Shift Keying",
            "pam": "Pulse Amplitude Mod",
            "fsk": "Freq Shift Keying",
            "msk": "Minimum Shift Keying",
            "ofdm": "Orthogonal Freq Division Mux",
            "am": "Amplitude Modulation",
            "fm": "Frequency Modulation",
        };
        return familyDescs[family.toLowerCase()] || "";
    }
    return "";
}

function _familyToSuperFamily(family) {
    if (!family) return "";
    var f = family.toLowerCase();
    if (f === "qam" || f === "pam") return "LINEAR_DIGITAL";
    if (f === "psk") return "CONSTANT_ENVELOPE";
    if (f === "fsk" || f === "msk" || f === "gmsk") return "CONSTANT_ENVELOPE";
    if (f === "am" || f === "ssb" || f === "dsb") return "AMPLITUDE_ONLY";
    if (f === "fm" || f === "wbfm" || f === "nbfm") return "ANALOG";
    if (f === "ofdm") return "MULTI_CARRIER";
    if (f === "cdma" || f === "dsss" || f === "fhss") return "SPREAD_SPECTRUM";
    return "";
}

/* ================================================================
   Investigation Checklist (RF Deep-Dive)
   ================================================================ */

DetectionDashboard.prototype._renderInvestigationChecklist = function(det) {
    var c = document.getElementById("dd-investigation-checklist");
    var rec = document.getElementById("dd-investigation-recommendation");
    if (!c) return;

    var s = this;
    var steps = [];
    var passCount = 0, warnCount = 0, failCount = 0;

    // Step 1: SNR Check
    var snr = det.snr_db;
    var snrStatus, snrDetail;
    if (snr == null) {
        snrStatus = "unknown"; snrDetail = "SNR data not available";
    } else if (snr > 10) {
        snrStatus = "pass"; snrDetail = "SNR " + snr.toFixed(1) + " dB — good signal quality";
    } else if (snr >= 0) {
        snrStatus = "warn"; snrDetail = "SNR " + snr.toFixed(1) + " dB — marginal signal, classification may be unreliable";
    } else {
        snrStatus = "fail"; snrDetail = "SNR " + snr.toFixed(1) + " dB — below noise floor, likely a false detection";
    }
    steps.push({ label: "SNR Check", status: snrStatus, detail: snrDetail });

    // Step 2: Baseline Comparison
    var baseStatus = det.baseline_status || "";
    var anomScore = det.anomaly_score != null ? det.anomaly_score : 0;
    var blStatus, blDetail;
    if (!baseStatus || baseStatus === "stable") {
        blStatus = "pass"; blDetail = "Signal matches baseline — within normal deviation";
    } else if (baseStatus === "learning") {
        blStatus = "warn"; blDetail = "Baseline still learning — insufficient historical data";
    } else if (anomScore > 0.7) {
        blStatus = "fail"; blDetail = "Significant deviation from baseline (score " + anomScore.toFixed(2) + " > 0.7)";
    } else if (anomScore > 0.4) {
        blStatus = "warn"; blDetail = "Moderate deviation from baseline (score " + anomScore.toFixed(2) + ")";
    } else {
        blStatus = "pass"; blDetail = "Minor deviation (score " + anomScore.toFixed(2) + ")";
    }
    steps.push({ label: "Baseline Comparison", status: blStatus, detail: blDetail });

    // Step 3: Classification Confidence
    var conf = det.confidence;
    var confStatus, confDetail;
    if (conf == null) {
        confStatus = "unknown"; confDetail = "Confidence data not available";
    } else if (conf > 0.8) {
        confStatus = "pass"; confDetail = "Confidence " + (conf * 100).toFixed(1) + "% — high certainty classification";
    } else if (conf >= 0.5) {
        confStatus = "warn"; confDetail = "Confidence " + (conf * 100).toFixed(1) + "% — moderate certainty, review waveform";
    } else {
        confStatus = "fail"; confDetail = "Confidence " + (conf * 100).toFixed(1) + "% — low certainty, likely misclassification";
    }
    steps.push({ label: "Classification Confidence", status: confStatus, detail: confDetail });

    // Step 4: Multi-node Correlation
    var nodeId = det.node_id || "";
    var mnStatus = "unknown";
    var mnDetail = "Checking other nodes...";
    steps.push({ label: "Multi-Node Correlation", status: mnStatus, detail: mnDetail, id: "inv-multi-node" });
    // Settle the step on its grade: class, icon and detail together.
    var settleMultiNode = function(status, detail) {
        var mnEl = document.getElementById("inv-multi-node");
        if (!mnEl) return;
        var icons = { pass: "\u2714", warn: "\u26A0", fail: "\u2716", unknown: "\u2014" };
        mnEl.className = "inv-step inv-" + status;
        var iconEl = mnEl.querySelector(".inv-step-icon");
        if (iconEl) iconEl.textContent = icons[status] || "\u2014";
        var detailEl = mnEl.querySelector(".inv-step-detail");
        if (detailEl) detailEl.textContent = detail;
    };

    // Async fetch for multi-node check
    s.db.apiFetch("/api/detections/recent?minutes=60&limit=200")
        .then(function(d) {
            var dets = (d && d.detections) ? d.detections : (Array.isArray(d) ? d : []);
            var cls = det.signal_class || "";
            var otherNodes = {};
            for (var i = 0; i < dets.length; i++) {
                if (dets[i].signal_class === cls && dets[i].node_id && dets[i].node_id !== nodeId) {
                    otherNodes[dets[i].node_id] = true;
                }
            }
            var otherCount = Object.keys(otherNodes).length;
            if (otherCount > 0) {
                settleMultiNode("pass", "Corroborated — also seen on " + otherCount + " other node" + (otherCount > 1 ? "s" : "") + " (" + Object.keys(otherNodes).join(", ") + ")");
            } else {
                settleMultiNode("warn", "Single-node detection only — no corroboration from other sensors");
            }
        })
        .catch(function() {
            settleMultiNode("unknown", "Could not check other nodes");
        });

    // Step 5: IQ Waveform Review
    var iqStatus, iqDetail;
    if (det.has_iq_capture) {
        iqStatus = "pass"; iqDetail = "IQ capture available — review constellation and PSD above";
    } else {
        iqStatus = "warn"; iqDetail = "No IQ capture — using synthetic reference only";
    }
    steps.push({ label: "IQ Waveform Review", status: iqStatus, detail: iqDetail });

    // Step 6: Threat Assessment (summary)
    for (var si = 0; si < steps.length; si++) {
        if (steps[si].status === "pass") passCount++;
        else if (steps[si].status === "warn") warnCount++;
        else if (steps[si].status === "fail") failCount++;
    }

    var threatStatus, threatDetail;
    if (failCount >= 2) {
        threatStatus = "fail"; threatDetail = "Multiple failures detected — investigate further or escalate";
    } else if (failCount >= 1) {
        threatStatus = "warn"; threatDetail = "One failure flag — review details before taking action";
    } else if (warnCount >= 2) {
        threatStatus = "warn"; threatDetail = "Multiple warnings — consider additional monitoring";
    } else {
        threatStatus = "pass"; threatDetail = "All checks nominal — likely benign or expected signal";
    }
    steps.push({ label: "Threat Assessment", status: threatStatus, detail: threatDetail });

    // Render steps
    var statusIcons = { pass: "\u2714", warn: "\u26A0", fail: "\u2716", unknown: "\u2014" };
    var h = "";
    for (var i = 0; i < steps.length; i++) {
        var st = steps[i];
        var idAttr = st.id ? " id=\"" + esc(st.id) + "\"" : "";
        h += "<div class=\"inv-step inv-" + esc(st.status) + "\"" + idAttr + ">"
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
        if (failCount >= 2 || (failCount >= 1 && anomScore > 0.7)) {
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
   Bulk Selection (RF Anomalies)
   ================================================================ */

DetectionDashboard.prototype._initBulkSelection = function() {
    var s = this;
    var bar = document.getElementById("rf-bulk-bar");
    var selectAllCb = document.getElementById("rf-select-all");
    var dismissBtn = document.getElementById("rf-bulk-dismiss");
    var escalateBtn = document.getElementById("rf-bulk-escalate");
    var exportBtn = document.getElementById("rf-bulk-export");

    // Show bulk bar whenever anomalies exist (handled in _updateRfBulkBar)
    if (selectAllCb) {
        selectAllCb.addEventListener("change", function() {
            var checked = selectAllCb.checked;
            s._selectedRfIds = {};
            if (checked) {
                // Only anomalies with a stored row ID can be acted on in bulk:
                // a detection_id or a list position is not an rf_anomalies ID.
                var selectable = s._rfSelectableIds();
                for (var i = 0; i < selectable.length; i++) {
                    s._selectedRfIds[selectable[i]] = true;
                }
            }
            s._renderAnomalyQueue();
            s._updateRfBulkBar();
        });
    }

    if (dismissBtn) {
        dismissBtn.addEventListener("click", function() {
            var ids = Object.keys(s._selectedRfIds);
            if (!ids.length) return;
            if (ids.length > 1 && !confirm("Dismiss " + ids.length + " selected anomalies?")) return;
            s.db.apiFetch("/api/detections/anomalies/bulk/dismiss", {
                method: "PUT",
                body: { ids: ids }
            }).then(function() {
                showToast("Dismissed " + ids.length + " anomalies", "success");
                s._selectedRfIds = {};
                s._updateRfBulkBar();
                s._fetchAnomalies();
            }).catch(function() {
                showToast("Bulk dismiss failed", "error");
            });
        });
    }

    if (escalateBtn) {
        escalateBtn.addEventListener("click", function() {
            var ids = Object.keys(s._selectedRfIds);
            if (!ids.length || !escalationFits(ids.length)) return;
            if (!confirm("Escalate " + ids.length + " selected anomalies? One critical alert names them; none is dismissed.")) return;
            // Escalation raises an alert and leaves the anomalies in the queue.
            s.db.apiFetch("/api/detections/anomalies/bulk/escalate", {
                method: "POST",
                body: { ids: ids }
            }).then(function(d) {
                showToast(escalationSummary(d), "warning");
                s._selectedRfIds = {};
                s._updateRfBulkBar();
                s._fetchAnomalies();
            }).catch(function(e) {
                showToast("Bulk escalation failed: " + ((e && (e.detail || e.message)) || "unknown error"), "error");
            });
        });
    }

    if (exportBtn) {
        exportBtn.addEventListener("click", function() {
            var ids = Object.keys(s._selectedRfIds);
            if (!ids.length) return;
            // Build export URL with IDs as query params
            var params = "?format=json&ids=" + ids.map(encodeURIComponent).join(",");
            window.open("/api/export/rf_anomalies" + params, "_blank");
            showToast("Exporting " + ids.length + " anomalies", "info");
        });
    }
};

DetectionDashboard.prototype._bindRfBulkCheckboxes = function(c) {
    var s = this;
    // Individual checkboxes (flat view)
    c.querySelectorAll("[data-rf-bulk-id]").forEach(function(cb) {
        cb.addEventListener("change", function(e) {
            e.stopPropagation();
            var aid = this.getAttribute("data-rf-bulk-id");
            if (this.checked) {
                s._selectedRfIds[aid] = true;
            } else {
                delete s._selectedRfIds[aid];
            }
            // Toggle visual selection on card
            var card = this.closest(".anomaly-card");
            if (card) card.classList.toggle("bulk-selected", this.checked);
            s._updateRfBulkBar();
        });
    });

    // Group checkboxes (grouped view)
    c.querySelectorAll("[data-rf-bulk-group]").forEach(function(cb) {
        cb.addEventListener("change", function(e) {
            e.stopPropagation();
            var ids = this.getAttribute("data-rf-bulk-group").split(",").filter(Boolean);
            for (var i = 0; i < ids.length; i++) {
                if (this.checked) {
                    s._selectedRfIds[ids[i]] = true;
                } else {
                    delete s._selectedRfIds[ids[i]];
                }
            }
            var card = this.closest(".anomaly-card");
            if (card) card.classList.toggle("bulk-selected", this.checked);
            s._updateRfBulkBar();
        });
    });

    s._updateRfBulkBar();
};

/* Row IDs of the loaded anomalies that bulk actions can name. */
DetectionDashboard.prototype._rfSelectableIds = function() {
    var ids = [];
    for (var i = 0; i < this.anomalies.length; i++) {
        if (this.anomalies[i].id != null) ids.push(String(this.anomalies[i].id));
    }
    return ids;
};

DetectionDashboard.prototype._updateRfBulkBar = function() {
    var bar = document.getElementById("rf-bulk-bar");
    var countEl = document.getElementById("rf-bulk-count");
    var selectAllCb = document.getElementById("rf-select-all");
    var dismissBtn = document.getElementById("rf-bulk-dismiss");
    var escalateBtn = document.getElementById("rf-bulk-escalate");
    var exportBtn = document.getElementById("rf-bulk-export");

    if (!bar) return;

    var count = Object.keys(this._selectedRfIds).length;
    bar.style.display = this.anomalies.length > 0 ? "" : "none";
    if (countEl) countEl.textContent = count + " selected";
    if (dismissBtn) dismissBtn.disabled = count === 0;
    if (escalateBtn) escalateBtn.disabled = count === 0;
    if (exportBtn) exportBtn.disabled = count === 0;

    if (selectAllCb) {
        var selectable = this._rfSelectableIds();
        var sel = this._selectedRfIds;
        selectAllCb.checked = selectable.length > 0 && selectable.every(function(id) { return !!sel[id]; });
    }
};

/* ================================================================
   IQ Captures Panel
   ================================================================ */

DetectionDashboard.prototype._fetchIQStats = function() {
    var s = this;
    s.db.apiFetch("/api/iq/stats").then(function(data) {
        var el = function(id) { return document.getElementById(id); };
        if (el("iq-stat-total")) el("iq-stat-total").textContent = data.total_captures || 0;
        if (el("iq-stat-size")) el("iq-stat-size").textContent = _fmtBytes(data.total_size_bytes || 0);
        var bt = data.by_tier || {};
        if (el("iq-stat-critical")) el("iq-stat-critical").textContent = bt.critical || 0;
        if (el("iq-stat-standard")) el("iq-stat-standard").textContent = bt.standard || 0;
        if (el("iq-stat-temporary")) el("iq-stat-temporary").textContent = bt.temporary || 0;
        if (el("iq-captures-badge")) el("iq-captures-badge").textContent = data.total_captures || 0;
    }).catch(function() {});
};

DetectionDashboard.prototype._fetchIQCommands = function() {
    var s = this;
    s.db.apiFetch("/api/nodes/commands").then(function(cmds) {
        var container = document.getElementById("iq-commands-list");
        if (!container) return;
        // Filter to iq_capture commands only
        var iqCmds = (cmds || []).filter(function(c) { return c.command === "iq_capture"; });
        if (iqCmds.length === 0) {
            container.innerHTML = "<p style=\"color:var(--text-secondary);font-size:0.9em;\">No pending captures</p>";
            return;
        }
        var html = "<table class=\"data-table\"><thead><tr><th>Node</th><th>Frequency</th><th>Duration</th><th>Status</th><th>Queued</th></tr></thead><tbody>";
        for (var i = 0; i < iqCmds.length; i++) {
            var c = iqCmds[i];
            var p = c.params || {};
            var freq = p.freq_hz ? (p.freq_hz / 1e6).toFixed(3) + " MHz" : "--";
            var dur = p.duration_ms ? esc(p.duration_ms) + " ms" : "--";
            var statusClass = c.status === "queued" ? "accent-yellow" : c.status === "dispatched" ? "accent-blue" : "accent-green";
            var time = c.queued_at ? _fmtTimeShort(c.queued_at) : "--";
            html += "<tr><td>" + esc(c.node_id) + "</td><td>" + freq + "</td><td>" + dur + "</td>"
                + "<td><span style=\"color:var(--" + statusClass + ")\">" + esc(c.status) + "</span></td>"
                + "<td>" + time + "</td></tr>";
        }
        html += "</tbody></table>";
        container.innerHTML = html;
    }).catch(function() {});
};

DetectionDashboard.prototype._fetchIQCaptures = function() {
    var s = this;
    var qs = "?limit=100";
    var nodeEl = document.getElementById("iq-filter-node");
    var classEl = document.getElementById("iq-filter-class");
    var tierEl = document.getElementById("iq-filter-tier");
    if (nodeEl && nodeEl.value) qs += "&node_id=" + encodeURIComponent(nodeEl.value);
    if (classEl && classEl.value) qs += "&signal_class=" + encodeURIComponent(classEl.value);
    if (tierEl && tierEl.value) qs += "&tier=" + encodeURIComponent(tierEl.value);

    s.db.apiFetch("/api/iq/index" + qs).then(function(rows) {
        var tbody = document.getElementById("iq-captures-tbody");
        var empty = document.getElementById("iq-captures-empty");
        if (!tbody) return;
        if (!rows || rows.length === 0) {
            tbody.innerHTML = "";
            if (empty) empty.style.display = "";
            return;
        }
        if (empty) empty.style.display = "none";

        var nodes = {}, classes = {};
        var html = "";
        s._iqRowsById = {};
        for (var i = 0; i < rows.length; i++) {
            var r = rows[i];
            if (r.detection_id) s._iqRowsById[r.detection_id] = r;
            var detShort = esc(String(r.detection_id || "").substring(0, 12));
            var freqMhz = r.freq_hz ? (r.freq_hz / 1e6).toFixed(3) + " MHz" : "--";
            var samples = r.n_samples ? _fmtNum(r.n_samples) : "--";
            var size = r.file_size_bytes ? _fmtBytes(r.file_size_bytes) : "--";
            var quality = r.quality_score != null ? Math.round(r.quality_score * 100) + "%" : "--";
            var tier = esc(r.tier || "standard");
            var tierClass = tier === "critical" ? "accent-red" : tier === "temporary" ? "text-secondary" : "accent-yellow";
            var captured = r.captured_at ? _fmtTimeShort(r.captured_at) : "--";
            var nodeId = esc(r.node_id || "--");
            var sigClass = esc(r.signal_class || "--");

            if (r.node_id) nodes[r.node_id] = true;
            if (r.signal_class) classes[r.signal_class] = true;

            html += "<tr>"
                + "<td title=\"" + esc(r.detection_id || "") + "\"><code>" + detShort + "</code></td>"
                + "<td>" + nodeId + "</td>"
                + "<td>" + freqMhz + "</td>"
                + "<td><span class=\"signal-class-badge\">" + sigClass + "</span></td>"
                + "<td>" + samples + "</td>"
                + "<td>" + size + "</td>"
                + "<td>" + quality + "</td>"
                + "<td><span style=\"color:var(--" + tierClass + ")\">" + tier + "</span></td>"
                + "<td>" + captured + "</td>"
                + "<td>"
                + "<button class=\"btn btn-sm\" data-iq-view=\"" + esc(r.detection_id || "") + "\" title=\"View constellation &amp; spectrogram\">View</button>"
                + "</td>"
                + "</tr>";
        }
        tbody.innerHTML = html;

        // Populate filter dropdowns with discovered values
        _populateSelect("iq-filter-node", nodes);
        _populateSelect("iq-filter-class", classes);

        // Bind view buttons
        tbody.querySelectorAll("[data-iq-view]").forEach(function(btn) {
            btn.addEventListener("click", function() {
                var detId = btn.getAttribute("data-iq-view");
                if (detId && window.dashboard && window.dashboard.detectionDashboard) {
                    window.dashboard.detectionDashboard._showIQDetail(detId);
                }
            });
        });
    }).catch(function() {});
};

DetectionDashboard.prototype._showIQDetail = function(detId) {
    var s = this;
    s.db.apiFetch("/api/detections/" + encodeURIComponent(detId) + "/iq").then(function(data) {
        // _showDeepDive takes a detection object: build it from the inventory
        // row and the IQ reply's metadata, for exactly this captured detection.
        var row = (s._iqRowsById && s._iqRowsById[detId]) || {};
        var detection = {};
        var k;
        for (k in row) {
            if (Object.prototype.hasOwnProperty.call(row, k)) detection[k] = row[k];
        }
        if (data && typeof data === "object" && !Array.isArray(data)) {
            for (k in data) {
                if (!Object.prototype.hasOwnProperty.call(data, k)) continue;
                var v = data[k];
                // Sample arrays are drawn by the deep dive itself; keep scalars.
                if (v !== null && typeof v === "object") continue;
                if (detection[k] == null) detection[k] = v;
            }
        }
        if (detection.center_freq_hz == null && detection.freq_hz) detection.center_freq_hz = detection.freq_hz;
        detection.detection_id = detId;
        detection.has_iq_capture = true;
        s._showDeepDive(detection);
    }).catch(function(err) {
        showToast("Failed to load IQ data: " + ((err && err.detail) || err.message || "Unknown error"), "error");
    });
};

DetectionDashboard.prototype._initIQCaptures = function() {
    var s = this;
    var refreshBtn = document.getElementById("iq-refresh");
    if (refreshBtn) refreshBtn.addEventListener("click", function() { s._fetchIQStats(); s._fetchIQCommands(); s._fetchIQCaptures(); });

    var nodeEl = document.getElementById("iq-filter-node");
    var classEl = document.getElementById("iq-filter-class");
    var tierEl = document.getElementById("iq-filter-tier");
    if (nodeEl) nodeEl.addEventListener("change", function() { s._fetchIQCaptures(); });
    if (classEl) classEl.addEventListener("change", function() { s._fetchIQCaptures(); });
    if (tierEl) tierEl.addEventListener("change", function() { s._fetchIQCaptures(); });

    s._fetchIQStats();
    s._fetchIQCommands();
    s._fetchIQCaptures();

    // Poll commands every 10s to update status
    s._pollIQCommands = setInterval(function() {
        if (!s.paused && s.autoRefresh && isPageActive()) s._fetchIQCommands();
    }, 10000);
};

/* IQ Captures — helpers */

function _fmtBytes(b) {
    if (b == null || b < 0) return "--";
    if (b < 1024) return Number(b) + " B";
    if (b < 1048576) return (b / 1024).toFixed(1) + " KB";
    if (b < 1073741824) return (b / 1048576).toFixed(1) + " MB";
    return (b / 1073741824).toFixed(2) + " GB";
}

function _fmtNum(n) {
    if (n == null) return "--";
    if (n >= 1000000) return (n / 1000000).toFixed(1) + "M";
    if (n >= 1000) return (n / 1000).toFixed(1) + "K";
    return esc(n);
}

function _fmtTimeShort(iso) {
    if (!iso) return "--";
    try { return new Date(iso).toLocaleString(undefined, { hour12: false, month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); }
    catch (_) { return esc(String(iso).substring(0, 16)); }
}

function _populateSelect(id, valMap) {
    var sel = document.getElementById(id);
    if (!sel) return;
    var current = sel.value;
    var existing = {};
    for (var i = 0; i < sel.options.length; i++) existing[sel.options[i].value] = true;
    var keys = Object.keys(valMap).sort();
    for (var j = 0; j < keys.length; j++) {
        if (!existing[keys[j]]) {
            var opt = document.createElement("option");
            opt.value = keys[j];
            opt.textContent = keys[j];
            sel.appendChild(opt);
        }
    }
    sel.value = current;
}
