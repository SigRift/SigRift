/**
 * The Bridge — Cross-Node Correlation Dashboard
 * Matrix heatmap, multi-node timeline, and cluster cards
 * for visualizing correlated detections across nodes.
 * Security: All dynamic content HTML-escaped via esc().
 */
"use strict";

/* ================================================================
   CorrelationView Class
   ================================================================ */

function CorrelationView(dashboard) {
    this.db = dashboard;
    this.rangeHours = 4;
    this._pollTimer = null;
    this._initControls();
}

/* -- Node colors (reused from NodeComparison palette) ----------- */

CorrelationView.COLORS = [
    "#58a6ff", "#3fb950", "#a371f7", "#d29922",
    "#f85149", "#79c0ff", "#56d364", "#db61a2"
];

/* -- Controls --------------------------------------------------- */

CorrelationView.prototype._initControls = function() {
    var self = this;

    // Range buttons
    var btns = document.querySelectorAll(".corr-range-btn");
    for (var i = 0; i < btns.length; i++) {
        btns[i].addEventListener("click", function() {
            var all = document.querySelectorAll(".corr-range-btn");
            for (var j = 0; j < all.length; j++) all[j].classList.remove("active");
            this.classList.add("active");
            self.rangeHours = parseInt(this.getAttribute("data-corr-range"), 10) || 4;
            self.refresh();
        });
    }

    // Refresh button
    var refBtn = document.getElementById("corr-refresh-btn");
    if (refBtn) {
        refBtn.addEventListener("click", function() { self.refresh(); });
    }
};

/* -- Start / Stop polling --------------------------------------- */

CorrelationView.prototype.start = function() {
    this.refresh();
    var self = this;
    this._pollTimer = setInterval(function() { self.refresh(); }, 30000);
};

CorrelationView.prototype.stop = function() {
    if (this._pollTimer) { clearInterval(this._pollTimer); this._pollTimer = null; }
};

/* -- Refresh all correlation data ------------------------------- */

CorrelationView.prototype.refresh = function() {
    var self = this;
    var h = self.rangeHours;

    // Fetch all three endpoints in parallel
    self.db.apiFetch("/api/detections/correlations/matrix?hours=" + h)
        .then(function(d) { self._renderMatrix(d); })
        .catch(function() {});

    self.db.apiFetch("/api/detections/correlations/timeline?hours=" + h + "&buckets=60")
        .then(function(d) { self._renderTimeline(d); })
        .catch(function() {});

    self.db.apiFetch("/api/detections/correlations/clusters?hours=" + h + "&limit=20")
        .then(function(d) { self._renderClusters(d); self._updateKPIs(d); })
        .catch(function() {});

    self.db.apiFetch("/api/detections/correlations/summary")
        .then(function(d) { self._updateSummaryKPI(d); })
        .catch(function() {});
};

/* -- KPI updates ------------------------------------------------ */

CorrelationView.prototype._updateKPIs = function(data) {
    if (!data) return;
    setText("corr-kpi-clusters", data.cluster_count || 0);
    setText("corr-kpi-nodes", data.total_active_nodes || 0);

    var badge = document.getElementById("corr-cluster-badge");
    if (badge) badge.textContent = String(data.cluster_count || 0);

    // Max agreement across clusters
    var maxAgree = 0;
    var clusters = data.clusters || [];
    for (var i = 0; i < clusters.length; i++) {
        if (clusters[i].agreement > maxAgree) maxAgree = clusters[i].agreement;
    }
    setText("corr-kpi-agreement", maxAgree > 0 ? (maxAgree * 100).toFixed(0) + "%" : "--");
};

CorrelationView.prototype._updateSummaryKPI = function(data) {
    if (!data) return;
    setText("corr-kpi-24h", data.total_correlations_24h || 0);
};

/* -- Matrix Heatmap --------------------------------------------- */

CorrelationView.prototype._renderMatrix = function(data) {
    var cv = document.getElementById("corr-matrix-canvas");
    var emptyEl = document.getElementById("corr-matrix-empty");
    if (!cv) return;
    var ctx = cv.getContext("2d");

    var nodes = data && data.node_ids ? data.node_ids : [];
    var matrix = data && data.matrix ? data.matrix : {};

    if (nodes.length < 2) {
        ctx.fillStyle = "#0d1117"; ctx.fillRect(0, 0, cv.width, cv.height);
        if (emptyEl) emptyEl.style.display = "";
        return;
    }
    if (emptyEl) emptyEl.style.display = "none";

    var n = nodes.length;
    var pad = 90;
    var cellSize = Math.min(Math.floor((cv.width - pad) / n), 60);
    var totalSize = pad + n * cellSize + 10;

    cv.width = totalSize;
    cv.height = totalSize;
    ctx = cv.getContext("2d");

    ctx.fillStyle = "#0d1117";
    ctx.fillRect(0, 0, cv.width, cv.height);

    // Draw cells
    for (var r = 0; r < n; r++) {
        for (var c = 0; c < n; c++) {
            var x = pad + c * cellSize;
            var y = pad + r * cellSize;

            var val;
            if (r === c) {
                val = 1.0;
            } else {
                var k1 = nodes[r] < nodes[c] ? nodes[r] + "|" + nodes[c] : nodes[c] + "|" + nodes[r];
                val = matrix[k1] != null ? matrix[k1] : 0;
            }

            // Color: interpolate from dark blue (0) to bright green (1)
            var intensity = Math.min(1, Math.max(0, val));
            var red = Math.round(intensity * 63);
            var green = Math.round(30 + intensity * 155);
            var blue = Math.round(80 + (1 - intensity) * 100);
            ctx.fillStyle = "rgb(" + red + "," + green + "," + blue + ")";
            ctx.fillRect(x + 1, y + 1, cellSize - 2, cellSize - 2);

            // Value text
            ctx.fillStyle = intensity > 0.5 ? "#0d1117" : "#e6edf3";
            ctx.font = "bold 11px monospace";
            ctx.textAlign = "center";
            ctx.textBaseline = "middle";
            ctx.fillText(val.toFixed(2), x + cellSize / 2, y + cellSize / 2);
        }
    }

    // Row labels (left)
    ctx.fillStyle = "#8b949e";
    ctx.font = "10px monospace";
    ctx.textAlign = "right";
    ctx.textBaseline = "middle";
    for (var ri = 0; ri < n; ri++) {
        var lbl = nodes[ri].length > 12 ? nodes[ri].substring(0, 12) : nodes[ri];
        ctx.fillText(lbl, pad - 4, pad + ri * cellSize + cellSize / 2);
    }

    // Column labels (top, rotated)
    ctx.save();
    ctx.fillStyle = "#8b949e";
    ctx.font = "10px monospace";
    ctx.textAlign = "left";
    for (var ci = 0; ci < n; ci++) {
        var clbl = nodes[ci].length > 12 ? nodes[ci].substring(0, 12) : nodes[ci];
        ctx.save();
        ctx.translate(pad + ci * cellSize + cellSize / 2, pad - 4);
        ctx.rotate(-Math.PI / 4);
        ctx.fillText(clbl, 0, 0);
        ctx.restore();
    }
    ctx.restore();
};

/* -- Cross-Node Timeline ---------------------------------------- */

CorrelationView.prototype._renderTimeline = function(data) {
    var cv = document.getElementById("corr-timeline-canvas");
    var emptyEl = document.getElementById("corr-timeline-empty");
    if (!cv) return;
    var ctx = cv.getContext("2d");
    var w = cv.width, h = cv.height;
    ctx.fillStyle = "#0d1117"; ctx.fillRect(0, 0, w, h);

    var nodeIds = data && data.node_ids ? data.node_ids : [];
    var series = data && data.series ? data.series : {};
    var overlap = data && data.overlap ? data.overlap : [];
    var labels = data && data.time_labels ? data.time_labels : [];

    if (!nodeIds.length) {
        if (emptyEl) emptyEl.style.display = "";
        return;
    }
    if (emptyEl) emptyEl.style.display = "none";

    var padLeft = 90, padBottom = 25, padTop = 10;
    var stripH = Math.max(20, Math.floor((h - padBottom - padTop) / (nodeIds.length + 1)));
    var chartW = w - padLeft - 10;
    var buckets = data.buckets || 60;
    var barW = chartW / buckets;

    // Draw overlap strip first (top)
    var overlapY = padTop;
    ctx.fillStyle = "#161b22";
    ctx.fillRect(padLeft, overlapY, chartW, stripH - 2);
    ctx.fillStyle = "#8b949e"; ctx.font = "10px monospace"; ctx.textAlign = "right";
    ctx.fillText("Overlap", padLeft - 6, overlapY + stripH / 2 + 4);

    var maxOverlap = 1;
    for (var oi = 0; oi < overlap.length; oi++) {
        if (overlap[oi] > maxOverlap) maxOverlap = overlap[oi];
    }
    for (var obi = 0; obi < overlap.length; obi++) {
        if (overlap[obi] > 0) {
            var obH = (overlap[obi] / maxOverlap) * (stripH - 4);
            ctx.fillStyle = "rgba(248, 81, 73, 0.8)";
            ctx.fillRect(padLeft + obi * barW, overlapY + stripH - 2 - obH, barW - 1, obH);
        }
    }

    // Draw per-node strips
    for (var ni = 0; ni < nodeIds.length; ni++) {
        var nid = nodeIds[ni];
        var nodeData = series[nid] || [];
        var y = padTop + (ni + 1) * stripH;
        var color = CorrelationView.COLORS[ni % CorrelationView.COLORS.length];

        // Node label
        var nlbl = nid.length > 12 ? nid.substring(0, 12) : nid;
        ctx.fillStyle = "#8b949e"; ctx.font = "10px monospace"; ctx.textAlign = "right";
        ctx.fillText(nlbl, padLeft - 6, y + stripH / 2 + 4);

        // Background strip
        ctx.fillStyle = "#161b22";
        ctx.fillRect(padLeft, y, chartW, stripH - 2);

        // Activity bars
        if (nodeData.length > 0) {
            var mx = 1;
            for (var ti = 0; ti < nodeData.length; ti++) { if (nodeData[ti] > mx) mx = nodeData[ti]; }

            for (var tii = 0; tii < nodeData.length; tii++) {
                if (nodeData[tii] > 0) {
                    var bH = (nodeData[tii] / mx) * (stripH - 4);
                    ctx.fillStyle = color;
                    ctx.globalAlpha = 0.75;
                    ctx.fillRect(padLeft + tii * barW, y + stripH - 2 - bH, barW - 1, bH);
                    ctx.globalAlpha = 1.0;
                }
            }
        }
    }

    // Time axis
    ctx.fillStyle = "#8b949e"; ctx.font = "9px monospace"; ctx.textAlign = "center";
    var step = Math.max(1, Math.floor(labels.length / 8));
    for (var li = 0; li < labels.length; li += step) {
        var lx = padLeft + (li / (labels.length - 1 || 1)) * chartW;
        ctx.fillText(labels[li] || "", lx, h - 4);
    }
};

/* -- Cluster Cards ---------------------------------------------- */

CorrelationView.prototype._renderClusters = function(data) {
    var grid = document.getElementById("corr-cluster-grid");
    var emptyEl = document.getElementById("corr-cluster-empty");
    if (!grid) return;

    var clusters = data && data.clusters ? data.clusters : [];
    if (!clusters.length) {
        grid.innerHTML = "";
        if (emptyEl) emptyEl.style.display = "";
        return;
    }
    if (emptyEl) emptyEl.style.display = "none";

    var html = "";
    for (var i = 0; i < clusters.length; i++) {
        var c = clusters[i];
        var agreeClass = c.agreement >= 0.7 ? "corr-agree-high" : c.agreement >= 0.4 ? "corr-agree-medium" : "corr-agree-low";
        var freqMHz = (c.freq_hz / 1e6).toFixed(2);
        var nodeList = (c.node_ids || []).map(function(n) { return esc(n); }).join(", ");

        html += "<div class=\"corr-cluster-card\">"
            + "<div class=\"corr-cluster-header\">"
            + "<span class=\"corr-cluster-signal\">" + esc(c.signal_class) + "</span>"
            + "<span class=\"corr-cluster-agree " + agreeClass + "\">" + (c.agreement * 100).toFixed(0) + "% agree</span>"
            + "</div>"
            + "<div class=\"corr-cluster-body\">"
            + "<div class=\"corr-cluster-row\"><span class=\"corr-lbl\">Frequency</span><span>" + esc(freqMHz) + " MHz</span></div>"
            + "<div class=\"corr-cluster-row\"><span class=\"corr-lbl\">Nodes</span><span>" + esc(String(c.node_count)) + " (" + nodeList + ")</span></div>"
            + "<div class=\"corr-cluster-row\"><span class=\"corr-lbl\">Detections</span><span>" + esc(String(c.detection_count)) + "</span></div>"
            + "<div class=\"corr-cluster-row\"><span class=\"corr-lbl\">Avg Confidence</span><span>" + (c.avg_confidence * 100).toFixed(1) + "%</span></div>"
            + "<div class=\"corr-cluster-row\"><span class=\"corr-lbl\">Duration</span><span>" + c.duration_sec.toFixed(1) + "s</span></div>"
            + "<div class=\"corr-cluster-row\"><span class=\"corr-lbl\">First Seen</span><span>" + fmtTime(c.first_seen) + "</span></div>"
            + "</div>"
            + "</div>";
    }
    grid.innerHTML = html;
};
