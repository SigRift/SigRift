/**
 * The Bridge — Node Comparison
 * Radar chart for family distributions, cross-correlation table,
 * and parallel detection timeline across selected nodes.
 * Security: All dynamic content HTML-escaped via esc().
 */
"use strict";

/* ================================================================
   NodeComparison Class
   ================================================================ */

function NodeComparison(dashboard) {
    this.db = dashboard;
    this.selectedNodes = [];
    this.compData = null;
    this._initControls();
}

/* -- Node colors for radar polygons ----------------------------- */

NodeComparison.NODE_COLORS = [
    { stroke: "#58a6ff", fill: "rgba(88,166,255,0.2)" },
    { stroke: "#3fb950", fill: "rgba(63,185,80,0.2)" },
    { stroke: "#a371f7", fill: "rgba(163,113,247,0.2)" },
    { stroke: "#d29922", fill: "rgba(210,153,34,0.2)" },
    { stroke: "#f85149", fill: "rgba(248,81,73,0.2)" },
    { stroke: "#79c0ff", fill: "rgba(121,192,255,0.2)" }
];

/* -- Radar chart axes (signal families) ------------------------- */

NodeComparison.RADAR_AXES = ["ASK", "PAM", "PSK", "QAM", "APSK", "FSK", "MSK", "OFDM", "ANALOG"];

/* -- Controls --------------------------------------------------- */

NodeComparison.prototype._initControls = function() {
    var s = this;
    var compareBtn = document.getElementById("compare-nodes-btn");
    if (compareBtn) {
        compareBtn.addEventListener("click", function() {
            s._openModal();
        });
    }

    var refreshBtn = document.getElementById("nc-refresh");
    if (refreshBtn) {
        refreshBtn.addEventListener("click", function() {
            if (s.selectedNodes.length >= 2) s._fetchComparison(s.selectedNodes, 1);
        });
    }

    var closeBtn = document.getElementById("node-compare-close");
    var closeBtn2 = document.getElementById("nc-close-btn");
    var overlay = document.getElementById("node-compare-overlay");
    var closeFn = function() { if (overlay) overlay.style.display = "none"; };
    if (closeBtn) closeBtn.addEventListener("click", closeFn);
    if (closeBtn2) closeBtn2.addEventListener("click", closeFn);
    if (overlay) overlay.addEventListener("click", function(e) { if (e.target === overlay) closeFn(); });
};

/* -- Show modal and populate node checkboxes -------------------- */

NodeComparison.prototype._openModal = function() {
    var s = this;
    var overlay = document.getElementById("node-compare-overlay");
    if (!overlay) return;
    overlay.style.display = "";

    // Fetch current nodes to populate checkboxes
    s.db.apiFetch("/api/nodes/").then(function(nodes) {
        s._renderNodeSelector(nodes);
    }).catch(function() {});
};

NodeComparison.prototype.show = function(nodeIds) {
    var overlay = document.getElementById("node-compare-overlay");
    if (!overlay) return;
    overlay.style.display = "";

    this.selectedNodes = nodeIds.slice(0, 6);
    this._fetchComparison(this.selectedNodes, 1);

    // Also render selector with pre-selected nodes
    var s = this;
    s.db.apiFetch("/api/nodes/").then(function(nodes) {
        s._renderNodeSelector(nodes);
    }).catch(function() {});
};

NodeComparison.prototype._renderNodeSelector = function(nodes) {
    var c = document.getElementById("nc-selector");
    if (!c) return;
    var s = this;

    var h = "";
    for (var i = 0; i < nodes.length; i++) {
        var n = nodes[i];
        var id = n.node_id || "";
        var checked = s.selectedNodes.indexOf(id) !== -1;
        var cls = checked ? " checked" : "";
        h += "<label class=\"nc-node-check" + cls + "\">"
            + "<input type=\"checkbox\" data-nc-node=\"" + esc(id) + "\"" + (checked ? " checked" : "") + "> "
            + esc(id)
            + "</label>";
    }
    c.innerHTML = h;

    c.querySelectorAll("input[data-nc-node]").forEach(function(cb) {
        cb.addEventListener("change", function() {
            var nid = this.getAttribute("data-nc-node");
            var lbl = this.closest(".nc-node-check");
            if (this.checked) {
                if (s.selectedNodes.length < 6) {
                    s.selectedNodes.push(nid);
                    if (lbl) lbl.classList.add("checked");
                } else {
                    this.checked = false;
                }
            } else {
                s.selectedNodes = s.selectedNodes.filter(function(x) { return x !== nid; });
                if (lbl) lbl.classList.remove("checked");
            }
            if (s.selectedNodes.length >= 2) {
                s._fetchComparison(s.selectedNodes, 1);
            }
        });
    });
};

/* -- Fetch comparison data -------------------------------------- */

NodeComparison.prototype._fetchComparison = function(nodeIds, rangeHours) {
    var s = this;
    var ids = nodeIds.join(",");
    s.db.apiFetch("/api/detections/nodes/compare?node_ids=" + encodeURIComponent(ids) + "&range_hours=" + (rangeHours || 1))
        .then(function(d) {
            s.compData = d;
            s._renderRadar(d);
            s._renderCorrelation(d);
            s._renderTimeline(d);
        })
        .catch(function() {});
};

/* -- Radar Chart ------------------------------------------------ */

NodeComparison.prototype._renderRadar = function(data) {
    var cv = document.getElementById("nc-radar");
    if (!cv || !data || !data.nodes) return;
    var ctx = cv.getContext("2d");
    var w = cv.width, h = cv.height;
    var cx = w / 2, cy = h / 2;
    var radius = Math.min(cx, cy) - 50;

    // Clear
    ctx.fillStyle = "#0d1117"; ctx.fillRect(0, 0, w, h);

    var axes = NodeComparison.RADAR_AXES;
    var nAxes = axes.length;
    var angleStep = (2 * Math.PI) / nAxes;

    // Find global max for normalization
    var globalMax = 1;
    var nodeKeys = Object.keys(data.nodes);
    for (var ni = 0; ni < nodeKeys.length; ni++) {
        var families = data.nodes[nodeKeys[ni]].families || {};
        for (var ai = 0; ai < nAxes; ai++) {
            var val = families[axes[ai]] || 0;
            if (val > globalMax) globalMax = val;
        }
    }

    // Draw axis lines and labels
    ctx.strokeStyle = "#30363d"; ctx.lineWidth = 0.5;
    ctx.fillStyle = "#8b949e"; ctx.font = "10px monospace"; ctx.textAlign = "center";

    for (var a = 0; a < nAxes; a++) {
        var angle = -Math.PI / 2 + a * angleStep;
        var ax = cx + Math.cos(angle) * radius;
        var ay = cy + Math.sin(angle) * radius;
        ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(ax, ay); ctx.stroke();

        var lx = cx + Math.cos(angle) * (radius + 18);
        var ly = cy + Math.sin(angle) * (radius + 18);
        ctx.fillText(axes[a], lx, ly + 4);
    }

    // Draw concentric rings
    for (var ring = 1; ring <= 4; ring++) {
        var rr = radius * ring / 4;
        ctx.beginPath();
        for (var ra = 0; ra <= nAxes; ra++) {
            var rang = -Math.PI / 2 + ra * angleStep;
            var rx = cx + Math.cos(rang) * rr;
            var ry = cy + Math.sin(rang) * rr;
            ra === 0 ? ctx.moveTo(rx, ry) : ctx.lineTo(rx, ry);
        }
        ctx.stroke();
    }

    // Draw node polygons
    for (var nj = 0; nj < nodeKeys.length; nj++) {
        var nodeId = nodeKeys[nj];
        var fams = data.nodes[nodeId].families || {};
        var color = NodeComparison.NODE_COLORS[nj % NodeComparison.NODE_COLORS.length];

        ctx.beginPath();
        for (var aj = 0; aj < nAxes; aj++) {
            var ang = -Math.PI / 2 + aj * angleStep;
            var v = (fams[axes[aj]] || 0) / globalMax;
            var px = cx + Math.cos(ang) * radius * v;
            var py = cy + Math.sin(ang) * radius * v;
            aj === 0 ? ctx.moveTo(px, py) : ctx.lineTo(px, py);
        }
        ctx.closePath();
        ctx.fillStyle = color.fill;
        ctx.fill();
        ctx.strokeStyle = color.stroke;
        ctx.lineWidth = 2;
        ctx.stroke();
    }

    // Legend below canvas
    var legendEl = cv.parentNode.querySelector(".nc-legend");
    if (!legendEl) {
        legendEl = document.createElement("div");
        legendEl.className = "nc-legend";
        cv.parentNode.appendChild(legendEl);
    }
    var lh = "";
    for (var nl = 0; nl < nodeKeys.length; nl++) {
        var nc = NodeComparison.NODE_COLORS[nl % NodeComparison.NODE_COLORS.length];
        lh += "<span class=\"nc-legend-item\">"
            + "<span class=\"nc-legend-swatch\" style=\"background:" + nc.stroke + "\"></span>"
            + esc(nodeKeys[nl])
            + "</span>";
    }
    legendEl.innerHTML = lh;
};

/* -- Cross-Correlation Table ------------------------------------ */

NodeComparison.prototype._renderCorrelation = function(data) {
    var c = document.getElementById("nc-correlation");
    if (!c || !data) return;

    if (data.correlations) {
        var nodeKeys = Object.keys(data.nodes || {});
        var h = "<table class=\"nc-corr-table\"><thead><tr><th></th>";
        for (var i = 0; i < nodeKeys.length; i++) {
            h += "<th>" + esc(nodeKeys[i]) + "</th>";
        }
        h += "</tr></thead><tbody>";

        for (var r = 0; r < nodeKeys.length; r++) {
            h += "<tr><th>" + esc(nodeKeys[r]) + "</th>";
            for (var co = 0; co < nodeKeys.length; co++) {
                if (r === co) {
                    h += "<td class=\"nc-corr-high\">1.00</td>";
                } else {
                    var key = nodeKeys[r] < nodeKeys[co]
                        ? nodeKeys[r] + "|" + nodeKeys[co]
                        : nodeKeys[co] + "|" + nodeKeys[r];
                    var corr = data.correlations[key] != null ? data.correlations[key] : 0;
                    var cls = corr >= 0.7 ? "nc-corr-high" : corr >= 0.4 ? "nc-corr-medium" : "nc-corr-low";
                    h += "<td class=\"" + cls + "\">" + corr.toFixed(2) + "</td>";
                }
            }
            h += "</tr>";
        }
        h += "</tbody></table>";
        c.innerHTML = h;
    } else {
        c.innerHTML = "<p class=\"empty-state\">No correlation data available</p>";
    }
};

/* -- Detection Timeline ----------------------------------------- */

NodeComparison.prototype._renderTimeline = function(data) {
    var cv = document.getElementById("nc-timeline");
    if (!cv || !data || !data.nodes) return;
    var ctx = cv.getContext("2d");
    var w = cv.width, h = cv.height;
    ctx.fillStyle = "#0d1117"; ctx.fillRect(0, 0, w, h);

    var nodeKeys = Object.keys(data.nodes);
    if (!nodeKeys.length) return;

    var stripH = Math.max(16, Math.floor((h - 30) / nodeKeys.length));
    var padLeft = 80;

    ctx.fillStyle = "#8b949e"; ctx.font = "10px monospace"; ctx.textAlign = "right";

    for (var n = 0; n < nodeKeys.length; n++) {
        var nodeId = nodeKeys[n];
        var nodeData = data.nodes[nodeId];
        var timeline = nodeData.timeline || [];
        var y = 10 + n * stripH;
        var color = NodeComparison.NODE_COLORS[n % NodeComparison.NODE_COLORS.length];

        // Node label
        var label = nodeId.length > 10 ? nodeId.substring(0, 10) : nodeId;
        ctx.fillStyle = "#8b949e";
        ctx.fillText(label, padLeft - 6, y + stripH / 2 + 4);

        // Background strip
        ctx.fillStyle = "#161b22";
        ctx.fillRect(padLeft, y, w - padLeft - 10, stripH - 2);

        // Activity bars
        if (timeline.length > 0) {
            var barW = Math.max(1, (w - padLeft - 10) / timeline.length);
            var mx = 1;
            for (var t = 0; t < timeline.length; t++) { if (timeline[t] > mx) mx = timeline[t]; }

            for (var ti = 0; ti < timeline.length; ti++) {
                if (timeline[ti] > 0) {
                    var barH = (timeline[ti] / mx) * (stripH - 4);
                    ctx.fillStyle = color.stroke;
                    ctx.globalAlpha = 0.7;
                    ctx.fillRect(padLeft + ti * barW, y + stripH - 2 - barH, barW - 1, barH);
                    ctx.globalAlpha = 1.0;
                }
            }
        }
    }

    // Time axis
    ctx.fillStyle = "#8b949e"; ctx.font = "9px monospace"; ctx.textAlign = "center";
    var labels = data.time_labels || [];
    var step = Math.max(1, Math.floor(labels.length / 6));
    for (var li = 0; li < labels.length; li += step) {
        var lx = padLeft + (li / (labels.length - 1 || 1)) * (w - padLeft - 10);
        ctx.fillText(labels[li] || "", lx, h - 2);
    }
};
