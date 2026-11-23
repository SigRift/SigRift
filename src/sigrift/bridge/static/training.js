/**
 * The Bridge — Training Tab
 * Live training run viewer with log tail, accuracy chart, and run cards.
 * Polls training API endpoints every 10 seconds.
 * Security: All dynamic content is HTML-escaped via esc().
 *
 * Works in both dashboard and admin panel contexts.
 * In admin context, auto-initializes when adminPanel is available.
 */
"use strict";

/* -- Compatibility shims for admin panel context ------------------- */
if (typeof setText === "undefined") {
    // eslint-disable-next-line no-unused-vars
    var setText = function(id, val) {
        var el = document.getElementById(id);
        if (el) el.textContent = val == null ? "" : String(val);
    };
}
if (typeof setLoadingState === "undefined") {
    var setLoadingState = function() {};
}
if (typeof clearFetchError === "undefined") {
    var clearFetchError = function() {};
}
if (typeof trackFetchError === "undefined") {
    var trackFetchError = function(_id, e) { console.error("TrainingPanel fetch error:", e); };
}
if (typeof isPageActive === "undefined") {
    var isPageActive = function() { return !document.hidden; };
}

function TrainingPanel(dashboard) {
    this.db = dashboard;
    this.runs = [];
    this.selectedRunId = null;
    this.logPaused = false;
    this.logAutoScroll = true;
    this.logLines = [];
    this.logTotalLines = 0;
    this.metrics = [];
    this.pollTimer = null;

    this._initControls();
    this._loadRuns();
    this._startPolling();
}

/* -- Auto-init in admin panel context ------------------------------ */
(function() {
    // If we're in the admin panel (adminPanel exists, no dashboard), auto-init
    function tryInit() {
        if (typeof TrainingPanel === "function" && window.adminPanel && !window.dashboard) {
            if (!window.adminPanel._trainingPanel) {
                window.adminPanel._trainingPanel = new TrainingPanel(window.adminPanel);
            }
        }
    }
    // Try immediately (admin.js may have already run)
    if (document.readyState === "complete" || document.readyState === "interactive") {
        setTimeout(tryInit, 0);
    }
    // Also try on DOMContentLoaded and load
    document.addEventListener("DOMContentLoaded", function() { setTimeout(tryInit, 100); });
    window.addEventListener("load", function() { setTimeout(tryInit, 100); });
})();

/* -- Controls --------------------------------------------------- */

TrainingPanel.prototype._initControls = function() {
    var s = this;

    var refreshBtn = document.getElementById("training-refresh-btn");
    if (refreshBtn) {
        refreshBtn.addEventListener("click", function() { s._loadRuns(); });
    }

    var pauseBtn = document.getElementById("training-log-pause");
    if (pauseBtn) {
        pauseBtn.addEventListener("click", function() {
            s.logPaused = !s.logPaused;
            pauseBtn.textContent = s.logPaused ? "Resume" : "Pause";
        });
    }

    var topBtn = document.getElementById("training-log-top");
    if (topBtn) {
        topBtn.addEventListener("click", function() {
            var el = document.getElementById("training-log-output");
            if (el) el.scrollTop = 0;
        });
    }
};

/* -- Polling ----------------------------------------------------- */

TrainingPanel.prototype._startPolling = function() {
    var s = this;
    s.pollTimer = setInterval(function() {
        if (s.selectedRunId && !s.logPaused && isPageActive()) {
            s._pollLog();
            s._pollMetrics();
        }
    }, 10000);
};

/* -- Load Runs --------------------------------------------------- */

TrainingPanel.prototype._loadRuns = function() {
    var s = this;
    var listEl = document.getElementById("training-runs-list");
    if (listEl && !listEl.innerHTML) {
        if (typeof setLoadingState === "function") setLoadingState("training-runs-list", true);
    }
    s.db.apiFetch("/api/training/runs")
        .then(function(runs) {
            s.runs = runs || [];
            s._renderRuns();
            clearFetchError("training-runs");
            // Auto-select first run if none selected
            if (!s.selectedRunId && s.runs.length > 0) {
                s._selectRun(s.runs[0].run_id);
            }
        })
        .catch(function(e) {
            trackFetchError("training-runs", e);
            if (typeof setLoadingState === "function") {
                var retryRef = window.dashboard
                    ? "window.dashboard.trainingPanel._loadRuns.bind(window.dashboard.trainingPanel)"
                    : window.adminPanel && window.adminPanel._trainingPanel
                    ? "window.adminPanel._trainingPanel._loadRuns.bind(window.adminPanel._trainingPanel)"
                    : "";
                setLoadingState("training-runs-list", false, "Failed to load training runs", retryRef);
            }
        });
};

/* -- Render Runs ------------------------------------------------- */

TrainingPanel.prototype._renderRuns = function() {
    var listEl = document.getElementById("training-runs-list");
    var emptyEl = document.getElementById("training-runs-empty");
    if (!listEl) return;

    setText("training-run-count", this.runs.length);

    if (!this.runs.length) {
        listEl.innerHTML = "";
        if (emptyEl) emptyEl.style.display = "";
        return;
    }
    if (emptyEl) emptyEl.style.display = "none";

    var s = this;
    var h = "<div class=\"training-runs-grid\">";
    for (var i = 0; i < this.runs.length; i++) {
        var r = this.runs[i];
        var statusCls = r.status === "active" ? "status-active" : r.status === "completed" ? "status-completed" : r.status === "stalled" ? "status-stalled" : r.status === "failed" ? "status-failed" : "status-starting";
        var isSelected = r.run_id === s.selectedRunId;
        var accPct = r.best_val_acc != null ? (r.best_val_acc * 100).toFixed(1) + "%" : "--";
        var accCls = r.best_val_acc != null && r.best_val_acc >= 0.65 ? "accent-green" : r.best_val_acc != null && r.best_val_acc >= 0.5 ? "accent-yellow" : "accent-red";

        h += "<div class=\"training-run-card" + (isSelected ? " selected" : "") + "\" data-run-id=\"" + esc(r.run_id) + "\">"
            + "<div class=\"training-run-header\">"
            + "<span class=\"training-run-status " + statusCls + "\">" + esc(r.status || "unknown") + "</span>"
            + "<strong>" + esc(r.dir) + "</strong>"
            + "</div>"
            + "<div class=\"training-run-meta\">";

        if (r.gpu) h += "<span>GPU: " + esc(r.gpu) + "</span>";
        if (r.current_epoch != null) h += "<span>Epoch: " + esc(r.current_epoch) + "/" + esc(r.total_epochs || "?") + "</span>";
        h += "<span style=\"color:var(--" + accCls + ")\">Best: " + esc(accPct) + "</span>";
        if (r.lr != null) h += "<span>LR: " + esc(r.lr) + "</span>";
        if (r.batch_size) h += "<span>Batch: " + esc(r.batch_size) + "</span>";
        if (r.gamma != null) h += "<span>Gamma: " + esc(r.gamma) + "</span>";
        if (r.start_time) h += "<span>" + esc(r.start_time) + "</span>";
        if (r.last_activity_s != null) h += "<span>Last: " + (r.last_activity_s < 60 ? r.last_activity_s.toFixed(0) + "s ago" : (r.last_activity_s / 60).toFixed(0) + "m ago") + "</span>";

        h += "</div></div>";
    }
    h += "</div>";
    listEl.innerHTML = h;

    // Bind click events
    listEl.querySelectorAll("[data-run-id]").forEach(function(card) {
        card.addEventListener("click", function() {
            s._selectRun(this.getAttribute("data-run-id"));
        });
    });
};

/* -- Select Run -------------------------------------------------- */

TrainingPanel.prototype._selectRun = function(runId) {
    this.selectedRunId = runId;
    this.logLines = [];
    this.logTotalLines = 0;

    // Update card selection styling
    var cards = document.querySelectorAll(".training-run-card");
    for (var i = 0; i < cards.length; i++) {
        cards[i].classList.toggle("selected", cards[i].getAttribute("data-run-id") === runId);
    }

    // Find run metadata
    var run = null;
    for (var j = 0; j < this.runs.length; j++) {
        if (this.runs[j].run_id === runId) { run = this.runs[j]; break; }
    }
    var label = run ? run.dir + "/" + run.filename : runId;
    setText("training-log-label", label);
    setText("training-chart-label", label);

    // Clear log and chart
    var logEl = document.getElementById("training-log-output");
    if (logEl) logEl.textContent = "Loading log...";

    this._pollLog();
    this._pollMetrics();
    this._updateSuggestions();
};

/* -- Poll Log ---------------------------------------------------- */

TrainingPanel.prototype._pollLog = function() {
    var s = this;
    if (!s.selectedRunId) return;
    var parts = s.selectedRunId.split("/");
    if (parts.length < 2) return;
    var runDir = parts[0];
    var runName = parts[1];

    s.db.apiFetch("/api/training/runs/" + encodeURIComponent(runDir) + "/" + encodeURIComponent(runName) + "/log?lines=500")
        .then(function(d) {
            s.logLines = d.lines || [];
            s.logTotalLines = d.total_lines || 0;
            s._renderLog();
            clearFetchError("training-log");
        })
        .catch(function(e) {
            trackFetchError("training-log", e);
        });
};

/* -- Render Log -------------------------------------------------- */

TrainingPanel.prototype._renderLog = function() {
    var el = document.getElementById("training-log-output");
    if (!el) return;

    var h = "";
    for (var i = 0; i < this.logLines.length; i++) {
        var line = this.logLines[i];
        var cls = "";

        // Color-code lines
        if (line.indexOf("ERROR") !== -1 || line.indexOf("[ERROR]") !== -1) {
            cls = "log-error";
        } else if (line.indexOf("WARNING") !== -1 || line.indexOf("[WARNING]") !== -1) {
            cls = "log-warn";
        } else if (line.indexOf("Epoch") !== -1 && line.indexOf("val_acc") !== -1) {
            cls = "log-epoch";
        } else if (line.indexOf("New best") !== -1) {
            cls = "log-best";
        } else if (line.indexOf("=====") !== -1) {
            cls = "log-header";
        }

        h += "<span class=\"log-line " + cls + "\">" + esc(line) + "</span>\n";
    }
    el.innerHTML = h;

    // Auto-scroll to bottom
    if (this.logAutoScroll && !this.logPaused) {
        el.scrollTop = el.scrollHeight;
    }
};

/* -- Poll Metrics ------------------------------------------------ */

TrainingPanel.prototype._pollMetrics = function() {
    var s = this;
    if (!s.selectedRunId) return;
    var parts = s.selectedRunId.split("/");
    if (parts.length < 2) return;
    var runDir = parts[0];
    var runName = parts[1];

    s.db.apiFetch("/api/training/runs/" + encodeURIComponent(runDir) + "/" + encodeURIComponent(runName) + "/metrics")
        .then(function(d) {
            s.metrics = d.epochs || [];
            s._renderAccuracyChart();
            s._updateSuggestions();
            clearFetchError("training-metrics");
        })
        .catch(function(e) {
            trackFetchError("training-metrics", e);
        });
};

/* -- Accuracy Chart ---------------------------------------------- */

TrainingPanel.prototype._renderAccuracyChart = function() {
    var cv = document.getElementById("training-acc-canvas");
    if (!cv || !this.metrics.length) {
        if (cv) {
            var ctx = cv.getContext("2d");
            ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--bg-primary").trim() || "#0d1117";
            ctx.fillRect(0, 0, cv.width, cv.height);
            ctx.fillStyle = "#8b949e";
            ctx.font = "12px sans-serif";
            ctx.textAlign = "center";
            ctx.fillText("No epoch data yet", cv.width / 2, cv.height / 2);
        }
        return;
    }

    if (typeof ChartUtils !== "undefined" && ChartUtils.resizeCanvas) {
        ChartUtils.resizeCanvas(cv);
    }
    var ctx = cv.getContext("2d");
    var w = cv.width, h = cv.height;
    var pad = { top: 20, right: 20, bottom: 30, left: 50 };
    var plotW = w - pad.left - pad.right;
    var plotH = h - pad.top - pad.bottom;

    // Clear
    var bgColor = getComputedStyle(document.documentElement).getPropertyValue("--bg-primary").trim() || "#0d1117";
    ctx.fillStyle = bgColor;
    ctx.fillRect(0, 0, w, h);

    var epochs = this.metrics;
    var maxEpoch = epochs[epochs.length - 1].epoch;
    var totalEpochs = epochs[epochs.length - 1].total_epochs || maxEpoch;

    // Y-axis: 0 to 1.0
    var yMin = 0, yMax = 1.0;

    function xPos(epoch) { return pad.left + (epoch / totalEpochs) * plotW; }
    function yPos(val) { return pad.top + (1 - (val - yMin) / (yMax - yMin)) * plotH; }

    // Grid lines
    ctx.strokeStyle = "#30363d";
    ctx.lineWidth = 0.5;
    for (var g = 0; g <= 4; g++) {
        var gy = pad.top + plotH * g / 4;
        ctx.beginPath();
        ctx.moveTo(pad.left, gy);
        ctx.lineTo(w - pad.right, gy);
        ctx.stroke();
    }

    // Target line at 65%
    ctx.strokeStyle = "#d29922";
    ctx.lineWidth = 1;
    ctx.setLineDash([4, 4]);
    ctx.beginPath();
    ctx.moveTo(pad.left, yPos(0.65));
    ctx.lineTo(w - pad.right, yPos(0.65));
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = "#d29922";
    ctx.font = "10px monospace";
    ctx.textAlign = "left";
    ctx.fillText("65% target", w - pad.right - 65, yPos(0.65) - 4);

    // Val accuracy line
    ctx.beginPath();
    ctx.strokeStyle = "#58a6ff";
    ctx.lineWidth = 2;
    for (var i = 0; i < epochs.length; i++) {
        var x = xPos(epochs[i].epoch);
        var y = yPos(epochs[i].val_acc);
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    }
    ctx.stroke();

    // Train accuracy line (dimmer)
    ctx.beginPath();
    ctx.strokeStyle = "rgba(88,166,255,0.3)";
    ctx.lineWidth = 1;
    for (var j = 0; j < epochs.length; j++) {
        var x2 = xPos(epochs[j].epoch);
        var y2 = yPos(epochs[j].train_acc);
        j === 0 ? ctx.moveTo(x2, y2) : ctx.lineTo(x2, y2);
    }
    ctx.stroke();

    // Val loss line (red, secondary axis conceptual)
    ctx.beginPath();
    ctx.strokeStyle = "rgba(248,81,73,0.5)";
    ctx.lineWidth = 1;
    var maxLoss = 0;
    for (var k = 0; k < epochs.length; k++) {
        if (epochs[k].val_loss > maxLoss) maxLoss = epochs[k].val_loss;
    }
    if (maxLoss > 0) {
        for (var l = 0; l < epochs.length; l++) {
            var x3 = xPos(epochs[l].epoch);
            var y3 = pad.top + (epochs[l].val_loss / maxLoss) * plotH;
            l === 0 ? ctx.moveTo(x3, y3) : ctx.lineTo(x3, y3);
        }
        ctx.stroke();
    }

    // Best val_acc marker
    var bestAcc = 0, bestEpoch = 0;
    for (var m = 0; m < epochs.length; m++) {
        if (epochs[m].val_acc > bestAcc) {
            bestAcc = epochs[m].val_acc;
            bestEpoch = epochs[m].epoch;
        }
    }
    if (bestAcc > 0) {
        ctx.fillStyle = "#3fb950";
        ctx.beginPath();
        ctx.arc(xPos(bestEpoch), yPos(bestAcc), 4, 0, 2 * Math.PI);
        ctx.fill();
        ctx.fillStyle = "#3fb950";
        ctx.font = "10px monospace";
        ctx.textAlign = "left";
        ctx.fillText((bestAcc * 100).toFixed(1) + "%", xPos(bestEpoch) + 6, yPos(bestAcc) - 4);
    }

    // Axis labels
    ctx.fillStyle = "#8b949e";
    ctx.font = "10px monospace";
    ctx.textAlign = "right";
    for (var a = 0; a <= 4; a++) {
        var val = yMax - (a / 4) * (yMax - yMin);
        ctx.fillText((val * 100).toFixed(0) + "%", pad.left - 4, pad.top + plotH * a / 4 + 4);
    }
    ctx.textAlign = "center";
    ctx.fillText("Epoch", w / 2, h - 4);

    // Epoch numbers
    var step = Math.max(1, Math.floor(totalEpochs / 10));
    for (var e = 0; e <= totalEpochs; e += step) {
        ctx.fillText(String(e), xPos(e), h - 14);
    }

    // Legend
    ctx.font = "10px sans-serif";
    ctx.textAlign = "left";
    ctx.fillStyle = "#58a6ff";
    ctx.fillText("val_acc", pad.left + 4, pad.top + 12);
    ctx.fillStyle = "rgba(248,81,73,0.7)";
    ctx.fillText("val_loss", pad.left + 60, pad.top + 12);
};

/* -- Suggested Improvements -------------------------------------- */

TrainingPanel.prototype._updateSuggestions = function() {
    var body = document.getElementById("training-suggestions-body");
    var empty = document.getElementById("training-suggestions-empty");
    var badge = document.getElementById("training-suggestions-badge");
    if (!body) return;

    // Find current run
    var run = null;
    for (var i = 0; i < this.runs.length; i++) {
        if (this.runs[i].run_id === this.selectedRunId) { run = this.runs[i]; break; }
    }

    if (!run) {
        if (empty) empty.style.display = "";
        body.querySelector(".training-suggestions-list")
            && body.querySelector(".training-suggestions-list").remove();
        if (badge) badge.textContent = "--";
        return;
    }
    if (empty) empty.style.display = "none";

    var suggestions = this._generateSuggestions(run, this.metrics);
    if (badge) badge.textContent = String(suggestions.length);

    var h = '<div class="training-suggestions-list">';
    if (suggestions.length === 0) {
        h += '<p style="color:var(--text-secondary);padding:8px 0;">No suggestions — model looks good.</p>';
    }
    for (var j = 0; j < suggestions.length; j++) {
        var s = suggestions[j];
        var iconColor = s.priority === "high" ? "var(--accent-red)"
            : s.priority === "medium" ? "var(--accent-yellow)"
            : "var(--accent-green)";
        var icon = s.priority === "high" ? "&#9888;" : s.priority === "medium" ? "&#9679;" : "&#10003;";
        h += '<div style="padding:8px 0;border-bottom:1px solid var(--border-color);display:flex;gap:10px;align-items:flex-start;">'
            + '<span style="color:' + iconColor + ';font-size:16px;flex-shrink:0;">' + icon + '</span>'
            + '<div>'
            + '<strong style="font-size:13px;">' + esc(s.title) + '</strong>'
            + '<p style="margin:2px 0 0;font-size:12px;color:var(--text-secondary);">' + esc(s.detail) + '</p>'
            + '</div></div>';
    }
    h += '</div>';
    body.innerHTML = h;
};

TrainingPanel.prototype._generateSuggestions = function(run, metrics) {
    var suggestions = [];
    var bestAcc = run.best_val_acc;
    var epochs = metrics || [];
    var lastEpoch = epochs.length > 0 ? epochs[epochs.length - 1] : null;

    // -- Accuracy-based suggestions --
    if (bestAcc != null && bestAcc < 0.50) {
        suggestions.push({
            priority: "high",
            title: "Very low accuracy (" + (bestAcc * 100).toFixed(1) + "%)",
            detail: "Model is barely learning. Check data pipeline, verify labels are correct, reduce learning rate, or simplify architecture. Consider starting with fewer classes.",
        });
    } else if (bestAcc != null && bestAcc < 0.65) {
        suggestions.push({
            priority: "medium",
            title: "Below target accuracy (" + (bestAcc * 100).toFixed(1) + "% vs 65% target)",
            detail: "Try: increase training epochs, add data augmentation (SNR jitter, frequency offset, phase noise), use curriculum learning with progressive SNR difficulty.",
        });
    } else if (bestAcc != null && bestAcc < 0.75) {
        suggestions.push({
            priority: "low",
            title: "Good accuracy, room for improvement (" + (bestAcc * 100).toFixed(1) + "%)",
            detail: "To push higher: add real hardware training data, tune class weights for confused pairs, increase DSP feature injection, try ensemble methods.",
        });
    }

    // -- Overfitting detection --
    if (lastEpoch && lastEpoch.train_acc && lastEpoch.val_acc) {
        var gap = lastEpoch.train_acc - lastEpoch.val_acc;
        if (gap > 0.15) {
            suggestions.push({
                priority: "high",
                title: "Overfitting detected (train-val gap: " + (gap * 100).toFixed(1) + "%)",
                detail: "Train accuracy significantly exceeds validation. Add dropout, increase weight decay, reduce model capacity, or add more training data diversity.",
            });
        } else if (gap > 0.08) {
            suggestions.push({
                priority: "medium",
                title: "Mild overfitting (train-val gap: " + (gap * 100).toFixed(1) + "%)",
                detail: "Consider: stronger augmentation, label smoothing (if not already used), or early stopping with lower patience.",
            });
        }
    }

    // -- Learning rate suggestions --
    if (run.lr != null) {
        if (run.lr > 0.01) {
            suggestions.push({
                priority: "medium",
                title: "High learning rate (" + run.lr + ")",
                detail: "LR > 0.01 can cause instability with 30-class classification. Try cosine annealing from " + run.lr + " to 1e-5, or reduce to 1e-3 with warmup.",
            });
        }
    }

    // -- Convergence detection --
    if (epochs.length >= 10) {
        var recentAccs = [];
        for (var i = Math.max(0, epochs.length - 10); i < epochs.length; i++) {
            recentAccs.push(epochs[i].val_acc);
        }
        var accRange = Math.max.apply(null, recentAccs) - Math.min.apply(null, recentAccs);
        if (accRange < 0.005 && epochs.length > 20) {
            suggestions.push({
                priority: "medium",
                title: "Training has plateaued",
                detail: "Validation accuracy has not changed by more than 0.5% in the last 10 epochs. Try: reducing LR by 10x, switching optimizer, adding real hardware data, or changing architecture.",
            });
        }
    }

    // -- Loss divergence --
    if (epochs.length >= 5) {
        var recentLoss = [];
        for (var k = Math.max(0, epochs.length - 5); k < epochs.length; k++) {
            recentLoss.push(epochs[k].val_loss);
        }
        var lossIncreasing = true;
        for (var l = 1; l < recentLoss.length; l++) {
            if (recentLoss[l] <= recentLoss[l - 1]) { lossIncreasing = false; break; }
        }
        if (lossIncreasing && recentLoss.length >= 3) {
            suggestions.push({
                priority: "high",
                title: "Validation loss is increasing",
                detail: "Loss has increased for 5+ consecutive epochs — model is diverging. Reduce learning rate immediately or restore from best checkpoint.",
            });
        }
    }

    // -- Batch size suggestions --
    if (run.batch_size) {
        if (run.batch_size < 32) {
            suggestions.push({
                priority: "low",
                title: "Small batch size (" + run.batch_size + ")",
                detail: "Batch sizes < 32 increase gradient noise. If GPU memory allows, try 64 or 128 for more stable training.",
            });
        } else if (run.batch_size > 256) {
            suggestions.push({
                priority: "low",
                title: "Large batch size (" + run.batch_size + ")",
                detail: "Very large batches can reduce generalization. If accuracy is flat, try reducing to 64-128 with LR scaling.",
            });
        }
    }

    // -- Hardware data suggestion (always relevant for synthetic-only) --
    if (bestAcc != null && bestAcc > 0.60) {
        suggestions.push({
            priority: "medium",
            title: "Validate with real hardware data",
            detail: "Current accuracy (" + (bestAcc * 100).toFixed(1) + "%) is on synthetic data. Real-world signals have hardware impairments (DC offset, IQ imbalance, phase noise) that synthetic data doesn't model. Capture OTA signals for validation.",
        });
    }

    // -- Epoch count --
    if (lastEpoch && lastEpoch.epoch < 30 && bestAcc != null && bestAcc < 0.70) {
        suggestions.push({
            priority: "low",
            title: "May need more epochs (" + lastEpoch.epoch + " completed)",
            detail: "30-class modulation classification typically needs 50-100 epochs to converge fully. Consider running longer with early stopping patience=30.",
        });
    }

    return suggestions;
};
