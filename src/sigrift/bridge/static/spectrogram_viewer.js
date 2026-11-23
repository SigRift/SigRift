/**
 * The Bridge — Spectrogram / Waterfall Viewer
 *
 * Reusable SpectrogramViewer class for rendering time-frequency-power
 * heatmaps from IQ capture data.  Uses Canvas 2D with bulk ImageData
 * pixel writes (same pattern as ChartUtils.drawHeatmap).
 *
 * Colormaps: jet (default), viridis, hot.
 * Mouse interaction: crosshair + tooltip, click to freeze.
 * Controls: setColormap, setDbRange, exportPng, loadDetection.
 */
"use strict";

/* ================================================================
   SpectrogramViewer Class
   ================================================================ */

/**
 * @param {string} canvasId   DOM id of the <canvas> element
 * @param {Object} [opts]     Optional configuration
 * @param {string} [opts.colormap]    "jet" | "viridis" | "hot"
 * @param {number} [opts.dbMin]       Floor dB for colour mapping
 * @param {number} [opts.dbMax]       Ceiling dB for colour mapping
 * @param {string} [opts.title]       Static title text
 * @param {boolean} [opts.showAxes]   Draw axes (default true)
 * @param {boolean} [opts.showColorbar] Draw colour bar (default true)
 */
function SpectrogramViewer(canvasId, opts) {
    opts = opts || {};
    this._canvasId = canvasId;
    this._canvas = document.getElementById(canvasId);
    this._ctx = this._canvas ? this._canvas.getContext("2d") : null;

    // Rendering options
    this._colormapName = opts.colormap || "jet";
    this._colormap = null;        // built lazily
    this._dbMin = opts.dbMin != null ? opts.dbMin : null;
    this._dbMax = opts.dbMax != null ? opts.dbMax : null;
    this._title = opts.title || "";
    this._showAxes = opts.showAxes !== false;
    this._showColorbar = opts.showColorbar !== false;

    // Last rendered data (kept for mouse interaction)
    this._data = null;            // raw API response
    this._normMatrix = null;      // normalised 0-1 Float32Array per row
    this._dataDbMin = -100;
    this._dataDbMax = -20;
    this._margin = { top: 28, right: 70, bottom: 38, left: 66 };

    // Mouse state
    this._mouseX = -1;
    this._mouseY = -1;
    this._crosshairFrozen = false;
    this._tooltipEl = null;

    this._initEvents();
}

/* ----------------------------------------------------------------
   Theme helpers (match ChartUtils / spectrum_analysis patterns)
   ---------------------------------------------------------------- */

SpectrogramViewer.prototype._themeColor = function(varName, fallback) {
    var s = getComputedStyle(document.documentElement).getPropertyValue(varName);
    return s ? s.trim() : fallback;
};

SpectrogramViewer.prototype._bgPrimary = function() {
    return this._themeColor("--bg-primary", "#0d1117");
};

/* ----------------------------------------------------------------
   Colormap builders
   ---------------------------------------------------------------- */

SpectrogramViewer._colormaps = {};

/** Jet — identical to the one in spectrum_analysis.js / chart_utils.js */
SpectrogramViewer._buildJet = function() {
    var cmap = new Array(256);
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
        cmap[i] = [r, g, b];
    }
    return cmap;
};

/** Viridis (perceptually uniform, dark-to-yellow) */
SpectrogramViewer._buildViridis = function() {
    // 5-stop linear interpolation that approximates viridis
    var stops = [
        [0.0,   68,   1,  84],
        [0.25,  59,  82, 139],
        [0.50,  33, 145, 140],
        [0.75, 94,  201,  98],
        [1.0,  253, 231,  37]
    ];
    return SpectrogramViewer._interpStops(stops);
};

/** Hot (black-red-yellow-white) */
SpectrogramViewer._buildHot = function() {
    var stops = [
        [0.0,     0,   0,   0],
        [0.333, 178,  34,  34],
        [0.667, 255, 165,   0],
        [1.0,   255, 255, 255]
    ];
    return SpectrogramViewer._interpStops(stops);
};

/** Linearly interpolate between colour stops to produce a 256-entry LUT. */
SpectrogramViewer._interpStops = function(stops) {
    var cmap = new Array(256);
    for (var i = 0; i < 256; i++) {
        var t = i / 255;
        // Find bounding stops
        var lo = stops[0], hi = stops[stops.length - 1];
        for (var s = 0; s < stops.length - 1; s++) {
            if (t >= stops[s][0] && t <= stops[s + 1][0]) {
                lo = stops[s];
                hi = stops[s + 1];
                break;
            }
        }
        var frac = (hi[0] === lo[0]) ? 0 : (t - lo[0]) / (hi[0] - lo[0]);
        cmap[i] = [
            Math.round(lo[1] + (hi[1] - lo[1]) * frac),
            Math.round(lo[2] + (hi[2] - lo[2]) * frac),
            Math.round(lo[3] + (hi[3] - lo[3]) * frac)
        ];
    }
    return cmap;
};

SpectrogramViewer.prototype._getColormap = function() {
    var name = this._colormapName || "jet";
    if (!SpectrogramViewer._colormaps[name]) {
        if (name === "viridis") SpectrogramViewer._colormaps[name] = SpectrogramViewer._buildViridis();
        else if (name === "hot") SpectrogramViewer._colormaps[name] = SpectrogramViewer._buildHot();
        else SpectrogramViewer._colormaps[name] = SpectrogramViewer._buildJet();
    }
    return SpectrogramViewer._colormaps[name];
};

/* ----------------------------------------------------------------
   Public API — setColormap / setDbRange / exportPng
   ---------------------------------------------------------------- */

SpectrogramViewer.prototype.setColormap = function(name) {
    this._colormapName = name;
    this._colormap = null;
    if (this._data) this.render(this._data);
};

SpectrogramViewer.prototype.setDbRange = function(min, max) {
    this._dbMin = min;
    this._dbMax = max;
    if (this._data) this.render(this._data);
};

SpectrogramViewer.prototype.exportPng = function() {
    if (!this._canvas) return;
    var link = document.createElement("a");
    link.download = "spectrogram_" + Date.now() + ".png";
    link.href = this._canvas.toDataURL("image/png");
    link.click();
};

/* ----------------------------------------------------------------
   loadDetection — fetch from backend and render
   ---------------------------------------------------------------- */

/**
 * @param {string} detectionId
 * @param {Object} [opts]  { nfft, overlap, window }
 */
SpectrogramViewer.prototype.loadDetection = function(detectionId, opts) {
    var self = this;
    opts = opts || {};
    var nfft = opts.nfft || 256;
    var overlap = opts.overlap != null ? opts.overlap : Math.floor(nfft / 2);
    var win = opts.window || "hann";

    // Ensure overlap < nfft
    if (overlap >= nfft) overlap = nfft - 1;

    var url = "/api/detections/" + encodeURIComponent(detectionId)
        + "/spectrogram?nfft=" + nfft
        + "&overlap=" + overlap
        + "&window=" + encodeURIComponent(win);

    // Use dashboard apiFetch if available, else plain fetch
    var fetchFn;
    if (window.dashboard && window.dashboard.apiFetch) {
        fetchFn = window.dashboard.apiFetch(url);
    } else {
        fetchFn = fetch(url).then(function(r) {
            if (!r.ok) return Promise.reject(new Error("HTTP " + r.status));
            return r.json();
        });
    }

    fetchFn.then(function(data) {
        self._title = "Detection " + detectionId;
        self.render(data);
    }).catch(function(e) {
        self._renderError("Failed to load spectrogram: " + (e.message || e));
    });
};

/* ----------------------------------------------------------------
   render — main rendering entry point
   ---------------------------------------------------------------- */

SpectrogramViewer.prototype.render = function(data) {
    var ctx = this._ctx;
    var canvas = this._canvas;
    if (!ctx || !canvas) return;

    this._data = data;
    var w = canvas.width;
    var h = canvas.height;
    var m = this._margin;

    // Clear
    ctx.fillStyle = this._bgPrimary();
    ctx.fillRect(0, 0, w, h);

    var matrix = data.spectrogram || data.power_matrix || [];
    var timeAxis = data.time_axis || [];
    var freqAxis = data.freq_axis || [];

    if (!matrix.length || !matrix[0] || !matrix[0].length) {
        this._renderError("No spectrogram data");
        return;
    }

    var nTime = matrix.length;
    var nFreq = matrix[0].length;

    // Determine dB range
    var dbMin = Infinity, dbMax = -Infinity;
    for (var ti = 0; ti < nTime; ti++) {
        for (var fi = 0; fi < nFreq; fi++) {
            var v = matrix[ti][fi];
            if (v != null) {
                if (v < dbMin) dbMin = v;
                if (v > dbMax) dbMax = v;
            }
        }
    }
    if (dbMin === Infinity) { dbMin = -100; dbMax = -20; }

    // Override with user-specified range if set
    if (this._dbMin != null) dbMin = this._dbMin;
    if (this._dbMax != null) dbMax = this._dbMax;
    var dbRange = dbMax - dbMin || 1;
    this._dataDbMin = dbMin;
    this._dataDbMax = dbMax;

    // Compute plot area
    var plotW = w - m.left - m.right;
    var plotH = h - m.top - m.bottom;
    if (plotW < 1 || plotH < 1) return;

    // Build normalised matrix and render via ImageData (bulk pixel write)
    var cmap = this._getColormap();
    var cmapLen = cmap.length - 1;
    var pxW = Math.ceil(plotW);
    var pxH = Math.ceil(plotH);
    var imgData = ctx.createImageData(pxW, pxH);
    var pixels = imgData.data;
    var cellW = plotW / nFreq;
    var cellH = plotH / nTime;

    // Store norm matrix for tooltip lookup
    this._normMatrix = new Array(nTime);

    for (var r = 0; r < nTime; r++) {
        var rowData = matrix[r];
        this._normMatrix[r] = new Float32Array(nFreq);
        var y0 = Math.floor(r * cellH);
        var y1 = Math.floor((r + 1) * cellH);

        for (var c = 0; c < nFreq; c++) {
            var val = rowData[c] != null ? rowData[c] : dbMin;
            var norm = (val - dbMin) / dbRange;
            if (norm < 0) norm = 0;
            if (norm > 1) norm = 1;
            this._normMatrix[r][c] = norm;

            var ci = Math.floor(norm * cmapLen);
            var rgb = cmap[ci];
            var x0 = Math.floor(c * cellW);
            var x1 = Math.floor((c + 1) * cellW);

            for (var py = y0; py < y1 && py < pxH; py++) {
                var rowOff = py * pxW;
                for (var px = x0; px < x1 && px < pxW; px++) {
                    var off = (rowOff + px) << 2;
                    pixels[off]     = rgb[0];
                    pixels[off + 1] = rgb[1];
                    pixels[off + 2] = rgb[2];
                    pixels[off + 3] = 255;
                }
            }
        }
    }
    ctx.putImageData(imgData, m.left, m.top);

    // Draw axes and overlays
    if (this._showAxes) {
        this._drawAxes(timeAxis, freqAxis, nTime, nFreq, plotW, plotH);
    }
    if (this._showColorbar) {
        this._drawColorbar(plotH);
    }
    if (this._title) {
        this._drawTitle();
    }

    // Re-draw crosshair if frozen
    if (this._crosshairFrozen && this._mouseX >= 0) {
        this._drawCrosshair();
    }
};

/* ----------------------------------------------------------------
   Axes rendering
   ---------------------------------------------------------------- */

SpectrogramViewer.prototype._drawAxes = function(timeAxis, freqAxis, nTime, nFreq, plotW, plotH) {
    var ctx = this._ctx;
    var m = this._margin;
    var w = this._canvas.width;
    var h = this._canvas.height;

    ctx.fillStyle = this._themeColor("--text-secondary", "#8b949e");
    ctx.font = "10px monospace";

    // Frequency axis (bottom)
    ctx.textAlign = "center";
    var freqStep = Math.max(1, Math.floor(nFreq / 8));
    for (var f = 0; f < nFreq; f += freqStep) {
        var fx = m.left + (f / nFreq) * plotW + (plotW / nFreq) / 2;
        var freqLabel;
        if (freqAxis.length > f) {
            var fVal = freqAxis[f];
            if (Math.abs(fVal) < 10) {
                // Normalised frequency
                freqLabel = fVal.toFixed(2);
            } else {
                freqLabel = (fVal / 1e6).toFixed(2) + " MHz";
            }
        } else {
            freqLabel = String(f);
        }
        ctx.fillText(freqLabel, fx, h - m.bottom + 14);

        // Tick mark
        ctx.strokeStyle = this._themeColor("--border-color", "#30363d");
        ctx.lineWidth = 0.5;
        ctx.beginPath();
        ctx.moveTo(fx, h - m.bottom);
        ctx.lineTo(fx, h - m.bottom + 4);
        ctx.stroke();
    }

    // Time axis (left)
    ctx.textAlign = "right";
    var timeStep = Math.max(1, Math.floor(nTime / 8));
    for (var t = 0; t < nTime; t += timeStep) {
        var ty = m.top + (t / nTime) * plotH + (plotH / nTime) / 2;
        var timeLabel;
        if (timeAxis.length > t) {
            var tVal = timeAxis[t];
            if (tVal < 60) {
                timeLabel = tVal.toFixed(2) + " s";
            } else {
                timeLabel = (tVal / 60).toFixed(1) + " m";
            }
        } else {
            timeLabel = String(t);
        }
        ctx.fillText(timeLabel, m.left - 4, ty + 3);

        // Tick mark
        ctx.strokeStyle = this._themeColor("--border-color", "#30363d");
        ctx.lineWidth = 0.5;
        ctx.beginPath();
        ctx.moveTo(m.left, ty);
        ctx.lineTo(m.left - 4, ty);
        ctx.stroke();
    }

    // Axis lines
    ctx.strokeStyle = this._themeColor("--border-color", "#30363d");
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(m.left, m.top);
    ctx.lineTo(m.left, h - m.bottom);
    ctx.lineTo(w - m.right, h - m.bottom);
    ctx.stroke();

    // Axis titles
    ctx.fillStyle = this._themeColor("--text-secondary", "#8b949e");
    ctx.font = "10px sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("Frequency", m.left + plotW / 2, h - 2);

    ctx.save();
    ctx.translate(12, m.top + plotH / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText("Time", 0, 0);
    ctx.restore();
};

/* ----------------------------------------------------------------
   Colour bar legend (right side)
   ---------------------------------------------------------------- */

SpectrogramViewer.prototype._drawColorbar = function(plotH) {
    var ctx = this._ctx;
    var canvas = this._canvas;
    var m = this._margin;
    var barW = 14;
    var barX = canvas.width - m.right + 12;
    var barY = m.top;
    var barH = plotH;

    var cmap = this._getColormap();
    var cmapLen = cmap.length - 1;

    // Draw colour gradient bar
    for (var py = 0; py < barH; py++) {
        // Top = high dB, bottom = low dB
        var norm = 1.0 - (py / (barH - 1 || 1));
        var ci = Math.floor(norm * cmapLen);
        var rgb = cmap[ci];
        ctx.fillStyle = "rgb(" + rgb[0] + "," + rgb[1] + "," + rgb[2] + ")";
        ctx.fillRect(barX, barY + py, barW, 1);
    }

    // Border
    ctx.strokeStyle = this._themeColor("--border-color", "#30363d");
    ctx.lineWidth = 1;
    ctx.strokeRect(barX, barY, barW, barH);

    // Labels
    ctx.fillStyle = this._themeColor("--text-secondary", "#8b949e");
    ctx.font = "9px monospace";
    ctx.textAlign = "left";

    var nLabels = 5;
    for (var i = 0; i <= nLabels; i++) {
        var frac = i / nLabels;
        var dbVal = this._dataDbMax - (this._dataDbMax - this._dataDbMin) * frac;
        var ly = barY + frac * barH;
        ctx.fillText(dbVal.toFixed(0) + " dB", barX + barW + 3, ly + 3);
    }
};

/* ----------------------------------------------------------------
   Title bar
   ---------------------------------------------------------------- */

SpectrogramViewer.prototype._drawTitle = function() {
    var ctx = this._ctx;
    var m = this._margin;
    ctx.fillStyle = this._themeColor("--text-primary", "#c9d1d9");
    ctx.font = "11px sans-serif";
    ctx.textAlign = "left";

    var titleStr = this._title;
    if (this._data) {
        var nfft = this._data.nfft;
        var nSeg = this._data.n_segments;
        if (nfft) titleStr += "  |  NFFT: " + nfft;
        if (nSeg) titleStr += "  |  Segments: " + nSeg;
    }
    ctx.fillText(titleStr, m.left + 4, m.top - 8);
};

/* ----------------------------------------------------------------
   Mouse interaction — crosshair + tooltip
   ---------------------------------------------------------------- */

SpectrogramViewer.prototype._initEvents = function() {
    var self = this;
    if (!this._canvas) return;

    this._canvas.addEventListener("mousemove", function(e) {
        if (self._crosshairFrozen) return;
        var rect = self._canvas.getBoundingClientRect();
        self._mouseX = e.clientX - rect.left;
        self._mouseY = e.clientY - rect.top;
        self._onMouseMove();
    });

    this._canvas.addEventListener("click", function() {
        self._crosshairFrozen = !self._crosshairFrozen;
        if (!self._crosshairFrozen && self._data) {
            self._hideTooltip();
        }
    });

    this._canvas.addEventListener("mouseleave", function() {
        if (!self._crosshairFrozen) {
            self._mouseX = -1;
            self._mouseY = -1;
            self._hideTooltip();
            if (self._data) self.render(self._data);
        }
    });
};

SpectrogramViewer.prototype._onMouseMove = function() {
    if (!this._data || !this._normMatrix) return;
    this.render(this._data);
    this._drawCrosshair();
};

SpectrogramViewer.prototype._drawCrosshair = function() {
    var ctx = this._ctx;
    var m = this._margin;
    var canvas = this._canvas;
    var w = canvas.width;
    var h = canvas.height;
    var mx = this._mouseX;
    var my = this._mouseY;
    var plotW = w - m.left - m.right;
    var plotH = h - m.top - m.bottom;

    // Only draw inside plot area
    if (mx < m.left || mx > w - m.right || my < m.top || my > h - m.bottom) {
        this._hideTooltip();
        return;
    }

    // Crosshair lines
    ctx.strokeStyle = "rgba(255,255,255,0.5)";
    ctx.lineWidth = 1;
    ctx.setLineDash([4, 3]);

    // Vertical line
    ctx.beginPath();
    ctx.moveTo(mx, m.top);
    ctx.lineTo(mx, h - m.bottom);
    ctx.stroke();

    // Horizontal line
    ctx.beginPath();
    ctx.moveTo(m.left, my);
    ctx.lineTo(w - m.right, my);
    ctx.stroke();

    ctx.setLineDash([]);

    // Compute data coordinates
    var data = this._data;
    var matrix = data.spectrogram || data.power_matrix || [];
    var timeAxis = data.time_axis || [];
    var freqAxis = data.freq_axis || [];
    var nTime = matrix.length;
    var nFreq = matrix[0] ? matrix[0].length : 0;

    var fx = (mx - m.left) / plotW;
    var fy = (my - m.top) / plotH;
    var freqIdx = Math.floor(fx * nFreq);
    var timeIdx = Math.floor(fy * nTime);

    if (freqIdx < 0) freqIdx = 0;
    if (freqIdx >= nFreq) freqIdx = nFreq - 1;
    if (timeIdx < 0) timeIdx = 0;
    if (timeIdx >= nTime) timeIdx = nTime - 1;

    var powerDb = matrix[timeIdx] ? matrix[timeIdx][freqIdx] : null;
    var timeVal = timeAxis.length > timeIdx ? timeAxis[timeIdx] : timeIdx;
    var freqVal = freqAxis.length > freqIdx ? freqAxis[freqIdx] : freqIdx;

    // Format tooltip values
    var freqStr;
    if (typeof freqVal === "number") {
        if (Math.abs(freqVal) < 10) {
            freqStr = freqVal.toFixed(3);
        } else {
            freqStr = (freqVal / 1e6).toFixed(3) + " MHz";
        }
    } else {
        freqStr = String(freqVal);
    }

    var timeStr;
    if (typeof timeVal === "number") {
        if (timeVal < 60) {
            timeStr = timeVal.toFixed(3) + " s";
        } else {
            timeStr = (timeVal / 60).toFixed(2) + " m";
        }
    } else {
        timeStr = String(timeVal);
    }

    var powerStr = powerDb != null ? powerDb.toFixed(1) + " dB" : "--";

    this._showTooltip(mx, my, timeStr, freqStr, powerStr);
};

SpectrogramViewer.prototype._showTooltip = function(x, y, timeStr, freqStr, powerStr) {
    if (!this._tooltipEl) {
        this._tooltipEl = document.createElement("div");
        this._tooltipEl.className = "sg-tooltip";
        this._tooltipEl.style.cssText = "position:absolute;pointer-events:none;"
            + "background:var(--bg-secondary,#161b22);color:var(--text-primary,#e6edf3);"
            + "border:1px solid var(--border-color,#30363d);border-radius:4px;"
            + "padding:4px 8px;font:10px monospace;white-space:nowrap;z-index:100;";
        this._canvas.parentElement.style.position = "relative";
        this._canvas.parentElement.appendChild(this._tooltipEl);
    }

    this._tooltipEl.textContent = "Time: " + timeStr + "  Freq: " + freqStr + "  Power: " + powerStr;
    this._tooltipEl.style.display = "";

    // Position tooltip above and to the right of cursor, clamp to container
    var rect = this._canvas.parentElement.getBoundingClientRect();
    var canvasRect = this._canvas.getBoundingClientRect();
    var offX = canvasRect.left - rect.left;
    var offY = canvasRect.top - rect.top;

    var tipX = offX + x + 12;
    var tipY = offY + y - 28;
    if (tipX + 200 > rect.width) tipX = offX + x - 200;
    if (tipY < 0) tipY = offY + y + 12;

    this._tooltipEl.style.left = tipX + "px";
    this._tooltipEl.style.top = tipY + "px";
};

SpectrogramViewer.prototype._hideTooltip = function() {
    if (this._tooltipEl) this._tooltipEl.style.display = "none";
};

/* ----------------------------------------------------------------
   Error / empty state
   ---------------------------------------------------------------- */

SpectrogramViewer.prototype._renderError = function(msg) {
    var ctx = this._ctx;
    var canvas = this._canvas;
    if (!ctx || !canvas) return;

    var w = canvas.width, h = canvas.height;
    ctx.fillStyle = this._bgPrimary();
    ctx.fillRect(0, 0, w, h);
    ctx.fillStyle = this._themeColor("--text-secondary", "#8b949e");
    ctx.font = "14px sans-serif";
    ctx.textAlign = "center";
    ctx.fillText(msg || "No data", w / 2, h / 2);
};

/* ================================================================
   Integration: wire up spectrogram card controls in the Deep-Dive modal
   ================================================================ */

var spectrogramViewer = null;

(function() {
    /**
     * Initialise the spectrogram viewer once the DOM is ready.
     * Called from the IIFE that hooks into BridgeDashboard._initTabs.
     */
    function initSpectrogramCard() {
        var canvas = document.getElementById("spectrogram-canvas");
        if (!canvas) return;

        spectrogramViewer = new SpectrogramViewer("spectrogram-canvas", {
            colormap: "jet"
        });

        // Export PNG (bound here: the page allows no inline handlers)
        var exportBtn = document.getElementById("sg-export-png");
        if (exportBtn) {
            exportBtn.addEventListener("click", function() {
                if (spectrogramViewer) spectrogramViewer.exportPng();
            });
        }

        // Wire colormap selector
        var cmapSel = document.getElementById("sg-colormap");
        if (cmapSel) {
            cmapSel.addEventListener("change", function() {
                spectrogramViewer.setColormap(cmapSel.value);
            });
        }

        // Wire NFFT / window controls to re-fetch when changed
        var nfftSel = document.getElementById("sg-nfft");
        var windowSel = document.getElementById("sg-window");
        var reloadFn = function() {
            var card = document.getElementById("spectrogram-card");
            var detId = card ? card.getAttribute("data-detection-id") : null;
            if (detId) {
                _sgLoadCurrent(detId);
            }
        };
        if (nfftSel) nfftSel.addEventListener("change", reloadFn);
        if (windowSel) windowSel.addEventListener("change", reloadFn);
    }

    /** Load spectrogram for a given detection using current control values. */
    function _sgLoadCurrent(detectionId) {
        if (!spectrogramViewer) return;
        var nfftSel = document.getElementById("sg-nfft");
        var windowSel = document.getElementById("sg-window");
        var nfft = nfftSel ? parseInt(nfftSel.value) || 256 : 256;
        var win = windowSel ? windowSel.value : "hann";
        spectrogramViewer.loadDetection(detectionId, {
            nfft: nfft,
            overlap: Math.floor(nfft / 2),
            window: win
        });
    }

    /**
     * Public function: show the spectrogram card for a detection.
     * Called from detections.js _showDeepDive when has_iq_capture is true.
     */
    window.showSpectrogramForDetection = function(detectionId) {
        var card = document.getElementById("spectrogram-card");
        if (!card) return;
        card.style.display = "";
        card.setAttribute("data-detection-id", detectionId);
        if (spectrogramViewer) {
            _sgLoadCurrent(detectionId);
        }
    };

    /** Hide the spectrogram card. */
    window.hideSpectrogramCard = function() {
        var card = document.getElementById("spectrogram-card");
        if (card) {
            card.style.display = "none";
            card.removeAttribute("data-detection-id");
        }
    };

    // Hook into BridgeDashboard._initTabs to initialise
    var _prevInit = BridgeDashboard.prototype._initTabs;
    BridgeDashboard.prototype._initTabs = function() {
        _prevInit.call(this);
        initSpectrogramCard();
    };
})();
