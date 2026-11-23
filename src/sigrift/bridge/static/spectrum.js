/**
 * MLRF Gen4 Dashboard - Spectrum Viewer
 *
 * Canvas-based FFT and waterfall display with rtl_tcp connection
 * management and live signal identification overlay.
 */

"use strict";

/* ================================================================
   Color Map — viridis (perceptually uniform, colorblind-safe)
   ----------------------------------------------------------------
   Previously a jet-like gradient (blue -> cyan -> green -> yellow ->
   red), which collided with the dashboard's red=critical /
   yellow=warning semantic. Bright red simply meant "high power" at
   433 MHz ISM, but an operator coming from the Alerts tab would
   misread a healthy spectrum as a danger signal. Jet is also
   perceptually non-uniform (eye perceives the green-yellow transition
   sharper than blue-cyan).

   Viridis (matplotlib default) has monotonic luminance, is CVD-safe,
   and carries no "red = bad" prior. Stops in the LUT below:
     t=0    -> (68, 1, 84)    dark purple = lowest magnitude
     t=0.5  -> (33, 145, 140) teal
     t=1    -> (253, 231, 37) yellow      = highest magnitude
   The 256-entry LUT is the canonical matplotlib viridis table
   (BSD-licensed). A polynomial approximation was tried first but
   diverged at the high end, so the exact LUT is inlined.

   Cog-review dashboard refs: section 5.3 (semantic colormap collision),
   section 5.4 (classification color/magnitude conflation).
   ================================================================ */

var COLORMAP_SIZE = 256;
var COLORMAP_NAME = "viridis";
var _colormap = null;

var VIRIDIS_LUT_256 = [
    [68,1,84],[68,2,86],[69,4,87],[69,5,89],
    [70,7,90],[70,8,92],[70,10,93],[70,11,94],
    [71,13,96],[71,14,97],[71,16,99],[71,17,100],
    [71,19,101],[72,20,103],[72,22,104],[72,23,105],
    [72,24,106],[72,26,108],[72,27,109],[72,28,110],
    [72,29,111],[72,31,112],[72,32,113],[72,33,115],
    [72,35,116],[72,36,117],[72,37,118],[72,38,119],
    [72,40,120],[72,41,121],[71,42,122],[71,44,122],
    [71,45,123],[71,46,124],[71,47,125],[70,48,126],
    [70,50,126],[70,51,127],[70,52,128],[69,53,129],
    [69,55,129],[69,56,130],[68,57,131],[68,58,131],
    [68,59,132],[67,61,132],[67,62,133],[66,63,133],
    [66,64,134],[66,65,134],[65,66,135],[65,68,135],
    [64,69,136],[64,70,136],[63,71,136],[63,72,137],
    [62,73,137],[62,74,137],[62,76,138],[61,77,138],
    [61,78,138],[60,79,138],[60,80,139],[59,81,139],
    [59,82,139],[58,83,139],[58,84,140],[57,85,140],
    [57,86,140],[56,88,140],[56,89,140],[55,90,140],
    [55,91,141],[54,92,141],[54,93,141],[53,94,141],
    [53,95,141],[52,96,141],[52,97,141],[51,98,141],
    [51,99,141],[50,100,142],[50,101,142],[49,102,142],
    [49,103,142],[49,104,142],[48,105,142],[48,106,142],
    [47,107,142],[47,108,142],[46,109,142],[46,110,142],
    [46,111,142],[45,112,142],[45,113,142],[44,113,142],
    [44,114,142],[44,115,142],[43,116,142],[43,117,142],
    [42,118,142],[42,119,142],[42,120,142],[41,121,142],
    [41,122,142],[41,123,142],[40,124,142],[40,125,142],
    [39,126,142],[39,127,142],[39,128,142],[38,129,142],
    [38,130,142],[38,130,142],[37,131,142],[37,132,142],
    [37,133,142],[36,134,142],[36,135,142],[35,136,142],
    [35,137,142],[35,138,141],[34,139,141],[34,140,141],
    [34,141,141],[33,142,141],[33,143,141],[33,144,141],
    [33,145,140],[32,146,140],[32,146,140],[32,147,140],
    [31,148,140],[31,149,139],[31,150,139],[31,151,139],
    [31,152,139],[31,153,138],[31,154,138],[30,155,138],
    [30,156,137],[30,157,137],[31,158,137],[31,159,136],
    [31,160,136],[31,161,136],[31,161,135],[31,162,135],
    [32,163,134],[32,164,134],[33,165,133],[33,166,133],
    [34,167,133],[34,168,132],[35,169,131],[36,170,131],
    [37,171,130],[37,172,130],[38,173,129],[39,173,129],
    [40,174,128],[41,175,127],[42,176,127],[44,177,126],
    [45,178,125],[46,179,124],[47,180,124],[49,181,123],
    [50,182,122],[52,182,121],[53,183,121],[55,184,120],
    [56,185,119],[58,186,118],[59,187,117],[61,188,116],
    [63,188,115],[64,189,114],[66,190,113],[68,191,112],
    [70,192,111],[72,193,110],[74,193,109],[76,194,108],
    [78,195,107],[80,196,106],[82,197,105],[84,197,104],
    [86,198,103],[88,199,101],[90,200,100],[92,200,99],
    [94,201,98],[96,202,96],[99,203,95],[101,203,94],
    [103,204,92],[105,205,91],[108,205,90],[110,206,88],
    [112,207,87],[115,208,86],[117,208,84],[119,209,83],
    [122,209,81],[124,210,80],[127,211,78],[129,211,77],
    [132,212,75],[134,213,73],[137,213,72],[139,214,70],
    [142,214,69],[144,215,67],[147,215,65],[149,216,64],
    [152,216,62],[155,217,60],[157,217,59],[160,218,57],
    [162,218,55],[165,219,54],[168,219,52],[170,220,50],
    [173,220,48],[176,221,47],[178,221,45],[181,222,43],
    [184,222,41],[186,222,40],[189,223,38],[192,223,37],
    [194,223,35],[197,224,33],[200,224,32],[202,225,31],
    [205,225,29],[208,225,28],[210,226,27],[213,226,26],
    [216,226,25],[218,227,25],[221,227,24],[223,227,24],
    [226,228,24],[229,228,25],[231,228,25],[234,229,26],
    [236,229,27],[239,229,28],[241,229,29],[244,230,30],
    [246,230,32],[248,230,33],[251,231,35],[253,231,37]
];

function buildColormap() {
    if (_colormap) return _colormap;
    _colormap = new Array(COLORMAP_SIZE);
    for (var i = 0; i < COLORMAP_SIZE; i++) {
        var c = VIRIDIS_LUT_256[i];
        _colormap[i] = [c[0], c[1], c[2]];
    }
    return _colormap;
}

function dbToColorIndex(db, minDb, maxDb) {
    var norm = (db - minDb) / (maxDb - minDb);
    if (norm < 0) norm = 0;
    if (norm > 1) norm = 1;
    return Math.floor(norm * (COLORMAP_SIZE - 1));
}

/* ================================================================
   SpectrumViewer Class
   ================================================================ */

function SpectrumViewer(dashboard) {
    this.dashboard = dashboard;
    this.connected = false;
    this.paused = false;
    this.ws = null;
    this.config = { center_freq_hz: 433920000, sample_rate_hz: 2048000, gain_db: 40, fft_size: 1024 };
    this.minDb = -80;
    this.maxDb = 0;
    this.peakHold = false;
    this.peakData = null;
    this.averaging = 1;
    this._avgBuffer = [];
    this.signals = [];
    this._frameCount = 0;
    this._fpsTime = 0;
    this._fps = 0;

    this.fftCanvas = document.getElementById("spectrum-canvas");
    this.waterfallCanvas = document.getElementById("waterfall-canvas");
    this.fftCtx = this.fftCanvas ? this.fftCanvas.getContext("2d") : null;
    this.wfCtx = this.waterfallCanvas ? this.waterfallCanvas.getContext("2d") : null;

    this.wsRetries = 0;
    this.wsMaxRetries = 10;

    this._initControls();
    this._resizeCanvases();
    this._drawEmptyFFT();
    this._drawEmptyWaterfall();

    // Resize canvases when window resizes
    var self = this;
    window.addEventListener("resize", function() { self._resizeCanvases(); });
}

/* ----------------------------------------------------------------
   Canvas sizing — match pixel buffer to display size
   ---------------------------------------------------------------- */

SpectrumViewer.prototype._resizeCanvases = function() {
    var containers = [
        { canvas: this.fftCanvas, ctx: "fftCtx", h: 220 },
        { canvas: this.waterfallCanvas, ctx: "wfCtx", h: 200 },
    ];
    for (var i = 0; i < containers.length; i++) {
        var c = containers[i];
        if (!c.canvas) continue;
        var rect = c.canvas.getBoundingClientRect();
        var w = Math.max(rect.width, 400);
        if (c.canvas.width !== Math.floor(w) || c.canvas.height !== c.h) {
            c.canvas.width = Math.floor(w);
            c.canvas.height = c.h;
        }
    }
    this.fftCtx = this.fftCanvas ? this.fftCanvas.getContext("2d") : null;
    this.wfCtx = this.waterfallCanvas ? this.waterfallCanvas.getContext("2d") : null;
};

/* ----------------------------------------------------------------
   Controls
   ---------------------------------------------------------------- */

SpectrumViewer.prototype._initControls = function() {
    var self = this;
    var connectBtn = document.getElementById("spec-connect");
    var disconnectBtn = document.getElementById("spec-disconnect");
    var refreshBtn = document.getElementById("spec-refresh-nodes");
    var pauseBtn = document.getElementById("spec-pause");
    var peakBtn = document.getElementById("spec-peak-hold");
    var avgSlider = document.getElementById("spec-averaging");
    var minDbSlider = document.getElementById("spec-min-db");
    var maxDbSlider = document.getElementById("spec-max-db");

    if (connectBtn) {
        connectBtn.addEventListener("click", function() { self.connect(); });
    }
    if (disconnectBtn) {
        disconnectBtn.addEventListener("click", function() { self.disconnect(); });
    }
    if (refreshBtn) {
        refreshBtn.addEventListener("click", function() { self._loadNodes(); });
    }
    if (pauseBtn) {
        pauseBtn.addEventListener("click", function() {
            self.paused = !self.paused;
            pauseBtn.textContent = self.paused ? "Resume" : "Pause";
            pauseBtn.classList.toggle("btn-warning", self.paused);
        });
    }
    if (peakBtn) {
        peakBtn.addEventListener("click", function() {
            self.peakHold = !self.peakHold;
            if (!self.peakHold) self.peakData = null;
            peakBtn.classList.toggle("active", self.peakHold);
        });
    }
    if (avgSlider) {
        avgSlider.addEventListener("input", function() {
            self.averaging = parseInt(avgSlider.value) || 1;
            self._avgBuffer = [];
            var label = document.getElementById("spec-avg-label");
            if (label) label.textContent = self.averaging === 1 ? "Off" : self.averaging + "x";
        });
    }
    if (minDbSlider) {
        minDbSlider.value = self.minDb;
        minDbSlider.addEventListener("input", function() {
            self.minDb = parseInt(minDbSlider.value);
            var label = document.getElementById("spec-min-db-label");
            if (label) label.textContent = self.minDb + " dB";
        });
    }
    if (maxDbSlider) {
        maxDbSlider.value = self.maxDb;
        maxDbSlider.addEventListener("input", function() {
            self.maxDb = parseInt(maxDbSlider.value);
            var label = document.getElementById("spec-max-db-label");
            if (label) label.textContent = self.maxDb + " dB";
        });
    }

    // Only load nodes if we already have auth; otherwise _onAuthSuccess will call _loadNodes
    if (this.dashboard.apiKey || this.dashboard.sessionToken) {
        this._loadNodes();
    }
};

SpectrumViewer.prototype._loadNodes = function() {
    var self = this;
    var select = document.getElementById("spec-node");
    if (!select) return;
    self.dashboard.apiFetch("/api/spectrum/nodes")
        .then(function(nodes) {
            if (!nodes || !Array.isArray(nodes)) return;
            var prev = select.value;
            select.innerHTML = '<option value="">-- Select node --</option>';
            for (var i = 0; i < nodes.length; i++) {
                var n = nodes[i];
                var opt = document.createElement("option");
                opt.value = n.node_id;
                var label = n.node_id + " (" + (n.host || "?") + ")";
                if (n.capture_mode) label += " [" + n.capture_mode + "]";
                opt.textContent = label;
                select.appendChild(opt);
            }
            if (prev) select.value = prev;
        })
        .catch(function(err) {
            console.warn("spectrum: failed to load nodes:", err);
        });
};

SpectrumViewer.prototype.connect = function() {
    var self = this;
    var nodeSelect = document.getElementById("spec-node");
    var freq = document.getElementById("spec-freq");
    var gain = document.getElementById("spec-gain");
    var rate = document.getElementById("spec-sample-rate");

    var nodeId = nodeSelect ? nodeSelect.value : "";
    if (!nodeId) {
        self._updateBadge("Select a node");
        return;
    }

    var sampleRate = rate ? parseFloat(rate.value) * 1e6 : 2048000;

    var body = {
        node_id: nodeId,
        center_freq_hz: freq ? parseFloat(freq.value) * 1e6 : 433920000,
        gain_db: gain ? parseFloat(gain.value) : 40,
        sample_rate_hz: sampleRate
    };

    self._updateBadge("Connecting...");
    self.dashboard.apiFetch("/api/spectrum/connect", { method: "POST", body: body })
        .then(function(data) {
            self.connected = true;
            self.config.center_freq_hz = body.center_freq_hz;
            self.config.sample_rate_hz = body.sample_rate_hz;
            self.config.gain_db = body.gain_db;
            self._updateUI();
            self._connectWS();
            self._loadConfig();
        })
        .catch(function(err) {
            var msg = (err && err.detail) || (err && err.message) || "Connection failed";
            self._updateBadge("Error");
            console.error("spectrum connect:", msg);
            alert("Spectrum connect failed: " + msg);
        });
};

SpectrumViewer.prototype.disconnect = function() {
    var self = this;
    self.dashboard.apiFetch("/api/spectrum/disconnect")
        .then(function() {
            self.connected = false;
            self._disconnectWS();
            self._updateUI();
        })
        .catch(function() {});
};

SpectrumViewer.prototype._loadConfig = function() {
    var self = this;
    self.dashboard.apiFetch("/api/spectrum/config").then(function(cfg) {
        if (cfg) self.config = cfg;
    }).catch(function() {});
};

SpectrumViewer.prototype._updateUI = function() {
    var connectBtn = document.getElementById("spec-connect");
    var disconnectBtn = document.getElementById("spec-disconnect");
    var pauseBtn = document.getElementById("spec-pause");
    if (connectBtn) connectBtn.disabled = this.connected;
    if (disconnectBtn) disconnectBtn.disabled = !this.connected;
    if (pauseBtn) pauseBtn.disabled = !this.connected;
    this._updateBadge(this.connected ? "Connected" : "Disconnected");
};

SpectrumViewer.prototype._updateBadge = function(text) {
    var badge = document.getElementById("spectrum-badge");
    if (badge) badge.textContent = text;
};

/* ----------------------------------------------------------------
   WebSocket for FFT data
   ---------------------------------------------------------------- */

SpectrumViewer.prototype._connectWS = function() {
    var self = this;
    if (self.ws && self.ws.readyState <= 1) return;

    var authKey = self.dashboard.apiKey || self.dashboard.sessionToken;
    if (!authKey && !self.dashboard._cookieAuth) {
        console.warn("spectrum: no auth key available for WS");
        return;
    }
    var proto = location.protocol === "https:" ? "wss:" : "ws:";
    var url = proto + "//" + location.host + "/api/spectrum/ws/spectrum";

    try {
        // Cookie mode: no sub-protocol, the session cookie authenticates.
        self.ws = new WebSocket(url, authKey ? ["bridge-v1", authKey] : []);
    } catch(e) {
        console.error("spectrum: WS create failed:", e);
        return;
    }

    self.ws.onmessage = function(ev) {
        if (self.paused) return;
        try {
            var data = JSON.parse(ev.data);
            if (data.magnitudes_db) {
                // FPS counter
                self._frameCount++;
                var now = performance.now();
                if (now - self._fpsTime >= 1000) {
                    self._fps = self._frameCount;
                    self._frameCount = 0;
                    self._fpsTime = now;
                    var fpsEl = document.getElementById("spec-fps");
                    if (fpsEl) fpsEl.textContent = self._fps + " fps";
                }

                var mags = data.magnitudes_db;

                // Averaging
                if (self.averaging > 1) {
                    self._avgBuffer.push(mags);
                    if (self._avgBuffer.length > self.averaging) {
                        self._avgBuffer.shift();
                    }
                    mags = self._computeAverage(self._avgBuffer);
                }

                // Peak hold
                if (self.peakHold) {
                    if (!self.peakData || self.peakData.length !== mags.length) {
                        self.peakData = mags.slice();
                    } else {
                        for (var p = 0; p < mags.length; p++) {
                            if (mags[p] > self.peakData[p]) self.peakData[p] = mags[p];
                        }
                    }
                }

                // Update config from frame
                if (data.fc) self.config.center_freq_hz = data.fc * 1e6;
                if (data.bw) self.config.sample_rate_hz = data.bw * 1e6;

                self._renderFFT(mags);
                self._addWaterfallRow(mags);
            }
            if (data.signals) {
                self.signals = data.signals;
                self._renderSignalList();
            }
        } catch(e) {
            console.error("spectrum: onmessage error:", e);
        }
    };

    self.ws.onopen = function() {
        self.wsRetries = 0;
        console.log("spectrum: WS connected");
        self._updateBadge("Streaming");
    };
    self.ws.onclose = function(ev) {
        console.log("spectrum: WS closed, code=" + ev.code);
        self.ws = null;
        if (self.connected && self.wsRetries < self.wsMaxRetries) {
            self.wsRetries++;
            var delay = Math.min(3000 * Math.pow(2, self.wsRetries - 1), 30000);
            setTimeout(function() { self._connectWS(); }, delay);
        } else if (self.wsRetries >= self.wsMaxRetries) {
            self.connected = false;
            self._updateUI();
        }
    };
    self.ws.onerror = function(e) {
        console.error("spectrum: WS error:", e);
        self.ws.close();
    };
};

SpectrumViewer.prototype._disconnectWS = function() {
    if (this.ws) {
        this.ws.close();
        this.ws = null;
    }
    this.peakData = null;
    this._avgBuffer = [];
    this._fps = 0;
    var fpsEl = document.getElementById("spec-fps");
    if (fpsEl) fpsEl.textContent = "";
};

SpectrumViewer.prototype._computeAverage = function(buffers) {
    if (buffers.length === 0) return [];
    var n = buffers[0].length;
    var avg = new Array(n);
    for (var i = 0; i < n; i++) {
        var sum = 0;
        for (var j = 0; j < buffers.length; j++) {
            sum += buffers[j][i] || 0;
        }
        avg[i] = sum / buffers.length;
    }
    return avg;
};

/* ----------------------------------------------------------------
   FFT Display
   ---------------------------------------------------------------- */

SpectrumViewer.prototype._drawEmptyFFT = function() {
    if (!this.fftCtx) return;
    var ctx = this.fftCtx;
    var w = this.fftCanvas.width;
    var h = this.fftCanvas.height;
    ctx.fillStyle = "#0d1117";
    ctx.fillRect(0, 0, w, h);
    ctx.strokeStyle = "#30363d";
    ctx.lineWidth = 1;
    for (var i = 1; i < 4; i++) {
        var y = h * i / 4;
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
    }
    this._drawFFTAxes(ctx, w, h);
};

SpectrumViewer.prototype._drawFFTAxes = function(ctx, w, h) {
    ctx.fillStyle = "#8b949e";
    ctx.font = "10px monospace";
    ctx.textAlign = "center";

    var fc = this.config.center_freq_hz || 0;
    var bw = this.config.sample_rate_hz || 2048000;
    var fMin = (fc - bw / 2) / 1e6;
    var fMax = (fc + bw / 2) / 1e6;

    for (var i = 0; i <= 4; i++) {
        var x = w * i / 4;
        var f = fMin + (fMax - fMin) * i / 4;
        ctx.fillText(f.toFixed(2) + " MHz", x, h - 4);
    }

    ctx.textAlign = "left";
    for (var j = 0; j <= 4; j++) {
        var y = h * j / 4;
        var db = this.maxDb - (this.maxDb - this.minDb) * j / 4;
        ctx.fillText(db.toFixed(0) + " dB", 4, y + 12);
    }
};

SpectrumViewer.prototype._renderFFT = function(mags) {
    if (!this.fftCtx) return;
    var ctx = this.fftCtx;
    var w = this.fftCanvas.width;
    var h = this.fftCanvas.height;
    var n = mags.length;

    ctx.fillStyle = "#0d1117";
    ctx.fillRect(0, 0, w, h);

    // Grid
    ctx.strokeStyle = "#30363d";
    ctx.lineWidth = 0.5;
    for (var g = 1; g < 4; g++) {
        var gy = h * g / 4;
        ctx.beginPath(); ctx.moveTo(0, gy); ctx.lineTo(w, gy); ctx.stroke();
    }

    // Peak hold trace (behind live trace)
    if (this.peakHold && this.peakData) {
        ctx.beginPath();
        ctx.strokeStyle = "rgba(248, 81, 73, 0.6)";
        ctx.lineWidth = 1;
        for (var p = 0; p < this.peakData.length; p++) {
            var px = (p / this.peakData.length) * w;
            var pnorm = (this.peakData[p] - this.minDb) / (this.maxDb - this.minDb);
            if (pnorm < 0) pnorm = 0;
            if (pnorm > 1) pnorm = 1;
            var py = h - pnorm * h;
            if (p === 0) ctx.moveTo(px, py);
            else ctx.lineTo(px, py);
        }
        ctx.stroke();
    }

    // Live FFT line
    ctx.beginPath();
    ctx.strokeStyle = "#58a6ff";
    ctx.lineWidth = 1.5;
    for (var i = 0; i < n; i++) {
        var x = (i / n) * w;
        var norm = (mags[i] - this.minDb) / (this.maxDb - this.minDb);
        if (norm < 0) norm = 0;
        if (norm > 1) norm = 1;
        var y = h - norm * h;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    }
    ctx.stroke();

    // Fill under curve
    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    ctx.fillStyle = "rgba(88, 166, 255, 0.08)";
    ctx.fill();

    this._drawFFTAxes(ctx, w, h);
    this._drawSignalMarkers(ctx, w, h, n);
    this._drawDetectionOverlay(ctx, w, h);

    // FPS indicator
    if (this._fps > 0) {
        ctx.fillStyle = "#8b949e";
        ctx.font = "10px monospace";
        ctx.textAlign = "right";
        ctx.fillText(this._fps + " fps", w - 6, 12);
    }
};

SpectrumViewer.prototype._drawSignalMarkers = function(ctx, w, h, fftLen) {
    if (!this.signals || this.signals.length === 0) return;
    var fc = this.config.center_freq_hz || 0;
    var bw = this.config.sample_rate_hz || 2048000;
    var fMin = fc - bw / 2;
    var fMax = fc + bw / 2;

    ctx.font = "10px sans-serif";
    ctx.textAlign = "center";

    for (var i = 0; i < this.signals.length; i++) {
        var sig = this.signals[i];
        var sigCenter = sig.center_hz || 0;
        var sigBw = sig.bandwidth_hz || 0;

        if (sigCenter < fMin || sigCenter > fMax) continue;

        var xCenter = ((sigCenter - fMin) / (fMax - fMin)) * w;
        var xWidth = (sigBw / (fMax - fMin)) * w;

        ctx.fillStyle = "rgba(163, 113, 247, 0.15)";
        ctx.fillRect(xCenter - xWidth / 2, 0, xWidth, h - 20);

        ctx.strokeStyle = "#a371f7";
        ctx.lineWidth = 1;
        ctx.setLineDash([4, 4]);
        ctx.beginPath();
        ctx.moveTo(xCenter, 0); ctx.lineTo(xCenter, h - 20);
        ctx.stroke();
        ctx.setLineDash([]);

        ctx.fillStyle = "#a371f7";
        ctx.fillText(sig.name || "Signal", xCenter, 12);
    }
};

/* ----------------------------------------------------------------
   Detection Overlay — show classified signals on spectrum
   ---------------------------------------------------------------- */

SpectrumViewer.prototype._drawDetectionOverlay = function(ctx, w, h) {
    if (!this.signals || this.signals.length === 0) return;
    if (!window.dashboard || !window.dashboard.detectionDashboard) return;

    var feed = window.dashboard.detectionDashboard.feed;
    if (!feed || !feed.length) return;

    var fc = this.config.center_freq_hz || 0;
    var bw = this.config.sample_rate_hz || 2048000;
    var fMin = fc - bw / 2;
    var fMax = fc + bw / 2;

    var detByFreq = {};
    for (var d = 0; d < feed.length; d++) {
        var det = feed[d];
        if (det.center_freq_hz == null) continue;
        var bin = Math.round(det.center_freq_hz / 100000) * 100000;
        if (!detByFreq[bin] || det.confidence > detByFreq[bin].confidence) {
            detByFreq[bin] = det;
        }
    }

    ctx.font = "9px monospace";
    ctx.textAlign = "center";

    for (var i = 0; i < this.signals.length; i++) {
        var sig = this.signals[i];
        var sigCenter = sig.center_hz || 0;
        if (sigCenter < fMin || sigCenter > fMax) continue;

        var sigBin = Math.round(sigCenter / 100000) * 100000;
        var det2 = detByFreq[sigBin];
        if (!det2) continue;

        var xCenter = ((sigCenter - fMin) / (fMax - fMin)) * w;
        var expected = sig.expected_classes || [];
        var detClass = det2.signal_class || "";
        var conf = det2.confidence != null ? (det2.confidence * 100).toFixed(0) : "?";

        var isExpected = expected.indexOf(detClass) !== -1;
        // Dual-encode classification: SHAPE primary (CVD-safe), color redundant.
        // Filled square = expected (matches signal catalog); hollow ring = unexpected.
        // Dashboard cog-review §5.4.
        var color = isExpected ? "#3fb950" : "#f85149";
        var markerY = 20;
        var markerSize = 6;
        if (isExpected) {
            ctx.fillStyle = color;
            ctx.fillRect(xCenter - markerSize / 2, markerY - markerSize / 2, markerSize, markerSize);
        } else {
            ctx.strokeStyle = color;
            ctx.lineWidth = 1.5;
            ctx.beginPath();
            ctx.arc(xCenter, markerY, markerSize / 2, 0, Math.PI * 2);
            ctx.stroke();
        }

        ctx.fillStyle = color;
        var label = _specEsc(detClass) + " (" + conf + "%)";
        ctx.fillText(label, xCenter, 34);
    }
};

/* ----------------------------------------------------------------
   Waterfall Display
   ---------------------------------------------------------------- */

SpectrumViewer.prototype._drawEmptyWaterfall = function() {
    if (!this.wfCtx) return;
    var ctx = this.wfCtx;
    var w = this.waterfallCanvas.width;
    var h = this.waterfallCanvas.height;
    ctx.fillStyle = "#0d1117";
    ctx.fillRect(0, 0, w, h);
};

SpectrumViewer.prototype._addWaterfallRow = function(mags) {
    if (!this.wfCtx) return;
    var ctx = this.wfCtx;
    var w = this.waterfallCanvas.width;
    var h = this.waterfallCanvas.height;
    var n = mags.length;

    var cmap = buildColormap();
    var rowImg = ctx.createImageData(w, 1);
    var data = rowImg.data;

    for (var px = 0; px < w; px++) {
        var idx = Math.floor((px / w) * n);
        if (idx >= n) idx = n - 1;
        var ci = dbToColorIndex(mags[idx], this.minDb, this.maxDb);
        var c = cmap[ci];
        var off = px * 4;
        data[off] = c[0];
        data[off + 1] = c[1];
        data[off + 2] = c[2];
        data[off + 3] = 255;
    }

    // Scroll existing content down by 1 pixel
    var existing = ctx.getImageData(0, 0, w, h - 1);
    ctx.putImageData(existing, 0, 1);
    ctx.putImageData(rowImg, 0, 0);

    // Repaint the colormap legend on top so it isn't scrolled out.
    this._drawColormapLegend(ctx, w, h);
};

/* ----------------------------------------------------------------
   Colormap Legend — viridis strip with dB labels
   ---------------------------------------------------------------- */

SpectrumViewer.prototype._drawColormapLegend = function(ctx, w, h) {
    // Skip if canvas is too narrow to spare the room (dashboard §5.3).
    if (w < 200) return;

    var stripW = 12;
    var stripH = Math.min(128, h - 40);
    if (stripH < 40) return;

    var pad = 8;
    var labelW = 48;
    var x0 = w - stripW - labelW - pad;
    var y0 = pad;

    var cmap = buildColormap();

    // Background swatch behind the legend for legibility.
    ctx.fillStyle = "rgba(13, 17, 23, 0.78)";
    ctx.fillRect(x0 - 4, y0 - 4, stripW + labelW + 8, stripH + 8);

    // Colormap strip — top = high dB, bottom = low dB.
    for (var py = 0; py < stripH; py++) {
        var t = 1 - (py / (stripH - 1));
        var ci = Math.floor(t * (COLORMAP_SIZE - 1));
        var c = cmap[ci];
        ctx.fillStyle = "rgb(" + c[0] + "," + c[1] + "," + c[2] + ")";
        ctx.fillRect(x0, y0 + py, stripW, 1);
    }

    // Border.
    ctx.strokeStyle = "#30363d";
    ctx.lineWidth = 1;
    ctx.strokeRect(x0 + 0.5, y0 + 0.5, stripW - 1, stripH - 1);

    // Labels.
    ctx.fillStyle = "#c9d1d9";
    ctx.font = "10px monospace";
    ctx.textAlign = "left";
    ctx.textBaseline = "middle";
    ctx.fillText(this.maxDb.toFixed(0) + " dB", x0 + stripW + 4, y0 + 4);
    ctx.fillText(this.minDb.toFixed(0) + " dB", x0 + stripW + 4, y0 + stripH - 4);
    ctx.textBaseline = "alphabetic";
};

/* ----------------------------------------------------------------
   Signal List
   ---------------------------------------------------------------- */

SpectrumViewer.prototype._renderSignalList = function() {
    var container = document.getElementById("signal-list");
    if (!container) return;

    if (!this.signals || this.signals.length === 0) {
        container.innerHTML = "";
        return;
    }

    var html = "";
    for (var i = 0; i < this.signals.length; i++) {
        var sig = this.signals[i];
        var freqMhz = sig.center_hz ? (sig.center_hz / 1e6).toFixed(3) : "--";
        var name = sig.name || "Unknown";
        var classes = sig.expected_classes || [];

        html += "<div class=\"class-card\">"
            + "<strong>" + _specEsc(name) + "</strong><br>"
            + _specEsc(freqMhz) + " MHz<br>"
            + "<small>" + _specEsc(classes.join(", ")) + "</small>"
            + "</div>";
    }
    container.innerHTML = html;
};

/* ----------------------------------------------------------------
   Utility (local escape to avoid dependency on global)
   ---------------------------------------------------------------- */

/* HTML-escape text (& < > " ') for element content and for quoted attribute
 * values. Not for unquoted attributes, URLs, inline handlers, script elements or style. */
function _specEsc(str) {
    if (str == null) return "";
    return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
