/**
 * MLRF Gen4 Dashboard - Spectrum Viewer
 *
 * Canvas-based FFT and waterfall display with rtl_tcp connection
 * management and live signal identification overlay.
 */

"use strict";

/* ================================================================
   Color Map — jet-like gradient for dB values
   ================================================================ */

var COLORMAP_SIZE = 256;
var _colormap = null;

function buildColormap() {
    if (_colormap) return _colormap;
    _colormap = new Array(COLORMAP_SIZE);
    for (var i = 0; i < COLORMAP_SIZE; i++) {
        var t = i / (COLORMAP_SIZE - 1);
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
        _colormap[i] = [r, g, b];
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
    this.ws = null;
    this.config = { center_freq_hz: 433920000, sample_rate_hz: 2048000, gain_db: 40, fft_size: 1024 };
    this.minDb = -80;
    this.maxDb = 0;
    this.signals = [];

    this.fftCanvas = document.getElementById("spectrum-canvas");
    this.waterfallCanvas = document.getElementById("waterfall-canvas");
    this.fftCtx = this.fftCanvas ? this.fftCanvas.getContext("2d") : null;
    this.wfCtx = this.waterfallCanvas ? this.waterfallCanvas.getContext("2d") : null;

    this.waterfallRows = [];
    this.maxWfRows = 200;

    this._initControls();
    this._drawEmptyFFT();
    this._drawEmptyWaterfall();
}

/* ----------------------------------------------------------------
   Controls
   ---------------------------------------------------------------- */

SpectrumViewer.prototype._initControls = function() {
    var self = this;
    var connectBtn = document.getElementById("spec-connect");
    var disconnectBtn = document.getElementById("spec-disconnect");

    if (connectBtn) {
        connectBtn.addEventListener("click", function() { self.connect(); });
    }
    if (disconnectBtn) {
        disconnectBtn.addEventListener("click", function() { self.disconnect(); });
    }
};

SpectrumViewer.prototype.connect = function() {
    var self = this;
    var host = document.getElementById("spec-host");
    var port = document.getElementById("spec-port");
    var freq = document.getElementById("spec-freq");
    var gain = document.getElementById("spec-gain");

    var body = {
        host: host ? host.value : "127.0.0.1",
        port: port ? parseInt(port.value) : 1234,
        center_freq_hz: freq ? parseFloat(freq.value) * 1e6 : 433920000,
        gain_db: gain ? parseFloat(gain.value) : 40,
        sample_rate_hz: 2048000
    };

    self.dashboard.apiFetch("/api/spectrum/connect", { method: "POST", body: body })
        .then(function() {
            self.connected = true;
            self._updateUI();
            self._connectWS();
            self._loadConfig();
        })
        .catch(function(err) {
            self._updateBadge("Error");
            /* 403: connecting needs an analyst key (reported, not dropped). */
            self.dashboard._writeFailed("connect to rtl_tcp", err);
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
        .catch(function(err) { self.dashboard._writeFailed("disconnect from rtl_tcp", err); });
};

SpectrumViewer.prototype._loadConfig = function() {
    var self = this;
    self.dashboard.apiFetch("/api/spectrum/config").then(function(cfg) {
        self.config = cfg;
    }).catch(function() {});
};

SpectrumViewer.prototype._updateUI = function() {
    var connectBtn = document.getElementById("spec-connect");
    var disconnectBtn = document.getElementById("spec-disconnect");
    if (connectBtn) connectBtn.disabled = this.connected;
    if (disconnectBtn) disconnectBtn.disabled = !this.connected;
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

    var apiKey = self.dashboard.apiKey;
    var proto = location.protocol === "https:" ? "wss:" : "ws:";
    var url = proto + "//" + location.host + "/api/spectrum/ws/spectrum";
    /* Key as the "bridge-v1, <key>" subprotocol, never in the URL. */
    var protocols = apiKey ? ["bridge-v1", apiKey] : [];

    try { self.ws = new WebSocket(url, protocols); } catch(_) { return; }

    self.ws.onmessage = function(ev) {
        try {
            var data = JSON.parse(ev.data);
            if (data.magnitudes_db) {
                self._renderFFT(data.magnitudes_db);
                self._addWaterfallRow(data.magnitudes_db);
            }
            if (data.signals) {
                self.signals = data.signals;
                self._renderSignalList();
            }
            if (data.connected != null) {
                self.connected = data.connected;
                self._updateUI();
            }
        } catch(_) {}
    };

    self.ws.onclose = function() {
        self.ws = null;
        if (self.connected) {
            setTimeout(function() { self._connectWS(); }, 3000);
        }
    };
    self.ws.onerror = function() { self.ws.close(); };
};

SpectrumViewer.prototype._disconnectWS = function() {
    if (this.ws) {
        this.ws.close();
        this.ws = null;
    }
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

    // FFT line
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

    // Signal markers
    this._drawSignalMarkers(ctx, w, h, n);
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
