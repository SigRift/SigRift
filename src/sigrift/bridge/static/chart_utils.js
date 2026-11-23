/**
 * The Bridge — Shared Chart Utilities
 * Canvas primitives for stacked area, treemap, heatmap, sparkline, and helpers.
 */
"use strict";

var ChartUtils = (function() {

    /* -- Canvas helpers ----------------------------------------- */

    function getThemeColor(varName, fallback) {
        var s = getComputedStyle(document.documentElement).getPropertyValue(varName);
        return s ? s.trim() : fallback;
    }

    function clearCanvas(ctx, canvas) {
        ctx.fillStyle = getThemeColor("--bg-primary", "#0d1117");
        ctx.fillRect(0, 0, canvas.width, canvas.height);
    }

    function drawGrid(ctx, w, h, xSteps, ySteps, color) {
        ctx.strokeStyle = color || getThemeColor("--border-color", "#30363d");
        ctx.lineWidth = 0.5;
        for (var i = 1; i < xSteps; i++) {
            var x = w * i / xSteps;
            ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
        }
        for (var j = 1; j < ySteps; j++) {
            var y = h * j / ySteps;
            ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
        }
    }

    function drawAxisLabels(ctx, labels, axis, w, h) {
        ctx.fillStyle = getThemeColor("--text-secondary", "#8b949e");
        ctx.font = "10px monospace";
        if (axis === "x") {
            ctx.textAlign = "center";
            for (var i = 0; i < labels.length; i++) {
                var x = (i / (labels.length - 1 || 1)) * w;
                ctx.fillText(labels[i], x, h - 4);
            }
        } else {
            ctx.textAlign = "left";
            for (var j = 0; j < labels.length; j++) {
                var y = (j / (labels.length - 1 || 1)) * h;
                ctx.fillText(labels[j], 4, y + 12);
            }
        }
    }

    /* -- Colormap (jet) ----------------------------------------- */

    var _colormap = null;
    var _colormapStrings = null;
    var CMAP_SIZE = 256;

    function buildColormap(steps) {
        var sz = steps || CMAP_SIZE;
        if (_colormap && _colormap.length === sz) return _colormap;
        _colormap = new Array(sz);
        _colormapStrings = new Array(sz);
        for (var i = 0; i < sz; i++) {
            var t = i / (sz - 1);
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
            _colormapStrings[i] = "rgb(" + r + "," + g + "," + b + ")";
        }
        return _colormap;
    }

    function getColormapStrings() {
        if (!_colormapStrings) buildColormap();
        return _colormapStrings;
    }

    /* -- Stacked Area Chart ------------------------------------- */

    function drawStackedArea(ctx, canvas, data, colors, timeLabels, yLabel) {
        var w = canvas.width, h = canvas.height;
        var pad = 40;
        var plotW = w - pad * 2, plotH = h - pad * 2;

        clearCanvas(ctx, canvas);
        drawGrid(ctx, w, h, 6, 4, "#30363d");

        if (!data || !data.length || !data[0].length) return;

        var nSeries = data.length, nPoints = data[0].length;

        // Precompute cumulative sums per point (O(n*s) once, not O(n*s^2))
        // cumSums[s][p] = sum of series 0..s at point p
        var cumSums = new Array(nSeries);
        var cumMax = 0;
        for (var s = 0; s < nSeries; s++) {
            cumSums[s] = new Float64Array(nPoints);
            for (var p = 0; p < nPoints; p++) {
                cumSums[s][p] = (s > 0 ? cumSums[s - 1][p] : 0) + (data[s][p] || 0);
            }
        }
        for (var p2 = 0; p2 < nPoints; p2++) {
            if (cumSums[nSeries - 1][p2] > cumMax) cumMax = cumSums[nSeries - 1][p2];
        }
        if (cumMax === 0) cumMax = 1;

        var xScale = plotW / (nPoints - 1 || 1);
        var yScale = plotH / cumMax;

        // Draw from bottom to top
        for (var si = nSeries - 1; si >= 0; si--) {
            ctx.beginPath();
            ctx.fillStyle = colors[si % colors.length] || "#58a6ff";
            ctx.globalAlpha = 0.6;

            // Bottom line (cumulative of series below) — use precomputed
            var belowSums = si > 0 ? cumSums[si - 1] : null;
            for (var pi = nPoints - 1; pi >= 0; pi--) {
                var below = belowSums ? belowSums[pi] : 0;
                var x = pad + pi * xScale;
                var y = pad + plotH - below * yScale;
                if (pi === nPoints - 1) ctx.moveTo(x, y); else ctx.lineTo(x, y);
            }

            // Top line (cumulative including this series) — use precomputed
            for (var pj = 0; pj < nPoints; pj++) {
                var x2 = pad + pj * xScale;
                var y2 = pad + plotH - cumSums[si][pj] * yScale;
                ctx.lineTo(x2, y2);
            }

            ctx.closePath();
            ctx.fill();
            ctx.globalAlpha = 1.0;
        }

        // Time labels
        if (timeLabels && timeLabels.length) {
            ctx.fillStyle = "#8b949e";
            ctx.font = "10px monospace";
            ctx.textAlign = "center";
            var step = Math.max(1, Math.floor(timeLabels.length / 6));
            for (var ti = 0; ti < timeLabels.length; ti += step) {
                var tx = pad + (ti / (timeLabels.length - 1 || 1)) * plotW;
                ctx.fillText(timeLabels[ti], tx, h - 6);
            }
        }

        // Y-axis label
        if (yLabel) {
            ctx.save();
            ctx.fillStyle = "#8b949e";
            ctx.font = "10px monospace";
            ctx.textAlign = "center";
            ctx.translate(12, h / 2);
            ctx.rotate(-Math.PI / 2);
            ctx.fillText(yLabel, 0, 0);
            ctx.restore();
        }

        // Y-axis values
        ctx.fillStyle = "#8b949e";
        ctx.font = "10px monospace";
        ctx.textAlign = "left";
        for (var yi = 0; yi <= 4; yi++) {
            var yv = pad + plotH * yi / 4;
            var lbl = formatNumber(cumMax * (1 - yi / 4));
            ctx.fillText(lbl, 4, yv + 4);
        }
    }

    /* -- Treemap ------------------------------------------------ */

    function drawTreemap(ctx, canvas, items, colorFn) {
        var w = canvas.width, h = canvas.height;
        clearCanvas(ctx, canvas);

        if (!items || !items.length) return;

        // Sort descending
        items = items.slice().sort(function(a, b) { return b.value - a.value; });

        // Compute total for percentage display
        var grandTotal = 0;
        for (var k = 0; k < items.length; k++) grandTotal += items[k].value;

        // Squarified treemap layout
        var rects = _squarify(items, { x: 4, y: 4, w: w - 8, h: h - 8 });

        ctx.font = "11px monospace";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";

        for (var i = 0; i < rects.length; i++) {
            var r = rects[i];
            var color = colorFn ? colorFn(r.item, i) : _defaultTreemapColor(i);

            ctx.fillStyle = color;
            ctx.globalAlpha = 0.75;
            ctx.fillRect(r.x + 1, r.y + 1, r.w - 2, r.h - 2);
            ctx.globalAlpha = 1.0;

            ctx.strokeStyle = "#0d1117";
            ctx.lineWidth = 1;
            ctx.strokeRect(r.x + 1, r.y + 1, r.w - 2, r.h - 2);

            // Label if cell is large enough
            if (r.w > 40 && r.h > 20) {
                var pct = grandTotal > 0 ? (r.item.value / grandTotal * 100) : 0;
                var pctStr = pct >= 10 ? pct.toFixed(0) + "%" : pct.toFixed(1) + "%";
                ctx.fillStyle = "#fff";
                var label = r.item.label || "";
                if (label.length > Math.floor(r.w / 7)) label = label.substring(0, Math.floor(r.w / 7));
                // Vertical layout depends on cell height
                if (r.h > 36) {
                    ctx.fillText(label, r.x + r.w / 2, r.y + r.h / 2 - 10);
                    ctx.font = "10px monospace";
                    ctx.fillStyle = "rgba(255,255,255,0.85)";
                    ctx.fillText(pctStr, r.x + r.w / 2, r.y + r.h / 2 + 4);
                    ctx.font = "9px monospace";
                    ctx.fillStyle = "rgba(255,255,255,0.6)";
                    ctx.fillText(formatNumber(r.item.value), r.x + r.w / 2, r.y + r.h / 2 + 16);
                } else {
                    ctx.fillText(label, r.x + r.w / 2, r.y + r.h / 2 - 6);
                    ctx.font = "9px monospace";
                    ctx.fillStyle = "rgba(255,255,255,0.7)";
                    ctx.fillText(pctStr + " (" + formatNumber(r.item.value) + ")", r.x + r.w / 2, r.y + r.h / 2 + 8);
                }
                ctx.font = "11px monospace";
            }
        }
    }

    function _squarify(items, rect) {
        var rects = [];
        var total = 0;
        for (var i = 0; i < items.length; i++) total += items[i].value;
        if (total <= 0) return rects;

        _layoutRow(items, 0, items.length, rect, total, rects);
        return rects;
    }

    function _layoutRow(items, start, end, rect, total, rects) {
        if (start >= end) return;
        if (end - start === 1) {
            rects.push({ x: rect.x, y: rect.y, w: rect.w, h: rect.h, item: items[start] });
            return;
        }

        var isHoriz = rect.w >= rect.h;
        var mid = start + 1;
        var partialSum = items[start].value;
        var halfTotal = total / 2;

        for (var i = start + 1; i < end; i++) {
            if (partialSum + items[i].value / 2 > halfTotal) break;
            partialSum += items[i].value;
            mid = i + 1;
        }

        var frac = partialSum / total;
        var r1, r2;
        if (isHoriz) {
            var splitW = rect.w * frac;
            r1 = { x: rect.x, y: rect.y, w: splitW, h: rect.h };
            r2 = { x: rect.x + splitW, y: rect.y, w: rect.w - splitW, h: rect.h };
        } else {
            var splitH = rect.h * frac;
            r1 = { x: rect.x, y: rect.y, w: rect.w, h: splitH };
            r2 = { x: rect.x, y: rect.y + splitH, w: rect.w, h: rect.h - splitH };
        }

        _layoutRow(items, start, mid, r1, partialSum, rects);
        _layoutRow(items, mid, end, r2, total - partialSum, rects);
    }

    function _defaultTreemapColor(index) {
        var palette = ["#58a6ff", "#3fb950", "#a371f7", "#d29922", "#f85149", "#79c0ff", "#7ee787", "#d2a8ff"];
        return palette[index % palette.length];
    }

    /* -- Heatmap ------------------------------------------------ */

    function drawHeatmap(ctx, canvas, data, xLabels, yLabels, colormap) {
        var w = canvas.width, h = canvas.height;
        var padL = 72;  // left: room for freq labels
        var padB = 40;  // bottom: room for time labels
        var plotW = w - padL - 20, plotH = h - padB - 10;

        clearCanvas(ctx, canvas);

        if (!data || !data.length) return;

        var cmap = colormap || buildColormap();
        var maxVal = 0;
        for (var i = 0; i < data.length; i++) {
            for (var j = 0; j < data[i].length; j++) {
                if (data[i][j] > maxVal) maxVal = data[i][j];
            }
        }
        if (maxVal === 0) maxVal = 1;

        var rows = data.length, cols = data[0].length;
        var cellW = plotW / cols, cellH = plotH / rows;
        var cmapLen = cmap.length - 1;
        var invMax = 1 / maxVal;

        // Use ImageData for bulk pixel rendering instead of per-cell fillRect
        var pxW = Math.ceil(plotW), pxH = Math.ceil(plotH);
        if (pxW > 0 && pxH > 0) {
            var imgData = ctx.createImageData(pxW, pxH);
            var pixels = imgData.data;

            for (var r = 0; r < rows; r++) {
                var rowData = data[r];
                var y0 = Math.floor(r * cellH);
                var y1 = Math.floor((r + 1) * cellH);
                for (var c = 0; c < cols; c++) {
                    var ci = Math.floor((rowData[c] || 0) * invMax * cmapLen);
                    var rgb = cmap[ci];
                    var x0 = Math.floor(c * cellW);
                    var x1 = Math.floor((c + 1) * cellW);
                    // Fill the cell pixels
                    for (var py = y0; py < y1 && py < pxH; py++) {
                        var rowOff = py * pxW;
                        for (var px = x0; px < x1 && px < pxW; px++) {
                            var off = (rowOff + px) << 2;
                            pixels[off] = rgb[0];
                            pixels[off + 1] = rgb[1];
                            pixels[off + 2] = rgb[2];
                            pixels[off + 3] = 255;
                        }
                    }
                }
            }
            ctx.putImageData(imgData, padL, 10);
        }

        // Axis labels
        if (xLabels) {
            ctx.fillStyle = "#8b949e";
            ctx.font = "9px monospace";
            ctx.textAlign = "center";
            var xStep = Math.max(1, Math.floor(cols / 8));
            for (var xi = 0; xi < cols; xi += xStep) {
                ctx.fillText(xLabels[xi] || "", padL + xi * cellW + cellW / 2, h - 4);
            }
        }
        if (yLabels) {
            ctx.fillStyle = "#8b949e";
            ctx.font = "9px monospace";
            ctx.textAlign = "right";
            var yStep = Math.max(1, Math.floor(rows / 8));
            for (var yi = 0; yi < rows; yi += yStep) {
                ctx.fillText(yLabels[yi] || "", padL - 4, 10 + yi * cellH + cellH / 2 + 3);
            }
        }
    }

    /* -- Sparkline ---------------------------------------------- */

    function drawSparkline(ctx, canvas, values, color, fillColor) {
        var w = canvas.width, h = canvas.height;
        clearCanvas(ctx, canvas);

        if (!values || values.length < 2) return;

        var mn = values[0], mx = values[0];
        for (var i = 1; i < values.length; i++) {
            if (values[i] < mn) mn = values[i];
            if (values[i] > mx) mx = values[i];
        }
        if (mx === mn) mx = mn + 1;

        var n = values.length;
        ctx.beginPath();
        ctx.strokeStyle = color || "#58a6ff";
        ctx.lineWidth = 1.5;

        for (var j = 0; j < n; j++) {
            var x = (j / (n - 1)) * w;
            var y = h - ((values[j] - mn) / (mx - mn)) * (h - 4) - 2;
            if (j === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
        }
        ctx.stroke();

        if (fillColor) {
            ctx.lineTo(w, h);
            ctx.lineTo(0, h);
            ctx.closePath();
            ctx.fillStyle = fillColor;
            ctx.fill();
        }
    }

    /* -- Number / Frequency / Time formatting ------------------- */

    function formatNumber(n) {
        if (n == null) return "--";
        if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
        if (n >= 1e3) return (n / 1e3).toFixed(1) + "K";
        if (n % 1 !== 0) return n.toFixed(1);
        return String(n);
    }

    function formatFreq(hz) {
        if (hz == null) return "--";
        if (hz >= 1e9) return (hz / 1e9).toFixed(2) + " GHz";
        if (hz >= 1e6) return (hz / 1e6).toFixed(2) + " MHz";
        if (hz >= 1e3) return (hz / 1e3).toFixed(1) + " kHz";
        return hz.toFixed(0) + " Hz";
    }

    function formatTime(ts) {
        if (!ts) return "--";
        try {
            var d = new Date(ts);
            return d.toLocaleTimeString(undefined, { hour12: false, hour: "2-digit", minute: "2-digit" });
        } catch (_) {
            return "--";
        }
    }

    /* -- Canvas resize guard (avoids context reset if unchanged) - */

    function resizeCanvas(cv) {
        var dispW = cv.parentElement ? cv.parentElement.clientWidth : cv.clientWidth;
        if (dispW > 0 && cv.width !== dispW) cv.width = dispW;
    }

    /* -- Chart Tooltip ------------------------------------------ */

    /**
     * ChartTooltip — shows a floating div tooltip on canvas mousemove.
     * Displays data point values (x, y, label) based on mouse position.
     *
     * Usage:
     *   var tip = ChartUtils.createTooltip(canvas);
     *   canvas.addEventListener("mousemove", function(e) {
     *       var pt = findNearestPoint(e, data);
     *       if (pt) tip.show(e, pt.x, pt.y, pt.label);
     *       else tip.hide();
     *   });
     *   canvas.addEventListener("mouseleave", function() { tip.hide(); });
     *
     * @param {HTMLCanvasElement} canvas - The canvas to attach the tooltip to.
     * @returns {object} Tooltip controller with show(event, x, y, label) and hide().
     */
    function createTooltip(canvas) {
        var el = document.createElement("div");
        el.className = "chart-tooltip";
        el.style.display = "none";
        document.body.appendChild(el);

        function show(event, xVal, yVal, label) {
            var parts = [];
            if (label) parts.push('<span class="chart-tooltip-label">' + _escText(label) + '</span>');
            if (xVal != null) parts.push('<span class="chart-tooltip-x">' + _escText(String(xVal)) + '</span>');
            if (yVal != null) parts.push('<span class="chart-tooltip-y">' + _escText(String(yVal)) + '</span>');
            el.innerHTML = parts.join("");
            el.style.display = "";
            // Position relative to viewport with offset
            var tipW = el.offsetWidth;
            var tipH = el.offsetHeight;
            var px = event.clientX + 12;
            var py = event.clientY - tipH - 8;
            // Keep within viewport
            if (px + tipW > window.innerWidth) px = event.clientX - tipW - 12;
            if (py < 0) py = event.clientY + 16;
            el.style.left = px + "px";
            el.style.top = py + "px";
        }

        function hide() {
            el.style.display = "none";
        }

        function destroy() {
            if (el.parentNode) el.parentNode.removeChild(el);
        }

        return { show: show, hide: hide, destroy: destroy };
    }

    /* HTML-escape text (& < > " ') for element content and for quoted attribute
     * values. Not for unquoted attributes, URLs, inline handlers, script elements or style. */
    function _escText(str) {
        if (str == null) return "";
        return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
    }

    /* -- Chart Zoom --------------------------------------------- */

    /**
     * ChartZoom — manages zoom level and offset for time-axis charts.
     * Attaches mouse wheel (zoom in/out) and double-click (reset) listeners.
     *
     * Usage:
     *   var zoom = ChartUtils.createZoom(canvas, function() { redrawChart(); });
     *   // In your draw function, use zoom.getRange(totalPoints) to get
     *   // { start, end } indices for the visible window.
     *
     * @param {HTMLCanvasElement} canvas - The canvas element.
     * @param {function} onChange - Called whenever zoom/pan state changes.
     * @returns {object} Zoom controller.
     */
    function createZoom(canvas, onChange) {
        var _zoom = 1.0;    // 1.0 = full view, higher = zoomed in
        var _offset = 0.5;  // 0..1, center position of the viewport
        var _maxZoom = 20;

        function _clamp(v, lo, hi) { return v < lo ? lo : v > hi ? hi : v; }

        function _update() {
            // Clamp offset so viewport stays within [0, 1]
            var halfView = 0.5 / _zoom;
            _offset = _clamp(_offset, halfView, 1 - halfView);
            if (typeof onChange === "function") onChange();
        }

        canvas.addEventListener("wheel", function(e) {
            e.preventDefault();
            var rect = canvas.getBoundingClientRect();
            var mx = (e.clientX - rect.left) / rect.width; // 0..1 mouse position
            var oldZoom = _zoom;
            var factor = e.deltaY < 0 ? 1.15 : 1 / 1.15;
            _zoom = _clamp(_zoom * factor, 1.0, _maxZoom);
            // Adjust offset to keep the point under the mouse stable
            if (_zoom !== oldZoom) {
                _offset = mx + (_offset - mx) * (oldZoom / _zoom);
            }
            _update();
        }, { passive: false });

        canvas.addEventListener("dblclick", function() {
            _zoom = 1.0;
            _offset = 0.5;
            _update();
        });

        /**
         * Get the visible range of data indices.
         * @param {number} totalPoints - Total number of data points.
         * @returns {{ start: number, end: number, zoom: number }}
         */
        function getRange(totalPoints) {
            if (_zoom <= 1.0 || totalPoints <= 0) {
                return { start: 0, end: totalPoints, zoom: 1.0 };
            }
            var halfView = 0.5 / _zoom;
            var lo = _clamp(_offset - halfView, 0, 1);
            var hi = _clamp(_offset + halfView, 0, 1);
            return {
                start: Math.floor(lo * totalPoints),
                end: Math.ceil(hi * totalPoints),
                zoom: _zoom
            };
        }

        function reset() {
            _zoom = 1.0;
            _offset = 0.5;
        }

        function getZoom() { return _zoom; }

        return { getRange: getRange, reset: reset, getZoom: getZoom };
    }

    /* -- Public API --------------------------------------------- */

    return {
        clearCanvas: clearCanvas,
        drawGrid: drawGrid,
        drawAxisLabels: drawAxisLabels,
        buildColormap: buildColormap,
        getColormapStrings: getColormapStrings,
        drawStackedArea: drawStackedArea,
        drawTreemap: drawTreemap,
        drawHeatmap: drawHeatmap,
        drawSparkline: drawSparkline,
        resizeCanvas: resizeCanvas,
        formatNumber: formatNumber,
        formatFreq: formatFreq,
        formatTime: formatTime,
        createTooltip: createTooltip,
        createZoom: createZoom
    };

})();
