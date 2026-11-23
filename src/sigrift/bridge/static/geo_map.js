/**
 * The Bridge — Geolocation Map Module
 * Leaflet.js-based map showing nodes, detection heatmap, and coverage.
 */
"use strict";

function GeoMap(dashboard) {
    this.dashboard = dashboard;
    this.map = null;
    this.nodeMarkers = {};
    this.heatmapLayer = null;
    this.coverageLayer = null;
    this.showHeatmap = false;
    this.showCoverage = false;
    this.refreshTimer = null;
    this.initialized = false;
    this._placeMode = false;
    this._placePending = null;  // L.marker for pending placement
    this._allNodes = [];        // all node IDs from /api/nodes/
}

GeoMap.prototype.init = function() {
    if (this.initialized) return;

    var container = document.getElementById("geo-map-container");
    if (!container) return;

    // Defer creation until container is actually visible (non-zero dimensions)
    if (container.offsetWidth === 0 || container.offsetHeight === 0) {
        return;  // Will be called again by activateTab → invalidateSize
    }

    this.initialized = true;

    this.map = L.map("geo-map-container", {
        center: [39.8283, -98.5795],
        zoom: 4,
        zoomControl: true,
    });

    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
        attribution: "&copy; OpenStreetMap contributors",
        maxZoom: 19,
    }).addTo(this.map);

    this.coverageLayer = L.layerGroup().addTo(this.map);
    this.heatmapLayer = L.layerGroup();

    // Bind toggle controls
    var self = this;
    var heatBtn = document.getElementById("geo-toggle-heatmap");
    if (heatBtn) {
        heatBtn.addEventListener("click", function() {
            self.showHeatmap = !self.showHeatmap;
            heatBtn.classList.toggle("active", self.showHeatmap);
            if (self.showHeatmap) {
                self.map.addLayer(self.heatmapLayer);
                self.loadHeatmap();
            } else {
                self.map.removeLayer(self.heatmapLayer);
            }
        });
    }

    var covBtn = document.getElementById("geo-toggle-coverage");
    if (covBtn) {
        covBtn.addEventListener("click", function() {
            self.showCoverage = !self.showCoverage;
            covBtn.classList.toggle("active", self.showCoverage);
            if (self.showCoverage) {
                self.loadCoverage();
            } else {
                self.coverageLayer.clearLayers();
            }
        });
    }

    var refreshBtn = document.getElementById("geo-refresh-btn");
    if (refreshBtn) {
        refreshBtn.addEventListener("click", function() { self.refresh(); });
    }

    // Place Node mode
    var placeBtn = document.getElementById("geo-place-node");
    if (placeBtn) {
        placeBtn.addEventListener("click", function() {
            self._placeMode = !self._placeMode;
            placeBtn.classList.toggle("active", self._placeMode);
            container.style.cursor = self._placeMode ? "crosshair" : "";
            if (!self._placeMode && self._placePending) {
                self.map.removeLayer(self._placePending);
                self._placePending = null;
            }
            // Toggle draggability on existing markers
            for (var nid in self.nodeMarkers) {
                if (self._placeMode) {
                    self.nodeMarkers[nid].dragging.enable();
                } else {
                    self.nodeMarkers[nid].dragging.disable();
                }
            }
            if (self._placeMode) self._loadAllNodes();
        });
    }

    this.map.on("click", function(e) {
        if (!self._placeMode) return;
        self._showPlacePopup(e.latlng);
    });

    this.refresh();
    this.startAutoRefresh();
};

GeoMap.prototype.startAutoRefresh = function() {
    var self = this;
    if (this.refreshTimer) clearInterval(this.refreshTimer);
    this.refreshTimer = setInterval(function() { self.refresh(); }, 30000);
};

GeoMap.prototype.stopAutoRefresh = function() {
    if (this.refreshTimer) {
        clearInterval(this.refreshTimer);
        this.refreshTimer = null;
    }
};

GeoMap.prototype.refresh = function() {
    this.loadNodes();
    if (this.showHeatmap) this.loadHeatmap();
    if (this.showCoverage) this.loadCoverage();
};

GeoMap.prototype.loadNodes = function() {
    var self = this;
    self.dashboard.apiFetch("/api/geo/map")
        .then(function(nodes) {
            self.updateMarkers(nodes);
            var badge = document.getElementById("geo-node-count-badge");
            if (badge) badge.textContent = nodes.length + " nodes";
            var empty = document.getElementById("geo-map-empty");
            if (empty) empty.style.display = nodes.length > 0 ? "none" : "";
        })
        .catch(function(err) {
            if (typeof trackFetchError === "function") trackFetchError("geo_map", err);
        });
};

GeoMap.prototype._nodeIcon = function(color) {
    return L.divIcon({
        className: "geo-node-icon",
        html: '<div style="width:18px;height:18px;border-radius:50%;background:' + color + ';border:2px solid #fff;box-shadow:0 1px 4px rgba(0,0,0,.4);"></div>',
        iconSize: [18, 18],
        iconAnchor: [9, 9],
        popupAnchor: [0, -12],
    });
};

GeoMap.prototype.updateMarkers = function(nodes) {
    var self = this;
    var seen = {};
    var bounds = [];

    for (var i = 0; i < nodes.length; i++) {
        var n = nodes[i];
        seen[n.node_id] = true;
        var color = n.status === "active" ? "#22c55e" :
                    n.status === "stale"  ? "#eab308" : "#ef4444";
        var latlng = [n.latitude, n.longitude];
        bounds.push(latlng);

        var marker = self.nodeMarkers[n.node_id];
        if (marker) {
            marker.setLatLng(latlng);
            marker.setIcon(self._nodeIcon(color));
            if (self._placeMode) {
                marker.dragging.enable();
            } else {
                marker.dragging.disable();
            }
        } else {
            marker = L.marker(latlng, {
                icon: self._nodeIcon(color),
                draggable: self._placeMode,
            }).addTo(self.map);
            self.nodeMarkers[n.node_id] = marker;
            self._makeMarkerDraggable(n.node_id, marker);
        }

        marker.unbindPopup();
        var popupHtml =
            "<div class='geo-popup'>" +
            "<strong>" + esc(n.node_id) + "</strong><br>" +
            "<span class='geo-status geo-status-" + esc(n.status) + "'>" + esc(n.status) + "</span><br>" +
            (n.location_name ? "<em>" + esc(n.location_name) + "</em><br>" : "") +
            "Detections (1h): <strong>" + esc(n.detection_count_1h) + "</strong><br>" +
            "Anomalies (1h): <strong>" + esc(n.anomaly_count_1h) + "</strong><br>" +
            (n.top_signals.length ? "Top signals: " + n.top_signals.map(esc).join(", ") + "<br>" : "") +
            (n.last_heartbeat ? "Last seen: " + fmtTime(n.last_heartbeat) : "") +
            "</div>";
        marker.bindPopup(popupHtml);
    }

    // Remove markers for nodes no longer present
    for (var nid in self.nodeMarkers) {
        if (!seen[nid]) {
            self.map.removeLayer(self.nodeMarkers[nid]);
            delete self.nodeMarkers[nid];
        }
    }

    // Fit bounds if we have markers
    if (bounds.length > 0) {
        self.map.fitBounds(bounds, { padding: [50, 50], maxZoom: 14 });
    }
};

GeoMap.prototype.loadHeatmap = function() {
    var self = this;
    self.dashboard.apiFetch("/api/geo/heatmap?hours=24")
        .then(function(points) {
            self.heatmapLayer.clearLayers();
            for (var i = 0; i < points.length; i++) {
                var p = points[i];
                var radius = Math.min(Math.max(Math.sqrt(p.weight) * 2, 5), 50);
                L.circleMarker([p.latitude, p.longitude], {
                    radius: radius,
                    fillColor: "#f97316",
                    color: "transparent",
                    fillOpacity: 0.3,
                }).addTo(self.heatmapLayer);
            }
        })
        .catch(function(err) {
            if (typeof trackFetchError === "function") trackFetchError("geo_heatmap", err);
        });
};

GeoMap.prototype.loadCoverage = function() {
    var self = this;
    self.dashboard.apiFetch("/api/geo/coverage")
        .then(function(areas) {
            self.coverageLayer.clearLayers();
            for (var i = 0; i < areas.length; i++) {
                var a = areas[i];
                L.circle([a.latitude, a.longitude], {
                    radius: a.radius_km * 1000,
                    fillColor: "#3b82f6",
                    color: "#3b82f6",
                    weight: 1,
                    fillOpacity: 0.1,
                    dashArray: "5,5",
                }).addTo(self.coverageLayer);
            }
        })
        .catch(function(err) {
            if (typeof trackFetchError === "function") trackFetchError("geo_coverage", err);
        });
};

GeoMap.prototype.invalidateSize = function() {
    if (!this.initialized) {
        // Try init now that tab may be visible
        var self = this;
        setTimeout(function() { self.init(); }, 50);
        setTimeout(function() {
            self.init();
            if (self.map) self.map.invalidateSize();
        }, 200);
        return;
    }
    if (this.map) {
        var m = this.map;
        setTimeout(function() { m.invalidateSize(); }, 50);
        setTimeout(function() { m.invalidateSize(); }, 200);
        setTimeout(function() { m.invalidateSize(); }, 500);
    }
};

/* -- Node Placement ------------------------------------------------- */

GeoMap.prototype._loadAllNodes = function() {
    var self = this;
    self.dashboard.apiFetch("/api/nodes/")
        .then(function(data) {
            var nodes = data.nodes || data || [];
            self._allNodes = nodes.map(function(n) { return n.node_id; });
        })
        .catch(function() {});
};

GeoMap.prototype._showPlacePopup = function(latlng) {
    var self = this;

    // Remove previous pending marker
    if (self._placePending) {
        self.map.removeLayer(self._placePending);
    }

    // Drop a draggable marker
    self._placePending = L.marker(latlng, { draggable: true }).addTo(self.map);

    // Build node options — unplaced nodes first, then placed
    var placedSet = {};
    for (var nid in self.nodeMarkers) placedSet[nid] = true;
    var unplaced = self._allNodes.filter(function(n) { return !placedSet[n]; });
    var placed = self._allNodes.filter(function(n) { return placedSet[n]; });
    var sorted = unplaced.concat(placed);

    var opts = "";
    if (sorted.length === 0) {
        opts = '<option value="">No nodes found</option>';
    } else {
        opts = '<option value="">Select node...</option>';
        if (unplaced.length > 0) {
            opts += '<optgroup label="Unplaced">';
            for (var i = 0; i < unplaced.length; i++) {
                opts += '<option value="' + esc(unplaced[i]) + '">' + esc(unplaced[i]) + '</option>';
            }
            opts += '</optgroup>';
        }
        if (placed.length > 0) {
            opts += '<optgroup label="Already placed">';
            for (var j = 0; j < placed.length; j++) {
                opts += '<option value="' + esc(placed[j]) + '">' + esc(placed[j]) + ' (move)</option>';
            }
            opts += '</optgroup>';
        }
    }

    var popupHtml =
        '<div style="min-width:200px;">' +
        '<strong style="font-size:13px;">Place Node</strong><br>' +
        '<div style="margin:6px 0;">' +
        '<select id="geo-place-select" style="width:100%;padding:4px 6px;border:1px solid var(--border-color);border-radius:4px;background:var(--bg-primary);color:var(--text-primary);font-size:12px;">' +
        opts +
        '</select>' +
        '</div>' +
        '<div style="margin:4px 0;">' +
        '<input id="geo-place-name" type="text" placeholder="Location name (optional)" ' +
        'style="width:100%;padding:4px 6px;border:1px solid var(--border-color);border-radius:4px;background:var(--bg-primary);color:var(--text-primary);font-size:12px;box-sizing:border-box;" />' +
        '</div>' +
        '<div style="font-size:11px;color:var(--text-secondary);margin:4px 0;" id="geo-place-coords">' +
        latlng.lat.toFixed(6) + ', ' + latlng.lng.toFixed(6) +
        '</div>' +
        '<div style="display:flex;gap:6px;margin-top:6px;">' +
        '<button id="geo-place-save" class="btn btn-sm" style="flex:1;">Save</button>' +
        '<button id="geo-place-cancel" class="btn btn-sm" style="flex:1;background:var(--bg-secondary);">Cancel</button>' +
        '</div>' +
        '</div>';

    var popup = L.popup({ closeOnClick: false, autoClose: false, maxWidth: 260 })
        .setLatLng(latlng)
        .setContent(popupHtml)
        .openOn(self.map);

    // Update coords when marker is dragged
    self._placePending.on("dragend", function() {
        var pos = self._placePending.getLatLng();
        popup.setLatLng(pos);
        var coordsEl = document.getElementById("geo-place-coords");
        if (coordsEl) coordsEl.textContent = pos.lat.toFixed(6) + ", " + pos.lng.toFixed(6);
    });

    // Wire save/cancel after popup DOM is ready
    setTimeout(function() {
        var saveBtn = document.getElementById("geo-place-save");
        var cancelBtn = document.getElementById("geo-place-cancel");

        if (saveBtn) {
            saveBtn.addEventListener("click", function() {
                var sel = document.getElementById("geo-place-select");
                var nameInput = document.getElementById("geo-place-name");
                var nodeId = sel ? sel.value : "";
                var locName = nameInput ? nameInput.value.trim() : "";
                if (!nodeId) {
                    sel.style.borderColor = "var(--accent-red)";
                    return;
                }
                var pos = self._placePending.getLatLng();
                self._saveNodeLocation(nodeId, pos.lat, pos.lng, locName, popup);
            });
        }
        if (cancelBtn) {
            cancelBtn.addEventListener("click", function() {
                self.map.closePopup(popup);
                if (self._placePending) {
                    self.map.removeLayer(self._placePending);
                    self._placePending = null;
                }
            });
        }
    }, 50);
};

GeoMap.prototype._saveNodeLocation = function(nodeId, lat, lng, locName, popup) {
    var self = this;
    var saveBtn = document.getElementById("geo-place-save");
    if (saveBtn) { saveBtn.disabled = true; saveBtn.textContent = "Saving..."; }

    self.dashboard.apiFetch("/api/nodes/" + encodeURIComponent(nodeId) + "/location", {
        method: "PUT",
        body: { latitude: lat, longitude: lng, location_name: locName },
    }).then(function() {
        if (typeof showToast === "function") showToast("Placed " + nodeId + " at " + lat.toFixed(4) + ", " + lng.toFixed(4), "success");
        self.map.closePopup(popup);
        if (self._placePending) {
            self.map.removeLayer(self._placePending);
            self._placePending = null;
        }
        self.refresh();
    }).catch(function(e) {
        var msg = (e && e.detail) || (e && e.message) || "Failed to save location";
        if (typeof showToast === "function") showToast(msg, "error");
        if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = "Save"; }
    });
};

/* -- Existing marker dragging in place mode ------------------------- */

GeoMap.prototype._makeMarkerDraggable = function(nodeId, marker) {
    var self = this;
    marker.on("dragend", function() {
        var pos = marker.getLatLng();
        var locName = "";
        // Try to preserve existing location name from popup
        var popup = marker.getPopup();
        if (popup) {
            var content = popup.getContent() || "";
            var match = content.match(/<em>(.*?)<\/em>/);
            if (match) locName = match[1];
        }
        self._saveNodeLocation(nodeId, pos.lat, pos.lng, locName, null);
    });
};

GeoMap.prototype.destroy = function() {
    this.stopAutoRefresh();
    if (this.map) {
        this.map.remove();
        this.map = null;
    }
    this.nodeMarkers = {};
    this.initialized = false;
};
