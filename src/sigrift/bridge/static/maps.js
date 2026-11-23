/**
 * Map Viewer module for The Bridge dashboard.
 *
 * Displays node positions, emitter locations, and tracks on both
 * outdoor maps (Leaflet/OpenStreetMap) and indoor floor plans.
 */

/* global L */

// Authenticated fetch — always returns native Response (not parsed JSON)
function _mapApiFetch(path, opts) {
    opts = opts || {};
    var h = opts.headers || {};
    h['Accept'] = 'application/json';
    var token = sessionStorage.getItem('bridge_session_token') || '';
    var key = sessionStorage.getItem('bridge_api_key') || sessionStorage.getItem('bridge_admin_key') || '';
    if (token) h['Authorization'] = 'Bearer ' + token;
    else if (key) h['X-API-Key'] = key;
    opts.headers = h;
    opts.credentials = 'same-origin';
    return fetch(path, opts);
}

class MapViewer {
    constructor(containerId) {
        this.containerId = containerId;
        this.container = document.getElementById(containerId);
        this.leafletMap = null;
        this.floorPlanOverlay = null;
        this.nodeMarkers = {};
        this.emitterMarkers = {};
        this.trackLines = {};
        this.zonePolygons = [];
        this.autoRefreshTimer = null;
        this.currentFloorPlanId = null;
        this._initialized = false;
    }

    async init() {
        if (!this.container || this._initialized) return;
        if (typeof L === 'undefined') return;

        // Defer creation until container is visible (non-zero dimensions)
        if (this.container.offsetWidth === 0 || this.container.offsetHeight === 0) {
            return;
        }

        this._initialized = true;

        this.leafletMap = L.map(this.containerId, {
            center: [0, 0],
            zoom: 2,
            zoomControl: true,
        });

        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; OpenStreetMap contributors',
            maxZoom: 19,
        }).addTo(this.leafletMap);

        // Load initial data
        await this.loadOverlay();
        await this.loadFloorPlanList();
    }

    async loadOverlay() {
        if (!this.leafletMap) return;
        try {
            const resp = await _mapApiFetch('/api/maps/overlay');
            if (!resp.ok) return;
            const data = await resp.json();

            // Clear existing markers
            this._clearMarkers();

            // Place node markers (blue circles)
            if (data.nodes && data.nodes.length > 0) {
                const bounds = [];
                for (const node of data.nodes) {
                    if (node.lat == null || node.lon == null) continue;
                    const marker = L.circleMarker([node.lat, node.lon], {
                        radius: 8,
                        color: '#3b82f6',
                        fillColor: node.status === 'online' ? '#22c55e' :
                                   node.status === 'stale' ? '#eab308' : '#ef4444',
                        fillOpacity: 0.8,
                        weight: 2,
                    }).addTo(this.leafletMap);
                    marker.bindPopup(
                        `<b>Node: ${esc(node.node_id)}</b><br>Status: ${esc(node.status || 'unknown')}`
                    );
                    this.nodeMarkers[node.node_id] = marker;
                    bounds.push([node.lat, node.lon]);
                }

                // Place emitter markers (red circles)
                if (data.emitters) {
                    for (const em of data.emitters) {
                        if (em.lat == null || em.lon == null) continue;
                        const marker = L.circleMarker([em.lat, em.lon], {
                            radius: 6,
                            color: '#ef4444',
                            fillColor: '#ef4444',
                            fillOpacity: 0.6,
                            weight: 2,
                        }).addTo(this.leafletMap);
                        marker.bindPopup(
                            `<b>Emitter: ${esc(em.emitter_id || 'unknown')}</b><br>` +
                            `Confidence: ${(em.confidence || 0).toFixed(2)}`
                        );
                        this.emitterMarkers[em.emitter_id] = marker;
                        bounds.push([em.lat, em.lon]);
                    }
                }

                if (bounds.length > 0) {
                    this.leafletMap.fitBounds(bounds, { padding: [30, 30] });
                }
            }

            // Update floor plan badges if applicable
            const fpSelect = document.getElementById('map-floor-plan');
            if (fpSelect && data.floor_plans) {
                for (const fp of data.floor_plans) {
                    // Matched as text: a floor plan ID is never built into a selector.
                    const opt = Array.prototype.some.call(fpSelect.options, o => o.value === String(fp.id));
                    if (!opt) {
                        const newOpt = document.createElement('option');
                        newOpt.value = fp.id;
                        newOpt.textContent = fp.name;
                        fpSelect.appendChild(newOpt);
                    }
                }
            }
        } catch (err) {
            console.debug('Map overlay fetch failed:', err);
        }
    }

    async loadFloorPlanList() {
        try {
            const resp = await _mapApiFetch('/api/maps/floor-plans');
            if (!resp.ok) return;
            const plans = await resp.json();
            const fpSelect = document.getElementById('map-floor-plan');
            if (!fpSelect) return;

            // Keep the outdoor option, clear the rest
            while (fpSelect.options.length > 1) {
                fpSelect.remove(1);
            }

            for (const plan of plans) {
                const opt = document.createElement('option');
                opt.value = plan.id;
                opt.textContent = plan.name || plan.id;
                fpSelect.appendChild(opt);
            }
        } catch (err) {
            console.debug('Floor plan list fetch failed:', err);
        }
    }

    async loadFloorPlan(planId) {
        if (!this.leafletMap) return;
        this.currentFloorPlanId = planId;

        // Clear existing floor plan overlay
        this._clearFloorPlan();

        if (!planId) {
            // Switch back to outdoor map
            await this.loadOverlay();
            return;
        }

        try {
            const resp = await _mapApiFetch(`/api/maps/view/${planId}`);
            if (!resp.ok) return;
            const data = await resp.json();
            const plan = data.floor_plan;

            // Clear outdoor markers
            this._clearMarkers();

            // If floor plan has geo coords, show it on the map
            if (plan.geo_lat != null && plan.geo_lon != null) {
                const imgUrl = plan.image_url;
                const w = (plan.width_px || 100) * (plan.scale_x || 1);
                const h = (plan.height_px || 100) * (plan.scale_y || 1);
                const mPerDegLat = 111320;
                const mPerDegLon = mPerDegLat * Math.cos(plan.geo_lat * Math.PI / 180);
                const dlat = h / mPerDegLat;
                const dlon = w / (mPerDegLon || mPerDegLat);

                const bounds = [
                    [plan.geo_lat, plan.geo_lon],
                    [plan.geo_lat + dlat, plan.geo_lon + dlon],
                ];
                this.floorPlanOverlay = L.imageOverlay(imgUrl, bounds, {
                    opacity: 0.7,
                }).addTo(this.leafletMap);
                this.leafletMap.fitBounds(bounds, { padding: [20, 20] });
            } else {
                // Use CRS.Simple for local coordinate floor plans
                const wp = plan.width_px || 500;
                const hp = plan.height_px || 400;
                const bounds = [[0, 0], [hp, wp]];
                this.leafletMap.fitBounds(bounds);
            }

            // Place nodes on floor plan
            if (data.nodes) {
                for (const node of data.nodes) {
                    const lat = node.py != null ? node.py : node.y;
                    const lng = node.px != null ? node.px : node.x;
                    if (lat == null || lng == null) continue;

                    let markerPos;
                    if (plan.geo_lat != null) {
                        // Convert pixel to geo
                        const mPerDegLat = 111320;
                        const mPerDegLon = mPerDegLat * Math.cos(plan.geo_lat * Math.PI / 180);
                        markerPos = [
                            plan.geo_lat + (node.y * (plan.scale_y || 1)) / mPerDegLat,
                            plan.geo_lon + (node.x * (plan.scale_x || 1)) / (mPerDegLon || mPerDegLat),
                        ];
                    } else {
                        markerPos = [lat, lng];
                    }

                    const marker = L.circleMarker(markerPos, {
                        radius: 8,
                        color: '#3b82f6',
                        fillColor: '#22c55e',
                        fillOpacity: 0.8,
                        weight: 2,
                    }).addTo(this.leafletMap);
                    marker.bindPopup(`<b>Node: ${esc(node.node_id)}</b>`);
                    this.nodeMarkers[node.node_id] = marker;
                }
            }

            // Place emitters
            if (data.emitters) {
                for (const em of data.emitters) {
                    const lat = em.py != null ? em.py : em.y;
                    const lng = em.px != null ? em.px : em.x;
                    if (lat == null || lng == null) continue;

                    const marker = L.circleMarker([lat, lng], {
                        radius: 6,
                        color: '#ef4444',
                        fillColor: '#ef4444',
                        fillOpacity: 0.6,
                        weight: 2,
                    }).addTo(this.leafletMap);
                    marker.bindPopup(
                        `<b>Emitter: ${esc(em.emitter_id || 'unknown')}</b><br>` +
                        `Confidence: ${(em.confidence || 0).toFixed(2)}`
                    );
                    this.emitterMarkers[em.emitter_id || 'unknown'] = marker;
                }
            }

            // Draw zones
            if (data.zones) {
                for (const zone of data.zones) {
                    if (!zone.polygon || zone.polygon.length < 3) continue;
                    const latlngs = zone.polygon.map(p => [p[1], p[0]]);
                    const poly = L.polygon(latlngs, {
                        color: zone.color || '#3388ff',
                        fillOpacity: 0.15,
                        weight: 2,
                    }).addTo(this.leafletMap);
                    poly.bindPopup(`<b>${esc(zone.name)}</b><br>Type: ${esc(zone.zone_type || 'area')}`);
                    this.zonePolygons.push(poly);
                }
            }
        } catch (err) {
            console.debug('Floor plan view fetch failed:', err);
        }
    }

    async loadTracks(trackId) {
        // Placeholder for track loading via /api/tracking endpoints
        // Will draw polylines when tracking API is available
    }

    startAutoRefresh(intervalMs) {
        if (typeof intervalMs === 'undefined') intervalMs = 5000;
        this.stopAutoRefresh();
        this.autoRefreshTimer = setInterval(() => {
            if (this.currentFloorPlanId) {
                this.loadFloorPlan(this.currentFloorPlanId);
            } else {
                this.loadOverlay();
            }
        }, intervalMs);
    }

    stopAutoRefresh() {
        if (this.autoRefreshTimer) {
            clearInterval(this.autoRefreshTimer);
            this.autoRefreshTimer = null;
        }
    }

    _clearMarkers() {
        for (const key of Object.keys(this.nodeMarkers)) {
            this.nodeMarkers[key].remove();
        }
        this.nodeMarkers = {};
        for (const key of Object.keys(this.emitterMarkers)) {
            this.emitterMarkers[key].remove();
        }
        this.emitterMarkers = {};
        for (const key of Object.keys(this.trackLines)) {
            this.trackLines[key].remove();
        }
        this.trackLines = {};
        for (const poly of this.zonePolygons) {
            poly.remove();
        }
        this.zonePolygons = [];
    }

    _clearFloorPlan() {
        if (this.floorPlanOverlay) {
            this.floorPlanOverlay.remove();
            this.floorPlanOverlay = null;
        }
    }

    destroy() {
        this.stopAutoRefresh();
        this._clearMarkers();
        this._clearFloorPlan();
        if (this.leafletMap) {
            this.leafletMap.remove();
            this.leafletMap = null;
        }
        this._initialized = false;
    }
}

// ---------------------------------------------------------------------------
// Dashboard integration
// ---------------------------------------------------------------------------

let _mapViewer = null;

function initMapPanel() {
    const fpSelect = document.getElementById('map-floor-plan');
    const refreshBtn = document.getElementById('map-refresh');
    const autoRefreshCb = document.getElementById('map-auto-refresh');

    if (fpSelect) {
        fpSelect.addEventListener('change', () => {
            if (_mapViewer) {
                _mapViewer.loadFloorPlan(fpSelect.value || null);
            }
        });
    }

    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            if (_mapViewer) {
                if (_mapViewer.currentFloorPlanId) {
                    _mapViewer.loadFloorPlan(_mapViewer.currentFloorPlanId);
                } else {
                    _mapViewer.loadOverlay();
                }
            }
        });
    }

    if (autoRefreshCb) {
        autoRefreshCb.addEventListener('change', () => {
            if (!_mapViewer) return;
            if (autoRefreshCb.checked) {
                _mapViewer.startAutoRefresh(5000);
            } else {
                _mapViewer.stopAutoRefresh();
            }
        });
    }
}

async function activateMapPanel() {
    if (!_mapViewer) {
        _mapViewer = new MapViewer('map-view-container');
    }
    // Multiple attempts — container may not be sized yet after CSS transition
    for (var delay of [50, 200, 500]) {
        await new Promise(r => setTimeout(r, delay));
        await _mapViewer.init();
        if (_mapViewer.leafletMap) {
            _mapViewer.leafletMap.invalidateSize();
            break;
        }
    }
}

function deactivateMapPanel() {
    if (_mapViewer) {
        _mapViewer.stopAutoRefresh();
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initMapPanel);
} else {
    initMapPanel();
}
