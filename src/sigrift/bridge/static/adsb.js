// ADS-B tab logic
(function() {
    const table = document.querySelector('#aircraft-table tbody');
    if (!table) return;

    function getAuthHeaders() {
        var headers = {};
        var token = sessionStorage.getItem('bridge_session_token');
        var apiKey = sessionStorage.getItem('bridge_api_key') || sessionStorage.getItem('bridge_admin_key');
        if (token) headers['X-Session-Token'] = token;
        else if (apiKey) headers['X-API-Key'] = apiKey;
        return headers;
    }

    // Defer Leaflet map creation until tab is first visible
    var map = null;
    var markers = {};
    var trails = {};
    var mapInitialized = false;

    function initMap() {
        if (mapInitialized) return;
        var mapEl = document.getElementById('adsb-map');
        if (!mapEl || typeof L === 'undefined') return;
        mapInitialized = true;
        mapEl.innerHTML = '';
        mapEl.style.display = 'block';
        map = L.map('adsb-map').setView([39.8283, -98.5795], 4);
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; OpenStreetMap',
            maxZoom: 18
        }).addTo(map);
        // Force resize after creation
        setTimeout(function() { if (map) map.invalidateSize(); }, 100);
        setTimeout(function() { if (map) map.invalidateSize(); }, 300);
    }

    function altitudeColor(alt) {
        if (!alt) return '#888';
        if (alt < 5000) return '#2ecc71';
        if (alt < 15000) return '#f1c40f';
        if (alt < 30000) return '#e67e22';
        return '#e74c3c';
    }

    async function refreshAircraft() {
        if (!window.dashboard || !window.dashboard.isTabAvailable("adsb")) return;
        try {
            var resp = await fetch('/api/aircraft/?max_age=300', { headers: getAuthHeaders() });
            if (!resp.ok) return;
            var data = await resp.json();
            table.innerHTML = '';
            var seen = {};
            (data.aircraft || []).forEach(function(a) {
                seen[a.icao_address] = true;
                var tr = document.createElement('tr');
                // Aircraft text is heard over the air: escaped (esc() from dashboard.js).
                tr.innerHTML = '<td>' + esc(a.icao_address || '') + '</td>' +
                    '<td>' + esc(a.callsign || '') + '</td>' +
                    '<td><span class="badge">' + esc(a.source || '') + '</span></td>' +
                    '<td>' + (a.altitude_ft ? Math.round(a.altitude_ft) + ' ft' : '') + '</td>' +
                    '<td>' + (a.velocity_kts ? Math.round(a.velocity_kts) + ' kts' : '') + '</td>' +
                    '<td>' + (a.lat && a.lon ? a.lat.toFixed(4) + ', ' + a.lon.toFixed(4) : '') + '</td>' +
                    '<td>' + (a.rssi_dbm ? a.rssi_dbm.toFixed(1) + ' dBm' : '') + '</td>' +
                    '<td>' + esc(a.last_seen || '') + '</td>';
                table.appendChild(tr);

                // Update map markers
                if (map && a.lat && a.lon) {
                    var color = altitudeColor(a.altitude_ft);
                    if (markers[a.icao_address]) {
                        markers[a.icao_address].setLatLng([a.lat, a.lon]);
                        markers[a.icao_address].setStyle({fillColor: color});
                    } else {
                        markers[a.icao_address] = L.circleMarker([a.lat, a.lon], {
                            radius: 6, fillColor: color, color: '#333',
                            weight: 1, opacity: 1, fillOpacity: 0.9
                        }).addTo(map).bindPopup(
                            '<b>' + esc(a.callsign || a.icao_address) + '</b><br>' +
                            'ICAO: ' + esc(a.icao_address) + '<br>' +
                            'Alt: ' + (a.altitude_ft ? Math.round(a.altitude_ft) + ' ft' : '?') + '<br>' +
                            'Spd: ' + (a.velocity_kts ? Math.round(a.velocity_kts) + ' kts' : '?') + '<br>' +
                            'Source: ' + esc(a.source || '?')
                        );
                    }
                    // Trail
                    if (!trails[a.icao_address]) trails[a.icao_address] = [];
                    trails[a.icao_address].push([a.lat, a.lon]);
                    if (trails[a.icao_address].length > 50) trails[a.icao_address].shift();
                }
            });
            // Remove stale markers
            Object.keys(markers).forEach(function(icao) {
                if (!seen[icao]) {
                    map && map.removeLayer(markers[icao]);
                    delete markers[icao];
                    delete trails[icao];
                }
            });
            // Show count
            var countEl = document.getElementById('adsb-count');
            if (countEl) countEl.textContent = (data.aircraft || []).length + ' aircraft';
        } catch(e) { console.error('ADS-B refresh error:', e); }
    }

    refreshAircraft();
    setInterval(refreshAircraft, 2000);

    // Expose invalidateSize for tab activation (Leaflet needs resize when tab becomes visible)
    window._adsbMapInvalidate = function() {
        initMap();
        if (map) {
            setTimeout(function() { map.invalidateSize(); }, 50);
            setTimeout(function() { map.invalidateSize(); }, 200);
            setTimeout(function() { map.invalidateSize(); }, 500);
        }
    };
})();
