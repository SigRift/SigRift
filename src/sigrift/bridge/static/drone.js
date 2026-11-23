// Drone detection tab logic
(function() {
    const table = document.querySelector('#drone-table tbody');
    if (!table) return;

    async function refreshDrones() {
        if (!window.dashboard || !window.dashboard.isTabAvailable("drone")) return;
        try {
            const resp = await fetch('/api/detections/recent?minutes=30&limit=50');
            const data = await resp.json();
            const droneClasses = ['dji-ofdm', 'dji_ofdm', 'fpv-analog', 'fpv_analog', 'elrs'];
            const dets = (data.detections || []).filter(
                d => droneClasses.includes((d.signal_class || '').toLowerCase())
            );
            table.innerHTML = '';
            dets.forEach(d => {
                const tr = document.createElement('tr');
                // Detection text comes from sensors: escaped (esc() from dashboard.js).
                tr.innerHTML = `<td>${esc(d.signal_class || '')}</td>
                    <td>${esc(d.signal_class || '')}</td>
                    <td>${d.freq_hz ? (d.freq_hz/1e6).toFixed(1) + ' MHz' : ''}</td>
                    <td>${d.power_dbm != null ? d.power_dbm.toFixed(1) + ' dBm' : ''}</td>
                    <td>${esc(d.timestamp || '')}</td>
                    <td>${esc(d.timestamp || '')}</td>
                    <td><span class="badge badge-warning">Active</span></td>`;
                table.appendChild(tr);
            });
        } catch(e) { console.error('Drone refresh error:', e); }
    }

    refreshDrones();
    setInterval(refreshDrones, 5000);
})();
