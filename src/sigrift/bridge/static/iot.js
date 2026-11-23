// IoT protocol tab logic
(function() {
    const zwaveEl = document.getElementById('zwave-devices');
    const tpmsEl = document.getElementById('tpms-ids');
    const ism433El = document.getElementById('ism433-activity');
    const nrf24El = document.getElementById('nrf24-channels');
    const sigfoxEl = document.getElementById('sigfox-msgs');
    const sidewalkEl = document.getElementById('sidewalk-msgs');
    if (!zwaveEl) return;

    async function refreshIoT() {
        if (!window.dashboard || !window.dashboard.isTabAvailable("iot")) return;
        try {
            const resp = await fetch('/api/detections/recent?minutes=60&limit=500');
            const data = await resp.json();
            const dets = data.detections || [];
            let zwave = 0, tpms = 0, ism433 = 0, nrf24 = 0, sigfox = 0, sidewalk = 0;
            dets.forEach(d => {
                const cls = (d.signal_class || '').toLowerCase();
                if (cls.includes('zwave') || cls.includes('z-wave')) zwave++;
                else if (cls.includes('tpms')) tpms++;
                else if (cls.includes('ism433') || cls === '433mhz') ism433++;
                else if (cls.includes('nrf24')) nrf24++;
                else if (cls.includes('sigfox')) sigfox++;
                else if (cls.includes('sidewalk')) sidewalk++;
            });
            zwaveEl.textContent = zwave;
            tpmsEl.textContent = tpms;
            ism433El.textContent = ism433;
            nrf24El.textContent = nrf24;
            sigfoxEl.textContent = sigfox;
            sidewalkEl.textContent = sidewalk;
        } catch(e) { console.error('IoT refresh error:', e); }
    }

    refreshIoT();
    setInterval(refreshIoT, 10000);
})();
