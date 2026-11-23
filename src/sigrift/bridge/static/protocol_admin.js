// Protocol Detection admin panel logic
(function() {
    const container = document.getElementById('protocol-toggles');
    const saveBtn = document.getElementById('save-protocols');
    const resultEl = document.getElementById('protocol-save-result');
    if (!container || !saveBtn) return;

    const PROTO_LABELS = {
        adsb: 'ADS-B',
        dect: 'DECT',
        p25: 'P25',
        scada_fsk: 'SCADA FSK',
        zwave: 'Z-Wave',
        tpms: 'TPMS',
        ism433: 'ISM 433 MHz',
        nrf24: 'nRF24',
        dji_ofdm: 'DJI OFDM',
        fpv_analog: 'FPV Analog',
        elrs: 'ExpressLRS',
        sigfox: 'Sigfox',
        sidewalk: 'Amazon Sidewalk',
        nbiot: 'NB-IoT',
        wireless_hart: 'WirelessHART',
        isa100: 'ISA100.11a',
        wisun: 'Wi-SUN',
        pmr446: 'PMR446',
        lora_meshtastic: 'Meshtastic',
        lora_meshcore: 'MeshCore',
    };

    let protocols = {};

    async function loadProtocols() {
        try {
            const resp = await fetch('/api/admin/protocols');
            const data = await resp.json();
            protocols = data.protocols || {};
            render();
        } catch(e) {
            container.innerHTML = '<p style="color:var(--accent-red)">Failed to load protocol config</p>';
        }
    }

    function render() {
        container.innerHTML = '';
        Object.entries(protocols).forEach(([proto, info]) => {
            const label = PROTO_LABELS[proto] || proto;
            const licensed = info.licensed !== false;
            const enabled = info.enabled && licensed;
            const div = document.createElement('div');
            div.style.cssText = 'padding:10px 12px;border:1px solid var(--border-primary);border-radius:6px;background:var(--bg-secondary);display:flex;align-items:center;justify-content:space-between;';
            if (!licensed) div.style.opacity = '0.5';
            div.innerHTML = `
                <div>
                    <div style="font-weight:600;font-size:13px;">${esc(label)}</div>
                    ${!licensed ? '<div style="font-size:11px;color:var(--accent-yellow);">Unlicensed</div>' : ''}
                </div>
                <label class="toggle-switch" style="position:relative;display:inline-block;width:40px;height:22px;">
                    <input type="checkbox" data-proto="${esc(proto)}" ${enabled ? 'checked' : ''} ${!licensed ? 'disabled' : ''} style="opacity:0;width:0;height:0;">
                    <span style="position:absolute;cursor:${licensed ? 'pointer' : 'not-allowed'};top:0;left:0;right:0;bottom:0;background:${enabled ? 'var(--accent-green)' : 'var(--bg-tertiary)'};border-radius:11px;transition:.3s;"></span>
                </label>`;
            container.appendChild(div);

            // Toggle visual feedback
            const cb = div.querySelector('input');
            const span = div.querySelector('span:last-child');
            if (cb && span) {
                cb.addEventListener('change', () => {
                    span.style.background = cb.checked ? 'var(--accent-green)' : 'var(--bg-tertiary)';
                });
            }
        });
    }

    saveBtn.addEventListener('click', async () => {
        const body = {};
        container.querySelectorAll('input[data-proto]').forEach(cb => {
            if (!cb.disabled) body[cb.dataset.proto] = cb.checked;
        });
        try {
            const resp = await fetch('/api/admin/protocols', {
                method: 'PUT',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(body),
            });
            const data = await resp.json();
            if (resultEl) {
                resultEl.style.display = 'block';
                resultEl.textContent = data.status === 'ok' ? 'Protocol settings saved.' : 'Error: ' + JSON.stringify(data);
                resultEl.style.color = data.status === 'ok' ? 'var(--accent-green)' : 'var(--accent-red)';
                setTimeout(() => { resultEl.style.display = 'none'; }, 3000);
            }
            loadProtocols();
        } catch(e) {
            if (resultEl) {
                resultEl.style.display = 'block';
                resultEl.textContent = 'Save failed: ' + e.message;
                resultEl.style.color = 'var(--accent-red)';
            }
        }
    });

    // Load on tab activation
    const navItem = document.querySelector('[data-tab="protocols"]');
    if (navItem) {
        navItem.addEventListener('click', loadProtocols);
    }
    // Also load if already visible
    const panel = document.getElementById('tab-protocols');
    if (panel && panel.style.display !== 'none') loadProtocols();
})();
