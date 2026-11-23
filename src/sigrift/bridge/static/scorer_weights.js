// Scorer Weights editor for admin panel
document.addEventListener('DOMContentLoaded', function() {
    var container = document.getElementById('scorer-weights-container');
    var saveBtn = document.getElementById('scorer-save-btn');
    var totalEl = document.getElementById('scorer-total');
    var statusEl = document.getElementById('scorer-status');
    if (!container || !saveBtn) return;

    var weights = {};
    var labels = {
        novel_class: 'Novel Class', rare_class: 'Rare Class', low_confidence: 'Low Confidence',
        power_zscore: 'Power Z-Score', snr_zscore: 'SNR Z-Score', timing_anomaly: 'Timing Anomaly',
        quiet_frequency: 'Quiet Frequency', iq_quality: 'IQ Quality', spectral_anomaly: 'Spectral Anomaly',
        modulation_anomaly: 'Modulation Anomaly', correlation: 'Correlation',
        signature_match: 'SIGNATURE MATCH (Threat Detection)',
        bandwidth_anomaly: 'Bandwidth Anomaly', inter_arrival_anomaly: 'Inter-Arrival Anomaly'
    };
    var highlight = { signature_match: true };

    function doFetch(path, opts) {
        if (window.adminPanel) return window.adminPanel.apiFetch(path, opts);
        opts = opts || {};
        var h = opts.headers || {};
        h['Accept'] = 'application/json';
        var key = sessionStorage.getItem('bridge_admin_key') || sessionStorage.getItem('bridge_api_key') || '';
        if (key) h['X-API-Key'] = key;
        var token = sessionStorage.getItem('bridge_session_token');
        if (token && !key) h['X-Session-Token'] = token;
        if (opts.body && typeof opts.body === 'object' && !(opts.body instanceof FormData)) {
            h['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(opts.body);
        }
        opts.headers = h;
        return fetch(path, opts).then(function(r) {
            if (!r.ok) return r.text().then(function(t) { return Promise.reject(new Error('HTTP ' + r.status)); });
            return r.json();
        });
    }

    function loadWeights() {
        container.innerHTML = '<p style="color:var(--text-secondary);">Loading weights...</p>';
        doFetch('/api/admin/detection-config').then(function(data) {
            weights = (data.config || {}).rf_dimension_weights || {};
            if (Object.keys(weights).length === 0) {
                container.innerHTML = '<p style="color:var(--text-secondary);">No weights returned.</p>';
                return;
            }
            renderWeights();
        }).catch(function(e) {
            container.innerHTML = '<p style="color:#ef4444;">Failed to load: ' + esc(e.message || 'error') + '</p>';
        });
    }

    function renderWeights() {
        container.innerHTML = '';
        var keys = Object.keys(weights).sort(function(a, b) {
            if (a === 'signature_match') return -1;
            if (b === 'signature_match') return 1;
            return (weights[b] || 0) - (weights[a] || 0);
        });
        keys.forEach(function(k) {
            var v = weights[k] || 0;
            var label = labels[k] || k;
            var isHighlight = highlight[k];
            var div = document.createElement('div');
            div.style.cssText = 'display:flex;align-items:center;gap:8px;padding:8px;border-radius:6px;' +
                (isHighlight ? 'background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);' : 'background:var(--bg-secondary);');
            div.innerHTML =
                '<label style="flex:1;font-size:0.85em;' + (isHighlight ? 'font-weight:700;color:#ef4444;' : '') + '">' +
                    esc(label) +
                '</label>' +
                '<input type="range" min="0" max="0.5" step="0.01" value="' + esc(v) + '" ' +
                    'data-key="' + esc(k) + '" style="flex:1;accent-color:' + (isHighlight ? '#ef4444' : 'var(--accent-blue)') + ';">' +
                '<input type="number" min="0" max="1" step="0.01" value="' + esc(v) + '" ' +
                    'data-key="' + esc(k) + '" style="width:60px;text-align:center;background:var(--bg-primary);color:var(--text-primary);border:1px solid var(--border-color);border-radius:4px;padding:2px 4px;">';
            container.appendChild(div);

            var range = div.querySelector('input[type=range]');
            var num = div.querySelector('input[type=number]');
            range.addEventListener('input', function() { num.value = range.value; weights[k] = parseFloat(range.value); updateTotal(); });
            num.addEventListener('input', function() { range.value = num.value; weights[k] = parseFloat(num.value) || 0; updateTotal(); });
        });
        updateTotal();
    }

    function updateTotal() {
        var t = 0;
        for (var k in weights) t += weights[k] || 0;
        if (totalEl) {
            totalEl.textContent = t.toFixed(2);
            totalEl.style.color = t > 1.3 ? '#ef4444' : t < 0.8 ? '#eab308' : '#22c55e';
        }
    }

    saveBtn.addEventListener('click', function() {
        saveBtn.disabled = true;
        saveBtn.textContent = 'Saving...';
        doFetch('/api/admin/detection-config', {
            method: 'PUT',
            body: { rf_dimension_weights: weights }
        }).then(function() {
            if (statusEl) {
                statusEl.style.display = '';
                statusEl.style.color = '#22c55e';
                statusEl.textContent = 'Weights saved successfully.';
                setTimeout(function() { statusEl.style.display = 'none'; }, 5000);
            }
        }).catch(function(e) {
            if (statusEl) {
                statusEl.style.display = '';
                statusEl.style.color = '#ef4444';
                statusEl.textContent = 'Save failed: ' + (e.message || 'error');
            }
        }).finally(function() {
            saveBtn.disabled = false;
            saveBtn.textContent = 'Save Weights';
        });
    });

    // Load when scorer tab becomes visible
    var navItem = document.querySelector('a[data-tab="scorer"]');
    if (navItem) {
        navItem.addEventListener('click', function() { setTimeout(loadWeights, 100); });
    }
    if (window.location.hash === '#scorer') setTimeout(loadWeights, 300);
});
