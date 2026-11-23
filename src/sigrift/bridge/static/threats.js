/**
 * Threat Signature Browser — Frontend module.
 *
 * Manages threat signature CRUD, filtering, inline test matching,
 * seed defaults, and auto-refresh.
 */
(function () {
    'use strict';

    var API = '/api/signatures';
    var refreshInterval = null;
    var expandedSigId = null;
    var currentFilters = { category: '', level: '', search: '' };

    // ── Auth ─────────────────────────────────────────────────────────

    function getAuthHeaders() {
        var headers = { 'Content-Type': 'application/json' };
        var token = sessionStorage.getItem('bridge_session_token');
        var apiKey = sessionStorage.getItem('bridge_api_key') || sessionStorage.getItem('bridge_admin_key');
        if (token) headers['X-Session-Token'] = token;
        else if (apiKey) headers['X-API-Key'] = apiKey;
        return headers;
    }

    function authHeaders() {
        var headers = {};
        var token = sessionStorage.getItem('bridge_session_token');
        var apiKey = sessionStorage.getItem('bridge_api_key') || sessionStorage.getItem('bridge_admin_key');
        if (token) headers['X-Session-Token'] = token;
        else if (apiKey) headers['X-API-Key'] = apiKey;
        return headers;
    }

    // ── Helpers ──────────────────────────────────────────────────────

    /* HTML-escape text (& < > " ') for element content and for quoted attribute
     * values. Not for unquoted attributes, URLs, inline handlers, script elements or style. */
    function esc(s) {
        if (s == null) return '';
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    /* Plain text, not markup: callers escape it. */
    function fmtFreq(hz) {
        if (hz == null) return '--';
        if (hz >= 1e9) return (hz / 1e9).toFixed(3) + ' GHz';
        if (hz >= 1e6) return (hz / 1e6).toFixed(3) + ' MHz';
        if (hz >= 1e3) return (hz / 1e3).toFixed(1) + ' kHz';
        return hz + ' Hz';
    }

    var CATEGORY_COLORS = {
        covert_mic: '#fc8181',
        video_tx: '#d6bcfa',
        body_worn_tx: '#f6ad55',
        gps_tracker: '#63b3ed',
        jammer: '#fc8181',
        remote_control: '#fefcbf',
        imsi_catcher: '#fc8181',
        drone_surveillance: '#63b3ed',
        data_exfil: '#d6bcfa',
        surveillance_infra: '#c6f6d5',
        counter_surveillance: '#fefcbf',
        unknown_threat: '#a0aec0'
    };

    var LEVEL_COLORS = {
        critical: '#fc8181',
        high: '#f6ad55',
        medium: '#fefcbf',
        low: '#c6f6d5'
    };

    function categoryBadge(cat) {
        var bg = CATEGORY_COLORS[cat] || '#e2e8f0';
        return '<span style="background:' + bg + ';color:#1a1a2e;padding:2px 8px;border-radius:4px;font-size:0.85em;font-weight:600;">' +
            esc(cat ? cat.replace(/_/g, ' ') : '') + '</span>';
    }

    function levelBadge(level) {
        var bg = LEVEL_COLORS[level] || '#e2e8f0';
        return '<span style="background:' + bg + ';color:#1a1a2e;padding:2px 8px;border-radius:4px;font-size:0.85em;font-weight:600;">' +
            esc(level || '') + '</span>';
    }

    // ── Stats Bar ────────────────────────────────────────────────────

    function refreshStats() {
        fetch(API + '/stats', { headers: authHeaders() })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (data) {
                if (!data) return;
                var el;
                el = document.getElementById('threat-stat-total');
                if (el) el.textContent = data.total != null ? data.total : '--';
                el = document.getElementById('threat-stat-threats');
                if (el) el.textContent = data.threat_count != null ? data.threat_count : '--';

                // Category breakdown
                var catEl = document.getElementById('threat-stat-categories');
                if (catEl && data.by_threat_category) {
                    var cats = data.by_threat_category;
                    var parts = [];
                    for (var c in cats) {
                        if (cats.hasOwnProperty(c) && cats[c] > 0) {
                            parts.push(esc(c.replace(/_/g, ' ')) + ': ' + cats[c]);
                        }
                    }
                    catEl.textContent = parts.length > 0 ? parts.join(', ') : 'none';
                }

                // Level counts
                var levels = data.by_threat_level || {};
                el = document.getElementById('threat-stat-critical');
                if (el) el.textContent = levels.critical || 0;
                el = document.getElementById('threat-stat-high');
                if (el) el.textContent = levels.high || 0;
                el = document.getElementById('threat-stat-medium');
                if (el) el.textContent = levels.medium || 0;
                el = document.getElementById('threat-stat-low');
                if (el) el.textContent = levels.low || 0;
            })
            .catch(function (e) { console.error('Threat stats error:', e); });
    }

    // ── Threat List ─────────────────────────────────────────────────

    function refreshThreats() {
        var params = [];
        if (currentFilters.category) params.push('threat_category=' + encodeURIComponent(currentFilters.category));
        if (currentFilters.level) params.push('threat_level=' + encodeURIComponent(currentFilters.level));
        var qs = params.length > 0 ? '?' + params.join('&') : '';

        fetch(API + '/threats/list' + qs, { headers: authHeaders() })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (data) {
                if (!data) return;
                var tbody = document.getElementById('threats-tbody');
                var empty = document.getElementById('threats-empty');
                if (!tbody) return;

                // Client-side search filter
                var items = data;
                if (currentFilters.search) {
                    var q = currentFilters.search.toLowerCase();
                    items = items.filter(function (sig) {
                        return (sig.name || '').toLowerCase().indexOf(q) !== -1 ||
                            (sig.description || '').toLowerCase().indexOf(q) !== -1 ||
                            (sig.signal_class || '').toLowerCase().indexOf(q) !== -1;
                    });
                }

                if (items.length === 0) {
                    tbody.innerHTML = '';
                    if (empty) empty.style.display = '';
                    return;
                }
                if (empty) empty.style.display = 'none';

                var html = '';
                items.forEach(function (sig) {
                    var id = sig.id || sig.sig_id || '';
                    var rowClass = expandedSigId === id ? ' class="row-selected"' : '';
                    var freqRange = '';
                    if (sig.freq_min_hz != null && sig.freq_max_hz != null) {
                        freqRange = fmtFreq(sig.freq_min_hz) + ' - ' + fmtFreq(sig.freq_max_hz);
                    } else if (sig.center_freq_hz != null) {
                        freqRange = fmtFreq(sig.center_freq_hz);
                    }
                    var active = sig.active !== false;

                    html += '<tr' + rowClass + ' data-id="' + esc(id) + '" style="cursor:pointer;">' +
                        '<td>' + esc(sig.name) + '</td>' +
                        '<td>' + categoryBadge(sig.threat_category) + '</td>' +
                        '<td>' + levelBadge(sig.threat_level) + '</td>' +
                        '<td>' + esc(sig.signal_class || '--') + '</td>' +
                        '<td>' + esc(freqRange || '--') + '</td>' +
                        '<td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + esc(sig.description || '') + '</td>' +
                        '<td><span style="color:' + (active ? 'var(--accent-green)' : 'var(--accent-red)') + ';">' + (active ? 'Active' : 'Inactive') + '</span></td>' +
                        '</tr>';

                    if (expandedSigId === id) {
                        html += '<tr class="detail-row"><td colspan="7">' +
                            '<div id="threat-detail-' + esc(id) + '" class="threat-detail-panel">' +
                            '<div style="text-align:center;padding:16px;color:var(--text-dim);">Loading...</div>' +
                            '</div></td></tr>';
                    }
                });
                tbody.innerHTML = html;

                // Wire click handlers
                tbody.querySelectorAll('tr[data-id]').forEach(function (row) {
                    row.addEventListener('click', function (e) {
                        if (e.target.closest('button, input, select, textarea, a')) return;
                        var id = row.getAttribute('data-id');
                        toggleDetail(id);
                    });
                });

                // Load expanded detail if any
                if (expandedSigId) {
                    loadDetail(expandedSigId);
                }
            })
            .catch(function (e) { console.error('Threat list error:', e); });
    }

    // ── Detail Panel ────────────────────────────────────────────────

    function toggleDetail(sigId) {
        if (expandedSigId === sigId) {
            expandedSigId = null;
        } else {
            expandedSigId = sigId;
        }
        refreshThreats();
    }

    function loadDetail(sigId) {
        var panel = document.getElementById('threat-detail-' + sigId);
        if (!panel) return;

        fetch(API + '/' + encodeURIComponent(sigId), { headers: authHeaders() })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (sig) {
                if (!sig) { panel.innerHTML = '<p style="color:var(--accent-red);">Failed to load signature</p>'; return; }
                renderDetail(panel, sig);
            })
            .catch(function (e) {
                panel.innerHTML = '<p style="color:var(--accent-red);">Error: ' + esc(e.message) + '</p>';
            });
    }

    function renderDetail(panel, sig) {
        var id = sig.id || sig.sig_id || '';
        var html = '';

        // Full details grid
        html += '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:16px;">';
        html += '<div>';
        html += '<h4 style="margin:0 0 8px;">Details</h4>';
        html += '<div><strong>Name:</strong> ' + esc(sig.name) + '</div>';
        html += '<div><strong>Protocol:</strong> ' + esc(sig.protocol || '--') + '</div>';
        html += '<div><strong>Signal Class:</strong> ' + esc(sig.signal_class || '--') + '</div>';
        html += '<div><strong>Category:</strong> ' + categoryBadge(sig.threat_category) + '</div>';
        html += '<div><strong>Level:</strong> ' + levelBadge(sig.threat_level) + '</div>';
        html += '<div><strong>Active:</strong> ' + (sig.active !== false ? 'Yes' : 'No') + '</div>';
        html += '</div>';

        html += '<div>';
        html += '<h4 style="margin:0 0 8px;">Parameters</h4>';
        html += '<div><strong>Freq Min:</strong> ' + esc(fmtFreq(sig.freq_min_hz)) + '</div>';
        html += '<div><strong>Freq Max:</strong> ' + esc(fmtFreq(sig.freq_max_hz)) + '</div>';
        html += '<div><strong>Center Freq:</strong> ' + esc(fmtFreq(sig.center_freq_hz)) + '</div>';
        html += '<div><strong>Power Min:</strong> ' + (sig.power_min_dbm != null ? esc(sig.power_min_dbm) + ' dBm' : '--') + '</div>';
        html += '<div><strong>Power Max:</strong> ' + (sig.power_max_dbm != null ? esc(sig.power_max_dbm) + ' dBm' : '--') + '</div>';
        html += '</div>';

        html += '<div>';
        html += '<h4 style="margin:0 0 8px;">Timing</h4>';
        html += '<div><strong>Burst Duration:</strong> ' + (sig.burst_duration_ms != null ? esc(sig.burst_duration_ms) + ' ms' : '--') + '</div>';
        html += '<div><strong>Burst Interval:</strong> ' + (sig.burst_interval_ms != null ? esc(sig.burst_interval_ms) + ' ms' : '--') + '</div>';
        if (sig.description) html += '<div style="margin-top:8px;"><strong>Description:</strong> ' + esc(sig.description) + '</div>';
        html += '</div>';
        html += '</div>';

        // Test Match form
        html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">';
        html += '<div style="background:var(--bg-secondary);padding:12px;border-radius:6px;border:1px solid var(--border-color);">';
        html += '<h4 style="margin:0 0 8px;">Test Parameter Match</h4>';
        html += '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;">';
        html += '<div><label style="font-size:0.8em;">Freq (Hz)</label><br><input type="number" id="threat-test-freq-' + esc(id) + '" class="form-input" placeholder="e.g. 2437000000" style="width:140px;"></div>';
        html += '<div><label style="font-size:0.8em;">Signal Class</label><br><input type="text" id="threat-test-class-' + esc(id) + '" class="form-input" placeholder="e.g. wifi" style="width:120px;"></div>';
        html += '<div><label style="font-size:0.8em;">Power (dBm)</label><br><input type="number" id="threat-test-power-' + esc(id) + '" class="form-input" placeholder="e.g. -30" style="width:100px;"></div>';
        html += '<button class="btn btn-sm btn-primary" id="threat-test-btn-' + esc(id) + '">Test Match</button>';
        html += '</div>';
        html += '<div id="threat-test-result-' + esc(id) + '" style="margin-top:8px;"></div>';
        html += '</div>';

        // Edit form
        html += '<div style="background:var(--bg-secondary);padding:12px;border-radius:6px;border:1px solid var(--border-color);">';
        html += '<h4 style="margin:0 0 8px;">Edit Signature</h4>';
        html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;">';
        html += '<div><label style="font-size:0.8em;">Name</label><input type="text" id="threat-edit-name-' + esc(id) + '" class="form-input" value="' + esc(sig.name || '') + '" style="width:100%;"></div>';
        html += '<div><label style="font-size:0.8em;">Signal Class</label><input type="text" id="threat-edit-class-' + esc(id) + '" class="form-input" value="' + esc(sig.signal_class || '') + '" style="width:100%;"></div>';
        html += '<div><label style="font-size:0.8em;">Description</label><input type="text" id="threat-edit-desc-' + esc(id) + '" class="form-input" value="' + esc(sig.description || '') + '" style="width:100%;"></div>';
        html += '<div><label style="font-size:0.8em;">Source</label><input type="text" id="threat-edit-source-' + esc(id) + '" class="form-input" value="' + esc(sig.source || '') + '" style="width:100%;"></div>';
        html += '</div>';
        html += '<div style="margin-top:8px;display:flex;gap:8px;">';
        html += '<button class="btn btn-sm btn-primary" id="threat-edit-save-' + esc(id) + '">Save</button>';
        html += '<button class="btn btn-sm" style="color:var(--accent-red);" id="threat-delete-btn-' + esc(id) + '">Delete</button>';
        html += '</div>';
        html += '</div>';
        html += '</div>';

        panel.innerHTML = html;

        // Wire test match
        var testBtn = document.getElementById('threat-test-btn-' + id);
        if (testBtn) {
            testBtn.addEventListener('click', function () {
                var freq = document.getElementById('threat-test-freq-' + id);
                var cls = document.getElementById('threat-test-class-' + id);
                var pwr = document.getElementById('threat-test-power-' + id);
                var body = {};
                if (freq && freq.value) body.freq_hz = parseFloat(freq.value);
                if (cls && cls.value) body.signal_class = cls.value.trim();
                if (pwr && pwr.value) body.power_dbm = parseFloat(pwr.value);

                fetch(API + '/threats/match', {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify(body)
                })
                    .then(function (r) { return r.ok ? r.json() : null; })
                    .then(function (result) {
                        var el = document.getElementById('threat-test-result-' + id);
                        if (!el || !result) return;
                        if (result.matched) {
                            var matchHtml = '<div style="color:var(--accent-red);font-weight:600;">' + esc(result.count) + ' match(es) found:</div>';
                            result.matches.forEach(function (m) {
                                matchHtml += '<div style="margin-top:4px;padding:4px 8px;background:var(--bg-tertiary);border-radius:4px;">' +
                                    esc(m.name) + ' — ' + levelBadge(m.threat_level) + ' — score: ' + (m.match_score != null ? (m.match_score * 100).toFixed(0) + '%' : 'N/A') +
                                    '</div>';
                            });
                            el.innerHTML = matchHtml;
                        } else {
                            el.innerHTML = '<span style="color:var(--accent-green);">No matches</span>';
                        }
                    })
                    .catch(function (e) {
                        var el = document.getElementById('threat-test-result-' + id);
                        if (el) el.innerHTML = '<span style="color:var(--accent-red);">Error: ' + esc(e.message) + '</span>';
                    });
            });
        }

        // Wire edit save
        var saveBtn = document.getElementById('threat-edit-save-' + id);
        if (saveBtn) {
            saveBtn.addEventListener('click', function () {
                var updates = {};
                var nameEl = document.getElementById('threat-edit-name-' + id);
                var classEl = document.getElementById('threat-edit-class-' + id);
                var descEl = document.getElementById('threat-edit-desc-' + id);
                var sourceEl = document.getElementById('threat-edit-source-' + id);
                if (nameEl && nameEl.value.trim()) updates.name = nameEl.value.trim();
                if (classEl) updates.signal_class = classEl.value.trim();
                if (descEl) updates.description = descEl.value.trim();
                if (sourceEl) updates.source = sourceEl.value.trim();

                fetch(API + '/' + encodeURIComponent(id), {
                    method: 'PUT',
                    headers: getAuthHeaders(),
                    body: JSON.stringify(updates)
                })
                    .then(function (r) {
                        if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
                        return r.json();
                    })
                    .then(function () {
                        refreshThreats();
                        refreshStats();
                    })
                    .catch(function (e) { alert('Failed to save: ' + e.message); });
            });
        }

        // Wire delete
        var delBtn = document.getElementById('threat-delete-btn-' + id);
        if (delBtn) {
            delBtn.addEventListener('click', function () {
                if (!confirm('Delete threat signature "' + sig.name + '"?')) return;
                fetch(API + '/' + encodeURIComponent(id), {
                    method: 'DELETE',
                    headers: getAuthHeaders()
                })
                    .then(function (r) {
                        if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
                        expandedSigId = null;
                        refreshThreats();
                        refreshStats();
                    })
                    .catch(function (e) { alert('Failed to delete: ' + e.message); });
            });
        }
    }

    // ── Create Signature ────────────────────────────────────────────

    function createSignature() {
        var name = (document.getElementById('threat-create-name') || {}).value;
        if (!name || !name.trim()) { alert('Name is required'); return; }

        var formData = new FormData();
        formData.append('name', name.trim());
        formData.append('protocol', ((document.getElementById('threat-create-protocol') || {}).value || '').trim());
        formData.append('signal_class', ((document.getElementById('threat-create-signal-class') || {}).value || '').trim());
        formData.append('description', ((document.getElementById('threat-create-description') || {}).value || '').trim());

        var threatCategory = ((document.getElementById('threat-create-category') || {}).value || '').trim();
        var threatLevel = ((document.getElementById('threat-create-level') || {}).value || '').trim();
        var freqMin = (document.getElementById('threat-create-freq-min') || {}).value;
        var freqMax = (document.getElementById('threat-create-freq-max') || {}).value;
        var centerFreq = (document.getElementById('threat-create-center-freq') || {}).value;
        var powerMin = (document.getElementById('threat-create-power-min') || {}).value;
        var powerMax = (document.getElementById('threat-create-power-max') || {}).value;
        var burstDuration = (document.getElementById('threat-create-burst-duration') || {}).value;
        var burstInterval = (document.getElementById('threat-create-burst-interval') || {}).value;

        if (centerFreq) formData.append('center_freq_hz', centerFreq);

        // Encode threat-specific fields as tags JSON for storage
        var tags = [];
        if (threatCategory) tags.push('threat_category:' + threatCategory);
        if (threatLevel) tags.push('threat_level:' + threatLevel);
        if (freqMin) tags.push('freq_min_hz:' + freqMin);
        if (freqMax) tags.push('freq_max_hz:' + freqMax);
        if (powerMin) tags.push('power_min_dbm:' + powerMin);
        if (powerMax) tags.push('power_max_dbm:' + powerMax);
        if (burstDuration) tags.push('burst_duration_ms:' + burstDuration);
        if (burstInterval) tags.push('burst_interval_ms:' + burstInterval);
        formData.append('tags', JSON.stringify(tags));
        formData.append('source', 'manual_threat');

        // Use auth headers without Content-Type (FormData sets it)
        var headers = {};
        var token = sessionStorage.getItem('bridge_session_token');
        var apiKey = sessionStorage.getItem('bridge_api_key') || sessionStorage.getItem('bridge_admin_key');
        if (token) headers['X-Session-Token'] = token;
        else if (apiKey) headers['X-API-Key'] = apiKey;

        fetch(API + '/', {
            method: 'POST',
            headers: headers,
            body: formData
        })
            .then(function (r) {
                if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
                return r.json();
            })
            .then(function () {
                toggleCreateForm(false);
                clearCreateForm();
                refreshThreats();
                refreshStats();
            })
            .catch(function (e) { alert('Failed to create signature: ' + e.message); });
    }

    function clearCreateForm() {
        var ids = [
            'threat-create-name', 'threat-create-protocol', 'threat-create-signal-class',
            'threat-create-description', 'threat-create-freq-min', 'threat-create-freq-max',
            'threat-create-center-freq', 'threat-create-power-min', 'threat-create-power-max',
            'threat-create-burst-duration', 'threat-create-burst-interval'
        ];
        ids.forEach(function (id) {
            var el = document.getElementById(id);
            if (el) el.value = '';
        });
        var catSel = document.getElementById('threat-create-category');
        if (catSel) catSel.value = '';
        var lvlSel = document.getElementById('threat-create-level');
        if (lvlSel) lvlSel.value = '';
    }

    function toggleCreateForm(show) {
        var form = document.getElementById('threat-create-form');
        if (!form) return;
        if (show === undefined) {
            form.style.display = form.style.display === 'none' ? '' : 'none';
        } else {
            form.style.display = show ? '' : 'none';
        }
    }

    // ── Seed Defaults ───────────────────────────────────────────────

    function seedDefaults() {
        if (!confirm('Seed default TSCM threat signatures? This will add curated signatures to the library.')) return;
        fetch(API + '/threats/seed', {
            method: 'POST',
            headers: getAuthHeaders()
        })
            .then(function (r) {
                if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
                return r.json();
            })
            .then(function (d) {
                alert('Seeded ' + (d.seeded || 0) + ' threat signatures');
                refreshThreats();
                refreshStats();
            })
            .catch(function (e) { alert('Failed to seed: ' + e.message); });
    }

    // ── Wire UI ─────────────────────────────────────────────────────

    function init() {
        var tab = document.getElementById('tab-threats');
        if (!tab) return;

        // Filter controls
        var catFilter = document.getElementById('threat-filter-category');
        if (catFilter) catFilter.addEventListener('change', function () {
            currentFilters.category = catFilter.value;
            refreshThreats();
        });

        var lvlFilter = document.getElementById('threat-filter-level');
        if (lvlFilter) lvlFilter.addEventListener('change', function () {
            currentFilters.level = lvlFilter.value;
            refreshThreats();
        });

        var searchInput = document.getElementById('threat-filter-search');
        if (searchInput) {
            var debounce = null;
            searchInput.addEventListener('input', function () {
                clearTimeout(debounce);
                debounce = setTimeout(function () {
                    currentFilters.search = searchInput.value.trim();
                    refreshThreats();
                }, 400);
            });
        }

        // Create form
        var createBtn = document.getElementById('threat-create-btn');
        if (createBtn) createBtn.addEventListener('click', function () { toggleCreateForm(); });

        var submitBtn = document.getElementById('threat-create-submit');
        if (submitBtn) submitBtn.addEventListener('click', createSignature);

        var cancelBtn = document.getElementById('threat-create-cancel');
        if (cancelBtn) cancelBtn.addEventListener('click', function () { toggleCreateForm(false); });

        // Seed defaults
        var seedBtn = document.getElementById('threat-seed-btn');
        if (seedBtn) seedBtn.addEventListener('click', seedDefaults);

        // Refresh button
        var refreshBtn = document.getElementById('threat-refresh-btn');
        if (refreshBtn) refreshBtn.addEventListener('click', function () {
            refreshThreats();
            refreshStats();
        });

        // Tab visibility observer
        var observer = new MutationObserver(function () {
            if (tab.classList.contains('active')) {
                refreshThreats();
                refreshStats();
            }
        });
        observer.observe(tab, { attributes: true, attributeFilter: ['class'] });

        // Auto-refresh every 30s when tab is visible
        refreshInterval = setInterval(function () {
            if (tab.classList.contains('active')) {
                refreshThreats();
                refreshStats();
            }
        }, 30000);
    }

    init();
})();
